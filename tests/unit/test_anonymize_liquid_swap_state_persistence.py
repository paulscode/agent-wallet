# SPDX-License-Identifier: MIT
"""Tests for the Liquid swap_state persistence layer.

The dispatcher's process-wide ``swap_state`` cache is in-memory.
A wallet restart between the leg-1 LN-payment broadcast and the
leg-1 cooperative claim would lose the wallet-generated secrets
(preimage, claim privkey) without persistence — leaving the L-BTC
stranded at Boltz's lockup until the refund path activates.

These tests exercise the encrypt/persist/decrypt/restore round-
trip and the cache-overlay semantics:

* Persisting a session's swap_state writes a non-empty token into
  ``pipeline_json[_PIPELINE_JSON_KEY]``.
* Restoring on a fresh cache rehydrates every entry that belonged
  to the session.
* Restoring is a no-op when the cache already holds the session's
  entries (does not clobber live state).
* Multi-session isolation: a session's persisted state never leaks
  entries from a different session.
* Corrupt ciphertext is rejected silently (the bounded-retry loop
  routes the session to reconciliation, not panic).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

from app.services.anonymize.liquid_swap_state_persistence import (
    persist_session_swap_state,
    restore_session_swap_state,
)


@dataclass
class _StubSession:
    """Minimal stub mirroring ``AnonymizeSession``'s persistence fields."""

    id: UUID
    pipeline_json: dict[str, Any] = field(default_factory=dict)


def _entry(session_id: UUID, leg: str) -> dict[str, Any]:
    """Build a representative per-swap state entry for ``leg``."""
    return {
        "session_id": str(session_id),
        "leg": leg,
        "preimage_hex": "aa" * 32,
        "claim_private_key_hex": "bb" * 32,
        "lockup_script_hex": "0014" + "cc" * 20,
        "blinding_privkey_hex": "dd" * 32,
        "expected_amount_sat": 250_000,
        "swap_tree_claim_leaf": "82" + "00" * 31,
        "swap_tree_refund_leaf": "20" + "00" * 31,
    }


# ── Round-trip ─────────────────────────────────────────────────────


def test_persist_then_restore_round_trips_entries() -> None:
    sid = uuid4()
    session = _StubSession(id=sid)
    state: dict[str, dict[str, Any]] = {"swap-a": _entry(sid, "ln_to_lbtc")}
    persist_session_swap_state(session, state)

    # The persisted token is opaque ciphertext, not the plaintext map.
    assert "liquid_swap_state_enc" in session.pipeline_json
    assert "preimage_hex" not in str(session.pipeline_json["liquid_swap_state_enc"])

    # Fresh process: empty cache hydrates from the session row.
    fresh_state: dict[str, dict[str, Any]] = {}
    assert restore_session_swap_state(session, fresh_state) is True
    assert "swap-a" in fresh_state
    assert fresh_state["swap-a"]["preimage_hex"] == "aa" * 32


def test_persist_is_noop_when_session_has_no_entries() -> None:
    """Persisting against an empty session-scope cache must not
    overwrite a prior blob; the cache miss is treated as transient."""
    sid = uuid4()
    session = _StubSession(id=sid)
    # Seed a persisted blob.
    persist_session_swap_state(session, {"swap-a": _entry(sid, "ln_to_lbtc")})
    pre_token = session.pipeline_json["liquid_swap_state_enc"]

    # A subsequent tick with an empty cache must not clobber it.
    persist_session_swap_state(session, {})
    assert session.pipeline_json["liquid_swap_state_enc"] == pre_token


# ── Cache-overlay semantics ────────────────────────────────────────


def test_restore_does_not_clobber_live_cache_entries() -> None:
    """When the in-process cache already has the session's entries,
    restore must be a no-op so a fresh post-persist mutation isn't
    lost on the next tick."""
    sid = uuid4()
    session = _StubSession(id=sid)
    persist_session_swap_state(session, {"swap-a": _entry(sid, "ln_to_lbtc")})

    live_state: dict[str, dict[str, Any]] = {
        "swap-a": {"session_id": str(sid), "leg": "ln_to_lbtc", "fresh": True},
    }
    # Live entry is newer — restore must not overwrite it.
    assert restore_session_swap_state(session, live_state) is False
    assert live_state["swap-a"].get("fresh") is True


def test_restore_returns_false_when_no_persisted_blob() -> None:
    session = _StubSession(id=uuid4())
    assert restore_session_swap_state(session, {}) is False


# ── Multi-session isolation ────────────────────────────────────────


def test_persist_only_writes_entries_for_the_target_session() -> None:
    sid_a = uuid4()
    sid_b = uuid4()
    session_a = _StubSession(id=sid_a)
    # Process-wide cache holds entries for two sessions.
    state: dict[str, dict[str, Any]] = {
        "swap-a": _entry(sid_a, "ln_to_lbtc"),
        "swap-b": _entry(sid_b, "ln_to_lbtc"),
    }
    persist_session_swap_state(session_a, state)

    # session_a's blob must NOT leak swap-b.
    fresh: dict[str, dict[str, Any]] = {}
    restore_session_swap_state(session_a, fresh)
    assert "swap-a" in fresh
    assert "swap-b" not in fresh


# ── Corruption ─────────────────────────────────────────────────────


def test_restore_handles_corrupt_blob_silently() -> None:
    """A corrupt ciphertext returns False; the hop body falls back to
    the bounded-retry path rather than crashing the dispatcher."""
    session = _StubSession(
        id=uuid4(),
        pipeline_json={"liquid_swap_state_enc": "not-a-fernet-token"},
    )
    assert restore_session_swap_state(session, {}) is False


# ── End-to-end restart simulation ──────────────────────────────────


def test_full_restart_simulation_preserves_wallet_secrets() -> None:
    """Simulates the exact loss vector: wallet broadcasts the LN
    payment, persists the leg-1 secrets, then crashes. A fresh
    process restores swap_state and can complete the claim."""
    sid = uuid4()
    session = _StubSession(id=sid)
    # Process 1: populates the cache from `_create_ln_to_lbtc` and
    # persists immediately.
    state_p1: dict[str, dict[str, Any]] = {
        "boltz-swap-xyz": {
            "session_id": str(sid),
            "leg": "ln_to_lbtc",
            "preimage_hex": "ee" * 32,
            "claim_private_key_hex": "11" * 32,
            "session_blinding_seed_index": 12345,
            "swap_tree_claim_leaf": "82" + "00" * 31,
            "swap_tree_refund_leaf": "20" + "00" * 31,
            "refund_public_key_hex": "02" + "aa" * 32,
            "lockup_script_hex": "0014" + "cc" * 20,
            "blinding_privkey_hex": "dd" * 32,
            "expected_amount_sat": 250_000,
        },
    }
    persist_session_swap_state(session, state_p1)

    # Process 2 (after restart): swap_state cache is empty.
    state_p2: dict[str, dict[str, Any]] = {}
    assert restore_session_swap_state(session, state_p2) is True
    restored = state_p2["boltz-swap-xyz"]
    # The wallet-generated secrets must survive — they're not
    # re-derivable from Boltz or the chain.
    assert restored["preimage_hex"] == "ee" * 32
    assert restored["claim_private_key_hex"] == "11" * 32
    # The Boltz-supplied data is also preserved (faster than re-fetching).
    assert restored["lockup_script_hex"] == "0014" + "cc" * 20
    assert restored["expected_amount_sat"] == 250_000
