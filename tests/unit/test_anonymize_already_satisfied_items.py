# SPDX-License-Identifier: MIT
"""Verification tests for items already satisfied by the helpers.

These items are partial because they describe an
*invariant* the orchestrator must hold; the helpers we shipped in
earlier turns already encode the invariant. The tests here pin the
behavior so a future regression is caught at PR time.

Items covered:

* Reuse-key vs destination-retention horizon invariant
  (now wired via :func:`assert_key_retention_horizons_satisfied`).
* Transactional event-collapse pass (idempotent shape).
* Window-aggregated audit suppression marker.
* Distinct chain-client SOCKS listeners (now wired via
  :func:`assert_chain_client_listeners_distinct`).
* Per-operator quote-cache namespacing.
* Bounded-retention hop_idempotency_key (rotation
  framework + horizon invariant).
* Decoy K-decrement headroom invariant.
* Two-step migration 020 default.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import settings
from app.services.anonymize.audit_summary import (
    aggregate_window_emission,
    build_bucket_summary,
)
from app.services.anonymize.cooperative_claim import (
    sample_decoy_decrement_decision,
)
from app.services.anonymize.gc import (
    GC_PASS_EVENT_COLLAPSE,
    is_pass_complete,
    run_event_collapse_pass,
)
from app.services.anonymize.quote_cache import CacheKey
from app.services.anonymize.rotation import (
    all_policies,
    hop_idempotency_policy,
    horizon_invariant_satisfied,
)
from app.services.anonymize.startup import (
    AnonymizeStartupError,
    assert_chain_client_listeners_distinct,
    assert_key_retention_horizons_satisfied,
)

# ── item 72 / horizon invariant ──────────────────────────


def test_horizon_invariant_passes_with_documented_defaults(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    monkeypatch.setattr(settings, "anonymize_reuse_detection_key_rotation_days", 30)
    monkeypatch.setattr(settings, "anonymize_reuse_detection_key_retention_days", 90)
    monkeypatch.setattr(settings, "anonymize_hop_idempotency_key_rotation_days", 7)
    monkeypatch.setattr(settings, "anonymize_hop_idempotency_key_retention_days", 14)
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_rotation_days", 1)
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_retention_days", 8)
    assert_key_retention_horizons_satisfied()  # no raise


def test_horizon_invariant_rejects_short_reuse_retention(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    monkeypatch.setattr(settings, "anonymize_reuse_detection_key_rotation_days", 30)
    monkeypatch.setattr(settings, "anonymize_reuse_detection_key_retention_days", 30)  # 30 < 7+30
    with pytest.raises(AnonymizeStartupError, match="reuse_detection"):
        assert_key_retention_horizons_satisfied()


def test_each_policy_individually_satisfies_invariant(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    for p in all_policies():
        assert horizon_invariant_satisfied(
            p,
            destination_retention_days=7,
        ), f"{p.name} fails the invariant under defaults"


# ── item 76 — transactional event-collapse idempotency ────────────


@pytest.mark.asyncio
async def test_event_collapse_is_re_runnable_without_side_effects(
    db_session,
) -> None:
    """A re-run against a partially-collapsed session is a no-op."""
    from datetime import datetime, timezone
    from uuid import uuid4

    from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

    sess = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.COMPLETED.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(sess)
    await db_session.flush()

    first = await run_event_collapse_pass(db_session, sess)
    second = await run_event_collapse_pass(db_session, sess)
    third = await run_event_collapse_pass(db_session, sess)
    assert first is True
    assert second is False
    assert third is False
    assert is_pass_complete(sess.gc_passes_completed, GC_PASS_EVENT_COLLAPSE)


# ── item 77 — window-aggregated suppression marker ────────────────


def test_window_emits_single_had_suppressed_buckets_marker() -> None:
    """One per-window boolean replaces per-bucket suppression markers."""
    a = build_bucket_summary(
        bucket_start_unix_s=1_000,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 7},
        counts_by_source_kind={"ext-lightning": 7},
        min_bucket_count=5,
    )
    b = build_bucket_summary(
        bucket_start_unix_s=4_600,
        bucket_seconds=3600,
        counts_by_terminal_state={"completed": 1},
        counts_by_source_kind={"ext-lightning": 1},
        min_bucket_count=5,
    )
    win = aggregate_window_emission(
        [a, b],
        window_start_unix_s=0,
        window_end_unix_s=86_400,
    )
    # The window emits one boolean, NOT one marker per suppressed bucket.
    assert win.had_suppressed_buckets is True
    assert len(win.summaries) == 1
    # The summaries list excludes suppressed buckets entirely.
    assert all(s.bucket_start_unix_s == 1_000 for s in win.summaries)


# ── item 78 — distinct chain-client listeners ─────────────────────


def test_chain_listeners_distinct_passes_under_default_config() -> None:
    """Default config maps chain_backend_general and _anonymize to
    different SOCKS listener ports."""
    assert_chain_client_listeners_distinct()  # no raise


def test_chain_listeners_distinct_rejects_collision(monkeypatch) -> None:
    """Operator misconfig that points both clients at the same
    listener trips the gate."""
    # Force both factories to return the same listener label.
    from app.services.anonymize import chain as chain_mod

    def _shared_general():
        return chain_mod.ChainClientSpec(
            purpose="general",
            socks_listener="shared",
            backend_url="tcp://x",
            first_connect_jitter_s=0,
        )

    def _shared_anonymize():
        return chain_mod.ChainClientSpec(
            purpose="anonymize",
            socks_listener="shared",
            backend_url="tcp://x",
            first_connect_jitter_s=30,
        )

    monkeypatch.setattr(chain_mod, "get_general_chain_client_spec", _shared_general)
    monkeypatch.setattr(chain_mod, "get_anonymize_chain_client_spec", _shared_anonymize)
    with pytest.raises(AnonymizeStartupError, match="distinct SOCKS"):
        assert_chain_client_listeners_distinct()


# ── item 83 — per-operator quote-cache namespacing ────────────────


def test_cache_key_changes_with_operator_id() -> None:
    """A poisoned response from operator A does NOT affect a session
    that selected operator B."""
    a = CacheKey(operator_id="op-a", pair="BTC/BTC", asset="BTC")
    b = CacheKey(operator_id="op-b", pair="BTC/BTC", asset="BTC")
    assert a != b
    assert hash(a) != hash(b)
    # Same operator-id ⇒ same key.
    a2 = CacheKey(operator_id="op-a", pair="BTC/BTC", asset="BTC")
    assert a == a2


# ── item 101 — bounded-retention hop_idempotency_key ──────────────


def test_hop_idempotency_policy_horizon(monkeypatch) -> None:
    """The horizon invariant covers the hop_idempotency key set."""
    monkeypatch.setattr(settings, "anonymize_destination_retention_days", 7)
    monkeypatch.setattr(settings, "anonymize_hop_idempotency_key_rotation_days", 7)
    monkeypatch.setattr(settings, "anonymize_hop_idempotency_key_retention_days", 14)
    p = hop_idempotency_policy()
    assert horizon_invariant_satisfied(p, destination_retention_days=7) is True


# ── item 132 — decoy K-decrement headroom invariant ───────────────


def test_decoy_decrement_obeys_headroom_invariant(monkeypatch) -> None:
    """Requested_k below floor + headroom never decrements."""
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_rate", 1.0)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_k_min_executed", 2)
    monkeypatch.setattr(settings, "anonymize_reverse_mpp_decoy_decrement_headroom", 2)
    # Floor + headroom = 4. K=3 is below the threshold ⇒ never decrement.
    for _ in range(20):
        assert sample_decoy_decrement_decision(requested_k=3) is False
    # K=4 is at the threshold ⇒ admitted (rate=1.0).
    assert sample_decoy_decrement_decision(requested_k=4) is True


# ── item 133 — two-step migration 020 default ─────────────────────


def test_two_step_020_migrations_exist() -> None:
    """020a_*.py + 020b_*.py exist as the recommended-default path."""
    repo_root = Path(__file__).resolve().parents[2]
    versions = repo_root / "alembic" / "versions"
    a = versions / "020a_anonymize_runtime_state_add_enc_column.py"
    b = versions / "020b_anonymize_runtime_state_finalize.py"
    assert a.is_file(), f"missing two-step migration: {a}"
    assert b.is_file(), f"missing two-step migration: {b}"


def test_020a_chains_to_020b() -> None:
    """The two migrations form an ordered chain (020a → 020b)."""
    repo_root = Path(__file__).resolve().parents[2]
    a_text = (repo_root / "alembic" / "versions" / "020a_anonymize_runtime_state_add_enc_column.py").read_text(
        encoding="utf-8"
    )
    b_text = (repo_root / "alembic" / "versions" / "020b_anonymize_runtime_state_finalize.py").read_text(
        encoding="utf-8"
    )
    assert "020a_anonymize_runtime_state_add_enc_column" in b_text
    assert "019_anonymize_k_decrement_counter" in a_text
