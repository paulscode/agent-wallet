# SPDX-License-Identifier: MIT
"""Step-up nonce + verify rate-limit."""

from __future__ import annotations

import time

from app.core.config import settings
from app.services.anonymize.stepup import (
    CookieVerifyState,
    assert_nonce_entropy_floor,
    decode_nonce_from_transport,
    encode_nonce_for_transport,
    generate_nonce,
    is_cookie_locked_out,
    is_nonce_expired,
    record_failed_verify,
    reset_cookie_state,
)

# ── nonce entropy + transport ────────────────────────────────────────


def test_nonce_default_is_32_bytes(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_bytes", 32)
    n = generate_nonce()
    assert len(n) == 32


def test_nonce_clamped_above_hard_floor(monkeypatch) -> None:
    """A configured length below 16 is clamped to the default 32."""
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_bytes", 8)
    n = generate_nonce()
    assert len(n) == 32  # auto-clamped


def test_nonces_are_unique() -> None:
    seen = {generate_nonce() for _ in range(20)}
    assert len(seen) == 20  # no collisions


def test_nonce_transport_roundtrip() -> None:
    n = generate_nonce()
    enc = encode_nonce_for_transport(n)
    assert "=" not in enc  # rstrip pad
    assert decode_nonce_from_transport(enc) == n


def test_assert_entropy_floor_returns_clamped_value(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_bytes", 4)
    out = assert_nonce_entropy_floor()
    assert out == 32


def test_assert_entropy_floor_passes_above_floor(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_bytes", 64)
    assert assert_nonce_entropy_floor() == 64


# ── nonce TTL ───────────────────────────────────────────────────────


def test_nonce_not_expired_within_ttl(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_ttl_s", 60)
    issued = time.time()
    assert is_nonce_expired(issued_at_unix_s=issued) is False


def test_nonce_expired_past_ttl(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_stepup_nonce_ttl_s", 60)
    issued = time.time() - 120
    assert is_nonce_expired(issued_at_unix_s=issued) is True


# ── per-cookie verify rate-limit ────────────────────────────────────


def test_record_failed_verify_increments_counter() -> None:
    state = CookieVerifyState()
    out = record_failed_verify(state, rate_per_min=10, lockout_s=300)
    assert out.failed_verifies_in_window == 1
    assert out.last_failure_unix_s is not None
    assert out.locked_out_until_unix_s is None


def test_record_failed_verify_resets_after_window() -> None:
    """Failures older than 60 s reset the rolling counter."""
    earlier = time.time() - 120
    state = CookieVerifyState(
        failed_verifies_in_window=5,
        last_failure_unix_s=earlier,
    )
    out = record_failed_verify(state, rate_per_min=10, lockout_s=300)
    assert out.failed_verifies_in_window == 1


def test_record_failed_verify_locks_out_at_threshold() -> None:
    state = CookieVerifyState()
    for _ in range(9):
        state = record_failed_verify(state, rate_per_min=10, lockout_s=300)
        assert state.locked_out_until_unix_s is None
    state = record_failed_verify(state, rate_per_min=10, lockout_s=300)
    assert state.locked_out_until_unix_s is not None


def test_is_cookie_locked_out_predicate() -> None:
    now = time.time()
    state = CookieVerifyState(locked_out_until_unix_s=now + 100)
    assert is_cookie_locked_out(state, now_unix_s=now) is True
    assert is_cookie_locked_out(state, now_unix_s=now + 200) is False


def test_is_cookie_locked_out_when_never_locked() -> None:
    assert is_cookie_locked_out(CookieVerifyState()) is False


def test_reset_cookie_state_returns_fresh() -> None:
    fresh = reset_cookie_state()
    assert fresh.failed_verifies_in_window == 0
    assert fresh.last_failure_unix_s is None
    assert fresh.locked_out_until_unix_s is None
