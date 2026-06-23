# SPDX-License-Identifier: MIT
"""/ items 60 + 73 — recurring rotation framework."""

from __future__ import annotations

from app.core.config import settings
from app.services.anonymize.rotation import (
    RotationPolicy,
    all_policies,
    hop_idempotency_policy,
    horizon_invariant_satisfied,
    is_purge_due,
    is_rotation_due,
    quote_token_policy,
    reuse_detection_policy,
)


def test_reuse_detection_policy_reads_settings(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reuse_detection_key_rotation_days", 30)
    monkeypatch.setattr(settings, "anonymize_reuse_detection_key_retention_days", 90)
    p = reuse_detection_policy()
    assert p.name == "reuse_detection"
    assert p.rotation_days == 30
    assert p.retention_days == 90
    assert p.runtime_state_key == "reuse_detection_key_rotation_last_at"


def test_hop_idempotency_policy_defaults(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_hop_idempotency_key_rotation_days", 7)
    monkeypatch.setattr(settings, "anonymize_hop_idempotency_key_retention_days", 14)
    p = hop_idempotency_policy()
    assert p.rotation_days == 7
    assert p.retention_days == 14


def test_quote_token_policy_defaults(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_rotation_days", 1)
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_retention_days", 7)
    p = quote_token_policy()
    assert p.rotation_days == 1
    assert p.retention_days == 7


def test_all_policies_returns_each_managed_keyset() -> None:
    names = [p.name for p in all_policies()]
    assert "reuse_detection" in names
    assert "hop_idempotency" in names
    assert "quote_token_hmac" in names
    assert "quote_cache_signing" in names


def _policy(*, rotation_days: int = 30, retention_days: int = 90) -> RotationPolicy:
    return RotationPolicy(
        name="reuse_detection",
        rotation_days=rotation_days,
        retention_days=retention_days,
        runtime_state_key="x",
    )


def test_rotation_due_when_never_rotated() -> None:
    """First-ever run must rotate so the active generation is recorded."""
    assert is_rotation_due(_policy(), last_rotation_unix_s=None) is True


def test_rotation_due_when_threshold_passed(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reuse_detection_key_rotation_min_interval_s", 60)
    p = _policy(rotation_days=1)
    now = 1_000_000.0
    last = now - (2 * 86_400)  # 2 days ago
    assert is_rotation_due(p, last_rotation_unix_s=last, now_unix_s=now) is True


def test_rotation_not_due_within_threshold(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_reuse_detection_key_rotation_min_interval_s", 60)
    p = _policy(rotation_days=1)
    now = 1_000_000.0
    last = now - (3600)  # 1 hour ago
    assert is_rotation_due(p, last_rotation_unix_s=last, now_unix_s=now) is False


def test_rotation_disabled_when_rotation_days_zero() -> None:
    p = _policy(rotation_days=0)
    assert is_rotation_due(p, last_rotation_unix_s=None) is False


def test_rotation_idempotency_floor_blocks_double_rotate(monkeypatch) -> None:
    """Even if the threshold has passed, rotations are floored."""
    p = _policy(rotation_days=1)
    now = 1_000_000.0
    # Just rotated 5 seconds ago; floor is 60.
    last = now - 5
    assert is_rotation_due(p, last_rotation_unix_s=last, now_unix_s=now, min_interval_s=60) is False


def test_rotation_clock_backwards_returns_false() -> None:
    """A clock blip that makes elapsed negative must not double-rotate."""
    p = _policy(rotation_days=1)
    now = 1_000_000.0
    last = now + 100  # in the future — clock went backwards
    assert is_rotation_due(p, last_rotation_unix_s=last, now_unix_s=now) is False


def test_purge_due_after_retention_horizon() -> None:
    p = _policy(rotation_days=1, retention_days=7)
    now = 1_000_000.0
    rotated_out = now - (8 * 86_400)
    assert is_purge_due(p, rotated_out_at_unix_s=rotated_out, now_unix_s=now) is True


def test_purge_not_due_within_retention() -> None:
    p = _policy(rotation_days=1, retention_days=7)
    now = 1_000_000.0
    rotated_out = now - 86_400  # 1 day ago
    assert is_purge_due(p, rotated_out_at_unix_s=rotated_out, now_unix_s=now) is False


def test_horizon_invariant_satisfied_when_retention_dominates() -> None:
    p = _policy(rotation_days=30, retention_days=90)
    assert horizon_invariant_satisfied(p, destination_retention_days=7) is True
    # 90 < 7 + 30 + 60? — invariant requires retention >= dest + rotation:
    # 90 >= 7 + 30 = 37 ⇒ satisfied.
    assert horizon_invariant_satisfied(p, destination_retention_days=7) is True


def test_horizon_invariant_violated_when_retention_too_short() -> None:
    p = _policy(rotation_days=30, retention_days=14)
    assert horizon_invariant_satisfied(p, destination_retention_days=7) is False


# ── Quote-token-specific horizon invariant ──────────────────────


def test_quote_token_horizon_invariant_accepts_default(monkeypatch) -> None:
    """Defaults (rotation=1d, retention=8d, ttl=300s) satisfy the bound."""
    from app.services.anonymize.rotation import (
        quote_token_horizon_invariant_satisfied,
        quote_token_policy,
    )

    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_rotation_days", 1)
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_retention_days", 8)
    monkeypatch.setattr(settings, "anonymize_quote_token_ttl_s", 300)
    pol = quote_token_policy()
    assert quote_token_horizon_invariant_satisfied(pol, quote_ttl_s=300) is True


def test_quote_token_horizon_invariant_rejects_short_retention(monkeypatch) -> None:
    """Retention=1 fails (1 < ceil(300/86400)=1 + rotation=1 = 2)."""
    from app.services.anonymize.rotation import (
        quote_token_horizon_invariant_satisfied,
        quote_token_policy,
    )

    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_rotation_days", 1)
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_retention_days", 1)
    pol = quote_token_policy()
    assert quote_token_horizon_invariant_satisfied(pol, quote_ttl_s=300) is False


def test_quote_token_horizon_invariant_handles_multi_day_ttl(monkeypatch) -> None:
    """TTL=2 days + rotation=1 day ⇒ retention must be >= 3 days."""
    from app.services.anonymize.rotation import (
        quote_token_horizon_invariant_satisfied,
        quote_token_policy,
    )

    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_rotation_days", 1)
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_retention_days", 3)
    pol = quote_token_policy()
    assert quote_token_horizon_invariant_satisfied(pol, quote_ttl_s=172_800) is True
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_retention_days", 2)
    pol = quote_token_policy()
    assert quote_token_horizon_invariant_satisfied(pol, quote_ttl_s=172_800) is False


def test_quote_token_horizon_invariant_rejects_wrong_policy() -> None:
    """The helper refuses to apply to the wrong rotation policy."""
    import pytest

    from app.services.anonymize.rotation import (
        quote_token_horizon_invariant_satisfied,
        reuse_detection_policy,
    )

    with pytest.raises(ValueError, match="quote_token_hmac only"):
        quote_token_horizon_invariant_satisfied(
            reuse_detection_policy(),
            quote_ttl_s=300,
        )
