# SPDX-License-Identifier: MIT
"""/ items 94 + 125 — quote-cache rotation soft-stale."""

from __future__ import annotations

import time

from app.core.config import settings
from app.services.anonymize.quote_cache import (
    CacheEntry,
    CacheKey,
    sample_reverify_jitter_s,
    soft_stale_read_decision,
)


def _entry(
    *,
    fetched_at: float | None = None,
    sig_gen: int | None = 0,
) -> CacheEntry:
    return CacheEntry(
        key=CacheKey(operator_id="op-a", pair="BTC/BTC", asset="BTC"),
        payload={"fee": 100},
        fetched_at_unix_s=fetched_at if fetched_at is not None else time.time(),
        operator_signature=b"sig",
        signing_key_generation=sig_gen,
    )


def test_decision_serve_when_fresh_and_active_key(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_cache_max_age_s", 1800)
    decision = soft_stale_read_decision(
        _entry(),
        active_signing_key_generation=0,
    )
    assert decision == "serve"


def test_decision_block_for_refresh_when_rotated_out_key(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_cache_max_age_s", 1800)
    # Entry was signed under generation 1 but the active is now 0
    # (after rotation that promoted a new key to position 0).
    decision = soft_stale_read_decision(
        _entry(sig_gen=1),
        active_signing_key_generation=0,
    )
    assert decision == "block_for_refresh"


def test_decision_stale_503_when_past_max_age(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_cache_max_age_s", 60)
    old = time.time() - 600
    decision = soft_stale_read_decision(
        _entry(fetched_at=old, sig_gen=0),
        active_signing_key_generation=0,
    )
    assert decision == "stale_503"


def test_stale_takes_precedence_over_signature(monkeypatch) -> None:
    """A stale entry never reaches the signature check — it's a 503 either way."""
    monkeypatch.setattr(settings, "anonymize_quote_cache_max_age_s", 60)
    old = time.time() - 600
    decision = soft_stale_read_decision(
        _entry(fetched_at=old, sig_gen=1),  # rotated-out, but past max-age too
        active_signing_key_generation=0,
    )
    assert decision == "stale_503"


def test_decision_block_when_signature_generation_unknown(monkeypatch) -> None:
    """``signing_key_generation=None`` ⇒ unknown provenance ⇒ block-for-refresh."""
    monkeypatch.setattr(settings, "anonymize_quote_cache_max_age_s", 1800)
    decision = soft_stale_read_decision(
        _entry(sig_gen=None),
        active_signing_key_generation=0,
    )
    assert decision == "block_for_refresh"


def test_reverify_jitter_within_band(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_cache_reverify_jitter_s", 60)
    for _ in range(50):
        out = sample_reverify_jitter_s()
        assert 0.0 <= out <= 60.0


def test_reverify_jitter_zero_when_disabled(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_cache_reverify_jitter_s", 0)
    assert sample_reverify_jitter_s() == 0.0


# ── soft_stale_block_should_503 timeout ─────────────────────────


def test_soft_stale_block_returns_false_before_timeout(monkeypatch) -> None:
    from app.services.anonymize.quote_cache import soft_stale_block_should_503

    monkeypatch.setattr(
        settings,
        "anonymize_quote_cache_soft_stale_refresh_timeout_s",
        5,
    )
    assert (
        soft_stale_block_should_503(
            block_started_unix_s=1_000.0,
            now_unix_s=1_002.0,
        )
        is False
    )


def test_soft_stale_block_returns_true_at_or_past_timeout(monkeypatch) -> None:
    from app.services.anonymize.quote_cache import soft_stale_block_should_503

    monkeypatch.setattr(
        settings,
        "anonymize_quote_cache_soft_stale_refresh_timeout_s",
        5,
    )
    assert (
        soft_stale_block_should_503(
            block_started_unix_s=1_000.0,
            now_unix_s=1_005.0,
        )
        is True
    )
    assert (
        soft_stale_block_should_503(
            block_started_unix_s=1_000.0,
            now_unix_s=1_010.0,
        )
        is True
    )


def test_soft_stale_block_zero_timeout_503_immediately(monkeypatch) -> None:
    """A misconfigured zero-timeout disables soft-stale blocking entirely."""
    from app.services.anonymize.quote_cache import soft_stale_block_should_503

    monkeypatch.setattr(
        settings,
        "anonymize_quote_cache_soft_stale_refresh_timeout_s",
        0,
    )
    assert (
        soft_stale_block_should_503(
            block_started_unix_s=1_000.0,
            now_unix_s=1_000.001,
        )
        is True
    )
