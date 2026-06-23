# SPDX-License-Identifier: MIT
"""Quote cache helpers."""

from __future__ import annotations

import time
from collections import Counter

import pytest

from app.core.config import settings
from app.services.anonymize.quote_cache import (
    CacheEntry,
    CacheKey,
    is_entry_eligible_for_soft_stale_read,
    is_entry_fresh,
    sample_refresh_interval_s,
)


def test_sample_refresh_interval_within_band(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_cache_refresh_min_s", 450)
    monkeypatch.setattr(settings, "anonymize_quote_cache_refresh_max_s", 750)
    seen: Counter[int] = Counter()
    for _ in range(200):
        v = sample_refresh_interval_s()
        assert 450 <= v <= 750
        seen[v] += 1
    # The randomization should produce a reasonable spread; we don't
    # demand a specific distribution but we want at least 10 distinct
    # values across 200 samples (statistically near-certain).
    assert len(seen) > 10


def test_sample_refresh_interval_misconfig_falls_back_to_min(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_cache_refresh_min_s", 600)
    monkeypatch.setattr(settings, "anonymize_quote_cache_refresh_max_s", 100)  # bogus
    out = sample_refresh_interval_s()
    assert out == 600


def test_cache_key_requires_non_empty_strings() -> None:
    with pytest.raises(ValueError):
        CacheKey(operator_id="", pair="BTC/BTC", asset="BTC")
    with pytest.raises(ValueError):
        CacheKey(operator_id="op", pair="", asset="BTC")
    with pytest.raises(ValueError):
        CacheKey(operator_id="op", pair="BTC/BTC", asset="")


def test_cache_key_namespacing_is_per_operator() -> None:
    """The cache MUST be keyed on operator_id, not just pair/asset."""
    a = CacheKey(operator_id="op-a", pair="BTC/BTC", asset="BTC")
    b = CacheKey(operator_id="op-b", pair="BTC/BTC", asset="BTC")
    assert a != b
    assert hash(a) != hash(b)


def _entry(*, fetched_at: float, sig_gen: int | None = 0) -> CacheEntry:
    return CacheEntry(
        key=CacheKey(operator_id="op", pair="BTC/BTC", asset="BTC"),
        payload={"fee": 100},
        fetched_at_unix_s=fetched_at,
        operator_signature=b"sig",
        signing_key_generation=sig_gen,
    )


def test_is_entry_fresh_within_max_age(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_cache_max_age_s", 1800)
    now = time.time()
    fresh = _entry(fetched_at=now - 100)
    stale = _entry(fetched_at=now - 3600)
    assert is_entry_fresh(fresh, now_unix_s=now) is True
    assert is_entry_fresh(stale, now_unix_s=now) is False


def test_is_entry_fresh_zero_max_age_disables_caching(monkeypatch) -> None:
    """A zero / negative max-age means everything is stale."""
    monkeypatch.setattr(settings, "anonymize_quote_cache_max_age_s", 0)
    now = time.time()
    e = _entry(fetched_at=now)
    assert is_entry_fresh(e, now_unix_s=now) is False


def test_soft_stale_eligibility_requires_active_signing_key() -> None:
    """Only active-generation entries are eligible for soft-stale reads."""
    e = _entry(fetched_at=time.time(), sig_gen=0)
    assert is_entry_eligible_for_soft_stale_read(e, active_signing_key_generation=0)
    # Rotated-out signing key — must NOT serve via soft-stale.
    assert not is_entry_eligible_for_soft_stale_read(e, active_signing_key_generation=1)


def test_soft_stale_unsigned_entry_not_eligible() -> None:
    e = _entry(fetched_at=time.time(), sig_gen=None)
    assert not is_entry_eligible_for_soft_stale_read(e, active_signing_key_generation=0)
