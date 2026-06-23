# SPDX-License-Identifier: MIT
"""Quote-cache invalidation hook.

When ``operator_health.record_operator_outlier`` flags an operator
as degraded, the wallet MUST evict every quote-cache entry that
priced through that operator. Without this, the quote endpoint
could return a stale-but-validated quote that then explodes at
session-create time when the per-session loop hits the degraded
operator.
"""

from __future__ import annotations

from app.services.anonymize.quote_cache import (
    CacheEntry,
    CacheKey,
    get_quote_cache,
    invalidate_quote_cache_for_operator,
    reset_quote_cache,
)


def setup_function():
    reset_quote_cache()


def teardown_function():
    reset_quote_cache()


def _seed(operator_id: str, *, payload: dict | None = None) -> None:
    cache = get_quote_cache()
    cache.put(
        CacheEntry(
            key=CacheKey(operator_id=operator_id, pair="BTC/BTC", asset="BTC"),
            payload=payload or {"fee_floor_sat_per_vb": 1.0},
            fetched_at_unix_s=0.0,
        )
    )


def test_invalidate_for_operator_evicts_only_that_operator() -> None:
    """The invalidator scopes to a single operator_id — entries for
    other operators stay intact."""
    _seed("middleway")
    _seed("eldamar")
    _seed("boltz-canonical")

    invalidate_quote_cache_for_operator("middleway")

    cache = get_quote_cache()
    assert (
        cache.get(
            CacheKey(operator_id="middleway", pair="BTC/BTC", asset="BTC"),
        )
        is None
    )
    # The other operators remain.
    assert (
        cache.get(
            CacheKey(operator_id="eldamar", pair="BTC/BTC", asset="BTC"),
        )
        is not None
    )
    assert (
        cache.get(
            CacheKey(operator_id="boltz-canonical", pair="BTC/BTC", asset="BTC"),
        )
        is not None
    )


def test_invalidate_for_unknown_operator_is_noop() -> None:
    """Invalidating an operator that has no cache entry must not
    raise — it's a no-op so the health-record path stays robust."""
    _seed("middleway")
    invalidate_quote_cache_for_operator("never-cached")
    # Original entry unaffected.
    cache = get_quote_cache()
    assert (
        cache.get(
            CacheKey(operator_id="middleway", pair="BTC/BTC", asset="BTC"),
        )
        is not None
    )


def test_record_operator_outlier_calls_invalidator() -> None:
    """wiring — the hook is wired from
    ``operator_health.record_operator_outlier`` so a real
    degradation event evicts cache entries automatically. Static
    code check: the wired call exists in the source."""
    from pathlib import Path

    src = Path("app/services/anonymize/operator_health.py").read_text(encoding="utf-8")
    assert "invalidate_quote_cache_for_operator" in src
    assert "invalidate_probe_cache" in src
