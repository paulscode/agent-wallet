# SPDX-License-Identifier: MIT
"""Liquid fee oracle.

Covers: refresh + cache, floor/ceiling clamp, stale-cache fallback,
no-cache initial state, refresh error transparency on fresh cache.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.liquid_backend import MockLiquidBackend
from app.services.anonymize.liquid_fee_oracle import (
    CachedFeeRate,
    LiquidFeeOracle,
    LiquidFeeOracleError,
    get_liquid_fee_oracle,
    reset_liquid_fee_oracle,
)


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_liquid_fee_oracle()
    yield
    reset_liquid_fee_oracle()


# ── Construction ───────────────────────────────────────────────────


def test_oracle_uses_settings_defaults(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_fee_rate_floor_sat_per_vb",
        0.5,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_fee_rate_ceiling_sat_per_vb",
        500.0,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_fee_rate_cache_ttl_s",
        120,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_liquid_fee_rate_default_target_blocks",
        3,
    )
    backend = MockLiquidBackend()
    oracle = LiquidFeeOracle(backend)
    assert oracle.floor_sat_per_vb == 0.5
    assert oracle.ceiling_sat_per_vb == 500.0
    assert oracle.cache_ttl_s == 120


def test_oracle_rejects_non_positive_floor() -> None:
    with pytest.raises(LiquidFeeOracleError):
        LiquidFeeOracle(MockLiquidBackend(), floor_sat_per_vb=0)


def test_oracle_rejects_ceiling_below_floor() -> None:
    with pytest.raises(LiquidFeeOracleError):
        LiquidFeeOracle(
            MockLiquidBackend(),
            floor_sat_per_vb=10.0,
            ceiling_sat_per_vb=5.0,
        )


def test_oracle_rejects_non_positive_ttl() -> None:
    with pytest.raises(LiquidFeeOracleError):
        LiquidFeeOracle(MockLiquidBackend(), cache_ttl_s=0)


def test_oracle_rejects_non_positive_target_blocks() -> None:
    with pytest.raises(LiquidFeeOracleError):
        LiquidFeeOracle(MockLiquidBackend(), default_target_blocks=0)


# ── No-cache initial state ─────────────────────────────────────────


def test_no_cache_returns_ceiling_and_no_cache_marker() -> None:
    """Before the first refresh, reads must return the
    maximally-conservative ceiling + a clear marker."""
    backend = MockLiquidBackend()
    oracle = LiquidFeeOracle(
        backend,
        floor_sat_per_vb=1.0,
        ceiling_sat_per_vb=100.0,
        cache_ttl_s=60,
    )
    rate, err = oracle.get_fee_sat_per_vb()
    assert rate == 100.0
    assert err == "no_cache"
    assert oracle.cached is None
    assert oracle.is_cache_fresh() is False


# ── Refresh + fresh-cache read ─────────────────────────────────────


@pytest.mark.asyncio
async def test_refresh_populates_cache() -> None:
    backend = MockLiquidBackend()
    backend.set_fee_sat_per_vb(3.5)
    oracle = LiquidFeeOracle(
        backend,
        floor_sat_per_vb=0.1,
        ceiling_sat_per_vb=100.0,
        cache_ttl_s=60,
    )
    err = await oracle.refresh(now_unix_s=1_000.0)
    assert err is None
    assert isinstance(oracle.cached, CachedFeeRate)
    assert oracle.cached.rate_sat_per_vb == 3.5
    assert oracle.cached.fetched_at_unix_s == 1_000.0


@pytest.mark.asyncio
async def test_fresh_cache_read_returns_value_and_no_error() -> None:
    backend = MockLiquidBackend()
    backend.set_fee_sat_per_vb(5.0)
    oracle = LiquidFeeOracle(
        backend,
        floor_sat_per_vb=0.1,
        ceiling_sat_per_vb=100.0,
        cache_ttl_s=60,
    )
    await oracle.refresh(now_unix_s=1_000.0)
    rate, err = oracle.get_fee_sat_per_vb(now_unix_s=1_030.0)
    assert err is None
    assert rate == 5.0


# ── Clamping ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_clamps_to_floor_when_backend_returns_below() -> None:
    backend = MockLiquidBackend()
    backend.set_fee_sat_per_vb(0.001)  # well below floor
    oracle = LiquidFeeOracle(
        backend,
        floor_sat_per_vb=0.5,
        ceiling_sat_per_vb=100.0,
        cache_ttl_s=60,
    )
    await oracle.refresh(now_unix_s=1_000.0)
    rate, err = oracle.get_fee_sat_per_vb(now_unix_s=1_001.0)
    assert err is None
    assert rate == 0.5  # clamped


@pytest.mark.asyncio
async def test_clamps_to_ceiling_when_backend_returns_above() -> None:
    backend = MockLiquidBackend()
    backend.set_fee_sat_per_vb(99_999.0)
    oracle = LiquidFeeOracle(
        backend,
        floor_sat_per_vb=0.5,
        ceiling_sat_per_vb=100.0,
        cache_ttl_s=60,
    )
    await oracle.refresh(now_unix_s=1_000.0)
    rate, err = oracle.get_fee_sat_per_vb(now_unix_s=1_001.0)
    assert err is None
    assert rate == 100.0  # clamped to ceiling


@pytest.mark.asyncio
async def test_passes_through_when_within_band() -> None:
    backend = MockLiquidBackend()
    backend.set_fee_sat_per_vb(7.5)
    oracle = LiquidFeeOracle(
        backend,
        floor_sat_per_vb=1.0,
        ceiling_sat_per_vb=100.0,
        cache_ttl_s=60,
    )
    await oracle.refresh(now_unix_s=1_000.0)
    rate, err = oracle.get_fee_sat_per_vb(now_unix_s=1_001.0)
    assert err is None
    assert rate == 7.5


# ── Stale cache fallback ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_stale_cache_returns_value_with_stale_marker() -> None:
    backend = MockLiquidBackend()
    backend.set_fee_sat_per_vb(2.0)
    oracle = LiquidFeeOracle(
        backend,
        floor_sat_per_vb=0.1,
        ceiling_sat_per_vb=100.0,
        cache_ttl_s=60,
    )
    await oracle.refresh(now_unix_s=1_000.0)
    # Read at t=2000 — well past 60s TTL.
    rate, err = oracle.get_fee_sat_per_vb(now_unix_s=2_000.0)
    assert rate == 2.0  # the prior value
    assert err == "stale"
    assert oracle.is_cache_fresh(now_unix_s=2_000.0) is False


# ── Refresh error paths ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_refresh_error_leaves_cache_intact() -> None:
    """When refresh fails, the existing cache must persist — a
    transient backend failure shouldn't invalidate a known-good value."""
    backend = MockLiquidBackend()
    backend.set_fee_sat_per_vb(4.0)
    oracle = LiquidFeeOracle(
        backend,
        floor_sat_per_vb=0.1,
        ceiling_sat_per_vb=100.0,
        cache_ttl_s=60,
    )
    await oracle.refresh(now_unix_s=1_000.0)  # cache populated
    backend.fail("estimate_fee", "rpc_timeout")
    err = await oracle.refresh(now_unix_s=1_010.0)
    assert err == "rpc_timeout"
    # Cache value + timestamp must be unchanged.
    assert oracle.cached.rate_sat_per_vb == 4.0
    assert oracle.cached.fetched_at_unix_s == 1_000.0


@pytest.mark.asyncio
async def test_refresh_failure_transparent_when_cache_fresh() -> None:
    backend = MockLiquidBackend()
    backend.set_fee_sat_per_vb(4.0)
    oracle = LiquidFeeOracle(
        backend,
        floor_sat_per_vb=0.1,
        ceiling_sat_per_vb=100.0,
        cache_ttl_s=60,
    )
    await oracle.refresh(now_unix_s=1_000.0)
    backend.fail("estimate_fee", "transient")
    await oracle.refresh(now_unix_s=1_010.0)
    # Cache still within TTL; read returns fresh.
    rate, err = oracle.get_fee_sat_per_vb(now_unix_s=1_020.0)
    assert err is None
    assert rate == 4.0


@pytest.mark.asyncio
async def test_refresh_with_none_rate_returns_error() -> None:
    """A backend that returns ``(None, None)`` is treated as an error
    (the bug is the backend's — refuse to update the cache)."""

    class _BadBackend(MockLiquidBackend):
        async def estimate_fee_sat_per_vb(self, target_blocks=6):
            return None, None

    oracle = LiquidFeeOracle(
        _BadBackend(),
        floor_sat_per_vb=0.1,
        ceiling_sat_per_vb=100.0,
        cache_ttl_s=60,
    )
    err = await oracle.refresh()
    assert err is not None
    assert "no fee rate" in err
    assert oracle.cached is None


# ── Singleton ──────────────────────────────────────────────────────


def test_singleton_first_call_requires_backend() -> None:
    with pytest.raises(LiquidFeeOracleError):
        get_liquid_fee_oracle()


def test_singleton_returns_same_instance() -> None:
    backend = MockLiquidBackend()
    a = get_liquid_fee_oracle(backend)
    b = get_liquid_fee_oracle()
    assert a is b


def test_reset_clears_singleton() -> None:
    backend = MockLiquidBackend()
    a = get_liquid_fee_oracle(backend)
    reset_liquid_fee_oracle()
    b = get_liquid_fee_oracle(backend)
    assert a is not b


# ── End-to-end refresh + read pattern ──────────────────────────────


@pytest.mark.asyncio
async def test_recurring_refresh_then_quote_time_read() -> None:
    """The pattern: recurring refresh updates the cache; per-
    quote reads are cache-only with no egress."""
    backend = MockLiquidBackend()
    backend.set_fee_sat_per_vb(3.0)
    oracle = LiquidFeeOracle(
        backend,
        floor_sat_per_vb=0.1,
        ceiling_sat_per_vb=100.0,
        cache_ttl_s=60,
    )
    # Recurring task fires.
    await oracle.refresh(now_unix_s=1_000.0)
    # Quote-time reads — many, cheap, no backend egress.
    for offset in range(0, 60, 5):
        rate, err = oracle.get_fee_sat_per_vb(now_unix_s=1_000.0 + offset)
        assert err is None
        assert rate == 3.0
    # Backend rate changes — but the cache is sticky.
    backend.set_fee_sat_per_vb(10.0)
    rate, err = oracle.get_fee_sat_per_vb(now_unix_s=1_030.0)
    assert err is None
    assert rate == 3.0  # still cached
    # Next refresh picks up the change.
    await oracle.refresh(now_unix_s=1_040.0)
    rate, err = oracle.get_fee_sat_per_vb(now_unix_s=1_040.0)
    assert err is None
    assert rate == 10.0


# ── is_liquid_indexer_reachable() — outage liveness signal ─────────


class TestIsLiquidIndexerReachable:
    """The dashboard policy endpoint surfaces an electrs-liquid
    outage hint via ``is_liquid_indexer_reachable()``. The contract
    is: never raises, and returns ``False`` whenever the oracle's
    last refresh isn't fresh-cache-fresh (uninitialised, never
    refreshed, stale, or backend-raising)."""

    def test_returns_false_when_singleton_uninitialised(self) -> None:
        """Liquid hop disabled → no oracle ever constructed → False."""
        from app.services.anonymize.liquid_fee_oracle import (
            is_liquid_indexer_reachable,
        )

        assert is_liquid_indexer_reachable() is False

    def test_returns_false_before_first_refresh(self) -> None:
        """Oracle exists but has no cache yet — indexer is not
        confirmed reachable."""
        from app.services.anonymize.liquid_fee_oracle import (
            is_liquid_indexer_reachable,
        )

        get_liquid_fee_oracle(MockLiquidBackend())
        assert is_liquid_indexer_reachable() is False

    @pytest.mark.asyncio
    async def test_returns_true_after_successful_refresh(self) -> None:
        from app.services.anonymize.liquid_fee_oracle import (
            is_liquid_indexer_reachable,
        )

        backend = MockLiquidBackend()
        backend.set_fee_sat_per_vb(3.0)
        oracle = get_liquid_fee_oracle(backend)
        await oracle.refresh()
        assert is_liquid_indexer_reachable() is True

    @pytest.mark.asyncio
    async def test_returns_false_when_cache_goes_stale(self) -> None:
        from app.services.anonymize.liquid_fee_oracle import (
            is_liquid_indexer_reachable,
        )

        backend = MockLiquidBackend()
        backend.set_fee_sat_per_vb(3.0)
        oracle = LiquidFeeOracle(
            backend,
            floor_sat_per_vb=0.1,
            ceiling_sat_per_vb=100.0,
            cache_ttl_s=60,
        )
        # Install our oracle as the singleton.
        import app.services.anonymize.liquid_fee_oracle as _mod

        _mod._INSTANCE = oracle
        await oracle.refresh(now_unix_s=1_000.0)
        # Monkey-patch is_cache_fresh to report the cache as stale —
        # the indexer reachability signal must follow the freshness
        # signal exactly.
        oracle.is_cache_fresh = lambda *_a, **_kw: False  # type: ignore[assignment]
        assert is_liquid_indexer_reachable() is False

    def test_swallows_internal_exception(self) -> None:
        """Liveness check must never raise — a failing
        ``is_cache_fresh`` should degrade to ``False``."""
        import app.services.anonymize.liquid_fee_oracle as _mod
        from app.services.anonymize.liquid_fee_oracle import (
            is_liquid_indexer_reachable,
        )

        class _Boom:
            def is_cache_fresh(self, *_a, **_kw):  # noqa: D401
                raise RuntimeError("boom")

        _mod._INSTANCE = _Boom()  # type: ignore[assignment]
        assert is_liquid_indexer_reachable() is False
