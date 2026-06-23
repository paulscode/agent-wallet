# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.onion_only_detect`` plus the
polling-mode resolution helpers in the BOLT 12 subscribers that
consume it (S2 auto-default).
"""

from __future__ import annotations

import pytest

# ── Pure classifier ─────────────────────────────────────────────


def test_onion_only_detect_pure_classifier_true():
    """Only onion URIs → True."""
    from app.services.bolt12.onion_only_detect import _is_onion_only

    uris = [
        "020439b@kfs5iiwt4m6musumw6epatzgsjeuoxo7s2mdd3lr.onion:9735",
    ]
    assert _is_onion_only(uris) is True


def test_onion_only_detect_pure_classifier_mixed():
    """A clearnet address present → False."""
    from app.services.bolt12.onion_only_detect import _is_onion_only

    uris = [
        "abc@1.2.3.4:9735",
        "abc@xyz.onion:9735",
    ]
    assert _is_onion_only(uris) is False


def test_onion_only_detect_pure_classifier_empty_returns_false():
    """No URIs → False (can't classify as onion-only)."""
    from app.services.bolt12.onion_only_detect import _is_onion_only

    assert _is_onion_only([]) is False


# ── Caching behaviour ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_onion_only_detect_cached_after_first_call(monkeypatch):
    """Two calls in a row hit the LND helper exactly once."""
    from app.services.bolt12 import onion_only_detect as ood

    ood.reset_cache_for_tests()
    call_count = 0

    async def _fake_getinfo():
        nonlocal call_count
        call_count += 1
        return {"uris": ["abc@xyz.onion:9735"]}, None

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service.get_info",
        _fake_getinfo,
    )
    r1 = await ood.detect_onion_only()
    r2 = await ood.detect_onion_only()
    assert r1 is True and r2 is True
    assert call_count == 1


@pytest.mark.asyncio
async def test_onion_only_detect_does_not_cache_transient_failures(monkeypatch):
    """Regression: an earlier version cached `False` on transient
    LND failures (network blip, timeout). That pinned polling-
    mode off for the rest of the process lifetime — even after
    LND recovered. Now we only cache successful classifications,
    so a subsequent call retries on failure."""
    from app.services.bolt12 import onion_only_detect as ood

    ood.reset_cache_for_tests()
    call_count = 0

    async def _flaky_getinfo():
        nonlocal call_count
        call_count += 1
        # First two calls fail (simulating Tor blip), third
        # succeeds with an onion-only response.
        if call_count <= 2:
            return None, "simulated transient error"
        return {"uris": ["abc@xyz.onion:9735"]}, None

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service.get_info",
        _flaky_getinfo,
    )
    # First call: failure, returns False, NOT cached.
    r1 = await ood.detect_onion_only()
    assert r1 is False
    # Second call: failure again, NOT cached (verifies the fix).
    r2 = await ood.detect_onion_only()
    assert r2 is False
    # Third call: success — classified as onion-only, AND cached.
    r3 = await ood.detect_onion_only()
    assert r3 is True
    # Fourth call: cache hit, no new LND call.
    r4 = await ood.detect_onion_only()
    assert r4 is True
    assert call_count == 3, (
        "should have called LND 3 times (2 failures + 1 success), not capped at 1 by transient-failure caching"
    )


# ── Polling-mode resolver (settlement subscriber) ───────────────


@pytest.mark.asyncio
async def test_polling_mode_auto_detect_kill_switch_honoured(monkeypatch):
    """When ``bolt12_subscriber_polling_mode_auto_detect=false``,
    the auto-detect path is skipped and the polling-mode setting
    is returned verbatim — so an operator who explicitly chose
    ``polling_mode_enabled=false`` on an onion-only LND actually
    gets polling off."""
    from app.services.bolt12 import settlement_subscriber as sub

    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_polling_mode_enabled",
        False,
    )
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_polling_mode_auto_detect",
        False,
    )

    async def _onion_only():
        return True

    monkeypatch.setattr(
        "app.services.bolt12.onion_only_detect.detect_onion_only",
        _onion_only,
    )
    assert await sub._polling_mode_active() is False


@pytest.mark.asyncio
async def test_polling_mode_auto_detect_active_returns_detect_result(
    monkeypatch,
):
    """When the kill switch is on (default) and the polling-mode
    setting is False, the auto-detect result wins."""
    from datetime import datetime, timezone

    from app.services import lnd_keepalive
    from app.services.bolt12 import settlement_subscriber as sub

    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_polling_mode_enabled",
        False,
    )
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_polling_mode_auto_detect",
        True,
    )
    # 2026-06-12: the resolver now waits for the LND keepalive's
    # first success before running detect (to dodge the cold-start
    # Tor race). Mark a success so the wait returns immediately.
    lnd_keepalive.get_state().last_success_at = datetime.now(timezone.utc)

    async def _onion_only():
        return True

    monkeypatch.setattr(
        "app.services.bolt12.onion_only_detect.detect_onion_only",
        _onion_only,
    )
    assert await sub._polling_mode_active() is True


# ── Cold-start wait gate (2026-06-12) ────────────────────────────


@pytest.mark.asyncio
async def test_resolve_polling_mode_waits_for_keepalive_first_success(
    monkeypatch,
):
    """The shared resolver MUST wait for the LND keepalive's first
    success before running detect, so a cold-start Tor warmup
    doesn't cause detect to time out and silently drop us into
    streaming mode.

    Verifies the wait helper observes ``last_success_at`` flipping
    from None → set and short-circuits the polling loop.
    """
    import asyncio
    from datetime import datetime, timezone

    from app.services import lnd_keepalive
    from app.services.bolt12 import onion_only_detect as ood

    ood.reset_cache_for_tests()
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_polling_mode_enabled",
        False,
    )
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_polling_mode_auto_detect",
        True,
    )
    # Speed up the poll interval so the test runs in <1 s.
    monkeypatch.setattr(ood, "_KEEPALIVE_POLL_INTERVAL_S", 0.01)
    # Reset keepalive state so the wait sees None.
    lnd_keepalive.get_state().last_success_at = None

    detect_ran_at: list[float] = []

    async def _track_detect():
        import time as _t

        detect_ran_at.append(_t.monotonic())
        return True

    monkeypatch.setattr(ood, "detect_onion_only", _track_detect)

    async def _delayed_keepalive_success():
        await asyncio.sleep(0.05)
        lnd_keepalive.get_state().last_success_at = datetime.now(
            timezone.utc,
        )

    success_task = asyncio.create_task(_delayed_keepalive_success())
    try:
        import time as _t

        t0 = _t.monotonic()
        result = await ood.resolve_polling_mode_active()
        assert result is True
        assert detect_ran_at, "detect should have run"
        # Detect must NOT have fired before the keepalive success
        # was published (~0.05 s after the call).
        assert detect_ran_at[0] - t0 >= 0.04, (
            "resolver fired detect before keepalive's first success — the wait gate is broken"
        )
    finally:
        await success_task


@pytest.mark.asyncio
async def test_resolve_polling_mode_proceeds_after_keepalive_wait_timeout(
    monkeypatch,
):
    """If the keepalive never publishes a success within the
    timeout, the resolver must still proceed with detect (fail-
    open, not fail-closed). Detect may then return False, which is
    the same behaviour we'd have had without the wait — but we
    never want to deadlock the subscriber's startup."""
    from app.services import lnd_keepalive
    from app.services.bolt12 import onion_only_detect as ood

    ood.reset_cache_for_tests()
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_polling_mode_enabled",
        False,
    )
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_polling_mode_auto_detect",
        True,
    )
    # Tiny timeout + tiny poll interval so the test finishes fast.
    monkeypatch.setattr(ood, "_KEEPALIVE_WAIT_TIMEOUT_S", 0.05)
    monkeypatch.setattr(ood, "_KEEPALIVE_POLL_INTERVAL_S", 0.01)
    lnd_keepalive.get_state().last_success_at = None

    detect_called = False

    async def _detect():
        nonlocal detect_called
        detect_called = True
        return False

    monkeypatch.setattr(ood, "detect_onion_only", _detect)

    result = await ood.resolve_polling_mode_active()
    assert result is False
    assert detect_called, "resolver must fall through to detect after timeout"


@pytest.mark.asyncio
async def test_resolve_polling_mode_cache_hit_skips_wait(monkeypatch):
    """A cached classification short-circuits the keepalive wait —
    a subscriber restart shouldn't stall on a wait we already
    resolved earlier in the process."""
    from app.services.bolt12 import onion_only_detect as ood

    ood.reset_cache_for_tests()
    # Pre-populate the cache as if a prior call had succeeded.
    ood._cached_result = True
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_polling_mode_enabled",
        False,
    )
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_polling_mode_auto_detect",
        True,
    )

    wait_called = False

    async def _explode_wait(**kwargs):
        nonlocal wait_called
        wait_called = True
        raise AssertionError("wait gate should be skipped when cache is populated")

    monkeypatch.setattr(ood, "_wait_for_lnd_first_success", _explode_wait)
    try:
        result = await ood.resolve_polling_mode_active()
        assert result is True
        assert wait_called is False
    finally:
        ood.reset_cache_for_tests()


@pytest.mark.asyncio
async def test_detect_onion_only_timeout_logs_at_info_not_error(
    monkeypatch,
    caplog,
):
    """Regression: a previous version logged ``asyncio.TimeoutError``
    at ERROR with a full traceback during the cold-start Tor warmup
    race. Operators saw an ERROR every fresh boot for what is a
    normal transient. The branch now logs at INFO without a
    traceback so the ERROR channel stays clean."""
    import asyncio as _asyncio
    import logging

    from app.services.bolt12 import onion_only_detect as ood

    ood.reset_cache_for_tests()

    async def _slow_getinfo():
        await _asyncio.sleep(10.0)
        return {}, None

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service.get_info",
        _slow_getinfo,
    )
    caplog.set_level(logging.INFO, logger="app.services.bolt12.onion_only_detect")

    result = await ood.detect_onion_only(timeout_s=0.05)
    assert result is False

    timeout_records = [
        r for r in caplog.records if r.name == "app.services.bolt12.onion_only_detect" and "timed out" in r.getMessage()
    ]
    assert timeout_records, "should log a timeout INFO record"
    for r in timeout_records:
        assert r.levelno == logging.INFO, f"timeout log must be INFO, got {r.levelname}"
        assert r.exc_info is None, "timeout INFO must NOT carry a traceback"
