# SPDX-License-Identifier: MIT
"""Tests for the subscriber stream warmup probe (S4).

Lives in ``app.services.bolt12.subscriber_recovery`` alongside
the NEWNYM transport-error recovery helpers; this file isolates
the warmup probe so its kill-switch + error-path behaviour is
visible in one place.
"""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_warmup_probe_disabled_returns_true_without_call(monkeypatch):
    """Disabled setting short-circuits without touching LND."""
    from app.services.bolt12 import subscriber_recovery as rec

    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_warmup_probe_enabled",
        False,
    )
    called = False

    async def _explode(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("warmup probe must not call when disabled")

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service.get_info",
        _explode,
    )
    assert await rec.warmup_probe(subscriber_name="settlement") is True
    assert called is False


@pytest.mark.asyncio
async def test_warmup_probe_returns_false_on_error(monkeypatch):
    """Probe failure is signalled to the caller without raising."""
    from app.services.bolt12 import subscriber_recovery as rec

    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_warmup_probe_enabled",
        True,
    )

    async def _fail():
        return None, "simulated error"

    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service.get_info",
        _fail,
    )
    assert await rec.warmup_probe(subscriber_name="settlement") is False
