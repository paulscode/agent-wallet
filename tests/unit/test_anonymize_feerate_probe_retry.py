# SPDX-License-Identifier: MIT
"""Two-probe feerate fail-mode."""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.cooperative_claim import (
    FeerateProbeUnavailableError,
    probe_economy_feerate_with_retry,
)


@pytest.mark.asyncio
async def test_returns_first_successful_probe(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_feerate_probe_retry_delay_s", 0)

    def _fetch() -> float:
        return 12.5

    out = await probe_economy_feerate_with_retry(_fetch)
    assert out == 12.5


@pytest.mark.asyncio
async def test_retries_after_first_failure(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_feerate_probe_retry_delay_s", 0)
    calls = {"n": 0}

    def _fetch() -> float:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("first probe failed")
        return 8.0

    out = await probe_economy_feerate_with_retry(_fetch)
    assert out == 8.0
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_raises_after_two_consecutive_failures(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_feerate_probe_retry_delay_s", 0)

    def _fetch() -> float:
        raise RuntimeError("backend down")

    with pytest.raises(FeerateProbeUnavailableError):
        await probe_economy_feerate_with_retry(_fetch)


@pytest.mark.asyncio
async def test_supports_async_fetch(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_claim_feerate_probe_retry_delay_s", 0)

    async def _fetch() -> float:
        return 5.0

    out = await probe_economy_feerate_with_retry(_fetch)
    assert out == 5.0


@pytest.mark.asyncio
async def test_explicit_retry_delay_used() -> None:
    """The caller can override the configured delay (e.g., in tests)."""
    calls = {"n": 0}

    def _fetch() -> float:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("x")
        return 7.0

    out = await probe_economy_feerate_with_retry(_fetch, retry_delay_s=0.0)
    assert out == 7.0
