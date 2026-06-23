# SPDX-License-Identifier: MIT
"""Regression tests for untrusted chain-backend feerate clamping (security H7).

A malicious/compromised Electrum or mempool server must not be able to
feed an enormous (or malformed) feerate that an automated send would burn
as miner fee. Feerates are clamped to a sane ceiling at the parse
boundary; malformed values are rejected so the caller falls back.
"""


import pytest

from app.services.chain.backend import (
    MAX_SANE_FEERATE_SAT_PER_VB,
    clamp_feerate_sat_per_vb,
)
from app.services.chain.mempool_http import MempoolHttpBackend


@pytest.mark.parametrize(
    "value,expected",
    [
        (1, 1),
        (50, 50),
        (MAX_SANE_FEERATE_SAT_PER_VB, MAX_SANE_FEERATE_SAT_PER_VB),
        (MAX_SANE_FEERATE_SAT_PER_VB + 1, MAX_SANE_FEERATE_SAT_PER_VB),
        (9999, MAX_SANE_FEERATE_SAT_PER_VB),
        (10**9, MAX_SANE_FEERATE_SAT_PER_VB),
        (3.7, 3),
    ],
)
def test_clamp_valid_values(value, expected):
    assert clamp_feerate_sat_per_vb(value) == expected


@pytest.mark.parametrize("bad", [None, "x", "", -1, 0, -0.5, float("nan"), float("inf")])
def test_clamp_rejects_bad_values(bad):
    assert clamp_feerate_sat_per_vb(bad) is None


@pytest.mark.asyncio
async def test_mempool_clamps_oversized_feerate(monkeypatch):
    backend = MempoolHttpBackend()

    async def _fake_request(_path):
        return {
            "fastestFee": 99999,  # malicious oversized
            "halfHourFee": 50000,
            "hourFee": 30000,
            "economyFee": 2,
            "minimumFee": 1,
        }, None

    monkeypatch.setattr(backend, "_request", _fake_request)
    fees, err = await backend.get_recommended_fees()
    assert err is None
    assert fees is not None
    assert fees["fastestFee"] == MAX_SANE_FEERATE_SAT_PER_VB
    assert fees["halfHourFee"] == MAX_SANE_FEERATE_SAT_PER_VB
    assert all(fees[k] <= MAX_SANE_FEERATE_SAT_PER_VB for k in fees if isinstance(fees[k], int))


@pytest.mark.asyncio
async def test_mempool_rejects_non_numeric_feerate(monkeypatch):
    backend = MempoolHttpBackend()

    async def _fake_request(_path):
        return {
            "fastestFee": "not-a-number",
            "halfHourFee": 5,
            "hourFee": 3,
            "economyFee": 2,
            "minimumFee": 1,
        }, None

    monkeypatch.setattr(backend, "_request", _fake_request)
    fees, err = await backend.get_recommended_fees()
    assert fees is None
    assert err is not None and "invalid fastestFee" in err
