# SPDX-License-Identifier: MIT
"""Per-method facade override tests for ``MempoolFeeService``.

Each public chain method has two code paths:

* electrum unconfigured → straight delegation to the HTTP super.
* electrum configured → dispatch via ``_dispatch`` (auto-fallback or
  strict, depending on ``CHAIN_BACKEND``).

The existing facade-level tests cover ``get_transaction``; this file
exercises the remaining methods (`get_address`, `get_address_utxos`,
`get_block_tip_height`, `get_block_by_height`, `get_mempool_stats`,
`get_transaction_confirmations`, `get_fee_for_priority`,
`get_target_conf_for_priority`) plus the strict-mode startup-failure
path.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.services.chain.electrum import (
    _ELECTRUM_BREAKER,
    ElectrumChainBackend,
    ElectrumClient,
)
from app.services.chain.mempool_http import MempoolHttpBackend
from app.services.mempool_fee_service import MempoolFeeService
from tests.unit._fake_electrum import FakeElectrumServer


@pytest.fixture
async def electrum_facade(monkeypatch):
    """Facade in auto mode wired to a fake electrum server."""
    async with FakeElectrumServer() as server:
        # Fixture-level breaker reset.
        _ELECTRUM_BREAKER.state = "closed"
        _ELECTRUM_BREAKER.consecutive_failures = 0
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.lnd_electrum_url",
            server.url,
        )
        monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "auto")
        svc = MempoolFeeService()
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        svc._electrum = ElectrumChainBackend(client=client, network="bitcoin")
        await svc.start()
        try:
            yield svc, server
        finally:
            await svc.close()


# ─── Each facade method dispatches through electrum on the happy path ─


@pytest.mark.asyncio
async def test_facade_get_address_uses_electrum(electrum_facade):
    svc, server = electrum_facade
    server.set_response(
        "blockchain.scripthash.get_balance",
        {"confirmed": 1234, "unconfirmed": 0},
    )
    server.set_response("blockchain.scripthash.get_history", [])
    out, err = await svc.get_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    assert err is None and out is not None
    assert out["confirmed_balance_sats"] == 1234


@pytest.mark.asyncio
async def test_facade_get_address_utxos_uses_electrum(electrum_facade):
    svc, server = electrum_facade
    server.set_response(
        "blockchain.scripthash.listunspent",
        [{"tx_hash": "ab" * 32, "tx_pos": 0, "value": 5000, "height": 800_001}],
    )
    out, err = await svc.get_address_utxos("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    assert err is None
    assert out == [
        {
            "txid": "ab" * 32,
            "vout": 0,
            "value_sats": 5000,
            "confirmed": True,
            "block_height": 800_001,
        }
    ]


@pytest.mark.asyncio
async def test_facade_get_block_tip_height_uses_electrum(electrum_facade):
    svc, _server = electrum_facade
    height, err = await svc.get_block_tip_height()
    assert err is None
    # Default fake server response: 800_000.
    assert height == 800_000


@pytest.mark.asyncio
async def test_facade_get_block_by_height_uses_electrum(electrum_facade):
    svc, server = electrum_facade
    server.set_response("blockchain.block.header", "00" * 80)
    out, err = await svc.get_block_by_height(800_000)
    assert err is None and out is not None
    assert out["height"] == 800_000
    assert out["tx_count"] is None  # documented gap


@pytest.mark.asyncio
async def test_facade_get_mempool_stats_uses_electrum(electrum_facade):
    svc, server = electrum_facade
    server.set_response("mempool.get_fee_histogram", [[5.0, 1000]])
    stats, err = await svc.get_mempool_stats()
    assert err is None and stats is not None
    assert stats["fee_histogram"] == [[5.0, 1000]]


@pytest.mark.asyncio
async def test_facade_get_transaction_confirmations_uses_electrum(electrum_facade):
    svc, server = electrum_facade
    server.set_response(
        "blockchain.transaction.get",
        {"txid": "cc" * 32, "confirmations": 0, "vin": [], "vout": []},
    )
    out, err = await svc.get_transaction_confirmations("cc" * 32)
    assert err is None and out is not None
    assert out["confirmed"] is False


@pytest.mark.asyncio
async def test_facade_get_fee_for_priority_uses_electrum(electrum_facade):
    svc, server = electrum_facade
    server.set_response("blockchain.estimatefee", 0.00010000)
    rate = await svc.get_fee_for_priority("medium")
    assert rate is not None and rate >= 1


@pytest.mark.asyncio
async def test_facade_get_fee_for_priority_falls_back_in_auto_mode(electrum_facade, monkeypatch):
    """If Electrum yields ``None`` and we're in auto mode, fall back to
    the inherited HTTP implementation."""
    svc, server = electrum_facade
    server.set_error("blockchain.estimatefee", -1, "no estimate")

    fallback = AsyncMock(return_value=42)
    monkeypatch.setattr(MempoolHttpBackend, "get_fee_for_priority", fallback)
    rate = await svc.get_fee_for_priority("high")
    assert rate == 42
    fallback.assert_awaited_once()


@pytest.mark.asyncio
async def test_facade_get_fee_for_priority_strict_returns_none(monkeypatch):
    """In strict ``electrum`` mode, ``None`` from Electrum is final."""
    async with FakeElectrumServer() as server:
        _ELECTRUM_BREAKER.state = "closed"
        _ELECTRUM_BREAKER.consecutive_failures = 0
        server.set_error("blockchain.estimatefee", -1, "no estimate")
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.lnd_electrum_url",
            server.url,
        )
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.chain_backend",
            "electrum",
        )
        svc = MempoolFeeService()
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        svc._electrum = ElectrumChainBackend(client=client, network="bitcoin")
        await svc.start()

        fallback = AsyncMock(return_value=99)
        monkeypatch.setattr(MempoolHttpBackend, "get_fee_for_priority", fallback)
        try:
            rate = await svc.get_fee_for_priority("medium")
            assert rate is None
            fallback.assert_not_awaited()
        finally:
            await svc.close()


@pytest.mark.asyncio
async def test_facade_get_target_conf_for_priority_known_and_unknown():
    """``get_target_conf_for_priority`` is a pure local mapping —
    same shape regardless of backend."""
    svc = MempoolFeeService()
    try:
        low = svc.get_target_conf_for_priority("low")
        med = svc.get_target_conf_for_priority("medium")
        high = svc.get_target_conf_for_priority("high")
        assert isinstance(low, int) and isinstance(med, int) and isinstance(high, int)
        # Unknown → default (6).
        assert svc.get_target_conf_for_priority("zonk") == 6
    finally:
        await svc.close()


# ─── Strict-mode startup failure ─────────────────────────────────────


@pytest.mark.asyncio
async def test_strict_mode_startup_raises_when_unreachable(monkeypatch):
    """``CHAIN_BACKEND=electrum`` + an unreachable URL must raise from
    ``svc.start()`` — operators chose strict mode precisely so we
    fail loud rather than silently leak to mempool.space."""
    monkeypatch.setattr(
        "app.services.mempool_fee_service.settings.lnd_electrum_url",
        "tcp://127.0.0.1:1",  # nothing listens there
    )
    monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "electrum")
    _ELECTRUM_BREAKER.state = "closed"
    _ELECTRUM_BREAKER.consecutive_failures = 0
    svc = MempoolFeeService()
    client = ElectrumClient(
        "tcp://127.0.0.1:1",
        connect_timeout_s=0.2,
        request_timeout_s=0.2,
    )
    svc._electrum = ElectrumChainBackend(client=client, network="bitcoin")
    try:
        with pytest.raises((ConnectionError, TimeoutError, OSError)):
            await svc.start()
    finally:
        await svc.close()


@pytest.mark.asyncio
async def test_auto_mode_startup_does_not_raise_when_unreachable(monkeypatch):
    """In ``auto`` mode the same scenario must NOT raise — the supervisor
    keeps retrying in the background and the HTTP fallback covers gaps."""
    monkeypatch.setattr(
        "app.services.mempool_fee_service.settings.lnd_electrum_url",
        "tcp://127.0.0.1:1",
    )
    monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "auto")
    _ELECTRUM_BREAKER.state = "closed"
    _ELECTRUM_BREAKER.consecutive_failures = 0
    svc = MempoolFeeService()
    client = ElectrumClient(
        "tcp://127.0.0.1:1",
        connect_timeout_s=0.2,
        request_timeout_s=0.2,
    )
    svc._electrum = ElectrumChainBackend(client=client, network="bitcoin")
    try:
        # Must complete without raising even though connect will fail.
        await svc.start()
    finally:
        await svc.close()
