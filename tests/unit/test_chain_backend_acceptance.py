# SPDX-License-Identifier: MIT
"""Acceptance tests for the electrs integration.

These tests cover three explicit acceptance criteria that aren't
proven elsewhere:

1. ``httpx`` traffic is zero when ``CHAIN_BACKEND=electrum`` and the
   Electrum backend is healthy. We patch ``httpx.AsyncClient.request``
   to fail the test if invoked.

2. The shared health registry surfaces an ``electrum`` entry once the
   facade has started, with ``enabled=True``.

3. Existing facade methods (``get_transaction``, ``get_address``,
   ``get_recommended_fees``, ``get_block_tip_height``,
   ``get_mempool_stats``) round-trip correctly through the Electrum
   adapter without touching the HTTP backend.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.services.chain.electrum import ElectrumChainBackend, ElectrumClient
from app.services.health import all_health, get_health
from app.services.mempool_fee_service import MempoolFeeService
from tests.unit._fake_electrum import FakeElectrumServer


def _block_header_hex() -> str:
    """An 80-byte hex block header (any valid bytes — content unchecked)."""
    return "00" * 80


@pytest.fixture
async def strict_electrum_service(monkeypatch):
    """A ``MempoolFeeService`` in strict ``electrum`` mode wired to a fake
    server. Yields ``(svc, server)`` and tears down both."""
    async with FakeElectrumServer() as server:
        # Pre-load typical default responses so any call succeeds
        # without per-test setup.
        server.set_response(
            "blockchain.estimatefee",
            0.00010000,  # 10 sat/vB
        )
        server.set_response("mempool.get_fee_histogram", [[10.0, 1500]])
        server.set_response(
            "blockchain.transaction.get",
            {
                "txid": "ab" * 32,
                "confirmations": 3,
                "blockhash": "cd" * 32,
                "blocktime": 1700000000,
                "size": 200,
                "weight": 800,
                "vsize": 200,
                "fee": 0.00001000,
                "vin": [],
                "vout": [],
                "version": 2,
                "locktime": 0,
            },
        )
        server.set_response(
            "blockchain.scripthash.get_balance",
            {"confirmed": 100_000, "unconfirmed": 0},
        )
        server.set_response("blockchain.scripthash.get_history", [])
        server.set_response("blockchain.scripthash.listunspent", [])
        server.set_response("blockchain.block.header", _block_header_hex())

        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.lnd_electrum_url",
            server.url,
        )
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.chain_backend",
            "electrum",
        )

        svc = MempoolFeeService()
        # Replace facade's auto-built electrum with one wired to the
        # fake server (same URL, but explicit so we control timeouts).
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        svc._electrum = ElectrumChainBackend(client=client, network="bitcoin")
        try:
            await svc.start()
            yield svc, server
        finally:
            await svc.close()


@pytest.mark.asyncio
async def test_no_httpx_traffic_in_strict_electrum_mode(
    strict_electrum_service,
):
    """Acceptance: ``CHAIN_BACKEND=electrum`` issues zero HTTP calls."""
    svc, _server = strict_electrum_service

    def _fail(*args, **kwargs):
        raise AssertionError(f"Unexpected httpx request in electrum mode: args={args!r}")

    # Patch every plausible egress point on httpx.AsyncClient.
    with (
        patch("httpx.AsyncClient.request", side_effect=_fail),
        patch("httpx.AsyncClient.send", side_effect=_fail),
        patch("httpx.AsyncClient.get", side_effect=_fail),
        patch("httpx.AsyncClient.post", side_effect=_fail),
    ):
        # Hit every public chain method that backs a /v1/mempool/* route.
        fees, err = await svc.get_recommended_fees()
        assert err is None and fees is not None

        tx, err = await svc.get_transaction("ab" * 32)
        assert err is None and tx is not None

        confs, err = await svc.get_transaction_confirmations("ab" * 32)
        assert err is None and confs is not None

        addr, err = await svc.get_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        assert err is None and addr is not None

        utxos, err = await svc.get_address_utxos("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        assert err is None and utxos is not None

        stats, err = await svc.get_mempool_stats()
        assert err is None and stats is not None

        height, err = await svc.get_block_tip_height()
        assert err is None and height is not None

        block, err = await svc.get_block_by_height(800_000)
        assert err is None and block is not None


@pytest.mark.asyncio
async def test_health_registry_exposes_electrum_entry(
    strict_electrum_service,
):
    """Acceptance: ``/v1/admin/services`` (via ``all_health()``)
    must surface an ``electrum`` entry when the backend is active."""
    _svc, _server = strict_electrum_service
    h = get_health("electrum")
    assert h is not None
    assert h.enabled is True
    snapshot = h.snapshot()
    assert snapshot["name"] == "electrum"
    # And it's included in the global all_health() listing.
    names = [s.name for s in all_health()]
    assert "electrum" in names


@pytest.mark.asyncio
async def test_mempool_stats_shape_documents_null_gaps(
    strict_electrum_service,
):
    """Acceptance: documented gaps for ``mempool_stats`` are returned
    as ``None`` (not missing keys / not synthesized)."""
    svc, _server = strict_electrum_service
    stats, err = await svc.get_mempool_stats()
    assert err is None
    assert stats is not None
    # fee_histogram is preserved verbatim.
    assert stats["fee_histogram"] == [[10.0, 1500]]
    # tx_count / total_vsize / total_fee_btc are documented as ``None``.
    assert stats["tx_count"] is None
    assert stats["total_vsize"] is None
    assert stats["total_fee_btc"] is None


@pytest.mark.asyncio
async def test_block_shape_documents_null_gaps(strict_electrum_service):
    """Acceptance: ``block.{tx_count,size,weight,difficulty}`` are
    ``None`` in electrum mode (header-only data)."""
    svc, _server = strict_electrum_service
    block, err = await svc.get_block_by_height(800_000)
    assert err is None
    assert block is not None
    # Header-derived fields are populated.
    assert block["height"] == 800_000
    assert "hash" in block
    # Documented gaps.
    assert block["tx_count"] is None
    assert block["size"] is None
    assert block["weight"] is None
    assert block["difficulty"] is None
