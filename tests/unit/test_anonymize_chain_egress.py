# SPDX-License-Identifier: MIT
"""Anonymize-stack-direct chain client.

The chain-confirmation poll + self-broadcast fallback must NOT route
through the general-wallet ``mempool_fee_service`` (which would let
the chain-backend operator correlate anonymize lookups with wallet
activity). These tests assert:

* both helpers go through :func:`get_anonymize_client` with the
  ``chain_backend_anonymize`` call site;
* the broadcast helper returns the txid the backend echoed;
* the confirmation helper computes ``tip - block + 1``.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
import pytest

from app.core.config import settings
from app.services.anonymize import chain_egress


@dataclass
class _ClientCall:
    call_site: str
    socks_host: str
    socks_port: int
    requests: list[httpx.Request]


def _install_mock_anonymize_client(monkeypatch, handler) -> list[_ClientCall]:
    captured: list[_ClientCall] = []

    @asynccontextmanager
    async def _factory(*, call_site, socks_host, socks_port, timeout_s=30.0):
        call = _ClientCall(
            call_site=call_site,
            socks_host=socks_host,
            socks_port=socks_port,
            requests=[],
        )
        captured.append(call)

        def _wrapped(request: httpx.Request) -> httpx.Response:
            call.requests.append(request)
            return handler(request)

        transport = httpx.MockTransport(_wrapped)
        async with httpx.AsyncClient(transport=transport) as client:
            yield client

    monkeypatch.setattr(chain_egress, "get_anonymize_client", _factory)
    return captured


@pytest.fixture
def backend_configured(monkeypatch):
    monkeypatch.setattr(
        settings,
        "lnd_electrum_url",
        "https://chain.invalid",
    )
    monkeypatch.setattr(
        settings,
        "anonymize_tor_socks_ports",
        "boltz_submarine=9050,boltz_reverse=9051,liquid=9052,"
        "chain_backend=9053,bip353_dns=9054,quote_cache_refresh=9055,"
        "chain_backend_general=9056,chain_backend_anonymize=9057",
    )


# ── get_anonymize_tx_confirmations ──────────────────────────────────


@pytest.mark.asyncio
async def test_get_tx_confirmations_returns_zero_for_404(
    monkeypatch,
    backend_configured,
) -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    captured = _install_mock_anonymize_client(monkeypatch, _handler)
    data, err = await chain_egress.get_anonymize_tx_confirmations("ab" * 32)
    assert err is None
    assert data == {
        "txid": "ab" * 32,
        "confirmed": False,
        "confirmations": 0,
        "block_height": None,
    }
    assert captured[0].call_site == "chain_backend_anonymize"
    assert captured[0].socks_port == 9057


@pytest.mark.asyncio
async def test_get_tx_confirmations_returns_zero_for_unconfirmed(
    monkeypatch,
    backend_configured,
) -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"status": {"confirmed": False}},
        )

    _install_mock_anonymize_client(monkeypatch, _handler)
    data, err = await chain_egress.get_anonymize_tx_confirmations("ab" * 32)
    assert err is None
    assert data["confirmations"] == 0


@pytest.mark.asyncio
async def test_get_tx_confirmations_computes_tip_minus_block_plus_one(
    monkeypatch,
    backend_configured,
) -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/blocks/tip/height"):
            return httpx.Response(200, text="105")
        return httpx.Response(
            200,
            json={
                "status": {
                    "confirmed": True,
                    "block_height": 100,
                    "block_hash": "00" * 32,
                }
            },
        )

    _install_mock_anonymize_client(monkeypatch, _handler)
    data, err = await chain_egress.get_anonymize_tx_confirmations("ab" * 32)
    assert err is None
    assert data["confirmed"] is True
    assert data["confirmations"] == 6
    assert data["block_height"] == 100


@pytest.mark.asyncio
async def test_get_tx_confirmations_rejects_bad_txid(monkeypatch) -> None:
    with pytest.raises(Exception):
        await chain_egress.get_anonymize_tx_confirmations("not-hex")


@pytest.mark.asyncio
async def test_get_tx_confirmations_errors_when_backend_unset(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    data, err = await chain_egress.get_anonymize_tx_confirmations("ab" * 32)
    assert data is None
    assert "backend URL not configured" in (err or "")


# ── anonymize_broadcast_tx ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_broadcast_returns_txid_from_response_body(
    monkeypatch,
    backend_configured,
) -> None:
    expected_txid = "cd" * 32

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path.endswith("/api/tx")
        assert request.content == b"deadbeef"
        return httpx.Response(200, text=expected_txid)

    captured = _install_mock_anonymize_client(monkeypatch, _handler)
    txid, err = await chain_egress.anonymize_broadcast_tx("deadbeef")
    assert err is None
    assert txid == expected_txid
    assert captured[0].call_site == "chain_backend_anonymize"


@pytest.mark.asyncio
async def test_broadcast_rejects_response_with_non_hex_body(
    monkeypatch,
    backend_configured,
) -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="boom not-a-txid")

    _install_mock_anonymize_client(monkeypatch, _handler)
    txid, err = await chain_egress.anonymize_broadcast_tx("deadbeef")
    assert txid is None
    assert "invalid txid" in (err or "")


@pytest.mark.asyncio
async def test_broadcast_propagates_400_error_from_backend(
    monkeypatch,
    backend_configured,
) -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad-tx: dust output")

    _install_mock_anonymize_client(monkeypatch, _handler)
    txid, err = await chain_egress.anonymize_broadcast_tx("deadbeef")
    assert txid is None
    assert "400" in (err or "")
    assert "bad-tx" in (err or "")


@pytest.mark.asyncio
async def test_broadcast_errors_when_backend_unset(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    txid, err = await chain_egress.anonymize_broadcast_tx("deadbeef")
    assert txid is None
    assert "backend URL not configured" in (err or "")


# ── get_anonymize_economy_feerate ───────────────────────────────────


@pytest.mark.asyncio
async def test_economy_feerate_reads_economy_field(
    monkeypatch,
    backend_configured,
) -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path.endswith("/fees/recommended")
        return httpx.Response(
            200,
            json={
                "fastestFee": 50,
                "halfHourFee": 30,
                "hourFee": 20,
                "economyFee": 5,
                "minimumFee": 1,
            },
        )

    captured = _install_mock_anonymize_client(monkeypatch, _handler)
    value, err = await chain_egress.get_anonymize_economy_feerate()
    assert err is None
    assert value == 5.0
    assert captured[0].call_site == "chain_backend_anonymize"


@pytest.mark.asyncio
async def test_economy_feerate_falls_back_to_minimum(
    monkeypatch,
    backend_configured,
) -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "fastestFee": 50,
                "minimumFee": 2,
            },
        )

    _install_mock_anonymize_client(monkeypatch, _handler)
    value, err = await chain_egress.get_anonymize_economy_feerate()
    assert err is None
    assert value == 2.0


@pytest.mark.asyncio
async def test_economy_feerate_errors_when_field_missing(
    monkeypatch,
    backend_configured,
) -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"fastestFee": 50})

    _install_mock_anonymize_client(monkeypatch, _handler)
    value, err = await chain_egress.get_anonymize_economy_feerate()
    assert value is None
    assert "economyFee" in (err or "")


@pytest.mark.asyncio
async def test_economy_feerate_propagates_5xx(
    monkeypatch,
    backend_configured,
) -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream down")

    _install_mock_anonymize_client(monkeypatch, _handler)
    value, err = await chain_egress.get_anonymize_economy_feerate()
    assert value is None
    assert "503" in (err or "")
