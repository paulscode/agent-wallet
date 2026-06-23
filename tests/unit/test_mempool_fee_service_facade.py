# SPDX-License-Identifier: MIT
"""Tests for the ``MempoolFeeService`` facade routing in
``app/services/mempool_fee_service.py``.

* ``mempool`` mode: never touches Electrum.
* ``electrum`` mode: never falls back to HTTP.
* ``auto`` mode (default): tries Electrum first; falls back to HTTP
  on error string.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.services.chain.electrum import ElectrumChainBackend, ElectrumClient
from app.services.mempool_fee_service import MempoolFeeService
from tests.unit._fake_electrum import FakeElectrumServer


@pytest.mark.asyncio
async def test_mempool_only_when_no_electrum_url(monkeypatch) -> None:
    monkeypatch.setattr("app.services.mempool_fee_service.settings.lnd_electrum_url", "")
    monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "auto")
    svc = MempoolFeeService()
    try:
        assert svc.has_electrum is False
        assert svc.primary_backend_name == "mempool"
        assert svc._electrum is None
    finally:
        await svc.close()


@pytest.mark.asyncio
async def test_strict_electrum_mode_no_fallback(monkeypatch) -> None:
    async with FakeElectrumServer() as server:
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.lnd_electrum_url",
            server.url,
        )
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.chain_backend",
            "electrum",
        )
        # Build a service whose ElectrumChainBackend points at the fake.
        svc = MempoolFeeService()
        # Replace the auto-built electrum backend with one wired to the
        # fake server (the auto-built one parses url from settings — same).
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        svc._electrum = ElectrumChainBackend(client=client, network="bitcoin")
        try:
            assert svc.has_electrum is True
            assert svc.has_fallback is False
            await svc.start()
            # Electrum returns an error → strict mode surfaces it.
            server.set_error("blockchain.transaction.get", -1, "boom")
            tx, err = await svc.get_transaction("aa" * 32)
            assert tx is None
            assert err is not None and "boom" in err
        finally:
            await svc.close()


@pytest.mark.asyncio
async def test_auto_mode_falls_back_to_mempool_http(monkeypatch) -> None:
    async with FakeElectrumServer() as server:
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.lnd_electrum_url",
            server.url,
        )
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.chain_backend",
            "auto",
        )
        svc = MempoolFeeService()
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        svc._electrum = ElectrumChainBackend(client=client, network="bitcoin")
        try:
            await svc.start()
            # Make Electrum fail, and mock the HTTP fallback to return success.
            server.set_error("blockchain.transaction.get", -1, "electrum down")
            fallback_tx = {"txid": "bb" * 32, "confirmed": True}
            # Patch the inherited HTTP method directly.
            from app.services.chain.mempool_http import MempoolHttpBackend

            mock_http = AsyncMock(return_value=(fallback_tx, None))
            monkeypatch.setattr(MempoolHttpBackend, "get_transaction", mock_http)

            tx, err = await svc.get_transaction("bb" * 32)
            assert err is None
            assert tx == fallback_tx
            assert mock_http.await_count == 1
        finally:
            await svc.close()


@pytest.mark.asyncio
async def test_auto_mode_uses_electrum_when_healthy(monkeypatch) -> None:
    async with FakeElectrumServer() as server:
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.lnd_electrum_url",
            server.url,
        )
        monkeypatch.setattr(
            "app.services.mempool_fee_service.settings.chain_backend",
            "auto",
        )
        svc = MempoolFeeService()
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        svc._electrum = ElectrumChainBackend(client=client, network="bitcoin")
        try:
            await svc.start()
            server.set_response(
                "blockchain.transaction.get",
                {
                    "txid": "cc" * 32,
                    "confirmations": 1,
                    "vin": [],
                    "vout": [],
                },
            )
            from app.services.chain.mempool_http import MempoolHttpBackend

            mock_http = AsyncMock(return_value=(None, "should-not-call"))
            monkeypatch.setattr(MempoolHttpBackend, "get_transaction", mock_http)

            tx, err = await svc.get_transaction("cc" * 32)
            assert err is None
            assert tx is not None and tx["txid"] == "cc" * 32
            mock_http.assert_not_awaited()
        finally:
            await svc.close()


@pytest.mark.asyncio
async def test_default_facade_passes_through_to_http(monkeypatch) -> None:
    """With no electrum configured, every legacy patch point still works."""
    monkeypatch.setattr("app.services.mempool_fee_service.settings.lnd_electrum_url", "")
    monkeypatch.setattr("app.services.mempool_fee_service.settings.chain_backend", "auto")
    svc = MempoolFeeService()
    try:
        # Patch ``svc._request`` (the inherited HTTP primitive) — this
        # is the legacy patch surface used by tons of unit tests.
        from unittest.mock import patch

        # When ``_request`` returns an error, the facade should pass
        # the error through unchanged (no electrum fallback configured).
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(None, "mempool unavailable"),
        ):
            tx, err = await svc.get_transaction("dd" * 32)
        assert tx is None
        assert err == "mempool unavailable"
    finally:
        await svc.close()
