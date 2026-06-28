# SPDX-License-Identifier: MIT
"""
Unit tests for app.services.mempool_fee_service.

Tests:
- Fee fetching with mocked HTTP
- Caching behavior (module-level globals)
- Priority fee mapping

NOTE: ``MempoolFeeService`` was extended to spin up an
``ElectrumChainBackend`` when ``LND_ELECTRUM_URL`` is set. The
electrum path takes precedence over the mocked HTTP path. The
auto-applied ``_force_mempool_only`` fixture below pins
``chain_backend="mempool"`` for every test in this file so they
exercise the pure HTTP surface they were authored against.
"""

import asyncio
import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.core.config import settings


@pytest.fixture(autouse=True)
def _force_mempool_only(monkeypatch):
    """Skip electrum-first dispatch for the HTTP-path tests in this file.

    The tests in this module predate the electrum integration. They
    mock ``httpx.AsyncClient.get`` and expect the result to flow
    through ``MempoolHttpBackend`` unchanged. The electrum-first
    dispatch added in 5bbd3f8 broke that assumption — on a host with
    a reachable Tor proxy the electrum backend connects and returns
    the real chain's fee rates, ignoring the mocked HTTP response.

    Force ``chain_backend="mempool"`` for the duration of each test
    so ``MempoolFeeService.__init__`` leaves ``self._electrum``
    unset and ``get_recommended_fees`` delegates straight to
    ``super().get_recommended_fees()``.
    """
    monkeypatch.setattr(settings, "chain_backend", "mempool")


def _make_response(status_code: int, json_data: dict) -> httpx.Response:
    """Create an httpx.Response with a fake request set (needed for raise_for_status)."""
    request = httpx.Request("GET", "https://mempool.space/api/v1/fees/recommended")
    response = httpx.Response(status_code, json=json_data, request=request)
    return response


class TestMempoolFeeService:
    """Tests for MempoolFeeService."""

    @pytest.mark.asyncio
    async def test_get_recommended_fees_success(self):
        """Fetch recommended fees from (mocked) Mempool API."""
        from app.services.mempool_fee_service import MempoolFeeService

        mock_data = {
            "fastestFee": 50,
            "halfHourFee": 30,
            "hourFee": 15,
            "economyFee": 8,
            "minimumFee": 1,
        }

        mock_response = _make_response(200, mock_data)

        svc = MempoolFeeService()

        with patch("app.services.chain.mempool_http.request_capped", new_callable=AsyncMock, return_value=mock_response):
            result, error = await svc.get_recommended_fees()

        assert result is not None
        assert result["fastestFee"] == 50
        assert result["hourFee"] == 15

    @pytest.mark.asyncio
    async def test_tx_404_is_not_found_and_does_not_trip_breaker(self):
        """A 404 (tx not indexed yet) is a clean answer from a healthy
        server: it maps to a 'not found' error and must NOT count as a
        circuit-breaker failure (otherwise a lagging indexer cascades
        into the fee endpoints)."""
        from app.services.chain.mempool_http import _MEMPOOL_BREAKER
        from app.services.mempool_fee_service import MempoolFeeService

        _MEMPOOL_BREAKER.reset()
        svc = MempoolFeeService()
        resp = _make_response(404, {"error": "not found"})

        with patch("app.services.chain.mempool_http.request_capped", new_callable=AsyncMock, return_value=resp):
            data, error = await svc.get_transaction("ab" * 32)

        assert data is None
        assert error == "not found"
        assert _MEMPOOL_BREAKER.consecutive_failures == 0
        assert _MEMPOOL_BREAKER.state == "closed"

    def test_http_client_rebinds_on_loop_change(self):
        """The singleton's httpx client must be recreated when the running
        event loop changes (Celery runs each task on its own throwaway
        loop); reusing a client bound to a closed loop raises 'Event loop
        is closed'."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()

        async def getc():
            return await svc._get_client()

        c1 = asyncio.run(getc())
        c2 = asyncio.run(getc())
        assert c1 is not c2  # recreated on the second (different) loop
        assert svc._client is c2

    @pytest.mark.asyncio
    async def test_get_fee_for_priority_high(self):
        """get_fee_for_priority('high') maps to fastestFee."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        svc._fee_cache = {
            "fastestFee": 50,
            "halfHourFee": 30,
            "hourFee": 15,
            "economyFee": 8,
            "minimumFee": 1,
        }
        svc._fee_cache_time = time.time()

        result = await svc.get_fee_for_priority("high")
        assert result == 50

    @pytest.mark.asyncio
    async def test_get_fee_for_priority_medium(self):
        """get_fee_for_priority('medium') maps to halfHourFee."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        svc._fee_cache = {
            "fastestFee": 50,
            "halfHourFee": 30,
            "hourFee": 15,
            "economyFee": 8,
            "minimumFee": 1,
        }
        svc._fee_cache_time = time.time()

        result = await svc.get_fee_for_priority("medium")
        assert result == 30

    @pytest.mark.asyncio
    async def test_get_fee_for_priority_low(self):
        """get_fee_for_priority('low') maps to hourFee."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        svc._fee_cache = {
            "fastestFee": 50,
            "halfHourFee": 30,
            "hourFee": 15,
            "economyFee": 8,
            "minimumFee": 1,
        }
        svc._fee_cache_time = time.time()

        result = await svc.get_fee_for_priority("low")
        assert result == 15

    @pytest.mark.asyncio
    async def test_get_fee_for_unknown_priority_falls_back(self):
        """Unknown priority falls back to medium."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        svc._fee_cache = {
            "fastestFee": 50,
            "halfHourFee": 30,
            "hourFee": 15,
            "economyFee": 8,
            "minimumFee": 1,
        }
        svc._fee_cache_time = time.time()

        result = await svc.get_fee_for_priority("ultra")
        # Falls back to "medium" → halfHourFee
        assert result == 30

    @pytest.mark.asyncio
    async def test_cache_expiry(self):
        """Cache should expire after TTL, causing a fresh fetch."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        svc._fee_cache = {"fastestFee": 50, "halfHourFee": 30, "hourFee": 15, "economyFee": 8, "minimumFee": 1}
        svc._fee_cache_time = time.time() - 120

        mock_response = _make_response(
            200,
            {
                "fastestFee": 75,
                "halfHourFee": 50,
                "hourFee": 25,
                "economyFee": 10,
                "minimumFee": 1,
            },
        )

        svc = MempoolFeeService()
        with patch("app.services.chain.mempool_http.request_capped", new_callable=AsyncMock, return_value=mock_response):
            result, error = await svc.get_recommended_fees()

        assert result["fastestFee"] == 75

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        """Fresh cache should be returned without HTTP call."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        svc._fee_cache = {"fastestFee": 42, "halfHourFee": 20, "hourFee": 10, "economyFee": 5, "minimumFee": 1}
        svc._fee_cache_time = time.time()

        result, error = await svc.get_recommended_fees()
        assert result["fastestFee"] == 42


class TestTransactionLookup:
    """Tests for transaction lookup and confirmation tracking."""

    @pytest.mark.asyncio
    async def test_get_transaction_success(self):
        """get_transaction returns structured tx data."""
        from app.services.mempool_fee_service import MempoolFeeService

        mock_tx = {
            "txid": "abc123" * 10 + "abcd",
            "status": {
                "confirmed": True,
                "block_height": 800000,
                "block_hash": "0000" * 16,
                "block_time": 1700000000,
            },
            "fee": 1500,
            "size": 250,
            "weight": 680,
            "version": 2,
            "locktime": 0,
            "vin": [{"txid": "prev", "vout": 0}],
            "vout": [
                {"scriptpubkey_address": "bc1qtest", "value": 50000},
                {"scriptpubkey_address": "bc1qchange", "value": 48500},
            ],
        }

        svc = MempoolFeeService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(mock_tx, None)):
            result, error = await svc.get_transaction("a" * 64)

        assert result is not None
        assert result["confirmed"] is True
        assert result["block_height"] == 800000
        assert result["fee"] == 1500
        assert result["vin_count"] == 1
        assert result["vout_count"] == 2
        assert len(result["vout"]) == 2
        assert result["vout"][0]["value"] == 50000

    @pytest.mark.asyncio
    async def test_get_transaction_unconfirmed(self):
        """Unconfirmed tx should have confirmed=False."""
        from app.services.mempool_fee_service import MempoolFeeService

        mock_tx = {
            "txid": "b" * 64,
            "status": {"confirmed": False},
            "fee": 500,
            "size": 200,
            "weight": 600,
            "version": 2,
            "locktime": 0,
            "vin": [],
            "vout": [],
        }

        svc = MempoolFeeService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(mock_tx, None)):
            result, error = await svc.get_transaction("b" * 64)

        assert result["confirmed"] is False
        assert result["block_height"] is None

    @pytest.mark.asyncio
    async def test_get_transaction_not_found(self):
        """Missing tx returns None."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "not found")):
            result, error = await svc.get_transaction("c" * 64)

        assert result is None

    @pytest.mark.asyncio
    async def test_get_transaction_confirmations(self):
        """Confirmations = tip_height - block_height + 1."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()

        mock_tx = {
            "txid": "d" * 64,
            "confirmed": True,
            "block_height": 800000,
            "block_time": 1700000000,
            "fee": 1000,
            "size": 200,
            "weight": 600,
            "vin_count": 1,
            "vout_count": 1,
            "vout": [],
        }

        with patch.object(svc, "get_transaction", new_callable=AsyncMock, return_value=(mock_tx, None)):
            with patch.object(svc, "get_block_tip_height", new_callable=AsyncMock, return_value=(800005, None)):
                result, error = await svc.get_transaction_confirmations("d" * 64)

        assert result is not None
        assert result["confirmed"] is True
        assert result["confirmations"] == 6  # 800005 - 800000 + 1

    @pytest.mark.asyncio
    async def test_get_transaction_confirmations_unconfirmed(self):
        """Unconfirmed tx returns 0 confirmations."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        mock_tx = {
            "txid": "e" * 64,
            "confirmed": False,
            "block_height": None,
        }

        with patch.object(svc, "get_transaction", new_callable=AsyncMock, return_value=(mock_tx, None)):
            result, error = await svc.get_transaction_confirmations("e" * 64)

        assert result["confirmed"] is False
        assert result["confirmations"] == 0


class TestAddressLookup:
    """Tests for address balance and UTXO lookups."""

    @pytest.mark.asyncio
    async def test_get_address_success(self):
        """get_address returns balance and tx counts."""
        from app.services.mempool_fee_service import MempoolFeeService

        mock_data = {
            "address": "bc1qtest",
            "chain_stats": {
                "funded_txo_sum": 1_000_000,
                "spent_txo_sum": 200_000,
                "tx_count": 5,
                "funded_txo_count": 3,
                "spent_txo_count": 1,
            },
            "mempool_stats": {
                "funded_txo_sum": 50_000,
                "spent_txo_sum": 0,
                "tx_count": 1,
            },
        }

        svc = MempoolFeeService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(mock_data, None)):
            result, error = await svc.get_address("bc1qtest")

        assert result is not None
        assert result["confirmed_balance_sats"] == 800_000  # 1M - 200K
        assert result["unconfirmed_balance_sats"] == 50_000
        assert result["total_balance_sats"] == 850_000
        assert result["confirmed_tx_count"] == 5
        assert result["unconfirmed_tx_count"] == 1

    @pytest.mark.asyncio
    async def test_get_address_not_found(self):
        """Missing address returns None."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "not found")):
            result, error = await svc.get_address("bc1qnotfound")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_address_utxos(self):
        """get_address_utxos returns structured UTXO list."""
        from app.services.mempool_fee_service import MempoolFeeService

        mock_utxos = [
            {
                "txid": "a" * 64,
                "vout": 0,
                "value": 100_000,
                "status": {"confirmed": True, "block_height": 800000},
            },
            {
                "txid": "b" * 64,
                "vout": 1,
                "value": 50_000,
                "status": {"confirmed": False},
            },
        ]

        svc = MempoolFeeService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(mock_utxos, None)):
            result, error = await svc.get_address_utxos("bc1qtest")

        assert result is not None
        assert len(result) == 2
        assert result[0]["value_sats"] == 100_000
        assert result[0]["confirmed"] is True
        assert result[1]["confirmed"] is False

    @pytest.mark.asyncio
    async def test_get_address_utxos_empty(self):
        """Address with no UTXOs returns empty list."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=([], None)):
            result, error = await svc.get_address_utxos("bc1qtest")

        assert result == []


class TestMempoolStats:
    """Tests for mempool congestion statistics."""

    @pytest.mark.asyncio
    async def test_get_mempool_stats_success(self):
        """get_mempool_stats returns congestion data."""
        from app.services.mempool_fee_service import MempoolFeeService

        mock_data = {
            "count": 12500,
            "vsize": 45_000_000,
            "total_fee": 1.25,
            "fee_histogram": [[50, 12000], [30, 8000], [10, 5000]],
        }

        svc = MempoolFeeService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(mock_data, None)):
            result, error = await svc.get_mempool_stats()

        assert result is not None
        assert result["tx_count"] == 12500
        assert result["total_vsize"] == 45_000_000
        assert result["total_fee_btc"] == 1.25
        assert len(result["fee_histogram"]) == 3

    @pytest.mark.asyncio
    async def test_mempool_stats_caching(self):
        """Stats should be cached for 30s."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        svc._mempool_stats_cache = {"tx_count": 99, "total_vsize": 100, "total_fee_btc": 0.1, "fee_histogram": []}
        svc._mempool_stats_cache_time = time.time()

        result, error = await svc.get_mempool_stats()
        assert result["tx_count"] == 99

    @pytest.mark.asyncio
    async def test_mempool_stats_unavailable(self):
        """Returns None when Mempool API is unreachable."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "unavailable")):
            result, error = await svc.get_mempool_stats()

        assert result is None


class TestBlockHeight:
    """Tests for block height and block lookup."""

    @pytest.mark.asyncio
    async def test_get_block_tip_height(self):
        """get_block_tip_height returns an integer."""
        from app.services.mempool_fee_service import MempoolFeeService

        mock_response = httpx.Response(
            200,
            text="800123",
            request=httpx.Request("GET", "https://mempool.space/api/blocks/tip/height"),
        )

        svc = MempoolFeeService()
        with patch("app.services.chain.mempool_http.request_capped", new_callable=AsyncMock, return_value=mock_response):
            result, error = await svc.get_block_tip_height()

        assert result == 800123

    @pytest.mark.asyncio
    async def test_get_block_tip_height_failure(self):
        """Returns None when API is down."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        with patch("app.services.chain.mempool_http.request_capped", new_callable=AsyncMock, side_effect=httpx.ConnectError("offline")):
            result, error = await svc.get_block_tip_height()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_block_by_height(self):
        """get_block_by_height returns block header info."""
        from app.services.mempool_fee_service import MempoolFeeService

        mock_hash_response = httpx.Response(
            200,
            text="0000" * 16,
            request=httpx.Request("GET", "https://mempool.space/api/block-height/800000"),
        )

        mock_block = {
            "id": "0000" * 16,
            "height": 800000,
            "timestamp": 1700000000,
            "tx_count": 2500,
            "size": 1_500_000,
            "weight": 3_993_000,
            "difficulty": 57321508229258,
            "previousblockhash": "1111" * 16,
        }

        svc = MempoolFeeService()
        with patch("app.services.chain.mempool_http.request_capped", new_callable=AsyncMock, return_value=mock_hash_response):
            with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(mock_block, None)):
                result, error = await svc.get_block_by_height(800000)

        assert result is not None
        assert result["height"] == 800000
        assert result["tx_count"] == 2500
        assert result["timestamp"] == 1700000000


# ─── TLS Verify Configuration ────────────────────────────────────────


class TestMempoolTLSVerify:
    """TLS verification for Mempool service respects settings.mempool_tls_verify."""

    def test_verify_tls_default_true(self):
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        assert svc._verify_tls() is True

    @patch("app.services.chain.mempool_http.settings")
    def test_verify_tls_respects_setting(self, mock_settings):
        from app.services.mempool_fee_service import MempoolFeeService

        mock_settings.mempool_tls_verify = False
        svc = MempoolFeeService()
        assert svc._verify_tls() is False

    @pytest.mark.asyncio
    @patch("app.services.chain.mempool_http.settings")
    async def test_client_created_with_verify_flag(self, mock_settings):
        from app.services.mempool_fee_service import MempoolFeeService

        mock_settings.mempool_tls_verify = True
        mock_settings.lnd_mempool_url = "https://mempool.space"
        mock_settings.chain_backend_force_tor_enabled.return_value = False

        svc = MempoolFeeService()
        client = await svc._get_client()
        try:
            # httpx stores verify as a ssl.SSLContext or bool
            assert client._transport._pool._ssl_context is not None
        finally:
            await client.aclose()


# ─── Proxy Detection ─────────────────────────────────────────────────


class TestMempoolProxy:
    """Tests for _needs_proxy and _get_proxy (Tor/.onion/.local routing)."""

    @patch("app.services.chain.mempool_http.settings")
    def test_needs_proxy_onion(self, mock_settings):
        from app.services.mempool_fee_service import MempoolFeeService

        mock_settings.lnd_mempool_url = "http://abcdef.onion/api"
        svc = MempoolFeeService()
        assert svc._needs_proxy() is True

    @patch("app.services.chain.mempool_http.settings")
    def test_needs_proxy_local(self, mock_settings):
        from app.services.mempool_fee_service import MempoolFeeService

        mock_settings.lnd_mempool_url = "http://mempool.local/api"
        svc = MempoolFeeService()
        assert svc._needs_proxy() is True

    @patch("app.services.chain.mempool_http.settings")
    def test_needs_proxy_clearnet(self, mock_settings):
        from app.services.mempool_fee_service import MempoolFeeService

        mock_settings.lnd_mempool_url = "https://mempool.space"
        mock_settings.chain_backend_force_tor_enabled.return_value = False
        svc = MempoolFeeService()
        assert svc._needs_proxy() is False

    @patch("app.services.chain.mempool_http.settings")
    def test_get_proxy_with_tor(self, mock_settings):
        from app.services.mempool_fee_service import MempoolFeeService

        mock_settings.lnd_mempool_url = "http://abcdef.onion/api"
        mock_settings.lnd_tor_proxy = "socks5://tor-proxy:9050"
        svc = MempoolFeeService()
        # Normalized to socks5h so the destination resolves at the proxy.
        assert svc._get_proxy() == "socks5h://tor-proxy:9050"

    @patch("app.services.chain.mempool_http.settings")
    def test_get_proxy_onion_no_proxy_configured(self, mock_settings):
        from app.services.mempool_fee_service import MempoolFeeService

        mock_settings.lnd_mempool_url = "http://abcdef.onion/api"
        mock_settings.lnd_tor_proxy = ""
        svc = MempoolFeeService()
        assert svc._get_proxy() is None

    @patch("app.services.chain.mempool_http.settings")
    def test_get_proxy_clearnet(self, mock_settings):
        from app.services.mempool_fee_service import MempoolFeeService

        mock_settings.lnd_mempool_url = "https://mempool.space"
        mock_settings.chain_backend_force_tor_enabled.return_value = False
        svc = MempoolFeeService()
        assert svc._get_proxy() is None


# ─── Fee Edge Cases ──────────────────────────────────────────────────


class TestFeeEdgeCases:
    """Edge cases for fee-related methods."""

    @pytest.mark.asyncio
    async def test_get_fee_for_priority_minimum_floor(self):
        """Fee rate below 1 is bumped to 1."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        mock_fees = {
            "fastestFee": 10,
            "halfHourFee": 5,
            "hourFee": 0,  # below 1
            "economyFee": 1,
            "minimumFee": 1,
        }
        with patch.object(svc, "get_recommended_fees", new_callable=AsyncMock, return_value=(mock_fees, None)):
            result = await svc.get_fee_for_priority("low")
        assert result == 1  # floored from 0

    @pytest.mark.asyncio
    async def test_get_fee_for_priority_returns_none_on_failure(self):
        """Returns None when fee API is unavailable."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        with patch.object(svc, "get_recommended_fees", new_callable=AsyncMock, return_value=(None, "offline")):
            result = await svc.get_fee_for_priority("high")
        assert result is None

    @pytest.mark.asyncio
    async def test_recommended_fees_missing_fields(self):
        """Returns error when response is missing required fields."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        incomplete = {"fastestFee": 10}  # missing other required fields
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(incomplete, None)):
            data, error = await svc.get_recommended_fees()
        assert data is None
        assert "missing required fields" in error

    def test_target_conf_for_priority(self):
        """get_target_conf_for_priority returns correct block targets."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        assert svc.get_target_conf_for_priority("high") == 1
        assert svc.get_target_conf_for_priority("medium") == 6
        assert svc.get_target_conf_for_priority("low") == 144
        assert svc.get_target_conf_for_priority("unknown") == 6  # default

    @pytest.mark.asyncio
    async def test_get_block_by_height_hash_lookup_failure(self):
        """get_block_by_height returns error when hash lookup fails."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        with patch("app.services.chain.mempool_http.request_capped", new_callable=AsyncMock, side_effect=httpx.ConnectError("offline")):
            result, error = await svc.get_block_by_height(800000)
        assert result is None
        assert "Block-height lookup failed" in error

    @pytest.mark.asyncio
    async def test_close_client(self):
        """close() properly closes the HTTP client."""
        from app.services.mempool_fee_service import MempoolFeeService

        svc = MempoolFeeService()
        # Create a client first
        with patch("app.services.chain.mempool_http.settings") as mock_settings:
            mock_settings.lnd_mempool_url = "https://mempool.space"
            mock_settings.mempool_tls_verify = True
            mock_settings.chain_backend_force_tor_enabled.return_value = False
            client = await svc._get_client()
            assert client is not None
            assert svc._client is not None
        await svc.close()
        assert svc._client is None


class TestMempoolUrlSSRFGuard:
    """``LND_MEMPOOL_URL`` must not target internal addresses unless the
    operator opts in via ``MEMPOOL_ALLOW_INTERNAL=true``. The guard runs
    in the FastAPI ``lifespan`` so a misconfigured deployment fails to
    start rather than reflecting requests against the cloud metadata
    service or RFC1918 hosts."""

    @pytest.mark.asyncio
    async def test_rejects_metadata_service_ip(self):
        from app.main import _validate_mempool_url

        with patch("app.main.settings") as mock_settings:
            mock_settings.lnd_mempool_url = "http://169.254.169.254/latest"
            mock_settings.mempool_allow_internal = False
            with pytest.raises(RuntimeError, match="non-routable"):
                _validate_mempool_url()

    @pytest.mark.asyncio
    async def test_rejects_hostname_resolving_to_private_ip(self):
        from app.main import _validate_mempool_url

        with (
            patch("app.main.settings") as mock_settings,
            patch(
                "socket.getaddrinfo",
                return_value=[(None, None, None, "", ("10.0.0.5", 0))],
            ),
        ):
            mock_settings.lnd_mempool_url = "https://internal.example.test"
            mock_settings.mempool_allow_internal = False
            with pytest.raises(RuntimeError, match="non-routable"):
                _validate_mempool_url()

    @pytest.mark.asyncio
    async def test_allows_when_opt_in_set(self):
        from app.main import _validate_mempool_url

        with patch("app.main.settings") as mock_settings:
            mock_settings.lnd_mempool_url = "http://10.0.0.5/api"
            mock_settings.mempool_allow_internal = True
            _validate_mempool_url()  # Must not raise

    @pytest.mark.asyncio
    async def test_allows_onion_hostname(self):
        from app.main import _validate_mempool_url

        with patch("app.main.settings") as mock_settings:
            mock_settings.lnd_mempool_url = "http://abcd.onion/api"
            mock_settings.mempool_allow_internal = False
            _validate_mempool_url()  # Onion routes via Tor proxy — allowed

    @pytest.mark.asyncio
    async def test_allows_public_hostname(self):
        from app.main import _validate_mempool_url

        with (
            patch("app.main.settings") as mock_settings,
            patch(
                "socket.getaddrinfo",
                return_value=[(None, None, None, "", ("8.8.8.8", 0))],
            ),
        ):
            mock_settings.lnd_mempool_url = "https://mempool.space"
            mock_settings.mempool_allow_internal = False
            _validate_mempool_url()  # Must not raise


class TestMempoolPathComponentQuoting:
    """Attacker-influenced path components are percent-encoded so they
    cannot traverse to a different endpoint on the configured host."""

    @pytest.mark.asyncio
    async def test_address_path_component_is_quoted(self):
        from app.services.chain.mempool_http import MempoolHttpBackend

        backend = MempoolHttpBackend()
        captured = {}

        async def _capture(path):
            captured["path"] = path
            return ({}, None)

        with patch.object(backend, "_request", new=_capture):
            await backend.get_address("../blocks/tip/height")

        assert "../" not in captured["path"]
        assert "%2F" in captured["path"] or "%2E%2E" in captured["path"]

    @pytest.mark.asyncio
    async def test_txid_path_component_is_quoted(self):
        from app.services.chain.mempool_http import MempoolHttpBackend

        backend = MempoolHttpBackend()
        captured = {}

        async def _capture(path):
            captured["path"] = path
            return ({}, None)

        with patch.object(backend, "_request", new=_capture):
            await backend.get_transaction("aa/../../evil")

        assert "/../" not in captured["path"]
        assert captured["path"].startswith("/api/tx/")

    @pytest.mark.asyncio
    async def test_address_utxo_path_component_is_quoted(self):
        from app.services.chain.mempool_http import MempoolHttpBackend

        backend = MempoolHttpBackend()
        captured = {}

        async def _capture(path):
            captured["path"] = path
            return ({}, None)

        with patch.object(backend, "_request", new=_capture):
            await backend.get_address_utxos("../../evil")

        assert "/../" not in captured["path"]
        assert captured["path"].startswith("/api/address/")
        assert captured["path"].endswith("/utxo")
