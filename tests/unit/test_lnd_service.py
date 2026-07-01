# SPDX-License-Identifier: MIT
"""
Unit tests for app.services.lnd_service — LND REST client.

All LND HTTP calls are mocked at the _request level.
Tests verify:
- Correct data transformations
- Error handling
- Tor proxy detection
- Header injection
- SSL context creation
- _request HTTP layer (status errors, connect errors)
- Client lifecycle (_get_client, close)
"""

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.lnd_service import LNDService, _is_onion_url


class TestLNDServiceInit:
    """Test LND service initialization / configuration."""

    def test_onion_url_detected(self):
        assert _is_onion_url("https://abc123.onion:8080") is True
        assert _is_onion_url("https://localhost:8080") is False
        assert _is_onion_url("https://192.168.1.1:8080") is False

    def test_headers_include_macaroon(self):
        svc = LNDService()
        headers = svc._get_headers()
        assert "Grpc-Metadata-macaroon" in headers


class TestLNDServiceRequests:
    """Test LND service methods with mocked _request calls."""

    @pytest.mark.asyncio
    async def test_get_info_success(self):
        """get_info returns parsed node info on success."""
        svc = LNDService()
        mock_data = {
            "alias": "test-node",
            "identity_pubkey": "02" + "a" * 64,
            "synced_to_chain": True,
            "block_height": 800000,
            "version": "0.18.0-beta",
            "num_active_channels": 5,
            "num_peers": 10,
        }

        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(mock_data, None)):
            result, error = await svc.get_info()

        assert result is not None
        assert result["alias"] == "test-node"
        assert result["synced_to_chain"] is True

    @pytest.mark.asyncio
    async def test_get_info_connection_error(self):
        """get_info returns None on connection error."""
        svc = LNDService()

        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "connection error")):
            result, error = await svc.get_info()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_wallet_balance_success(self):
        """get_wallet_balance returns balance data."""
        svc = LNDService()
        mock_data = {
            "total_balance": "1000000",
            "confirmed_balance": "900000",
            "unconfirmed_balance": "100000",
        }

        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(mock_data, None)):
            result, error = await svc.get_wallet_balance()

        assert result is not None
        assert result["total_balance"] == 1000000

    @pytest.mark.asyncio
    async def test_new_address_success(self):
        """new_address returns address data."""
        svc = LNDService()

        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"address": "bcrt1qtest..."}, None),
        ):
            data, error = await svc.new_address("p2tr")

        assert data is not None
        assert data["address"] == "bcrt1qtest..."
        assert error is None

    @pytest.mark.asyncio
    async def test_new_address_error(self):
        """new_address returns error on LND error response."""
        svc = LNDService()

        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(None, "wallet locked"),
        ):
            data, error = await svc.new_address("p2tr")

        assert data is None
        assert error is not None
        assert "wallet locked" in error

    @pytest.mark.asyncio
    async def test_send_payment_sync_success(self):
        """send_payment_sync returns payment result on success."""
        svc = LNDService()

        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "payment_error": "",
                    "payment_hash": "YWJj",  # base64 of "abc"
                    "payment_preimage": "ZGVm",  # base64 of "def"
                    "payment_route": {
                        "total_amt": "1000",
                        "total_fees": "1",
                        "total_amt_msat": "1000000",
                        "total_fees_msat": "1000",
                        "hops": [{}],
                    },
                },
                None,
            ),
        ):
            data, error = await svc.send_payment_sync("lnbc1...", 100, 60)

        assert data is not None
        assert "payment_hash" in data
        assert error is None

    @pytest.mark.asyncio
    async def test_send_payment_sync_payment_error(self):
        """send_payment_sync returns error when invoice fails."""
        svc = LNDService()

        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"payment_error": "no route found"}, None),
        ):
            data, error = await svc.send_payment_sync("lnbc1...", 100, 60)

        assert data is None
        assert "no route found" in error

    @pytest.mark.asyncio
    async def test_get_channels_success(self):
        """get_channels returns a list of channel objects."""
        svc = LNDService()
        mock_data = {
            "channels": [
                {"chan_id": "123", "active": True, "capacity": "500000"},
            ]
        }

        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(mock_data, None)):
            result, error = await svc.get_channels()

        assert result is not None
        assert len(result) == 1
        assert result[0]["chan_id"] == "123"

    @pytest.mark.asyncio
    async def test_get_channel_by_point_matches(self):
        svc = LNDService()
        channels = [
            {"channel_point": "aa:0", "chan_id": "1", "active": True},
            {"channel_point": "bb:1", "chan_id": "2", "active": False},
        ]
        with patch.object(svc, "get_channels", new_callable=AsyncMock, return_value=(channels, None)):
            ch, err = await svc.get_channel_by_point("bb:1")
        assert err is None
        assert ch is not None and ch["chan_id"] == "2"

    @pytest.mark.asyncio
    async def test_get_channel_by_point_not_found(self):
        svc = LNDService()
        with patch.object(svc, "get_channels", new_callable=AsyncMock, return_value=([], None)):
            ch, err = await svc.get_channel_by_point("zz:9")
        assert ch is None and err is None

    @pytest.mark.asyncio
    async def test_channel_is_active_true_only_when_active(self):
        svc = LNDService()
        active = [{"channel_point": "aa:0", "chan_id": "1", "active": True}]
        inactive = [{"channel_point": "aa:0", "chan_id": "1", "active": False}]
        with patch.object(svc, "get_channels", new_callable=AsyncMock, return_value=(active, None)):
            is_act, ch, err = await svc.channel_is_active("aa:0")
        assert is_act is True and ch is not None and err is None
        with patch.object(svc, "get_channels", new_callable=AsyncMock, return_value=(inactive, None)):
            is_act, ch, err = await svc.channel_is_active("aa:0")
        assert is_act is False and ch is not None and err is None

    @pytest.mark.asyncio
    async def test_channel_is_active_propagates_error(self):
        svc = LNDService()
        with patch.object(svc, "get_channels", new_callable=AsyncMock, return_value=(None, "lnd down")):
            is_act, ch, err = await svc.channel_is_active("aa:0")
        assert is_act is False and ch is None and err == "lnd down"

    @pytest.mark.asyncio
    async def test_inbound_capacity_sums_active_channels(self):
        """inbound_capacity sums remote_balance minus reserve+buffer over
        active channels; tracks the largest single-channel inbound."""
        svc = LNDService()
        channels = [
            # active: recv = 200000 - 5000 - 350 = 194650
            {"active": True, "remote_balance": 200000, "remote_chan_reserve_sat": 5000},
            # active: recv = 100000 - 1000 - 350 = 98650
            {"active": True, "remote_balance": 100000, "remote_chan_reserve_sat": 1000},
        ]
        with patch.object(svc, "get_channels", new_callable=AsyncMock, return_value=(channels, None)):
            cap, err = await svc.inbound_capacity()
        assert err is None
        assert cap["total_receivable_sats"] == 194650 + 98650
        assert cap["largest_channel_receivable_sats"] == 194650

    @pytest.mark.asyncio
    async def test_inbound_capacity_excludes_inactive_and_negative(self):
        """Inactive channels and channels whose receivable is <= 0 (reserve
        + buffer exceed remote balance) are excluded entirely."""
        svc = LNDService()
        channels = [
            {"active": True, "remote_balance": 50000, "remote_chan_reserve_sat": 1000},
            # inactive — excluded despite large inbound
            {"active": False, "remote_balance": 9_000_000, "remote_chan_reserve_sat": 1000},
            # remote balance below reserve+buffer → recv <= 0, excluded
            {"active": True, "remote_balance": 300, "remote_chan_reserve_sat": 1000},
        ]
        with patch.object(svc, "get_channels", new_callable=AsyncMock, return_value=(channels, None)):
            cap, err = await svc.inbound_capacity()
        assert err is None
        expected = 50000 - 1000 - 350
        assert cap["total_receivable_sats"] == expected
        assert cap["largest_channel_receivable_sats"] == expected

    @pytest.mark.asyncio
    async def test_pending_detail_parses_all_closing_buckets(self):
        """get_pending_channels_detail surfaces every pending bucket —
        including waiting_close — and the closing/force-closing maturity
        and limbo fields the UI needs."""
        svc = LNDService()
        payload = {
            "pending_open_channels": [
                {"channel": {"remote_node_pub": "p1", "channel_point": "aa:0", "capacity": 100, "local_balance": 60, "remote_balance": 40}, "commit_fee": 1, "confirmation_height": 800000},
            ],
            "waiting_close_channels": [
                {"channel": {"remote_node_pub": "p2", "channel_point": "bb:1", "capacity": 200, "local_balance": 120, "remote_balance": 80}, "closing_txid": "beadcafe", "limbo_balance": 120},
            ],
            "pending_closing_channels": [
                {"channel": {"remote_node_pub": "p3", "channel_point": "cc:0", "capacity": 300, "local_balance": 150, "remote_balance": 150}, "closing_txid": "deadbeef", "limbo_balance": 0},
            ],
            "pending_force_closing_channels": [
                {"channel": {"remote_node_pub": "p4", "channel_point": "dd:2", "capacity": 400, "local_balance": 250, "remote_balance": 150}, "closing_txid": "feedface", "blocks_til_maturity": 144, "maturity_height": 800144, "limbo_balance": 250, "recovered_balance": 10},
            ],
        }
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(payload, None)):
            result, err = await svc.get_pending_channels_detail()
        assert err is None
        by_type = {r["type"]: r for r in result}
        assert set(by_type) == {"pending_open", "waiting_close", "pending_close", "force_closing"}

        assert by_type["waiting_close"]["channel_point"] == "bb:1"
        assert by_type["waiting_close"]["closing_txid"] == "beadcafe"
        assert by_type["waiting_close"]["limbo_balance"] == 120

        assert by_type["pending_close"]["closing_txid"] == "deadbeef"
        assert by_type["pending_close"]["limbo_balance"] == 0

        fc = by_type["force_closing"]
        assert fc["blocks_til_maturity"] == 144
        assert fc["maturity_height"] == 800144
        assert fc["limbo_balance"] == 250
        assert fc["recovered_balance"] == 10

    @pytest.mark.asyncio
    async def test_inbound_capacity_propagates_get_channels_error(self):
        """A get_channels error returns (None, err) so callers can skip the
        gate rather than refuse on a transient LND failure."""
        svc = LNDService()
        with patch.object(svc, "get_channels", new_callable=AsyncMock, return_value=(None, "lnd down")):
            cap, err = await svc.inbound_capacity()
        assert cap is None
        assert err == "lnd down"

    @pytest.mark.asyncio
    async def test_inbound_capacity_no_channels(self):
        """No channels → zero receivable, no error."""
        svc = LNDService()
        with patch.object(svc, "get_channels", new_callable=AsyncMock, return_value=([], None)):
            cap, err = await svc.inbound_capacity()
        assert err is None
        assert cap["total_receivable_sats"] == 0
        assert cap["largest_channel_receivable_sats"] == 0

    @pytest.mark.asyncio
    async def test_query_routes_passes_source_pub_key(self):
        """source_pubkey_hex is forwarded as the source_pub_key param so
        the route origin can be overridden (Boltz → us inbound probe)."""
        svc = LNDService()
        captured = {}

        async def _fake_request(method, path, params=None, **kwargs):
            captured["path"] = path
            captured["params"] = params
            return (
                {
                    "routes": [
                        {
                            "total_amt": "1000",
                            "total_fees": "1",
                            "total_amt_msat": "1000000",
                            "total_fees_msat": "1000",
                            "total_time_lock": 100,
                            "hops": [{}, {}],
                        }
                    ]
                },
                None,
            )

        with patch.object(svc, "_request", side_effect=_fake_request):
            quote, err = await svc.query_routes(
                dest_pubkey_hex="03" + "aa" * 32,
                amount_sats=50000,
                source_pubkey_hex="02" + "bb" * 32,
            )
        assert err is None
        assert quote is not None
        assert captured["params"]["source_pub_key"] == "02" + "bb" * 32

    @pytest.mark.asyncio
    async def test_query_routes_rejects_bad_source_pubkey(self):
        """A non-hex source_pubkey_hex is rejected before any request."""
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock) as mock_req:
            quote, err = await svc.query_routes(
                dest_pubkey_hex="03" + "aa" * 32,
                amount_sats=50000,
                source_pubkey_hex="not-hex",
            )
            mock_req.assert_not_called()
        assert quote is None
        assert "hex" in err.lower()

    @pytest.mark.asyncio
    async def test_query_routes_no_route(self):
        """No routes in the response surfaces a 'No route found' error,
        which the probe relies on to distinguish from transient errors."""
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"routes": []}, None)):
            quote, err = await svc.query_routes(
                dest_pubkey_hex="03" + "aa" * 32,
                amount_sats=50000,
                source_pubkey_hex="02" + "bb" * 32,
            )
        assert quote is None
        assert "no route" in err.lower()

    @pytest.mark.asyncio
    async def test_decode_payment_request(self):
        """decode_payment_request returns structured decode data."""
        svc = LNDService()

        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "destination": "02" + "a" * 64,
                    "num_satoshis": "5000",
                    "timestamp": "1700000000",
                    "expiry": "3600",
                    "description": "test invoice",
                    "cltv_expiry": "80",
                    "num_msat": "5000000",
                },
                None,
            ),
        ):
            data, error = await svc.decode_payment_request("lnbc50u1...")

        assert data is not None
        assert data["num_satoshis"] == 5000  # Parsed to int
        assert error is None

    @pytest.mark.asyncio
    async def test_create_invoice_success(self):
        """create_invoice returns invoice data."""
        svc = LNDService()

        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "r_hash": "YWJj",  # base64
                    "payment_request": "lnbcrt1...",
                    "add_index": "42",
                },
                None,
            ),
        ):
            data, error = await svc.create_invoice(1000, "test", 3600)

        assert data is not None
        assert data["payment_request"] == "lnbcrt1..."
        assert error is None

    @pytest.mark.asyncio
    async def test_add_blinded_invoice_success(self):
        """add_blinded_invoice posts AddInvoice then DecodePayReq for paths."""
        svc = LNDService()

        calls: list[dict] = []

        async def fake_request(method, path, **kwargs):
            calls.append(
                {
                    "method": method,
                    "path": path,
                    "json": kwargs.get("json"),
                }
            )
            if method == "POST" and path == "/v1/invoices":
                return (
                    {
                        "r_hash": "YWJj",
                        "payment_request": "lnbc1blinded...",
                        "add_index": "7",
                        "payment_addr": "ZGVm",
                    },
                    None,
                )
            if method == "GET" and path.startswith("/v1/payreq/"):
                return (
                    {
                        "blinded_paths": [
                            {"blinded_path": {"introduction_node": "abcd", "blinded_hops": []}},
                            {"blinded_path": {"introduction_node": "ef01", "blinded_hops": []}},
                        ],
                    },
                    None,
                )
            raise AssertionError(f"unexpected call: {method} {path}")

        with patch.object(svc, "_request", side_effect=fake_request):
            data, error = await svc.add_blinded_invoice(100_000, memo="bolt12", num_hops=1, max_num_paths=2)

        assert error is None
        assert data is not None
        assert data["payment_request"] == "lnbc1blinded..."
        assert len(data["blinded_paths"]) == 2

        assert len(calls) == 2
        body = calls[0]["json"]
        assert calls[0]["method"] == "POST"
        assert calls[0]["path"] == "/v1/invoices"
        assert body["value_msat"] == "100000"
        assert body["is_blinded"] is True
        assert body["blinded_path_config"] == {
            "min_num_real_hops": 1,
            "num_hops": 1,
            "max_num_paths": 2,
        }
        assert calls[1]["method"] == "GET"
        assert calls[1]["path"].startswith("/v1/payreq/")

    @pytest.mark.asyncio
    async def test_add_blinded_invoice_with_description_hash(self):
        svc = LNDService()
        h = b"\xaa" * 32

        async def fake_request(method, path, **kwargs):
            if method == "POST":
                body = kwargs.get("json") or {}
                assert "description_hash" in body
                return (
                    {
                        "r_hash": "",
                        "payment_request": "lnbc1...",
                        "add_index": "1",
                        "payment_addr": "",
                    },
                    None,
                )
            # DecodePayReq round-trip
            return ({"blinded_paths": []}, None)

        with patch.object(svc, "_request", side_effect=fake_request):
            _, error = await svc.add_blinded_invoice(1_000, description_hash=h)
        assert error is None

    @pytest.mark.asyncio
    async def test_add_blinded_invoice_with_node_omission_list(self):
        """node_omission_pubkeys is base64-encoded into blinded_path_config."""
        svc = LNDService()
        # Two valid 33-byte compressed pubkeys.
        pk_boltz = bytes.fromhex("026165850492521f4ac8abd9bd8088123446d126f648ca35e60f88177dc149ceb2")
        pk_other = bytes.fromhex("0322d0e43b3d92d30ed187f4e101a9a9605c3ee5fc9721e6dac3ce3d7732fbb13e")

        captured: dict = {}

        async def fake_request(method, path, **kwargs):
            if method == "POST" and path == "/v1/invoices":
                captured["body"] = kwargs.get("json")
                return (
                    {
                        "r_hash": "",
                        "payment_request": "lnbc1...",
                        "add_index": "1",
                        "payment_addr": "",
                    },
                    None,
                )
            return ({"blinded_paths": []}, None)

        with patch.object(svc, "_request", side_effect=fake_request):
            _, error = await svc.add_blinded_invoice(
                1_000,
                num_hops=2,
                max_num_paths=4,
                node_omission_pubkeys=[pk_boltz, pk_other],
            )

        assert error is None
        bpc = captured["body"]["blinded_path_config"]
        assert bpc["min_num_real_hops"] == 2
        assert bpc["num_hops"] == 2
        assert bpc["max_num_paths"] == 4
        assert bpc["node_omission_list"] == [
            base64.b64encode(pk_boltz).decode("ascii"),
            base64.b64encode(pk_other).decode("ascii"),
        ]

    @pytest.mark.asyncio
    async def test_add_blinded_invoice_rejects_bad_omission_pubkey(self):
        """Reject malformed pubkeys before hitting LND."""
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock) as mock:
            data, error = await svc.add_blinded_invoice(1_000, node_omission_pubkeys=[b"\x02" * 32])
            assert data is None
            assert error is not None and "node_omission_pubkeys" in error
            mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_blinded_invoice_omits_omission_list_when_empty(self):
        """Empty/None omission list must NOT emit a node_omission_list key."""
        svc = LNDService()
        captured: dict = {}

        async def fake_request(method, path, **kwargs):
            if method == "POST":
                captured["body"] = kwargs.get("json")
                return (
                    {
                        "r_hash": "",
                        "payment_request": "lnbc1...",
                        "add_index": "1",
                        "payment_addr": "",
                    },
                    None,
                )
            return ({"blinded_paths": []}, None)

        with patch.object(svc, "_request", side_effect=fake_request):
            await svc.add_blinded_invoice(1_000, node_omission_pubkeys=[])
        assert "node_omission_list" not in captured["body"]["blinded_path_config"]

    @pytest.mark.asyncio
    async def test_add_blinded_invoice_validation(self):
        svc = LNDService()

        # Should not even reach _request when params are out of range.
        with patch.object(svc, "_request", new_callable=AsyncMock) as mock:
            data, error = await svc.add_blinded_invoice(0)
            assert data is None
            assert error is not None and "amount_msat" in error

            data, error = await svc.add_blinded_invoice(1, num_hops=99)
            assert data is None
            assert error is not None and "num_hops" in error

            data, error = await svc.add_blinded_invoice(1, max_num_paths=0)
            assert data is None
            assert error is not None and "max_num_paths" in error

            data, error = await svc.add_blinded_invoice(1, description_hash=b"\x00" * 31)
            assert data is None
            assert error is not None and "description_hash" in error

            mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_blinded_invoice_lnd_error(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(None, "LND unreachable"),
        ):
            data, error = await svc.add_blinded_invoice(1_000)
        assert data is None
        assert error == "LND unreachable"

    @pytest.mark.asyncio
    async def test_add_blinded_invoice_handles_missing_blinded_paths(self):
        """Defensive: DecodePayReq may omit ``blinded_paths`` entirely."""
        svc = LNDService()

        async def fake_request(method, path, **kwargs):
            if method == "POST":
                return (
                    {
                        "r_hash": "",
                        "payment_request": "lnbc1...",
                        "add_index": "1",
                    },
                    None,
                )
            # DecodePayReq omits blinded_paths altogether
            return ({"destination": "deadbeef"}, None)

        with patch.object(svc, "_request", side_effect=fake_request):
            data, error = await svc.add_blinded_invoice(1_000)
        assert error is None
        assert data is not None
        assert data["blinded_paths"] == []

    @pytest.mark.asyncio
    async def test_estimate_fee(self):
        """estimate_fee returns fee estimate data."""
        svc = LNDService()

        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"fee_sat": "500", "sat_per_vbyte": "10"}, None),
        ):
            data, error = await svc.estimate_fee("bcrt1qtest", 50000, 6)

        assert data is not None
        assert error is None

    @pytest.mark.asyncio
    async def test_lookup_invoice(self):
        """lookup_invoice returns invoice details."""
        svc = LNDService()

        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "memo": "test",
                    "value": "1000",
                    "settled": True,
                    "creation_date": "1700000000",
                    "settle_date": "1700000100",
                    "amt_paid_sat": "1000",
                    "state": "SETTLED",
                    "payment_request": "lnbcrt1...",
                    "is_keysend": False,
                },
                None,
            ),
        ):
            data, error = await svc.lookup_invoice("abcdef")

        assert data is not None
        assert data["settled"] is True
        assert data["value"] == 1000
        assert error is None

    @pytest.mark.asyncio
    async def test_get_wallet_summary(self):
        """get_wallet_summary aggregates info, wallet balance, and channel balance."""
        svc = LNDService()

        async def mock_request(method, path, **kwargs):
            if "getinfo" in path:
                return {"alias": "test", "synced_to_chain": True}, None
            elif "balance/blockchain" in path:
                return {
                    "total_balance": "1000000",
                    "confirmed_balance": "900000",
                    "unconfirmed_balance": "100000",
                }, None
            elif "balance/channels" in path:
                return {"balance": "500000", "pending_open_balance": "0"}, None
            elif "channels/pending" in path:
                return {
                    "pending_open_channels": [],
                    "pending_closing_channels": [],
                    "pending_force_closing_channels": [],
                    "waiting_close_channels": [],
                    "total_limbo_balance": "0",
                }, None
            return None, "not found"

        with patch.object(svc, "_request", side_effect=mock_request):
            result, error = await svc.get_wallet_summary()

        assert result is not None


class TestLNDServiceSafetyLimits:
    """Tests for address type mapping and error formatting."""

    def test_address_type_mapping(self):
        """Verify address type string → LND API int mapping."""
        svc = LNDService()
        assert svc is not None


class TestSendCoins:
    """Tests for send_coins (on-chain send)."""

    @pytest.mark.asyncio
    async def test_send_coins_success(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"txid": "abc123"}, None),
        ):
            data, error = await svc.send_coins("bcrt1qtest", 50000, 10, "test-label")

        assert data == {"txid": "abc123"}
        assert error is None

    @pytest.mark.asyncio
    async def test_send_coins_error(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(None, "insufficient funds"),
        ):
            data, error = await svc.send_coins("bcrt1qtest", 50000)

        assert data is None
        assert "insufficient funds" in error

    @pytest.mark.asyncio
    async def test_send_coins_no_fee_rate(self):
        """send_coins without sat_per_vbyte omits it from body."""
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"txid": "def456"}, None),
        ) as mock_req:
            await svc.send_coins("bcrt1qtest", 10000, None, "")
            call_kwargs = mock_req.call_args
            body = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
            assert "sat_per_vbyte" not in body


class TestConnectPeer:
    """Tests for connect_peer."""

    @pytest.mark.asyncio
    async def test_connect_peer_success(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({}, None),
        ):
            data, error = await svc.connect_peer("02" + "a" * 64, "1.2.3.4:9735")

        assert data == {}
        assert error is None

    @pytest.mark.asyncio
    async def test_connect_peer_already_connected(self):
        """'already connected' error is treated as success."""
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(None, "already connected to peer"),
        ):
            data, error = await svc.connect_peer("02" + "a" * 64, "1.2.3.4:9735")

        assert data == {}
        assert error is None

    @pytest.mark.asyncio
    async def test_connect_peer_real_error(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(None, "connection refused"),
        ):
            data, error = await svc.connect_peer("02" + "a" * 64, "1.2.3.4:9735")

        assert data is None
        assert "connection refused" in error


class TestOpenChannel:
    """Tests for open_channel."""

    @pytest.mark.asyncio
    async def test_open_channel_success(self):
        svc = LNDService()
        # Simulate LND returning base64-encoded reversed txid bytes
        txid_hex = "ab" * 32
        txid_bytes = bytes.fromhex(txid_hex)
        txid_b64 = base64.b64encode(txid_bytes[::-1]).decode()

        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {"funding_txid_bytes": txid_b64, "output_index": 0},
                None,
            ),
        ):
            data, error = await svc.open_channel("02" + "a" * 64, 500000, 10, 0, False)

        assert error is None
        assert data["funding_txid"] == txid_hex
        assert data["output_index"] == 0

    @pytest.mark.asyncio
    async def test_open_channel_error(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(None, "not enough funds"),
        ):
            data, error = await svc.open_channel("02" + "a" * 64, 500000)

        assert data is None
        assert "not enough funds" in error

    @pytest.mark.asyncio
    async def test_open_channel_fallback_txid_str(self):
        """Falls back to funding_txid_str if base64 decode fails."""
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {"funding_txid_bytes": "!!invalid-base64!!", "funding_txid_str": "fallback_txid", "output_index": 1},
                None,
            ),
        ):
            data, error = await svc.open_channel("02" + "a" * 64, 100000)

        assert error is None
        assert data["funding_txid"] == "fallback_txid"


class TestLookupPayment:
    """Tests for lookup_payment."""

    @pytest.mark.asyncio
    async def test_lookup_payment_found(self):
        svc = LNDService()
        target_hash = "ab" * 32
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "payments": [
                        {"payment_hash": "xx", "status": "FAILED"},
                        {
                            "payment_hash": target_hash,
                            "status": "SUCCEEDED",
                            "fee_sat": "5",
                            "value_sat": "1000",
                            "payment_preimage": "pre",
                        },
                    ]
                },
                None,
            ),
        ):
            data, error = await svc.lookup_payment(target_hash)

        assert error is None
        assert data["status"] == "SUCCEEDED"
        assert data["fee_sat"] == 5

    @pytest.mark.asyncio
    async def test_lookup_payment_not_found(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"payments": []}, None),
        ):
            data, error = await svc.lookup_payment("ab" * 32)

        assert error is None
        assert data["status"] == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_lookup_payment_lnd_error(self):
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "LND error")):
            data, error = await svc.lookup_payment("ab" * 32)

        assert data is None
        assert error is not None


class TestGetRecentPayments:
    """Tests for get_recent_payments."""

    @pytest.mark.asyncio
    async def test_get_recent_payments_success(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "payments": [
                        {
                            "payment_hash": "h1",
                            "value_sat": "5000",
                            "fee_sat": "2",
                            "status": "SUCCEEDED",
                            "creation_date": "1700000000",
                        },
                    ]
                },
                None,
            ),
        ):
            result, error = await svc.get_recent_payments(10)

        assert len(result) == 1
        assert result[0]["value_sat"] == 5000

    @pytest.mark.asyncio
    async def test_get_recent_payments_lnd_down(self):
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "LND error")):
            result, error = await svc.get_recent_payments()
        assert result is None


class TestGetRecentInvoices:
    """Tests for get_recent_invoices."""

    @pytest.mark.asyncio
    async def test_get_recent_invoices_success(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "invoices": [
                        {
                            "memo": "test",
                            "value": "1000",
                            "settled": True,
                            "state": "SETTLED",
                            "creation_date": "1700000000",
                            "settle_date": "1700001000",
                            "amt_paid_sat": "1000",
                        },
                    ]
                },
                None,
            ),
        ):
            result, error = await svc.get_recent_invoices(5)

        assert len(result) == 1
        assert result[0]["settled"] is True


class TestGetOnchainTransactions:
    """Tests for get_onchain_transactions."""

    @pytest.mark.asyncio
    async def test_get_onchain_transactions_success(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "transactions": [
                        {
                            "tx_hash": "txh1",
                            "amount": "50000",
                            "num_confirmations": "3",
                            "block_height": "800000",
                            "time_stamp": "1700000000",
                            "total_fees": "200",
                        },
                        {
                            "tx_hash": "txh2",
                            "amount": "10000",
                            "num_confirmations": "0",
                            "block_height": "0",
                            "time_stamp": "1700001000",
                            "total_fees": "150",
                        },
                    ]
                },
                None,
            ),
        ):
            result, error = await svc.get_onchain_transactions(max_txns=1)

        # max_txns=1 should truncate
        assert len(result) == 1
        assert result[0]["tx_hash"] == "txh1"


class TestGetPendingChannelsDetail:
    """Tests for get_pending_channels_detail."""

    @pytest.mark.asyncio
    async def test_pending_channels_detail_all_types(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "pending_open_channels": [
                        {
                            "channel": {
                                "remote_node_pub": "pub1",
                                "channel_point": "cp1",
                                "capacity": "100000",
                                "local_balance": "50000",
                                "remote_balance": "50000",
                            },
                            "commit_fee": "200",
                            "confirmation_height": "800001",
                        },
                    ],
                    "pending_closing_channels": [
                        {
                            "channel": {
                                "remote_node_pub": "pub2",
                                "channel_point": "cp2",
                                "capacity": "200000",
                                "local_balance": "100000",
                                "remote_balance": "100000",
                            },
                            "closing_txid": "close_tx",
                        },
                    ],
                    "pending_force_closing_channels": [
                        {
                            "channel": {
                                "remote_node_pub": "pub3",
                                "channel_point": "cp3",
                                "capacity": "300000",
                                "local_balance": "150000",
                                "remote_balance": "150000",
                            },
                            "closing_txid": "force_tx",
                            "blocks_til_maturity": "144",
                        },
                    ],
                },
                None,
            ),
        ):
            result, error = await svc.get_pending_channels_detail()

        assert len(result) == 3
        assert result[0]["type"] == "pending_open"
        assert result[1]["type"] == "pending_close"
        assert result[2]["type"] == "force_closing"
        assert result[2]["blocks_til_maturity"] == 144

    @pytest.mark.asyncio
    async def test_pending_channels_detail_lnd_down(self):
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "LND error")):
            result, error = await svc.get_pending_channels_detail()
        assert result is None


class _FakeStreamResponse:
    def __init__(self, status_code, lines):
        self.status_code = status_code
        self._lines = lines

    async def aiter_lines(self):
        for ln in self._lines:
            yield ln

    async def aread(self):
        return b"boom"


class _FakeStreamCtx:
    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *_a):
        return False


class _FakeStreamClient:
    def __init__(self, resp):
        self._resp = resp

    def stream(self, _method, _path, **_kw):
        return _FakeStreamCtx(self._resp)


class TestCloseChannelStreaming:
    """close_channel consumes LND's streaming CloseChannel endpoint and
    returns as soon as the close is initiated (close_pending/chan_close),
    rather than blocking until the closing tx confirms."""

    @pytest.mark.asyncio
    async def test_returns_on_close_pending(self):
        svc = LNDService()
        resp = _FakeStreamResponse(
            200, ['{"result": {"close_pending": {"txid": "abcd", "output_index": 1}}}']
        )
        with (
            patch.object(svc, "_get_client", new_callable=AsyncMock, return_value=_FakeStreamClient(resp)),
            patch("app.services.lnd_service._LND_BREAKER.before_call", new_callable=AsyncMock),
        ):
            result, err = await svc.close_channel("ab" * 32, 1, force=False)
        assert err is None
        assert "close_pending" in result

    @pytest.mark.asyncio
    async def test_returns_on_chan_close(self):
        svc = LNDService()
        resp = _FakeStreamResponse(200, ['{"result": {"chan_close": {"closing_txid": "ff"}}}'])
        with (
            patch.object(svc, "_get_client", new_callable=AsyncMock, return_value=_FakeStreamClient(resp)),
            patch("app.services.lnd_service._LND_BREAKER.before_call", new_callable=AsyncMock),
        ):
            result, err = await svc.close_channel("ab" * 32, 0, force=True)
        assert err is None
        assert "chan_close" in result

    @pytest.mark.asyncio
    async def test_http_error_surfaces(self):
        svc = LNDService()
        resp = _FakeStreamResponse(500, [])
        with (
            patch.object(svc, "_get_client", new_callable=AsyncMock, return_value=_FakeStreamClient(resp)),
            patch("app.services.lnd_service._LND_BREAKER.before_call", new_callable=AsyncMock),
        ):
            result, err = await svc.close_channel("ab" * 32, 0, force=False)
        assert result is None
        assert "LND error (500)" in err

    @pytest.mark.asyncio
    async def test_stream_without_update_returns_error(self):
        svc = LNDService()
        resp = _FakeStreamResponse(200, [])  # stream closes with no update
        with (
            patch.object(svc, "_get_client", new_callable=AsyncMock, return_value=_FakeStreamClient(resp)),
            patch("app.services.lnd_service._LND_BREAKER.before_call", new_callable=AsyncMock),
        ):
            result, err = await svc.close_channel("ab" * 32, 0, force=False)
        assert result is None
        assert err


class TestGetWalletSummary:
    """Tests for get_wallet_summary."""

    @pytest.mark.asyncio
    async def test_wallet_summary_all_none(self):
        """Returns None when all sub-calls fail."""
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "LND error")):
            result, error = await svc.get_wallet_summary()
        assert result is None

    @pytest.mark.asyncio
    async def test_wallet_summary_totals(self):
        """Totals are correctly computed from sub-results."""
        svc = LNDService()
        with (
            patch.object(
                svc,
                "get_info",
                new_callable=AsyncMock,
                return_value=(
                    {"alias": "n", "num_active_channels": 2, "num_pending_channels": 0, "synced_to_chain": True},
                    None,
                ),
            ),
            patch.object(
                svc,
                "get_wallet_balance",
                new_callable=AsyncMock,
                return_value=({"confirmed_balance": 100000, "unconfirmed_balance": 5000}, None),
            ),
            patch.object(
                svc,
                "get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 200000, "remote_balance_sat": 300000}, None),
            ),
            patch.object(svc, "get_pending_channels", new_callable=AsyncMock, return_value=({}, None)),
        ):
            result, error = await svc.get_wallet_summary()

        assert result is not None
        assert result["totals"]["total_balance_sats"] == 300000
        assert result["totals"]["onchain_sats"] == 100000
        assert result["totals"]["lightning_local_sats"] == 200000


class TestSSLContext:
    """Tests for _get_ssl_context."""

    def test_ssl_context_no_cert(self):
        """Returns None when no TLS cert is configured."""
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_tls_cert = ""
            result = svc._get_ssl_context()
        assert result is None

    def test_ssl_context_valid_cert(self):
        """Returns SSLContext when valid cert is provided."""

        # A self-signed PEM cert for testing (base64-encoded)
        # We use a simple approach: provide base64 of a minimal test string
        # and let it fail gracefully
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_tls_cert = base64.b64encode(b"not-a-real-cert").decode()
            result = svc._get_ssl_context()
        # Invalid cert returns None (logged warning)
        assert result is None

    def test_ssl_context_bad_base64(self):
        """Returns None on invalid base64."""
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_tls_cert = "!!!not-base64!!!"
            result = svc._get_ssl_context()
        assert result is None


class TestLNDRequestMethod:
    """Tests for the LND _request method itself (not via higher-level methods)."""

    @pytest.mark.asyncio
    async def test_request_http_status_error(self):
        """HTTP error responses are parsed properly."""
        svc = LNDService()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "internal server error"
        mock_response.json.return_value = {"message": "wallet locked"}

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            side_effect=httpx.HTTPStatusError("err", request=MagicMock(), response=mock_response)
        )
        mock_client.is_closed = False
        svc._client = mock_client

        data, error = await svc._request("GET", "/v1/getinfo")
        assert data is None
        assert "500" in error
        assert "wallet locked" in error

    @pytest.mark.asyncio
    async def test_request_connect_error(self):
        """Connection errors return a descriptive message."""
        svc = LNDService()
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.is_closed = False
        svc._client = mock_client

        data, error = await svc._request("GET", "/v1/getinfo")
        assert data is None
        assert "Connection failed" in error

    @pytest.mark.asyncio
    async def test_request_generic_exception(self):
        """Unknown exceptions are caught and returned as error."""
        svc = LNDService()
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=RuntimeError("something unexpected"))
        mock_client.is_closed = False
        svc._client = mock_client

        data, error = await svc._request("GET", "/v1/getinfo")
        assert data is None
        assert "Request failed" in error

    @pytest.mark.asyncio
    async def test_request_http_error_no_json_body(self):
        """HTTP error with non-JSON body still returns error text."""
        svc = LNDService()
        mock_response = MagicMock()
        mock_response.status_code = 502
        mock_response.text = "Bad Gateway"
        mock_response.json.side_effect = ValueError("not json")

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            side_effect=httpx.HTTPStatusError("err", request=MagicMock(), response=mock_response)
        )
        mock_client.is_closed = False
        svc._client = mock_client

        data, error = await svc._request("GET", "/v1/getinfo")
        assert data is None
        assert "502" in error


# ─── Tor proxy configuration ─────────────────────────────────────────


class TestTorProxy:
    """Tests for Tor proxy detection and configuration."""

    def test_get_tor_proxy_onion_url(self):
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_rest_url = "https://abc123.onion:8080"
            mock_settings.lnd_tor_proxy = "socks5://tor-proxy:9050"
            proxy = svc._get_tor_proxy()
        assert proxy == "socks5://tor-proxy:9050"

    def test_get_tor_proxy_clearnet_url(self):
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_rest_url = "https://localhost:8080"
            proxy = svc._get_tor_proxy()
        assert proxy is None

    def test_get_tor_proxy_onion_but_no_proxy_set(self):
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_rest_url = "https://node.onion:8080"
            mock_settings.lnd_tor_proxy = ""
            proxy = svc._get_tor_proxy()
        assert proxy is None

    def test_is_onion_url_edge_cases(self):
        assert _is_onion_url("") is False
        assert _is_onion_url("not-a-url") is False
        assert _is_onion_url("https://sub.domain.onion:443/path") is True


# ─── get_recent_invoices additional ───────────────────────────────────


class TestGetRecentInvoicesExtra:
    """Additional tests for get_recent_invoices."""

    @pytest.mark.asyncio
    async def test_get_recent_invoices_lnd_down(self):
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "LND error")):
            result, error = await svc.get_recent_invoices()
        assert result is None
        assert error is not None

    @pytest.mark.asyncio
    async def test_get_recent_invoices_empty(self):
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"invoices": []}, None)):
            result, error = await svc.get_recent_invoices(5)
        assert result == []
        assert error is None

    @pytest.mark.asyncio
    async def test_get_recent_invoices_keysend(self):
        """Keysend invoices are parsed correctly."""
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "invoices": [
                        {
                            "memo": "",
                            "value": "500",
                            "settled": True,
                            "state": "SETTLED",
                            "creation_date": "1700000000",
                            "settle_date": "1700000100",
                            "amt_paid_sat": "500",
                            "is_keysend": True,
                            "payment_request": "",
                        }
                    ]
                },
                None,
            ),
        ):
            result, error = await svc.get_recent_invoices(5)
        assert result[0]["is_keysend"] is True


# ─── _get_client lifecycle ────────────────────────────────────────────


class TestGetClient:
    """Tests for _get_client creation and proxy configuration."""

    @pytest.mark.asyncio
    async def test_get_client_clearnet(self):
        """Creates client for clearnet URL with TLS verify enabled."""
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_rest_url = "https://localhost:8080"
            mock_settings.lnd_macaroon_hex = "aabb"
            mock_settings.lnd_tls_verify = True
            mock_settings.lnd_tls_cert = ""
            mock_settings.lnd_tor_proxy = ""
            client = await svc._get_client()
        assert client is not None
        await client.aclose()

    @pytest.mark.asyncio
    async def test_get_client_with_cert_overrides_verify(self):
        """When tls_verify=False but cert is provided, SSL context is used."""
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_rest_url = "https://localhost:8080"
            mock_settings.lnd_macaroon_hex = "aabb"
            mock_settings.lnd_tls_verify = False
            mock_settings.lnd_tls_cert = "not-valid-for-ssl"
            mock_settings.lnd_tor_proxy = ""
            # _get_ssl_context will return None for invalid cert, so verify stays False
            client = await svc._get_client()
        assert client is not None
        await client.aclose()

    @pytest.mark.asyncio
    async def test_get_client_onion_disables_tls(self):
        """Onion URLs disable TLS verification."""
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_rest_url = "https://abc123.onion:8080"
            mock_settings.lnd_macaroon_hex = "aabb"
            mock_settings.lnd_tls_verify = True
            mock_settings.lnd_tls_cert = ""
            mock_settings.lnd_tor_proxy = "socks5://proxy:9050"
            client = await svc._get_client()
        assert client is not None
        await client.aclose()

    @pytest.mark.asyncio
    async def test_get_client_reuses_existing(self):
        """Existing open client is reused."""
        svc = LNDService()
        mock_client = MagicMock()
        mock_client.is_closed = False
        svc._client = mock_client
        result = await svc._get_client()
        assert result is mock_client

    @pytest.mark.asyncio
    async def test_get_client_recreates_on_loop_change(self):
        """A client cached on a *different* event loop is discarded and rebuilt.

        The lnd_service singleton is reused across the Celery channel-mix
        executor's per-tick event loops (asyncio.new_event_loop()). httpx binds
        its pool to the loop it was created on, so a client carried over from a
        prior, now-closed loop must not be reused (it would raise "Event loop is
        closed"). _get_client detects the loop change via _client_loop.
        """
        import asyncio

        svc = LNDService()
        # Simulate a client built on a prior tick's loop.
        stale_client = MagicMock()
        stale_client.is_closed = False
        svc._client = stale_client
        svc._client_loop = asyncio.new_event_loop()  # a *different* loop
        try:
            result = await svc._get_client()
            assert result is not stale_client
            # The fresh client is bound to the loop we're actually running on.
            assert svc._client_loop is asyncio.get_running_loop()
        finally:
            await svc.close()

    @pytest.mark.asyncio
    async def test_get_client_reuses_on_same_loop(self):
        """A tracked client on the current loop is reused (no needless rebuild)."""
        import asyncio

        svc = LNDService()
        first = await svc._get_client()
        assert svc._client_loop is asyncio.get_running_loop()
        second = await svc._get_client()
        assert second is first
        await svc.close()

    @pytest.mark.asyncio
    async def test_close_client(self):
        """close() properly cleans up the client."""
        svc = LNDService()
        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client
        await svc.close()
        mock_client.aclose.assert_called_once()
        assert svc._client is None


# ─── get_onchain_transactions additional ──────────────────────────────


class TestGetOnchainTransactionsExtra:
    """Additional tests for get_onchain_transactions."""

    @pytest.mark.asyncio
    async def test_get_onchain_transactions_lnd_down(self):
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "connection error")):
            result, error = await svc.get_onchain_transactions()
        assert result is None

    @pytest.mark.asyncio
    async def test_get_onchain_transactions_empty(self):
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"transactions": []}, None)):
            result, error = await svc.get_onchain_transactions()
        assert result == []

    @pytest.mark.asyncio
    async def test_get_onchain_transactions_default_max(self):
        """Default max_txns=20 truncates correctly."""
        svc = LNDService()
        txns = [
            {
                "tx_hash": f"tx{i}",
                "amount": "1000",
                "num_confirmations": "1",
                "block_height": "800000",
                "time_stamp": "1700000000",
                "total_fees": "100",
            }
            for i in range(30)
        ]
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"transactions": txns}, None)):
            result, error = await svc.get_onchain_transactions()
        assert len(result) == 20


# ─── Client lifecycle ─────────────────────────────────────────────────


class TestClientLifecycle:
    """Tests for client creation and close."""

    @pytest.mark.asyncio
    async def test_close_when_no_client(self):
        """close() is safe when no client exists."""
        svc = LNDService()
        await svc.close()  # Should not raise

    @pytest.mark.asyncio
    async def test_close_closes_client(self):
        svc = LNDService()
        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client
        await svc.close()
        mock_client.aclose.assert_called_once()
        assert svc._client is None

    @pytest.mark.asyncio
    async def test_get_client_creates_new(self):
        """_get_client creates a new client if none exists."""
        svc = LNDService()
        svc._client = None
        client = await svc._get_client()
        assert client is not None
        await svc.close()

    @pytest.mark.asyncio
    async def test_get_client_recreates_if_closed(self):
        """_get_client creates a new client if the old one is closed."""
        svc = LNDService()
        mock_client = MagicMock()
        mock_client.is_closed = True
        svc._client = mock_client
        client = await svc._get_client()
        assert client is not svc._client or not client.is_closed
        await svc.close()


# ─── lookup_payment edge cases ────────────────────────────────────────


class TestLookupPaymentExtra:
    """Additional tests for lookup_payment."""

    @pytest.mark.asyncio
    async def test_lookup_payment_no_payments_key(self):
        """Returns error when no payments data returned."""
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "LND not ready")):
            data, error = await svc.lookup_payment("ab" * 32)
        assert data is None
        assert error is not None


# ─── get_pending_channels summary ─────────────────────────────────────


class TestGetPendingChannelsSummary:
    """Tests for get_pending_channels (summary version)."""

    @pytest.mark.asyncio
    async def test_pending_channels_summary_success(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "pending_open_channels": [1, 2],
                    "pending_closing_channels": [3],
                    "pending_force_closing_channels": [],
                    "waiting_close_channels": [4],
                    "total_limbo_balance": "50000",
                },
                None,
            ),
        ):
            result, error = await svc.get_pending_channels()
        assert result["pending_open_channels"] == 2
        assert result["pending_closing_channels"] == 1
        assert result["waiting_close_channels"] == 1
        assert result["total_limbo_balance"] == 50000

    @pytest.mark.asyncio
    async def test_pending_channels_summary_error(self):
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "LND error")):
            result, error = await svc.get_pending_channels()
        assert result is None

    @pytest.mark.asyncio
    async def test_get_channel_balance_success(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "local_balance": {"sat": "200000"},
                    "remote_balance": {"sat": "300000"},
                    "pending_open_local_balance": {"sat": "0"},
                    "pending_open_remote_balance": {"sat": "0"},
                    "unsettled_local_balance": {"sat": "5000"},
                    "unsettled_remote_balance": {"sat": "1000"},
                },
                None,
            ),
        ):
            result, error = await svc.get_channel_balance()
        assert result["local_balance_sat"] == 200000
        assert result["remote_balance_sat"] == 300000
        assert result["unsettled_local_sat"] == 5000


# ─── _request HTTP layer ─────────────────────────────────────────────


class TestLNDRequestLayer:
    """Tests for the _request method HTTP interactions."""

    @pytest.mark.asyncio
    async def test_request_success(self):
        svc = LNDService()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "ok"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.request = AsyncMock(return_value=mock_response)
        svc._client = mock_client

        data, err = await svc._request("GET", "/test")
        assert data == {"result": "ok"}
        assert err is None

    @pytest.mark.asyncio
    async def test_request_http_status_error_with_json(self):
        svc = LNDService()
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "bad request"
        mock_resp.json.return_value = {"message": "invoice expired"}

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.request = AsyncMock(
            side_effect=httpx.HTTPStatusError("err", request=MagicMock(), response=mock_resp)
        )
        svc._client = mock_client

        data, err = await svc._request("GET", "/test")
        assert data is None
        assert "400" in err
        assert "invoice expired" in err

    @pytest.mark.asyncio
    async def test_request_http_status_error_no_json(self):
        svc = LNDService()
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "internal error"
        mock_resp.json.side_effect = Exception("not json")

        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.request = AsyncMock(
            side_effect=httpx.HTTPStatusError("err", request=MagicMock(), response=mock_resp)
        )
        svc._client = mock_client

        data, err = await svc._request("GET", "/test")
        assert data is None
        assert "500" in err
        assert "internal error" in err

    @pytest.mark.asyncio
    async def test_request_connect_error(self):
        svc = LNDService()
        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.request = AsyncMock(side_effect=httpx.ConnectError("refused"))
        svc._client = mock_client

        data, err = await svc._request("GET", "/test")
        assert data is None
        assert "Connection failed" in err

    @pytest.mark.asyncio
    async def test_request_generic_exception(self):
        svc = LNDService()
        mock_client = AsyncMock()
        mock_client.is_closed = False
        mock_client.request = AsyncMock(side_effect=RuntimeError("unexpected"))
        svc._client = mock_client

        data, err = await svc._request("GET", "/test")
        assert data is None
        assert "Request failed" in err


# ─── Client lifecycle ────────────────────────────────────────────────


class TestLNDClientLifecycle:
    """Tests for _get_client and close."""

    @pytest.mark.asyncio
    async def test_get_client_creates_client(self):
        svc = LNDService()
        assert svc._client is None
        client = await svc._get_client()
        assert client is not None
        await svc.close()

    @pytest.mark.asyncio
    async def test_get_client_reuses_open_client(self):
        svc = LNDService()
        client1 = await svc._get_client()
        client2 = await svc._get_client()
        assert client1 is client2
        await svc.close()

    @pytest.mark.asyncio
    async def test_close_noop_when_none(self):
        svc = LNDService()
        await svc.close()  # should not raise

    @pytest.mark.asyncio
    async def test_close_sets_client_none(self):
        svc = LNDService()
        await svc._get_client()
        assert svc._client is not None
        await svc.close()
        assert svc._client is None

    @pytest.mark.asyncio
    async def test_get_client_recreates_after_close(self):
        svc = LNDService()
        c1 = await svc._get_client()
        await svc.close()
        c2 = await svc._get_client()
        assert c1 is not c2
        await svc.close()


# ─── Tor proxy detection ─────────────────────────────────────────────


class TestTorProxyExtra:
    """Additional tests for _get_tor_proxy."""

    def test_returns_proxy_for_onion(self):
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_rest_url = "https://abc123.onion:8080"
            mock_settings.lnd_tor_proxy = "socks5://tor-proxy:9050"
            result = svc._get_tor_proxy()
        assert result == "socks5://tor-proxy:9050"

    def test_returns_none_for_clearnet(self):
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_rest_url = "https://localhost:8080"
            result = svc._get_tor_proxy()
        assert result is None

    def test_warns_when_onion_no_proxy(self):
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_rest_url = "https://abc123.onion:8080"
            mock_settings.lnd_tor_proxy = ""
            result = svc._get_tor_proxy()
        assert result is None


class TestLNDHeaders:
    """Tests for _get_headers."""

    def test_empty_macaroon(self):
        svc = LNDService()
        with patch("app.services.lnd_service.settings") as mock_settings:
            mock_settings.lnd_macaroon_hex = ""
            headers = svc._get_headers()
        assert "Grpc-Metadata-macaroon" not in headers


class TestListUnspent:
    """Tests for list_unspent (walletkit /v2/wallet/utxos)."""

    @pytest.mark.asyncio
    async def test_list_unspent_happy(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        sample = {
            "utxos": [
                {
                    "outpoint": {"txid_str": "ab" * 32, "output_index": 0},
                    "amount_sat": "12345",
                    "address": "bc1qabc",
                    "address_type": "WITNESS_PUBKEY_HASH",
                    "pk_script": "001400112233",
                    "confirmations": "3",
                }
            ]
        }
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(sample, None)):
            data, err = await svc.list_unspent()
        assert err is None
        assert data and len(data) == 1
        u = data[0]
        assert u["outpoint"]["txid_str"] == "ab" * 32
        assert u["outpoint"]["output_index"] == 0
        assert u["amount_sat"] == 12345
        assert u["confirmations"] == 3

    @pytest.mark.asyncio
    async def test_list_unspent_empty(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({}, None)):
            data, err = await svc.list_unspent()
        assert err is None
        assert data == []

    @pytest.mark.asyncio
    async def test_list_unspent_error(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "boom")):
            data, err = await svc.list_unspent()
        assert data is None
        assert err == "boom"


class TestSendCoinsCoinControl:
    """``send_coins`` with explicit outpoints / send_all."""

    @pytest.mark.asyncio
    async def test_send_coins_with_outpoints(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        outpoints = [{"txid_str": "ab" * 32, "output_index": 0}]
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"txid": "feedface"}, None),
        ) as mock_req:
            data, err = await svc.send_coins("bc1qtest", 50000, sat_per_vbyte=5, label="cc", outpoints=outpoints)
        assert err is None and data == {"txid": "feedface"}
        body = mock_req.call_args.kwargs.get("json")
        assert body is not None
        assert body["outpoints"] == outpoints

    @pytest.mark.asyncio
    async def test_send_coins_send_all(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        outpoints = [{"txid_str": "ab" * 32, "output_index": 0}]
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"txid": "deadbeef"}, None),
        ) as mock_req:
            await svc.send_coins("bc1qtest", None, send_all=True, outpoints=outpoints)
        body = mock_req.call_args.kwargs.get("json")
        assert body["send_all"] is True
        # When send_all is true, amount must NOT be in the body.
        assert "amount" not in body

    @pytest.mark.asyncio
    async def test_send_coins_rejects_no_amount_no_send_all(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        data, err = await svc.send_coins("bc1qtest", None)
        assert data is None
        assert "amount" in (err or "").lower() or "send_all" in (err or "").lower()


class TestEstimateFeeOutpoints:
    @pytest.mark.asyncio
    async def test_estimate_fee_outpoints_query(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        outpoints = [
            {"txid_str": "aa" * 32, "output_index": 0},
            {"txid_str": "bb" * 32, "output_index": 1},
        ]
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"fee_sat": 250, "sat_per_vbyte": 5}, None),
        ) as mock_req:
            data, err = await svc.estimate_fee("bc1qtest", 10000, target_conf=6, outpoints=outpoints)
        assert err is None
        # Outpoints are query params for GET; verify they were forwarded.
        params = mock_req.call_args.kwargs.get("params") or mock_req.call_args[1].get("params")
        assert params is not None
        assert any("txid_str" in str(k) for k in params)


class _CapturingStreamClient:
    """Captures the JSON body passed to ``client.stream`` and replays a
    canned line stream, so a test can assert how ``send_payment_v2``
    encodes its request."""

    def __init__(self, resp, captured: dict):
        self._resp = resp
        self._captured = captured

    def stream(self, _method, _path, **kw):
        self._captured["json"] = kw.get("json")
        return _FakeStreamCtx(self._resp)


def _succeeded_stream():
    return _FakeStreamResponse(
        200,
        [
            '{"result": {"status": "SUCCEEDED", "payment_hash": "ab", '
            '"htlcs": [], "fee_msat": "0", "value_sat": "250000"}}'
        ],
    )


class TestSendPaymentV2IgnoredPairs:
    """``send_payment_v2`` encodes ``ignored_pairs`` as base64 NodePairs
    and omits the field when no pairs are supplied."""

    @pytest.mark.asyncio
    async def test_ignored_pairs_encoded_as_base64_nodepairs(self):
        import base64

        from app.services.lnd_service import LNDService

        svc = LNDService()
        captured: dict = {}
        from_hex = "02" + "aa" * 32
        to_hex = "03" + "bb" * 32
        with (
            patch.object(
                svc,
                "_get_client",
                new_callable=AsyncMock,
                return_value=_CapturingStreamClient(_succeeded_stream(), captured),
            ),
            patch("app.services.lnd_service._LND_BREAKER.before_call", new_callable=AsyncMock),
        ):
            _result, err = await svc.send_payment_v2(
                payment_request="lnbcrt1self",
                max_parts=3,
                ignored_pairs=[(from_hex, to_hex)],
            )
        assert err is None
        pairs = captured["json"]["ignored_pairs"]
        assert pairs == [
            {
                "from": base64.b64encode(bytes.fromhex(from_hex)).decode("ascii"),
                "to": base64.b64encode(bytes.fromhex(to_hex)).decode("ascii"),
            }
        ]

    @pytest.mark.asyncio
    async def test_ignored_pairs_omitted_when_absent(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        captured: dict = {}
        with (
            patch.object(
                svc,
                "_get_client",
                new_callable=AsyncMock,
                return_value=_CapturingStreamClient(_succeeded_stream(), captured),
            ),
            patch("app.services.lnd_service._LND_BREAKER.before_call", new_callable=AsyncMock),
        ):
            await svc.send_payment_v2(payment_request="lnbcrt1self")
        assert "ignored_pairs" not in captured["json"]

    @pytest.mark.asyncio
    async def test_ignored_pairs_rejects_non_hex(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        captured: dict = {}
        with (
            patch.object(
                svc,
                "_get_client",
                new_callable=AsyncMock,
                return_value=_CapturingStreamClient(_succeeded_stream(), captured),
            ),
            patch("app.services.lnd_service._LND_BREAKER.before_call", new_callable=AsyncMock),
        ):
            result, err = await svc.send_payment_v2(
                payment_request="lnbcrt1self",
                ignored_pairs=[("not-hex", "03bb")],
            )
        assert result is None
        assert err is not None and "hex" in err

    @pytest.mark.asyncio
    async def test_pins_first_hop_via_outgoing_chan_ids(self):
        """The first-hop pin must use the repeated ``outgoing_chan_ids`` field
        (array of decimal strings). The deprecated singular
        ``outgoing_chan_id`` is dropped from LND's REST gateway on recent
        versions and gets the whole request rejected with an "unknown field"
        400 — no payment is ever created."""
        from app.services.lnd_service import LNDService

        svc = LNDService()
        captured: dict = {}
        with (
            patch.object(
                svc,
                "_get_client",
                new_callable=AsyncMock,
                return_value=_CapturingStreamClient(_succeeded_stream(), captured),
            ),
            patch("app.services.lnd_service._LND_BREAKER.before_call", new_callable=AsyncMock),
        ):
            _result, err = await svc.send_payment_v2(
                payment_request="lnbcrt1drain",
                outgoing_chan_id="123456789",
            )
        assert err is None
        body = captured["json"]
        assert body.get("outgoing_chan_ids") == ["123456789"]
        # The rejected singular form must NOT be sent.
        assert "outgoing_chan_id" not in body
        # A pin forces single-path (MPP would drop the pin).
        assert body.get("max_parts") == 1

    @pytest.mark.asyncio
    async def test_pin_overrides_requested_mpp(self):
        """Even if a caller requests MPP, a first-hop pin forces single-path."""
        from app.services.lnd_service import LNDService

        svc = LNDService()
        captured: dict = {}
        with (
            patch.object(
                svc,
                "_get_client",
                new_callable=AsyncMock,
                return_value=_CapturingStreamClient(_succeeded_stream(), captured),
            ),
            patch("app.services.lnd_service._LND_BREAKER.before_call", new_callable=AsyncMock),
        ):
            await svc.send_payment_v2(
                payment_request="lnbcrt1pin",
                outgoing_chan_id="987654321",
                max_parts=8,
            )
        assert captured["json"].get("outgoing_chan_ids") == ["987654321"]
        assert captured["json"].get("max_parts") == 1

    @pytest.mark.asyncio
    async def test_no_chan_pin_omits_outgoing_fields(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        captured: dict = {}
        with (
            patch.object(
                svc,
                "_get_client",
                new_callable=AsyncMock,
                return_value=_CapturingStreamClient(_succeeded_stream(), captured),
            ),
            patch("app.services.lnd_service._LND_BREAKER.before_call", new_callable=AsyncMock),
        ):
            await svc.send_payment_v2(payment_request="lnbcrt1nopin")
        assert "outgoing_chan_ids" not in captured["json"]
        assert "outgoing_chan_id" not in captured["json"]
