# SPDX-License-Identifier: MIT
"""
Unit tests for the channel rebalance feature.

Covers:
- ``RebalanceQuoteRequest`` / ``RebalanceRequest`` Pydantic validation.
- ``_rebalance_max_sendable`` / ``_rebalance_max_receivable`` math.
- ``LNDService.query_routes`` (probe) request shape + parsing.
- ``LNDService.send_payment_v2`` streaming terminal-state handling.
- ``rebalance_quote`` / ``rebalance`` endpoint behaviour with mocked LND.
"""

from __future__ import annotations

import base64
import json
import math
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request
from pydantic import ValidationError

from app.core.config import settings
from app.dashboard.api import (
    RebalanceQuoteRequest,
    RebalanceRequest,
    _rebalance_max_receivable,
    _rebalance_max_sendable,
    _resolve_rebalance_channels,
    rebalance,
    rebalance_quote,
    rebalance_recent,
)
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog
from app.services.lnd_service import LNDService

# ── Pydantic validation ────────────────────────────────────────────────


class TestRebalanceQuoteRequest:
    def test_valid(self):
        body = RebalanceQuoteRequest(
            source_chan_id="123456789",
            dest_chan_id="987654321",
            amount_sats=10_000,
            fee_limit_sats=50,
        )
        assert body.amount_sats == 10_000

    def test_rejects_non_numeric_chan_id(self):
        with pytest.raises(ValidationError):
            RebalanceQuoteRequest(
                source_chan_id="abc",
                dest_chan_id="987654321",
                amount_sats=10_000,
            )

    def test_rejects_chan_id_too_long(self):
        with pytest.raises(ValidationError):
            RebalanceQuoteRequest(
                source_chan_id="1" * 21,
                dest_chan_id="987654321",
                amount_sats=10_000,
            )

    def test_accepts_uint64_max_chan_id(self):
        """20-digit values that fit in uint64 are accepted."""
        body = RebalanceQuoteRequest(
            source_chan_id="18446744073709551615",
            dest_chan_id="18446744073709551615",
            amount_sats=10_000,
        )
        assert body.source_chan_id == "18446744073709551615"

    def test_rejects_chan_id_above_uint64_max(self):
        """20-digit values that overflow uint64 must be rejected.

        LND treats chan_id as uint64 over the wire; silently passing
        an overflowed value to LND has previously caused crashes.
        """
        with pytest.raises(ValidationError, match="exceeds uint64 max"):
            RebalanceQuoteRequest(
                source_chan_id="18446744073709551616",
                dest_chan_id="987654321",
                amount_sats=10_000,
            )
        with pytest.raises(ValidationError, match="exceeds uint64 max"):
            RebalanceRequest(
                source_chan_id="987654321",
                dest_chan_id="99999999999999999999",
                amount_sats=10_000,
                fee_limit_sats=50,
            )

    def test_rejects_zero_amount(self):
        with pytest.raises(ValidationError):
            RebalanceQuoteRequest(
                source_chan_id="123",
                dest_chan_id="456",
                amount_sats=0,
            )

    def test_fee_limit_optional(self):
        body = RebalanceQuoteRequest(
            source_chan_id="123",
            dest_chan_id="456",
            amount_sats=1_000,
        )
        assert body.fee_limit_sats is None


class TestRebalanceRequest:
    def test_requires_fee_limit(self):
        with pytest.raises(ValidationError):
            RebalanceRequest(
                source_chan_id="123",
                dest_chan_id="456",
                amount_sats=1_000,
            )  # type: ignore[call-arg]

    def test_default_timeout(self):
        body = RebalanceRequest(
            source_chan_id="123",
            dest_chan_id="456",
            amount_sats=1_000,
            fee_limit_sats=10,
        )
        assert body.timeout_seconds == 60

    def test_timeout_bounds(self):
        with pytest.raises(ValidationError):
            RebalanceRequest(
                source_chan_id="123",
                dest_chan_id="456",
                amount_sats=1_000,
                fee_limit_sats=10,
                timeout_seconds=4,
            )
        with pytest.raises(ValidationError):
            RebalanceRequest(
                source_chan_id="123",
                dest_chan_id="456",
                amount_sats=1_000,
                fee_limit_sats=10,
                timeout_seconds=301,
            )

    def test_fee_must_not_exceed_amount(self):
        # Defensive cap from plan \u00a73.5: never burn more in fees than principal.
        with pytest.raises(ValidationError, match="fee_limit_sats"):
            RebalanceRequest(
                source_chan_id="123",
                dest_chan_id="456",
                amount_sats=100,
                fee_limit_sats=200,
            )


# ── Headroom math ──────────────────────────────────────────────────────


class TestRebalanceMaxMath:
    def test_max_sendable_subtracts_reserve_unsettled_and_safety(self):
        ch = {
            "local_balance": 100_000,
            "local_chan_reserve_sat": 5_000,
            "unsettled_balance": 1_000,
            "capacity": 200_000,  # 1% safety = 2_000
        }
        # 100_000 - 5_000 - 1_000 - 2_000 = 92_000
        assert _rebalance_max_sendable(ch) == 92_000

    def test_max_sendable_clamps_to_zero(self):
        ch = {
            "local_balance": 100,
            "local_chan_reserve_sat": 5_000,
            "unsettled_balance": 0,
            "capacity": 200_000,
        }
        assert _rebalance_max_sendable(ch) == 0

    def test_max_receivable_uses_remote_reserve(self):
        ch = {
            "remote_balance": 80_000,
            "remote_chan_reserve_sat": 5_000,
            "unsettled_balance": 0,
            "capacity": 200_000,
        }
        # 80_000 - 5_000 - 0 - 2_000 = 73_000
        assert _rebalance_max_receivable(ch) == 73_000

    def test_handles_missing_keys(self):
        assert _rebalance_max_sendable({}) == 0
        assert _rebalance_max_receivable({}) == 0

    def test_max_sendable_reserves_commit_fee_for_initiator(self):
        # Small channel where the initiator's commit fee + anchor pad
        # exceeds the 1% floor — the source must keep that headroom or LND
        # rejects the send with "insufficient local balance".
        ch = {
            "local_balance": 30_000,
            "local_chan_reserve_sat": 1_000,
            "unsettled_balance": 0,
            "capacity": 30_000,  # 1% floor = 300
            "initiator": True,
            "commit_fee": 2_000,
        }
        # headroom = max(300, 2_000 + 1_000) = 3_000
        # 30_000 - 1_000 - 0 - 3_000 = 26_000
        assert _rebalance_max_sendable(ch) == 26_000

    def test_max_sendable_ignores_commit_fee_for_non_initiator(self):
        # The non-initiator doesn't pay the commitment fee, so only the
        # fixed anchor/growth pad applies (above the 1% floor).
        ch = {
            "local_balance": 30_000,
            "local_chan_reserve_sat": 1_000,
            "unsettled_balance": 0,
            "capacity": 30_000,
            "initiator": False,
            "commit_fee": 2_000,
        }
        # headroom = max(300, 0 + 1_000) = 1_000
        # 30_000 - 1_000 - 0 - 1_000 = 28_000
        assert _rebalance_max_sendable(ch) == 28_000


def _reserve_fee(sendable: int, mode: str, pct: float, sats: int) -> int:
    """Mirror of the JS ``_rebalanceReserveFee`` — reduce a sendable
    amount so amount + routing fee fits within it. Kept in sync with
    ``app/dashboard/static/dashboard.js``."""
    if mode == "percent":
        if not (pct > 0):
            return sendable
        return math.floor(sendable / (1 + pct / 100))
    fee = sats if sats > 0 else 0
    return max(sendable - fee, 0)


class TestRebalanceMaxFeeReservation:
    """The Max amount must leave room for the routing fee — the source
    forwards amount + fee, so amount alone can't equal the full sendable."""

    def test_percent_mode_reserves_proportional_fee(self):
        # 2% fee: 102_000 / 1.02 = 100_000 → amount + 2% fits 102_000.
        amount = _reserve_fee(102_000, "percent", 2.0, 0)
        assert amount == 100_000
        assert amount + math.ceil(amount * 2 / 100) <= 102_000

    def test_sats_mode_subtracts_flat_fee(self):
        assert _reserve_fee(50_000, "sats", 0, 250) == 49_750

    def test_zero_percent_leaves_sendable_unchanged(self):
        assert _reserve_fee(50_000, "percent", 0, 0) == 50_000

    def test_never_negative(self):
        assert _reserve_fee(100, "sats", 0, 500) == 0


# ── _resolve_rebalance_channels ────────────────────────────────────────


def _channels_fixture():
    return [
        {
            "chan_id": "111",
            "active": True,
            "capacity": 200_000,
            "local_balance": 150_000,
            "remote_balance": 48_000,
            "local_chan_reserve_sat": 2_000,
            "remote_chan_reserve_sat": 2_000,
            "unsettled_balance": 0,
            "remote_pubkey": "02" + "a" * 64,
            "peer_alias": "src-peer",
        },
        {
            "chan_id": "222",
            "active": True,
            "capacity": 200_000,
            "local_balance": 30_000,
            "remote_balance": 168_000,
            "local_chan_reserve_sat": 2_000,
            "remote_chan_reserve_sat": 2_000,
            "unsettled_balance": 0,
            "remote_pubkey": "03" + "b" * 64,
            "peer_alias": "dst-peer",
        },
        {
            "chan_id": "333",
            "active": False,
            "capacity": 200_000,
            "local_balance": 100_000,
            "remote_balance": 98_000,
            "local_chan_reserve_sat": 2_000,
            "remote_chan_reserve_sat": 2_000,
            "unsettled_balance": 0,
            "remote_pubkey": "02" + "c" * 64,
            "peer_alias": "inactive",
        },
    ]


class TestResolveRebalanceChannels:
    @pytest.mark.asyncio
    async def test_same_chan_id_rejected(self):
        src, dst, err = await _resolve_rebalance_channels("111", "111")
        assert src is None and dst is None
        assert err is not None and "differ" in err

    @pytest.mark.asyncio
    async def test_inactive_source_rejected(self):
        with patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=(_channels_fixture(), None),
        ):
            _, _, err = await _resolve_rebalance_channels("333", "222")
        assert err is not None and "inactive" in err.lower()

    @pytest.mark.asyncio
    async def test_unknown_chan_id_rejected(self):
        with patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=(_channels_fixture(), None),
        ):
            _, _, err = await _resolve_rebalance_channels("999", "222")
        assert err is not None and "not found" in err.lower()

    @pytest.mark.asyncio
    async def test_happy_path(self):
        with patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=(_channels_fixture(), None),
        ):
            src, dst, err = await _resolve_rebalance_channels("111", "222")
        assert err is None
        assert src is not None and dst is not None
        assert src["chan_id"] == "111"
        assert dst["chan_id"] == "222"


# ── LNDService.query_routes ────────────────────────────────────────────


class TestQueryRoutes:
    @pytest.mark.asyncio
    async def test_rejects_non_positive_amount(self):
        svc = LNDService()
        data, err = await svc.query_routes(dest_pubkey_hex="02" + "a" * 64, amount_sats=0)
        assert data is None
        assert err is not None and "positive" in err

    @pytest.mark.asyncio
    async def test_builds_correct_request_and_parses_route(self):
        svc = LNDService()
        captured: dict = {}

        async def fake_request(method, path, **kwargs):
            captured["method"] = method
            captured["path"] = path
            captured["params"] = kwargs.get("params")
            return (
                {
                    "routes": [
                        {
                            "total_amt": "10001",
                            "total_fees": "1",
                            "total_amt_msat": "10001000",
                            "total_fees_msat": "1000",
                            "total_time_lock": 700,
                            "hops": [{}, {}, {}],
                        }
                    ]
                },
                None,
            )

        with patch.object(svc, "_request", side_effect=fake_request):
            quote, err = await svc.query_routes(
                dest_pubkey_hex="02" + "a" * 64,
                amount_sats=10_000,
                outgoing_chan_id="111",
                last_hop_pubkey_hex="03" + "b" * 64,
                fee_limit_sats=25,
            )

        assert err is None
        assert quote is not None
        assert quote["hops"] == 3
        assert quote["total_fees_sat"] == 1
        # ppm: floor(1000/1000) * 1_000_000 / 10_000 = 100
        assert quote["ppm"] == 100

        assert captured["method"] == "GET"
        assert captured["path"] == f"/v1/graph/routes/{'02' + 'a' * 64}/10000"
        params = captured["params"]
        assert params["outgoing_chan_id"] == "111"
        assert params["fee_limit.fixed"] == "25"
        # last_hop_pubkey is base64 of the hex bytes
        expected_b64 = base64.b64encode(bytes.fromhex("03" + "b" * 64)).decode("ascii")
        assert params["last_hop_pubkey"] == expected_b64

    @pytest.mark.asyncio
    async def test_no_routes_returns_error(self):
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"routes": []}, None)):
            data, err = await svc.query_routes(dest_pubkey_hex="02" + "a" * 64, amount_sats=1_000)
        assert data is None
        assert err == "No route found"

    @pytest.mark.asyncio
    async def test_invalid_last_hop_hex(self):
        svc = LNDService()
        with patch.object(svc, "_request", new_callable=AsyncMock) as mock_req:
            data, err = await svc.query_routes(
                dest_pubkey_hex="02" + "a" * 64,
                amount_sats=1_000,
                last_hop_pubkey_hex="not-hex",
            )
        assert data is None
        assert err is not None and "hex" in err
        mock_req.assert_not_called()


# ── LNDService.send_payment_v2 ─────────────────────────────────────────


class _FakeStreamResponse:
    """Minimal async-context-manager mimicking ``httpx`` streaming."""

    def __init__(self, status_code: int, lines: list[str]):
        self.status_code = status_code
        self._lines = lines

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def aiter_lines(self):
        for ln in self._lines:
            yield ln

    async def aread(self) -> bytes:
        return b""


def _make_fake_client(stream_response: _FakeStreamResponse) -> MagicMock:
    client = MagicMock()
    client.stream = MagicMock(return_value=stream_response)
    return client


class TestSendPaymentV2:
    @pytest.mark.asyncio
    async def test_succeeds_on_terminal_succeeded(self):
        svc = LNDService()
        stream = _FakeStreamResponse(
            200,
            [
                json.dumps({"result": {"status": "IN_FLIGHT"}}),
                json.dumps(
                    {
                        "result": {
                            "status": "SUCCEEDED",
                            "payment_hash": "YWJj",
                            "payment_preimage": "ZGVm",
                            "value_sat": "10000",
                            "fee_sat": "2",
                            "fee_msat": "2000",
                            "htlcs": [
                                {
                                    "status": "SUCCEEDED",
                                    "route": {"hops": [{}, {}]},
                                }
                            ],
                        }
                    }
                ),
            ],
        )
        with patch.object(svc, "_get_client", new_callable=AsyncMock, return_value=_make_fake_client(stream)):
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                outgoing_chan_id="111",
                last_hop_pubkey_hex="03" + "b" * 64,
                fee_limit_sats=10,
                timeout_seconds=5,
            )
        assert err is None
        assert data is not None
        assert data["amount_sats"] == 10_000
        assert data["fee_sats"] == 2
        assert data["hops"] == 2

    @pytest.mark.asyncio
    async def test_fails_on_terminal_failed(self):
        svc = LNDService()
        stream = _FakeStreamResponse(
            200,
            [json.dumps({"result": {"status": "FAILED", "failure_reason": "FAILURE_REASON_NO_ROUTE"}})],
        )
        with patch.object(svc, "_get_client", new_callable=AsyncMock, return_value=_make_fake_client(stream)):
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                outgoing_chan_id="111",
                last_hop_pubkey_hex="03" + "b" * 64,
                fee_limit_sats=10,
                timeout_seconds=5,
            )
        assert data is None
        assert err is not None and "FAILURE_REASON_NO_ROUTE" in err

    @pytest.mark.asyncio
    async def test_http_error_returned(self):
        svc = LNDService()
        stream = _FakeStreamResponse(500, [])
        with patch.object(svc, "_get_client", new_callable=AsyncMock, return_value=_make_fake_client(stream)):
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                fee_limit_sats=10,
                timeout_seconds=5,
            )
        assert data is None
        assert err is not None and "500" in err

    @pytest.mark.asyncio
    async def test_invalid_last_hop_hex(self):
        svc = LNDService()
        with patch.object(svc, "_get_client", new_callable=AsyncMock) as mock_get:
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                last_hop_pubkey_hex="zzz",
                fee_limit_sats=10,
            )
        assert data is None
        assert err is not None and "hex" in err
        mock_get.assert_not_called()


# ── Endpoint integration with mocked LND ──────────────────────────────


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


def _mock_request() -> MagicMock:
    req = MagicMock(spec=Request)
    req.client.host = "127.0.0.1"
    req.cookies = {}
    req.headers = {"X-Requested-With": "XMLHttpRequest"}
    return req


class TestRebalanceQuoteEndpoint:
    @pytest.mark.asyncio
    async def test_quote_happy_path(self):
        body = RebalanceQuoteRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
            fee_limit_sats=50,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_info",
                new_callable=AsyncMock,
                return_value=({"identity_pubkey": "02" + "f" * 64}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.query_routes",
                new_callable=AsyncMock,
                return_value=(
                    {
                        "hops": 2,
                        "total_amt_sat": 10_001,
                        "total_fees_sat": 1,
                        "total_amt_msat": 10_001_000,
                        "total_fees_msat": 1_000,
                        "total_time_lock": 700,
                        "ppm": 100,
                    },
                    None,
                ),
            ),
        ):
            resp = await rebalance_quote(body)
        assert resp["ok"] is True
        assert resp["route"]["hops"] == 2
        assert resp["max_sendable_sats"] > 0
        assert resp["max_receivable_sats"] > 0

    @pytest.mark.asyncio
    async def test_quote_amount_exceeds_max_sendable(self):
        body = RebalanceQuoteRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=1_000_000,  # way more than fixture local_balance
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_info",
                new_callable=AsyncMock,
                return_value=({"identity_pubkey": "02" + "f" * 64}, None),
            ),
        ):
            resp = await rebalance_quote(body)
        assert resp.status_code == 400
        assert b"max sendable" in resp.body

    @pytest.mark.asyncio
    async def test_quote_query_routes_failure_returns_502(self):
        body = RebalanceQuoteRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_info",
                new_callable=AsyncMock,
                return_value=({"identity_pubkey": "02" + "f" * 64}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.query_routes",
                new_callable=AsyncMock,
                return_value=(None, "LND unreachable: connection refused"),
            ),
        ):
            resp = await rebalance_quote(body)
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_quote_targets_dest_peer_not_self(self):
        """Regression: ``QueryRoutes`` does NOT reliably handle
        self-payments (source==dest). Quoting must instead probe a
        route from us to the *destination channel's peer*, pinning
        the source channel as the outgoing hop. Verifies the call
        shape so we don't accidentally regress to the self-payment
        recipe that returns "unable to find a path to destination"
        for any input on real LND nodes."""
        body = RebalanceQuoteRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
            fee_limit_sats=50,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch(
                "app.dashboard.api.lnd_service.query_routes",
                new_callable=AsyncMock,
                return_value=(
                    {
                        "hops": 2,
                        "total_amt_sat": 10_001,
                        "total_fees_sat": 1,
                        "total_amt_msat": 10_001_000,
                        "total_fees_msat": 1_000,
                        "total_time_lock": 700,
                        "ppm": 100,
                    },
                    None,
                ),
            ) as mock_qr,
        ):
            resp = await rebalance_quote(body)

        assert resp["ok"] is True
        # Exactly one call, with dest = the destination channel's
        # peer pubkey (NOT our own identity_pubkey), and NO
        # last_hop_pubkey constraint (self-payment recipe).
        mock_qr.assert_called_once()
        kwargs = mock_qr.call_args.kwargs
        assert kwargs["dest_pubkey_hex"] == "03" + "b" * 64  # dst-peer fixture
        assert kwargs["outgoing_chan_id"] == "111"
        assert "last_hop_pubkey_hex" not in kwargs or kwargs["last_hop_pubkey_hex"] is None

    @pytest.mark.asyncio
    async def test_quote_no_route_returns_200_with_flag(self):
        """LND "unable to find a path" is surfaced as a friendly
        ``no_route: true`` response (200) rather than a 502, so the UI
        can show an inline hint instead of treating it as a fault."""
        body = RebalanceQuoteRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_info",
                new_callable=AsyncMock,
                return_value=({"identity_pubkey": "02" + "f" * 64}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.query_routes",
                new_callable=AsyncMock,
                return_value=(None, 'LND error (500): {"code":2, "message":"unable to find a path to destination"}'),
            ),
        ):
            resp = await rebalance_quote(body)
        # Plain dict (200) — not a JSONResponse error.
        assert isinstance(resp, dict)
        assert resp["ok"] is False
        assert resp["no_route"] is True
        assert "No route" in resp["detail"]


class TestRebalanceEndpoint:
    @pytest.mark.asyncio
    async def test_rebalance_happy_path(self, db_session):
        request = _mock_request()
        body = RebalanceRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
            fee_limit_sats=50,
            timeout_seconds=10,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch(
                "app.dashboard.api.lnd_service.create_invoice",
                new_callable=AsyncMock,
                return_value=(
                    {"payment_request": "lnbc1...", "r_hash": "YWJj", "add_index": "1"},
                    None,
                ),
            ),
            patch(
                "app.dashboard.api.lnd_service.send_payment_v2",
                new_callable=AsyncMock,
                return_value=(
                    {
                        "payment_hash": "abc",
                        "payment_preimage": "def",
                        "amount_sats": 10_000,
                        "fee_sats": 1,
                        "fee_msat": 1_000,
                        "hops": 2,
                        "duration_ms": 500,
                    },
                    None,
                ),
            ),
        ):
            resp = await rebalance(request, body, db_session)
        # Either dict (success) or JSONResponse — happy path returns dict
        assert isinstance(resp, dict)
        assert resp["ok"] is True
        assert resp["result"]["fee_sats"] == 1

    @pytest.mark.asyncio
    async def test_rebalance_send_failure_returns_502_and_audits(self, db_session):
        request = _mock_request()
        body = RebalanceRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
            fee_limit_sats=50,
            timeout_seconds=10,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch(
                "app.dashboard.api.lnd_service.create_invoice",
                new_callable=AsyncMock,
                return_value=(
                    {"payment_request": "lnbc1...", "r_hash": "YWJj", "add_index": "1"},
                    None,
                ),
            ),
            patch(
                "app.dashboard.api.lnd_service.send_payment_v2",
                new_callable=AsyncMock,
                return_value=(None, "Payment failed: TIMEOUT"),
            ),
            patch("app.dashboard.api.log_dashboard_action", new_callable=AsyncMock) as mock_log,
        ):
            resp = await rebalance(request, body, db_session)

        assert resp.status_code == 502
        # Audit logged with success=False
        mock_log.assert_called_once()
        call = mock_log.call_args
        # action is passed positionally as the 3rd arg
        assert call.args[2] == "rebalance_channel"
        assert call.kwargs["success"] is False

    @pytest.mark.asyncio
    async def test_rebalance_send_no_route_returns_400_with_friendly_msg(self, db_session):
        """A real-send failure that LND attributes to no-route gets a
        400 with a clear hint rather than a 502 + sanitized blob."""
        request = _mock_request()
        body = RebalanceRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
            fee_limit_sats=50,
            timeout_seconds=10,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch(
                "app.dashboard.api.lnd_service.create_invoice",
                new_callable=AsyncMock,
                return_value=(
                    {"payment_request": "lnbc1...", "r_hash": "YWJj", "add_index": "1"},
                    None,
                ),
            ),
            patch(
                "app.dashboard.api.lnd_service.send_payment_v2",
                new_callable=AsyncMock,
                return_value=(None, "FAILURE_REASON_NO_ROUTE"),
            ),
            patch("app.dashboard.api.log_dashboard_action", new_callable=AsyncMock),
        ):
            resp = await rebalance(request, body, db_session)
        assert resp.status_code == 400
        assert b"No route" in resp.body

    @pytest.mark.asyncio
    async def test_rebalance_invoice_mint_failure_returns_502(self, db_session):
        request = _mock_request()
        body = RebalanceRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
            fee_limit_sats=50,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch(
                "app.dashboard.api.lnd_service.create_invoice",
                new_callable=AsyncMock,
                return_value=(None, "LND unreachable"),
            ),
        ):
            resp = await rebalance(request, body, db_session)
        assert resp.status_code == 502


# ── Additional query_routes coverage ──────────────────────────────────


class TestQueryRoutesExtra:
    @pytest.mark.asyncio
    async def test_omits_optional_params_when_unset(self):
        """Without outgoing_chan_id, last_hop, or fee_limit we should
        send only ``final_cltv_delta`` so LND uses defaults."""
        svc = LNDService()
        captured: dict = {}

        async def fake_request(method, path, **kwargs):
            captured.update(kwargs)
            return (
                {
                    "routes": [
                        {
                            "total_amt": "1000",
                            "total_fees": "0",
                            "total_amt_msat": "1000000",
                            "total_fees_msat": "0",
                            "total_time_lock": 144,
                            "hops": [{}],
                        }
                    ]
                },
                None,
            )

        with patch.object(svc, "_request", side_effect=fake_request):
            quote, err = await svc.query_routes(dest_pubkey_hex="02" + "a" * 64, amount_sats=1_000)
        assert err is None and quote is not None
        params = captured["params"]
        assert "outgoing_chan_id" not in params
        assert "last_hop_pubkey" not in params
        assert "fee_limit.fixed" not in params
        assert params["final_cltv_delta"] == "144"

    @pytest.mark.asyncio
    async def test_request_error_propagates(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(None, "LND down"),
        ):
            quote, err = await svc.query_routes(dest_pubkey_hex="02" + "a" * 64, amount_sats=1_000)
        assert quote is None
        assert err == "LND down"

    @pytest.mark.asyncio
    async def test_ppm_uses_zero_fee(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(
                {
                    "routes": [
                        {
                            "total_amt": "1000",
                            "total_fees": "0",
                            "total_amt_msat": "1000000",
                            "total_fees_msat": "0",
                            "total_time_lock": 144,
                            "hops": [{}, {}],
                        }
                    ]
                },
                None,
            ),
        ):
            quote, err = await svc.query_routes(dest_pubkey_hex="02" + "a" * 64, amount_sats=1_000)
        assert err is None
        assert quote is not None
        assert quote["ppm"] == 0

    @pytest.mark.asyncio
    async def test_negative_fee_limit_skipped(self):
        """fee_limit_sats < 0 must not be forwarded as a parameter."""
        svc = LNDService()
        captured: dict = {}

        async def fake_request(method, path, **kwargs):
            captured.update(kwargs)
            return (
                {
                    "routes": [
                        {
                            "total_amt": "1000",
                            "total_fees": "0",
                            "total_amt_msat": "1000000",
                            "total_fees_msat": "0",
                            "total_time_lock": 144,
                            "hops": [{}],
                        }
                    ]
                },
                None,
            )

        with patch.object(svc, "_request", side_effect=fake_request):
            await svc.query_routes(
                dest_pubkey_hex="02" + "a" * 64,
                amount_sats=1_000,
                fee_limit_sats=-1,
            )
        assert "fee_limit.fixed" not in captured["params"]


# ── Additional send_payment_v2 coverage ───────────────────────────────


class TestSendPaymentV2Extra:
    @pytest.mark.asyncio
    async def test_skips_blank_lines_and_bad_json(self):
        """Streaming endpoint: empty lines and JSON-decode errors are
        ignored; we keep reading until a terminal status is found."""
        svc = LNDService()
        stream = _FakeStreamResponse(
            200,
            [
                "",
                "   ",
                "not-json",
                json.dumps({"result": {"status": "IN_FLIGHT"}}),
                json.dumps(
                    {
                        "result": {
                            "status": "SUCCEEDED",
                            "payment_hash": "YWJj",
                            "payment_preimage": "ZGVm",
                            "value_sat": "1000",
                            "fee_msat": "0",
                            "htlcs": [{"status": "SUCCEEDED", "route": {"hops": [{}]}}],
                        }
                    }
                ),
            ],
        )
        with patch.object(
            svc,
            "_get_client",
            new_callable=AsyncMock,
            return_value=_make_fake_client(stream),
        ):
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                fee_limit_sats=10,
                timeout_seconds=5,
            )
        assert err is None
        assert data is not None
        assert data["amount_sats"] == 1_000

    @pytest.mark.asyncio
    async def test_grpc_error_envelope(self):
        """``{"error": {...}}`` envelopes must surface as a clean error
        without retry."""
        svc = LNDService()
        stream = _FakeStreamResponse(
            200,
            [json.dumps({"error": {"message": "some grpc problem"}})],
        )
        with patch.object(
            svc,
            "_get_client",
            new_callable=AsyncMock,
            return_value=_make_fake_client(stream),
        ):
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                fee_limit_sats=10,
                timeout_seconds=5,
            )
        assert data is None
        assert err is not None and "grpc problem" in err

    @pytest.mark.asyncio
    async def test_no_terminal_status(self):
        """Stream ends without SUCCEEDED/FAILED: surface a clear error
        instead of returning a half-baked success."""
        svc = LNDService()
        stream = _FakeStreamResponse(
            200,
            [json.dumps({"result": {"status": "IN_FLIGHT"}})],
        )
        with patch.object(
            svc,
            "_get_client",
            new_callable=AsyncMock,
            return_value=_make_fake_client(stream),
        ):
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                fee_limit_sats=10,
                timeout_seconds=5,
            )
        assert data is None
        assert err is not None and "terminal" in err.lower()

    @pytest.mark.asyncio
    async def test_succeeded_without_htlcs_uses_fallback(self):
        svc = LNDService()
        stream = _FakeStreamResponse(
            200,
            [
                json.dumps(
                    {
                        "result": {
                            "status": "SUCCEEDED",
                            "payment_hash": "",
                            "payment_preimage": "",
                            "value_sat": "100",
                            "fee_msat": "0",
                            # no htlcs
                        }
                    }
                )
            ],
        )
        with patch.object(
            svc,
            "_get_client",
            new_callable=AsyncMock,
            return_value=_make_fake_client(stream),
        ):
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                fee_limit_sats=10,
                timeout_seconds=5,
            )
        assert err is None
        assert data is not None
        assert data["hops"] == 0
        assert data["fee_sats"] == 0

    @pytest.mark.asyncio
    async def test_breaker_open_returns_unavailable(self):
        """When the circuit breaker is open we must fast-fail with a
        friendly message and never touch the network."""
        from app.core.resilience import BreakerOpenError

        svc = LNDService()
        with (
            patch(
                "app.services.lnd_service._LND_BREAKER.before_call",
                new_callable=AsyncMock,
                side_effect=BreakerOpenError("open"),
            ),
            patch.object(svc, "_get_client", new_callable=AsyncMock) as mock_get,
        ):
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                fee_limit_sats=10,
                timeout_seconds=5,
            )
        assert data is None
        assert err is not None and "circuit breaker" in err.lower()
        mock_get.assert_not_called()

    @pytest.mark.asyncio
    async def test_connection_error_returned(self):
        """Network errors must surface as ``Connection failed`` rather
        than crash the request handler."""
        import httpx as _httpx

        svc = LNDService()

        class _BoomStream:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                raise _httpx.ConnectError("boom")

            async def __aexit__(self, *exc):
                return False

        client = MagicMock()
        client.stream = MagicMock(return_value=_BoomStream())
        with patch.object(
            svc,
            "_get_client",
            new_callable=AsyncMock,
            return_value=client,
        ):
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                fee_limit_sats=10,
                timeout_seconds=5,
            )
        assert data is None
        assert err is not None and "Connection failed" in err


# ── More endpoint paths ───────────────────────────────────────────────


class TestRebalanceQuoteEndpointExtra:
    @pytest.mark.asyncio
    async def test_resolve_error_returns_400(self):
        body = RebalanceQuoteRequest(
            source_chan_id="111",
            dest_chan_id="111",  # same id ⇒ rejected before any LND call
            amount_sats=1_000,
        )
        resp = await rebalance_quote(body)
        assert resp.status_code == 400
        assert b"differ" in resp.body

    @pytest.mark.asyncio
    async def test_get_info_failure_returns_502(self):
        body = RebalanceQuoteRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_info",
                new_callable=AsyncMock,
                return_value=(None, "no info"),
            ),
        ):
            resp = await rebalance_quote(body)
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_amount_exceeds_max_receivable(self):
        # Force max-sendable >> amount but max-receivable < amount.
        chans = _channels_fixture()
        # Pump dest local so receivable shrinks.
        chans[1]["remote_balance"] = 500
        body = RebalanceQuoteRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(chans, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_info",
                new_callable=AsyncMock,
                return_value=({"identity_pubkey": "02" + "f" * 64}, None),
            ),
        ):
            resp = await rebalance_quote(body)
        assert resp.status_code == 400
        assert b"max receivable" in resp.body


class TestRebalanceEndpointExtra:
    @pytest.mark.asyncio
    async def test_dashboard_payment_limit_blocks(self, db_session):
        """When ``DASHBOARD_MAX_PAYMENT_SATS`` is set, exceeding it
        raises 400 *before* we touch LND."""
        request = _mock_request()
        body = RebalanceRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
            fee_limit_sats=50,
        )
        with (
            patch.object(settings, "dashboard_max_payment_sats", 100),
            patch("app.dashboard.api.lnd_service.get_channels", new_callable=AsyncMock) as mock_chans,
        ):
            from fastapi import HTTPException

            with pytest.raises(HTTPException) as exc:
                await rebalance(request, body, db_session)
            assert exc.value.status_code == 400
            mock_chans.assert_not_called()

    @pytest.mark.asyncio
    async def test_resolve_error_returns_400_no_lnd_calls(self, db_session):
        request = _mock_request()
        body = RebalanceRequest(
            source_chan_id="111",
            dest_chan_id="111",  # same → rejected
            amount_sats=10_000,
            fee_limit_sats=50,
        )
        with (
            patch("app.dashboard.api.lnd_service.create_invoice", new_callable=AsyncMock) as mock_inv,
            patch("app.dashboard.api.lnd_service.send_payment_v2", new_callable=AsyncMock) as mock_send,
        ):
            resp = await rebalance(request, body, db_session)
        assert resp.status_code == 400
        mock_inv.assert_not_called()
        mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_amount_exceeds_max_sendable_no_lnd_calls(self, db_session):
        request = _mock_request()
        body = RebalanceRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000_000,  # absurd
            fee_limit_sats=50,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch("app.dashboard.api.lnd_service.create_invoice", new_callable=AsyncMock) as mock_inv,
            patch("app.dashboard.api.lnd_service.send_payment_v2", new_callable=AsyncMock) as mock_send,
        ):
            resp = await rebalance(request, body, db_session)
        assert resp.status_code == 400
        assert b"max sendable" in resp.body
        mock_inv.assert_not_called()
        mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_amount_exceeds_max_receivable_no_lnd_calls(self, db_session):
        request = _mock_request()
        body = RebalanceRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
            fee_limit_sats=50,
        )
        chans = _channels_fixture()
        chans[1]["remote_balance"] = 500  # tiny inbound
        with (
            patch("app.dashboard.api.lnd_service.get_channels", new_callable=AsyncMock, return_value=(chans, None)),
            patch("app.dashboard.api.lnd_service.create_invoice", new_callable=AsyncMock) as mock_inv,
            patch("app.dashboard.api.lnd_service.send_payment_v2", new_callable=AsyncMock) as mock_send,
        ):
            resp = await rebalance(request, body, db_session)
        assert resp.status_code == 400
        assert b"max receivable" in resp.body
        mock_inv.assert_not_called()
        mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_channels_error_returns_400(self, db_session):
        request = _mock_request()
        body = RebalanceRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
            fee_limit_sats=50,
        )
        with patch(
            "app.dashboard.api.lnd_service.get_channels", new_callable=AsyncMock, return_value=(None, "LND down")
        ):
            resp = await rebalance(request, body, db_session)
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_happy_path_writes_audit_with_full_metadata(self, db_session):
        """Real-DB happy path: audit row exists with success=True and
        the JSON details we expect."""
        from sqlalchemy import select

        # Sentinel APIKey row required by the FK on AuditLog.
        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.api_key import APIKey

        existing = await db_session.get(APIKey, DASHBOARD_KEY_ID)
        if existing is None:
            db_session.add(
                APIKey(
                    id=DASHBOARD_KEY_ID,
                    name="__dashboard__",
                    key_hash="dashboard-sentinel",
                    is_admin=True,
                    is_active=True,
                )
            )
            await db_session.commit()

        request = _mock_request()
        body = RebalanceRequest(
            source_chan_id="111",
            dest_chan_id="222",
            amount_sats=10_000,
            fee_limit_sats=50,
            timeout_seconds=10,
        )
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(_channels_fixture(), None),
            ),
            patch(
                "app.dashboard.api.lnd_service.create_invoice",
                new_callable=AsyncMock,
                return_value=({"payment_request": "lnbc1...", "r_hash": "YWJj", "add_index": "1"}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.send_payment_v2",
                new_callable=AsyncMock,
                return_value=(
                    {
                        "payment_hash": "abc",
                        "payment_preimage": "def",
                        "amount_sats": 10_000,
                        "fee_sats": 1,
                        "fee_msat": 1_000,
                        "hops": 2,
                        "duration_ms": 500,
                    },
                    None,
                ),
            ),
        ):
            resp = await rebalance(request, body, db_session)
        assert isinstance(resp, dict) and resp["ok"] is True

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "rebalance_channel"))).scalars().all()
        )
        assert len(rows) == 1
        row = rows[0]
        assert row.success is True
        assert row.amount_sats == 10_000
        assert row.api_key_name == "__dashboard__"
        d = row.details or {}
        assert d["source_chan_id"] == "111"
        assert d["dest_chan_id"] == "222"
        assert d["fee_sats"] == 1
        assert d["hops"] == 2
        assert d["duration_ms"] == 500


# ── Recent endpoint (real DB) ─────────────────────────────────────────


async def _ensure_dashboard_key(db_session) -> None:
    from app.dashboard import DASHBOARD_KEY_ID

    if await db_session.get(APIKey, DASHBOARD_KEY_ID) is None:
        db_session.add(
            APIKey(
                id=DASHBOARD_KEY_ID,
                name="__dashboard__",
                key_hash="dashboard-sentinel",
                is_admin=True,
                is_active=True,
            )
        )
        await db_session.commit()


class TestRebalanceRecent:
    @pytest.mark.asyncio
    async def test_returns_only_successful_rebalance_rows_newest_first(self, db_session):
        """``/rebalance/recent`` must filter ``action=rebalance_channel
        AND success=True`` and order by ``created_at`` desc."""
        from app.dashboard import DASHBOARD_KEY_ID
        from app.services.audit_service import log_dashboard_action

        await _ensure_dashboard_key(db_session)

        # Three rebalance rows + one unrelated action.
        await log_dashboard_action(
            db_session,
            DASHBOARD_KEY_ID,
            "rebalance_channel",
            "channel",
            amount_sats=1_000,
            success=True,
            details={
                "source_chan_id": "111",
                "dest_chan_id": "222",
                "fee_sats": 1,
                "hops": 2,
                "source_alias": "a",
                "dest_alias": "b",
            },
        )
        await log_dashboard_action(
            db_session,
            DASHBOARD_KEY_ID,
            "rebalance_channel",
            "channel",
            amount_sats=2_000,
            success=False,
            error_message="NO_ROUTE",
            details={"source_chan_id": "333", "dest_chan_id": "444"},
        )
        await log_dashboard_action(
            db_session,
            DASHBOARD_KEY_ID,
            "rebalance_channel",
            "channel",
            amount_sats=3_000,
            success=True,
            details={
                "source_chan_id": "555",
                "dest_chan_id": "666",
                "fee_sats": 5,
                "hops": 4,
                "source_alias": "c",
                "dest_alias": "d",
            },
        )
        await log_dashboard_action(
            db_session,
            DASHBOARD_KEY_ID,
            "open_channel",
            "channel",
            amount_sats=99,
            success=True,
        )
        await db_session.commit()

        resp = await rebalance_recent(limit=5, db=db_session)
        items = resp["rebalances"]
        assert len(items) == 2
        # Newest first
        assert items[0]["amount_sats"] == 3_000
        assert items[1]["amount_sats"] == 1_000
        # Filtered to successful rebalances only
        for it in items:
            assert it["amount_sats"] != 2_000
        # Details surfaced into top-level response
        assert items[0]["fee_sats"] == 5
        assert items[0]["hops"] == 4
        assert items[0]["source_alias"] == "c"

    @pytest.mark.asyncio
    async def test_respects_limit(self, db_session):
        from app.dashboard import DASHBOARD_KEY_ID
        from app.services.audit_service import log_dashboard_action

        await _ensure_dashboard_key(db_session)

        for i in range(4):
            await log_dashboard_action(
                db_session,
                DASHBOARD_KEY_ID,
                "rebalance_channel",
                "channel",
                amount_sats=1_000 + i,
                success=True,
                details={"source_chan_id": str(i), "dest_chan_id": str(i + 1)},
            )
        await db_session.commit()

        resp = await rebalance_recent(limit=2, db=db_session)
        assert len(resp["rebalances"]) == 2

    @pytest.mark.asyncio
    async def test_handles_missing_details(self, db_session):
        """Older audit rows with ``details=None`` must not crash the
        endpoint."""
        from app.dashboard import DASHBOARD_KEY_ID
        from app.services.audit_service import log_dashboard_action

        await _ensure_dashboard_key(db_session)
        await log_dashboard_action(
            db_session,
            DASHBOARD_KEY_ID,
            "rebalance_channel",
            "channel",
            amount_sats=42,
            success=True,
            details=None,
        )
        await db_session.commit()

        resp = await rebalance_recent(limit=5, db=db_session)
        assert len(resp["rebalances"]) == 1
        item = resp["rebalances"][0]
        assert item["amount_sats"] == 42
        assert item["fee_sats"] is None
        assert item["hops"] is None

    @pytest.mark.asyncio
    async def test_empty_db_returns_empty_list(self, db_session):
        resp = await rebalance_recent(limit=5, db=db_session)
        assert resp == {"rebalances": []}


# ── Final edge cases ──────────────────────────────────────────────────


class TestResolveRebalanceChannelsExtra:
    @pytest.mark.asyncio
    async def test_dest_not_found(self):
        with patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=(_channels_fixture(), None),
        ):
            _, _, err = await _resolve_rebalance_channels("111", "999")
        assert err is not None and "Destination" in err and "not found" in err

    @pytest.mark.asyncio
    async def test_inactive_dest_rejected(self):
        with patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=(_channels_fixture(), None),
        ):
            # 333 is inactive in the fixture. Use 111 as src.
            _, _, err = await _resolve_rebalance_channels("111", "333")
        assert err is not None and "Destination" in err and "inactive" in err.lower()

    @pytest.mark.asyncio
    async def test_get_channels_returns_none_handled(self):
        with patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=(None, None),
        ):
            src, dst, err = await _resolve_rebalance_channels("111", "222")
        assert src is None and dst is None
        # Error is sanitized (raw upstream message hidden by
        # sanitize_upstream_error). What matters is that we get *an*
        # error back instead of crashing.
        assert err is not None and "lnd" in err.lower()


class TestSendPaymentV2EdgeCases:
    @pytest.mark.asyncio
    async def test_unexpected_exception_returned(self):
        """Any non-httpx exception during the stream becomes a clean
        ``Request failed`` error rather than a 500."""
        svc = LNDService()

        class _BadStream:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                raise RuntimeError("kaboom")

            async def __aexit__(self, *exc):
                return False

        client = MagicMock()
        client.stream = MagicMock(return_value=_BadStream())
        with patch.object(
            svc,
            "_get_client",
            new_callable=AsyncMock,
            return_value=client,
        ):
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                fee_limit_sats=10,
                timeout_seconds=5,
            )
        assert data is None
        assert err is not None and "Request failed" in err

    @pytest.mark.asyncio
    async def test_request_body_pins_routing_constraints(self):
        """Verify the request body sent to ``/v2/router/send`` carries
        ``outgoing_chan_id``, base64 ``last_hop_pubkey``, and
        ``allow_self_payment``."""
        svc = LNDService()
        captured: dict = {}

        class _CapturingStream:
            def __init__(self, *args, **kwargs):
                captured["args"] = args
                captured["kwargs"] = kwargs

            async def __aenter__(self):
                return _FakeStreamResponse(
                    200,
                    [
                        json.dumps(
                            {
                                "result": {
                                    "status": "SUCCEEDED",
                                    "value_sat": "1000",
                                    "fee_msat": "0",
                                    "htlcs": [{"status": "SUCCEEDED", "route": {"hops": [{}]}}],
                                }
                            }
                        )
                    ],
                )

            async def __aexit__(self, *exc):
                return False

        client = MagicMock()
        client.stream = MagicMock(side_effect=_CapturingStream)
        with patch.object(
            svc,
            "_get_client",
            new_callable=AsyncMock,
            return_value=client,
        ):
            data, err = await svc.send_payment_v2(
                payment_request="lnbc1...",
                outgoing_chan_id="111",
                last_hop_pubkey_hex="03" + "b" * 64,
                fee_limit_sats=25,
                timeout_seconds=7,
            )
        assert err is None and data is not None
        body = captured["kwargs"]["json"]
        assert body["payment_request"] == "lnbc1..."
        # First-hop pin uses the repeated ``outgoing_chan_ids`` field (the
        # singular is rejected by LND's REST gateway), and forces single-path.
        assert body["outgoing_chan_ids"] == ["111"]
        assert "outgoing_chan_id" not in body
        assert body["max_parts"] == 1
        assert body["fee_limit_sat"] == "25"
        assert body["timeout_seconds"] == 7
        assert body["allow_self_payment"] is True
        assert body["no_inflight_updates"] is True
        # last_hop encoded as base64 of the hex bytes
        expected = base64.b64encode(bytes.fromhex("03" + "b" * 64)).decode("ascii")
        assert body["last_hop_pubkey"] == expected
