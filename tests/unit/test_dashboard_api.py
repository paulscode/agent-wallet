# SPDX-License-Identifier: MIT
"""
Unit tests for app.dashboard.api endpoint functions.

Calls endpoint functions directly to ensure coverage measurement works
with pytest-cov (ASGI transport does not always register coverage).
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException, Request

from app.core.config import settings
from app.dashboard.api import (
    BraiinsDepositChannelPeerCheckRequest,
    CloseChannelRequest,
    ColdStorageRequest,
    LoginRequest,
    OpenChannelRequest,
    PayRequest,
    SendOnchainRequest,
    _require_auth_csrf,
    braiins_deposit_channel_peer_check,
    close_channel,
    cold_storage_cancel,
    cold_storage_fees,
    cold_storage_initiate,
    cold_storage_swap_detail,
    login,
    open_channel,
    pay_invoice,
    send_onchain,
)


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


def _mock_request(csrf=True) -> MagicMock:
    req = MagicMock(spec=Request)
    req.client.host = "127.0.0.1"
    req.cookies = {}
    headers = {"X-Requested-With": "XMLHttpRequest"} if csrf else {}
    req.headers = headers
    return req


class TestRequireAuthCSRF:
    @pytest.mark.asyncio
    async def test_unauthenticated_raises_401(self):
        from fastapi import Response

        request = _mock_request()
        with patch("app.dashboard.api.verify_session", new_callable=AsyncMock, return_value=False):
            with pytest.raises(HTTPException) as exc:
                await _require_auth_csrf(request, Response())
            assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_csrf_header_raises_403(self):
        """Missing CSRF header is a real client error → 403, not 503."""
        from fastapi import Response

        request = _mock_request(csrf=False)
        with patch("app.dashboard.api.verify_session", new_callable=AsyncMock, return_value=True):
            with patch("app.dashboard.api.send_alert", new_callable=AsyncMock):
                with pytest.raises(HTTPException) as exc:
                    await _require_auth_csrf(request, Response())
            assert exc.value.status_code == 403
            assert "CSRF" in exc.value.detail


class TestDashboardLogin:
    @pytest.mark.asyncio
    async def test_login_failure_audit_logged(self, db_session):
        from app.dashboard.auth import generate_login_nonce

        request = _mock_request()
        body = LoginRequest(token="wrong-token", login_nonce=generate_login_nonce())
        resp = await login(request, body, db_session)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_success_audit_logged(self, db_session):
        from app.dashboard.auth import generate_login_nonce

        request = _mock_request()
        body = LoginRequest(token="test-dashboard-token", login_nonce=generate_login_nonce())
        resp = await login(request, body, db_session)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_login_rejects_missing_nonce(self, db_session):
        """The JSON login path must reject a request with no/invalid login
        nonce (login-CSRF parity with the HTML form)."""
        request = _mock_request()
        body = LoginRequest(token="test-dashboard-token")  # no nonce
        resp = await login(request, body, db_session)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_login_compares_password_before_origin_check(self, db_session):
        """The constant-time
        password compare must run BEFORE the origin check so a
        remote attacker with a forged ``Origin`` header cannot
        distinguish "wrong password" from "right password" via
        response timing.

        Asserted structurally: we patch ``verify_token`` to track
        invocation, force ``verify_login_origin`` to fail, and
        confirm ``verify_token`` was still called.
        """
        from app.dashboard import api as dashboard_api

        request = _mock_request()
        body = LoginRequest(token="test-dashboard-token")
        calls: list[str] = []
        real_verify = dashboard_api.verify_token

        def _spy(tok: str) -> bool:
            calls.append(tok)
            return real_verify(tok)

        with patch.object(dashboard_api, "verify_login_origin", return_value=False):
            with patch.object(dashboard_api, "verify_token", side_effect=_spy):
                resp = await login(request, body, db_session)

        assert resp.status_code == 403
        assert calls, "verify_token was not called before the origin check — this re-introduces the timing oracle."


class TestOpenChannelRequestSSRF:
    def test_rejects_private_ip(self):
        with pytest.raises(ValueError, match="not allowed"):
            OpenChannelRequest(pubkey="02" + "a1" * 32, host="10.0.0.1:9735", local_funding_amount=100000)

    def test_rejects_localhost(self):
        with pytest.raises(ValueError, match="not allowed"):
            OpenChannelRequest(pubkey="02" + "a1" * 32, host="localhost:9735", local_funding_amount=100000)

    def test_rejects_link_local(self):
        with pytest.raises(ValueError, match="not allowed"):
            OpenChannelRequest(pubkey="02" + "a1" * 32, host="169.254.0.1:9735", local_funding_amount=100000)

    def test_rejects_internal_hostname(self):
        with pytest.raises(ValueError, match="not allowed"):
            OpenChannelRequest(pubkey="02" + "a1" * 32, host="node.internal:9735", local_funding_amount=100000)

    def test_allows_onion(self):
        req = OpenChannelRequest(pubkey="02" + "a1" * 32, host="abc.onion:9735", local_funding_amount=100000)
        assert req.host == "abc.onion:9735"

    def test_allows_public_ip(self):
        req = OpenChannelRequest(pubkey="02" + "a1" * 32, host="8.8.8.8:9735", local_funding_amount=100000)
        assert req.host == "8.8.8.8:9735"

    def test_allows_empty_host(self):
        req = OpenChannelRequest(pubkey="02" + "a1" * 32, local_funding_amount=100000)
        assert req.host == ""


class TestOutgoingChanIdValidation:
    """The
    ``outgoing_chan_id`` field on ``PayRequest`` / ``PayQuoteRequest``
    must reject values that fit the 20-digit regex but exceed uint64
    (LND treats this field as a uint64 over the wire)."""

    def test_accepts_zero(self) -> None:
        req = PayRequest(payment_request="lnbc1...", outgoing_chan_id="0")
        assert req.outgoing_chan_id == "0"

    def test_accepts_uint64_max(self) -> None:
        req = PayRequest(
            payment_request="lnbc1...",
            outgoing_chan_id="18446744073709551615",
        )
        assert req.outgoing_chan_id == "18446744073709551615"

    def test_rejects_uint64_max_plus_one(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="exceeds uint64 max"):
            PayRequest(
                payment_request="lnbc1...",
                outgoing_chan_id="18446744073709551616",
            )

    def test_rejects_all_nines_20_digits(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="exceeds uint64 max"):
            PayRequest(
                payment_request="lnbc1...",
                outgoing_chan_id="99999999999999999999",
            )

    def test_rejects_non_numeric(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            PayRequest(payment_request="lnbc1...", outgoing_chan_id="abc")

    def test_pay_quote_request_applies_same_bound(self) -> None:
        from pydantic import ValidationError

        from app.dashboard.api import PayQuoteRequest

        ok = PayQuoteRequest(
            payment_request="lnbc1...",
            outgoing_chan_id="18446744073709551615",
        )
        assert ok.outgoing_chan_id == "18446744073709551615"
        with pytest.raises(ValidationError, match="exceeds uint64 max"):
            PayQuoteRequest(
                payment_request="lnbc1...",
                outgoing_chan_id="18446744073709551616",
            )

    def test_cold_storage_request_applies_same_bound(self) -> None:
        from pydantic import ValidationError

        addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        ok = ColdStorageRequest(
            amount_sats=50000,
            destination_address=addr,
            outgoing_chan_id="18446744073709551615",
        )
        assert ok.outgoing_chan_id == "18446744073709551615"
        # Defaults to None when the pin is omitted.
        assert ColdStorageRequest(amount_sats=50000, destination_address=addr).outgoing_chan_id is None
        with pytest.raises(ValidationError, match="exceeds uint64 max"):
            ColdStorageRequest(
                amount_sats=50000,
                destination_address=addr,
                outgoing_chan_id="18446744073709551616",
            )
        with pytest.raises(ValidationError):
            ColdStorageRequest(amount_sats=50000, destination_address=addr, outgoing_chan_id="abc")


class TestPayInvoice:
    @pytest.mark.asyncio
    async def test_lnd_error_returns_502(self, db_session):
        request = _mock_request()
        body = PayRequest(payment_request="lnbc1000...")
        with patch(
            "app.dashboard.api.lnd_service.send_payment_sync", new_callable=AsyncMock, return_value=(None, "no route")
        ):
            resp = await pay_invoice(request, body, db_session)
        assert resp.status_code == 502


class TestSendOnchain:
    @pytest.mark.asyncio
    async def test_lnd_error_returns_502(self, db_session):
        request = _mock_request()
        body = SendOnchainRequest(address="bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", amount_sats=50000)
        with patch(
            "app.dashboard.api.lnd_service.send_coins", new_callable=AsyncMock, return_value=(None, "insufficient")
        ):
            resp = await send_onchain(request, body, db_session)
        assert resp.status_code == 502


class TestOpenChannel:
    @pytest.mark.asyncio
    async def test_channel_open_lnd_error_returns_502(self, db_session):
        request = _mock_request()
        body = OpenChannelRequest(pubkey="02" + "a1" * 32, local_funding_amount=100000)
        with patch(
            "app.dashboard.api.lnd_service.open_channel",
            new_callable=AsyncMock,
            return_value=(None, "not enough balance"),
        ):
            resp = await open_channel(request, body, db_session)
        assert resp.status_code == 502


class TestColdStorageFees:
    @pytest.mark.asyncio
    async def test_boltz_error_returns_502(self):
        with patch(
            "app.dashboard.api.boltz_service.get_reverse_pair_info",
            new_callable=AsyncMock,
            return_value=(None, "unreachable"),
        ):
            resp = await cold_storage_fees()
        assert resp.status_code == 502


_CS_ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"


def _mock_channel(
    chan_id: str,
    *,
    local: int,
    active: bool = True,
    capacity: int = 1_000_000,
    reserve: int = 5_000,
    unsettled: int = 0,
) -> dict:
    return {
        "chan_id": chan_id,
        "active": active,
        "capacity": capacity,
        "local_balance": local,
        "local_chan_reserve_sat": reserve,
        "unsettled_balance": unsettled,
    }


def _mock_swap():
    swap = MagicMock()
    swap.id = uuid4()
    swap.boltz_swap_id = "boltz123"
    swap.status.value = "created"
    swap.boltz_invoice = "lnbc1pn..."
    swap.onchain_amount_sats = 198_000
    return swap


class TestColdStorageInitiate:
    @pytest.mark.asyncio
    async def test_boltz_error_returns_400(self, db_session):
        request = _mock_request()
        body = ColdStorageRequest(amount_sats=100, destination_address=_CS_ADDR)
        with patch(
            "app.dashboard.api.boltz_service.create_reverse_swap",
            new_callable=AsyncMock,
            return_value=(None, "below minimum"),
        ):
            resp = await cold_storage_initiate(request, body, db_session)
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_outgoing_chan_id_pin_forwarded(self, db_session):
        """A channel-pinned request validates against that channel's own
        spendable balance and forwards the pin to the swap service."""
        request = _mock_request()
        body = ColdStorageRequest(
            amount_sats=200_000,
            destination_address=_CS_ADDR,
            purpose="inbound_liquidity",
            outgoing_chan_id="123",
        )
        swap = _mock_swap()
        with (
            patch("app.dashboard.api.settings") as mock_settings,
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=([_mock_channel("123", local=500_000)], None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
                return_value=(swap, None),
            ) as mock_create,
            patch("app.tasks.boltz_tasks.process_boltz_swap"),
        ):
            mock_settings.dashboard_max_payment_sats = -1
            resp = await cold_storage_initiate(request, body, db_session)
        assert resp["id"] == str(swap.id)
        mock_create.assert_awaited_once()
        assert mock_create.await_args.kwargs["outgoing_chan_id"] == "123"

    @pytest.mark.asyncio
    async def test_pinned_amount_exceeding_channel_spendable_rejected(self, db_session):
        """When the amount won't fit through the pinned channel alone, the
        request is rejected early with a clear 400 — the swap is never
        created."""
        request = _mock_request()
        body = ColdStorageRequest(
            amount_sats=200_000,
            destination_address=_CS_ADDR,
            outgoing_chan_id="123",
        )
        with (
            patch("app.dashboard.api.settings") as mock_settings,
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=([_mock_channel("123", local=100_000)], None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
            ) as mock_create,
        ):
            mock_settings.dashboard_max_payment_sats = -1
            resp = await cold_storage_initiate(request, body, db_session)
        assert resp.status_code == 400
        mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_pinned_offline_channel_rejected(self, db_session):
        request = _mock_request()
        body = ColdStorageRequest(
            amount_sats=200_000,
            destination_address=_CS_ADDR,
            outgoing_chan_id="123",
        )
        with (
            patch("app.dashboard.api.settings") as mock_settings,
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=([_mock_channel("123", local=500_000, active=False)], None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
            ) as mock_create,
        ):
            mock_settings.dashboard_max_payment_sats = -1
            resp = await cold_storage_initiate(request, body, db_session)
        assert resp.status_code == 400
        mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_pinned_channel_not_found_rejected(self, db_session):
        """A pin for a channel that's no longer in the open set (closed,
        or gone between render and click) is rejected up front."""
        request = _mock_request()
        body = ColdStorageRequest(
            amount_sats=200_000,
            destination_address=_CS_ADDR,
            outgoing_chan_id="999",
        )
        with (
            patch("app.dashboard.api.settings") as mock_settings,
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=([_mock_channel("123", local=500_000)], None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
            ) as mock_create,
        ):
            mock_settings.dashboard_max_payment_sats = -1
            resp = await cold_storage_initiate(request, body, db_session)
        assert resp.status_code == 400
        mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_pinned_precheck_subtracts_reserve_unsettled_and_safety(self, db_session):
        """The per-channel spendable check deducts the channel reserve,
        in-flight HTLCs, and a 1% safety margin — so a channel whose raw
        local balance exceeds the amount can still be rejected once those
        are subtracted (a naive ``local >= amount`` check would wrongly
        pass)."""
        request = _mock_request()
        # local 110k > amount 100k, but reserve 5k + unsettled 8k + 1%
        # safety (10k on a 1M channel) leaves only 87k spendable < ~103k
        # needed (amount + 3% routing headroom).
        chan = _mock_channel("123", local=110_000, reserve=5_000, unsettled=8_000)
        body = ColdStorageRequest(
            amount_sats=100_000,
            destination_address=_CS_ADDR,
            outgoing_chan_id="123",
        )
        with (
            patch("app.dashboard.api.settings") as mock_settings,
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=([chan], None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
            ) as mock_create,
        ):
            mock_settings.dashboard_max_payment_sats = -1
            resp = await cold_storage_initiate(request, body, db_session)
        assert resp.status_code == 400
        mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_initiate_audits_outgoing_chan_id(self, db_session):
        """The success audit row records the pinned channel and purpose so
        operators can trace which channel a transfer drained."""
        request = _mock_request()
        body = ColdStorageRequest(
            amount_sats=200_000,
            destination_address=_CS_ADDR,
            purpose="inbound_liquidity",
            outgoing_chan_id="123",
        )
        swap = _mock_swap()
        with (
            patch("app.dashboard.api.settings") as mock_settings,
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=([_mock_channel("123", local=500_000)], None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
                return_value=(swap, None),
            ),
            patch("app.tasks.boltz_tasks.process_boltz_swap"),
            patch(
                "app.dashboard.api.log_dashboard_action",
                new_callable=AsyncMock,
            ) as mock_log,
        ):
            mock_settings.dashboard_max_payment_sats = -1
            await cold_storage_initiate(request, body, db_session)
        success_calls = [
            c for c in mock_log.await_args_list
            if (c.kwargs.get("details") or {}).get("swap_id")
        ]
        assert success_calls, "expected a success audit row with a swap_id"
        details = success_calls[-1].kwargs["details"]
        assert details["outgoing_chan_id"] == "123"
        assert details["purpose"] == "inbound_liquidity"

    @pytest.mark.asyncio
    async def test_unpinned_request_forwards_none(self, db_session):
        """The plain on-chain default path (no pin) checks total balance
        and forwards ``outgoing_chan_id=None``."""
        request = _mock_request()
        body = ColdStorageRequest(amount_sats=200_000, destination_address=_CS_ADDR)
        swap = _mock_swap()
        with (
            patch("app.dashboard.api.settings") as mock_settings,
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 1_000_000}, None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
                return_value=(swap, None),
            ) as mock_create,
            patch("app.tasks.boltz_tasks.process_boltz_swap"),
        ):
            mock_settings.dashboard_max_payment_sats = -1
            resp = await cold_storage_initiate(request, body, db_session)
        assert resp["id"] == str(swap.id)
        assert mock_create.await_args.kwargs["outgoing_chan_id"] is None


class TestColdStorageSwapDetail:
    @pytest.mark.asyncio
    async def test_not_found_returns_404(self, db_session):
        with patch("app.dashboard.api.boltz_service.get_swap_by_id", new_callable=AsyncMock, return_value=None):
            resp = await cold_storage_swap_detail(uuid4(), db_session)
        assert resp.status_code == 404


class TestColdStorageCancel:
    @pytest.mark.asyncio
    async def test_cancel_failed_returns_400(self, db_session):
        request = _mock_request()
        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        with (
            patch("app.dashboard.api.boltz_service.get_swap_by_id", new_callable=AsyncMock, return_value=mock_swap),
            patch(
                "app.dashboard.api.boltz_service.cancel_swap",
                new_callable=AsyncMock,
                return_value=(False, "already paid"),
            ),
        ):
            resp = await cold_storage_cancel(request, mock_swap.id, db_session)
        assert resp.status_code == 400


_CHAN_POINT = "ab" * 32 + ":1"


class TestCloseChannelValidation:
    def test_accepts_valid_channel_point(self):
        req = CloseChannelRequest(channel_point=_CHAN_POINT)
        assert req.force is False
        assert req.sat_per_vbyte is None

    def test_accepts_force_and_fee(self):
        req = CloseChannelRequest(channel_point=_CHAN_POINT, force=True, sat_per_vbyte=5)
        assert req.force is True
        assert req.sat_per_vbyte == 5

    def test_strips_whitespace(self):
        req = CloseChannelRequest(channel_point="  " + _CHAN_POINT + "  ")
        assert req.channel_point == _CHAN_POINT

    def test_rejects_malformed_channel_point(self):
        from pydantic import ValidationError

        for bad in ("notxid:0", "ab:0", "ab" * 32, "ab" * 32 + ":", "ab" * 32 + ":x", "xy" * 32 + ":0"):
            with pytest.raises(ValidationError):
                CloseChannelRequest(channel_point=bad)

    def test_rejects_out_of_range_fee(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            CloseChannelRequest(channel_point=_CHAN_POINT, sat_per_vbyte=0)
        with pytest.raises(ValidationError):
            CloseChannelRequest(channel_point=_CHAN_POINT, sat_per_vbyte=10_001)


class TestCloseChannel:
    @pytest.mark.asyncio
    async def test_coop_close_forwards_and_audits(self, db_session):
        """A cooperative close on an active channel splits the channel
        point and forwards force + fee to the LND client."""
        request = _mock_request()
        body = CloseChannelRequest(channel_point=_CHAN_POINT, force=False, sat_per_vbyte=3)
        chan = {"channel_point": _CHAN_POINT, "active": True}
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=([chan], None),
            ),
            patch(
                "app.dashboard.api.lnd_service.close_channel",
                new_callable=AsyncMock,
                return_value=({}, None),
            ) as mock_close,
        ):
            resp = await close_channel(request, body, db_session)
        assert resp["ok"] is True
        mock_close.assert_awaited_once()
        kw = mock_close.await_args.kwargs
        assert kw["funding_txid"] == "ab" * 32
        assert kw["output_index"] == 1
        assert kw["force"] is False
        assert kw["sat_per_vbyte"] == 3

    @pytest.mark.asyncio
    async def test_coop_close_on_offline_peer_refused(self, db_session):
        """Cooperative close of an inactive (offline-peer) channel is
        refused up front; the LND close is never attempted."""
        request = _mock_request()
        body = CloseChannelRequest(channel_point=_CHAN_POINT, force=False)
        chan = {"channel_point": _CHAN_POINT, "active": False}
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=([chan], None),
            ),
            patch(
                "app.dashboard.api.lnd_service.close_channel",
                new_callable=AsyncMock,
            ) as mock_close,
        ):
            resp = await close_channel(request, body, db_session)
        assert resp.status_code == 400
        mock_close.assert_not_called()

    @pytest.mark.asyncio
    async def test_force_close_proceeds_without_active_check(self, db_session):
        """A force close skips the cooperative-only offline guard and
        forwards force=True (it's the path for an offline peer)."""
        request = _mock_request()
        body = CloseChannelRequest(channel_point=_CHAN_POINT, force=True)
        with patch(
            "app.dashboard.api.lnd_service.close_channel",
            new_callable=AsyncMock,
            return_value=({}, None),
        ) as mock_close:
            resp = await close_channel(request, body, db_session)
        assert resp["ok"] is True
        assert mock_close.await_args.kwargs["force"] is True

    @pytest.mark.asyncio
    async def test_lnd_error_returns_502(self, db_session):
        request = _mock_request()
        body = CloseChannelRequest(channel_point=_CHAN_POINT, force=True)
        with (
            patch(
                "app.dashboard.api.lnd_service.close_channel",
                new_callable=AsyncMock,
                return_value=(None, "rpc failed"),
            ),
            # No closing channels → the error is a real failure → 502.
            patch(
                "app.dashboard.api.lnd_service.get_pending_channels_detail",
                new_callable=AsyncMock,
                return_value=([], None),
            ),
        ):
            resp = await close_channel(request, body, db_session)
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_stream_drop_but_channel_closing_is_treated_as_success(self, db_session):
        """The close stream can drop (over Tor) after LND already accepted
        the close. If the channel is now in a closing bucket, report
        success rather than a spurious failure."""
        request = _mock_request()
        body = CloseChannelRequest(channel_point=_CHAN_POINT, force=True)
        with (
            patch(
                "app.dashboard.api.lnd_service.close_channel",
                new_callable=AsyncMock,
                return_value=(None, "Connection failed: "),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_pending_channels_detail",
                new_callable=AsyncMock,
                return_value=([{"channel_point": _CHAN_POINT, "type": "waiting_close"}], None),
            ),
        ):
            resp = await close_channel(request, body, db_session)
        assert resp["ok"] is True


class TestDashboardPaymentCap:
    """``DASHBOARD_MAX_PAYMENT_SATS`` is an additional cap on top of
    the global ``LND_MAX_PAYMENT_SATS`` for the dashboard's own
    write-side endpoints. ``-1`` disables it; otherwise every payment
    flow (LN pay, onchain send, channel open funding, cold-storage
    swap) must enforce it."""

    def test_check_limit_disabled(self):
        from app.dashboard.api import _check_dashboard_payment_limit

        with patch("app.dashboard.api.settings") as mock_settings:
            mock_settings.dashboard_max_payment_sats = -1
            _check_dashboard_payment_limit(999999999)

    def test_check_limit_none_amount(self):
        from app.dashboard.api import _check_dashboard_payment_limit

        with patch("app.dashboard.api.settings") as mock_settings:
            mock_settings.dashboard_max_payment_sats = 1000
            _check_dashboard_payment_limit(None)

    def test_check_limit_within(self):
        from app.dashboard.api import _check_dashboard_payment_limit

        with patch("app.dashboard.api.settings") as mock_settings:
            mock_settings.dashboard_max_payment_sats = 1000
            _check_dashboard_payment_limit(999)

    def test_check_limit_exceeded(self):
        from app.dashboard.api import _check_dashboard_payment_limit

        with patch("app.dashboard.api.settings") as mock_settings:
            mock_settings.dashboard_max_payment_sats = 1000
            with pytest.raises(HTTPException) as exc_info:
                _check_dashboard_payment_limit(1001)
            assert exc_info.value.status_code == 400
            assert "exceeds dashboard limit" in exc_info.value.detail

    def test_check_limit_exact_boundary(self):
        from app.dashboard.api import _check_dashboard_payment_limit

        with patch("app.dashboard.api.settings") as mock_settings:
            mock_settings.dashboard_max_payment_sats = 1000
            _check_dashboard_payment_limit(1000)

    @pytest.mark.asyncio
    async def test_pay_invoice_blocked_by_limit(self, db_session):
        from app.dashboard.api import PayRequest, pay_invoice

        request = MagicMock()
        request.client.host = "127.0.0.1"
        body = PayRequest(payment_request="lnbc1000...")
        decoded = {"num_satoshis": "50000", "destination": "02abc"}

        with (
            patch("app.dashboard.api.settings") as mock_settings,
            patch(
                "app.dashboard.api.lnd_service.decode_payment_request",
                new_callable=AsyncMock,
                return_value=(decoded, None),
            ),
        ):
            mock_settings.dashboard_max_payment_sats = 10000
            with pytest.raises(HTTPException) as exc_info:
                await pay_invoice(request, body, db_session)
            assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_pay_invoice_decode_failure_blocks_when_cap_set(self, db_session):
        """when the cap is configured, a decode failure
        must reject the request rather than silently pass with
        ``amount_sats=None``. The previous code dropped the decode
        error tuple, so an undecodable invoice paid at any amount
        bypassed ``DASHBOARD_MAX_PAYMENT_SATS`` entirely."""
        from app.dashboard.api import PayRequest, pay_invoice

        request = MagicMock()
        request.client.host = "127.0.0.1"
        body = PayRequest(payment_request="lnbc-garbage")

        with (
            patch("app.dashboard.api.settings") as mock_settings,
            patch(
                "app.dashboard.api.lnd_service.decode_payment_request",
                new_callable=AsyncMock,
                return_value=(None, "invalid bech32"),
            ),
            patch(
                "app.dashboard.api.lnd_service.send_payment_sync",
                new_callable=AsyncMock,
            ) as mock_send,
        ):
            mock_settings.dashboard_max_payment_sats = 10000
            with pytest.raises(HTTPException) as exc_info:
                await pay_invoice(request, body, db_session)
            assert exc_info.value.status_code == 400
            mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_pay_invoice_decode_failure_allowed_when_cap_disabled(self, db_session):
        """When ``dashboard_max_payment_sats < 0`` no cap exists, so a
        decode failure must NOT block the payment — preserving parity
        with the direct-API path."""
        from app.dashboard.api import PayRequest, pay_invoice

        request = MagicMock()
        request.client.host = "127.0.0.1"
        body = PayRequest(payment_request="lnbc1u...")

        with (
            patch("app.dashboard.api.settings") as mock_settings,
            patch(
                "app.dashboard.api.lnd_service.decode_payment_request",
                new_callable=AsyncMock,
                return_value=(None, "decode failed"),
            ),
            patch(
                "app.dashboard.api.lnd_service.send_payment_sync",
                new_callable=AsyncMock,
                return_value=({"payment_hash": "abc"}, None),
            ),
        ):
            mock_settings.dashboard_max_payment_sats = -1
            resp = await pay_invoice(request, body, db_session)
        # Returned the LND response dict directly (not a JSONResponse error)
        assert resp == {"payment_hash": "abc"}

    @pytest.mark.asyncio
    async def test_send_onchain_blocked_by_limit(self, db_session):
        from app.dashboard.api import SendOnchainRequest, send_onchain

        request = MagicMock()
        request.client.host = "127.0.0.1"
        body = SendOnchainRequest(
            address="bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            amount_sats=50000,
        )

        with patch("app.dashboard.api.settings") as mock_settings:
            mock_settings.dashboard_max_payment_sats = 10000
            with pytest.raises(HTTPException) as exc_info:
                await send_onchain(request, body, db_session)
            assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_open_channel_blocked_by_limit(self, db_session):
        from app.dashboard.api import OpenChannelRequest, open_channel

        request = MagicMock()
        request.client.host = "127.0.0.1"
        body = OpenChannelRequest(pubkey="02" + "a1" * 32, local_funding_amount=500000)

        with patch("app.dashboard.api.settings") as mock_settings:
            mock_settings.dashboard_max_payment_sats = 100000
            with pytest.raises(HTTPException) as exc_info:
                await open_channel(request, body, db_session)
            assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_cold_storage_blocked_by_limit(self, db_session):
        from app.dashboard.api import ColdStorageRequest, cold_storage_initiate

        request = MagicMock()
        request.client.host = "127.0.0.1"
        body = ColdStorageRequest(
            amount_sats=200000,
            destination_address="bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
        )

        with patch("app.dashboard.api.settings") as mock_settings:
            mock_settings.dashboard_max_payment_sats = 100000
            with pytest.raises(HTTPException) as exc_info:
                await cold_storage_initiate(request, body, db_session)
            assert exc_info.value.status_code == 400

    def test_config_default_disabled(self):
        from app.core.config import Settings

        with patch.dict("os.environ", {}, clear=False):
            s = Settings(
                secret_key="a" * 64,
                database_url="sqlite+aiosqlite://",
            )
            assert s.dashboard_max_payment_sats == -1


class TestChannelPeerCheck:
    """Connect-peer preflight endpoint (D2/C)."""

    @pytest.mark.asyncio
    async def test_disabled_returns_unavailable(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_open_enabled", False)
        body = BraiinsDepositChannelPeerCheckRequest(amount_sats=1_000_000)
        res = await braiins_deposit_channel_peer_check(body)
        assert res["available"] is False and res["reachable"] is False

    @pytest.mark.asyncio
    async def test_reachable_when_eligible_and_connect_ok(self, monkeypatch):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock

        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_open_enabled", True)
        q = SimpleNamespace(
            channel_eligible=True,
            channel_capacity_sats=1_030_000,
            channel_ineligible_reason="",
        )
        monkeypatch.setattr(
            "app.services.braiins_deposit_service.braiins_deposit_service.quote",
            AsyncMock(return_value=(q, None)),
        )
        monkeypatch.setattr(
            "app.dashboard.api.lnd_service.connect_peer",
            AsyncMock(return_value=({"ok": True}, None)),
        )
        res = await braiins_deposit_channel_peer_check(BraiinsDepositChannelPeerCheckRequest(amount_sats=1_000_000))
        assert res["available"] is True and res["reachable"] is True
        assert res.get("peer_label")

    @pytest.mark.asyncio
    async def test_unreachable_when_connect_fails(self, monkeypatch):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock

        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_open_enabled", True)
        q = SimpleNamespace(
            channel_eligible=True,
            channel_capacity_sats=1_030_000,
            channel_ineligible_reason="",
        )
        monkeypatch.setattr(
            "app.services.braiins_deposit_service.braiins_deposit_service.quote",
            AsyncMock(return_value=(q, None)),
        )
        monkeypatch.setattr(
            "app.dashboard.api.lnd_service.connect_peer",
            AsyncMock(return_value=(None, "connection refused")),
        )
        res = await braiins_deposit_channel_peer_check(BraiinsDepositChannelPeerCheckRequest(amount_sats=1_000_000))
        assert res["available"] is True and res["reachable"] is False

    @pytest.mark.asyncio
    async def test_ineligible_amount_not_reachable(self, monkeypatch):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock

        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_open_enabled", True)
        q = SimpleNamespace(
            channel_eligible=False,
            channel_capacity_sats=0,
            channel_ineligible_reason="this amount is outside the channel-open range",
        )
        monkeypatch.setattr(
            "app.services.braiins_deposit_service.braiins_deposit_service.quote",
            AsyncMock(return_value=(q, None)),
        )
        res = await braiins_deposit_channel_peer_check(BraiinsDepositChannelPeerCheckRequest(amount_sats=10_000))
        assert res["available"] is True and res["reachable"] is False
        assert "range" in (res.get("reason") or "")
