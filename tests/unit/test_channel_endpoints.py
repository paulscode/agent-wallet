# SPDX-License-Identifier: MIT
"""
Unit tests for app.api.channels — endpoint functions and SSRF validation.
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException, Request

from app.api.channels import (
    ConnectPeerRequest,
    OpenChannelRequest,
    connect_peer,
    open_channel,
)
from app.models.api_key import APIKey


def _mock_request() -> MagicMock:
    req = MagicMock(spec=Request)
    req.client.host = "127.0.0.1"
    # A real mapping so the Idempotency-Key lookup resolves to absent rather
    # than a truthy MagicMock attribute.
    req.headers = {}
    return req


def _make_admin_key() -> APIKey:
    return APIKey(id=uuid4(), name="admin", key_hash="a" * 64, is_admin=True, is_active=True)


class TestSSRFValidation:
    def test_allows_onion_address(self):
        req = ConnectPeerRequest(pubkey="02" + "a1" * 32, host="abcdef.onion:9735")
        assert req.host == "abcdef.onion:9735"

    def test_blocks_private_ip(self):
        with pytest.raises(ValueError, match="not allowed"):
            ConnectPeerRequest(pubkey="02" + "a1" * 32, host="10.0.0.1:9735")

    def test_blocks_loopback(self):
        with pytest.raises(ValueError, match="not allowed"):
            ConnectPeerRequest(pubkey="02" + "a1" * 32, host="127.0.0.1:9735")

    def test_blocks_link_local(self):
        with pytest.raises(ValueError, match="not allowed"):
            ConnectPeerRequest(pubkey="02" + "a1" * 32, host="169.254.1.1:9735")

    def test_blocks_localhost(self):
        with pytest.raises(ValueError, match="not allowed"):
            ConnectPeerRequest(pubkey="02" + "a1" * 32, host="localhost:9735")

    def test_blocks_dot_local(self):
        with pytest.raises(ValueError, match="not allowed"):
            ConnectPeerRequest(pubkey="02" + "a1" * 32, host="node.local:9735")

    def test_blocks_dot_internal(self):
        with pytest.raises(ValueError, match="not allowed"):
            ConnectPeerRequest(pubkey="02" + "a1" * 32, host="node.internal:9735")

    def test_allows_public_ip(self):
        req = ConnectPeerRequest(pubkey="02" + "a1" * 32, host="8.8.8.8:9735")
        assert req.host == "8.8.8.8:9735"


class TestConnectPeer:
    @pytest.mark.asyncio
    async def test_connect_peer_success(self, db_session):
        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        req = ConnectPeerRequest(pubkey="02" + "a1" * 32, host="8.8.8.8:9735")
        with patch(
            "app.api.channels.lnd_service.connect_peer", new_callable=AsyncMock, return_value=({"status": "ok"}, None)
        ):
            result = await connect_peer(req, _mock_request(), admin, db_session)
        assert result["status"] == "connected"

    @pytest.mark.asyncio
    async def test_connect_peer_lnd_error(self, db_session):
        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        req = ConnectPeerRequest(pubkey="02" + "a1" * 32, host="8.8.8.8:9735")
        with patch("app.api.channels.lnd_service.connect_peer", new_callable=AsyncMock, return_value=(None, "refused")):
            with pytest.raises(HTTPException) as exc:
                await connect_peer(req, _mock_request(), admin, db_session)
            assert exc.value.status_code == 502


class TestOpenChannelFeeBound:
    """The funding-tx fee rate must be bounded so a tiny channel with a huge
    ``sat_per_vbyte`` cannot drain the wallet as miner fee (parity with
    send-onchain)."""

    def test_rejects_fee_rate_above_ceiling(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            OpenChannelRequest(node_pubkey="02" + "a1" * 32, local_funding_amount=100000, sat_per_vbyte=5000)

    def test_accepts_fee_rate_at_ceiling(self):
        req = OpenChannelRequest(node_pubkey="02" + "a1" * 32, local_funding_amount=100000, sat_per_vbyte=1000)
        assert req.sat_per_vbyte == 1000

    def test_rejects_fee_rate_just_over_ceiling(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            OpenChannelRequest(node_pubkey="02" + "a1" * 32, local_funding_amount=100000, sat_per_vbyte=1001)

    @pytest.mark.asyncio
    async def test_open_channel_folds_fee_into_spend_window(self, db_session):
        """The funding-tx fee budget is charged against the cumulative cap."""
        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        req = OpenChannelRequest(node_pubkey="02" + "a1" * 32, local_funding_amount=5000, sat_per_vbyte=900)
        with (
            patch(
                "app.api.channels.check_payment_limits",
                new_callable=AsyncMock,
                return_value=(True, None, {"api_key_id": "k"}),
            ) as mock_rl,
            patch(
                "app.api.channels.lnd_service.open_channel",
                new_callable=AsyncMock,
                return_value=({"funding_txid": "tx"}, None),
            ),
        ):
            await open_channel(req, _mock_request(), admin, db_session)

        # funding (5000) + fee budget (900 * 250 = 225_000).
        assert mock_rl.call_args.args[0] == 5000 + 900 * 250


class TestOpenChannel:
    @pytest.mark.asyncio
    async def test_open_channel_rate_limit_exceeded(self, db_session):
        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        req = OpenChannelRequest(node_pubkey="02" + "a1" * 32, local_funding_amount=5000)
        with patch(
            "app.api.channels.check_payment_limits", new_callable=AsyncMock, return_value=(False, "Spend limit", None)
        ):
            with pytest.raises(HTTPException) as exc:
                await open_channel(req, _mock_request(), admin, db_session)
            assert exc.value.status_code == 429

    @pytest.mark.asyncio
    async def test_open_channel_lnd_error_rolls_back(self, db_session):
        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        req = OpenChannelRequest(node_pubkey="02" + "a1" * 32, local_funding_amount=5000)
        with (
            patch(
                "app.api.channels.check_payment_limits",
                new_callable=AsyncMock,
                return_value=(True, None, {"api_key_id": "k"}),
            ),
            patch(
                "app.api.channels.lnd_service.open_channel", new_callable=AsyncMock, return_value=(None, "bad channel")
            ),
            patch("app.api.channels.rollback_payment_limits", new_callable=AsyncMock) as mock_rollback,
        ):
            with pytest.raises(HTTPException) as exc:
                await open_channel(req, _mock_request(), admin, db_session)
            assert exc.value.status_code == 502
            mock_rollback.assert_called_once()

    @pytest.mark.asyncio
    async def test_open_channel_success(self, db_session):
        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        req = OpenChannelRequest(node_pubkey="02" + "a1" * 32, local_funding_amount=5000)
        with (
            patch(
                "app.api.channels.check_payment_limits",
                new_callable=AsyncMock,
                return_value=(True, None, {"api_key_id": "k"}),
            ),
            patch(
                "app.api.channels.lnd_service.open_channel",
                new_callable=AsyncMock,
                return_value=({"funding_txid": "abc"}, None),
            ),
        ):
            result = await open_channel(req, _mock_request(), admin, db_session)
        assert result["funding_txid"] == "abc"

    @pytest.mark.asyncio
    async def test_open_channel_idempotent_replay(self, db_session, monkeypatch):
        """A retried open with the same Idempotency-Key returns the original
        funding transaction and does not open a second channel."""
        from app.core import idempotency
        from tests.unit.test_idempotency import _FakeRedis

        fake = _FakeRedis()
        monkeypatch.setattr(idempotency, "_redis_client", lambda: fake)

        admin = _make_admin_key()
        db_session.add(admin)
        await db_session.commit()

        req = OpenChannelRequest(node_pubkey="02" + "a1" * 32, local_funding_amount=5000)
        request = _mock_request()
        request.headers = {"Idempotency-Key": "11111111-1111-1111-1111-111111111111"}

        calls = {"n": 0}

        async def _open(*_a, **_k):
            calls["n"] += 1
            return ({"funding_txid": "tx-once"}, None)

        with (
            patch(
                "app.api.channels.check_payment_limits",
                new_callable=AsyncMock,
                return_value=(True, None, {"api_key_id": "k"}),
            ),
            patch("app.api.channels.lnd_service.open_channel", side_effect=_open),
        ):
            first = await open_channel(req, request, admin, db_session)
            second = await open_channel(req, request, admin, db_session)

        assert first["funding_txid"] == "tx-once"
        assert second == first
        assert calls["n"] == 1  # second request served from the cache
