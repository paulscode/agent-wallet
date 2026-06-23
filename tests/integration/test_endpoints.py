# SPDX-License-Identifier: MIT
"""
Integration tests for API endpoints.

Tests the full request → FastAPI → handler → response cycle.
LND and Boltz services are mocked; database and auth are real.
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.security import generate_api_key, hash_api_key
from app.models.api_key import APIKey

# ─── Health Endpoint ──────────────────────────────────────────────────


class TestHealthEndpoint:
    """Tests for /health — no auth required."""

    @pytest.mark.asyncio
    async def test_health_ok(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "network" not in data  # no config leakage


class TestReadinessEndpoint:
    """Tests for /ready — checks database connectivity."""

    @pytest.mark.asyncio
    async def test_ready_ok(self, client: AsyncClient, db_engine):
        """Readiness probe returns 200 when DB is reachable."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        test_sm = async_sessionmaker(db_engine, expire_on_commit=False)

        with patch("app.main.get_session_maker", return_value=test_sm):
            resp = await client.get("/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["database"] == "connected"

    @pytest.mark.asyncio
    async def test_ready_503_on_db_failure(self, client: AsyncClient):
        """Readiness probe returns 503 when database is unreachable."""
        with patch("app.main.get_session_maker") as mock_sm:
            mock_sm.side_effect = Exception("connection refused")
            resp = await client.get("/ready")
        assert resp.status_code == 503
        data = resp.json()
        assert data["status"] == "unavailable"

    @pytest.mark.asyncio
    async def test_ready_does_not_leak_exception_detail(self, client: AsyncClient):
        """503 response must not expose raw exception text."""
        with patch("app.main.get_session_maker") as mock_sm:
            mock_sm.side_effect = Exception("psycopg2.OperationalError: could not connect to server: 10.0.0.5")
            resp = await client.get("/ready")

        assert resp.status_code == 503
        body = resp.json()
        assert body["database"] == "connection_failed"
        # Ensure no raw exception text is exposed
        assert "psycopg2" not in str(body)
        assert "10.0.0.5" not in str(body)
        assert "could not connect" not in str(body)


# ─── Auth Tests ───────────────────────────────────────────────────────


class TestAuthentication:
    """Tests for API key authentication across endpoints."""

    @pytest.mark.asyncio
    async def test_no_auth_returns_401(self, client: AsyncClient):
        """Endpoints should return 401/403 without auth header."""
        resp = await client.get("/v1/wallet/info")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_invalid_key_returns_401(self, client: AsyncClient):
        """Invalid API key returns 401."""
        resp = await client.get(
            "/v1/wallet/info",
            headers={"Authorization": "Bearer lwk_invalid_key_123456789012345678901234"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_key_accepted(self, authed_client):
        """Valid admin key gives access to endpoints."""
        client, raw_key, key_id = authed_client

        with patch("app.services.lnd_service.lnd_service.get_info", new_callable=AsyncMock) as mock_info:
            mock_info.return_value = (
                {
                    "alias": "test-node",
                    "identity_pubkey": "02" + "a" * 64,
                    "synced_to_chain": True,
                },
                None,
            )
            resp = await client.get("/v1/wallet/info")

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_monitor_key_blocked_from_spend(self, client, db_engine):
        """A monitor key is blocked from fund-moving operations."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
        async with session_factory() as session:
            raw_key = generate_api_key()
            api_key = APIKey(
                id=uuid4(),
                name="monitor",
                key_hash=hash_api_key(raw_key),
                scope="monitor",
                is_active=True,
            )
            session.add(api_key)
            await session.commit()

        resp = await client.post(
            "/v1/payments/pay",
            headers={"Authorization": f"Bearer {raw_key}"},
            json={"payment_request": "lnbc1bogus"},
        )
        assert resp.status_code == 403


# ─── Wallet Endpoints ────────────────────────────────────────────────


class TestWalletEndpoints:
    """Tests for /v1/wallet/* endpoints."""

    @pytest.mark.asyncio
    async def test_wallet_config(self, authed_client):
        """GET /v1/wallet/config returns configuration."""
        client, _, _ = authed_client
        resp = await client.get("/v1/wallet/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "lnd_configured" in data
        assert data["network"] == "regtest"

    @pytest.mark.asyncio
    async def test_wallet_summary_success(self, authed_client):
        """GET /v1/wallet/summary returns summary on LND success."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_wallet_summary", new_callable=AsyncMock) as mock:
            mock.return_value = (
                {
                    "onchain": {"total_balance": 500000},
                    "lightning": {"local_balance_sat": 300000},
                    "node": {"alias": "test"},
                },
                None,
            )
            resp = await client.get("/v1/wallet/summary")

        assert resp.status_code == 200
        assert resp.json()["onchain"]["total_balance"] == 500000

    @pytest.mark.asyncio
    async def test_wallet_summary_lnd_down(self, authed_client):
        """GET /v1/wallet/summary returns 503 when LND is down."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_wallet_summary", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND unavailable")
            resp = await client.get("/v1/wallet/summary")

        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_wallet_balance(self, authed_client):
        """GET /v1/wallet/balance returns combined balance."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.get_wallet_balance", new_callable=AsyncMock) as mock_w,
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock_c,
        ):
            mock_w.return_value = ({"total_balance": "1000000"}, None)
            mock_c.return_value = ({"local_balance_sat": "500000"}, None)

            resp = await client.get("/v1/wallet/balance")

        assert resp.status_code == 200
        data = resp.json()
        assert "onchain" in data
        assert "lightning" in data

    @pytest.mark.asyncio
    async def test_wallet_channels(self, authed_client):
        """GET /v1/wallet/channels returns channel list."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_channels", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"chan_id": "123", "active": True}], None)
            resp = await client.get("/v1/wallet/channels")

        assert resp.status_code == 200
        assert len(resp.json()["channels"]) == 1


# ─── Payment Endpoints ───────────────────────────────────────────────


class TestPaymentEndpoints:
    """Tests for /v1/payments/* endpoints."""

    @pytest.mark.asyncio
    async def test_create_invoice(self, authed_client):
        """POST /v1/payments/invoice creates a Lightning invoice."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.create_invoice", new_callable=AsyncMock) as mock:
            mock.return_value = (
                {"r_hash": "abc", "payment_request": "lnbcrt1..."},
                None,
            )
            resp = await client.post(
                "/v1/payments/invoice",
                json={"amount_sats": 1000, "memo": "test", "expiry": 3600},
            )

        assert resp.status_code == 200
        assert resp.json()["r_hash"] == "abc"

    @pytest.mark.asyncio
    async def test_decode_payment_request(self, authed_client):
        """POST /v1/payments/decode decodes a BOLT11 string."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock:
            mock.return_value = (
                {"destination": "02" + "a" * 64, "num_satoshis": "5000"},
                None,
            )
            resp = await client.post(
                "/v1/payments/decode",
                json={"payment_request": "lnbcrt50u1..."},
            )

        assert resp.status_code == 200
        assert resp.json()["num_satoshis"] == "5000"

    @pytest.mark.asyncio
    async def test_pay_invoice_safety_limit(self, authed_client):
        """Pay invoice rejects payments exceeding safety limit."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock:
            mock.return_value = (
                {"num_satoshis": 999999, "destination": "02" + "a" * 64},
                None,
            )
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "lnbcrt1..."},
            )

        # Default limit is 10,000 sats; 999,999 exceeds it
        assert resp.status_code == 400
        assert "safety limit" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_new_address(self, authed_client):
        """POST /v1/payments/address generates a new address."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.new_address", new_callable=AsyncMock) as mock:
            mock.return_value = ({"address": "bcrt1qtest..."}, None)
            resp = await client.post(
                "/v1/payments/address",
                json={"address_type": "p2tr"},
            )

        assert resp.status_code == 200
        assert resp.json()["address"] == "bcrt1qtest..."

    @pytest.mark.asyncio
    async def test_new_address_invalid_type_rejected(self, authed_client):
        """POST /v1/payments/address rejects invalid address_type values."""
        client, _, _ = authed_client

        resp = await client.post(
            "/v1/payments/address",
            json={"address_type": "p2pkh"},
        )
        assert resp.status_code == 422  # Pydantic validation error

    @pytest.mark.asyncio
    async def test_new_address_valid_types_accepted(self, authed_client):
        """POST /v1/payments/address accepts all valid address_type values."""
        client, _, _ = authed_client

        for addr_type in ("p2wkh", "np2wkh", "p2tr"):
            with patch("app.services.lnd_service.lnd_service.new_address", new_callable=AsyncMock) as mock:
                mock.return_value = ({"address": f"addr-{addr_type}"}, None)
                resp = await client.post(
                    "/v1/payments/address",
                    json={"address_type": addr_type},
                )
            assert resp.status_code == 200, f"Failed for {addr_type}"

    @pytest.mark.asyncio
    async def test_estimate_fee(self, authed_client):
        """POST /v1/payments/estimate-fee returns fee estimate."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.estimate_fee", new_callable=AsyncMock) as mock:
            mock.return_value = ({"fee_sat": "500", "sat_per_vbyte": "10"}, None)
            resp = await client.post(
                "/v1/payments/estimate-fee",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 50000},
            )

        assert resp.status_code == 200
        assert resp.json()["fee_sat"] == "500"


# ─── Admin Endpoints ─────────────────────────────────────────────────


class TestAdminEndpoints:
    """Tests for /v1/admin/* endpoints."""

    @pytest.mark.asyncio
    async def test_no_create_api_key_route(self, authed_client):
        """Key minting is operator-only (dashboard session), never
        API-key-authed, so no key of any scope can mint another. The
        admin surface accepts only GET on this path."""
        client, _, _ = authed_client

        resp = await client.post(
            "/v1/admin/api-keys",
            json={"name": "new-agent-key", "is_admin": False},
        )
        # 405: the path serves the read-only GET listing, so POST is
        # "method not allowed" rather than a missing route.
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_list_api_keys(self, authed_client):
        """GET /v1/admin/api-keys lists all keys."""
        client, _, _ = authed_client

        resp = await client.get("/v1/admin/api-keys")
        assert resp.status_code == 200
        assert "keys" in resp.json()

    @pytest.mark.asyncio
    async def test_health_check(self, authed_client):
        """GET /v1/admin/health returns system health."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_info", new_callable=AsyncMock) as mock:
            mock.return_value = (
                {
                    "alias": "test",
                    "synced_to_chain": True,
                    "block_height": 100,
                    "version": "0.18.0",
                },
                None,
            )
            resp = await client.get("/v1/admin/health")

        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_health_check_lnd_down(self, authed_client):
        """Health check reports degraded when LND is unreachable."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_info", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND unreachable")
            resp = await client.get("/v1/admin/health")

        assert resp.status_code == 200
        assert resp.json()["status"] == "degraded"

    @pytest.mark.asyncio
    async def test_audit_log(self, authed_client):
        """GET /v1/admin/audit-log returns audit entries."""
        client, _, _ = authed_client

        resp = await client.get("/v1/admin/audit-log")
        assert resp.status_code == 200
        assert "entries" in resp.json()

    @pytest.mark.asyncio
    async def test_no_key_mutation_routes(self, authed_client):
        """No API-key-authed route can mutate keys. PATCH / DELETE /
        purge on the admin surface all 404 — the admin surface's only
        ``/api-keys`` method is the read-only GET listing."""
        client, _, key_id = authed_client

        patch_resp = await client.patch(f"/v1/admin/api-keys/{key_id}", json={"name": "x"})
        delete_resp = await client.delete(f"/v1/admin/api-keys/{key_id}")
        purge_resp = await client.post(f"/v1/admin/api-keys/{key_id}/purge")
        assert patch_resp.status_code == 404
        assert delete_resp.status_code == 404
        assert purge_resp.status_code == 404


# ─── Cold Storage Endpoints ──────────────────────────────────────────


class TestColdStorageEndpoints:
    """Tests for /v1/cold-storage/* endpoints."""

    @pytest.mark.asyncio
    async def test_get_swap_fees(self, authed_client):
        """GET /v1/cold-storage/fees returns Boltz fee info."""
        client, _, _ = authed_client

        with patch("app.services.boltz_service.boltz_service.get_reverse_pair_info", new_callable=AsyncMock) as mock:
            mock.return_value = (
                {
                    "min": 50000,
                    "max": 25000000,
                    "fees_percentage": 0.25,
                    "fees_miner_lockup": 3000,
                    "fees_miner_claim": 2500,
                },
                None,
            )
            resp = await client.get("/v1/cold-storage/fees")

        assert resp.status_code == 200
        data = resp.json()
        assert data["min_amount_sats"] == 50000
        assert data["fee_percentage"] == 0.25

    @pytest.mark.asyncio
    async def test_list_swaps_empty(self, authed_client):
        """GET /v1/cold-storage/swaps returns empty list initially."""
        client, _, _ = authed_client

        with patch("app.services.boltz_service.boltz_service.get_swaps_for_key", new_callable=AsyncMock) as mock:
            mock.return_value = []
            resp = await client.get("/v1/cold-storage/swaps")

        assert resp.status_code == 200
        assert resp.json()["swaps"] == []

    @pytest.mark.asyncio
    async def test_get_swap_status_not_found(self, authed_client):
        """GET /v1/cold-storage/swaps/{id} returns 404 for unknown swap."""
        client, _, _ = authed_client
        fake_id = str(uuid4())

        with patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock:
            mock.return_value = None
            resp = await client.get(f"/v1/cold-storage/swaps/{fake_id}")

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_invalid_swap_id_format(self, authed_client):
        """GET /v1/cold-storage/swaps/{id} rejects invalid UUID."""
        client, _, _ = authed_client

        resp = await client.get("/v1/cold-storage/swaps/not-a-uuid")
        assert resp.status_code == 400


# ─── Mempool Explorer Endpoints ──────────────────────────────────────


class TestMempoolEndpoints:
    """Tests for /v1/mempool/* endpoints."""

    @pytest.mark.asyncio
    async def test_get_transaction(self, authed_client):
        """GET /v1/mempool/tx/{txid} returns tx details."""
        client, _, _ = authed_client
        txid = "a" * 64

        mock_tx = {
            "txid": txid,
            "confirmed": True,
            "block_height": 800000,
            "fee": 1500,
            "size": 250,
            "weight": 680,
            "vin_count": 1,
            "vout_count": 2,
            "vout": [{"scriptpubkey_address": "bc1qtest", "value": 50000}],
            "block_hash": "0" * 64,
            "block_time": 1700000000,
            "version": 2,
            "locktime": 0,
        }

        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_transaction",
            new_callable=AsyncMock,
            return_value=(mock_tx, None),
        ):
            resp = await client.get(f"/v1/mempool/tx/{txid}")

        assert resp.status_code == 200
        data = resp.json()
        assert data["confirmed"] is True
        assert data["block_height"] == 800000

    @pytest.mark.asyncio
    async def test_get_transaction_invalid_txid(self, authed_client):
        """GET /v1/mempool/tx/{txid} rejects invalid txid format."""
        client, _, _ = authed_client
        resp = await client.get("/v1/mempool/tx/not-a-valid-txid")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_get_transaction_not_found(self, authed_client):
        """GET /v1/mempool/tx/{txid} returns 404 for unknown tx."""
        client, _, _ = authed_client
        txid = "f" * 64

        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_transaction",
            new_callable=AsyncMock,
            return_value=(None, "not found"),
        ):
            resp = await client.get(f"/v1/mempool/tx/{txid}")

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_confirmations(self, authed_client):
        """GET /v1/mempool/tx/{txid}/confirmations returns confirmation count."""
        client, _, _ = authed_client
        txid = "b" * 64

        mock_result = {
            "txid": txid,
            "confirmed": True,
            "confirmations": 6,
            "block_height": 800000,
            "block_time": 1700000000,
        }

        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_transaction_confirmations",
            new_callable=AsyncMock,
            return_value=(mock_result, None),
        ):
            resp = await client.get(f"/v1/mempool/tx/{txid}/confirmations")

        assert resp.status_code == 200
        assert resp.json()["confirmations"] == 6

    @pytest.mark.asyncio
    async def test_get_address_info(self, authed_client):
        """GET /v1/mempool/address/{addr} returns balance info."""
        client, _, _ = authed_client

        mock_info = {
            "address": "bc1qtest123456789012345678901234567",
            "confirmed_balance_sats": 800000,
            "unconfirmed_balance_sats": 50000,
            "total_balance_sats": 850000,
            "confirmed_tx_count": 5,
            "unconfirmed_tx_count": 1,
            "funded_txo_count": 3,
            "spent_txo_count": 1,
        }

        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_address",
            new_callable=AsyncMock,
            return_value=(mock_info, None),
        ):
            resp = await client.get("/v1/mempool/address/bc1qtest123456789012345678901234567")

        assert resp.status_code == 200
        data = resp.json()
        assert data["total_balance_sats"] == 850000

    @pytest.mark.asyncio
    async def test_get_address_utxos(self, authed_client):
        """GET /v1/mempool/address/{addr}/utxos returns UTXO list."""
        client, _, _ = authed_client

        mock_utxos = [
            {"txid": "a" * 64, "vout": 0, "value_sats": 100000, "confirmed": True, "block_height": 800000},
        ]

        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_address_utxos",
            new_callable=AsyncMock,
            return_value=(mock_utxos, None),
        ):
            resp = await client.get("/v1/mempool/address/bc1qtest123456789012345678901234567/utxos")

        assert resp.status_code == 200
        data = resp.json()
        assert data["utxo_count"] == 1

    @pytest.mark.asyncio
    async def test_get_mempool_stats(self, authed_client):
        """GET /v1/mempool/stats returns congestion data."""
        client, _, _ = authed_client

        mock_stats = {
            "tx_count": 12500,
            "total_vsize": 45000000,
            "total_fee_btc": 1.25,
            "fee_histogram": [[50, 12000]],
        }

        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_mempool_stats",
            new_callable=AsyncMock,
            return_value=(mock_stats, None),
        ):
            resp = await client.get("/v1/mempool/stats")

        assert resp.status_code == 200
        assert resp.json()["tx_count"] == 12500

    @pytest.mark.asyncio
    async def test_get_block_tip_height(self, authed_client):
        """GET /v1/mempool/block/tip/height returns current chain height."""
        client, _, _ = authed_client

        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_block_tip_height",
            new_callable=AsyncMock,
            return_value=(800123, None),
        ):
            resp = await client.get("/v1/mempool/block/tip/height")

        assert resp.status_code == 200
        assert resp.json()["height"] == 800123

    @pytest.mark.asyncio
    async def test_get_block_by_height(self, authed_client):
        """GET /v1/mempool/block/{height} returns block header data."""
        client, _, _ = authed_client

        mock_block = {
            "hash": "0000" * 16,
            "height": 800000,
            "timestamp": 1700000000,
            "tx_count": 2500,
            "size": 1500000,
            "weight": 3993000,
            "difficulty": 57321508229258,
            "previous_block_hash": "1111" * 16,
        }

        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_block_by_height",
            new_callable=AsyncMock,
            return_value=(mock_block, None),
        ):
            resp = await client.get("/v1/mempool/block/800000")

        assert resp.status_code == 200
        data = resp.json()
        assert data["height"] == 800000
        assert data["tx_count"] == 2500

    @pytest.mark.asyncio
    async def test_get_block_negative_height(self, authed_client):
        """GET /v1/mempool/block/{height} rejects negative heights."""
        client, _, _ = authed_client
        resp = await client.get("/v1/mempool/block/-1")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_mempool_auth_required(self, client: AsyncClient):
        """Mempool endpoints require API key auth."""
        resp = await client.get("/v1/mempool/stats")
        assert resp.status_code in (401, 403)


class TestAdminAuditLogFilter:
    """Tests for GET /v1/admin/audit-log with action filter."""

    @pytest.mark.asyncio
    async def test_audit_log_with_action_filter(self, authed_client):
        client, _, _ = authed_client

        # Trigger an auditable admin action on the API surface.
        # Re-anchoring emits an ``audit_chain_reanchor`` entry
        # attributed to the caller.
        await client.post("/v1/admin/audit-log/reanchor")

        resp = await client.get("/v1/admin/audit-log?action=audit_chain_reanchor")
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert all(e["action"] == "audit_chain_reanchor" for e in entries)
        assert len(entries) >= 1

    @pytest.mark.asyncio
    async def test_audit_log_no_match(self, authed_client):
        client, _, _ = authed_client
        resp = await client.get("/v1/admin/audit-log?action=nonexistent_action")
        assert resp.status_code == 200
        assert resp.json()["entries"] == []


# ─── Payment Extended ─────────────────────────────────────────────────


class TestPayInvoiceSuccess:
    """Tests for POST /v1/payments/pay — successful payment."""

    @pytest.mark.asyncio
    async def test_pay_invoice_success(self, authed_client):
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch("app.services.lnd_service.lnd_service.send_payment_sync", new_callable=AsyncMock) as mock_pay,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_rl,
        ):
            mock_decode.return_value = ({"num_satoshis": 5000, "destination": "02aa", "description": "test"}, None)
            mock_pay.return_value = ({"payment_hash": "ph123", "payment_preimage": "pre123"}, None)
            mock_rl.return_value = (True, None, None)

            resp = await client.post("/v1/payments/pay", json={"payment_request": "lnbcrt50u1..."})

        assert resp.status_code == 200
        assert resp.json()["payment_hash"] == "ph123"

    @pytest.mark.asyncio
    async def test_pay_invoice_omitted_fee_limit_passes_explicit_bound(self, authed_client):
        """When the caller omits ``fee_limit_sats`` the wallet reserves 5%
        of the amount — and must pass that same explicit bound to LND so
        the actual payment can't exceed the per-payment ceiling we
        checked (rather than letting LND apply its own default budget)."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch("app.services.lnd_service.lnd_service.send_payment_sync", new_callable=AsyncMock) as mock_pay,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_rl,
        ):
            mock_decode.return_value = ({"num_satoshis": 5000, "destination": "02aa", "description": "t"}, None)
            mock_pay.return_value = ({"payment_hash": "ph", "payment_preimage": "pre"}, None)
            mock_rl.return_value = (True, None, None)

            # No fee_limit_sats in the request body.
            resp = await client.post("/v1/payments/pay", json={"payment_request": "lnbcrt50u1..."})

        assert resp.status_code == 200
        # send_payment_sync(payment_request, fee_limit_sats, timeout) — the
        # fee limit must be the explicit 5% reserve (250), never None.
        passed_fee_limit = mock_pay.call_args.args[1]
        assert passed_fee_limit == max(1, int(5000 * 0.05))
        assert passed_fee_limit is not None

    @pytest.mark.asyncio
    async def test_pay_invoice_rejects_amountless(self, authed_client):
        client, _, _ = authed_client

        with patch(
            "app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock
        ) as mock_decode:
            mock_decode.return_value = ({"num_satoshis": 0, "destination": "02aa"}, None)
            resp = await client.post("/v1/payments/pay", json={"payment_request": "lnbcrt1..."})

        assert resp.status_code == 400
        assert "amountless" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_pay_invoice_decode_error(self, authed_client):
        client, _, _ = authed_client

        with patch(
            "app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock
        ) as mock_decode:
            mock_decode.return_value = (None, "invalid bolt11")
            resp = await client.post("/v1/payments/pay", json={"payment_request": "lnbcrt1..."})

        assert resp.status_code == 400
        assert "Cannot decode" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_pay_invoice_lnd_error(self, authed_client):
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch("app.services.lnd_service.lnd_service.send_payment_sync", new_callable=AsyncMock) as mock_pay,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_rl,
        ):
            mock_decode.return_value = ({"num_satoshis": 1000, "destination": "02aa"}, None)
            mock_pay.return_value = (None, "no route found")
            mock_rl.return_value = (True, None, None)

            resp = await client.post("/v1/payments/pay", json={"payment_request": "lnbcrt1..."})

        assert resp.status_code == 502


class TestSendOnchain:
    """Tests for POST /v1/payments/send-onchain."""

    @pytest.mark.asyncio
    async def test_send_onchain_success(self, authed_client):
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_rl,
        ):
            mock.return_value = ({"txid": "tx123"}, None)
            mock_rl.return_value = (True, None, None)
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={
                    "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "amount_sats": 5000,
                    "sat_per_vbyte": 5,
                },
            )

        assert resp.status_code == 200
        assert resp.json()["txid"] == "tx123"

    @pytest.mark.asyncio
    async def test_send_onchain_rejects_excessive_fee_rate(self, authed_client):
        """``sat_per_vbyte`` is bounded so a caller cannot drain the wallet as
        miner fee — a rate above the ceiling is rejected at validation (422)."""
        client, _, _ = authed_client

        resp = await client.post(
            "/v1/payments/send-onchain",
            json={
                "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                "amount_sats": 1000,
                "sat_per_vbyte": 5000,  # above MAX_SAT_PER_VBYTE (1000)
            },
        )

        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_send_onchain_fee_rate_boundary(self, authed_client):
        """Exactly the ceiling (1000) is accepted; one above (1001) is rejected."""
        client, _, _ = authed_client

        # 1001 rejected at validation.
        resp = await client.post(
            "/v1/payments/send-onchain",
            json={
                "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                "amount_sats": 1000,
                "sat_per_vbyte": 1001,
            },
        )
        assert resp.status_code == 422

        # 1000 accepted (passes validation; spend cap is mocked open).
        with (
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
        ):
            mock.return_value = ({"txid": "txb"}, None)
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={
                    "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "amount_sats": 1000,
                    "sat_per_vbyte": 1000,
                },
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_send_onchain_clamps_mempool_rate_to_ceiling(self, authed_client):
        """An anomalous mempool/priority fee estimate above the ceiling is
        clamped before it reaches LND and before the fee is folded into the cap."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock_send,
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.get_fee_for_priority",
                new_callable=AsyncMock,
                return_value=9999,  # absurd estimate, above ceiling
            ),
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)) as mock_rl,
        ):
            mock_send.return_value = ({"txid": "txc"}, None)
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={
                    "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "amount_sats": 1000,
                    "fee_priority": "high",
                },
            )

        assert resp.status_code == 200
        # The rate handed to LND is clamped to 1000, not 9999.
        assert mock_send.call_args.args[2] == 1000
        # And the folded fee budget uses the clamped rate (1000 * 250).
        assert mock_rl.call_args.args[0] == 1000 + 1000 * 250

    @pytest.mark.asyncio
    async def test_send_onchain_automatic_rate_folds_no_fee(self, authed_client):
        """An automatic send (no caller rate) folds NO fee into the cap — LND's
        market rate is not attacker-controlled — and passes sat_per_vbyte=None."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock_send,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)) as mock_rl,
        ):
            mock_send.return_value = ({"txid": "txd"}, None)
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={
                    "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "amount_sats": 4000,
                },
            )

        assert resp.status_code == 200
        assert mock_send.call_args.args[2] is None
        assert mock_rl.call_args.args[0] == 4000  # no fee folded

    @pytest.mark.asyncio
    async def test_send_onchain_folds_fee_into_spend_window(self, authed_client):
        """The caller-controlled fee budget is charged against the cumulative
        spend window so a small amount with a high fee rate is accounted for."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_rl,
        ):
            mock.return_value = ({"txid": "tx789"}, None)
            mock_rl.return_value = (True, None, None)
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={
                    "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "amount_sats": 1000,
                    "sat_per_vbyte": 800,
                },
            )

        assert resp.status_code == 200
        # check_payment_limits must see amount (1000) + fee budget
        # (800 * 250 = 200_000), not the bare amount.
        called_amount = mock_rl.call_args.args[0]
        assert called_amount == 1000 + 800 * 250

    @pytest.mark.asyncio
    async def test_send_onchain_exceeds_limit(self, authed_client):
        client, _, _ = authed_client

        resp = await client.post(
            "/v1/payments/send-onchain",
            json={
                "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                "amount_sats": 999999,
            },
        )

        assert resp.status_code == 400
        assert "safety limit" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_send_onchain_with_fee_priority(self, authed_client):
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock_send,
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.get_fee_for_priority", new_callable=AsyncMock
            ) as mock_fee,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_rl,
        ):
            mock_fee.return_value = 15
            mock_send.return_value = ({"txid": "tx456"}, None)
            mock_rl.return_value = (True, None, None)

            resp = await client.post(
                "/v1/payments/send-onchain",
                json={
                    "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "amount_sats": 3000,
                    "fee_priority": "high",
                },
            )

        assert resp.status_code == 200
        mock_fee.assert_called_once_with("high")

    @pytest.mark.asyncio
    async def test_send_onchain_lnd_error(self, authed_client):
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_rl,
        ):
            mock.return_value = (None, "insufficient funds")
            mock_rl.return_value = (True, None, None)
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={
                    "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "amount_sats": 5000,
                },
            )

        assert resp.status_code == 502


class TestLookupEndpoints:
    """Tests for lookup payment/invoice endpoints."""

    @pytest.mark.asyncio
    async def test_lookup_payment_success(self, authed_client):
        client, _, _ = authed_client
        ph = "ab" * 32

        with patch("app.services.lnd_service.lnd_service.lookup_payment", new_callable=AsyncMock) as mock:
            mock.return_value = ({"status": "SUCCEEDED", "payment_hash": ph}, None)
            resp = await client.get(f"/v1/payments/lookup/{ph}")

        assert resp.status_code == 200
        assert resp.json()["status"] == "SUCCEEDED"

    @pytest.mark.asyncio
    async def test_lookup_payment_lnd_error(self, authed_client):
        client, _, _ = authed_client
        ph = "cd" * 32

        with patch("app.services.lnd_service.lnd_service.lookup_payment", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get(f"/v1/payments/lookup/{ph}")

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_lookup_payment_invalid_hash(self, authed_client):
        """Non-hex64 payment hash is rejected with 400."""
        client, _, _ = authed_client
        resp = await client.get("/v1/payments/lookup/abc123")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_lookup_invoice_success(self, authed_client):
        client, _, _ = authed_client
        rh = "ef" * 32

        with patch("app.services.lnd_service.lnd_service.lookup_invoice", new_callable=AsyncMock) as mock:
            mock.return_value = ({"r_hash": rh, "settled": True, "value": 1000}, None)
            resp = await client.get(f"/v1/payments/invoice/{rh}")

        assert resp.status_code == 200
        assert resp.json()["settled"] is True

    @pytest.mark.asyncio
    async def test_lookup_invoice_error(self, authed_client):
        client, _, _ = authed_client
        rh = "ef" * 32

        with patch("app.services.lnd_service.lnd_service.lookup_invoice", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "not found")
            resp = await client.get(f"/v1/payments/invoice/{rh}")

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_lookup_invoice_invalid_hash(self, authed_client):
        """Non-hex64 invoice hash is rejected with 400."""
        client, _, _ = authed_client
        resp = await client.get("/v1/payments/invoice/abc")
        assert resp.status_code == 400


# ─── Channel Endpoints ───────────────────────────────────────────────


class TestChannelEndpoints:
    """Tests for /v1/channels/* endpoints."""

    @pytest.mark.asyncio
    async def test_connect_peer_success(self, authed_client):
        client, _, _ = authed_client
        pubkey = "02" + "a" * 64

        with patch("app.services.lnd_service.lnd_service.connect_peer", new_callable=AsyncMock) as mock:
            mock.return_value = ({}, None)
            resp = await client.post(
                "/v1/channels/connect-peer",
                json={
                    "pubkey": pubkey,
                    "host": "1.2.3.4:9735",
                },
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "connected"

    @pytest.mark.asyncio
    async def test_connect_peer_error(self, authed_client):
        client, _, _ = authed_client
        pubkey = "02" + "a" * 64

        with patch("app.services.lnd_service.lnd_service.connect_peer", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "connection refused")
            resp = await client.post(
                "/v1/channels/connect-peer",
                json={
                    "pubkey": pubkey,
                    "host": "1.2.3.4:9735",
                },
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_open_channel_success(self, authed_client):
        client, _, _ = authed_client
        pubkey = "02" + "a" * 64

        with (
            patch("app.api.channels.settings") as mock_settings,
            patch("app.api.channels.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
            patch("app.services.lnd_service.lnd_service.open_channel", new_callable=AsyncMock) as mock,
        ):
            mock_settings.lnd_max_payment_sats = -1
            mock.return_value = ({"funding_txid": "tx123", "output_index": 0}, None)
            resp = await client.post(
                "/v1/channels/open",
                json={
                    "node_pubkey": pubkey,
                    "local_funding_amount": 500000,
                },
            )

        assert resp.status_code == 200
        assert resp.json()["funding_txid"] == "tx123"

    @pytest.mark.asyncio
    async def test_open_channel_error(self, authed_client):
        client, _, _ = authed_client
        pubkey = "02" + "a" * 64

        with (
            patch("app.api.channels.settings") as mock_settings,
            patch("app.api.channels.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
            patch("app.services.lnd_service.lnd_service.open_channel", new_callable=AsyncMock) as mock,
        ):
            mock_settings.lnd_max_payment_sats = -1
            mock.return_value = (None, "not enough funds")
            resp = await client.post(
                "/v1/channels/open",
                json={
                    "node_pubkey": pubkey,
                    "local_funding_amount": 500000,
                },
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_pending_channels_detail_success(self, authed_client):
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_pending_channels_detail", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"type": "pending_open", "capacity": 500000}], None)
            resp = await client.get("/v1/channels/pending/detail")

        assert resp.status_code == 200
        assert len(resp.json()["channels"]) == 1

    @pytest.mark.asyncio
    async def test_pending_channels_detail_lnd_down(self, authed_client):
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_pending_channels_detail", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND unavailable")
            resp = await client.get("/v1/channels/pending/detail")

        assert resp.status_code == 503


# ─── Cold Storage Extended ────────────────────────────────────────────


class TestColdStorageInitiate:
    """Tests for POST /v1/cold-storage/initiate."""

    @pytest.mark.asyncio
    async def test_initiate_swap_success(self, authed_client):
        client, _, _ = authed_client

        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        mock_swap.boltz_swap_id = "boltz-123"
        mock_swap.status.value = "created"
        mock_swap.boltz_status = "swap.created"
        mock_swap.invoice_amount_sats = 100000
        mock_swap.onchain_amount_sats = 98000
        mock_swap.destination_address = "bcrt1qdest"
        mock_swap.fee_percentage = "0.25"
        mock_swap.miner_fee_sats = 5500
        mock_swap.boltz_invoice = "lnbcrt1..."
        mock_swap.claim_txid = None
        mock_swap.error_message = None
        mock_swap.status_history = []
        mock_swap.created_at = None
        mock_swap.updated_at = None
        mock_swap.completed_at = None

        with (
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock_balance,
            patch(
                "app.services.boltz_service.boltz_service.create_reverse_swap", new_callable=AsyncMock
            ) as mock_create,
            patch("app.tasks.boltz_tasks.process_boltz_swap.delay") as mock_celery,
            patch("app.api.cold_storage.check_payment_limits", new_callable=AsyncMock) as mock_rl,
            patch("app.api.cold_storage.settings") as mock_settings,
        ):
            mock_balance.return_value = ({"local_balance_sat": 500000}, None)
            mock_create.return_value = (mock_swap, None)
            mock_rl.return_value = (True, None, None)
            mock_settings.lnd_max_payment_sats = -1

            resp = await client.post(
                "/v1/cold-storage/initiate",
                json={
                    "amount_sats": 100000,
                    "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                },
            )

        assert resp.status_code == 200
        assert resp.json()["boltz_swap_id"] == "boltz-123"
        mock_celery.assert_called_once()

    @pytest.mark.asyncio
    async def test_initiate_swap_insufficient_balance(self, authed_client):
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock,
            patch("app.api.cold_storage.check_payment_limits", new_callable=AsyncMock) as mock_rl,
            patch("app.api.cold_storage.settings") as mock_settings,
        ):
            mock.return_value = ({"local_balance_sat": 10000}, None)
            mock_rl.return_value = (True, None, None)
            mock_settings.lnd_max_payment_sats = -1
            resp = await client.post(
                "/v1/cold-storage/initiate",
                json={
                    "amount_sats": 100000,
                    "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                },
            )

        assert resp.status_code == 400
        assert "Insufficient" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_initiate_swap_boltz_error(self, authed_client):
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock_balance,
            patch(
                "app.services.boltz_service.boltz_service.create_reverse_swap", new_callable=AsyncMock
            ) as mock_create,
            patch("app.api.cold_storage.check_payment_limits", new_callable=AsyncMock) as mock_rl,
            patch("app.api.cold_storage.settings") as mock_settings,
        ):
            mock_balance.return_value = ({"local_balance_sat": 500000}, None)
            mock_create.return_value = (None, "Boltz API unavailable")
            mock_rl.return_value = (True, None, None)
            mock_settings.lnd_max_payment_sats = -1

            resp = await client.post(
                "/v1/cold-storage/initiate",
                json={
                    "amount_sats": 100000,
                    "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                },
            )

        assert resp.status_code == 502


class TestColdStorageCancel:
    """Tests for POST /v1/cold-storage/swaps/{id}/cancel."""

    @pytest.mark.asyncio
    async def test_cancel_swap_success(self, authed_client):
        client, _, key_id = authed_client
        swap_id = uuid4()

        mock_swap = MagicMock()
        mock_swap.id = swap_id
        mock_swap.api_key_id = UUID(key_id)
        mock_swap.boltz_swap_id = "boltz-cancel"
        mock_swap.status.value = "cancelled"
        mock_swap.boltz_status = "swap.created"
        mock_swap.invoice_amount_sats = 100000
        mock_swap.onchain_amount_sats = 98000
        mock_swap.destination_address = "bcrt1qdest"
        mock_swap.fee_percentage = "0.25"
        mock_swap.miner_fee_sats = 5500
        mock_swap.boltz_invoice = "lnbcrt1..."
        mock_swap.claim_txid = None
        mock_swap.error_message = None
        mock_swap.status_history = []
        mock_swap.created_at = None
        mock_swap.updated_at = None
        mock_swap.completed_at = None

        with (
            patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock_get,
            patch("app.services.boltz_service.boltz_service.cancel_swap", new_callable=AsyncMock) as mock_cancel,
        ):
            mock_get.return_value = mock_swap
            mock_cancel.return_value = (True, None)

            resp = await client.post(f"/v1/cold-storage/swaps/{swap_id}/cancel")

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_cancel_invalid_uuid(self, authed_client):
        client, _, _ = authed_client
        resp = await client.post("/v1/cold-storage/swaps/bad-id/cancel")
        assert resp.status_code == 400


# ─── Wallet Extended ─────────────────────────────────────────────────


class TestWalletExtended:
    """Additional wallet endpoint tests."""

    @pytest.mark.asyncio
    async def test_get_fees(self, authed_client):
        client, _, _ = authed_client

        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_recommended_fees", new_callable=AsyncMock
        ) as mock:
            mock.return_value = (
                {"fastestFee": 25, "halfHourFee": 15, "hourFee": 8, "economyFee": 4, "minimumFee": 1},
                None,
            )
            resp = await client.get("/v1/wallet/fees")

        assert resp.status_code == 200
        assert resp.json()["priorities"]["high"]["sat_per_vbyte"] == 25

    @pytest.mark.asyncio
    async def test_get_fees_unavailable(self, authed_client):
        client, _, _ = authed_client

        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_recommended_fees", new_callable=AsyncMock
        ) as mock:
            mock.return_value = (None, "Mempool unavailable")
            resp = await client.get("/v1/wallet/fees")

        assert resp.status_code == 200
        assert resp.json()["unavailable"] is True

    @pytest.mark.asyncio
    async def test_get_node_info_lnd_down(self, authed_client):
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_info", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND unavailable")
            resp = await client.get("/v1/wallet/info")

        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_get_payments(self, authed_client):
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_recent_payments", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"payment_hash": "ph1", "value_sat": 1000}], None)
            resp = await client.get("/v1/wallet/payments")

        assert resp.status_code == 200
        assert len(resp.json()["payments"]) == 1

    @pytest.mark.asyncio
    async def test_get_payments_lnd_down(self, authed_client):
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_recent_payments", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND unavailable")
            resp = await client.get("/v1/wallet/payments")

        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_get_invoices(self, authed_client):
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_recent_invoices", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"r_hash": "rh1", "settled": True}], None)
            resp = await client.get("/v1/wallet/invoices")

        assert resp.status_code == 200
        assert len(resp.json()["invoices"]) == 1

    @pytest.mark.asyncio
    async def test_get_transactions(self, authed_client):
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_onchain_transactions", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"tx_hash": "tx1", "amount": 50000}], None)
            resp = await client.get("/v1/wallet/transactions")

        assert resp.status_code == 200
        assert len(resp.json()["transactions"]) == 1

    @pytest.mark.asyncio
    async def test_get_pending_channels(self, authed_client):
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_pending_channels", new_callable=AsyncMock) as mock:
            mock.return_value = ({"pending_open_channels": 1, "total_limbo_balance": 0}, None)
            resp = await client.get("/v1/wallet/channels/pending")

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_balance_both_lnd_down(self, authed_client):
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.get_wallet_balance", new_callable=AsyncMock) as m1,
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as m2,
        ):
            m1.return_value = (None, "LND error")
            m2.return_value = (None, "LND error")
            resp = await client.get("/v1/wallet/balance")

        assert resp.status_code == 503


# ─── Security Headers ────────────────────────────────────────────────


class TestSecurityHeaders:
    """Verify security headers are present on responses."""

    @pytest.mark.asyncio
    async def test_security_headers_present(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Cache-Control"] == "no-store"

    @pytest.mark.asyncio
    async def test_docs_disabled_by_default(self, client: AsyncClient):
        """OpenAPI docs are disabled when ENABLE_DOCS is False (default)."""
        resp = await client.get("/docs")
        assert resp.status_code == 404

        resp = await client.get("/openapi.json")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_no_hsts_by_default(self, client: AsyncClient):
        """HSTS header absent when enable_hsts is False (default)."""
        resp = await client.get("/health")
        assert "Strict-Transport-Security" not in resp.headers

    @pytest.mark.asyncio
    async def test_hsts_present_when_enabled(self):
        """HSTS header present when enable_hsts is True."""
        from app.core.config import settings
        from app.main import app

        original = settings.enable_hsts
        try:
            settings.enable_hsts = True
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.get("/health")
            assert "Strict-Transport-Security" in resp.headers
            assert "max-age=" in resp.headers["Strict-Transport-Security"]
        finally:
            settings.enable_hsts = original

    @pytest.mark.asyncio
    async def test_docs_csp_relaxed_when_enabled(self):
        """when ``ENABLE_DOCS=true`` the Swagger UI and
        ReDoc pages need to load JS/CSS from a CDN and inline-execute
        bootstrap scripts. The default ``default-src 'none'`` policy
        blanks them out, so the docs paths must receive a relaxed CSP
        that still locks down framing, form posts, and base-uri.
        """
        from app.core.config import settings
        from app.main import app

        original = settings.enable_docs
        try:
            settings.enable_docs = True
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                for path in ("/docs", "/redoc", "/openapi.json"):
                    resp = await ac.get(path)
                    csp = resp.headers.get("Content-Security-Policy", "")
                    assert "cdn.jsdelivr.net" in csp, f"{path} CSP: {csp}"
                    assert "frame-ancestors 'none'" in csp
                    assert "form-action 'none'" in csp
                # A non-docs path under the same app must still get
                # the strict default-src 'none' policy.
                resp = await ac.get("/health")
                assert resp.headers["Content-Security-Policy"].startswith("default-src 'none'")
        finally:
            settings.enable_docs = original

    @pytest.mark.asyncio
    async def test_docs_csp_strict_when_disabled(self):
        """When ``ENABLE_DOCS=false`` (default) the docs paths receive
        the strict default-src 'none' policy — they 404 anyway, but
        the relaxed CSP must not leak."""
        from app.main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/docs")
        assert resp.status_code == 404
        assert resp.headers["Content-Security-Policy"].startswith("default-src 'none'")


# ─── Audit Log Limit Validation ──────────────────────────────────────


class TestAuditLogLimit:
    """Query param `limit` on /v1/admin/audit-log is validated via Query(ge=1, le=200)."""

    @pytest.mark.asyncio
    async def test_limit_zero_rejected(self, authed_client):
        client, _, _ = authed_client
        resp = await client.get("/v1/admin/audit-log", params={"limit": 0})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_limit_negative_rejected(self, authed_client):
        client, _, _ = authed_client
        resp = await client.get("/v1/admin/audit-log", params={"limit": -1})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_limit_over_200_rejected(self, authed_client):
        client, _, _ = authed_client
        resp = await client.get("/v1/admin/audit-log", params={"limit": 201})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_limit_1_accepted(self, authed_client):
        client, _, _ = authed_client
        resp = await client.get("/v1/admin/audit-log", params={"limit": 1})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_limit_200_accepted(self, authed_client):
        client, _, _ = authed_client
        resp = await client.get("/v1/admin/audit-log", params={"limit": 200})
        assert resp.status_code == 200


class TestAPIPrefix:
    """Tests that all routers use the shared API_V1_PREFIX."""

    @pytest.mark.asyncio
    async def test_all_versioned_routes_use_v1_prefix(self, client: AsyncClient):
        """Every non-system, non-framework route should start with /v1/."""
        from app.main import app

        # ``/livez`` is intentionally root-level: Docker / k8s
        # healthcheck convention is unversioned (the probe shouldn't
        # need to know which API version is shipped). Same rationale
        # as the rest of the exclusion list.
        excluded_prefixes = (
            "/health",
            "/livez",
            "/ready",
            "/metrics",
            "/openapi.json",
            "/docs",
            "/redoc",
            "/dashboard",
        )
        for route in app.routes:
            path = getattr(route, "path", None)
            if path and not path.startswith(excluded_prefixes) and not path.startswith("/v1/"):
                pytest.fail(f"Route {path} missing /v1/ prefix")


# ─── Payment Endpoint Edge Cases ─────────────────────────────────────


class TestPaymentEdgeCases:
    """Additional tests for payment endpoints — rate limits, fee estimation, on-chain sends."""

    @pytest.mark.asyncio
    async def test_pay_invoice_rate_limit_exceeded(self, authed_client):
        """Payment blocked by rate limiter returns 429."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_limits,
        ):
            mock_decode.return_value = ({"num_satoshis": 1000, "destination": "02" + "a" * 64}, None)
            mock_limits.return_value = (False, "Spend limit of 100,000 sats exceeded", None)
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "lnbcrt1..."},
            )

        assert resp.status_code == 429
        assert "Spend limit" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_pay_invoice_decode_failure(self, authed_client):
        """Pay fails if invoice cannot be decoded."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "invalid bech32")
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "not-a-real-invoice"},
            )

        assert resp.status_code == 400
        assert "Cannot decode" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_pay_invoice_lnd_error(self, authed_client):
        """Payment returns 502 when LND sends an error."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_limits,
            patch("app.services.lnd_service.lnd_service.send_payment_sync", new_callable=AsyncMock) as mock_pay,
        ):
            mock_decode.return_value = ({"num_satoshis": 1000, "destination": "02" + "a" * 64}, None)
            mock_limits.return_value = (True, None, None)
            mock_pay.return_value = (None, "no route found")
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "lnbcrt1..."},
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_pay_ambiguous_failure_keeps_inflight_marker(self, authed_client):
        """A transport-level send failure with the HTLC possibly in flight
        holds the idempotency slot pending (recording the payment hash) and
        does not release it, so a same-key retry is reconciled, not re-sent."""
        client, _, _ = authed_client
        idem = "12345678-1234-1234-1234-1234567890ab"

        with (
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_limits,
            patch("app.services.lnd_service.lnd_service.send_payment_sync", new_callable=AsyncMock) as mock_pay,
            patch("app.api.payments.lookup_or_reserve", return_value=None),
            patch("app.api.payments.peek", return_value=None),
            patch("app.api.payments.mark_pending") as mock_mark,
            patch("app.api.payments.release_inflight") as mock_release,
        ):
            mock_decode.return_value = (
                {"num_satoshis": 1000, "destination": "02" + "a" * 64, "payment_hash": "ph123"},
                None,
            )
            mock_limits.return_value = (True, None, None)
            mock_pay.return_value = (None, "Connection failed: timed out")
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "lnbcrt1..."},
                headers={"Idempotency-Key": idem},
            )

        assert resp.status_code == 502
        mock_mark.assert_called_once()
        assert mock_mark.call_args.kwargs["payment_hash"] == "ph123"
        mock_release.assert_not_called()

    @pytest.mark.asyncio
    async def test_pay_terminal_failure_releases_marker(self, authed_client):
        """A definitive ``Payment failed:`` outcome means no HTLC settled, so
        the slot is released for an immediate retry."""
        client, _, _ = authed_client
        idem = "12345678-1234-1234-1234-1234567890ac"

        with (
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_limits,
            patch("app.services.lnd_service.lnd_service.send_payment_sync", new_callable=AsyncMock) as mock_pay,
            patch("app.api.payments.lookup_or_reserve", return_value=None),
            patch("app.api.payments.peek", return_value=None),
            patch("app.api.payments.mark_pending") as mock_mark,
            patch("app.api.payments.release_inflight") as mock_release,
        ):
            mock_decode.return_value = (
                {"num_satoshis": 1000, "destination": "02" + "a" * 64, "payment_hash": "ph123"},
                None,
            )
            mock_limits.return_value = (True, None, None)
            mock_pay.return_value = (None, "Payment failed: no_route")
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "lnbcrt1..."},
                headers={"Idempotency-Key": idem},
            )

        assert resp.status_code == 502
        mock_mark.assert_not_called()
        mock_release.assert_called_once()

    @pytest.mark.asyncio
    async def test_pay_reconciles_pending_settled_payment(self, authed_client):
        """A retry whose pending slot resolves to a SUCCEEDED payment returns
        the stored result without sending again."""
        client, _, _ = authed_client
        idem = "12345678-1234-1234-1234-1234567890ad"

        with (
            patch("app.api.payments.peek", return_value={"state": "pending", "payment_hash": "ph9", "fp": "x"}),
            patch("app.services.lnd_service.lnd_service.lookup_payment", new_callable=AsyncMock) as mock_lookup,
            patch("app.api.payments.store_result") as mock_store,
            patch("app.services.lnd_service.lnd_service.send_payment_sync", new_callable=AsyncMock) as mock_pay,
        ):
            mock_lookup.return_value = (
                {"status": "SUCCEEDED", "payment_preimage": "pre", "value_sat": 1000, "fee_sat": 1},
                None,
            )
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "lnbcrt1..."},
                headers={"Idempotency-Key": idem},
            )

        assert resp.status_code == 200
        assert resp.json()["payment_hash"] == "ph9"
        mock_pay.assert_not_called()
        mock_store.assert_called_once()

    @pytest.mark.asyncio
    async def test_pay_invoice_success(self, authed_client):
        """Successful payment returns payment result."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_limits,
            patch("app.services.lnd_service.lnd_service.send_payment_sync", new_callable=AsyncMock) as mock_pay,
        ):
            mock_decode.return_value = (
                {"num_satoshis": 1000, "destination": "02" + "a" * 64, "description": "test"},
                None,
            )
            mock_limits.return_value = (True, None, None)
            mock_pay.return_value = ({"payment_hash": "abc123", "payment_preimage": "def456"}, None)
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "lnbcrt1...", "fee_limit_sats": 10},
            )

        assert resp.status_code == 200
        assert resp.json()["payment_hash"] == "abc123"

    @pytest.mark.asyncio
    async def test_send_onchain_rate_limit_exceeded(self, authed_client):
        """On-chain send blocked by rate limiter returns 429."""
        client, _, _ = authed_client

        with patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_limits:
            mock_limits.return_value = (False, "Velocity limit exceeded", None)
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 5000},
            )

        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_send_onchain_safety_limit(self, authed_client):
        """On-chain send exceeding safety limit returns 400."""
        client, _, _ = authed_client

        resp = await client.post(
            "/v1/payments/send-onchain",
            json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 999999},
        )
        assert resp.status_code == 400
        assert "safety limit" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_send_onchain_success(self, authed_client):
        """Successful on-chain send returns txid."""
        client, _, _ = authed_client

        with (
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_limits,
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock_send,
        ):
            mock_limits.return_value = (True, None, None)
            mock_send.return_value = ({"txid": "onchain_tx_123"}, None)
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 5000},
            )

        assert resp.status_code == 200
        assert resp.json()["txid"] == "onchain_tx_123"

    @pytest.mark.asyncio
    async def test_send_onchain_with_fee_priority(self, authed_client):
        """On-chain send with fee_priority uses mempool rate."""
        client, _, _ = authed_client

        with (
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_limits,
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.get_fee_for_priority", new_callable=AsyncMock
            ) as mock_fee,
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock_send,
        ):
            mock_limits.return_value = (True, None, None)
            mock_fee.return_value = 15
            mock_send.return_value = ({"txid": "tx456"}, None)
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={
                    "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "amount_sats": 5000,
                    "fee_priority": "high",
                },
            )

        assert resp.status_code == 200
        mock_send.assert_called_once()
        call_args = mock_send.call_args
        assert call_args[0][2] == 15  # sat_per_vbyte from mempool

    @pytest.mark.asyncio
    async def test_send_onchain_lnd_error(self, authed_client):
        """On-chain send LND error returns 502."""
        client, _, _ = authed_client

        with (
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock) as mock_limits,
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock_send,
        ):
            mock_limits.return_value = (True, None, None)
            mock_send.return_value = (None, "insufficient funds")
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 5000},
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_estimate_fee_lnd_error(self, authed_client):
        """Fee estimation LND error returns 502."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.estimate_fee", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.post(
                "/v1/payments/estimate-fee",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 50000},
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_lookup_payment_invalid_hash(self, authed_client):
        """Lookup with invalid hash format returns 400."""
        client, _, _ = authed_client
        resp = await client.get("/v1/payments/lookup/not-a-valid-hash")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_lookup_payment_success(self, authed_client):
        """Lookup payment returns payment details."""
        client, _, _ = authed_client
        hash_hex = "ab" * 32
        with patch("app.services.lnd_service.lnd_service.lookup_payment", new_callable=AsyncMock) as mock:
            mock.return_value = ({"status": "SUCCEEDED", "payment_hash": hash_hex, "fee_sat": 5}, None)
            resp = await client.get(f"/v1/payments/lookup/{hash_hex}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "SUCCEEDED"

    @pytest.mark.asyncio
    async def test_lookup_invoice_invalid_hash(self, authed_client):
        """Lookup invoice with invalid hash returns 400."""
        client, _, _ = authed_client
        resp = await client.get("/v1/payments/invoice/short")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_lookup_invoice_success(self, authed_client):
        """Lookup invoice returns invoice details."""
        client, _, _ = authed_client
        hash_hex = "cd" * 32
        with patch("app.services.lnd_service.lnd_service.lookup_invoice", new_callable=AsyncMock) as mock:
            mock.return_value = ({"memo": "test", "settled": True, "value": 1000}, None)
            resp = await client.get(f"/v1/payments/invoice/{hash_hex}")
        assert resp.status_code == 200
        assert resp.json()["settled"] is True

    @pytest.mark.asyncio
    async def test_create_invoice_lnd_error(self, authed_client):
        """Invoice creation LND error returns 502."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.create_invoice", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "wallet locked")
            resp = await client.post(
                "/v1/payments/invoice",
                json={"amount_sats": 1000},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_decode_payment_request_lnd_error(self, authed_client):
        """Decode error returns 502."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.post("/v1/payments/decode", json={"payment_request": "lnbcrt50u1..."})
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_new_address_lnd_error(self, authed_client):
        """New address LND error returns 502."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.new_address", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "wallet not ready")
            resp = await client.post("/v1/payments/address", json={"address_type": "p2tr"})
        assert resp.status_code == 502


# ─── Admin Endpoint Edge Cases ───────────────────────────────────────


class TestScopeEnforcementAtEndpoints:
    """End-to-end proof that the scope gate is wired onto the live
    routes: a monitor key may receive but not spend, a spend key clears
    the spend gate, and a spend key is still denied an admin endpoint."""

    async def _mint(self, db_engine, scope: str) -> str:
        from sqlalchemy.ext.asyncio import async_sessionmaker

        session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
        raw = generate_api_key()
        async with session_factory() as session:
            session.add(
                APIKey(
                    id=uuid4(),
                    name=f"{scope}-key",
                    key_hash=hash_api_key(raw),
                    scope=scope,
                    is_active=True,
                )
            )
            await session.commit()
        return raw

    @pytest.mark.asyncio
    async def test_monitor_key_can_receive(self, client, db_engine):
        # The floor tier may take payments in — generate a receive address.
        raw = await self._mint(db_engine, "monitor")
        client.headers["Authorization"] = f"Bearer {raw}"
        with patch("app.services.lnd_service.lnd_service.new_address", new_callable=AsyncMock) as mock:
            mock.return_value = ({"address": "bcrt1qexampleaddress"}, None)
            resp = await client.post("/v1/payments/address", json={})
        assert resp.status_code != 403

    @pytest.mark.asyncio
    async def test_monitor_key_denied_spend_endpoint(self, client, db_engine):
        # The scope gate denies a monitor key a fund-moving endpoint
        # before the endpoint body runs (no LND / Redis touched).
        raw = await self._mint(db_engine, "monitor")
        client.headers["Authorization"] = f"Bearer {raw}"
        resp = await client.post("/v1/payments/pay", json={"payment_request": "lnbc1bogus"})
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_spend_key_clears_spend_gate(self, client, db_engine):
        raw = await self._mint(db_engine, "spend")
        client.headers["Authorization"] = f"Bearer {raw}"
        with patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "unparseable")
            resp = await client.post("/v1/payments/pay", json={"payment_request": "lnbc1bogus"})
        # Past the gate: the endpoint reached its own decode step and
        # rejected the bogus invoice (400), not an authorization denial.
        assert resp.status_code != 403
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_spend_key_denied_admin_endpoint(self, client, db_engine):
        raw = await self._mint(db_engine, "spend")
        client.headers["Authorization"] = f"Bearer {raw}"
        resp = await client.post(
            "/v1/channels/connect-peer",
            json={"pubkey": "02" + "a" * 64, "host": "203.0.113.5:9735"},
        )
        assert resp.status_code == 403


class TestAdminEdgeCases:
    """The admin API surface is read-only with respect to API keys —
    minting, updating, deleting, and purging are absent so that no API
    key can escalate or revoke another. Those flows are operator-only on
    the dashboard's session-authed router (see
    ``tests/integration/test_dashboard_api_keys.py``)."""

    @pytest.mark.asyncio
    async def test_all_key_mutation_verbs_404(self, authed_client):
        client, _, key_id = authed_client

        results = {
            "patch": (await client.patch(f"/v1/admin/api-keys/{key_id}", json={"name": "x"})).status_code,
            "delete": (await client.delete(f"/v1/admin/api-keys/{key_id}")).status_code,
            "purge": (await client.post(f"/v1/admin/api-keys/{key_id}/purge")).status_code,
        }
        assert results == {"patch": 404, "delete": 404, "purge": 404}

    @pytest.mark.asyncio
    async def test_list_keys_available(self, authed_client):
        """The read-only inventory GET is the admin surface's only key route."""
        client, _, _ = authed_client
        resp = await client.get("/v1/admin/api-keys")
        assert resp.status_code == 200
        assert "keys" in resp.json()

    @pytest.mark.asyncio
    async def test_audit_log_filter_by_action(self, authed_client):
        """GET /v1/admin/audit-log with action filter."""
        client, _, _ = authed_client

        # Trigger an auditable action on the API surface.
        await client.post("/v1/admin/audit-log/reanchor")

        resp = await client.get(
            "/v1/admin/audit-log",
            params={"action": "audit_chain_reanchor"},
        )
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert len(entries) >= 1
        for e in entries:
            assert e["action"] == "audit_chain_reanchor"

    @pytest.mark.asyncio
    async def test_audit_log_with_limit(self, authed_client):
        """GET /v1/admin/audit-log respects limit parameter."""
        client, _, _ = authed_client

        # Generate a few audit entries via a still-existing action.
        for _ in range(3):
            await client.post("/v1/admin/audit-log/reanchor")

        resp = await client.get("/v1/admin/audit-log", params={"limit": 2})
        assert resp.status_code == 200
        assert len(resp.json()["entries"]) <= 2

    @pytest.mark.asyncio
    async def test_list_api_keys_structure(self, authed_client):
        """List API keys returns expected fields and excludes key_hash."""
        client, _, _ = authed_client

        resp = await client.get("/v1/admin/api-keys")
        assert resp.status_code == 200
        keys = resp.json()["keys"]
        assert len(keys) >= 1  # the fixture admin key
        for k in keys:
            assert "id" in k
            assert "name" in k
            assert "scope" in k
            assert "is_admin" in k
            assert "is_active" in k
            assert "created_at" in k
            assert "key_hash" not in k
            assert "key" not in k

    @pytest.mark.asyncio
    async def test_health_check_lnd_exception(self, authed_client):
        """Health check returns degraded when LND throws an exception."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_info", new_callable=AsyncMock) as mock:
            mock.side_effect = Exception("connection reset")
            resp = await client.get("/v1/admin/health")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["lnd_connected"] is False
        assert data["lnd_info"] is None

    @pytest.mark.asyncio
    async def test_health_check_response_fields(self, authed_client):
        """Health check includes all LND info fields when healthy."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_info", new_callable=AsyncMock) as mock:
            mock.return_value = (
                {
                    "alias": "my-node",
                    "synced_to_chain": True,
                    "block_height": 850000,
                    "version": "0.18.3",
                },
                None,
            )
            resp = await client.get("/v1/admin/health")

        assert resp.status_code == 200
        data = resp.json()
        assert data["lnd_info"]["alias"] == "my-node"
        assert data["lnd_info"]["synced_to_chain"] is True
        assert data["lnd_info"]["block_height"] == 850000
        assert data["lnd_info"]["version"] == "0.18.3"


class TestColdStorageEdgeCases:
    """Additional tests for cold storage endpoints."""

    @pytest.mark.asyncio
    async def test_initiate_swap_insufficient_balance(self, authed_client):
        """Initiate swap fails when Lightning balance is insufficient."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock_bal,
            patch("app.api.cold_storage.check_payment_limits", new_callable=AsyncMock) as mock_rl,
            patch("app.api.cold_storage.settings") as mock_settings,
        ):
            mock_bal.return_value = ({"local_balance_sat": 10000}, None)
            mock_rl.return_value = (True, None, None)
            mock_settings.lnd_max_payment_sats = -1
            resp = await client.post(
                "/v1/cold-storage/initiate",
                json={"amount_sats": 100000, "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
            )

        assert resp.status_code == 400
        assert "Insufficient" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_initiate_swap_boltz_error(self, authed_client):
        """Initiate swap returns 502 when Boltz API fails."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock_bal,
            patch("app.services.boltz_service.boltz_service.create_reverse_swap", new_callable=AsyncMock) as mock_swap,
            patch("app.api.cold_storage.check_payment_limits", new_callable=AsyncMock) as mock_rl,
            patch("app.api.cold_storage.settings") as mock_settings,
        ):
            mock_bal.return_value = ({"local_balance_sat": 500000}, None)
            mock_swap.return_value = (None, "Boltz API 503: Service Unavailable")
            mock_rl.return_value = (True, None, None)
            mock_settings.lnd_max_payment_sats = -1
            resp = await client.post(
                "/v1/cold-storage/initiate",
                json={"amount_sats": 100000, "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_initiate_swap_success(self, authed_client):
        """Successful swap initiation returns swap details."""
        client, _, _ = authed_client
        from datetime import datetime, timezone

        from app.models.boltz_swap import SwapStatus

        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        mock_swap.boltz_swap_id = "boltz-123"
        mock_swap.status = SwapStatus.CREATED
        mock_swap.boltz_status = "swap.created"
        mock_swap.invoice_amount_sats = 100000
        mock_swap.onchain_amount_sats = 98000
        mock_swap.destination_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        mock_swap.fee_percentage = "0.25"
        mock_swap.miner_fee_sats = 5500
        mock_swap.boltz_invoice = "lnbcrt1..."
        mock_swap.claim_txid = None
        mock_swap.error_message = None
        mock_swap.status_history = [{"status": "created"}]
        mock_swap.created_at = datetime.now(timezone.utc)
        mock_swap.updated_at = None
        mock_swap.completed_at = None

        with (
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock_bal,
            patch(
                "app.services.boltz_service.boltz_service.create_reverse_swap", new_callable=AsyncMock
            ) as mock_create,
            patch("app.tasks.boltz_tasks.process_boltz_swap") as mock_task,
            patch("app.api.cold_storage.check_payment_limits", new_callable=AsyncMock) as mock_rl,
            patch("app.api.cold_storage.settings") as mock_settings,
        ):
            mock_bal.return_value = ({"local_balance_sat": 500000}, None)
            mock_create.return_value = (mock_swap, None)
            mock_task.delay = MagicMock()
            mock_rl.return_value = (True, None, None)
            mock_settings.lnd_max_payment_sats = -1
            resp = await client.post(
                "/v1/cold-storage/initiate",
                json={"amount_sats": 100000, "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["boltz_swap_id"] == "boltz-123"
        assert data["status"] == "created"
        mock_task.delay.assert_called_once()

    @pytest.mark.asyncio
    async def test_cancel_swap_success(self, authed_client):
        """Cancel a swap in CREATED state."""
        client, _, key_id = authed_client
        from datetime import datetime, timezone

        from app.models.boltz_swap import SwapStatus

        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        mock_swap.api_key_id = UUID(key_id)
        mock_swap.boltz_swap_id = "boltz-cancel"
        mock_swap.status = SwapStatus.CANCELLED
        mock_swap.boltz_status = "swap.created"
        mock_swap.invoice_amount_sats = 50000
        mock_swap.onchain_amount_sats = 48000
        mock_swap.destination_address = "bcrt1qtest"
        mock_swap.fee_percentage = "0.25"
        mock_swap.miner_fee_sats = 5500
        mock_swap.boltz_invoice = "lnbcrt1..."
        mock_swap.claim_txid = None
        mock_swap.error_message = "Cancelled by API client"
        mock_swap.status_history = [{"status": "cancelled"}]
        mock_swap.created_at = datetime.now(timezone.utc)
        mock_swap.updated_at = None
        mock_swap.completed_at = datetime.now(timezone.utc)

        swap_id = str(uuid4())
        with (
            patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock_get,
            patch("app.services.boltz_service.boltz_service.cancel_swap", new_callable=AsyncMock) as mock_cancel,
        ):
            mock_get.return_value = mock_swap
            mock_cancel.return_value = (True, None)
            resp = await client.post(f"/v1/cold-storage/swaps/{swap_id}/cancel")

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_cancel_swap_not_found(self, authed_client):
        """Cancel non-existent swap returns 404."""
        client, _, _ = authed_client
        swap_id = str(uuid4())
        with patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock:
            mock.return_value = None
            resp = await client.post(f"/v1/cold-storage/swaps/{swap_id}/cancel")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cancel_swap_wrong_state(self, authed_client):
        """Cancel swap that's not cancellable returns 400."""
        client, _, key_id = authed_client

        mock_swap = MagicMock()
        mock_swap.api_key_id = UUID(key_id)

        swap_id = str(uuid4())
        with (
            patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock_get,
            patch("app.services.boltz_service.boltz_service.cancel_swap", new_callable=AsyncMock) as mock_cancel,
        ):
            mock_get.return_value = mock_swap
            mock_cancel.return_value = (False, "Cannot cancel swap in status 'invoice_paid'")
            resp = await client.post(f"/v1/cold-storage/swaps/{swap_id}/cancel")

        assert resp.status_code == 400
        assert "Cannot cancel" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_cancel_swap_invalid_id(self, authed_client):
        """Cancel with invalid UUID returns 400."""
        client, _, _ = authed_client
        resp = await client.post("/v1/cold-storage/swaps/not-a-uuid/cancel")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_get_swap_fees_error(self, authed_client):
        """GET /v1/cold-storage/fees returns 503 when Boltz is down."""
        client, _, _ = authed_client
        with patch("app.services.boltz_service.boltz_service.get_reverse_pair_info", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "Tor connection failed")
            resp = await client.get("/v1/cold-storage/fees")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_get_swap_status_wrong_api_key(self, authed_client):
        """Swap belonging to different key returns 404 (not 403)."""
        client, _, key_id = authed_client
        swap_id = str(uuid4())

        mock_swap = MagicMock()
        mock_swap.api_key_id = uuid4()  # Different key

        with patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock:
            mock.return_value = mock_swap
            resp = await client.get(f"/v1/cold-storage/swaps/{swap_id}")

        assert resp.status_code == 404


# ─── Channel Endpoint Tests ──────────────────────────────────────────


class TestChannelEndpointsExtended:
    """Extended tests for /v1/channels/* endpoints."""

    @pytest.mark.asyncio
    async def test_connect_peer_success(self, authed_client):
        """POST /v1/channels/connect-peer connects successfully."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.connect_peer", new_callable=AsyncMock) as mock:
            mock.return_value = ({}, None)
            resp = await client.post(
                "/v1/channels/connect-peer",
                json={"pubkey": "02" + "a" * 64, "host": "1.2.3.4:9735"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "connected"

    @pytest.mark.asyncio
    async def test_connect_peer_error(self, authed_client):
        """POST /v1/channels/connect-peer returns 502 on error."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.connect_peer", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "connection refused")
            resp = await client.post(
                "/v1/channels/connect-peer",
                json={"pubkey": "02" + "a" * 64, "host": "1.2.3.4:9735"},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_open_channel_success(self, authed_client):
        """POST /v1/channels/open opens a channel."""
        client, _, _ = authed_client
        with (
            patch("app.services.lnd_service.lnd_service.open_channel", new_callable=AsyncMock) as mock,
            patch("app.api.channels.check_payment_limits", new_callable=AsyncMock) as mock_rl,
            patch("app.api.channels.settings") as mock_settings,
        ):
            mock.return_value = ({"funding_txid": "abc123", "output_index": 0}, None)
            mock_rl.return_value = (True, None, None)
            mock_settings.lnd_max_payment_sats = -1
            resp = await client.post(
                "/v1/channels/open",
                json={"node_pubkey": "02" + "a" * 64, "local_funding_amount": 500000},
            )
        assert resp.status_code == 200
        assert resp.json()["funding_txid"] == "abc123"

    @pytest.mark.asyncio
    async def test_open_channel_error(self, authed_client):
        """POST /v1/channels/open returns 502 on error."""
        client, _, _ = authed_client
        with (
            patch("app.services.lnd_service.lnd_service.open_channel", new_callable=AsyncMock) as mock,
            patch("app.api.channels.check_payment_limits", new_callable=AsyncMock) as mock_rl,
            patch("app.api.channels.settings") as mock_settings,
        ):
            mock.return_value = (None, "not enough funds")
            mock_rl.return_value = (True, None, None)
            mock_settings.lnd_max_payment_sats = -1
            resp = await client.post(
                "/v1/channels/open",
                json={"node_pubkey": "02" + "a" * 64, "local_funding_amount": 500000},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_get_pending_channels_detail_success(self, authed_client):
        """GET /v1/channels/pending/detail returns channel data."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_pending_channels_detail", new_callable=AsyncMock) as mock:
            mock.return_value = (
                [
                    {"type": "pending_open", "remote_node_pub": "pub1"},
                    {"type": "force_closing", "remote_node_pub": "pub2"},
                ],
                None,
            )
            resp = await client.get("/v1/channels/pending/detail")
        assert resp.status_code == 200
        assert len(resp.json()["channels"]) == 2

    @pytest.mark.asyncio
    async def test_get_pending_channels_detail_error(self, authed_client):
        """GET /v1/channels/pending/detail returns 503 on error."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_pending_channels_detail", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND not available")
            resp = await client.get("/v1/channels/pending/detail")
        assert resp.status_code == 503


# ─── Wallet Endpoint Edge Cases ──────────────────────────────────────


class TestWalletEdgeCases:
    """Additional wallet endpoint tests."""

    @pytest.mark.asyncio
    async def test_wallet_info_lnd_down(self, authed_client):
        """GET /v1/wallet/info returns 503 when LND is unreachable."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_info", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "connection failed")
            resp = await client.get("/v1/wallet/info")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_wallet_balance_both_fail(self, authed_client):
        """GET /v1/wallet/balance returns 503 when both balances fail."""
        client, _, _ = authed_client
        with (
            patch("app.services.lnd_service.lnd_service.get_wallet_balance", new_callable=AsyncMock) as mock_w,
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock_c,
        ):
            mock_w.return_value = (None, "LND error")
            mock_c.return_value = (None, "LND error")
            resp = await client.get("/v1/wallet/balance")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_wallet_balance_partial_success(self, authed_client):
        """GET /v1/wallet/balance succeeds when only one balance is available."""
        client, _, _ = authed_client
        with (
            patch("app.services.lnd_service.lnd_service.get_wallet_balance", new_callable=AsyncMock) as mock_w,
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock_c,
        ):
            mock_w.return_value = ({"total_balance": 100000}, None)
            mock_c.return_value = (None, "LND error")
            resp = await client.get("/v1/wallet/balance")
        assert resp.status_code == 200
        assert resp.json()["onchain"]["total_balance"] == 100000
        assert resp.json()["lightning"] is None

    @pytest.mark.asyncio
    async def test_wallet_channels_error(self, authed_client):
        """GET /v1/wallet/channels returns 503 on error."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_channels", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get("/v1/wallet/channels")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_wallet_channels_empty(self, authed_client):
        """GET /v1/wallet/channels returns empty list."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_channels", new_callable=AsyncMock) as mock:
            mock.return_value = ([], None)
            resp = await client.get("/v1/wallet/channels")
        assert resp.status_code == 200
        assert resp.json()["channels"] == []

    @pytest.mark.asyncio
    async def test_wallet_pending_channels(self, authed_client):
        """GET /v1/wallet/channels/pending returns pending data."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_pending_channels", new_callable=AsyncMock) as mock:
            mock.return_value = ({"pending_open_channels": 1, "total_limbo_balance": 0}, None)
            resp = await client.get("/v1/wallet/channels/pending")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_wallet_pending_channels_error(self, authed_client):
        """GET /v1/wallet/channels/pending 503 on error."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_pending_channels", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get("/v1/wallet/channels/pending")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_wallet_payments(self, authed_client):
        """GET /v1/wallet/payments returns payment list."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_recent_payments", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"payment_hash": "h1", "value_sat": 5000}], None)
            resp = await client.get("/v1/wallet/payments")
        assert resp.status_code == 200
        assert len(resp.json()["payments"]) == 1

    @pytest.mark.asyncio
    async def test_wallet_payments_error(self, authed_client):
        """GET /v1/wallet/payments 503 on error."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_recent_payments", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get("/v1/wallet/payments")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_wallet_invoices(self, authed_client):
        """GET /v1/wallet/invoices returns invoice list."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_recent_invoices", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"memo": "test", "settled": True}], None)
            resp = await client.get("/v1/wallet/invoices")
        assert resp.status_code == 200
        assert len(resp.json()["invoices"]) == 1

    @pytest.mark.asyncio
    async def test_wallet_invoices_error(self, authed_client):
        """GET /v1/wallet/invoices 503 on error."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_recent_invoices", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get("/v1/wallet/invoices")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_wallet_transactions(self, authed_client):
        """GET /v1/wallet/transactions returns tx list."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_onchain_transactions", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"tx_hash": "tx1", "amount": 50000}], None)
            resp = await client.get("/v1/wallet/transactions")
        assert resp.status_code == 200
        assert len(resp.json()["transactions"]) == 1

    @pytest.mark.asyncio
    async def test_wallet_transactions_error(self, authed_client):
        """GET /v1/wallet/transactions 503 on error."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_onchain_transactions", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get("/v1/wallet/transactions")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_wallet_fees_available(self, authed_client):
        """GET /v1/wallet/fees returns fee estimates."""
        client, _, _ = authed_client
        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_recommended_fees", new_callable=AsyncMock
        ) as mock:
            mock.return_value = (
                {"fastestFee": 50, "halfHourFee": 25, "hourFee": 10, "economyFee": 5, "minimumFee": 1},
                None,
            )
            resp = await client.get("/v1/wallet/fees")
        assert resp.status_code == 200
        data = resp.json()
        assert data["priorities"]["high"]["sat_per_vbyte"] == 50

    @pytest.mark.asyncio
    async def test_wallet_fees_unavailable(self, authed_client):
        """GET /v1/wallet/fees returns graceful response when mempool is down."""
        client, _, _ = authed_client
        with patch(
            "app.services.mempool_fee_service.mempool_fee_service.get_recommended_fees", new_callable=AsyncMock
        ) as mock:
            mock.return_value = (None, "mempool unreachable")
            resp = await client.get("/v1/wallet/fees")
        assert resp.status_code == 200
        data = resp.json()
        assert data["unavailable"] is True


# ─── Additional Wallet Endpoints ─────────────────────────────────────


class TestWalletEndpointsExtended:
    """Tests for additional wallet endpoints."""

    @pytest.mark.asyncio
    async def test_get_pending_channels(self, authed_client):
        """GET /v1/wallet/channels/pending returns pending channels."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_pending_channels", new_callable=AsyncMock) as mock:
            mock.return_value = (
                {
                    "pending_open_channels": 1,
                    "pending_closing_channels": 0,
                    "pending_force_closing_channels": 0,
                    "waiting_close_channels": 0,
                    "total_limbo_balance": 0,
                },
                None,
            )
            resp = await client.get("/v1/wallet/channels/pending")
        assert resp.status_code == 200
        assert resp.json()["pending_open_channels"] == 1

    @pytest.mark.asyncio
    async def test_get_pending_channels_error(self, authed_client):
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_pending_channels", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND unreachable")
            resp = await client.get("/v1/wallet/channels/pending")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_get_payments(self, authed_client):
        """GET /v1/wallet/payments returns payment list."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_recent_payments", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"payment_hash": "h1", "value_sat": 1000, "status": "SUCCEEDED"}], None)
            resp = await client.get("/v1/wallet/payments")
        assert resp.status_code == 200
        assert len(resp.json()["payments"]) == 1

    @pytest.mark.asyncio
    async def test_get_payments_error(self, authed_client):
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_recent_payments", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get("/v1/wallet/payments")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_get_invoices(self, authed_client):
        """GET /v1/wallet/invoices returns invoice list."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_recent_invoices", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"memo": "test", "value": 500, "settled": True}], None)
            resp = await client.get("/v1/wallet/invoices")
        assert resp.status_code == 200
        assert len(resp.json()["invoices"]) == 1

    @pytest.mark.asyncio
    async def test_get_invoices_error(self, authed_client):
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_recent_invoices", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get("/v1/wallet/invoices")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_get_transactions(self, authed_client):
        """GET /v1/wallet/transactions returns transaction list."""
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_onchain_transactions", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"tx_hash": "tx1", "amount": 50000}], None)
            resp = await client.get("/v1/wallet/transactions")
        assert resp.status_code == 200
        assert len(resp.json()["transactions"]) == 1

    @pytest.mark.asyncio
    async def test_get_transactions_error(self, authed_client):
        client, _, _ = authed_client
        with patch("app.services.lnd_service.lnd_service.get_onchain_transactions", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get("/v1/wallet/transactions")
        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_wallet_balance_both_unavailable(self, authed_client):
        """GET /v1/wallet/balance returns 503 when both balances fail."""
        client, _, _ = authed_client
        with (
            patch("app.services.lnd_service.lnd_service.get_wallet_balance", new_callable=AsyncMock) as mock_w,
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock_c,
        ):
            mock_w.return_value = (None, "LND unreachable")
            mock_c.return_value = (None, "LND unreachable")
            resp = await client.get("/v1/wallet/balance")
        assert resp.status_code == 503


# ─── Additional Payment Endpoints ────────────────────────────────────


class TestPaymentEndpointsExtended:
    """Tests for additional payment endpoints."""

    @pytest.mark.asyncio
    async def test_pay_invoice_success(self, authed_client):
        """POST /v1/payments/pay succeeds with valid amount under limit."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch("app.services.lnd_service.lnd_service.send_payment_sync", new_callable=AsyncMock) as mock_pay,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
        ):
            mock_decode.return_value = (
                {"num_satoshis": 100, "destination": "02" + "a" * 64, "description": "test"},
                None,
            )
            mock_pay.return_value = ({"payment_hash": "abc", "payment_preimage": "def"}, None)
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "lnbcrt1..."},
            )

        assert resp.status_code == 200
        assert resp.json()["payment_hash"] == "abc"

    @pytest.mark.asyncio
    async def test_pay_invoice_rate_limited(self, authed_client):
        """POST /v1/payments/pay returns 429 when rate limited."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch(
                "app.api.payments.check_payment_limits",
                new_callable=AsyncMock,
                return_value=(False, "Spend limit reached", None),
            ),
        ):
            mock_decode.return_value = ({"num_satoshis": 100, "destination": "02" + "a" * 64}, None)
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "lnbcrt1..."},
            )

        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_pay_invoice_lnd_error(self, authed_client):
        """POST /v1/payments/pay returns 502 on LND payment failure."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch("app.services.lnd_service.lnd_service.send_payment_sync", new_callable=AsyncMock) as mock_pay,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
        ):
            mock_decode.return_value = ({"num_satoshis": 100, "destination": "02" + "a" * 64}, None)
            mock_pay.return_value = (None, "no route found")
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "lnbcrt1..."},
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_pay_invoice_decode_error(self, authed_client):
        """POST /v1/payments/pay returns 400 when decode fails."""
        client, _, _ = authed_client

        with patch(
            "app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock
        ) as mock_decode:
            mock_decode.return_value = (None, "bad invoice")
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "invalid..."},
            )

        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_send_onchain_success(self, authed_client):
        """POST /v1/payments/send-onchain succeeds."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock_send,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
        ):
            mock_send.return_value = ({"txid": "tx123"}, None)
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 5000},
            )

        assert resp.status_code == 200
        assert resp.json()["txid"] == "tx123"

    @pytest.mark.asyncio
    async def test_send_onchain_safety_limit(self, authed_client):
        """POST /v1/payments/send-onchain rejects exceeding safety limit."""
        client, _, _ = authed_client

        resp = await client.post(
            "/v1/payments/send-onchain",
            json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 999999},
        )

        assert resp.status_code == 400
        assert "safety limit" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_send_onchain_rate_limited(self, authed_client):
        """POST /v1/payments/send-onchain returns 429 when rate limited."""
        client, _, _ = authed_client

        with patch(
            "app.api.payments.check_payment_limits", new_callable=AsyncMock, return_value=(False, "Spend limit", None)
        ):
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 1000},
            )

        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_send_onchain_lnd_error(self, authed_client):
        """POST /v1/payments/send-onchain returns 502 on LND error."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock_send,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
        ):
            mock_send.return_value = (None, "insufficient funds")
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 1000},
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_send_onchain_with_fee_priority(self, authed_client):
        """POST /v1/payments/send-onchain uses mempool fee for priority."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.send_coins", new_callable=AsyncMock) as mock_send,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.get_fee_for_priority",
                new_callable=AsyncMock,
                return_value=25,
            ),
        ):
            mock_send.return_value = ({"txid": "tx456"}, None)
            resp = await client.post(
                "/v1/payments/send-onchain",
                json={
                    "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "amount_sats": 1000,
                    "fee_priority": "medium",
                },
            )

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_lookup_payment_success(self, authed_client):
        """GET /v1/payments/lookup/{hash} returns payment info."""
        client, _, _ = authed_client
        payment_hash = "ab" * 32

        with patch("app.services.lnd_service.lnd_service.lookup_payment", new_callable=AsyncMock) as mock:
            mock.return_value = ({"status": "SUCCEEDED", "payment_hash": payment_hash, "fee_sat": 5}, None)
            resp = await client.get(f"/v1/payments/lookup/{payment_hash}")

        assert resp.status_code == 200
        assert resp.json()["status"] == "SUCCEEDED"

    @pytest.mark.asyncio
    async def test_lookup_payment_invalid_hash(self, authed_client):
        """GET /v1/payments/lookup/{hash} rejects invalid hash."""
        client, _, _ = authed_client
        resp = await client.get("/v1/payments/lookup/not-a-valid-hash")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_lookup_payment_lnd_error(self, authed_client):
        """GET /v1/payments/lookup/{hash} returns 502 on LND error."""
        client, _, _ = authed_client
        payment_hash = "ab" * 32

        with patch("app.services.lnd_service.lnd_service.lookup_payment", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get(f"/v1/payments/lookup/{payment_hash}")

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_lookup_invoice_success(self, authed_client):
        """GET /v1/payments/invoice/{hash} returns invoice info."""
        client, _, _ = authed_client
        r_hash = "cd" * 32

        with patch("app.services.lnd_service.lnd_service.lookup_invoice", new_callable=AsyncMock) as mock:
            mock.return_value = ({"r_hash": r_hash, "value": 1000, "settled": True}, None)
            resp = await client.get(f"/v1/payments/invoice/{r_hash}")

        assert resp.status_code == 200
        assert resp.json()["settled"] is True

    @pytest.mark.asyncio
    async def test_lookup_invoice_invalid_hash(self, authed_client):
        """GET /v1/payments/invoice/{hash} rejects invalid hash."""
        client, _, _ = authed_client
        resp = await client.get("/v1/payments/invoice/not-valid")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_lookup_invoice_lnd_error(self, authed_client):
        """GET /v1/payments/invoice/{hash} returns 502 on LND error."""
        client, _, _ = authed_client
        r_hash = "cd" * 32

        with patch("app.services.lnd_service.lnd_service.lookup_invoice", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get(f"/v1/payments/invoice/{r_hash}")

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_new_address_lnd_error(self, authed_client):
        """POST /v1/payments/address returns 502 on LND error."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.new_address", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "wallet locked")
            resp = await client.post(
                "/v1/payments/address",
                json={"address_type": "p2tr"},
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_create_invoice_lnd_error(self, authed_client):
        """POST /v1/payments/invoice returns 502 on LND error."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.create_invoice", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.post(
                "/v1/payments/invoice",
                json={"amount_sats": 1000, "memo": "test"},
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_pay_invoice_no_limit(self, authed_client):
        """POST /v1/payments/pay succeeds when max_payment_sats is -1 (no limit)."""
        client, _, _ = authed_client

        with (
            patch("app.api.payments.settings") as mock_settings,
            patch("app.services.lnd_service.lnd_service.decode_payment_request", new_callable=AsyncMock) as mock_decode,
            patch("app.services.lnd_service.lnd_service.send_payment_sync", new_callable=AsyncMock) as mock_pay,
            patch("app.api.payments.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
        ):
            mock_settings.lnd_max_payment_sats = -1
            mock_decode.return_value = (
                {"num_satoshis": 999999, "destination": "02" + "a" * 64, "description": ""},
                None,
            )
            mock_pay.return_value = ({"payment_hash": "abc"}, None)
            resp = await client.post(
                "/v1/payments/pay",
                json={"payment_request": "lnbcrt1..."},
            )

        assert resp.status_code == 200


# Admin API-key *mutation* (create / update / delete / purge) is not on
# this API-key-authed surface — see ``TestAdminEdgeCases`` for the
# route-absence checks and ``test_dashboard_api_keys.py`` for the
# session-authed lifecycle coverage.


# ─── Channel Endpoints ───────────────────────────────────────────────


class TestChannelEndpointsSafety:
    """Safety and error tests for /v1/channels/* endpoints."""

    @pytest.mark.asyncio
    async def test_connect_peer_success(self, authed_client):
        """POST /v1/channels/connect-peer connects to a peer."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.connect_peer", new_callable=AsyncMock) as mock:
            mock.return_value = ({}, None)
            resp = await client.post(
                "/v1/channels/connect-peer",
                json={"pubkey": "02" + "a" * 64, "host": "1.2.3.4:9735"},
            )

        assert resp.status_code == 200
        assert resp.json()["status"] == "connected"

    @pytest.mark.asyncio
    async def test_connect_peer_error(self, authed_client):
        """POST /v1/channels/connect-peer returns 502 on LND error."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.connect_peer", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "connection refused")
            resp = await client.post(
                "/v1/channels/connect-peer",
                json={"pubkey": "02" + "a" * 64, "host": "1.2.3.4:9735"},
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_open_channel_success(self, authed_client):
        """POST /v1/channels/open opens a channel."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.open_channel", new_callable=AsyncMock) as mock,
            patch("app.api.channels.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
        ):
            mock.return_value = ({"funding_txid": "tx123", "output_index": 0}, None)
            resp = await client.post(
                "/v1/channels/open",
                json={"node_pubkey": "02" + "a" * 64, "local_funding_amount": 5000},
            )

        assert resp.status_code == 200
        assert resp.json()["funding_txid"] == "tx123"

    @pytest.mark.asyncio
    async def test_open_channel_safety_limit(self, authed_client):
        """POST /v1/channels/open rejects amount exceeding safety limit."""
        client, _, _ = authed_client

        resp = await client.post(
            "/v1/channels/open",
            json={"node_pubkey": "02" + "a" * 64, "local_funding_amount": 999999},
        )

        assert resp.status_code == 400
        assert "safety limit" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_open_channel_rate_limited(self, authed_client):
        """POST /v1/channels/open returns 429 when rate limited."""
        client, _, _ = authed_client

        with patch(
            "app.api.channels.check_payment_limits", new_callable=AsyncMock, return_value=(False, "Spend limit", None)
        ):
            resp = await client.post(
                "/v1/channels/open",
                json={"node_pubkey": "02" + "a" * 64, "local_funding_amount": 5000},
            )

        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_open_channel_lnd_error(self, authed_client):
        """POST /v1/channels/open returns 502 on LND error."""
        client, _, _ = authed_client

        with (
            patch("app.services.lnd_service.lnd_service.open_channel", new_callable=AsyncMock) as mock,
            patch("app.api.channels.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
        ):
            mock.return_value = (None, "insufficient funds")
            resp = await client.post(
                "/v1/channels/open",
                json={"node_pubkey": "02" + "a" * 64, "local_funding_amount": 5000},
            )

        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_get_pending_channels_detail(self, authed_client):
        """GET /v1/channels/pending/detail returns detailed pending channel info."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_pending_channels_detail", new_callable=AsyncMock) as mock:
            mock.return_value = ([{"type": "pending_open", "capacity": 100000}], None)
            resp = await client.get("/v1/channels/pending/detail")

        assert resp.status_code == 200
        assert len(resp.json()["channels"]) == 1

    @pytest.mark.asyncio
    async def test_get_pending_channels_detail_error(self, authed_client):
        """GET /v1/channels/pending/detail returns 503 on LND error."""
        client, _, _ = authed_client

        with patch("app.services.lnd_service.lnd_service.get_pending_channels_detail", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "LND error")
            resp = await client.get("/v1/channels/pending/detail")

        assert resp.status_code == 503


# ─── Additional Cold Storage Endpoints ────────────────────────────────


class TestColdStorageEndpointsExtended:
    """Tests for additional cold storage endpoints."""

    @pytest.mark.asyncio
    async def test_get_swap_fees_error(self, authed_client):
        """GET /v1/cold-storage/fees returns 503 when Boltz is unavailable."""
        client, _, _ = authed_client

        with patch("app.services.boltz_service.boltz_service.get_reverse_pair_info", new_callable=AsyncMock) as mock:
            mock.return_value = (None, "Boltz timeout")
            resp = await client.get("/v1/cold-storage/fees")

        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_get_swap_status_success(self, authed_client):
        """GET /v1/cold-storage/swaps/{id} returns swap info."""
        client, _, key_id = authed_client

        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        mock_swap.api_key_id = UUID(key_id)
        mock_swap.boltz_swap_id = "swap-123"
        mock_swap.status = MagicMock(value="created")
        mock_swap.boltz_status = "swap.created"
        mock_swap.invoice_amount_sats = 50000
        mock_swap.onchain_amount_sats = 48000
        mock_swap.destination_address = "bcrt1qdest"
        mock_swap.fee_percentage = "0.25"
        mock_swap.miner_fee_sats = 5500
        mock_swap.boltz_invoice = "lnbcrt1..."
        mock_swap.claim_txid = None
        mock_swap.error_message = None
        mock_swap.status_history = []
        mock_swap.created_at = None
        mock_swap.updated_at = None
        mock_swap.completed_at = None

        with patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock:
            mock.return_value = mock_swap
            resp = await client.get(f"/v1/cold-storage/swaps/{mock_swap.id}")

        assert resp.status_code == 200
        assert resp.json()["boltz_swap_id"] == "swap-123"

    @pytest.mark.asyncio
    async def test_get_swap_status_wrong_key(self, authed_client):
        """GET /v1/cold-storage/swaps/{id} returns 404 for swap belonging to another key."""
        client, _, key_id = authed_client

        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        mock_swap.api_key_id = uuid4()  # different key

        with patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock:
            mock.return_value = mock_swap
            resp = await client.get(f"/v1/cold-storage/swaps/{mock_swap.id}")

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_initiate_swap_success(self, authed_client):
        """POST /v1/cold-storage/initiate creates a swap."""
        client, _, key_id = authed_client

        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        mock_swap.boltz_swap_id = "new-swap"
        mock_swap.status = MagicMock(value="created")
        mock_swap.boltz_status = "swap.created"
        mock_swap.invoice_amount_sats = 50000
        mock_swap.onchain_amount_sats = 48000
        mock_swap.destination_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        mock_swap.fee_percentage = "0.25"
        mock_swap.miner_fee_sats = 200
        mock_swap.boltz_invoice = "lnbcrt1..."
        mock_swap.claim_txid = None
        mock_swap.error_message = None
        mock_swap.status_history = []
        mock_swap.created_at = None
        mock_swap.updated_at = None
        mock_swap.completed_at = None

        with (
            patch("app.api.cold_storage.settings") as mock_settings,
            patch(
                "app.services.boltz_service.boltz_service.create_reverse_swap", new_callable=AsyncMock
            ) as mock_create,
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock_bal,
            patch("app.api.cold_storage.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
            patch("app.tasks.boltz_tasks.process_boltz_swap") as mock_task,
        ):
            mock_settings.lnd_max_payment_sats = 100000
            mock_settings.bitcoin_network = "regtest"
            mock_create.return_value = (mock_swap, None)
            mock_bal.return_value = ({"local_balance_sat": 500000}, None)
            mock_task.delay = MagicMock()
            resp = await client.post(
                "/v1/cold-storage/initiate",
                json={"amount_sats": 50000, "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
            )

        assert resp.status_code == 200
        assert resp.json()["boltz_swap_id"] == "new-swap"

    @pytest.mark.asyncio
    async def test_initiate_swap_safety_limit(self, authed_client):
        """POST /v1/cold-storage/initiate rejects amount exceeding safety limit."""
        client, _, _ = authed_client

        with patch("app.api.cold_storage.settings") as mock_settings:
            mock_settings.lnd_max_payment_sats = 25000
            mock_settings.bitcoin_network = "regtest"
            resp = await client.post(
                "/v1/cold-storage/initiate",
                json={"amount_sats": 50000, "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
            )

        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_initiate_swap_safety_limit_includes_routing_fee(self, authed_client):
        """The per-payment ceiling counts the Lightning routing-fee
        budget, not just the principal: a principal under the limit whose
        principal+fee crosses it is rejected."""
        client, _, _ = authed_client

        with patch("app.api.cold_storage.settings") as mock_settings:
            # principal 50_000 is under the cap; 10% fee budget (5_000)
            # pushes the worst-case spend to 55_000, which is over it.
            mock_settings.lnd_max_payment_sats = 52000
            mock_settings.bitcoin_network = "regtest"
            resp = await client.post(
                "/v1/cold-storage/initiate",
                json={
                    "amount_sats": 50000,
                    "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "routing_fee_limit_percent": 10.0,
                },
            )

        assert resp.status_code == 400
        assert "routing fee" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_initiate_swap_insufficient_balance(self, authed_client):
        """POST /v1/cold-storage/initiate rejects when balance is too low."""
        client, _, _ = authed_client

        with (
            patch("app.api.cold_storage.settings") as mock_settings,
            patch("app.services.lnd_service.lnd_service.get_channel_balance", new_callable=AsyncMock) as mock_bal,
            patch("app.api.cold_storage.check_payment_limits", new_callable=AsyncMock, return_value=(True, None, None)),
        ):
            mock_settings.lnd_max_payment_sats = 100000
            mock_settings.bitcoin_network = "regtest"
            mock_bal.return_value = ({"local_balance_sat": 10000}, None)
            resp = await client.post(
                "/v1/cold-storage/initiate",
                json={"amount_sats": 50000, "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
            )

        assert resp.status_code == 400
        assert "Insufficient" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_cancel_swap_success(self, authed_client):
        """POST /v1/cold-storage/swaps/{id}/cancel cancels a swap."""
        client, _, key_id = authed_client

        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        mock_swap.api_key_id = UUID(key_id)
        mock_swap.boltz_swap_id = "cancel-me"
        mock_swap.status = MagicMock(value="cancelled")
        mock_swap.boltz_status = "swap.created"
        mock_swap.invoice_amount_sats = 50000
        mock_swap.onchain_amount_sats = 48000
        mock_swap.destination_address = "bcrt1qdest"
        mock_swap.fee_percentage = "0.25"
        mock_swap.miner_fee_sats = 200
        mock_swap.boltz_invoice = "lnbcrt1..."
        mock_swap.claim_txid = None
        mock_swap.error_message = None
        mock_swap.status_history = []
        mock_swap.created_at = None
        mock_swap.updated_at = None
        mock_swap.completed_at = None

        with (
            patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock_get,
            patch("app.services.boltz_service.boltz_service.cancel_swap", new_callable=AsyncMock) as mock_cancel,
        ):
            mock_get.return_value = mock_swap
            mock_cancel.return_value = (True, None)
            resp = await client.post(f"/v1/cold-storage/swaps/{mock_swap.id}/cancel")

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_cancel_swap_not_found(self, authed_client):
        """POST /v1/cold-storage/swaps/{id}/cancel returns 404 for unknown swap."""
        client, _, _ = authed_client

        with patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock:
            mock.return_value = None
            resp = await client.post(f"/v1/cold-storage/swaps/{uuid4()}/cancel")

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cancel_swap_wrong_key(self, authed_client):
        """POST /v1/cold-storage/swaps/{id}/cancel returns 404 for swap belonging to another key."""
        client, _, key_id = authed_client

        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        mock_swap.api_key_id = uuid4()  # different key

        with patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock:
            mock.return_value = mock_swap
            resp = await client.post(f"/v1/cold-storage/swaps/{mock_swap.id}/cancel")

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cancel_swap_not_cancellable(self, authed_client):
        """POST /v1/cold-storage/swaps/{id}/cancel returns 400 for non-cancellable swap."""
        client, _, key_id = authed_client

        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        mock_swap.api_key_id = UUID(key_id)

        with (
            patch("app.services.boltz_service.boltz_service.get_swap_by_id", new_callable=AsyncMock) as mock_get,
            patch("app.services.boltz_service.boltz_service.cancel_swap", new_callable=AsyncMock) as mock_cancel,
        ):
            mock_get.return_value = mock_swap
            mock_cancel.return_value = (False, "Cannot cancel: already paid")
            resp = await client.post(f"/v1/cold-storage/swaps/{mock_swap.id}/cancel")

        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_cancel_swap_invalid_uuid(self, authed_client):
        """POST /v1/cold-storage/swaps/{id}/cancel rejects invalid UUID."""
        client, _, _ = authed_client
        resp = await client.post("/v1/cold-storage/swaps/not-a-uuid/cancel")
        assert resp.status_code == 400
