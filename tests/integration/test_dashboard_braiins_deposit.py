# SPDX-License-Identifier: MIT
"""Integration tests for the Braiins Deposit dashboard endpoints.

These tests pin the public surface of the dashboard endpoints:

* presets returns the canonical bin set + the user's LN balance.
* quote produces a fee breakdown.
* session create validates destination + balance, links the BoltzSwap,
  and audits.
* session detail enriches with txid confirmations when available.
* cancel/retry-send respect state-machine preconditions.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.dashboard.auth import COOKIE_NAME
from app.models.audit_log import AuditLog
from app.models.braiins_deposit_session import (
    BraiinsDepositSession,
)

from .test_dashboard import _make_session_cookie, dashboard_client  # noqa: F401

_TEST_ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


@pytest.fixture(autouse=True)
def _bypass_csrf():
    """The braiins endpoints sit behind ``_require_auth_csrf``.
    Generating a real CSRF token in tests would require Redis;
    patching ``check_csrf_token`` to return "ok" is the same
    shortcut the existing Cold-Storage tests use.
    """
    with patch(
        "app.dashboard.api.check_csrf_token",
        new_callable=AsyncMock,
        return_value="ok",
    ):
        yield


@pytest.fixture(autouse=True)
def _stub_optional_confirmations():
    """Stub mempool confirmation lookups so we don't reach out
    over the network (or race the asyncio loop) during tests.
    """
    with patch(
        "app.dashboard.api.mempool_fee_service.optional_confirmations",
        new_callable=AsyncMock,
        return_value=None,
    ):
        yield


@pytest.fixture
def auth_cookies(dashboard_client):  # noqa: F811
    cookie = _make_session_cookie()
    dashboard_client.cookies.set(COOKIE_NAME, cookie)
    return {COOKIE_NAME: cookie}


def _stub_boltz_pair(monkeypatch_targets):
    """Patch the Boltz reverse-pair-info fetch on the singletons used
    by both the dashboard endpoint and the service module.
    """

    async def _stub_quote_impl(
        self, *, amount_sats, source_kind="lightning", include_extras=True, funding_strategy="swap"
    ):
        # Lightning-source default; onchain source returns a quote
        # carrying nonzero submarine_* fields so balance gates work.
        # External sources (ext_lightning / ext_onchain) surface the
        # user's intake via ``required_external_deposit_sats``.
        if source_kind == "onchain":
            q = _StubQuote(
                source_kind="onchain",
                deposit_amount_sats=amount_sats,
                invoice_amount_sats=1_010_000,
                boltz_percentage_fee_sats=5_000,
                boltz_miner_fee_sats=800,
                expected_fresh_utxo_sats=1_004_200,
                estimated_send_fee_sats=660,
                estimated_routing_fee_sats=30_300,
                total_fee_sats=42_000,
                required_lightning_balance_sats=0,
                boltz_min_sat=25_000,
                boltz_max_sat=25_000_000,
                submarine_invoice_amount_sats=1_040_300,
                submarine_lockup_amount_sats=1_045_500,
                submarine_percentage_fee_sats=1_041,
                submarine_miner_fee_sats=462,
                submarine_funding_fee_sats=840,
                required_onchain_balance_sats=1_046_340,
                required_external_deposit_sats=0,
            )
            return q, None
        if source_kind == "ext_lightning":
            q = _StubQuote(
                source_kind="ext_lightning",
                deposit_amount_sats=amount_sats,
                invoice_amount_sats=1_010_000,
                boltz_percentage_fee_sats=5_000,
                boltz_miner_fee_sats=800,
                expected_fresh_utxo_sats=1_004_200,
                estimated_send_fee_sats=660,
                estimated_routing_fee_sats=30_300,
                total_fee_sats=36_760,
                required_lightning_balance_sats=0,
                required_onchain_balance_sats=0,
                boltz_min_sat=25_000,
                boltz_max_sat=25_000_000,
                # User pays the Boltz invoice; intake = invoice_amount.
                required_external_deposit_sats=1_010_000,
            )
            return q, None
        if source_kind == "ext_onchain":
            q = _StubQuote(
                source_kind="ext_onchain",
                deposit_amount_sats=amount_sats,
                invoice_amount_sats=1_010_000,
                boltz_percentage_fee_sats=5_000,
                boltz_miner_fee_sats=800,
                expected_fresh_utxo_sats=1_004_200,
                estimated_send_fee_sats=660,
                estimated_routing_fee_sats=30_300,
                total_fee_sats=42_000,
                required_lightning_balance_sats=0,
                required_onchain_balance_sats=0,
                boltz_min_sat=25_000,
                boltz_max_sat=25_000_000,
                submarine_invoice_amount_sats=1_040_300,
                submarine_lockup_amount_sats=1_045_500,
                submarine_percentage_fee_sats=1_041,
                submarine_miner_fee_sats=462,
                submarine_funding_fee_sats=840,
                # User's deposit = wallet's submarine-side intake.
                required_external_deposit_sats=1_046_340,
            )
            return q, None
        q = _StubQuote(
            source_kind="lightning",
            deposit_amount_sats=amount_sats,
            invoice_amount_sats=1_010_000,
            boltz_percentage_fee_sats=5_000,
            boltz_miner_fee_sats=800,
            expected_fresh_utxo_sats=1_004_200,
            estimated_send_fee_sats=660,
            estimated_routing_fee_sats=30_300,
            total_fee_sats=36_760,
            required_lightning_balance_sats=1_040_300,
            required_onchain_balance_sats=0,
            boltz_min_sat=25_000,
            boltz_max_sat=25_000_000,
            required_external_deposit_sats=0,
        )
        return q, None

    return patch(
        "app.services.braiins_deposit_service.BraiinsDepositService.quote",
        autospec=True,
        side_effect=_stub_quote_impl,
    )


class _StubQuote:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def as_dict(self):
        return dict(self.__dict__)


class TestPresets:
    @pytest.mark.asyncio
    async def test_presets_returns_bin_amounts_and_balance(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_channel_balance",
            new_callable=AsyncMock,
            return_value=({"local_balance_sat": 2_500_000}, None),
        ):
            resp = await dashboard_client.get("/dashboard/api/braiins-deposit/presets")
        assert resp.status_code == 200
        body = resp.json()
        assert body["preset_amounts"] == [
            50_000,
            100_000,
            250_000,
            500_000,
            1_000_000,
            2_000_000,
            3_000_000,
            4_000_000,
            5_000_000,
        ]
        assert body["lightning_local_balance_sats"] == 2_500_000

    @pytest.mark.asyncio
    async def test_presets_returns_404_when_disabled(self, dashboard_client, auth_cookies):
        original = settings.braiins_deposit_enabled
        settings.braiins_deposit_enabled = False
        try:
            resp = await dashboard_client.get("/dashboard/api/braiins-deposit/presets")
            assert resp.status_code == 404
        finally:
            settings.braiins_deposit_enabled = original


class TestQuoteEndpoint:
    @pytest.mark.asyncio
    async def test_quote_returns_breakdown(self, dashboard_client, auth_cookies):
        with _stub_boltz_pair(()):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/quote",
                json={"amount_sats": 1_000_000},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["deposit_amount_sats"] == 1_000_000
        assert body["invoice_amount_sats"] > body["deposit_amount_sats"]
        assert body["required_lightning_balance_sats"] >= body["invoice_amount_sats"]

    @pytest.mark.asyncio
    async def test_quotes_batch_returns_all(self, dashboard_client, auth_cookies):
        amounts = [500_000, 1_000_000, 5_000_000]
        with _stub_boltz_pair(()):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/quotes-batch",
                json={"amount_sats_list": amounts},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "quotes" in body
        quotes = body["quotes"]
        # Keys are strings (amount_sats stringified).
        for amt in amounts:
            assert str(amt) in quotes
            q = quotes[str(amt)]
            assert q is not None
            assert q["deposit_amount_sats"] == amt


class TestCreateSession:
    @pytest.mark.asyncio
    async def test_create_session_happy_path(self, dashboard_client, auth_cookies, db_engine):
        # Real create_session — only mock the upstream LND + Boltz
        # calls + the advance() tick that would otherwise hit the
        # network.
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 5_000_000}, None),
            ),
            _stub_boltz_pair(()),
            patch(
                "app.services.braiins_deposit_service.BraiinsDepositService.advance",
                new_callable=AsyncMock,
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={"amount_sats": 1_000_000, "destination_address": _TEST_ADDR},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "created"
        assert body["deposit_amount_sats"] == 1_000_000
        assert body["destination_address"] == _TEST_ADDR
        assert body["id"]

    @pytest.mark.asyncio
    async def test_create_session_refuses_when_balance_too_low(self, dashboard_client, auth_cookies, db_engine):
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 100_000}, None),
            ),
            _stub_boltz_pair(()),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={"amount_sats": 1_000_000, "destination_address": _TEST_ADDR},
            )
        assert resp.status_code == 400
        assert "insufficient lightning balance" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_session_rejects_legacy_address(self, dashboard_client, auth_cookies):
        legacy = "1" + "1" * 33  # legacy P2PKH-ish prefix
        resp = await dashboard_client.post(
            "/dashboard/api/braiins-deposit/sessions",
            json={"amount_sats": 1_000_000, "destination_address": legacy},
        )
        # Validator rejects legacy prefix before reaching the handler
        # body, so we should see a 422 (FastAPI Pydantic validation).
        assert resp.status_code in (400, 422)

    @pytest.mark.asyncio
    async def test_create_session_rejects_off_preset_amount(self, dashboard_client, auth_cookies):
        """a non-bin amount_sats is rejected at the API boundary so a
        non-round send can't trip Braiins' anti-fraud algorithm."""
        resp = await dashboard_client.post(
            "/dashboard/api/braiins-deposit/sessions",
            json={"amount_sats": 1_234_567, "destination_address": _TEST_ADDR},
        )
        assert resp.status_code == 422
        assert "supported deposit amounts" in resp.text

    @pytest.mark.asyncio
    async def test_create_session_audits(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 5_000_000}, None),
            ),
            _stub_boltz_pair(()),
            patch(
                "app.services.braiins_deposit_service.BraiinsDepositService.advance",
                new_callable=AsyncMock,
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={"amount_sats": 1_000_000, "destination_address": _TEST_ADDR},
            )
            assert resp.status_code == 200

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (await session.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(5))).scalars().all()
            )
        actions = [r.action for r in rows]
        assert "braiins_deposit_session_created" in actions
        created = [r for r in rows if r.action == "braiins_deposit_session_created"][0]
        details = created.details or {}
        assert details.get("purpose") == "braiins_deposit"
        assert details.get("destination_address") == _TEST_ADDR


class TestQuoteStaleness:
    """Drift between submitted quote and fresh re-quote → 409."""

    @pytest.mark.asyncio
    async def test_quote_drift_returns_409_with_fresh_quote(self, dashboard_client, auth_cookies, db_engine):
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 5_000_000}, None),
            ),
            _stub_boltz_pair(()),
        ):
            # Submit a fee that's much lower than the server's fresh
            # quote (36_760 sats per _stub_boltz_pair) — drift well
            # over the 10% threshold.
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    "expected_total_fee_sats": 1_000,  # very stale
                },
            )
        assert resp.status_code == 409
        body = resp.json()
        assert body["detail"] == "quote_stale"
        assert "fresh_quote" in body
        assert body["fresh_quote"]["deposit_amount_sats"] == 1_000_000

    @pytest.mark.asyncio
    async def test_quote_drift_within_tolerance_succeeds(self, dashboard_client, auth_cookies, db_engine):
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 5_000_000}, None),
            ),
            _stub_boltz_pair(()),
            patch(
                "app.services.braiins_deposit_service.BraiinsDepositService.advance",
                new_callable=AsyncMock,
            ),
        ):
            # Fresh quote total_fee_sats is 36_760 (per the stub).
            # Send 35_000 — drift ~5%, well within the 10% tolerance.
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    "expected_total_fee_sats": 35_000,
                },
            )
        assert resp.status_code == 200, resp.text


class TestListAndDetail:
    @pytest.mark.asyncio
    async def test_list_sessions_empty(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.get("/dashboard/api/braiins-deposit/sessions")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_list_sessions_404_when_disabled(
        self,
        dashboard_client,
        auth_cookies,
    ):
        """When BRAIINS_DEPOSIT_ENABLED=false the list endpoint
        404s — the SPA tab must hide gracefully (driven by the
        bootstrap-config flag) rather than rendering and then
        flashing an error."""
        original = settings.braiins_deposit_enabled
        settings.braiins_deposit_enabled = False
        try:
            resp = await dashboard_client.get("/dashboard/api/braiins-deposit/sessions")
            assert resp.status_code == 404
        finally:
            settings.braiins_deposit_enabled = original

    @pytest.mark.asyncio
    async def test_list_sessions_returns_completed_at_field(
        self,
        dashboard_client,
        auth_cookies,
        db_engine,
    ):
        """The deposits-list tab depends on
        ``completed_at`` for the "completed Xh ago" caption. The
        projection emits this field for every session — pin it
        explicitly here so a future projection refactor that drops
        it would fail this test (and the dedicated-tab feature)
        rather than silently breaking the tab."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.braiins_deposit_session import (
            BraiinsDepositSession,
            BraiinsDepositStatus,
        )

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            session.add(
                BraiinsDepositSession(
                    api_key_id=DASHBOARD_KEY_ID,
                    deposit_amount_sats=100_000,
                    destination_address=_TEST_ADDR,
                    status=BraiinsDepositStatus.CREATED,
                    status_history=[],
                )
            )
            await session.commit()

        with patch(
            "app.services.braiins_deposit_service.BraiinsDepositService.advance",
            new_callable=AsyncMock,
        ):
            resp = await dashboard_client.get("/dashboard/api/braiins-deposit/sessions")
        assert resp.status_code == 200
        rows = resp.json()
        assert len(rows) == 1
        assert "completed_at" in rows[0], (
            "list projection must emit completed_at — the tab's "
            "row-time-label helper falls back through completed_at "
            "→ updated_at → created_at"
        )
        # Non-COMPLETED rows have null completed_at, so the helper
        # must fall back to updated_at / created_at. Pin those too.
        assert "updated_at" in rows[0]
        assert "created_at" in rows[0]

    @pytest.mark.asyncio
    async def test_list_sessions_default_limit_caps_at_20(
        self,
        dashboard_client,
        auth_cookies,
        db_engine,
    ):
        """The endpoint defaults to ``?limit=20`` when no query is
        passed. the SPA passes no limit and lets the
        server enforce the cap."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.braiins_deposit_session import (
            BraiinsDepositSession,
            BraiinsDepositStatus,
        )

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            for _ in range(25):
                session.add(
                    BraiinsDepositSession(
                        api_key_id=DASHBOARD_KEY_ID,
                        deposit_amount_sats=100_000,
                        destination_address=_TEST_ADDR,
                        status=BraiinsDepositStatus.COMPLETED,
                        status_history=[],
                    )
                )
            await session.commit()

        with patch(
            "app.services.braiins_deposit_service.BraiinsDepositService.advance",
            new_callable=AsyncMock,
        ):
            resp = await dashboard_client.get("/dashboard/api/braiins-deposit/sessions")
        assert resp.status_code == 200
        rows = resp.json()
        assert len(rows) == 20, "list endpoint default limit must cap at 20 to match plan.2"

    @pytest.mark.asyncio
    async def test_session_detail_404(self, dashboard_client, auth_cookies):
        bogus_id = uuid4()
        resp = await dashboard_client.get(f"/dashboard/api/braiins-deposit/sessions/{bogus_id}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_list_after_create_returns_one(self, dashboard_client, auth_cookies, db_engine):
        # Create a session, then list — verify it appears in the response
        # serialised with the documented fields.
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 5_000_000}, None),
            ),
            _stub_boltz_pair(()),
            patch(
                "app.services.braiins_deposit_service.BraiinsDepositService.advance",
                new_callable=AsyncMock,
            ),
        ):
            await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={"amount_sats": 1_000_000, "destination_address": _TEST_ADDR},
            )
        resp = await dashboard_client.get("/dashboard/api/braiins-deposit/sessions")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        row = body[0]
        # Every documented field on the wire surface should be present.
        for k in (
            "id",
            "status",
            "deposit_amount_sats",
            "destination_address",
            "fresh_address",
            "fresh_utxo_txid",
            "fresh_utxo_vout",
            "fresh_utxo_amount_sats",
            "send_txid",
            "send_confirmations",
            "broadcast_block_height",
            "error_message",
            "status_history",
            "created_at",
            "updated_at",
            "completed_at",
        ):
            assert k in row, f"list serialiser missing field {k!r}"

    @pytest.mark.asyncio
    async def test_session_detail_enriches_with_confirmations(self, dashboard_client, auth_cookies, db_engine):
        """When ``mempool_fee_service.optional_confirmations``
        returns a value for a txid, the response embeds it as
        ``fresh_utxo_confirmations`` / ``send_confirmations_live``."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.braiins_deposit_session import BraiinsDepositSession, BraiinsDepositStatus

        # Insert a session row directly so we can drive the detail
        # response without going through the create flow.
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                fresh_address="bcrt1pfresh",
                fresh_utxo_txid="b" * 64,
                fresh_utxo_vout=0,
                fresh_utxo_amount_sats=1_004_000,
                send_txid="c" * 64,
                status=BraiinsDepositStatus.BROADCAST,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        # Override the autouse stub to return concrete confirmation
        # numbers for both txids.
        with (
            patch(
                "app.dashboard.api.mempool_fee_service.optional_confirmations",
                new_callable=AsyncMock,
                side_effect=lambda txid: (
                    {"confirmations": 3, "confirmed": True}
                    if txid == "c" * 64
                    else {"confirmations": 5, "confirmed": True}
                ),
            ),
            patch(
                "app.services.braiins_deposit_service.BraiinsDepositService.advance",
                new_callable=AsyncMock,
            ),
        ):
            resp = await dashboard_client.get(f"/dashboard/api/braiins-deposit/sessions/{session_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["fresh_utxo_confirmations"] == 5
        assert body["send_confirmations_live"] == 3


class TestCancelEndpoint:
    """POST /braiins-deposit/sessions/{id}/cancel.

    Coverage: happy-path cancel from CREATED, refused cancel from
    BROADCAST, audit row written.
    """

    @pytest.mark.asyncio
    async def test_cancel_created_session(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.braiins_deposit_session import BraiinsDepositSession, BraiinsDepositStatus

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=500_000,
                destination_address=_TEST_ADDR,
                status=BraiinsDepositStatus.CREATED,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        resp = await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{session_id}/cancel")
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_terminal_returns_400(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.braiins_deposit_session import BraiinsDepositSession, BraiinsDepositStatus

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=500_000,
                destination_address=_TEST_ADDR,
                status=BraiinsDepositStatus.COMPLETED,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        resp = await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{session_id}/cancel")
        assert resp.status_code == 400
        assert "already" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_cancel_emits_cancel_attempted_audit(self, dashboard_client, auth_cookies, db_engine):
        """Every user-action endpoint writes a
        ``braiins_deposit_cancel_attempted`` audit row (success OR
        failure)."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.audit_log import AuditLog
        from app.models.braiins_deposit_session import BraiinsDepositSession, BraiinsDepositStatus

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=500_000,
                destination_address=_TEST_ADDR,
                status=BraiinsDepositStatus.CREATED,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        resp = await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{session_id}/cancel")
        assert resp.status_code == 200

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (await session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_cancel_attempted")))
                .scalars()
                .all()
            )
        assert rows
        assert rows[0].success is True
        # And the state-transition row from the service should also exist
        # (no double-emission of the same name from both layers).
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            transition_rows = (
                (await session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_cancelled")))
                .scalars()
                .all()
            )
        assert len(transition_rows) == 1, "service should emit exactly one session_cancelled row on success"

    @pytest.mark.asyncio
    async def test_cancel_404_when_missing(self, dashboard_client, auth_cookies):
        bogus = uuid4()
        resp = await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{bogus}/cancel")
        # Service returns "Session not found or locked" → API maps to 400.
        # (We tolerate either 400 or 404 — both communicate "no such session".)
        assert resp.status_code in (400, 404)


class TestRetrySendEndpoint:
    """POST /braiins-deposit/sessions/{id}/retry-send."""

    @pytest.mark.asyncio
    async def test_retry_send_failed_after_funded(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.braiins_deposit_session import BraiinsDepositSession, BraiinsDepositStatus

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                fresh_address="bcrt1pfresh",
                fresh_utxo_txid="b" * 64,
                fresh_utxo_vout=0,
                fresh_utxo_amount_sats=1_004_000,
                status=BraiinsDepositStatus.FAILED,
                error_message="fee too low",
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        with patch(
            "app.services.braiins_deposit_service.BraiinsDepositService.advance",
            new_callable=AsyncMock,
        ):
            resp = await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{session_id}/retry-send")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # Service flipped FAILED → FUNDED, error_message cleared.
        assert body["status"] == "funded"
        assert body["error_message"] is None

    @pytest.mark.asyncio
    async def test_retry_send_on_non_failed_returns_400(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.braiins_deposit_session import BraiinsDepositSession, BraiinsDepositStatus

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                fresh_utxo_txid="b" * 64,
                fresh_utxo_vout=0,
                status=BraiinsDepositStatus.SWAPPING,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id
        resp = await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{session_id}/retry-send")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_retry_send_emits_retry_send_attempted_audit(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.audit_log import AuditLog
        from app.models.braiins_deposit_session import BraiinsDepositSession, BraiinsDepositStatus

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                fresh_address="bcrt1pfresh",
                fresh_utxo_txid="b" * 64,
                fresh_utxo_vout=0,
                fresh_utxo_amount_sats=1_004_000,
                status=BraiinsDepositStatus.FAILED,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        with patch(
            "app.services.braiins_deposit_service.BraiinsDepositService.advance",
            new_callable=AsyncMock,
        ):
            await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{session_id}/retry-send")

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (
                    await session.execute(
                        select(AuditLog).where(AuditLog.action == "braiins_deposit_retry_send_attempted")
                    )
                )
                .scalars()
                .all()
            )
        assert rows
        assert rows[0].success is True


class TestSessionDetailRefetch:
    """GET on the session detail returns the full row."""

    @pytest.mark.asyncio
    async def test_detail_returns_all_documented_fields(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.braiins_deposit_session import BraiinsDepositSession, BraiinsDepositStatus

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=500_000,
                destination_address=_TEST_ADDR,
                status=BraiinsDepositStatus.SWAPPING,
                status_history=[{"status": "created", "timestamp": "2026-05-18T00:00:00"}],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        with patch(
            "app.services.braiins_deposit_service.BraiinsDepositService.advance",
            new_callable=AsyncMock,
        ):
            resp = await dashboard_client.get(f"/dashboard/api/braiins-deposit/sessions/{session_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "swapping"
        assert body["status_history"] == [{"status": "created", "timestamp": "2026-05-18T00:00:00"}]
        assert body["destination_address"] == _TEST_ADDR
        assert body["deposit_amount_sats"] == 500_000


# ── Dust prevention dashboard surface ─────────────────


class TestDustPreventionSessionJsonShape:
    """The dashboard JSON for a BROADCAST session must
    surface ``actual_sent_sats`` so the SPA can render the
    "(+847 absorbed)" delta. Plan — parked sessions surface
    ``send_infeasible_reason`` and the
    ``resume_threshold_sat_per_vbyte`` operator-watchable target.
    """

    @pytest.mark.asyncio
    async def test_broadcast_session_serializes_actual_sent_sats(
        self,
        dashboard_client,
        auth_cookies,
        db_engine,
    ):
        """A BROADCAST row with ``actual_sent_sats != deposit_amount_sats``
        must round-trip through the dashboard JSON so the SPA's
        "(+N absorbed)" label renders correctly. Pinned because the
        column was added in migration 032 and a future PR that
        drops it from ``_braiins_serialize`` would silently regress
        the dashboard display."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.braiins_deposit_session import (
            BraiinsDepositSession,
            BraiinsDepositStatus,
        )

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                actual_sent_sats=1_000_847,  # +847 absorbed
                destination_address=_TEST_ADDR,
                fresh_utxo_txid="b" * 64,
                fresh_utxo_vout=0,
                fresh_utxo_amount_sats=1_004_000,
                send_txid="c" * 64,
                status=BraiinsDepositStatus.BROADCAST,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        with patch(
            "app.services.braiins_deposit_service.BraiinsDepositService.advance",
            new_callable=AsyncMock,
        ):
            resp = await dashboard_client.get(f"/dashboard/api/braiins-deposit/sessions/{session_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["deposit_amount_sats"] == 1_000_000
        assert body["actual_sent_sats"] == 1_000_847, (
            "actual_sent_sats must round-trip through the dashboard JSON so the (+N absorbed) delta renders correctly."
        )

    @pytest.mark.asyncio
    async def test_parked_session_exposes_resume_threshold(
        self,
        dashboard_client,
        auth_cookies,
        db_engine,
    ):
        """A session in AWAITING_FEE_REDUCTION must surface BOTH the
        infeasibility reason AND the resume threshold sat/vB. The
        operator uses the threshold to know what fee rate they're
        waiting for; without it the parked state is opaque."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.braiins_deposit_session import (
            BraiinsDepositSession,
            BraiinsDepositStatus,
        )

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                fresh_utxo_txid="b" * 64,
                fresh_utxo_vout=0,
                fresh_utxo_amount_sats=1_010_000,  # 10k headroom
                status=BraiinsDepositStatus.AWAITING_FEE_REDUCTION,
                send_infeasible_reason="would_underpay_bin",
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        with patch(
            "app.services.braiins_deposit_service.BraiinsDepositService.advance",
            new_callable=AsyncMock,
        ):
            resp = await dashboard_client.get(f"/dashboard/api/braiins-deposit/sessions/{session_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "awaiting_fee_reduction"
        assert body["send_infeasible_reason"] == "would_underpay_bin"
        # 10,000 sats headroom / 140 vbytes = 71 sat/vB. The threshold
        # is the max fee rate at which the no-change send still
        # arrives at >= bin.
        assert body["resume_threshold_sat_per_vbyte"] == 71, (
            "the resume threshold gives operators a watchable target "
            '("fees need to drop to N sat/vB"). Computed from UTXO '
            "headroom over bin amount divided by 140 vbytes."
        )

    @pytest.mark.asyncio
    async def test_pre_funded_session_has_null_resume_threshold(
        self,
        dashboard_client,
        auth_cookies,
        db_engine,
    ):
        """A session with no fresh UTXO yet (e.g. in CREATED or
        SWAPPING) has no meaningful threshold — the field is
        ``None`` so the SPA can hide it. Pinned because surfacing a
        bogus threshold on early-stage sessions would confuse the
        operator."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.braiins_deposit_session import (
            BraiinsDepositSession,
            BraiinsDepositStatus,
        )

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=500_000,
                destination_address=_TEST_ADDR,
                status=BraiinsDepositStatus.SWAPPING,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        with patch(
            "app.services.braiins_deposit_service.BraiinsDepositService.advance",
            new_callable=AsyncMock,
        ):
            resp = await dashboard_client.get(f"/dashboard/api/braiins-deposit/sessions/{session_id}")
        body = resp.json()
        assert body["resume_threshold_sat_per_vbyte"] is None


# ── On-chain source path ────────────────────────────────────────────


class TestOnchainPresets:
    """On-chain source: presets endpoint returns both balances so the
    wizard can auto-select the default source."""

    @pytest.mark.asyncio
    async def test_presets_returns_both_balances(self, dashboard_client, auth_cookies):
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 2_500_000}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_wallet_balance",
                new_callable=AsyncMock,
                return_value=({"confirmed_balance": 10_000_000}, None),
            ),
        ):
            resp = await dashboard_client.get("/dashboard/api/braiins-deposit/presets")
        assert resp.status_code == 200
        body = resp.json()
        assert body["lightning_local_balance_sats"] == 2_500_000
        assert body["onchain_confirmed_balance_sats"] == 10_000_000


class TestOnchainQuote:
    @pytest.mark.asyncio
    async def test_quote_onchain_source(self, dashboard_client, auth_cookies):
        with _stub_boltz_pair(()):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/quote",
                json={"amount_sats": 1_000_000, "source_kind": "onchain"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["source_kind"] == "onchain"
        assert body["submarine_invoice_amount_sats"] > 0
        assert body["submarine_lockup_amount_sats"] > 0
        assert body["required_onchain_balance_sats"] > 0
        assert body["required_lightning_balance_sats"] == 0

    @pytest.mark.asyncio
    async def test_quote_rejects_invalid_source_kind(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/braiins-deposit/quote",
            json={"amount_sats": 1_000_000, "source_kind": "nope"},
        )
        # Pydantic validation → 422.
        assert resp.status_code == 422


class TestOnchainCreateSession:
    @pytest.mark.asyncio
    async def test_create_onchain_session_checks_onchain_balance(self, dashboard_client, auth_cookies, db_engine):
        with (
            patch(
                "app.dashboard.api.lnd_service.get_wallet_balance",
                new_callable=AsyncMock,
                return_value=({"confirmed_balance": 2_000_000}, None),
            ),
            _stub_boltz_pair(()),
            patch(
                "app.services.braiins_deposit_service.BraiinsDepositService.advance",
                new_callable=AsyncMock,
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    "source_kind": "onchain",
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["source_kind"] == "onchain"
        assert body["status"] == "created"

    @pytest.mark.asyncio
    async def test_create_onchain_refuses_insufficient_onchain(self, dashboard_client, auth_cookies, db_engine):
        with (
            patch(
                "app.dashboard.api.lnd_service.get_wallet_balance",
                new_callable=AsyncMock,
                return_value=({"confirmed_balance": 100_000}, None),  # too low
            ),
            _stub_boltz_pair(()),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    "source_kind": "onchain",
                },
            )
        assert resp.status_code == 400
        assert "on-chain" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_lightning_unaffected_by_onchain_balance(self, dashboard_client, auth_cookies, db_engine):
        """The lightning source path should consult LN balance, not
        on-chain. A user with only LN should still be able to start."""
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 5_000_000}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_wallet_balance",
                new_callable=AsyncMock,
                return_value=({"confirmed_balance": 0}, None),
            ),
            _stub_boltz_pair(()),
            patch(
                "app.services.braiins_deposit_service.BraiinsDepositService.advance",
                new_callable=AsyncMock,
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    # source_kind omitted → defaults to lightning
                },
            )
        assert resp.status_code == 200, resp.text

    @pytest.mark.asyncio
    async def test_session_response_includes_submarine_fields(self, dashboard_client, auth_cookies, db_engine):
        """The wire-serialised session must carry the submarine
        fields so the wizard can render the submarine progress step."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.braiins_deposit_session import (
            BraiinsDepositSession,
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.ONCHAIN,
                submarine_lockup_address="bcrt1qboltz_lockup",
                submarine_lockup_amount_sats=1_045_500,
                submarine_funding_txid="ff" * 32,
                status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        with patch(
            "app.services.braiins_deposit_service.BraiinsDepositService.advance",
            new_callable=AsyncMock,
        ):
            resp = await dashboard_client.get(f"/dashboard/api/braiins-deposit/sessions/{session_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["source_kind"] == "onchain"
        assert body["status"] == "submarine_swapping"
        assert body["submarine_lockup_address"] == "bcrt1qboltz_lockup"
        assert body["submarine_lockup_amount_sats"] == 1_045_500
        assert body["submarine_funding_txid"] == "ff" * 32


class TestOnchainSubmarineConfirmationEnrichment:
    """The session-detail endpoint enriches every relevant txid with
    a live confirmation count when the chain backend can provide one.
    The submarine funding tx is part of this set."""

    @pytest.mark.asyncio
    async def test_submarine_funding_confirmations_returned(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.braiins_deposit_session import (
            BraiinsDepositSession,
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.ONCHAIN,
                submarine_funding_txid="aa" * 32,
                submarine_lockup_address="bcrt1qlockup",
                submarine_lockup_amount_sats=1_055_500,
                status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        with (
            patch(
                "app.dashboard.api.mempool_fee_service.optional_confirmations",
                new_callable=AsyncMock,
                side_effect=lambda txid: {"confirmations": 2, "confirmed": True} if txid == "aa" * 32 else None,
            ),
            patch(
                "app.services.braiins_deposit_service.BraiinsDepositService.advance",
                new_callable=AsyncMock,
            ),
        ):
            resp = await dashboard_client.get(f"/dashboard/api/braiins-deposit/sessions/{session_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["submarine_funding_confirmations"] == 2


class TestOnchainSubmarineCancel:
    """Cancel during SUBMARINE_SWAPPING must be refused
    via the API (on-chain funds are already in flight to Boltz)."""

    @pytest.mark.asyncio
    async def test_cancel_during_submarine_swapping_refused(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.audit_log import AuditLog
        from app.models.braiins_deposit_session import (
            BraiinsDepositSession,
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.ONCHAIN,
                submarine_payment_hash_hex="ab" * 32,
                submarine_funding_txid="ff" * 32,
                status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        resp = await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{session_id}/cancel")
        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert "on-chain funds" in detail.lower() or "boltz" in detail.lower()

        # The cancel attempt should still produce a cancel_attempted
        # audit row with success=False, so operators can see the
        # rejected attempt.
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (await session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_cancel_attempted")))
                .scalars()
                .all()
            )
        assert rows
        assert rows[0].success is False


class TestCreateRejectedAudits:
    """Pre-creation failure paths in the session-create handler all
    emit ``braiins_deposit_create_rejected`` with a discriminator
    ``reason`` field. These were untested — without coverage, a
    refactor could silently drop the audit emit and operators would
    lose visibility into rejected attempts.
    """

    @pytest.mark.asyncio
    async def test_insufficient_lightning_balance_emits_create_rejected(
        self, dashboard_client, auth_cookies, db_engine
    ):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.audit_log import AuditLog

        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 100_000}, None),
            ),
            _stub_boltz_pair(()),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={"amount_sats": 1_000_000, "destination_address": _TEST_ADDR},
            )
        assert resp.status_code == 400

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (await session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_create_rejected")))
                .scalars()
                .all()
            )
        assert rows
        details = rows[0].details or {}
        assert details.get("reason") == "insufficient_balance"
        assert details.get("source_kind") == "lightning"
        assert rows[0].success is False

    @pytest.mark.asyncio
    async def test_insufficient_onchain_balance_emits_create_rejected(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.audit_log import AuditLog

        with (
            patch(
                "app.dashboard.api.lnd_service.get_wallet_balance",
                new_callable=AsyncMock,
                return_value=({"confirmed_balance": 100_000}, None),
            ),
            _stub_boltz_pair(()),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    "source_kind": "onchain",
                },
            )
        assert resp.status_code == 400

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (await session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_create_rejected")))
                .scalars()
                .all()
            )
        # Filter to the onchain-flavoured row (other tests in the
        # same session may have emitted lightning rejections).
        oc = [r for r in rows if (r.details or {}).get("source_kind") == "onchain"]
        assert oc
        details = oc[0].details or {}
        assert details.get("reason") == "insufficient_balance"

    @pytest.mark.asyncio
    async def test_quote_stale_drift_emits_create_rejected(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.models.audit_log import AuditLog

        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 5_000_000}, None),
            ),
            _stub_boltz_pair(()),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    "expected_total_fee_sats": 1_000,  # very stale
                },
            )
        assert resp.status_code == 409

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (await session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_create_rejected")))
                .scalars()
                .all()
            )
        stale = [r for r in rows if (r.details or {}).get("reason") == "quote_stale"]
        assert stale
        details = stale[0].details or {}
        assert details.get("submitted_total_fee_sats") == 1_000
        assert "fresh_total_fee_sats" in details


class TestOnchainQuoteStaleness:
    """Quote-drift 409 must work with source_kind=onchain
    just as it does for lightning. The on-chain total_fee_sats
    includes submarine fees, so a stale lightning-side quote vs
    a fresh on-chain quote can produce a large drift."""

    @pytest.mark.asyncio
    async def test_quote_drift_returns_409_for_onchain(self, dashboard_client, auth_cookies, db_engine):
        with (
            patch(
                "app.dashboard.api.lnd_service.get_wallet_balance",
                new_callable=AsyncMock,
                return_value=({"confirmed_balance": 5_000_000}, None),
            ),
            _stub_boltz_pair(()),
        ):
            # stub_boltz_pair's onchain total_fee_sats = 42_000.
            # Submit a very stale 1,000 — drift well over 10%.
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    "source_kind": "onchain",
                    "expected_total_fee_sats": 1_000,
                },
            )
        assert resp.status_code == 409
        body = resp.json()
        assert body["detail"] == "quote_stale"
        # Fresh quote in response body reflects the onchain source.
        fresh = body["fresh_quote"]
        assert fresh["source_kind"] == "onchain"
        assert fresh["submarine_lockup_amount_sats"] > 0
        assert fresh["required_onchain_balance_sats"] > 0


# ═══════════════════════════════════════════════════════════════════════
# External-source API endpoints
# ═══════════════════════════════════════════════════════════════════════


class TestExternalSourcePresets:
    @pytest.mark.asyncio
    async def test_presets_surfaces_ext_enabled(self, dashboard_client, auth_cookies):
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 1_000_000}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_wallet_balance",
                new_callable=AsyncMock,
                return_value=({"confirmed_balance": 0}, None),
            ),
        ):
            resp = await dashboard_client.get("/dashboard/api/braiins-deposit/presets")
        assert resp.status_code == 200
        body = resp.json()
        assert "ext_enabled" in body
        assert isinstance(body["ext_enabled"], bool)
        assert "ext_ln_invoice_ttl_s" in body


class TestExternalSourceQuote:
    @pytest.mark.asyncio
    async def test_quote_ext_lightning_returns_external_deposit(self, dashboard_client, auth_cookies):
        with _stub_boltz_pair(()):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/quote",
                json={"amount_sats": 1_000_000, "source_kind": "ext_lightning"},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["source_kind"] == "ext_lightning"
        assert body["required_external_deposit_sats"] > 0
        # Self-balance gates are zero for ext sources.
        assert body["required_lightning_balance_sats"] == 0
        assert body["required_onchain_balance_sats"] == 0

    @pytest.mark.asyncio
    async def test_quote_ext_onchain_returns_external_deposit(self, dashboard_client, auth_cookies):
        with _stub_boltz_pair(()):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/quote",
                json={"amount_sats": 1_000_000, "source_kind": "ext_onchain"},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["source_kind"] == "ext_onchain"
        assert body["required_external_deposit_sats"] > 0

    @pytest.mark.asyncio
    async def test_quote_rejects_invalid_source_kind(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/braiins-deposit/quote",
            json={"amount_sats": 1_000_000, "source_kind": "totally_made_up"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_quote_response_carries_ext_ln_invoice_ttl(self, dashboard_client, auth_cookies):
        """Plan.c — the quote response surfaces the operator-
        configured ext-LN invoice TTL so the wizard can render the
        countdown ceiling without a separate presets round-trip."""
        with _stub_boltz_pair(()):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/quote",
                json={"amount_sats": 1_000_000, "source_kind": "ext_lightning"},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "ext_ln_invoice_ttl_s" in body
        assert isinstance(body["ext_ln_invoice_ttl_s"], int)
        assert body["ext_ln_invoice_ttl_s"] > 0


class TestExternalSourceCreateSession:
    @pytest.mark.asyncio
    async def test_create_ext_lightning_skips_balance_gate(self, dashboard_client, auth_cookies):
        # Even with zero self-balance, the API should accept ext-LN.
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 0}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_wallet_balance",
                new_callable=AsyncMock,
                return_value=({"confirmed_balance": 0}, None),
            ),
            _stub_boltz_pair(()),
            patch(
                "app.services.braiins_deposit_service.BraiinsDepositService.advance",
                new_callable=AsyncMock,
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    "source_kind": "ext_lightning",
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["source_kind"] == "ext_lightning"

    @pytest.mark.asyncio
    async def test_create_ext_onchain_skips_balance_gate(self, dashboard_client, auth_cookies):
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 0}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.get_wallet_balance",
                new_callable=AsyncMock,
                return_value=({"confirmed_balance": 0}, None),
            ),
            _stub_boltz_pair(()),
            patch(
                "app.services.braiins_deposit_service.BraiinsDepositService.advance",
                new_callable=AsyncMock,
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    "source_kind": "ext_onchain",
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["source_kind"] == "ext_onchain"

    @pytest.mark.asyncio
    async def test_create_ext_lightning_returns_403_when_disabled(self, dashboard_client, auth_cookies):
        original = settings.braiins_deposit_ext_enabled
        settings.braiins_deposit_ext_enabled = False
        try:
            with _stub_boltz_pair(()):
                resp = await dashboard_client.post(
                    "/dashboard/api/braiins-deposit/sessions",
                    json={
                        "amount_sats": 1_000_000,
                        "destination_address": _TEST_ADDR,
                        "source_kind": "ext_lightning",
                    },
                )
            # The quote-level check fires first and surfaces a 400;
            # the API-level check also fires for a 403. Either is
            # acceptable as a "disabled" rejection.
            assert resp.status_code in (400, 403)
        finally:
            settings.braiins_deposit_ext_enabled = original


class TestExternalRegenerateInvoiceEndpoint:
    @pytest.mark.asyncio
    async def test_endpoint_400_on_non_awaiting_session(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.LIGHTNING,
                status=BraiinsDepositStatus.SWAPPING,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        resp = await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{session_id}/regenerate-invoice")
        assert resp.status_code == 400


class TestExternalSubmitRefundEndpoint:
    @pytest.mark.asyncio
    async def test_endpoint_validates_address(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
                ext_intake_received_sats=1_012_300,
                ext_intake_txids=[
                    {"txid": "aa" * 32, "vout": 0, "amount_sat": 1_012_300, "confirmations": 1},
                ],
                status=BraiinsDepositStatus.FAILED,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        # Invalid address → 422.
        resp = await dashboard_client.post(
            f"/dashboard/api/braiins-deposit/sessions/{session_id}/submit-refund",
            json={"refund_address": "n" * 5},  # too short to be valid
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_endpoint_400_when_no_funds_received(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
                ext_intake_received_sats=0,
                status=BraiinsDepositStatus.FAILED,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        resp = await dashboard_client.post(
            f"/dashboard/api/braiins-deposit/sessions/{session_id}/submit-refund",
            json={"refund_address": _TEST_ADDR},
        )
        assert resp.status_code == 400


class TestExternalSourceSessionDetailEnrichment:
    """Detail endpoint enriches ext-OC sessions with live
    confirmation counts on intake txids; ext-LN sessions get the
    Boltz invoice text + display expiry."""

    @pytest.mark.asyncio
    async def test_ext_onchain_detail_enriches_intake_txids(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
                ext_intake_address="bcrt1pintake",
                ext_intake_amount_sats=1_012_300,
                ext_intake_received_sats=500_000,
                ext_intake_txids=[
                    {"txid": "aa" * 32, "vout": 0, "amount_sat": 500_000, "confirmations": 1},
                ],
                status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        # Stub the chain backend to return a higher live conf count.
        with (
            patch(
                "app.dashboard.api.mempool_fee_service.optional_confirmations",
                new_callable=AsyncMock,
                return_value={"confirmations": 3},
            ),
            patch(
                "app.services.braiins_deposit_service.BraiinsDepositService.advance",
                new_callable=AsyncMock,
            ),
        ):
            resp = await dashboard_client.get(f"/dashboard/api/braiins-deposit/sessions/{session_id}")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["source_kind"] == "ext_onchain"
        assert body["ext_intake_address"] == "bcrt1pintake"
        assert body["ext_intake_received_sats"] == 500_000
        # The intake-tx entries are enriched with confirmations_live.
        txids = body["ext_intake_txids"]
        assert len(txids) == 1
        assert txids[0].get("confirmations_live") == 3


# ═══════════════════════════════════════════════════════════════════════
# External sources — additional integration coverage.
# ═══════════════════════════════════════════════════════════════════════


class TestExternalSourceSessionDetailExtLightning:
    """Session-detail for an ext-LN session in
    AWAITING_LN_FUNDS surfaces the BoltzSwap's invoice, a display
    expiry derived from configured TTL, and the current Boltz
    status string."""

    @pytest.mark.asyncio
    async def test_ext_lightning_detail_surfaces_invoice_and_expiry(self, dashboard_client, auth_cookies, db_engine):
        from datetime import datetime, timezone

        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.boltz_swap import BoltzSwap, BoltzSwapDirection, SwapStatus
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        # Pre-populate a BoltzSwap row with a known invoice string.
        swap_id = None
        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            swap = BoltzSwap(
                boltz_swap_id="swap_ext_ln_detail",
                direction=BoltzSwapDirection.REVERSE,
                api_key_id=DASHBOARD_KEY_ID,
                invoice_amount_sats=1_010_000,
                onchain_amount_sats=1_005_000,
                destination_address="bcrt1pfresh",
                boltz_invoice="lnbc1010000n1pj7zfakeinvoice",
                boltz_status="swap.created",
                status=SwapStatus.CREATED,
                status_history=[],
                created_at=datetime.now(timezone.utc),
            )
            session.add(swap)
            await session.commit()
            swap_id = swap.id

            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
                boltz_swap_id=swap_id,
                ext_intake_amount_sats=1_010_000,
                status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        with patch(
            "app.services.braiins_deposit_service.BraiinsDepositService.advance",
            new_callable=AsyncMock,
        ):
            resp = await dashboard_client.get(f"/dashboard/api/braiins-deposit/sessions/{session_id}")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["source_kind"] == "ext_lightning"
        assert body["ext_ln_invoice"] == "lnbc1010000n1pj7zfakeinvoice"
        assert "ext_ln_invoice_expires_at" in body
        assert body["ext_ln_boltz_status"] == "swap.created"


class TestExternalSourceRegenerateInvoiceSuccess:
    """End-to-end happy-path for the regenerate-invoice endpoint.
    Asserts the new swap is linked + the response carries the
    fresh session shape."""

    @pytest.mark.asyncio
    async def test_endpoint_regenerates_invoice_when_prior_unpaid(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.boltz_swap import BoltzSwap, BoltzSwapDirection, SwapStatus
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        prior_swap_id = None
        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            swap = BoltzSwap(
                boltz_swap_id="swap_regen_old",
                direction=BoltzSwapDirection.REVERSE,
                api_key_id=DASHBOARD_KEY_ID,
                invoice_amount_sats=1_010_000,
                onchain_amount_sats=1_005_000,
                destination_address="bcrt1pfreshold",
                boltz_invoice="lnbc_old",
                status=SwapStatus.CREATED,
                status_history=[],
            )
            session.add(swap)
            await session.commit()
            prior_swap_id = swap.id

            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
                boltz_swap_id=prior_swap_id,
                ext_intake_amount_sats=1_005_000,
                status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        # Mock the new swap that create_reverse_swap returns.
        new_swap_uuid = uuid4()

        async def _create_new(self, *, db, **_kw):
            # ``patch(..., new=...)`` replaces the bound method without
            # auto-binding, so ``self`` arrives as a positional arg.
            from app.models.boltz_swap import BoltzSwap as _BS

            new = _BS(
                id=new_swap_uuid,
                boltz_swap_id="swap_regen_new",
                direction=BoltzSwapDirection.REVERSE,
                api_key_id=DASHBOARD_KEY_ID,
                invoice_amount_sats=1_010_000,
                onchain_amount_sats=1_005_000,
                destination_address="bcrt1pfreshnew",
                boltz_invoice="lnbc_new",
                status=SwapStatus.CREATED,
                status_history=[],
            )
            db.add(new)
            await db.commit()
            return new, None

        with (
            _stub_boltz_pair(()),
            patch(
                "app.services.boltz_service.BoltzSwapService.cancel_swap",
                new_callable=AsyncMock,
                return_value=(True, None),
            ),
            patch(
                "app.services.boltz_service.BoltzSwapService.create_reverse_swap",
                new=_create_new,
            ),
            patch(
                "app.services.lnd_service.LNDService.new_address",
                new_callable=AsyncMock,
                return_value=({"address": "bcrt1pfreshnew", "address_type": "p2tr"}, None),
            ),
        ):
            resp = await dashboard_client.post(
                f"/dashboard/api/braiins-deposit/sessions/{session_id}/regenerate-invoice"
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["source_kind"] == "ext_lightning"
        # Re-read from DB to confirm the swap link was updated.
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            refreshed = (
                await session.execute(select(BraiinsDepositSession).where(BraiinsDepositSession.id == session_id))
            ).scalar_one()
            assert refreshed.boltz_swap_id == new_swap_uuid


class TestExternalSourceSubmitRefundSuccess:
    """End-to-end happy-path for submit-refund. Asserts the refund
    transaction is broadcast and the response carries refund_txid."""

    @pytest.mark.asyncio
    async def test_endpoint_sends_refund_and_records_txid(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
                ext_intake_address="bcrt1pintake",
                ext_intake_amount_sats=1_012_300,
                ext_intake_received_sats=1_012_300,
                ext_intake_txids=[
                    {"txid": "ab" * 32, "vout": 0, "amount_sat": 1_012_300, "confirmations": 1},
                ],
                status=BraiinsDepositStatus.FAILED,
                status_history=[],
                error_message="downstream submarine failed",
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        with (
            patch(
                "app.services.lnd_service.LNDService.send_coins",
                new_callable=AsyncMock,
                return_value=({"txid": "cd" * 32}, None),
            ),
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.get_recommended_fees",
                new_callable=AsyncMock,
                return_value=({"halfHourFee": 6}, None),
            ),
        ):
            resp = await dashboard_client.post(
                f"/dashboard/api/braiins-deposit/sessions/{session_id}/submit-refund",
                json={"refund_address": _TEST_ADDR},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["refund_txid"] == "cd" * 32
        assert body["refund_address"] == _TEST_ADDR


class TestExternalSourceSubmitRefundEdgeCases:
    @pytest.mark.asyncio
    async def test_endpoint_400_when_already_refunded(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
                ext_intake_received_sats=1_012_300,
                ext_intake_txids=[
                    {"txid": "aa" * 32, "vout": 0, "amount_sat": 1_012_300, "confirmations": 1},
                ],
                refund_address="bc1qprior",
                refund_txid="11" * 32,
                status=BraiinsDepositStatus.FAILED,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        resp = await dashboard_client.post(
            f"/dashboard/api/braiins-deposit/sessions/{session_id}/submit-refund",
            json={"refund_address": _TEST_ADDR},
        )
        assert resp.status_code == 400
        assert "already" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_endpoint_400_when_fresh_utxo_already_claimed(self, dashboard_client, auth_cookies, db_engine):
        """Plan.c — once the user's deposit has flowed
        downstream (Boltz claim landed = fresh_utxo_txid set), the
        refund-with-pinned-outpoints path would fail. Service must
        refuse cleanly and point at Retry Send."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
                ext_intake_received_sats=1_012_300,
                ext_intake_txids=[
                    {"txid": "aa" * 32, "vout": 0, "amount_sat": 1_012_300, "confirmations": 1},
                ],
                fresh_utxo_txid="bb" * 32,
                fresh_utxo_vout=0,
                fresh_utxo_amount_sats=1_004_200,
                status=BraiinsDepositStatus.FAILED,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        resp = await dashboard_client.post(
            f"/dashboard/api/braiins-deposit/sessions/{session_id}/submit-refund",
            json={"refund_address": _TEST_ADDR},
        )
        assert resp.status_code == 400
        body = resp.json()
        assert "flowed downstream" in body["detail"].lower()


class TestExternalSourceCancelExtStatesEndpoints:
    """API-level coverage for cancel on the new states. The service
    tests already cover the state transitions; these tests confirm
    the HTTP wrapper surfaces the right codes + payloads."""

    @pytest.mark.asyncio
    async def test_cancel_awaiting_ln_funds(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.boltz_swap import BoltzSwap, BoltzSwapDirection, SwapStatus
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            swap = BoltzSwap(
                boltz_swap_id="swap_cancel_ln",
                direction=BoltzSwapDirection.REVERSE,
                api_key_id=DASHBOARD_KEY_ID,
                invoice_amount_sats=1_010_000,
                onchain_amount_sats=1_005_000,
                destination_address="bcrt1pfresh",
                status=SwapStatus.CREATED,
                status_history=[],
            )
            session.add(swap)
            await session.commit()
            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
                boltz_swap_id=swap.id,
                ext_intake_amount_sats=1_010_000,
                status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        with patch(
            "app.services.boltz_service.BoltzSwapService.cancel_swap",
            new_callable=AsyncMock,
            return_value=(True, None),
        ):
            resp = await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{session_id}/cancel")
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_awaiting_onchain_funds_no_deposit(self, dashboard_client, auth_cookies, db_engine):
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
                ext_intake_address="bcrt1pintake",
                ext_intake_amount_sats=1_012_300,
                ext_intake_received_sats=0,
                status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        resp = await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{session_id}/cancel")
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_awaiting_onchain_funds_with_partial_funds(self, dashboard_client, auth_cookies, db_engine):
        """Cancel-with-funds routes to FAILED so the
        refund-prompt panel can render."""
        from sqlalchemy.ext.asyncio import async_sessionmaker

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.braiins_deposit_session import (
            BraiinsDepositSourceKind,
            BraiinsDepositStatus,
        )

        session_id = None
        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            row = BraiinsDepositSession(
                api_key_id=DASHBOARD_KEY_ID,
                deposit_amount_sats=1_000_000,
                destination_address=_TEST_ADDR,
                source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
                ext_intake_address="bcrt1pintake",
                ext_intake_amount_sats=1_012_300,
                ext_intake_received_sats=500_000,
                ext_intake_txids=[
                    {"txid": "ee" * 32, "vout": 0, "amount_sat": 500_000, "confirmations": 1},
                ],
                status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
                status_history=[],
            )
            session.add(row)
            await session.commit()
            session_id = row.id

        resp = await dashboard_client.post(f"/dashboard/api/braiins-deposit/sessions/{session_id}/cancel")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "failed"
        # The session is set up for the refund-prompt panel.
        assert (body.get("ext_intake_received_sats") or 0) > 0
        assert body.get("refund_txid") is None


class TestExternalSourceQuoteStaleness:
    """Quote-drift gate at session-create time
    applies to ext sources too."""

    @pytest.mark.asyncio
    async def test_quote_drift_returns_409_for_ext_lightning(self, dashboard_client, auth_cookies):
        with _stub_boltz_pair(()):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    "source_kind": "ext_lightning",
                    "expected_total_fee_sats": 1_000,  # very stale
                },
            )
        assert resp.status_code == 409
        body = resp.json()
        assert body["detail"] == "quote_stale"
        assert body["fresh_quote"]["source_kind"] == "ext_lightning"

    @pytest.mark.asyncio
    async def test_quote_drift_returns_409_for_ext_onchain(self, dashboard_client, auth_cookies):
        with _stub_boltz_pair(()):
            resp = await dashboard_client.post(
                "/dashboard/api/braiins-deposit/sessions",
                json={
                    "amount_sats": 1_000_000,
                    "destination_address": _TEST_ADDR,
                    "source_kind": "ext_onchain",
                    "expected_total_fee_sats": 1_000,
                },
            )
        assert resp.status_code == 409
        body = resp.json()
        assert body["detail"] == "quote_stale"
        assert body["fresh_quote"]["source_kind"] == "ext_onchain"
        # Ext-OC carries submarine fields too.
        assert body["fresh_quote"]["submarine_lockup_amount_sats"] > 0
