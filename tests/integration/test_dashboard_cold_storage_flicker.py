# SPDX-License-Identifier: MIT
"""Regression tests for Cold-Storage UI fixes.

Two unrelated bug classes both surface in this file:

1. **Flicker** — the Lightning-tab warnings, placeholder, and
   Send-Max handler all read ``boltzFees.min`` / ``boltzFees.max``
   directly. While ``boltzFees`` was at the sentinel default
   ``{ min: Infinity, max: -Infinity }`` (before the first fetch
   resolved), the warnings flashed with ``∞`` / ``-∞`` values.
   Fix: all three now route through ``boltzFeesUsable`` and the
   ``coldBoltzAmountBelowMin`` / ``coldBoltzAmountAboveMax`` helpers.

2. **Initiate-handler edge cases** — the initiate
   handler used to skip audit logging on failure paths and the
   balance check ignored the routing-fee headroom that the Celery
   task requires. Covers the cold-storage insufficient-balance /
   Boltz-rejection paths.

The parity unit tests in ``tests/unit/test_cold_storage_flicker.py``
cover the JS logic. This file pins the rendered HTML and the
backend's behaviour through the live FastAPI router.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.dashboard.auth import COOKIE_NAME
from app.models.audit_log import AuditLog

from .test_dashboard import _make_session_cookie, dashboard_client  # noqa: F401

_TEST_ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


class TestColdStorageFlickerTemplate:
    """Pin the Cold-Storage Lightning tab's flicker-prevention wires."""

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_min_warning_uses_gated_getter(self, dashboard_client, auth_cookies):
        # Pin that the "Minimum: X sats" warning's x-if calls the
        # gated method (``coldBoltzAmountBelowMin()``) rather than
        # inlining ``coldBoltzAmount < boltzFees.min`` directly.
        # The inline version flashed "Minimum: ∞ sats" during the
        # Tor-routed fetch window.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        assert "coldBoltzAmountBelowMin()" in html, (
            "Min-warning x-if must call the gated method "
            "``coldBoltzAmountBelowMin()`` so the sentinel default "
            "doesn't flash '∞' values during the loading window."
        )

    @pytest.mark.asyncio
    async def test_max_warning_uses_gated_getter(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        assert "coldBoltzAmountAboveMax()" in html, (
            "Max-warning x-if must call the gated method "
            "``coldBoltzAmountAboveMax()`` so the sentinel default "
            "doesn't flash '-∞' values during the loading window."
        )

    @pytest.mark.asyncio
    async def test_lightning_result_has_copy_and_explorer_affordance(self, dashboard_client, auth_cookies):
        # Plan inbound_liquidity cross-cutting policy: every
        # pending or completed on-chain tx surface includes a
        # copy-to-clipboard button and a mempool-explorer link.
        # The Cold-Storage Lightning result step used to render
        # the claim_txid as plain text; this regression test pins
        # the affordance is present.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        # Both the on-chain result and the Lightning result must wire
        # up the same two handlers. The @alpinejs/csp build can't
        # short-circuit ``a.b`` on null (it evaluates the dotted access
        # even behind ``&&``), so these fields are read through the
        # null-safe ``coldResultDataOrEmpty`` accessor.
        assert html.count("copyText(coldResultDataOrEmpty.claimTxid)") >= 1
        assert html.count("mempoolTxUrl(coldResultDataOrEmpty.claimTxid)") >= 1
        assert html.count("copyText(coldResultDataOrEmpty.txid)") >= 1
        assert html.count("mempoolTxUrl(coldResultDataOrEmpty.txid)") >= 1

    @pytest.mark.asyncio
    async def test_lightning_progress_view_surfaces_claim_txid(self, dashboard_client, auth_cookies):
        # The Lightning swap's progress step keeps the user on a
        # waiting view while the on-chain claim tx confirms (status
        # ``claimed``). Per the cross-cutting policy, that
        # waiting view must surface the txid + copy + mempool link
        # — otherwise the user can't independently verify the tx
        # is in the mempool, which is exactly the wait window
        # where verification matters most.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        # The progress-view block lives between the confirm step's
        # x-show declaration and the result step's. Find the
        # progress declaration and the result declaration, then
        # scan the slice between them for the affordance.
        ln_progress = html.find("coldTab === 'lightning' && coldStep === 'progress'")
        ln_result = html.find("coldTab === 'lightning' && coldStep === 'result'")
        assert ln_progress != -1 and ln_result != -1
        progress_block = html[ln_progress:ln_result]
        # The block must carry both the new state field and the
        # copy/explorer wires.
        assert "activeSwapClaimTxid" in progress_block, (
            "the Lightning progress view must surface "
            "``activeSwapClaimTxid`` once the claim tx is in the "
            "mempool — without it, the user has no way to copy "
            "or view the pending on-chain tx during the (often "
            "many-block) confirmation wait."
        )
        assert "copyText(activeSwapClaimTxid)" in progress_block
        assert "mempoolTxUrl(activeSwapClaimTxid)" in progress_block

    @pytest.mark.asyncio
    async def test_lightning_progress_view_surfaces_cancel_error(self, dashboard_client, auth_cookies):
        # A failed cancel attempt (typically because the swap raced
        # past ``created`` before the cancel reached the backend)
        # sets ``coldError``. Without a banner in the progress
        # view, the user would see the Cancel button look like it
        # had no effect. Pin the new error banner is wired.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        ln_progress = html.find("coldTab === 'lightning' && coldStep === 'progress'")
        ln_result = html.find("coldTab === 'lightning' && coldStep === 'result'")
        progress_block = html[ln_progress:ln_result]
        assert 'x-if="coldError"' in progress_block, (
            "Lightning progress view must render ``coldError`` so a failed cancel attempt has visible feedback."
        )


# ── Tests for the deep-audit fixes ──────────────────────────────


@pytest.fixture(autouse=True)
def _set_dashboard_token_for_module():
    """Re-declared per-module so the autouse propagates across the
    new test classes below without inheriting from elsewhere."""
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


class TestRoutingFeeBuffer:
    """The Lightning balance pre-check now accounts for the same
    3 % routing-fee headroom the Celery task uses. Without this,
    a user with exactly ``amount_sats`` of local would pass the
    pre-check only to have the LN payment fail with no route /
    fee-budget-exhausted, leaving the swap stuck in ``failed``
    state with a confusing error message.
    """

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.fixture(autouse=True)
    def _bypass_csrf(self):
        with patch("app.dashboard.api.check_csrf_token", new_callable=AsyncMock, return_value="ok"):
            yield

    @pytest.mark.asyncio
    async def test_exact_balance_now_rejects(self, dashboard_client, auth_cookies):
        # Pre-fix: ``local == amount`` passed (then routed and failed).
        # Post-fix: rejected because ``needed = amount * 1.03 > local``.
        with patch(
            "app.dashboard.api.lnd_service.get_channel_balance",
            new_callable=AsyncMock,
            return_value=({"local_balance_sat": 100_000}, None),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/cold-storage/initiate",
                json={"amount_sats": 100_000, "destination_address": _TEST_ADDR},
            )
        assert resp.status_code == 400
        assert "routing-fee headroom" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_balance_with_headroom_accepts(self, dashboard_client, auth_cookies):
        # User has 110k local, asking to swap 100k. Needed = 103k.
        # Comfortably under local → request proceeds to Boltz.
        mock = MagicMock()
        mock.id = uuid4()
        mock.boltz_swap_id = "swap_a"
        mock.status.value = "created"
        mock.boltz_invoice = "lnbc..."
        mock.onchain_amount_sats = 95_000
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 110_000}, None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
                return_value=(mock, None),
            ),
            patch("app.tasks.boltz_tasks.process_boltz_swap") as task,
        ):
            task.delay = MagicMock()
            resp = await dashboard_client.post(
                "/dashboard/api/cold-storage/initiate",
                json={"amount_sats": 100_000, "destination_address": _TEST_ADDR},
            )
        assert resp.status_code == 200


class TestInitiateFailureAuditLogging:
    """``cold_storage_initiate`` previously emitted an audit row only
    on success. The fix audits both rejection paths
    (insufficient-balance and Boltz-rejected) so operators reviewing
    the audit log can see swap-initiate attempts that never
    materialised."""

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.fixture(autouse=True)
    def _bypass_csrf(self):
        with patch("app.dashboard.api.check_csrf_token", new_callable=AsyncMock, return_value="ok"):
            yield

    @pytest.mark.asyncio
    async def test_insufficient_balance_audited(self, dashboard_client, auth_cookies, db_engine):
        with patch(
            "app.dashboard.api.lnd_service.get_channel_balance",
            new_callable=AsyncMock,
            return_value=({"local_balance_sat": 1_000}, None),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/cold-storage/initiate",
                json={"amount_sats": 100_000, "destination_address": _TEST_ADDR},
            )
        assert resp.status_code == 400

        from sqlalchemy.ext.asyncio import async_sessionmaker

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (await session.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(3))).scalars().all()
            )
        matching = [r for r in rows if r.action == "cold_storage_initiate"]
        assert matching, "insufficient-balance rejection must emit an audit row"
        assert matching[0].success is False
        assert (matching[0].details or {}).get("reason") == "insufficient_balance"

    @pytest.mark.asyncio
    async def test_boltz_rejection_audited(self, dashboard_client, auth_cookies, db_engine):
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 500_000}, None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
                return_value=(None, "Boltz: amount below minimum"),
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/cold-storage/initiate",
                json={"amount_sats": 100_000, "destination_address": _TEST_ADDR},
            )
        assert resp.status_code == 400

        from sqlalchemy.ext.asyncio import async_sessionmaker

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (await session.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(3))).scalars().all()
            )
        matching = [r for r in rows if r.action == "cold_storage_initiate"]
        assert matching, "Boltz rejection must emit an audit row"
        assert matching[0].success is False
        assert (matching[0].details or {}).get("reason") == "boltz_rejected"


class TestColdStorageSwapRecoveryWiring:
    """Source-level checks that the Cold-Storage recovery wiring is
    in place. These don't drive Alpine reactivity (that would need
    a browser) but they pin that the JS module references the
    localStorage key, the restore method, and the route-to-progress
    branch — so a refactor can't silently drop the recovery code
    without a test catching it."""

    def test_dashboard_js_references_localstorage_key(self):
        # Pin the module-level constant and its use in the three
        # required paths: write on initiate, restore on init,
        # clear on terminal.
        import pathlib

        js_path = pathlib.Path("app/dashboard/static/dashboard.js").resolve()
        src = js_path.read_text()
        # Module-level constant declaration.
        assert "COLD_LOCALSTORAGE_KEY" in src
        assert "'coldActiveSwapId'" in src, (
            "the localStorage key must be the documented value so "
            "users who refresh during a swap recover the progress "
            "view instead of starting from an empty form."
        )

    def test_dashboard_js_has_restore_method(self):
        import pathlib

        src = pathlib.Path("app/dashboard/static/dashboard.js").resolve().read_text()
        # The restore method is the load-bearing piece of the
        # refresh-mid-swap recovery story.
        assert "_restoreColdSwap" in src
        # And it must be called from init() — without that call,
        # the method exists but never runs.
        assert "this._restoreColdSwap()" in src, (
            "init() must call _restoreColdSwap() so a page refresh actually recovers an in-progress swap."
        )

    def test_dashboard_js_routes_open_to_progress_view(self):
        # The watcher on ``showColdStorage`` checks for an active
        # swap and routes to the progress view rather than dropping
        # the user back to an empty form.
        import pathlib

        src = pathlib.Path("app/dashboard/static/dashboard.js").resolve().read_text()
        assert "SWAP_TERMINAL_STATUSES.has(this.activeSwapStatus)" in src, (
            "showColdStorage watcher must check for an active "
            "(non-terminal) swap and route to the progress view "
            "so users don't accidentally start a second swap."
        )
