# SPDX-License-Identifier: MIT
"""Integration tests for dashboard routes and API endpoints."""

import time
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import settings
from app.core.database import get_db
from app.dashboard.auth import COOKIE_NAME, generate_login_nonce


def _login_nonce() -> str:
    """Mint a valid login nonce for tests (signed with SECRET_KEY)."""
    return generate_login_nonce()


def _make_session_cookie() -> str:
    """Create a valid HMAC-signed session cookie for testing.

    Uses the production ``_sign`` so the test stays in sync with the
    (domain-separated) cookie-signing key derivation.
    """
    from app.dashboard.auth import _sign

    expires = int(time.time()) + 86400
    # Modern cookie format: ``session_id:expires`` (the legacy id-less
    # format is rejected). Use a UNIQUE session id per cookie so a
    # revoke/logout test can't poison the process-local revocation
    # cache for other tests sharing this helper.
    import secrets as _secrets

    payload = f"sess-itest-{_secrets.token_urlsafe(8)}:{expires}"
    return f"{payload}.{_sign(payload)}"


@pytest_asyncio.fixture
async def dashboard_client(db_engine) -> AsyncGenerator[AsyncClient, None]:
    """Test client with dashboard routes enabled."""
    from fastapi import FastAPI

    from app.dashboard.api import router as dashboard_api
    from app.dashboard.routes import router as dashboard_routes

    app = FastAPI()
    app.include_router(dashboard_routes)
    app.include_router(dashboard_api)

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        follow_redirects=False,
        headers={"X-Requested-With": "XMLHttpRequest"},
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


# ── Auth / Route Tests ────────────────────────────────────────────────


class TestDashboardRoutes:
    @pytest.mark.asyncio
    async def test_login_page_returns_html(self, dashboard_client):
        resp = await dashboard_client.get("/dashboard/login")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_login_page_uses_password_terminology(self, dashboard_client):
        """The login UI labels the credential as 'Password', not
        'Token' — the env var is still DASHBOARD_TOKEN (unchanged)
        but the user-facing copy refers to it as a password."""
        resp = await dashboard_client.get("/dashboard/login")
        assert resp.status_code == 200
        body = resp.text
        assert "Dashboard Password" in body
        assert 'name="password"' in body
        assert 'placeholder="Enter your dashboard password"' in body
        # The bare label "Dashboard Token" must no longer be rendered.
        assert "Dashboard Token" not in body

    @pytest.mark.asyncio
    async def test_login_page_redirects_if_authenticated(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        resp = await dashboard_client.get("/dashboard/login")
        assert resp.status_code == 302
        assert "/dashboard/" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_login_page_renders_expired_message_on_error_query(self, dashboard_client):
        """When the dashboard bounces a user back here with
        ?error=expired (idle timeout / stale cookie / revoked
        session), the page shows a 'Session expired' banner so the
        user knows why they're back at login."""
        resp = await dashboard_client.get("/dashboard/login?error=expired")
        assert resp.status_code == 200
        assert "Session expired" in resp.text

    @pytest.mark.asyncio
    async def test_login_page_renders_invalid_password_on_error_query(self, dashboard_client):
        resp = await dashboard_client.get("/dashboard/login?error=invalid")
        assert resp.status_code == 200
        assert "Invalid password" in resp.text

    @pytest.mark.asyncio
    async def test_login_submit_valid_password(self, dashboard_client):
        resp = await dashboard_client.post(
            "/dashboard/login",
            data={"password": "test-dashboard-token", "login_nonce": _login_nonce()},
        )
        assert resp.status_code == 302
        assert "/dashboard/" in resp.headers["location"]
        assert COOKIE_NAME in resp.cookies

    @pytest.mark.asyncio
    async def test_login_submit_invalid_password(self, dashboard_client):
        resp = await dashboard_client.post(
            "/dashboard/login",
            data={"password": "wrong", "login_nonce": _login_nonce()},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_submit_accepts_legacy_token_field(self, dashboard_client):
        """The form-handler accepts ``token`` as a backward-compat
        alias for ``password`` so existing operator scripts don't
        break when the UI field is renamed."""
        resp = await dashboard_client.post(
            "/dashboard/login",
            data={"token": "test-dashboard-token", "login_nonce": _login_nonce()},
        )
        assert resp.status_code == 302
        assert COOKIE_NAME in resp.cookies

    @pytest.mark.asyncio
    async def test_login_submit_missing_nonce_rejected(self, dashboard_client):
        # Login CSRF defence: form submissions without a valid signed
        # nonce must be rejected even with the correct password.
        resp = await dashboard_client.post(
            "/dashboard/login",
            data={"password": "test-dashboard-token"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_login_submit_cross_origin_rejected(self, dashboard_client):
        # Explicit Origin pointing at a third-party host must be rejected.
        resp = await dashboard_client.post(
            "/dashboard/login",
            data={"password": "test-dashboard-token", "login_nonce": _login_nonce()},
            headers={"Origin": "http://evil.example"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_dashboard_page_requires_auth(self, dashboard_client):
        resp = await dashboard_client.get("/dashboard/")
        assert resp.status_code == 302
        assert "/dashboard/login" in resp.headers["location"]
        # No cookie at all → clean redirect with no expired-error query.
        assert "error=expired" not in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_dashboard_page_redirects_with_expired_when_cookie_stale(self, dashboard_client):
        """When the user has a session cookie that no longer validates
        (idle timeout / expired / revoked / IP mismatch), the
        dashboard route redirects to /dashboard/login?error=expired
        so the user sees a 'Session expired' message rather than a
        bare login page."""
        # Set a syntactically-valid-but-stale cookie. The auth layer
        # will reject it (any non-matching signature) and the route
        # should detect the cookie's presence to flip on the query
        # param.
        dashboard_client.cookies.set(COOKIE_NAME, "stale-cookie-value")
        resp = await dashboard_client.get("/dashboard/")
        assert resp.status_code == 302
        assert "/dashboard/login" in resp.headers["location"]
        assert "error=expired" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_dashboard_page_with_auth(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        resp = await dashboard_client.get("/dashboard/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_logout_get_is_rejected(self, dashboard_client):
        # GET /dashboard/logout must not revoke a session — it would
        # let any third-party page force-log-out an operator via
        # <img src="…/logout">.
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        resp = await dashboard_client.get("/dashboard/logout")
        assert resp.status_code == 405

    @pytest.mark.asyncio
    async def test_logout_post_clears_cookie(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        with patch(
            "app.dashboard.routes.check_csrf_token",
            new_callable=AsyncMock,
            return_value="ok",
        ):
            resp = await dashboard_client.post("/dashboard/logout")
        assert resp.status_code == 303
        assert "/dashboard/login" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_logout_post_without_csrf_does_not_revoke(self, dashboard_client):
        # Missing CSRF header → redirect back to dashboard, no revoke.
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        resp = await dashboard_client.post("/dashboard/logout")
        assert resp.status_code == 303
        assert "/dashboard/" in resp.headers["location"]
        assert "/dashboard/login" not in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_dashboard_page_bootstrap_config_emits_braiins_flag_enabled(
        self,
        dashboard_client,
    ):
        """The dashboard-config <script> JSON block must include
        ``braiins_deposit_enabled`` so the SPA's visibleTabs getter
        can gate the tab on the server's feature flag."""
        original = settings.braiins_deposit_enabled
        settings.braiins_deposit_enabled = True
        try:
            cookie = _make_session_cookie()
            dashboard_client.cookies.set(COOKIE_NAME, cookie)
            resp = await dashboard_client.get("/dashboard/")
            assert resp.status_code == 200
            body = resp.text
            assert 'id="dashboard-config"' in body
            assert '"braiins_deposit_enabled": true' in body
        finally:
            settings.braiins_deposit_enabled = original

    @pytest.mark.asyncio
    async def test_dashboard_page_bootstrap_config_emits_braiins_flag_disabled(
        self,
        dashboard_client,
    ):
        """When BRAIINS_DEPOSIT_ENABLED=false the boot config must
        emit ``"braiins_deposit_enabled": false`` so the SPA hides
        the tab."""
        original = settings.braiins_deposit_enabled
        settings.braiins_deposit_enabled = False
        try:
            cookie = _make_session_cookie()
            dashboard_client.cookies.set(COOKIE_NAME, cookie)
            resp = await dashboard_client.get("/dashboard/")
            assert resp.status_code == 200
            assert '"braiins_deposit_enabled": false' in resp.text
        finally:
            settings.braiins_deposit_enabled = original

    @pytest.mark.asyncio
    async def test_dashboard_render_hides_braiins_tab_when_disabled(
        self,
        dashboard_client,
    ):
        """End-to-end gate: when
        ``BRAIINS_DEPOSIT_ENABLED=false`` the rendered HTML must
        carry both the boot-config signal *and* the SPA-side
        ``visibleTabs`` getter that consumes it, so the tab
        disappears from the nav. Pinning both ends in one test
        catches the case where one is updated without the other."""
        original = settings.braiins_deposit_enabled
        settings.braiins_deposit_enabled = False
        try:
            cookie = _make_session_cookie()
            dashboard_client.cookies.set(COOKIE_NAME, cookie)
            resp = await dashboard_client.get("/dashboard/")
            assert resp.status_code == 200
            body = resp.text
            # Server side: flag is propagated through the boot config.
            assert '"braiins_deposit_enabled": false' in body
            # SPA side: the nav iterates the filtered list, not the
            # raw tabs array.
            assert 'x-for="t in visibleTabs"' in body, (
                "tab nav must iterate visibleTabs (which filters braiins-deposit on the boot-config flag)"
            )
            # The tab content block still exists in the template but
            # is hidden via x-show; that's by design — we render the
            # template once and let Alpine decide what's visible.
            assert "activeTab === 'braiins-deposit'" in body
        finally:
            settings.braiins_deposit_enabled = original


# ── API Auth Tests ────────────────────────────────────────────────────


class TestDashboardAPIAuth:
    @staticmethod
    async def _login_nonce(client):
        resp = await client.get("/dashboard/api/login-nonce")
        assert resp.status_code == 200
        return resp.json()["login_nonce"]

    @pytest.mark.asyncio
    async def test_api_login_valid_password(self, dashboard_client):
        nonce = await self._login_nonce(dashboard_client)
        resp = await dashboard_client.post(
            "/dashboard/api/login",
            json={"password": "test-dashboard-token", "login_nonce": nonce},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert COOKIE_NAME in resp.cookies

    @pytest.mark.asyncio
    async def test_api_login_invalid_password(self, dashboard_client):
        nonce = await self._login_nonce(dashboard_client)
        resp = await dashboard_client.post(
            "/dashboard/api/login",
            json={"password": "wrong", "login_nonce": nonce},
        )
        assert resp.status_code == 401
        # The user-facing error message now says "Invalid password".
        assert "password" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_api_login_missing_nonce_rejected(self, dashboard_client):
        """JSON login without a valid login nonce is rejected (login-CSRF
        parity with the HTML form path)."""
        resp = await dashboard_client.post(
            "/dashboard/api/login",
            json={"password": "test-dashboard-token"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_api_login_accepts_legacy_token_field(self, dashboard_client):
        """The JSON login endpoint accepts ``token`` as a
        backward-compat alias for ``password``."""
        nonce = await self._login_nonce(dashboard_client)
        resp = await dashboard_client.post(
            "/dashboard/api/login",
            json={"token": "test-dashboard-token", "login_nonce": nonce},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_api_endpoint_rejects_without_cookie(self, dashboard_client):
        resp = await dashboard_client.get("/dashboard/api/summary")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_api_logout_requires_auth(self, dashboard_client):
        resp = await dashboard_client.post("/dashboard/api/logout")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_api_logout_requires_csrf(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        resp = await dashboard_client.post("/dashboard/api/logout")
        # Authenticated but missing CSRF header — must be rejected
        # (403 for violation; 503 only when the CSRF backend is down).
        assert resp.status_code in (403, 503)

    @pytest.mark.asyncio
    async def test_api_logout_success(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        with patch(
            "app.dashboard.api.check_csrf_token",
            new_callable=AsyncMock,
            return_value="ok",
        ):
            resp = await dashboard_client.post("/dashboard/api/logout")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ── API Data Endpoint Tests ──────────────────────────────────────────


class TestDashboardReadEndpoints:
    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_summary_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_wallet_summary",
            new_callable=AsyncMock,
            return_value=({"total_balance": 100000}, None),
        ):
            resp = await dashboard_client.get("/dashboard/api/summary")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_summary_lnd_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_wallet_summary",
            new_callable=AsyncMock,
            return_value=(None, "connection refused"),
        ):
            resp = await dashboard_client.get("/dashboard/api/summary")
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_channels_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=([{"chan_id": "123"}], None),
        ):
            resp = await dashboard_client.get("/dashboard/api/channels")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_channels_enriches_with_peer_connected(self, dashboard_client, auth_cookies):
        """The dashboard's three-state channel-status icon (green=
        active, yellow=waiting-for-channel-ready, grey=peer-offline)
        relies on a ``peer_connected`` field that the backend enriches
        from a parallel ``/v1/peers`` query. Pin that:

        * ``peer_connected`` is added per channel, and
        * matches whether the channel's ``remote_pubkey`` appears in
          the connected-peers set.
        """
        peer_a = "02aa" + "00" * 31
        peer_b = "02bb" + "00" * 31
        channels = [
            # active=true is "fully ready" (icon stays green regardless).
            {"chan_id": "111", "remote_pubkey": peer_a, "active": True},
            # active=false + peer connected → waiting-for-channel_ready (yellow).
            {"chan_id": "222", "remote_pubkey": peer_b, "active": False},
            # active=false + peer NOT connected → offline (grey).
            {"chan_id": "333", "remote_pubkey": "02cc" + "00" * 31, "active": False},
        ]
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(channels, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.list_peer_pubkeys",
                new_callable=AsyncMock,
                return_value=({peer_a, peer_b}, None),
            ),
        ):
            resp = await dashboard_client.get("/dashboard/api/channels")
        assert resp.status_code == 200
        body = resp.json()
        assert {c["chan_id"]: c.get("peer_connected") for c in body} == {
            "111": True,   # active channel with connected peer
            "222": True,   # the waiting-for-channel_ready case
            "333": False,  # peer truly offline
        }

    @pytest.mark.asyncio
    async def test_channels_omits_peer_connected_when_peers_lookup_fails(
        self, dashboard_client, auth_cookies,
    ):
        """If ``/v1/peers`` errors out, the enrichment is skipped
        entirely — channels render with binary green/grey using just
        ``active``. The endpoint must NOT 502 just because the
        peer-connection lookup failed."""
        channels = [{"chan_id": "111", "remote_pubkey": "02aa" + "00" * 31, "active": False}]
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channels",
                new_callable=AsyncMock,
                return_value=(channels, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.list_peer_pubkeys",
                new_callable=AsyncMock,
                return_value=(None, "connection refused"),
            ),
        ):
            resp = await dashboard_client.get("/dashboard/api/channels")
        assert resp.status_code == 200
        body = resp.json()
        assert "peer_connected" not in body[0], (
            "When peers lookup fails the field must NOT be present so the "
            "JS falls back to its binary green/grey rendering — adding a "
            "default boolean would mislead the icon."
        )

    @pytest.mark.asyncio
    async def test_payments_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_recent_payments",
            new_callable=AsyncMock,
            return_value=([{"payment_hash": "abc"}], None),
        ):
            resp = await dashboard_client.get("/dashboard/api/payments")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_invoices_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_recent_invoices",
            new_callable=AsyncMock,
            return_value=([{"r_hash": "abc"}], None),
        ):
            resp = await dashboard_client.get("/dashboard/api/invoices")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_invoices_amount_column_reads_lnd_fields(self, dashboard_client, auth_cookies):
        # Bug: the Invoices tab's Amount column displayed 0 for every
        # row. The template read ``inv.value_sat || inv.amount_sat``
        # but the LND service returns ``value`` (requested amount) and
        # ``amt_paid_sat`` (settled amount). Pin that the template
        # reads those fields so the column doesn't silently regress
        # to the wrong key names again.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        # The Amount column's x-text expression must reference the
        # real LND-returned fields.
        assert "inv.amt_paid_sat || inv.value || 0" in html, (
            "Invoices Amount column must read ``inv.amt_paid_sat`` "
            "(settled amount) with a fallback to ``inv.value`` "
            "(requested amount) — the LND service returns those "
            "field names, not ``value_sat`` / ``amount_sat``."
        )
        # Defensive: the buggy field names should NOT appear in the
        # invoice row's x-text. ``value_sat`` is used elsewhere in
        # the page for other contexts, so scope the assertion to the
        # invoices x-for block.
        inv_for_idx = html.find('x-for="inv in (invoices')
        assert inv_for_idx != -1, "invoices x-for block not found"
        # End of the <tr> that contains the row's x-text expressions.
        inv_block_end = html.find("</tr>", inv_for_idx)
        assert inv_block_end != -1
        inv_block = html[inv_for_idx:inv_block_end]
        assert "inv.value_sat" not in inv_block, (
            "Invoices row must not reference ``inv.value_sat`` — LND returns ``value``, not ``value_sat``."
        )
        assert "inv.amount_sat" not in inv_block, (
            "Invoices row must not reference ``inv.amount_sat`` — LND returns ``amt_paid_sat`` for settled amounts."
        )

    @pytest.mark.asyncio
    async def test_offer_card_has_ocean_sign_payout_shortcut(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # The Offer Details card must surface a "Sign payout message"
        # button gated on ``bolt12CanSignPayoutMessage``. Pin both the
        # gate AND the click handler so a future refactor can't
        # silently break the OCEAN-payouts UX shortcut.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        assert "bolt12CanSignPayoutMessage(bolt12SelectedOffer())" in html, (
            "Offer Details card must gate the payout-sign button on "
            "``bolt12CanSignPayoutMessage`` so the shortcut only "
            "appears for owned OCEAN payout addresses"
        )
        assert "openOceanSignDialog(bolt12ExtractOceanAddress" in html, (
            "the payout-sign button must invoke "
            "``openOceanSignDialog`` with the address extracted from "
            "the offer description"
        )
        assert "Sign payout message" in html, "button label must match the documented affordance"

    @pytest.mark.asyncio
    async def test_ocean_sign_dialog_renders_streamlined_ui(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # The streamlined dialog drops the identity selector, the
        # verify tab, and the export-format chooser from the full
        # Sign dialog. Pin the contract.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        assert 'x-if="showOceanSignDialog"' in html, "streamlined sign dialog template must exist"
        # The address is shown as read-only context, not as an input.
        assert 'x-text="oceanSignAddress"' in html, "dialog must render the pre-filled address read-only"
        assert 'x-model="oceanSignMessage"' in html, "dialog must bind the message textarea to oceanSignMessage"
        # Submit calls into the dedicated handler (which reuses
        # /sign/address under the hood).
        assert "submitOceanSign()" in html, "dialog must wire its Sign button to submitOceanSign()"
        # Copy-signature shortcut is the entire reason for the
        # streamlined flow.
        assert "copyOceanSignature()" in html, "dialog must surface a one-click signature copy button"
        # The unverified-ownership disclaimer must be wired so users
        # on stripped LND builds have calibrated expectations when
        # the button is shown optimistically.
        assert 'x-if="oceanSignUnverified"' in html, (
            "dialog must render an 'ownership unverified' disclaimer when opened from the optimistic path"
        )
        assert "bolt12OceanOwnershipUnverified(bolt12SelectedOffer())" in html, (
            "the Sign-payout button must pass the unverified flag through to the dialog"
        )

    @pytest.mark.asyncio
    async def test_transactions_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_onchain_transactions",
            new_callable=AsyncMock,
            return_value=([{"tx_hash": "abc"}], None),
        ):
            resp = await dashboard_client.get("/dashboard/api/transactions")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_fees_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            new_callable=AsyncMock,
            return_value=({"fastestFee": 10}, None),
        ):
            resp = await dashboard_client.get("/dashboard/api/fees")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_info_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_info",
            new_callable=AsyncMock,
            return_value=({"alias": "test-node"}, None),
        ):
            resp = await dashboard_client.get("/dashboard/api/info")
        assert resp.status_code == 200


class TestDashboardReadErrorPaths:
    """Tests for error responses from all read endpoints."""

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_channels_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=(None, "LND unreachable"),
        ):
            resp = await dashboard_client.get("/dashboard/api/channels")
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_pending_channels_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_pending_channels_detail",
            new_callable=AsyncMock,
            return_value=(None, "LND unreachable"),
        ):
            resp = await dashboard_client.get("/dashboard/api/channels/pending")
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_payments_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_recent_payments",
            new_callable=AsyncMock,
            return_value=(None, "LND unreachable"),
        ):
            resp = await dashboard_client.get("/dashboard/api/payments")
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_invoices_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_recent_invoices",
            new_callable=AsyncMock,
            return_value=(None, "LND unreachable"),
        ):
            resp = await dashboard_client.get("/dashboard/api/invoices")
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_transactions_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_onchain_transactions",
            new_callable=AsyncMock,
            return_value=(None, "LND unreachable"),
        ):
            resp = await dashboard_client.get("/dashboard/api/transactions")
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_fees_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.mempool_fee_service.get_recommended_fees",
            new_callable=AsyncMock,
            return_value=(None, "mempool offline"),
        ):
            resp = await dashboard_client.get("/dashboard/api/fees")
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_info_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_info",
            new_callable=AsyncMock,
            return_value=(None, "LND unreachable"),
        ):
            resp = await dashboard_client.get("/dashboard/api/info")
        assert resp.status_code == 502


class TestDashboardWriteEndpoints:
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
    async def test_new_address(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.new_address",
            new_callable=AsyncMock,
            return_value=({"address": "bc1q..."}, None),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/address",
                json={"address_type": "p2tr"},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_new_address_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.new_address",
            new_callable=AsyncMock,
            return_value=(None, "LND error"),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/address",
                json={"address_type": "p2tr"},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_create_invoice(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.create_invoice",
            new_callable=AsyncMock,
            return_value=(
                {"r_hash": "abc", "payment_request": "lnbc...", "add_index": "1"},
                None,
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/invoice",
                json={"amount_sats": 1000, "memo": "test"},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_create_invoice_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.create_invoice",
            new_callable=AsyncMock,
            return_value=(None, "LND error"),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/invoice",
                json={"amount_sats": 1000},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_decode_payment(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.decode_payment_request",
            new_callable=AsyncMock,
            return_value=({"destination": "02abc", "num_satoshis": "1000"}, None),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/decode",
                json={"payment_request": "lnbc1..."},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_decode_payment_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.decode_payment_request",
            new_callable=AsyncMock,
            return_value=(None, "invalid payment request"),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/decode",
                json={"payment_request": "invalid"},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_invoice_validation_rejects_zero(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/invoice",
            json={"amount_sats": 0},
        )
        assert resp.status_code == 422


class TestDashboardActivity:
    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_activity_returns_list(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.get("/dashboard/api/activity")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data


# ── Dashboard Write Endpoint Tests (pay, send-onchain, etc.) ─────────


class TestDashboardPayEndpoints:
    """Tests for dashboard payment write endpoints."""

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
    async def test_pay_invoice_success(self, dashboard_client, auth_cookies):
        with (
            patch(
                "app.dashboard.api.lnd_service.decode_payment_request",
                new_callable=AsyncMock,
                return_value=({"destination": "02abc", "num_satoshis": 1000, "description": "test"}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.send_payment_sync",
                new_callable=AsyncMock,
                return_value=(
                    {
                        "payment_hash": "abc123",
                        "payment_preimage": "def456",
                        "payment_route": {"total_amt": 1000, "total_fees": 5},
                    },
                    None,
                ),
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay",
                json={"payment_request": "lnbc1000...", "fee_limit_sats": 100},
            )
        assert resp.status_code == 200
        assert resp.json()["payment_hash"] == "abc123"

    @pytest.mark.asyncio
    async def test_pay_invoice_lnd_error(self, dashboard_client, auth_cookies):
        with (
            patch(
                "app.dashboard.api.lnd_service.decode_payment_request",
                new_callable=AsyncMock,
                return_value=({"destination": "02abc", "num_satoshis": 1000}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.send_payment_sync",
                new_callable=AsyncMock,
                return_value=(None, "connection refused"),
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay",
                json={"payment_request": "lnbc1000..."},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_pay_invoice_no_route_returns_400(self, dashboard_client, auth_cookies):
        with (
            patch(
                "app.dashboard.api.lnd_service.decode_payment_request",
                new_callable=AsyncMock,
                return_value=({"destination": "02abc", "num_satoshis": 1000}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.send_payment_sync",
                new_callable=AsyncMock,
                return_value=(None, "unable to find a path to destination"),
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay",
                json={"payment_request": "lnbc1000..."},
            )
        assert resp.status_code == 400
        assert "no route" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_pay_invoice_outgoing_chan_id_uses_v2(self, dashboard_client, auth_cookies):
        """Pinning a source channel routes the call through send_payment_v2."""
        decode_mock = AsyncMock(return_value=({"destination": "02abc", "num_satoshis": 1000, "description": "x"}, None))
        v2_mock = AsyncMock(
            return_value=(
                {
                    "payment_hash": "deadbeef",
                    "payment_preimage": "feedface",
                    "amount_sats": 1000,
                    "fee_sats": 7,
                    "fee_msat": 7123,
                    "hops": 3,
                    "duration_ms": 1500,
                },
                None,
            )
        )
        sync_mock = AsyncMock(return_value=(None, "should not be called"))
        with (
            patch("app.dashboard.api.lnd_service.decode_payment_request", decode_mock),
            patch("app.dashboard.api.lnd_service.send_payment_v2", v2_mock),
            patch("app.dashboard.api.lnd_service.send_payment_sync", sync_mock),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay",
                json={
                    "payment_request": "lnbc1000...",
                    "fee_limit_sats": 50,
                    "outgoing_chan_id": "123456789",
                },
            )
        assert resp.status_code == 200
        assert v2_mock.await_count == 1
        assert sync_mock.await_count == 0
        kwargs = v2_mock.await_args.kwargs
        assert kwargs["outgoing_chan_id"] == "123456789"
        assert kwargs["fee_limit_sats"] == 50
        assert kwargs["allow_self_payment"] is False
        body = resp.json()
        # The streaming-API response is reshaped to the legacy
        # SendPaymentResult envelope so the dashboard JS keeps working.
        assert body["payment_hash"] == "deadbeef"
        assert body["payment_route"]["total_fees"] == 7
        assert body["payment_route"]["hops"] == 3

    @pytest.mark.asyncio
    async def test_pay_invoice_invalid_outgoing_chan_id(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/pay",
            json={"payment_request": "lnbc1000...", "outgoing_chan_id": "not-numeric"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_pay_audit_records_outgoing_chan_id(self, dashboard_client, auth_cookies, db_session):
        """When a source pin is set, the audit row includes it; otherwise it is omitted."""
        from sqlalchemy import select

        from app.models.audit_log import AuditLog

        decode_mock = AsyncMock(return_value=({"destination": "02abc", "num_satoshis": 1000, "description": "x"}, None))
        v2_mock = AsyncMock(
            return_value=(
                {
                    "payment_hash": "deadbeef",
                    "payment_preimage": "feedface",
                    "amount_sats": 1000,
                    "fee_sats": 7,
                    "fee_msat": 7123,
                    "hops": 3,
                    "duration_ms": 1500,
                },
                None,
            )
        )
        sync_mock = AsyncMock(
            return_value=(
                {
                    "payment_hash": "cafebabe",
                    "payment_preimage": "f00d",
                    "payment_route": {"total_amt": 1000, "total_fees": 1, "hops": []},
                },
                None,
            )
        )
        with (
            patch("app.dashboard.api.lnd_service.decode_payment_request", decode_mock),
            patch("app.dashboard.api.lnd_service.send_payment_v2", v2_mock),
            patch("app.dashboard.api.lnd_service.send_payment_sync", sync_mock),
        ):
            r1 = await dashboard_client.post(
                "/dashboard/api/pay",
                json={
                    "payment_request": "lnbc1000pinned",
                    "fee_limit_sats": 10,
                    "outgoing_chan_id": "987654321",
                },
            )
            r2 = await dashboard_client.post(
                "/dashboard/api/pay",
                json={"payment_request": "lnbc1000nopin", "fee_limit_sats": 10},
            )
        assert r1.status_code == 200
        assert r2.status_code == 200
        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "pay_invoice").order_by(AuditLog.id)))
            .scalars()
            .all()
        )
        # Other tests in this class also emit pay_invoice rows, so
        # locate ours by payment_hash rather than slicing the tail.
        by_hash = {(r.details or {}).get("payment_hash"): (r.details or {}) for r in rows}
        pinned_details = by_hash.get("deadbeef") or {}
        unpinned_details = by_hash.get("cafebabe") or {}
        assert pinned_details.get("outgoing_chan_id") == "987654321"
        assert "outgoing_chan_id" not in unpinned_details

    @pytest.mark.asyncio
    async def test_pay_quote_success(self, dashboard_client, auth_cookies):
        decode_mock = AsyncMock(
            return_value=(
                {"destination": "02abc", "num_satoshis": 5000},
                None,
            )
        )
        quote_mock = AsyncMock(
            return_value=(
                {
                    "hops": 4,
                    "total_amt_sat": 5000,
                    "total_fees_sat": 12,
                    "total_amt_msat": 5_000_000,
                    "total_fees_msat": 12_000,
                    "total_time_lock": 720,
                    "ppm": 2400,
                },
                None,
            )
        )
        with (
            patch("app.dashboard.api.lnd_service.decode_payment_request", decode_mock),
            patch("app.dashboard.api.lnd_service.query_routes", quote_mock),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay/quote",
                json={"payment_request": "lnbc5000...", "fee_limit_sats": 100},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["amount_sats"] == 5000
        assert body["destination"] == "02abc"
        assert body["route"]["hops"] == 4
        assert body["route"]["total_fees_sat"] == 12

    @pytest.mark.asyncio
    async def test_pay_quote_outgoing_chan_id_forwarded(self, dashboard_client, auth_cookies):
        decode_mock = AsyncMock(
            return_value=(
                {"destination": "02abc", "num_satoshis": 5000},
                None,
            )
        )
        quote_mock = AsyncMock(
            return_value=(
                {
                    "hops": 2,
                    "total_amt_sat": 5000,
                    "total_fees_sat": 1,
                    "total_amt_msat": 5_000_000,
                    "total_fees_msat": 1000,
                    "total_time_lock": 144,
                    "ppm": 200,
                },
                None,
            )
        )
        with (
            patch("app.dashboard.api.lnd_service.decode_payment_request", decode_mock),
            patch("app.dashboard.api.lnd_service.query_routes", quote_mock),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay/quote",
                json={
                    "payment_request": "lnbc5000...",
                    "fee_limit_sats": 50,
                    "outgoing_chan_id": "987654321",
                },
            )
        assert resp.status_code == 200
        kwargs = quote_mock.await_args.kwargs
        assert kwargs["outgoing_chan_id"] == "987654321"
        assert kwargs["fee_limit_sats"] == 50

    @pytest.mark.asyncio
    async def test_pay_quote_amountless_invoice_rejected(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.decode_payment_request",
            new_callable=AsyncMock,
            return_value=({"destination": "02abc", "num_satoshis": 0}, None),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay/quote",
                json={"payment_request": "lnbc..."},
            )
        assert resp.status_code == 400
        assert "fixed-amount" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_pay_quote_no_route(self, dashboard_client, auth_cookies):
        with (
            patch(
                "app.dashboard.api.lnd_service.decode_payment_request",
                new_callable=AsyncMock,
                return_value=({"destination": "02abc", "num_satoshis": 5000}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.query_routes",
                new_callable=AsyncMock,
                return_value=(None, "unable to find a path to destination"),
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay/quote",
                json={"payment_request": "lnbc5000..."},
            )
        # 200 + structured no_route flag — the UI renders a hint, not
        # a hard error.
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert body["no_route"] is True

    @pytest.mark.asyncio
    async def test_pay_quote_lnd_upstream_error(self, dashboard_client, auth_cookies):
        with (
            patch(
                "app.dashboard.api.lnd_service.decode_payment_request",
                new_callable=AsyncMock,
                return_value=({"destination": "02abc", "num_satoshis": 5000}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.query_routes",
                new_callable=AsyncMock,
                return_value=(None, "connection refused"),
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay/quote",
                json={"payment_request": "lnbc5000..."},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_pay_quote_decode_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.decode_payment_request",
            new_callable=AsyncMock,
            return_value=(None, "invalid bolt11"),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay/quote",
                json={"payment_request": "garbage"},
            )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_pay_quote_missing_destination_rejected(self, dashboard_client, auth_cookies):
        """A decoded invoice without a destination pubkey is a 400, not a 502 from QueryRoutes."""
        with (
            patch(
                "app.dashboard.api.lnd_service.decode_payment_request",
                new_callable=AsyncMock,
                return_value=({"destination": "", "num_satoshis": 5000}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.query_routes",
                new_callable=AsyncMock,
            ) as quote_mock,
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay/quote",
                json={"payment_request": "lnbc5000..."},
            )
        assert resp.status_code == 400
        assert "destination" in resp.json()["detail"].lower()
        # We must short-circuit before contacting LND.
        assert quote_mock.await_count == 0

    @pytest.mark.asyncio
    async def test_pay_quote_default_fee_limit_forwarded(self, dashboard_client, auth_cookies):
        """When the client omits fee_limit_sats, the server forwards the documented default."""
        decode_mock = AsyncMock(
            return_value=(
                {"destination": "02abc", "num_satoshis": 5000},
                None,
            )
        )
        quote_mock = AsyncMock(
            return_value=(
                {
                    "hops": 1,
                    "total_amt_sat": 5000,
                    "total_fees_sat": 0,
                    "total_amt_msat": 5_000_000,
                    "total_fees_msat": 0,
                    "total_time_lock": 144,
                    "ppm": 0,
                },
                None,
            )
        )
        with (
            patch("app.dashboard.api.lnd_service.decode_payment_request", decode_mock),
            patch("app.dashboard.api.lnd_service.query_routes", quote_mock),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay/quote",
                json={"payment_request": "lnbc5000..."},
            )
        assert resp.status_code == 200
        kwargs = quote_mock.await_args.kwargs
        # The PayQuoteRequest default; if this changes, update both sides.
        assert kwargs["fee_limit_sats"] == 1_000_000
        assert kwargs["outgoing_chan_id"] is None

    @pytest.mark.asyncio
    async def test_pay_invoice_v2_no_route_returns_400(self, dashboard_client, auth_cookies):
        """The no-route mapping applies to the v2 (pinned-source) path too."""
        decode_mock = AsyncMock(
            return_value=(
                {"destination": "02abc", "num_satoshis": 1000, "description": "x"},
                None,
            )
        )
        v2_mock = AsyncMock(return_value=(None, "no_route"))
        with (
            patch("app.dashboard.api.lnd_service.decode_payment_request", decode_mock),
            patch("app.dashboard.api.lnd_service.send_payment_v2", v2_mock),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/pay",
                json={
                    "payment_request": "lnbc1000...",
                    "fee_limit_sats": 5,
                    "outgoing_chan_id": "111",
                },
            )
        assert resp.status_code == 400
        assert "no route" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_pay_invoice_outgoing_chan_id_too_long_rejected(self, dashboard_client, auth_cookies):
        """The numeric pattern caps the chan_id at 20 digits to defend the audit detail blob."""
        resp = await dashboard_client.post(
            "/dashboard/api/pay",
            json={
                "payment_request": "lnbc1000...",
                "outgoing_chan_id": "1" * 21,
            },
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_send_onchain_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.send_coins",
            new_callable=AsyncMock,
            return_value=({"txid": "abc123txid"}, None),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/send-onchain",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 50000},
            )
        assert resp.status_code == 200
        assert resp.json()["txid"] == "abc123txid"

    @pytest.mark.asyncio
    async def test_send_onchain_lnd_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.send_coins",
            new_callable=AsyncMock,
            return_value=(None, "insufficient funds"),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/send-onchain",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 50000},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_send_onchain_invalid_address(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/send-onchain",
            json={"address": "invalid-addr", "amount_sats": 50000},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_estimate_fee_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.estimate_fee",
            new_callable=AsyncMock,
            return_value=({"fee_sat": 450, "feerate_sat_per_byte": 5, "sat_per_vbyte": 5}, None),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/estimate-fee",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 100000},
            )
        assert resp.status_code == 200
        assert resp.json()["fee_sat"] == 450

    @pytest.mark.asyncio
    async def test_estimate_fee_lnd_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.estimate_fee",
            new_callable=AsyncMock,
            return_value=(None, "estimation failed"),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/estimate-fee",
                json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "amount_sats": 100000},
            )
        assert resp.status_code == 502


class TestDashboardChannelEndpoints:
    """Tests for dashboard channel management endpoints."""

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
    async def test_open_channel_without_host(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.open_channel",
            new_callable=AsyncMock,
            return_value=({"funding_txid": "abc123"}, None),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/channel/open",
                json={"pubkey": "02" + "a1" * 32, "local_funding_amount": 100000},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_open_channel_with_host(self, dashboard_client, auth_cookies):
        with (
            patch(
                "app.dashboard.api.lnd_service.connect_peer",
                new_callable=AsyncMock,
                return_value=({}, None),
            ) as mock_connect,
            patch(
                "app.dashboard.api.lnd_service.open_channel",
                new_callable=AsyncMock,
                return_value=({"funding_txid": "abc123"}, None),
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/channel/open",
                json={
                    "pubkey": "02" + "a1" * 32,
                    "host": "8.8.8.8:9735",
                    "local_funding_amount": 100000,
                },
            )
        assert resp.status_code == 200
        mock_connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_open_channel_peer_connect_failure(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.connect_peer",
            new_callable=AsyncMock,
            return_value=(None, "connection refused"),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/channel/open",
                json={
                    "pubkey": "02" + "a1" * 32,
                    "host": "8.8.8.8:9735",
                    "local_funding_amount": 100000,
                },
            )
        assert resp.status_code == 502
        assert "LND service error" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_open_channel_lnd_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.open_channel",
            new_callable=AsyncMock,
            return_value=(None, "insufficient funds"),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/channel/open",
                json={"pubkey": "02" + "a1" * 32, "local_funding_amount": 100000},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_pending_channels_detail(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_pending_channels_detail",
            new_callable=AsyncMock,
            return_value=([{"type": "pending_open", "capacity": 100000}], None),
        ):
            resp = await dashboard_client.get("/dashboard/api/channels/pending")
        assert resp.status_code == 200


class TestDashboardColdStorageEndpoints:
    """Tests for dashboard cold storage (Boltz) endpoints."""

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
    async def test_cold_storage_fees_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.boltz_service.get_reverse_pair_info",
            new_callable=AsyncMock,
            return_value=({"max_amount": 1000000, "min_amount": 10000}, None),
        ):
            resp = await dashboard_client.get("/dashboard/api/cold-storage/fees")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_cold_storage_fees_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.boltz_service.get_reverse_pair_info",
            new_callable=AsyncMock,
            return_value=(None, "Boltz unreachable"),
        ):
            resp = await dashboard_client.get("/dashboard/api/cold-storage/fees")
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_cold_storage_initiate_success(self, dashboard_client, auth_cookies):
        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        mock_swap.boltz_swap_id = "swap123"
        mock_swap.status.value = "created"
        mock_swap.boltz_invoice = "lnbc..."
        mock_swap.onchain_amount_sats = 95000

        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 500000}, None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
                return_value=(mock_swap, None),
            ),
            patch("app.tasks.boltz_tasks.process_boltz_swap") as mock_task,
        ):
            mock_task.delay = MagicMock()
            resp = await dashboard_client.post(
                "/dashboard/api/cold-storage/initiate",
                json={"amount_sats": 100000, "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
            )
        assert resp.status_code == 200
        assert resp.json()["boltz_swap_id"] == "swap123"

    @pytest.mark.asyncio
    async def test_cold_storage_initiate_error(self, dashboard_client, auth_cookies):
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 500000}, None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
                return_value=(None, "Amount below minimum"),
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/cold-storage/initiate",
                json={"amount_sats": 100, "destination_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
            )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_cold_storage_swaps_list(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.get("/dashboard/api/cold-storage/swaps")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    @pytest.mark.asyncio
    async def test_cold_storage_swap_detail_found(self, dashboard_client, auth_cookies):
        mock_swap = MagicMock()
        mock_swap.id = uuid4()
        mock_swap.boltz_swap_id = "swap123"
        mock_swap.status.value = "completed"
        mock_swap.boltz_status = "transaction.claimed"
        mock_swap.invoice_amount_sats = 100000
        mock_swap.onchain_amount_sats = 95000
        mock_swap.destination_address = "bcrt1q..."
        mock_swap.claim_txid = "txid123"
        mock_swap.error_message = None
        mock_swap.status_history = []
        mock_swap.created_at.isoformat.return_value = "2026-04-18T00:00:00"
        mock_swap.completed_at.isoformat.return_value = "2026-04-18T00:01:00"

        with patch(
            "app.dashboard.api.boltz_service.get_swap_by_id",
            new_callable=AsyncMock,
            return_value=mock_swap,
        ):
            resp = await dashboard_client.get(f"/dashboard/api/cold-storage/swaps/{mock_swap.id}")
        assert resp.status_code == 200
        assert resp.json()["boltz_swap_id"] == "swap123"

    @pytest.mark.asyncio
    async def test_cold_storage_swap_detail_not_found(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.boltz_service.get_swap_by_id",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await dashboard_client.get(f"/dashboard/api/cold-storage/swaps/{uuid4()}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cold_storage_cancel_success(self, dashboard_client, auth_cookies):
        mock_swap = MagicMock()
        mock_swap.id = uuid4()

        with (
            patch(
                "app.dashboard.api.boltz_service.get_swap_by_id",
                new_callable=AsyncMock,
                return_value=mock_swap,
            ),
            patch(
                "app.dashboard.api.boltz_service.cancel_swap",
                new_callable=AsyncMock,
                return_value=(True, None),
            ),
        ):
            resp = await dashboard_client.post(f"/dashboard/api/cold-storage/swaps/{mock_swap.id}/cancel")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_cold_storage_cancel_not_found(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.boltz_service.get_swap_by_id",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await dashboard_client.post(f"/dashboard/api/cold-storage/swaps/{uuid4()}/cancel")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cold_storage_cancel_not_cancellable(self, dashboard_client, auth_cookies):
        mock_swap = MagicMock()
        mock_swap.id = uuid4()

        with (
            patch(
                "app.dashboard.api.boltz_service.get_swap_by_id",
                new_callable=AsyncMock,
                return_value=mock_swap,
            ),
            patch(
                "app.dashboard.api.boltz_service.cancel_swap",
                new_callable=AsyncMock,
                return_value=(False, "Cannot cancel: already paid"),
            ),
        ):
            resp = await dashboard_client.post(f"/dashboard/api/cold-storage/swaps/{mock_swap.id}/cancel")
        assert resp.status_code == 400


# ── Sign / Verify Message Endpoints ──────────────────────────────────


class TestDashboardSignEndpoints:
    """Cover the seven /dashboard/api/sign|verify endpoints."""

    REGTEST_ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.fixture(autouse=True)
    def _bypass_csrf(self):
        with patch("app.dashboard.api.check_csrf_token", new_callable=AsyncMock, return_value="ok"):
            yield

    @pytest.fixture(autouse=True)
    def _no_rate_limit(self):
        with patch(
            "app.core.rate_limit.check_sign_rate_limit",
            new=AsyncMock(return_value=(True, None)),
        ):
            yield

    # ── /sign/config ─────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_sign_config_requires_auth(self, dashboard_client):
        resp = await dashboard_client.get("/dashboard/api/sign/config")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_sign_config_returns_settings(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.get("/dashboard/api/sign/config")
        assert resp.status_code == 200
        body = resp.json()
        assert "max_chars" in body and "autocomplete" in body
        assert body["autocomplete"] in ("txn_history", "wallet_addresses", "off")

    # ── /sign/addresses ──────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_sign_addresses_off_mode(self, dashboard_client, auth_cookies):
        with patch.object(settings, "sign_address_autocomplete", "off"):
            resp = await dashboard_client.get("/dashboard/api/sign/addresses")
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"mode": "off", "addresses": []}

    @pytest.mark.asyncio
    async def test_sign_addresses_txn_history(self, dashboard_client, auth_cookies):
        fake = {
            "transactions": [
                {"dest_addresses": [self.REGTEST_ADDR], "time_stamp": "1700000000"},
                {"dest_addresses": [self.REGTEST_ADDR, "bcrt1qother"], "time_stamp": "1700000100"},
            ]
        }
        with (
            patch.object(settings, "sign_address_autocomplete", "txn_history"),
            patch(
                "app.dashboard.api.lnd_service._request",
                new=AsyncMock(return_value=(fake, None)),
            ),
        ):
            resp = await dashboard_client.get("/dashboard/api/sign/addresses")
        assert resp.status_code == 200
        body = resp.json()
        assert body["mode"] == "txn_history"
        addrs = [a["address"] for a in body["addresses"]]
        # Dedup preserves first-seen order
        assert self.REGTEST_ADDR in addrs and "bcrt1qother" in addrs
        assert len(addrs) == len(set(addrs))

    @pytest.mark.asyncio
    async def test_sign_addresses_txn_history_lnd_error(self, dashboard_client, auth_cookies):
        with (
            patch.object(settings, "sign_address_autocomplete", "txn_history"),
            patch(
                "app.dashboard.api.lnd_service._request",
                new=AsyncMock(return_value=(None, "lnd down")),
            ),
        ):
            resp = await dashboard_client.get("/dashboard/api/sign/addresses")
        # Endpoint still 200 with empty list + error message (graceful degradation)
        assert resp.status_code == 200
        body = resp.json()
        assert body["addresses"] == []
        assert body.get("error")

    @pytest.mark.asyncio
    async def test_sign_addresses_wallet_addresses(self, dashboard_client, auth_cookies):
        fake = {
            "account_with_addresses": [
                {
                    "addresses": [
                        {"address": self.REGTEST_ADDR, "is_internal": False},
                        {"address": self.REGTEST_ADDR, "is_internal": False},  # dup
                        {"address": "bcrt1qchange", "is_internal": True},
                    ]
                }
            ]
        }
        with (
            patch.object(settings, "sign_address_autocomplete", "wallet_addresses"),
            patch(
                "app.dashboard.api.lnd_service._request",
                new=AsyncMock(return_value=(fake, None)),
            ),
        ):
            resp = await dashboard_client.get("/dashboard/api/sign/addresses")
        assert resp.status_code == 200
        body = resp.json()
        assert body["mode"] == "wallet_addresses"
        addrs = [a["address"] for a in body["addresses"]]
        assert addrs.count(self.REGTEST_ADDR) == 1
        assert {"address": "bcrt1qchange", "is_internal": True} in body["addresses"]

    # ── /sign/owns-address ───────────────────────────────────────
    @pytest.fixture(autouse=True)
    def _reset_owns_address_caches(self):
        # The endpoint caches "endpoint unsupported" verdicts at
        # module level so older LND builds don't re-probe 404s
        # forever. Tests need a fresh slate per case so each probe
        # is actually exercised.
        import app.dashboard.api as dashboard_api

        dashboard_api._is_our_address_supported = None
        dashboard_api._list_addresses_supported = None
        dashboard_api._sign_as_probe_supported = None
        dashboard_api._owned_address_cache = set()
        yield
        dashboard_api._is_our_address_supported = None
        dashboard_api._list_addresses_supported = None
        dashboard_api._sign_as_probe_supported = None
        dashboard_api._owned_address_cache = set()

    @pytest.mark.asyncio
    async def test_sign_owns_address_requires_auth(self, dashboard_client):
        resp = await dashboard_client.get(
            "/dashboard/api/sign/owns-address",
            params={"address": self.REGTEST_ADDR},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_sign_owns_address_true_via_is_our_address(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # Primary path: LND's IsOurAddress RPC returns true. This is
        # the canonical ownership check — works for any address the
        # wallet's keys could produce, including ones not in the
        # current ListAddresses snapshot.
        async def _route(method, path, **kwargs):
            assert method == "POST"
            assert path == "/v2/wallet/address/ours"
            assert kwargs.get("json") == {"addr": self.REGTEST_ADDR}
            return ({"is_our_address": True}, None)

        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(side_effect=_route),
        ):
            resp = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
        assert resp.status_code == 200
        assert resp.json() == {"owned": True, "address": self.REGTEST_ADDR}

    @pytest.mark.asyncio
    async def test_sign_owns_address_false_via_is_our_address(
        self,
        dashboard_client,
        auth_cookies,
    ):
        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(return_value=({"is_our_address": False}, None)),
        ):
            resp = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
        assert resp.status_code == 200
        assert resp.json() == {"owned": False, "address": self.REGTEST_ADDR}

    @pytest.mark.asyncio
    async def test_sign_owns_address_falls_back_to_list_addresses(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # Older LND that doesn't expose IsOurAddress — the endpoint
        # should fall back to scanning ListAddresses so the wallet
        # doesn't lose the ownership feature on a build behind the
        # latest. Models the failure by having the first call return
        # an error and the second succeed with the ListAddresses
        # shape.
        list_addrs_shape = {
            "account_with_addresses": [
                {
                    "addresses": [
                        {"address": "bcrt1qother", "is_internal": True},
                        {"address": self.REGTEST_ADDR, "is_internal": False},
                    ]
                },
            ]
        }
        call_count = {"n": 0}

        async def _route(method, path, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First call: IsOurAddress — simulate unavailable.
                assert path == "/v2/wallet/address/ours"
                return (None, "unimplemented")
            # Second call: ListAddresses fallback.
            assert method == "GET"
            assert path == "/v1/wallet/addresses"
            return (list_addrs_shape, None)

        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(side_effect=_route),
        ):
            resp = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
        assert resp.status_code == 200
        assert resp.json() == {"owned": True, "address": self.REGTEST_ADDR}
        assert call_count["n"] == 2, "both IsOurAddress and ListAddresses must be called"

    @pytest.mark.asyncio
    async def test_sign_owns_address_caches_unsupported_verdict(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # Regression for the production log-noise issue: on a 404
        # from IsOurAddress (LND build doesn't expose the RPC),
        # subsequent calls must skip the probe and go straight to
        # the next fallback. Otherwise every offer-card render fires
        # a 404 + ERROR log + spurious LND health-failure record.
        list_addrs_shape = {
            "account_with_addresses": [
                {"addresses": [{"address": self.REGTEST_ADDR, "is_internal": False}]},
            ]
        }
        is_our_address_calls = {"n": 0}
        list_addresses_calls = {"n": 0}

        async def _route(method, path, **kwargs):
            if path == "/v2/wallet/address/ours":
                is_our_address_calls["n"] += 1
                # Simulate the production 404 — same error-string
                # shape as ``_request`` produces for an httpx 404.
                return (None, "LND error (404): Not Found")
            if path == "/v1/wallet/addresses":
                list_addresses_calls["n"] += 1
                return (list_addrs_shape, None)
            raise AssertionError(f"unexpected LND call to {path}")

        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(side_effect=_route),
        ):
            # First call (REGTEST_ADDR): IsOurAddress 404 → caches
            # unavailable. ListAddresses found → owned: true →
            # cached positive.
            resp1 = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
            # Second call (same address): hits the positive cache
            # before any LND call.
            resp2 = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
            # Third call (different address, not in list): no
            # positive-cache hit; IsOurAddress is skipped (cached
            # unavailable); ListAddresses runs and returns false.
            resp3 = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": "bcrt1qother"},
            )

        for r in (resp1, resp2, resp3):
            assert r.status_code == 200

        # IsOurAddress is probed exactly once — after the 404 the
        # cache prevents re-probing.
        assert is_our_address_calls["n"] == 1, (
            f"IsOurAddress must be probed at most once after a 404, saw {is_our_address_calls['n']}"
        )
        # ListAddresses runs for call 1 (the first uncached probe)
        # and call 3 (different address; positive cache doesn't
        # apply). Call 2 short-circuits on the positive cache.
        assert list_addresses_calls["n"] == 2, (
            f"expected ListAddresses to run twice (call 1 + call 3); "
            f"call 2 must hit the positive cache. Saw "
            f"{list_addresses_calls['n']}"
        )

    @pytest.mark.asyncio
    async def test_sign_owns_address_does_not_cache_transient_errors(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # 5xx / connection errors on the PROBE-AVAILABILITY check
        # must NOT poison the endpoint-supported cache — those are
        # transient and the next call should retry the primary path.
        # Only 404 (semantic "endpoint missing") cements the fallback.
        is_our_address_calls = {"n": 0}

        async def _route(method, path, **kwargs):
            if path == "/v2/wallet/address/ours":
                is_our_address_calls["n"] += 1
                if is_our_address_calls["n"] == 1:
                    return (None, "LND error (500): internal")  # transient
                return ({"is_our_address": True}, None)  # recovered
            # First call falls through to ListAddresses (which
            # returns empty), then to the sign-probe path.
            if path == "/v1/wallet/addresses":
                return ({"account_with_addresses": []}, None)
            raise AssertionError(f"unexpected LND call to {path}")

        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(side_effect=_route),
        ):
            # First call: 5xx on IsOurAddress, falls through to
            # ListAddresses, which returns an empty set → owned: false.
            resp1 = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
            # Second call: IsOurAddress is retried (5xx didn't
            # poison the cache), succeeds with owned: true.
            resp2 = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )

        assert resp1.json()["owned"] is False
        assert resp2.json()["owned"] is True
        assert is_our_address_calls["n"] == 2, "5xx errors must not poison the cache — only 404 does"

    @pytest.mark.asyncio
    async def test_sign_owns_address_false_when_no_path_finds_it(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # IsOurAddress unavailable AND ListAddresses doesn't list the
        # address — endpoint must return ``owned: false``, NOT 404.
        # A 404 would force every offer-card render to treat the
        # lookup as an error path.
        list_addrs_shape = {
            "account_with_addresses": [
                {"addresses": [{"address": "bcrt1qsomethingelse", "is_internal": False}]},
            ]
        }
        call_count = {"n": 0}

        async def _route(method, path, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return (None, "unimplemented")
            return (list_addrs_shape, None)

        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(side_effect=_route),
        ):
            resp = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
        assert resp.status_code == 200
        assert resp.json() == {"owned": False, "address": self.REGTEST_ADDR}

    @pytest.mark.asyncio
    async def test_sign_owns_address_empty_address_rejected(
        self,
        dashboard_client,
        auth_cookies,
    ):
        resp = await dashboard_client.get(
            "/dashboard/api/sign/owns-address",
            params={"address": ""},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_sign_owns_address_oversize_rejected(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # Defence against a malicious caller pumping arbitrary bytes
        # into LND's gRPC channel via the query string. 128-char cap
        # is well above any real bitcoin address.
        resp = await dashboard_client.get(
            "/dashboard/api/sign/owns-address",
            params={"address": "x" * 200},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_sign_owns_address_transient_lnd_error_returns_502(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # Both probes fail with a transient (non-404) LND error —
        # endpoint must surface 502 so the dashboard JS treats the
        # result as a real outage (and hides the shortcut to avoid
        # surfacing the button during a flap). Distinct from the
        # 404+404 case (LND build genuinely lacks the endpoints)
        # which returns owned: null instead.
        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(return_value=(None, "LND unreachable")),
        ):
            resp = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_sign_owns_address_all_three_endpoints_404(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # User-reported failure mode: an LND build that exposes
        # NEITHER IsOurAddress NOR ListAddresses NOR
        # SignMessageWithAddr. With the sign-as-probe fallback, a 404
        # from the probe is interpreted as "owned: false" (since the
        # user couldn't sign with this address on this LND either —
        # see the comment in ``sign_owns_address`` about why marking
        # the endpoint unavailable globally would be wrong).
        async def _route(method, path, **kwargs):
            return (None, "LND error (404): Not Found")

        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(side_effect=_route),
        ):
            resp = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
        assert resp.status_code == 200
        body = resp.json()
        # All three probes failed → can't sign with this address →
        # owned: false. Hides the button, which is correct because a
        # real sign attempt would also fail.
        assert body["owned"] is False
        assert body["address"] == self.REGTEST_ADDR

    @pytest.mark.asyncio
    async def test_sign_owns_address_sign_probe_success_means_owned(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # When IsOurAddress + ListAddresses are 404 but
        # SignMessageWithAddr works AND succeeds, the address IS
        # owned by the wallet (only key-holders can produce valid
        # signatures). Owned: true.
        sign_calls = {"n": 0}

        async def _route(method, path, **kwargs):
            if path in ("/v2/wallet/address/ours", "/v1/wallet/addresses"):
                return (None, "LND error (404): Not Found")
            if path == "/v2/wallet/address/signmessage":
                sign_calls["n"] += 1
                # Verify the probe message — must be self-identifying
                # so it's distinguishable in LND logs from real signs.
                import base64

                body = kwargs.get("json", {})
                assert body.get("addr") == self.REGTEST_ADDR
                signed = base64.b64decode(body["msg"]).decode("utf-8")
                assert "ownership probe" in signed.lower(), (
                    "probe message must self-identify so it's obvious in LND logs"
                )
                return (
                    {"signature": "AAAA", "address_type": "p2wkh"},
                    None,
                )
            raise AssertionError(f"unexpected LND call to {path}")

        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(side_effect=_route),
        ):
            resp = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["owned"] is True
        assert sign_calls["n"] == 1, "sign-as-probe must fire exactly once when reached"

    @pytest.mark.asyncio
    async def test_sign_owns_address_sign_probe_semantic_error_means_not_owned(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # SignMessageWithAddr returns a semantic LND error like
        # "address not in wallet" — this is authoritative for the
        # specific address: not owned.
        async def _route(method, path, **kwargs):
            if path in ("/v2/wallet/address/ours", "/v1/wallet/addresses"):
                return (None, "LND error (404): Not Found")
            if path == "/v2/wallet/address/signmessage":
                # 400 from LND maps to ``LND error (400): ...`` via
                # the service-layer error formatter.
                return (None, "LND error (400): address not in wallet")
            raise AssertionError(f"unexpected LND call to {path}")

        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(side_effect=_route),
        ):
            resp = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
        assert resp.status_code == 200
        assert resp.json()["owned"] is False

    @pytest.mark.asyncio
    async def test_sign_owns_address_sign_probe_transient_error_returns_502(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # A connection-level failure on the sign probe (not a semantic
        # LND error) must NOT be classified as ``owned: false`` — that
        # would mislead users when LND is genuinely flapping. Instead,
        # propagate as 502 so the dashboard JS treats the result as
        # "couldn't verify" and the button stays hidden until LND
        # recovers.
        async def _route(method, path, **kwargs):
            if path in ("/v2/wallet/address/ours", "/v1/wallet/addresses"):
                return (None, "LND error (404): Not Found")
            if path == "/v2/wallet/address/signmessage":
                # Note: no ``LND error (XXX)`` prefix — this is the
                # shape used by ``_request`` for transport-layer
                # failures (connection refused, breaker open, etc.).
                return (None, "Connection failed: ECONNREFUSED")
            raise AssertionError(f"unexpected LND call to {path}")

        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(side_effect=_route),
        ):
            resp = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
        assert resp.status_code == 502, (
            "transient transport failures on the probe must propagate as 502 — not be misread as 'address not owned'"
        )

    @pytest.mark.asyncio
    async def test_sign_owns_address_caches_positive_per_address(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # Once an address is confirmed owned (via any path), the
        # endpoint must cache that result and skip all LND calls on
        # repeat queries for the same address. Otherwise every
        # offer-card render burns LND CPU.
        call_count = {"n": 0}

        async def _route(method, path, **kwargs):
            call_count["n"] += 1
            if path == "/v2/wallet/address/ours":
                return ({"is_our_address": True}, None)
            raise AssertionError(f"unexpected call to {path}")

        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(side_effect=_route),
        ):
            r1 = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
            r2 = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )
            r3 = await dashboard_client.get(
                "/dashboard/api/sign/owns-address",
                params={"address": self.REGTEST_ADDR},
            )

        for r in (r1, r2, r3):
            assert r.status_code == 200
            assert r.json()["owned"] is True

        assert call_count["n"] == 1, (
            f"positive result must be cached; saw {call_count['n']} LND calls for 3 identical queries"
        )

    @pytest.mark.asyncio
    async def test_sign_owns_address_caches_unsupported_list_endpoints(
        self,
        dashboard_client,
        auth_cookies,
    ):
        # Once IsOurAddress + ListAddresses are observed 404, the
        # endpoint must not re-probe them on subsequent calls (one
        # log line per RPC per process lifetime, not per call). The
        # sign-as-probe fallback still fires per call since semantic
        # answers are address-specific and not cached.
        is_our_address_calls = {"n": 0}
        list_addresses_calls = {"n": 0}
        sign_calls = {"n": 0}

        async def _route(method, path, **kwargs):
            if path == "/v2/wallet/address/ours":
                is_our_address_calls["n"] += 1
                return (None, "LND error (404): Not Found")
            if path == "/v1/wallet/addresses":
                list_addresses_calls["n"] += 1
                return (None, "LND error (404): Not Found")
            if path == "/v2/wallet/address/signmessage":
                sign_calls["n"] += 1
                # Address not in wallet — semantic answer.
                return (None, "LND error (400): address not in wallet")
            raise AssertionError(f"unexpected LND call to {path}")

        with patch(
            "app.dashboard.api.lnd_service._request",
            new=AsyncMock(side_effect=_route),
        ):
            for _ in range(3):
                resp = await dashboard_client.get(
                    "/dashboard/api/sign/owns-address",
                    params={"address": self.REGTEST_ADDR},
                )
                assert resp.status_code == 200
                assert resp.json()["owned"] is False

        # List endpoints exercised exactly once across three ownership
        # checks — the second + third calls hit only the cached
        # "unsupported" verdicts. The sign-probe fires every call
        # because semantic negatives aren't cached (a transient blip
        # shouldn't poison the cache).
        assert is_our_address_calls["n"] == 1, (
            f"IsOurAddress must be probed at most once after a 404, saw {is_our_address_calls['n']}"
        )
        assert list_addresses_calls["n"] == 1, (
            f"ListAddresses must be probed at most once after a 404, saw {list_addresses_calls['n']}"
        )
        assert sign_calls["n"] == 3, (
            f"sign-as-probe must run on each call for negative results (no cache poisoning), saw {sign_calls['n']}"
        )

    # ── /sign/address ────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_sign_address_requires_auth(self, dashboard_client):
        resp = await dashboard_client.post(
            "/dashboard/api/sign/address",
            json={"address": self.REGTEST_ADDR, "message": "hi"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_sign_address_success(self, dashboard_client, auth_cookies):
        fake = {
            "address": self.REGTEST_ADDR,
            "address_type": "p2wkh",
            "signature": "AAAA",
            "format": "BIP-322",
        }
        with patch(
            "app.dashboard.api.lnd_service.sign_message_with_address",
            new=AsyncMock(return_value=(fake, None)),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/sign/address",
                json={"address": self.REGTEST_ADDR, "message": "hello"},
            )
        assert resp.status_code == 200
        assert resp.json()["signature"] == "AAAA"

    @pytest.mark.asyncio
    async def test_sign_address_lnd_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.sign_message_with_address",
            new=AsyncMock(return_value=(None, "address not owned by wallet")),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/sign/address",
                json={"address": self.REGTEST_ADDR, "message": "hi"},
            )
        assert resp.status_code == 502
        assert "detail" in resp.json()

    @pytest.mark.asyncio
    async def test_sign_address_rejects_control_bytes(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/sign/address",
            json={"address": self.REGTEST_ADDR, "message": "hello\x00world"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_sign_address_rate_limited(self, dashboard_client, auth_cookies):
        with patch(
            "app.core.rate_limit.check_sign_rate_limit",
            new=AsyncMock(return_value=(False, "Sign rate limit reached: …")),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/sign/address",
                json={"address": self.REGTEST_ADDR, "message": "hi"},
            )
        assert resp.status_code == 429

    # ── /verify/address ──────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_verify_address_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.verify_message_with_address",
            new=AsyncMock(return_value=({"valid": True, "pubkey": "deadbeef"}, None)),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/verify/address",
                json={"address": self.REGTEST_ADDR, "message": "hi", "signature": "AAAA"},
            )
        assert resp.status_code == 200
        assert resp.json() == {"valid": True, "pubkey": "deadbeef"}

    @pytest.mark.asyncio
    async def test_verify_address_invalid_signature_is_not_an_error(self, dashboard_client, auth_cookies):
        """A failing verification is still a 200 — `valid=false` is the result, not an error."""
        with patch(
            "app.dashboard.api.lnd_service.verify_message_with_address",
            new=AsyncMock(return_value=({"valid": False, "pubkey": None}, None)),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/verify/address",
                json={"address": self.REGTEST_ADDR, "message": "hi", "signature": "AAAA"},
            )
        assert resp.status_code == 200
        assert resp.json()["valid"] is False

    @pytest.mark.asyncio
    async def test_verify_address_lnd_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.verify_message_with_address",
            new=AsyncMock(return_value=(None, "lnd unreachable")),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/verify/address",
                json={"address": self.REGTEST_ADDR, "message": "hi", "signature": "AAAA"},
            )
        assert resp.status_code == 502

    # ── /sign/node ───────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_sign_node_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.sign_message_node",
            new=AsyncMock(
                return_value=(
                    {"signature": "zsig", "node_pubkey": "02" + "f" * 64},
                    None,
                )
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/sign/node",
                json={"message": "hi"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["signature"] == "zsig"
        assert body["node_pubkey"].startswith("02")

    @pytest.mark.asyncio
    async def test_sign_node_lnd_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.sign_message_node",
            new=AsyncMock(return_value=(None, "boom")),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/sign/node",
                json={"message": "hi"},
            )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_sign_node_rate_limited(self, dashboard_client, auth_cookies):
        with patch(
            "app.core.rate_limit.check_sign_rate_limit",
            new=AsyncMock(return_value=(False, "limit")),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/sign/node",
                json={"message": "hi"},
            )
        assert resp.status_code == 429

    # ── /verify/node ─────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_verify_node_success(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.verify_message_node",
            new=AsyncMock(return_value=({"valid": True, "pubkey": "02deadbeef"}, None)),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/verify/node",
                json={"message": "hi", "signature": "zsig"},
            )
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    @pytest.mark.asyncio
    async def test_verify_node_lnd_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.verify_message_node",
            new=AsyncMock(return_value=(None, "boom")),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/verify/node",
                json={"message": "hi", "signature": "zsig"},
            )
        assert resp.status_code == 502

    # ── /sign/parse ──────────────────────────────────────────────
    @pytest.mark.asyncio
    async def test_parse_signed_json(self, dashboard_client, auth_cookies):
        blob = '{"address": "' + self.REGTEST_ADDR + '", "message": "hello", "signature": "AAAA", "format": "BIP-322"}'
        resp = await dashboard_client.post(
            "/dashboard/api/sign/parse",
            json={"blob": blob},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["identity"] == "address"
        assert body["address"] == self.REGTEST_ADDR
        assert body["message"] == "hello"
        assert body["signature"] == "AAAA"

    @pytest.mark.asyncio
    async def test_parse_signed_invalid(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/sign/parse",
            json={"blob": "not a recognisable format"},
        )
        assert resp.status_code == 400


# ── UTXO management endpoints ────────────────────────────────────────


class TestDashboardUtxos:
    """Tests for the UTXO management API.

    Covers list/label/consolidate happy paths and the validation
    failure modes the dashboard surface depends on (long labels,
    too-many outpoints, control bytes).
    """

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.fixture(autouse=True)
    def _bypass_csrf(self):
        with patch(
            "app.dashboard.api.check_csrf_token",
            new_callable=AsyncMock,
            return_value="ok",
        ):
            yield

    @staticmethod
    def _utxo_payload(txid: str, vout: int, *, addr: str = "bc1qabc", amt: int = 50000):
        return {
            "outpoint": {"txid_str": txid, "output_index": vout},
            "amount_sat": amt,
            "address": addr,
            "address_type": "WITNESS_PUBKEY_HASH",
            "pk_script": "",
            "confirmations": 3,
        }

    @pytest.mark.asyncio
    async def test_list_utxos_returns_labels(self, dashboard_client, auth_cookies):
        txid = "a" * 64
        with patch(
            "app.services.utxo_service.lnd_service.list_unspent",
            new_callable=AsyncMock,
            return_value=([self._utxo_payload(txid, 0)], None),
        ):
            # Seed a label first.
            r = await dashboard_client.patch(
                f"/dashboard/api/utxos/{txid}/0/label",
                json={"label": "Ocean payout"},
            )
            assert r.status_code == 200
            resp = await dashboard_client.get("/dashboard/api/utxos")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_sats"] == 50000
        assert len(body["utxos"]) == 1
        u = body["utxos"][0]
        assert u["txid"] == txid
        assert u["label"] == "Ocean payout"
        assert u["label_source"] == "user"

    @pytest.mark.asyncio
    async def test_label_rejects_too_long(self, dashboard_client, auth_cookies):
        txid = "b" * 64
        resp = await dashboard_client.patch(
            f"/dashboard/api/utxos/{txid}/0/label",
            json={"label": "x" * 81},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_label_rejects_control_bytes(self, dashboard_client, auth_cookies):
        txid = "c" * 64
        resp = await dashboard_client.patch(
            f"/dashboard/api/utxos/{txid}/0/label",
            json={"label": "hi\x01there"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_label_clear_with_empty_string(self, dashboard_client, auth_cookies):
        txid = "d" * 64
        # Set then clear — both should 200.
        r1 = await dashboard_client.patch(
            f"/dashboard/api/utxos/{txid}/0/label",
            json={"label": "tmp"},
        )
        assert r1.status_code == 200
        r2 = await dashboard_client.patch(
            f"/dashboard/api/utxos/{txid}/0/label",
            json={"label": ""},
        )
        assert r2.status_code == 200

    @pytest.mark.asyncio
    async def test_consolidate_rejects_empty_outpoints(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/consolidate",
            json={"outpoints": [], "dest_address_type": "p2wkh"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_consolidate_rejects_too_many(self, dashboard_client, auth_cookies):
        ops = [{"txid_str": "a" * 64, "output_index": i} for i in range(201)]
        resp = await dashboard_client.post(
            "/dashboard/api/consolidate",
            json={"outpoints": ops, "dest_address_type": "p2wkh"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_consolidate_happy_path(self, dashboard_client, auth_cookies):
        txid_a = "a" * 64
        txid_b = "b" * 64
        new_txid = "c" * 64
        ops = [
            {"txid_str": txid_a, "output_index": 0},
            {"txid_str": txid_b, "output_index": 1},
        ]
        with (
            patch(
                "app.dashboard.api.lnd_service.new_address",
                new_callable=AsyncMock,
                return_value=({"address": "bc1qsweep"}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.send_coins",
                new_callable=AsyncMock,
                return_value=({"txid": new_txid}, None),
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/consolidate",
                json={"outpoints": ops, "dest_address_type": "p2wkh"},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["txid"] == new_txid
        assert body["address"] == "bc1qsweep"
        assert body["input_count"] == 2

    @pytest.mark.asyncio
    async def test_send_onchain_with_outpoints(self, dashboard_client, auth_cookies):
        txid = "a" * 64
        with patch(
            "app.dashboard.api.lnd_service.send_coins",
            new_callable=AsyncMock,
            return_value=({"txid": "broadcast"}, None),
        ) as mock_send:
            resp = await dashboard_client.post(
                "/dashboard/api/send-onchain",
                json={
                    "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "amount_sats": 50000,
                    "outpoints": [{"txid_str": txid, "output_index": 0}],
                },
            )
        assert resp.status_code == 200
        # Verify the outpoints were forwarded to the LND service.
        call_kwargs = mock_send.call_args.kwargs
        assert call_kwargs.get("outpoints") == [{"txid_str": txid, "output_index": 0}]

    @pytest.mark.asyncio
    async def test_list_utxos_lnd_error_returns_502(self, dashboard_client, auth_cookies):
        with patch(
            "app.services.utxo_service.lnd_service.list_unspent",
            new_callable=AsyncMock,
            return_value=(None, "lnd offline"),
        ):
            resp = await dashboard_client.get("/dashboard/api/utxos")
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_list_utxos_search_filter(self, dashboard_client, auth_cookies):
        a = "a" * 64
        b = "b" * 64
        utxos = [
            self._utxo_payload(a, 0, addr="bc1qaaa", amt=10000),
            self._utxo_payload(b, 0, addr="bc1qbbb", amt=20000),
        ]
        with patch(
            "app.services.utxo_service.lnd_service.list_unspent",
            new_callable=AsyncMock,
            return_value=(utxos, None),
        ):
            # Seed a label so we can search by it.
            await dashboard_client.patch(
                f"/dashboard/api/utxos/{a}/0/label",
                json={"label": "Ocean payout"},
            )
            resp = await dashboard_client.get("/dashboard/api/utxos?q=ocean")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["utxos"]) == 1
        assert body["utxos"][0]["txid"] == a

    @pytest.mark.asyncio
    async def test_recently_spent_endpoint(self, dashboard_client, auth_cookies):
        # Empty initially.
        resp = await dashboard_client.get("/dashboard/api/utxos/recently-spent")
        assert resp.status_code == 200
        assert resp.json() == {"recently_spent": []}

    @pytest.mark.asyncio
    async def test_reconcile_endpoint_happy(self, dashboard_client, auth_cookies):
        with patch(
            "app.services.utxo_service.lnd_service.list_unspent",
            new_callable=AsyncMock,
            return_value=([], None),
        ):
            resp = await dashboard_client.post("/dashboard/api/utxos/reconcile")
        assert resp.status_code == 200
        body = resp.json()
        assert body["error"] == 0
        assert "spent_marked" in body
        assert "auto_labelled" in body
        assert "purged" in body

    @pytest.mark.asyncio
    async def test_reconcile_endpoint_lnd_error(self, dashboard_client, auth_cookies):
        with patch(
            "app.services.utxo_service.lnd_service.list_unspent",
            new_callable=AsyncMock,
            return_value=(None, "boom"),
        ):
            resp = await dashboard_client.post("/dashboard/api/utxos/reconcile")
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_label_rejects_invalid_txid(self, dashboard_client, auth_cookies):
        # Non-hex / wrong length txid should be 422.
        resp = await dashboard_client.patch(
            "/dashboard/api/utxos/zzz/0/label",
            json={"label": "x"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_label_rejects_negative_vout(self, dashboard_client, auth_cookies):
        # FastAPI path coercion turns "-1" into int(-1); the route's
        # explicit guard returns 422.
        txid = "a" * 64
        resp = await dashboard_client.patch(
            f"/dashboard/api/utxos/{txid}/-1/label",
            json={"label": "x"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_consolidate_rejects_bad_address_type(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/consolidate",
            json={
                "outpoints": [{"txid_str": "a" * 64, "output_index": 0}],
                "dest_address_type": "bogus",
            },
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_consolidate_writes_inherited_label(self, dashboard_client, auth_cookies):
        # End-to-end: seed labels on inputs, run consolidate, then
        # GET /utxos with the new outpoint mocked as live and assert
        # the synthesised "Consolidated: N inputs" label appears.
        txid_a = "a" * 64
        txid_b = "b" * 64
        new_txid = "c" * 64

        # 1. Label both parents.
        for t in (txid_a, txid_b):
            r = await dashboard_client.patch(
                f"/dashboard/api/utxos/{t}/0/label",
                json={"label": f"parent-{t[:4]}"},
            )
            assert r.status_code == 200

        with (
            patch(
                "app.dashboard.api.lnd_service.new_address",
                new_callable=AsyncMock,
                return_value=({"address": "bc1qsweep"}, None),
            ),
            patch(
                "app.dashboard.api.lnd_service.send_coins",
                new_callable=AsyncMock,
                return_value=({"txid": new_txid}, None),
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/consolidate",
                json={
                    "outpoints": [
                        {"txid_str": txid_a, "output_index": 0},
                        {"txid_str": txid_b, "output_index": 0},
                    ],
                    "dest_address_type": "p2wkh",
                },
            )
        assert resp.status_code == 200

        # The synthetic label should be on the new outpoint with
        # source=inherited; verify via /utxos.
        with patch(
            "app.services.utxo_service.lnd_service.list_unspent",
            new_callable=AsyncMock,
            return_value=([self._utxo_payload(new_txid, 0)], None),
        ):
            resp = await dashboard_client.get("/dashboard/api/utxos")
        assert resp.status_code == 200
        utxos = resp.json()["utxos"]
        assert len(utxos) == 1
        assert utxos[0]["label"] == "Consolidated: 2 inputs"
        assert utxos[0]["label_source"] == "inherited"

    @pytest.mark.asyncio
    async def test_send_onchain_audit_records_coin_control(self, dashboard_client, auth_cookies, db_session):
        # The send-onchain audit detail dict gains coin_control + input_count.
        from sqlalchemy import select

        from app.models.audit_log import AuditLog

        with patch(
            "app.dashboard.api.lnd_service.send_coins",
            new_callable=AsyncMock,
            return_value=({"txid": "tx1"}, None),
        ):
            r = await dashboard_client.post(
                "/dashboard/api/send-onchain",
                json={
                    "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                    "amount_sats": 10000,
                    "outpoints": [{"txid_str": "a" * 64, "output_index": 0}],
                },
            )
        assert r.status_code == 200
        rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "send_onchain"))).scalars().all()
        assert rows
        details = rows[-1].details or {}
        assert details.get("coin_control") is True
        assert details.get("input_count") == 1
