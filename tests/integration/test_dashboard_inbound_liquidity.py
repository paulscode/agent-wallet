# SPDX-License-Identifier: MIT
"""Integration tests for the Add-Receive-Capacity wizard.

The wizard re-uses the existing Cold-Storage swap endpoints
(``/cold-storage/fees`` / ``/cold-storage/initiate`` /
``/cold-storage/swaps/{id}`` / ``/cold-storage/swaps/{id}/cancel``).
These tests pin:

* The summary payload exposes ``totals.lightning_remote_sats`` —
  load-bearing for the banner in the Receive-Lightning dialog.
* ``/cold-storage/initiate`` accepts an optional ``purpose`` field
  and records it in the audit log so operators can distinguish
  Cold-Storage vs inbound-liquidity initiations.
* The swap-detail response carries every field the wizard's
  progress / success views read.
* Concurrent swaps are independent.
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


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    """Mirror of the autouse fixture in test_dashboard.py — autouse
    fixtures don't propagate across modules even when their function
    is imported, so we re-declare it here. Sets a deterministic
    dashboard token so the session cookie validates."""
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


@pytest.fixture(autouse=True)
def _stub_optional_confirmations():
    """The swap-detail endpoint enriches the response with an
    Electrum / mempool-HTTP confirmation count when ``claim_txid``
    is set. In the test process this would try to reach Tor's onion
    mempool and races with the asyncio event-loop teardown of
    earlier tests, producing flaky ``Event loop is closed`` errors.
    Stub the enrichment to ``None`` everywhere; we already pin the
    presence/absence of the field in dedicated tests."""
    with patch(
        "app.dashboard.api.mempool_fee_service.optional_confirmations",
        new_callable=AsyncMock,
        return_value=None,
    ):
        yield


# Reusable address validator-friendly address.
_TEST_ADDR = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"


def _summary_payload(**totals_overrides: int) -> dict:
    """Mirror of the structure ``lnd_service.get_wallet_summary``
    returns. Keep this in sync with the equivalent fixture in
    test_dashboard_onboarding.py."""
    totals = {
        "total_balance_sats": 0,
        "onchain_sats": 0,
        "lightning_local_sats": 0,
        "lightning_remote_sats": 0,
        "unconfirmed_sats": 0,
        "num_active_channels": 0,
        "num_pending_channels": 0,
        "synced": True,
    }
    totals.update(totals_overrides)
    return {
        "connected": True,
        "node_info": {},
        "onchain": {
            "confirmed_balance": totals["onchain_sats"],
            "unconfirmed_balance": totals["unconfirmed_sats"],
        },
        "lightning": {
            "local_balance_sat": totals["lightning_local_sats"],
            "remote_balance_sat": totals["lightning_remote_sats"],
        },
        "pending_channels": {},
        "totals": totals,
    }


def _mock_swap(**overrides) -> MagicMock:
    """Build a swap mock that satisfies attribute access on the
    cold-storage endpoints."""
    mock = MagicMock()
    mock.id = overrides.get("id", uuid4())
    mock.boltz_swap_id = overrides.get("boltz_swap_id", "swap_" + str(mock.id)[:8])
    mock.status.value = overrides.get("status", "created")
    mock.boltz_status = overrides.get("boltz_status", "swap.created")
    mock.boltz_invoice = overrides.get("boltz_invoice", "lnbc100u...")
    mock.invoice_amount_sats = overrides.get("invoice_amount_sats", 100_000)
    mock.onchain_amount_sats = overrides.get("onchain_amount_sats", 95_000)
    mock.destination_address = overrides.get("destination_address", _TEST_ADDR)
    mock.claim_txid = overrides.get("claim_txid", None)
    mock.timeout_block_height = overrides.get("timeout_block_height", None)
    mock.error_message = overrides.get("error_message", None)
    mock.status_history = overrides.get("status_history", [])
    mock.created_at.isoformat.return_value = "2026-05-17T00:00:00"
    mock.completed_at = None
    return mock


class TestSummaryCarriesRemoteSats:
    """The banner in the Receive-Lightning dialog reads
    ``summary.totals.lightning_remote_sats``. If a future refactor
    renames this key or drops it from the payload, every Receive-
    Lightning render breaks silently."""

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_summary_exposes_lightning_remote_sats(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_wallet_summary",
            new_callable=AsyncMock,
            return_value=(_summary_payload(lightning_remote_sats=42_000), None),
        ):
            resp = await dashboard_client.get("/dashboard/api/summary")
        assert resp.status_code == 200
        body = resp.json()
        assert "totals" in body
        assert "lightning_remote_sats" in body["totals"], (
            "summary.totals.lightning_remote_sats is the field the inbound-"
            "liquidity banner reads. Removing it would silently break the "
            "Receive-Lightning dialog's inbound-capacity prompt."
        )
        assert body["totals"]["lightning_remote_sats"] == 42_000


class TestInitiateSwapPurposeField:
    """The dashboard accepts an optional ``purpose`` field
    and records it in the audit log so a CSV/JSON export can
    distinguish the two swap intents."""

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.fixture(autouse=True)
    def _bypass_csrf(self):
        # The cold-storage endpoints sit behind ``_require_auth_csrf``.
        # Generating a real CSRF token in tests would require Redis;
        # patching ``check_csrf_token`` to return "ok" is the same
        # shortcut the existing Cold-Storage tests use.
        with patch("app.dashboard.api.check_csrf_token", new_callable=AsyncMock, return_value="ok"):
            yield

    @pytest.mark.asyncio
    async def test_initiate_with_inbound_liquidity_purpose_logged(self, dashboard_client, auth_cookies, db_engine):
        mock = _mock_swap()
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 500_000}, None),
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
                json={
                    "amount_sats": 100_000,
                    "destination_address": _TEST_ADDR,
                    "purpose": "inbound_liquidity",
                },
            )
        assert resp.status_code == 200

        # Audit log should now carry the purpose in its details.
        from sqlalchemy.ext.asyncio import async_sessionmaker

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (await session.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(5))).scalars().all()
            )
        matching = [r for r in rows if r.action == "cold_storage_initiate"]
        assert matching, "expected at least one cold_storage_initiate audit row"
        details = matching[0].details or {}
        assert details.get("purpose") == "inbound_liquidity", (
            f"audit row details should record purpose='inbound_liquidity'; got {details!r}"
        )
        # The destination address is included so operators reviewing
        # the audit log can see *where* funds went without having to
        # cross-reference the swap_id against the swap table.
        assert details.get("destination_address") == _TEST_ADDR, (
            f"audit row should record destination_address; got {details!r}"
        )

    @pytest.mark.asyncio
    async def test_initiate_without_purpose_defaults_to_cold_storage(self, dashboard_client, auth_cookies, db_engine):
        # Legacy clients (the original Cold Storage UI hasn't been
        # updated to send ``purpose``). They must continue to work,
        # and the audit log defaults to ``"cold_storage"`` so
        # operator queries filtering by ``purpose`` aren't blind to
        # un-flagged entries.
        mock = _mock_swap()
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 500_000}, None),
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

        from sqlalchemy.ext.asyncio import async_sessionmaker

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (await session.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(5))).scalars().all()
            )
        matching = [r for r in rows if r.action == "cold_storage_initiate"]
        assert matching
        assert (matching[0].details or {}).get("purpose") == "cold_storage"

    @pytest.mark.asyncio
    async def test_initiate_with_unknown_purpose_silently_normalised(self, dashboard_client, auth_cookies, db_engine):
        # The Pydantic validator allow-lists the two known values;
        # anything else collapses to ``None`` which the handler
        # treats as default ("cold_storage"). Prevents arbitrary
        # client-injected strings from polluting operator queries.
        mock = _mock_swap()
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 500_000}, None),
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
                json={
                    "amount_sats": 100_000,
                    "destination_address": _TEST_ADDR,
                    "purpose": "<script>alert(1)</script>",
                },
            )
        assert resp.status_code == 200

        from sqlalchemy.ext.asyncio import async_sessionmaker

        async with async_sessionmaker(db_engine, expire_on_commit=False)() as session:
            rows = (
                (await session.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(5))).scalars().all()
            )
        matching = [r for r in rows if r.action == "cold_storage_initiate"]
        assert matching
        assert (matching[0].details or {}).get("purpose") == "cold_storage"


class TestSelfMintedAddressFlow:
    """The wizard's submit handler runs the two
    endpoints in sequence — first ``POST /address`` to mint a fresh
    on-chain destination, then ``POST /cold-storage/initiate`` with
    that just-minted address as the swap output.

    The user never sees or chooses the address; the result is that
    the on-chain leg of the reverse swap lands in their own wallet.
    These tests pin that both endpoints accept the inbound-flow
    inputs (purpose='inbound_liquidity' on both) so the JS doesn't
    break next time someone refactors a request schema."""

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
    async def test_address_endpoint_accepts_inbound_liquidity_purpose(self, dashboard_client, auth_cookies):
        # Step 1 of the wizard's submit: mint a fresh address with
        # ``purpose='inbound_liquidity'`` so the UTXO is labelled
        # correctly in the UTXOs tab. Plan — the purpose store
        # accepts free-text labels.
        with (
            patch(
                "app.dashboard.api.lnd_service.new_address",
                new_callable=AsyncMock,
                return_value=({"address": _TEST_ADDR}, None),
            ),
            patch(
                "app.dashboard.api.utxo_service.record_address_purpose",
                new_callable=AsyncMock,
            ) as record_purpose,
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/address",
                json={"address_type": "p2wkh", "purpose": "inbound_liquidity"},
            )
        assert resp.status_code == 200
        assert resp.json()["address"] == _TEST_ADDR
        # The purpose was forwarded to the UTXO store — verifies
        # the label-routing wiring.
        record_purpose.assert_called_once()
        assert "inbound_liquidity" in record_purpose.call_args.args

    @pytest.mark.asyncio
    async def test_initiate_swap_with_self_minted_address(self, dashboard_client, auth_cookies):
        # End-to-end (two-step) round-trip: mint an address, then
        # initiate the swap using that same address as the
        # destination. This pins the full wizard contract: both
        # endpoints work in sequence with the expected payloads.
        with (
            patch(
                "app.dashboard.api.lnd_service.new_address",
                new_callable=AsyncMock,
                return_value=({"address": _TEST_ADDR}, None),
            ),
            patch(
                "app.dashboard.api.utxo_service.record_address_purpose",
                new_callable=AsyncMock,
            ),
        ):
            addr_resp = await dashboard_client.post(
                "/dashboard/api/address",
                json={"address_type": "p2wkh", "purpose": "inbound_liquidity"},
            )
        assert addr_resp.status_code == 200
        minted_address = addr_resp.json()["address"]

        mock = _mock_swap(destination_address=minted_address)
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 500_000}, None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
                return_value=(mock, None),
            ) as create_swap,
            patch("app.tasks.boltz_tasks.process_boltz_swap") as task,
        ):
            task.delay = MagicMock()
            init_resp = await dashboard_client.post(
                "/dashboard/api/cold-storage/initiate",
                json={
                    "amount_sats": 100_000,
                    "destination_address": minted_address,
                    "purpose": "inbound_liquidity",
                },
            )
        assert init_resp.status_code == 200
        # The destination address that ``boltz_service.create_reverse_swap``
        # was called with must be the one we just minted — there's no
        # accidental swap of cold-storage and inbound destinations.
        kwargs = create_swap.call_args.kwargs
        assert kwargs["destination_address"] == minted_address


class TestInitiateSwapAmountValidation:
    """Existing safety behaviour at the dashboard layer — pinned
    here as a contract for the wizard, because the form's
    canSubmit getter relies on the backend rejecting bad inputs
    if the user ever bypasses the client-side gate (DevTools
    fiddling, replayed request, etc.)."""

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
    async def test_initiate_exceeds_local_balance_returns_400(self, dashboard_client, auth_cookies):
        # User has 50k channel local; tries to initiate 100k swap.
        # The dashboard layer rejects before reaching Boltz.
        with patch(
            "app.dashboard.api.lnd_service.get_channel_balance",
            new_callable=AsyncMock,
            return_value=({"local_balance_sat": 50_000}, None),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/cold-storage/initiate",
                json={
                    "amount_sats": 100_000,
                    "destination_address": _TEST_ADDR,
                    "purpose": "inbound_liquidity",
                },
            )
        assert resp.status_code == 400
        assert "balance" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_initiate_below_boltz_min_returns_400(self, dashboard_client, auth_cookies):
        # Sub-25k amounts: the dashboard layer doesn't pre-check the
        # Boltz minimum (the request schema just enforces ``> 0``),
        # so the rejection comes from ``boltz_service.create_reverse_swap``
        # and surfaces as a 400 with the upstream message. The
        # wizard's submit gate prevents this from happening in
        # practice (``inboundCanSubmit`` enforces the 25k floor
        # client-side), but a DevTools-replayed request or a stale
        # client must still get cleanly rejected.
        with (
            patch(
                "app.dashboard.api.lnd_service.get_channel_balance",
                new_callable=AsyncMock,
                return_value=({"local_balance_sat": 500_000}, None),
            ),
            patch(
                "app.dashboard.api.boltz_service.create_reverse_swap",
                new_callable=AsyncMock,
                return_value=(None, "Amount 10000 below minimum 25000"),
            ),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/cold-storage/initiate",
                json={
                    "amount_sats": 10_000,
                    "destination_address": _TEST_ADDR,
                    "purpose": "inbound_liquidity",
                },
            )
        assert resp.status_code == 400
        # The upstream error is sanitised before reaching the user
        # (``sanitize_upstream_error``), so we can't assert on the
        # specific message — only that we got a 400 with a detail
        # field. The wizard's submit handler routes the same way
        # any other Boltz failure does, surfacing the sanitised
        # text in ``inboundError``.
        assert "detail" in resp.json()


class TestSwapDetailShape:
    """The wizard's progress view reads ``status``, ``claim_txid``,
    and (when available) ``claim_confirmations`` from this endpoint.
    The success view reads ``claim_txid``. Pin the shape so a
    backend rename doesn't silently break the wizard."""

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_swap_detail_carries_wizard_keys(self, dashboard_client, auth_cookies):
        mock = _mock_swap(status="claimed", claim_txid="deadbeef" * 8)
        with patch(
            "app.dashboard.api.boltz_service.get_swap_by_id",
            new_callable=AsyncMock,
            return_value=mock,
        ):
            resp = await dashboard_client.get(f"/dashboard/api/cold-storage/swaps/{mock.id}")
        assert resp.status_code == 200
        body = resp.json()
        for field in ("status", "claim_txid", "invoice_amount_sats", "destination_address"):
            assert field in body, (
                f"swap detail missing {field!r} — wizard's progress / success view will render with blank values."
            )
        assert body["status"] == "claimed"
        assert body["claim_txid"] == "deadbeef" * 8


class TestCancelSemantics:
    """Cancel only renders in the wizard UI while the
    swap is in ``created``. The backend endpoint still accepts a
    cancel attempt in ``paying_invoice`` (it's a server-side state
    machine), so these tests document both layers of the contract:

    * The backend endpoint behaves identically for both Cold Storage
      and the inbound wizard (they share the route).
    * The wizard's visibility gate (``inboundIsCancellable``) is
      stricter than the endpoint — see
      ``tests/unit/test_inbound_liquidity.py::TestIsCancellable``.

    These wrappers exist so a grep for ``cancel_swap_in_*_state``
    documents the intent. The underlying behaviour is already
    covered by ``test_dashboard.py::test_cold_storage_cancel_*``."""

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
    async def test_cancel_swap_in_created_state_succeeds(self, dashboard_client, auth_cookies):
        # ``created`` is the only state the wizard surfaces the Cancel
        # button for. The endpoint accepts the cancel and the swap is
        # marked cancelled.
        mock = _mock_swap(status="created")
        with (
            patch(
                "app.dashboard.api.boltz_service.get_swap_by_id",
                new_callable=AsyncMock,
                return_value=mock,
            ),
            patch(
                "app.dashboard.api.boltz_service.cancel_swap",
                new_callable=AsyncMock,
                return_value=(True, None),
            ),
        ):
            resp = await dashboard_client.post(f"/dashboard/api/cold-storage/swaps/{mock.id}/cancel")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_swap_in_paying_invoice_state_succeeds_at_endpoint(self, dashboard_client, auth_cookies):
        # Documents the layering: backend accepts the cancel even in
        # ``paying_invoice``, but the wizard's
        # ``inboundIsCancellable`` getter is stricter and hides the
        # button. This test pins the endpoint half; the unit-parity
        # tests pin the UI half. Together they prevent a future
        # refactor from accidentally removing one without the other.
        mock = _mock_swap(status="paying_invoice")
        with (
            patch(
                "app.dashboard.api.boltz_service.get_swap_by_id",
                new_callable=AsyncMock,
                return_value=mock,
            ),
            patch(
                "app.dashboard.api.boltz_service.cancel_swap",
                new_callable=AsyncMock,
                return_value=(True, None),
            ),
        ):
            resp = await dashboard_client.post(f"/dashboard/api/cold-storage/swaps/{mock.id}/cancel")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_cancel_swap_in_late_state_rejects(self, dashboard_client, auth_cookies):
        # Late states (``claimed``, ``completed``) cannot be
        # cancelled at the endpoint either — Boltz has already
        # broadcast the on-chain HTLC. The endpoint returns 400.
        mock = _mock_swap(status="claimed")
        with (
            patch(
                "app.dashboard.api.boltz_service.get_swap_by_id",
                new_callable=AsyncMock,
                return_value=mock,
            ),
            patch(
                "app.dashboard.api.boltz_service.cancel_swap",
                new_callable=AsyncMock,
                return_value=(False, "Cannot cancel: on-chain claim already in flight"),
            ),
        ):
            resp = await dashboard_client.post(f"/dashboard/api/cold-storage/swaps/{mock.id}/cancel")
        assert resp.status_code == 400


class TestInboundDialogTemplate:
    """Smoke test that the inbound-liquidity dialog renders into the
    dashboard HTML with all four step views and the celebration soft
    link. Catches template syntax errors and accidental deletions
    before they reach a browser.

    These tests assert on the *served HTML body* — they don't
    exercise Alpine reactivity (that would require a browser), but
    they pin that the static template structure is intact."""

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_dashboard_renders_inbound_dialog_block(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.get("/dashboard/")
        assert resp.status_code == 200
        html = resp.text
        # Title + every view's x-show gate must be present.
        assert "Add receive capacity" in html
        assert "inboundStep === 'form'" in html
        assert "inboundStep === 'progress'" in html
        assert "inboundStep === 'success'" in html
        assert "inboundStep === 'failed'" in html

    @pytest.mark.asyncio
    async def test_form_view_has_three_state_fees_status(self, dashboard_client, auth_cookies):
        # Plan + the "loading vs unreachable" split. Verify both
        # the loading copy and the unreachable copy are in the
        # template, gated on the right getters.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        assert "inboundFeesLoading" in html
        assert "Looking up current rates" in html
        assert "Our liquidity service is temporarily unreachable" in html

    @pytest.mark.asyncio
    async def test_progress_view_carries_txid_affordance(self, dashboard_client, auth_cookies):
        # Plan cross-cutting policy: any pending on-chain tx
        # surfaces copy + mempool-explorer affordances. Pin that
        # the inbound progress view follows the policy — both for
        # the claim txid display gate and the affordance handlers.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        assert "inboundShouldShowClaimTxid" in html
        assert "copyText(inboundClaimTxid)" in html
        assert "mempoolTxUrl(inboundClaimTxid)" in html

    @pytest.mark.asyncio
    async def test_success_view_carries_persistent_txid_affordance(self, dashboard_client, auth_cookies):
        # The success view keeps the txid + copy + mempool
        # link visible after completion. Two affordance pairs in the
        # rendered HTML (one progress, one success) confirms both
        # are present.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        # Both views render the same affordance, so the strings
        # appear at least twice.
        assert html.count("copyText(inboundClaimTxid)") >= 2
        assert html.count("mempoolTxUrl(inboundClaimTxid)") >= 2

    @pytest.mark.asyncio
    async def test_receive_lightning_banner_present(self, dashboard_client, auth_cookies):
        # The banner mounts above the amount input inside
        # the Receive-Lightning dialog. The CTA wires through to
        # ``inboundOpenFromBanner``.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        assert "inboundBannerPayload" in html
        assert "inboundOpenFromBanner" in html

    @pytest.mark.asyncio
    async def test_onboarding_celebration_carries_soft_link(self, dashboard_client, auth_cookies):
        # Plan second entry point: a soft link in the onboarding
        # wizard's celebration view. Pin that the text + handler
        # are present so a future refactor of the celebration view
        # doesn't silently drop the link.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        assert "Want to be able to receive payments too" in html
        assert "openInboundCapacity(0)" in html

    @pytest.mark.asyncio
    async def test_fee_preview_gated_on_boltz_reachable(self, dashboard_client, auth_cookies):
        # Anti-flicker: the fee preview block shows "0 sats" math
        # while ``boltzFees`` is still in flight. Pin that the
        # block is gated on ``inboundBoltzReachable`` so it
        # doesn't render zeros during the loading window.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        # The fee preview's "You'll pay" copy and the
        # reachable gate must appear adjacently — the simplest
        # way to assert this without HTML parsing is that the
        # reachable gate appears *before* "You'll pay" in the
        # source. (The x-if attribute precedes the gated div.)
        idx_reachable = html.find('x-if="inboundBoltzReachable"')
        idx_youll_pay = html.find("You'll pay")
        assert idx_reachable != -1, "fee preview must be wrapped in a reachable gate"
        assert idx_youll_pay != -1
        assert idx_reachable < idx_youll_pay, (
            "the reachable gate must precede the You'll-pay copy — "
            "otherwise the fee preview leaks during the loading window"
        )

    @pytest.mark.asyncio
    async def test_progress_view_surfaces_cancel_error(self, dashboard_client, auth_cookies):
        # A failed cancel attempt sets ``inboundError`` while the
        # user is on the progress view. Pin that the progress view
        # actually surfaces that error so the user doesn't see a
        # Cancel button that appears to do nothing.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        # The progress view's block in the dialog. Find the
        # progress x-show declaration and confirm an inboundError
        # template lives between it and the next view's x-show.
        progress_idx = html.find("inboundStep === 'progress'")
        success_idx = html.find("inboundStep === 'success'")
        assert progress_idx != -1 and success_idx != -1
        progress_block = html[progress_idx:success_idx]
        assert 'x-if="inboundError"' in progress_block, (
            "the progress view must render a banner for inboundError so a failed cancel attempt has visible feedback"
        )


class TestConcurrentSwapsIndependent:
    """Initiating two swaps in parallel must not bleed state
    between them. Each ``/cold-storage/swaps/{id}`` lookup is
    scoped by ``swap_id``."""

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_two_swap_lookups_return_distinct_payloads(self, dashboard_client, auth_cookies):
        swap_a = _mock_swap(status="paying_invoice", invoice_amount_sats=100_000)
        swap_b = _mock_swap(status="claimed", claim_txid="b" * 64, invoice_amount_sats=200_000)

        def by_id(_db, swap_id):
            # Mimic the real ``get_swap_by_id``: match on the UUID.
            if str(swap_id) == str(swap_a.id):
                return swap_a
            if str(swap_id) == str(swap_b.id):
                return swap_b
            return None

        with patch(
            "app.dashboard.api.boltz_service.get_swap_by_id",
            new_callable=AsyncMock,
            side_effect=by_id,
        ):
            resp_a = await dashboard_client.get(f"/dashboard/api/cold-storage/swaps/{swap_a.id}")
            resp_b = await dashboard_client.get(f"/dashboard/api/cold-storage/swaps/{swap_b.id}")

        assert resp_a.status_code == 200
        assert resp_b.status_code == 200
        assert resp_a.json()["status"] == "paying_invoice"
        assert resp_a.json()["invoice_amount_sats"] == 100_000
        assert resp_b.json()["status"] == "claimed"
        assert resp_b.json()["invoice_amount_sats"] == 200_000
        assert resp_b.json()["claim_txid"] == "b" * 64
