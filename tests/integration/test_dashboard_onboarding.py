# SPDX-License-Identifier: MIT
"""Contract tests for the dashboard onboarding wizard.

The wizard's state machine (``onboardingStep`` in
``app/dashboard/static/dashboard.js``) keys off five fields nested
under ``summary.totals``:

* ``num_active_channels``
* ``num_pending_channels``
* ``onchain_sats``
* ``unconfirmed_sats``
* ``lightning_local_sats``

These are produced by ``lnd_service.get_wallet_summary`` and returned
verbatim from ``/dashboard/api/summary``. If any of these keys ever
gets renamed or moved, the wizard silently falls through to the
``welcome`` step on every refresh — even for users with millions of
sats — because the getter sees zeros for everything.

The pure-unit parity test (``tests/unit/test_onboarding_step.py``)
covers the JS logic. This integration test pins the *contract*: a
well-formed mock summary must round-trip through the live FastAPI
router with all five keys still present and named correctly.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.dashboard.auth import COOKIE_NAME

from .test_dashboard import _make_session_cookie, _set_dashboard_token, dashboard_client  # noqa: F401

# Canonical totals shape used by the wizard. The exact field names
# here ARE the contract — bumping any of these requires also updating
# the JS getter at ``app/dashboard/static/dashboard.js`` and the
# parity test at ``tests/unit/test_onboarding_step.py``.
_REQUIRED_TOTAL_FIELDS = (
    "num_active_channels",
    "num_pending_channels",
    "onchain_sats",
    "unconfirmed_sats",
    "lightning_local_sats",
)


def _mock_summary_payload(**totals_overrides: int) -> dict:
    """Build a get_wallet_summary() return value with sensible defaults."""
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


class TestOnboardingSummaryContract:
    """Pin the shape /dashboard/api/summary returns for the wizard."""

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_summary_response_contains_all_wizard_keys(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_wallet_summary",
            new_callable=AsyncMock,
            return_value=(_mock_summary_payload(), None),
        ):
            resp = await dashboard_client.get("/dashboard/api/summary")
        assert resp.status_code == 200
        body = resp.json()
        assert "totals" in body, "wizard requires summary.totals"
        for field in _REQUIRED_TOTAL_FIELDS:
            assert field in body["totals"], (
                f"summary.totals.{field} missing — onboarding wizard "
                "will misroute every user. Update the JS getter "
                "(``onboardingStep``) in lockstep if you rename this."
            )

    @pytest.mark.asyncio
    async def test_empty_wallet_payload_has_only_zero_totals(self, dashboard_client, auth_cookies):
        """An empty wallet must produce zeros for every wizard key.
        This is what triggers the ``welcome`` step on the client side."""
        with patch(
            "app.dashboard.api.lnd_service.get_wallet_summary",
            new_callable=AsyncMock,
            return_value=(_mock_summary_payload(), None),
        ):
            resp = await dashboard_client.get("/dashboard/api/summary")
        totals = resp.json()["totals"]
        for field in _REQUIRED_TOTAL_FIELDS:
            assert totals[field] == 0, f"empty wallet leaked non-zero {field}"

    @pytest.mark.asyncio
    async def test_funded_payload_surfaces_onchain_balance(self, dashboard_client, auth_cookies):
        """200,000 confirmed sats must appear at ``totals.onchain_sats``."""
        with patch(
            "app.dashboard.api.lnd_service.get_wallet_summary",
            new_callable=AsyncMock,
            return_value=(_mock_summary_payload(onchain_sats=200_000), None),
        ):
            resp = await dashboard_client.get("/dashboard/api/summary")
        assert resp.json()["totals"]["onchain_sats"] == 200_000

    @pytest.mark.asyncio
    async def test_pending_channel_payload_surfaces_num_pending(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_wallet_summary",
            new_callable=AsyncMock,
            return_value=(_mock_summary_payload(num_pending_channels=1, onchain_sats=10_000), None),
        ):
            resp = await dashboard_client.get("/dashboard/api/summary")
        assert resp.json()["totals"]["num_pending_channels"] == 1

    @pytest.mark.asyncio
    async def test_unconfirmed_deposit_surfaces_unconfirmed_sats(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_wallet_summary",
            new_callable=AsyncMock,
            return_value=(_mock_summary_payload(unconfirmed_sats=42_000), None),
        ):
            resp = await dashboard_client.get("/dashboard/api/summary")
        assert resp.json()["totals"]["unconfirmed_sats"] == 42_000


class TestPendingChannelsShape:
    """Pin the shape /dashboard/api/channels/pending returns.

    The wizard's ``connecting`` step extracts the funding txid, peer
    pubkey, and capacity from this payload. A regression that
    re-groups the response into a dict (e.g. ``{pending_open: [...]}``)
    would silently break the wizard — the step would render with
    blank fields and no mempool-explorer link.
    """

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_pending_channels_is_flat_list(self, dashboard_client, auth_cookies):
        mock_payload = [
            {
                "type": "pending_open",
                "remote_node_pub": "0322d0e4" + "0" * 58,
                "channel_point": "abc123:0",
                "capacity": 200_000,
                "local_balance": 200_000,
                "remote_balance": 0,
                "commit_fee": 1_000,
                "confirmation_height": 0,
            }
        ]
        with patch(
            "app.dashboard.api.lnd_service.get_pending_channels_detail",
            new_callable=AsyncMock,
            return_value=(mock_payload, None),
        ):
            resp = await dashboard_client.get("/dashboard/api/channels/pending")
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list), (
            "wizard expects a flat list — re-grouping into a dict will "
            "break onboardingPendingChannel (it scans for type === "
            "'pending_open')"
        )
        assert len(body) == 1
        entry = body[0]
        # These are the four fields the connecting step reads:
        for field in ("type", "remote_node_pub", "channel_point", "capacity"):
            assert field in entry, (
                f"channel_point detail missing {field!r} — wizard's connecting step will render with blank values."
            )
        assert entry["type"] == "pending_open"
        # channel_point format must be "txid:vout" — the wizard splits
        # on `:` to derive the funding txid for the mempool link.
        assert ":" in entry["channel_point"]

    @pytest.mark.asyncio
    async def test_empty_pending_channels_returns_empty_list(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.lnd_service.get_pending_channels_detail",
            new_callable=AsyncMock,
            return_value=([], None),
        ):
            resp = await dashboard_client.get("/dashboard/api/channels/pending")
        assert resp.json() == []


class TestTransactionsShape:
    """Pin the shape /dashboard/api/transactions returns.

    The wizard reads four fields per entry:

    * ``tx_hash`` — joined against ``channel_point`` to find the
      channel-funding tx and read its ``num_confirmations``.
    * ``amount`` — gates the awaiting_deposit list (positive only).
    * ``num_confirmations`` — drives the awaiting_deposit "is this
      still in the mempool?" filter AND the connecting step's
      progress bar.
    * ``time_stamp`` — sorts the awaiting_deposit list newest-first.

    Renaming any of these silently breaks the wizard.
    """

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_transactions_response_carries_wizard_keys(self, dashboard_client, auth_cookies):
        sample = [
            {
                "tx_hash": "deadbeef" * 8,
                "amount": 250_000,
                "num_confirmations": 0,
                "block_height": 0,
                "time_stamp": 1_700_000_000,
                "total_fees": 0,
                "label": "",
            }
        ]
        with patch(
            "app.dashboard.api.lnd_service.get_onchain_transactions",
            new_callable=AsyncMock,
            return_value=(sample, None),
        ):
            resp = await dashboard_client.get("/dashboard/api/transactions")
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)
        assert len(body) == 1
        entry = body[0]
        for field in ("tx_hash", "amount", "num_confirmations", "time_stamp"):
            assert field in entry, (
                f"transactions response missing {field!r} — wizard's "
                "awaiting_deposit / connecting views will misroute or "
                "crash. Update the JS getters in lockstep if you "
                "rename this field."
            )

    @pytest.mark.asyncio
    async def test_transactions_sorted_newest_first(self, dashboard_client, auth_cookies):
        # The endpoint sorts by ``time_stamp`` descending. Wizard's
        # ``onboardingDepositTxs`` re-sorts client-side defensively
        # too, but the contract here is the server's behaviour.
        sample = [
            {"tx_hash": "old", "amount": 100, "num_confirmations": 0, "time_stamp": 1},
            {"tx_hash": "new", "amount": 200, "num_confirmations": 0, "time_stamp": 100},
            {"tx_hash": "mid", "amount": 150, "num_confirmations": 0, "time_stamp": 50},
        ]
        with patch(
            "app.dashboard.api.lnd_service.get_onchain_transactions",
            new_callable=AsyncMock,
            return_value=(sample, None),
        ):
            resp = await dashboard_client.get("/dashboard/api/transactions")
        order = [t["tx_hash"] for t in resp.json()]
        assert order == ["new", "mid", "old"]
