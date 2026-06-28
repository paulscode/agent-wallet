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


# ─── Picker surface ──────────────────────────────────────────────────
#
# The wizard's peer picker reads from the small-channel peer catalog
# served at ``/dashboard/api/peer-catalog/small-channel``. There's no
# JS test harness in this codebase, so the verification is split into
# two layers:
#
# * **Static checks** against the JS / template / model sources confirm
#   the hardcoded peer constants are gone and the catalog-driven
#   bindings are present.
# * **Catalog-shape contract** confirms the bundled JSON populates every
#   field the dashboard JS reads off each peer.


import re as _re  # noqa: E402 — module-level imports stay above the class
from pathlib import Path as _Path  # noqa: E402

_REPO_ROOT = _Path(__file__).resolve().parents[2]
_DASHBOARD_JS_PATH = _REPO_ROOT / "app" / "dashboard" / "static" / "dashboard.js"
_DASHBOARD_HTML_PATH = _REPO_ROOT / "app" / "dashboard" / "templates" / "dashboard.html"
_BRAIINS_MODEL_PATH = _REPO_ROOT / "app" / "models" / "braiins_deposit_session.py"


@pytest.fixture(scope="module")
def dashboard_js_text() -> str:
    return _DASHBOARD_JS_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def dashboard_html_text() -> str:
    return _DASHBOARD_HTML_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def braiins_model_text() -> str:
    return _BRAIINS_MODEL_PATH.read_text(encoding="utf-8")


class TestPickerJSSurface:
    """The wizard's picker reads from a fetched catalog rather than a
    hardcoded peer constant."""

    def test_hardcoded_peer_constant_is_absent(self, dashboard_js_text: str) -> None:
        assert "MEGALITHIC_NODES" not in dashboard_js_text

    def test_picker_state_fields_present(self, dashboard_js_text: str) -> None:
        for field in (
            "onboardingPeerChoiceMode",
            "onboardingPickedPubkey",
            "onboardingPickFromListSort",
            "smallChannelPeerCatalog",
            "smallChannelPeerCatalogLoadState",
        ):
            assert field in dashboard_js_text, f"missing field: {field}"

    def test_picker_helper_methods_present(self, dashboard_js_text: str) -> None:
        for fn in (
            "_peersAcceptingAmount",
            "_lookupCatalogPeer",
            "_recommendedPeerForAmount",
            "_ensureSmallChannelPeerCatalog",
            "onboardingRetryCatalog",
            "onboardingPickCatalogPeer",
        ):
            assert fn in dashboard_js_text, f"missing helper: {fn}"

    def test_picker_getters_present(self, dashboard_js_text: str) -> None:
        for getter in (
            "onboardingRecommendedPeer",
            "onboardingFilteredPeers",
            "onboardingPeerStats",
            "onboardingCatalogAvailable",
            "onboardingCustomModeOnly",
            "onboardingCatalogSnapshotDate",
            "onboardingAmountTooSmallReason",
        ):
            assert getter in dashboard_js_text, f"missing getter: {getter}"

    def test_catalog_fetch_uses_dashboard_endpoint(self, dashboard_js_text: str) -> None:
        # The catalog comes through the session-authed wrapper so the
        # dashboard SPA doesn't need an API key. The ``this.api(...)``
        # helper auto-prepends ``/dashboard/api`` to every path it sends,
        # so the catalog fetch must pass the BARE endpoint path —
        # passing the full ``/dashboard/api/...`` string would
        # double-prefix to ``/dashboard/api/dashboard/api/...`` and
        # produce a 404.
        assert "this.api('GET', '/peer-catalog/small-channel')" in dashboard_js_text
        # Guard the same shape across every ``this.api(...)`` call so a
        # different consumer can't introduce the double-prefix bug
        # under cover of the api-helper's already-prepended root.
        import re

        for match in re.finditer(
            r"this\.api\(\s*['\"](?:GET|POST|PUT|PATCH|DELETE)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            dashboard_js_text,
        ):
            path = match.group(1)
            assert not path.startswith("/dashboard/api"), (
                f"double-prefixed api() path detected: {path!r} — the "
                "api() helper auto-prepends /dashboard/api, so callers "
                "must pass the bare endpoint path (e.g. '/foo' not "
                "'/dashboard/api/foo')."
            )

    def test_catalog_retry_backoffs_defined(self, dashboard_js_text: str) -> None:
        # The "couldn't load catalog" UX needs a retry budget. The
        # constant naming is a contract the JS helpers reference.
        assert "CATALOG_FETCH_RETRY_BACKOFFS_MS" in dashboard_js_text


class TestPickerHTMLTemplate:
    """Template binds the picker state fields and exposes all three
    modes (recommended / pick-from-list / custom)."""

    def test_three_picker_modes_rendered(self, dashboard_html_text: str) -> None:
        # Each mode binds the ``onboardingPeerChoiceMode`` field to one
        # of the three values.
        for value in ("recommended_default", "pick_from_list", "custom"):
            assert f'value="{value}"' in dashboard_html_text, f"missing radio for: {value}"

    def test_pick_from_list_table_uses_catalog_data(self, dashboard_html_text: str) -> None:
        # Catalog table iterates onboardingFilteredPeers and pulls each
        # peer's identifying fields out.
        assert "onboardingFilteredPeers" in dashboard_html_text
        assert "onboardingPickCatalogPeer" in dashboard_html_text

    def test_catalog_fetch_failed_footer_present(self, dashboard_html_text: str) -> None:
        # The "couldn't load peer catalog" footer + retry affordance.
        assert "smallChannelPeerCatalogLoadState === 'failed'" in dashboard_html_text
        assert "onboardingRetryCatalog" in dashboard_html_text

    def test_amount_too_small_reason_rendered(self, dashboard_html_text: str) -> None:
        assert "onboardingAmountTooSmallReason" in dashboard_html_text


class TestUserFacingCopyUsesCatalogNeutralLanguage:
    """Every user-facing surface — the glossary, the Braiins channel-open
    advisory, the wizard copy — describes the chosen peer in
    catalog-neutral language. Code-comments and other non-user-facing
    surfaces are out of scope here."""

    def test_glossary_open_a_channel_uses_neutral_copy(self, dashboard_js_text: str) -> None:
        # Find the glossary entry and verify the body doesn't surface
        # "Megalithic" by name.
        m = _re.search(r"'open-a-channel':\s*{[^}]*?body:\s*'([^']*?)'", dashboard_js_text, _re.DOTALL)
        assert m, "glossary 'open-a-channel' entry not found"
        body = m.group(1)
        assert "Megalithic" not in body, body

    def test_braiins_channel_open_advisory_uses_neutral_copy(self, dashboard_html_text: str) -> None:
        # The "If a swap can't be routed to your node..." paragraph in
        # the Braiins deposit wizard.
        assert "to Megalithic" not in dashboard_html_text
        # Sanity: the replacement copy is present.
        assert "recommended routing peer" in dashboard_html_text

    def test_braiins_deposit_session_docstrings_use_neutral_copy(self, braiins_model_text: str) -> None:
        # Docstrings + column comments referenced "Megalithic" by name —
        # generalised to "the recommended routing peer."
        assert "Megalithic" not in braiins_model_text


class TestCatalogShapeMatchesJSPickerExpectations:
    """The JS picker reads specific fields off each peer. Pin that the
    bundled catalog populates every one of those fields for every peer
    so a future catalog refresh can't quietly break the picker."""

    def test_every_field_the_js_picker_reads_is_populated(self) -> None:
        from app.services.small_channel_peers import all_peers

        peers = all_peers(network="bitcoin")
        assert peers, "bundled catalog should ship with peers for mainnet"
        for peer in peers:
            assert peer.alias
            assert peer.node_id_hex
            assert peer.address
            assert peer.min_channel_size_sats > 0
            assert peer.typical.fee_base_msat >= 0
            assert peer.typical.fee_rate_milli_msat >= 0
            assert peer.channels_count > 0
            assert peer.capacity_btc > 0
            # ``location`` may be empty for one bundled entry; JS
            # handles "" fine via ``peer.location || ''``.
            assert isinstance(peer.location, str)
            # ``tags`` is a tuple of strings; the picker checks
            # ``(peer.tags || []).indexOf('recommended_default') !== -1``.
            assert isinstance(peer.tags, tuple)


class TestPeersAcceptingAmountContract:
    """Server-side equivalents of the JS picker's
    ``_peersAcceptingAmount(sats)``. Pin the behavior at the contract
    boundary the JS reads from so a catalog refresh that bumps a peer's
    ``min_channel_size_sats`` can't silently break the wizard's filter."""

    def test_150k_sat_amount_returns_full_catalog(self) -> None:
        # Every bundled peer's floor is 150k sats — at exactly that
        # amount, every catalog peer must be eligible. The JS picker
        # pivots on this: the "Pick from list" mode renders one row per
        # eligible peer.
        from app.services.small_channel_peers import all_peers, for_amount

        peers = for_amount(150_000, network="bitcoin")
        assert len(peers) == len(all_peers(network="bitcoin"))

    def test_below_smallest_floor_returns_empty(self) -> None:
        # 100k sats is below every bundled peer's floor — the picker
        # must surface the "amount too small" reason rather than an
        # empty default.
        from app.services.small_channel_peers import for_amount

        peers = for_amount(100_000, network="bitcoin")
        assert peers == ()

    def test_non_mainnet_returns_empty_regardless_of_amount(self) -> None:
        # ``_peersAcceptingAmount`` short-circuits to ``[]`` when the
        # catalog is empty for the current network. The JS picker
        # branches on this to render the custom-only mode.
        from app.services.small_channel_peers import for_amount

        for network in ("regtest", "testnet", "signet"):
            assert for_amount(150_000, network=network) == ()


class TestRecommendedSelectionExcludesMarginalRouting:
    """Marginal-routing peers (``caveats: [{kind: 'marginal_routing'}]``)
    must NOT be auto-picked by the Recommended mode. They stay visible
    in Pick-from-list (rendered with a ⚠️ badge), but a fresh wallet
    shouldn't auto-route into a peer whose own gossip says they refuse
    to forward."""

    def test_coingate_is_in_the_catalog(self) -> None:
        from app.services.small_channel_peers import lookup

        coingate = lookup(
            "0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3",
            network="bitcoin",
        )
        assert coingate is not None
        # Sanity: the marginal-routing caveat is present.
        kinds = {c.kind for c in coingate.caveats}
        assert "marginal_routing" in kinds

    def test_recommended_picker_logic_skips_marginal_routing(self) -> None:
        # Mirrors the JS ``_recommendedPeerForAmount`` filter chain:
        # filter accepting peers by NOT marginal_routing, then rank by
        # ⭐ tag, then by ppm + base. The ⭐ peers (Babylon, krut42,
        # New Horizons) are all non-marginal, so the recommended at
        # 150k sats is krut42 (cheapest ppm = 0).
        from app.services.small_channel_peers import for_amount

        accepting = for_amount(150_000, network="bitcoin")
        # Apply the marginal-routing filter.
        filtered = tuple(
            p for p in accepting
            if not any(c.kind == "marginal_routing" for c in p.caveats)
        )
        assert filtered, "filter shouldn't drop every peer"
        # CoinGate is the only marginal_routing peer in the bundled
        # catalog; the filter must drop exactly that one.
        coingate_pub = "0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3"
        assert coingate_pub not in {p.node_id_hex for p in filtered}
        # Recommended-default tag is the next pivot.
        starred = tuple(p for p in filtered if "recommended_default" in p.tags)
        assert starred, "expected ⭐ peers to remain after the marginal-routing filter"


class TestPickerJSCustomOnlyExplanation:
    """The JS picker collapses to custom-only mode in three scenarios.
    The non-failure scenarios get explanatory copy via
    ``onboardingCustomOnlyExplanation``; the failure scenario gets its
    own retry footer. Pin the JS branches via static checks since
    there's no JS test harness."""

    def test_custom_only_explanation_getter_exists(self) -> None:
        # The getter is what the template binds to.
        from pathlib import Path

        text = (
            Path(__file__).resolve().parents[2]
            / "app" / "dashboard" / "static" / "dashboard.js"
        ).read_text(encoding="utf-8")
        assert "onboardingCustomOnlyExplanation" in text

    def test_explanation_distinguishes_non_mainnet_from_killswitch(self) -> None:
        from pathlib import Path

        text = (
            Path(__file__).resolve().parents[2]
            / "app" / "dashboard" / "static" / "dashboard.js"
        ).read_text(encoding="utf-8")
        # Non-mainnet branch surfaces a "mainnet-only" message.
        assert "mainnet-only" in text
        # Kill-switch branch surfaces a "turned off" message.
        assert "turned off" in text

    def test_failed_state_has_retry_button_not_explanation(self) -> None:
        # The retry footer renders only when load state is 'failed'; the
        # explanation getter explicitly returns '' for that state so the
        # two surfaces don't compete.
        from pathlib import Path

        text = (
            Path(__file__).resolve().parents[2]
            / "app" / "dashboard" / "static" / "dashboard.js"
        ).read_text(encoding="utf-8")
        assert "onboardingRetryCatalog" in text
        # The failed-state branch returns '' so the template's
        # ``x-if="onboardingCustomOnlyExplanation"`` skips rendering
        # when the retry footer is already showing.
        assert "if (this.smallChannelPeerCatalogLoadState === 'failed') return ''" in text


class TestCatalogFetchRetryBudget:
    """The catalog fetch retries with a 500 ms / 2 s / 5 s backoff
    budget. After the final attempt, the load state flips to ``failed``
    and the picker collapses to custom-only with a retry affordance —
    the open-the-channel button stays enabled because the custom mode
    is still available."""

    def test_retry_backoffs_use_planned_schedule(self) -> None:
        from pathlib import Path

        text = (
            Path(__file__).resolve().parents[2]
            / "app" / "dashboard" / "static" / "dashboard.js"
        ).read_text(encoding="utf-8")
        # Constant declares the three planned backoffs in ms.
        # Together with the immediate first attempt the total wall-
        # clock window before final failure is ~10 s.
        assert "CATALOG_FETCH_RETRY_BACKOFFS_MS = [500, 2000, 5000]" in text

    def test_failed_state_does_not_disable_custom_mode_open_button(self) -> None:
        # ``onboardingCanOpen`` reads ``onboardingPeerChoiceMode`` and
        # the custom URI — neither depends on the catalog state, so a
        # failed fetch can't strand the user. Pin the JS branch.
        from pathlib import Path

        text = (
            Path(__file__).resolve().parents[2]
            / "app" / "dashboard" / "static" / "dashboard.js"
        ).read_text(encoding="utf-8")
        # Custom mode's open-readiness checks the parsed pubkey/URI,
        # not the catalog load state.
        assert "_parsePubkeyOrUri(this.onboardingCustomUri)" in text
