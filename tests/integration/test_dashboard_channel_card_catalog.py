# SPDX-License-Identifier: MIT
"""Integration coverage for the channel-card catalog enrichment.

Each channel card in the Channels tab consults the small-channel peer
catalog and renders a ⭐ / ⚠️ badge plus an info-icon tooltip when the
peer matches a catalog entry. Unmatched peers render silently (no badge,
no icon, no judgement).

There's no JS test harness in the codebase, so the JS surface is
covered with static checks against ``dashboard.js`` / ``dashboard.html``
and contract tests against ``app/services/small_channel_peers`` (which
is what the JS picker mirrors).
"""

from __future__ import annotations

from pathlib import Path

import pytest

# ``dashboard_client`` is the shared fixture other integration suites use
# to drive the dashboard router with a stubbed DB. Importing it here makes
# it available as a fixture parameter to the render-snapshot tests below.
from .test_dashboard import dashboard_client  # noqa: F401

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DASHBOARD_JS = _REPO_ROOT / "app" / "dashboard" / "static" / "dashboard.js"
_DASHBOARD_HTML = _REPO_ROOT / "app" / "dashboard" / "templates" / "dashboard.html"


@pytest.fixture(scope="module")
def dashboard_js_text() -> str:
    return _DASHBOARD_JS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def dashboard_html_text() -> str:
    return _DASHBOARD_HTML.read_text(encoding="utf-8")


class TestChannelCardJSHelpers:
    """The JS layer exposes a small surface of catalog-aware helpers
    that the template binds to. Each is required for the card
    enrichment to render."""

    def test_channel_peer_catalog_info_present(self, dashboard_js_text: str) -> None:
        # ``channelPeerCatalogInfo(ch)`` is the lookup helper the
        # template uses to gate badge + tooltip rendering.
        assert "channelPeerCatalogInfo(ch)" in dashboard_js_text

    def test_badge_helper_present(self, dashboard_js_text: str) -> None:
        # Returns ``'star'`` | ``'warning'`` | ``''``.
        assert "channelPeerBadge(ch)" in dashboard_js_text

    def test_verified_days_ago_helper_present(self, dashboard_js_text: str) -> None:
        # Drives the "verified N days ago" tooltip line so a long-
        # running deploy with a stale snapshot sees the age inline.
        assert "channelPeerVerifiedDaysAgo(ch)" in dashboard_js_text

    def test_tooltip_state_field_present(self, dashboard_js_text: str) -> None:
        # At most one tooltip is open at a time; this field carries the
        # chan_id (or pending channel_point) of whichever card is open.
        assert "openChannelInfoTooltip" in dashboard_js_text

    def test_tooltip_toggle_and_close_methods_present(self, dashboard_js_text: str) -> None:
        for fn in ("toggleChannelInfo", "closeChannelInfo"):
            assert fn in dashboard_js_text, f"missing tooltip handler: {fn}"

    def test_channels_tab_summary_getters_present(self, dashboard_js_text: str) -> None:
        for getter in (
            "catalogMatchedChannelCount",
            "totalChannelCount",
            "shouldShowCatalogMatchedSummary",
        ):
            assert getter in dashboard_js_text, f"missing getter: {getter}"

    def test_label_helpers_present(self, dashboard_js_text: str) -> None:
        # Tooltip body lines need human-readable labels for fee tier,
        # connectivity tier, and the outbound percentage.
        for fn in (
            "channelPeerFeeTierLabel",
            "channelPeerConnectivityLabel",
            "channelPeerOutboundPct",
        ):
            assert fn in dashboard_js_text, f"missing label helper: {fn}"

    def test_catalog_fetched_on_dashboard_mount(self, dashboard_js_text: str) -> None:
        # The channel cards consult the catalog at every render, so the
        # fetch fires from ``fetchAll()`` (the dashboard's mount-time
        # parallel fetch chain) — independently of the onboarding
        # wizard's own catalog fetch.
        fetch_all_idx = dashboard_js_text.find("async fetchAll()")
        assert fetch_all_idx > 0, "fetchAll() not found"
        # The next ``_ensureSmallChannelPeerCatalog`` after ``fetchAll``'s
        # opening brace should land inside the function body.
        next_call_idx = dashboard_js_text.find(
            "_ensureSmallChannelPeerCatalog", fetch_all_idx,
        )
        assert next_call_idx > 0, "catalog fetch not wired into fetchAll()"
        # And it should land within ~5,000 chars so we know it's in the
        # same function, not somewhere unrelated downstream.
        assert next_call_idx - fetch_all_idx < 5000


class TestChannelCardTemplate:
    """The Channels-tab template binds to the catalog helpers and renders
    the badge, info icon, tooltip body, and summary line."""

    def test_badges_rendered_for_both_kinds(self, dashboard_html_text: str) -> None:
        # ⭐ branch for recommended_default tag.
        assert "channelPeerBadge(ch) === 'star'" in dashboard_html_text
        # ⚠️ branch for marginal_routing caveat.
        assert "channelPeerBadge(ch) === 'warning'" in dashboard_html_text

    def test_info_icon_gated_on_catalog_match(self, dashboard_html_text: str) -> None:
        # Info icon and tooltip render only when ``channelPeerCatalogInfo(ch)``
        # returns a non-null catalog entry. Unmatched peers see no icon.
        assert "channelPeerCatalogInfo(ch)" in dashboard_html_text

    def test_tooltip_body_renders_required_fields(self, dashboard_html_text: str) -> None:
        # Plan calls for: summary, fee tier, outbound ratio, snapshot
        # date. All four must appear in the tooltip template binding.
        # ``alias`` is the title line.
        for binding in (
            ".alias",
            ".summary",
            "channelPeerFeeTierLabel",
            "channelPeerOutboundPct",
            "channelPeerVerifiedDaysAgo",
        ):
            assert binding in dashboard_html_text, f"missing tooltip binding: {binding}"

    def test_tooltip_uses_x_text_not_inner_html(self, dashboard_html_text: str) -> None:
        # CSP-safe rendering: every user-facing string in the tooltip
        # body MUST flow through ``x-text`` (which sets ``textContent``).
        # Catch any accidental ``x-html`` reintroduction.
        assert "x-html=\"channelPeerCatalogInfo" not in dashboard_html_text
        assert "x-html=\"channelPeer" not in dashboard_html_text

    def test_tooltip_closes_on_escape(self, dashboard_html_text: str) -> None:
        # The tooltip block binds Esc to ``closeChannelInfo()``.
        assert "@keydown.escape.window=\"closeChannelInfo()\"" in dashboard_html_text

    def test_tooltip_closes_on_outside_click(self, dashboard_html_text: str) -> None:
        # Outside-click handler is bound; the close fires only when
        # this card's tooltip is the one currently open (so clicking
        # outside another card doesn't close this one). The ownership
        # check lives in a JS getter (``closeChannelInfoIfOwned``)
        # because Alpine's CSP expression parser can't compile an
        # ``if (cond) call()`` statement form inline in a directive.
        assert '@click.outside="closeChannelInfoIfOwned(ch)"' in dashboard_html_text
        assert '@click.outside="closeChannelInfoIfOwned(pc)"' in dashboard_html_text

    def test_no_inline_if_statement_directives(self, dashboard_html_text: str) -> None:
        # Alpine's CSP build accepts expressions, not statements —
        # ``if (...) call()`` inline in a directive trips the parser
        # and shows up at runtime as ``Unexpected token: <call name>``.
        # Sweep every event-handler / x-* directive body and flag any
        # that opens with ``if (``.
        import re

        for match in re.finditer(
            r"(?:@[a-zA-Z.]+|x-[a-z]+)\s*=\s*\"(if\s*\([^\"]*)\"",
            dashboard_html_text,
        ):
            raise AssertionError(
                "inline 'if (...)' directive found — Alpine CSP can't "
                "parse statement forms in directive bodies. Extract "
                "to a JS getter / method instead. Offending fragment: "
                f"{match.group(1)!r}"
            )

    def test_channels_tab_summary_line_present(self, dashboard_html_text: str) -> None:
        # "X of your Y channels are with peers in our vetted catalog."
        assert "shouldShowCatalogMatchedSummary" in dashboard_html_text
        assert "in our vetted catalog" in dashboard_html_text

    def test_pending_channels_get_catalog_treatment_too(self, dashboard_html_text: str) -> None:
        # Plan explicitly asks for pending channels to surface the
        # badge + info icon on a pubkey-only catalog match.
        # ``channelPeerCatalogInfo(pc)`` is the pending-channel surface.
        assert "channelPeerCatalogInfo(pc)" in dashboard_html_text


class TestChannelCardCatalogContract:
    """Server-side equivalents of the JS helpers. Pin the data the
    template will render so a catalog refresh that drops a key field
    can't quietly break the rendered tooltip."""

    def test_babylon_is_recommended_default(self) -> None:
        # The dashboard renders the ⭐ badge for any catalog peer
        # whose tags include ``recommended_default``. Babylon-4a is one
        # of the three bundled ⭐ peers.
        from app.services.small_channel_peers import lookup

        babylon = lookup(
            "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3",
            network="bitcoin",
        )
        assert babylon is not None
        assert "recommended_default" in babylon.tags

    def test_coingate_carries_marginal_routing_caveat(self) -> None:
        # The dashboard renders the ⚠️ badge for any catalog peer with
        # a ``marginal_routing`` caveat. CoinGate is the bundled
        # canonical example.
        from app.services.small_channel_peers import lookup

        coingate = lookup(
            "0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3",
            network="bitcoin",
        )
        assert coingate is not None
        kinds = {c.kind for c in coingate.caveats}
        assert "marginal_routing" in kinds

    def test_tooltip_body_fields_present_for_every_catalog_peer(self) -> None:
        # Every field the tooltip binds to must be populated on every
        # catalog peer so the rendered tooltip never shows a blank row.
        from app.services.small_channel_peers import all_peers

        for peer in all_peers(network="bitcoin"):
            assert peer.alias
            assert peer.summary, f"{peer.alias} missing summary"
            assert peer.fee_tier, f"{peer.alias} missing fee_tier"
            assert peer.connectivity_tier, f"{peer.alias} missing connectivity_tier"
            assert peer.verified_at, f"{peer.alias} missing verified_at"
            # outbound_enabled_ratio CAN be None (when not sampled this
            # snapshot); the JS tooltip just skips that row.

    def test_unmatched_peer_returns_none_silently(self) -> None:
        # Plan: "Catalog miss is silent — no badge, no info icon."
        from app.services.small_channel_peers import lookup

        # A pubkey that decodes correctly but isn't in the catalog.
        result = lookup("02" + "00" * 32, network="bitcoin")
        assert result is None


class TestChannelCardRenderSnapshot:
    """End-to-end render test the plan calls for: a wallet with one
    catalog-matching channel + one unknown-peer channel must surface
    the catalog enrichment on the first and stay silent on the second.

    There's no JS test harness, so this verifies the *server-side*
    halves of the contract:

    * The ``/channels`` endpoint returns both channels in the shape the
      JS picker reads from (``remote_pubkey`` field).
    * The catalog lookup for the matching pubkey returns a peer with
      the badge-driving fields populated, while the unknown pubkey
      returns ``None`` (the silent miss the JS template gates on).

    Together with the ``TestChannelCardJSHelpers`` and
    ``TestChannelCardTemplate`` static checks above, this is the
    closest we can get to a rendered-DOM snapshot without spawning a
    headless browser."""

    @pytest.fixture
    def auth_cookies(self):
        # Local import so the snapshot suite doesn't share fixtures with
        # unrelated suites. The dashboard_client fixture comes from
        # tests/integration/test_dashboard.py via the
        # tests/integration/conftest.py wiring.
        from app.dashboard.auth import COOKIE_NAME

        from .test_dashboard import _make_session_cookie

        return {COOKIE_NAME: _make_session_cookie()}

    @pytest.mark.asyncio
    async def test_channels_endpoint_returns_remote_pubkey_for_catalog_lookup(
        self, dashboard_client, auth_cookies,
    ):
        # The JS picker reads ``ch.remote_pubkey`` (active) and
        # ``ch.remote_node_pub`` (pending) and runs the catalog lookup
        # client-side. Pin that the active channels payload carries
        # ``remote_pubkey`` so the lookup actually has a key to match.
        from unittest.mock import AsyncMock, patch

        from app.dashboard.auth import COOKIE_NAME

        babylon_pub = "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3"
        unknown_pub = "02" + "00" * 32
        mock_channels = [
            {
                "chan_id": "1",
                "remote_pubkey": babylon_pub,
                "active": True,
                "capacity": 200_000,
                "local_balance": 100_000,
                "remote_balance": 100_000,
            },
            {
                "chan_id": "2",
                "remote_pubkey": unknown_pub,
                "active": True,
                "capacity": 200_000,
                "local_balance": 100_000,
                "remote_balance": 100_000,
            },
        ]
        dashboard_client.cookies.set(COOKIE_NAME, auth_cookies[COOKIE_NAME])
        with patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=(mock_channels, None),
        ):
            resp = await dashboard_client.get("/dashboard/api/channels")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 2
        for entry in body:
            assert "remote_pubkey" in entry, "JS picker reads ch.remote_pubkey"

    def test_known_pubkey_matches_catalog_unknown_does_not(self) -> None:
        # The badge + tooltip render logic is gated entirely on the
        # catalog lookup result. Verify the contract end-to-end: a
        # Babylon-4a channel resolves to a catalog peer with the
        # badge-driving fields; an arbitrary unknown pubkey returns
        # ``None`` so the template renders no badge / no tooltip.
        from app.services.small_channel_peers import lookup

        babylon_pub = "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3"
        unknown_pub = "02" + "00" * 32

        babylon = lookup(babylon_pub, network="bitcoin")
        assert babylon is not None
        # Badge + tooltip surface read these fields.
        assert babylon.alias == "Babylon-4a"
        assert "recommended_default" in babylon.tags
        assert babylon.summary
        assert babylon.fee_tier
        assert babylon.connectivity_tier
        assert babylon.verified_at

        unknown = lookup(unknown_pub, network="bitcoin")
        assert unknown is None, "unknown peer must miss the catalog so the card stays silent"


class TestSummaryLineAndDocsLink:
    """The Channels-tab summary line and the channel-card tooltip both
    carry a link back to the catalog's user-facing guide so the user
    can read the underlying methodology + per-peer summaries. Pin both
    surfaces."""

    def test_summary_line_includes_learn_more_link(self, dashboard_html_text: str) -> None:
        # The summary line must include a "(learn more)" anchor per the
        # plan. Find the summary paragraph and verify the link text +
        # href are both present in the nearby markup. Generous buffer
        # accommodates the multi-attribute anchor formatting.
        anchor = dashboard_html_text.find("shouldShowCatalogMatchedSummary")
        assert anchor > 0
        nearby = dashboard_html_text[anchor : anchor + 1500]
        assert "learn more" in nearby
        assert "small-channel-peers" in nearby

    def test_tooltip_includes_read_more_link(self, dashboard_html_text: str) -> None:
        # Each tooltip body (active + pending) carries a "Read more
        # about this peer" link. The plan specifies the link as
        # part of the tooltip body — same docs page as the summary.
        assert "Read more about this peer" in dashboard_html_text
        # The link target matches the summary-line target so they wire
        # up to the same eventual deployment-served HTML.
        # Count: appears once per tooltip body × 2 tooltips (active +
        # pending) = 2 occurrences.
        assert dashboard_html_text.count("Read more about this peer") >= 2
