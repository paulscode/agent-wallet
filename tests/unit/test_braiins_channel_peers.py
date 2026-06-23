# SPDX-License-Identifier: MIT
"""Unit tests for app.services.braiins_channel_peers — channel-open peer
presets, amount-driven selection, and capacity sizing.
"""

from pathlib import Path

from app.core.config import settings
from app.services import braiins_channel_peers as peers

_REPO = Path(__file__).resolve().parents[2]
_DASHBOARD_JS = _REPO / "app" / "dashboard" / "static" / "dashboard.js"


class TestPeerSelection:
    def test_prefers_proper_for_large_amounts(self):
        # capacity ≥ proper_min (1,000,000) → main
        p = peers.select_peer_for_capacity(2_000_000)
        assert p is not None and p.key == "main"

    def test_small_node_for_mid_amounts(self):
        # small_min (150,000) ≤ capacity < proper_min → small
        p = peers.select_peer_for_capacity(200_000)
        assert p is not None and p.key == "small"

    def test_at_proper_min_exactly_uses_proper(self):
        p = peers.select_peer_for_capacity(1_000_000)
        assert p is not None and p.key == "main"

    def test_below_small_min_is_ineligible(self):
        assert peers.select_peer_for_capacity(149_999) is None
        assert peers.select_peer_for_capacity(50_000) is None

    def test_smallest_peer_is_the_floor(self):
        sp = peers.smallest_peer()
        assert sp is not None and sp.key == "small"
        assert sp.min_sats == 150_000

    def test_smallest_peer_none_when_unconfigured(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_peer_pubkey", "")
        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_peer_small_pubkey", "")
        assert peers.smallest_peer() is None

    def test_respects_per_peer_max(self, monkeypatch):
        # Cap the proper node so a huge amount falls through to ineligible
        # (small has no overlap above its own — also capped here).
        monkeypatch.setattr(
            "app.core.config.settings.braiins_deposit_channel_peer_max_sats",
            5_000_000,
        )
        monkeypatch.setattr(
            "app.core.config.settings.braiins_deposit_channel_peer_small_max_sats",
            900_000,
        )
        assert peers.select_peer_for_capacity(10_000_000) is None

    def test_no_peers_configured_is_ineligible(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_peer_pubkey", "")
        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_peer_small_pubkey", "")
        assert peers.peer_presets() == []
        assert peers.select_peer_for_capacity(2_000_000) is None


class TestCapacitySizing:
    def test_capacity_covers_invoice_after_reserve_and_safety(self):
        invoice = 1_000_000
        cap = peers.size_channel_capacity(invoice)
        # Usable outbound (capacity - reserve - safety) must cover the
        # invoice amount.
        usable = cap - int(cap * peers.RESERVE_PCT) - int(cap * peers.SAFETY_PCT)
        assert usable >= invoice
        # And it's a modest premium, not wildly oversized (< 5%).
        assert cap < invoice * 1.05

    def test_headroom_applied(self, monkeypatch):
        monkeypatch.setattr(
            "app.core.config.settings.braiins_deposit_channel_capacity_headroom_pct",
            0.0,
        )
        cap0 = peers.size_channel_capacity(1_000_000)
        monkeypatch.setattr(
            "app.core.config.settings.braiins_deposit_channel_capacity_headroom_pct",
            0.05,
        )
        cap5 = peers.size_channel_capacity(1_000_000)
        assert cap5 > cap0


class TestSingleSourceOfTruth:
    """The backend presets MUST match the frontend MEGALITHIC_NODES so
    the two copies can't drift (D2)."""

    def test_backend_presets_match_dashboard_js(self):
        js = _DASHBOARD_JS.read_text(encoding="utf-8")
        # Both pubkeys + mins from config must appear verbatim in the JS.
        assert settings.braiins_deposit_channel_peer_pubkey in js, (
            "main pubkey missing from dashboard.js MEGALITHIC_NODES"
        )
        assert settings.braiins_deposit_channel_peer_small_pubkey in js, (
            "small pubkey missing from dashboard.js MEGALITHIC_NODES"
        )
        assert "minSats: 1000000" in js or "minSats: 1_000_000" in js
        assert "minSats:   150000" in js or "minSats: 150000" in js or "minSats: 150_000" in js
        # Hosts too.
        assert settings.braiins_deposit_channel_peer_host in js
        assert settings.braiins_deposit_channel_peer_small_host in js
