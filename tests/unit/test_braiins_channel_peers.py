# SPDX-License-Identifier: MIT
"""Unit tests for app.services.braiins_channel_peers — channel-open peer
presets, amount-driven selection, and capacity sizing.
"""

from app.services import braiins_channel_peers as peers


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




class TestChannelOpenCandidates:
    """Ordered channel-open candidates: large band → proper node only;
    small band → cheapest catalog peers first, then the small preset."""

    def test_large_band_uses_proper_node_only(self):
        cands = peers.channel_open_candidates(1_500_000, network="bitcoin")
        assert [c.key for c in cands] == ["main"]
        assert "main node" in cands[0].label

    def test_small_band_catalog_cheapest_first_then_preset_fallback(self):
        from app.services import small_channel_peers as catalog

        cands = peers.channel_open_candidates(210_000, network="bitcoin")
        # All but the last are catalog peers; the last is the small preset.
        assert len(cands) >= 2
        assert all(c.key == "catalog" for c in cands[:-1])
        assert cands[-1].key == "small"

        all_cat = catalog.all_peers(network="bitcoin")
        # Marginal-routing peers are excluded from the auto-fallback list.
        marginal = {
            p.node_id_hex.lower()
            for p in all_cat
            if any(cav.kind == "marginal_routing" for cav in p.caveats)
        }
        assert marginal.isdisjoint({c.pubkey.lower() for c in cands})

        # Catalog candidates are ordered by (ppm, base fee) ascending.
        lut = {p.node_id_hex.lower(): p for p in all_cat}
        fees = [
            (lut[c.pubkey.lower()].typical.fee_rate_milli_msat, lut[c.pubkey.lower()].typical.fee_base_msat)
            for c in cands
            if c.key == "catalog"
        ]
        assert fees == sorted(fees)

    def test_small_band_falls_back_to_preset_when_catalog_disabled(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.small_channel_peer_catalog_enabled", False)
        cands = peers.channel_open_candidates(210_000, network="bitcoin")
        assert [c.key for c in cands] == ["small"]

    def test_non_mainnet_has_no_catalog_uses_preset_only(self):
        cands = peers.channel_open_candidates(210_000, network="testnet")
        assert [c.key for c in cands] == ["small"]

    def test_empty_when_nothing_configured_and_catalog_off(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.small_channel_peer_catalog_enabled", False)
        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_peer_pubkey", "")
        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_peer_small_pubkey", "")
        assert peers.channel_open_candidates(210_000, network="bitcoin") == []
