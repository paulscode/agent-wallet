# SPDX-License-Identifier: MIT
"""Unit tests for :mod:`app.services.small_channel_peers`.

Covers:

* The bundled JSON loads cleanly and every entry has a valid 33-byte
  pubkey (typo guard).
* Network gating — mainnet-only entries don't surface on testnet /
  signet / regtest.
* Each filter/sort helper returns the expected subset shape.
* The recommended-default override env var swaps the ⭐ tag onto the
  operator's picks.
* The overrides-path file can add, replace, and block entries.
* The master kill-switch yields an empty registry.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from app.services import small_channel_peers as scp_module


@pytest.fixture
def reload_module(monkeypatch):
    """Re-import the module after each test that mutates env-driven state
    so the next test sees a clean catalog.

    The settings object in ``app.core.config`` is constructed at import
    time and cached as the ``settings`` symbol that downstream modules
    bind to. To honor a per-test env-var change, the fixture also patches
    the three settings the catalog reads — re-importing config alone
    would create a *new* settings instance, but the module-level reload
    of ``small_channel_peers`` would still re-import its frozen view.
    Patching the attributes on the live instance is simpler and matches
    the contract callers actually rely on.

    Cross-test isolation: at fixture teardown ``monkeypatch`` is still
    active (teardown order is LIFO; monkeypatch was set up first), so
    a naïve ``importlib.reload`` here would re-read the test's patched
    settings and leak a stale catalog into the next test. The teardown
    block explicitly re-pins the three settings to their bundled
    defaults before reloading so the module always comes back to a
    clean state.
    """
    import os

    from app.core import config as config_module

    def _reload():
        # Sync the live settings instance with whatever env vars the test
        # has set via monkeypatch, then re-execute the catalog module.
        monkeypatch.setattr(
            config_module.settings,
            "small_channel_peer_catalog_enabled",
            os.environ.get("SMALL_CHANNEL_PEER_CATALOG_ENABLED", "true").lower() != "false",
            raising=False,
        )
        monkeypatch.setattr(
            config_module.settings,
            "small_channel_peer_overrides_path",
            os.environ.get("SMALL_CHANNEL_PEER_OVERRIDES_PATH", ""),
            raising=False,
        )
        monkeypatch.setattr(
            config_module.settings,
            "small_channel_peer_recommended_defaults",
            os.environ.get("SMALL_CHANNEL_PEER_RECOMMENDED_DEFAULTS", ""),
            raising=False,
        )
        importlib.reload(scp_module)

    yield _reload
    # Explicit cleanup: re-pin settings to bundled defaults before
    # reloading. ``monkeypatch`` will undo this immediately after, but
    # by then the module reload has already happened and the next test
    # inherits a clean catalog.
    monkeypatch.setattr(config_module.settings, "small_channel_peer_catalog_enabled", True, raising=False)
    monkeypatch.setattr(config_module.settings, "small_channel_peer_overrides_path", "", raising=False)
    monkeypatch.setattr(config_module.settings, "small_channel_peer_recommended_defaults", "", raising=False)
    importlib.reload(scp_module)


class TestBundledData:
    def test_loads_without_errors(self) -> None:
        # If the JSON has a malformed pubkey or a missing required key,
        # ``_load_bundled`` raises at import — which means importing the
        # module here would already have failed. The assertion below
        # just pins a positive existence check.
        assert isinstance(scp_module.SMALL_CHANNEL_PEERS, tuple)
        assert len(scp_module.SMALL_CHANNEL_PEERS) >= 1

    def test_every_pubkey_decodes_to_33_bytes(self) -> None:
        for peer in scp_module.SMALL_CHANNEL_PEERS:
            assert len(peer.node_id_hex) == 66, peer.alias
            raw = bytes.fromhex(peer.node_id_hex)
            assert len(raw) == 33, peer.alias

    def test_every_entry_has_an_address(self) -> None:
        for peer in scp_module.SMALL_CHANNEL_PEERS:
            assert peer.address.strip(), f"{peer.alias} has empty address"

    def test_every_entry_is_mainnet(self) -> None:
        for peer in scp_module.SMALL_CHANNEL_PEERS:
            assert peer.network == "bitcoin", peer.alias

    def test_outbound_ratio_is_in_unit_range_or_none(self) -> None:
        for peer in scp_module.SMALL_CHANNEL_PEERS:
            if peer.outbound_enabled_ratio is None:
                continue
            assert 0.0 <= peer.outbound_enabled_ratio <= 1.0, peer.alias

    def test_at_least_one_recommended_default(self) -> None:
        starred = [p for p in scp_module.SMALL_CHANNEL_PEERS if "recommended_default" in p.tags]
        assert starred, "catalog should ship with at least one ⭐ peer"

    def test_snapshot_date_is_iso_yyyy_mm_dd(self) -> None:
        assert len(scp_module.SNAPSHOT_DATE) == 10
        assert scp_module.SNAPSHOT_DATE[4] == "-"
        assert scp_module.SNAPSHOT_DATE[7] == "-"


class TestNetworkGating:
    def test_mainnet_returns_full_catalog(self) -> None:
        peers = scp_module.all_peers(network="bitcoin")
        assert len(peers) == len(scp_module.SMALL_CHANNEL_PEERS)

    def test_testnet_returns_empty(self) -> None:
        assert scp_module.all_peers(network="testnet") == ()

    def test_signet_returns_empty(self) -> None:
        assert scp_module.all_peers(network="signet") == ()

    def test_regtest_returns_empty(self) -> None:
        assert scp_module.all_peers(network="regtest") == ()


class TestHelpers:
    def test_recommended_defaults_returns_starred_only(self) -> None:
        out = scp_module.recommended_defaults(network="bitcoin")
        assert all("recommended_default" in p.tags for p in out)
        # Same set as the property test above, surfaced through the helper.
        assert out

    def test_healthy_routers_filters_below_threshold(self) -> None:
        healthy = scp_module.healthy_routers(network="bitcoin")
        for peer in healthy:
            if peer.outbound_enabled_ratio is None:
                # Unsampled peers are kept (benefit of the doubt).
                continue
            assert peer.outbound_enabled_ratio >= 0.87, peer.alias

    def test_healthy_routers_excludes_known_marginal_peer(self) -> None:
        # CoinGate ships with outbound_enabled_ratio=0.36; helper drops it.
        coingate = scp_module.lookup(
            "0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3",
            network="bitcoin",
        )
        assert coingate is not None
        assert coingate.outbound_enabled_ratio is not None
        assert coingate.outbound_enabled_ratio < 0.87
        healthy = scp_module.healthy_routers(network="bitcoin")
        assert coingate not in healthy

    def test_by_fee_tier_returns_only_that_tier(self) -> None:
        very_low = scp_module.by_fee_tier("very_low", network="bitcoin")
        assert very_low
        for peer in very_low:
            assert peer.fee_tier == "very_low"

    def test_cheapest_n_orders_by_fee_rate_then_base(self) -> None:
        top3 = scp_module.cheapest_n(3, network="bitcoin", min_capacity_btc=2.0)
        assert len(top3) == 3
        # Strictly non-decreasing ppm.
        rates = [p.typical.fee_rate_milli_msat for p in top3]
        assert rates == sorted(rates)

    def test_cheapest_n_respects_min_capacity(self) -> None:
        # Filter out small-capacity peers so we don't over-recommend
        # them — a peer with 0.5 BTC capacity should not pip a larger one.
        top = scp_module.cheapest_n(5, network="bitcoin", min_capacity_btc=10.0)
        for peer in top:
            assert peer.capacity_btc >= 10.0, peer.alias

    def test_cheapest_n_handles_n_larger_than_catalog(self) -> None:
        # Asking for more than the catalog holds returns the whole
        # (filtered) catalog, not an error.
        out = scp_module.cheapest_n(99, network="bitcoin", min_capacity_btc=0.0)
        assert len(out) == len(scp_module.SMALL_CHANNEL_PEERS)

    def test_for_amount_filters_by_open_floor(self) -> None:
        # Every bundled peer's floor is 150k sats — at 100k they're all
        # gated out.
        assert scp_module.for_amount(100_000, network="bitcoin") == ()
        # At 150k they all pass.
        assert len(scp_module.for_amount(150_000, network="bitcoin")) == len(scp_module.SMALL_CHANNEL_PEERS)

    def test_lookup_finds_known_pubkey(self) -> None:
        babylon = scp_module.lookup(
            "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3",
            network="bitcoin",
        )
        assert babylon is not None
        assert babylon.alias == "Babylon-4a"

    def test_lookup_misses_unknown_pubkey(self) -> None:
        result = scp_module.lookup(
            "02" + "00" * 32,
            network="bitcoin",
        )
        assert result is None

    def test_lookup_is_case_insensitive(self) -> None:
        babylon_lower = scp_module.lookup(
            "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3",
            network="bitcoin",
        )
        babylon_upper = scp_module.lookup(
            "0340CFADAA3324E0DD176A9969BE050114278F93260E1B6333BD2A2A2EA03C64A3",
            network="bitcoin",
        )
        assert babylon_lower is babylon_upper


class TestPubkeyValidation:
    def test_short_pubkey_raises(self) -> None:
        with pytest.raises(ValueError, match="66 hex chars"):
            scp_module._decode_peer(
                {
                    "alias": "x",
                    "node_id_hex": "0340cf",  # too short
                    "address": "1.2.3.4:9735",
                    "tor_address": None,
                    "network": "bitcoin",
                    "min_channel_size_sats": 150000,
                    "channels_count": 1,
                    "capacity_btc": 0.01,
                    "top_20_hub_connections": 0,
                    "outbound_enabled_ratio": None,
                    "typical": {
                        "fee_base_msat": 0,
                        "fee_rate_milli_msat": 0,
                        "min_htlc_msat": 1000,
                        "time_lock_delta": 80,
                        "max_htlc_msat": 1000,
                    },
                    "fee_tier": "very_low",
                    "connectivity_tier": "adequate",
                    "location": "",
                    "tags": (),
                    "summary": "",
                    "verified_at": "2026-06-27",
                    "funding_txid": "ff" * 32,
                }
            )

    def test_outbound_ratio_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            scp_module._decode_peer(
                {
                    "alias": "x",
                    "node_id_hex": "02" + "aa" * 32,
                    "address": "1.2.3.4:9735",
                    "tor_address": None,
                    "network": "bitcoin",
                    "min_channel_size_sats": 150000,
                    "channels_count": 1,
                    "capacity_btc": 0.01,
                    "top_20_hub_connections": 0,
                    "outbound_enabled_ratio": 1.7,  # > 1.0
                    "typical": {
                        "fee_base_msat": 0,
                        "fee_rate_milli_msat": 0,
                        "min_htlc_msat": 1000,
                        "time_lock_delta": 80,
                        "max_htlc_msat": 1000,
                    },
                    "fee_tier": "very_low",
                    "connectivity_tier": "adequate",
                    "location": "",
                    "tags": (),
                    "summary": "",
                    "verified_at": "2026-06-27",
                    "funding_txid": "ff" * 32,
                }
            )


class TestRecommendedOverride:
    def test_operator_pick_swaps_the_tag(self, reload_module, monkeypatch) -> None:
        # Pick a non-recommended peer (CoinGate has no ⭐ in the bundled
        # catalog) and assert the override puts the tag on it.
        coingate_pub = "0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3"
        monkeypatch.setenv("SMALL_CHANNEL_PEER_RECOMMENDED_DEFAULTS", coingate_pub)
        reload_module()
        starred = scp_module.recommended_defaults(network="bitcoin")
        starred_pubs = {p.node_id_hex for p in starred}
        assert coingate_pub in starred_pubs
        # The bundled ⭐ peers lose their tag.
        bundled_starred = {
            "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3",  # Babylon
            "02961ed16db648f99ff5aa121a263420911d6b6011794f2a99b79397b5e8b2eed4",  # krut42
            "03e86afe389d298f8f53a2f09fcc4d50cdd34e2fbd8f32cbd55583c596413705c2",  # New Horizons
        }
        assert not (bundled_starred & starred_pubs)

    def test_unknown_pubkey_silently_skipped(self, reload_module, monkeypatch, caplog) -> None:
        unknown_pubkey = "deadbeef" * 8 + "ff" * 2  # 66 hex chars, not in the catalog
        monkeypatch.setenv("SMALL_CHANNEL_PEER_RECOMMENDED_DEFAULTS", unknown_pubkey)
        reload_module()
        # Operator picked an unknown pubkey. The override wipes the
        # bundled ⭐ tags but the unknown pubkey can't be granted one
        # either, so the catalog carries no recommended defaults.
        # ``recommended_defaults`` is the canonical surface for this
        # state and must return an empty tuple.
        assert scp_module.recommended_defaults(network="bitcoin") == ()
        # Sanity: the rest of the catalog is still loaded (the override
        # only affects the ⭐ tag).
        assert len(scp_module.all_peers(network="bitcoin")) == 16


class TestOverridesPath:
    def test_blocks_a_bundled_peer(self, reload_module, monkeypatch, tmp_path) -> None:
        babylon_pub = "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3"
        override_file = tmp_path / "overrides.json"
        override_file.write_text(json.dumps({"peers": [{"node_id_hex": babylon_pub, "blocked": True}]}))
        monkeypatch.setenv("SMALL_CHANNEL_PEER_OVERRIDES_PATH", str(override_file))
        reload_module()
        assert scp_module.lookup(babylon_pub, network="bitcoin") is None

    def test_replaces_a_field_on_a_bundled_peer(self, reload_module, monkeypatch, tmp_path) -> None:
        babylon_pub = "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3"
        override_file = tmp_path / "overrides.json"
        override_file.write_text(
            json.dumps(
                {
                    "peers": [
                        {
                            "node_id_hex": babylon_pub,
                            "summary": "Operator-supplied summary override.",
                        }
                    ]
                }
            )
        )
        monkeypatch.setenv("SMALL_CHANNEL_PEER_OVERRIDES_PATH", str(override_file))
        reload_module()
        babylon = scp_module.lookup(babylon_pub, network="bitcoin")
        assert babylon is not None
        assert babylon.summary == "Operator-supplied summary override."
        # Other fields stay bundled.
        assert babylon.alias == "Babylon-4a"
        assert babylon.channels_count == 284

    def test_appends_a_new_peer(self, reload_module, monkeypatch, tmp_path) -> None:
        new_pub = "02" + "aa" * 32
        override_file = tmp_path / "overrides.json"
        override_file.write_text(
            json.dumps(
                {
                    "peers": [
                        {
                            "alias": "Operator Test Peer",
                            "node_id_hex": new_pub,
                            "address": "10.0.0.1:9735",
                            "tor_address": None,
                            "network": "bitcoin",
                            "min_channel_size_sats": 100000,
                            "channels_count": 5,
                            "capacity_btc": 0.5,
                            "top_20_hub_connections": 1,
                            "outbound_enabled_ratio": 1.0,
                            "typical": {
                                "fee_base_msat": 0,
                                "fee_rate_milli_msat": 100,
                                "min_htlc_msat": 1000,
                                "time_lock_delta": 80,
                                "max_htlc_msat": 1000000000,
                            },
                            "fee_tier": "low",
                            "connectivity_tier": "limited",
                            "location": "Operator infrastructure",
                            "tags": [],
                            "summary": "Custom peer added by the operator.",
                            "verified_at": "2026-06-27",
                            "funding_txid": "ff" * 32,
                        }
                    ]
                }
            )
        )
        monkeypatch.setenv("SMALL_CHANNEL_PEER_OVERRIDES_PATH", str(override_file))
        reload_module()
        peer = scp_module.lookup(new_pub, network="bitcoin")
        assert peer is not None
        assert peer.alias == "Operator Test Peer"

    def test_bad_json_falls_back_to_bundled(self, reload_module, monkeypatch, tmp_path) -> None:
        override_file = tmp_path / "overrides.json"
        override_file.write_text("{this is not valid json}")
        monkeypatch.setenv("SMALL_CHANNEL_PEER_OVERRIDES_PATH", str(override_file))
        reload_module()
        # Bundled catalog is intact.
        assert scp_module.all_peers(network="bitcoin")

    def test_missing_overrides_file_falls_back_to_bundled(self, reload_module, monkeypatch) -> None:
        monkeypatch.setenv("SMALL_CHANNEL_PEER_OVERRIDES_PATH", "/nonexistent/path/overrides.json")
        reload_module()
        assert scp_module.all_peers(network="bitcoin")


class TestFeatureFlag:
    def test_disabled_yields_empty_registry(self, reload_module, monkeypatch) -> None:
        monkeypatch.setenv("SMALL_CHANNEL_PEER_CATALOG_ENABLED", "false")
        reload_module()
        assert scp_module.SMALL_CHANNEL_PEERS == ()
        assert scp_module.all_peers(network="bitcoin") == ()
        # Snapshot date still surfaces so downstream callers have a
        # defined value (we read the bundled date during the disabled
        # initialise pass).
        assert scp_module.SNAPSHOT_DATE
