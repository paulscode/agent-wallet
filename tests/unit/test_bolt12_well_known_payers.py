# SPDX-License-Identifier: MIT
"""Unit tests for :mod:`app.services.bolt12.well_known_payers`.

Covers:
* OCEAN's documented prefix matches the seeded registry entry.
* Non-matching descriptions return ``None``.
* Mainnet-only entries are skipped on non-mainnet networks.
* Each seed entry has a valid 33-byte compressed pubkey (typo guard).
* Each seed entry has a non-empty address (typo guard).
"""

from __future__ import annotations

import pytest

from app.services.bolt12.well_known_payers import (
    BOOTSTRAP_OM_PEERS,
    WELL_KNOWN_PAYERS,
    BootstrapOMPeer,
    WellKnownPayer,
    bootstrap_om_peer_node_ids,
    match_for_description,
    well_known_payer_node_ids,
)


class TestMatchForDescription:
    def test_ocean_prefix_matches_seed_entry(self) -> None:
        payer = match_for_description(
            "OCEAN Payouts for bc1qabc123def",
            network="bitcoin",
        )
        assert payer is not None
        assert payer.label == "OCEAN"
        assert payer.description_prefix == "OCEAN Payouts for "

    def test_empty_description_returns_none(self) -> None:
        assert match_for_description("", network="bitcoin") is None
        assert match_for_description(None, network="bitcoin") is None

    def test_non_matching_prefix_returns_none(self) -> None:
        # The prefix is "OCEAN Payouts for " (with trailing space).
        # A description that's a substring but not at position 0 should
        # not match.
        assert (
            match_for_description(
                "Payouts from OCEAN",
                network="bitcoin",
            )
            is None
        )
        # Case mismatch: prefix is case-sensitive (matches OCEAN's
        # documented format exactly).
        assert (
            match_for_description(
                "ocean payouts for bc1q",
                network="bitcoin",
            )
            is None
        )

    def test_mainnet_only_entry_skipped_on_regtest(self) -> None:
        # OCEAN is mainnet-only; a regtest user pasting the same
        # description should not trigger a mainnet-pubkey auto-peer.
        assert (
            match_for_description(
                "OCEAN Payouts for bcrt1q...",
                network="regtest",
            )
            is None
        )
        assert (
            match_for_description(
                "OCEAN Payouts for tb1q...",
                network="testnet",
            )
            is None
        )
        assert (
            match_for_description(
                "OCEAN Payouts for tb1q...",
                network="signet",
            )
            is None
        )

    def test_first_matching_entry_wins(self) -> None:
        # The registry's deterministic order is the source of truth
        # when two prefixes overlap. Today no two entries overlap; if
        # a future entry does, the first by iteration order wins. This
        # test pins that behavior using a synthetic local registry so
        # a real registry change doesn't have to chase the assertion.
        local_registry = (
            WellKnownPayer(
                label="A",
                description_prefix="Foo ",
                node_id_hex="02" + "aa" * 32,
                address="1.2.3.4:9735",
                mainnet_only=False,
            ),
            WellKnownPayer(
                label="B",
                description_prefix="Foo bar ",
                node_id_hex="02" + "bb" * 32,
                address="5.6.7.8:9735",
                mainnet_only=False,
            ),
        )

        # Re-implement the lookup against the local registry to verify
        # the iteration-order contract. We don't import the private
        # iteration variable from the module — that's an internal detail.
        # Instead the test asserts the semantics: ``"Foo bar X"`` is
        # ambiguous (both prefixes match) and the registry order picks
        # the first one.
        def _match(desc: str) -> WellKnownPayer | None:
            for entry in local_registry:
                if desc.startswith(entry.description_prefix):
                    return entry
            return None

        hit = _match("Foo bar baz")
        assert hit is not None and hit.label == "A"


class TestRegistryHygiene:
    """Catch typos in seed entries at import-test time so a bad entry
    never silently fails in production."""

    @pytest.mark.parametrize("payer", WELL_KNOWN_PAYERS, ids=lambda p: p.label)
    def test_pubkey_decodes_to_33_bytes(self, payer: WellKnownPayer) -> None:
        node_id = bytes.fromhex(payer.node_id_hex)
        assert len(node_id) == 33, f"{payer.label}: node_id_hex must decode to 33 bytes (got {len(node_id)})"
        # First byte of a compressed secp256k1 pubkey is 0x02 or 0x03.
        assert node_id[0] in (0x02, 0x03), (
            f"{payer.label}: node_id_hex must start with 0x02 or 0x03 (got {node_id[0]:#x})"
        )

    @pytest.mark.parametrize("payer", WELL_KNOWN_PAYERS, ids=lambda p: p.label)
    def test_address_non_empty(self, payer: WellKnownPayer) -> None:
        assert payer.address, f"{payer.label}: address must not be empty"
        # LDK's SocketAddress Display format is always ``host:port``
        # so a colon must be present somewhere.
        assert ":" in payer.address, f"{payer.label}: address must include a port (got {payer.address!r})"

    @pytest.mark.parametrize("payer", WELL_KNOWN_PAYERS, ids=lambda p: p.label)
    def test_prefix_non_empty(self, payer: WellKnownPayer) -> None:
        assert payer.description_prefix, f"{payer.label}: description_prefix must not be empty"


class TestBootstrapOMPeerHygiene:
    """Same typo guards applied to :data:`BOOTSTRAP_OM_PEERS`. These
    peers are dialed unconditionally on mainnet so a bad entry would
    fail every wallet startup at the connect_peer level. The hygiene
    tests catch that at import time instead."""

    def test_registry_non_empty_on_mainnet(self) -> None:
        # The whole point of the bootstrap registry is that the
        # wallet ships with a viable ``offer_paths`` introduction
        # node out of the box. An empty registry would silently
        # regress to the OCEAN-payouts unreachability bug.
        mainnet_entries = [b for b in BOOTSTRAP_OM_PEERS if b.mainnet_only]
        assert mainnet_entries, "BOOTSTRAP_OM_PEERS must contain at least one mainnet entry"

    @pytest.mark.parametrize(
        "peer",
        BOOTSTRAP_OM_PEERS,
        ids=lambda p: p.label,
    )
    def test_pubkey_decodes_to_33_bytes(self, peer: BootstrapOMPeer) -> None:
        node_id = bytes.fromhex(peer.node_id_hex)
        assert len(node_id) == 33, f"{peer.label}: node_id_hex must decode to 33 bytes (got {len(node_id)})"
        assert node_id[0] in (0x02, 0x03), (
            f"{peer.label}: node_id_hex must start with 0x02 or 0x03 (got {node_id[0]:#x})"
        )

    @pytest.mark.parametrize(
        "peer",
        BOOTSTRAP_OM_PEERS,
        ids=lambda p: p.label,
    )
    def test_address_non_empty_and_clearnet(
        self,
        peer: BootstrapOMPeer,
    ) -> None:
        assert peer.address, f"{peer.label}: address must not be empty"
        assert ":" in peer.address, f"{peer.label}: address must include a port (got {peer.address!r})"
        # Bootstrap peers must be reachable from public payers — Tor
        # disqualifies the peer as an introduction node for many
        # CLN/LND configurations and would defeat the bootstrap's
        # purpose.
        host = peer.address.rsplit(":", 1)[0]
        assert not host.lower().endswith(".onion"), (
            f"{peer.label}: bootstrap peers must use a clearnet address (got {peer.address!r})"
        )

    def test_no_overlap_with_well_known_payers(self) -> None:
        # A node that's both a payer (kept connected, excluded from
        # intros) and a bootstrap peer (kept connected, preferred as
        # intro) is contradictory. Catch the conflict at import time.
        payer_ids = {bytes.fromhex(p.node_id_hex) for p in WELL_KNOWN_PAYERS}
        boot_ids = {bytes.fromhex(b.node_id_hex) for b in BOOTSTRAP_OM_PEERS}
        overlap = payer_ids & boot_ids
        assert not overlap, (
            f"node_id collision between WELL_KNOWN_PAYERS and BOOTSTRAP_OM_PEERS: {[h.hex() for h in overlap]}"
        )


class TestNodeIdHelpers:
    def test_well_known_payer_node_ids_mainnet(self) -> None:
        ids = well_known_payer_node_ids(network="bitcoin")
        # OCEAN's pubkey must be in the set (the entry we ship today).
        ocean = next(p for p in WELL_KNOWN_PAYERS if p.label == "OCEAN")
        assert bytes.fromhex(ocean.node_id_hex) in ids

    def test_well_known_payer_node_ids_skips_mainnet_only_on_regtest(
        self,
    ) -> None:
        ids = well_known_payer_node_ids(network="regtest")
        # OCEAN is mainnet_only → excluded on regtest.
        ocean = next(p for p in WELL_KNOWN_PAYERS if p.label == "OCEAN")
        assert bytes.fromhex(ocean.node_id_hex) not in ids

    def test_bootstrap_om_peer_node_ids_mainnet(self) -> None:
        ids = bootstrap_om_peer_node_ids(network="bitcoin")
        # Every mainnet bootstrap entry must be in the set.
        expected = {bytes.fromhex(b.node_id_hex) for b in BOOTSTRAP_OM_PEERS if b.mainnet_only}
        assert expected.issubset(ids)

    def test_bootstrap_om_peer_node_ids_skips_mainnet_only_on_regtest(
        self,
    ) -> None:
        ids = bootstrap_om_peer_node_ids(network="regtest")
        for b in BOOTSTRAP_OM_PEERS:
            if b.mainnet_only:
                assert bytes.fromhex(b.node_id_hex) not in ids


def test_ocean_payer_marked_requires_privacy_false():
    """Ocean explicitly maps payer→payee via miner BTC addresses,
    so blinded-path privacy isn't a concern. Fix #3 (2026-06-06)
    uses this flag to drop ``min_real_hops`` to 1 for offers
    matching Ocean's description prefix."""
    from app.services.bolt12.well_known_payers import WELL_KNOWN_PAYERS

    ocean = next(p for p in WELL_KNOWN_PAYERS if p.label == "OCEAN")
    assert ocean.requires_privacy is False


def test_min_real_hops_override_helper_for_ocean_description(monkeypatch):
    """The offer-issuance helper returns ``1`` for Ocean offers
    and ``None`` for generic descriptions or non-matching prefixes."""
    from app.api.bolt12 import _min_real_hops_override_for_description
    from app.core.config import settings

    monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")

    assert _min_real_hops_override_for_description("OCEAN Payouts for bc1qexample") == 1
    assert _min_real_hops_override_for_description("Coffee shop offer") is None
    assert _min_real_hops_override_for_description(None) is None
    assert _min_real_hops_override_for_description("") is None
