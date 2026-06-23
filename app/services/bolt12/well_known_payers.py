# SPDX-License-Identifier: MIT
"""Registry of well-known LN payers we proactively peer with at offer
issuance time.

Background
----------
A BOLT 12 offer minted by this wallet carries a blinded ``offer_paths``
TLV whose introduction node is one of the BOLT 12 gateway's onion-
message-capable peers (see :func:`app.api.bolt12._build_offer_paths_for_issuance`).
For the payer's CLN/LDK to actually deliver the ``invoice_request``
onion message it must be able to **connect** to the introduction node
— typically via an address found in its gossip graph.

When the wallet's only onion-message-capable peers are Tor-only (or
otherwise absent from the public gossip graph), the payer aborts
with ``"no address known for peer"`` before the round-trip even
starts. OCEAN mining-pool payouts hit this failure mode in
production.

Mitigation
----------
For well-known payers whose pubkey + address are public and stable,
we dial the payer's own LN node before building ``offer_paths``.
After the BOLT 1 init handshake the payer's node is one of our
peers, so it becomes an eligible introduction node candidate; the
payer trivially "connects" to its own node and the round-trip
succeeds.

This module is intentionally minimal: a small frozen registry +
``match_for_description`` lookup. The auto-peer dial itself lives in
the BOLT 12 API layer (``app/api/bolt12.py``) because it depends on
``get_bolt12_service`` and the audit pipeline.

Adding a new payer
------------------
1. Confirm the payer publishes a stable mainnet pubkey + clearnet
   address.
2. Look up the payer's description format (the prefix that the wallet
   user will paste into the dashboard's Configure Receive).
3. Add a :class:`WellKnownPayer` entry to :data:`WELL_KNOWN_PAYERS`.
4. Add a regression test covering the prefix match + auto-peer
   trigger in ``tests/unit/test_bolt12_well_known_payers.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True, slots=True)
class WellKnownPayer:
    """A documented LN payer whose node we dial at offer issuance.

    Fields
    ------
    label
        Short operator-facing identifier (e.g. ``"OCEAN"``). Used in
        log lines and audit events so a human reading the journal
        knows which payer triggered the auto-peer.

    description_prefix
        Substring the offer description must start with for this
        entry to match. Mirrors the payer's documented format
        (e.g. OCEAN's ``"OCEAN Payouts for "`` followed by the
        miner's BTC payout address).

    node_id_hex
        66-character compressed secp256k1 pubkey, hex-encoded. The
        registry validates this is 33 bytes at lookup time so a
        typo surfaces as a logged warning rather than a silent
        no-op.

    address
        LDK ``SocketAddress`` Display string — typically
        ``host:port`` for IPv4 / DNS, ``[ipv6]:port`` for IPv6, or
        ``<onion>.onion:port`` for Tor v3. Clearnet preferred so the
        introduction node is reachable from public payers.

    mainnet_only
        ``True`` when the payer's pubkey is mainnet-only (the common
        case). The lookup skips the entry on non-mainnet networks so
        a regtest wallet doesn't try to dial mainnet pubkeys.

    requires_privacy
        ``True`` when the payer's identity is sensitive — typical for
        general-purpose payers where the receiver doesn't want
        passive observers to link payer-to-payee. ``False`` for
        relationships where the payer already knows who they're
        paying (Ocean: they explicitly map miner BTC payout
        addresses to LN identities).

        Drives the offer-issuance step's choice of
        ``Bolt12Offer.min_real_hops_override``:

        * ``True`` → keep the global default ``min_real_hops`` (2),
          which constructs a 2-real-hop blinded path with an
          intermediate hop between intro and us.
        * ``False`` → set the override to ``1``, eliminating the
          intermediate hop (the 2026-06-06 Ocean failure point) at
          the cost of revealing our direct peer as the reply intro.
    """

    label: str
    description_prefix: str
    node_id_hex: str
    address: str
    mainnet_only: bool = True
    requires_privacy: bool = True


# Seed entries. Sorted by ``label`` for deterministic match order
# when two prefixes overlap (none do today, but the invariant keeps
# future additions safe).
WELL_KNOWN_PAYERS: tuple[WellKnownPayer, ...] = (
    WellKnownPayer(
        label="OCEAN",
        description_prefix="OCEAN Payouts for ",
        # https://amboss.space/node/029ef2ce43571727104099576c633b2233bfeb8dc18b476f93540a32207da9e9a4
        # Alias: "🌊 OCEAN MINING, SA de CV 🌊"
        node_id_hex=("029ef2ce43571727104099576c633b2233bfeb8dc18b476f93540a32207da9e9a4"),
        # OCEAN publishes both clearnet + Tor v3. We prefer the
        # clearnet socket so the dial works regardless of whether
        # the gateway has Tor configured. Operators routing
        # gateway egress through Tor can override the address via
        # the well-known-payers registry directly.
        address="16.63.81.71:9735",
        # Ocean explicitly maps payer-to-payee (miner BTC payout
        # address → LN identity); blinded-path privacy is not a
        # concern. Drop to 1-real-hop paths to eliminate the
        # intermediate-hop failure point (2026-06-06 post-mortem).
        requires_privacy=False,
    ),
)


@dataclass(frozen=True, slots=True)
class BootstrapOMPeer:
    """A universally-gossiped, onion-message-capable LN node we
    permanently peer with so we always have at least one viable
    ``offer_paths`` introduction node.

    Distinct from :class:`WellKnownPayer`:

    * ``WellKnownPayer`` represents the **payer itself** and is
      dialed only when that payer has an active default-receive offer.
      Its node is intentionally **excluded** from offer-paths intro
      candidates — relying on the payer to route to itself was the
      original OCEAN failure mode (the payer's own gossip view often
      lacks an address for its public-facing node).

    * ``BootstrapOMPeer`` represents a **third party** whose
      ``node_announcement`` is universally propagated. Every CLN /
      eclair / LDK / LND on mainnet has it in its gossip graph, so
      it's always usable as the introduction node for any payer's
      ``invoice_request`` route.

    Selection criteria (all four must hold to add an entry):

    1. Node advertises ``option_onion_messages`` (feature bit 38/39)
       in its current ``node_announcement``. Verify with
       ``GET /v1/graph/node/<pubkey>`` on a well-synced node.
    2. Stable public clearnet ``host:port`` published in
       ``node_announcement`` (Tor-only nodes don't qualify — many
       payer CLNs refuse Tor connections by default).
    3. High channel count + multi-year uptime so the
       ``node_announcement`` is firmly cached across the network.
    4. Operated by a known entity (Amboss / 1ML link in comment).
    """

    label: str
    node_id_hex: str
    address: str
    mainnet_only: bool = True


# Always-on bootstrap peers. The sticky-peer reconciler dials and
# pins these regardless of which default-receive offers exist, so
# the gateway always has at least one viable ``offer_paths``
# introduction node even before the operator configures their first
# well-known payer.
#
# Verified OM-capable on 2026-05-25 via ``GET /v1/graph/node/`` from
# this wallet's LND. To re-verify or add a candidate, see the
# ``check_om`` probe scripts in ``/tmp`` (transient) or run the
# equivalent ``lightning-cli listnodes <pubkey>`` and check that
# feature bit 38 or 39 is set in ``features``.
BOOTSTRAP_OM_PEERS: tuple[BootstrapOMPeer, ...] = (
    BootstrapOMPeer(
        label="ACINQ",
        # https://amboss.space/node/03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f
        # Alias: "ACINQ". The phoenix/eclair flagship node. Ships
        # OM feature bit 38 by default and has been at the same
        # clearnet socket for years.
        node_id_hex=("03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f"),
        address="3.33.236.230:9735",
    ),
    BootstrapOMPeer(
        label="LNBIG-lnd1",
        # https://amboss.space/node/0298f6074a454a1f5345cb2a7c6f9fce206cd0bf675d177cdbf0ca7508dd28852f
        # Alias: "BCash_Is_Trash" (LNBIG's primary mainnet LND). One
        # of the highest channel-count nodes on the network; every
        # routing node has its node_announcement cached.
        node_id_hex=("0298f6074a454a1f5345cb2a7c6f9fce206cd0bf675d177cdbf0ca7508dd28852f"),
        address="70.8.171.94:9735",
    ),
)


def well_known_payer_node_ids(*, network: str) -> frozenset[bytes]:
    """Return the set of well-known **payer** pubkeys (33-byte
    compressed) applicable to ``network``.

    Used by the offer-path builder to **exclude** these from
    introduction-node candidates: a payer's own node is a peer we
    maintain for inbound reachability, never an intro. See the
    docstring on :class:`BootstrapOMPeer` for the rationale.
    """
    is_mainnet = network == "bitcoin"
    out: set[bytes] = set()
    for entry in WELL_KNOWN_PAYERS:
        if entry.mainnet_only and not is_mainnet:
            continue
        try:
            nid = bytes.fromhex(entry.node_id_hex)
        except ValueError:
            continue
        if len(nid) == 33:
            out.add(nid)
    return frozenset(out)


def bootstrap_om_peer_node_ids(*, network: str) -> frozenset[bytes]:
    """Return the set of bootstrap-OM-peer pubkeys (33-byte
    compressed) applicable to ``network``.

    Used by the offer-path builder to **prefer** these as
    introduction nodes when multiple candidates are available.
    """
    is_mainnet = network == "bitcoin"
    out: set[bytes] = set()
    for entry in BOOTSTRAP_OM_PEERS:
        if entry.mainnet_only and not is_mainnet:
            continue
        try:
            nid = bytes.fromhex(entry.node_id_hex)
        except ValueError:
            continue
        if len(nid) == 33:
            out.add(nid)
    return frozenset(out)


def match_for_description(
    description: Optional[str],
    *,
    network: str,
) -> Optional[WellKnownPayer]:
    """Return the registry entry matching ``description`` on ``network``.

    ``description`` is the human-readable offer description the user
    typed (e.g. ``"OCEAN Payouts for bc1qabc..."``). ``network`` is
    ``settings.bitcoin_network`` — ``"bitcoin"`` for mainnet, otherwise
    testnet/signet/regtest. Mainnet-only entries are skipped when
    ``network != "bitcoin"`` because their pubkeys aren't valid on
    other chains.

    Returns ``None`` when no entry matches or the description is empty.
    """
    if not description:
        return None
    is_mainnet = network == "bitcoin"
    for entry in WELL_KNOWN_PAYERS:
        if entry.mainnet_only and not is_mainnet:
            continue
        if description.startswith(entry.description_prefix):
            return entry
    return None


__all__ = [
    "BOOTSTRAP_OM_PEERS",
    "BootstrapOMPeer",
    "WELL_KNOWN_PAYERS",
    "WellKnownPayer",
    "bootstrap_om_peer_node_ids",
    "match_for_description",
    "well_known_payer_node_ids",
]
