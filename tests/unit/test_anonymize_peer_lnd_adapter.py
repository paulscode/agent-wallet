# SPDX-License-Identifier: MIT
"""LND ``describe_graph`` adapter."""

from __future__ import annotations

from app.services.anonymize.peer_selection import candidates_from_lnd_graph

_OUR_PUBKEY = "02" + "0" * 64
_PEER_A = "02" + "a" * 64
_PEER_B = "02" + "b" * 64
_PEER_C = "02" + "c" * 64


def test_returns_empty_list_for_empty_graph() -> None:
    out = candidates_from_lnd_graph(nodes=[], channels=[])
    assert out == []


def test_aggregates_capacity_per_node() -> None:
    nodes = [{"pub_key": _PEER_A}, {"pub_key": _PEER_B}]
    channels = [
        {"node1_pub": _PEER_A, "node2_pub": _PEER_B, "capacity": 1_000_000},
        {"node1_pub": _PEER_A, "node2_pub": _PEER_B, "capacity": 5_000_000},
    ]
    out = candidates_from_lnd_graph(nodes=nodes, channels=channels)
    by_pk = {c.pubkey: c for c in out}
    # Both peers participate in both channels ⇒ capacity = 6_000_000 each.
    assert by_pk[_PEER_A].outbound_capacity_sat == 6_000_000
    assert by_pk[_PEER_B].outbound_capacity_sat == 6_000_000


def test_excludes_our_own_node() -> None:
    nodes = [{"pub_key": _PEER_A}, {"pub_key": _OUR_PUBKEY}]
    channels = [{"node1_pub": _PEER_A, "node2_pub": _OUR_PUBKEY, "capacity": 100_000}]
    out = candidates_from_lnd_graph(
        nodes=nodes,
        channels=channels,
        our_node_pubkey=_OUR_PUBKEY,
    )
    pks = {c.pubkey for c in out}
    assert _OUR_PUBKEY not in pks
    assert _PEER_A in pks


def test_centrality_score_is_log_scaled() -> None:
    """Capacity 1M and 1B should not produce a 1000× weight ratio."""
    nodes = [{"pub_key": _PEER_A}, {"pub_key": _PEER_B}]
    channels = [
        {"node1_pub": _PEER_A, "node2_pub": _PEER_C, "capacity": 1_000_000},
        {"node1_pub": _PEER_B, "node2_pub": _PEER_C, "capacity": 1_000_000_000},
    ]
    out = candidates_from_lnd_graph(nodes=nodes, channels=channels)
    by_pk = {c.pubkey: c for c in out}
    a_score = by_pk[_PEER_A].centrality_score
    b_score = by_pk[_PEER_B].centrality_score
    assert b_score > a_score
    # The log-scaled ratio should be much smaller than the raw 1000×.
    assert b_score / a_score < 5.0


def test_skips_nodes_without_pubkey() -> None:
    nodes = [{}, {"pub_key": _PEER_A}, {"pub_key": ""}]
    channels = [{"node1_pub": _PEER_A, "node2_pub": _PEER_B, "capacity": 100}]
    out = candidates_from_lnd_graph(nodes=nodes, channels=channels)
    pks = {c.pubkey for c in out}
    assert pks == {_PEER_A}


def test_supports_alternate_pubkey_field() -> None:
    """Some LND versions expose ``pubkey`` instead of ``pub_key``."""
    nodes = [{"pubkey": _PEER_A}]
    channels = [{"node1_pub": _PEER_A, "node2_pub": _PEER_B, "capacity": 100}]
    out = candidates_from_lnd_graph(nodes=nodes, channels=channels)
    assert len(out) == 1
    assert out[0].pubkey == _PEER_A


def test_node_with_no_channels_has_zero_capacity() -> None:
    nodes = [{"pub_key": _PEER_A}]
    out = candidates_from_lnd_graph(nodes=nodes, channels=[])
    assert len(out) == 1
    assert out[0].outbound_capacity_sat == 0
