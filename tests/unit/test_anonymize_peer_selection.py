# SPDX-License-Identifier: MIT
"""Auto peer-selection randomization.

Filter chain (blocklist → capacity → cooldown → top-K) plus
weighted-random pick over centrality.
"""

from __future__ import annotations

import secrets
from collections import Counter

from app.services.anonymize.peer_selection import (
    PeerCandidate,
    select_auto_peer,
    select_eligible_candidates,
    weighted_random_choice,
)


def _peer(pk: str, *, cent: float, cap_sat: int = 10_000_000) -> PeerCandidate:
    return PeerCandidate(pubkey=pk, centrality_score=cent, outbound_capacity_sat=cap_sat)


def test_filter_chain_drops_blocklisted() -> None:
    cands = [_peer("a", cent=10), _peer("b", cent=5)]
    out = select_eligible_candidates(
        cands,
        blocklist=frozenset({"a"}),
        recent_pubkeys=frozenset(),
        min_outbound_capacity_sat=1,
        top_k=10,
    )
    assert [p.pubkey for p in out] == ["b"]


def test_filter_chain_drops_thin_capacity() -> None:
    cands = [
        _peer("a", cent=10, cap_sat=1_000),
        _peer("b", cent=5, cap_sat=10_000_000),
    ]
    out = select_eligible_candidates(
        cands,
        blocklist=frozenset(),
        recent_pubkeys=frozenset(),
        min_outbound_capacity_sat=1_000_000,
        top_k=10,
    )
    assert [p.pubkey for p in out] == ["b"]


def test_filter_chain_drops_recent() -> None:
    cands = [_peer("a", cent=10), _peer("b", cent=5)]
    out = select_eligible_candidates(
        cands,
        blocklist=frozenset(),
        recent_pubkeys=frozenset({"a"}),
        min_outbound_capacity_sat=1,
        top_k=10,
    )
    assert [p.pubkey for p in out] == ["b"]


def test_filter_chain_top_k_limits_output() -> None:
    cands = [_peer(f"p{i}", cent=float(i)) for i in range(20)]
    out = select_eligible_candidates(
        cands,
        blocklist=frozenset(),
        recent_pubkeys=frozenset(),
        min_outbound_capacity_sat=1,
        top_k=3,
    )
    # Highest-centrality first.
    assert [p.pubkey for p in out] == ["p19", "p18", "p17"]


def test_filter_chain_top_k_zero_returns_empty() -> None:
    cands = [_peer("a", cent=10)]
    assert (
        select_eligible_candidates(
            cands,
            blocklist=frozenset(),
            recent_pubkeys=frozenset(),
            min_outbound_capacity_sat=1,
            top_k=0,
        )
        == []
    )


def test_weighted_random_returns_none_for_empty() -> None:
    assert weighted_random_choice([]) is None


def test_weighted_random_picks_proportional_to_centrality() -> None:
    """Over many samples, higher-centrality peer is chosen more often."""
    rng = secrets.SystemRandom()
    cands = [_peer("a", cent=9.0), _peer("b", cent=1.0)]
    counts: Counter[str] = Counter()
    for _ in range(200):
        chosen = weighted_random_choice(cands, rng=rng)
        assert chosen is not None
        counts[chosen.pubkey] += 1
    # 'a' has 9× the weight of 'b'; expect 'a' significantly more often.
    # We use a generous lower bound so the test is robust to RNG variance.
    assert counts["a"] > counts["b"] * 2


def test_weighted_random_falls_back_to_uniform_on_zero_weights() -> None:
    cands = [_peer("a", cent=0), _peer("b", cent=0), _peer("c", cent=0)]
    counts: Counter[str] = Counter()
    for _ in range(150):
        chosen = weighted_random_choice(cands)
        assert chosen is not None
        counts[chosen.pubkey] += 1
    # Each should be picked at least once.
    assert all(counts[k] > 0 for k in ("a", "b", "c"))


def test_select_auto_peer_returns_none_when_no_eligible() -> None:
    cands = [_peer("a", cent=10)]
    out = select_auto_peer(
        cands,
        blocklist=frozenset({"a"}),
        recent_pubkeys=frozenset(),
        min_outbound_capacity_sat=1,
        top_k=10,
    )
    assert out is None


def test_select_auto_peer_obeys_blocklist() -> None:
    cands = [_peer("a", cent=10), _peer("b", cent=5)]
    for _ in range(50):
        chosen = select_auto_peer(
            cands,
            blocklist=frozenset({"a"}),
            recent_pubkeys=frozenset(),
            min_outbound_capacity_sat=1,
            top_k=10,
        )
        assert chosen is not None
        assert chosen.pubkey == "b"
