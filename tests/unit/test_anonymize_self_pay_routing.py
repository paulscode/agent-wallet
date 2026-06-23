# SPDX-License-Identifier: MIT
"""LN self-pay routing-mode resolution unit tests.

The resolver picks one of two mutually-exclusive postures for the
circular self-payment:

* **pinned** — one ``outgoing_chan_id``, no MPP.
* **split** — ``max_parts`` MPP with ``ignored_pairs`` first-hop
  exclusions, no pinned channel.

All assertions are deterministic-equality; the weighted-random pinned
pick is driven by an injected RNG stub so the chosen channel is fixed.
"""

from __future__ import annotations

from app.services.anonymize.self_pay_routing import (
    SelfPayRoute,
    build_ignored_pairs,
    choose_pinned_channel,
    eligible_pinned_channels,
    resolve_self_pay_route,
)

OUR = "02" + "aa" * 32
PEER_A = "03" + "11" * 32
PEER_B = "03" + "22" * 32
PEER_C = "03" + "33" * 32
PEER_D = "03" + "44" * 32


class _FixedRng:
    """RNG stub: ``randrange`` always returns the configured value."""

    def __init__(self, value: int) -> None:
        self._value = value

    def randrange(self, _n: int) -> int:
        return self._value


def _chan(chan_id: str, *, local: int, peer: str, active: bool = True) -> dict:
    return {"chan_id": chan_id, "local_balance": local, "remote_pubkey": peer, "active": active}


# ── eligible_pinned_channels ────────────────────────────────────────


def test_eligible_excludes_inactive_blocklisted_and_underfunded() -> None:
    channels = [
        _chan("1", local=500_000, peer=PEER_A),
        _chan("2", local=500_000, peer=PEER_B, active=False),  # inactive
        _chan("3", local=10, peer=PEER_C),  # underfunded
        _chan("4", local=500_000, peer=PEER_B),  # blocklisted peer
    ]
    eligibles = eligible_pinned_channels(
        channels,
        min_local_balance_sat=250_000,
        avoid_pubkeys=frozenset({PEER_B}),
    )
    assert [c["chan_id"] for c in eligibles] == ["1"]


# ── build_ignored_pairs ─────────────────────────────────────────────


def test_ignored_pairs_are_our_to_each_blocklisted_peer() -> None:
    pairs = build_ignored_pairs(OUR, frozenset({PEER_A, PEER_B}))
    assert pairs == ((OUR, PEER_A), (OUR, PEER_B))


def test_ignored_pairs_empty_without_our_pubkey() -> None:
    assert build_ignored_pairs("", frozenset({PEER_A})) == ()


def test_ignored_pairs_excludes_self_edge() -> None:
    assert build_ignored_pairs(OUR, frozenset({OUR})) == ()


# ── choose_pinned_channel ───────────────────────────────────────────


def test_choose_pinned_channel_weighted_pick_is_deterministic_with_rng() -> None:
    eligibles = [_chan("1", local=100_000, peer=PEER_A), _chan("2", local=900_000, peer=PEER_C)]
    # pick=0 lands in the first channel's weight band.
    assert choose_pinned_channel(eligibles, rng=_FixedRng(0)) == "1"
    # pick=500_000 is past channel 1's weight (100_000) → channel 2.
    assert choose_pinned_channel(eligibles, rng=_FixedRng(500_000)) == "2"


def test_choose_pinned_channel_none_when_empty() -> None:
    assert choose_pinned_channel([], rng=_FixedRng(0)) is None


# ── resolve_self_pay_route ──────────────────────────────────────────


def test_resolve_pinned_when_few_channels_auto() -> None:
    channels = [_chan("1", local=500_000, peer=PEER_A)]
    route, err = resolve_self_pay_route(
        channels=channels,
        our_pubkey=OUR,
        avoid_pubkeys=set(),
        bin_amount_sat=250_000,
        mode_policy="auto",
        split_min_channels=3,
        mpp_max_parts=4,
        rng=_FixedRng(0),
    )
    assert err is None
    assert route == SelfPayRoute(mode="pinned", outgoing_chan_id="1")


def test_resolve_split_when_enough_channels_auto() -> None:
    channels = [
        _chan("1", local=100_000, peer=PEER_A),
        _chan("2", local=100_000, peer=PEER_C),
        _chan("3", local=100_000, peer=PEER_D),
        _chan("4", local=100_000, peer=PEER_B),  # blocklisted
    ]
    route, err = resolve_self_pay_route(
        channels=channels,
        our_pubkey=OUR,
        avoid_pubkeys={PEER_B},
        bin_amount_sat=250_000,
        mode_policy="auto",
        split_min_channels=3,
        mpp_max_parts=4,
    )
    assert err is None
    assert route is not None
    assert route.mode == "split"
    # 3 active unblocked channels (PEER_B excluded) → max_parts capped at 3.
    assert route.max_parts == 3
    assert route.outgoing_chan_id is None
    # ignored_pairs carries only the blocklisted peer's first-hop edge.
    assert route.ignored_pairs == ((OUR, PEER_B),)


def test_resolve_split_explicit_policy_overrides_channel_count() -> None:
    channels = [
        _chan("1", local=200_000, peer=PEER_A),
        _chan("2", local=200_000, peer=PEER_C),
    ]
    route, err = resolve_self_pay_route(
        channels=channels,
        our_pubkey=OUR,
        avoid_pubkeys=set(),
        bin_amount_sat=250_000,
        mode_policy="split",
        split_min_channels=3,  # would pin under auto, but policy forces split
        mpp_max_parts=4,
    )
    assert err is None
    assert route is not None and route.mode == "split"


def test_resolve_pinned_falls_back_to_split_when_no_single_channel() -> None:
    """Pinned policy but no single channel can source the full amount;
    the aggregate can, so it falls back to a split."""
    channels = [
        _chan("1", local=150_000, peer=PEER_A),
        _chan("2", local=150_000, peer=PEER_C),
    ]
    route, err = resolve_self_pay_route(
        channels=channels,
        our_pubkey=OUR,
        avoid_pubkeys=set(),
        bin_amount_sat=250_000,
        mode_policy="pinned",
        split_min_channels=99,
        mpp_max_parts=4,
    )
    assert err is None
    assert route is not None and route.mode == "split"


def test_resolve_errors_on_insufficient_aggregate_balance() -> None:
    channels = [_chan("1", local=50_000, peer=PEER_A), _chan("2", local=50_000, peer=PEER_C)]
    route, err = resolve_self_pay_route(
        channels=channels,
        our_pubkey=OUR,
        avoid_pubkeys=set(),
        bin_amount_sat=250_000,
        mode_policy="split",
        split_min_channels=2,
        mpp_max_parts=4,
    )
    assert route is None
    assert err == "insufficient_local_balance_for_self_pay"


def test_resolve_split_fails_closed_when_blocklist_unenforceable() -> None:
    """A configured blocklist that can't be expressed as ignored
    first-hop edges (no node pubkey) must refuse the split rather than
    fire one that could route through a blocklisted peer."""
    channels = [
        _chan("1", local=100_000, peer=PEER_A),
        _chan("2", local=100_000, peer=PEER_C),
        _chan("3", local=100_000, peer=PEER_D),
    ]
    route, err = resolve_self_pay_route(
        channels=channels,
        our_pubkey="",  # get_info failed → no pubkey to build pairs
        avoid_pubkeys={PEER_B},  # but a blocklist IS configured
        bin_amount_sat=250_000,
        mode_policy="split",
        split_min_channels=3,
        mpp_max_parts=4,
    )
    assert route is None
    assert err == "self_pay_blocklist_unenforceable"


def test_resolve_split_without_blocklist_tolerates_missing_pubkey() -> None:
    """With no blocklist configured, a missing node pubkey is harmless —
    there are no first-hop edges to exclude."""
    channels = [
        _chan("1", local=100_000, peer=PEER_A),
        _chan("2", local=100_000, peer=PEER_C),
        _chan("3", local=100_000, peer=PEER_D),
    ]
    route, err = resolve_self_pay_route(
        channels=channels,
        our_pubkey="",
        avoid_pubkeys=set(),
        bin_amount_sat=250_000,
        mode_policy="split",
        split_min_channels=3,
        mpp_max_parts=4,
    )
    assert err is None
    assert route is not None and route.mode == "split"
    assert route.ignored_pairs == ()


def test_resolve_rejects_nonpositive_amount() -> None:
    route, err = resolve_self_pay_route(
        channels=[_chan("1", local=500_000, peer=PEER_A)],
        our_pubkey=OUR,
        avoid_pubkeys=set(),
        bin_amount_sat=0,
        mode_policy="auto",
        split_min_channels=3,
        mpp_max_parts=4,
    )
    assert route is None
    assert err == "bin_amount_sat must be positive"
