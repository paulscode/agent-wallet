# SPDX-License-Identifier: MIT
"""Routing-mode resolution for the LN self-pay source hop.

A self-payment reshuffles the wallet's channel balances immediately
before the reverse-swap exit, rewriting the channel-balance
fingerprint so the on-chain exit output does not map cleanly onto the
pre-mix channel state. Two mutually-exclusive modes carry it:

* **pinned** — the payment leaves through one chosen channel
  (``outgoing_chan_id``): a deterministic single-path reshuffle.
* **split** — the payment fans out across several channels
  (``max_parts`` MPP) while ``ignored_pairs`` excludes the first-hop
  edges to blocklisted peers so the split steers away from them.

Pinning a single first hop while also MPP-splitting is
contradictory — a pinned channel cannot fan out — so a session runs
in exactly one mode. The avoid set is the operator peer blocklist;
blocklisted peers are excluded both as pinned source channels and as
first-hop edges in split mode.

The functions here are pure (no LND / DB / network) so the hop's
adapter can be exercised deterministically; the deps builder in the
dispatcher supplies the live channel snapshot.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Literal, Optional


@dataclass(frozen=True)
class SelfPayRoute:
    """Resolved routing posture for one self-payment.

    Exactly one of ``outgoing_chan_id`` (pinned) or ``max_parts``
    (split) is populated; ``ignored_pairs`` is only meaningful in
    split mode.
    """

    mode: Literal["pinned", "split"]
    outgoing_chan_id: Optional[str] = None
    max_parts: Optional[int] = None
    ignored_pairs: tuple[tuple[str, str], ...] = ()


def _active_unblocked(channels: list[dict[str, Any]], avoid_pubkeys: frozenset[str]) -> list[dict[str, Any]]:
    """Active channels whose remote peer is not in the avoid set."""
    out: list[dict[str, Any]] = []
    for ch in channels or []:
        if not ch.get("active"):
            continue
        if (ch.get("remote_pubkey") or "") in avoid_pubkeys:
            continue
        if not str(ch.get("chan_id") or ""):
            continue
        out.append(ch)
    return out


def eligible_pinned_channels(
    channels: list[dict[str, Any]],
    *,
    min_local_balance_sat: int,
    avoid_pubkeys: frozenset[str],
) -> list[dict[str, Any]]:
    """Active, unblocked channels with enough local balance to source
    the whole self-payment through one channel."""
    return [
        ch
        for ch in _active_unblocked(channels, avoid_pubkeys)
        if int(ch.get("local_balance") or 0) >= int(min_local_balance_sat)
    ]


def build_ignored_pairs(our_pubkey: str, avoid_pubkeys: frozenset[str]) -> tuple[tuple[str, str], ...]:
    """Directed ``(our_pubkey, peer)`` first-hop edges to exclude from
    path-finding, one per blocklisted peer. Excluding the our→peer edge
    steers a split self-payment away from those channels without
    forbidding the peer as an intermediate hop elsewhere."""
    if not our_pubkey:
        return ()
    return tuple((our_pubkey, p) for p in sorted(avoid_pubkeys) if p and p != our_pubkey)


def choose_pinned_channel(
    eligibles: list[dict[str, Any]],
    *,
    rng: "secrets.SystemRandom | None" = None,
) -> Optional[str]:
    """Weighted-random pick over eligible channels, weighted by local
    balance (mirrors the priv_channel peer-selection idiom). Returns the
    chosen ``chan_id`` or ``None`` when there are no eligibles."""
    weighted = [(str(ch["chan_id"]), max(1, int(ch.get("local_balance") or 0))) for ch in eligibles]
    if not weighted:
        return None
    rng = rng or secrets.SystemRandom()
    total = sum(w for _, w in weighted)
    pick = rng.randrange(total)
    upto = 0
    for cid, w in weighted:
        upto += w
        if pick < upto:
            return cid
    return weighted[-1][0]


def resolve_self_pay_route(
    *,
    channels: list[dict[str, Any]],
    our_pubkey: str,
    avoid_pubkeys: "frozenset[str] | set[str]",
    bin_amount_sat: int,
    mode_policy: str,
    split_min_channels: int,
    mpp_max_parts: int,
    rng: "secrets.SystemRandom | None" = None,
) -> tuple[Optional[SelfPayRoute], Optional[str]]:
    """Resolve the self-pay routing posture.

    ``mode_policy`` is ``pinned`` | ``split`` | ``auto``; ``auto``
    splits when at least ``split_min_channels`` active unblocked
    channels exist, else pins. Returns ``(route, None)`` or
    ``(None, error)`` when no posture is viable (e.g. insufficient
    aggregate local balance, or no single channel can source a pinned
    payment).
    """
    avoid = frozenset(p for p in (avoid_pubkeys or set()) if p)
    active = _active_unblocked(channels, avoid)
    total_local = sum(int(ch.get("local_balance") or 0) for ch in active)
    amount = int(bin_amount_sat)
    if amount <= 0:
        return None, "bin_amount_sat must be positive"

    policy = (mode_policy or "auto").strip().lower()
    if policy not in {"pinned", "split", "auto"}:
        policy = "auto"

    def _split() -> tuple[Optional[SelfPayRoute], Optional[str]]:
        if total_local < amount or len(active) < 2:
            return None, "insufficient_local_balance_for_self_pay"
        pairs = build_ignored_pairs(our_pubkey, avoid)
        # Fail closed: when peers are blocklisted but cannot be expressed
        # as ignored first-hop edges (no node pubkey resolved), refuse the
        # split rather than fire one that could route through a
        # blocklisted peer. Blocklisted channels are already excluded as
        # sources via ``_active_unblocked``; this guards the routing side.
        if avoid and not pairs:
            return None, "self_pay_blocklist_unenforceable"
        parts = max(2, min(int(mpp_max_parts), len(active)))
        return SelfPayRoute(mode="split", max_parts=parts, ignored_pairs=pairs), None

    def _pinned() -> tuple[Optional[SelfPayRoute], Optional[str]]:
        eligibles = eligible_pinned_channels(channels, min_local_balance_sat=amount, avoid_pubkeys=avoid)
        cid = choose_pinned_channel(eligibles, rng=rng)
        if cid is None:
            return None, None  # no single channel can source it — caller may fall back
        return SelfPayRoute(mode="pinned", outgoing_chan_id=cid), None

    want_split = policy == "split" or (policy == "auto" and len(active) >= int(split_min_channels))
    if want_split:
        return _split()

    route, err = _pinned()
    if route is not None:
        return route, None
    if err is not None:
        return None, err
    # No single channel can source a pinned payment. Fall back to a
    # split if the aggregate local balance can cover it.
    return _split()


__all__ = [
    "SelfPayRoute",
    "eligible_pinned_channels",
    "build_ignored_pairs",
    "choose_pinned_channel",
    "resolve_self_pay_route",
]
