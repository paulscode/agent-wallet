# SPDX-License-Identifier: MIT
"""BOLT 12 blinded-path post-processing pipeline.

After LND returns a set of blinded paths from
``add_blinded_invoice``, the pipeline here:

1. **Clamps** each path's advertised ``htlc_max_msat`` to the
   live receivable on the terminal channel. Eliminates the
   over-claim that occurs when a channel's gossiped htlc_max
   exceeds its live receivable balance, which makes blinded paths
   advertise amounts that fail at forward time.

2. **Drops** paths whose clamped htlc_max is below the requested
   amount — better to send fewer paths than to
   advertise unroutable ones.

3. **Probes** each remaining path for liveness:
   intro_pubkey is in LND's connected-peers set, and the
   identified terminal channel is ``active``. Skipped when
   ``BOLT12_PROBE_PATHS_BEFORE_MINT=false``.

4. **Selects diverse paths**: group by
   ``intro_pubkey``; keep only the lowest-fee path per intro.
   Prevents the all-paths-through-one-intro single-point-of-
   failure topology.

5. **Filters via the per-intro circuit breaker**:
   intros marked ``open`` are deprioritised (used last if no
   alternatives). Half-open intros get a single probationary
   attempt. Successful settles close the breaker; failures
   reopen it with exponential cooldown.

Returns the final list of paths (mutated dicts with clamped
htlc_max) and a parallel summary suitable for persisting on the
Bolt12Invoice row for later breaker bookkeeping.
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from app.core.config import settings
from app.services.lnd_service import LNDService

logger = logging.getLogger(__name__)


# ── clamp per-path htlc_max to live remote_balance ────


def _safe_cap_sat(remote_balance_sat: int, buffer_ppm: int) -> int:
    """Apply a ppm-scaled safety buffer to a channel's
    remote_balance. ``remote_balance_sat * (1 - buffer_ppm/1e6)``,
    clamped at 0."""
    if remote_balance_sat <= 0:
        return 0
    buffer = (remote_balance_sat * buffer_ppm) // 1_000_000
    return max(0, remote_balance_sat - buffer)


def _identify_terminal_channel(
    path: dict,
    channels: list[dict],
    our_pubkey: str,
) -> dict | None:
    """Best-effort: identify which of our channels is the terminal
    hop of a blinded path.

    Strategies (in priority order):

    A. **Pre-assigned via pigeonhole** — if the caller already
       paired this path to a channel via
       :func:`_pigeonhole_pair_paths_to_channels`, use that.

    B. **1-hop intro = peer** — when ``real_hops == 1`` and the
       intro is one of our direct peers, the intro IS the terminal
       hop.

    C. **Gossiped htlc_max exact match** — when the path's
       advertised aggregate ``htlc_max_msat`` exactly matches one
       channel's gossiped inbound max_htlc. Works only when our
       channel is the binding (smallest) hop in the path.

    Returns the matched channel dict, or ``None`` if we can't
    confidently identify it. Callers fall back to a conservative
    aggregate clamp.
    """
    # Strategy A: pre-assigned via pigeonhole.
    presumed = path.get("_presumed_terminal_channel")
    if isinstance(presumed, dict):
        return presumed

    intro_hex = path.get("_intro_pubkey_hex")
    real_hops = path.get("_real_hops", 2)
    advertised_max_msat = int(path.get("htlc_max_msat") or 0)

    # Strategy B: 1-hop blinded path where intro = peer.
    if real_hops == 1 and intro_hex:
        for ch in channels:
            if ch.get("remote_pubkey") == intro_hex:
                return ch

    # Strategy C: match on gossiped inbound max_htlc_msat.
    matches = [ch for ch in channels if (ch.get("gossiped_inbound_max_htlc_msat") or 0) == advertised_max_msat]
    if len(matches) == 1:
        return matches[0]

    return None


def _pigeonhole_pair_paths_to_channels(
    paths: list[dict],
    channels: list[dict],
    *,
    amount_msat: int,
) -> None:
    """Pair each path to a presumed terminal
    channel using a sorted-fee ↔ sorted-balance pigeonhole.

    The heuristic: LND's blinded-path construction tends to route
    cheaper paths through smaller terminal channels (fewer/simpler
    intermediates), and more expensive paths through larger
    channels (longer routes). So sort paths ascending by aggregate
    effective fee, sort channels ascending by remote_balance, and
    pair them up.

    **Only fires when**:

    * The setting ``BOLT12_PATH_PIGEONHOLE_PAIRING_ENABLED`` is on.
    * The number of paths equals the number of active channels
      with positive remote_balance.

    Otherwise this is a no-op and the per-path strategies B/C apply.

    Mutates ``paths`` in place by setting ``_presumed_terminal_channel``
    on each path; the clamp picks it up via Strategy A.
    """
    if not settings.bolt12_path_pigeonhole_pairing_enabled:
        return
    if not paths or not channels:
        return
    usable_channels = [ch for ch in channels if int(ch.get("remote_balance") or 0) > 0 and ch.get("active", False)]
    if len(paths) != len(usable_channels):
        return

    # Skip paths whose terminal channel
    # is unambiguously identified by Strategy B (real_hops==1 AND
    # intro is one of our peers). Pigeonhole pairing is a heuristic
    # for multi-hop paths where we genuinely don't know which
    # channel terminates the route — but for 1-hop paths, the
    # intro IS the terminal hop, and pre-stamping a wrong channel
    # via pigeonhole would override Strategy B's accurate match.
    direct_peer_pubkeys = {ch.get("remote_pubkey") for ch in usable_channels}
    pigeonhole_candidates: list[dict] = []
    pigeonhole_channels: list[dict] = list(usable_channels)
    for p in paths:
        intro_hex = p.get("_intro_pubkey_hex")
        real_hops = p.get("_real_hops", 2)
        if real_hops == 1 and intro_hex and intro_hex in direct_peer_pubkeys:
            # Strategy B will identify this path's terminal directly.
            # Mark the matched channel as consumed so pigeonhole
            # doesn't double-assign it to another path.
            for ch in pigeonhole_channels:
                if ch.get("remote_pubkey") == intro_hex:
                    pigeonhole_channels.remove(ch)
                    break
            continue
        pigeonhole_candidates.append(p)

    # Run pigeonhole only on the remaining (truly ambiguous) paths.
    if not pigeonhole_candidates or not pigeonhole_channels:
        return
    if len(pigeonhole_candidates) != len(pigeonhole_channels):
        return

    paths_sorted = sorted(
        pigeonhole_candidates,
        key=lambda p: _path_effective_fee_msat(p, amount_msat),
    )
    chans_sorted = sorted(
        pigeonhole_channels,
        key=lambda c: int(c.get("remote_balance") or 0),
    )
    for p, ch in zip(paths_sorted, chans_sorted):
        p["_presumed_terminal_channel"] = ch
        logger.info(
            "bolt12 pigeonhole: paired path intro=%s → channel %s (peer=%s, remote_balance=%d sat)",
            (p.get("_intro_pubkey_hex") or "?")[:16],
            ch.get("chan_id", "?"),
            (ch.get("remote_pubkey") or "?")[:16],
            int(ch.get("remote_balance") or 0),
        )


# ── gossip-policy refresh ─────────────────────────


async def refresh_path_policy_from_gossip(
    path: dict,
    lnd: LNDService,
    *,
    our_pubkey: str,
    channels: list[dict],
) -> dict[str, Any]:
    """Overwrite ``path``'s encoded fee/htlc-bounds fields with the
    intro's CURRENT gossiped peer-side policy.

    **Why this exists**: LND's ``add_blinded_invoice``
    constructs blinded paths using its internal per-channel
    ``channel_update`` cache, which can lag the gossip table by
    minutes-to-hours. When the intro updates its policy and gossip
    reflects this but LND's path-builder doesn't yet, we encode
    stale fees → payer pays the old fee budget → intro deducts its
    *current* (higher) fee → our LND sees an amount shortfall on
    the final hop → HTLC CANCELED → CLN reports an opaque
    blinded-path error.

    Mutates ``path`` in place; returns a diff dict
    ``{field: {"old", "new"}}`` of fields actually changed (empty
    on no-op). Best-effort: any failure (gossip unavailable, intro
    isn't a direct peer, channel not in our list) leaves the path
    unmodified.

    Scope:

    * Real-hops=1 only — for multi-hop blinded paths the encoded
      fees are an *aggregate* across hops; one hop's gossip can't
      reconstruct that aggregate. Skip.
    * Fees (``base_fee_msat``, ``proportional_fee_rate``) and HTLC
      bounds (``htlc_min_msat``, ``htlc_max_msat``) only. CLTV
      (``total_cltv_delta``) is NOT refreshed: it's a path-
      aggregate that depends on LND's internal final-padding
      constant, which we don't know from outside.
    """
    if not int(path.get("_real_hops") or 0) == 1:
        return {}
    intro_pubkey = path.get("_intro_pubkey_hex") or ""
    if not intro_pubkey:
        return {}

    target_chans = [ch for ch in channels if isinstance(ch, dict) and ch.get("remote_pubkey") == intro_pubkey]
    if not target_chans:
        return {}
    chan_id = target_chans[0].get("chan_id")
    if not chan_id:
        return {}

    try:
        edge, err = await lnd.get_channel_edge(chan_id)
        if err or edge is None:
            return {}
    except Exception:  # noqa: BLE001
        logger.debug(
            "bolt12 path policy refresh: edge fetch raised for intro=%s",
            intro_pubkey[:16],
            exc_info=True,
        )
        return {}

    # Reuse the failure-diagnostics extractor for a single
    # source-of-truth on what counts as "peer-side outgoing
    # policy" — divergence between the two would silently re-introduce
    # the very bug this stage closes.
    from app.services.bolt12.failure_diagnostics import (
        _extract_peer_side_policy,
        _to_int_or_none,
    )

    policy = _extract_peer_side_policy(
        edge,
        our_pubkey=our_pubkey,
        peer_pubkey=intro_pubkey,
    )
    if policy is None:
        return {}

    diff: dict[str, Any] = {}
    # Each field: ``(path_key, gossip_key)``. LND's path-dict uses
    # ``base_fee_msat`` / ``proportional_fee_rate`` /
    # ``htlc_min_msat`` / ``htlc_max_msat``; gossip uses
    # ``fee_base_msat`` / ``fee_rate_milli_msat`` / ``min_htlc`` /
    # ``max_htlc_msat``.
    refreshes = [
        ("base_fee_msat", "fee_base_msat"),
        ("proportional_fee_rate", "fee_rate_milli_msat"),
        ("htlc_min_msat", "min_htlc"),
        ("htlc_max_msat", "max_htlc_msat"),
    ]
    for path_key, gossip_key in refreshes:
        new_val = _to_int_or_none(policy.get(gossip_key))
        if new_val is None:
            continue
        old_val = _to_int_or_none(path.get(path_key))
        if old_val == new_val:
            continue
        diff[path_key] = {"old": old_val, "new": new_val}
        # LND's path dict accepts ints; ``encode_invoice_paths``
        # normalises via ``_to_int``.
        path[path_key] = new_val

    if diff:
        logger.info(
            "bolt12 path policy refresh: intro=%s refreshed from gossip — %s (chan_id=%s, last_update_age_s=%s)",
            intro_pubkey[:16],
            ",".join(f"{k}({v['old']}→{v['new']})" for k, v in diff.items()),
            chan_id,
            policy.get("last_update_age_s"),
        )
    return diff


def apply_payinfo_safety_margin(
    path: dict,
    *,
    margin_ppm: int,
    margin_base_msat: int,
) -> dict[str, Any]:
    """Pad ``path``'s encoded ``base_fee_msat`` /
    ``proportional_fee_rate`` by the configured safety margins.

    **Why this exists**: the gossip-refresh stage
    closes the LND-cache lag, but there is an ADDITIONAL structural
    cause: an intermediate hop's *actual* fee deduction at
    HTLC-forward time can exceed what it gossips. This is most
    likely a node-local ``setchannel`` policy that lags the gossip
    broadcast, or an auto-fee plugin (CLBOSS-style) that adjusts
    charges without re-gossiping.

    Effect on the payer: the BOLT 12 invoice tells them to budget
    a *slightly* higher fee than gossip predicts. They send extra
    msat into the path. The intro deducts their (higher-than-
    gossiped) actual fee; the excess pads through to our LND. The
    HTLC arrives at exactly the invoice amount OR a few msat
    above, and our LND settles.

    Mutates ``path`` in place. Also stamps two diagnostic fields:

    * ``_safety_margin_ppm_applied`` — what we added to ``proportional_fee_rate``
    * ``_safety_margin_base_msat_applied`` — what we added to ``base_fee_msat``

    These let ``failure_diagnostics.collect_path_policy_drift``
    subtract the deliberate margin before comparing against
    current gossip — otherwise every future audit row would
    falsely flag the margin as a policy-update divergence.

    Returns a small diff dict for logging (empty when both
    margins are 0).
    """
    margin_ppm = max(0, int(margin_ppm or 0))
    margin_base_msat = max(0, int(margin_base_msat or 0))
    # Always stamp the applied margins on the path even when zero
    # so the summary surfaces "we ran the stage and chose to apply
    # 0" vs "the stage didn't run" — a legacy row missing the key
    # is distinguishable from a row that recorded margin=0.
    path["_safety_margin_ppm_applied"] = margin_ppm
    path["_safety_margin_base_msat_applied"] = margin_base_msat
    if margin_ppm == 0 and margin_base_msat == 0:
        return {}

    diff: dict[str, Any] = {}
    if margin_ppm > 0:
        # LND returns ``proportional_fee_rate`` as int; tolerate
        # string for safety.
        try:
            old_ppm = int(path.get("proportional_fee_rate") or 0)
        except (TypeError, ValueError):
            old_ppm = 0
        new_ppm = old_ppm + margin_ppm
        path["proportional_fee_rate"] = new_ppm
        diff["proportional_fee_rate"] = {
            "old": old_ppm,
            "new": new_ppm,
            "margin": margin_ppm,
        }
    if margin_base_msat > 0:
        try:
            old_base = int(path.get("base_fee_msat") or 0)
        except (TypeError, ValueError):
            old_base = 0
        new_base = old_base + margin_base_msat
        path["base_fee_msat"] = new_base
        diff["base_fee_msat"] = {
            "old": old_base,
            "new": new_base,
            "margin": margin_base_msat,
        }

    if diff:
        intro = (path.get("_intro_pubkey_hex") or "?")[:16]
        logger.info(
            "bolt12 path payinfo margin: intro=%s padded — %s",
            intro,
            ",".join(f"{k}({v['old']}→{v['new']}, +{v['margin']})" for k, v in diff.items()),
        )
    return diff


def clamp_path_htlc_max(
    path: dict,
    channels: list[dict],
    our_pubkey: str,
    *,
    safety_buffer_ppm: int,
) -> dict:
    """Clamp implementation: mutate ``path`` in place, setting
    ``htlc_max_msat`` to ``min(advertised, terminal_remote_balance
    - safety_buffer)``.

    When we can't identify the terminal channel, fall back to
    ``min(advertised, max_channel_remote_balance - safety_buffer)``
    — the most-permissive safe bound. Better to leave the path
    slightly over-advertised than to clamp every path to the
    smallest channel's bound (which would underutilise the wallet's
    larger channels).

    Adds two diagnostic fields to ``path``:

    * ``_htlc_max_msat_advertised`` — the original value from LND
    * ``_terminal_peer_pubkey`` — pubkey of the identified terminal
      peer (``None`` if not identified)
    """
    advertised = int(path.get("htlc_max_msat") or 0)
    path["_htlc_max_msat_advertised"] = advertised

    terminal_ch = _identify_terminal_channel(path, channels, our_pubkey)
    if terminal_ch is not None:
        cap_sat = _safe_cap_sat(
            int(terminal_ch.get("remote_balance") or 0),
            safety_buffer_ppm,
        )
        path["_terminal_peer_pubkey"] = terminal_ch.get("remote_pubkey")
    else:
        # Conservative-permissive fallback: use the LARGEST channel's
        # cap. No path we own can carry more than our largest
        # channel's remote_balance; that's the safe upper bound.
        max_remote = max(
            (int(ch.get("remote_balance") or 0) for ch in channels),
            default=0,
        )
        cap_sat = _safe_cap_sat(max_remote, safety_buffer_ppm)
        path["_terminal_peer_pubkey"] = None

    cap_msat = cap_sat * 1000
    if cap_msat > 0 and cap_msat < advertised:
        # The clamp derives from the live ``remote_balance``; advertising it
        # raw would disclose the wallet's receivable balance to any payer that
        # reads the invoice back. Round DOWN to a coarse bucket so the
        # disclosed ceiling stays a safe upper bound for routing while
        # revealing only the bucket floor, not the exact balance.
        disclosed = _bucket_floor_msat(cap_msat, int(settings.bolt12_htlc_max_bucket_msat))
        path["htlc_max_msat"] = disclosed
        if disclosed <= 0:
            # The live capacity is below one disclosure bucket: it cannot carry
            # a bucket's worth, and advertising ``htlc_max_msat=0`` would be an
            # invalid payinfo (and would itself signal a near-drained channel).
            # Mark it so the pipeline drops it unconditionally, regardless of
            # the ``bolt12_drop_undersized_paths`` setting.
            path["_clamped_below_bucket"] = True
        # DEBUG, not INFO: the line carries peer pubkeys + capacity detail that
        # together form a topology/balance trail in a durable log.
        logger.debug(
            "bolt12 path clamp: intro=%s clamped htlc_max %d → %d msat (terminal_peer=%s)",
            (path.get("_intro_pubkey_hex") or "?")[:16],
            advertised,
            disclosed,
            (path.get("_terminal_peer_pubkey") or "?unidentified")[:16],
        )
    return path


def _bucket_floor_msat(value_msat: int, bucket_msat: int) -> int:
    """Round ``value_msat`` DOWN to a multiple of ``bucket_msat``.

    Rounding down keeps the result ``<= value_msat`` so it stays a safe upper
    bound for routing. ``bucket_msat <= 0`` disables bucketing (returns the
    value unchanged).
    """
    if bucket_msat <= 0:
        return value_msat
    return (value_msat // bucket_msat) * bucket_msat


# ── drop undersized paths ──────────────────────


def path_meets_amount(path: dict, amount_msat: int) -> bool:
    """A path is usable only if its (clamped) ``htlc_max_msat``
    can carry the requested amount AND its ``htlc_min_msat`` is
    not larger than the amount. Without this check, the wallet
    would ask the payer to attempt a path it knows cannot succeed.
    """
    htlc_max = int(path.get("htlc_max_msat") or 0)
    htlc_min = int(path.get("htlc_min_msat") or 0)
    if htlc_max and htlc_max < amount_msat:
        return False
    if htlc_min and htlc_min > amount_msat:
        return False
    return True


# ── lightweight liveness probe ─────────────────


async def probe_path_liveness(
    path: dict,
    lnd: LNDService,
    *,
    connected_peer_pubkeys: set[str] | None = None,
    channels: list[dict] | None = None,
) -> bool:
    """Return True if this path is "alive" — intro is reachable
    and the identified terminal channel is active.

    "Probe" is a misnomer: we do NOT traverse the actual blinded
    path. That would require a real onion forward at small but
    nonzero cost, and adds significant latency. Instead we sanity-
    check the two things we CAN observe cheaply:

    * Is the intro_pubkey currently a peer of our LND? (Or
      reachable via a recent gossip-confirmed connection?)
    * If we identified the terminal hop, is that channel
      currently ``active``?

    This catches the "intro disconnected" and "our channel went
    offline mid-mint" failure modes. It does NOT catch
    intermediate-hop liquidity problems — those require actual
    traversal.

    On any LND error, returns True (fail-open): better to
    advertise a possibly-bad path than to drop everything if our
    liveness probe is itself flaky.
    """
    intro_hex = path.get("_intro_pubkey_hex")
    if not intro_hex:
        return True  # nothing to check

    try:
        if connected_peer_pubkeys is None:
            connected_peer_pubkeys = await _fetch_connected_peers(lnd)
    except Exception:  # noqa: BLE001
        logger.exception("bolt12 path probe: peer-list fetch failed")
        return True

    # Intro must be reachable. We accept either "directly connected
    # peer" or — for paths where the intro is a peer-of-peer —
    # presence in our LND's gossip graph (so the intro is at least
    # known to us). We can't verify gossip-graph liveness without
    # real probes, so this is a weak signal at best.
    if intro_hex not in connected_peer_pubkeys:
        # Intro is not directly connected. We can't quickly verify
        # the intro is alive; pass through so we don't drop paths
        # whose intros happen to be peer-of-peer.
        pass
    else:
        # Intro IS one of our peers. Verify the relevant channel
        # is active.
        terminal_pubkey = path.get("_terminal_peer_pubkey") or intro_hex
        if channels is None:
            return True
        match_chs = [ch for ch in channels if ch.get("remote_pubkey") == terminal_pubkey]
        if match_chs and not any(ch.get("active") for ch in match_chs):
            logger.info(
                "bolt12 path probe: terminal peer %s has no active channel — dropping path",
                terminal_pubkey[:16],
            )
            return False
    return True


async def _fetch_connected_peers(lnd: LNDService) -> set[str]:
    """LND ``ListPeers`` REST call → set of pubkey hex strings."""
    data, err = await lnd._request("GET", "/v1/peers")
    if err is not None or not isinstance(data, dict):
        return set()
    out: set[str] = set()
    for p in data.get("peers", []):
        pk = p.get("pub_key") or ""
        if pk:
            out.add(pk)
    return out


# ── diversity by intro_pubkey ──────────────────


def _path_effective_fee_msat(path: dict, amount_msat: int) -> int:
    """Compute the fee a payer would pay for this path at the
    requested amount. Used as the tiebreaker when multiple paths
    share an intro."""
    base = int(path.get("base_fee_msat") or 0)
    ppm = int(path.get("proportional_fee_rate") or 0)
    return base + (amount_msat * ppm) // 1_000_000


def select_diverse_paths(
    paths: list[dict],
    amount_msat: int,
    *,
    max_count: int,
) -> list[dict]:
    """Keep at most one path per ``intro_pubkey``, prefer the
    lowest-effective-fee one. Then truncate to ``max_count``
    sorted by fee ascending (cheapest first).

    When ``BOLT12_PATH_DIVERSITY_ENFORCE=false``, the caller skips
    this function. Otherwise this is the only filter; an
    additional pass to keep the cheapest N is implicit in the
    truncate.
    """
    by_intro: dict[str, dict] = {}
    for p in paths:
        intro = p.get("_intro_pubkey_hex") or ""
        if not intro:
            # No intro known — keep under a synthetic key so we
            # don't accidentally cluster multiple unknown paths.
            intro = f"_unknown_{id(p)}"
        fee = _path_effective_fee_msat(p, amount_msat)
        existing = by_intro.get(intro)
        if existing is None or fee < _path_effective_fee_msat(existing, amount_msat):
            by_intro[intro] = p
    chosen = sorted(
        by_intro.values(),
        key=lambda p: _path_effective_fee_msat(p, amount_msat),
    )
    return chosen[:max_count]


# ── per-intro circuit breaker ──────────────────


@dataclass
class _BreakerState:
    """In-memory state for one ``intro_pubkey``'s breaker."""

    state: str = "closed"  # closed | open | half_open
    consecutive_failures: int = 0
    opened_at: float = 0.0  # monotonic
    cooldown_s: float = 0.0
    probationary_probe_claimed: bool = False
    """True while a half-open intro has had its one probationary
    probe issued but not yet resolved (no record_failure /
    record_success has come back). Concurrent mints arriving in
    this window treat the intro as ``open`` so we don't fire
    N parallel probes at an already-suspect intro."""

    def is_effectively_open(self, *, now: float) -> bool:
        """Return True when the path-selection logic should
        treat this intro as DEPRIORITISED. Combines two cases:

        * Hard open — cooldown not yet elapsed
        * Half-open but probationary probe already in flight —
          one probe is enough; second concurrent mint deferred
        """
        if self.state == "open" and (now - self.opened_at) < self.cooldown_s:
            return True
        if self.state == "half_open" and self.probationary_probe_claimed:
            return True
        return False

    def can_probe_half_open(self, *, now: float) -> bool:
        """An open intro becomes half-open once its cooldown
        elapses. The next mint that considers this intro gets a
        single probationary attempt; subsequent mints during
        half-open MUST go to other intros (so we don't flood the
        already-suspect intro with retries)."""
        if self.state != "open":
            return False
        return (now - self.opened_at) >= self.cooldown_s


class PathBreakerRegistry:
    """Module-level registry of per-intro breakers.

    In-memory only. Resets on wallet restart — deliberate, so
    stale judgments never carry across deployments.

    **Process-local state**: this registry lives in each Python
    process's memory. Failure / success signals from one process
    do NOT reach the registry in another process. In our
    deployment:

    * The API process runs the responder (path selection) AND
      the HtlcEvent + settlement subscribers (signal sources).
      Failures observed via HtlcEvent ``link_failed`` /
      ``forward_failed`` and successes via the settlement stream
      DO reach the API's breaker — so path selection learns from
      them.
    * The Celery worker process runs the settle watchdog (which
      detects the "minted but never settled" pattern). Its
      breaker updates happen in the Celery process and don't
      affect the API's selection. The watchdog's audit-row
      emission is the operator-facing signal; breaker updates in
      this process are effectively no-ops for path selection.

    **Known limitation**: HTLCs that die UPSTREAM (before
    reaching our LND) produce no HtlcEvent. The API breaker
    therefore does not learn from upstream-death failures. The
    ``htlc_max`` clamp is the primary fix for that class; the
    breaker covers the "HTLC reached us and our LND rejected it"
    class.

    Thread-safe insofar as Python's GIL guarantees dict access
    atomicity. Coroutines on a single event loop are not
    preempted mid-access.
    """

    # Hard cap on tracked intro nodes so the per-intro breaker map can't
    # grow without bound across the process lifetime. On overflow the
    # oldest-inserted entry is evicted (dicts preserve insertion order);
    # a re-encountered intro simply re-initialises with a clean breaker.
    _MAX_ENTRIES = 8192

    def __init__(self) -> None:
        self._intros: dict[str, _BreakerState] = {}

    def _get(self, intro_pubkey_hex: str) -> _BreakerState:
        st = self._intros.get(intro_pubkey_hex)
        if st is None:
            st = _BreakerState()
            self._intros[intro_pubkey_hex] = st
            while len(self._intros) > self._MAX_ENTRIES:
                oldest = next(iter(self._intros))
                del self._intros[oldest]
        return st

    def record_failure(self, intro_pubkey_hex: str) -> None:
        """A path through this intro failed (e.g., settle
        watchdog timed out, or HtlcEvent link-failed)."""
        if not intro_pubkey_hex:
            return
        st = self._get(intro_pubkey_hex)
        st.consecutive_failures += 1
        # The probationary probe (if any) has now resolved —
        # release the one-probe latch regardless of which branch
        # we hit below.
        st.probationary_probe_claimed = False

        if st.state == "half_open":
            # Failed during probationary attempt → re-open with
            # doubled cooldown (capped).
            st.state = "open"
            st.cooldown_s = min(
                st.cooldown_s * 2.0 if st.cooldown_s else settings.bolt12_path_breaker_initial_cooldown_s,
                float(settings.bolt12_path_breaker_cooldown_cap_s),
            )
            st.opened_at = time.monotonic()
            logger.warning(
                "bolt12 path breaker: intro %s re-opened (half-open probe failed; cooldown=%.0fs)",
                intro_pubkey_hex[:16],
                st.cooldown_s,
            )
            return

        threshold = settings.bolt12_path_breaker_failures_to_open
        if st.consecutive_failures >= threshold and st.state == "closed":
            st.state = "open"
            st.cooldown_s = float(settings.bolt12_path_breaker_initial_cooldown_s)
            st.opened_at = time.monotonic()
            logger.warning(
                "bolt12 path breaker: intro %s OPENED after %d failures (cooldown=%.0fs)",
                intro_pubkey_hex[:16],
                st.consecutive_failures,
                st.cooldown_s,
            )

    def record_success(self, intro_pubkey_hex: str) -> None:
        """A settle observed through this intro — closes the
        breaker (or re-confirms it closed) and resets failure
        history."""
        if not intro_pubkey_hex:
            return
        st = self._get(intro_pubkey_hex)
        prior_state = st.state
        st.state = "closed"
        st.consecutive_failures = 0
        st.cooldown_s = 0.0
        st.opened_at = 0.0
        st.probationary_probe_claimed = False
        if prior_state != "closed":
            logger.info(
                "bolt12 path breaker: intro %s CLOSED (recovery confirmed)",
                intro_pubkey_hex[:16],
            )

    def is_open(self, intro_pubkey_hex: str, *, now: float | None = None) -> bool:
        if not intro_pubkey_hex or intro_pubkey_hex not in self._intros:
            return False
        st = self._intros[intro_pubkey_hex]
        n = now if now is not None else time.monotonic()
        # Tick state forward: if we've crossed the cooldown,
        # transition open → half-open lazily and arm the
        # one-probationary-probe latch.
        if st.can_probe_half_open(now=n):
            st.state = "half_open"
            st.probationary_probe_claimed = False
            logger.info(
                "bolt12 path breaker: intro %s → half_open (cooldown elapsed)",
                intro_pubkey_hex[:16],
            )
        # If we're returning False for a half-open intro, this
        # caller is the one whose mint will probe — claim the
        # latch so subsequent concurrent lookups see "open" until
        # record_success or record_failure resolves the state.
        effectively_open = st.is_effectively_open(now=n)
        if not effectively_open and st.state == "half_open" and not st.probationary_probe_claimed:
            st.probationary_probe_claimed = True
        return effectively_open

    def snapshot(self) -> dict[str, dict]:
        """Diagnostic snapshot for ``/v1/bolt12/status`` exposure."""
        out: dict[str, dict] = {}
        now = time.monotonic()
        for intro, st in self._intros.items():
            out[intro] = {
                "state": st.state,
                "consecutive_failures": st.consecutive_failures,
                "cooldown_s_remaining": max(0.0, st.cooldown_s - (now - st.opened_at)) if st.state == "open" else 0.0,
                "probationary_probe_in_flight": (st.state == "half_open" and st.probationary_probe_claimed),
            }
        return out

    def reset_for_tests(self) -> None:
        self._intros.clear()


# Module singleton — same pattern as the Bolt12Runtime singleton.
_PATH_BREAKER = PathBreakerRegistry()


def get_path_breaker() -> PathBreakerRegistry:
    return _PATH_BREAKER


def all_intros_open(paths: list[dict]) -> bool:
    """Return True iff EVERY path's intro is in the breaker's
    ``open`` state. Used by the responder's adaptive-depth
    fallback to decide whether to re-mint at the alternative hop
    depth.

    Returns False when ``paths`` is empty (no paths to evaluate
    means "nothing's known-bad", not "all bad").
    """
    if not paths:
        return False
    if not settings.bolt12_path_breaker_enabled:
        return False
    breaker = get_path_breaker()
    return all(breaker.is_open(p.get("_intro_pubkey_hex") or "") for p in paths)


def apply_breaker_filter(paths: list[dict]) -> list[dict]:
    """Reorder paths so any whose intros are ``open`` come LAST.
    Does NOT remove them — even a deprioritised path is preferable
    to a silent drop when no alternatives exist.

    Returns a new list; does not mutate.
    """
    if not settings.bolt12_path_breaker_enabled:
        return list(paths)
    breaker = get_path_breaker()
    healthy: list[dict] = []
    deprioritised: list[dict] = []
    for p in paths:
        intro = p.get("_intro_pubkey_hex") or ""
        if breaker.is_open(intro):
            deprioritised.append(p)
        else:
            healthy.append(p)
    if deprioritised:
        logger.info(
            "bolt12 path breaker: %d/%d paths deprioritised",
            len(deprioritised),
            len(paths),
        )
    return healthy + deprioritised


# ── Path metadata extraction (intro + real_hops) ─────────────


def annotate_path_metadata(path: dict) -> None:
    """Decode the per-path metadata fields (intro_pubkey hex,
    real_hops) onto private attributes so the downstream
    pipeline stages don't each re-parse the wire format."""
    inner = path.get("blinded_path") if isinstance(path.get("blinded_path"), dict) else {}
    intro_b64 = inner.get("introduction_node", "") if isinstance(inner, dict) else ""
    try:
        intro_bytes = base64.b64decode(intro_b64) if intro_b64 else b""
    except (ValueError, TypeError):
        intro_bytes = b""
    path["_intro_pubkey_hex"] = intro_bytes.hex() if intro_bytes else ""
    blinded_hops = inner.get("blinded_hops") if isinstance(inner, dict) else None
    path["_real_hops"] = max(0, len(blinded_hops or []) - 1)


def build_paths_summary(paths: list[dict]) -> dict[str, Any]:
    """Distill the postprocessed paths into the JSON shape stored
    on ``Bolt12Invoice.blinded_paths_summary``. Used by the settle
    watchdog + settlement subscriber to update the breaker without
    decoding the bech32 invoice blob.

    The ``encoded_*`` fields capture the fee/cltv/htlc-bounds triplet
    we put into the blinded-path payload at mint time. The settle
    watchdog re-queries each intro's current advertised policy at
    failure time and compares the two — if the values diverged
    between mint and HTLC arrival, that points at a
    policy-update race rather than a Tor blip.
    """
    return {
        "paths": [
            {
                "intro_pubkey": p.get("_intro_pubkey_hex"),
                "real_hops": p.get("_real_hops"),
                "htlc_max_msat_advertised": p.get(
                    "_htlc_max_msat_advertised",
                    p.get("htlc_max_msat"),
                ),
                "htlc_max_msat_clamped": int(p.get("htlc_max_msat") or 0),
                "terminal_peer_pubkey": p.get("_terminal_peer_pubkey"),
                "encoded_base_fee_msat": p.get("base_fee_msat"),
                "encoded_proportional_fee_rate": p.get("proportional_fee_rate"),
                "encoded_total_cltv_delta": p.get("total_cltv_delta"),
                "encoded_htlc_min_msat": p.get("htlc_min_msat"),
                # Deliberate over-quote on top of the
                # refresh-corrected gossip. ``failure_diagnostics``
                # subtracts these before comparing encoded vs
                # current gossip so we never falsely flag the
                # margin as a policy-update divergence.
                "safety_margin_ppm_applied": p.get("_safety_margin_ppm_applied"),
                "safety_margin_base_msat_applied": p.get("_safety_margin_base_msat_applied"),
            }
            for p in paths
        ],
    }


# ── Pipeline orchestrator ────────────────────────────────────


@dataclass
class PostprocessResult:
    paths: list[dict]
    summary: dict[str, Any]
    drops: dict[str, int] = field(default_factory=dict)


async def postprocess_blinded_paths(
    raw_paths: list[dict],
    *,
    amount_msat: int,
    lnd: LNDService,
    channels: list[dict],
    our_pubkey: str,
    max_paths: int,
) -> PostprocessResult:
    """Run the full pipeline. Always returns at least the input
    path list (possibly mutated, possibly reordered) — the
    responder owns the "0 paths after filtering" decision since
    its existing fallback to ``num_hops=1`` already handles that
    case.
    """
    drops = {
        "starting": len(raw_paths),
        "after_clamp": 0,
        "after_undersized_drop": 0,
        "after_probe": 0,
        "after_diversity": 0,
        "deprioritised_by_breaker": 0,
    }

    # Annotate metadata first (intro_pubkey, real_hops) so
    # pigeonhole pairing can compute effective fees.
    for p in raw_paths:
        annotate_path_metadata(p)

    # Refresh each path's encoded policy from the
    # intro's current gossip BEFORE pigeonhole/clamp/diversity.
    # LND's path-builder uses a stale per-channel ``channel_update``
    # cache; the BOLT 12 invoice signed off by us must reflect the
    # intro's current fees or the payer underpays and the HTLC
    # fails at our LND. Pigeonhole sorts by aggregate fee, so the
    # refresh must run BEFORE it. Best-effort; if gossip is
    # unavailable the path stays as LND returned it.
    if settings.bolt12_blinded_path_refresh_policy_from_gossip:
        for p in raw_paths:
            try:
                await refresh_path_policy_from_gossip(
                    p,
                    lnd,
                    our_pubkey=our_pubkey,
                    channels=channels,
                )
            except Exception:  # noqa: BLE001
                logger.debug(
                    "bolt12 postprocess: policy refresh raised for intro=%s — leaving path unchanged",
                    (p.get("_intro_pubkey_hex") or "?")[:16],
                    exc_info=True,
                )

    # PAYINFO safety margin. Closes the residual gossip-vs-actual-
    # fee gap where an intermediate hop deducts more than it
    # gossips. Runs AFTER refresh so the margin is
    # applied on top of the refresh-corrected gossip values, and
    # BEFORE clamp so the summary's downstream diagnostic fields
    # see the margin. Unconditional pure-Python op; no LND RTT.
    for p in raw_paths:
        try:
            apply_payinfo_safety_margin(
                p,
                margin_ppm=int(settings.bolt12_blinded_path_payinfo_safety_margin_ppm),
                margin_base_msat=int(settings.bolt12_blinded_path_payinfo_safety_margin_base_msat),
            )
        except Exception:  # noqa: BLE001
            logger.debug(
                "bolt12 postprocess: payinfo margin raised for intro=%s",
                (p.get("_intro_pubkey_hex") or "?")[:16],
                exc_info=True,
            )

    # Pigeonhole pairing — assigns ``_presumed_terminal_channel``
    # to each path when N paths == N usable channels. Strategy A
    # in ``_identify_terminal_channel`` picks this up.
    _pigeonhole_pair_paths_to_channels(
        raw_paths,
        channels,
        amount_msat=amount_msat,
    )

    for p in raw_paths:
        clamp_path_htlc_max(
            p,
            channels,
            our_pubkey,
            safety_buffer_ppm=settings.bolt12_htlc_max_safety_buffer_ppm,
        )
    # Drop paths the clamp reduced below one disclosure bucket — advertising
    # htlc_max_msat=0 is invalid and leaks a near-drained channel. This runs
    # regardless of ``bolt12_drop_undersized_paths`` because a 0 cap is never
    # a usable advertisement.
    raw_paths = [p for p in raw_paths if not p.get("_clamped_below_bucket")]
    drops["after_clamp"] = len(raw_paths)

    # drop undersized
    if settings.bolt12_drop_undersized_paths:
        paths = [p for p in raw_paths if path_meets_amount(p, amount_msat)]
        if len(paths) < len(raw_paths):
            logger.info(
                "bolt12 postprocess: dropped %d undersized paths (amount=%d msat)",
                len(raw_paths) - len(paths),
                amount_msat,
            )
    else:
        paths = list(raw_paths)
    drops["after_undersized_drop"] = len(paths)

    # liveness probe (off by default)
    if settings.bolt12_probe_paths_before_mint and paths:
        connected = await _fetch_connected_peers(lnd)
        live_paths: list[dict] = []
        for p in paths:
            if await probe_path_liveness(
                p,
                lnd,
                connected_peer_pubkeys=connected,
                channels=channels,
            ):
                live_paths.append(p)
        if len(live_paths) < len(paths):
            logger.info(
                "bolt12 postprocess: %d paths failed liveness probe",
                len(paths) - len(live_paths),
            )
        paths = live_paths
    drops["after_probe"] = len(paths)

    # diversity
    if settings.bolt12_path_diversity_enforce and len(paths) > 1:
        paths = select_diverse_paths(
            paths,
            amount_msat,
            max_count=max_paths,
        )
    drops["after_diversity"] = len(paths)

    # per-intro breaker (reorder, don't drop)
    if settings.bolt12_path_breaker_enabled:
        paths = apply_breaker_filter(paths)
        deprio = 0
        breaker = get_path_breaker()
        for p in paths:
            intro = p.get("_intro_pubkey_hex") or ""
            if breaker.is_open(intro):
                deprio += 1
        drops["deprioritised_by_breaker"] = deprio

    summary = build_paths_summary(paths)
    return PostprocessResult(paths=paths, summary=summary, drops=drops)


__all__ = [
    "PathBreakerRegistry",
    "PostprocessResult",
    "all_intros_open",
    "annotate_path_metadata",
    "apply_breaker_filter",
    "apply_payinfo_safety_margin",
    "build_paths_summary",
    "clamp_path_htlc_max",
    "get_path_breaker",
    "path_meets_amount",
    "postprocess_blinded_paths",
    "probe_path_liveness",
    "refresh_path_policy_from_gossip",
    "select_diverse_paths",
    "_pigeonhole_pair_paths_to_channels",
]
