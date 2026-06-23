# SPDX-License-Identifier: MIT
"""Settle-timeout failure diagnostics (2026-06-13).

When the BOLT 12 settle watchdog fires on an open invoice, we add
two extra signals to the audit row to discriminate between the
hypotheses for *why* the payer failed inside the blinded path:

1. **Encoded-vs-current policy comparison** for each intro hop.
   We already persist what we encoded (``encoded_base_fee_msat``,
   ``encoded_proportional_fee_rate``, ``encoded_total_cltv_delta``,
   ``encoded_htlc_min_msat``) on ``blinded_paths_summary`` at mint
   time. Here we re-query each intro's *currently advertised*
   policy via ``/v1/graph/edge`` and pair the two — a divergence
   between mint and HTLC arrival points at a policy-update race,
   not a Tor blip.

2. **LND-side HTLC view** for the invoice's payment hash. Polling
   mode silently drops streaming HTLC events, so a failed forward
   is normally invisible to us. The LND invoice's ``htlcs`` array
   still records any HTLCs that *reached our LND* (even if
   subsequently CANCELED or never reached ACCEPTED), so reading
   it on watchdog tick tells us whether the failure was upstream
   (Megalithic→us) or final-hop (our LND rejected).

Hot-path principles: best-effort only — every helper returns
``None``/``{}`` on error and is wrapped in ``try/except`` by the
caller. Never block or escalate the watchdog's audit-emit path on
a failed diagnostic query.
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


def _extract_peer_side_policy(
    edge: dict | None,
    *,
    our_pubkey: str,
    peer_pubkey: str,
    now_epoch: float | None = None,
) -> dict | None:
    """Return ``edge``'s policy attributed to ``peer_pubkey`` (the
    side forwarding TO us). LND sorts the pair lexicographically
    as ``node1_pub``/``node2_pub`` and reports each direction's
    outbound policy under ``node{1,2}_policy``.

    Only the policy fields relevant to a BOLT 12 blinded-path
    forward decision are returned, keyed by their gossip names
    (no renaming) so a reader can grep the audit row against the
    LND wire shape.

    The derived ``last_update_age_s`` is added on top of the raw
    ``last_update`` epoch — a low value (< ~60 s) is the strongest
    single signal of a policy-update race between mint and HTLC
    arrival. Pass ``now_epoch`` for deterministic tests; default
    is ``time.time()``.
    """
    if not isinstance(edge, dict):
        return None
    node1 = edge.get("node1_pub", "")
    node2 = edge.get("node2_pub", "")
    if node1 == peer_pubkey and node2 == our_pubkey:
        policy = edge.get("node1_policy")
    elif node2 == peer_pubkey and node1 == our_pubkey:
        policy = edge.get("node2_policy")
    else:
        policy = None
    if not isinstance(policy, dict):
        return None
    last_update_raw = policy.get("last_update")
    last_update_age_s: int | None = None
    try:
        if last_update_raw is not None and last_update_raw != "":
            now = now_epoch if now_epoch is not None else time.time()
            last_update_age_s = max(0, int(now) - int(last_update_raw))
    except (TypeError, ValueError):
        last_update_age_s = None
    return {
        "fee_base_msat": policy.get("fee_base_msat"),
        "fee_rate_milli_msat": policy.get("fee_rate_milli_msat"),
        "time_lock_delta": policy.get("time_lock_delta"),
        "min_htlc": policy.get("min_htlc"),
        "max_htlc_msat": policy.get("max_htlc_msat"),
        "disabled": policy.get("disabled"),
        "last_update": last_update_raw,
        "last_update_age_s": last_update_age_s,
    }


async def query_intro_policy_now(
    lnd: Any,
    *,
    intro_pubkey: str,
) -> dict | None:
    """Look up the channel(s) we have with ``intro_pubkey`` and
    return their current peer-side advertised policy from gossip.

    Returns ``None`` when the intro isn't a direct peer (i.e., it's
    a multi-hop blinded path's entry), when channel-edge lookup
    fails, or when the gossiped policy is missing. Otherwise
    returns a dict ``{"chan_id": str, "policy": {...}}``; if we
    have multiple channels with the same peer, the first one wins
    (the audit row is for discrimination, not exhaustive coverage).
    """
    try:
        info, info_err = await lnd.get_info()
        if info_err or not isinstance(info, dict):
            return None
        our_pubkey = info.get("identity_pubkey", "") or ""
        if not our_pubkey:
            return None

        channels, ch_err = await lnd.get_channels()
        if ch_err or not channels:
            return None
        target_chans = [ch for ch in channels if isinstance(ch, dict) and ch.get("remote_pubkey") == intro_pubkey]
        if not target_chans:
            return None
        chan_id = target_chans[0].get("chan_id")
        if not chan_id:
            return None

        edge, edge_err = await lnd.get_channel_edge(chan_id)
        if edge_err or edge is None:
            return None
        policy = _extract_peer_side_policy(
            edge,
            our_pubkey=our_pubkey,
            peer_pubkey=intro_pubkey,
        )
        if policy is None:
            return None
        return {"chan_id": chan_id, "policy": policy}
    except Exception:  # noqa: BLE001
        logger.debug(
            "bolt12 failure diag: intro policy lookup raised for %s",
            (intro_pubkey or "")[:16],
            exc_info=True,
        )
        return None


def _to_int_or_none(v: Any) -> int | None:
    """Coerce ``v`` to ``int``; return ``None`` if missing/blank/
    non-numeric. LND's gossip wire returns integer fields as
    strings (``"1100"``), so we always normalise."""
    if v in (None, ""):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _diff_encoded_vs_current(
    *,
    comparisons: list[tuple[str, Any, Any]],
) -> dict[str, dict[str, Any]]:
    """Compute a per-field divergence dict from a list of
    ``(output_key, encoded_value, current_value)`` triples.

    A field is flagged as divergent ONLY when both sides are
    present AND unequal after integer-normalisation. Fields where
    either side is missing are silently skipped — we cannot
    compare, so we do not pretend to. This avoids two false-
    positive classes:

    * **Legacy rows** minted before the encoded-triplet shipped:
      their ``encoded`` side is None; flagging would mark every
      such row as "all fields drifted" when in fact we just
      don't have the data.
    * **Gossip unavailable** (LND breaker open during diagnostic
      query): ``current`` side is None; flagging would attribute
      a divergence to a query failure.

    Both halves of the comparison stay visible to the reader in
    the per-intro ``encoded`` / ``current`` blocks of the audit
    row — only the *divergence summary* is silenced when the
    comparison is impossible.
    """
    diff: dict[str, dict[str, Any]] = {}
    for output_key, e_val, c_val in comparisons:
        e_int = _to_int_or_none(e_val)
        c_int = _to_int_or_none(c_val)
        if e_int is None or c_int is None:
            continue  # can't compare → don't flag
        if e_int == c_int:
            continue
        diff[output_key] = {"encoded": e_int, "current": c_int}
    return diff


async def collect_path_policy_drift(
    lnd: Any,
    paths_summary: dict | None,
) -> list[dict[str, Any]]:
    """Walk the paths in ``paths_summary`` and, for each intro,
    pair what we encoded into the blinded-path payload (or
    advertised in the summary) against the intro's currently
    advertised gossip policy. Returns a list of per-path dicts
    safe to embed in an audit row.

    Output shape (one entry per path)::

        {
          "intro_pubkey": "02a98c…",
          "encoded": {                       # source-of-truth for the audit
            "base_fee_msat": 1100,
            "proportional_fee_rate": 1206,
            "total_cltv_delta": 201,         # path-aggregate, NOT per-hop
            "htlc_min_msat": 1100,
            "htlc_max_msat_advertised": 133650000,
          },
          "current": {                       # gossip right now
            "chan_id": "1042763633773182977",
            "policy": { ... LND wire shape ... },
          } | None,
          "divergence": {                    # only fields that diverged
            "fee_rate_milli_msat": {"encoded": 1206, "current": 1500},
          },
        }

    Divergence semantics:

    * ``fee_base_msat``, ``fee_rate_milli_msat``, ``min_htlc``, and
      ``max_htlc_msat`` are gossip fields we encode directly
      from the intro's then-advertised policy → 1:1 comparable.
      A divergence here is a real policy-update race.
    * ``time_lock_delta`` (gossip) is the intro's per-hop CLTV
      delta; ``encoded_total_cltv_delta`` is the path-AGGREGATE
      (per-hop × real_hops + final padding). The two are NOT
      directly comparable, so we surface both for the reader but
      do NOT auto-flag them as divergent — false-positive risk
      outweighs the diagnostic value.
    * Fields where either side is None are skipped (legacy row
      or gossip query failure) — see ``_diff_encoded_vs_current``.
    """
    if not isinstance(paths_summary, dict):
        return []
    paths = paths_summary.get("paths") or []
    out: list[dict[str, Any]] = []
    for p in paths:
        if not isinstance(p, dict):
            continue
        intro = p.get("intro_pubkey")
        if not intro:
            continue
        current = await query_intro_policy_now(lnd, intro_pubkey=intro)
        encoded = {
            "base_fee_msat": p.get("encoded_base_fee_msat"),
            "proportional_fee_rate": p.get("encoded_proportional_fee_rate"),
            "total_cltv_delta": p.get("encoded_total_cltv_delta"),
            "htlc_min_msat": p.get("encoded_htlc_min_msat"),
            "htlc_max_msat_advertised": p.get("htlc_max_msat_advertised"),
        }
        # 2026-06-14: subtract the safety margin from the encoded
        # fee fields before comparing against gossip. We
        # DELIBERATELY over-quote the payer above gossip to
        # absorb undisclosed-margin behavior (see ``apply_payinfo_
        # safety_margin``); without this subtraction, every audit
        # row would show ``fee_base_msat`` / ``fee_rate_milli_msat``
        # divergence equal to the margin and drown out real
        # gossip drift signals.
        ppm_margin = _to_int_or_none(p.get("safety_margin_ppm_applied")) or 0
        base_margin = _to_int_or_none(p.get("safety_margin_base_msat_applied")) or 0
        base_for_compare = (
            (encoded["base_fee_msat"] - base_margin)
            if encoded["base_fee_msat"] is not None and base_margin > 0
            else encoded["base_fee_msat"]
        )
        ppm_for_compare = (
            (encoded["proportional_fee_rate"] - ppm_margin)
            if encoded["proportional_fee_rate"] is not None and ppm_margin > 0
            else encoded["proportional_fee_rate"]
        )
        policy = (current or {}).get("policy") or {}
        # Output keys use the LND-gossip name so the audit row
        # reader can grep against the wire shape. Each entry is
        # (output_key, encoded_value, current_value).
        comparisons = [
            (
                "fee_base_msat",
                base_for_compare,
                policy.get("fee_base_msat"),
            ),
            (
                "fee_rate_milli_msat",
                ppm_for_compare,
                policy.get("fee_rate_milli_msat"),
            ),
            (
                "min_htlc",
                encoded["htlc_min_msat"],
                policy.get("min_htlc"),
            ),
            (
                "max_htlc_msat",
                encoded["htlc_max_msat_advertised"],
                policy.get("max_htlc_msat"),
            ),
        ]
        divergence = _diff_encoded_vs_current(comparisons=comparisons)
        out.append(
            {
                "intro_pubkey": intro,
                "encoded": encoded,
                "current": current,
                "divergence": divergence,
                "safety_margin_ppm_applied": ppm_margin,
                "safety_margin_base_msat_applied": base_margin,
            }
        )
    return out


async def query_invoice_htlc_state(
    lnd: Any,
    *,
    payment_hash_hex: str,
) -> dict | None:
    """Return LND's view of the invoice for ``payment_hash_hex``,
    including the raw ``htlcs`` array (NOT exposed by the
    higher-level ``lookup_invoice`` wrapper). The ``htlcs`` array
    records every HTLC that reached our LND for this invoice —
    including ones that were ACCEPTED-then-CANCELED — so a
    non-empty list disproves "the HTLC never arrived" hypothesis.

    Returns the subset of fields useful for failure diagnosis;
    ``None`` on lookup failure.
    """
    try:
        data, err = await lnd._request(
            "GET",
            f"/v1/invoice/{payment_hash_hex}",
        )
        if err or not isinstance(data, dict):
            return None
        htlcs_raw = data.get("htlcs") or []
        # Trim each HTLC to the diagnostic-relevant fields so we
        # don't bloat audit rows with custom-records / encrypted
        # payloads. ``state`` is the key signal (ACCEPTED, SETTLED,
        # CANCELED) — paired with the cltv/amt to discriminate
        # "wrong amount/cltv at final hop" from "never arrived".
        htlcs: list[dict[str, Any]] = []
        for h in htlcs_raw:
            if not isinstance(h, dict):
                continue
            htlcs.append(
                {
                    "state": h.get("state"),
                    "amt_msat": h.get("amt_msat") or h.get("amt"),
                    "accept_time": h.get("accept_time"),
                    "resolve_time": h.get("resolve_time"),
                    "expiry_height": h.get("expiry_height"),
                    "chan_id": h.get("chan_id"),
                    "htlc_index": h.get("htlc_index"),
                }
            )
        return {
            "state": data.get("state"),
            "amt_paid_msat": data.get("amt_paid_msat"),
            "htlcs": htlcs,
        }
    except Exception:  # noqa: BLE001
        logger.debug(
            "bolt12 failure diag: invoice htlc lookup raised for %s",
            (payment_hash_hex or "")[:16],
            exc_info=True,
        )
        return None


__all__ = [
    "collect_path_policy_drift",
    "query_intro_policy_now",
    "query_invoice_htlc_state",
]
