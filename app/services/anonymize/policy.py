# SPDX-License-Identifier: MIT
"""AnonymityScorer + fee estimator + jitter helpers.

This is a deterministic *heuristic* scorer. It exists to drive UI
copy and the hard-cap enforcement at execute time. It explicitly does
**not** claim to estimate true anonymity; the score is documented as
"weak / moderate / strong" with the breakdown shown verbatim.

The hard-cap logic is the load-bearing part — many.x mitigations
trade off a small amount of usability for a hard cap that no amount
of mixing can bypass (e.g., on-chain source without distinct operators
caps at `moderate` regardless of how many hops are added).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Literal

from .pipelines import Pipeline

Tier = Literal["weak", "moderate", "strong"]


_TIER_RANK: dict[Tier, int] = {"weak": 0, "moderate": 1, "strong": 2}


def min_tier(a: Tier, b: Tier) -> Tier:
    """Return the lower-ranked tier."""
    return a if _TIER_RANK[a] <= _TIER_RANK[b] else b


@dataclass
class PipelineEnv:
    """Inputs to the scorer that come from the live deployment, not the pipeline."""

    has_onchain_source: bool
    distinct_operators: bool
    amount_is_binned: bool
    exit_diversity: Literal["asn", "country", "off"]
    tor_process_shared_with_lnd: bool
    public_chain_backend_enabled: bool
    exact_audit_logs_enabled: bool
    destination_script_type: str
    plain_bolt11_ext_deposit: bool
    operator_registry_size: int
    has_funding_change: bool
    egress_endpoints_onion_only: bool
    in_flight_concurrent_sessions: int
    used_preconsolidation: bool
    audit_bucket_suppression_disabled: bool
    # Reverse-leg
    # volume drives the tier cap. The reverse operator's logs are the
    # only place the destination address is exposed; only reverse-leg
    # anonymity-set dilution materially affects destination privacy.
    # For LN-only and single-operator sessions this is the volume of
    # the single configured operator.
    reverse_attested_volume_satoshis: int
    # Drives a soft informational advisory note only; does
    # NOT affect tier. Zero / unset for LN-only and single-operator
    # paths (no separate submarine leg exists).
    submarine_attested_volume_satoshis: int
    operator_min_volume_multiple: int
    chain_anchor_redaction_disabled: bool
    registry_signature_verification_failed_at_load: bool


@dataclass
class ScoreReport:
    tier: Tier
    points: int
    cap: Tier
    breakdown: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def score(pipeline: Pipeline, env: PipelineEnv) -> ScoreReport:
    """Pipeline scorer.

    The math is intentionally simple. The notes list is the user-
    facing explanation — every cap should produce a note.
    """
    points = 0
    notes: list[str] = []
    breakdown: list[str] = []

    # ── source ───────────────────────────────────────────────────
    src = pipeline.source.kind
    if src in {"ext-lightning", "lightning-self"}:
        points += 3
        breakdown.append("source: lightning (no on-chain entry) +3")
    elif src == "ext-onchain":
        points += 1
        breakdown.append("source: ext-onchain +1")
    else:
        breakdown.append("source: onchain-self +0")

    # ── mixing hops ──────────────────────────────────────────────
    if any(h.kind == "ln_self_pay" for h in pipeline.hops):
        points += 1
        breakdown.append("hop: ln_self_pay +1")
    if any(h.kind == "priv_channel" for h in pipeline.hops):
        points += 2
        breakdown.append("hop: priv_channel +2")
    if any(h.kind == "liquid" for h in pipeline.hops):
        points += 3
        breakdown.append("hop: liquid +3")

    # ── timing ──────────────────────────────────────────────────
    if pipeline.delay_policy.min_seconds >= 3600:
        points += 1
        breakdown.append("timing: delay_policy.min_seconds ≥ 1 h +1")
    if env.has_onchain_source and pipeline.inter_leg_delay and pipeline.inter_leg_delay.min_seconds >= 6 * 3600:
        points += 1
        breakdown.append("timing: inter-leg delay ≥ 6 h +1")

    # ── swap protections ────────────────────────────────────────
    if pipeline.exit.cooperative_only:
        points += 1
        breakdown.append("exit: cooperative-only claim +1")
    if env.amount_is_binned:
        points += 1
        breakdown.append("amount: binned +1")
    if env.distinct_operators:
        points += 1
        breakdown.append("operators: distinct submarine/reverse +1")
    if env.exit_diversity == "asn":
        points += 1
        breakdown.append("tor: exit-relay ASN-distinct +1")

    # ── HARD CAPS ───────────────────────────────────────────────
    cap: Tier = "strong"
    if env.has_onchain_source and not env.distinct_operators:
        cap = min_tier(cap, "moderate")
        notes.append("on-chain source without distinct operators is capped at `moderate`")
    if env.has_onchain_source and not any(h.kind == "liquid" for h in pipeline.hops):
        cap = min_tier(cap, "moderate")
        notes.append("on-chain source without a Liquid round-trip is capped at `moderate`")
    if not env.amount_is_binned:
        cap = min_tier(cap, "weak")
        notes.append("un-binned amounts are capped at `weak`")
    if env.tor_process_shared_with_lnd:
        cap = min_tier(cap, "moderate")
        notes.append("shared Tor process with LND caps at `moderate`")
    if env.public_chain_backend_enabled:
        cap = min_tier(cap, "weak")
        notes.append("public chain backend or explorer links cap at `weak`")
    if env.exact_audit_logs_enabled:
        cap = min_tier(cap, "weak")
        notes.append("exact anonymize audit logs cap at `weak`")
    if env.destination_script_type not in {"p2tr", "p2wpkh"}:
        cap = min_tier(cap, "moderate")
        notes.append("uncommon destination script type caps at `moderate`")
    if env.plain_bolt11_ext_deposit:
        cap = min_tier(cap, "weak")
        notes.append("plain BOLT11 external deposit caps at `weak`")
    if env.has_onchain_source and env.operator_registry_size < 3:
        cap = min_tier(cap, "moderate")
        notes.append("on-chain source with fewer than 3 registered operators caps at `moderate`")
    if env.has_onchain_source and env.has_funding_change:
        cap = min_tier(cap, "weak")
        notes.append("on-chain source with submarine-funding change UTXO caps at `weak`")
    if not env.egress_endpoints_onion_only:
        cap = min_tier(cap, "weak")
        notes.append("non-onion external endpoints cap at `weak`")
    if env.in_flight_concurrent_sessions > 1:
        cap = min_tier(cap, "moderate")
        notes.append("more than one in-flight session caps at `moderate`")
    if env.used_preconsolidation:
        cap = min_tier(cap, "moderate")
        notes.append("on-chain source via pre-anonymize consolidation caps at `moderate`")
    if env.audit_bucket_suppression_disabled:
        cap = min_tier(cap, "weak")
        notes.append("audit-bucket k-anonymity disabled caps at `weak`")
    # Reverse-leg
    # volume drives the tier cap. Only the reverse operator's logs
    # contain the destination address; submarine-leg volume is not a
    # per-operator-compromise threat for destination privacy under
    # the no-collusion assumption.
    _volume_threshold = pipeline.bin_amount_sat * env.operator_min_volume_multiple
    if env.reverse_attested_volume_satoshis < _volume_threshold:
        cap = min_tier(cap, "moderate")
        if env.reverse_attested_volume_satoshis <= 0:
            notes.append(
                "Reverse-leg operator does not currently publish a 24-hour "
                "swap volume attestation. Tier is capped as a precaution, "
                "not because a low number was observed."
            )
        else:
            notes.append(
                "Reverse-leg operator's recent 24-hour swap volume is below "
                "the dilution floor for your bin amount — fewer simultaneous "
                "destinations to blend into, so the privacy tier is capped "
                "conservatively."
            )

    # Soft informational note on submarine-leg volume. Does
    # NOT affect tier. Fires only for on-chain sources where a
    # distinct submarine leg exists. Single-operator sessions skip
    # this entirely (the cap-to-moderate already speaks to the
    # operator's logs).
    if (
        env.has_onchain_source
        and env.submarine_attested_volume_satoshis > 0
        and env.submarine_attested_volume_satoshis < _volume_threshold
    ):
        _est_sessions = max(
            1,
            env.submarine_attested_volume_satoshis // max(1, pipeline.bin_amount_sat),
        )
        notes.append(
            f"Submarine-leg operator processes about {_est_sessions} "
            "session(s) at your bin size in 24 hours. This does NOT affect "
            "the tier (your destination is protected by the reverse leg's "
            "anonymity set), but matters if you're concerned about a "
            "scenario where both operators' logs become available to the "
            "same attacker."
        )
    if env.chain_anchor_redaction_disabled:
        cap = min_tier(cap, "weak")
        notes.append("chain-anchor redaction on retention is disabled — destination recoverable past redaction")
    if env.registry_signature_verification_failed_at_load:
        cap = min_tier(cap, "weak")
        notes.append("operator registry was loaded without signature verification — capped at `weak`")

    raw_tier: Tier = "weak" if points < 3 else "moderate" if points < 6 else "strong"
    final_tier = min_tier(raw_tier, cap)
    return ScoreReport(
        tier=final_tier,
        points=points,
        cap=cap,
        breakdown=breakdown,
        notes=notes,
    )


# --------------------------------------------------------------------
# Helpers used elsewhere (jitter feerate jitter, etc.)
# --------------------------------------------------------------------
def quantize_to_bin(amount_sat: int, bins: list[int]) -> int:
    """Quantize an amount down to the nearest bin.

    Returns 0 if the amount is below the smallest bin (caller should
    treat that as a validation error).
    """
    eligible = [b for b in sorted(bins) if b <= amount_sat]
    return eligible[-1] if eligible else 0


def random_uniform_int(rng: secrets.SystemRandom, min_s: int, max_s: int) -> int:
    """Inclusive ``Uniform(min_s, max_s)`` via ``SystemRandom``."""
    if max_s < min_s:
        raise ValueError(f"max_s ({max_s}) < min_s ({min_s})")
    return rng.randint(min_s, max_s)


__all__ = [
    "Tier",
    "PipelineEnv",
    "ScoreReport",
    "score",
    "min_tier",
    "quantize_to_bin",
    "random_uniform_int",
]
