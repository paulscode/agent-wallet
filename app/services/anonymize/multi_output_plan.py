# SPDX-License-Identifier: MIT
"""Multi-output session plan.

A multi-output session produces N base-layer outputs at N user-
supplied destination addresses, each with its own bin amount and
randomized schedule offset. This module owns:

* :class:`OutputSpec` — the per-output value object.
* :class:`MultiOutputPlan` — the session-level container.
* :func:`validate_multi_output_plan` — refuses invalid plans (count
  cap, distinct addresses, in-binset amounts, monotonic indices).
* :func:`sample_schedule_offsets_s` — per-output randomized offsets
  in the ``[ANONYMIZE_MULTI_OUTPUT_SCHEDULE_MIN_S,
  ANONYMIZE_MULTI_OUTPUT_SCHEDULE_MAX_S]`` band, sorted ascending.
* :func:`persist_outputs` — writes :class:`AnonymizeSessionOutput`
  rows for the plan; the caller commits.

The actual quote-builder + state-machine wiring (accepting an
N-destination request, dispatching the per-output egress) lands
alongside this layer in a follow-on session.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable, Sequence
from uuid import UUID

from app.core.config import settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from .quote_token import QuoteTokenKeySet


class MultiOutputPlanError(ValueError):
    """Raised when a multi-output plan is rejected at validation."""


@dataclass(frozen=True)
class OutputSpec:
    """Per-output specification.

    ``destination_address`` is the cleartext bech32 / base58 string
    that the quote layer eventually Fernet-wraps into
    ``destination_address_enc``. ``destination_script_type`` follows
    the existing single-output column (``p2tr``, ``p2wpkh``, etc.).
    """

    destination_address: str
    destination_script_type: str
    bin_amount_sat: int


@dataclass(frozen=True)
class MultiOutputPlan:
    """The full session-level plan."""

    session_id: UUID
    outputs: Sequence[OutputSpec]


def validate_multi_output_plan(plan: MultiOutputPlan) -> None:
    """Refuse plans that violate the invariants.

    Refusal cases:

    * Empty output list — caller must use the single-output path.
    * Count exceeds ``ANONYMIZE_MULTI_OUTPUT_MAX_COUNT`` — operators
      compose multiple sessions for larger fan-out.
    * Two outputs share a destination address — defeats
      reuse detection at the same time as it leaks
      "this user has 2x the same destination" to a chain observer.
    * Any output's ``bin_amount_sat`` is not in the
      ``ANONYMIZE_AMOUNT_BINS_SAT`` set — defeats amount
      binning.
    * Any output's ``bin_amount_sat`` is non-positive.
    * ``destination_script_type`` empty — the retention pass
      reads this column for script-type-preserved redactions.
    * The sum of all ``bin_amount_sat`` exceeds
      ``ANONYMIZE_MULTI_OUTPUT_MAX_TOTAL_SAT`` — the aggregate value
      ceiling, so the count cap cannot multiply the per-output bound.
    """
    if not plan.outputs:
        raise MultiOutputPlanError("multi-output plan must have at least one output")
    max_count = int(settings.anonymize_multi_output_max_count)
    if len(plan.outputs) > max_count:
        raise MultiOutputPlanError(
            f"multi-output plan has {len(plan.outputs)} outputs; ANONYMIZE_MULTI_OUTPUT_MAX_COUNT is {max_count}"
        )

    bins = set(settings.anonymize_amount_bins_list)
    seen_addresses: set[str] = set()
    for i, spec in enumerate(plan.outputs):
        if not spec.destination_address:
            raise MultiOutputPlanError(f"output #{i}: destination_address must be non-empty")
        if not spec.destination_script_type:
            raise MultiOutputPlanError(f"output #{i}: destination_script_type must be non-empty")
        if spec.bin_amount_sat <= 0:
            raise MultiOutputPlanError(f"output #{i}: bin_amount_sat must be positive")
        if bins and spec.bin_amount_sat not in bins:
            raise MultiOutputPlanError(
                f"output #{i}: bin_amount_sat={spec.bin_amount_sat} is not in ANONYMIZE_AMOUNT_BINS_SAT"
            )
        if spec.destination_address in seen_addresses:
            raise MultiOutputPlanError(
                f"output #{i}: destination_address {spec.destination_address!r} duplicates an earlier output"
            )
        seen_addresses.add(spec.destination_address)

    # Aggregate value ceiling. Each output is independently within
    # [min_sat, max_sat], but the sum must also stay within the
    # session-level ceiling so the output count cannot multiply the
    # single-output value bound.
    total = sum(int(s.bin_amount_sat) for s in plan.outputs)
    max_total = int(settings.anonymize_multi_output_max_total_sat)
    if total > max_total:
        raise MultiOutputPlanError(
            f"multi-output plan total {total} exceeds ANONYMIZE_MULTI_OUTPUT_MAX_TOTAL_SAT {max_total}"
        )


def sample_schedule_offsets_s(
    n: int,
    *,
    rng: secrets.SystemRandom | None = None,
    now_unix_s: float | None = None,
) -> list[float]:
    """Sample ``n`` per-output schedule offsets, sorted ascending.

    Each offset is drawn uniformly from
    ``[ANONYMIZE_MULTI_OUTPUT_SCHEDULE_MIN_S,
    ANONYMIZE_MULTI_OUTPUT_SCHEDULE_MAX_S]``. The output list is
    sorted so the orchestrator can iterate output_index by ascending
    schedule_at_unix_s.

    Returned values are *absolute* unix seconds (now + offset), not
    relative — the caller persists them directly into
    ``anonymize_session_output.scheduled_at_unix_s``.

    ``n=0`` returns the empty list. Inverted config (max < min)
    collapses to a single-value point at min.
    """
    if n <= 0:
        return []
    rng = rng or secrets.SystemRandom()
    lo = int(settings.anonymize_multi_output_schedule_min_s)
    hi = int(settings.anonymize_multi_output_schedule_max_s)
    base = now_unix_s if now_unix_s is not None else datetime.now(timezone.utc).timestamp()
    if hi < lo:
        # Inverted config — degenerate to all-at-min so an operator
        # who misconfigures min/max can still ship.
        return [base + float(lo)] * n
    offsets = [base + rng.uniform(float(lo), float(hi)) for _ in range(n)]
    offsets.sort()
    return offsets


async def persist_outputs(
    db: AsyncSession,
    *,
    plan: MultiOutputPlan,
    encrypt_address: "Callable[[str], bytes]",
    blake2b_keyed: "Callable[[str], bytes]",
    reuse_key_generation: int,
    schedule_offsets_unix_s: Sequence[float] | None = None,
) -> None:
    """Write :class:`AnonymizeSessionOutput` rows for the plan.

    The caller injects the same address-encryption + reuse-detection
    helpers the single-output path uses so the data layer stays
    consistent. ``schedule_offsets_unix_s`` is normally produced by
    :func:`sample_schedule_offsets_s`; ``None`` is allowed (e.g.,
    test fixtures) and leaves the column NULL.

    The caller commits.
    """
    from app.models.anonymize_session import AnonymizeSessionOutput

    if schedule_offsets_unix_s is not None and (len(schedule_offsets_unix_s) != len(plan.outputs)):
        raise MultiOutputPlanError("schedule_offsets_unix_s length must match plan.outputs length")

    for i, spec in enumerate(plan.outputs):
        addr_enc = encrypt_address(spec.destination_address)
        addr_hash = blake2b_keyed(spec.destination_address)
        scheduled = float(schedule_offsets_unix_s[i]) if schedule_offsets_unix_s is not None else None
        db.add(
            AnonymizeSessionOutput(
                session_id=plan.session_id,
                output_index=i,
                destination_address_enc=addr_enc,
                destination_script_type=spec.destination_script_type,
                bin_amount_sat=int(spec.bin_amount_sat),
                scheduled_at_unix_s=scheduled,
                destination_address_blake2b_keyed=addr_hash,
                destination_reuse_key_generation=int(reuse_key_generation),
            )
        )


@dataclass(frozen=True)
class MultiOutputQuoteRequest:
    """Multi-output flavor of :class:`QuoteRequest`.

    Each ``(destination_address, requested_amount_sat)`` pair is
    validated independently using the same single-output destination
    parser + amount quantizer the existing flow uses, then the batch
    as a whole is validated through :func:`validate_multi_output_plan`.

    The ``source_kind`` constraint matches the single-output rules
    (LN sources are admitted everywhere; on-chain sources require
    distinct Boltz operator configuration).
    """

    source_kind: str
    destinations: Sequence[tuple[str, int]]  # [(address, requested_amount_sat), ...]
    cookie_subject: str
    canonical_request_body: bytes


def build_multi_output_plan_from_request(
    request: MultiOutputQuoteRequest,
    *,
    session_id: UUID,
) -> MultiOutputPlan:
    """Produce a validated :class:`MultiOutputPlan` from an N-destination
    quote request.

    Mirrors the destination-validation + amount-binning shape of
    :func:`quote_builder.build_quote` but for the multi-output path.
    Each destination is parsed once with
    :func:`address.parse_and_validate_destination` (network check +
    script-type extraction); each requested amount is quantized via
    :func:`policy.quantize_to_bin`; the whole plan is then validated
    via :func:`validate_multi_output_plan` (distinct addresses, count
    cap, etc.).

    Raises :class:`MultiOutputPlanError` on any failure. The caller
    composes the per-output egress schedule via
    :func:`sample_schedule_offsets_s` and persists via
    :func:`persist_outputs`.
    """
    from .address import DestinationRejectedError, parse_and_validate_destination
    from .policy import quantize_to_bin

    if not request.destinations:
        raise MultiOutputPlanError("multi-output quote request must have at least one destination")

    if request.source_kind not in {
        "lightning-self",
        "ext-lightning",
        "onchain-self",
        "ext-onchain",
    }:
        raise MultiOutputPlanError(f"unsupported source kind: {request.source_kind!r}")
    if request.source_kind in {"onchain-self", "ext-onchain"}:
        from .operators import has_distinct_legs_configured

        if not has_distinct_legs_configured():
            raise MultiOutputPlanError("on-chain sources require distinct Boltz operator URLs ")

    min_sat = int(settings.anonymize_min_sat)
    max_sat = int(settings.anonymize_max_sat)
    bins = settings.anonymize_amount_bins_list

    specs: list[OutputSpec] = []
    for i, (addr, amount) in enumerate(request.destinations):
        try:
            requested_amount_sat = int(amount)
        except (TypeError, ValueError) as exc:
            raise MultiOutputPlanError(f"output #{i}: requested_amount_sat must be int") from exc
        if not (min_sat <= requested_amount_sat <= max_sat):
            raise MultiOutputPlanError(
                f"output #{i}: requested_amount_sat={requested_amount_sat} outside [{min_sat}, {max_sat}]"
            )
        try:
            dest_addr, script_type = parse_and_validate_destination(addr)
        except DestinationRejectedError as exc:
            raise MultiOutputPlanError(f"output #{i}: destination rejected: {exc}") from exc
        bin_amount = quantize_to_bin(requested_amount_sat, bins)
        specs.append(
            OutputSpec(
                destination_address=dest_addr,
                destination_script_type=script_type,
                bin_amount_sat=int(bin_amount),
            )
        )

    plan = MultiOutputPlan(session_id=session_id, outputs=specs)
    validate_multi_output_plan(plan)
    return plan


# ── Quote-token-bound flow ──────────────────────────────────────────


@dataclass(frozen=True)
class MultiOutputQuoteResult:
    """Builder output for the multi-output quote endpoint.

    Mirrors the single-output :class:`quote_builder.QuoteResult` but
    carries the per-output bin amounts (one per destination, in
    input order) instead of a singular ``bin_amount_sat``.
    """

    quote_token: str
    bin_amounts_sat: list[int]
    issued_at_unix_s: int
    ttl_s: int


def _canonical_multi_output_pipeline_json(
    *,
    source_kind: str,
    plan: "MultiOutputPlan",
) -> bytes:
    """Serialise the multi-output pipeline to the canonical JSON form
    that gets MAC-bound into the quote token."""
    import json as _json

    obj = {
        "schema_version": 10,
        "flow_kind": "multi_output",
        "source": {"kind": source_kind},
        "outputs": [
            {
                "address": spec.destination_address,
                "bin_amount_sat": int(spec.bin_amount_sat),
                "script_type": spec.destination_script_type,
            }
            for spec in plan.outputs
        ],
    }
    return _json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_multi_output_canonical_pipeline_json(
    canonical: bytes,
) -> tuple[str, list[OutputSpec]]:
    """Inverse of :func:`_canonical_multi_output_pipeline_json`.

    Returns ``(source_kind, outputs)``. Raises
    :class:`MultiOutputPlanError` when the JSON is missing the
    multi-output marker (``flow_kind == "multi_output"``) — the
    session-create endpoint uses that to reject single-output
    tokens at the multi-output surface.
    """
    import json as _json

    try:
        obj = _json.loads(canonical)
    except Exception as exc:  # noqa: BLE001
        raise MultiOutputPlanError(f"canonical_pipeline_json is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise MultiOutputPlanError("canonical_pipeline_json is not a JSON object")
    if obj.get("flow_kind") != "multi_output":
        raise MultiOutputPlanError("canonical_pipeline_json is not a multi-output plan")
    source_kind = obj.get("source", {}).get("kind", "")
    if not isinstance(source_kind, str) or not source_kind:
        raise MultiOutputPlanError("canonical_pipeline_json missing source.kind")
    raw_outputs = obj.get("outputs", [])
    if not isinstance(raw_outputs, list) or not raw_outputs:
        raise MultiOutputPlanError("canonical_pipeline_json missing outputs")
    outputs: list[OutputSpec] = []
    for i, raw in enumerate(raw_outputs):
        if not isinstance(raw, dict):
            raise MultiOutputPlanError(f"output #{i} is not a JSON object")
        addr = raw.get("address", "")
        amount = raw.get("bin_amount_sat", 0)
        script_type = raw.get("script_type", "")
        if not isinstance(addr, str) or not addr or not isinstance(script_type, str) or not script_type:
            raise MultiOutputPlanError(f"output #{i} is missing address/script_type")
        try:
            amount_int = int(amount)
        except (TypeError, ValueError) as exc:
            raise MultiOutputPlanError(f"output #{i} bin_amount_sat is not int") from exc
        outputs.append(
            OutputSpec(
                destination_address=addr,
                destination_script_type=script_type,
                bin_amount_sat=amount_int,
            )
        )
    return source_kind, outputs


def build_multi_output_quote(
    request: "MultiOutputQuoteRequest",
    *,
    keyset: "QuoteTokenKeySet",
    session_id: UUID | None = None,
    now_unix_s: int | None = None,
) -> MultiOutputQuoteResult:
    """Produce a signed quote token covering an N-destination plan.

    Mirrors :func:`quote_builder.build_quote` shape but binds the
    multi-output canonical pipeline JSON into the token. The token
    carries:

    * The full per-output destination + amount + script_type list
      (in ``canonical_pipeline_json``).
    * The cookie-subject HMAC (defeats cross-cookie replay).
    * The canonical request-body hash (defeats body mutation).
    * The TTL window from ``ANONYMIZE_QUOTE_TOKEN_TTL_S``.

    The session-create endpoint validates the token + parses the
    multi-output pipeline back out to drive persistence.
    """
    import hashlib
    import time

    from .quote_builder import _hmac_cookie_subject
    from .quote_token import QuoteTokenPayload, sign_quote_token

    # ``session_id`` is only used by the underlying validator to
    # construct the plan object; the *real* session id is generated
    # at session-create time. Use a deterministic placeholder so the
    # quote-build path doesn't unnecessarily consume entropy.
    sid = session_id if session_id is not None else UUID(int=0)
    plan = build_multi_output_plan_from_request(request, session_id=sid)

    canonical = _canonical_multi_output_pipeline_json(
        source_kind=request.source_kind,
        plan=plan,
    )
    issued = int(now_unix_s) if now_unix_s is not None else int(time.time())
    ttl = int(settings.anonymize_quote_token_ttl_s)
    cookie_hmac = _hmac_cookie_subject(
        request.cookie_subject,
        keyset.active_key,
    )
    body_hash = hashlib.sha256(request.canonical_request_body).digest()

    payload = QuoteTokenPayload(
        canonical_pipeline_json=canonical,
        bin_amount_sat=sum(s.bin_amount_sat for s in plan.outputs),
        submarine_operator_id=None,
        reverse_operator_id=None,
        delay_min_s=int(settings.anonymize_default_delay_min_s),
        delay_max_s=int(settings.anonymize_default_delay_max_s),
        inter_leg_min_s=None,
        inter_leg_max_s=None,
        requested_mpp_k=0,
        issued_at_unix_s=issued,
        ttl_s=ttl,
        cookie_subject_hmac=cookie_hmac,
        canonical_request_body_hash=body_hash,
    )
    token = sign_quote_token(payload, keyset=keyset)
    return MultiOutputQuoteResult(
        quote_token=token,
        bin_amounts_sat=[int(s.bin_amount_sat) for s in plan.outputs],
        issued_at_unix_s=issued,
        ttl_s=ttl,
    )


__all__ = [
    "MultiOutputPlan",
    "MultiOutputPlanError",
    "MultiOutputQuoteRequest",
    "MultiOutputQuoteResult",
    "OutputSpec",
    "build_multi_output_plan_from_request",
    "build_multi_output_quote",
    "parse_multi_output_canonical_pipeline_json",
    "persist_outputs",
    "sample_schedule_offsets_s",
    "validate_multi_output_plan",
]
