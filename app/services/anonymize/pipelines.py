# SPDX-License-Identifier: MIT
"""Anonymize pipeline / hop dataclasses + normalization invariant.

A *pipeline* is an ordered list of hops with a typed source and exit.
The invariant — "every on-chain source must traverse a submarine
hop as the first hop, and there is at most one submarine hop in any
pipeline" — is enforced both at session-creation time and at hop-
execution boundaries (so a corrupted DB row cannot bypass the rule).

The lightning-side sources use the ``ln_self_pay`` + ``reverse``
hops; the on-chain self-source and Liquid round-trip paths add the
rest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from app.models.anonymize_session import AnonymizeSourceKind

# Ordered set of hop kinds, in roughly the order they appear in a
# pipeline. ``ln_self_pay`` and ``reverse`` serve the LN-source path;
# the others are accepted by validators only when their feature guard
# is enabled.
HopKind = Literal["submarine", "ln_self_pay", "priv_channel", "liquid", "reverse"]


@dataclass(frozen=True)
class Source:
    """Pipeline source (where the sats come from).

    For ``ext-lightning`` sources the depositor pays one of:

    * ``deposit_invoice`` — a blinded BOLT 11 payment-request (the
      legacy single-use path).
    * ``deposit_bolt12_offer`` — a BOLT 12 offer string (``lno1...``).
      The wallet's existing BOLT 12 responder signs an invoice when
      the depositor's wallet sends an ``invoice_request``. The offer
      is bound to the session via :attr:`deposit_offer_id` so the
      anonymize-side reconciliation can join the inbound
      :class:`Bolt12Invoice` row back to the session.
    * ``deposit_bip353_handle`` — an optional ``user@domain`` BIP-353
      handle whose DNS TXT record carries the same BOLT 12 offer.
      Only populated when ``ANONYMIZE_BIP353_DEPOSIT_DOMAIN`` is
      configured; the operator publishes the corresponding TXT
      record out-of-band (manual zone-file edit, DNS provider API,
      etc. — the wallet emits the record contents but does not
      reach out to a DNS host).

    BOLT 11 and BOLT 12 deposit modes are mutually exclusive on a
    single session; the session-create endpoint enforces this.
    """

    kind: str  # AnonymizeSourceKind value
    selected_outpoints: tuple[str, ...] = ()  # onchain-self only
    deposit_invoice: str | None = None  # ext-lightning BOLT 11
    deposit_address: str | None = None  # ext-onchain, set post-create
    # BOLT 12 deposit fields. Only one of ``deposit_invoice`` /
    # ``deposit_bolt12_offer`` may be set on a given ext-lightning
    # session.
    deposit_method: str | None = None  # "bolt11" | "bolt12" | None
    deposit_bolt12_offer: str | None = None
    deposit_offer_id: str | None = None  # bolt12_offers.id (UUID string)
    deposit_bip353_handle: str | None = None
    deposit_bip353_txt_record: str | None = None  # zone-file fragment


@dataclass(frozen=True)
class Hop:
    """Single hop in a pipeline."""

    kind: str  # HopKind value
    # Hop-specific parameters carried opaquely through pipeline_json.
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Exit:
    """Pipeline exit primitive.

    Two kinds are supported:

    * ``"reverse"`` — a Boltz reverse swap whose final on-chain
      output lands at ``destination_address``. This is the default
      for raw-address destinations and for BIP-353 handles whose
      publisher includes a ``bitcoin:`` fallback in the BIP-21 URI.
    * ``"bolt12_pay"`` — a direct BOLT 12 payment to a resolved
      offer. Used when a BIP-353 handle publishes only ``lno=`` /
      ``lightning=`` (no on-chain fallback). The hop body pays via
      LND's blinded-path router; the session settles on the
      Lightning network with no on-chain exit.

    For the BOLT 12 case, ``destination_address`` carries the
    original BIP-353 handle (``user@domain``) so the session-reuse
    detection continues to hash a stable identifier.
    The ``bolt12_offer`` field holds the *resolved* offer string
    bound into the quote token — re-resolving at session-create
    time would let a tampered TXT response substitute a different
    offer mid-flight.
    """

    kind: Literal["reverse", "bolt12_pay"]
    destination_address: str
    cooperative_only: bool = True
    # Only populated when ``kind == "bolt12_pay"``: the resolved
    # BOLT 12 offer string the wallet will pay at exit time.
    bolt12_offer: str | None = None
    # Only populated when the input was a BIP-353 handle (regardless
    # of exit kind) — the original ``user@domain`` for audit.
    bip353_handle: str | None = None


@dataclass(frozen=True)
class DelayPolicy:
    """Intra-mix delay policy (LN-side default)."""

    kind: Literal["immediate", "uniform", "scheduled", "utc_window"] = "uniform"
    min_seconds: int = 3600
    max_seconds: int = 21600
    scheduled_start: int | None = None  # unix seconds
    scheduled_end: int | None = None
    utc_window_start_hour: int | None = None
    utc_window_end_hour: int | None = None


@dataclass(frozen=True)
class InterLegDelay:
    """On-chain inter-leg delay (floor 6h, ceiling 48h)."""

    min_seconds: int = 6 * 3600
    max_seconds: int = 48 * 3600


@dataclass(frozen=True)
class Pipeline:
    """Frozen pipeline policy persisted in ``anonymize_session.pipeline_json``."""

    schema_version: int
    source: Source
    hops: tuple[Hop, ...]
    exit: Exit
    bin_amount_sat: int
    delay_policy: DelayPolicy
    inter_leg_delay: InterLegDelay | None = None


class PipelineValidationError(ValueError):
    """Raised when a pipeline violates or the bounds."""


def validate_pipeline(
    pipeline: Pipeline,
    *,
    max_hops: int,
    max_pipeline_json_bytes: int | None = None,
) -> None:
    """Enforce normalization invariant + bounds.

    Run at session-creation time and re-asserted at hop-execution
    boundaries by the orchestrator. ``max_pipeline_json_bytes`` is the
     / item 53 size cap applied to ``pipeline_to_json(pipeline)``.
    """
    if len(pipeline.hops) > max_hops:
        raise PipelineValidationError(f"pipeline exceeds max_hops={max_hops} ({len(pipeline.hops)} hops)")
    if max_pipeline_json_bytes is not None:
        encoded = pipeline_to_json(pipeline)
        if len(encoded) > max_pipeline_json_bytes:
            raise PipelineValidationError(
                f"pipeline_json size {len(encoded)} bytes exceeds limit {max_pipeline_json_bytes}"
            )

    src = pipeline.source.kind
    hops = pipeline.hops

    if src in {AnonymizeSourceKind.ONCHAIN_SELF.value, AnonymizeSourceKind.EXT_ONCHAIN.value}:
        if not hops or hops[0].kind != "submarine":
            raise PipelineValidationError("on-chain source requires a `submarine` first hop (normalization invariant)")
        if any(h.kind == "submarine" for h in hops[1:]):
            raise PipelineValidationError("pipeline contains more than one submarine hop")
    elif src in {AnonymizeSourceKind.LIGHTNING_SELF.value, AnonymizeSourceKind.EXT_LIGHTNING.value}:
        if any(h.kind == "submarine" for h in hops):
            raise PipelineValidationError("LN source must not include a submarine hop")
        # ext-lightning sources may carry either a BOLT 11 deposit
        # invoice or a BOLT 12 deposit offer, but never both. The two
        # deposit modes feed entirely different LND code paths
        # (AddInvoice vs. the BOLT 12 responder), and accepting both
        # at once would let an attacker race the depositor's payments
        # across two listeners. Refuse the combination at the
        # validation boundary.
        has_bolt11 = bool((pipeline.source.deposit_invoice or "").strip())
        has_bolt12 = bool((pipeline.source.deposit_bolt12_offer or "").strip())
        if has_bolt11 and has_bolt12:
            raise PipelineValidationError(
                "ext-lightning source must not carry both a deposit_invoice "
                "and a deposit_bolt12_offer; the two modes are mutually "
                "exclusive"
            )
        # A BIP-353 handle is only meaningful when a BOLT 12 offer is
        # also present — the handle's DNS TXT record points at the
        # offer. Without an offer the handle has nothing to publish.
        if (pipeline.source.deposit_bip353_handle or "").strip() and not has_bolt12:
            raise PipelineValidationError("deposit_bip353_handle requires a non-empty deposit_bolt12_offer")
    else:
        raise PipelineValidationError(f"unknown source kind: {src!r}")

    if pipeline.exit.kind not in {"reverse", "bolt12_pay"}:
        raise PipelineValidationError(f"exit kind must be 'reverse' or 'bolt12_pay', got {pipeline.exit.kind!r}")

    if pipeline.exit.kind == "bolt12_pay":
        # BOLT 12 exit settles on LN — only LN sources have outbound
        # capacity to pay an offer. On-chain sources would need to
        # swap their balance into LN first, which the pipeline
        # accomplishes via a submarine hop; we don't yet support
        # that composition. Reject the combination loudly so a
        # later wiring change doesn't accidentally produce a
        # session that can't make progress.
        if src in {
            AnonymizeSourceKind.ONCHAIN_SELF.value,
            AnonymizeSourceKind.EXT_ONCHAIN.value,
        }:
            raise PipelineValidationError(
                "bolt12_pay exit requires an LN source kind "
                "(lightning-self or ext-lightning); on-chain sources "
                "with BOLT 12 destinations are not yet supported"
            )
        if not (pipeline.exit.bolt12_offer or "").strip():
            raise PipelineValidationError("bolt12_pay exit requires a non-empty bolt12_offer")

    # Any pipeline containing a submarine hop MUST carry a
    # non-trivial inter-leg delay window. The mandatory delay defeats
    # the temporal-correlation channel between the on-chain submarine
    # leg and the off-chain reverse leg; an LN-only pipeline can
    # omit the field (the on-chain leg doesn't exist).
    if any(h.kind == "submarine" for h in hops):
        if pipeline.inter_leg_delay is None:
            raise PipelineValidationError(
                "pipeline containing a submarine hop requires an inter_leg_delay window (mandatory delay)"
            )
        if pipeline.inter_leg_delay.min_seconds <= 0:
            raise PipelineValidationError("inter_leg_delay.min_seconds must be positive for submarine pipelines")
        if pipeline.inter_leg_delay.max_seconds < pipeline.inter_leg_delay.min_seconds:
            raise PipelineValidationError("inter_leg_delay.max_seconds must be >= min_seconds")


# --------------------------------------------------------------------
# Frozen pipeline policy persistence.
#
# All execution-time policy reads from ``anonymize_session.pipeline_json``,
# never from live config. The schema version is bound into the JSON
# blob so a session created under a since-retired schema version
# transitions to ``awaiting_reconciliation`` rather than silently
# misexecuting on the new code path.
# --------------------------------------------------------------------


class PipelineSchemaTooOldError(PipelineValidationError):
    """Raised when a stored pipeline_json's schema_version is below the
    code's ``MIN_SUPPORTED_PIPELINE_SCHEMA_VERSION``."""


def pipeline_to_json(pipeline: Pipeline) -> bytes:
    """Serialize a frozen ``Pipeline`` to canonical JSON bytes.

    Canonical = sorted keys + no whitespace. The result is what gets
    persisted in ``anonymize_session.pipeline_json``; rotating the
    canonical form would break in-flight sessions, so this is
    schema-stable.
    """
    import json as _json

    obj = {
        "schema_version": pipeline.schema_version,
        "source": {
            "kind": pipeline.source.kind,
            "selected_outpoints": list(pipeline.source.selected_outpoints),
            "deposit_invoice": pipeline.source.deposit_invoice,
            "deposit_address": pipeline.source.deposit_address,
            "deposit_method": pipeline.source.deposit_method,
            "deposit_bolt12_offer": pipeline.source.deposit_bolt12_offer,
            "deposit_offer_id": pipeline.source.deposit_offer_id,
            "deposit_bip353_handle": pipeline.source.deposit_bip353_handle,
            "deposit_bip353_txt_record": (pipeline.source.deposit_bip353_txt_record),
        },
        "hops": [{"kind": h.kind, "params": h.params} for h in pipeline.hops],
        "exit": {
            "kind": pipeline.exit.kind,
            "destination_address": pipeline.exit.destination_address,
            "cooperative_only": pipeline.exit.cooperative_only,
            # New BOLT 12 fields — only meaningful for
            # ``kind == "bolt12_pay"``, but serialised on every exit
            # so the JSON shape is stable.
            "bolt12_offer": pipeline.exit.bolt12_offer,
            "bip353_handle": pipeline.exit.bip353_handle,
        },
        "bin_amount_sat": pipeline.bin_amount_sat,
        "delay_policy": {
            "kind": pipeline.delay_policy.kind,
            "min_seconds": pipeline.delay_policy.min_seconds,
            "max_seconds": pipeline.delay_policy.max_seconds,
            "scheduled_start": pipeline.delay_policy.scheduled_start,
            "scheduled_end": pipeline.delay_policy.scheduled_end,
            "utc_window_start_hour": pipeline.delay_policy.utc_window_start_hour,
            "utc_window_end_hour": pipeline.delay_policy.utc_window_end_hour,
        },
        "inter_leg_delay": (
            None
            if pipeline.inter_leg_delay is None
            else {
                "min_seconds": pipeline.inter_leg_delay.min_seconds,
                "max_seconds": pipeline.inter_leg_delay.max_seconds,
            }
        ),
    }
    return _json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pipeline_from_json(
    payload: dict | bytes | str,
    *,
    min_supported_schema_version: int,
) -> Pipeline:
    """Re-hydrate a frozen ``Pipeline`` from its persisted JSON form.

    Raises :class:`PipelineSchemaTooOldError` when the stored schema version
    is below ``min_supported_schema_version``.
    The orchestrator reads sessions through this helper exclusively so
    schema-too-old transitions route uniformly to
    ``awaiting_reconciliation``.
    """
    import json as _json

    if isinstance(payload, (bytes, str)):
        obj = _json.loads(payload)
    else:
        obj = payload

    schema_version = int(obj.get("schema_version", 0))
    if schema_version < min_supported_schema_version:
        raise PipelineSchemaTooOldError(
            f"pipeline schema_version={schema_version} is below the running "
            f"code's minimum supported schema_version={min_supported_schema_version}"
        )

    src = obj["source"]
    source = Source(
        kind=src["kind"],
        selected_outpoints=tuple(src.get("selected_outpoints", []) or []),
        deposit_invoice=src.get("deposit_invoice"),
        deposit_address=src.get("deposit_address"),
        deposit_method=src.get("deposit_method"),
        deposit_bolt12_offer=src.get("deposit_bolt12_offer"),
        deposit_offer_id=src.get("deposit_offer_id"),
        deposit_bip353_handle=src.get("deposit_bip353_handle"),
        deposit_bip353_txt_record=src.get("deposit_bip353_txt_record"),
    )
    hops = tuple(Hop(kind=h["kind"], params=dict(h.get("params", {}) or {})) for h in obj.get("hops", []))
    ex = obj["exit"]
    exit_ = Exit(
        kind=ex["kind"],
        destination_address=ex["destination_address"],
        cooperative_only=bool(ex.get("cooperative_only", True)),
        # New BOLT 12 fields — absent on legacy rows.
        bolt12_offer=ex.get("bolt12_offer"),
        bip353_handle=ex.get("bip353_handle"),
    )
    dp = obj["delay_policy"]
    delay_policy = DelayPolicy(
        kind=dp["kind"],
        min_seconds=int(dp["min_seconds"]),
        max_seconds=int(dp["max_seconds"]),
        scheduled_start=dp.get("scheduled_start"),
        scheduled_end=dp.get("scheduled_end"),
        utc_window_start_hour=dp.get("utc_window_start_hour"),
        utc_window_end_hour=dp.get("utc_window_end_hour"),
    )
    ild_obj = obj.get("inter_leg_delay")
    inter_leg = (
        None
        if ild_obj is None
        else InterLegDelay(
            min_seconds=int(ild_obj["min_seconds"]),
            max_seconds=int(ild_obj["max_seconds"]),
        )
    )
    return Pipeline(
        schema_version=schema_version,
        source=source,
        hops=hops,
        exit=exit_,
        bin_amount_sat=int(obj["bin_amount_sat"]),
        delay_policy=delay_policy,
        inter_leg_delay=inter_leg,
    )


__all__ = [
    "Source",
    "Hop",
    "Exit",
    "DelayPolicy",
    "InterLegDelay",
    "Pipeline",
    "PipelineValidationError",
    "PipelineSchemaTooOldError",
    "validate_pipeline",
    "pipeline_to_json",
    "pipeline_from_json",
]
