# SPDX-License-Identifier: MIT
"""Build + sign a quote token.

The dashboard `POST /anonymize/quote` endpoint reads only local caches
(quote network silence). This module is the pure builder it
calls into: given the user's destination + requested amount + cookie
binding, it:

1. Validates the destination address against ``BITCOIN_NETWORK``.
2. Quantizes the amount to the configured bin set.
3. Samples per-session MPP-K and freezes it.
4. Builds the default :class:`Pipeline` (LN source →
   reverse exit, no intermediate hops; on-chain self-source wires
   in priv-channel + submarine).
5. Scores the pipeline against a `PipelineEnv` populated from
   live settings + the app's anonymize_health snapshot.
6. Builds + signs a :class:`QuoteTokenPayload` against the active
   keyset, binding the cookie subject + canonical request body
   (#7 OWASP A01/A03).

The result is a flat dict the endpoint serialises directly.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from app.core.config import settings

from .address import DestinationRejectedError, parse_and_validate_destination
from .cooperative_claim import (
    min_executed_chunks_for_target_tier,
    sample_requested_mpp_k,
)
from .operator_selection import OperatorSelectionResult
from .pipelines import (
    DelayPolicy,
    Exit,
    Hop,
    InterLegDelay,
    Pipeline,
    Source,
    pipeline_to_json,
    validate_pipeline,
)
from .policy import PipelineEnv, quantize_to_bin, score
from .quote_cache import (
    CacheEntry,
    CacheKey,
    get_quote_cache,
    is_entry_fresh,
    verify_cache_entry,
)
from .quote_token import (
    QuoteTokenKeySet,
    QuoteTokenPayload,
    sign_quote_token,
)


class QuoteBuildError(ValueError):
    """Raised when a quote request can't be built — caller maps to 422."""


@dataclass(frozen=True)
class QuoteRequest:
    """Input shape the endpoint validates before calling the builder."""

    source_kind: str
    destination_address: str
    requested_amount_sat: int
    cookie_subject: str  # the dashboard cookie subject (sub claim)
    canonical_request_body: bytes  # raw bytes of the request body
    # Option C — per-quote opt-in for the Liquid round-trip
    # hop. The runtime decision combines this with the operator-wide
    # ``ANONYMIZE_LIQUID_ENABLED`` master switch; defaults to False so
    # existing callers continue to get the LN-only pipeline.
    prefer_liquid: bool = False
    # Set when the destination came from a BIP-353 handle
    # whose record published only a BOLT 12 offer (no on-chain
    # fallback). The endpoint resolves the handle before calling the
    # builder; the builder then constructs a Lightning-exit pipeline
    # (no reverse swap) bound to the resolved offer. When ``None``
    # the builder follows the legacy reverse-exit path.
    exit_kind: Literal["reverse", "bolt12_pay"] = "reverse"
    bolt12_offer: str | None = None
    bip353_handle: str | None = None
    # Ext-lightning deposit method. Bound at quote-build
    # time so a tampered create-body cannot switch the deposit type
    # after the quote was signed. The string is mirrored into the
    # pipeline_json so the session-create branch knows whether to
    # mint a BOLT 11 invoice or a BOLT 12 offer. Only
    # ``"bolt11"`` and ``"bolt12"`` are accepted; the default
    # falls back to the operator-wide
    # ``ANONYMIZE_EXT_LIGHTNING_DEPOSIT_METHOD`` setting.
    deposit_method: Literal["bolt11", "bolt12"] | None = None
    # Explicit
    # per-session consent flag set by the SPA after the
    # chain-exhaustion modal. The selector reads this to decide
    # whether to consolidate on Boltz canonical (single-operator
    # fallback) when both alts fail. Defaults to False so a request
    # that didn't explicitly opt in cannot silently degrade.
    allow_single_operator_fallback: bool = False


@dataclass(frozen=True)
class QuoteResult:
    """Builder output the endpoint serialises directly to JSON."""

    quote_token: str
    bin_amount_sat: int
    advisory_tier: str
    advisory_tier_notes: list[str]
    min_executed_chunks_for_target_tier: int
    issued_at_unix_s: int
    ttl_s: int
    # Option C — True when the session will route through the
    # Liquid round-trip hop. Computed as ``request.prefer_liquid AND
    # anonymize_liquid_enabled``; the SPA renders this back to the
    # operator so an opt-in that the server downgraded (because the
    # operator has the master switch off) is visible.
    uses_liquid: bool = False
    # Operator-ID
    # fields the SPA renders directly. None for LN-only quotes.
    submarine_operator_id: str | None = None
    reverse_operator_id: str | None = None
    # Chain trajectory. ``primary_attempted`` / ``primary_status``
    # / ``selected`` / ``selection_source`` are flat fields the SPA
    # reads; ``attempted`` is the full per-candidate outcome list
    # (audit / lower-level tooling). All Nones / [] for LN-only.
    submarine_chain_primary_attempted: str | None = None
    submarine_chain_primary_status: str | None = None
    submarine_chain_selected: str | None = None
    submarine_chain_selection_source: str | None = None
    submarine_chain_attempted: list[dict] = field(default_factory=list)


def _hmac_cookie_subject(subject: str, key: bytes) -> bytes:
    """Bind the cookie subject opaquely so the audit chain never
    receives the cleartext."""
    return hmac.new(key, subject.encode("utf-8"), hashlib.sha256).digest()


def build_quote(
    request: QuoteRequest,
    *,
    keyset: QuoteTokenKeySet,
    operator_registry_size: int = 0,
    egress_endpoints_onion_only: bool = True,
    tor_process_shared_with_lnd: bool = False,
    audit_bucket_suppression_disabled: bool = False,
    chain_anchor_redaction_disabled: bool = False,
    public_chain_backend_enabled: bool = False,
    now_unix_s: int | None = None,
    # Pre-computed
    # selection from :func:`operator_selection.select_operators_for_onchain_session`.
    # Required for on-chain source kinds (the endpoint runs the async
    # selector before calling this synchronous builder). LN-only
    # sources can leave this None and the builder picks the single
    # registry operator for the reverse leg.
    selection: "OperatorSelectionResult | None" = None,
) -> QuoteResult:
    """Produce a signed quote token for ``request``.

    The optional kwargs are populated by the endpoint from app state
    (health snapshot, registry size). Defaults reflect an LN-source
    deployment with onion-only egress + no public chain backend.

    Raises :class:`QuoteBuildError` on:
    * malformed / wrong-network destination
    * amount outside ``[ANONYMIZE_MIN_SAT, ANONYMIZE_MAX_SAT]``
    * unsupported source kind (LN-source-only deployments admit LN
      sources only)
    """
    # On-chain sources are admitted only when the operator has
    # configured distinct submarine + reverse Boltz URLs.
    # Deployments without that configuration get a clear error
    # pointing at the required setting.
    if request.source_kind not in {
        "lightning-self",
        "ext-lightning",
        "onchain-self",
        "ext-onchain",
    }:
        raise QuoteBuildError(f"unsupported source kind: {request.source_kind!r}")
    # On-chain sources are *preferred* with two distinct
    # Boltz operators (one per swap leg) so neither operator
    # individually sees both ends of the mix. Single-operator
    # deployments are still admitted: the session is honestly
    # tier-capped at ``moderate`` by the scorer (see
    # :func:`policy.score` — distinct-operators / Liquid-round-trip /
    # ≥3-registry-size caps stack against single-operator on-chain),
    # and the SPA renders a "single-operator deployment" advisory
    # banner (with a Learn more link to
    # docs/anonymize_operator_diversity.md) so the user understands
    # the trust posture before committing. Operators who configure
    # a second Boltz onion via ``BOLTZ_SUBMARINE_ONION_URL`` +
    # ``BOLTZ_REVERSE_ONION_URL`` get the banner suppressed and
    # the tier ceiling rises to ``strong`` automatically.

    min_sat = int(settings.anonymize_min_sat)
    max_sat = int(settings.anonymize_max_sat)
    if not (min_sat <= request.requested_amount_sat <= max_sat):
        raise QuoteBuildError(f"requested_amount_sat={request.requested_amount_sat} outside [{min_sat}, {max_sat}]")

    # On-chain sources fund the mix through a submarine swap, which has
    # an operator-set minimum above the global floor. Reject below-
    # minimum on-chain requests here so the session fails fast at quote
    # time with a clear message, instead of being created and then
    # wedging at swap-create (a 400 from the submarine operator).
    if request.source_kind in ("onchain-self", "ext-onchain"):
        onchain_min = int(settings.anonymize_onchain_source_min_sat)
        if request.requested_amount_sat < onchain_min:
            raise QuoteBuildError(
                f"On-chain sources require at least {onchain_min:,} sats "
                f"(submarine swap minimum); requested {request.requested_amount_sat:,}."
            )

    # BOLT 12 exit branch. The destination has already been
    # resolved by the endpoint (via the DoH BIP-353 resolver); no
    # on-chain address exists here, so we skip
    # ``parse_and_validate_destination`` and carry the resolved offer
    # straight into the pipeline. The bin-amount + score paths still
    # run because we want the same advisory tier + delay policy on a
    # LN exit as on a reverse-swap exit.
    if request.exit_kind == "bolt12_pay":
        if request.source_kind not in {"lightning-self", "ext-lightning"}:
            raise QuoteBuildError("bolt12_pay exit requires a Lightning source (lightning-self or ext-lightning)")
        if not (request.bolt12_offer or "").strip():
            raise QuoteBuildError("bolt12_pay exit requires a non-empty bolt12_offer")
        dest_addr = ""
        # No on-chain script for an LN exit. The scorer treats a
        # ``None`` here as "no script-type cap"; the legacy
        # P2PKH cap simply doesn't apply when there is no on-chain
        # output. Use the most-eligible script type so the score
        # doesn't get capped on a non-existent cap channel.
        script_type = "p2tr"
    else:
        try:
            dest_addr, script_type = parse_and_validate_destination(
                request.destination_address,
            )
        except DestinationRejectedError as exc:
            raise QuoteBuildError(f"destination rejected: {exc}") from exc

    bin_amount = quantize_to_bin(
        request.requested_amount_sat,
        settings.anonymize_amount_bins_list,
    )

    # Read per-operator quote-cache. Single-operator
    # deployments populate a single ``default`` operator entry; the
    # cache hit short-circuits any external pair-info query the
    # quote endpoint would otherwise make. Cache miss falls back to
    # local defaults; the recurring refresh task populates
    # entries asynchronously without blocking the quote.
    cache = get_quote_cache()
    cache_key = CacheKey(
        operator_id="default",
        pair="BTC/BTC",
        asset="BTC",
    )
    cached = cache.get(cache_key)
    # Verify the HMAC signature on read; a mismatch
    # routes through cache-miss path so a tampered line cannot
    # influence the quote.
    cache_signed_ok = cached is not None and verify_cache_entry(cached)
    if cached is None or not is_entry_fresh(cached) or not cache_signed_ok:
        # Seed a fresh entry with the local fee floor so subsequent
        # quotes hit warm cache. The refresh task overwrites with
        # the live Boltz pair-info when it next runs.
        cache.put(
            CacheEntry(
                key=cache_key,
                payload={"fee_floor_sat_per_vb": 1.0},
                fetched_at_unix_s=float(time.time()),
                operator_signature=None,
                signing_key_generation=0,
            )
        )

    # Determine source-kind branch up front — the operator-selection
    # logic below + the pipeline shape below both need this.
    is_onchain_source = request.source_kind in {
        "onchain-self",
        "ext-onchain",
    }

    # Operator
    # selection.
    #
    # On-chain sources REQUIRE the caller to pre-compute the
    # selection via :func:`select_operators_for_onchain_session`
    # (the selector is async; this builder is sync). The endpoint
    # invokes the selector and passes the result in via the
    # ``selection`` kwarg.
    #
    # LN-only sources pick the single reverse-leg operator inline
    # from the registry — no chain walk, no probes (there is no
    # submarine leg, and the reverse-leg's actual reachability is
    # exercised at session-create time).
    sampled_submarine_id: str | None = None
    sampled_reverse_id: str | None = None
    # Split into reverse (tier-capping) and submarine
    # (soft-note) volumes per the reverse-leg-only model.
    sampled_reverse_attested_volume: int = 0
    sampled_submarine_attested_volume: int = 0
    if is_onchain_source:
        if selection is not None:
            sampled_submarine_id = selection.submarine.operator_id
            sampled_reverse_id = selection.reverse.operator_id
            sampled_reverse_attested_volume = int(selection.reverse.attested_min_24h_volume_satoshis or 0)
            sampled_submarine_attested_volume = int(selection.submarine.attested_min_24h_volume_satoshis or 0)
        else:
            # URL-pin bypass — the endpoint detected
            # ``BOLTZ_SUBMARINE_ONION_URL`` / ``BOLTZ_REVERSE_ONION_URL``
            # in settings and skipped the chain selector. The legacy
            # single-operator-deployment path takes over: operator IDs
            # stay None (the swap egress reads URLs directly from
            # settings via ``resolve_*_leg_url``), and both attested-
            # volume figures stay 0 so the scorer caps the tier
            # honestly without surfacing a volume-specific note.
            #
            # Refuse only when the endpoint failed to pre-resolve a
            # selection AND no URL pins are set — that's a wiring
            # bug, not a power-user escape hatch.
            if not (
                getattr(settings, "boltz_submarine_onion_url", "") or getattr(settings, "boltz_reverse_onion_url", "")
            ):
                raise QuoteBuildError(
                    "on-chain source requires pre-computed operator "
                    "selection — the endpoint must call "
                    "select_operators_for_onchain_session() first"
                )
    else:
        # LN-only path — no submarine leg, single reverse pick from
        # the registry. Submarine attested volume stays 0 so the
        # soft note is suppressed (the `> 0` guard).
        try:
            from .operators import load_signed_operator_registry

            ln_registry = load_signed_operator_registry()
        except Exception:  # noqa: BLE001
            ln_registry = []
        if ln_registry:
            sampled_reverse_id = ln_registry[0].operator_id
            sampled_reverse_attested_volume = int(ln_registry[0].attested_min_24h_volume_satoshis or 0)

    # Pipeline shape depends on source kind:
    # * lightning-self: a self-pay source hop, reverse exit.
    # * ext-lightning: empty hop list (externally funded), reverse exit.
    # * on-chain sources: submarine hop first, reverse exit, with a
    # mandatory inter-leg delay window.
    requested_k = sample_requested_mpp_k()
    hops: tuple = ()
    inter_leg: InterLegDelay | None = None
    if is_onchain_source:
        hops = (Hop(kind="submarine"),)
        # Mandatory 6–48 h inter-leg delay; defaults come
        # from :class:`InterLegDelay` (which mirrors the documented
        # ``Uniform(6h, 48h)`` window).
        inter_leg = InterLegDelay()
    elif request.source_kind == "lightning-self":
        # The self-pay source hop fires a circular self-payment that
        # reshuffles channel balances before the reverse exit. An
        # externally-funded ext-lightning source does no such self-pay,
        # so it carries no hop here.
        hops = (Hop(kind="ln_self_pay"),)
    if request.exit_kind == "bolt12_pay":
        exit_obj = Exit(
            kind="bolt12_pay",
            # No on-chain output. The bound ``destination_address`` is
            # kept empty so any downstream that reads ``exit.destination_address``
            # without inspecting ``exit.kind`` fails loudly rather
            # than misinterpreting the field.
            destination_address="",
            cooperative_only=True,
            bolt12_offer=request.bolt12_offer,
            bip353_handle=request.bip353_handle,
        )
    else:
        exit_obj = Exit(
            kind="reverse",
            destination_address=dest_addr,
            cooperative_only=True,
            bip353_handle=request.bip353_handle,
        )

    # Resolve the ext-lightning deposit method. Per-quote
    # override (``request.deposit_method``) takes precedence over
    # the operator-wide default. Only ``ext-lightning`` sources
    # carry a meaningful deposit-method; other source kinds ignore
    # the field and the pipeline_json marker is omitted entirely.
    resolved_deposit_method: str | None = None
    if request.source_kind == "ext-lightning":
        candidate = request.deposit_method or str(
            getattr(
                settings,
                "anonymize_ext_lightning_deposit_method",
                "bolt11",
            )
        )
        if candidate not in {"bolt11", "bolt12"}:
            raise QuoteBuildError(f"unsupported deposit_method: {candidate!r}")
        resolved_deposit_method = candidate

    pipeline = Pipeline(
        schema_version=int(settings.anonymize_pipeline_schema_version_current),
        source=Source(
            kind=request.source_kind,
            deposit_method=resolved_deposit_method,
        ),
        hops=hops,
        exit=exit_obj,
        bin_amount_sat=bin_amount,
        delay_policy=DelayPolicy(
            kind="uniform",
            min_seconds=int(settings.anonymize_default_delay_min_s),
            max_seconds=int(settings.anonymize_default_delay_max_s),
        ),
        inter_leg_delay=inter_leg,
    )
    # Freeze K + advisory MPP into params on the (empty) hop list by
    # carrying it on the exit instead — pipeline_to_json captures both.
    # We use a small extra dict so the orchestrator + scorer can read it.
    canonical = pipeline_to_json(pipeline)
    validate_pipeline(
        pipeline,
        max_hops=int(settings.anonymize_max_hops),
        max_pipeline_json_bytes=int(settings.anonymize_max_pipeline_json_bytes),
    )

    from .operators import has_distinct_legs_configured

    env = PipelineEnv(
        has_onchain_source=request.source_kind.startswith("onchain") or request.source_kind.startswith("ext-onchain"),
        # On-chain pipelines require distinct legs; LN-only
        # falls back to "shared OK" because there's only one leg.
        distinct_operators=(has_distinct_legs_configured() if is_onchain_source else True),
        amount_is_binned=(bin_amount == request.requested_amount_sat),
        exit_diversity="asn",
        tor_process_shared_with_lnd=tor_process_shared_with_lnd,
        public_chain_backend_enabled=public_chain_backend_enabled,
        exact_audit_logs_enabled=bool(settings.anonymize_exact_audit_logs),
        destination_script_type=script_type,
        plain_bolt11_ext_deposit=False,
        operator_registry_size=int(operator_registry_size),
        has_funding_change=False,
        egress_endpoints_onion_only=egress_endpoints_onion_only,
        in_flight_concurrent_sessions=0,
        used_preconsolidation=False,
        audit_bucket_suppression_disabled=audit_bucket_suppression_disabled,
        reverse_attested_volume_satoshis=int(sampled_reverse_attested_volume),
        submarine_attested_volume_satoshis=int(sampled_submarine_attested_volume),
        operator_min_volume_multiple=int(settings.anonymize_operator_min_volume_multiple),
        chain_anchor_redaction_disabled=chain_anchor_redaction_disabled,
        registry_signature_verification_failed_at_load=False,
    )
    report = score(pipeline, env)

    # Server-side
    # advisory notes for chain-walk outcomes. The SPA also renders an
    # inline yellow pill from ``selection_source`` (template-gated),
    # but the structured note in ``advisory_tier_notes`` ensures the
    # information appears on every surface that renders the notes list
    # (review screen, audit-log diagnostic exports, etc.).
    if selection is not None:
        if selection.selection_source == "secondary_after_primary_failed":
            report.notes.append("primary submarine operator unreachable — using secondary alt")
        elif selection.selection_source == "single_operator_after_chain_exhausted":
            report.notes.append("submarine alt operators exhausted — proceeding single-operator with user consent")

    issued = int(now_unix_s) if now_unix_s is not None else int(time.time())
    ttl = int(settings.anonymize_quote_token_ttl_s)

    cookie_hmac = _hmac_cookie_subject(
        request.cookie_subject,
        keyset.active_key,
    )
    body_hash = hashlib.sha256(request.canonical_request_body).digest()

    # Option C — the per-quote opt-in only takes effect when
    # the operator has the Liquid hop master switch on. A request
    # asking for Liquid against an operator that hasn't enabled it
    # downgrades silently to the LN-only pipeline; the SPA sees the
    # downgrade via :class:`QuoteResult.uses_liquid` and can flag it.
    uses_liquid = bool(request.prefer_liquid) and bool(getattr(settings, "anonymize_liquid_enabled", False))

    payload = QuoteTokenPayload(
        canonical_pipeline_json=canonical,
        bin_amount_sat=bin_amount,
        # The sampled operator IDs are bound into the
        # signed token so the create endpoint + per-session loop
        # can re-assert them at execute time. Single-operator
        # registries leave submarine_operator_id None.
        submarine_operator_id=sampled_submarine_id,
        reverse_operator_id=sampled_reverse_id,
        delay_min_s=int(pipeline.delay_policy.min_seconds),
        delay_max_s=int(pipeline.delay_policy.max_seconds),
        inter_leg_min_s=None,
        inter_leg_max_s=None,
        requested_mpp_k=int(requested_k),
        issued_at_unix_s=issued,
        ttl_s=ttl,
        cookie_subject_hmac=cookie_hmac,
        canonical_request_body_hash=body_hash,
        uses_liquid=uses_liquid,
        # Bind chain-walk outcome for the session-create
        # handler's audit emission.
        selection_source=(selection.selection_source if selection is not None else ""),
    )
    token = sign_quote_token(payload, keyset=keyset)

    # Populate operator-attribution + chain-trajectory fields
    # from the pre-computed selection. LN-only quotes leave these
    # at their dataclass defaults (None / []).
    sub_primary: str | None = None
    sub_primary_status: str | None = None
    sub_selected: str | None = None
    sub_selection_source: str | None = None
    sub_attempted: list[dict] = []
    if selection is not None:
        sub_primary = selection.submarine_primary
        sub_selected = selection.submarine.operator_id
        sub_selection_source = selection.selection_source
        sub_attempted = [
            {"operator_id": a.operator_id, "status": a.status} for a in selection.submarine_chain_attempted
        ]
        # Derive primary_status from the first chain attempt that
        # matched the configured primary id (the selector records
        # every candidate considered in order).
        if sub_primary is not None:
            for a in selection.submarine_chain_attempted:
                if a.operator_id == sub_primary:
                    sub_primary_status = a.status
                    break

    return QuoteResult(
        quote_token=token,
        bin_amount_sat=int(bin_amount),
        advisory_tier=str(report.tier),
        advisory_tier_notes=list(report.notes),
        min_executed_chunks_for_target_tier=min_executed_chunks_for_target_tier(
            str(report.tier),
        ),
        issued_at_unix_s=issued,
        ttl_s=ttl,
        uses_liquid=uses_liquid,
        submarine_operator_id=sampled_submarine_id,
        reverse_operator_id=sampled_reverse_id,
        submarine_chain_primary_attempted=sub_primary,
        submarine_chain_primary_status=sub_primary_status,
        submarine_chain_selected=sub_selected,
        submarine_chain_selection_source=sub_selection_source,
        submarine_chain_attempted=sub_attempted,
    )


def result_to_dict(r: QuoteResult) -> dict[str, Any]:
    """Flat dict shape the endpoint serialises to JSON."""
    out: dict[str, Any] = {
        "quote_token": r.quote_token,
        "bin_amount_sat": r.bin_amount_sat,
        "advisory_tier": r.advisory_tier,
        "advisory_tier_notes": r.advisory_tier_notes,
        "min_executed_chunks_for_target_tier": (r.min_executed_chunks_for_target_tier),
        "issued_at_unix_s": r.issued_at_unix_s,
        "ttl_s": r.ttl_s,
        "uses_liquid": bool(r.uses_liquid),
    }
    # Only attach the chain-trajectory fields when a
    # submarine leg actually ran. LN-only quotes leave them off
    # so the SPA can `x-show`-gate on field presence.
    if r.submarine_operator_id is not None:
        out["submarine_operator_id"] = r.submarine_operator_id
        out["submarine_chain"] = {
            "primary_attempted": r.submarine_chain_primary_attempted,
            "primary_status": r.submarine_chain_primary_status,
            "selected": r.submarine_chain_selected,
            "selection_source": r.submarine_chain_selection_source,
            "attempted": list(r.submarine_chain_attempted),
        }
    if r.reverse_operator_id is not None:
        out["reverse_operator_id"] = r.reverse_operator_id
    return out


__all__ = [
    "QuoteBuildError",
    "QuoteRequest",
    "QuoteResult",
    "build_quote",
    "result_to_dict",
]
