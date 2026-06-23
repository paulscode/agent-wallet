# SPDX-License-Identifier: MIT
"""Source-side UTXO selector and labelling rules.

* exact-bin source funding + ``auto:anonymize-change`` +
  ``do_not_spend=true`` escalation.
* pre-anonymize over-pad consolidation + pre-existing exact-bin
  UTXO refusal (gated on ``ANONYMIZE_FEATURE_ENABLED_AT_DAY``).
* decoy-output consolidation + opportunistic merge mode.
* submarine-refund UTXO lockdown.
* anonymize-decoy seed (separate from primary xpub).

The pure-helper layer covers the over-pad value sampling and the
post-roll bin-set safety check; the on-chain self-source wiring (UTXO
selector, ``do_not_spend`` labelling, submarine-funding spend) layers
on top.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING
from uuid import UUID

from app.core.config import settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# Re-sample cap for the over-pad value when the rolled-out
# consolidation output collides with another bin within tolerance.
class OverPadResampleExceededError(RuntimeError):
    """Raised when the over-pad sampler can't find a bin-clear value."""


def _bin_set() -> list[int]:
    """Return the current published bin set (sorted ascending)."""
    return list(settings.anonymize_amount_bins_list)


def collides_with_any_bin(
    candidate_value_sat: int,
    *,
    bins: list[int] | None = None,
    tolerance_sat: int | None = None,
) -> bool:
    """Does ``candidate_value_sat`` fall within tolerance of ANY published bin?

    The over-pad sampler must avoid coinciding with a *different*
    bin's exact-bin UTXO range, otherwise the consolidation output
    re-acquires the exact-bin chain marker for the wrong bin.
    """
    if bins is None:
        bins = _bin_set()
    if tolerance_sat is None:
        tolerance_sat = int(settings.anonymize_exact_bin_tolerance_sat)
    for b in bins:
        if abs(candidate_value_sat - b) <= tolerance_sat:
            return True
    return False


def sample_over_pad(
    *,
    bin_amount_sat: int,
    max_estimated_fee_sat: int,
    rng: secrets.SystemRandom | None = None,
) -> int:
    """Sample the over-pad consolidation output value.

    Returns ``bin_amount_sat + max_estimated_fee_sat + Uniform(min, max)``
    where the over-pad band is the configured
    ``ANONYMIZE_PRECONSOLIDATION_OVERPAD_(MIN|MAX)_SAT``. The caller
    passes the funding-tx fee estimate so we can compute the
    consolidation output value precisely; the over-pad becomes ordinary
    submarine-funding change at execute time.

    The sampled value is checked against the
    *full* published bin set with ``ANONYMIZE_EXACT_BIN_TOLERANCE_SAT``
    — colliding samples are re-rolled up to
    ``ANONYMIZE_PRECONSOLIDATION_OVERPAD_RESAMPLE_LIMIT`` times. On
    cap exhaustion :class:`OverPadResampleExceededError` is raised; the
    wizard surfaces the error and asks the user to wait for a different
    fee market or pick a different bin.
    """
    rng = rng or secrets.SystemRandom()
    overpad_min = max(0, int(settings.anonymize_preconsolidation_overpad_min_sat))
    overpad_max = max(overpad_min, int(settings.anonymize_preconsolidation_overpad_max_sat))
    cap = max(1, int(settings.anonymize_preconsolidation_overpad_resample_limit))
    bins = _bin_set()
    tol = int(settings.anonymize_exact_bin_tolerance_sat)

    base = int(bin_amount_sat) + int(max_estimated_fee_sat)

    for _ in range(cap):
        overpad = rng.randint(overpad_min, overpad_max)
        candidate = base + overpad
        # Reject collision with *any other* bin (the consolidation
        # output's value must not look like a different bin's exact-bin
        # UTXO). The chosen bin itself is fine: the user is anonymizing
        # against that bin's anonymity set.
        if not _collides_with_other_bin(
            candidate,
            target_bin=int(bin_amount_sat),
            bins=bins,
            tolerance_sat=tol,
        ):
            return candidate
    raise OverPadResampleExceededError(f"could not find a bin-clear over-pad value within {cap} samples")


def _collides_with_other_bin(
    candidate_value_sat: int,
    *,
    target_bin: int,
    bins: list[int],
    tolerance_sat: int,
) -> bool:
    """True iff ``candidate_value_sat`` is within ``tolerance_sat`` of any
    bin other than ``target_bin``."""
    for b in bins:
        if b == target_bin:
            continue
        if abs(candidate_value_sat - b) <= tolerance_sat:
            return True
    return False


# --------------------------------------------------------------------
# Exact-bin source coin-selection.
# --------------------------------------------------------------------


from dataclasses import dataclass


@dataclass(frozen=True)
class WalletUtxo:
    """One spendable UTXO at the source side."""

    outpoint: str  # "txid:vout"
    value_sat: int
    confirmations: int = 0
    label: str = ""


@dataclass(frozen=True)
class CoinSelection:
    """Result of an exact-bin coin-selection attempt."""

    chosen_outpoints: tuple[str, ...]
    total_value_sat: int
    has_change: bool
    needs_consolidation: bool
    target_funding_value_sat: int


def select_exact_bin_funding(
    utxos: list[WalletUtxo],
    *,
    bin_amount_sat: int,
    max_estimated_fee_sat: int,
    tolerance_sat: int | None = None,
) -> CoinSelection:
    """Prefer a single UTXO whose value matches ``bin + max_fee``.

    Returns a :class:`CoinSelection` describing the chosen outpoints
    and whether the resulting funding tx will have change. The caller
    routes change-bearing sessions through the over-pad
    consolidation flow (a soft-fail) or accepts the ``weak``
    cap for change-bearing pipelines.

    Decision rule:
    1. If any single UTXO's value falls within ``tolerance_sat`` of
       ``target = bin + max_fee``, pick it. ``has_change=False``,
       ``needs_consolidation=False``.
    2. Otherwise, ``needs_consolidation=True`` — the wizard surfaces
       the over-pad consolidation step, and the caller may either
       run consolidation or fall back to a multi-UTXO selection that
       *does* produce change.
    """
    tol = tolerance_sat if tolerance_sat is not None else int(settings.anonymize_exact_bin_tolerance_sat)
    target = int(bin_amount_sat) + int(max_estimated_fee_sat)
    confirmed = [u for u in utxos if u.confirmations > 0 and u.value_sat > 0]

    # Closest single UTXO to the target.
    candidates = sorted(confirmed, key=lambda u: abs(u.value_sat - target))
    for u in candidates:
        if abs(u.value_sat - target) <= tol:
            return CoinSelection(
                chosen_outpoints=(u.outpoint,),
                total_value_sat=u.value_sat,
                has_change=False,
                needs_consolidation=False,
                target_funding_value_sat=target,
            )

    # No exact-bin UTXO; fall back to "needs consolidation" — the
    # wizard surfaces the over-pad consolidation flow. We do NOT
    # auto-select multiple UTXOs here; the user must opt in.
    return CoinSelection(
        chosen_outpoints=(),
        total_value_sat=0,
        has_change=False,
        needs_consolidation=True,
        target_funding_value_sat=target,
    )


def is_existing_utxo_exact_bin_shaped(
    utxo: WalletUtxo,
    *,
    bins: list[int] | None = None,
    tolerance_sat: int | None = None,
) -> bool:
    """Would using this UTXO as source be refused?

    Returns True when the UTXO's value falls within tolerance of any
    *currently published* bin. The orchestrator uses this together
    with ``ANONYMIZE_FEATURE_ENABLED_AT_DAY`` to refuse pre-existing
    exact-bin UTXOs that pre-date the feature.
    The "did this UTXO predate the feature day" check is decoupled —
    the caller passes through ``settings_store.get_feature_enabled_at_day()``
    and compares the UTXO's confirmation height to that day.
    """
    if bins is None:
        bins = _bin_set()
    if tolerance_sat is None:
        tolerance_sat = int(settings.anonymize_exact_bin_tolerance_sat)
    return collides_with_any_bin(utxo.value_sat, bins=bins, tolerance_sat=tolerance_sat)


# --------------------------------------------------------------------
# Pre-existing exact-bin UTXO refusal.
# --------------------------------------------------------------------


from datetime import date as _date  # noqa: E402
from datetime import datetime as _datetime


def is_utxo_refused_as_anonymize_source(
    utxo: WalletUtxo,
    *,
    confirmed_at: _datetime,
    feature_enabled_at_day: _date | None,
    bins_at_confirmation: list[int] | None = None,
    tolerance_sat: int | None = None,
) -> tuple[bool, str | None]:
    """Would this UTXO trigger the source-refusal rule?

    Returns ``(refused, reason)``. ``refused=True`` means the wizard
    must surface the over-pad consolidation flow rather than
    admitting the UTXO directly. The rule is:

    1. Resolve the bin set active at the UTXO's confirmation height
       (caller passes ``bins_at_confirmation`` from
       :mod:`bin_set_history`).
    2. If the UTXO value collides with any bin within tolerance, AND
    3. ``feature_enabled_at_day`` is set AND
    4. The UTXO confirmed *on or after* ``feature_enabled_at_day``,
       the UTXO is refused.

    UTXOs that predate the feature day are admitted (the user's
    historical balance shouldn't be permanently locked out).

    Pure / no I/O — the caller resolves the active bin set + the
    feature-enabled day from the appropriate stores.
    """
    if not is_existing_utxo_exact_bin_shaped(
        utxo,
        bins=bins_at_confirmation,
        tolerance_sat=tolerance_sat,
    ):
        return False, None

    if feature_enabled_at_day is None:
        # Feature not yet enabled on this wallet — no refusal, but the
        # caller must call ``set_feature_enabled_at_day_if_unset()``
        # before admitting the session. We return False (no refusal)
        # with a hint.
        return False, "feature_enabled_at_day not yet recorded"

    confirmed_day = (
        confirmed_at.date()
        if confirmed_at.tzinfo is None
        else confirmed_at.astimezone(_datetime.now().astimezone().tzinfo).date()
    )
    # Use UTC consistently for the date extraction.
    from datetime import timezone

    confirmed_day = (
        confirmed_at.astimezone(timezone.utc).date() if confirmed_at.tzinfo is not None else confirmed_at.date()
    )

    if confirmed_day < feature_enabled_at_day:
        # Predates the feature ⇒ admit (the user's historical balance
        # is not part of the chain analyst's anonymize-marker pattern).
        return False, None

    return True, (
        "UTXO value matches a published bin and confirmed on or after "
        "feature_enabled_at_day; use the over-pad consolidation flow"
    )


# --------------------------------------------------------------------
# items 99 + 105 — decoy-output helpers.
# --------------------------------------------------------------------


def sample_decoy_output_value_sat(
    *,
    rng: secrets.SystemRandom | None = None,
    histogram: list[int] | None = None,
) -> int:
    """Sample the decoy-output value.

    When a rolling histogram of recent non-anonymize change outputs
    is supplied, sample uniformly from it (empirical-distribution
    mimicry). Otherwise fall back to a uniform draw over the
    configured ``ANONYMIZE_CONSOLIDATION_DECOY_(MIN|MAX)_SAT`` band.
    """
    rng = rng or secrets.SystemRandom()
    if histogram:
        return int(rng.choice(histogram))
    lo = max(0, int(settings.anonymize_consolidation_decoy_min_sat))
    hi = max(lo, int(settings.anonymize_consolidation_decoy_max_sat))
    return rng.randint(lo, hi)


def sample_consolidation_to_submarine_delay_s(
    *,
    rng: secrets.SystemRandom | None = None,
) -> int:
    """Pre-funding delay sampler.

    Breaks the chain-side temporal cluster: the
    consolidation tx and the subsequent submarine swap must not
    appear back-to-back.
    """
    rng = rng or secrets.SystemRandom()
    lo = max(0, int(settings.anonymize_consolidation_to_submarine_delay_min_s))
    hi = max(lo, int(settings.anonymize_consolidation_to_submarine_delay_max_s))
    return rng.randint(lo, hi)


# --------------------------------------------------------------------
# Orchestrator-driven decoy-consolidation flow.
# --------------------------------------------------------------------


from dataclasses import dataclass as _dataclass


@_dataclass(frozen=True)
class DecoyConsolidationOutputs:
    """Two-output payload the consolidation tx builder emits.

    The wallet's PSBT layer translates this into a concrete tx + signs +
    broadcasts. The in-process flow records both outputs in
    ``anonymize_decoy_output`` (decoy) + tags the consolidation output
    with ``auto:anonymize-overpad`` on the UtxoLabel table.
    """

    consolidation_value_sat: int  # the over-padded output
    decoy_value_sat: int  # decoy mimicry output
    decoy_address: str | None  # BIP-86 wallet-controlled address
    decoy_derivation_index: int  # for the decoy_seed row write


def build_decoy_consolidation_outputs(
    *,
    bin_amount_sat: int,
    max_estimated_fee_sat: int,
    decoy_address: str | None,
    decoy_derivation_index: int,
    rng: secrets.SystemRandom | None = None,
    decoy_histogram: list[int] | None = None,
    over_pad_bins: list[int] | None = None,
) -> DecoyConsolidationOutputs:
    """Assemble the two-output consolidation payload.

    Output 1: over-padded consolidation output (used to fund the
    upcoming submarine lockup). Sized as ``bin_amount + max_fee +
    sample_over_pad``.
    Output 2: decoy output to a separately-derived wallet-controlled
    address. The value sampler runs over the supplied
    empirical histogram (or falls back to the configured band).

    Pure / no I/O — the caller does the PSBT-level signing + the DB
    row writes (`record_decoy_output` + `UtxoLabel` for the
    consolidation output).
    """
    if bin_amount_sat <= 0:
        raise ValueError("bin_amount_sat must be positive")
    _ = over_pad_bins  # unused arg kept for forward-compat signature
    rng = rng or secrets.SystemRandom()
    consolidation_value = sample_over_pad(
        bin_amount_sat=int(bin_amount_sat),
        max_estimated_fee_sat=int(max_estimated_fee_sat),
        rng=rng,
    )
    decoy_value = sample_decoy_output_value_sat(
        rng=rng,
        histogram=decoy_histogram,
    )
    return DecoyConsolidationOutputs(
        consolidation_value_sat=consolidation_value,
        decoy_value_sat=decoy_value,
        decoy_address=decoy_address,
        decoy_derivation_index=int(decoy_derivation_index),
    )


# --------------------------------------------------------------------
# Submarine refund-UTXO lockdown.
# --------------------------------------------------------------------


@dataclass(frozen=True)
class RefundUtxoLabel:
    """Label payload written when a submarine refund returns funds."""

    outpoint: str  # "txid:vout"
    reason: str  # "timeout" | "operator_unreachable" | "partition"
    label: str = "auto:anonymize-refund"
    do_not_spend: bool = True


def make_refund_lockdown_label(
    *,
    outpoint: str,
    reason: str,
) -> RefundUtxoLabel:
    """Build the refund-UTXO lockdown label.

    Pure / no I/O. The orchestrator persists via the existing
    ``utxo_label`` machinery.
    """
    if reason not in {"timeout", "operator_unreachable", "partition"}:
        raise ValueError(
            f"refund reason {reason!r} not in the documented enum (timeout / operator_unreachable / partition)"
        )
    return RefundUtxoLabel(outpoint=outpoint, reason=reason)


def refund_lockdown_enabled() -> bool:
    """Feature flag for the refund-UTXO hardening."""
    return bool(settings.anonymize_refund_utxo_hardening_enabled)


def refund_override_spends_refused() -> bool:
    """Hard-refusal of refund-UTXO override spends.

    On-chain self-source default is ``False`` (step-up confirmation
    gates override); the strongest tier defaults to ``True``
    (override-spends hard-refused).
    """
    return bool(settings.anonymize_refuse_refund_override_spends)


def decoy_override_spends_refused() -> bool:
    """Hard-refusal of decoy-UTXO override
    spends.

    Symmetric to :func:`refund_override_spends_refused`. The on-chain
    self-source default is ``False`` (step-up confirmation required);
    the strongest tier flips the default to ``True``.
    """
    return bool(settings.anonymize_refuse_decoy_override_spends)


# Labels the wallet's coin-selector must treat
# as ``do_not_spend=true`` for non-anonymize wallet flows.
_DO_NOT_SPEND_LABEL_PREFIXES: tuple[str, ...] = (
    "auto:anonymize-refund",
    "auto:anonymize-overpad",
    "auto:anonymize-decoy",
    "auto:anonymize-change",
)


def is_do_not_spend_label(label: str | None) -> bool:
    """Return True iff ``label`` marks a UTXO that non-anonymize
    wallet flows MUST exclude from coin selection.

    The wallet's coin selector calls this helper when ranking
    UTXOs; matched outputs are dropped (or escalated through the
     step-up flow for spend-override).
    """
    if not label:
        return False
    return any(label.startswith(p) for p in _DO_NOT_SPEND_LABEL_PREFIXES)


async def apply_refund_lockdown_label(
    db: AsyncSession,
    *,
    outpoint: str,
    reason: str,
    spent_txid: str | None = None,
) -> None:
    """Write the refund-UTXO lockdown label.

    The orchestrator calls this after a successful submarine refund
    broadcast. The created :class:`UtxoLabel` carries the
    ``auto:anonymize-refund`` label so the wallet's coin selector
    excludes the output via :func:`is_do_not_spend_label`. An
    ``anonymize_refund_locked`` event is emitted alongside so the
    audit chain has the lockdown evidence.

    The caller is responsible for committing.
    """
    from app.models.utxo_label import UtxoLabel, UtxoLabelSource

    payload = make_refund_lockdown_label(outpoint=outpoint, reason=reason)
    try:
        txid, vout_str = payload.outpoint.split(":", 1)
        vout = int(vout_str)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"refund lockdown outpoint must be 'txid:vout'; got {outpoint!r}") from exc

    db.add(
        UtxoLabel(
            txid=txid.lower(),
            vout=vout,
            label=payload.label,
            source=UtxoLabelSource.AUTO_SWAP,
            spent_txid=(spent_txid.lower() if spent_txid else None),
            note=f"refund-lockdown:{reason}",
        )
    )


# --------------------------------------------------------------------
# Spend-override eligibility decision.
# --------------------------------------------------------------------


from typing import Literal

SpendEligibility = Literal[
    "admit",  # Label is non-anonymize OR refusal flag is off.
    "refuse",  # Hard-refusal flag is on for this label family.
    "require_stepup",  # Operator may proceed after step-up re-auth.
]


def check_anonymize_spend_eligibility(label: str | None) -> SpendEligibility:
    """Decide what the wallet's coin selector does
    when a non-anonymize flow selects a UTXO bearing an anonymize-*
    label.

    Three outcomes:

    * ``admit`` — the label is not in the anonymize-do-not-spend
      family, so the spend proceeds without any extra gate.
    * ``refuse`` — the relevant hard-refusal flag is on
      (strongest-tier default). The coin selector raises rather than
      silently spending; the operator must override the flag
      explicitly via config.
    * ``require_stepup`` — on-chain self-source default. The dashboard
      surfaces a step-up re-auth prompt + emits the
      ``anonymize_{decoy,refund}_spend_override`` audit event on
      success.

    The function discriminates between the refund family (auto:anonymize-
    refund*) and the decoy / overpad / change family so deployments
    can flip the two flags independently.
    """
    if not label or not is_do_not_spend_label(label):
        return "admit"
    is_refund = label.startswith("auto:anonymize-refund")
    if is_refund:
        if refund_override_spends_refused():
            return "refuse"
        return "require_stepup"
    # decoy / overpad / change → family.
    if decoy_override_spends_refused():
        return "refuse"
    return "require_stepup"


def spend_override_event_kind(label: str | None) -> str | None:
    """Return the audit-event kind the dashboard emits when an
    operator overrides a do-not-spend label.

    Returns ``"anonymize_refund_spend_override"`` for refund-family
    labels, ``"anonymize_decoy_spend_override"`` for decoy / overpad /
    change labels, or ``None`` for unlabeled / non-anonymize UTXOs.
    """
    if not label or not is_do_not_spend_label(label):
        return None
    if label.startswith("auto:anonymize-refund"):
        return "anonymize_refund_spend_override"
    return "anonymize_decoy_spend_override"


async def emit_spend_override_event(
    db: AsyncSession,
    *,
    session_id: UUID,
    outpoint: str,
    label: str,
    stepup_nonce_id: str | None = None,
) -> None:
    """Emit the spend-override audit event.

    Called by the dashboard's coin-selector hook after the operator
    has cleared the step-up re-auth gate + selected an
    ``auto:anonymize-*`` UTXO for a non-anonymize spend. The event
    records the outpoint + the label class + the step-up nonce ID
    used to authorize the override.

    The caller is responsible for committing.
    """
    kind = spend_override_event_kind(label)
    if kind is None:
        return
    from datetime import datetime, timezone

    from app.models.anonymize_session import AnonymizeSessionEvent

    db.add(
        AnonymizeSessionEvent(
            session_id=session_id,
            ts=datetime.now(timezone.utc),
            kind=kind,
            detail_json={
                "outpoint": outpoint,
                "label": label,
                "stepup_nonce_id": stepup_nonce_id or "",
            },
        )
    )


__all__ = [
    "OverPadResampleExceededError",
    "WalletUtxo",
    "CoinSelection",
    "RefundUtxoLabel",
    "SpendEligibility",
    "collides_with_any_bin",
    "sample_over_pad",
    "select_exact_bin_funding",
    "is_existing_utxo_exact_bin_shaped",
    "is_utxo_refused_as_anonymize_source",
    "sample_decoy_output_value_sat",
    "sample_consolidation_to_submarine_delay_s",
    "make_refund_lockdown_label",
    "refund_lockdown_enabled",
    "refund_override_spends_refused",
    "decoy_override_spends_refused",
    "check_anonymize_spend_eligibility",
    "spend_override_event_kind",
    "emit_spend_override_event",
    "is_do_not_spend_label",
    "apply_refund_lockdown_label",
    "DecoyConsolidationOutputs",
    "build_decoy_consolidation_outputs",
]
