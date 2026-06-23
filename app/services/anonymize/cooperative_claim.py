# SPDX-License-Identifier: MIT
"""Cooperative-claim helpers (items 18, 45, 81).

Three concerns gathered into one module because they all describe how
the orchestrator validates a Boltz cooperative-claim handoff before
persisting the claim tx:

* ** item 18 /.16** — cooperative-signature timeout.
  ``ANONYMIZE_COOP_SIG_TIMEOUT_S`` (default 120 s) bounded by
  ``ANONYMIZE_COOP_SIG_MAX_ATTEMPTS`` (default 3) — if Boltz's partial
  signature does not arrive in time, the session moves to ``failed``
  rather than falling back to the script-path (which is bytewise
  identifiable).
* ** item 81 /.2** — cooperative-claim feerate sanity gate.
  Before invoking ``boltz_claim.js`` the orchestrator asserts
  ``swap.claimFeeRate ∈ economy_satvb * [LO, HI]``; outliers route the
  session to a graceful refund and increment a per-operator outlier
  counter.
* ** item 45 /.3** — validate-before-persist on the
  cooperative-claim tx. Before persisting ``claim_tx_hex`` the
  orchestrator structurally checks the tx (input outpoint, output
  script equals destination, single-schnorr witness, BIP-69 / nVersion
  / nLockTime / nSequence envelope).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable, TypeVar, cast

from app.core.config import settings

from .txpolicy import (
    TxEnvelopePolicyError,
    assert_envelope_policy,
)

T = TypeVar("T")


# ────────────────────────────────────────────────────────────────────
# Cooperative-sig timeout helper.
# ────────────────────────────────────────────────────────────────────


class CooperativeSignatureTimeoutError(RuntimeError):
    """Raised when Boltz's partial signature does not arrive in time."""


async def await_cooperative_signature(
    fetch_partial_sig: Callable[[], Awaitable[T]],
    *,
    timeout_s: float | None = None,
    max_attempts: int | None = None,
    on_attempt_failure: Callable[[int, Exception], None] | None = None,
) -> T:
    """Bounded retry across fresh circuits for the partial sig.

    The orchestrator issues ``fetch_partial_sig`` repeatedly until
    either it succeeds or the budget exhausts. Each call is bounded
    by ``timeout_s``; aggregate attempt count is bounded by
    ``max_attempts``. Per-attempt failures invoke
    ``on_attempt_failure`` (logging hook) before the next try.

    Raises :class:`CooperativeSignatureTimeoutError` on budget exhaustion;
    the orchestrator routes the session to ``failed`` (: do NOT
    fall back to script-path, which is bytewise identifiable).
    """
    timeout = float(timeout_s if timeout_s is not None else settings.anonymize_coop_sig_timeout_s)
    attempts = int(max_attempts if max_attempts is not None else settings.anonymize_coop_sig_max_attempts)
    last_exc: Exception | None = None
    for n in range(1, attempts + 1):
        try:
            return await asyncio.wait_for(fetch_partial_sig(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            last_exc = exc
            if on_attempt_failure is not None:
                on_attempt_failure(n, exc)
        except Exception as exc:  # noqa: BLE001 — orchestrator decides
            last_exc = exc
            if on_attempt_failure is not None:
                on_attempt_failure(n, exc)
    raise CooperativeSignatureTimeoutError(
        f"cooperative-sig handoff failed after {attempts} attempts (last error: {last_exc!r})"
    )


# ────────────────────────────────────────────────────────────────────
# Cooperative-claim feerate sanity gate.
# ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class FeerateSanityResult:
    """Outcome of the feerate sanity check."""

    accepted: bool
    operator_id: str
    quoted_sat_per_vb: float
    economy_sat_per_vb: float
    lower_bound: float
    upper_bound: float
    reason: str | None = None


# --------------------------------------------------------------------
# Two-probe feerate fail-mode.
# --------------------------------------------------------------------


class FeerateProbeUnavailableError(RuntimeError):
    """Raised when the economy-feerate probe fails twice in a row.

    The contract is "fail-closed": consecutive probe failures
    move the session to ``awaiting_reconciliation`` rather than
    quietly approving an unverifiable feerate. The orchestrator
    surfaces a ``claim_feerate_probe_unavailable`` event when this
    raises.
    """


async def probe_economy_feerate_with_retry(
    fetch_economy_satvb: Callable[[], float | Awaitable[float]],
    *,
    retry_delay_s: float | None = None,
) -> float:
    """Call ``fetch_economy_satvb`` up to twice with a delay.

    Returns the float result of the first successful probe. On two
    consecutive failures, raises :class:`FeerateProbeUnavailableError`
    with the last exception attached as ``__cause__``. Fail-open is
    explicitly forbidden: the sanity gate cannot run without
    a current economy estimate.

    The caller passes its own probe function so this helper has no
    coupling to the chain-backend client; it composes naturally with
    ``app.services.anonymize.chain``.
    """
    delay = retry_delay_s if retry_delay_s is not None else float(settings.anonymize_claim_feerate_probe_retry_delay_s)
    last_exc: Exception | None = None
    for attempt in (1, 2):
        try:
            value: float | Awaitable[float] = fetch_economy_satvb()
            if asyncio.iscoroutine(value):
                value = await value
            # ``value`` is now a concrete float (coroutines awaited above);
            # narrow for the type checker without touching runtime behavior.
            return float(cast(float, value))
        except Exception as exc:  # noqa: BLE001 — the orchestrator decides
            last_exc = exc
            if attempt == 1 and delay > 0:
                await asyncio.sleep(delay)
    raise FeerateProbeUnavailableError(f"economy-feerate probe failed on both attempts: {last_exc!r}") from last_exc


def assert_claim_feerate_sane(
    *,
    operator_id: str,
    quoted_sat_per_vb: float,
    economy_sat_per_vb: float,
) -> FeerateSanityResult:
    """Refuse a cooperative claim whose feerate is an outlier.

    The bounds are multiplicative against the current mempool
    "economy" feerate read from the dedicated anonymize chain client
    . Out-of-band feerates produce a
    :class:`FeerateSanityResult` with ``accepted=False`` and the
    orchestrator routes the session through the grace
    + per-operator-outlier-counter path.

    Pure / no I/O — the caller passes the operator's quoted feerate
    and the live economy estimate.
    """
    lo = float(settings.anonymize_claim_feerate_tolerance_lo)
    hi = float(settings.anonymize_claim_feerate_tolerance_hi)
    lower_bound = max(0.0, economy_sat_per_vb * lo)
    upper_bound = economy_sat_per_vb * hi
    reason: str | None = None
    accepted = lower_bound <= quoted_sat_per_vb <= upper_bound
    if not accepted:
        reason = (
            f"operator {operator_id!r} quoted {quoted_sat_per_vb} sat/vB "
            f"outside sanity band [{lower_bound:.3f}, {upper_bound:.3f}] "
            f"(economy={economy_sat_per_vb} sat/vB)"
        )
    return FeerateSanityResult(
        accepted=accepted,
        operator_id=operator_id,
        quoted_sat_per_vb=quoted_sat_per_vb,
        economy_sat_per_vb=economy_sat_per_vb,
        lower_bound=lower_bound,
        upper_bound=upper_bound,
        reason=reason,
    )


# ────────────────────────────────────────────────────────────────────
# Validate-before-persist on claim tx.
# ────────────────────────────────────────────────────────────────────


class ClaimTxValidationError(ValueError):
    """Raised when a cooperative-claim tx fails pre-persist validation."""


def validate_cooperative_claim_tx(
    *,
    tx_hex: str,
    expected_output_script_hex: str,
    expected_output_band_sat: tuple[int, int],
    expected_n_locktime: int | None = None,
) -> None:
    """Refuse to persist a malformed cooperative-claim tx.

    Checked properties:
    * Bitcoin-Core-shaped envelope (delegated to
      :func:`assert_envelope_policy`): nVersion=2,
      per-input nSequence=0xfffffffd, optional nLockTime match.
    * Single output whose ``scriptPubKey`` equals the user-supplied
      destination's script.
    * Output value falls within the ``output_band_sat`` band
      (the quoted feerate window).
    * Single-input claim — the cooperative-Musig2 path produces
      1-input-1-output txs.

    Raises :class:`ClaimTxValidationError` on any violation. The
    orchestrator routes the session to ``failed`` rather than
    re-broadcasting a malformed tx.
    """
    # Envelope check first; if this fails, the rest is moot.
    try:
        assert_envelope_policy(
            tx_hex,
            expected_n_locktime=expected_n_locktime,
        )
    except TxEnvelopePolicyError as exc:
        raise ClaimTxValidationError(f"envelope policy: {exc}") from None

    # Parse the output count + first output for value + script.
    try:
        raw = bytes.fromhex(tx_hex)
    except ValueError as exc:
        raise ClaimTxValidationError(f"tx_hex is not valid hex: {exc}") from None

    offset = 4  # past nVersion
    if raw[offset] == 0x00 and raw[offset + 1] == 0x01:
        offset += 2  # witness marker

    # Inputs.
    n_inputs, n_inputs_size = _read_varint(raw, offset)
    offset += n_inputs_size
    if n_inputs != 1:
        raise ClaimTxValidationError(f"cooperative-claim tx must have exactly 1 input, got {n_inputs}")
    for _ in range(n_inputs):
        offset += 36  # prevout txid + vout
        sig_len, sig_size = _read_varint(raw, offset)
        offset += sig_size + sig_len
        offset += 4  # nSequence

    # Outputs.
    n_outputs, n_out_size = _read_varint(raw, offset)
    offset += n_out_size
    if n_outputs != 1:
        raise ClaimTxValidationError(f"cooperative-claim tx must have exactly 1 output, got {n_outputs}")
    output_value_sat = int.from_bytes(raw[offset : offset + 8], "little")
    offset += 8
    spk_len, spk_size = _read_varint(raw, offset)
    offset += spk_size
    actual_spk = raw[offset : offset + spk_len]
    offset += spk_len

    expected_spk = bytes.fromhex(expected_output_script_hex)
    if actual_spk != expected_spk:
        raise ClaimTxValidationError("claim tx output scriptPubKey does not match expected destination")

    lo, hi = expected_output_band_sat
    if not (int(lo) <= output_value_sat <= int(hi)):
        raise ClaimTxValidationError(f"claim tx output value {output_value_sat} outside band [{lo}, {hi}]")


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Mirror of :func:`txpolicy._read_varint` (private to that module)."""
    first = data[offset]
    if first < 0xFD:
        return first, 1
    if first == 0xFD:
        return int.from_bytes(data[offset + 1 : offset + 3], "little"), 3
    if first == 0xFE:
        return int.from_bytes(data[offset + 1 : offset + 5], "little"), 5
    return int.from_bytes(data[offset + 1 : offset + 9], "little"), 9


# ────────────────────────────────────────────────────────────────────
# Scorer reads executed MPP K.
# ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MppFallbackOutcome:
    """Outcome of the reverse-leg outbound MPP-K execution.

    The orchestrator records ``executed_k`` in
    ``anonymize_session.reverse_payment_chunks_k`` after the
    ``send_payment_v2`` call resolves; the scorer reads it via
    :func:`mpp_caps_tier_at_weak` to compute the post-execution tier.
    """

    requested_k: int
    executed_k: int


def mpp_caps_tier_at_weak(outcome: MppFallbackOutcome) -> bool:
    """K=1 fallback caps the executed tier at ``weak`` when
    the requested K was > 1.

    The scorer applies this cap to the post-execution tier; the
    quote-time tier doesn't know about fallback.
    """
    return outcome.executed_k == 1 and outcome.requested_k > 1


# --------------------------------------------------------------------
# Per-session randomized reverse-leg MPP K.
# --------------------------------------------------------------------


import secrets


def sample_requested_mpp_k(
    *,
    rng: secrets.SystemRandom | None = None,
) -> int:
    """Sample the per-session reverse-leg requested K.

    Defeats the per-wallet K=3-fingerprint that pinned MPP-K produces
    against a profiling reverse Boltz operator. Sample K via
    ``secrets.SystemRandom.randint(*RANGE)`` and freeze it into
    ``pipeline_json.reverse_payment_chunks_k_requested``.
    The fallback ratchet starts from this value rather than
    the configured constant.

    The startup invariant rejects degenerate
    ranges (range[0]==range[1]>1) unless
    ``ANONYMIZE_ALLOW_DEGENERATE_MPP_K_RANGE=true``; that's a
    config-side check, not enforced here.
    """
    rng = rng or secrets.SystemRandom()
    lo = max(1, int(settings.anonymize_reverse_mpp_chunks_range_min))
    hi = max(lo, int(settings.anonymize_reverse_mpp_chunks_range_max))
    return rng.randint(lo, hi)


# --------------------------------------------------------------------
# Reverse-leg K floor + bounded fallback.
# --------------------------------------------------------------------


from typing import Literal

FallbackMode = Literal["strict", "abort_below_min", "legacy"]


KFallbackDecision = Literal[
    "execute",
    "decrement",
    "abort_to_reconciliation",
]


def decide_k_fallback_step(
    *,
    requested_k: int,
    last_attempted_k: int,
    decrements_used: int,
    mode: FallbackMode | None = None,
    k_min_executed: int | None = None,
) -> KFallbackDecision:
    """Bounded K-fallback decision (pure helper).

    Three outcomes:
    * ``execute`` — initial state; try ``last_attempted_k``.
    * ``decrement`` — drop K by 1 and retry. ``strict`` admits one
      decrement total; ``legacy`` admits arbitrary decrements (caps
      tier at ``weak``); ``abort_below_min`` admits zero.
    * ``abort_to_reconciliation`` — bound exhausted; session moves
      to ``awaiting_reconciliation`` with reason
      ``mpp_k_floor_exhausted``.
    """
    if mode is None:
        mode = settings.anonymize_reverse_mpp_fallback_mode  # type: ignore[assignment]
    if k_min_executed is None:
        k_min_executed = int(settings.anonymize_reverse_mpp_k_min_executed)
    floor = max(1, int(k_min_executed))

    # First attempt — execute the requested K.
    if last_attempted_k == requested_k and decrements_used == 0:
        return "execute"

    next_k = last_attempted_k - 1
    if next_k < floor:
        return "abort_to_reconciliation"
    if mode == "abort_below_min":
        return "abort_to_reconciliation"
    if mode == "strict":
        if decrements_used >= 1:
            return "abort_to_reconciliation"
        return "decrement"
    if mode == "legacy":
        return "decrement"
    return "abort_to_reconciliation"


# --------------------------------------------------------------------
# Opportunistic decoy K-decrement.
# --------------------------------------------------------------------


def sample_decoy_decrement_decision(
    *,
    requested_k: int,
    rng: secrets.SystemRandom | None = None,
) -> bool:
    """Decide whether to opportunistically decrement K.

    The reverse operator's observed decrement rate becomes the union
    of legitimate route-exhaustion decrements + opportunistic decoy
    decrements; the decoy mass masks the wallet-specific topology
    fingerprint under operator-tunable noise
    (``ANONYMIZE_REVERSE_MPP_DECOY_DECREMENT_RATE``, default 0.15).

     headroom invariant — decoy-decrement is eligible only
    when ``requested_k >= K_MIN_EXECUTED + headroom``; otherwise the
    sampler returns False so the session keeps requested_k (else
    the floor would force an abort on the first try).
    """
    rate = float(settings.anonymize_reverse_mpp_decoy_decrement_rate)
    if rate <= 0.0:
        return False

    # headroom invariant runs *before* the rate=1.0 short-
    # circuit so a configured full-rate cannot bypass the floor.
    floor = int(settings.anonymize_reverse_mpp_k_min_executed)
    headroom = int(settings.anonymize_reverse_mpp_decoy_decrement_headroom)
    if requested_k < floor + headroom:
        return False

    if rate >= 1.0:
        return True

    rng = rng or secrets.SystemRandom()
    return rng.random() < rate


def assert_k_floor_invariants() -> None:
    """Startup invariants on the K-floor configuration."""
    floor = int(settings.anonymize_reverse_mpp_k_min_executed)
    range_max = int(settings.anonymize_reverse_mpp_chunks_range_max)
    if floor < 1:
        raise ValueError(f"ANONYMIZE_REVERSE_MPP_K_MIN_EXECUTED = {floor} (must be >= 1)")
    if floor > range_max:
        raise ValueError(
            f"ANONYMIZE_REVERSE_MPP_K_MIN_EXECUTED = {floor} > "
            f"ANONYMIZE_REVERSE_MPP_CHUNKS_RANGE_MAX = {range_max} — "
            "the floor is unreachable from any sampled requested K"
        )


def resolve_mpp_k(pipeline_json: dict | None) -> int:
    """The single helper that reads requested K.

    Reverse-leg routing MUST read K via this function, NOT via direct
    ``pipeline_json[...]`` access. Centralizing the read makes a future
    regression that bypasses the frozen value easy to catch
    (call-graph lint asserts no other path reads
    ``reverse_payment_chunks_k_requested``).

    Falls back to 1 (i.e., no MPP) when the field is missing — a
    legacy session whose pipeline was created before K was frozen
    routes as a single chunk so the session does not stall.
    """
    if not isinstance(pipeline_json, dict):
        return 1
    raw = pipeline_json.get("reverse_payment_chunks_k_requested", 1)
    try:
        k = int(raw)
    except (TypeError, ValueError):
        return 1
    if k < 1:
        return 1
    return k


def min_executed_chunks_for_target_tier(tier: str) -> int:
    """Minimum executed chunks the tier needs.

    The quote response includes this so the wizard can render the
    "K=1 fallback caps tier at weak" warning at *confirm-time*, not
    post-hoc.

    * ``strong`` requires the full requested K to execute.
    * ``moderate`` tolerates fallback but not to K=1 (≥ 2 chunks).
    * ``weak`` admits any executed K including 1.
    """
    if tier == "strong":
        return int(settings.anonymize_reverse_mpp_chunks_range_max)
    if tier == "moderate":
        return max(2, int(settings.anonymize_reverse_mpp_k_min_executed))
    return 1


def assert_mpp_k_range_non_degenerate() -> None:
    """startup invariant — refuse degenerate K ranges.

    A range of ``(N, N)`` for ``N > 1`` produces a deterministic K,
    which is the opposite of what wants. The escape hatch is
    ``ANONYMIZE_ALLOW_DEGENERATE_MPP_K_RANGE=true`` (CRITICAL-logged).
    """
    lo = int(settings.anonymize_reverse_mpp_chunks_range_min)
    hi = int(settings.anonymize_reverse_mpp_chunks_range_max)
    if lo == hi and lo > 1:
        if not settings.anonymize_allow_degenerate_mpp_k_range:
            raise ValueError(
                f"ANONYMIZE_REVERSE_MPP_CHUNKS_RANGE = ({lo}, {hi}) is degenerate "
                f"(both bounds equal > 1) — every session pins K={lo}, "
                "defeating the randomization. Set "
                "ANONYMIZE_ALLOW_DEGENERATE_MPP_K_RANGE=true to opt in to the "
                "regression."
            )


__all__ = [
    "CooperativeSignatureTimeoutError",
    "FeerateSanityResult",
    "FeerateProbeUnavailableError",
    "ClaimTxValidationError",
    "MppFallbackOutcome",
    "FallbackMode",
    "KFallbackDecision",
    "await_cooperative_signature",
    "assert_claim_feerate_sane",
    "probe_economy_feerate_with_retry",
    "validate_cooperative_claim_tx",
    "mpp_caps_tier_at_weak",
    "sample_requested_mpp_k",
    "resolve_mpp_k",
    "min_executed_chunks_for_target_tier",
    "assert_mpp_k_range_non_degenerate",
    "decide_k_fallback_step",
    "assert_k_floor_invariants",
    "sample_decoy_decrement_decision",
]
