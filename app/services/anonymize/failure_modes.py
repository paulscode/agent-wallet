# SPDX-License-Identifier: MIT
"""Failure-mode helpers (items 9, 10, 21).

Three concerns landed in one module because they all describe how the
orchestrator turns a transient error into a deterministic state-machine
transition:

* ** item 9** — Boltz error strings can include backend metadata; we
  map known error codes to short user-safe messages and stash the raw
  error in ``anonymize_session_event.detail_json`` for post-mortem.
  The dashboard never echoes the raw upstream error.
* ** item 10** — refund bounds. A session whose total elapsed time
  in any waiting state exceeds the larger of
  ``delay_policy.max_s + 24h`` and ``inter_leg_delay.max_s + 24h``
  auto-transitions to ``failed`` and surfaces a triage notice. The
  bound is computed from the *session's frozen* policy so a
  config change does not retroactively expire in-flight sessions.
* ** item 21** — stuck-HTLC alarm. Orchestrator halts and alerts on
  a stuck HTLC; never auto-force-closes. This module provides the
  predicate + alert payload builder; the LND-side detection lives in
  the orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import settings

# ────────────────────────────────────────────────────────────────────
# Boltz error → user-safe message mapping.
# ────────────────────────────────────────────────────────────────────


# Documented Boltz error codes (subset; the full set is in Boltz's
# OpenAPI schema). Anything not in this map gets the generic fallback.
_BOLTZ_ERROR_USER_MESSAGES: dict[str, str] = {
    "INVALID_INVOICE": ("the swap operator rejected the invoice — check the amount and try again"),
    "INVOICE_AMOUNT_TOO_LOW": ("the swap amount is below the operator's minimum — pick a larger bin"),
    "INVOICE_AMOUNT_TOO_HIGH": ("the swap amount is above the operator's maximum — pick a smaller bin"),
    "INVOICE_EXPIRED": ("the invoice expired before the operator could pay it — create a new session"),
    "PAIR_HASH_MISMATCH": ("the operator's fee schedule changed mid-flight — re-quote and try again"),
    "REFUND_REQUIRED": ("the swap could not complete and is being refunded"),
    "RATE_LIMIT_EXCEEDED": ("the operator is currently rate-limiting requests — try again in a few minutes"),
    "SWAP_NOT_FOUND": ("the operator no longer has a record of this swap — the session has been moved to triage"),
}

_GENERIC_BOLTZ_USER_MESSAGE = (
    "the swap operator returned an error — the session has been moved "
    "to triage; the raw error is in the session event log"
)


@dataclass(frozen=True)
class TriageError:
    """A user-safe message + the raw upstream error for the event log."""

    user_message: str
    raw_error: str
    boltz_error_code: str | None = None


def map_boltz_error(*, code: str | None, raw_error: str) -> TriageError:
    """Return a :class:`TriageError` carrying the user-safe message.

    ``code`` is the Boltz error code (e.g., ``"INVALID_INVOICE"``) when
    the response carried one; ``raw_error`` is the full error string
    that we will stash in ``detail_json``. The user-facing
    ``user_message`` is the entry the dashboard SPA renders.
    """
    if code and code in _BOLTZ_ERROR_USER_MESSAGES:
        msg = _BOLTZ_ERROR_USER_MESSAGES[code]
    else:
        msg = _GENERIC_BOLTZ_USER_MESSAGE
    return TriageError(
        user_message=msg,
        raw_error=raw_error,
        boltz_error_code=code,
    )


# ────────────────────────────────────────────────────────────────────
# Refund bound from frozen policy.
# ────────────────────────────────────────────────────────────────────


# 24-hour grace beyond the policy's max delay.
_REFUND_GRACE_S: int = 24 * 3600


def compute_refund_bound_seconds(
    *,
    delay_policy_max_s: int,
    inter_leg_delay_max_s: int | None,
) -> int:
    """Return the item 10 refund-bound: max waiting-state lifetime.

    A session that exceeds this time in any waiting state auto-fails
    rather than silently sitting on hot funds. The bound is computed
    from the *session's frozen policy* — a config change
    does NOT retroactively expire in-flight sessions, because the
    orchestrator reads from ``pipeline_json``.

    LN-source pipelines have no inter-leg delay; pass
    ``inter_leg_delay_max_s=None``.
    """
    candidates = [int(delay_policy_max_s) + _REFUND_GRACE_S]
    if inter_leg_delay_max_s is not None:
        candidates.append(int(inter_leg_delay_max_s) + _REFUND_GRACE_S)
    return max(candidates)


def is_session_past_refund_bound(
    *,
    session_started_unix_s: float,
    now_unix_s: float,
    delay_policy_max_s: int,
    inter_leg_delay_max_s: int | None,
) -> bool:
    """True iff the session has exceeded its refund-bound."""
    bound_s = compute_refund_bound_seconds(
        delay_policy_max_s=delay_policy_max_s,
        inter_leg_delay_max_s=inter_leg_delay_max_s,
    )
    return (now_unix_s - session_started_unix_s) > bound_s


# ────────────────────────────────────────────────────────────────────
# Stuck-HTLC alarm.
# ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class StuckHtlcAlarm:
    """Alert payload produced when an HTLC has been stuck past threshold.

    The orchestrator emits a :class:`StuckHtlcAlarm` and pauses the
    session for human review; it MUST NOT auto-force-close (the
    force-close tx contains the HTLC output script with the
    ``payment_hash``, which would itself be a chain-side fingerprint —
    ).
    """

    session_id: str
    payment_hash: str
    stuck_for_seconds: float
    cltv_blocks_remaining: int


# Threshold (in seconds) past which an HTLC is considered "stuck".
# The default of 1 hour is conservative; the orchestrator may
# tune this by call site.
DEFAULT_STUCK_HTLC_THRESHOLD_S: int = 3600


def is_htlc_stuck(
    *,
    in_flight_seconds: float,
    threshold_s: int = DEFAULT_STUCK_HTLC_THRESHOLD_S,
) -> bool:
    """True iff the HTLC has been in flight longer than ``threshold_s``."""
    return in_flight_seconds > threshold_s


def build_stuck_htlc_alarm(
    *,
    session_id: str,
    payment_hash: str,
    in_flight_seconds: float,
    cltv_blocks_remaining: int,
) -> StuckHtlcAlarm:
    """Construct an alarm payload for the operator's triage queue."""
    return StuckHtlcAlarm(
        session_id=session_id,
        payment_hash=payment_hash,
        stuck_for_seconds=in_flight_seconds,
        cltv_blocks_remaining=cltv_blocks_remaining,
    )


async def emit_stuck_htlc_alarm(alarm: "StuckHtlcAlarm") -> None:
    """Surface a stuck-HTLC alarm to the operator.

    The alarm fans out via :func:`app.services.alert_service.send_alert`
    so the operator's existing wallet-side alert channel (email,
    webhook, etc.) receives the structured payload. The session-id +
    payment-hash are blinded by the redactor before egress.
    """
    try:
        from app.services.alert_service import send_alert

        await send_alert(
            "anonymize_stuck_htlc",
            (
                f"anonymize HTLC stuck for {alarm.stuck_for_seconds:.0f}s, "
                f"{alarm.cltv_blocks_remaining} blocks of CLTV remaining"
            ),
            details={
                "session_id": alarm.session_id,
                "payment_hash": alarm.payment_hash,
                "stuck_for_seconds": float(alarm.stuck_for_seconds),
                "cltv_blocks_remaining": int(alarm.cltv_blocks_remaining),
            },
        )
    except Exception:  # noqa: BLE001
        # Operator alerting is best-effort; a failure here doesn't
        # block the orchestrator's reconciliation path.
        return


def cltv_margin_bump_blocks() -> int:
    """Extra CLTV blocks added to the HTLC's expiry on retry.

    A stuck HTLC may be the result of a short CLTV margin colliding
    with a slow downstream peer; the orchestrator's retry path
    increases the margin by this many blocks per attempt so a
    persistent peer-latency issue doesn't permanently lock the HTLC.
    """
    return max(0, int(settings.anonymize_stuck_htlc_cltv_margin_bump_blocks))


__all__ = [
    "TriageError",
    "StuckHtlcAlarm",
    "DEFAULT_STUCK_HTLC_THRESHOLD_S",
    "map_boltz_error",
    "compute_refund_bound_seconds",
    "is_session_past_refund_bound",
    "is_htlc_stuck",
    "build_stuck_htlc_alarm",
    "emit_stuck_htlc_alarm",
    "cltv_margin_bump_blocks",
]
