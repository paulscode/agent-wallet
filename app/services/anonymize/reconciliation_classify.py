# SPDX-License-Identifier: MIT
"""Reason classifier for ``AWAITING_RECONCILIATION`` recovery.

Each persisted ``awaiting_reconciliation_reason`` maps to one of three
classes that drive recovery behavior:

* **Class A — transient.** The wallet auto-retries with the
  configurable budget (``ANONYMIZE_RECONCILIATION_MAX_RETRIES_TRANSIENT``).
  Examples: ``circuit_rebuild_throttled`` (token bucket refills),
  ``wall_clock_budget_exceeded`` (operator state may have changed),
  ``bounded_retry_exhausted`` (the loop hit too many transient
  failures in a row), ``external_state_unknown`` (Boltz unreachable).

* **Class B — semi-terminal.** Retry a small fixed number of times
  (constant ``MAX_RETRIES_SEMI = 3``; this is intentionally
  NOT configurable because the budget is tied to fund-safety
  semantics — see the constant's docstring). Then escalate.
  Examples: ``mpp_k_floor_exhausted`` (LN routing failed), the
  not-yet-shipped ``claim_feerate_outlier`` and ``stuck_htlc_alarm``.

* **Class C — terminal.** No automated retry. The operator must
  inspect ``last_error`` + the audit log and decide. Examples:
  ``operator_signature_mismatch`` (security-critical),
  ``claim_tx_validation_failed`` (signing error),
  ``clock_skew_exceeds_deadline_margin`` (system-config issue),
  ``pipeline_schema_below_min_supported`` (session predates the
  running schema).

Unknown reason codes default to **Class C** so a new bug-driven
reason can't get silently retried until someone explicitly classifies
it.

The classifier is the gate the cancel-edge consumes:
``is_cancellable(reason)`` is true iff the reason is in the
no-funds-moved subset, which guards
``AWAITING_RECONCILIATION → CANCELLED``.
"""

from __future__ import annotations

from typing import Literal

ReconciliationClass = Literal["A", "B", "C"]

# Class A — transient. Auto-retry by re-entering ``pre_reconciliation_status``.
CLASS_TRANSIENT: ReconciliationClass = "A"
# Class B — semi-terminal. Bounded auto-retry, then escalate.
CLASS_SEMI: ReconciliationClass = "B"
# Class C — terminal. No automated retry. Operator decides.
CLASS_TERMINAL: ReconciliationClass = "C"


# — Class B budget is a code-level constant. Raising this
# above 3 is **unsafe**: Class B reasons all have funds-state implications
# (LN payment may be in flight, claim signing may have failed, operator
# may have changed fees mid-session), so unbounded retries on these
# would either leak through unsafe retries or pile up duplicate audit
# events. If a future deployment legitimately needs to override, add a
# knob then — not by default.
MAX_RETRIES_SEMI = 3


_TRANSIENT_REASONS = frozenset(
    {
        "circuit_rebuild_throttled",
        "wall_clock_budget_exceeded",
        "bounded_retry_exhausted",
        "external_state_unknown",
        "economy_feerate_unavailable",
        # The submarine hop's pre-lockup inbound re-check aborted BEFORE
        # broadcasting the on-chain funding tx because the node can no
        # longer receive the bin amount over Lightning from the provider
        # (inbound dropped since session creation — see the Braiins
        # on-chain deposit gate this mirrors). No funds moved. Classed
        # transient because inbound can legitimately recover (a pending
        # channel confirms, a rebalance lands); behaviourally this resolves
        # exactly like ``bounded_retry_exhausted`` when it fires from
        # FUNDING: there is no ``AWAITING_RECONCILIATION → FUNDING`` resume
        # edge, so the probe escalates the row to FAILED rather than
        # resuming. Clean terminal, no funds at risk; the user re-creates
        # once inbound is back.
        "inbound_insufficient_at_lockup",
    }
)

_SEMI_REASONS = frozenset(
    {
        "mpp_k_floor_exhausted",
        "claim_feerate_outlier",
        "stuck_htlc_alarm",
    }
)

_TERMINAL_REASONS = frozenset(
    {
        "operator_signature_mismatch",
        "claim_tx_validation_failed",
        "clock_skew_exceeds_deadline_margin",
        "pipeline_schema_below_min_supported",
    }
)


# — the cancel-edge ``AWAITING_RECONCILIATION → CANCELLED``
# only fires when no funds have moved. These are the reasons where
# the wallet's state-machine analysis says we can guarantee that:
# - ``circuit_rebuild_throttled``: throttled before the Tor circuit
#   was ever used.
# - ``bounded_retry_exhausted``: the loop wrapped around a tick that
#   never made a fund-moving call (the hop body's idempotency keys
#   protect against double-spends but the bookkeeping is conservative
#   and only marks this set "cancellable" when the per-session loop's
#   own state machine never advanced past pre-payment).
# - ``mpp_k_floor_exhausted``: LN routing failed → no HTLC committed.
# - ``wall_clock_budget_exceeded``: idle-detector flip, by definition
#   pre-payment.
#
# Everything else is either funds-in-flight (Class B post-payment
# reasons) or operator-judgement-required (Class C). The operator
# can always force-FAIL via the fail endpoint; only this set gets
# the user-friendly "Cancel" copy.
_CANCELLABLE_REASONS = frozenset(
    {
        "mpp_k_floor_exhausted",
        "circuit_rebuild_throttled",
        "bounded_retry_exhausted",
        "wall_clock_budget_exceeded",
        # Pre-lockup inbound re-check aborted BEFORE the on-chain funding
        # broadcast — no funds moved, so the user-friendly "Cancel" edge is
        # safe (the alternative is waiting for the probe to escalate to
        # FAILED).
        "inbound_insufficient_at_lockup",
    }
)


def classify_reason(reason: str | None) -> ReconciliationClass:
    """Return the recovery class for a persisted reason code.

    Empty / None / unknown reasons default to Class C so a new
    unclassified reason waits for operator review rather than getting
    auto-retried into a tight loop.
    """
    if not reason:
        return CLASS_TERMINAL
    r = str(reason).strip()
    if r in _TRANSIENT_REASONS:
        return CLASS_TRANSIENT
    if r in _SEMI_REASONS:
        return CLASS_SEMI
    if r in _TERMINAL_REASONS:
        return CLASS_TERMINAL
    return CLASS_TERMINAL  # Default: unknown = operator-actionable.


def is_cancellable(reason: str | None) -> bool:
    """True iff the reason is in the no-funds-moved set.

    Gates the ``AWAITING_RECONCILIATION → CANCELLED`` state-machine
    edge and the dashboard's "Cancel" button on awaiting-reconciliation
    rows. Outside this set the operator must use "Refund" (when funds
    are recoverable) or "Stop trying"/"Mark done" (to FAILED).
    """
    if not reason:
        return False
    return str(reason).strip() in _CANCELLABLE_REASONS


__all__ = [
    "CLASS_TRANSIENT",
    "CLASS_SEMI",
    "CLASS_TERMINAL",
    "MAX_RETRIES_SEMI",
    "ReconciliationClass",
    "classify_reason",
    "is_cancellable",
]
