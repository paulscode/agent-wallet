# SPDX-License-Identifier: MIT
"""Broadcast-via-Boltz primary path + self-broadcast fallback.

Anonymize sessions default to ``ANONYMIZE_BROADCAST_VIA="boltz"`` —
broadcasting through Boltz removes our IP from mempool propagation
, since Boltz already sees the swap.

The risk is that Boltz controls the wall-clock claim-tx
broadcast time, defeating the randomized broadcast jitter.
The mitigation is a *local* deadline: the orchestrator computes
``broadcast_deadline_unix_s = local_jittered_broadcast_at_ts +
ANONYMIZE_BOLTZ_BROADCAST_GRACE_S`` and self-broadcasts via the
dedicated anonymize chain-backend connection if the
deadline + one poll interval passes without observing the claim
tx on chain. The deadline is **not** sent to Boltz.

 self-broadcast crash-consistency: write
``self_broadcast_attempted_at_ts`` *before* the chain-backend POST so
post-crash startup reconciliation distinguishes "already issued, just
verify chain presence" from "still need to self-broadcast". Without
this, a restart could double-leak our chain-backend connection.

The deadline + self-broadcast decision helpers serve the
reverse-claim path. The actual chain-backend POST + crash-consistency
write happens in the orchestrator's broadcast call site.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

from app.core.config import settings

from .clock import ClockSkewState, is_deadline_inside_skew_window


def compute_boltz_broadcast_deadline(
    *,
    scheduled_broadcast_at_unix_s: float,
    grace_s: int | None = None,
) -> int:
    """Local-only deadline at which we'd self-broadcast.

    The deadline is the scheduled jittered broadcast time plus the
    configured grace. It's *not* transmitted to Boltz — that would be
    a fingerprint of anonymize-wallet behavior (regular Boltz users
    don't supply one), and Boltz needs no cooperation from us to
    honor a deadline we enforce ourselves.
    """
    grace = grace_s if grace_s is not None else int(settings.anonymize_boltz_broadcast_grace_s)
    return int(scheduled_broadcast_at_unix_s) + max(0, grace)


SelfBroadcastDecision = Literal[
    "wait",  # Deadline not yet reached.
    "hold_for_skew",  # Deadline inside the clock-skew window.
    "pause_unhealthy_clock",  # Skew has been unhealthy for >3×grace; stop firing.
    "verify_chain",  # Self-broadcast already issued; just verify presence.
    "self_broadcast",  # Issue the self-broadcast through the dedicated client.
]


@dataclass(frozen=True)
class BroadcastState:
    """Inputs the decision helper needs (no DB I/O at this layer)."""

    broadcast_deadline_unix_s: int | None
    self_broadcast_attempted_at_ts: float | None
    claim_tx_observed_on_chain: bool
    poll_interval_s: int
    skew_unhealthy_since_unix_s: float | None = None


def decide_self_broadcast_action(
    state: BroadcastState,
    *,
    clock_state: ClockSkewState,
    now_unix_s: float | None = None,
) -> SelfBroadcastDecision:
    """Choose the next broadcast-side state-machine step.

    Returns one of the four documented outcomes:

    * ``wait`` — deadline not yet reached, keep polling.
    * ``hold_for_skew`` — deadline lies inside the current
      clock-skew window; the orchestrator stays at ``delaying``
      rather than firing a possibly-premature self-broadcast.
    * ``verify_chain`` — ``self_broadcast_attempted_at_ts`` is set,
      meaning a previous attempt already issued the broadcast;
      restart reconciliation only needs to confirm the tx made it
      onto the chain (no re-submit).
    * ``self_broadcast`` — Boltz missed the deadline + one poll
      interval; issue our own broadcast through the dedicated
      anonymize chain-backend client.
    """
    now = now_unix_s if now_unix_s is not None else time.time()

    # If the chain has already accepted the tx, no further action.
    if state.claim_tx_observed_on_chain:
        return "wait"

    if state.broadcast_deadline_unix_s is None:
        return "wait"

    # Crash-consistency: if a prior attempt already issued the
    # broadcast, do NOT re-submit; only verify presence.
    if state.self_broadcast_attempted_at_ts is not None:
        return "verify_chain"

    # unhealthy-clock gate: if skew has been over the
    # runtime threshold for longer than 3× grace, stop checking
    # the deadline entirely until the watcher recovers.
    if state.skew_unhealthy_since_unix_s is not None:
        pause_threshold_s = 3.0 * float(settings.anonymize_boltz_broadcast_grace_s)
        if now - state.skew_unhealthy_since_unix_s > pause_threshold_s:
            return "pause_unhealthy_clock"

    # Deadline math: only fall back when deadline + one poll interval
    # have passed AND the deadline is comfortably outside the
    # / skew window.
    deadline = float(state.broadcast_deadline_unix_s)
    if now < deadline + state.poll_interval_s:
        return "wait"
    if is_deadline_inside_skew_window(deadline, state=clock_state, now_unix_s=now):
        return "hold_for_skew"
    return "self_broadcast"


def should_use_boltz_broadcast() -> bool:
    """True iff ``ANONYMIZE_BROADCAST_VIA == "boltz"`` (default)."""
    return settings.anonymize_broadcast_via == "boltz"


# --------------------------------------------------------------------
# Restart reconciliation decision.
# --------------------------------------------------------------------


RestartRecoveryAction = Literal[
    "post",  # No prior attempt — safe to issue chain POST.
    "verify_only",  # Prior attempt — verify presence; never re-post.
    "awaiting_reconciliation",  # Verify timed out — escalate.
]


def decide_restart_recovery_action(
    state: BroadcastState,
    *,
    now_unix_s: float | None = None,
    verify_timeout_s: int | None = None,
) -> RestartRecoveryAction:
    """What should the orchestrator do for a session post-restart?

    The invariant is: ``self_broadcast_attempted_at_ts`` is
    written in the **same** transaction that schedules the chain-
    backend POST. After a crash + restart we have exactly three cases:

    * Neither side committed (no row mutation) — ``"post"`` is safe
      because by construction the previous attempt did not reach the
      chain backend.
    * Both sides committed — the row carries the timestamp.
      ``"verify_only"`` is the only safe action: we cannot re-post
      because the previous attempt MAY have reached the chain. If
      ``now - attempted_at > verify_timeout_s`` we escalate to
      ``"awaiting_reconciliation"`` rather than spinning forever.
    * Chain already observed — no action needed; falls into the
      regular wait path, so this helper just returns ``"verify_only"``
      and lets the caller short-circuit.
    """
    if state.self_broadcast_attempted_at_ts is None:
        return "post"
    now = now_unix_s if now_unix_s is not None else time.time()
    timeout = (
        int(verify_timeout_s)
        if verify_timeout_s is not None
        else int(settings.anonymize_self_broadcast_verify_timeout_s)
    )
    if now - state.self_broadcast_attempted_at_ts > float(timeout):
        return "awaiting_reconciliation"
    return "verify_only"


__all__ = [
    "BroadcastState",
    "SelfBroadcastDecision",
    "RestartRecoveryAction",
    "compute_boltz_broadcast_deadline",
    "decide_self_broadcast_action",
    "decide_restart_recovery_action",
    "should_use_boltz_broadcast",
]
