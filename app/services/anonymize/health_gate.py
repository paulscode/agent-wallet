# SPDX-License-Identifier: MIT
"""Health-gate hysteresis.

A flapping health probe (Tor regression, NTP excursion, operator
unavailability) can rapidly oscillate the global "anonymize healthy"
boolean. Without hysteresis, every flip would tear down per-session
tasks + refuse new sessions, defeating the purpose of the gate.

 mitigation:

* The gate's external boolean is a function of the last ``N`` probe
  results, not the latest single observation (``N =
  ANONYMIZE_HEALTH_FLIP_THRESHOLD``).
* In-flight sessions are insulated from gate flips — they keep
  ticking even when the gate flips to "unhealthy".  The gate only
  affects the *create* endpoint, which 409s with a re-quote hint.
* Operator-unavailable returns ``409`` (with a re-quote suggestion)
  rather than 503 so the SPA can disambiguate "temporary, retry"
  from "outage, stop trying".

This module ships the *pure* hysteresis state-machine + the
admission gate the create endpoint reads. The actual probe loop
that feeds the buffer lives in the recurring scheduler.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque

from app.core.config import settings


@dataclass
class HealthGateState:
    """Sliding window of recent probe results.

    ``recent`` is bounded; pushes past the cap evict from the head.
    Defaults size to ``ANONYMIZE_HEALTH_FLIP_THRESHOLD`` so the gate
    flips after exactly ``N`` consecutive same-direction observations.
    """

    threshold: int
    recent: Deque[bool] = field(default_factory=deque)
    last_gate: bool = True

    @classmethod
    def from_settings(cls) -> "HealthGateState":
        return cls(threshold=int(settings.anonymize_health_flip_threshold))

    def record(self, healthy: bool) -> None:
        """Record one probe outcome."""
        self.recent.append(bool(healthy))
        while len(self.recent) > self.threshold:
            self.recent.popleft()

    def admitted(self) -> bool:
        """Current gate state with hysteresis applied.

        Flips to ``True`` only when the window is FULL and unanimously
        healthy; flips to ``False`` only when the window is FULL and
        unanimously unhealthy. Any other state (mixed window, or a
        not-yet-full window) preserves the previously-decided gate
        state — that's the hysteresis: a single bad probe doesn't
        close the gate, and a single good probe after a closure
        doesn't reopen it.

        On fresh deployment (empty window) the gate is open so
        Lightning-only deployments without an active probe still admit.
        """
        if not self.recent:
            return self.last_gate
        if len(self.recent) < self.threshold:
            return self.last_gate
        if all(self.recent):
            self.last_gate = True
        elif not any(self.recent):
            self.last_gate = False
        # Mixed full window — preserve the last gate.
        return self.last_gate


def operator_unavailable_response_kind() -> str:
    """The dashboard surface uses 409 + re-quote on operator
    unavailability so the SPA can distinguish a transient operator
    failure (let the user re-quote) from an outright outage (stop)."""
    return "409_operator_unavailable_requote"


__all__ = [
    "HealthGateState",
    "operator_unavailable_response_kind",
]
