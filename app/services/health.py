# SPDX-License-Identifier: MIT
"""Process-wide service-health registry.

Every external dependency owns one :class:`ServiceHealth` instance.
The registry aggregates them for ``/v1/status/services`` and
``/ready``. The intent is that operators answer "is this service
healthy?" from a single endpoint without reading logs.

Each service module imports :func:`register_health` once at import
time, holds the returned :class:`ServiceHealth`, and updates it from
its retry wrapper. Callers never construct ``ServiceHealth``
directly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.core.resilience import CircuitBreaker

logger = logging.getLogger(__name__)


@dataclass
class ServiceHealth:
    """Health snapshot for one external dependency.

    All fields are read by the JSON serialiser — keep types
    JSON-native and document any non-obvious meaning.
    """

    name: str
    """Short stable identifier (e.g. ``"lnd"``, ``"boltz"``)."""

    enabled: bool = True
    """``False`` when the operator has disabled the dependency
    via config; readers should not treat ``healthy=False`` as an
    outage in that case."""

    last_success_at: datetime | None = None
    last_error: str | None = None
    consecutive_failures: int = 0
    breaker: CircuitBreaker | None = None
    """Optional — services that don't yet have a breaker leave this
    ``None`` and the snapshot omits the field."""

    extra: dict[str, Any] = field(default_factory=dict)
    """Service-specific fields (chain height, peer count, etc.)
    Kept open-ended so each service can surface what's useful
    without coupling the registry to its internals."""

    @property
    def healthy(self) -> bool:
        """A service is healthy when:

        * It is enabled, AND
        * Its breaker (if any) is not open, AND
        * It either has a recent success or has never been called.
        """
        if not self.enabled:
            return True  # disabled is not unhealthy
        if self.breaker is not None and self.breaker.state == "open":
            return False
        # If we've never seen a success but also no failures, treat
        # as healthy (steady state at boot before first call).
        if self.consecutive_failures > 0 and self.last_success_at is None:
            return False
        return True

    def record_success(self) -> None:
        self.last_success_at = datetime.now(timezone.utc)
        self.last_error = None
        self.consecutive_failures = 0
        # NOTE: We deliberately do NOT call ``self.breaker.record_success()``
        # here. The breaker is updated authoritatively by the resilience
        # layer (``with_retry``) and by mutating-call handlers that consult
        # ``before_call`` directly. ``ServiceHealth`` is an observer only.

    def record_failure(self, error: str) -> None:
        self.last_error = error
        self.consecutive_failures += 1
        # NOTE: We deliberately do NOT call ``self.breaker.record_failure()``
        # here. Doing so would:
        #   1. Double-count failures (``with_retry`` already records each
        #      real upstream failure into the breaker), driving
        #      ``consecutive_failures`` well past the configured threshold.
        #   2. Cause exponential growth of ``breaker.last_error`` when
        #      callers feed a ``BreakerOpenError`` message back in: the
        #      message embeds the prior ``last_error`` via ``!r``, so each
        #      pass through doubles the escape depth, eventually OOM'ing
        #      the process.
        # The breaker is the single source of truth; health is an observer.

    def snapshot(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self.name,
            "enabled": self.enabled,
            "healthy": self.healthy,
            "last_success_at": (self.last_success_at.isoformat() if self.last_success_at else None),
            "last_error": self.last_error,
            "consecutive_failures": self.consecutive_failures,
        }
        if self.breaker is not None:
            result["breaker"] = self.breaker.snapshot()
        if self.extra:
            result["extra"] = dict(self.extra)
        return result


# ─── Process-wide registry ───────────────────────────────────────────────

_registry: dict[str, ServiceHealth] = {}


def register_health(
    name: str,
    *,
    enabled: bool = True,
    breaker: CircuitBreaker | None = None,
) -> ServiceHealth:
    """Get-or-create the singleton :class:`ServiceHealth` for ``name``.

    Idempotent — calling twice with the same name returns the same
    instance, so module-level registrations across re-imports
    (e.g. test reload) don't fragment state.
    """
    existing = _registry.get(name)
    if existing is not None:
        # Update enabled / breaker if caller is re-registering with
        # different config (handled in tests).
        existing.enabled = enabled
        if breaker is not None:
            existing.breaker = breaker
        return existing
    h = ServiceHealth(name=name, enabled=enabled, breaker=breaker)
    _registry[name] = h
    return h


def all_health() -> list[ServiceHealth]:
    """Snapshot of every registered service's health (stable order)."""
    return [_registry[k] for k in sorted(_registry.keys())]


def get_health(name: str) -> ServiceHealth | None:
    return _registry.get(name)


def _reset_for_tests() -> None:
    """Drop every registration. Test-only."""
    _registry.clear()
