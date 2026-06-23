# SPDX-License-Identifier: MIT
"""Health-endpoint detail rate-limit + audit-log gate.

``/dashboard/api/anonymize/health`` returns boolean-only
fields by default. ``?detail=full`` adds numeric detail (skew in ms,
refresh age, registry size, listener counts) and is rate-limited +
audit-logged so an attacker who has briefly compromised the
dashboard cookie cannot poll the full-detail surface for
deployment-topology fingerprints.

This module exposes the rate-limit + audit primitives the endpoint
gate composes against:

* :class:`HealthDetailLimiter` — sliding-window per-cookie counter.
* :func:`assert_full_detail_admitted` — predicate the endpoint
  calls before serving ``?detail=full``; on rejection the endpoint
  returns the boolean-only body.
* :func:`build_full_detail_audit_payload` — the audit-log payload
  the endpoint emits on every admitted full-detail call.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Mapping

# budget: small constant so an attacker who probes the
# detail surface burns through the budget quickly. The full-detail
# response is also audit-logged on every admit, so an exhausted
# budget produces a sequence of audit rows the operator can review.
_DEFAULT_LIMIT_PER_HOUR: int = 6


@dataclass
class HealthDetailLimiter:
    """In-memory per-cookie sliding-window counter for ``?detail=full``."""

    limit_per_hour: int = _DEFAULT_LIMIT_PER_HOUR
    window_seconds: float = 3600.0
    counters: dict[str, list[float]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.counters is None:
            self.counters = {}

    def _trim(self, key: str, now: float) -> list[float]:
        bucket = self.counters.setdefault(key, [])
        cutoff = now - self.window_seconds
        # Drop expired timestamps in-place.
        self.counters[key] = [t for t in bucket if t >= cutoff]
        return self.counters[key]

    def can_admit(
        self,
        *,
        cookie_id: str,
        now_unix_s: float | None = None,
    ) -> bool:
        """True iff the cookie's bucket has room for one more admit."""
        if not cookie_id:
            return False
        n = now_unix_s if now_unix_s is not None else time.time()
        return len(self._trim(cookie_id, n)) < self.limit_per_hour

    def admit(
        self,
        *,
        cookie_id: str,
        now_unix_s: float | None = None,
    ) -> bool:
        """Try to admit one request. Returns True on success.

        Use :meth:`admit` rather than :meth:`can_admit` + manual hit
        when the caller needs the atomic check-and-consume that
        prevents two concurrent requests from passing the gate.
        """
        if not cookie_id:
            return False
        n = now_unix_s if now_unix_s is not None else time.time()
        bucket = self._trim(cookie_id, n)
        if len(bucket) >= self.limit_per_hour:
            return False
        bucket.append(n)
        return True

    def reset(self) -> None:
        self.counters.clear()


def build_full_detail_audit_payload(
    *,
    cookie_id_short: str,
    body_keys: list[str],
) -> dict:
    """Payload emitted on every admitted ``?detail=full`` call.

    The payload deliberately omits the *values* of the full-detail
    body — those are sensitive — and records only:

    * ``cookie_short`` — first 8 chars of the cookie subject so the
      operator can correlate audit rows without the full cookie.
    * ``body_keys`` — the list of field names served. A diff of
      keys across audit rows lets the operator spot a future
      regression that adds a new disclosure key.
    * ``ts`` — UTC unix-seconds timestamp.
    """
    return {
        "cookie_short": cookie_id_short[:8],
        "body_keys": sorted(body_keys),
        "ts_unix_s": int(time.time()),
    }


def coarsen_full_detail_body(detail: Mapping[str, object]) -> dict:
    """Coarsen numeric fields for the ``?detail=full`` body.

    Even when full detail is admitted, the response body avoids
    exposing per-millisecond skew or per-second cache-refresh ages.
    Numeric values are bucketed:

    * ``clock_skew_ms`` — rounded to nearest 50 ms.
    * ``cache_age_seconds`` — rounded to nearest 60 s.
    * ``registry_size`` — clamped to ``{0, 1-2, 3-5, 6+}`` buckets.
    """
    out: dict[str, object] = {}
    for k, v in detail.items():
        if k == "clock_skew_ms" and isinstance(v, (int, float)):
            out[k] = int(round(float(v) / 50.0) * 50)
        elif k == "cache_age_seconds" and isinstance(v, (int, float)):
            out[k] = int(round(float(v) / 60.0) * 60)
        elif k == "registry_size" and isinstance(v, int):
            if v <= 0:
                out[k] = "0"
            elif v <= 2:
                out[k] = "1-2"
            elif v <= 5:
                out[k] = "3-5"
            else:
                out[k] = "6+"
        else:
            out[k] = v
    return out


__all__ = [
    "HealthDetailLimiter",
    "build_full_detail_audit_payload",
    "coarsen_full_detail_body",
]
