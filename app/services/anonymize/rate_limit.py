# SPDX-License-Identifier: MIT
"""Anonymize-stack rate-limit primitives (/ items 71 + 93).

The destination-reuse hard-block has a per-cookie probe limit
to defeat enumeration via the reuse oracle. The hardening
adds two more budgets to defeat cookie-rotation evasion:

* per-cookie (default; binds the limit to the dashboard session).
* per-authenticated-user (when the dashboard supports user accounts;
  unused in the single-user dashboard).
* per-source-IP-or-Tor-circuit (``/24`` IPv4 fallback).

The budgets are walked in *fallback* order: cookie →
authenticated-user → coarse IP. Whichever budget exhausts first
triggers the normalized 422 ``destination_rejected``. Multi-user
onion-service deployments opt into the coarse IP bucket via
``ANONYMIZE_REUSE_CHECK_ALLOW_COARSE_IDENTITY``; default deployment
is single-user with stream isolation.

This module ships the *primitive*: a sliding-window counter and the
identity-fallback resolver. The actual integration with the
dashboard endpoint lands when the create endpoint wires up.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque

from app.core.config import settings


@dataclass
class SlidingWindowCounter:
    """In-memory sliding-window counter.

    The orchestrator can stash one of these per identity-key in a
    dict. For multi-process deployments the production version uses
    Redis; the in-memory primitive is what unit tests exercise.
    """

    window_seconds: float
    timestamps: Deque[float] = field(default_factory=deque)

    def trim(self, *, now: float | None = None) -> None:
        n = now if now is not None else time.monotonic()
        cutoff = n - self.window_seconds
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()

    def count(self, *, now: float | None = None) -> int:
        self.trim(now=now)
        return len(self.timestamps)

    def hit(self, *, now: float | None = None) -> int:
        n = now if now is not None else time.monotonic()
        self.trim(now=n)
        self.timestamps.append(n)
        return len(self.timestamps)


@dataclass(frozen=True)
class RequestIdentity:
    """The trio of identifiers the hierarchy resolves."""

    cookie_id: str | None
    authenticated_user_id: str | None
    source_ip: str | None  # IPv4 or IPv6 string


def _ipv4_slash_24(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    return ".".join(parts[:3]) + ".0/24"


def _ip_block(ip: str) -> str:
    """Return the coarse IP-block key (``/24`` for IPv4, ``/64`` for IPv6)."""
    if ":" in ip:
        return ":".join(ip.split(":")[:4]) + "::/64"
    return _ipv4_slash_24(ip)


def resolve_identity_keys(identity: RequestIdentity) -> tuple[str, ...]:
    """Return the ordered identity tuple to walk.

    Order:
    1. cookie_id (if present)
    2. authenticated_user_id (if present)
    3. coarse IP block (only when
       ``ANONYMIZE_REUSE_CHECK_ALLOW_COARSE_IDENTITY=true``)

    The orchestrator hits each key's bucket in order; whichever
    exhausts first triggers the rejection. Empty tuple ⇒ the request
    has no identity at all (e.g., unauthenticated, no source IP) and
    the caller falls back to the most conservative defense (refuse).
    """
    out: list[str] = []
    if identity.cookie_id:
        out.append(f"cookie:{identity.cookie_id}")
    if identity.authenticated_user_id:
        out.append(f"user:{identity.authenticated_user_id}")
    if identity.source_ip and settings.anonymize_reuse_check_allow_coarse_identity:
        out.append(f"ip:{_ip_block(identity.source_ip)}")
    return tuple(out)


@dataclass
class ThreeBudgetLimiter:
    """A 3-budget sliding-window limiter.

    The orchestrator constructs a per-process instance and looks up
    counters by identity-key. ``check_and_consume`` returns True iff
    *none* of the in-scope buckets is exhausted; on False, the
    caller emits the normalized 422 + the
    ``reuse_check_rate_limited`` event.
    """

    limit_per_window: int
    window_seconds: float
    counters: dict[str, SlidingWindowCounter] = field(default_factory=dict)

    def _bucket(self, key: str) -> SlidingWindowCounter:
        b = self.counters.get(key)
        if b is None:
            b = SlidingWindowCounter(window_seconds=self.window_seconds)
            self.counters[key] = b
        return b

    def check_and_consume(
        self,
        identity: RequestIdentity,
        *,
        now: float | None = None,
    ) -> bool:
        """Return True iff the request may proceed.

        Walks every identity key in order; a request that has zero
        keys is treated as "no identity → refuse" (False).
        """
        keys = resolve_identity_keys(identity)
        if not keys:
            return False
        # Pre-flight: any bucket already at or above the limit?
        for k in keys:
            b = self._bucket(k)
            if b.count(now=now) >= self.limit_per_window:
                return False
        # Consume from every applicable bucket so the limiter doesn't
        # admit a sneak-through path via a key we didn't bump.
        for k in keys:
            self._bucket(k).hit(now=now)
        return True

    def check_and_consume_with_reason(
        self,
        identity: RequestIdentity,
        *,
        now: float | None = None,
    ) -> "ReuseCheckDecision":
        """Same as :meth:`check_and_consume` but exposes which budget
        exhausted, so the ``reuse_check_rate_limited`` audit
        event can record the responsible bucket without revealing the
        exact identity to the audit chain.

        Returns:
            ``ReuseCheckDecision(admitted=True, exhausted_bucket=None)``
            on success.
            ``ReuseCheckDecision(admitted=False, exhausted_bucket="cookie"|"user"|"ip"|None)``
            on rejection. ``None`` indicates the request had no
            identity at all (caller falls back to the most
            conservative defense).
        """
        keys = resolve_identity_keys(identity)
        if not keys:
            return ReuseCheckDecision(admitted=False, exhausted_bucket=None)
        for k in keys:
            b = self._bucket(k)
            if b.count(now=now) >= self.limit_per_window:
                # Strip the per-identity suffix; only the bucket type leaks.
                bucket_type = k.split(":", 1)[0]
                return ReuseCheckDecision(
                    admitted=False,
                    exhausted_bucket=bucket_type,
                )
        for k in keys:
            self._bucket(k).hit(now=now)
        return ReuseCheckDecision(admitted=True, exhausted_bucket=None)

    def reset(self) -> None:
        self.counters.clear()


@dataclass(frozen=True)
class ReuseCheckDecision:
    """Rate-limit decision shape consumed by the create endpoint.

    The audit event records only ``exhausted_bucket`` (``"cookie"`` /
    ``"user"`` / ``"ip"``), never the identity itself, so the audit
    chain remains identity-blinded.
    """

    admitted: bool
    exhausted_bucket: str | None  # "cookie" | "user" | "ip" | None


__all__ = [
    "SlidingWindowCounter",
    "RequestIdentity",
    "ReuseCheckDecision",
    "ThreeBudgetLimiter",
    "resolve_identity_keys",
]
