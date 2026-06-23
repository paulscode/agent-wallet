# SPDX-License-Identifier: MIT
"""Per-leg operator selection for on-chain anonymize sessions.

Default policy: canonical Boltz on the **reverse** leg (where the
destination address is visible) and a curated alt operator on the
**submarine** leg (where only the funding UTXO is visible — which
under the threat model already assumes is identity-linked).

A pre-funding fallback chain (Middleway → Eldamar → user-consented
single-operator-Boltz) lets a single alt-operator outage degrade
gracefully without forcing the user to abandon the session. Once the
user has funded the submarine lockup, the operator is fixed for that
session and the existing refund machinery handles failures.

Selection happens at quote-build time; the result is bound into the
signed quote token and persisted on the session row at session-create
time. The session-create handler does NOT re-run selection.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Literal

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.http_limits import request_capped

from .metadata import ANONYMIZE_LOGGER_NAME
from .operators import OperatorEntry
from .tor import resolve_socks_host, resolve_socks_port

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


# ── Probe status enum ────────────────────────────────────────

ProbeStatus = Literal[
    "selected",  # probe succeeded; candidate chosen
    "unreachable",  # connect/TLS/timeout/5xx/sig-fail
    "degraded",  # in all_degraded_operator_ids
    "skipped_amount_unsupported",  # /pairs cache says maximal < bin
    "skipped_explicit_config",  # configured chain didn't include it
]


@dataclass(frozen=True)
class ChainAttempt:
    """One candidate the selector considered for the submarine slot."""

    operator_id: str
    status: ProbeStatus


# ── Outcome types ────────────────────────────────────────────


@dataclass(frozen=True)
class OperatorSelectionResult:
    """Successful selection. Carries both legs + chain trajectory."""

    submarine: OperatorEntry
    reverse: OperatorEntry
    submarine_chain_attempted: tuple[ChainAttempt, ...]
    submarine_primary: str | None
    selection_source: Literal[
        "primary",
        "secondary_after_primary_failed",
        "single_operator_after_chain_exhausted",
    ]


@dataclass(frozen=True)
class SubmarineChainExhausted:
    """Sentinel returned when no submarine candidate passed the three
    gates and the caller did not consent to single-operator fallback."""

    chain_attempted: tuple[ChainAttempt, ...]
    single_operator_fallback_available: bool


@dataclass(frozen=True)
class ReverseProbeFailed:
    """Sentinel returned when the reverse-leg probe failed.

    ``from_single_operator_fallback`` discriminates the two 503 codes
    the quote endpoint maps to.
    """

    operator_id: str
    status: Literal["unreachable", "degraded"]
    from_single_operator_fallback: bool = False


# ── Probe-result cache ─────────────────────────────────────


@dataclass(frozen=True)
class _ProbeCacheEntry:
    reachable: bool
    recorded_at_unix_s: float


# Cache key is ``(operator_id, call_site)`` — listener-specific so a
# successful probe on ``boltz_reverse`` doesn't mask a listener-side
# failure on ``boltz_submarine`` (matters for the consolidated
# single-operator-fallback probe).
_PROBE_CACHE: dict[tuple[str, str], _ProbeCacheEntry] = {}


def _probe_cache_get(
    operator_id: str,
    call_site: str,
) -> _ProbeCacheEntry | None:
    key = (operator_id, call_site)
    entry = _PROBE_CACHE.get(key)
    if entry is None:
        return None
    ttl = float(settings.anonymize_operator_probe_cache_ttl_s)
    if time.time() - entry.recorded_at_unix_s > ttl:
        _PROBE_CACHE.pop(key, None)
        return None
    return entry


def _probe_cache_put(
    operator_id: str,
    call_site: str,
    *,
    reachable: bool,
) -> None:
    _PROBE_CACHE[(operator_id, call_site)] = _ProbeCacheEntry(
        reachable=reachable,
        recorded_at_unix_s=time.time(),
    )


def invalidate_probe_cache(operator_id: str) -> None:
    """Called by :func:`operator_health.record_operator_outlier` so a
    real degradation event bypasses a stale ``reachable`` entry.

    Evicts every cache entry for the operator across all listeners —
    if the operator is degraded, no listener should be trusted to
    keep returning success.
    """
    for key in list(_PROBE_CACHE.keys()):
        if key[0] == operator_id:
            _PROBE_CACHE.pop(key, None)


def _reset_probe_cache_for_tests() -> None:
    """Test helper — never call from production code."""
    _PROBE_CACHE.clear()


# ── Capacity pre-filter ────────────────────────────────────


def _capacity_supports_bin(
    operator_id: str,
    bin_amount_sat: int,
) -> bool:
    """Capacity pre-filter — return False when the cached ``/v2/pairs`` data says
    this operator can't serve ``bin_amount_sat`` (``maximal < bin``).

    Returns True on cache miss so the probe + actual ``/createswap``
    handle the filtering ("When the cache is empty, the
    selector treats every operator as capacity-OK").
    """
    pair_info = _cached_pair_info_max(operator_id)
    if pair_info is None:
        return True
    return pair_info >= bin_amount_sat


def _cached_pair_info_max(operator_id: str) -> int | None:
    """Read ``payload['BTC']['BTC']['limits']['maximal']`` from the
    quote-cache for ``operator_id``. Returns None when there is no
    cached entry or the payload shape doesn't expose a numeric maximal.

    The quote-cache stores the reverse-pair-info payload from Boltz
    ``GET /swap/reverse``; the maximal field is the operator's upper
    bin limit for the BTC/BTC pair.
    """
    from .quote_cache import CacheKey, get_quote_cache

    cache = get_quote_cache()
    entry = cache.get(CacheKey(operator_id=operator_id, pair="BTC/BTC", asset="BTC"))
    if entry is None:
        return None
    payload = entry.payload or {}
    try:
        # Boltz pair-info shape: {"BTC": {"BTC": {"limits": {"maximal": int}}}}.
        node = payload.get("BTC", {}).get("BTC", {})
        limits = node.get("limits") if isinstance(node, dict) else None
        if isinstance(limits, dict):
            maximal = limits.get("maximal")
            if isinstance(maximal, (int, float)):
                return int(maximal)
    except (AttributeError, TypeError):
        return None
    return None


# ── Probe (fresh network probe) ─────────────────────────────────────


async def _probe_operator(
    *,
    operator: OperatorEntry,
    call_site: Literal["boltz_submarine", "boltz_reverse"],
) -> bool:
    """Issue a cheap ``GET /v2/version`` probe to ``operator`` through
    the per-leg SOCKS listener. Returns True iff the operator is
    reachable.

    The probe is wrapped in a broad ``try/except`` because every
    failure mode (connect, timeout, TLS, 5xx, signature) maps to the
    same ``reachable=False`` cache entry.
    """
    timeout_s = float(settings.anonymize_operator_probe_timeout_s)
    base_url = operator.onion.rstrip("/")
    if "://" not in base_url:
        base_url = "http://" + base_url
    url = f"{base_url}/version"

    try:
        socks_host = resolve_socks_host()
        socks_port = resolve_socks_port(call_site)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "operator-selection: SOCKS listener unresolved for %s call_site=%s: %s",
            operator.operator_id,
            call_site,
            exc,
        )
        return False

    # Build a minimal SOCKS-proxied client; bypass the heavier
    # get_anonymize_client wrapper because the probe doesn't need the
    # JA4 pinning / header lints that protect session-bound egress —
    # /v2/version is a public endpoint everyone hits.
    # httpx ≥0.27 requires the bare ``socks5`` scheme — the underlying
    # socksio library always resolves at the proxy, matching the
    # historical ``socks5h`` semantics.
    proxy = f"socks5://{socks_host}:{socks_port}"
    try:
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=timeout_s,
            http2=False,
        ) as client:
            response = await request_capped(client, "GET", url)
    except (httpx.TimeoutException, httpx.TransportError, httpx.ConnectError) as exc:
        logger.info(
            "operator-selection: probe failed for %s: %s",
            operator.operator_id,
            exc,
        )
        return False
    except Exception as exc:  # noqa: BLE001
        logger.info(
            "operator-selection: probe error for %s: %s",
            operator.operator_id,
            exc,
        )
        return False

    status = response.status_code
    if status >= 500:
        return False
    if 400 <= status < 500 and status != 404:
        # 404 on /v2/version means the operator is up but mis-pathed —
        # treat as available, fall through to actual swap creation.
        return False
    return True


# ── Chain composition ────────────────────────────────────────


@dataclass(frozen=True)
class _ChainConfig:
    """Resolved chain composition for an on-chain session."""

    primary: OperatorEntry | None
    secondary: OperatorEntry | None
    reverse: OperatorEntry
    primary_source: Literal["explicit", "default"]
    secondary_source: Literal["explicit", "default", "absent"]
    reverse_source: Literal["explicit", "default"]


def _resolve_by_id(
    registry: list[OperatorEntry],
    operator_id: str,
) -> OperatorEntry | None:
    for entry in registry:
        if entry.operator_id == operator_id:
            return entry
    return None


def _compute_chain(
    registry: list[OperatorEntry],
) -> _ChainConfig:
    """Resolve (primary, secondary, reverse) for the given registry.

    : env vars take precedence; blank values fall through to
    the default-computation rule (Boltz canonical on reverse;
    remaining operators sorted by last_audit_date desc, then by
    attested volume desc, for primary + secondary).
    """
    # Step 1 — reverse pick.
    cfg_reverse = (settings.anonymize_reverse_operator or "").strip()
    reverse: OperatorEntry | None
    reverse_source: Literal["explicit", "default"]
    if cfg_reverse:
        reverse = _resolve_by_id(registry, cfg_reverse)
        reverse_source = "explicit"
    else:
        reverse = _resolve_by_id(registry, "boltz-canonical")
        if reverse is None and registry:
            reverse = registry[0]
        reverse_source = "default"

    if reverse is None:
        raise RuntimeError("operator-selection: cannot compute reverse leg — registry is empty")

    # Step 2 — submarine pick from non-reverse operators.
    non_reverse = [e for e in registry if e.operator_id != reverse.operator_id]

    cfg_primary = (settings.anonymize_submarine_operator_primary or "").strip()
    cfg_secondary = (settings.anonymize_submarine_operator_secondary or "").strip()

    primary: OperatorEntry | None
    primary_source: Literal["explicit", "default"]
    if cfg_primary:
        primary = _resolve_by_id(registry, cfg_primary)
        primary_source = "explicit"
    elif non_reverse:
        sorted_non_reverse = sorted(
            non_reverse,
            key=lambda e: (
                _sort_key_last_audit(e),
                -int(e.attested_min_24h_volume_satoshis or 0),
            ),
        )
        primary = sorted_non_reverse[0]
        primary_source = "default"
    else:
        primary = None
        primary_source = "default"

    secondary: OperatorEntry | None
    secondary_source: Literal["explicit", "default", "absent"]
    if cfg_secondary:
        secondary = _resolve_by_id(registry, cfg_secondary)
        secondary_source = "explicit"
    elif primary is not None and len(non_reverse) >= 2:
        sorted_non_reverse = sorted(
            [e for e in non_reverse if e.operator_id != primary.operator_id],
            key=lambda e: (
                _sort_key_last_audit(e),
                -int(e.attested_min_24h_volume_satoshis or 0),
            ),
        )
        secondary = sorted_non_reverse[0] if sorted_non_reverse else None
        secondary_source = "default" if secondary else "absent"
    else:
        secondary = None
        secondary_source = "absent"

    return _ChainConfig(
        primary=primary,
        secondary=secondary,
        reverse=reverse,
        primary_source=primary_source,
        secondary_source=secondary_source,
        reverse_source=reverse_source,
    )


def _sort_key_last_audit(entry: OperatorEntry) -> tuple[int, str]:
    """Sort key putting most-recently-audited operators first.

    Strategy: tuple ``(missing_flag, reversed_lex)`` where
    ``missing_flag`` is 0 for present dates (so they sort before
    missing) and the reversed lex string is the per-digit
    complement of the original ISO date so larger dates sort
    earlier under the ascending sort that ``sorted()`` performs.
    """
    raw = (entry.last_audit_date or "").strip()
    if not raw:
        return (1, "")
    # Complement each digit so newer ISO-8601 dates produce smaller
    # strings under ascending lex sort.
    flipped = "".join(str(9 - int(ch)) if ch.isdigit() else ch for ch in raw)
    return (0, flipped)


# ── Per-candidate gate evaluation ──────────────────────────────────


async def _evaluate_candidate(
    candidate: OperatorEntry,
    *,
    bin_amount_sat: int,
    degraded_ids: frozenset[str],
    call_site: Literal["boltz_submarine", "boltz_reverse"],
) -> ProbeStatus:
    """Run the capacity pre-filter, probe-result cache, and fresh
    network probe against ``candidate``. Returns the resulting status."""
    # Probe-cache short-circuit — degraded operators are skipped without probing.
    if candidate.operator_id in degraded_ids:
        return "degraded"

    # Capacity pre-filter.
    if not _capacity_supports_bin(candidate.operator_id, bin_amount_sat):
        return "skipped_amount_unsupported"

    # Probe-result cache (positive or negative). Keyed on
    # ``(operator_id, call_site)`` so a successful probe on one
    # listener doesn't mask a listener-side failure on another.
    cached = _probe_cache_get(candidate.operator_id, call_site)
    if cached is not None:
        return "selected" if cached.reachable else "unreachable"

    # Fresh network probe.
    ok = await _probe_operator(operator=candidate, call_site=call_site)
    _probe_cache_put(candidate.operator_id, call_site, reachable=ok)
    return "selected" if ok else "unreachable"


# ── Reverse-leg probe ───────────────────────────────────────────────


async def _evaluate_reverse(
    reverse: OperatorEntry,
    *,
    degraded_ids: frozenset[str],
) -> tuple[bool, Literal["unreachable", "degraded"] | None]:
    """Probe the reverse operator. Returns ``(reachable, failure_status)``
    where ``failure_status`` is None on success."""
    if reverse.operator_id in degraded_ids:
        return False, "degraded"

    # Reverse probe goes through the reverse-leg SOCKS listener.
    cached = _probe_cache_get(reverse.operator_id, "boltz_reverse")
    if cached is not None:
        if cached.reachable:
            return True, None
        return False, "unreachable"

    ok = await _probe_operator(operator=reverse, call_site="boltz_reverse")
    _probe_cache_put(reverse.operator_id, "boltz_reverse", reachable=ok)
    if ok:
        return True, None
    return False, "unreachable"


# ── Main entry point ─────────────────────────────────────────


async def select_operators_for_onchain_session(
    *,
    registry: list[OperatorEntry],
    bin_amount_sat: int,
    allow_single_operator_fallback: bool,
    db: AsyncSession,
) -> OperatorSelectionResult | SubmarineChainExhausted | ReverseProbeFailed:
    """Resolve the operator pair for an on-chain anonymize session.

    Concurrently probes the configured reverse operator AND walks the
    configured submarine chain in priority order. For each submarine
    candidate, runs the three gates from.

    Outcomes (checked in order; reverse-probe failure wins when both
    fail because the quote can't proceed without a reverse leg):

    * Reverse probe failed → :class:`ReverseProbeFailed`.
    * Submarine chain exhausted (no consent) → :class:`SubmarineChainExhausted`.
    * Submarine chain exhausted (with consent) but consolidated probe
      also failed → :class:`ReverseProbeFailed` (with
      ``from_single_operator_fallback=True``).
    * Both succeed → :class:`OperatorSelectionResult`.
    """
    from .operator_health import all_degraded_operator_ids

    if not registry:
        raise RuntimeError("operator-selection: cannot select operators — registry is empty")

    chain = _compute_chain(registry)
    degraded_ids = await all_degraded_operator_ids(db)

    # Walk the submarine chain. each candidate's probe goes
    # through ``boltz_submarine``. The reverse probe runs concurrently
    # through ``boltz_reverse``; we launch it now and await its result
    # only after the chain walk is complete.
    reverse_task = asyncio.create_task(
        _evaluate_reverse(chain.reverse, degraded_ids=degraded_ids),
    )

    attempts: list[ChainAttempt] = []
    selected_submarine: OperatorEntry | None = None
    selection_source: Literal[
        "primary",
        "secondary_after_primary_failed",
        "single_operator_after_chain_exhausted",
    ] = "primary"

    candidates: list[tuple[OperatorEntry, Literal["primary", "secondary"]]] = []
    if chain.primary is not None:
        candidates.append((chain.primary, "primary"))
    if chain.secondary is not None:
        candidates.append((chain.secondary, "secondary"))

    for candidate, role in candidates:
        status = await _evaluate_candidate(
            candidate,
            bin_amount_sat=bin_amount_sat,
            degraded_ids=degraded_ids,
            call_site="boltz_submarine",
        )
        attempts.append(ChainAttempt(operator_id=candidate.operator_id, status=status))
        if status == "selected":
            selected_submarine = candidate
            selection_source = "primary" if role == "primary" else "secondary_after_primary_failed"
            break

    # Wait for the reverse-leg probe outcome before deciding.
    reverse_ok, reverse_failure_status = await reverse_task

    if selected_submarine is not None and reverse_ok:
        # Happy path: both legs available.
        return OperatorSelectionResult(
            submarine=selected_submarine,
            reverse=chain.reverse,
            submarine_chain_attempted=tuple(attempts),
            submarine_primary=(chain.primary.operator_id if chain.primary is not None else None),
            selection_source=selection_source,
        )

    if not reverse_ok:
        # Reverse-side failure wins.
        return ReverseProbeFailed(
            operator_id=chain.reverse.operator_id,
            status=reverse_failure_status or "unreachable",
            from_single_operator_fallback=False,
        )

    # Submarine chain exhausted (reverse is fine).
    fallback_available = _single_operator_fallback_available(
        chain.reverse,
        bin_amount_sat,
    )
    if not allow_single_operator_fallback:
        return SubmarineChainExhausted(
            chain_attempted=tuple(attempts),
            single_operator_fallback_available=fallback_available,
        )

    # User consented to single-operator fallback. The reverse-leg
    # probe (on the ``boltz_reverse`` listener) succeeded, but the
    # consolidated path also has to route the submarine-leg traffic
    # to the same operator through the ``boltz_submarine`` listener.
    # calls for a consolidated-target probe before declaring the
    # path viable — otherwise we'd return success and the per-session
    # loop would discover at swap-create time that the submarine
    # listener can't reach Boltz canonical.
    consolidated_status = await _evaluate_candidate(
        chain.reverse,
        bin_amount_sat=bin_amount_sat,
        degraded_ids=degraded_ids,
        call_site="boltz_submarine",
    )
    if consolidated_status != "selected":
        # Map the consolidated-probe failure back to the audit /
        # error-response surface. ``from_single_operator_fallback=True``
        # is what makes the quote endpoint emit
        # ``all_submarine_operators_unreachable`` (503) instead of
        # the plain ``reverse_probe_failed``.
        status_for_sentinel: Literal["unreachable", "degraded"] = (
            "degraded" if consolidated_status == "degraded" else "unreachable"
        )
        return ReverseProbeFailed(
            operator_id=chain.reverse.operator_id,
            status=status_for_sentinel,
            from_single_operator_fallback=True,
        )

    return OperatorSelectionResult(
        submarine=chain.reverse,
        reverse=chain.reverse,
        submarine_chain_attempted=tuple(attempts),
        submarine_primary=(chain.primary.operator_id if chain.primary is not None else None),
        selection_source="single_operator_after_chain_exhausted",
    )


def _single_operator_fallback_available(
    reverse: OperatorEntry,
    bin_amount_sat: int,
) -> bool:
    """True iff the resolved reverse operator could serve the
    submarine leg too (capacity-wise).

    The reverse-probe outcome is checked separately by the caller;
    this helper only checks capacity. The reverse-probe success is
    implicit when this helper is called — see the chain-exhaustion
    branch in :func:`select_operators_for_onchain_session`.
    """
    return _capacity_supports_bin(reverse.operator_id, bin_amount_sat)


async def emit_operator_selection_audit_events(
    db: AsyncSession,
    *,
    submarine_operator_id: str | None,
    reverse_operator_id: str | None,
    selection_source: str,
) -> None:
    """Emit per-session selection audit-log rows.

    Called from the session-create handler after the session row is
    persisted (so the audit row reflects a committed selection, not
    a transient quote that might never be acted on).

    Both operator-id fields default to None for LN-only sessions
    that didn't go through the submarine chain; in that case no
    submarine row is emitted.
    """
    from app.models.audit_log import AuditLog
    from app.services.audit_service import _finalize_entry

    if submarine_operator_id is not None:
        sub_entry = AuditLog(
            api_key_id=None,
            api_key_name="__system__",
            action="anonymize_submarine_operator_selected",
            resource="anonymize_session",
            details={
                "operator_id": submarine_operator_id,
                "selection_source": selection_source,
            },
            success=True,
        )
        await _finalize_entry(db, sub_entry)
    if reverse_operator_id is not None:
        rev_entry = AuditLog(
            api_key_id=None,
            api_key_name="__system__",
            action="anonymize_reverse_operator_selected",
            resource="anonymize_session",
            details={"operator_id": reverse_operator_id},
            success=True,
        )
        await _finalize_entry(db, rev_entry)


async def emit_reverse_probe_failed_audit(
    db: AsyncSession,
    *,
    operator_id: str,
    status: Literal["unreachable", "degraded"],
) -> None:
    """Emit an audit row when the reverse-leg probe fails.

    Called at quote-build time. No session row exists yet at this
    point; the audit chain still receives the row (via
    ``_finalize_entry``) so the deployment-wide reverse-probe failure
    rate metric has the right denominator.
    """
    from app.models.audit_log import AuditLog
    from app.services.audit_service import _finalize_entry

    entry = AuditLog(
        api_key_id=None,
        api_key_name="__system__",
        action="anonymize_reverse_probe_failed",
        resource="anonymize_session",
        details={
            "operator_id": operator_id,
            "status": status,
        },
        success=False,
    )
    await _finalize_entry(db, entry)


__all__ = [
    "ChainAttempt",
    "OperatorSelectionResult",
    "ProbeStatus",
    "ReverseProbeFailed",
    "SubmarineChainExhausted",
    "emit_operator_selection_audit_events",
    "emit_reverse_probe_failed_audit",
    "invalidate_probe_cache",
    "select_operators_for_onchain_session",
]
