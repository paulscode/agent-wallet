# SPDX-License-Identifier: MIT
"""NTP skew probe + dashboard health-card data.

Every anonymize-egress call leaks our system clock via TLS
records, HTTP ``Date`` headers, JWT timestamps, etc. A wallet host
with a unique skew is identifiable to Boltz across legs even with
stream isolation. The mitigation is operator-side (run NTP via Tor)
plus a startup gate that refuses session creation when skew exceeds
``ANONYMIZE_MAX_CLOCK_SKEW_MS`` (default 100 ms).

Re-probe every 30 minutes; sessions whose deadlines fall
inside the drift window move to ``awaiting_reconciliation``.

This module ships:
* :class:`ClockSkewState` — holds the most-recent measurement so the
  health endpoint and quote/create gates can read without touching
  the network.
* :func:`is_clock_skew_within_threshold` — pure predicate the
  endpoint guards call before admitting a session.
* :func:`update_clock_skew` — called by the recurring probe (filled
  in alongside the supervisor); the value is also stamped at startup
  during :func:`run_anonymize_startup_gates`.

The probe itself (NTP query over Tor) ships with the supervisor; the
state container exists now so the rest of the call sites can read it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Optional

from app.core.config import settings

if TYPE_CHECKING:
    import httpx
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass
class ClockSkewState:
    """Snapshot of the most-recent skew measurement.

    Implemented as a plain dataclass so it can be stashed on
    ``app.state.anonymize_clock`` and updated atomically by the probe.
    The refresh path replaces the whole instance to avoid torn reads.

    ``sample_count`` records how many raw samples backed the median in
    ``skew_ms``. The post-aggregation probe (see
    :func:`aggregate_samples`) sets this to the number of samples that
    survived the trim; older single-sample probe paths and callers
    that don't care leave it at the default ``0``.
    """

    skew_ms: Optional[int] = None
    measured_at_unix_s: Optional[float] = None
    sources_consulted: tuple[str, ...] = field(default_factory=tuple)
    sample_count: int = 0

    @classmethod
    def empty(cls) -> "ClockSkewState":
        return cls()

    def is_stale(self, *, max_age_s: float) -> bool:
        if self.measured_at_unix_s is None:
            return True
        return (time.time() - self.measured_at_unix_s) > max_age_s


# Uniform[0, 1) phase truncation bias correction. floor() of
# the server's wall-clock second always rounds DOWN, so E[delta_raw] =
# true_skew − 500 ms. We add 500 ms back after aggregating to recover
# an unbiased estimator.
_TRUNCATION_BIAS_MS: int = 500


def aggregate_samples(
    raw_delta_ms: list[int],
    *,
    trim_fraction: float,
    min_samples: int,
) -> Optional[int]:
    """Return the trimmed-median + bias-corrected skew estimate.

    Pure / no I/O. The probe loop collects per-sample ``(server_date
    − local_midpoint) * 1000`` deltas; this helper aggregates them into
    a single ``skew_ms`` estimate that is robust to outliers (one Tor
    circuit stall doesn't shift the result) and unbiased (the always-
    rounds-down truncation in the server's ``Date`` header is
    compensated by adding 500 ms back).

    Returns ``None`` when fewer than ``min_samples`` survived (caller
    treats that as "probe failed; leave prior state in place").

    Trim fraction is symmetric: ``trim_fraction=0.15`` drops 15 % from
    each end, then takes the median of the remaining 70 %. A value of
    ``0.0`` reverts to plain median over the full input.
    """
    if not raw_delta_ms or len(raw_delta_ms) < min_samples:
        return None
    ordered = sorted(raw_delta_ms)
    drop = int(len(ordered) * trim_fraction)
    kept = ordered[drop : len(ordered) - drop] if drop > 0 else ordered
    if not kept:
        # Degenerate trim (e.g. trim_fraction=0.5); fall back to the
        # untrimmed median so we still return *something* rather than
        # silently dropping a tick.
        kept = ordered
    median = kept[len(kept) // 2]
    return int(median + _TRUNCATION_BIAS_MS)


def is_clock_skew_within_threshold(state: ClockSkewState) -> bool:
    """Return True iff ``|state.skew_ms| ≤ ANONYMIZE_MAX_CLOCK_SKEW_MS``.

    A ``None`` skew (probe never ran) returns False — fail-closed.

    The default threshold (1000 ms) accommodates Tor circuit
    path-asymmetry: the probe's half-RTT midpoint compensation
    assumes the outbound and inbound legs of the round-trip are
    equal-length, but Tor builds independent paths for each
    direction, so a "perfectly-synced" host clock routinely measures
    a few hundred ms of apparent skew. The aggregation's own
    standard error at N=12 is only ~85 ms — the rest of the budget
    is for Tor reality.

    Tightening this requires either swapping the probe for a
    sub-second time source (NTP / roughtime) or accepting that
    correctly-synced Tor clocks will sometimes be refused.
    """
    if state.skew_ms is None:
        return False
    return abs(state.skew_ms) <= settings.anonymize_max_clock_skew_ms


def update_clock_skew(
    state: ClockSkewState,
    *,
    skew_ms: int,
    sources_consulted: tuple[str, ...] = (),
) -> ClockSkewState:
    """Return a fresh state holding the new measurement.

    The recurring probe builds the new state and atomically swaps it
    onto the holder. Pure / no-side-effect; the caller owns mutation.
    """
    return ClockSkewState(
        skew_ms=int(skew_ms),
        measured_at_unix_s=time.time(),
        sources_consulted=tuple(sources_consulted),
    )


# --------------------------------------------------------------------
# Persisted clock-skew state in ``anonymize_runtime_state``.
# --------------------------------------------------------------------


_CLOCK_SKEW_RUNTIME_STATE_KEY = "clock_skew_state"


async def load_clock_skew_state(db: AsyncSession) -> ClockSkewState:
    """Read the most-recent clock skew measurement from runtime state.

    The NTP probe (when wired) writes its result here via
    :func:`store_clock_skew_state`; the self-broadcast tick
    reads it to decide whether the skew-window gate
    permits firing. An absent record falls back to
    :meth:`ClockSkewState.empty` — that path holds the broadcast,
    which is the fail-closed default.
    """
    from .runtime_state import read_runtime_state

    raw = await read_runtime_state(db, key=_CLOCK_SKEW_RUNTIME_STATE_KEY)
    if not isinstance(raw, dict):
        return ClockSkewState.empty()
    skew_ms = raw.get("skew_ms")
    measured_at = raw.get("measured_at_unix_s")
    sources = raw.get("sources_consulted") or ()
    try:
        skew_ms_int = int(skew_ms) if skew_ms is not None else None
    except (TypeError, ValueError):
        skew_ms_int = None
    return ClockSkewState(
        skew_ms=skew_ms_int,
        measured_at_unix_s=(float(measured_at) if measured_at is not None else None),
        sources_consulted=tuple(sources) if isinstance(sources, (list, tuple)) else (),
    )


# Module-level imports so tests can monkeypatch
# ``clock.get_anonymize_client`` / ``clock.resolve_socks_*`` without
# the function-local ``from .http import ...`` re-resolving on every
# call.
from .http import get_anonymize_client
from .tor import resolve_socks_host, resolve_socks_port


def _clock_skew_sources_fallback_urls() -> tuple[str, ...]:
    """Return URLs from the signed clock-skew sources registry.

    Used when ``ANONYMIZE_CLOCK_SKEW_PROBE_SOURCES`` is blank. The
    registry is a separately-curated, separately-signed artifact
    (independent of the swap-operator registry) so a single compromised
    swap operator cannot simultaneously poison the clock-skew
    measurement and a swap leg.

    Imported lazily to keep this module importable in stripped-down
    environments. Any load/signature failure returns ``()``, in which
    case the probe falls through to ``ClockSkewState.empty`` exactly
    as before — fail-closed, not fail-open.
    """
    try:
        from .clock_skew_sources import load_signed_clock_skew_sources
    except Exception:  # noqa: BLE001
        return ()
    try:
        entries = load_signed_clock_skew_sources()
    except Exception:  # noqa: BLE001
        return ()
    urls: list[str] = []
    for entry in entries or ():
        url = (getattr(entry, "url", "") or "").strip()
        if url:
            urls.append(url)
    return tuple(urls)


async def _single_sample(
    *,
    client: httpx.AsyncClient,
    url: str,
    now_fn: Callable[[], float],
) -> int | None:
    """One HEAD request → raw ``delta_ms`` (uncompensated for truncation bias).

    Takes a pre-opened anonymize HTTP ``client`` so all samples in a
    probe tick share the same SOCKS auth pair (and therefore the same
    Tor circuit). This is required to fit within the
    circuit-rebuild throttle, which permits only a small burst of
    circuit rebuilds per listener per window — opening a fresh client
    per sample would exhaust the budget after ~3 samples.

    Returns ``None`` when the request failed, the response had no
    ``Date`` header, or the header was unparseable. The caller drops
    these and aggregates the survivors.
    """
    import email.utils as _emu

    try:
        request_sent_unix_s = float(now_fn())
        response = await client.head(url)
        response_recv_unix_s = float(now_fn())
    except Exception:  # noqa: BLE001
        return None

    date_hdr = response.headers.get("date")
    if not date_hdr:
        return None
    try:
        parsed = _emu.parsedate_to_datetime(date_hdr)
    except (TypeError, ValueError):
        return None
    server_unix_s = float(parsed.timestamp())
    # Half-RTT midpoint compensation for one-way latency.
    local_unix_s = (request_sent_unix_s + response_recv_unix_s) / 2.0
    return int((server_unix_s - local_unix_s) * 1000.0)


async def probe_clock_skew_via_http(
    *,
    sources: tuple[str, ...] | None = None,
    socks_host: str | None = None,
    socks_port: int | None = None,
    timeout_s: float = 10.0,
    now_fn: Callable[[], float] = time.time,
    progress_fn: Callable[[int], None] | None = None,
) -> ClockSkewState:
    """Measure local clock skew via HTTP ``Date`` headers.

    The probe issues a sequence of ``HEAD`` requests against the
    configured sources through the dedicated ``chain_backend_anonymize``
    SOCKS listener. ``N`` samples (``ANONYMIZE_CLOCK_SKEW_SAMPLES_PER_TICK``,
    default 12) are spread across a ``W``-second window
    (``ANONYMIZE_CLOCK_SKEW_SAMPLE_WINDOW_S``, default 20.0) using
    stratified jittered scheduling so each sample lands at an
    independent sub-second phase of the local clock. The trimmed
    median of the survivors, plus the +500 ms truncation-bias
    correction, becomes the persisted ``skew_ms``.

    Returns :meth:`ClockSkewState.empty` when fewer than
    ``ANONYMIZE_CLOCK_SKEW_MIN_SAMPLES_FOR_DECISION`` samples succeed
    (caller leaves the prior measurement in place rather than
    overwriting with an unreliable one).

    ``sources`` defaults to ``settings.anonymize_clock_skew_probe_sources``;
    when that is blank the probe falls back to URLs from the signed
    ``clock_skew_sources.json`` registry.

    ``progress_fn`` (optional) is called with ``samples_collected`` after
    each sample so the health card can surface live progress to the
    wizard's warm-up banner.
    """
    import asyncio
    import random as _random

    raw_sources = sources
    if raw_sources is None:
        raw_sources = tuple(
            _parse_clock_skew_probe_sources(
                settings.anonymize_clock_skew_probe_sources,
            )
        )
    raw_sources = tuple(s for s in raw_sources if s.strip())
    if not raw_sources and sources is None:
        raw_sources = _clock_skew_sources_fallback_urls()
    if not raw_sources:
        return ClockSkewState.empty()

    resolved_host = socks_host or resolve_socks_host()
    resolved_port = socks_port if socks_port is not None else resolve_socks_port("chain_backend_anonymize")

    n = max(1, int(settings.anonymize_clock_skew_samples_per_tick))
    window_s = max(0.0, float(settings.anonymize_clock_skew_sample_window_s))
    min_samples = max(1, int(settings.anonymize_clock_skew_min_samples_for_decision))
    trim = max(0.0, min(0.49, float(settings.anonymize_clock_skew_trim_fraction)))

    # Stratified jittered schedule: one sample per slot, fired at a
    # random offset within the slot, so per-sample sub-second phases
    # are independent — independent phases are what
    # makes the truncation-noise averaging actually converge.
    slot_width = (window_s / n) if n > 0 else 0.0
    offsets = [(i + _random.random()) * slot_width for i in range(n)] if slot_width > 0 else [0.0] * n

    raw_deltas: list[int] = []
    consulted: set[str] = set()
    t0 = float(now_fn())
    # Open ONE anonymize client for the whole tick. All N samples
    # share the same SOCKS auth pair → Tor reuses the same circuit
    # across samples, which consumes exactly ONE token from the
    # circuit-rebuild budget per tick (instead of N). Per-
    # sample isolation is unnecessary here because we're measuring
    # the local clock, not doing anonymity-sensitive operations.
    try:
        async with get_anonymize_client(
            call_site="chain_backend_anonymize",
            socks_host=resolved_host,
            socks_port=resolved_port,
            timeout_s=timeout_s,
        ) as client:
            for i, fire_offset_s in enumerate(offsets):
                target = t0 + fire_offset_s
                sleep_for = target - float(now_fn())
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)
                # Round-robin sources so no single source sees the
                # rapid-fire pattern; with N=12 / 3 sources each source
                # sees 4 samples.
                url = raw_sources[i % len(raw_sources)]
                delta_ms = await _single_sample(
                    client=client,
                    url=url,
                    now_fn=now_fn,
                )
                if delta_ms is not None:
                    raw_deltas.append(delta_ms)
                    consulted.add(url)
                if progress_fn is not None:
                    try:
                        progress_fn(len(raw_deltas))
                    except Exception:  # noqa: BLE001
                        pass
    except Exception:  # noqa: BLE001
        # Throttled at the get_anonymize_client level or other
        # acquisition error — return whatever samples we collected
        # (if any) and let aggregate_samples decide. The probe runner
        # treats an empty result as "fall back to prior measurement".
        pass

    skew_ms = aggregate_samples(
        raw_deltas,
        trim_fraction=trim,
        min_samples=min_samples,
    )
    if skew_ms is None:
        return ClockSkewState.empty()

    return ClockSkewState(
        skew_ms=skew_ms,
        measured_at_unix_s=float(now_fn()),
        sources_consulted=tuple(sorted(consulted)),
        sample_count=len(raw_deltas),
    )


def _parse_clock_skew_probe_sources(raw: str) -> list[str]:
    """Parse the comma/whitespace-separated sources setting."""
    if not raw:
        return []
    if raw.strip().startswith("["):
        import json as _json

        try:
            arr = _json.loads(raw)
        except _json.JSONDecodeError:
            return []
        return [str(x) for x in arr if isinstance(x, str)]
    out: list[str] = []
    for chunk in raw.replace("\n", ",").split(","):
        s = chunk.strip()
        if s:
            out.append(s)
    return out


async def store_clock_skew_state(db: AsyncSession, state: ClockSkewState) -> None:
    """Persist a :class:`ClockSkewState` snapshot into runtime state."""
    from .runtime_state import write_runtime_state

    await write_runtime_state(
        db,
        key=_CLOCK_SKEW_RUNTIME_STATE_KEY,
        payload={
            "skew_ms": state.skew_ms,
            "measured_at_unix_s": state.measured_at_unix_s,
            "sources_consulted": list(state.sources_consulted),
        },
    )


# --------------------------------------------------------------------
# Mid-flight clock-drift re-assertion.
# --------------------------------------------------------------------


def is_runtime_clock_skew_acceptable(state: ClockSkewState) -> bool:
    """Mid-flight predicate (looser than the create-time gate).

    Some skew over a 72-hour session lifetime is expected; the
    create-time gate (``ANONYMIZE_MAX_CLOCK_SKEW_MS``, default 100)
    is tight, while the runtime tolerance
    (``ANONYMIZE_MAX_RUNTIME_CLOCK_SKEW_MS``, default 5000) is
    permissive enough to accept reasonable drift across hours.

    Returns ``False`` when no measurement has ever been taken
    (fail-closed) so an in-flight session whose probe has never
    succeeded routes to ``awaiting_reconciliation`` rather than
    proceeding on a possibly-bogus clock.
    """
    if state.skew_ms is None:
        return False
    return abs(state.skew_ms) <= settings.anonymize_max_runtime_clock_skew_ms


def is_deadline_inside_skew_window(
    deadline_unix_s: int | float | None,
    *,
    state: ClockSkewState,
    now_unix_s: float | None = None,
) -> bool:
    """Would the deadline fire inside the skew bound?

    A self-broadcast deadline whose miss-window is smaller than our
    measured drift estimate must be held at ``delaying`` rather than
    fired, otherwise a brief NTP excursion would cause a spurious
    self-broadcast and double-leak the chain-backend connection.

    Returns ``True`` when the deadline is *within* the skew window
    of the current wall clock — i.e., we cannot safely tell whether
    the deadline has actually passed.
    """
    if deadline_unix_s is None:
        return False
    if state.skew_ms is None:
        # No measurement: treat as "inside window" so the orchestrator
        # holds rather than fires.
        return True
    skew_s = abs(state.skew_ms) / 1000.0
    now = now_unix_s if now_unix_s is not None else time.time()
    return abs(now - float(deadline_unix_s)) <= skew_s


# --------------------------------------------------------------------
# Mid-flight clock-drift watcher.
# --------------------------------------------------------------------


from dataclasses import dataclass
from typing import Literal

WatcherDecision = Literal[
    "ok",  # skew is within runtime threshold; continue.
    "stale_no_probe",  # we haven't probed in too long; trigger one.
    "drift_excursion",  # latest probe shows skew > runtime threshold;
    # active sessions should move to awaiting_reconciliation.
]


@dataclass(frozen=True)
class ClockWatcherInputs:
    """The pieces the watcher consults on each tick."""

    state: ClockSkewState
    now_unix_s: float
    last_probe_unix_s: float | None  # None when never probed


def _max_state_age_s() -> float:
    """The watcher's "consider state stale" cap.

    Defaults to twice the configured re-probe interval so a single
    missed probe is tolerated before declaring stale.
    """
    return float(settings.anonymize_clock_recheck_interval_s) * 2.0


def watcher_decision(inputs: ClockWatcherInputs) -> WatcherDecision:
    """Pure decision function for the recurring clock watcher.

    The orchestrator's recurring task ticks at
    ``ANONYMIZE_CLOCK_RECHECK_INTERVAL_S`` (default 30 minutes) and
    calls this with the most-recent state. The decision drives:

    * ``ok`` — continue.
    * ``stale_no_probe`` — kick off a new NTP probe; while the probe
      is in flight, the watcher does not transition sessions.
    * ``drift_excursion`` — the latest probe says skew is above the
      runtime threshold; sessions whose deadlines fall inside the
      drift window move to ``awaiting_reconciliation`` (
      handles the per-session decision via
      :func:`is_deadline_inside_skew_window`).
    """
    state = inputs.state
    if state.skew_ms is None:
        # Never probed → kick off the first probe.
        return "stale_no_probe"
    if state.is_stale(max_age_s=_max_state_age_s()):
        return "stale_no_probe"
    if not is_runtime_clock_skew_acceptable(state):
        return "drift_excursion"
    return "ok"


def time_since_last_probe_s(inputs: ClockWatcherInputs) -> float:
    """Helper used by the supervisor to schedule the next probe."""
    if inputs.last_probe_unix_s is None:
        return float("inf")
    return max(0.0, inputs.now_unix_s - inputs.last_probe_unix_s)


__all__ = [
    "ClockSkewState",
    "ClockWatcherInputs",
    "WatcherDecision",
    "is_clock_skew_within_threshold",
    "is_runtime_clock_skew_acceptable",
    "is_deadline_inside_skew_window",
    "update_clock_skew",
    "watcher_decision",
    "time_since_last_probe_s",
    "load_clock_skew_state",
    "store_clock_skew_state",
    "probe_clock_skew_via_http",
]
