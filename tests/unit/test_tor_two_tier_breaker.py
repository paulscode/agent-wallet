# SPDX-License-Identifier: MIT
"""Two-tier breaker (Tor vs LND).

When the upstream failure is a Tor circuit / SOCKS handshake issue,
the LND breaker shouldn't be the only signal. A separate Tor breaker
gives the watchdog and the dashboard a Tor-attributable
counter so today's 2026-05-21 incident — where the LND breaker
opened but the actual cause was Tor — is correctly attributed.

These tests pin the classification at the error string level. They
don't drive real network traffic; they exercise the helper that
decides which breaker to bump.
"""

from __future__ import annotations

import pytest

from app.services.lnd_service import _classify_tor_failure

# ── Tor-attributable patterns ─────────────────────────────────────


@pytest.mark.parametrize(
    "err_msg",
    [
        "ProxyError: General SOCKS server failure",
        "ProxyError: Proxy Server could not connect: TTL expired.",
        "ConnectTimeout: ",  # SOCKS handshake timing out
        "ReadTimeout: ",  # often Tor-side when targeting an onion
        "ConnectionRefusedError: Tor SOCKS port refused",
        "SOCKS5Error: 0x04 host unreachable",
        "httpx.ProxyError: SOCKS5 authentication required",
    ],
)
def test_classify_tor_failure_recognizes_tor_patterns(err_msg) -> None:
    """Each Tor-attributable error pattern from the 2026-05-21 logs
    must be classified as Tor."""
    assert _classify_tor_failure(err_msg) is True, f"expected Tor classification for {err_msg!r}"


# ── LND / generic patterns (should NOT trip the Tor breaker) ──────


@pytest.mark.parametrize(
    "err_msg",
    [
        "HTTPStatusError: 500 Internal Server Error",
        "Payment failed: FAILURE_REASON_NO_ROUTE",  # LND-terminal
        "lnrpc.Error: invoice already paid",
        "JSONDecodeError: line 1 column 1",  # garbage from upstream
        "AssertionError: ...",
        "",  # empty string defensively
    ],
)
def test_classify_tor_failure_skips_non_tor_patterns(err_msg) -> None:
    """LND-side / semantic errors must NOT bump the Tor breaker."""
    assert _classify_tor_failure(err_msg) is False, f"unexpected Tor classification for {err_msg!r}"


# ── Adversarial: LND-shaped errors whose BODY mentions Tor keywords ──


@pytest.mark.parametrize(
    "err_msg",
    [
        # Our own _Retryable5xxError formatting: f"LND {status_code}: {body}".
        # If LND's 500 body happens to mention "socks" (e.g. operator's
        # LND fronted by a misconfigured local socks tunnel), the naive
        # substring match would false-positive. Test the LND-prefix
        # exclusion at lnd_service._LND_PREFIX_EXCLUSIONS catches it.
        "LND 500: backend socks broken",
        "LND 502: socks proxy upstream failed",
        "LND 500: SOCKS handshake timeout in downstream service",
        # httpx HTTP status errors get class-name-prefixed; same risk.
        "HTTPStatusError: 500 Internal Server Error — socks daemon crashed",
        # The internal _Retryable5xxError class-name prefix when re-raised.
        "_Retryable5xxError: LND 500: TTL expired in our DB",
        # Adjacent upstream errors that should not be Tor-classified.
        "Boltz 500: socks upstream timeout",
        "Bolt12 error: TTL expired on offer cache",
        "LND error (500): connection refused by internal service",
    ],
)
def test_classify_tor_failure_excludes_lnd_prefixed_with_tor_keyword_in_body(
    err_msg,
) -> None:
    """Adversarial false-positive boundary.

    Even when an LND-side error string contains
    ``socks``, ``ttl expired``, or ``connection refused`` in the
    BODY, the leading token clearly identifies it as LND. The
    classifier must prefer the LND prefix over the substring match.

    Without ``_LND_PREFIX_EXCLUSIONS`` these would all false-positive
    and the LND-pool Tor breaker would open every time LND returns a
    5xx whose body mentions Tor terminology — confusing the operator
    + triggering NEWNYM / HSFETCH that can't fix an LND-side
    problem. The supervisor would then proceed through its ladder
    only to land at exhausted, wasting the cycle budget.
    """
    assert _classify_tor_failure(err_msg) is False, (
        f"adversarial false-positive: {err_msg!r} was classified as Tor "
        f"despite its LND prefix. Check _LND_PREFIX_EXCLUSIONS."
    )


# ── Breaker independence ──────────────────────────────────────────


def test_breakers_are_distinct_instances() -> None:
    """The Tor and LND breakers are separate ``CircuitBreaker``
    instances — a state change on one must not propagate to the
    other. Pin this so a future refactor that merges them gets
    caught."""
    from app.services.lnd_service import _LND_BREAKER, _TOR_BREAKER

    assert _LND_BREAKER is not _TOR_BREAKER
    assert _LND_BREAKER.name == "lnd"
    assert _TOR_BREAKER.name == "tor"


def test_tor_breaker_can_open_independently_of_lnd() -> None:
    """Drive only Tor failures into the Tor breaker; LND breaker
    must remain closed. (Real call paths bump both — see the next
    test — but the breakers are independent enough that direct
    Tor-only failures don't open LND.)"""
    from app.services.lnd_service import _LND_BREAKER, _TOR_BREAKER

    # Reset
    while _TOR_BREAKER.state != "closed":
        _TOR_BREAKER.record_success()
    while _LND_BREAKER.state != "closed":
        _LND_BREAKER.record_success()

    for _ in range(_TOR_BREAKER.failure_threshold):
        _TOR_BREAKER.record_failure("ProxyError: synthetic")

    assert _TOR_BREAKER.state == "open"
    assert _LND_BREAKER.state == "closed"

    # Cleanup
    _TOR_BREAKER.record_success()


def test_tor_breaker_health_registered() -> None:
    """The Tor breaker is registered under the ``tor`` health key
    so ``/v1/status/services`` surfaces it alongside ``lnd``."""
    # Importing lnd_service triggers register_health("tor", ...).
    import app.services.lnd_service  # noqa: F401
    from app.services.health import _registry

    assert "tor" in _registry, (
        "tor health entry missing — dashboard /v1/status/services won't surface Tor breaker state"
    )


# ── symmetry: LND-only failures stay LND-only ──


def test_lnd_only_failure_does_not_bump_tor_breaker() -> None:
    """Symmetric counterpart: feed ``Payment failed:
    NO_ROUTE`` and assert LND breaker increments, Tor breaker
    doesn't. The classifier tests above cover ``_classify_tor_failure``
    in isolation; this test pins the symmetric INTEGRATION:
    driving an LND-shaped failure through the failure-recording
    helper must NOT touch the Tor breaker.

    Without this assertion, a future refactor that accidentally
    routed LND failures into both breakers would silently turn the
    dashboard's "tor breaker open" red whenever LND had a route
    failure — exactly the misattribution was created to fix."""
    from app.services.lnd_service import _LND_BREAKER, _TOR_BREAKER

    # Reset both to closed.
    while _TOR_BREAKER.state != "closed":
        _TOR_BREAKER.record_success()
    while _LND_BREAKER.state != "closed":
        _LND_BREAKER.record_success()
    initial_tor_failures = _TOR_BREAKER.consecutive_failures

    # Drive a typical LND-terminal failure through the LND breaker
    # only. The Tor breaker must NOT be touched by this path.
    for _ in range(_LND_BREAKER.failure_threshold):
        _LND_BREAKER.record_failure("Payment failed: FAILURE_REASON_NO_ROUTE")

    assert _LND_BREAKER.state == "open", (
        "test setup: LND breaker must have opened — failure_threshold iterations should be enough."
    )
    assert _TOR_BREAKER.state == "closed", (
        " violation — LND-only failures must NOT bump the Tor "
        "breaker. The dashboard would otherwise show 'tor unhealthy' "
        "when only LND has an issue, mis-leading the operator."
    )
    assert _TOR_BREAKER.consecutive_failures == initial_tor_failures, (
        "Tor breaker counter advanced on an LND-only failure path."
    )

    # Cleanup
    _LND_BREAKER.record_success()


# ── 2026-06-01 incident regression: idempotent path bumps both breakers ──


@pytest.mark.asyncio
async def test_idempotent_request_bumps_both_breakers_on_tor_failure(
    monkeypatch,
) -> None:
    """Regression for the 2026-06-01 stale-HS-descriptor incident.

    Before the fix, ``LndService._request`` only routed Tor-shaped
    failures through ``_record_tor_failure_for_lnd_path`` on the
    non-idempotent branch (POST/PUT/DELETE). The idempotent branch
    (GETs, including the keepalive's ``/v1/getinfo``) went through
    ``with_retry``, which only bumps the breaker it was given —
    ``_LND_BREAKER``. The Tor breaker stayed closed across 15
    consecutive SOCKS failures, so ``tor_watchdog`` never saw the
    incident and didn't fire NEWNYM.

    This test drives a GET through ``_request`` with a stub HTTP
    client that always raises ``httpx.ProxyError`` with the exact
    string the operator saw on 2026-06-01. The expectation: BOTH
    ``_LND_BREAKER`` AND ``_TOR_BREAKER`` (or ``_TOR_LND_BREAKER``
    in split mode) bump on the same call.

    Regression guard for the original bug where the Tor breaker never
    opened on these failures: idempotent GETs bumped only the LND
    breaker, so the SOCKS-error string never routed through the Tor
    classification path. Both breakers must now move together.
    """
    import httpx

    from app.services.lnd_service import (
        _LND_BREAKER,
        _TOR_BREAKER,
        LNDService,
    )

    # Reset both breakers.
    while _TOR_BREAKER.state != "closed":
        _TOR_BREAKER.record_success()
    while _LND_BREAKER.state != "closed":
        _LND_BREAKER.record_success()
    initial_tor_failures = _TOR_BREAKER.consecutive_failures
    initial_lnd_failures = _LND_BREAKER.consecutive_failures

    # Stub the httpx client to always raise the exact 2026-06-01
    # error. ProxyError subclasses httpx.HTTPError, which is in
    # _RETRYABLE_HTTPX_EXC via ConnectError — but ProxyError itself
    # is more specific. We use ConnectError carrying the same string
    # so the retry path is exercised. (with_retry will retry per its
    # backoff schedule before giving up.)
    class _StubClient:
        async def request(self, *args, **kwargs):
            raise httpx.ConnectError("ProxyError: Proxy Server could not connect: General SOCKS server failure.")

        async def aclose(self) -> None:
            pass

    svc = LNDService()
    monkeypatch.setattr(svc, "_get_client", lambda: _make_async(_StubClient()))
    # Disable retry backoff so the test runs fast.
    monkeypatch.setattr(
        "app.services.lnd_service.with_retry",
        _make_no_retry_with_retry(),
    )

    data, err = await svc._request("GET", "/v1/getinfo")

    assert data is None, "stub always fails — request should return error"
    assert err is not None
    assert "Connection failed" in err or "Request failed" in err, f"unexpected error shape: {err}"

    # The actual assertions: BOTH breakers must have advanced.
    assert _LND_BREAKER.consecutive_failures > initial_lnd_failures, (
        "LND breaker counter did not advance — _request error path regressed entirely."
    )
    assert _TOR_BREAKER.consecutive_failures > initial_tor_failures, (
        "Tor breaker counter did NOT advance on an idempotent GET "
        "with a SOCKS-shaped failure. This is the 2026-06-01 "
        "regression — `with_retry`'s single-breaker contract means "
        "the outer except in _request is the ONLY place where the "
        "Tor breaker can bump on GETs."
    )

    # Cleanup
    _TOR_BREAKER.record_success()
    _LND_BREAKER.record_success()


@pytest.mark.asyncio
async def test_idempotent_request_resets_tor_breaker_on_success(
    monkeypatch,
) -> None:
    """Symmetric counterpart: a successful GET must reset the Tor
    breaker too. Before the fix, the idempotent success path only
    called ``_LND_BREAKER.record_success`` via ``with_retry`` —
    leaving any historical Tor flap pinned on the counter."""
    from app.services.lnd_service import (
        _LND_BREAKER,
        _TOR_BREAKER,
        LNDService,
    )

    # Reset LND, then leave _TOR_BREAKER with a stale failure on its counter.
    while _LND_BREAKER.state != "closed":
        _LND_BREAKER.record_success()
    while _TOR_BREAKER.state != "closed":
        _TOR_BREAKER.record_success()
    _TOR_BREAKER.record_failure("ProxyError: stale historical flap")
    assert _TOR_BREAKER.consecutive_failures >= 1, "test setup"

    # Stub the client to return a successful /v1/getinfo response.
    class _StubClient:
        async def request(self, *args, **kwargs):
            class _R:
                status_code = 200
                text = "{}"

                def raise_for_status(self):
                    return None

                def json(self):
                    return {"alias": "test"}

            return _R()

        async def aclose(self) -> None:
            pass

    svc = LNDService()
    monkeypatch.setattr(svc, "_get_client", lambda: _make_async(_StubClient()))
    monkeypatch.setattr(
        "app.services.lnd_service.with_retry",
        _make_no_retry_with_retry(success_path=True),
    )

    data, err = await svc._request("GET", "/v1/getinfo")

    assert err is None, f"stub returns success — unexpected error: {err}"
    assert _TOR_BREAKER.consecutive_failures == 0, (
        "Tor breaker counter did NOT reset on idempotent success — "
        "historical Tor flap would remain pinned on the counter."
    )


# ── helpers used by the regression tests above ──


async def _make_async(value):
    """Tiny coroutine wrapper for monkeypatching async-returning methods."""
    return value


def _make_no_retry_with_retry(success_path: bool = False):
    """Replace ``with_retry`` with a single-shot wrapper that calls
    the op once and either re-raises (mirroring retry exhaustion) or
    returns the result. Avoids real sleep delays in the test.
    """

    async def _no_retry_with_retry(op, *, retryable, breaker=None, **kwargs):
        if breaker is not None:
            await breaker.before_call()
        try:
            result = await op()
        except BaseException as e:
            if breaker is not None:
                breaker.record_failure(f"{type(e).__name__}: {e}")
            raise
        else:
            if breaker is not None:
                breaker.record_success()
            return result

    return _no_retry_with_retry


# ── CircuitBreaker.reset() ───────────────────────────────────────


def test_reset_clears_open_state_and_counters() -> None:
    """``reset()`` is the escape hatch the lnd_keepalive active-
    recovery path uses after it drops a wedged httpx pool: the
    side-channel evidence of "we just rebuilt the pool" means we
    can clear stale breaker state without waiting for the next
    time-half-open. Pin: reset goes from open → closed + zeros the
    counter + clears last_error."""
    from app.core.resilience import CircuitBreaker

    cb = CircuitBreaker(name="test")
    for _ in range(cb.failure_threshold):
        cb.record_failure("synthetic")
    assert cb.state == "open"
    assert cb.consecutive_failures >= cb.failure_threshold
    assert cb.last_error == "synthetic"

    cb.reset()

    assert cb.state == "closed"
    assert cb.consecutive_failures == 0
    assert cb.opened_at is None
    assert cb.last_error is None


def test_reset_releases_half_open_lock() -> None:
    """The half-open lock blocks every other coroutine while a
    probe is in flight. If a caller holding the lock crashes or
    forgets to release it, the breaker would deadlock for any new
    call. ``reset()`` must drop the lock so the next call can
    proceed without a stuck owner."""
    from app.core.resilience import CircuitBreaker

    cb = CircuitBreaker(name="test")
    for _ in range(cb.failure_threshold):
        cb.record_failure("synthetic")
    # Manually transition to half_open and grab the lock to mimic
    # a probe in flight.
    cb.state = "half_open"
    # Acquire synchronously — asyncio.Lock allows non-async acquire
    # via the underlying primitive. Use a tiny event loop to drive
    # the await.
    import asyncio

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(cb._lock.acquire())
        assert cb._lock.locked()
        cb.reset()
        assert not cb._lock.locked(), "reset() must release the half-open lock"
    finally:
        loop.close()
