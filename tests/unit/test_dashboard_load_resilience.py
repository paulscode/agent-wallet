# SPDX-License-Identifier: MIT
"""Regression guards for the dashboard's "don't hang forever when LND
is unreachable" contract.

Background: when LND's `.onion` host is unreachable (Tor circuit
wedged, hidden-service descriptor stale, LND restarted) the server-
side LND client can take up to ~2 minutes to give up — retries
multiplying against a 30 s connect timeout. The dashboard's initial
load gates on ``GET /summary``, so without a client-side bound the
"Connecting to node…" spinner runs for that full envelope. The user
sees an indefinite spinner and clicks refresh repeatedly.

The fix pins:

* ``api()`` accepts ``{timeoutMs}`` and aborts the fetch when it
  fires, surfacing a friendly "Request timed out — node may be
  unreachable" error rather than a bare ``AbortError``.
* ``fetchAll()`` passes a 10 s timeout to the ``/summary`` call so
  the dashboard transitions to the error state quickly, exposing
  the existing Retry button.

These tests are regex-against-source so they're cheap and catch the
"someone helpfully refactored the api helper" silent-revert case.
"""

from __future__ import annotations

import re
from pathlib import Path

_DASH_JS = Path(__file__).resolve().parents[2] / "app" / "dashboard" / "static" / "dashboard.js"


def _js() -> str:
    return _DASH_JS.read_text(encoding="utf-8")


def test_api_helper_accepts_optional_timeout() -> None:
    """``api()`` must accept an opts argument with ``timeoutMs`` so
    callers can put a wall-clock bound on individual requests."""
    js = _js()
    sig = re.search(r"async\s+api\s*\(\s*method\s*,\s*path\s*,\s*body\s*,\s*opts\s*\)", js)
    assert sig, (
        "api() signature must be (method, path, body, opts) so callers "
        "can pass {timeoutMs} on a per-request basis. The argument is "
        "load-bearing for the dashboard's no-hang-on-LND-down contract."
    )


def test_api_helper_wires_abort_signal_from_timeout() -> None:
    """The opts.timeoutMs must drive an AbortSignal so the underlying
    fetch is actually cancelled when the deadline fires (not just
    abandoned in JS while the request continues over the wire)."""
    js = _js()
    # ``api()`` is now a thin serialisation wrapper around
    # ``_apiSend(method, path, body, opts)``; the fetch + timeout
    # logic lives in the inner helper. Both names are acceptable
    # entry points to the contract — inspect whichever holds the
    # body.
    m = re.search(
        r"async\s+_apiSend\s*\([^)]*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "_apiSend() method body not found"
    body = m.group("body")
    assert "opts" in body and "timeoutMs" in body, "api() must consult opts.timeoutMs"
    # And it must wire that into an AbortSignal (either the modern
    # AbortSignal.timeout(ms) or a manual AbortController fallback —
    # both are acceptable, but at least one must appear).
    has_abort_signal = "AbortSignal.timeout" in body or "AbortController" in body
    assert has_abort_signal, (
        "api() must wire opts.timeoutMs into an AbortSignal so the fetch is actually cancelled when the deadline fires"
    )
    # The signal must be passed into the fetch options.
    assert "signal" in body, "api() must pass the abort signal into fetch() via reqOpts.signal"


def test_api_helper_translates_abort_to_friendly_error() -> None:
    """When the fetch aborts (timeout), the user-facing error must
    explain the likely cause (LND/Tor unreachable) rather than the
    raw browser ``AbortError`` / ``TimeoutError`` string."""
    js = _js()
    m = re.search(
        r"async\s+_apiSend\s*\([^)]*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m
    body = m.group("body")
    # The catch must check for AbortError / TimeoutError and produce
    # a friendly message that mentions either timed-out or unreachable.
    assert "AbortError" in body or "TimeoutError" in body, (
        "api()'s catch block must distinguish timeout/abort from other errors so it can produce a friendly message"
    )
    # Find the actual `if` branch that handles the AbortError. The
    # regex must look for the conditional check on e.name, not just
    # any mention of "AbortError" (which appears in code comments).
    abort_branch = re.search(
        r"e\.name\s*===\s*'(?:AbortError|TimeoutError)'.*?throw\s+err",
        body,
        re.DOTALL,
    )
    assert abort_branch, (
        "api()'s catch block must have an `if (e.name === 'AbortError' …)` "
        "branch that throws a friendly Error — without it the user "
        "would see the bare browser AbortError message"
    )
    handler = abort_branch.group(0)
    assert re.search(r"timed out|unreachable|LND|Tor", handler, re.IGNORECASE), (
        "the timeout/abort branch must surface a hint about LND/Tor "
        "connectivity so the user has somewhere to start debugging "
        "instead of just seeing 'Failed to fetch'"
    )


def test_fetch_all_passes_timeout_to_summary() -> None:
    """The dashboard's initial load gates on ``/summary``. That call
    MUST carry a wall-clock timeout so an unreachable LND can't
    block the dashboard for the full server-side retry envelope
    (~2 minutes worst case)."""
    js = _js()
    m = re.search(
        r"async\s+fetchAll\s*\(\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "fetchAll() method body not found"
    body = m.group("body")
    # The /summary fetch must include a timeoutMs argument.
    summary_call = re.search(
        r"this\.api\(\s*'GET'\s*,\s*'/summary'\s*,\s*null\s*,\s*"
        r"\{[^}]*timeoutMs\s*:\s*(?P<ms>\d+)[^}]*\}\s*\)",
        body,
    )
    assert summary_call, (
        "fetchAll() must call api('/summary') with a {timeoutMs} option "
        "so the gating fetch can't hang the dashboard indefinitely when "
        "LND is unreachable via Tor"
    )
    # Pin a reasonable upper bound — generous enough to absorb a
    # warm-Tor round trip, tight enough that the user doesn't give
    # up first.
    timeout_ms = int(summary_call.group("ms"))
    assert 5000 <= timeout_ms <= 15000, (
        f"summary timeout should be in the 5-15 s range (got {timeout_ms} ms) "
        "— shorter would cut off legitimately slow Tor handshakes; longer "
        "would defeat the point of the timeout"
    )
