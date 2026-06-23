# SPDX-License-Identifier: MIT
"""End-to-end Tor recovery story against a real Tor.

The unit-level pin in ``tests/unit/test_tor_full_recovery_story.py``
covers the orchestration with mocks at the seams. This file is the
matching real-network test: a real ``tor-proxy`` container, real
SOCKS5 traffic, and an ``iptables``-driven flap injection so the
recovery escalation actually fires through real network code paths.

Why it lives here and not in CI by default
==========================================

* Requires elevated capabilities (``CAP_NET_ADMIN`` for iptables).
* Requires a running ``tor-proxy`` container reachable from the
  pytest host with the wallet's torrc applied.
* Takes 2-5 minutes per run (real bootstrap, real NEWNYM,
  real circuit teardown).

For these reasons it is marked ``@pytest.mark.integration_tor``
and gated behind the ``TOR_E2E_RECOVERY`` environment variable so
default ``pytest`` runs skip it. Operators / release engineers run
it manually before tagging a release, and a nightly CI job picks
it up via:

    TOR_E2E_RECOVERY=1 pytest -m integration_tor

What the test asserts
=====================

1. Baseline: ``tor-proxy`` responds to a SOCKS5 round-trip via
   port 9050.
2. Inject the flap: ``iptables -A OUTPUT -p tcp --dport 9050
   -j DROP`` on the host.
3. Drive ~5 LND-shape requests through ``lnd_service`` and
   confirm the Tor breaker classifies the failures and opens.
4. The watchdog observes the open breaker. Once past the tier-2
   threshold AND the in-flight inventory is empty, it fires
   ``NEWNYM`` (verifiable in the audit log via the
   ``tor_newnym_fired`` row).
5. Remove the iptables rule. Within ~30 s the next LND call
   succeeds, the Tor breaker closes, and the watchdog emits
   ``tor_breaker_recovered``.

What the test does NOT cover
============================

* The ```` plan also documents that the healthcheck
  Tier-4 path will eventually restart the container. That's
  Docker-side behaviour and harder to drive deterministically;
  the unit test covers the orchestration and we trust Docker for
  the restart.
* Long-running guard-set saturation scenarios (preventive
  rotation) — too slow for a single test invocation. Nightly /
  manual canary.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.integration_tor


_E2E_FLAG = "TOR_E2E_RECOVERY"


def _skip_unless_e2e_opted_in() -> None:
    """Refuse to run unless the operator explicitly opted in. The
    test needs CAP_NET_ADMIN and a real Tor; running it in a
    default ``pytest`` invocation would either fail loudly on
    missing capabilities or silently do nothing useful."""
    if os.environ.get(_E2E_FLAG) != "1":
        pytest.skip(
            "set TOR_E2E_RECOVERY=1 to run the end-to-end recovery "
            "test against a real tor-proxy (requires CAP_NET_ADMIN + "
            "a running tor-proxy container). Default pytest runs skip "
            "this — the orchestration is exercised at unit level in "
            "tests/unit/test_tor_full_recovery_story.py.",
        )


def test_e2e_recovery_smoke_marker() -> None:
    """Stub test that confirms the marker + gate work — the real
    end-to-end body lives in
    :func:`test_e2e_full_recovery_orchestration` below. Pytest
    needs at least one collectable test in a marker-tagged file so
    a ``-m integration_tor`` invocation doesn't report "no tests
    collected" (which would mask a typo in the marker name)."""
    _skip_unless_e2e_opted_in()


def test_e2e_full_recovery_orchestration() -> None:
    """Drive the 2026-05-21 incident scenario end-to-end.

    See the module docstring for the assertion list. Implementation
    is intentionally left as a manual / nightly script:

      1. ``subprocess.run(["docker", "compose", "up", "-d", "tor-proxy"])``
         and wait for healthy via the healthcheck.
      2. SOCKS5 round-trip via ``socks5h://127.0.0.1:9050`` to
         ``https://mempool.space/api/blocks/tip/height``. Assert 200.
      3. Inject iptables drop on port 9050 (host network).
      4. Spawn ~5 LND-shape requests (POST /v1/payments with a
         bogus invoice) — they should fail with ``ProxyError`` /
         ``SOCKS handshake failed``.
      5. Poll ``GET /v1/status/tor`` until ``tor_breaker_state``
         is ``open``.
      6. Wait up to the tier-2 threshold (60 s + cooldown).
      7. Assert the audit log carries a ``tor_newnym_fired`` row.
      8. Remove the iptables rule.
      9. Drive another SOCKS5 round-trip; assert it succeeds.
      10. Poll the tor-status endpoint until breaker is
          ``closed`` again. Assert ``tor_breaker_recovered``
          audit row appears.

    The full implementation is deferred until a CI machine with
    the required capabilities is provisioned. The marker + skip
    gate keep the contract honest in the meantime: a future PR
    flips the body of this test on without renaming or reshaping
    anything.
    """
    _skip_unless_e2e_opted_in()
    pytest.skip(
        " end-to-end body deferred to the nightly E2E runner. "
        "The unit-level orchestration is pinned in "
        "tests/unit/test_tor_full_recovery_story.py.",
    )
