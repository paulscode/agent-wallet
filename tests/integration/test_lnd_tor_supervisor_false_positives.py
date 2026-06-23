# SPDX-License-Identifier: MIT
"""LND Tor Supervisor — false-positive integration harness.

These tests exercise the REAL supervisor against a real `tor-proxy`
container + stand-in LND target. Their purpose is to confirm that
the supervisor does NOT fire recovery on failure modes where
remediation wouldn't help:

  1. **LND-actually-down:** stop the LND stand-in. Breaker opens
     with `Connection refused`. Supervisor must NOT fire any
     recovery step.

  2. **Wallet cold start:** spin up the stack from scratch.
     Bombard LND with parallel calls during the 0-5 min uptime
     window. Supervisor must log `inhibited_i1` for any signature
     match (not arm a cycle).

  3. **Broad Tor outage:** firewall-drop all egress from
     `tor-proxy`. Multiple onions fail. Supervisor must log
     `inhibited_i4_broad_tor_outage`, not remediate.

  4. **Manual `docker restart tor-proxy`:** restart tor-proxy
     mid-run. For ~30 s after restart, supervisor must log
     `inhibited_i5_recent_tor_restart`.

# ────────────────────────────────────────────────────────────────────
# STATUS: STUB — tests are skipped by default because they require:
#   - A controllable LND stand-in container (responds to / refuses
#     gRPC + REST as the test directs).
#   - A `tor-proxy` container that the test harness can `docker
#     restart` mid-run (so the host running the tests needs Docker
#     socket access — or the tests are run from a separate
#     orchestrator that has it).
#   - Network namespace + iptables manipulation for scenario 3.
#
# To enable in an operator's local validation environment, set
# ``AGENT_WALLET_RUN_TOR_INTEGRATION=1`` and ensure the prerequisites
# above are present. CI runs them as ``skip`` until we have a
# matching CI lane with the harness baked in.
#
# The bodies below document EXACTLY what the test would do, so a
# future implementer doesn't have to re-derive the design.
# ────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import os

import pytest

_HARNESS_ENABLED = os.environ.get("AGENT_WALLET_RUN_TOR_INTEGRATION") == "1"

pytestmark = pytest.mark.skipif(
    not _HARNESS_ENABLED,
    reason=(
        "LND Tor supervisor integration harness not enabled. "
        "Set AGENT_WALLET_RUN_TOR_INTEGRATION=1 with a Docker-compose "
        "harness that exposes a controllable LND stand-in + tor-proxy "
        "restart hook."
    ),
)


@pytest.mark.asyncio
async def test_lnd_actually_down_does_not_trigger_recovery() -> None:
    """Scenario 1 — LND actually down: recovery must not fire.

    Steps:
      1. Stand up the wallet + tor-proxy.
      2. Stop the LND stand-in (`docker stop lnd-stub`).
      3. Wait for ``_LND_BREAKER`` to open with a non-Tor error
         (`Connection refused` — the SOCKS proxy returns this
         when LND's REST port is not bound).
      4. Wait through the supervisor's detect window
         (``LND_TOR_RECOVERY_DETECT_WINDOW_S`` = 60 s default).
      5. Assert no `tor_lnd_recovery_armed` audit in the last
         5 min. The audit log SHOULD contain
         `Connection refused` evidence in `_LND_BREAKER.last_error`
         BUT C2 (Tor-shape classifier) must return False because
         `connection refused` from a TCP-connect-to-LND is NOT
         Tor-shaped (it's after Tor has built the circuit; the
         destination doesn't have a listener).

         Subtle: the classifier DOES include "connection refused"
         in its needle set ([lnd_service.py:165]) — but only
         for "Tor SOCKS port refused" patterns. The string would
         also match "LND REST port refused". We accept this
         imprecision because real-world LND-down scenarios usually
         surface as gRPC `UNAVAILABLE` or httpx
         `ConnectError`/`ConnectTimeout`, not "Connection refused"
         literal. This test must assert no arm — and that's what
         the supervisor walks through, because even if C2 matches,
         C4 (HSFETCH) will succeed (Tor IS healthy; LND's HS
         descriptor IS published) → no arm.
    """
    pytest.skip("harness body — implement against real Docker stack")


@pytest.mark.asyncio
async def test_wallet_cold_start_inhibits_with_i1() -> None:
    """Scenario 2 — wallet cold start: the I1 cold-start inhibit blocks arming.

    Steps:
      1. `docker compose down && docker compose up` (fresh start).
      2. Within the first 5 minutes of uptime, force `_LND_BREAKER`
         open by blocking LND's REST port.
      3. The supervisor's signature check would otherwise match,
         but I1 (`process_start_ts` < 300 s) blocks it.
      4. Assert the audit log contains
         `tor_lnd_recovery_inhibited_i1_cold_start` and NOT
         `tor_lnd_recovery_armed`.
    """
    pytest.skip("harness body — implement against real Docker stack")


@pytest.mark.asyncio
async def test_broad_tor_outage_inhibits_with_i4() -> None:
    """Scenario 3 — broad Tor outage: the I4 broad-outage inhibit blocks arming.

    Steps:
      1. Stand up the wallet + tor-proxy + multiple configured onion
         backends (mempool + electrum).
      2. Apply an iptables DROP rule on all outbound traffic from
         the `tor-proxy` container (or sever its docker network).
      3. After all onions become unreachable, force `_LND_BREAKER`
         open.
      4. Supervisor's C3 probe (other-onion reachability) tries
         the 2 configured onions; both fail.
      5. Assert audit log contains
         `tor_lnd_recovery_inhibited_i4_broad_tor_outage` and NOT
         `tor_lnd_recovery_armed`.
    """
    pytest.skip("harness body — implement against real Docker stack")


@pytest.mark.asyncio
async def test_manual_tor_proxy_restart_inhibits_with_i5() -> None:
    """Scenario 4 — recent manual tor-proxy restart: the I5 inhibit blocks arming.

    Steps:
      1. Stand up the wallet + tor-proxy. Wait for steady state.
      2. Force `_LND_BREAKER` to open via blocked LND.
      3. Operator does `docker compose restart tor-proxy`.
      4. Within ~30 s of tor-proxy restart, supervisor's I5 probe
         (`get_tor_process_uptime_s` returns < 30) blocks the cycle.
      5. Assert audit log contains
         `tor_lnd_recovery_inhibited_i5_recent_tor_restart` for at
         least the first tick after restart.
      6. After ~30 s, the inhibit clears. If LND is still down,
         the cycle SHOULD fire (no longer inhibited) — assert
         `tor_lnd_recovery_armed` appears at T+~30..40 s.
    """
    pytest.skip("harness body — implement against real Docker stack")
