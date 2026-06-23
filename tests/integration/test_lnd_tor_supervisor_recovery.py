# SPDX-License-Identifier: MIT
"""LND Tor Supervisor — true-positive integration harness (chutney).

The acceptance test for the WHOLE supervisor: reproduce the
2026-06-01 stale-HS-descriptor incident in a controlled
environment, then assert the supervisor's recovery ladder clears
it within bounded wall-clock time.

# ────────────────────────────────────────────────────────────────────
# Harness design:
#
#   1. Stand up a private Tor network via ``chutney`` with:
#        - 1 client (our `tor-proxy` container, pointed at the
#          private network's authorities)
#        - 3 directory authorities
#        - 4 relays (so onion service descriptors have enough
#          HSDir reachability for v3)
#        - 1 hidden service publisher (stands in for the
#          operator's Start9 LND)
#
#   2. The publisher exposes a stub HTTP server on the onion. The
#      wallet's LND_REST_URL points at this onion.
#
#   3. Variant A — step 1 (HSFETCH) clears:
#        - Wait until the descriptor is published + the wallet's
#          tor-proxy has it cached.
#        - Corrupt the wallet's tor-proxy cached-descs file (write
#          garbage at the offset of the descriptor for our onion).
#        - Issue an LND call → SOCKS error → `_LND_BREAKER` opens.
#        - Within ~60 s, supervisor fires HSFETCH → fresh
#          descriptor → next keepalive succeeds → breaker closes.
#        - Assert audit log contains
#          `tor_lnd_recovery_step_1_outcome` with `success` AND
#          `tor_lnd_recovery_cleared` with `cleared_at_step=hsfetch`.
#
#   4. Variant B — step 2 (NEWNYM) clears:
#        - Same setup, but corrupt in a way that HSFETCH alone
#          doesn't fix (e.g. block one of the HSDirs the
#          descriptor is published to). HSFETCH succeeds at
#          fetching the descriptor but the wallet's *circuits*
#          go through a stale guard that can't reach the new
#          intro points. NEWNYM rebuilds circuits → recovery.
#        - Assert `cleared_at_step=newnym`.
#
#   5. Variant C — step 3 (SIGHUP) clears:
#        - Disable all the HSDirs the descriptor was published to
#          (so HSFETCH+NEWNYM can't help). SIGHUP reloads the
#          consensus + picks fresh HSDirs from the new network
#          view → recovery.
#        - Assert `cleared_at_step=sighup`.
#
#   6. Variant D — step 4/5 (yield + exhausted):
#        - Disable the publisher's onion service entirely.
#          Supervisor walks all 4 steps without clearing →
#          assert `tor_lnd_recovery_yielded_to_healthcheck` then
#          `tor_lnd_recovery_exhausted`.
#
# Each variant has a target wall-clock budget:
#   Variant A: ≤ 2 minutes (the supervisor's acceptance budget — the
#              incident must clear without operator action this fast).
#   Variant B: ≤ 3 minutes.
#   Variant C: ≤ 5 minutes.
#   Variant D: ≤ 10 minutes.
#
# STATUS: STUB — tests are skipped by default because chutney is
# not packaged in the wallet's test environment. To enable, install
# chutney (`pip install chutney` or git-clone from
# https://gitlab.torproject.org/tpo/core/chutney) and set
# ``AGENT_WALLET_RUN_TOR_INTEGRATION=1``.
#
# The bodies below document EXACTLY what the test would do.
# ────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import os
import shutil

import pytest

_HARNESS_ENABLED = os.environ.get("AGENT_WALLET_RUN_TOR_INTEGRATION") == "1"
_CHUTNEY_AVAILABLE = shutil.which("chutney") is not None

pytestmark = pytest.mark.skipif(
    not (_HARNESS_ENABLED and _CHUTNEY_AVAILABLE),
    reason=(
        "LND Tor supervisor true-positive harness needs chutney + "
        "the integration harness flag. Install chutney and set "
        "AGENT_WALLET_RUN_TOR_INTEGRATION=1."
    ),
)


@pytest.mark.asyncio
async def test_step_1_hsfetch_clears_stale_descriptor() -> None:
    """Variant A — within 2 min of incident start, the supervisor
    recovers via HSFETCH (its acceptance budget).

    Implementation steps in module docstring above. Assertions:

      - `tor_lnd_recovery_armed` audit fires.
      - `tor_lnd_recovery_step_1_outcome` audit with
        ``outcome=success``.
      - `tor_lnd_recovery_cleared` audit with
        ``cleared_at_step=hsfetch``.
      - End-to-end wall-clock from breaker-open → breaker-close
        ≤ 120 s.
    """
    pytest.skip("requires chutney private Tor network harness")


@pytest.mark.asyncio
async def test_step_2_newnym_clears_when_hsfetch_alone_insufficient() -> None:
    """Variant B. HSFETCH refreshes the descriptor but the
    wallet's circuits go through a stale guard that can't reach
    the new intro points. NEWNYM clears.

    Assertions:
      - `tor_lnd_recovery_step_1_outcome` with ``outcome=success``
        (HSFETCH did fetch).
      - `tor_lnd_recovery_step_2_started` (HSFETCH wasn't enough).
      - `tor_lnd_recovery_cleared` with
        ``cleared_at_step=newnym``.
    """
    pytest.skip("requires chutney private Tor network harness")


@pytest.mark.asyncio
async def test_step_3_sighup_clears_when_newnym_insufficient() -> None:
    """Variant C. The descriptor was published to HSDirs that are
    now offline; HSFETCH can't fetch (returns FAILED), NEWNYM
    can't help (no descriptor to circuit to). SIGHUP reloads
    consensus + picks fresh HSDirs → success.

    Assertions:
      - `tor_lnd_recovery_step_3_outcome` with ``outcome=success``.
      - `tor_lnd_recovery_cleared` with
        ``cleared_at_step=sighup``.
    """
    pytest.skip("requires chutney private Tor network harness")


@pytest.mark.asyncio
async def test_step_4_yields_then_exhausted_when_publisher_dead() -> None:
    """Variant D. Publisher's onion service is fully down — no
    amount of local Tor manipulation can help. Supervisor walks
    all 4 steps, yields, then declares exhausted.

    Assertions:
      - `tor_lnd_recovery_yielded_to_healthcheck` audit fires.
      - `tor_lnd_recovery_exhausted` audit fires after the yield
        grace period.
      - No subsequent cycles fire within the cooldown window
        (`tor_lnd_recovery_inhibited_i3_cooldown_active` instead).
    """
    pytest.skip("requires chutney private Tor network harness")


@pytest.mark.asyncio
async def test_cycle_cap_disables_after_4_in_24h() -> None:
    """Stress variant. Inject 4 stale-descriptor incidents in
    quick succession (advance the test's clock between cycles).

    After the 4th cycle completes:
      - `tor_lnd_recovery_disabled_cycle_cap` audit fires.
      - 5th induced incident does NOT arm a cycle; instead
        emits `tor_lnd_recovery_inhibited_i3_cooldown_active`.
      - State's ``cycles_disabled_until_ts`` is set to a time
        roughly 24 h after the oldest cycle.
    """
    pytest.skip("requires chutney private Tor network harness")
