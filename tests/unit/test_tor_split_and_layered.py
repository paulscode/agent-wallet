# SPDX-License-Identifier: MIT
"""Split-mode + layered-torrc structural tests.

Pins:
  - The repo ships role-specific torrcs (``torrc.lnd``,
    ``torrc.anonymize``) and an operator-override stub.
  - The Dockerfile copies all three into the image.
  - The entrypoint shim picks the right defaults file based on
    ``$TOR_ROLE``.
  - ``docker-compose.tor-split.yml`` declares the two split-mode
    services with their own volumes + resource limits + envs.
  - Settings ship a ``tor_split_mode`` flag plus the host knobs
    code paths consult to pick a pool.
  - The LND-side Tor breaker is wired in ``lnd_service`` and
    only routes failures when split mode is on.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

_REPO = Path(__file__).resolve().parents[2]
_COMPOSE_SPLIT = _REPO / "docker-compose.tor-split.yml"
_DOCKERFILE = _REPO / "tor-proxy" / "Dockerfile"
_ENTRYPOINT = _REPO / "tor-proxy" / "entrypoint.sh"
_TORRC_LND = _REPO / "tor-proxy" / "torrc.lnd"
_TORRC_ANON = _REPO / "tor-proxy" / "torrc.anonymize"
_OPERATOR = _REPO / "tor-proxy" / "operator.conf"


# ── layered torrc ───────────────────────────────────────────


def test_operator_override_stub_ships_in_repo() -> None:
    """The empty operator override must exist so the image can
    boot when no operator file is mounted (Tor's -f needs the
    file to exist)."""
    assert _OPERATOR.is_file(), (
        "tor-proxy/operator.conf must ship as an empty stub so "
        "Tor's -f flag has a file to read in the default install "
        "."
    )


def test_dockerfile_copies_torrc_layered_structure() -> None:
    """Dockerfile must lay out /etc/tor/torrc.d/00-default.conf
    + .lnd / .anonymize variants + 99-operator.conf."""
    text = _DOCKERFILE.read_text(encoding="utf-8")
    assert "torrc.d/00-default.conf" in text, "Dockerfile must copy the unified torrc into the layered directory."
    assert "torrc.d/00-default.conf.lnd" in text, "Dockerfile must copy the LND-role torrc."
    assert "torrc.d/00-default.conf.anonymize" in text, "Dockerfile must copy the anonymize-role torrc."
    assert "torrc.d/99-operator.conf" in text, "Dockerfile must copy the operator-override stub."


def test_entrypoint_branches_on_tor_role() -> None:
    """Entrypoint must switch on $TOR_ROLE and pick the
    role-appropriate defaults file."""
    text = _ENTRYPOINT.read_text(encoding="utf-8")
    assert "TOR_ROLE" in text, "entrypoint.sh must read $TOR_ROLE to pick the layered defaults file."
    # All three known roles must be handled.
    assert "unified" in text
    assert "lnd)" in text
    assert "anonymize)" in text


def test_entrypoint_passes_both_files_to_tor() -> None:
    """The exec line must use --defaults-torrc + -f so Tor merges
    the wallet defaults with the operator override."""
    text = _ENTRYPOINT.read_text(encoding="utf-8")
    assert "--defaults-torrc" in text, (
        "entrypoint.sh must invoke tor with --defaults-torrc so the operator file can override default directives."
    )
    assert "-f " in text or "-f\n" in text or '-f "' in text, "entrypoint.sh must pass the operator override via -f."


# ── role-specific torrcs ─────────────────────────────────────


def test_torrc_lnd_has_one_socks_port() -> None:
    """LND pool has a single listener on 9050. Anonymize pool has
    8. The whole point of the split is independent guard sets per
    role; SocksPort counts are the structural invariant."""
    text = _TORRC_LND.read_text(encoding="utf-8")
    socks_lines = [ln for ln in text.splitlines() if ln.strip().startswith("SocksPort ") and "0.0.0.0:" in ln]
    assert len(socks_lines) == 1, f"torrc.lnd must declare exactly one SocksPort; got {len(socks_lines)}."
    assert "9050" in socks_lines[0]


def test_torrc_anonymize_has_eight_socks_ports() -> None:
    text = _TORRC_ANON.read_text(encoding="utf-8")
    socks_lines = [ln for ln in text.splitlines() if ln.strip().startswith("SocksPort ") and "0.0.0.0:" in ln]
    assert len(socks_lines) == 8, (
        f"torrc.anonymize must declare eight SocksPorts (one per call site); got {len(socks_lines)}."
    )


def test_split_torrcs_carry_isolation_flags() -> None:
    """Both role files must include IsolateDestAddr +
    IsolateDestPort + IsolateSOCKSAuth on every listener so the
    application's per-call SOCKS auth still triggers isolation
    inside each pool."""
    for path in (_TORRC_LND, _TORRC_ANON):
        text = path.read_text(encoding="utf-8")
        socks_lines = [ln for ln in text.splitlines() if ln.strip().startswith("SocksPort ") and "0.0.0.0:" in ln]
        for ln in socks_lines:
            assert "IsolateDestAddr" in ln, f"{path.name}: {ln!r}"
            assert "IsolateDestPort" in ln, f"{path.name}: {ln!r}"
            assert "IsolateSOCKSAuth" in ln, (
                f"{path.name}: split-mode torrc dropped IsolateSOCKSAuth "
                f"on {ln!r} — application-side per-call auth pairs "
                f"would become no-ops."
            )


def test_split_torrcs_each_carry_control_port_placeholder() -> None:
    """The entrypoint shim's HashedControlPassword injection needs
    to find the placeholder line in whichever role file it
    renders. Either file missing the placeholder would silently
    boot Tor with the literal placeholder comment, leaving the
    control port unauthenticated."""
    for path in (_TORRC_LND, _TORRC_ANON):
        text = path.read_text(encoding="utf-8")
        assert "__HASHED_CONTROL_PASSWORD_LINE__" in text, f"{path.name}: entrypoint placeholder missing."
        assert "ControlPort 0.0.0.0:9100" in text, f"{path.name}: ControlPort directive missing."


# ── compose override ─────────────────────────────────────────


def test_compose_split_declares_both_pools() -> None:
    text = _COMPOSE_SPLIT.read_text(encoding="utf-8")
    assert "tor-lnd:" in text, "docker-compose.tor-split.yml must define a ``tor-lnd`` service."
    assert "tor-anonymize:" in text


def test_compose_split_disables_single_tor_proxy() -> None:
    """The override must deactivate the default tor-proxy service
    so the operator isn't accidentally running THREE Tor
    instances."""
    text = _COMPOSE_SPLIT.read_text(encoding="utf-8")
    # Either replicas: 0 or some explicit disable marker.
    assert "tor-proxy:" in text
    assert "replicas: 0" in text or "scale: 0" in text, (
        "docker-compose.tor-split.yml must deactivate the default tor-proxy service."
    )


def test_compose_split_independent_data_volumes() -> None:
    """Each pool must mount its own DataDirectory volume —
    sharing the volume defeats the wedge-isolation property the
    split is supposed to deliver."""
    text = _COMPOSE_SPLIT.read_text(encoding="utf-8")
    assert "tor_lnd_data" in text, "split compose must declare a tor_lnd_data named volume ."
    assert "tor_anonymize_data" in text


def test_compose_split_sets_tor_role_env_per_pool() -> None:
    """Each container's entrypoint reads $TOR_ROLE to pick which
    default torrc to load. The override must set it explicitly on
    each service (no defaulting)."""
    text = _COMPOSE_SPLIT.read_text(encoding="utf-8")
    # ``TOR_ROLE: lnd`` and ``TOR_ROLE: anonymize`` somewhere in
    # the file — order doesn't matter.
    assert "TOR_ROLE: lnd" in text, "tor-lnd service must set TOR_ROLE=lnd."
    assert "TOR_ROLE: anonymize" in text


def test_compose_split_repoints_api_at_split_services() -> None:
    """The api service must get the split-mode env knobs so the
    code paths route to the right pools without operator
    intervention."""
    text = _COMPOSE_SPLIT.read_text(encoding="utf-8")
    assert 'TOR_SPLIT_MODE: "true"' in text or "TOR_SPLIT_MODE: true" in text
    assert "LND_TOR_PROXY: socks5://tor-lnd:9050" in text
    assert "ANONYMIZE_TOR_SOCKS_HOST: tor-anonymize" in text
    assert "LND_TOR_CONTROL_HOST: tor-lnd" in text


def test_compose_split_both_pools_have_explicit_resource_limits() -> None:
    """Both pool containers must declare memory + cpu
    limits. Unified-mode tor-proxy has 256M / 0.5 CPU; split mode
    halves these per pool (128M + 128M = 256M
    total). Without an explicit limit the host could be OOM'd
    by a runaway Tor descriptor cache.

    Pin both pools individually so a future edit that drops the
    limit from one (but not the other) is still caught."""
    text = _COMPOSE_SPLIT.read_text(encoding="utf-8")
    import re

    # Slice the override into per-service blocks so the limits
    # assertion can scope to one service at a time.
    def _service_block(name: str) -> str:
        start = text.find(f"  {name}:")
        assert start != -1, f"split compose missing service {name!r}"
        rest = text[start:]
        # Find the next top-level service marker (two-space
        # indented "name:" line). We use a simple regex.
        matches = list(re.finditer(r"\n  [a-z][a-z0-9-]*:\n", rest))
        # Matches[0] is the start of THIS service; matches[1] is
        # the next service.
        if len(matches) >= 2:
            return rest[: matches[1].start()]
        return rest

    for pool in ("tor-lnd", "tor-anonymize"):
        block = _service_block(pool)
        assert "memory:" in block, f"split-mode service {pool!r} must declare a memory limit."
        assert "cpus:" in block, f"split-mode service {pool!r} must declare a CPU limit."
        # 128M is the documented per-pool budget (256M total
        # across both pools matches the unified-mode 256M
        # single-instance limit, so split mode doesn't quietly
        # bloat host memory).
        assert "memory: 128M" in block, (
            f"split-mode service {pool!r} must use the documented "
            f"128M per-pool budget so two pools together don't "
            f"exceed the unified single-instance ceiling."
        )


# ── settings + breaker plumbing ──────────────────────────────


def test_settings_default_to_single_mode() -> None:
    """Out-of-the-box ``tor_split_mode`` is False so existing
    deploys don't silently change behaviour."""
    from app.core.config import Settings

    s = Settings()
    assert s.tor_split_mode is False
    assert s.anonymize_tor_socks_host == "tor-proxy"
    assert s.lnd_tor_control_host == ""


def test_lnd_pool_breaker_is_registered_unconditionally() -> None:
    """``tor-lnd`` breaker is always registered so the health
    endpoint shape stays stable across modes — in single mode the
    breaker is just always-closed (never bumped)."""
    # Importing lnd_service registers the breakers.
    import app.services.lnd_service  # noqa: F401
    from app.services.health import get_health

    h = get_health("tor-lnd")
    assert h is not None, (
        "register_health('tor-lnd') must run at module load so /v1/status/services includes the entry in both modes."
    )


def test_lnd_path_failure_routes_by_split_mode_flag() -> None:
    """Verify the routing helper picks the right breaker based
    on ``settings.tor_split_mode``."""
    from app.services.lnd_service import (
        _TOR_BREAKER,
        _TOR_LND_BREAKER,
        _record_tor_failure_for_lnd_path,
    )

    # Reset both breakers to closed before each branch.
    while _TOR_BREAKER.state != "closed":
        _TOR_BREAKER.record_success()
    while _TOR_LND_BREAKER.state != "closed":
        _TOR_LND_BREAKER.record_success()

    initial_tor_failures = _TOR_BREAKER.consecutive_failures
    initial_lnd_pool_failures = _TOR_LND_BREAKER.consecutive_failures

    # Single mode (default): failure routes into the shared breaker.
    with patch("app.core.config.settings.tor_split_mode", False):
        _record_tor_failure_for_lnd_path("simulated single-mode wedge")
    assert _TOR_BREAKER.consecutive_failures == initial_tor_failures + 1
    assert _TOR_LND_BREAKER.consecutive_failures == initial_lnd_pool_failures

    # Split mode: failure routes into the LND-pool breaker only.
    with patch("app.core.config.settings.tor_split_mode", True):
        _record_tor_failure_for_lnd_path("simulated split-mode wedge")
    assert _TOR_BREAKER.consecutive_failures == initial_tor_failures + 1, (
        "split-mode failures must NOT bump the anonymize/shared Tor breaker — that would mis-attribute the wedge."
    )
    assert _TOR_LND_BREAKER.consecutive_failures == initial_lnd_pool_failures + 1


# ── watchdog pool-aware tick ─────────────────────────────────


@pytest.mark.asyncio
async def test_watchdog_tick_lnd_pool_reads_lnd_breaker() -> None:
    """``_watchdog_tick(pool="lnd")`` must read ``_TOR_LND_BREAKER``,
    not the shared ``_TOR_BREAKER``. We open the LND-pool breaker
    and verify the tick observes it open (records a
    ``tor_breaker_opened_observed`` audit with ``pool="lnd"``)."""
    from unittest.mock import AsyncMock

    from app.services.lnd_service import _TOR_LND_BREAKER
    from app.services.tor_watchdog import _watchdog_tick, get_pool_state

    # Reset LND-pool state + breaker.
    state = get_pool_state("lnd")
    state.tor_breaker_opened_at_ts = 0.0
    state.consecutive_tier_3_fires = 0
    while _TOR_LND_BREAKER.state != "closed":
        _TOR_LND_BREAKER.record_success()
    for _ in range(_TOR_LND_BREAKER.failure_threshold + 1):
        _TOR_LND_BREAKER.record_failure("synthetic LND-pool wedge")
    assert _TOR_LND_BREAKER.state == "open"

    audit = AsyncMock()
    with patch("app.services.tor_watchdog._emit_audit", audit):
        await _watchdog_tick(pool="lnd")

    # The tick must have observed the open breaker and recorded
    # the audit row with pool="lnd".
    seen_pools = []
    for call in audit.await_args_list:
        args, kwargs = call
        details = kwargs.get("details") or {}
        if isinstance(details, dict) and "pool" in details:
            seen_pools.append(details["pool"])
    assert "lnd" in seen_pools, (
        f"watchdog tick for pool='lnd' must emit audit rows tagged with pool='lnd'; got {seen_pools}"
    )


@pytest.mark.asyncio
async def test_event_stream_pool_counters_are_independent() -> None:
    """A dispatch into the LND-pool counters must not bump the
    default counters (and vice versa). Without per-pool counters
    the operator can't tell which pool is wedging."""
    import app.services.tor_event_stream as mod
    from app.services.tor_event_stream import (
        EventCounters,
        _dispatch_event,
        get_counters,
        get_pool_counters,
    )

    # Reset both counter sets.
    mod._COUNTERS = EventCounters()
    mod._COUNTERS_LND = EventCounters()

    _dispatch_event(
        "650 WARN All current guards excluded by path restriction",
        counters=get_pool_counters("lnd"),
    )
    lnd = get_pool_counters("lnd")
    anon = get_counters()
    assert lnd.guard_excluded_total == 1
    assert anon.guard_excluded_total == 0, "LND-pool dispatch must not bump anonymize-pool counters."


# ── prewarm proxy selection ─────────────────────────────────


def test_prewarm_proxy_for_url_uses_lnd_for_lnd_rest_in_split() -> None:
    """In split mode the LND REST onion must be prewarmed through
    ``tor-lnd``; everything else goes through ``tor-anonymize``."""
    from app.services.tor_prewarm import _proxy_for_url

    lnd_onion = "http://abc.onion/rest"
    with (
        patch("app.core.config.settings.tor_split_mode", True),
        patch("app.core.config.settings.lnd_rest_url", lnd_onion),
        patch("app.core.config.settings.lnd_tor_proxy", "socks5h://tor-lnd:9050"),
        patch("app.core.config.settings.anonymize_tor_socks_host", "tor-anonymize"),
    ):
        proxy_lnd = _proxy_for_url(lnd_onion)
        proxy_other = _proxy_for_url("http://other.onion/")
    assert "tor-lnd" in proxy_lnd
    assert "tor-anonymize" in proxy_other


def test_prewarm_proxy_for_url_unified_in_single_mode() -> None:
    """Single mode routes everything through the same ``lnd_tor_proxy``."""
    from app.services.tor_prewarm import _proxy_for_url

    with (
        patch("app.core.config.settings.tor_split_mode", False),
        patch("app.core.config.settings.lnd_tor_proxy", "socks5h://tor-proxy:9050"),
    ):
        assert "tor-proxy" in _proxy_for_url("http://anything.onion/")
        assert "tor-proxy" in _proxy_for_url("http://other.onion/")
