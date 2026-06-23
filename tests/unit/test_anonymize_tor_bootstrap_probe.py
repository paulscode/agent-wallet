# SPDX-License-Identifier: MIT
"""Tor control-port bootstrap probe + recheck tick.

The probe speaks Tor's text-based control protocol over an asyncio
TCP connection, parses the bootstrap progress + circuit-established
flags, and pushes the resulting "ready / not ready" boolean onto
``app.state.anonymize_health["tor_bootstrap_ready"]``. The
create-endpoint admission gate then refuses session creation until
the boolean flips to True.

Unit tests stand up a minimal asyncio TCP server that imitates the
Tor control port enough to exercise the parser.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.services.anonymize import service as anon_service
from app.services.anonymize import tor as tor_mod
from app.services.anonymize.service import (
    get_anonymize_service,
    reset_anonymize_service,
)


@pytest.fixture(autouse=True)
def reset_service_between_tests():
    reset_anonymize_service()
    yield
    reset_anonymize_service()


async def _stand_up_fake_control_port(
    responses: dict[bytes, bytes],
) -> tuple[asyncio.AbstractServer, int]:
    """Spawn a fake Tor control port that replies to a fixed command set."""

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                cmd = line.strip()
                resp = responses.get(cmd)
                if resp is None:
                    # Default: 250 OK
                    resp = b"250 OK\r\n"
                writer.write(resp)
                await writer.drain()
                if cmd == b"QUIT":
                    break
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(_handle, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    return server, port


@pytest.mark.asyncio
async def test_probe_reports_ready_when_bootstrap_complete(monkeypatch) -> None:
    responses = {
        b"AUTHENTICATE": b"250 OK\r\n",
        b"GETINFO status/bootstrap-phase": (
            b'250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"\r\n250 OK\r\n'
        ),
        b"GETINFO status/circuit-established": (b"250-status/circuit-established=1\r\n250 OK\r\n"),
        b"QUIT": b"250 closing connection\r\n",
    }
    server, port = await _stand_up_fake_control_port(responses)
    try:
        status = await tor_mod.probe_tor_bootstrap_status(
            host="127.0.0.1",
            port=port,
            password=None,
            timeout_s=5.0,
        )
        assert status.control_port_reachable is True
        assert status.bootstrap_phase_progress == 100
        assert status.circuit_established is True
        assert status.fully_bootstrapped is True
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_probe_reports_not_ready_during_bootstrap(monkeypatch) -> None:
    responses = {
        b"AUTHENTICATE": b"250 OK\r\n",
        b"GETINFO status/bootstrap-phase": (
            b'250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=45 TAG=conn_dir SUMMARY="Connecting"\r\n250 OK\r\n'
        ),
        b"GETINFO status/circuit-established": (b"250-status/circuit-established=0\r\n250 OK\r\n"),
        b"QUIT": b"250 closing connection\r\n",
    }
    server, port = await _stand_up_fake_control_port(responses)
    try:
        status = await tor_mod.probe_tor_bootstrap_status(
            host="127.0.0.1",
            port=port,
            password=None,
            timeout_s=5.0,
        )
        assert status.control_port_reachable is True
        assert status.bootstrap_phase_progress == 45
        assert status.circuit_established is False
        assert status.fully_bootstrapped is False
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_probe_reports_not_reachable_when_port_dead() -> None:
    # Port 1 is virtually guaranteed to be unbound on a normal host.
    status = await tor_mod.probe_tor_bootstrap_status(
        host="127.0.0.1",
        port=1,
        password=None,
        timeout_s=1.0,
    )
    assert status.control_port_reachable is False
    assert status.fully_bootstrapped is False


@pytest.mark.asyncio
async def test_probe_returns_not_ready_when_auth_fails(monkeypatch) -> None:
    responses = {
        b"AUTHENTICATE": b"515 Authentication failed\r\n",
    }
    server, port = await _stand_up_fake_control_port(responses)
    try:
        status = await tor_mod.probe_tor_bootstrap_status(
            host="127.0.0.1",
            port=port,
            password=None,
            timeout_s=5.0,
        )
        # The connection succeeded so control_port_reachable=True
        # but the GETINFO commands either fail or return non-success;
        # the result is "not ready". (Our parser fails-open on
        # GETINFO failures and reports progress=0.)
        assert status.control_port_reachable is True
        assert status.fully_bootstrapped is False
    finally:
        server.close()
        await server.wait_closed()


# ── _tor_bootstrap_recheck_run tick ────────────────────────────────


@pytest.mark.asyncio
async def test_tick_updates_health_card(monkeypatch) -> None:
    fake_app = SimpleNamespace(
        state=SimpleNamespace(
            anonymize_health={"tor_bootstrap_ready": True},
        ),
    )
    svc = get_anonymize_service()
    svc._fastapi_app = fake_app  # type: ignore[attr-defined]

    async def _stub_not_ready(**_):
        return tor_mod.TorBootstrapStatus(
            control_port_reachable=True,
            bootstrap_phase_progress=80,
            circuit_established=False,
        )

    monkeypatch.setattr(tor_mod, "probe_tor_bootstrap_status", _stub_not_ready)

    await anon_service._tor_bootstrap_recheck_run()
    assert fake_app.state.anonymize_health["tor_bootstrap_ready"] is False


# ── probe_tor_circuit_status ────────────────────────────────────────


@pytest.mark.asyncio
async def test_circuit_status_parses_built_circuits() -> None:
    """Parse one or more BUILT circuits from the control port."""
    responses = {
        b"AUTHENTICATE": b"250 OK\r\n",
        b"GETINFO circuit-status": (
            b"250+circuit-status=\r\n"
            b"42 BUILT $AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555~NodeA,"
            b"$FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000~ExitNode "
            b"BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL\r\n"
            b".\r\n"
            b"250 OK\r\n"
        ),
        b"QUIT": b"250 closing connection\r\n",
    }
    server, port = await _stand_up_fake_control_port(responses)
    try:
        circuits, err = await tor_mod.probe_tor_circuit_status(
            host="127.0.0.1",
            port=port,
            password=None,
            timeout_s=5.0,
        )
        assert err is None
        assert len(circuits) == 1
        c = circuits[0]
        assert c.circuit_id == "42"
        assert c.exit_fingerprint == ("ffff6666aaaa7777bbbb8888cccc9999dddd0000")
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_circuit_status_ignores_non_built_states() -> None:
    """Circuits in ``LAUNCHED`` / ``CLOSED`` / ``FAILED`` are dropped."""
    responses = {
        b"AUTHENTICATE": b"250 OK\r\n",
        b"GETINFO circuit-status": (
            b"250+circuit-status=\r\n"
            b"10 LAUNCHED $AAAA~A,$BBBB~B PURPOSE=GENERAL\r\n"
            b"11 BUILT $AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555~NodeA,"
            b"$FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000~ExitOk\r\n"
            b"12 FAILED $AAAA~A,$BBBB~B REASON=TIMEOUT\r\n"
            b".\r\n"
            b"250 OK\r\n"
        ),
        b"QUIT": b"250 closing connection\r\n",
    }
    server, port = await _stand_up_fake_control_port(responses)
    try:
        circuits, err = await tor_mod.probe_tor_circuit_status(
            host="127.0.0.1",
            port=port,
            password=None,
            timeout_s=5.0,
        )
        assert err is None
        # Only the BUILT circuit survives.
        assert [c.circuit_id for c in circuits] == ["11"]
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_circuit_status_returns_error_when_port_dead() -> None:
    circuits, err = await tor_mod.probe_tor_circuit_status(
        host="127.0.0.1",
        port=1,
        password=None,
        timeout_s=1.0,
    )
    assert circuits == []
    assert err is not None


@pytest.mark.asyncio
async def test_circuit_status_returns_empty_when_no_circuits() -> None:
    """Idle Tor with zero built circuits returns ``[]`` cleanly."""
    responses = {
        b"AUTHENTICATE": b"250 OK\r\n",
        b"GETINFO circuit-status": (b"250+circuit-status=\r\n.\r\n250 OK\r\n"),
        b"QUIT": b"250 closing connection\r\n",
    }
    server, port = await _stand_up_fake_control_port(responses)
    try:
        circuits, err = await tor_mod.probe_tor_circuit_status(
            host="127.0.0.1",
            port=port,
            password=None,
            timeout_s=5.0,
        )
        assert err is None
        assert circuits == []
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_tick_marks_ready_when_probe_fully_bootstrapped(
    monkeypatch,
) -> None:
    fake_app = SimpleNamespace(
        state=SimpleNamespace(
            anonymize_health={"tor_bootstrap_ready": False},
        ),
    )
    svc = get_anonymize_service()
    svc._fastapi_app = fake_app  # type: ignore[attr-defined]

    async def _stub_ready(**_):
        return tor_mod.TorBootstrapStatus(
            control_port_reachable=True,
            bootstrap_phase_progress=100,
            circuit_established=True,
        )

    monkeypatch.setattr(tor_mod, "probe_tor_bootstrap_status", _stub_ready)

    await anon_service._tor_bootstrap_recheck_run()
    assert fake_app.state.anonymize_health["tor_bootstrap_ready"] is True


# ── compute_effective_tor_ready (derivation helper) ─────────────────


def test_effective_tor_ready_true_when_control_port_says_ready() -> None:
    """Authoritative path: control-port probe positive → True regardless
    of other signals."""
    assert (
        tor_mod.compute_effective_tor_ready(
            {"tor_bootstrap_ready": True, "clock_skew_status": "unhealthy"},
        )
        is True
    )


def test_effective_tor_ready_true_when_clock_skew_proves_socks_works() -> None:
    """Derivation path: control-port probe says NOT ready, but a
    healthy clock-skew measurement proves SOCKS + Tor circuits + an
    .onion round-trip all just succeeded. That's strictly stronger
    than the control-port signal, so we admit. This is the case for
    Docker deployments without an exposed Tor ControlPort."""
    assert (
        tor_mod.compute_effective_tor_ready(
            {"tor_bootstrap_ready": False, "clock_skew_status": "healthy"},
        )
        is True
    )


def test_effective_tor_ready_false_when_neither_signal_positive() -> None:
    """Fail-closed: both signals negative → block. The wizard's banner
    persists, the create endpoint 503s."""
    assert (
        tor_mod.compute_effective_tor_ready(
            {"tor_bootstrap_ready": False, "clock_skew_status": "unhealthy"},
        )
        is False
    )
    assert (
        tor_mod.compute_effective_tor_ready(
            {"tor_bootstrap_ready": False, "clock_skew_status": "warming_up"},
        )
        is False
    )
    assert (
        tor_mod.compute_effective_tor_ready(
            {"tor_bootstrap_ready": False, "clock_skew_status": "unknown"},
        )
        is False
    )


def test_effective_tor_ready_defaults_to_false_when_unset() -> None:
    """Empty health dict (fresh boot, no probe has run) now fails CLOSED
    — egress is gated until a positive signal (control-port bootstrap or
    a healthy clock-skew probe) exists. A missing signal must not admit
    Tor-only egress."""
    assert tor_mod.compute_effective_tor_ready({}) is False


def test_effective_tor_ready_clock_skew_alone_admits() -> None:
    """If the clock-skew probe completes ``healthy`` BEFORE the Tor
    control-port probe has run (or in a deployment where the control
    port is unreachable), the create gate must admit. Without this
    derivation, the user's wallet was perpetually blocked at the
    ``anonymize_tor_not_bootstrapped`` 503."""
    assert (
        tor_mod.compute_effective_tor_ready(
            {"clock_skew_status": "healthy"},  # tor_bootstrap_ready not set yet
        )
        is True
    )


# ── Reconnect-with-backoff + bootstrap recheck watcher ──────────


def test_reconnect_backoff_schedule_doubles_to_cap(monkeypatch) -> None:
    from app.services.anonymize.tor import compute_reconnect_backoff_schedule

    monkeypatch.setattr(settings, "anonymize_tor_control_reconnect_attempts", 5)
    monkeypatch.setattr(settings, "anonymize_tor_control_reconnect_backoff_s", 1)
    out = compute_reconnect_backoff_schedule(cap_seconds=16.0)
    assert out == [1.0, 2.0, 4.0, 8.0, 16.0]


def test_reconnect_backoff_schedule_caps_aggressive_backoff() -> None:
    from app.services.anonymize.tor import compute_reconnect_backoff_schedule

    out = compute_reconnect_backoff_schedule(
        attempts=8,
        base_seconds=4,
        cap_seconds=16.0,
    )
    # 4, 8, 16, 32→16, 64→16, ...
    assert out == [4.0, 8.0, 16.0, 16.0, 16.0, 16.0, 16.0, 16.0]


def test_reconnect_backoff_schedule_empty_when_disabled() -> None:
    from app.services.anonymize.tor import compute_reconnect_backoff_schedule

    assert compute_reconnect_backoff_schedule(attempts=0, base_seconds=1) == []
    assert compute_reconnect_backoff_schedule(attempts=5, base_seconds=0) == []


def test_recheck_decision_ok_when_steady() -> None:
    from app.services.anonymize.tor import (
        BootstrapRecheckState,
        TorBootstrapStatus,
        bootstrap_recheck_decision,
    )

    state = BootstrapRecheckState(
        last_known_ready=True,
        last_status=None,
        consecutive_regressions=0,
    )
    fresh = TorBootstrapStatus(
        control_port_reachable=True,
        bootstrap_phase_progress=100,
        circuit_established=True,
    )
    assert bootstrap_recheck_decision(state=state, fresh_status=fresh) == "ok"


def test_recheck_decision_regression_first_then_pause() -> None:
    """A single regression emits but does not pause; the next confirms."""
    from app.services.anonymize.tor import (
        BootstrapRecheckState,
        TorBootstrapStatus,
        bootstrap_recheck_decision,
    )

    fresh_bad = TorBootstrapStatus(
        control_port_reachable=True,
        bootstrap_phase_progress=85,
        circuit_established=False,
    )
    # First regression after being ready.
    state1 = BootstrapRecheckState(
        last_known_ready=True,
        last_status=None,
        consecutive_regressions=0,
    )
    assert bootstrap_recheck_decision(state=state1, fresh_status=fresh_bad) == "regression_first"
    # Second probe still bad — pauses egress.
    state2 = BootstrapRecheckState(
        last_known_ready=False,
        last_status=fresh_bad,
        consecutive_regressions=1,
    )
    assert bootstrap_recheck_decision(state=state2, fresh_status=fresh_bad) == "regression_pause"


def test_recheck_decision_recovery_clears_flag() -> None:
    from app.services.anonymize.tor import (
        BootstrapRecheckState,
        TorBootstrapStatus,
        bootstrap_recheck_decision,
    )

    fresh_good = TorBootstrapStatus(
        control_port_reachable=True,
        bootstrap_phase_progress=100,
        circuit_established=True,
    )
    state = BootstrapRecheckState(
        last_known_ready=False,
        last_status=None,
        consecutive_regressions=3,
    )
    assert bootstrap_recheck_decision(state=state, fresh_status=fresh_good) == "ok_recovered"


def test_recheck_interval_seconds_uses_setting(monkeypatch) -> None:
    from app.services.anonymize.tor import bootstrap_recheck_interval_seconds

    monkeypatch.setattr(
        settings,
        "anonymize_tor_bootstrap_recheck_interval_s",
        600,
    )
    assert bootstrap_recheck_interval_seconds() == 600
