# SPDX-License-Identifier: MIT
"""
Unit tests for app.services.anonymize.tor control-port SIGNAL helpers and
the pure diversity / readiness / backoff helpers.

The SIGNAL helpers (NEWNYM / HUP / CLEARDNSCACHE) drive Tor circuit
recovery; they must report failure (never a false success) on a rejected
AUTHENTICATE, a rejected SIGNAL, an unreachable control port, or a
missing configuration. They are exercised against the in-process Tor
control-port mock rather than a live Tor.
"""

import asyncio

import pytest

from app.services.anonymize.tor import (
    BootstrapRecheckState,
    CircuitExitInfo,
    TorBootstrapStatus,
    _exit_diversity_key,
    _ip_slash_16,
    _send_tor_signal,
    bootstrap_recheck_decision,
    compute_effective_tor_ready,
    compute_reconnect_backoff_schedule,
    get_tor_process_uptime_s,
    is_tor_bootstrap_ready,
    is_tor_control_port_reachable,
    signal_cleardnscache,
    signal_newnym,
    signal_reload,
)
from tests.unit._tor_control_mock import TorControlPortMock, mock_tor_control

_READY = TorBootstrapStatus(control_port_reachable=True, bootstrap_phase_progress=100, circuit_established=True)
_NOT_READY = TorBootstrapStatus(control_port_reachable=False, bootstrap_phase_progress=0, circuit_established=False)

_HOST = "127.0.0.1"
_PORT = 9051


class TestSendTorSignal:
    async def test_success_no_password(self, monkeypatch):
        mock = TorControlPortMock()
        with mock_tor_control(monkeypatch, mock):
            ok, err = await _send_tor_signal("NEWNYM", host=_HOST, port=_PORT, password="")
        assert ok is True and err is None
        assert "SIGNAL NEWNYM" in mock.commands
        assert mock.commands[0] == "AUTHENTICATE"  # no password → bare auth
        assert mock.closed is True  # connection torn down

    async def test_success_with_password_authenticates(self, monkeypatch):
        mock = TorControlPortMock()
        with mock_tor_control(monkeypatch, mock):
            ok, err = await _send_tor_signal("NEWNYM", host=_HOST, port=_PORT, password="s3cret")
        assert ok is True and err is None
        assert mock.commands[0].startswith("AUTHENTICATE ")  # password supplied

    async def test_auth_rejected(self, monkeypatch):
        mock = TorControlPortMock(accept_auth=False)
        with mock_tor_control(monkeypatch, mock):
            ok, err = await _send_tor_signal("NEWNYM", host=_HOST, port=_PORT, password="wrong")
        assert ok is False
        assert err is not None and "AUTHENTICATE rejected" in err

    async def test_signal_rejected(self, monkeypatch):
        mock = TorControlPortMock()
        mock.set_response("SIGNAL NEWNYM", "552 Unrecognized signal\r\n")
        with mock_tor_control(monkeypatch, mock):
            ok, err = await _send_tor_signal("NEWNYM", host=_HOST, port=_PORT, password="")
        assert ok is False
        assert err is not None and "SIGNAL NEWNYM rejected" in err

    async def test_connect_failure(self, monkeypatch):
        async def _boom(*args, **kwargs):
            raise ConnectionRefusedError("no control port")

        monkeypatch.setattr(asyncio, "open_connection", _boom)
        ok, err = await _send_tor_signal("NEWNYM", host=_HOST, port=_PORT, password="")
        assert ok is False
        assert err is not None and "connect failed" in err

    async def test_not_configured_when_port_nonpositive(self):
        ok, err = await _send_tor_signal("NEWNYM", host=_HOST, port=0, password="")
        assert ok is False
        assert err == "tor control-port not configured"


class TestSignalWrappers:
    async def test_newnym_sends_newnym(self, monkeypatch):
        mock = TorControlPortMock()
        with mock_tor_control(monkeypatch, mock):
            ok, _ = await signal_newnym(host=_HOST, port=_PORT, password="")
        assert ok is True and "SIGNAL NEWNYM" in mock.commands

    async def test_reload_sends_hup(self, monkeypatch):
        mock = TorControlPortMock()
        with mock_tor_control(monkeypatch, mock):
            ok, _ = await signal_reload(host=_HOST, port=_PORT, password="")
        assert ok is True and "SIGNAL HUP" in mock.commands

    async def test_cleardnscache_sends_cleardnscache(self, monkeypatch):
        mock = TorControlPortMock()
        with mock_tor_control(monkeypatch, mock):
            ok, _ = await signal_cleardnscache(host=_HOST, port=_PORT, password="")
        assert ok is True and "SIGNAL CLEARDNSCACHE" in mock.commands


class TestIpSlash16:
    def test_ipv4_returns_slash16(self):
        assert _ip_slash_16("203.0.113.7") == "203.0"

    def test_ipv6_returns_first_64_bits(self):
        assert _ip_slash_16("2001:db8:abcd:1234:5678::1") == "2001:db8:abcd:1234"

    def test_malformed_ipv4_passthrough(self):
        assert _ip_slash_16("not-an-ip") == "not-an-ip"


class TestExitDiversityKey:
    def _info(self, **kw):
        base = dict(circuit_id="c1", exit_fingerprint="fp", exit_ip="203.0.113.7", asn=None, country=None)
        base.update(kw)
        return CircuitExitInfo(**base)

    def test_off_mode_is_per_circuit(self):
        assert _exit_diversity_key(self._info(circuit_id="abc"), "off") == "abc"

    def test_asn_mode_prefers_asn(self):
        assert _exit_diversity_key(self._info(asn="AS64500"), "asn") == "AS64500"

    def test_asn_mode_falls_back_to_ip_block(self):
        assert _exit_diversity_key(self._info(asn=None), "asn") == "203.0"

    def test_country_mode_prefers_country_then_asn_then_ip(self):
        assert _exit_diversity_key(self._info(country="US"), "country") == "US"
        assert _exit_diversity_key(self._info(country=None, asn="AS64500"), "country") == "AS64500"
        assert _exit_diversity_key(self._info(country=None, asn=None), "country") == "203.0"


class TestReadinessHelpers:
    def test_bootstrap_ready_requires_all_three(self):
        ready = TorBootstrapStatus(control_port_reachable=True, bootstrap_phase_progress=100, circuit_established=True)
        assert is_tor_bootstrap_ready(ready) is True
        for partial in (
            TorBootstrapStatus(False, 100, True),
            TorBootstrapStatus(True, 99, True),
            TorBootstrapStatus(True, 100, False),
        ):
            assert is_tor_bootstrap_ready(partial) is False

    def test_effective_ready_control_port_positive(self):
        assert compute_effective_tor_ready({"tor_bootstrap_ready": True}) is True

    def test_effective_ready_clock_skew_unblocks(self):
        assert compute_effective_tor_ready({"clock_skew_status": "healthy"}) is True

    def test_effective_ready_fails_closed(self):
        assert compute_effective_tor_ready({}) is False
        assert compute_effective_tor_ready({"tor_bootstrap_ready": "maybe"}) is False


class TestBootstrapRecheckDecision:
    def test_steady_ready(self):
        state = BootstrapRecheckState(last_known_ready=True, last_status=_READY, consecutive_regressions=0)
        assert bootstrap_recheck_decision(state=state, fresh_status=_READY) == "ok"

    def test_recovered_in_one_tick(self):
        state = BootstrapRecheckState(last_known_ready=False, last_status=_NOT_READY, consecutive_regressions=3)
        assert bootstrap_recheck_decision(state=state, fresh_status=_READY) == "ok_recovered"

    def test_first_regression_does_not_pause(self):
        state = BootstrapRecheckState(last_known_ready=True, last_status=_READY, consecutive_regressions=0)
        assert bootstrap_recheck_decision(state=state, fresh_status=_NOT_READY) == "regression_first"

    def test_pauses_after_hysteresis(self):
        state = BootstrapRecheckState(last_known_ready=False, last_status=_NOT_READY, consecutive_regressions=1)
        assert (
            bootstrap_recheck_decision(state=state, fresh_status=_NOT_READY, hysteresis_ticks=2) == "regression_pause"
        )

    def test_still_paused_below_hysteresis(self):
        state = BootstrapRecheckState(last_known_ready=False, last_status=_NOT_READY, consecutive_regressions=0)
        assert bootstrap_recheck_decision(state=state, fresh_status=_NOT_READY, hysteresis_ticks=3) == "still_paused"


class TestProcessUptime:
    async def test_success_parses_seconds(self, monkeypatch):
        mock = TorControlPortMock()
        mock.set_response("GETINFO process/uptime", "250-process/uptime=12345\r\n250 OK\r\n")
        with mock_tor_control(monkeypatch, mock):
            uptime, err = await get_tor_process_uptime_s(host=_HOST, port=_PORT, password="")
        assert err is None and uptime == 12345.0

    async def test_unparseable_response(self, monkeypatch):
        mock = TorControlPortMock()
        mock.set_response("GETINFO process/uptime", "250-process/foo=bar\r\n250 OK\r\n")
        with mock_tor_control(monkeypatch, mock):
            uptime, err = await get_tor_process_uptime_s(host=_HOST, port=_PORT, password="")
        assert uptime is None and err is not None and "unparseable" in err

    async def test_not_configured(self):
        uptime, err = await get_tor_process_uptime_s(host=_HOST, port=0, password="")
        assert uptime is None and err == "tor control-port not configured"


class TestControlPortReachable:
    async def test_reachable_on_auth_ok(self, monkeypatch):
        mock = TorControlPortMock()
        with mock_tor_control(monkeypatch, mock):
            assert await is_tor_control_port_reachable(host=_HOST, port=_PORT, password="") is True

    async def test_unreachable_on_auth_failure(self, monkeypatch):
        mock = TorControlPortMock(accept_auth=False)
        with mock_tor_control(monkeypatch, mock):
            assert await is_tor_control_port_reachable(host=_HOST, port=_PORT, password="wrong") is False

    async def test_unreachable_on_connect_failure(self, monkeypatch):
        async def _boom(*args, **kwargs):
            raise ConnectionRefusedError("down")

        monkeypatch.setattr(asyncio, "open_connection", _boom)
        assert await is_tor_control_port_reachable(host=_HOST, port=_PORT, password="") is False

    async def test_unreachable_when_not_configured(self):
        assert await is_tor_control_port_reachable(host=_HOST, port=0, password="") is False


class TestReconnectBackoff:
    def test_default_doubling_schedule_clamped(self):
        sched = compute_reconnect_backoff_schedule(attempts=5, base_seconds=1, cap_seconds=16.0)
        assert sched == [1.0, 2.0, 4.0, 8.0, 16.0]

    def test_cap_is_applied(self):
        sched = compute_reconnect_backoff_schedule(attempts=6, base_seconds=1, cap_seconds=8.0)
        assert sched == [1.0, 2.0, 4.0, 8.0, 8.0, 8.0]

    @pytest.mark.parametrize("attempts,base", [(0, 1), (5, 0)])
    def test_degenerate_inputs_yield_empty(self, attempts, base):
        assert compute_reconnect_backoff_schedule(attempts=attempts, base_seconds=base) == []
