# SPDX-License-Identifier: MIT
"""Group E startup checks + LND HS
descriptor freshness tests.

Pins:
  - The proxy-reach check skips when no proxy is configured
    (clearnet deploy) and fails loud (logs error) on unreachable.
  - The DNS-leak check skips when no proxy is configured and
    surfaces ``IsTor=false`` as a confirmed leak (loud log).
  - The LND HS descriptor check skips when LND is clearnet,
    handles HSFETCH RECEIVED / FAILED outcomes, and emits an
    audit row only after consecutive failures cross the
    suppression threshold (so a single transient HSDir blip
    doesn't spam operators).
  - The operator runbook ships at the documented path with the
    expected playbook anchors so the in-code references
    (``docs/operator_tor_runbook.md ``, ````, etc.) stay
    valid as the doc evolves.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

_REPO = Path(__file__).resolve().parents[2]
_RUNBOOK = _REPO / "docs" / "operator_tor_runbook.md"


# ── proxy-reach check ───────────────────────────────────────


@pytest.mark.asyncio
async def test_proxy_reach_check_skips_when_no_proxy(monkeypatch) -> None:
    """Empty LND_TOR_PROXY → skipped, no probe."""
    monkeypatch.setattr("app.core.config.settings.lnd_tor_proxy", "")
    from app.services.tor_proxy_reach_check import check_tor_proxy_reachable

    result = await check_tor_proxy_reachable()
    assert result.skipped is True
    assert result.ok is True


@pytest.mark.asyncio
async def test_proxy_reach_check_ok_on_success() -> None:
    """A successful SOCKS5 round-trip returns ok=True."""

    class _Resp:
        def raise_for_status(self) -> None:
            return None

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, _url):
            return _Resp()

    with (
        patch("httpx.AsyncClient", return_value=_Client()),
        patch(
            "app.core.config.settings.lnd_tor_proxy",
            "socks5h://tor-proxy:9050",
        ),
    ):
        from app.services.tor_proxy_reach_check import (
            check_tor_proxy_reachable,
        )

        result = await check_tor_proxy_reachable()
    assert result.ok is True
    assert result.skipped is False


@pytest.mark.asyncio
async def test_proxy_reach_check_failure_records_error() -> None:
    """An exception during the probe surfaces as ok=False with the
    error captured (truncated)."""

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, _url):
            raise RuntimeError("connect refused")

    with (
        patch("httpx.AsyncClient", return_value=_Client()),
        patch(
            "app.core.config.settings.lnd_tor_proxy",
            "socks5h://tor-proxy:9050",
        ),
    ):
        from app.services.tor_proxy_reach_check import (
            check_tor_proxy_reachable,
        )

        result = await check_tor_proxy_reachable()
    assert result.ok is False
    assert "connect refused" in (result.error or "")


# ── DNS-leak check ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_dns_leak_check_skips_when_no_proxy(monkeypatch) -> None:
    monkeypatch.setattr("app.core.config.settings.lnd_tor_proxy", "")
    from app.services.tor_dns_leak_check import check_for_dns_leak

    result = await check_for_dns_leak()
    assert result.skipped is True


@pytest.mark.asyncio
async def test_dns_leak_check_ok_when_istor_true() -> None:
    """Successful probe with IsTor=true is the happy path."""

    class _Resp:
        def raise_for_status(self) -> None:
            return None

        def json(self):
            return {"IsTor": True, "IP": "1.2.3.4"}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, _url):
            return _Resp()

    with (
        patch("httpx.AsyncClient", return_value=_Client()),
        patch(
            "app.core.config.settings.lnd_tor_proxy",
            "socks5h://tor-proxy:9050",
        ),
    ):
        from app.services.tor_dns_leak_check import check_for_dns_leak

        result = await check_for_dns_leak()
    assert result.ok is True
    assert result.is_tor is True


@pytest.mark.asyncio
async def test_dns_leak_check_flags_istor_false_as_leak() -> None:
    """IsTor=false is a CONFIRMED leak — must surface as ok=False
    with is_tor=False so the operator notices."""

    class _Resp:
        def raise_for_status(self) -> None:
            return None

        def json(self):
            return {"IsTor": False, "IP": "10.0.0.1"}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, _url):
            return _Resp()

    with (
        patch("httpx.AsyncClient", return_value=_Client()),
        patch(
            "app.core.config.settings.lnd_tor_proxy",
            "socks5h://tor-proxy:9050",
        ),
    ):
        from app.services.tor_dns_leak_check import check_for_dns_leak

        result = await check_for_dns_leak()
    assert result.ok is False
    assert result.is_tor is False
    assert result.observed_ip == "10.0.0.1"


@pytest.mark.asyncio
async def test_dns_leak_check_network_failure_is_informational() -> None:
    """A network failure during the probe must NOT be reported as
    a leak — we have no signal about routing. Ok=True (no failure
    surfaced) with error captured."""

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, _url):
            raise RuntimeError("cert expired")

    with (
        patch("httpx.AsyncClient", return_value=_Client()),
        patch(
            "app.core.config.settings.lnd_tor_proxy",
            "socks5h://tor-proxy:9050",
        ),
    ):
        from app.services.tor_dns_leak_check import check_for_dns_leak

        result = await check_for_dns_leak()
    assert result.ok is True
    assert result.is_tor is None
    assert "cert expired" in (result.error or "")


# ── LND HS descriptor freshness ─────────────────────────────


@pytest.mark.asyncio
async def test_descriptor_check_skips_when_lnd_is_clearnet(monkeypatch) -> None:
    """Clearnet LND deploy → no descriptor to check; skipped."""
    monkeypatch.setattr(
        "app.core.config.settings.lnd_rest_url",
        "https://lnd.local:8080",
    )
    from app.services.lnd_hs_descriptor_check import (
        check_lnd_hs_descriptor_freshness,
    )

    result = await check_lnd_hs_descriptor_freshness()
    assert result["status"] == "skipped"
    assert result["reason"] == "lnd_url_not_onion"


@pytest.mark.asyncio
async def test_descriptor_check_records_success_and_resets_counter(
    monkeypatch,
) -> None:
    """A successful HSFETCH resets ``consecutive_failures`` to 0
    and updates ``last_fetch_ok_ts``."""
    monkeypatch.setattr(
        "app.core.config.settings.lnd_rest_url",
        "http://abcdefg0123456789abcdefg0123456789abcdefg0123456789abcd.onion/rest",
    )
    from app.services.lnd_hs_descriptor_check import (
        _STATE,
        check_lnd_hs_descriptor_freshness,
    )

    # Pre-seed a failure history to confirm reset.
    _STATE.consecutive_failures = 3
    _STATE.last_error = "previous"
    _STATE.last_fetch_ok_ts = 0.0

    with (
        patch(
            "app.services.lnd_hs_descriptor_check._hsfetch_and_wait",
            AsyncMock(return_value=(True, None)),
        ),
        patch(
            "app.services.tor_watchdog._emit_audit",
            AsyncMock(),
        ),
    ):
        result = await check_lnd_hs_descriptor_freshness()

    assert result["status"] == "fresh"
    assert _STATE.consecutive_failures == 0
    assert _STATE.last_error is None
    assert _STATE.last_fetch_ok_ts > 0.0


@pytest.mark.asyncio
async def test_descriptor_check_first_failure_does_not_emit_alarm(
    monkeypatch,
) -> None:
    """The first consecutive failure is silent — a one-tick HSDir
    blip shouldn't wake the operator. Threshold is 2."""
    monkeypatch.setattr(
        "app.core.config.settings.lnd_rest_url",
        "http://abcdefg0123456789abcdefg0123456789abcdefg0123456789abcd.onion/rest",
    )
    from app.services.lnd_hs_descriptor_check import (
        _STATE,
        check_lnd_hs_descriptor_freshness,
    )

    # Start with a clean slate.
    _STATE.consecutive_failures = 0

    audit = AsyncMock()
    with (
        patch(
            "app.services.lnd_hs_descriptor_check._hsfetch_and_wait",
            AsyncMock(return_value=(False, "NOT_FOUND")),
        ),
        patch(
            "app.services.tor_watchdog._emit_audit",
            audit,
        ),
    ):
        result = await check_lnd_hs_descriptor_freshness()

    assert result["status"] == "stale"
    assert _STATE.consecutive_failures == 1
    audit.assert_not_called()


@pytest.mark.asyncio
async def test_descriptor_check_emits_after_second_consecutive_failure(
    monkeypatch,
) -> None:
    """Two consecutive failures cross the threshold and emit the
    ``lnd_hs_descriptor_stale`` audit row so the dashboard +
    operator-runbook entry surface."""
    monkeypatch.setattr(
        "app.core.config.settings.lnd_rest_url",
        "http://abcdefg0123456789abcdefg0123456789abcdefg0123456789abcd.onion/rest",
    )
    from app.services.lnd_hs_descriptor_check import (
        _STATE,
        check_lnd_hs_descriptor_freshness,
    )

    _STATE.consecutive_failures = 1  # one prior failure already on record

    audit = AsyncMock()
    with (
        patch(
            "app.services.lnd_hs_descriptor_check._hsfetch_and_wait",
            AsyncMock(return_value=(False, "NOT_FOUND")),
        ),
        patch(
            "app.services.tor_watchdog._emit_audit",
            audit,
        ),
    ):
        await check_lnd_hs_descriptor_freshness()

    assert _STATE.consecutive_failures == 2
    audit.assert_awaited_once()
    args, kwargs = audit.await_args
    action = args[0]
    details = kwargs.get("details") or {}
    assert action == "lnd_hs_descriptor_stale"
    assert details["consecutive_failures"] == 2
    assert "NOT_FOUND" in str(details["last_error"])


def test_extract_onion_hostname_handles_clearnet() -> None:
    """``_extract_onion_hostname`` returns None for non-onion URLs.
    Pinned because the descriptor task uses the None as its
    "skip" signal."""
    from app.services.lnd_hs_descriptor_check import _extract_onion_hostname

    assert _extract_onion_hostname("https://lnd.local:8080") is None
    assert _extract_onion_hostname("") is None
    assert _extract_onion_hostname("http://example.com/onion") is None


def test_extract_onion_hostname_returns_bare_hostname() -> None:
    """Onion URL must surface as just the host (no port, no path)."""
    from app.services.lnd_hs_descriptor_check import _extract_onion_hostname

    onion = "abcdefg0123456789abcdefg0123456789abcdefg0123456789abcd.onion"
    assert _extract_onion_hostname(f"http://{onion}:8080/rest") == onion
    assert _extract_onion_hostname(f"https://{onion}/api/v1") == onion


# ── HSFETCH control-protocol event parsing ──────────────────


@pytest.mark.asyncio
async def test_hsfetch_protocol_parses_received_event() -> None:
    """The descriptor check sends ``HSFETCH <addr>`` and
    reads Tor's async ``HS_DESC RECEIVED ...`` reply. Pin the
    parser so a Tor version that re-orders fields, lowercases the
    action, or changes whitespace doesn't silently break the
    freshness alarm."""

    import app.services.lnd_hs_descriptor_check as mod

    bare = "abcdefg0123456789abcdefg0123456789abcdefg0123456789abcd"
    onion = bare + ".onion"

    # Build a fake control-port stream that responds to the
    # AUTHENTICATE / SETEVENTS / HSFETCH sequence then emits the
    # HS_DESC RECEIVED event for our address.
    sent_commands: list[str] = []

    class _FakeReader:
        def __init__(self, lines):
            self._lines = lines

        async def readline(self):
            if not self._lines:
                return b""
            return self._lines.pop(0)

    class _FakeWriter:
        def write(self, data):
            sent_commands.append(data.decode("ascii").strip())

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    lines = [
        b"250 OK\r\n",  # AUTHENTICATE
        b"250 OK\r\n",  # SETEVENTS
        b"250 OK\r\n",  # HSFETCH ack
        # The async event the parser actually consumes:
        f"650 HS_DESC RECEIVED {bare} NO_AUTH $FP1 abc123\r\n".encode("ascii"),
    ]
    reader = _FakeReader(lines)
    writer = _FakeWriter()

    async def _open_connection(host, port):
        return reader, writer

    import asyncio

    with patch.object(asyncio, "open_connection", _open_connection):
        ok, err = await mod._hsfetch_and_wait(onion)

    assert ok is True, f"expected ok=True; got err={err!r}"
    assert err is None
    # Verify the parser actually sent HSFETCH with the BARE address
    # (no .onion suffix) — Tor's control protocol rejects the
    # suffixed form.
    assert any(cmd.startswith("HSFETCH ") for cmd in sent_commands), (
        f"HSFETCH command not sent; commands={sent_commands}"
    )
    hsfetch_cmd = next(c for c in sent_commands if c.startswith("HSFETCH "))
    assert hsfetch_cmd == f"HSFETCH {bare}", f"HSFETCH must use bare address (no .onion suffix); got {hsfetch_cmd!r}"


@pytest.mark.asyncio
async def test_hsfetch_protocol_parses_failed_event_with_reason() -> None:
    """The ``HS_DESC FAILED`` line carries a ``REASON=`` token the
    operator-facing error must surface. Pin the parser so a
    silently-dropped reason wouldn't hide stale-descriptor diagnosis
    behind a generic 'failed' message."""
    import app.services.lnd_hs_descriptor_check as mod

    bare = "abcdefg0123456789abcdefg0123456789abcdefg0123456789abcd"
    onion = bare + ".onion"

    class _FakeReader:
        def __init__(self, lines):
            self._lines = lines

        async def readline(self):
            if not self._lines:
                return b""
            return self._lines.pop(0)

    class _FakeWriter:
        def write(self, data):
            return None

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    lines = [
        b"250 OK\r\n",
        b"250 OK\r\n",
        b"250 OK\r\n",
        f"650 HS_DESC FAILED {bare} NO_AUTH $FP1 REASON=NOT_FOUND\r\n".encode("ascii"),
    ]

    async def _open_connection(host, port):
        return _FakeReader(lines), _FakeWriter()

    import asyncio

    with patch.object(asyncio, "open_connection", _open_connection):
        ok, err = await mod._hsfetch_and_wait(onion)

    assert ok is False
    assert err is not None
    assert "NOT_FOUND" in err, f"HSFETCH parser dropped the REASON token; got err={err!r}"


@pytest.mark.asyncio
async def test_hsfetch_ignores_events_for_other_addresses() -> None:
    """When Tor is querying multiple HSDirs for several onions
    simultaneously, our parser must filter events by address so
    a different onion's RECEIVED doesn't false-positive our
    descriptor check. Pinned because the parser correlates
    descriptor events by the address field."""
    import app.services.lnd_hs_descriptor_check as mod

    bare = "abcdefg0123456789abcdefg0123456789abcdefg0123456789abcd"
    onion = bare + ".onion"
    other = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

    class _FakeReader:
        def __init__(self, lines):
            self._lines = lines

        async def readline(self):
            if not self._lines:
                return b""
            return self._lines.pop(0)

    class _FakeWriter:
        def write(self, data):
            return None

        async def drain(self):
            return None

        def close(self):
            return None

        async def wait_closed(self):
            return None

    lines = [
        b"250 OK\r\n",
        b"250 OK\r\n",
        b"250 OK\r\n",
        # First, an unrelated onion's RECEIVED — must NOT satisfy us.
        f"650 HS_DESC RECEIVED {other} NO_AUTH $FP1 abc\r\n".encode("ascii"),
        # Then OUR onion's FAILED — that's the result we expect.
        f"650 HS_DESC FAILED {bare} NO_AUTH $FP2 REASON=GENERIC\r\n".encode("ascii"),
    ]

    async def _open_connection(host, port):
        return _FakeReader(lines), _FakeWriter()

    import asyncio

    with patch.object(asyncio, "open_connection", _open_connection):
        ok, err = await mod._hsfetch_and_wait(onion)

    # We must have IGNORED the other onion's RECEIVED and waited
    # for our own — the FAILED reply for our address is the
    # authoritative result.
    assert ok is False, (
        "parser accepted another onion's HS_DESC RECEIVED as our "
        "own — descriptor-freshness alarm would silently miss real "
        "stale descriptors."
    )
    assert "GENERIC" in (err or "")


# ── operator runbook ────────────────────────────────────────


def test_runbook_ships_at_documented_path() -> None:
    """The runbook path is referenced from in-code error messages
    (``docs/operator_tor_runbook.md`` in tor_proxy_reach_check.py
    and tor_dns_leak_check.py). The file must exist."""
    assert _RUNBOOK.is_file(), (
        "docs/operator_tor_runbook.md must ship — the proxy-reach and DNS-leak checks reference it in their error logs."
    )


def test_runbook_carries_canonical_section_anchors() -> None:
    """The in-code references point at specific runbook sections.
    If a future doc edit renumbers or removes them, the error logs
    would point at a missing anchor."""
    text = _RUNBOOK.read_text(encoding="utf-8")
    # Section anchors used by error-message references in:
    # tor_proxy_reach_check.py →
    # tor_dns_leak_check.py →
    # plus the canonical playbook list.
    for section in ["", "", "", "", "", ""]:
        assert section in text, (
            f"operator runbook missing required section {section!r} — in-code log lines reference these by number."
        )


# ──: tor-proxy entrypoint fail-closed behaviour ───────────────


import os
import shutil
import subprocess
import tempfile
import textwrap

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ENTRYPOINT_SRC = _REPO_ROOT / "tor-proxy" / "entrypoint.sh"


def _run_entrypoint_until_exec(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run the tor-proxy entrypoint with `tor` and `tini` shimmed so
    we never actually start tor. Returns the CompletedProcess for the
    caller to assert on stderr / exit code.

    The shim binaries:
      * `tor` — when called with `--hash-password X`, prints a
        deterministic fake hash. When called any other way, exits 0
        (so the final `exec tini -- tor ...` returns success).
      * `tini` — execs its third argument onwards, so the trailing
        `tor` invocation runs through our shim.
    """
    tmp = tempfile.mkdtemp(prefix="tor-entrypoint-test-")
    try:
        binroot = Path(tmp) / "bin"
        binroot.mkdir()
        (binroot / "tor").write_text(
            textwrap.dedent("""\
            #!/bin/sh
            if [ "$1" = "--hash-password" ]; then
                printf '16:%s\\n' "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
                exit 0
            fi
            exit 0
        """)
        )
        (binroot / "tor").chmod(0o755)
        # tini -- tor --defaults-torrc X -f Y  → just succeed.
        (binroot / "tini").write_text("#!/bin/sh\nexit 0\n")
        (binroot / "tini").chmod(0o755)
        # /sbin/tini is hard-coded in the entrypoint; symlink it in.
        sbin = Path(tmp) / "sbin"
        sbin.mkdir()
        (sbin / "tini").symlink_to(binroot / "tini")

        # Stub the torrc.d input + operator override.
        etc_torrc = Path(tmp) / "etc" / "tor" / "torrc.d"
        etc_torrc.mkdir(parents=True)
        (etc_torrc / "00-default.conf").write_text("SocksPort 0.0.0.0:9050\n#__HASHED_CONTROL_PASSWORD_LINE__\n")
        (etc_torrc / "99-operator.conf").write_text("# operator override\n")

        # Patch the entrypoint to look at our tempdir's /etc/tor and
        # use our shimmed PATH for `tor`. We do this by copying the
        # entrypoint into the tempdir and rewriting the hard-coded
        # `/etc/tor` + `/sbin/tini` paths.
        src = _ENTRYPOINT_SRC.read_text(encoding="utf-8")
        patched = src.replace("/etc/tor", str(Path(tmp) / "etc" / "tor")).replace("/sbin/tini", str(sbin / "tini"))
        ep = Path(tmp) / "entrypoint.sh"
        ep.write_text(patched)
        ep.chmod(0o755)

        full_env = {
            **os.environ,
            **env,
            "PATH": f"{binroot}:" + os.environ.get("PATH", "/usr/bin:/bin"),
        }
        return subprocess.run(
            ["/bin/sh", str(ep)],
            env=full_env,
            capture_output=True,
            text=True,
            timeout=10,
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class TestTorEntrypointFailClosed:
    """Without a
    TOR_CONTROL_PASSWORD the entrypoint must refuse to boot outside
    development. A misconfigured production deploy that landed here
    would have rendered an unauthenticated ControlPort reachable by
    every sidecar on the docker network."""

    def test_entrypoint_refuses_when_control_password_missing_in_production(
        self,
    ) -> None:
        result = _run_entrypoint_until_exec({"TOR_CONTROL_PASSWORD": "", "TOR_ENVIRONMENT": "production"})
        assert result.returncode != 0, (
            f"entrypoint must exit non-zero when "
            f"TOR_CONTROL_PASSWORD is unset in production "
            f"(got rc={result.returncode}, stderr={result.stderr!r})"
        )
        assert "REFUSING" in result.stderr, f"expected REFUSING in stderr, got {result.stderr!r}"

    def test_entrypoint_warns_but_boots_when_control_password_missing_in_dev(
        self,
    ) -> None:
        result = _run_entrypoint_until_exec({"TOR_CONTROL_PASSWORD": "", "TOR_ENVIRONMENT": "development"})
        assert result.returncode == 0, (
            f"entrypoint must succeed in development with no password "
            f"(got rc={result.returncode}, stderr={result.stderr!r})"
        )
        assert "WARNING" in result.stderr and "unauthenticated" in result.stderr, (
            f"expected dev-mode warning, got {result.stderr!r}"
        )

    def test_entrypoint_renders_hashed_password_when_provided(self) -> None:
        result = _run_entrypoint_until_exec({"TOR_CONTROL_PASSWORD": "hunter2", "TOR_ENVIRONMENT": "production"})
        assert result.returncode == 0, (
            f"entrypoint must succeed when a control password is set "
            f"(got rc={result.returncode}, stderr={result.stderr!r})"
        )
        assert "HashedControlPassword" in result.stderr
