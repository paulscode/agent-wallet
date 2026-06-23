# SPDX-License-Identifier: MIT
"""Per-call-site Tor SOCKS listener resolution + control-port helpers.

Every call site (boltz_submarine, boltz_reverse, liquid,
chain_backend, bip353_dns, quote_cache_refresh) is bound to its own
SOCKS listener so circuits cannot be shared across call sites.

Startup assertion that the anonymize Tor process is distinct
from the LND-side Tor process.

Exit-relay diversity check via ``GETINFO circuit-status``.

Bootstrap gate: refuse to admit anonymize traffic until
``GETINFO status/circuit-established == 1`` and
``status/bootstrap-phase`` reports ready, plus
``ANONYMIZE_FIRST_EGRESS_BOOTSTRAP_JITTER_S`` jitter.

The actual control-port client is implemented incrementally; this
module exposes the call-site → SOCKS-port resolver up front because
:mod:`http` needs it from day one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from app.core.config import settings

if TYPE_CHECKING:
    import secrets


class TorListenerNotConfiguredError(RuntimeError):
    """Raised when a call site has no SOCKS listener mapping."""


def _quote_control_password(pw: str) -> str:
    """Return a Tor control-protocol QuotedString for ``pw``.

    The control protocol's ``QuotedString`` requires backslash and
    double-quote to be backslash-escaped. The wizard-generated password
    (``token_urlsafe``) never contains these, but a hand-set
    ``TOR_CONTROL_PASSWORD`` might — without escaping, a ``"`` would
    break the quoting and could be misread as extra control tokens.
    """
    escaped = pw.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def resolve_socks_port(call_site: str) -> int:
    """Return the SOCKS port bound to ``call_site``."""
    ports = settings.anonymize_tor_socks_ports_dict
    if call_site not in ports:
        raise TorListenerNotConfiguredError(
            f"No SOCKS listener configured for call_site={call_site!r}. Configured: {sorted(ports.keys())}"
        )
    return ports[call_site]


def resolve_socks_host() -> str:
    """Return the SOCKS host shared across all anonymize listeners.

    This reuses the existing ``LND_TOR_PROXY`` host; the dedicated Tor
    supervisor spawns separate processes and overrides this
    resolution.
    """
    raw = (settings.lnd_tor_proxy or "").strip()
    if not raw:
        return "127.0.0.1"
    # ``socks5h://host:port`` — extract host.
    from urllib.parse import urlparse

    parsed = urlparse(raw)
    return (parsed.hostname or "127.0.0.1").lower()


# --------------------------------------------------------------------
# Exit-relay diversity check.
# --------------------------------------------------------------------


from dataclasses import dataclass


@dataclass(frozen=True)
class CircuitExitInfo:
    """One Tor circuit's exit-relay metadata.

    The orchestrator builds these from the Tor control-port's
    ``GETINFO circuit-status`` + ``ns/id/<fp>`` lookups; this module
    operates on the resolved info so the diversity logic is
    independently testable.
    """

    circuit_id: str
    exit_fingerprint: str
    exit_ip: str  # may be IPv4 or IPv6
    asn: str | None = None  # populated when the consensus has GeoIP data
    country: str | None = None


def _ip_slash_16(ip: str) -> str:
    """Return the ``/16`` block of an IPv4 address, or the address as-is for IPv6.

    The ASN-mode diversity check is operationally approximated
    by the ``/16`` since real ASN data is operator-supplied; the
    helper falls back to that prefix when the consensus row carries
    no ASN.
    """
    if ":" in ip:
        # IPv6 — return the first 64 bits as the "block".
        parts = ip.split(":")
        return ":".join(parts[:4])
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    return ".".join(parts[:2])


def _exit_diversity_key(info: CircuitExitInfo, mode: str) -> str:
    """Reduce a circuit's exit info to the diversity-check identifier.

    ``mode`` selects the granularity:
    * ``"asn"`` (default per ``ANONYMIZE_REQUIRE_EXIT_DIVERSITY``) —
      the ASN string when present, else the IPv4 ``/16`` (or IPv6 ``/64``).
    * ``"country"`` — the consensus country code, falling back to
      ASN/IP when missing.
    * ``"off"`` — every circuit gets a unique key (no diversity check).
    """
    if mode == "off":
        return info.circuit_id
    if mode == "country":
        return info.country or info.asn or _ip_slash_16(info.exit_ip)
    # mode == "asn" (default)
    return info.asn or _ip_slash_16(info.exit_ip)


def assert_exit_relay_diversity(
    submarine_circuit: CircuitExitInfo,
    reverse_circuit: CircuitExitInfo,
    *,
    mode: str | None = None,
) -> None:
    """Refuse a session whose two legs share an exit.

    A submarine + reverse pair whose Tor circuits emerge through the
    same exit (or the same ASN, depending on mode) lets a compromised
    exit-relay operator correlate the two legs. The orchestrator
    rebuilds the reverse circuit (``NEWNYM``) until exits differ;
    this helper is the predicate.

    Raises :class:`ValueError` on collision. Mode defaults to
    :attr:`settings.anonymize_require_exit_diversity`; ``"off"``
    disables the check entirely.
    """
    if mode is None:
        mode = settings.anonymize_require_exit_diversity
    if mode == "off":
        return
    sub_key = _exit_diversity_key(submarine_circuit, mode)
    rev_key = _exit_diversity_key(reverse_circuit, mode)
    if sub_key == rev_key:
        raise ValueError(
            f"submarine + reverse legs share the same exit-relay "
            f"diversity key ({mode}={sub_key!r}); rebuild the reverse "
            "circuit before issuing the second leg"
        )


# --------------------------------------------------------------------
# Tor control-port reach probe.
# --------------------------------------------------------------------


@dataclass(frozen=True)
class TorBootstrapStatus:
    """Snapshot of one Tor process's bootstrap state.

    The supervisor probes its child Tor processes via the control
    port; this dataclass is the resolved outcome the rest of the
    anonymize stack consumes (e.g., the health endpoint).
    """

    control_port_reachable: bool
    bootstrap_phase_progress: int  # 0..100
    circuit_established: bool

    @property
    def fully_bootstrapped(self) -> bool:
        return self.control_port_reachable and self.bootstrap_phase_progress >= 100 and self.circuit_established


def is_tor_bootstrap_ready(status: TorBootstrapStatus) -> bool:
    """Predicate the orchestrator gates first-egress on.

    Requires control-port reachability + 100% bootstrap progress +
    ``status/circuit-established == 1``. Anything short of all three
    keeps the anonymize service in "waiting for Tor" mode.
    """
    return status.fully_bootstrapped


def compute_effective_tor_ready(health: dict) -> bool:
    """Return the effective Tor-readiness signal for admission gates.

    The dedicated Tor control-port probe (``tor_bootstrap_ready``) is
    authoritative when reachable, but many deployments (notably Docker
    Compose without an exposed ``ControlPort`` in the ``tor-proxy``
    image) can't reach it. In those cases the probe stays stuck at
    ``False`` even though SOCKS traffic is demonstrably working.

    To avoid a perpetually-blocked admission gate in those deployments,
    we OR the control-port signal with a positive *derived* signal:
    a successful clock-skew probe (``clock_skew_status == "healthy"``)
    proves SOCKS5 + Tor circuits + an .onion HEAD round-trip all
    succeeded, which is a strictly stronger fact than "control port
    reachable".

    Returns ``True`` iff at least one positive signal is present:

    * ``tor_bootstrap_ready`` is explicitly ``True`` (control-port probe
      positive), OR
    * ``clock_skew_status == "healthy"`` (proves SOCKS works).

    Fails CLOSED: a missing/unknown ``tor_bootstrap_ready`` no longer
    counts as ready, so egress stays gated until a positive signal
    exists. The clock-skew OR-branch still unblocks deployments whose
    control port can't confirm bootstrap.
    """
    raw = health.get("tor_bootstrap_ready", False)
    control_port_says_ready = raw is True
    clock_proves_tor_works = health.get("clock_skew_status") == "healthy"
    return bool(control_port_says_ready or clock_proves_tor_works)


def sample_first_egress_jitter_s(
    rng: "secrets.SystemRandom | None" = None,
) -> float:
    """First-egress jitter.

    After Tor reports bootstrap-ready, the orchestrator sleeps a
    uniform-random ``[0, ANONYMIZE_FIRST_EGRESS_BOOTSTRAP_JITTER_S)``
    before issuing the first quote-cache refresh. The jitter smears
    the "fresh wallet host" first-egress timing signal across a
    ≥1-minute window so a passive observer cannot pin first-egress
    to a known process-start moment.

    Pure helper — the orchestrator wraps this in
    ``await asyncio.sleep(...)`` immediately before the first
    refresh task fires.
    """
    import secrets as _secrets

    rng = rng or _secrets.SystemRandom()
    cap = max(0, int(settings.anonymize_first_egress_bootstrap_jitter_s))
    if cap <= 0:
        return 0.0
    return rng.uniform(0.0, float(cap))


async def probe_tor_bootstrap_status(
    *,
    host: str | None = None,
    port: int | None = None,
    password: str | None = None,
    timeout_s: float = 10.0,
) -> "TorBootstrapStatus":
    """Probe the Tor control port for bootstrap state.

    Speaks Tor's text-based control protocol over a TCP socket:

    1. ``AUTHENTICATE [password|""]``
    2. ``GETINFO status/bootstrap-phase``
    3. ``GETINFO status/circuit-established``
    4. ``QUIT``

    Returns a :class:`TorBootstrapStatus` whose
    ``fully_bootstrapped`` predicate the orchestrator checks before
    admitting anonymize traffic. A control-port that doesn't respond
    or refuses auth returns a "not ready" status with
    ``control_port_reachable=False`` so the read-only path
    (recurring tick + create-endpoint gate) can render it without
    raising.
    """
    import asyncio
    import re

    resolved_host = host or settings.anonymize_tor_control_host or "127.0.0.1"
    resolved_port = int(
        port if port is not None else settings.anonymize_tor_control_port,
    )
    # Resolve via the unified accessor that prefers the new
    # ``TOR_CONTROL_PASSWORD`` knob and falls back to the legacy
    # ``ANONYMIZE_TOR_CONTROL_PASSWORD``.
    resolved_pw = password if password is not None else settings.resolved_tor_control_password
    if not resolved_host or resolved_port <= 0:
        return TorBootstrapStatus(
            control_port_reachable=False,
            bootstrap_phase_progress=0,
            circuit_established=False,
        )

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(resolved_host, resolved_port),
            timeout=timeout_s,
        )
    except Exception:  # noqa: BLE001
        return TorBootstrapStatus(
            control_port_reachable=False,
            bootstrap_phase_progress=0,
            circuit_established=False,
        )

    async def _send(cmd: str) -> str:
        writer.write((cmd + "\r\n").encode("ascii"))
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
            if not line:
                break
            chunks.append(line)
            # Tor's reply is terminated by a line starting with the
            # status code followed by a space (e.g., ``250 OK\r\n``)
            # or ``250-`` for multi-line replies.
            text = line.decode("ascii", errors="replace")
            if re.match(r"^[2-5]\d{2} ", text):
                break
        return b"".join(chunks).decode("ascii", errors="replace")

    try:
        # AUTHENTICATE — password in quotes if present, else empty.
        if resolved_pw:
            await _send(f'AUTHENTICATE {_quote_control_password(resolved_pw)}')
        else:
            await _send("AUTHENTICATE")

        phase_resp = await _send("GETINFO status/bootstrap-phase")
        circuit_resp = await _send("GETINFO status/circuit-established")

        try:
            await _send("QUIT")
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return TorBootstrapStatus(
            control_port_reachable=True,
            bootstrap_phase_progress=0,
            circuit_established=False,
        )

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass

    # Parse ``PROGRESS=NN`` from the bootstrap-phase line.
    m = re.search(r"PROGRESS=(\d+)", phase_resp)
    progress = int(m.group(1)) if m else 0
    # ``status/circuit-established`` returns ``250-status/circuit-established=1``
    # (or =0).
    circuit_ok = bool(re.search(r"circuit-established=1", circuit_resp))

    return TorBootstrapStatus(
        control_port_reachable=True,
        bootstrap_phase_progress=progress,
        circuit_established=circuit_ok,
    )


async def probe_tor_circuit_status(
    *,
    host: str | None = None,
    port: int | None = None,
    password: str | None = None,
    timeout_s: float = 10.0,
) -> tuple[list[CircuitExitInfo], str | None]:
    """Read ``GETINFO circuit-status`` from the Tor control port.

    Returns ``(circuits, None)`` on success or ``([], error)`` on
    failure. Each :class:`CircuitExitInfo` carries the circuit id +
    the exit relay's fingerprint (the last hop's ``$FP~Name`` token).

    The exit-relay diversity check feeds the returned list
    into :func:`assert_exit_relay_diversity` to refuse a submarine +
    reverse pair whose two circuits emerge through the same exit.

    The protocol is documented at
    https://spec.torproject.org/control-spec/replies.html#GETINFO —
    one line per circuit:
    ``650 CIRC <id> <status> <path> ...``  (event form) or
    ``250+circuit-status=`` followed by lines and a ``.`` terminator.
    """
    import asyncio
    import re

    resolved_host = host or settings.anonymize_tor_control_host or "127.0.0.1"
    resolved_port = int(
        port if port is not None else settings.anonymize_tor_control_port,
    )
    # Resolve via the unified accessor that prefers the new
    # ``TOR_CONTROL_PASSWORD`` knob and falls back to the legacy
    # ``ANONYMIZE_TOR_CONTROL_PASSWORD``.
    resolved_pw = password if password is not None else settings.resolved_tor_control_password
    if not resolved_host or resolved_port <= 0:
        return [], "tor control-port not configured"

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(resolved_host, resolved_port),
            timeout=timeout_s,
        )
    except Exception as exc:  # noqa: BLE001
        return [], f"tor control connect failed: {exc}"

    async def _send_and_read(cmd: str, multi_line: bool = False) -> str:
        writer.write((cmd + "\r\n").encode("ascii"))
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
            if not line:
                break
            chunks.append(line)
            text = line.decode("ascii", errors="replace")
            if multi_line:
                # 250+key=...\r\n  ... \r\n.\r\n  250 OK
                if re.match(r"^[2-5]\d{2} ", text):
                    break
            else:
                if re.match(r"^[2-5]\d{2} ", text):
                    break
        return b"".join(chunks).decode("ascii", errors="replace")

    try:
        if resolved_pw:
            await _send_and_read(f'AUTHENTICATE {_quote_control_password(resolved_pw)}')
        else:
            await _send_and_read("AUTHENTICATE")
        resp = await _send_and_read(
            "GETINFO circuit-status",
            multi_line=True,
        )
        try:
            await _send_and_read("QUIT")
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return [], f"tor control exchange failed: {exc}"

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass

    # Parse the multi-line response. Each circuit's line looks like:
    # 250-<id> <status> <hop1>,<hop2>,...,<hopN> ...
    # where each hop is ``$FP~Name`` (fingerprint + nickname).
    circuits: list[CircuitExitInfo] = []
    for raw_line in resp.splitlines():
        # Strip the 250- prefix when present.
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("250-circuit-status="):
            line = line[len("250-circuit-status=") :]
        elif line.startswith("250-"):
            line = line[4:]
        elif line.startswith("250 "):
            continue
        elif line == ".":
            continue
        # Tokenize: <id> <status> <path>
        parts = line.split(" ", 3)
        if len(parts) < 3:
            continue
        circuit_id, status, path = parts[0], parts[1], parts[2]
        if status not in {"BUILT", "EXTENDED", "GUARD_WAIT"}:
            continue
        hops = [h for h in path.split(",") if h]
        if not hops:
            continue
        last = hops[-1]
        m = re.match(r"\$([0-9A-Fa-f]+)(?:~(.+))?$", last)
        if not m:
            continue
        circuits.append(
            CircuitExitInfo(
                circuit_id=circuit_id,
                exit_fingerprint=m.group(1).lower(),
                exit_ip="",  # filled by ``ns/id/<fp>`` lookup; deferred
                asn=None,
                country=None,
            )
        )
    return circuits, None


# --------------------------------------------------------------------
# Entry-guards + network-liveness diagnostics.
# --------------------------------------------------------------------


@dataclass(frozen=True)
class EntryGuardInfo:
    """One Tor entry-guard's status snapshot.

    Surface for the dashboard health panel so operators can see
    whether their current guards are reachable / listed / dropped.
    Today's 2026-05-21 incident manifested as "All current guards
    excluded by path restriction type 2" — exposing the guard list is
    what makes that diagnosable from the UI.
    """

    fingerprint: str
    nickname: str  # empty if unknown
    status: str  # "up" | "down" | "unlisted" | "never-connected" | other


async def probe_entry_guards(
    *,
    host: str | None = None,
    port: int | None = None,
    password: str | None = None,
    timeout_s: float = 10.0,
) -> tuple[list[EntryGuardInfo], str | None]:
    """Read ``GETINFO entry-guards`` from the Tor control port.

    Returns ``(guards, None)`` on success or ``([], error)`` on
    failure. Each :class:`EntryGuardInfo` carries the guard's
    fingerprint, nickname (when known), and Tor's most recent
    reachability assessment.

    Response shape (from the Tor control-spec):

        250+entry-guards=
        $FINGERPRINT~Nickname status [details...]
        $FINGERPRINT~Nickname status [details...]
        .
        250 OK
    """
    import asyncio
    import re

    resolved_host = host or settings.anonymize_tor_control_host or "127.0.0.1"
    resolved_port = int(
        port if port is not None else settings.anonymize_tor_control_port,
    )
    resolved_pw = password if password is not None else settings.resolved_tor_control_password
    if not resolved_host or resolved_port <= 0:
        return [], "tor control-port not configured"

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(resolved_host, resolved_port),
            timeout=timeout_s,
        )
    except Exception as exc:  # noqa: BLE001
        return [], f"tor control connect failed: {exc}"

    async def _send_and_read(cmd: str) -> str:
        writer.write((cmd + "\r\n").encode("ascii"))
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
            if not line:
                break
            chunks.append(line)
            text = line.decode("ascii", errors="replace")
            if re.match(r"^[2-5]\d{2} ", text):
                break
        return b"".join(chunks).decode("ascii", errors="replace")

    try:
        if resolved_pw:
            await _send_and_read(f'AUTHENTICATE {_quote_control_password(resolved_pw)}')
        else:
            await _send_and_read("AUTHENTICATE")
        resp = await _send_and_read("GETINFO entry-guards")
        try:
            await _send_and_read("QUIT")
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return [], f"tor control exchange failed: {exc}"

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass

    guards: list[EntryGuardInfo] = []
    for raw_line in resp.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("250+entry-guards="):
            continue
        if line.startswith("250 ") or line == ".":
            continue
        # Each guard line is "$FP[~Nickname] status [extra]".
        # Some Tor versions prefix the data lines with "250-"; strip
        # defensively.
        if line.startswith("250-"):
            line = line[4:]
        m = re.match(
            r"\$([0-9A-Fa-f]+)(?:~(\S+))?\s+(\S+)",
            line,
        )
        if not m:
            continue
        guards.append(
            EntryGuardInfo(
                fingerprint=m.group(1).lower(),
                nickname=m.group(2) or "",
                status=m.group(3).lower(),
            )
        )
    return guards, None


async def probe_network_liveness(
    *,
    host: str | None = None,
    port: int | None = None,
    password: str | None = None,
    timeout_s: float = 10.0,
) -> tuple[bool, str | None]:
    """Read ``GETINFO network-liveness`` from the Tor control port.

    Returns ``(is_live, None)`` on success or ``(False, error)`` on
    failure. ``network-liveness`` is Tor's own assessment of whether
    the network looks reachable — "up" or "down" string from Tor.
    """
    import asyncio
    import re

    resolved_host = host or settings.anonymize_tor_control_host or "127.0.0.1"
    resolved_port = int(
        port if port is not None else settings.anonymize_tor_control_port,
    )
    resolved_pw = password if password is not None else settings.resolved_tor_control_password
    if not resolved_host or resolved_port <= 0:
        return False, "tor control-port not configured"

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(resolved_host, resolved_port),
            timeout=timeout_s,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"tor control connect failed: {exc}"

    async def _send_and_read(cmd: str) -> str:
        writer.write((cmd + "\r\n").encode("ascii"))
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
            if not line:
                break
            chunks.append(line)
            text = line.decode("ascii", errors="replace")
            if re.match(r"^[2-5]\d{2} ", text):
                break
        return b"".join(chunks).decode("ascii", errors="replace")

    try:
        if resolved_pw:
            await _send_and_read(f'AUTHENTICATE {_quote_control_password(resolved_pw)}')
        else:
            await _send_and_read("AUTHENTICATE")
        resp = await _send_and_read("GETINFO network-liveness")
        try:
            await _send_and_read("QUIT")
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return False, f"tor control exchange failed: {exc}"

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass

    # Response is "250-network-liveness=up" or "=down".
    m = re.search(r"network-liveness=(\w+)", resp)
    if not m:
        return False, f"unparseable network-liveness response: {resp[:120]!r}"
    return m.group(1).lower() == "up", None


# --------------------------------------------------------------------
# Control-port SIGNAL helpers (NEWNYM + HUP).
# --------------------------------------------------------------------


async def _send_tor_signal(
    signal_name: str,
    *,
    host: str | None = None,
    port: int | None = None,
    password: str | None = None,
    timeout_s: float = 10.0,
) -> tuple[bool, str | None]:
    """Send a ``SIGNAL <name>`` command to the Tor control port.

    Returns ``(ok, error_message)``. ``signal_name`` is the Tor
    spec's signal token: ``NEWNYM``, ``HUP``, ``DUMP``, etc. The
    function handles the AUTHENTICATE round-trip + cleanup.

    Used by:
      * watchdog — ``SIGNAL NEWNYM`` to rebuild circuits.
      * reload — ``SIGNAL HUP`` to re-read torrc.
    """
    import asyncio
    import re

    resolved_host = host or settings.anonymize_tor_control_host or "127.0.0.1"
    resolved_port = int(
        port if port is not None else settings.anonymize_tor_control_port,
    )
    resolved_pw = password if password is not None else settings.resolved_tor_control_password
    if not resolved_host or resolved_port <= 0:
        return False, "tor control-port not configured"

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(resolved_host, resolved_port),
            timeout=timeout_s,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"tor control connect failed: {exc}"

    async def _send_and_read(cmd: str) -> str:
        writer.write((cmd + "\r\n").encode("ascii"))
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
            if not line:
                break
            chunks.append(line)
            text = line.decode("ascii", errors="replace")
            if re.match(r"^[2-5]\d{2} ", text):
                break
        return b"".join(chunks).decode("ascii", errors="replace")

    try:
        if resolved_pw:
            auth_resp = await _send_and_read(f'AUTHENTICATE {_quote_control_password(resolved_pw)}')
        else:
            auth_resp = await _send_and_read("AUTHENTICATE")
        if not auth_resp.startswith("250"):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return False, f"tor AUTHENTICATE rejected: {auth_resp.strip()[:120]}"

        signal_resp = await _send_and_read(f"SIGNAL {signal_name}")
        try:
            await _send_and_read("QUIT")
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return False, f"tor control exchange failed: {exc}"

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass

    if not signal_resp.startswith("250"):
        return False, f"tor SIGNAL {signal_name} rejected: {signal_resp.strip()[:120]}"
    return True, None


async def signal_newnym(
    *,
    host: str | None = None,
    port: int | None = None,
    password: str | None = None,
    timeout_s: float = 10.0,
) -> tuple[bool, str | None]:
    """Issue ``SIGNAL NEWNYM`` to force new circuits.

    Per the Tor control-spec: NEWNYM marks all existing circuits as
    "dirty" (won't be reused for new streams) but does NOT tear down
    streams already in flight. Tor rate-limits NEWNYM at 10s; calls
    inside the rate-limit window are silently no-ops on Tor's side.
    Callers should track their own last-fired timestamp and throttle
    accordingly (the watchdog uses ``settings.tor_newnym_min_interval_s``).

    Returns ``(ok, error)``.
    """
    return await _send_tor_signal(
        "NEWNYM",
        host=host,
        port=port,
        password=password,
        timeout_s=timeout_s,
    )


async def signal_reload(
    *,
    host: str | None = None,
    port: int | None = None,
    password: str | None = None,
    timeout_s: float = 10.0,
) -> tuple[bool, str | None]:
    """Issue ``SIGNAL HUP`` (a.k.a. RELOAD) to re-read torrc
    without restarting Tor. Useful for runtime config changes
    triggered via the operator-Tor dashboard panel.

    Returns ``(ok, error)``."""
    return await _send_tor_signal(
        "HUP",
        host=host,
        port=port,
        password=password,
        timeout_s=timeout_s,
    )


async def signal_cleardnscache(
    *,
    host: str | None = None,
    port: int | None = None,
    password: str | None = None,
    timeout_s: float = 10.0,
) -> tuple[bool, str | None]:
    """Issue ``SIGNAL CLEARDNSCACHE`` to drop the Tor client's
    resolver cache. Pairs well with ``NEWNYM`` when retrying after
    a transient circuit failure: cached entries that resolved via
    a now-dirty circuit are evicted so the next call re-resolves
    on the fresh circuits NEWNYM provoked.

    Cheap (~1 ms); safe to call inside hot retry loops.

    Returns ``(ok, error)``."""
    return await _send_tor_signal(
        "CLEARDNSCACHE",
        host=host,
        port=port,
        password=password,
        timeout_s=timeout_s,
    )


def bootstrap_timeout_seconds() -> int:
    """Hard timeout on the bootstrap probe.

    The supervisor refuses to start the anonymize service when the
    probe never reports ready within this window.
    """
    return max(1, int(settings.anonymize_tor_bootstrap_timeout_s))


# --------------------------------------------------------------------
# Control-port reconnect-with-backoff +
# bootstrap-regression watcher.
# --------------------------------------------------------------------


def compute_reconnect_backoff_schedule(
    *,
    attempts: int | None = None,
    base_seconds: int | None = None,
    cap_seconds: float = 16.0,
) -> list[float]:
    """Exponential backoff for control-port reconnection.

    Returns the sleep schedule the supervisor walks between
    ``GETINFO`` reconnect attempts:

        ``[base, base*2, base*4, ...]`` clamped to ``cap_seconds``.

    Defaults follow ``ANONYMIZE_TOR_CONTROL_RECONNECT_ATTEMPTS`` (5)
    and ``ANONYMIZE_TOR_CONTROL_RECONNECT_BACKOFF_S`` (1), so an
    operator who never overrides anything gets ``[1, 2, 4, 8, 16]``
    — total ~31 s before the supervisor surfaces a hard failure.
    """
    n = int(attempts) if attempts is not None else int(settings.anonymize_tor_control_reconnect_attempts)
    base = (
        float(base_seconds) if base_seconds is not None else float(settings.anonymize_tor_control_reconnect_backoff_s)
    )
    if n <= 0 or base <= 0:
        return []
    return [min(base * (2.0**i), cap_seconds) for i in range(n)]


@dataclass(frozen=True)
class BootstrapRecheckState:
    """Inputs the recheck watcher consults on every tick."""

    last_known_ready: bool
    last_status: TorBootstrapStatus | None
    consecutive_regressions: int


BootstrapRecheckDecision = Literal[
    "ok",  # still ready; do nothing.
    "ok_recovered",  # was regressed; now ready again — clear the flag.
    "regression_first",  # first regression observed; emit + start hysteresis.
    "regression_pause",  # regression confirmed; pause egress.
    "still_paused",  # still regressed; keep egress paused.
]


def bootstrap_recheck_decision(
    *,
    state: BootstrapRecheckState,
    fresh_status: TorBootstrapStatus,
    hysteresis_ticks: int = 2,
) -> BootstrapRecheckDecision:
    """Hysteresis-bounded recheck watcher.

    A single failed probe never pauses egress (Tor occasionally
    burps); we require ``hysteresis_ticks`` consecutive failures
    before pausing. Conversely, a single successful probe is enough
    to clear the regression flag — we don't make the operator wait
    once Tor is back.
    """
    now_ready = fresh_status.fully_bootstrapped

    if state.last_known_ready and now_ready:
        return "ok"

    if now_ready and not state.last_known_ready:
        return "ok_recovered"

    # now_ready is False from here on.
    if state.last_known_ready:
        return "regression_first"

    # Already in regression — count up consecutive failures.
    if state.consecutive_regressions + 1 >= hysteresis_ticks:
        return "regression_pause"
    return "still_paused"


def bootstrap_recheck_interval_seconds() -> int:
    """Cadence of the post-bootstrap recheck loop."""
    return max(1, int(settings.anonymize_tor_bootstrap_recheck_interval_s))


async def get_tor_process_uptime_s(
    *,
    host: str | None = None,
    port: int | None = None,
    password: str | None = None,
    timeout_s: float = 5.0,
) -> tuple[float | None, str | None]:
    """Read ``GETINFO process/uptime`` from the Tor control port.

    Returns ``(uptime_seconds, None)`` on success or ``(None, error)``
    on failure. ``process/uptime`` is Tor's own measure of seconds
    since the daemon started; used by the LND Tor supervisor to
    detect a fresh tor-proxy restart (inhibit I5 — don't auto-
    remediate within ~30 s of a manual restart because the operator
    already did the right fix).
    """
    import asyncio
    import re

    resolved_host = host or settings.anonymize_tor_control_host or "127.0.0.1"
    resolved_port = int(
        port if port is not None else settings.anonymize_tor_control_port,
    )
    resolved_pw = password if password is not None else settings.resolved_tor_control_password
    if not resolved_host or resolved_port <= 0:
        return None, "tor control-port not configured"

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(resolved_host, resolved_port),
            timeout=timeout_s,
        )
    except Exception as exc:  # noqa: BLE001
        return None, f"tor control connect failed: {exc}"

    async def _send_and_read(cmd: str) -> str:
        writer.write((cmd + "\r\n").encode("ascii"))
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
            if not line:
                break
            chunks.append(line)
            text = line.decode("ascii", errors="replace")
            if re.match(r"^[2-5]\d{2} ", text):
                break
        return b"".join(chunks).decode("ascii", errors="replace")

    try:
        if resolved_pw:
            await _send_and_read(f'AUTHENTICATE {_quote_control_password(resolved_pw)}')
        else:
            await _send_and_read("AUTHENTICATE")
        resp = await _send_and_read("GETINFO process/uptime")
        try:
            await _send_and_read("QUIT")
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
        return None, f"tor control exchange failed: {exc}"

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass

    # Response shape: "250-process/uptime=<seconds>".
    m = re.search(r"process/uptime=(\d+)", resp)
    if not m:
        return None, f"unparseable process/uptime response: {resp[:120]!r}"
    return float(m.group(1)), None


async def is_tor_control_port_reachable(
    *,
    host: str | None = None,
    port: int | None = None,
    password: str | None = None,
    timeout_s: float = 3.0,
) -> bool:
    """Cheap reachability probe for the Tor control port.

    Used by the LND Tor supervisor's I2 inhibit (don't try to
    remediate when the control port itself is unreachable; all
    remediation steps go through it). Distinct from HSFETCH-based
    probes because we want to detect "control port is gone" as
    its own signal — failing-loud rather than walking the full
    ladder when every step is structurally guaranteed to fail.

    Returns True iff we can open a TCP connection + complete
    ``AUTHENTICATE`` within ``timeout_s``.
    """
    import asyncio

    resolved_host = host or settings.anonymize_tor_control_host or "127.0.0.1"
    resolved_port = int(
        port if port is not None else settings.anonymize_tor_control_port,
    )
    resolved_pw = password if password is not None else settings.resolved_tor_control_password
    if not resolved_host or resolved_port <= 0:
        return False

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(resolved_host, resolved_port),
            timeout=timeout_s,
        )
    except Exception:  # noqa: BLE001
        return False

    try:
        auth_cmd = f'AUTHENTICATE {_quote_control_password(resolved_pw)}\r\n' if resolved_pw else "AUTHENTICATE\r\n"
        writer.write(auth_cmd.encode("ascii"))
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=timeout_s)
        ok = line.startswith(b"250 ")
        try:
            writer.write(b"QUIT\r\n")
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001
        ok = False
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
    return ok


__all__ = [
    "TorListenerNotConfiguredError",
    "CircuitExitInfo",
    "TorBootstrapStatus",
    "BootstrapRecheckState",
    "BootstrapRecheckDecision",
    "EntryGuardInfo",
    "resolve_socks_port",
    "resolve_socks_host",
    "assert_exit_relay_diversity",
    "is_tor_bootstrap_ready",
    "compute_effective_tor_ready",
    "sample_first_egress_jitter_s",
    "bootstrap_timeout_seconds",
    "compute_reconnect_backoff_schedule",
    "bootstrap_recheck_decision",
    "bootstrap_recheck_interval_seconds",
    "probe_tor_bootstrap_status",
    "probe_tor_circuit_status",
    "probe_entry_guards",
    "probe_network_liveness",
    "signal_newnym",
    "signal_reload",
    "get_tor_process_uptime_s",
    "is_tor_control_port_reachable",
]
