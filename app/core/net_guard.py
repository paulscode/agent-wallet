# SPDX-License-Identifier: MIT
"""Outbound egress guard for clearnet HTTP requests.

Outbound requests to operator- or recipient-supplied hosts (LNURL
recipients, the configured chain-explorer URL) are resolved once, refused
when they land on a non-routable range, and pinned to the validated
address. Pinning is the important part: the IP that passed validation is
the exact IP the socket connects to, so a host whose authoritative DNS
returns a public address for the check and a private address a moment
later cannot redirect the request at internal infrastructure.

``.onion`` hosts are never resolved or pinned here — they are resolved
remotely by the Tor SOCKS proxy and carry no DNS-rebinding risk.
"""

import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

__all__ = [
    "BlockedHostError",
    "is_blocked_ip",
    "is_onion_host",
    "host_resolves_to_blocked",
    "resolve_pinned_ip",
    "pin_request_args",
    "validate_peer_host_not_internal",
]


class BlockedHostError(Exception):
    """Raised when a host is non-routable, unresolvable, or otherwise refused."""


def _embedded_ipv4s(
    addr: ipaddress.IPv6Address,
) -> list[ipaddress.IPv4Address]:
    """Decode any IPv4 address embedded in an IPv6 address.

    Covers IPv4-mapped (``::ffff:a.b.c.d``), 6to4 (``2002::/16``) and
    Teredo (``2001::/32``) encodings. A bare ``is_blocked_ip`` check on
    the IPv6 form would treat e.g. ``2002:a9fe:a9fe::1`` (which embeds
    ``169.254.169.254``, the cloud metadata IP) as an ordinary global
    address and let it through. We extract the embedded v4 so the SSRF
    guard judges the address it would actually reach.
    """
    out: list[ipaddress.IPv4Address] = []
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        out.append(mapped)
    sixtofour = getattr(addr, "sixtofour", None)
    if sixtofour is not None:
        out.append(sixtofour)
    teredo = getattr(addr, "teredo", None)
    if teredo is not None:
        # (server, client) — the client is the tunnelled endpoint; the
        # server is the relay. Judge both.
        out.extend(t for t in teredo if t is not None)
    return out


def is_blocked_ip(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private: bool = False,
) -> bool:
    """Return True for any address in a non-routable / internal range.

    Blocks the classic private/loopback/link-local/reserved/multicast/
    unspecified ranges AND anything that is not globally routable
    (``not is_global`` additionally catches CGNAT ``100.64.0.0/10`` per
    RFC 6598, the ``198.18.0.0/15`` benchmarking range, documentation
    ranges, etc.). For IPv6, any embedded IPv4 (6to4 / mapped / Teredo)
    is decoded and judged on its own merits.

    ``allow_private`` relaxes the policy for self-hosted backends (a local
    electrs lives on loopback / RFC1918 / CGNAT space). In that mode only
    the ranges that are never a real backend are refused — link-local
    (which covers the cloud metadata IP ``169.254.169.254``), multicast,
    unspecified, and reserved — while loopback and private space are
    permitted.
    """
    if isinstance(addr, ipaddress.IPv6Address):
        if any(is_blocked_ip(v4, allow_private=allow_private) for v4 in _embedded_ipv4s(addr)):
            return True
    if allow_private:
        return addr.is_link_local or addr.is_multicast or addr.is_unspecified or addr.is_reserved
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
        or not addr.is_global
    )


def is_onion_host(host: str) -> bool:
    return host.lower().endswith(".onion")


def host_resolves_to_blocked(host: str) -> bool:
    """Return True when ``host`` is (or resolves to) a blocked address.

    Conservative: a single blocked address among the resolved set flips
    the verdict, so split-horizon DNS cannot slip a private target past
    the check, and an unresolvable host is treated as blocked. ``.onion``
    hosts are never resolved and are reported as not-blocked (they route
    via the Tor proxy).
    """
    if is_onion_host(host):
        return False
    try:
        return is_blocked_ip(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True
    for _fam, _kind, _proto, _name, sockaddr in infos:
        try:
            addr = ipaddress.ip_address(sockaddr[0])
        except (ValueError, IndexError):
            continue
        if is_blocked_ip(addr):
            return True
    return False


def resolve_pinned_ip(host: str, port: int | None = None, *, allow_private: bool = False) -> str:
    """Resolve ``host`` and return one validated IP literal to connect to.

    Every address the resolver returns must be routable; if any is in a
    blocked range the whole host is refused (``BlockedHostError``). A bare
    IP literal is validated directly without a DNS round-trip. Refusing on
    *any* blocked address — rather than filtering to the routable ones —
    means a round-robin record that mixes a public and a private answer
    cannot be used to reach the private one.

    ``allow_private`` is forwarded to :func:`is_blocked_ip` for self-hosted
    backends that legitimately live on loopback / private space.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None:
        if is_blocked_ip(addr, allow_private=allow_private):
            raise BlockedHostError(f"refusing to connect to non-routable address: {host}")
        return str(addr)

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BlockedHostError(f"could not resolve host: {host}") from exc

    pinned: str | None = None
    for _fam, _kind, _proto, _name, sockaddr in infos:
        try:
            resolved = ipaddress.ip_address(sockaddr[0])
        except (ValueError, IndexError):
            continue
        if is_blocked_ip(resolved, allow_private=allow_private):
            raise BlockedHostError(f"host {host} resolves to a non-routable address: {resolved}")
        if pinned is None:
            pinned = str(resolved)
    if pinned is None:
        raise BlockedHostError(f"no usable address for host: {host}")
    return pinned


def _strip_host_port(host: str) -> str:
    """Extract the host portion from ``ip:port`` / ``[v6]:port`` / ``v6``.

    A bracketed form yields the inner address. An unbracketed value with
    more than one colon is a bare IPv6 literal (which has no port and must
    NOT be split on its last colon — doing so produces a malformed string
    that slips past the IP check and is then treated as an unresolvable
    hostname). A single colon is an ``ip:port`` / ``host:port`` pair.
    """
    raw = host.strip()
    if raw.startswith("["):
        end = raw.find("]")
        return raw[1:end] if end != -1 else raw.strip("[]")
    if raw.count(":") == 1:
        return raw.rsplit(":", 1)[0]
    # No colon (bare host) or many colons (bare IPv6) — use as-is.
    return raw


def validate_peer_host_not_internal(host: str) -> str:
    """Validate an LND peer ``host`` against the egress policy and return it.

    Accepts ``ip:port`` / ``[v6]:port`` / ``hostname[:port]`` forms.
    ``.onion`` peers are permitted (the Tor proxy resolves them remotely and
    they carry no rebinding risk). A bare IP literal is judged directly by
    :func:`is_blocked_ip`; a hostname is refused when it is a known internal
    name or resolves to any non-routable address. The resolution branch uses
    the same :func:`is_blocked_ip` policy as the literal branch, so CGNAT,
    benchmarking, documentation and IPv6-embedded-IPv4 ranges are caught
    consistently. An unresolvable hostname is allowed through here — the
    connection attempt fails later at the LND layer.

    Raises ``ValueError`` (suitable for a pydantic field validator) when the
    host targets non-routable / internal space.

    NOTE: a TOCTOU window remains because the resolving system (this API)
    differs from the connecting system (LND); the risk is minimal as LND
    peer connections have limited SSRF utility.
    """
    host_part = _strip_host_port(host)

    if host_part.lower().endswith(".onion"):
        return host

    try:
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(host_part)
    except ValueError:
        addr = None

    if addr is not None:
        if is_blocked_ip(addr):
            raise ValueError(f"Private/internal addresses are not allowed: {host_part}")
        return host

    lower = host_part.lower()
    if lower == "localhost" or lower.endswith(".local") or lower.endswith(".internal"):
        raise ValueError(f"Internal hostnames are not allowed: {host_part}")

    # Resolve and apply the same routability policy to every answer.
    try:
        for _fam, _kind, _proto, _name, sockaddr in socket.getaddrinfo(host_part, None):
            resolved = ipaddress.ip_address(sockaddr[0])
            if is_blocked_ip(resolved):
                raise ValueError(f"Hostname resolves to private/internal address: {host_part} → {resolved}")
    except socket.gaierror:
        pass  # Unresolvable — the connection fails later at the LND layer.

    return host


def pin_request_args(url: str) -> tuple[str, dict[str, str], dict[str, str]]:
    """Build pinned request arguments for a clearnet ``httpx`` request.

    Returns ``(pinned_url, headers, extensions)`` where ``pinned_url`` has
    its host replaced by a validated IP literal, ``headers`` carries the
    original ``Host`` so the recipient routes correctly, and
    ``extensions`` sets ``sni_hostname`` so the TLS handshake and
    certificate verification still run against the real hostname. Pass the
    three straight through to ``client.get`` / ``client.stream``.

    Raises ``BlockedHostError`` for non-routable / unresolvable hosts and
    ``ValueError`` for ``.onion`` hosts (which must route via Tor, not be
    pinned).
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        raise BlockedHostError("missing host")
    if is_onion_host(host):
        raise ValueError("onion hosts must route via the Tor proxy, not pinned")

    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port or default_port
    pinned_ip = resolve_pinned_ip(host, port)

    ip_literal = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    pinned_netloc = f"{ip_literal}:{port}"
    pinned_url = urlunparse(parsed._replace(netloc=pinned_netloc))

    # Preserve the caller's port presence in the Host header.
    host_header = host if parsed.port is None else f"{host}:{parsed.port}"

    return pinned_url, {"Host": host_header}, {"sni_hostname": host}
