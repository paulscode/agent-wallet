# SPDX-License-Identifier: MIT
"""Electrum protocol primitives used by the Electrum chain backend.

Two responsibilities:

* **Address → scripthash** — Electrum identifies addresses by the
  little-endian hex of ``sha256(scriptPubKey)``. We derive
  ``scriptPubKey`` directly from the wallet's address strings without
  pulling in any heavy third-party Bitcoin library.
* **Transport opener** — TCP/SSL over either direct ``asyncio`` or a
  SOCKS5 proxy (Tor) for ``.onion`` hosts. Returns a
  ``(reader, writer)`` pair the JSON-RPC client framing layer in
  :mod:`app.services.chain.electrum` consumes.

The framing layer (line-delimited JSON-RPC, request/response
correlation, subscription dispatch, reconnect) lives in
:mod:`app.services.chain.electrum`.

References:

* Electrum protocol: https://electrumx-spesmilo.readthedocs.io/en/latest/protocol-basics.html
* BIP-141 (P2WPKH/P2WSH): bech32 SegWit addresses
* BIP-350 (P2TR): bech32m SegWit v1 addresses
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import socket
import ssl
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ─── Bech32 / bech32m (minimal, segwit-only) ─────────────────────────────

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data: list[int], frombits: int, tobits: int, pad: bool) -> Optional[list[int]]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def _decode_segwit(addr: str) -> Optional[tuple[str, int, bytes]]:
    """Decode a SegWit address into ``(hrp, witver, witprog)``.

    Returns ``None`` on any decode error. Validates checksum constant
    against witness version (v0 = bech32, v1+ = bech32m).
    """
    if not isinstance(addr, str) or not addr:
        return None
    if addr.lower() != addr and addr.upper() != addr:
        return None
    addr = addr.lower()
    if len(addr) > 90 or len(addr) < 8:
        return None
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        return None
    hrp = addr[:pos]
    data: list[int] = []
    for c in addr[pos + 1 :]:
        idx = _BECH32_CHARSET.find(c)
        if idx == -1:
            return None
        data.append(idx)
    if len(data) < 6:
        return None
    witver = data[0]
    if witver > 16:
        return None
    expected_const = _BECH32_CONST if witver == 0 else _BECH32M_CONST
    if _polymod(_hrp_expand(hrp) + data) != expected_const:
        return None
    decoded = _convertbits(data[1:-6], 5, 8, False)
    if decoded is None:
        return None
    witprog = bytes(decoded)
    if len(witprog) < 2 or len(witprog) > 40:
        return None
    if witver == 0 and len(witprog) not in (20, 32):
        return None
    return hrp, witver, witprog


# ─── Base58Check (minimal) ───────────────────────────────────────────────

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58_decode(s: str) -> Optional[bytes]:
    if not isinstance(s, str) or not s:
        return None
    n = 0
    for ch in s:
        idx = _B58_ALPHABET.find(ch.encode("ascii"))
        if idx < 0:
            return None
        n = n * 58 + idx
    full = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    # leading '1's = leading zero bytes
    zeros = 0
    for ch in s:
        if ch == "1":
            zeros += 1
        else:
            break
    return b"\x00" * zeros + full


def _decode_base58check(addr: str) -> Optional[tuple[int, bytes]]:
    """Decode a base58check address into ``(version_byte, payload)``."""
    raw = _b58_decode(addr)
    if raw is None or len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    h = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if h != checksum:
        return None
    if len(payload) != 21:
        return None
    return payload[0], payload[1:]


# ─── Network → expected prefixes ─────────────────────────────────────────

# Map ``settings.bitcoin_network`` to the prefixes we'll accept.
_NETWORK_PREFIXES: dict[str, dict[str, object]] = {
    "bitcoin": {
        "bech32_hrp": "bc",
        "p2pkh_version": 0x00,
        "p2sh_version": 0x05,
    },
    "testnet": {
        "bech32_hrp": "tb",
        "p2pkh_version": 0x6F,
        "p2sh_version": 0xC4,
    },
    "signet": {
        "bech32_hrp": "tb",
        "p2pkh_version": 0x6F,
        "p2sh_version": 0xC4,
    },
    "regtest": {
        "bech32_hrp": "bcrt",
        "p2pkh_version": 0x6F,
        "p2sh_version": 0xC4,
    },
}


# ─── Address → scriptPubKey → scripthash ─────────────────────────────────


def address_to_script_pubkey(address: str, network: str = "bitcoin") -> bytes:
    """Derive the on-chain ``scriptPubKey`` bytes for a wallet address.

    Supports P2PKH, P2SH (incl. P2SH-P2WPKH wrappers), P2WPKH (v0,
    bech32, 20-byte program), P2WSH (v0, bech32, 32-byte program), and
    P2TR (v1, bech32m, 32-byte program). Raises ``ValueError`` for any
    unsupported / malformed address.

    ``network`` is one of ``"bitcoin"``, ``"testnet"``, ``"signet"``,
    ``"regtest"`` (matches the wallet's ``BITCOIN_NETWORK`` setting).
    """
    if not isinstance(address, str) or not address:
        raise ValueError("address must be a non-empty string")
    prefixes = _NETWORK_PREFIXES.get(network)
    if prefixes is None:
        raise ValueError(f"unsupported network {network!r}")

    # Try bech32 / bech32m first (cheaper to fail-fast on prefix).
    seg = _decode_segwit(address)
    if seg is not None:
        hrp, witver, witprog = seg
        if hrp != prefixes["bech32_hrp"]:
            raise ValueError(
                f"address HRP {hrp!r} does not match network {network!r} (expected {prefixes['bech32_hrp']!r})"
            )
        # OP_<witver> <push len> <program>
        op_n = 0x00 if witver == 0 else (0x50 + witver)
        return bytes([op_n, len(witprog)]) + witprog

    b58 = _decode_base58check(address)
    if b58 is not None:
        version, payload = b58
        if version == prefixes["p2pkh_version"]:
            # OP_DUP OP_HASH160 <20> <h160> OP_EQUALVERIFY OP_CHECKSIG
            return b"\x76\xa9\x14" + payload + b"\x88\xac"
        if version == prefixes["p2sh_version"]:
            # OP_HASH160 <20> <h160> OP_EQUAL
            return b"\xa9\x14" + payload + b"\x87"
        raise ValueError(f"unsupported base58check version 0x{version:02x} for network {network!r}")

    raise ValueError(f"unrecognised address format: {address!r}")


def address_to_scripthash(address: str, network: str = "bitcoin") -> str:
    """Return the Electrum scripthash for ``address``.

    Electrum scripthash = ``sha256(scriptPubKey)`` reversed (little-
    endian) and hex-encoded. See the Electrum protocol spec.
    """
    spk = address_to_script_pubkey(address, network)
    h = hashlib.sha256(spk).digest()
    return h[::-1].hex()


# ─── Transport opener ────────────────────────────────────────────────────


class ElectrumUrl:
    """Parsed ``tcp://host:port`` / ``ssl://host:port`` URL."""

    DEFAULT_PORTS = {"tcp": 50001, "ssl": 50002}

    __slots__ = ("scheme", "host", "port")

    def __init__(self, scheme: str, host: str, port: int) -> None:
        self.scheme = scheme
        self.host = host
        self.port = port

    @classmethod
    def parse(cls, url: str) -> "ElectrumUrl":
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("tcp", "ssl"):
            raise ValueError(f"electrum URL must use tcp:// or ssl:// (got {scheme!r})")
        host = (parsed.hostname or "").lower()
        if not host:
            raise ValueError("electrum URL is missing a hostname")
        port = parsed.port or cls.DEFAULT_PORTS[scheme]
        if not (1 <= port <= 65535):
            raise ValueError(f"electrum URL port out of range: {port}")
        return cls(scheme, host, port)

    @property
    def is_onion(self) -> bool:
        return self.host.endswith(".onion")

    def __repr__(self) -> str:  # pragma: no cover
        return f"ElectrumUrl({self.scheme}://{self.host}:{self.port})"


def _build_ssl_context(*, verify: bool, ca_cert: str, server_hostname: str, is_onion: bool) -> ssl.SSLContext:
    """Build an SSL context for an Electrum connection.

    For ``.onion`` hosts, hostname verification is disabled regardless
    of ``verify`` because ``.onion`` names are not part of the Web PKI
    trust chain. The cryptographic identity is supplied by Tor's
    rendezvous protocol.
    """
    ctx = ssl.create_default_context()
    if is_onion or not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if ca_cert and not is_onion and verify:
        # Accept either a file path or a base64-encoded PEM blob.
        ca_text: Optional[str] = None
        if os.path.isfile(ca_cert):
            with open(ca_cert, "r", encoding="utf-8") as f:
                ca_text = f.read()
        else:
            # Try base64 of a PEM
            import base64

            try:
                ca_text = base64.b64decode(ca_cert).decode("utf-8")
            except Exception:
                ca_text = ca_cert if "BEGIN CERTIFICATE" in ca_cert else None
        if ca_text:
            ctx.load_verify_locations(cadata=ca_text)
    return ctx


async def _socks5_connect(
    proxy_url: str,
    target_host: str,
    target_port: int,
    *,
    timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP connection to ``target_host:target_port`` via SOCKS5.

    Implements the SOCKS5 no-auth handshake by hand (~25 lines). Tor's
    SOCKS port always supports no-auth so we don't bother negotiating
    other methods. ``proxy_url`` must be ``socks5://host:port``.
    """
    parsed = urlparse(proxy_url)
    if parsed.scheme not in ("socks5", "socks5h"):
        raise ValueError(f"SOCKS proxy URL must use socks5:// or socks5h:// (got {parsed.scheme!r})")
    proxy_host = parsed.hostname
    proxy_port = parsed.port or 9050
    if not proxy_host:
        raise ValueError("SOCKS proxy URL is missing a hostname")

    reader, writer = await asyncio.wait_for(asyncio.open_connection(proxy_host, proxy_port), timeout=timeout)
    try:
        # Greeting: VER=5, NMETHODS=1, METHODS=[NO_AUTH]
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        greeting = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if greeting[0] != 0x05 or greeting[1] != 0x00:
            raise ConnectionError(f"SOCKS5 greeting rejected: {greeting.hex()} (proxy may require authentication)")

        # CONNECT request: VER=5, CMD=CONNECT(1), RSV=0, ATYP=DOMAINNAME(3),
        # <len><name>, <port-hi><port-lo>
        host_bytes = target_host.encode("idna")
        if len(host_bytes) > 255:
            raise ValueError("hostname too long for SOCKS5 DOMAINNAME")
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + target_port.to_bytes(2, "big")
        writer.write(req)
        await writer.drain()

        resp_head = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if resp_head[0] != 0x05:
            raise ConnectionError(f"SOCKS5 bad version in response: {resp_head[0]}")
        if resp_head[1] != 0x00:
            # Tor REPLY codes: 1 general, 2 not allowed, 3 net unreach,
            # 4 host unreach, 5 conn refused, 6 ttl expired, 7 cmd not
            # supported, 8 atyp not supported.
            raise ConnectionError(f"SOCKS5 connect failed: REP=0x{resp_head[1]:02x}")
        atyp = resp_head[3]
        if atyp == 0x01:
            await asyncio.wait_for(reader.readexactly(4 + 2), timeout=timeout)
        elif atyp == 0x03:
            n = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
            await asyncio.wait_for(reader.readexactly(n[0] + 2), timeout=timeout)
        elif atyp == 0x04:
            await asyncio.wait_for(reader.readexactly(16 + 2), timeout=timeout)
        else:
            raise ConnectionError(f"SOCKS5 unknown ATYP=0x{atyp:02x}")
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise
    return reader, writer


async def open_electrum_transport(
    url: ElectrumUrl,
    *,
    tls_verify: bool = True,
    ca_cert: str = "",
    tor_proxy: str = "",
    force_tor: bool = False,
    connect_timeout: float = 10.0,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a (reader, writer) pair to an Electrum server.

    Honours the wallet's normal SOCKS5/Tor convention: ``.onion``
    targets MUST be reached via ``tor_proxy``. When ``force_tor`` is set,
    clearnet hosts are also reached through ``tor_proxy``, which resolves
    the hostname remotely so the host IP is not exposed. Otherwise plain
    hosts use ``asyncio.open_connection`` directly. SSL is layered on top
    in all cases.
    """
    use_proxy = url.is_onion or (force_tor and bool(tor_proxy))
    if url.is_onion and not tor_proxy:
        raise ValueError(f"electrum URL {url!r} is .onion but no Tor proxy supplied")

    ssl_ctx: Optional[ssl.SSLContext] = None
    if url.scheme == "ssl":
        ssl_ctx = _build_ssl_context(
            verify=tls_verify,
            ca_cert=ca_cert,
            server_hostname=url.host,
            is_onion=url.is_onion,
        )

    if use_proxy:
        reader, writer = await _socks5_connect(tor_proxy, url.host, url.port, timeout=connect_timeout)
        if ssl_ctx is not None:
            # Wrap the existing stream in TLS. For .onion targets we
            # never verify hostnames (see _build_ssl_context).
            try:
                await writer.start_tls(
                    ssl_ctx,
                    server_hostname=None if url.is_onion else url.host,
                )
            except Exception:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                raise
        # TCP-keepalive on the underlying socket so Tor circuits don't
        # silently rot.
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except OSError:
                pass
        return reader, writer

    # Direct connection. Resolve and pin the IP so a host whose DNS
    # later flips to the cloud metadata IP (169.254.169.254) or another
    # never-a-backend range cannot redirect the Electrum stream. TLS,
    # when present, still verifies against the real hostname via
    # ``server_hostname``. ``allow_private`` keeps a self-hosted electrs
    # on loopback / LAN reachable while refusing link-local / multicast /
    # unspecified / reserved targets.
    from app.core.net_guard import resolve_pinned_ip

    connect_host = resolve_pinned_ip(url.host, url.port, allow_private=True)
    open_kwargs: dict[str, object] = {}
    if ssl_ctx is not None:
        open_kwargs["ssl"] = ssl_ctx
        open_kwargs["server_hostname"] = url.host
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(connect_host, url.port, **open_kwargs),  # type: ignore[arg-type]
        timeout=connect_timeout,
    )
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass
    return reader, writer
