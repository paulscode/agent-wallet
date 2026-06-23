# SPDX-License-Identifier: MIT
"""Tests for the Electrum transport layer.

Covers ``ElectrumUrl.parse``, ``_build_ssl_context``,
``_socks5_connect``, and ``open_electrum_transport`` —
the previously-untested glue that selects between direct TCP,
SSL, and SOCKS5/Tor.
"""

from __future__ import annotations

import asyncio
import base64
import socket
import ssl

import pytest

from app.services.chain.electrum_protocol import (
    ElectrumUrl,
    _build_ssl_context,
    _socks5_connect,
    open_electrum_transport,
)

# ─── ElectrumUrl.parse ────────────────────────────────────────────────


class TestElectrumUrlParse:
    def test_tcp_default_port(self):
        url = ElectrumUrl.parse("tcp://example.com")
        assert url.scheme == "tcp"
        assert url.host == "example.com"
        assert url.port == 50001
        assert url.is_onion is False

    def test_ssl_default_port(self):
        url = ElectrumUrl.parse("ssl://example.com")
        assert url.port == 50002

    def test_explicit_port(self):
        url = ElectrumUrl.parse("tcp://example.com:12345")
        assert url.port == 12345

    def test_onion_detection(self):
        url = ElectrumUrl.parse("tcp://abcdef234567.onion:50001")
        assert url.is_onion is True

    def test_uppercase_host_lowered(self):
        url = ElectrumUrl.parse("tcp://Example.COM:50001")
        assert url.host == "example.com"

    def test_rejects_http_scheme(self):
        with pytest.raises(ValueError, match="tcp:// or ssl://"):
            ElectrumUrl.parse("http://example.com:50001")

    def test_rejects_missing_host(self):
        with pytest.raises(ValueError, match="missing a hostname"):
            ElectrumUrl.parse("tcp://:50001")


# ─── _build_ssl_context ──────────────────────────────────────────────


class TestBuildSslContext:
    def test_default_verifies(self):
        ctx = _build_ssl_context(
            verify=True,
            ca_cert="",
            server_hostname="electrum.example.com",
            is_onion=False,
        )
        assert ctx.check_hostname is True
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_verify_false_disables(self):
        ctx = _build_ssl_context(
            verify=False,
            ca_cert="",
            server_hostname="electrum.example.com",
            is_onion=False,
        )
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_onion_always_disables_verify(self):
        ctx = _build_ssl_context(
            verify=True,
            ca_cert="",
            server_hostname="abc.onion",
            is_onion=True,
        )
        # .onion is not in the Web PKI; verify is force-disabled.
        assert ctx.check_hostname is False
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_ca_cert_from_pem_file(self, tmp_path):
        pem = self._self_signed_pem()
        f = tmp_path / "ca.pem"
        f.write_text(pem)
        # Must not raise — load_verify_locations succeeds with a valid PEM.
        _build_ssl_context(
            verify=True,
            ca_cert=str(f),
            server_hostname="x.example.com",
            is_onion=False,
        )

    def test_ca_cert_from_base64_pem(self):
        pem = self._self_signed_pem()
        b64 = base64.b64encode(pem.encode()).decode()
        _build_ssl_context(
            verify=True,
            ca_cert=b64,
            server_hostname="x.example.com",
            is_onion=False,
        )

    def test_ca_cert_inline_pem(self):
        pem = self._self_signed_pem()
        _build_ssl_context(
            verify=True,
            ca_cert=pem,
            server_hostname="x.example.com",
            is_onion=False,
        )

    def test_ca_cert_ignored_when_not_verifying(self):
        # When verify=False and is_onion=False, ca_cert path is skipped.
        # Pass garbage; if it were attempted to be parsed, this would
        # raise. It must not.
        _build_ssl_context(
            verify=False,
            ca_cert="not a valid PEM",
            server_hostname="x.example.com",
            is_onion=False,
        )

    @staticmethod
    def _self_signed_pem() -> str:
        """Generate an in-memory self-signed cert PEM. Used only as a
        valid input to ``ssl.SSLContext.load_verify_locations``."""
        try:
            from datetime import datetime, timedelta, timezone

            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
        except ImportError:  # pragma: no cover
            pytest.skip("cryptography not installed")

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()


# ─── In-process SOCKS5 proxy ─────────────────────────────────────────


class FakeSocks5Proxy:
    """Minimal SOCKS5 proxy supporting NO_AUTH + DOMAINNAME CONNECT.

    Forwards bytes to the real ``(target_host, target_port)``. Used to
    test the wallet's hand-rolled SOCKS5 client without depending on a
    real Tor daemon.
    """

    def __init__(
        self,
        *,
        reject_greeting: bool = False,
        rep_code: int = 0x00,
        atyp_response: int = 0x01,  # 0x01=IPv4, 0x03=DOMAIN, 0x04=IPv6
    ) -> None:
        self._server: asyncio.base_events.Server | None = None
        self.host = "127.0.0.1"
        self.port = 0
        self._reject_greeting = reject_greeting
        self._rep_code = rep_code
        self._atyp_response = atyp_response
        # Track CONNECT targets for assertions.
        self.targets: list[tuple[str, int]] = []

    @property
    def url(self) -> str:
        return f"socks5://{self.host}:{self.port}"

    async def __aenter__(self) -> "FakeSocks5Proxy":
        self._server = await asyncio.start_server(self._handle, host=self.host, port=0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            # Greeting: VER NMETHODS METHOD*
            head = await reader.readexactly(2)
            assert head[0] == 0x05
            n_methods = head[1]
            await reader.readexactly(n_methods)
            if self._reject_greeting:
                writer.write(b"\x05\xff")  # no acceptable methods
                await writer.drain()
                writer.close()
                return
            writer.write(b"\x05\x00")  # NO_AUTH selected
            await writer.drain()

            # Request: VER CMD RSV ATYP ...
            req_head = await reader.readexactly(4)
            assert req_head[0] == 0x05
            assert req_head[1] == 0x01  # CONNECT
            atyp = req_head[3]
            if atyp == 0x03:
                n = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(n)).decode("idna")
            elif atyp == 0x01:
                host = ".".join(str(b) for b in await reader.readexactly(4))
            else:  # pragma: no cover
                writer.close()
                return
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.targets.append((host, port))

            if self._rep_code != 0x00:
                # Send a failure reply with IPv4 BND.ADDR (0.0.0.0:0).
                writer.write(bytes([0x05, self._rep_code, 0x00, 0x01]) + b"\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return

            # Open the upstream connection.
            try:
                up_reader, up_writer = await asyncio.open_connection(host, port)
            except Exception:
                writer.write(bytes([0x05, 0x05, 0x00, 0x01]) + b"\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return

            # Reply: VER REP RSV ATYP BND.ADDR BND.PORT
            if self._atyp_response == 0x01:
                bnd = b"\x01" + b"\x7f\x00\x00\x01" + b"\x00\x00"
            elif self._atyp_response == 0x03:
                name = b"localhost"
                bnd = b"\x03" + bytes([len(name)]) + name + b"\x00\x00"
            else:  # 0x04 IPv6
                bnd = b"\x04" + b"\x00" * 16 + b"\x00\x00"
            writer.write(b"\x05\x00\x00" + bnd)
            await writer.drain()

            # Bidirectional pump. When either side closes, tear both
            # down so the test can clean up promptly.
            async def pump(src, dst):
                try:
                    while True:
                        data = await src.read(4096)
                        if not data:
                            return
                        dst.write(data)
                        await dst.drain()
                except Exception:
                    return
                finally:
                    try:
                        dst.close()
                    except Exception:
                        pass

            await asyncio.gather(
                pump(reader, up_writer),
                pump(up_reader, writer),
                return_exceptions=True,
            )
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


# ─── _socks5_connect ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_socks5_connect_happy_path():
    """SOCKS5 client opens a forwarded TCP stream end-to-end."""
    # Echo server — what we'll proxy to.
    echo = await asyncio.start_server(_echo_handler, host="127.0.0.1", port=0)
    echo_port = echo.sockets[0].getsockname()[1]
    try:
        async with FakeSocks5Proxy() as proxy:
            r, w = await _socks5_connect(proxy.url, "127.0.0.1", echo_port, timeout=2.0)
            try:
                w.write(b"hello\n")
                await w.drain()
                line = await asyncio.wait_for(r.readline(), timeout=2.0)
                assert line == b"hello\n"
                assert proxy.targets == [("127.0.0.1", echo_port)]
            finally:
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
    finally:
        echo.close()
        await echo.wait_closed()


async def _echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                return
            writer.write(data)
            await writer.drain()
    except Exception:
        return
    finally:
        try:
            writer.close()
        except Exception:
            pass


@pytest.mark.asyncio
async def test_socks5_rejects_non_socks_scheme():
    with pytest.raises(ValueError, match="socks5://"):
        await _socks5_connect("http://proxy:9050", "host", 50001, timeout=1.0)


@pytest.mark.asyncio
async def test_socks5_greeting_refused_raises():
    async with FakeSocks5Proxy(reject_greeting=True) as proxy:
        with pytest.raises(ConnectionError, match="greeting"):
            await _socks5_connect(proxy.url, "any", 50001, timeout=2.0)


@pytest.mark.asyncio
async def test_socks5_connect_failure_rep_code():
    """REP=0x05 (connection refused) surfaces as ConnectionError."""
    async with FakeSocks5Proxy(rep_code=0x05) as proxy:
        with pytest.raises(ConnectionError, match="REP=0x05"):
            await _socks5_connect(proxy.url, "127.0.0.1", 1, timeout=2.0)


@pytest.mark.asyncio
async def test_socks5_handles_domainname_atyp_response():
    """Some SOCKS5 servers reply with ATYP=0x03; client must consume it."""
    echo = await asyncio.start_server(_echo_handler, host="127.0.0.1", port=0)
    echo_port = echo.sockets[0].getsockname()[1]
    try:
        async with FakeSocks5Proxy(atyp_response=0x03) as proxy:
            r, w = await _socks5_connect(proxy.url, "127.0.0.1", echo_port, timeout=2.0)
            w.write(b"x\n")
            await w.drain()
            assert await asyncio.wait_for(r.readline(), 2.0) == b"x\n"
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
    finally:
        echo.close()
        await echo.wait_closed()


@pytest.mark.asyncio
async def test_socks5_handles_ipv6_atyp_response():
    echo = await asyncio.start_server(_echo_handler, host="127.0.0.1", port=0)
    echo_port = echo.sockets[0].getsockname()[1]
    try:
        async with FakeSocks5Proxy(atyp_response=0x04) as proxy:
            r, w = await _socks5_connect(proxy.url, "127.0.0.1", echo_port, timeout=2.0)
            w.write(b"y\n")
            await w.drain()
            assert await asyncio.wait_for(r.readline(), 2.0) == b"y\n"
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
    finally:
        echo.close()
        await echo.wait_closed()


# ─── open_electrum_transport ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_open_transport_direct_tcp():
    """Plain ``tcp://`` host bypasses the proxy and connects directly."""
    echo = await asyncio.start_server(_echo_handler, host="127.0.0.1", port=0)
    port = echo.sockets[0].getsockname()[1]
    try:
        url = ElectrumUrl.parse(f"tcp://127.0.0.1:{port}")
        r, w = await open_electrum_transport(url, tor_proxy="", connect_timeout=2.0)
        try:
            w.write(b"ping\n")
            await w.drain()
            assert await asyncio.wait_for(r.readline(), 2.0) == b"ping\n"
        finally:
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
    finally:
        echo.close()
        await echo.wait_closed()


@pytest.mark.asyncio
async def test_open_transport_onion_without_tor_raises():
    url = ElectrumUrl.parse("tcp://abc234567xyz.onion:50001")
    with pytest.raises(ValueError, match="Tor proxy"):
        await open_electrum_transport(url, tor_proxy="", connect_timeout=1.0)


@pytest.mark.asyncio
async def test_open_transport_direct_refuses_metadata_ip():
    """A direct Electrum host that resolves to the cloud metadata IP
    (link-local 169.254.169.254) is refused before any connection —
    a self-hosted backend never lives there."""
    from app.core.net_guard import BlockedHostError

    url = ElectrumUrl.parse("tcp://169.254.169.254:50001")
    with pytest.raises(BlockedHostError):
        await open_electrum_transport(url, tor_proxy="", connect_timeout=1.0)


@pytest.mark.asyncio
async def test_open_transport_direct_tcp_keepalive_set():
    """The connection must enable SO_KEEPALIVE for long-lived sockets."""
    echo = await asyncio.start_server(_echo_handler, host="127.0.0.1", port=0)
    port = echo.sockets[0].getsockname()[1]
    try:
        url = ElectrumUrl.parse(f"tcp://127.0.0.1:{port}")
        r, w = await open_electrum_transport(url, tor_proxy="", connect_timeout=2.0)
        try:
            sock = w.get_extra_info("socket")
            assert sock is not None
            keep = sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
            assert keep == 1
        finally:
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
    finally:
        echo.close()
        await echo.wait_closed()
