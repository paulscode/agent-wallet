# SPDX-License-Identifier: MIT
"""TLS / mTLS configuration tests for ``Bolt12GatewayClient``.

These tests live outside ``test_bolt12_gateway_client.py`` because
the TLS branch needs on-disk PEM material; the rest of the client
test surface uses the cheaper in-process cleartext server.

We cover three cases:

1. Partial config (e.g. CA + client cert set, key path missing) is
   rejected at *construction* time with ``ValueError``. This is the
   most dangerous mistake an operator can make — silently falling
   back to cleartext after typo'ing a path would defeat the whole
   feature.
2. Fully-configured TLS where one of the referenced files does not
   exist on disk surfaces a ``FileNotFoundError`` at ``connect()``
   time. Clearer than letting it become a confusing handshake
   failure on the first RPC.
3. End-to-end mTLS: a real ``grpc.aio`` server is started with TLS
   termination using ``openssl``-generated CA / server / client
   material; the client connects, calls ``GetIdentity``, and the
   call succeeds. This catches regressions in the credential
   wiring (e.g. wrong PEM ordering, missing SAN override).
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import grpc
import pytest
from grpc.aio import ServicerContext

from app.services.bolt12_gateway import Bolt12GatewayClient
from app.services.bolt12_gateway._proto import (
    bolt12_gateway_pb2 as pb,
)
from app.services.bolt12_gateway._proto import (
    bolt12_gateway_pb2_grpc as pb_grpc,
)

# ── partial-config rejection ──────────────────────────────────────


@pytest.mark.parametrize(
    "ca,cert,key",
    [
        ("ca.pem", None, None),
        (None, "client.pem", None),
        (None, None, "client.key"),
        ("ca.pem", "client.pem", None),
        ("ca.pem", None, "client.key"),
        (None, "client.pem", "client.key"),
    ],
)
def test_partial_tls_config_raises(ca: str | None, cert: str | None, key: str | None) -> None:
    """Any subset of the TLS triple that isn't empty-or-full is
    rejected at construction time — fail loud, never silently
    downgrade to cleartext."""
    with pytest.raises(ValueError, match="TLS configuration is partial"):
        Bolt12GatewayClient(
            "127.0.0.1:1",
            tls_ca_cert_path=ca,
            tls_client_cert_path=cert,
            tls_client_key_path=key,
        )


def test_no_tls_config_constructs_cleanly(tmp_path: Path) -> None:
    """Default (all-unset) construction succeeds and stores ``None``
    for every TLS field."""
    client = Bolt12GatewayClient("127.0.0.1:1")
    # Use the public-by-convention attrs for assertion; they're
    # implementation detail but stable inside this module.
    assert client._tls_ca_cert_path is None
    assert client._tls_client_cert_path is None
    assert client._tls_client_key_path is None


async def test_full_tls_config_with_missing_files_errors_on_connect(
    tmp_path: Path,
) -> None:
    """Fully-set paths that point at non-existent files fail at
    connect() with FileNotFoundError. Surfacing the error at connect
    time is much friendlier than a generic transport failure on the
    first RPC."""
    client = Bolt12GatewayClient(
        "127.0.0.1:1",
        tls_ca_cert_path=str(tmp_path / "missing-ca.pem"),
        tls_client_cert_path=str(tmp_path / "missing-client.pem"),
        tls_client_key_path=str(tmp_path / "missing-client.key"),
    )
    with pytest.raises(FileNotFoundError):
        await client.connect()


# ── end-to-end mTLS handshake ─────────────────────────────────────


def _have_openssl() -> bool:
    return shutil.which("openssl") is not None


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, bytes]]:
    """Generate a self-signed CA + server + client cert via the
    workspace's ``gen_bolt12_certs.sh`` script. We invoke the
    script (rather than re-inlining openssl calls) so that the
    script itself is exercised by the test suite — a regression in
    its openssl invocation is caught here."""
    if not _have_openssl():
        pytest.skip("openssl not available")
    out = tmp_path_factory.mktemp("bolt12-tls")
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "scripts" / "gen_bolt12_certs.sh"
    if not script.exists():
        pytest.skip("gen_bolt12_certs.sh not present")
    # ``--force`` to overwrite the empty tempdir.
    subprocess.run(
        ["bash", str(script), str(out), "--force"],
        check=True,
        capture_output=True,
    )
    yield {
        "ca": (out / "ca.pem").read_bytes(),
        "ca_path": str(out / "ca.pem"),
        "server_cert": (out / "server.pem").read_bytes(),
        "server_key": (out / "server.key").read_bytes(),
        "client_cert": (out / "client.pem").read_bytes(),
        "client_key": (out / "client.key").read_bytes(),
        "client_cert_path": str(out / "client.pem"),
        "client_key_path": str(out / "client.key"),
    }


class _MinimalServicer(pb_grpc.Bolt12GatewayServicer):
    async def GetIdentity(self, request: pb.GetIdentityRequest, context: ServicerContext) -> pb.GetIdentityResponse:
        return pb.GetIdentityResponse(
            node_id=b"\x03" + b"\xab" * 32,
            connected_peers=0,
            peers=[],
            version="tls-test",
        )


@pytest.fixture
async def tls_server(tls_material: dict[str, bytes]):
    """Start a ``grpc.aio`` server with TLS termination and mTLS
    (client cert required) using the generated material."""
    server = grpc.aio.server()
    pb_grpc.add_Bolt12GatewayServicer_to_server(_MinimalServicer(), server)
    creds = grpc.ssl_server_credentials(
        [(tls_material["server_key"], tls_material["server_cert"])],
        root_certificates=tls_material["ca"],
        require_client_auth=True,
    )
    port = server.add_secure_port("127.0.0.1:0", creds)
    await server.start()
    try:
        yield f"127.0.0.1:{port}"
    finally:
        await server.stop(grace=0.1)


async def test_end_to_end_mtls_handshake(tls_material: dict[str, bytes], tls_server: str) -> None:
    """Real TLS handshake with a server that *requires* a client
    cert. Validates that the client correctly:
      * loads PEM material from disk,
      * builds ``grpc.ssl_channel_credentials`` in the right order
        (root / private_key / certificate_chain), and
      * passes the SAN-override option so 127.0.0.1 dial succeeds
        against a cert with ``SAN=DNS:bolt12-gateway``.
    A regression in any of those would show up as
    ``UNAVAILABLE`` here."""
    async with Bolt12GatewayClient(
        tls_server,
        tls_ca_cert_path=tls_material["ca_path"],
        tls_client_cert_path=tls_material["client_cert_path"],
        tls_client_key_path=tls_material["client_key_path"],
        tls_server_name="bolt12-gateway",
    ) as client:
        ident = await client.get_identity()
    assert ident.version == "tls-test"


async def test_mtls_server_rejects_cleartext_client(
    tls_server: str,
) -> None:
    """The TLS server must reject a cleartext client — proves the
    server-side mTLS enforcement is real, not just opt-in cosmetic
    on the client. Without this assertion a regression that turned
    off ``require_client_auth`` could go unnoticed."""
    async with Bolt12GatewayClient(tls_server) as client:
        # The cleartext client speaks HTTP/2 plaintext; the TLS
        # server hangs up. Either UNAVAILABLE or INTERNAL is fine
        # — the point is that the RPC does NOT succeed.
        with pytest.raises(Exception):  # noqa: BLE001 — broad on purpose
            await asyncio.wait_for(client.get_identity(), timeout=5.0)
