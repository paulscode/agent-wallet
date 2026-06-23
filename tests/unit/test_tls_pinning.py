# SPDX-License-Identifier: MIT
"""Unit tests for the operator-supplied PEM helper in ``app.core.tls``
and the mempool client's ``_build_verify`` resolution.

Covers the fix from
.
"""

from __future__ import annotations

import base64
import ssl
from unittest.mock import patch

import pytest

from app.core.tls import load_pinned_ca_context

# A self-signed throwaway CA generated once for these tests. The key is
# discarded so this is harmless to commit. Subject CN = "agent-wallet-test-ca".
_TEST_CA_PEM = """\
-----BEGIN CERTIFICATE-----
MIIBezCCAS6gAwIBAgIUS+Q7nlYNw2bcq1uXNi6/wRJ9wHowBQYDK2VwMCAxHjAc
BgNVBAMMFWFnZW50LXdhbGxldC10ZXN0LWNhMB4XDTI1MDUyMjAwMDAwMFoXDTM1
MDUyMjAwMDAwMFowIDEeMBwGA1UEAwwVYWdlbnQtd2FsbGV0LXRlc3QtY2EwKjAF
BgMrZXADIQDh4/g+wQt9G7n4nJaT1sQOmW9p9YQ5p+e1u1JxgQ7gAaNjMGEwHQYD
VR0OBBYEFMz0G5T6lU3o8jKuXyf3oRtNYBC1MB8GA1UdIwQYMBaAFMz0G5T6lU3o
8jKuXyf3oRtNYBC1MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAUG
AytlcANBAKsf2k8YJj+Re/h6m3FYsoTRtm1g+ZG9ZN9R5+5Pq3HZdMQEAh3Qms5N
n6OK4lL6m6sUuG9X9aOiAv1HJqcAUgI=
-----END CERTIFICATE-----
"""


def _try_load_test_pem() -> str:
    """Return a PEM that ``ssl`` will accept on this platform.

    The handcrafted PEM above is fine on most builds, but ed25519
    signatures depend on a CA flag that some bundled OpenSSL builds
    reject. If the bundled cert won't load, generate a fresh one with
    ``cryptography`` so the test suite is portable.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cadata=_TEST_CA_PEM)
        return _TEST_CA_PEM
    except ssl.SSLError:
        pass

    # Fallback: generate at runtime with the cryptography library, which is
    # already a hard dep of the project.
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-wallet-test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM).decode("ascii")


@pytest.fixture(scope="module")
def test_pem() -> str:
    return _try_load_test_pem()


def _has_test_ca(ctx: ssl.SSLContext) -> bool:
    """True iff the test CA is present in the context's trust store.

    ``ssl.create_default_context()`` already loads the system CA bundle, so
    the helper just adds one extra cert on top — we look for its subject CN.
    """
    for cert in ctx.get_ca_certs():
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName" and value == "agent-wallet-test-ca":
                    return True
    return False


class TestLoadPinnedCaContext:
    def test_empty_returns_none(self):
        assert load_pinned_ca_context("") is None

    def test_raw_pem(self, test_pem):
        ctx = load_pinned_ca_context(test_pem)
        assert isinstance(ctx, ssl.SSLContext)
        assert _has_test_ca(ctx)

    def test_base64_pem(self, test_pem):
        b64 = base64.b64encode(test_pem.encode("ascii")).decode("ascii")
        ctx = load_pinned_ca_context(b64)
        assert isinstance(ctx, ssl.SSLContext)
        assert _has_test_ca(ctx)

    def test_file_path(self, tmp_path, test_pem):
        f = tmp_path / "ca.pem"
        f.write_text(test_pem, encoding="ascii")
        ctx = load_pinned_ca_context(str(f))
        assert isinstance(ctx, ssl.SSLContext)
        assert _has_test_ca(ctx)

    def test_garbage_returns_none(self):
        # Not a path, not base64, not PEM — must return None (caller falls
        # back to its configured verify=bool; we MUST NOT silently produce a
        # permissive context).
        assert load_pinned_ca_context("not-a-cert-and-not-a-path") is None

    def test_invalid_base64_pem_returns_none(self):
        # Decodes but isn't a certificate.
        b64 = base64.b64encode(b"hello world").decode("ascii")
        assert load_pinned_ca_context(b64) is None


class TestMempoolBuildVerify:
    """``MempoolHttpBackend._build_verify`` precedence chain."""

    @patch("app.services.chain.mempool_http.settings")
    def test_onion_skips_verification_regardless_of_pem(self, mock_settings, test_pem):
        from app.services.chain.mempool_http import MempoolHttpBackend

        mock_settings.lnd_mempool_url = "http://abcd.onion"
        mock_settings.mempool_tls_verify = True
        mock_settings.mempool_ca_cert = test_pem

        assert MempoolHttpBackend()._build_verify() is False

    @patch("app.services.chain.mempool_http.settings")
    def test_pinned_pem_wins_over_bool(self, mock_settings, test_pem):
        from app.services.chain.mempool_http import MempoolHttpBackend

        mock_settings.lnd_mempool_url = "https://mempool.example"
        # Even with verify=False the pin must take precedence: an explicit
        # pin is strictly stronger than "trust anything".
        mock_settings.mempool_tls_verify = False
        mock_settings.mempool_ca_cert = test_pem

        v = MempoolHttpBackend()._build_verify()
        assert isinstance(v, ssl.SSLContext)

    @patch("app.services.chain.mempool_http.settings")
    def test_no_pem_falls_back_to_verify_true(self, mock_settings):
        from app.services.chain.mempool_http import MempoolHttpBackend

        mock_settings.lnd_mempool_url = "https://mempool.space"
        mock_settings.mempool_tls_verify = True
        mock_settings.mempool_ca_cert = ""

        assert MempoolHttpBackend()._build_verify() is True

    @patch("app.services.chain.mempool_http.settings")
    def test_no_pem_falls_back_to_verify_false(self, mock_settings):
        from app.services.chain.mempool_http import MempoolHttpBackend

        mock_settings.lnd_mempool_url = "https://mempool.local"
        mock_settings.mempool_tls_verify = False
        mock_settings.mempool_ca_cert = ""

        assert MempoolHttpBackend()._build_verify() is False

    @patch("app.services.chain.mempool_http.settings")
    def test_unparseable_pem_does_not_weaken_to_false(self, mock_settings):
        """Garbage in MEMPOOL_CA_CERT must not silently disable verification."""
        from app.services.chain.mempool_http import MempoolHttpBackend

        mock_settings.lnd_mempool_url = "https://mempool.example"
        mock_settings.mempool_tls_verify = True
        mock_settings.mempool_ca_cert = "this-is-garbage"

        # Falls through to the configured bool, which is True here. The
        # critical property is that it does NOT become False.
        assert MempoolHttpBackend()._build_verify() is True
