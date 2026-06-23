# SPDX-License-Identifier: MIT
"""/ item 84 / — detached-signed registry loader.

The loader admits ``operators.json`` only when its detached ed25519
signature (``operators.sig``) verifies against at least one pinned
release-key fingerprint. The fingerprint is the hex-encoded 32-byte
ed25519 public key. — the loader walks the multi-fingerprint
allow-list so a rotation overlap (old key + new key both pinned) can
admit either signature.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.core.config import settings
from app.services.anonymize.operators import (
    OperatorEntry,
    RegistrySignatureError,
    load_signed_operator_registry,
    verify_detached_signature,
    verify_operator_api_response,
)


def _new_release_key() -> tuple[Ed25519PrivateKey, str]:
    """Generate a fresh ed25519 keypair + the hex fingerprint."""
    from cryptography.hazmat.primitives import serialization

    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, pub.hex()


def _sign(sk: Ed25519PrivateKey, canonical: bytes) -> bytes:
    return sk.sign(canonical)


_VALID_ENTRY = {
    "operator_id": "boltz-exchange-2026",
    "onion": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion",
    "public_key_hex": "02" + "a" * 64,
    "attested_min_24h_volume_satoshis": 50_000_000_000,
}


# ── verify_detached_signature primitives ────────────────────────────


def test_verify_signature_returns_true_for_matching_fingerprint() -> None:
    sk, fp = _new_release_key()
    canonical = b'[{"operator_id":"x"}]'
    sig = _sign(sk, canonical)
    assert (
        verify_detached_signature(
            canonical_bytes=canonical,
            signature_bytes=sig,
            fingerprint=fp,
        )
        is True
    )


def test_verify_signature_rejects_mismatched_fingerprint() -> None:
    sk_a, _ = _new_release_key()
    _, fp_b = _new_release_key()
    canonical = b'[{"operator_id":"x"}]'
    sig = _sign(sk_a, canonical)
    assert (
        verify_detached_signature(
            canonical_bytes=canonical,
            signature_bytes=sig,
            fingerprint=fp_b,
        )
        is False
    )


def test_verify_signature_rejects_tampered_payload() -> None:
    sk, fp = _new_release_key()
    canonical = b'[{"operator_id":"x"}]'
    sig = _sign(sk, canonical)
    # Verify against a *different* payload — the signature must not pass.
    assert (
        verify_detached_signature(
            canonical_bytes=b'[{"operator_id":"tampered"}]',
            signature_bytes=sig,
            fingerprint=fp,
        )
        is False
    )


def test_verify_signature_rejects_empty_signature() -> None:
    _, fp = _new_release_key()
    assert (
        verify_detached_signature(
            canonical_bytes=b"x",
            signature_bytes=b"",
            fingerprint=fp,
        )
        is False
    )


def test_verify_signature_rejects_empty_fingerprint() -> None:
    sk, _ = _new_release_key()
    sig = _sign(sk, b"x")
    assert (
        verify_detached_signature(
            canonical_bytes=b"x",
            signature_bytes=sig,
            fingerprint="",
        )
        is False
    )


def test_verify_signature_rejects_malformed_fingerprint() -> None:
    sk, _ = _new_release_key()
    sig = _sign(sk, b"x")
    # Wrong-length fingerprint (32 hex chars instead of 64).
    assert (
        verify_detached_signature(
            canonical_bytes=b"x",
            signature_bytes=sig,
            fingerprint="ab" * 16,
        )
        is False
    )
    # Non-hex characters.
    assert (
        verify_detached_signature(
            canonical_bytes=b"x",
            signature_bytes=sig,
            fingerprint="zz" * 32,
        )
        is False
    )


def test_verify_signature_tolerates_colon_separators_in_fingerprint() -> None:
    sk, fp = _new_release_key()
    # Insert colons every 2 hex chars (PGP / SSH style).
    spaced = ":".join(fp[i : i + 2] for i in range(0, len(fp), 2))
    sig = _sign(sk, b"x")
    assert (
        verify_detached_signature(
            canonical_bytes=b"x",
            signature_bytes=sig,
            fingerprint=spaced,
        )
        is True
    )


# ── load_signed_operator_registry ─────────────────────────────────


def test_load_signed_returns_empty_when_no_registry(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Lightning-only deployments without a registry pass without a signature."""
    monkeypatch.setattr(
        settings,
        "anonymize_registry_release_key_fingerprints",
        "",
    )
    monkeypatch.setattr(
        settings,
        "anonymize_registry_release_key_fingerprint",
        "",
    )
    out = load_signed_operator_registry(
        registry_path=str(tmp_path / "operators.json"),
        signature_path=str(tmp_path / "operators.sig"),
        fingerprints=[],
    )
    assert out == []


def test_load_signed_refuses_when_signature_missing(tmp_path: Path) -> None:
    reg = tmp_path / "operators.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    _, fp = _new_release_key()
    with pytest.raises(RegistrySignatureError, match="missing"):
        load_signed_operator_registry(
            registry_path=str(reg),
            signature_path=str(tmp_path / "operators.sig"),
            fingerprints=[fp],
        )


def test_load_signed_refuses_when_no_fingerprints_pinned(tmp_path: Path) -> None:
    reg = tmp_path / "operators.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    sig = tmp_path / "operators.sig"
    sig.write_bytes(b"some signature")
    with pytest.raises(RegistrySignatureError, match="release key"):
        load_signed_operator_registry(
            registry_path=str(reg),
            signature_path=str(sig),
            fingerprints=[],
        )


def test_load_signed_refuses_when_signature_does_not_verify(
    tmp_path: Path,
) -> None:
    reg = tmp_path / "operators.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    sig = tmp_path / "operators.sig"
    sig.write_bytes(b"forged signature")
    _, fp = _new_release_key()
    with pytest.raises(RegistrySignatureError, match="does not verify"):
        load_signed_operator_registry(
            registry_path=str(reg),
            signature_path=str(sig),
            fingerprints=[fp],
        )


def test_load_signed_returns_entries_when_signature_verifies(
    tmp_path: Path,
) -> None:
    reg = tmp_path / "operators.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    canonical = reg.read_text(encoding="utf-8").rstrip("\n ").encode("utf-8")
    sk, fp = _new_release_key()
    sig_bytes = _sign(sk, canonical)
    sig = tmp_path / "operators.sig"
    sig.write_bytes(sig_bytes)
    out = load_signed_operator_registry(
        registry_path=str(reg),
        signature_path=str(sig),
        fingerprints=[fp],
    )
    assert isinstance(out, list)
    assert len(out) == 1
    assert isinstance(out[0], OperatorEntry)
    assert out[0].operator_id == "boltz-exchange-2026"


def test_load_signed_admits_either_rotation_overlap_fingerprint(
    tmp_path: Path,
) -> None:
    """During a release-key rotation, both old and new
    fingerprints are pinned; either one's signature must admit the
    registry. This proves the loader walks the entire allow-list."""
    reg = tmp_path / "operators.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    canonical = reg.read_text(encoding="utf-8").rstrip("\n ").encode("utf-8")
    # Two release keys; sign with the SECOND, but pin both. The loader
    # must try the first (which fails) and then admit on the second.
    sk_old, fp_old = _new_release_key()
    sk_new, fp_new = _new_release_key()
    sig_bytes = _sign(sk_new, canonical)
    sig = tmp_path / "operators.sig"
    sig.write_bytes(sig_bytes)
    out = load_signed_operator_registry(
        registry_path=str(reg),
        signature_path=str(sig),
        fingerprints=[fp_old, fp_new],
    )
    assert len(out) == 1


def _operator(pubkey_hex: str) -> OperatorEntry:
    return OperatorEntry(
        operator_id="op-x",
        onion="x.onion",
        public_key_hex=pubkey_hex,
        attested_min_24h_volume_satoshis=0,
    )


# ── operator API-response signature verification ─────────


def test_verify_operator_api_response_accepts_valid_signature() -> None:
    sk, pub_hex = _new_release_key()
    body = b'{"id":"swap-xyz"}'
    sig = _sign(sk, body)
    assert (
        verify_operator_api_response(
            operator=_operator(pub_hex),
            response_body=body,
            signature_bytes=sig,
        )
        is True
    )


def test_verify_operator_api_response_rejects_wrong_key() -> None:
    sk_a, _ = _new_release_key()
    _, pub_b = _new_release_key()
    body = b'{"id":"swap-xyz"}'
    sig = _sign(sk_a, body)
    # Pinned operator key is B, signature was made with A.
    assert (
        verify_operator_api_response(
            operator=_operator(pub_b),
            response_body=body,
            signature_bytes=sig,
        )
        is False
    )


def test_verify_operator_api_response_rejects_tampered_body() -> None:
    sk, pub_hex = _new_release_key()
    sig = _sign(sk, b'{"id":"swap-xyz"}')
    assert (
        verify_operator_api_response(
            operator=_operator(pub_hex),
            response_body=b'{"id":"swap-evil"}',
            signature_bytes=sig,
        )
        is False
    )


def test_verify_operator_api_response_rejects_empty_signature() -> None:
    _, pub_hex = _new_release_key()
    assert (
        verify_operator_api_response(
            operator=_operator(pub_hex),
            response_body=b"x",
            signature_bytes=b"",
        )
        is False
    )


def test_verify_operator_api_response_rejects_empty_pubkey() -> None:
    sk, _ = _new_release_key()
    sig = _sign(sk, b"x")
    assert (
        verify_operator_api_response(
            operator=_operator(""),
            response_body=b"x",
            signature_bytes=sig,
        )
        is False
    )


def test_load_signed_refuses_when_signature_predates_rotation(
    tmp_path: Path,
) -> None:
    """An adversary cannot pin a rotated-out key + replay an old
    signature: the canonical bytes (which include the new registry
    content) cause the old signature to fail verification."""
    reg = tmp_path / "operators.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    sk_old, fp_old = _new_release_key()
    # Sign a DIFFERENT canonical payload — the registry's current
    # canonical bytes won't match.
    sig_bytes = _sign(sk_old, b"some-other-canonical-content")
    sig = tmp_path / "operators.sig"
    sig.write_bytes(sig_bytes)
    with pytest.raises(RegistrySignatureError, match="does not verify"):
        load_signed_operator_registry(
            registry_path=str(reg),
            signature_path=str(sig),
            fingerprints=[fp_old],
        )


# ── GPG / OpenPGP detached signature path ──────────────────


import os as _os
import shutil as _shutil
import subprocess as _subprocess


def _gpg_available() -> bool:
    return _shutil.which("gpg") is not None or _shutil.which("gpg2") is not None


@pytest.fixture
def gpg_keypair(tmp_path: Path):
    """Generate a throwaway RSA-2048 GPG keypair in an isolated home.

    Returns ``(gnupg_home, fingerprint, sign_function)`` where
    ``sign_function(data: bytes) -> bytes`` produces an armored
    OpenPGP detached signature over ``data`` using the throwaway key.
    """
    if not _gpg_available():
        pytest.skip("no `gpg` binary on PATH — GPG verification tests skipped")
    home = tmp_path / "gpg-home"
    home.mkdir(mode=0o700)
    env = {**_os.environ, "GNUPGHOME": str(home)}
    gen_conf = tmp_path / "genkey.conf"
    gen_conf.write_text(
        "%no-protection\n"
        "Key-Type: RSA\n"
        "Key-Length: 2048\n"
        "Key-Usage: sign\n"
        "Name-Real: Test Signer\n"
        "Name-Email: test@example.invalid\n"
        "Expire-Date: 0\n"
        "%commit\n"
    )
    _subprocess.run(
        ["gpg", "--batch", "--gen-key", str(gen_conf)],
        check=True,
        env=env,
        capture_output=True,
        timeout=30,
    )
    fp_out = _subprocess.run(
        ["gpg", "--fingerprint", "--with-colons"],
        env=env,
        capture_output=True,
        check=True,
        timeout=10,
    )
    fingerprint = ""
    for line in fp_out.stdout.decode().splitlines():
        if line.startswith("fpr:"):
            fingerprint = line.split(":")[9]
            break
    assert fingerprint, "could not extract test-key fingerprint"
    pubkey_out = _subprocess.run(
        ["gpg", "--armor", "--export", fingerprint],
        env=env,
        capture_output=True,
        check=True,
        timeout=10,
    )
    pubkey_path = home / "test-pubkey.asc"
    pubkey_path.write_bytes(pubkey_out.stdout)

    def _sign(data: bytes) -> bytes:
        data_path = home / "data.bin"
        sig_path = home / "data.sig.asc"
        data_path.write_bytes(data)
        _subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--armor",
                "--local-user",
                fingerprint,
                "--detach-sign",
                "--output",
                str(sig_path),
                str(data_path),
            ],
            check=True,
            env=env,
            timeout=10,
            capture_output=True,
        )
        return sig_path.read_bytes()

    return home, fingerprint, pubkey_path, _sign


@pytest.fixture
def swap_maintainer_pubkey(monkeypatch, gpg_keypair):
    """Temporarily swap the in-repo maintainer.asc for the test key's
    pubkey so the wallet's verifier admits signatures from the test
    key during these tests. Restored after the test runs."""
    from app.services.anonymize import operators as ops_mod

    _home, _fp, test_pubkey_path, _sign = gpg_keypair
    monkeypatch.setattr(
        ops_mod,
        "_MAINTAINER_PUBKEY_PATH",
        test_pubkey_path,
    )
    return gpg_keypair


def test_gpg_verify_accepts_real_signature(swap_maintainer_pubkey) -> None:
    """An armored OpenPGP detached signature over the
    canonical bytes, signed by the bundled maintainer key, verifies."""
    _home, fingerprint, _pub, sign = swap_maintainer_pubkey
    payload = b"canonical bytes for the signing test"
    sig = sign(payload)
    assert sig.startswith(b"-----BEGIN PGP SIGNATURE-----")
    assert (
        verify_detached_signature(
            canonical_bytes=payload,
            signature_bytes=sig,
            fingerprint=fingerprint,
        )
        is True
    )


def test_gpg_verify_rejects_wrong_fingerprint(swap_maintainer_pubkey) -> None:
    """A correct signature but a different pinned fingerprint MUST
    fail — even when the bundled maintainer key actually produced the
    signature, the allow-list must drive the verdict."""
    _home, fingerprint, _pub, sign = swap_maintainer_pubkey
    payload = b"canonical"
    sig = sign(payload)
    # Flip the last hex nibble.
    bad_fp = fingerprint[:-1] + ("0" if fingerprint[-1] != "0" else "1")
    assert (
        verify_detached_signature(
            canonical_bytes=payload,
            signature_bytes=sig,
            fingerprint=bad_fp,
        )
        is False
    )


def test_gpg_verify_rejects_tampered_payload(swap_maintainer_pubkey) -> None:
    """A signature valid for ``original`` does not verify against
    ``tampered``. The whole point of the signing ceremony."""
    _home, fingerprint, _pub, sign = swap_maintainer_pubkey
    sig = sign(b"original payload")
    assert (
        verify_detached_signature(
            canonical_bytes=b"tampered payload",
            signature_bytes=sig,
            fingerprint=fingerprint,
        )
        is False
    )


def test_gpg_verify_rejects_bogus_armored_signature(
    swap_maintainer_pubkey,
) -> None:
    """A malformed armored block (correct armor headers, garbage
    inside) MUST return False — not raise."""
    _home, fingerprint, _pub, _sign = swap_maintainer_pubkey
    bogus_sig = b"-----BEGIN PGP SIGNATURE-----\n\nNOT_BASE64_AT_ALL_$$$\n-----END PGP SIGNATURE-----\n"
    assert (
        verify_detached_signature(
            canonical_bytes=b"anything",
            signature_bytes=bogus_sig,
            fingerprint=fingerprint,
        )
        is False
    )


def test_load_signed_accepts_gpg_armored_sig_at_dot_asc(
    swap_maintainer_pubkey,
    tmp_path: Path,
) -> None:
    """End-to-end: ``operators.sig.asc`` (armored) + ``operators.json``
    + pinned GPG fingerprint loads cleanly via the signed loader.
    Future readers + maintainers exercising the production ceremony
    arrive at this code path."""
    _home, fingerprint, _pub, sign = swap_maintainer_pubkey
    reg = tmp_path / "operators.json"
    reg_payload = (
        "[\n"
        "  {\n"
        '    "operator_id": "test-op",\n'
        '    "onion": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion",\n'
        '    "public_key_hex": "",\n'
        '    "attested_min_24h_volume_satoshis": 0\n'
        "  }\n"
        "]\n"
    )
    reg.write_text(reg_payload, encoding="utf-8")
    # Canonical bytes = rstrip("\n ") + utf-8 encode.
    canonical = reg_payload.rstrip("\n ").encode("utf-8")
    sig_asc = sign(canonical)
    sig_asc_path = tmp_path / "operators.sig.asc"
    sig_asc_path.write_bytes(sig_asc)

    # Loader signature path points at the .sig (no .asc); the loader
    # auto-promotes .sig.asc when present.
    entries = load_signed_operator_registry(
        registry_path=str(reg),
        signature_path=str(tmp_path / "operators.sig"),
        fingerprints=[fingerprint],
    )
    assert len(entries) == 1
    assert entries[0].operator_id == "test-op"
