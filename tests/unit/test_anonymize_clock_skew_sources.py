# SPDX-License-Identifier: MIT
"""Signed clock-skew probe-source registry loader.

Mirrors the operator-registry signed-load tests; the clock-skew
sources registry has the same threat-model contract but a simpler
schema (no public_key_hex / attested_min_24h_volume_satoshis).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.services.anonymize.clock_skew_sources import (
    ClockSkewSource,
    ClockSkewSourcesLoadError,
    ClockSkewSourcesSignatureError,
    load_clock_skew_sources,
    load_signed_clock_skew_sources,
)


def _new_release_key() -> tuple[Ed25519PrivateKey, str]:
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
    "source_id": "duckduckgo-onion",
    "url": "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/",
    "label": "DuckDuckGo onion",
    "last_audit_date": "2026-05-15",
}


# ── load_clock_skew_sources (unsigned parse) ────────────────────────


def test_load_returns_empty_when_file_missing(tmp_path: Path) -> None:
    assert load_clock_skew_sources(tmp_path / "missing.json") == []


def test_load_returns_empty_when_file_blank(tmp_path: Path) -> None:
    p = tmp_path / "clock_skew_sources.json"
    p.write_text("")
    assert load_clock_skew_sources(p) == []


def test_load_parses_well_formed_entry(tmp_path: Path) -> None:
    p = tmp_path / "clock_skew_sources.json"
    p.write_text(json.dumps([_VALID_ENTRY]))
    out = load_clock_skew_sources(p)
    assert len(out) == 1
    assert isinstance(out[0], ClockSkewSource)
    assert out[0].source_id == "duckduckgo-onion"
    assert out[0].url.startswith("https://")
    assert out[0].label == "DuckDuckGo onion"


def test_load_rejects_top_level_object(tmp_path: Path) -> None:
    p = tmp_path / "clock_skew_sources.json"
    p.write_text(json.dumps({"not": "an array"}))
    with pytest.raises(ClockSkewSourcesLoadError, match="JSON array"):
        load_clock_skew_sources(p)


def test_load_rejects_missing_url(tmp_path: Path) -> None:
    p = tmp_path / "clock_skew_sources.json"
    bad = {"source_id": "x", "label": "no-url"}
    p.write_text(json.dumps([bad]))
    with pytest.raises(ClockSkewSourcesLoadError):
        load_clock_skew_sources(p)


def test_load_rejects_non_absolute_url(tmp_path: Path) -> None:
    p = tmp_path / "clock_skew_sources.json"
    bad = {"source_id": "x", "url": "/relative/path"}
    p.write_text(json.dumps([bad]))
    with pytest.raises(ClockSkewSourcesLoadError, match="absolute URL"):
        load_clock_skew_sources(p)


def test_load_rejects_duplicate_source_id(tmp_path: Path) -> None:
    p = tmp_path / "clock_skew_sources.json"
    dup = [
        {"source_id": "x", "url": "https://a.onion/"},
        {"source_id": "x", "url": "https://b.onion/"},
    ]
    p.write_text(json.dumps(dup))
    with pytest.raises(ClockSkewSourcesLoadError, match="duplicate source_id"):
        load_clock_skew_sources(p)


def test_load_rejects_duplicate_url(tmp_path: Path) -> None:
    p = tmp_path / "clock_skew_sources.json"
    dup = [
        {"source_id": "a", "url": "https://x.onion/"},
        {"source_id": "b", "url": "https://x.onion/"},
    ]
    p.write_text(json.dumps(dup))
    with pytest.raises(ClockSkewSourcesLoadError, match="duplicate url"):
        load_clock_skew_sources(p)


# ── load_signed_clock_skew_sources ──────────────────────────────────


def test_load_signed_returns_empty_when_no_registry(
    tmp_path: Path,
) -> None:
    """A missing/empty registry is admitted without a signature so
    deployments that haven't curated a list don't break."""
    out = load_signed_clock_skew_sources(
        sources_path=str(tmp_path / "clock_skew_sources.json"),
        signature_path=str(tmp_path / "clock_skew_sources.sig"),
        fingerprints=[],
    )
    assert out == []


def test_load_signed_refuses_when_signature_missing(tmp_path: Path) -> None:
    reg = tmp_path / "clock_skew_sources.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    _, fp = _new_release_key()
    with pytest.raises(ClockSkewSourcesSignatureError, match="missing"):
        load_signed_clock_skew_sources(
            sources_path=str(reg),
            signature_path=str(tmp_path / "clock_skew_sources.sig"),
            fingerprints=[fp],
        )


def test_load_signed_refuses_when_no_fingerprints_pinned(
    tmp_path: Path,
) -> None:
    reg = tmp_path / "clock_skew_sources.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    sig = tmp_path / "clock_skew_sources.sig"
    sig.write_bytes(b"some signature")
    with pytest.raises(ClockSkewSourcesSignatureError, match="release key"):
        load_signed_clock_skew_sources(
            sources_path=str(reg),
            signature_path=str(sig),
            fingerprints=[],
        )


def test_load_signed_refuses_when_signature_does_not_verify(
    tmp_path: Path,
) -> None:
    reg = tmp_path / "clock_skew_sources.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    sig = tmp_path / "clock_skew_sources.sig"
    sig.write_bytes(b"forged signature")
    _, fp = _new_release_key()
    with pytest.raises(ClockSkewSourcesSignatureError, match="does not verify"):
        load_signed_clock_skew_sources(
            sources_path=str(reg),
            signature_path=str(sig),
            fingerprints=[fp],
        )


def test_load_signed_returns_entries_when_signature_verifies(
    tmp_path: Path,
) -> None:
    reg = tmp_path / "clock_skew_sources.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    canonical = reg.read_text(encoding="utf-8").rstrip("\n ").encode("utf-8")
    sk, fp = _new_release_key()
    sig_bytes = _sign(sk, canonical)
    sig = tmp_path / "clock_skew_sources.sig"
    sig.write_bytes(sig_bytes)
    out = load_signed_clock_skew_sources(
        sources_path=str(reg),
        signature_path=str(sig),
        fingerprints=[fp],
    )
    assert len(out) == 1
    assert out[0].source_id == "duckduckgo-onion"


def test_load_signed_admits_either_rotation_overlap_fingerprint(
    tmp_path: Path,
) -> None:
    """Same rotation-overlap contract as operators.json: during a key
    rotation, both old and new fingerprints are pinned; either one's
    signature must admit the registry."""
    reg = tmp_path / "clock_skew_sources.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    canonical = reg.read_text(encoding="utf-8").rstrip("\n ").encode("utf-8")
    _, fp_old = _new_release_key()
    sk_new, fp_new = _new_release_key()
    sig_bytes = _sign(sk_new, canonical)
    sig = tmp_path / "clock_skew_sources.sig"
    sig.write_bytes(sig_bytes)
    out = load_signed_clock_skew_sources(
        sources_path=str(reg),
        signature_path=str(sig),
        fingerprints=[fp_old, fp_new],
    )
    assert len(out) == 1


def test_load_signed_prefers_armored_sig_asc_over_raw_sig(
    tmp_path: Path,
) -> None:
    """When both a raw ``.sig`` and an armored ``.sig.asc`` are present,
    the loader picks ``.sig.asc`` (matches operators-side behavior)."""
    reg = tmp_path / "clock_skew_sources.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    canonical = reg.read_text(encoding="utf-8").rstrip("\n ").encode("utf-8")
    # Raw signature with the wrong key — would fail if picked up.
    sk_bad, _ = _new_release_key()
    (tmp_path / "clock_skew_sources.sig").write_bytes(_sign(sk_bad, canonical))
    # ".sig.asc" with the right key — must be picked instead. We
    # simulate the armored format selection rather than actually
    # invoking GPG by writing raw bytes; the loader's selection logic
    # is what's under test here, not the verifier itself (covered by
    # the operators-side GPG tests).
    sk_good, fp_good = _new_release_key()
    sig_asc = tmp_path / "clock_skew_sources.sig.asc"
    sig_asc.write_bytes(_sign(sk_good, canonical))
    out = load_signed_clock_skew_sources(
        sources_path=str(reg),
        signature_path=str(tmp_path / "clock_skew_sources.sig"),
        fingerprints=[fp_good],
    )
    assert len(out) == 1
