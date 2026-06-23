# SPDX-License-Identifier: MIT
"""k-of-n threshold-signed operator registry.

External user-funded deployments opt into ``ANONYMIZE_REGISTRY_REQUIRE_THRESHOLD_SIG=true``
plus ``ANONYMIZE_REGISTRY_THRESHOLD_K`` and ship multiple ``.sig``
files — one per maintainer key — so a single compromised release-key
credential cannot replace the operator registry.

The threshold contract is strict: k *distinct* maintainer fingerprints
must each have at least one verifying signature.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.core.config import settings
from app.services.anonymize.operators import (
    OperatorEntry,
    RegistrySignatureError,
    count_distinct_verifying_fingerprints,
    load_operator_registry_dispatching,
    load_threshold_signed_operator_registry,
)


def _new_release_key() -> tuple[Ed25519PrivateKey, str]:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, pub.hex()


_VALID_ENTRY = {
    "operator_id": "boltz-exchange-2026",
    "onion": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion",
    "public_key_hex": "02" + "a" * 64,
    "attested_min_24h_volume_satoshis": 50_000_000_000,
}


def _write_registry(tmp_path: Path) -> tuple[Path, bytes]:
    reg = tmp_path / "operators.json"
    reg.write_text(json.dumps([_VALID_ENTRY]))
    canonical = reg.read_text(encoding="utf-8").rstrip("\n ").encode("utf-8")
    return reg, canonical


# ── count_distinct_verifying_fingerprints ───────────────────────────


def test_count_returns_zero_when_no_signatures(tmp_path: Path) -> None:
    _, canonical = _write_registry(tmp_path)
    _, fp = _new_release_key()
    assert (
        count_distinct_verifying_fingerprints(
            canonical_bytes=canonical,
            signature_paths=[],
            fingerprints=[fp],
        )
        == 0
    )


def test_count_skips_missing_files(tmp_path: Path) -> None:
    _, canonical = _write_registry(tmp_path)
    _, fp = _new_release_key()
    assert (
        count_distinct_verifying_fingerprints(
            canonical_bytes=canonical,
            signature_paths=[str(tmp_path / "nonexistent.sig")],
            fingerprints=[fp],
        )
        == 0
    )


def test_count_returns_one_for_single_verifying_sig(tmp_path: Path) -> None:
    _, canonical = _write_registry(tmp_path)
    sk, fp = _new_release_key()
    sig = tmp_path / "operators.sig"
    sig.write_bytes(sk.sign(canonical))
    assert (
        count_distinct_verifying_fingerprints(
            canonical_bytes=canonical,
            signature_paths=[str(sig)],
            fingerprints=[fp],
        )
        == 1
    )


def test_count_returns_three_for_three_distinct_maintainers(
    tmp_path: Path,
) -> None:
    """k-of-n proof: three maintainers each provide one signature."""
    _, canonical = _write_registry(tmp_path)
    sks = [_new_release_key() for _ in range(3)]
    sig_paths: list[str] = []
    for i, (sk, _) in enumerate(sks):
        p = tmp_path / f"operators.sig.{i}"
        p.write_bytes(sk.sign(canonical))
        sig_paths.append(str(p))
    fps = [fp for _, fp in sks]
    assert (
        count_distinct_verifying_fingerprints(
            canonical_bytes=canonical,
            signature_paths=sig_paths,
            fingerprints=fps,
        )
        == 3
    )


def test_count_dedups_two_signatures_by_same_maintainer(
    tmp_path: Path,
) -> None:
    """A single maintainer submitting two signatures only counts once.
    This is what makes the k-of-n threshold meaningful."""
    _, canonical = _write_registry(tmp_path)
    sk, fp = _new_release_key()
    sig1 = tmp_path / "operators.sig.1"
    sig2 = tmp_path / "operators.sig.2"
    sig1.write_bytes(sk.sign(canonical))
    sig2.write_bytes(sk.sign(canonical))
    assert (
        count_distinct_verifying_fingerprints(
            canonical_bytes=canonical,
            signature_paths=[str(sig1), str(sig2)],
            fingerprints=[fp],
        )
        == 1
    )


def test_count_ignores_signatures_under_unpinned_keys(
    tmp_path: Path,
) -> None:
    """A maintainer not in the pinned set contributes zero."""
    _, canonical = _write_registry(tmp_path)
    sk_known, fp_known = _new_release_key()
    sk_attacker, _ = _new_release_key()
    sig_known = tmp_path / "known.sig"
    sig_attacker = tmp_path / "attacker.sig"
    sig_known.write_bytes(sk_known.sign(canonical))
    sig_attacker.write_bytes(sk_attacker.sign(canonical))
    # Only the known fingerprint is pinned.
    assert (
        count_distinct_verifying_fingerprints(
            canonical_bytes=canonical,
            signature_paths=[str(sig_known), str(sig_attacker)],
            fingerprints=[fp_known],
        )
        == 1
    )


# ── load_threshold_signed_operator_registry ─────────────────────────


def test_threshold_loader_admits_at_threshold(tmp_path: Path) -> None:
    reg, canonical = _write_registry(tmp_path)
    # 3 maintainers, threshold 2
    sks = [_new_release_key() for _ in range(3)]
    paths: list[str] = []
    for i, (sk, _) in enumerate(sks):
        p = tmp_path / f"operators.sig.{i}"
        p.write_bytes(sk.sign(canonical))
        paths.append(str(p))
    fps = [fp for _, fp in sks]
    out = load_threshold_signed_operator_registry(
        registry_path=str(reg),
        signature_path=paths[0],
        extra_signature_paths=paths[1:2],  # k=2 sigs
        fingerprints=fps,
        threshold_k=2,
    )
    assert isinstance(out, list)
    assert len(out) == 1
    assert isinstance(out[0], OperatorEntry)


def test_threshold_loader_refuses_below_threshold(tmp_path: Path) -> None:
    """3 keys pinned, 2-of-3 threshold, only 1 signature → refuse."""
    reg, canonical = _write_registry(tmp_path)
    sk, fp = _new_release_key()
    _, fp2 = _new_release_key()
    _, fp3 = _new_release_key()
    sig = tmp_path / "operators.sig"
    sig.write_bytes(sk.sign(canonical))
    with pytest.raises(RegistrySignatureError) as exc:
        load_threshold_signed_operator_registry(
            registry_path=str(reg),
            signature_path=str(sig),
            extra_signature_paths=[],
            fingerprints=[fp, fp2, fp3],
            threshold_k=2,
        )
    assert "threshold" in str(exc.value).lower()


def test_threshold_loader_dedup_prevents_self_threshold(
    tmp_path: Path,
) -> None:
    """A single maintainer cannot satisfy k>=2 by submitting two
    signatures under the same key."""
    reg, canonical = _write_registry(tmp_path)
    sk, fp = _new_release_key()
    _, fp2 = _new_release_key()
    sig1 = tmp_path / "operators.sig"
    sig2 = tmp_path / "operators.sig.1"
    sig1.write_bytes(sk.sign(canonical))
    sig2.write_bytes(sk.sign(canonical))
    with pytest.raises(RegistrySignatureError):
        load_threshold_signed_operator_registry(
            registry_path=str(reg),
            signature_path=str(sig1),
            extra_signature_paths=[str(sig2)],
            fingerprints=[fp, fp2],
            threshold_k=2,
        )


def test_threshold_loader_refuses_when_k_exceeds_pinned_count(
    tmp_path: Path,
) -> None:
    """Configuration error: k=3 but only 2 fingerprints pinned. The
    threshold is unsatisfiable even with perfect signatures."""
    reg, _ = _write_registry(tmp_path)
    _, fp1 = _new_release_key()
    _, fp2 = _new_release_key()
    with pytest.raises(RegistrySignatureError) as exc:
        load_threshold_signed_operator_registry(
            registry_path=str(reg),
            signature_path=str(tmp_path / "missing.sig"),
            extra_signature_paths=[],
            fingerprints=[fp1, fp2],
            threshold_k=3,
        )
    assert "unsatisfiable" in str(exc.value).lower()


def test_threshold_loader_refuses_when_k_is_zero(tmp_path: Path) -> None:
    """k=0 is a misconfiguration; refuse rather than admit trivially."""
    reg, _ = _write_registry(tmp_path)
    _, fp = _new_release_key()
    with pytest.raises(RegistrySignatureError) as exc:
        load_threshold_signed_operator_registry(
            registry_path=str(reg),
            signature_path="",
            extra_signature_paths=[],
            fingerprints=[fp],
            threshold_k=0,
        )
    assert "k >= 1" in str(exc.value).lower() or ">= 1" in str(exc.value)


def test_threshold_loader_returns_empty_when_no_registry(
    tmp_path: Path,
) -> None:
    """Single-operator deployment without a registry → empty list, no signature
    required. (Threshold mode doesn't change this — the escape hatch is
    for fresh installs.)"""
    _, fp = _new_release_key()
    out = load_threshold_signed_operator_registry(
        registry_path=str(tmp_path / "nonexistent.json"),
        signature_path="",
        extra_signature_paths=[],
        fingerprints=[fp],
        threshold_k=1,
    )
    assert out == []


# ── load_operator_registry_dispatching ──────────────────────────────


def test_dispatching_uses_at_least_one_when_flag_off(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_registry_require_threshold_sig",
        False,
    )
    reg, canonical = _write_registry(tmp_path)
    sk, fp = _new_release_key()
    sig = tmp_path / "operators.sig"
    sig.write_bytes(sk.sign(canonical))
    out = load_operator_registry_dispatching(
        registry_path=str(reg),
        signature_path=str(sig),
        fingerprints=[fp],
    )
    assert len(out) == 1


def test_dispatching_uses_threshold_when_flag_on(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_registry_require_threshold_sig",
        True,
    )
    monkeypatch.setattr(settings, "anonymize_registry_threshold_k", 2)
    monkeypatch.setattr(
        settings,
        "anonymize_registry_threshold_sig_paths",
        "",
    )
    reg, canonical = _write_registry(tmp_path)
    sk, fp = _new_release_key()
    _, fp2 = _new_release_key()
    sig = tmp_path / "operators.sig"
    sig.write_bytes(sk.sign(canonical))
    with pytest.raises(RegistrySignatureError):
        # Only 1 signature, threshold 2 → refuse.
        load_operator_registry_dispatching(
            registry_path=str(reg),
            signature_path=str(sig),
            fingerprints=[fp, fp2],
        )


# ── load_signed_operator_registry itself honors the threshold flag ──
# The production call sites (boltz_egress, hop_dispatcher, quote_builder,
# startup, dashboard) all call load_signed_operator_registry — NOT the
# dispatching helper. Before the H3 fix the threshold flag was a silent
# no-op for them. These tests pin that the flag is now enforced at the
# single load entry point every site uses.


def test_load_signed_enforces_threshold_when_flag_on(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from app.services.anonymize.operators import load_signed_operator_registry

    monkeypatch.setattr(settings, "anonymize_registry_require_threshold_sig", True)
    monkeypatch.setattr(settings, "anonymize_registry_threshold_k", 2)
    monkeypatch.setattr(settings, "anonymize_registry_threshold_sig_paths", "")
    reg, canonical = _write_registry(tmp_path)
    sk, fp = _new_release_key()
    _, fp2 = _new_release_key()
    sig = tmp_path / "operators.sig"
    sig.write_bytes(sk.sign(canonical))
    # A single maintainer signature must NOT satisfy a k=2 threshold,
    # even though it would pass the single-sig loader.
    with pytest.raises(RegistrySignatureError):
        load_signed_operator_registry(
            registry_path=str(reg),
            signature_path=str(sig),
            fingerprints=[fp, fp2],
        )


def test_load_signed_admits_single_sig_when_flag_off(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from app.services.anonymize.operators import load_signed_operator_registry

    monkeypatch.setattr(settings, "anonymize_registry_require_threshold_sig", False)
    reg, canonical = _write_registry(tmp_path)
    sk, fp = _new_release_key()
    sig = tmp_path / "operators.sig"
    sig.write_bytes(sk.sign(canonical))
    out = load_signed_operator_registry(
        registry_path=str(reg),
        signature_path=str(sig),
        fingerprints=[fp],
    )
    assert len(out) == 1


def test_startup_gate_fails_closed_when_threshold_unsatisfied(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Boot must refuse when threshold mode is configured but only a
    single maintainer signature is present."""
    from app.services.anonymize.startup import (
        AnonymizeStartupError,
        assert_signed_operator_registry_loadable,
    )

    reg, canonical = _write_registry(tmp_path)
    sk, fp = _new_release_key()
    _, fp2 = _new_release_key()
    sig = tmp_path / "operators.sig"
    sig.write_bytes(sk.sign(canonical))

    monkeypatch.setattr(settings, "anonymize_registry_require_threshold_sig", True)
    monkeypatch.setattr(settings, "anonymize_registry_threshold_k", 2)
    monkeypatch.setattr(settings, "anonymize_registry_threshold_sig_paths", "")
    monkeypatch.setattr(settings, "anonymize_boltz_operator_registry_path", str(reg))
    monkeypatch.setattr(settings, "anonymize_registry_sig_path", str(sig))
    monkeypatch.setattr(
        settings,
        "anonymize_registry_release_key_fingerprints",
        f"{fp},{fp2}",
    )

    with pytest.raises(AnonymizeStartupError):
        assert_signed_operator_registry_loadable()
