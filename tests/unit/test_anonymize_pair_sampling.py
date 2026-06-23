# SPDX-License-Identifier: MIT
"""Per-session operator-pair sampling.

The quote builder picks one (LN-only) or two (on-chain self-source)
operators from the signed registry and binds the IDs into the
quote token + pipeline_json so the per-session loop hits the same
operator(s) at execute time.

The actual sampler is :func:`operators.sample_operator_pair`; these
tests cover the wire that runs at quote time + the binding into
the signed token payload.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from app.core.config import settings
from app.services.anonymize.quote_builder import QuoteRequest, build_quote
from app.services.anonymize.quote_token import (
    decode_quote_token,
    load_quote_token_keyset,
)

_REGTEST_P2TR = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"


@pytest.fixture
def _quote_keyset(monkeypatch):
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )


def _signed_registry(
    tmp_path: Path,
    *,
    operator_ids: list[str],
) -> tuple[str, str, str]:
    """Build a signed registry on disk; return paths + fingerprint."""
    sk = Ed25519PrivateKey.generate()
    pub_hex = (
        sk.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )
    entries = []
    for i, op_id in enumerate(operator_ids):
        # Each operator gets a distinct public_key_hex + onion so the
        # registry-parser de-duplication checks accept the list.
        suffix = format(i, "x").rjust(2, "0")
        entries.append(
            {
                "operator_id": op_id,
                "onion": (f"{suffix}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion"),
                "public_key_hex": "02" + (suffix * 32),
                "attested_min_24h_volume_satoshis": 60_000_000_000,
            }
        )
    reg = tmp_path / "operators.json"
    reg.write_text(json.dumps(entries))
    canonical = reg.read_text(encoding="utf-8").rstrip("\n ").encode("utf-8")
    sig = tmp_path / "operators.sig"
    sig.write_bytes(sk.sign(canonical))
    return str(reg), str(sig), pub_hex


def _build_request() -> QuoteRequest:
    return QuoteRequest(
        source_kind="ext-lightning",
        destination_address=_REGTEST_P2TR,
        requested_amount_sat=250_000,
        cookie_subject="abc",
        canonical_request_body=b"{}",
    )


def test_quote_binds_no_operator_ids_when_registry_empty(
    monkeypatch,
    tmp_path,
    _quote_keyset,
) -> None:
    """Single-operator deployment (no registry) leaves both IDs None."""
    monkeypatch.setattr(
        settings,
        "anonymize_boltz_operator_registry_path",
        str(tmp_path / "nonexistent.json"),
    )
    keyset = load_quote_token_keyset()
    out = build_quote(_build_request(), keyset=keyset)
    bound = decode_quote_token(out.quote_token, keyset=keyset)
    assert bound.get("submarine_operator_id") is None
    assert bound.get("reverse_operator_id") is None


def test_quote_binds_single_operator_id_when_only_one_registered(
    monkeypatch,
    tmp_path,
    _quote_keyset,
) -> None:
    """Single-operator registry — only the reverse leg ID is bound."""
    reg, sig, fp = _signed_registry(tmp_path, operator_ids=["op-solo"])
    monkeypatch.setattr(
        settings,
        "anonymize_boltz_operator_registry_path",
        reg,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_registry_sig_path",
        sig,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_registry_release_key_fingerprints",
        fp,
    )
    keyset = load_quote_token_keyset()
    out = build_quote(_build_request(), keyset=keyset)
    bound = decode_quote_token(out.quote_token, keyset=keyset)
    # Submarine leg has no operator (LN source).
    assert bound.get("submarine_operator_id") is None
    assert bound.get("reverse_operator_id") == "op-solo"


def test_sample_operator_pair_library_primitive_distributes_uniformly() -> None:
    """The in-quote
    sampling code path is replaced by chain-based selection, but
    :func:`sample_operator_pair` stays as a library primitive
    available to future v2 reverse-leg-fallback work. Its uniformity
    invariant must keep holding so that future selection logic
    that wants randomization can rely on it.

    This is the equivalent of the old
    ``test_pair_sampling_is_uniformly_distributed_over_pairs`` —
    rewritten to exercise the primitive directly instead of the
    build_quote pathway (which no longer samples).
    """
    from collections import Counter

    from app.services.anonymize.operators import (
        OperatorEntry,
        sample_operator_pair,
    )

    registry = [
        OperatorEntry(operator_id=f"op-{i}", onion=f"{i}.onion", public_key_hex=f"0{i}" * 32) for i in range(1, 4)
    ]
    pair_counts: Counter[tuple[str, str]] = Counter()
    for _ in range(120):
        pair = sample_operator_pair(registry)
        assert pair is not None
        sub, rev = pair
        pair_counts[(sub.operator_id, rev.operator_id)] += 1
    # 3 operators → 6 ordered distinct pairs. Each pair should
    # appear at least once over 120 draws (probability of any
    # specific pair never appearing is (5/6)^120 ≈ 10^-9).
    assert len(set(pair_counts.keys())) == 6


def test_quote_binds_reverse_only_for_ln_source_with_multi_registry(
    monkeypatch,
    tmp_path,
    _quote_keyset,
) -> None:
    """LN-only quotes pick a single reverse-leg operator from
    the registry; the submarine slot stays None (no submarine leg).
    Replaces the old ``test_quote_binds_distinct_pair_when_registry_has_multiple``
    test which assumed sampling-based dual-leg assignment for
    LN sources."""
    reg, sig, fp = _signed_registry(
        tmp_path,
        operator_ids=["op-a", "op-b", "op-c"],
    )
    monkeypatch.setattr(
        settings,
        "anonymize_boltz_operator_registry_path",
        reg,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_registry_sig_path",
        sig,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_registry_release_key_fingerprints",
        fp,
    )
    keyset = load_quote_token_keyset()
    out = build_quote(_build_request(), keyset=keyset)
    bound = decode_quote_token(out.quote_token, keyset=keyset)
    sub_id = bound.get("submarine_operator_id")
    rev_id = bound.get("reverse_operator_id")
    # LN-only — no submarine leg.
    assert sub_id is None
    # Reverse leg picks the first registry entry deterministically.
    assert rev_id == "op-a"
