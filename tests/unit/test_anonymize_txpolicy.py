# SPDX-License-Identifier: MIT
"""/ items 37 + 43 — Bitcoin-Core-shaped envelope + feerate jitter.

Builds a minimal compliant tx by hand to exercise the parser, then
flips one field at a time to verify each violation path.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.txpolicy import (
    ANONYMIZE_TX_NSEQUENCE,
    ANONYMIZE_TX_NVERSION,
    TxEnvelopePolicyError,
    assert_bip69_ordering_inputs,
    assert_envelope_policy,
    compute_txid_from_hex,
    feerate_jitter,
)


def _build_minimal_tx(
    *,
    n_version: int = 2,
    n_sequence: int = 0xFFFFFFFD,
    n_locktime: int = 0,
    n_inputs: int = 1,
    has_witness: bool = False,
) -> str:
    """Build a stripped-down legacy tx for envelope-policy testing.

    Single empty-script input and a single 0-value output with a
    1-byte scriptPubKey. Witness data is not exercised here — the
    parser skips it when the marker is present, but the envelope
    check operates only on nVersion + nSequence + nLockTime so a
    legacy serialization is sufficient.
    """
    tx = b""
    tx += n_version.to_bytes(4, "little")
    if has_witness:
        tx += b"\x00\x01"  # witness marker + flag
    tx += n_inputs.to_bytes(1, "little")  # varint < 0xFD
    for _ in range(n_inputs):
        tx += b"\x00" * 32  # prevout txid
        tx += (0).to_bytes(4, "little")  # prevout vout
        tx += b"\x00"  # script_sig length 0
        tx += n_sequence.to_bytes(4, "little")
    tx += b"\x01"  # 1 output
    tx += (0).to_bytes(8, "little")  # value
    tx += b"\x01\x00"  # script length 1, OP_0
    if has_witness:
        for _ in range(n_inputs):
            tx += b"\x00"  # empty witness stack per input
    tx += n_locktime.to_bytes(4, "little")
    return tx.hex()


def test_envelope_passes_for_compliant_tx() -> None:
    tx = _build_minimal_tx()
    # No raise.
    assert_envelope_policy(tx, expected_n_locktime=0)


def test_envelope_rejects_wrong_n_version() -> None:
    tx = _build_minimal_tx(n_version=1)
    with pytest.raises(TxEnvelopePolicyError, match="nVersion=1"):
        assert_envelope_policy(tx)


def test_envelope_rejects_wrong_n_sequence() -> None:
    tx = _build_minimal_tx(n_sequence=0xFFFFFFFE)
    with pytest.raises(TxEnvelopePolicyError, match="nSequence"):
        assert_envelope_policy(tx)


def test_envelope_rejects_wrong_n_locktime() -> None:
    tx = _build_minimal_tx(n_locktime=12345)
    with pytest.raises(TxEnvelopePolicyError, match="nLockTime=12345"):
        assert_envelope_policy(tx, expected_n_locktime=12346)


def test_envelope_locktime_check_optional() -> None:
    """No locktime expected ⇒ any value is fine."""
    tx = _build_minimal_tx(n_locktime=12345)
    assert_envelope_policy(tx)  # no raise


def test_envelope_handles_witness_marker() -> None:
    """Tx with the SegWit marker still passes the envelope check."""
    tx = _build_minimal_tx(has_witness=True)
    assert_envelope_policy(tx)


def test_envelope_rejects_bad_hex() -> None:
    with pytest.raises(TxEnvelopePolicyError, match="not valid hex"):
        assert_envelope_policy("not-a-hex-string")


def test_envelope_rejects_truncated_tx() -> None:
    with pytest.raises(TxEnvelopePolicyError, match="too short"):
        assert_envelope_policy("0a")


def test_constants_match_plan() -> None:
    """NVersion=2, nSequence=0xFFFFFFFD."""
    assert ANONYMIZE_TX_NVERSION == 2
    assert ANONYMIZE_TX_NSEQUENCE == 0xFFFFFFFD


# ── BIP-69 ordering ───────────────────────────────────────────────


def test_bip69_empty_passes() -> None:
    assert_bip69_ordering_inputs([])


def test_bip69_single_input_passes() -> None:
    assert_bip69_ordering_inputs([(b"\x01" * 32, 0)])


def test_bip69_sorted_inputs_pass() -> None:
    inputs = [
        (b"\x01" * 32, 0),
        (b"\x02" * 32, 0),
        (b"\x02" * 32, 1),  # tiebreak by vout
    ]
    assert_bip69_ordering_inputs(inputs)


def test_bip69_unsorted_inputs_fail() -> None:
    inputs = [
        (b"\x02" * 32, 0),
        (b"\x01" * 32, 0),
    ]
    with pytest.raises(TxEnvelopePolicyError, match="BIP-69"):
        assert_bip69_ordering_inputs(inputs)


# ── compute_txid_from_hex ─────────────────────────────────────────


def test_compute_txid_returns_64_char_lowercase_hex() -> None:
    tx = _build_minimal_tx()
    txid = compute_txid_from_hex(tx)
    assert len(txid) == 64
    assert all(c in "0123456789abcdef" for c in txid)


def test_compute_txid_is_stable_across_calls() -> None:
    tx = _build_minimal_tx()
    assert compute_txid_from_hex(tx) == compute_txid_from_hex(tx)


def test_compute_txid_changes_with_payload() -> None:
    a = _build_minimal_tx()
    b = _build_minimal_tx(n_locktime=99)
    assert compute_txid_from_hex(a) != compute_txid_from_hex(b)


def test_compute_txid_ignores_witness_section() -> None:
    """BIP-141 txid is computed over the *non-witness* serialization,
    so adding witnesses must not change the txid."""
    a = _build_minimal_tx(has_witness=False)
    b = _build_minimal_tx(has_witness=True)
    assert compute_txid_from_hex(a) == compute_txid_from_hex(b)


def test_compute_txid_rejects_bad_hex() -> None:
    with pytest.raises(TxEnvelopePolicyError):
        compute_txid_from_hex("not-hex")


# ── item 43 feerate jitter ─────────────────────────────────────


def test_feerate_jitter_within_configured_band(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_feerate_jitter_lo", 0.85)
    monkeypatch.setattr(settings, "anonymize_feerate_jitter_hi", 1.15)
    economy = 10.0
    for _ in range(200):
        out = feerate_jitter(economy, minrelay_sat_per_vb=1.0)
        assert 8.5 <= out <= 11.5


def test_feerate_jitter_clamps_to_minrelay(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_feerate_jitter_lo", 0.10)
    monkeypatch.setattr(settings, "anonymize_feerate_jitter_hi", 0.20)
    out = feerate_jitter(2.0, minrelay_sat_per_vb=5.0)
    assert out >= 5.0  # clamped


def test_feerate_jitter_uses_systemrandom() -> None:
    """Successive calls produce variation (not deterministic)."""
    seen: set[float] = set()
    for _ in range(20):
        seen.add(feerate_jitter(10.0, minrelay_sat_per_vb=0.5))
    assert len(seen) > 1
