# SPDX-License-Identifier: MIT
"""Bitcoin-Core-shaped tx envelope policy + feerate jitter.

Cooperative-claim tx and submarine funding tx use ``nVersion=2``,
``nLockTime=current_tip``, per-input ``nSequence=0xfffffffd``, BIP-69
input/output ordering. The cooperative-Musig2 claim path produces a
key-path P2TR spend (1-input-1-output, single 64-byte schnorr witness)
that is bytewise indistinguishable from a normal P2TR spend. Any
divergence from this envelope is a fingerprint-grade chain marker.

Feerate jitter for submarine funding and channel-open txs.
``feerate_jitter()`` multiplies ``mempool_economy_satvb`` by
``Uniform(ANONYMIZE_FEERATE_JITTER_LO, HI)``, clamped to the network
minrelayfee, sampled per tx.

The actual claim-tx / funding-tx assembly happens in
``boltz_service`` and ``boltz_claim.js``. This module exposes the
policy constants + helpers; the assembly call sites assert against
them.
"""

from __future__ import annotations

import secrets

from app.core.config import settings

# envelope constants.
ANONYMIZE_TX_NVERSION: int = 2
# RBF-enabled, anti-fee-sniping (matches Bitcoin Core's policy).
ANONYMIZE_TX_NSEQUENCE: int = 0xFFFFFFFD


def feerate_jitter(economy_sat_per_vb: float, *, minrelay_sat_per_vb: float = 1.0) -> float:
    """Jitter the economy feerate per tx, clamped to [minrelay, sane max].

    The upper clamp bounds the absolute fee a single tx can pay so an
    anomalous economy estimate or a misconfigured jitter range cannot
    drive a fee-burning broadcast.
    """
    from app.services.chain.backend import MAX_SANE_FEERATE_SAT_PER_VB

    rng = secrets.SystemRandom()
    factor = rng.uniform(
        settings.anonymize_feerate_jitter_lo,
        settings.anonymize_feerate_jitter_hi,
    )
    jittered = max(minrelay_sat_per_vb, economy_sat_per_vb * factor)
    return min(jittered, float(MAX_SANE_FEERATE_SAT_PER_VB))


# --------------------------------------------------------------------
# Bitcoin-Core-shaped envelope assertion.
# --------------------------------------------------------------------


class TxEnvelopePolicyError(ValueError):
    """Raised when a constructed tx violates envelope policy."""


def _read_u32_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Return (value, bytes_consumed)."""
    first = data[offset]
    if first < 0xFD:
        return first, 1
    if first == 0xFD:
        return int.from_bytes(data[offset + 1 : offset + 3], "little"), 3
    if first == 0xFE:
        return int.from_bytes(data[offset + 1 : offset + 5], "little"), 5
    return int.from_bytes(data[offset + 1 : offset + 9], "little"), 9


def compute_txid_from_hex(tx_hex: str) -> str:
    """Return the BIP-141-aware txid for a serialized tx in hex.

    The txid is the double-SHA256 of the *non-witness* serialization
    (BIP-141 ``txid != wtxid``): we re-serialize without the marker
    byte + witness flag + per-input witness stacks before hashing.

    Used by the chain-poll path to identify the on-chain
    claim tx without re-decoding the cached ``claim_tx_hex`` per
    tick. Returns the canonical txid in **little-endian hex** —
    the form REST APIs (mempool.space / electrs) expect.
    """
    import hashlib

    if not isinstance(tx_hex, str):
        raise TxEnvelopePolicyError("tx_hex must be a string")
    try:
        raw = bytes.fromhex(tx_hex)
    except ValueError as exc:
        raise TxEnvelopePolicyError(f"tx_hex is not valid hex: {exc}") from None
    if len(raw) < 10:
        raise TxEnvelopePolicyError("tx_hex too short to be a valid Bitcoin tx")

    # nVersion (4 bytes).
    pre = raw[:4]
    offset = 4
    has_witness = raw[offset] == 0x00 and raw[offset + 1] == 0x01
    if has_witness:
        offset += 2

    inputs_start = offset
    n_inputs, n_inputs_size = _read_varint(raw, offset)
    offset += n_inputs_size
    # Walk past inputs (we only need the bounds so the slice excludes
    # witnesses).
    for _ in range(n_inputs):
        offset += 36  # prevout txid + vout
        sig_len, sig_size = _read_varint(raw, offset)
        offset += sig_size + sig_len
        offset += 4  # nSequence
    inputs_section = raw[inputs_start:offset]

    n_outputs, n_out_size = _read_varint(raw, offset)
    outputs_start = offset
    offset += n_out_size
    for _ in range(n_outputs):
        offset += 8
        spk_len, spk_size = _read_varint(raw, offset)
        offset += spk_size + spk_len
    outputs_section = raw[outputs_start:offset]

    # Skip witnesses if present.
    if has_witness:
        for _ in range(n_inputs):
            stack_len, stack_len_size = _read_varint(raw, offset)
            offset += stack_len_size
            for _ in range(stack_len):
                item_len, item_size = _read_varint(raw, offset)
                offset += item_size + item_len

    if len(raw) < offset + 4:
        raise TxEnvelopePolicyError("truncated tx — nLockTime missing")
    locktime = raw[offset : offset + 4]

    # Re-serialize *without* witness data.
    stripped = pre + inputs_section + outputs_section + locktime
    digest = hashlib.sha256(hashlib.sha256(stripped).digest()).digest()
    return digest[::-1].hex()


def assert_envelope_policy(
    tx_hex: str,
    *,
    expected_n_locktime: int | None = None,
    expected_n_sequence: int = ANONYMIZE_TX_NSEQUENCE,
) -> None:
    """Assert a serialized tx matches Bitcoin Core's envelope.

    Checked properties:
    * ``nVersion == 2``
    * Per-input ``nSequence == 0xfffffffd`` (RBF-enabled, anti-fee-
      sniping; Core's policy)
    * ``nLockTime`` matches ``expected_n_locktime`` when provided
      (the orchestrator passes the current chain tip; tests pass an
      explicit value)
    * BIP-69 input ordering — the single-input claim case is
      trivially BIP-69-sorted; the full BIP-69 check is enforced by
      a separate helper because it needs the prevout values to break
      ties.

    The submarine-funding tx is built by LND and follows Core; this
    helper is what the cooperative-claim build path runs against the
    serialized output before persisting ``claim_tx_hex``.

    Raises :class:`TxEnvelopePolicyError` on any violation.
    """
    if not isinstance(tx_hex, str):
        raise TxEnvelopePolicyError("tx_hex must be a string")
    try:
        raw = bytes.fromhex(tx_hex)
    except ValueError as exc:
        raise TxEnvelopePolicyError(f"tx_hex is not valid hex: {exc}") from None
    if len(raw) < 10:
        raise TxEnvelopePolicyError("tx_hex too short to be a valid Bitcoin tx")

    n_version = _read_u32_le(raw, 0)
    if n_version != ANONYMIZE_TX_NVERSION:
        raise TxEnvelopePolicyError(f"nVersion={n_version} (expected {ANONYMIZE_TX_NVERSION})")

    # Inputs section. Tx may be witness-flagged (0x00 0x01 marker after
    # the version), in which case the input-count varint follows the
    # marker; otherwise it follows the version directly.
    offset = 4
    has_witness = False
    if raw[offset] == 0x00 and raw[offset + 1] == 0x01:
        has_witness = True
        offset += 2

    n_inputs, n_inputs_size = _read_varint(raw, offset)
    offset += n_inputs_size
    if n_inputs == 0:
        raise TxEnvelopePolicyError("tx has zero inputs")

    sequences: list[int] = []
    for _ in range(n_inputs):
        # 32-byte prevout txid + 4-byte prevout vout
        offset += 36
        # script_sig length + script_sig
        sig_len, sig_size = _read_varint(raw, offset)
        offset += sig_size + sig_len
        sequence = _read_u32_le(raw, offset)
        sequences.append(sequence)
        offset += 4

    # Outputs section.
    n_outputs, n_out_size = _read_varint(raw, offset)
    offset += n_out_size
    for _ in range(n_outputs):
        offset += 8  # output value
        spk_len, spk_size = _read_varint(raw, offset)
        offset += spk_size + spk_len

    # Witness data (skipped — we don't need to inspect witnesses for
    # the envelope check). It lives between outputs and nLockTime.
    if has_witness:
        for _ in range(n_inputs):
            stack_len, stack_len_size = _read_varint(raw, offset)
            offset += stack_len_size
            for _ in range(stack_len):
                item_len, item_size = _read_varint(raw, offset)
                offset += item_size + item_len

    # nLockTime is the last 4 bytes.
    if len(raw) < offset + 4:
        raise TxEnvelopePolicyError("truncated tx — nLockTime missing")
    n_locktime = _read_u32_le(raw, offset)

    # Per-input nSequence check.
    bad = [(i, s) for i, s in enumerate(sequences) if s != expected_n_sequence]
    if bad:
        raise TxEnvelopePolicyError(
            f"input(s) {[i for i, _ in bad]} have nSequence != "
            f"0x{expected_n_sequence:08x} (got {[hex(s) for _, s in bad]})"
        )

    if expected_n_locktime is not None and n_locktime != expected_n_locktime:
        raise TxEnvelopePolicyError(f"nLockTime={n_locktime} (expected {expected_n_locktime})")


def assert_bip69_ordering_inputs(
    prevout_tuples: list[tuple[bytes, int]],
) -> None:
    """Assert ``prevout_tuples`` are BIP-69-sorted.

    Each tuple is ``(prevout_txid_bytes_be, prevout_vout)``. BIP-69
    sorts by ``txid`` ascending (lexicographic over the 32-byte
    little-endian serialization, but BIP-69 specifies the *display*
    big-endian form), and breaks ties by ``vout`` ascending.

    The single-input case is trivially sorted; the helper is called
    by the multi-input submarine funding path that selects multiple
    UTXOs.
    """
    if not prevout_tuples:
        return
    sorted_tuples = sorted(prevout_tuples, key=lambda t: (t[0], t[1]))
    if sorted_tuples != prevout_tuples:
        raise TxEnvelopePolicyError("inputs are not BIP-69-sorted")


__all__ = [
    "ANONYMIZE_TX_NVERSION",
    "ANONYMIZE_TX_NSEQUENCE",
    "TxEnvelopePolicyError",
    "feerate_jitter",
    "compute_txid_from_hex",
    "assert_envelope_policy",
    "assert_bip69_ordering_inputs",
]
