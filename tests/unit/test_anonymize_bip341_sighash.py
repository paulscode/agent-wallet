# SPDX-License-Identifier: MIT
"""BIP-341 sighash + key-path sign verification.

The canonical anchor is BIP-341 wallet test vector ``keyPathSpending[0]``
input 4 (the SIGHASH_DEFAULT input). Source:
https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json

Vector data is hardcoded inline so the test is self-contained.
"""

from __future__ import annotations

import pytest

from app.services.anonymize.decoy_signer import (
    DecoySignerError,
    SpentInput,
    TxOutput,
    bip341_sighash_keypath,
    parse_unsigned_tx,
    sign_taproot_keypath_sighash,
    verify_taproot_keypath_sig,
)

# BIP-341 wallet-test-vectors.json → keyPathSpending[0]
_BIP341_RAW_UNSIGNED_TX = (
    "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c0"
    "10000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6d"
    "afdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d95"
    "7275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece7"
    "4310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d926"
    "4a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29"
    "718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a"
    "2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de676"
    "19e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a2"
    "63dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff02"
    "00ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840c"
    "b0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b"
    "0065cd1d"
)

# utxosSpent[0..8] from the BIP-341 vector.
_BIP341_UTXOS = [
    ("512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343", 420000000),
    ("5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3", 462000000),
    ("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", 294000000),
    ("5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e", 504000000),
    ("512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605", 630000000),
    ("00147dd65592d0ab2fe0d0257d571abf032cd9db93dc", 378000000),
    ("512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831", 672000000),
    ("5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5", 546000000),
    ("512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220", 588000000),
]

# Input 4 is the SIGHASH_DEFAULT key-path spend in the vector.
_BIP341_INPUT_INDEX = 4
_BIP341_EXPECTED_SIGHASH = bytes.fromhex("4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef")
_BIP341_TWEAKED_PRIVKEY = bytes.fromhex("a8e7aa924f0d58854185a490e6c41f6efb7b675c0f3331b7f14b549400b4d501")


def _build_spent_inputs() -> tuple[list[SpentInput], int, int]:
    """Parse the canonical raw tx and pair each input with its UTXO."""
    n_version, parsed_inputs, _, n_locktime = parse_unsigned_tx(
        _BIP341_RAW_UNSIGNED_TX,
    )
    assert len(parsed_inputs) == len(_BIP341_UTXOS)
    spent = []
    for (prev_txid, prev_vout, seq), (script_hex, amount) in zip(
        parsed_inputs,
        _BIP341_UTXOS,
    ):
        spent.append(
            SpentInput(
                prevout_txid=prev_txid,
                prevout_vout=prev_vout,
                sequence=seq,
                amount_sat=amount,
                script_pubkey=bytes.fromhex(script_hex),
            )
        )
    return spent, n_version, n_locktime


def test_parse_unsigned_tx_extracts_canonical_inputs() -> None:
    """The minimal tx parser pulls out 9 inputs + 2 outputs + version 2 +
    nLocktime 0x1dcd6500 from the canonical BIP-341 tx."""
    n_version, inputs, outputs, n_locktime = parse_unsigned_tx(
        _BIP341_RAW_UNSIGNED_TX,
    )
    assert n_version == 2
    assert len(inputs) == 9
    assert len(outputs) == 2
    assert n_locktime == 0x1DCD6500


def test_bip341_sighash_matches_canonical_vector() -> None:
    """Anchor test against published BIP-341 vector (key-path,
    SIGHASH_DEFAULT, input 4)."""
    spent, n_version, n_locktime = _build_spent_inputs()
    _, _, parsed_outputs, _ = parse_unsigned_tx(_BIP341_RAW_UNSIGNED_TX)
    sighash = bip341_sighash_keypath(
        n_version=n_version,
        n_locktime=n_locktime,
        spent_inputs=spent,
        outputs=parsed_outputs,
        input_index=_BIP341_INPUT_INDEX,
    )
    assert sighash == _BIP341_EXPECTED_SIGHASH, (
        f"sighash mismatch: got {sighash.hex()}, expected {_BIP341_EXPECTED_SIGHASH.hex()}"
    )


def test_signature_under_canonical_tweaked_privkey_verifies() -> None:
    """End-to-end: BIP-341 sighash + sign with the canonical tweaked
    private key + BIP-340 verify under the matching output pubkey."""

    spent, n_version, n_locktime = _build_spent_inputs()
    _, _, parsed_outputs, _ = parse_unsigned_tx(_BIP341_RAW_UNSIGNED_TX)
    sighash = bip341_sighash_keypath(
        n_version=n_version,
        n_locktime=n_locktime,
        spent_inputs=spent,
        outputs=parsed_outputs,
        input_index=_BIP341_INPUT_INDEX,
    )
    sig = sign_taproot_keypath_sighash(
        tweaked_priv32=_BIP341_TWEAKED_PRIVKEY,
        sighash32=sighash,
    )
    # The scriptPubKey of input 4 is OP_1 <32-byte-output-pubkey>.
    output_xonly = bytes.fromhex(_BIP341_UTXOS[_BIP341_INPUT_INDEX][0])[2:]
    assert (
        verify_taproot_keypath_sig(
            output_pub_xonly=output_xonly,
            sighash32=sighash,
            sig64=sig,
        )
        is True
    )


# ── Robustness ──────────────────────────────────────────────────────


def test_sighash_refuses_empty_inputs() -> None:
    with pytest.raises(DecoySignerError):
        bip341_sighash_keypath(
            n_version=2,
            n_locktime=0,
            spent_inputs=[],
            outputs=[],
            input_index=0,
        )


def test_sighash_refuses_input_index_out_of_range() -> None:
    spent = [
        SpentInput(
            prevout_txid=b"\x00" * 32,
            prevout_vout=0,
            sequence=0xFFFFFFFF,
            amount_sat=100_000,
            script_pubkey=b"\x51\x20" + b"\x00" * 32,
        )
    ]
    with pytest.raises(DecoySignerError):
        bip341_sighash_keypath(
            n_version=2,
            n_locktime=0,
            spent_inputs=spent,
            outputs=[],
            input_index=5,
        )


def test_sighash_changes_with_input_index() -> None:
    """The sighash must depend on input_index — that's what binds a
    signature to a specific input."""
    spent, n_version, n_locktime = _build_spent_inputs()
    _, _, parsed_outputs, _ = parse_unsigned_tx(_BIP341_RAW_UNSIGNED_TX)
    sh_0 = bip341_sighash_keypath(
        n_version=n_version,
        n_locktime=n_locktime,
        spent_inputs=spent,
        outputs=parsed_outputs,
        input_index=0,
    )
    sh_4 = bip341_sighash_keypath(
        n_version=n_version,
        n_locktime=n_locktime,
        spent_inputs=spent,
        outputs=parsed_outputs,
        input_index=4,
    )
    assert sh_0 != sh_4


def test_sighash_changes_with_outputs() -> None:
    """A different output set (different amount or scriptPubKey) must
    produce a different sighash — sha_outputs is part of the
    sighash message."""
    spent, n_version, n_locktime = _build_spent_inputs()
    _, _, parsed_outputs, _ = parse_unsigned_tx(_BIP341_RAW_UNSIGNED_TX)
    altered_outputs = [
        TxOutput(
            amount_sat=parsed_outputs[0].amount_sat + 1,
            script_pubkey=parsed_outputs[0].script_pubkey,
        ),
        parsed_outputs[1],
    ]
    sh_a = bip341_sighash_keypath(
        n_version=n_version,
        n_locktime=n_locktime,
        spent_inputs=spent,
        outputs=parsed_outputs,
        input_index=4,
    )
    sh_b = bip341_sighash_keypath(
        n_version=n_version,
        n_locktime=n_locktime,
        spent_inputs=spent,
        outputs=altered_outputs,
        input_index=4,
    )
    assert sh_a != sh_b


def test_sighash_changes_with_version() -> None:
    """nVersion is part of the sighash; changing it changes the sighash."""
    spent, _, n_locktime = _build_spent_inputs()
    _, _, parsed_outputs, _ = parse_unsigned_tx(_BIP341_RAW_UNSIGNED_TX)
    sh_v1 = bip341_sighash_keypath(
        n_version=1,
        n_locktime=n_locktime,
        spent_inputs=spent,
        outputs=parsed_outputs,
        input_index=4,
    )
    sh_v2 = bip341_sighash_keypath(
        n_version=2,
        n_locktime=n_locktime,
        spent_inputs=spent,
        outputs=parsed_outputs,
        input_index=4,
    )
    assert sh_v1 != sh_v2


def test_sighash_changes_with_locktime() -> None:
    spent, n_version, _ = _build_spent_inputs()
    _, _, parsed_outputs, _ = parse_unsigned_tx(_BIP341_RAW_UNSIGNED_TX)
    sh_0 = bip341_sighash_keypath(
        n_version=n_version,
        n_locktime=0,
        spent_inputs=spent,
        outputs=parsed_outputs,
        input_index=4,
    )
    sh_lt = bip341_sighash_keypath(
        n_version=n_version,
        n_locktime=12345,
        spent_inputs=spent,
        outputs=parsed_outputs,
        input_index=4,
    )
    assert sh_0 != sh_lt
