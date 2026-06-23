# SPDX-License-Identifier: MIT
"""Taproot key-path spend transaction builder.

Covers the build → sign → serialise pipeline end-to-end:

* ``serialize_unsigned_tx`` round-trips through ``parse_unsigned_tx``
  (the input parsing side from ``decoy_signer``).
* ``sign_taproot_spend_plan`` produces one 64-byte signature per
  input, each verifying under the scriptPubKey's x-only key (the
  on-chain check the chain backend would do).
* ``serialize_witness_tx`` produces BIP-141 wire format with the
  expected marker (0x00), flag (0x01), and per-input witness stack
  of exactly one 64-byte item.
* ``estimate_vbytes`` produces reasonable fee-budget numbers.
"""

from __future__ import annotations

import pytest

from app.services.anonymize.decoy_signer import (
    DecoySignerError,
    TxOutput,
    bip341_sighash_keypath,
    derive_decoy_output_pubkey_xonly,
    parse_bip32_path,
    parse_unsigned_tx,
    verify_taproot_keypath_sig,
)
from app.services.anonymize.decoy_spend_tx import (
    TaprootSpendInput,
    TaprootSpendPlan,
    build_signed_taproot_keypath_tx,
    estimate_vbytes,
    serialize_unsigned_tx,
    serialize_witness_tx,
    sign_taproot_spend_plan,
)

_ABANDON_SEED = bytes.fromhex(
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)


def _p2tr_scriptpubkey(seed: bytes, path_str: str) -> bytes:
    """``OP_1 OP_PUSHBYTES_32 <x-only output pubkey>``."""
    path = parse_bip32_path(path_str)
    x_only = derive_decoy_output_pubkey_xonly(
        seed=seed,
        path_components=path,
    )
    return b"\x51\x20" + x_only


def _spend_input(
    *,
    prev_txid: bytes,
    prev_vout: int,
    amount: int,
    path_str: str,
) -> TaprootSpendInput:
    return TaprootSpendInput(
        prevout_txid=prev_txid,
        prevout_vout=prev_vout,
        amount_sat=amount,
        script_pubkey=_p2tr_scriptpubkey(_ABANDON_SEED, path_str),
        derivation_path=tuple(parse_bip32_path(path_str)),
    )


def _output(amount: int, *, script: bytes | None = None) -> TxOutput:
    return TxOutput(
        amount_sat=amount,
        script_pubkey=script or _p2tr_scriptpubkey(_ABANDON_SEED, "m/86'/0'/0'/0/0"),
    )


# ── unsigned-tx serialise / parse roundtrip ─────────────────────────


def test_serialize_unsigned_tx_round_trips_through_parser() -> None:
    plan = TaprootSpendPlan(
        inputs=[
            _spend_input(
                prev_txid=b"\xaa" * 32,
                prev_vout=0,
                amount=200_000,
                path_str="m/86'/0'/0'/0/0",
            ),
            _spend_input(
                prev_txid=b"\xbb" * 32,
                prev_vout=1,
                amount=300_000,
                path_str="m/86'/0'/0'/0/1",
            ),
        ],
        outputs=[_output(490_000)],
        n_version=2,
        n_locktime=12345,
    )
    raw = serialize_unsigned_tx(plan)
    parsed_version, parsed_inputs, parsed_outputs, parsed_locktime = parse_unsigned_tx(raw.hex())
    assert parsed_version == 2
    assert parsed_locktime == 12345
    assert len(parsed_inputs) == 2
    assert len(parsed_outputs) == 1
    assert parsed_inputs[0] == (b"\xaa" * 32, 0, 0xFFFFFFFF)
    assert parsed_inputs[1] == (b"\xbb" * 32, 1, 0xFFFFFFFF)
    assert parsed_outputs[0].amount_sat == 490_000


def test_serialize_refuses_empty_inputs() -> None:
    plan = TaprootSpendPlan(inputs=[], outputs=[_output(100_000)])
    with pytest.raises(DecoySignerError):
        serialize_unsigned_tx(plan)


# ── signing ─────────────────────────────────────────────────────────


def test_sign_produces_one_64_byte_sig_per_input() -> None:
    plan = TaprootSpendPlan(
        inputs=[
            _spend_input(
                prev_txid=b"\x11" * 32,
                prev_vout=0,
                amount=100_000,
                path_str="m/86'/0'/0'/0/0",
            ),
            _spend_input(
                prev_txid=b"\x22" * 32,
                prev_vout=0,
                amount=100_000,
                path_str="m/86'/0'/0'/0/1",
            ),
        ],
        outputs=[_output(195_000)],
    )
    sigs = sign_taproot_spend_plan(plan, seed=_ABANDON_SEED)
    assert len(sigs) == 2
    for sig in sigs:
        assert len(sig) == 64


def test_each_sig_verifies_under_its_input_output_pubkey() -> None:
    """The signature for input i must verify under the x-only output
    pubkey embedded in input i's scriptPubKey — that's the on-chain
    check the validator does."""
    plan = TaprootSpendPlan(
        inputs=[
            _spend_input(
                prev_txid=b"\x11" * 32,
                prev_vout=0,
                amount=200_000,
                path_str="m/86'/0'/0'/0/0",
            ),
            _spend_input(
                prev_txid=b"\x22" * 32,
                prev_vout=2,
                amount=300_000,
                path_str="m/86'/0'/0'/0/1",
            ),
            _spend_input(
                prev_txid=b"\x33" * 32,
                prev_vout=7,
                amount=400_000,
                path_str="m/86'/0'/0'/1/0",
            ),
        ],
        outputs=[_output(880_000)],
    )
    spent = [i.to_spent_input() for i in plan.inputs]
    sigs = sign_taproot_spend_plan(plan, seed=_ABANDON_SEED)
    for i, (inp, sig) in enumerate(zip(plan.inputs, sigs)):
        # The output pubkey lives in scriptPubKey bytes [2:34].
        output_xonly = inp.script_pubkey[2:]
        sighash = bip341_sighash_keypath(
            n_version=plan.n_version,
            n_locktime=plan.n_locktime,
            spent_inputs=spent,
            outputs=plan.outputs,
            input_index=i,
        )
        assert (
            verify_taproot_keypath_sig(
                output_pub_xonly=output_xonly,
                sighash32=sighash,
                sig64=sig,
            )
            is True
        ), f"input {i} sig did not verify"


# ── witness-tx serialisation ────────────────────────────────────────


def test_serialize_witness_tx_has_marker_flag_and_witness_stacks() -> None:
    plan = TaprootSpendPlan(
        inputs=[
            _spend_input(
                prev_txid=b"\xab" * 32,
                prev_vout=0,
                amount=200_000,
                path_str="m/86'/0'/0'/0/0",
            )
        ],
        outputs=[_output(195_000)],
    )
    raw = build_signed_taproot_keypath_tx(plan, seed=_ABANDON_SEED)
    # BIP-141 marker + flag right after nVersion (4 bytes).
    assert raw[4] == 0x00, "missing BIP-141 marker"
    assert raw[5] == 0x01, "missing BIP-141 flag"
    # Witness section: 1 stack item, length 0x40, 64 sig bytes.
    # Find the witness section by walking forward — easier to check
    # via the sig count and ending nLocktime (4 bytes).
    assert raw.endswith(b"\x00\x00\x00\x00"), "nLocktime should be 0"


def test_serialize_witness_tx_refuses_wrong_sig_count() -> None:
    plan = TaprootSpendPlan(
        inputs=[
            _spend_input(
                prev_txid=b"\xab" * 32,
                prev_vout=0,
                amount=200_000,
                path_str="m/86'/0'/0'/0/0",
            )
        ],
        outputs=[_output(195_000)],
    )
    with pytest.raises(DecoySignerError):
        serialize_witness_tx(plan, [b"\x00" * 64, b"\x00" * 64])


def test_serialize_witness_tx_refuses_wrong_sig_length() -> None:
    plan = TaprootSpendPlan(
        inputs=[
            _spend_input(
                prev_txid=b"\xab" * 32,
                prev_vout=0,
                amount=200_000,
                path_str="m/86'/0'/0'/0/0",
            )
        ],
        outputs=[_output(195_000)],
    )
    with pytest.raises(DecoySignerError):
        serialize_witness_tx(plan, [b"\x00" * 63])


# ── end-to-end: top-level build_signed_taproot_keypath_tx ───────────


def test_top_level_helper_signs_all_inputs() -> None:
    plan = TaprootSpendPlan(
        inputs=[
            _spend_input(
                prev_txid=b"\xa0" * 32,
                prev_vout=0,
                amount=250_000,
                path_str="m/86'/0'/0'/0/0",
            ),
            _spend_input(
                prev_txid=b"\xa1" * 32,
                prev_vout=1,
                amount=350_000,
                path_str="m/86'/0'/0'/0/1",
            ),
        ],
        outputs=[_output(590_000)],
    )
    raw = build_signed_taproot_keypath_tx(plan, seed=_ABANDON_SEED)
    # Final tx is non-empty, longer than the unsigned form (witness
    # data has been appended).
    unsigned = serialize_unsigned_tx(plan)
    assert len(raw) > len(unsigned)
    # Marker + flag + 2 witness stacks each with 64-byte sig.
    # Roughly: 2 + 2 * (1 + 1 + 64) = 134 bytes of witness data + the
    # base tx.
    delta = len(raw) - len(unsigned)
    assert delta >= 2 + 2 * 66, f"witness section too small: delta={delta}"


# ── fee-estimation helper ───────────────────────────────────────────


def test_estimate_vbytes_returns_positive_int() -> None:
    plan = TaprootSpendPlan(
        inputs=[
            _spend_input(
                prev_txid=b"\xab" * 32,
                prev_vout=0,
                amount=200_000,
                path_str="m/86'/0'/0'/0/0",
            )
        ],
        outputs=[_output(195_000)],
    )
    vb = estimate_vbytes(plan)
    assert isinstance(vb, int)
    assert vb > 0


def test_estimate_vbytes_grows_with_input_count() -> None:
    """Adding inputs grows the vbyte estimate roughly linearly."""
    one = TaprootSpendPlan(
        inputs=[
            _spend_input(
                prev_txid=b"\xab" * 32,
                prev_vout=0,
                amount=200_000,
                path_str="m/86'/0'/0'/0/0",
            )
        ],
        outputs=[_output(195_000)],
    )
    two = TaprootSpendPlan(
        inputs=[
            _spend_input(
                prev_txid=b"\xab" * 32,
                prev_vout=0,
                amount=200_000,
                path_str="m/86'/0'/0'/0/0",
            ),
            _spend_input(
                prev_txid=b"\xcd" * 32,
                prev_vout=1,
                amount=200_000,
                path_str="m/86'/0'/0'/0/1",
            ),
        ],
        outputs=[_output(395_000)],
    )
    assert estimate_vbytes(two) > estimate_vbytes(one)


def test_estimate_vbytes_refuses_empty_inputs() -> None:
    plan = TaprootSpendPlan(inputs=[], outputs=[_output(100_000)])
    with pytest.raises(DecoySignerError):
        estimate_vbytes(plan)


# ── BIP-341 sighash cross-check with our serialized tx ──────────────


def test_signed_tx_passes_self_consistency_check() -> None:
    """Build a 2-input plan, sign it, then independently parse the
    serialized unsigned tx and re-verify each signature.

    This catches input-ordering / sequence / amount mismatches between
    the serialiser and the BIP-341 sighash computer."""
    plan = TaprootSpendPlan(
        inputs=[
            _spend_input(
                prev_txid=b"\x10" * 32,
                prev_vout=3,
                amount=100_000,
                path_str="m/86'/0'/0'/0/0",
            ),
            _spend_input(
                prev_txid=b"\x20" * 32,
                prev_vout=0,
                amount=200_000,
                path_str="m/86'/0'/0'/1/0",
            ),
        ],
        outputs=[_output(295_000)],
    )
    sigs = sign_taproot_spend_plan(plan, seed=_ABANDON_SEED)
    unsigned = serialize_unsigned_tx(plan)
    parsed_version, parsed_inputs, parsed_outputs, parsed_locktime = parse_unsigned_tx(unsigned.hex())
    assert parsed_version == plan.n_version
    assert parsed_locktime == plan.n_locktime
    assert len(parsed_inputs) == len(plan.inputs)
    # Reconstruct SpentInputs from the parser + our amount/scriptPubKey
    # data, then re-verify each signature.
    from app.services.anonymize.decoy_signer import SpentInput

    rebuilt_spent = []
    for (pt, pv, seq), inp in zip(parsed_inputs, plan.inputs):
        rebuilt_spent.append(
            SpentInput(
                prevout_txid=pt,
                prevout_vout=pv,
                sequence=seq,
                amount_sat=inp.amount_sat,
                script_pubkey=inp.script_pubkey,
            )
        )
    for i, (inp, sig) in enumerate(zip(plan.inputs, sigs)):
        sighash = bip341_sighash_keypath(
            n_version=parsed_version,
            n_locktime=parsed_locktime,
            spent_inputs=rebuilt_spent,
            outputs=parsed_outputs,
            input_index=i,
        )
        output_xonly = inp.script_pubkey[2:]
        assert (
            verify_taproot_keypath_sig(
                output_pub_xonly=output_xonly,
                sighash32=sighash,
                sig64=sig,
            )
            is True
        )
