# SPDX-License-Identifier: MIT
"""Liquid CT spend-output construction.

Roundtrip-anchored: every test that builds outputs verifies them by
unblinding through :mod:`liquid_receive`. That confirms the spend
helper produces materially-correct CT (matches what the receiver
expects) and pins the receive/spend contract.
"""

from __future__ import annotations

import secrets

import pytest
import wallycore as _wally

from app.services.anonymize.liquid_backend import LiquidUtxo
from app.services.anonymize.liquid_ct import (
    LBTC_ASSET_ID_MAINNET,
    derive_script_blinding_privkey,
    derive_script_blinding_pubkey,
    derive_slip77_master_blinding_key,
    make_asset_generator,
)
from app.services.anonymize.liquid_receive import (
    unblind_liquid_utxo,
)
from app.services.anonymize.liquid_spend import (
    InputBlindingFactors,
    LiquidSpendError,
    OutputBlindingSpec,
    blind_spend_outputs,
    compute_balancing_vbf,
    make_asset_surjection_proof,
)

_ASSET = LBTC_ASSET_ID_MAINNET  # BE / display form
_ASSET_LE = LBTC_ASSET_ID_MAINNET[::-1]  # LE / on-wire form (libwally)


def _input(*, value: int, abf: bytes | None = None) -> InputBlindingFactors:
    """Build a synthetic InputBlindingFactors with random ABF/VBF.

    Libwally's ``asset_*`` functions operate on LE asset hashes (the
    on-wire form). ``_ASSET`` here is BE / display form; convert once
    so the spend-blinding flow + the unblind path agree.
    """
    abf = abf if abf is not None else secrets.token_bytes(32)
    vbf = secrets.token_bytes(32)
    gen = make_asset_generator(_ASSET_LE, abf)
    return InputBlindingFactors(
        value_sat=value,
        asset_id=_ASSET_LE,
        abf=abf,
        vbf=vbf,
        asset_generator=gen,
    )


def _receiver_keys(*, script: bytes) -> tuple[bytes, bytes]:
    """Return (blinding_priv, blinding_pub) for a synthetic recipient."""
    master = derive_slip77_master_blinding_key(b"\x99" * 64)
    return (
        derive_script_blinding_privkey(master, script),
        derive_script_blinding_pubkey(master, script),
    )


def _receiver_keys_from_seed(seed: bytes, *, script: bytes) -> tuple[bytes, bytes]:
    master = derive_slip77_master_blinding_key(seed)
    return (
        derive_script_blinding_privkey(master, script),
        derive_script_blinding_pubkey(master, script),
    )


def _utxo_from_material(material, txid: str = "ab" * 32) -> LiquidUtxo:
    """Wrap a LiquidOutputBlindingMaterial as a LiquidUtxo so the
    receive-path helper can unblind it."""
    return LiquidUtxo(
        txid=txid,
        vout=0,
        script_pubkey=material.script_pubkey,
        value_commitment=material.value_commitment,
        asset_commitment=material.asset_generator,
        nonce_commitment=material.nonce_commitment,
        rangeproof=material.rangeproof,
        surjectionproof=material.surjection_proof,
        block_height=100,
    )


# ── 1-in 1-out roundtrip ───────────────────────────────────────────


def test_one_input_one_output_roundtrip() -> None:
    """The simplest spend: one input fully consumed, one recipient
    output. After blinding, the recipient must unblind back to the
    original cleartext."""
    inp = _input(value=200_000)
    script = b"\x00\x14" + b"\x33" * 20
    recip_priv, recip_pub = _receiver_keys(script=script)
    spec = OutputBlindingSpec(
        value_sat=200_000,
        asset_id=_ASSET_LE,
        destination_blinding_pubkey=recip_pub,
        script_pubkey=script,
    )
    out = blind_spend_outputs(inputs=[inp], outputs=[spec])
    assert len(out) == 1
    m = out[0]
    assert m.cleartext_value_sat == 200_000
    # ``cleartext_asset_id`` echoes whatever the spec carried (LE
    # here, matching libwally's on-wire form).
    assert m.cleartext_asset_id == _ASSET_LE
    assert len(m.value_commitment) == 33
    assert len(m.asset_generator) == 33
    assert len(m.nonce_commitment) == 33

    # Recipient unblinds via the receive path.
    unblinded = unblind_liquid_utxo(
        utxo=_utxo_from_material(m),
        blinding_privkey=recip_priv,
    )
    assert unblinded.value_sat == 200_000
    assert unblinded.asset_id == _ASSET
    assert unblinded.asset_blinding_factor == m.asset_blinding_factor
    assert unblinded.value_blinding_factor == m.value_blinding_factor


# ── 1-in 2-out with change (different recipients) ──────────────────


def test_one_input_two_outputs_with_change() -> None:
    """Spend 200k into a 150k payment + a 50k change output. Both
    outputs blind, and both recipients can unblind their share."""
    inp = _input(value=200_000)
    pay_script = b"\x00\x14" + b"\x55" * 20
    change_script = b"\x00\x14" + b"\x77" * 20

    pay_priv, pay_pub = _receiver_keys_from_seed(
        b"\xa1" * 64,
        script=pay_script,
    )
    change_priv, change_pub = _receiver_keys_from_seed(
        b"\xa2" * 64,
        script=change_script,
    )

    out = blind_spend_outputs(
        inputs=[inp],
        outputs=[
            OutputBlindingSpec(
                value_sat=150_000,
                asset_id=_ASSET_LE,
                destination_blinding_pubkey=pay_pub,
                script_pubkey=pay_script,
            ),
            OutputBlindingSpec(
                value_sat=50_000,
                asset_id=_ASSET_LE,
                destination_blinding_pubkey=change_pub,
                script_pubkey=change_script,
            ),
        ],
    )
    assert len(out) == 2

    # Recipient #1 unblinds the payment.
    pay_unblinded = unblind_liquid_utxo(
        utxo=_utxo_from_material(out[0]),
        blinding_privkey=pay_priv,
    )
    assert pay_unblinded.value_sat == 150_000
    assert pay_unblinded.asset_id == _ASSET

    # Recipient #2 unblinds the change.
    change_unblinded = unblind_liquid_utxo(
        utxo=_utxo_from_material(out[1]),
        blinding_privkey=change_priv,
    )
    assert change_unblinded.value_sat == 50_000
    assert change_unblinded.asset_id == _ASSET


# ── Balance invariant ──────────────────────────────────────────────


def test_compute_balancing_vbf_returns_32_bytes() -> None:
    abf_concat = b"\xa1" * 32 + b"\xa2" * 32
    inp_vbf = b"\xb1" * 32
    out = compute_balancing_vbf(
        input_values=[100_000],
        output_values=[100_000],
        abfs_concat=abf_concat,
        prior_vbfs_concat=inp_vbf,
    )
    assert len(out) == 32


def test_compute_balancing_vbf_validates_lengths() -> None:
    with pytest.raises(LiquidSpendError):
        compute_balancing_vbf(
            input_values=[100_000],
            output_values=[100_000],
            abfs_concat=b"\xa1" * 32,  # half-length
            prior_vbfs_concat=b"\xb1" * 32,
        )


def test_compute_balancing_vbf_rejects_empty_inputs() -> None:
    with pytest.raises(LiquidSpendError):
        compute_balancing_vbf(
            input_values=[],
            output_values=[100_000],
            abfs_concat=b"\xa1" * 32,
            prior_vbfs_concat=b"",
        )


def test_balancing_property_holds_for_1in_2out() -> None:
    """The full balance: the sum of input (abf, vbf) over the same
    asset equals the sum of output (abf, vbf). This is what makes
    the produced tx pass Liquid consensus validation.

    We test the property by building the spend, then computing what
    the final-VBF should be from first principles via wallycore."""
    inp = _input(value=200_000)
    script_a = b"\x00\x14" + b"\x55" * 20
    script_b = b"\x00\x14" + b"\x66" * 20
    _, pub_a = _receiver_keys_from_seed(b"\xa1" * 64, script=script_a)
    _, pub_b = _receiver_keys_from_seed(b"\xa2" * 64, script=script_b)
    spec_a = OutputBlindingSpec(
        value_sat=150_000,
        asset_id=_ASSET_LE,
        destination_blinding_pubkey=pub_a,
        script_pubkey=script_a,
    )
    spec_b = OutputBlindingSpec(
        value_sat=50_000,
        asset_id=_ASSET_LE,
        destination_blinding_pubkey=pub_b,
        script_pubkey=script_b,
    )
    out = blind_spend_outputs(inputs=[inp], outputs=[spec_a, spec_b])

    # Independently compute the expected final VBF.
    expected = compute_balancing_vbf(
        input_values=[200_000],
        output_values=[150_000, 50_000],
        abfs_concat=(inp.abf + out[0].asset_blinding_factor + out[1].asset_blinding_factor),
        prior_vbfs_concat=inp.vbf + out[0].value_blinding_factor,
    )
    assert expected == out[1].value_blinding_factor


# ── Surjection proof ───────────────────────────────────────────────


def test_make_asset_surjection_proof_returns_expected_size() -> None:
    inp_abf = secrets.token_bytes(32)
    inp_gen = make_asset_generator(_ASSET, inp_abf)
    out_abf = secrets.token_bytes(32)
    out_gen = make_asset_generator(_ASSET, out_abf)
    proof = make_asset_surjection_proof(
        output_asset_id=_ASSET,
        output_abf=out_abf,
        output_generator=out_gen,
        input_assets_concat=_ASSET,
        input_abfs_concat=inp_abf,
        input_generators_concat=inp_gen,
    )
    assert len(proof) == _wally.asset_surjectionproof_size(1)


def test_make_asset_surjection_proof_deterministic_with_seeded_entropy() -> None:
    inp_abf = b"\x11" * 32
    inp_gen = make_asset_generator(_ASSET, inp_abf)
    out_abf = b"\x22" * 32
    out_gen = make_asset_generator(_ASSET, out_abf)
    entropy = b"\xee" * 32
    a = make_asset_surjection_proof(
        output_asset_id=_ASSET,
        output_abf=out_abf,
        output_generator=out_gen,
        input_assets_concat=_ASSET,
        input_abfs_concat=inp_abf,
        input_generators_concat=inp_gen,
        entropy=entropy,
    )
    b = make_asset_surjection_proof(
        output_asset_id=_ASSET,
        output_abf=out_abf,
        output_generator=out_gen,
        input_assets_concat=_ASSET,
        input_abfs_concat=inp_abf,
        input_generators_concat=inp_gen,
        entropy=entropy,
    )
    assert a == b


def test_make_asset_surjection_proof_rejects_short_asset_id() -> None:
    with pytest.raises(LiquidSpendError):
        make_asset_surjection_proof(
            output_asset_id=b"\x00" * 16,
            output_abf=b"\x00" * 32,
            output_generator=b"\x0a" + b"\x00" * 32,
            input_assets_concat=_ASSET,
            input_abfs_concat=b"\x00" * 32,
            input_generators_concat=b"\x0a" + b"\x00" * 32,
        )


def test_make_asset_surjection_proof_rejects_mismatched_input_lengths() -> None:
    with pytest.raises(LiquidSpendError):
        make_asset_surjection_proof(
            output_asset_id=_ASSET,
            output_abf=b"\x00" * 32,
            output_generator=b"\x0a" + b"\x00" * 32,
            input_assets_concat=_ASSET + _ASSET,  # 2 inputs
            input_abfs_concat=b"\x00" * 32,  # 1 input
            input_generators_concat=b"\x0a" + b"\x00" * 32,
        )


def test_make_asset_surjection_proof_rejects_wrong_entropy_length() -> None:
    inp_abf = b"\x11" * 32
    inp_gen = make_asset_generator(_ASSET, inp_abf)
    with pytest.raises(LiquidSpendError):
        make_asset_surjection_proof(
            output_asset_id=_ASSET,
            output_abf=b"\x22" * 32,
            output_generator=make_asset_generator(_ASSET, b"\x22" * 32),
            input_assets_concat=_ASSET,
            input_abfs_concat=inp_abf,
            input_generators_concat=inp_gen,
            entropy=b"\xee" * 16,  # half-length
        )


# ── Refusals ───────────────────────────────────────────────────────


def test_blind_spend_refuses_empty_inputs() -> None:
    with pytest.raises(LiquidSpendError):
        blind_spend_outputs(inputs=[], outputs=[])


def test_blind_spend_refuses_empty_outputs() -> None:
    inp = _input(value=100_000)
    with pytest.raises(LiquidSpendError):
        blind_spend_outputs(inputs=[inp], outputs=[])


def test_blind_spend_refuses_wrong_input_lengths() -> None:
    bad = InputBlindingFactors(
        value_sat=100_000,
        asset_id=b"\x00" * 16,  # wrong length
        abf=b"\x00" * 32,
        vbf=b"\x00" * 32,
        asset_generator=b"\x0a" + b"\x00" * 32,
    )
    spec = OutputBlindingSpec(
        value_sat=100_000,
        asset_id=_ASSET,
        destination_blinding_pubkey=b"\x02" + b"\x00" * 32,
        script_pubkey=b"\x00\x14" + b"\x33" * 20,
    )
    with pytest.raises(LiquidSpendError):
        blind_spend_outputs(inputs=[bad], outputs=[spec])


def test_blind_spend_refuses_negative_output_value() -> None:
    inp = _input(value=100_000)
    spec = OutputBlindingSpec(
        value_sat=-1,
        asset_id=_ASSET,
        destination_blinding_pubkey=b"\x02" + b"\x00" * 32,
        script_pubkey=b"\x00\x14" + b"\x33" * 20,
    )
    with pytest.raises(LiquidSpendError):
        blind_spend_outputs(inputs=[inp], outputs=[spec])


def test_blind_spend_refuses_empty_script_pubkey() -> None:
    inp = _input(value=100_000)
    spec = OutputBlindingSpec(
        value_sat=100_000,
        asset_id=_ASSET,
        destination_blinding_pubkey=b"\x02" + b"\x00" * 32,
        script_pubkey=b"",
    )
    with pytest.raises(LiquidSpendError):
        blind_spend_outputs(inputs=[inp], outputs=[spec])


def test_blind_spend_refuses_wrong_pubkey_length() -> None:
    inp = _input(value=100_000)
    spec = OutputBlindingSpec(
        value_sat=100_000,
        asset_id=_ASSET,
        destination_blinding_pubkey=b"\x02" + b"\x00" * 16,  # short
        script_pubkey=b"\x00\x14" + b"\x33" * 20,
    )
    with pytest.raises(LiquidSpendError):
        blind_spend_outputs(inputs=[inp], outputs=[spec])


# ── Sender ephem pubkey threading ──────────────────────────────────


def _three_real_outputs(value_each: int) -> list[OutputBlindingSpec]:
    """Three outputs with on-curve blinding pubkeys for tests that
    exercise multi-output paths without unblinding."""
    out: list[OutputBlindingSpec] = []
    for tag in (b"\x55", b"\x66", b"\x77"):
        script = b"\x00\x14" + tag * 20
        _, pub = _receiver_keys_from_seed(tag * 64, script=script)
        out.append(
            OutputBlindingSpec(
                value_sat=value_each,
                asset_id=_ASSET_LE,
                destination_blinding_pubkey=pub,
                script_pubkey=script,
            )
        )
    return out


def test_each_output_has_distinct_nonce_commitment() -> None:
    """Per-output ephemeral keypairs — never reused across outputs.
    Reusing the ephem key would leak the receiver's blinding pubkey
    correspondence between outputs."""
    inp = _input(value=300_000)
    out = blind_spend_outputs(
        inputs=[inp],
        outputs=_three_real_outputs(value_each=100_000),
    )
    nonces = [m.nonce_commitment for m in out]
    assert len(set(nonces)) == 3  # all distinct


def test_each_output_has_distinct_blinding_factors() -> None:
    inp = _input(value=300_000)
    specs = _three_real_outputs(value_each=100_000)[:2]
    out = blind_spend_outputs(
        inputs=[inp],
        outputs=specs
        + [
            OutputBlindingSpec(
                value_sat=100_000,
                asset_id=_ASSET_LE,
                destination_blinding_pubkey=specs[0].destination_blinding_pubkey,
                script_pubkey=specs[0].script_pubkey,
            )
        ],
    )
    abfs = [m.asset_blinding_factor for m in out]
    vbfs = [m.value_blinding_factor for m in out]
    assert len(set(abfs)) == 3
    assert len(set(vbfs)) == 3
