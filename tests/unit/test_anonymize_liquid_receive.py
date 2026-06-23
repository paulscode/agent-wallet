# SPDX-License-Identifier: MIT
"""Liquid CT receive path.

Builds blinded Liquid UTXOs via wallycore (synthesising what a Boltz
chain swap would publish on Liquid), passes them through
:func:`unblind_liquid_utxo`, and confirms the recovered cleartext
matches. Negative paths cover:

* Wrong blinding key (output not for us).
* Tampered rangeproof.
* Wrong asset id.
* Out-of-range amount.
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
)
from app.services.anonymize.liquid_receive import (
    LiquidReceiveError,
    UnblindedUtxo,
    unblind_liquid_utxo,
    validate_lbtc_credit,
)

_SEED = bytes.fromhex("42" * 64)
_SCRIPT_P2WPKH = b"\x00\x14" + b"\x11" * 20
_ASSET_ID = LBTC_ASSET_ID_MAINNET


def _build_blinded_utxo(
    *,
    seed: bytes = _SEED,
    script: bytes = _SCRIPT_P2WPKH,
    asset_id: bytes = _ASSET_ID,
    amount_sat: int = 100_000,
    abf: bytes | None = None,
    vbf: bytes | None = None,
    sender_priv: bytes | None = None,
) -> tuple[LiquidUtxo, bytes]:
    """Synthesize a blinded Liquid UTXO that we should be able to unblind.

    Returns ``(utxo, receiver_blinding_privkey)``. Default blinding
    factors are random per call so the tests don't accidentally
    cache state across cases.
    """
    master = derive_slip77_master_blinding_key(seed)
    receiver_priv = derive_script_blinding_privkey(master, script)
    receiver_pub = derive_script_blinding_pubkey(master, script)

    sender_priv = sender_priv if sender_priv is not None else secrets.token_bytes(32)
    abf = abf if abf is not None else secrets.token_bytes(32)
    vbf = vbf if vbf is not None else secrets.token_bytes(32)

    # Libwally's ``asset_*`` functions operate on LE asset hashes
    # (the on-wire form). ``asset_id`` here is BE / display form;
    # reverse for libwally. The unblind path inside the wallet then
    # reverses back to BE.
    asset_id_le = bytes(asset_id)[::-1]
    asset_generator = bytes(_wally.asset_generator_from_bytes(asset_id_le, abf))
    value_commitment = bytes(
        _wally.asset_value_commitment(
            amount_sat,
            vbf,
            asset_generator,
        )
    )
    rangeproof = bytes(
        _wally.asset_rangeproof(
            amount_sat,
            receiver_pub,
            sender_priv,
            asset_id_le,
            abf,
            vbf,
            value_commitment,
            script,
            asset_generator,
            1,
            0,
            36,
        )
    )
    nonce_commitment = bytes(_wally.ec_public_key_from_private_key(sender_priv))
    utxo = LiquidUtxo(
        txid="ab" * 32,
        vout=0,
        script_pubkey=script,
        value_commitment=value_commitment,
        asset_commitment=asset_generator,
        nonce_commitment=nonce_commitment,
        rangeproof=rangeproof,
        surjectionproof=b"",  # not used by the receive path
        block_height=100,
    )
    return utxo, receiver_priv


# ── End-to-end roundtrip ───────────────────────────────────────────


def test_unblind_recovers_cleartext_value() -> None:
    utxo, priv = _build_blinded_utxo(amount_sat=250_000)
    out = unblind_liquid_utxo(utxo=utxo, blinding_privkey=priv)
    assert isinstance(out, UnblindedUtxo)
    assert out.value_sat == 250_000


def test_unblind_recovers_asset_id() -> None:
    utxo, priv = _build_blinded_utxo(asset_id=_ASSET_ID)
    out = unblind_liquid_utxo(utxo=utxo, blinding_privkey=priv)
    assert out.asset_id == _ASSET_ID


def test_unblind_recovers_blinding_factors() -> None:
    abf = secrets.token_bytes(32)
    vbf = secrets.token_bytes(32)
    utxo, priv = _build_blinded_utxo(abf=abf, vbf=vbf)
    out = unblind_liquid_utxo(utxo=utxo, blinding_privkey=priv)
    assert out.asset_blinding_factor == abf
    assert out.value_blinding_factor == vbf


def test_unblind_preserves_original_utxo() -> None:
    utxo, priv = _build_blinded_utxo()
    out = unblind_liquid_utxo(utxo=utxo, blinding_privkey=priv)
    # Round-trip the original blinded data through the unblinded view.
    assert out.utxo is utxo
    assert out.utxo.script_pubkey == _SCRIPT_P2WPKH


# ── Negative paths ─────────────────────────────────────────────────


def test_unblind_with_wrong_blinding_key_fails() -> None:
    """If the output isn't for us (or our blinding key has drifted),
    the unblind must fail — never silently return a wrong amount."""
    utxo, _ = _build_blinded_utxo()
    wrong_priv = secrets.token_bytes(32)
    with pytest.raises(LiquidReceiveError):
        unblind_liquid_utxo(utxo=utxo, blinding_privkey=wrong_priv)


def test_unblind_with_tampered_rangeproof_fails() -> None:
    """A rangeproof byte-flip must fail verification — defends
    against a backend or in-flight observer altering the on-wire
    output."""
    utxo, priv = _build_blinded_utxo()
    tampered_proof = bytearray(utxo.rangeproof)
    tampered_proof[10] ^= 0xFF  # flip a byte
    tampered = LiquidUtxo(
        txid=utxo.txid,
        vout=utxo.vout,
        script_pubkey=utxo.script_pubkey,
        value_commitment=utxo.value_commitment,
        asset_commitment=utxo.asset_commitment,
        nonce_commitment=utxo.nonce_commitment,
        rangeproof=bytes(tampered_proof),
        surjectionproof=utxo.surjectionproof,
        block_height=utxo.block_height,
    )
    with pytest.raises(LiquidReceiveError):
        unblind_liquid_utxo(utxo=tampered, blinding_privkey=priv)


def test_unblind_with_tampered_script_pubkey_fails() -> None:
    """The rangeproof's ``extra`` data binds to the scriptPubKey; a
    backend that swaps the script must fail to verify."""
    utxo, priv = _build_blinded_utxo()
    swapped = LiquidUtxo(
        txid=utxo.txid,
        vout=utxo.vout,
        script_pubkey=b"\x00\x14" + b"\x99" * 20,  # different script
        value_commitment=utxo.value_commitment,
        asset_commitment=utxo.asset_commitment,
        nonce_commitment=utxo.nonce_commitment,
        rangeproof=utxo.rangeproof,
        surjectionproof=utxo.surjectionproof,
        block_height=utxo.block_height,
    )
    with pytest.raises(LiquidReceiveError):
        unblind_liquid_utxo(utxo=swapped, blinding_privkey=priv)


def test_unblind_rejects_wrong_priv_length() -> None:
    utxo, _ = _build_blinded_utxo()
    with pytest.raises(LiquidReceiveError) as exc:
        unblind_liquid_utxo(utxo=utxo, blinding_privkey=b"\x00" * 16)
    assert "blinding_privkey must be" in str(exc.value)


def test_unblind_rejects_wrong_commitment_lengths() -> None:
    utxo, priv = _build_blinded_utxo()
    bad = LiquidUtxo(
        txid=utxo.txid,
        vout=utxo.vout,
        script_pubkey=utxo.script_pubkey,
        value_commitment=b"\x00" * 16,  # short
        asset_commitment=utxo.asset_commitment,
        nonce_commitment=utxo.nonce_commitment,
        rangeproof=utxo.rangeproof,
        surjectionproof=utxo.surjectionproof,
        block_height=utxo.block_height,
    )
    with pytest.raises(LiquidReceiveError) as exc:
        unblind_liquid_utxo(utxo=bad, blinding_privkey=priv)
    assert "value_commitment must be" in str(exc.value)


def test_unblind_rejects_empty_rangeproof() -> None:
    utxo, priv = _build_blinded_utxo()
    bad = LiquidUtxo(
        txid=utxo.txid,
        vout=utxo.vout,
        script_pubkey=utxo.script_pubkey,
        value_commitment=utxo.value_commitment,
        asset_commitment=utxo.asset_commitment,
        nonce_commitment=utxo.nonce_commitment,
        rangeproof=b"",  # empty
        surjectionproof=utxo.surjectionproof,
        block_height=utxo.block_height,
    )
    with pytest.raises(LiquidReceiveError) as exc:
        unblind_liquid_utxo(utxo=bad, blinding_privkey=priv)
    assert "rangeproof must be non-empty" in str(exc.value)


# ── validate_lbtc_credit ───────────────────────────────────────────


def _ub(*, value: int, asset: bytes = _ASSET_ID) -> UnblindedUtxo:
    """Bare UnblindedUtxo for the validator tests (we don't need a
    real LiquidUtxo for the validation predicate)."""
    return UnblindedUtxo(
        utxo=LiquidUtxo(
            txid="ab" * 32,
            vout=0,
            script_pubkey=_SCRIPT_P2WPKH,
            value_commitment=b"\x09" + b"\xa0" * 32,
            asset_commitment=b"\x0a" + b"\xb0" * 32,
            nonce_commitment=b"\x02" + b"\xc0" * 32,
            rangeproof=b"x" * 64,
            surjectionproof=b"",
            block_height=100,
        ),
        value_sat=value,
        asset_id=asset,
        asset_blinding_factor=b"\x00" * 32,
        value_blinding_factor=b"\x00" * 32,
    )


def test_validate_passes_on_expected_credit() -> None:
    ub = _ub(value=100_000)
    err = validate_lbtc_credit(
        ub,
        expected_asset_id=_ASSET_ID,
        expected_min_amount_sat=100_000,
        expected_max_amount_sat=100_000,
    )
    assert err is None


def test_validate_rejects_wrong_asset() -> None:
    """An operator who sends us a tokenised asset instead of L-BTC
    must be caught — the asset_id check is the only line of defense
    here (blinding hides the amount but not the asset commitment)."""
    other_asset = b"\xff" * 32
    ub = _ub(value=100_000, asset=other_asset)
    err = validate_lbtc_credit(
        ub,
        expected_asset_id=_ASSET_ID,
        expected_min_amount_sat=100_000,
    )
    assert err is not None
    assert "unexpected asset_id" in err


def test_validate_rejects_underpayment() -> None:
    ub = _ub(value=50_000)
    err = validate_lbtc_credit(
        ub,
        expected_asset_id=_ASSET_ID,
        expected_min_amount_sat=100_000,
    )
    assert err is not None
    assert "below minimum" in err


def test_validate_rejects_overpayment_when_max_supplied() -> None:
    ub = _ub(value=300_000)
    err = validate_lbtc_credit(
        ub,
        expected_asset_id=_ASSET_ID,
        expected_min_amount_sat=100_000,
        expected_max_amount_sat=250_000,
    )
    assert err is not None
    assert "above maximum" in err


def test_validate_admits_overpayment_when_max_unset() -> None:
    """Without an explicit max, overpayment is admitted — the
    operator's policy is to keep the excess, and the hop body
    decides whether to flag this."""
    ub = _ub(value=300_000)
    err = validate_lbtc_credit(
        ub,
        expected_asset_id=_ASSET_ID,
        expected_min_amount_sat=100_000,
    )
    assert err is None


def test_validate_rejects_wrong_expected_asset_id_length() -> None:
    ub = _ub(value=100_000)
    err = validate_lbtc_credit(
        ub,
        expected_asset_id=b"\x00" * 16,
        expected_min_amount_sat=100_000,
    )
    assert err is not None
    assert "expected_asset_id must be" in err


def test_validate_rejects_negative_minimum() -> None:
    ub = _ub(value=100_000)
    err = validate_lbtc_credit(
        ub,
        expected_asset_id=_ASSET_ID,
        expected_min_amount_sat=-1,
    )
    assert err is not None
    assert "non-negative" in err
