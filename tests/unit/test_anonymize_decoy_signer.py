# SPDX-License-Identifier: MIT
"""Decoy-output signer (BIP-32 / BIP-86 / BIP-340).

The hardness of the layer comes from the BIP-32 chain-walk + BIP-86
tweak; libsecp256k1 (via ``coincurve``) handles the elliptic-curve
operations and Schnorr signing.

Anchored test vectors:

* BIP-86 test vector 1 — the all-``abandon`` mnemonic seed at
  ``m/86'/0'/0'/0/0`` produces the published internal + output
  pubkeys. https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors

Round-trip tests confirm a Schnorr signature over a 32-byte sighash
verifies against the derived x-only output pubkey.
"""

from __future__ import annotations

import secrets

import pytest

from app.services.anonymize.decoy_signer import (
    HARDENED_OFFSET,
    DecoySignerError,
    bip32_derive_path,
    bip32_master_from_seed,
    bip86_internal_pubkey_xonly,
    bip86_output_pubkey_xonly,
    bip86_tweaked_priv,
    derive_decoy_output_pubkey_xonly,
    derive_decoy_signing_key,
    parse_bip32_path,
    sign_decoy_taproot_input,
    sign_taproot_keypath_sighash,
    verify_taproot_keypath_sig,
)

# BIP-39 "abandon abandon abandon abandon abandon abandon abandon
# abandon abandon abandon abandon about" seed (no passphrase).
_ABANDON_SEED_HEX = (
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)
_ABANDON_SEED = bytes.fromhex(_ABANDON_SEED_HEX)

# BIP-86 vector 1: m/86'/0'/0'/0/0 → first receiving address.
_BIP86_INTERNAL_XONLY = bytes.fromhex("cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115")
_BIP86_OUTPUT_XONLY = bytes.fromhex("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c")
# BIP-86 vector 2: m/86'/0'/0'/0/1.
_BIP86_VEC2_INTERNAL_XONLY = bytes.fromhex("83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145")
_BIP86_VEC2_OUTPUT_XONLY = bytes.fromhex("a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb")
# BIP-86 vector 3: m/86'/0'/0'/1/0 (change).
_BIP86_VEC3_INTERNAL_XONLY = bytes.fromhex("399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef")
_BIP86_VEC3_OUTPUT_XONLY = bytes.fromhex("882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc")


# ── parse_bip32_path ────────────────────────────────────────────────


def test_parse_path_handles_bare_m() -> None:
    assert parse_bip32_path("m") == []
    assert parse_bip32_path("m/") == []
    assert parse_bip32_path("") == []


def test_parse_path_handles_hardened_apostrophe() -> None:
    assert parse_bip32_path("m/86'/0'/0'/0/0") == [
        86 + HARDENED_OFFSET,
        0 + HARDENED_OFFSET,
        0 + HARDENED_OFFSET,
        0,
        0,
    ]


def test_parse_path_handles_hardened_h() -> None:
    assert parse_bip32_path("m/86h/0h/0h/0/1") == [
        86 + HARDENED_OFFSET,
        0 + HARDENED_OFFSET,
        0 + HARDENED_OFFSET,
        0,
        1,
    ]


def test_parse_path_accepts_path_without_leading_m() -> None:
    assert parse_bip32_path("86'/0'/0'/0/0") == [
        86 + HARDENED_OFFSET,
        0 + HARDENED_OFFSET,
        0 + HARDENED_OFFSET,
        0,
        0,
    ]


def test_parse_path_rejects_out_of_range_hardened() -> None:
    with pytest.raises(DecoySignerError):
        parse_bip32_path(f"m/{HARDENED_OFFSET}'/0/0")


def test_parse_path_rejects_out_of_range_nonhardened() -> None:
    with pytest.raises(DecoySignerError):
        parse_bip32_path(f"m/0'/{HARDENED_OFFSET}")


# ── BIP-32 master + derivation ──────────────────────────────────────


def test_master_from_seed_rejects_empty_seed() -> None:
    with pytest.raises(DecoySignerError):
        bip32_master_from_seed(b"")


def test_master_from_seed_returns_32_byte_priv_and_chaincode() -> None:
    priv, cc = bip32_master_from_seed(_ABANDON_SEED)
    assert len(priv) == 32
    assert len(cc) == 32
    assert priv != b"\x00" * 32


# ── BIP-86 test vectors — first receiving address (m/86'/0'/0'/0/0) ──


def test_bip86_internal_xonly_matches_vector_1() -> None:
    path = parse_bip32_path("m/86'/0'/0'/0/0")
    priv, _ = bip32_derive_path(_ABANDON_SEED, path)
    assert bip86_internal_pubkey_xonly(priv) == _BIP86_INTERNAL_XONLY


def test_bip86_output_xonly_matches_vector_1() -> None:
    path = parse_bip32_path("m/86'/0'/0'/0/0")
    priv, _ = bip32_derive_path(_ABANDON_SEED, path)
    assert bip86_output_pubkey_xonly(priv) == _BIP86_OUTPUT_XONLY


def test_bip86_internal_xonly_matches_vector_2() -> None:
    path = parse_bip32_path("m/86'/0'/0'/0/1")
    priv, _ = bip32_derive_path(_ABANDON_SEED, path)
    assert bip86_internal_pubkey_xonly(priv) == _BIP86_VEC2_INTERNAL_XONLY


def test_bip86_output_xonly_matches_vector_2() -> None:
    path = parse_bip32_path("m/86'/0'/0'/0/1")
    priv, _ = bip32_derive_path(_ABANDON_SEED, path)
    assert bip86_output_pubkey_xonly(priv) == _BIP86_VEC2_OUTPUT_XONLY


def test_bip86_internal_xonly_matches_vector_3() -> None:
    path = parse_bip32_path("m/86'/0'/0'/1/0")
    priv, _ = bip32_derive_path(_ABANDON_SEED, path)
    assert bip86_internal_pubkey_xonly(priv) == _BIP86_VEC3_INTERNAL_XONLY


def test_bip86_output_xonly_matches_vector_3() -> None:
    path = parse_bip32_path("m/86'/0'/0'/1/0")
    priv, _ = bip32_derive_path(_ABANDON_SEED, path)
    assert bip86_output_pubkey_xonly(priv) == _BIP86_VEC3_OUTPUT_XONLY


# ── Tweak + derive roundtrips ───────────────────────────────────────


def test_derive_signing_key_returns_32_bytes() -> None:
    path = parse_bip32_path("m/86'/0'/0'/0/0")
    tweaked = derive_decoy_signing_key(
        seed=_ABANDON_SEED,
        path_components=path,
    )
    assert len(tweaked) == 32


def test_derive_output_pubkey_matches_inline_tweak() -> None:
    """The high-level helper must produce the same output pubkey as
    chaining the individual steps."""
    path = parse_bip32_path("m/86'/0'/0'/0/0")
    via_helper = derive_decoy_output_pubkey_xonly(
        seed=_ABANDON_SEED,
        path_components=path,
    )
    priv, _ = bip32_derive_path(_ABANDON_SEED, path)
    via_steps = bip86_output_pubkey_xonly(priv)
    assert via_helper == via_steps


def test_bip86_tweak_changes_the_key() -> None:
    """The tweaked privkey is materially different from the internal
    privkey (the whole point of the tweak)."""
    path = parse_bip32_path("m/86'/0'/0'/0/0")
    internal_priv, _ = bip32_derive_path(_ABANDON_SEED, path)
    tweaked = bip86_tweaked_priv(internal_priv)
    assert tweaked != internal_priv


# ── BIP-340 sign + verify roundtrip ─────────────────────────────────


def test_sign_verify_roundtrip_under_output_pubkey() -> None:
    """The Schnorr signature produced by the helper must verify under
    the output (tweaked) pubkey — that's the key encoded in the
    on-chain ``OP_1 <32-byte-x-only>`` scriptPubKey."""
    path = parse_bip32_path("m/86'/0'/0'/0/0")
    output_xonly = derive_decoy_output_pubkey_xonly(
        seed=_ABANDON_SEED,
        path_components=path,
    )
    sighash = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    sig = sign_decoy_taproot_input(
        seed=_ABANDON_SEED,
        path_components=path,
        sighash32=sighash,
    )
    assert len(sig) == 64
    assert (
        verify_taproot_keypath_sig(
            output_pub_xonly=output_xonly,
            sighash32=sighash,
            sig64=sig,
        )
        is True
    )


def test_sign_with_wrong_path_fails_verify() -> None:
    """A signature produced under a different path must NOT verify
    against the first path's output pubkey."""
    path_a = parse_bip32_path("m/86'/0'/0'/0/0")
    path_b = parse_bip32_path("m/86'/0'/0'/0/1")
    output_a = derive_decoy_output_pubkey_xonly(
        seed=_ABANDON_SEED,
        path_components=path_a,
    )
    sighash = b"\x00" * 32
    sig_b = sign_decoy_taproot_input(
        seed=_ABANDON_SEED,
        path_components=path_b,
        sighash32=sighash,
    )
    assert (
        verify_taproot_keypath_sig(
            output_pub_xonly=output_a,
            sighash32=sighash,
            sig64=sig_b,
        )
        is False
    )


def test_sign_with_tampered_sighash_fails_verify() -> None:
    path = parse_bip32_path("m/86'/0'/0'/0/0")
    output_xonly = derive_decoy_output_pubkey_xonly(
        seed=_ABANDON_SEED,
        path_components=path,
    )
    sighash = b"\x11" * 32
    sig = sign_decoy_taproot_input(
        seed=_ABANDON_SEED,
        path_components=path,
        sighash32=sighash,
    )
    tampered = b"\x22" * 32
    assert (
        verify_taproot_keypath_sig(
            output_pub_xonly=output_xonly,
            sighash32=tampered,
            sig64=sig,
        )
        is False
    )


def test_sign_refuses_non_32_byte_sighash() -> None:
    path = parse_bip32_path("m/86'/0'/0'/0/0")
    tweaked = derive_decoy_signing_key(
        seed=_ABANDON_SEED,
        path_components=path,
    )
    with pytest.raises(DecoySignerError):
        sign_taproot_keypath_sighash(
            tweaked_priv32=tweaked,
            sighash32=b"too-short",
        )


# ── Robustness ──────────────────────────────────────────────────────


def test_verify_rejects_malformed_inputs() -> None:
    assert (
        verify_taproot_keypath_sig(
            output_pub_xonly=b"\x00" * 16,  # wrong length
            sighash32=b"\x00" * 32,
            sig64=b"\x00" * 64,
        )
        is False
    )


def test_different_seeds_produce_different_keys() -> None:
    """A fresh seed must produce a different output pubkey than the
    well-known vector — the derivation depends materially on the seed."""
    path = parse_bip32_path("m/86'/0'/0'/0/0")
    out_a = derive_decoy_output_pubkey_xonly(
        seed=_ABANDON_SEED,
        path_components=path,
    )
    out_b = derive_decoy_output_pubkey_xonly(
        seed=secrets.token_bytes(64),
        path_components=path,
    )
    assert out_a != out_b
