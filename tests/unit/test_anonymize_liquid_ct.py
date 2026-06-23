# SPDX-License-Identifier: MIT
"""Liquid CT primitives smoke tests.

Anchors the ``wallycore`` (Blockstream libwally) integration so a
later swap of the underlying library is a single-module change.
Covers:

* SLIP-77 master blinding key derivation — determinism + size +
  seed-sensitivity.
* Per-script blinding privkey + pubkey derivation — determinism +
  script-sensitivity + master-sensitivity.
* Asset generator + Pedersen value commitment math — sizes,
  determinism, sensitivity to inputs.
* Input validation — wrong-length args raise :class:`LiquidCTError`.
* L-BTC asset-id helper — built-in mainnet/testnet, regtest raises.
"""

from __future__ import annotations

import pytest

from app.services.anonymize.liquid_ct import (
    ASSET_GENERATOR_LEN,
    ASSET_ID_LEN,
    LBTC_ASSET_ID_MAINNET,
    LBTC_ASSET_ID_TESTNET,
    MASTER_BLINDING_KEY_LEN,
    SCRIPT_BLINDING_PRIVKEY_LEN,
    SCRIPT_BLINDING_PUBKEY_LEN,
    VALUE_COMMITMENT_LEN,
    LiquidCTError,
    derive_script_blinding_privkey,
    derive_script_blinding_pubkey,
    derive_slip77_master_blinding_key,
    lbtc_asset_id_for_network,
    make_asset_generator,
    make_value_commitment,
)

# A representative 64-byte seed (any high-entropy bytes will do for the
# smoke tests — these are not testnet/mainnet keys).
_SEED_A = bytes.fromhex("42" * 64)
_SEED_B = bytes.fromhex(
    "00112233445566778899aabbccddeeff" * 4  # 32 bytes * 2 = 64
)
_SCRIPT_P2WPKH = b"\x00\x14" + b"\x11" * 20  # OP_0 OP_PUSH20 <hash>
_SCRIPT_P2WPKH_B = b"\x00\x14" + b"\x22" * 20  # different hash


# ── SLIP-77 master blinding key ─────────────────────────────────────


def test_master_blinding_key_returns_64_bytes() -> None:
    out = derive_slip77_master_blinding_key(_SEED_A)
    assert isinstance(out, bytes)
    assert len(out) == MASTER_BLINDING_KEY_LEN == 64


def test_master_blinding_key_is_deterministic() -> None:
    assert derive_slip77_master_blinding_key(_SEED_A) == derive_slip77_master_blinding_key(_SEED_A)


def test_master_blinding_key_sensitive_to_seed() -> None:
    assert derive_slip77_master_blinding_key(_SEED_A) != derive_slip77_master_blinding_key(_SEED_B)


def test_master_blinding_key_rejects_empty_seed() -> None:
    with pytest.raises(LiquidCTError):
        derive_slip77_master_blinding_key(b"")


def test_master_blinding_key_rejects_non_bytes() -> None:
    with pytest.raises(LiquidCTError):
        derive_slip77_master_blinding_key("not-bytes")  # type: ignore[arg-type]


# ── Per-script blinding privkey ─────────────────────────────────────


def test_script_blinding_privkey_returns_32_bytes() -> None:
    master = derive_slip77_master_blinding_key(_SEED_A)
    priv = derive_script_blinding_privkey(master, _SCRIPT_P2WPKH)
    assert isinstance(priv, bytes)
    assert len(priv) == SCRIPT_BLINDING_PRIVKEY_LEN == 32


def test_script_blinding_privkey_is_deterministic() -> None:
    master = derive_slip77_master_blinding_key(_SEED_A)
    a = derive_script_blinding_privkey(master, _SCRIPT_P2WPKH)
    b = derive_script_blinding_privkey(master, _SCRIPT_P2WPKH)
    assert a == b


def test_script_blinding_privkey_sensitive_to_script() -> None:
    """SLIP-77 binds each blinding key to a specific scriptPubKey so
    every output gets a distinct key without cross-output linkage."""
    master = derive_slip77_master_blinding_key(_SEED_A)
    a = derive_script_blinding_privkey(master, _SCRIPT_P2WPKH)
    b = derive_script_blinding_privkey(master, _SCRIPT_P2WPKH_B)
    assert a != b


def test_script_blinding_privkey_sensitive_to_master() -> None:
    """Different seeds → different masters → different blinding keys
    even for the same script."""
    master_a = derive_slip77_master_blinding_key(_SEED_A)
    master_b = derive_slip77_master_blinding_key(_SEED_B)
    priv_a = derive_script_blinding_privkey(master_a, _SCRIPT_P2WPKH)
    priv_b = derive_script_blinding_privkey(master_b, _SCRIPT_P2WPKH)
    assert priv_a != priv_b


def test_script_blinding_privkey_rejects_short_master() -> None:
    with pytest.raises(LiquidCTError):
        derive_script_blinding_privkey(b"\x00" * 32, _SCRIPT_P2WPKH)


def test_script_blinding_privkey_rejects_empty_script() -> None:
    master = derive_slip77_master_blinding_key(_SEED_A)
    with pytest.raises(LiquidCTError):
        derive_script_blinding_privkey(master, b"")


# ── Per-script blinding pubkey ──────────────────────────────────────


def test_script_blinding_pubkey_returns_33_bytes() -> None:
    master = derive_slip77_master_blinding_key(_SEED_A)
    pub = derive_script_blinding_pubkey(master, _SCRIPT_P2WPKH)
    assert isinstance(pub, bytes)
    assert len(pub) == SCRIPT_BLINDING_PUBKEY_LEN == 33
    assert pub[0] in (0x02, 0x03)  # compressed-pubkey prefix


def test_script_blinding_pubkey_matches_privkey_via_coincurve() -> None:
    """Cross-check: wallycore's pubkey derivation matches what we'd
    get by computing it via coincurve from the same privkey. This
    confirms the underlying libsecp256k1 contract is consistent
    across the two bindings we use."""
    from coincurve import PrivateKey

    master = derive_slip77_master_blinding_key(_SEED_A)
    priv = derive_script_blinding_privkey(master, _SCRIPT_P2WPKH)
    pub_via_wally = derive_script_blinding_pubkey(master, _SCRIPT_P2WPKH)
    pub_via_coincurve = PrivateKey(priv).public_key.format(compressed=True)
    assert pub_via_wally == pub_via_coincurve


# ── Asset generator ─────────────────────────────────────────────────


def test_make_asset_generator_returns_33_bytes() -> None:
    gen = make_asset_generator(LBTC_ASSET_ID_MAINNET, b"\x33" * 32)
    assert isinstance(gen, bytes)
    assert len(gen) == ASSET_GENERATOR_LEN == 33


def test_make_asset_generator_is_deterministic() -> None:
    abf = b"\x33" * 32
    a = make_asset_generator(LBTC_ASSET_ID_MAINNET, abf)
    b = make_asset_generator(LBTC_ASSET_ID_MAINNET, abf)
    assert a == b


def test_make_asset_generator_sensitive_to_abf() -> None:
    a = make_asset_generator(LBTC_ASSET_ID_MAINNET, b"\x33" * 32)
    b = make_asset_generator(LBTC_ASSET_ID_MAINNET, b"\x44" * 32)
    assert a != b


def test_make_asset_generator_sensitive_to_asset() -> None:
    abf = b"\x33" * 32
    a = make_asset_generator(LBTC_ASSET_ID_MAINNET, abf)
    b = make_asset_generator(LBTC_ASSET_ID_TESTNET, abf)
    assert a != b


def test_make_asset_generator_rejects_short_asset_id() -> None:
    with pytest.raises(LiquidCTError):
        make_asset_generator(b"\x00" * 16, b"\x33" * 32)


def test_make_asset_generator_rejects_short_abf() -> None:
    with pytest.raises(LiquidCTError):
        make_asset_generator(LBTC_ASSET_ID_MAINNET, b"\x33" * 16)


# ── Value commitment ────────────────────────────────────────────────


def test_make_value_commitment_returns_33_bytes() -> None:
    gen = make_asset_generator(LBTC_ASSET_ID_MAINNET, b"\x33" * 32)
    comm = make_value_commitment(100_000, b"\x44" * 32, gen)
    assert isinstance(comm, bytes)
    assert len(comm) == VALUE_COMMITMENT_LEN == 33


def test_make_value_commitment_is_deterministic() -> None:
    gen = make_asset_generator(LBTC_ASSET_ID_MAINNET, b"\x33" * 32)
    vbf = b"\x44" * 32
    a = make_value_commitment(100_000, vbf, gen)
    b = make_value_commitment(100_000, vbf, gen)
    assert a == b


def test_make_value_commitment_sensitive_to_value() -> None:
    gen = make_asset_generator(LBTC_ASSET_ID_MAINNET, b"\x33" * 32)
    vbf = b"\x44" * 32
    assert make_value_commitment(100_000, vbf, gen) != make_value_commitment(100_001, vbf, gen)


def test_make_value_commitment_sensitive_to_vbf() -> None:
    gen = make_asset_generator(LBTC_ASSET_ID_MAINNET, b"\x33" * 32)
    assert make_value_commitment(100_000, b"\x44" * 32, gen) != make_value_commitment(100_000, b"\x55" * 32, gen)


def test_make_value_commitment_rejects_negative_value() -> None:
    gen = make_asset_generator(LBTC_ASSET_ID_MAINNET, b"\x33" * 32)
    with pytest.raises(LiquidCTError):
        make_value_commitment(-1, b"\x44" * 32, gen)


def test_make_value_commitment_rejects_wrong_generator_size() -> None:
    with pytest.raises(LiquidCTError):
        make_value_commitment(100_000, b"\x44" * 32, b"\x00" * 32)


# ── Asset-id helper ─────────────────────────────────────────────────


def test_lbtc_asset_id_for_network_mainnet() -> None:
    assert lbtc_asset_id_for_network("bitcoin") == LBTC_ASSET_ID_MAINNET
    assert lbtc_asset_id_for_network("mainnet") == LBTC_ASSET_ID_MAINNET
    assert lbtc_asset_id_for_network("liquidv1") == LBTC_ASSET_ID_MAINNET


def test_lbtc_asset_id_for_network_testnet() -> None:
    assert lbtc_asset_id_for_network("testnet") == LBTC_ASSET_ID_TESTNET
    assert lbtc_asset_id_for_network("liquidv1t") == LBTC_ASSET_ID_TESTNET


def test_lbtc_asset_id_for_network_regtest_raises() -> None:
    """Regtest L-BTC asset ID is operator-config-dependent so the
    helper raises rather than silently using a wrong constant."""
    with pytest.raises(LiquidCTError) as exc:
        lbtc_asset_id_for_network("regtest")
    assert "ANONYMIZE_LIQUID_BTC_ASSET_ID" in str(exc.value)


def test_lbtc_asset_id_constants_are_32_bytes() -> None:
    assert len(LBTC_ASSET_ID_MAINNET) == ASSET_ID_LEN == 32
    assert len(LBTC_ASSET_ID_TESTNET) == ASSET_ID_LEN == 32
    assert LBTC_ASSET_ID_MAINNET != LBTC_ASSET_ID_TESTNET
