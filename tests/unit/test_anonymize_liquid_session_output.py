# SPDX-License-Identifier: MIT
"""Tests for the per-session Liquid output derivation in ``liquid_seed``.

The Liquid hop body needs a deterministic, wallet-controlled CT
address for the leg-1 cooperative claim and a matching spending
keypair for the leg-2 lock TX. :func:`derive_session_liquid_output`
re-derives all four (spending priv/pub, script, blinding priv/pub,
CT address) from the master blinding key + persisted derivation
index.

These tests cover:

* Determinism: same inputs → same output across re-derivations.
* Domain separation: different sessions / different indexes produce
  different keypairs.
* Address validity: the produced CT address parses back to the
  derived scriptPubKey + blinding pubkey.
* Encrypt / decrypt round-trip of the derivation index.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from app.services.anonymize.liquid_address import (
    LiquidNetwork,
    parse_liquid_address,
)
from app.services.anonymize.liquid_ct import (
    derive_slip77_master_blinding_key,
)
from app.services.anonymize.liquid_seed import (
    LiquidSeedError,
    decrypt_session_blinding_seed_index,
    derive_session_liquid_output,
    encrypt_session_blinding_seed_index,
    generate_session_blinding_seed_index,
)


@pytest.fixture
def _master() -> bytes:
    return derive_slip77_master_blinding_key(b"\x42" * 64)


# ── Determinism ────────────────────────────────────────────────────


def test_derivation_is_deterministic(_master: bytes) -> None:
    sid = uuid4()
    out_a = derive_session_liquid_output(
        master_blinding_key=_master,
        session_id=sid,
        derivation_index=123,
        network=LiquidNetwork.REGTEST,
    )
    out_b = derive_session_liquid_output(
        master_blinding_key=_master,
        session_id=sid,
        derivation_index=123,
        network=LiquidNetwork.REGTEST,
    )
    assert out_a == out_b


def test_different_session_yields_different_keys(_master: bytes) -> None:
    out_a = derive_session_liquid_output(
        master_blinding_key=_master,
        session_id=uuid4(),
        derivation_index=1,
        network=LiquidNetwork.REGTEST,
    )
    out_b = derive_session_liquid_output(
        master_blinding_key=_master,
        session_id=uuid4(),
        derivation_index=1,
        network=LiquidNetwork.REGTEST,
    )
    assert out_a.spending_privkey != out_b.spending_privkey
    assert out_a.script_pubkey != out_b.script_pubkey


def test_different_index_yields_different_keys(_master: bytes) -> None:
    sid = uuid4()
    out_a = derive_session_liquid_output(
        master_blinding_key=_master,
        session_id=sid,
        derivation_index=1,
        network=LiquidNetwork.REGTEST,
    )
    out_b = derive_session_liquid_output(
        master_blinding_key=_master,
        session_id=sid,
        derivation_index=2,
        network=LiquidNetwork.REGTEST,
    )
    assert out_a.spending_privkey != out_b.spending_privkey


# ── Address shape ──────────────────────────────────────────────────


def test_ct_address_round_trips_to_script_and_blinding_pubkey(
    _master: bytes,
) -> None:
    out = derive_session_liquid_output(
        master_blinding_key=_master,
        session_id=uuid4(),
        derivation_index=7,
        network=LiquidNetwork.REGTEST,
    )
    parsed = parse_liquid_address(out.ct_address)
    assert parsed.script_pubkey == out.script_pubkey
    assert parsed.blinding_pubkey == out.blinding_pubkey


def test_script_is_p2wpkh_shape(_master: bytes) -> None:
    out = derive_session_liquid_output(
        master_blinding_key=_master,
        session_id=uuid4(),
        derivation_index=11,
        network=LiquidNetwork.MAINNET,
    )
    # OP_0 + 0x14 + 20-byte hash160
    assert out.script_pubkey[:2] == b"\x00\x14"
    assert len(out.script_pubkey) == 22


def test_blinding_priv_pub_pair_matches(_master: bytes) -> None:
    """The blinding priv/pub returned must be a valid ECDSA keypair."""
    import wallycore as _wally

    out = derive_session_liquid_output(
        master_blinding_key=_master,
        session_id=uuid4(),
        derivation_index=33,
        network=LiquidNetwork.MAINNET,
    )
    recomputed = bytes(_wally.ec_public_key_from_private_key(out.blinding_privkey))
    assert recomputed == out.blinding_pubkey


# ── Index lifecycle ────────────────────────────────────────────────


def test_generate_index_returns_positive_signed_32bit(monkeypatch) -> None:
    for _ in range(32):
        idx = generate_session_blinding_seed_index()
        assert 1 <= idx < (1 << 31)


def test_index_encrypt_decrypt_round_trip() -> None:
    """Round-trip a few representative index values through the
    ``app.core.encryption`` Fernet wrapper. The encryption key comes
    from ``settings.secret_key`` (already populated by the test config)
    so no extra setup is needed."""
    for v in (1, 12345, (1 << 31) - 1):
        ct = encrypt_session_blinding_seed_index(v)
        assert decrypt_session_blinding_seed_index(ct) == v


def test_decrypt_rejects_corrupt_ciphertext() -> None:
    with pytest.raises(LiquidSeedError):
        decrypt_session_blinding_seed_index(b"this-is-not-fernet")
