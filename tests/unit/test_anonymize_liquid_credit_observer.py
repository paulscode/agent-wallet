# SPDX-License-Identifier: MIT
"""Liquid credit observer.

Composes the receive-path unblinding with the backend abstraction to
encapsulate the "wait + unblind + validate" logic the hop body's
credit-observation step needs. Tests build synthetic blinded UTXOs
via wallycore and load them into a ``MockLiquidBackend``, then drive
the observer through every outcome path.
"""

from __future__ import annotations

import secrets

import pytest
import wallycore as _wally

from app.services.anonymize.liquid_backend import LiquidUtxo, MockLiquidBackend
from app.services.anonymize.liquid_credit_observer import (
    LiquidCreditObservation,
    observe_and_validate_credit,
)
from app.services.anonymize.liquid_ct import (
    LBTC_ASSET_ID_MAINNET,
    derive_script_blinding_privkey,
    derive_script_blinding_pubkey,
    derive_slip77_master_blinding_key,
)

_ASSET = LBTC_ASSET_ID_MAINNET
_SCRIPT = b"\x00\x14" + b"\x11" * 20


def _build_blinded_utxo(
    *,
    seed: bytes = b"\x42" * 64,
    script: bytes = _SCRIPT,
    asset_id: bytes = _ASSET,
    amount_sat: int = 100_000,
    sender_priv: bytes | None = None,
) -> tuple[LiquidUtxo, bytes]:
    """Synthesise a blinded UTXO; return ``(utxo, receiver_priv)``."""
    master = derive_slip77_master_blinding_key(seed)
    recv_priv = derive_script_blinding_privkey(master, script)
    recv_pub = derive_script_blinding_pubkey(master, script)
    sender_priv = sender_priv if sender_priv is not None else secrets.token_bytes(32)

    abf = secrets.token_bytes(32)
    vbf = secrets.token_bytes(32)
    # Libwally's ``asset_*`` functions operate on LE asset hashes
    # (the on-wire form). ``asset_id`` here is BE / display form
    # (matching ``LBTC_ASSET_ID_*`` constants); reverse for libwally.
    asset_id_le = bytes(asset_id)[::-1]
    gen = bytes(_wally.asset_generator_from_bytes(asset_id_le, abf))
    comm = bytes(_wally.asset_value_commitment(amount_sat, vbf, gen))
    proof = bytes(
        _wally.asset_rangeproof(
            amount_sat,
            recv_pub,
            sender_priv,
            asset_id_le,
            abf,
            vbf,
            comm,
            script,
            gen,
            1,
            0,
            36,
        )
    )
    nonce = bytes(_wally.ec_public_key_from_private_key(sender_priv))
    utxo = LiquidUtxo(
        txid="ab" * 32,
        vout=0,
        script_pubkey=script,
        value_commitment=comm,
        asset_commitment=gen,
        nonce_commitment=nonce,
        rangeproof=proof,
        surjectionproof=b"",
        block_height=100,
    )
    return utxo, recv_priv


# ── Happy path ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_returns_observation_when_credit_lands() -> None:
    backend = MockLiquidBackend()
    utxo, recv_priv = _build_blinded_utxo(amount_sat=100_000)
    backend.add_utxo(_SCRIPT, utxo)

    obs, err = await observe_and_validate_credit(
        backend=backend,
        lockup_script=_SCRIPT,
        blinding_privkey=recv_priv,
        expected_asset_id=_ASSET,
        expected_amount_sat=100_000,
    )
    assert err is None
    assert isinstance(obs, LiquidCreditObservation)
    assert obs.unblinded.value_sat == 100_000
    assert obs.unblinded.asset_id == _ASSET


@pytest.mark.asyncio
async def test_returns_none_none_when_no_credit_yet() -> None:
    """No UTXOs at the address → ``(None, None)`` so the hop body
    waits without flagging an error."""
    backend = MockLiquidBackend()
    obs, err = await observe_and_validate_credit(
        backend=backend,
        lockup_script=_SCRIPT,
        blinding_privkey=b"\x00" * 32,
        expected_asset_id=_ASSET,
        expected_amount_sat=100_000,
    )
    assert obs is None
    assert err is None


# ── Backend error path ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_returns_error_on_backend_failure() -> None:
    backend = MockLiquidBackend()
    backend.fail("get_address_utxos", "rpc_timeout")
    obs, err = await observe_and_validate_credit(
        backend=backend,
        lockup_script=_SCRIPT,
        blinding_privkey=b"\x00" * 32,
        expected_asset_id=_ASSET,
        expected_amount_sat=100_000,
    )
    assert obs is None
    assert err is not None
    assert "rpc_timeout" in err


# ── Validation paths ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_returns_error_on_wrong_asset() -> None:
    """A credit with the wrong asset id must surface as a hard error."""
    backend = MockLiquidBackend()
    wrong_asset = b"\xff" * 32
    utxo, recv_priv = _build_blinded_utxo(
        amount_sat=100_000,
        asset_id=wrong_asset,
    )
    backend.add_utxo(_SCRIPT, utxo)
    obs, err = await observe_and_validate_credit(
        backend=backend,
        lockup_script=_SCRIPT,
        blinding_privkey=recv_priv,
        expected_asset_id=_ASSET,  # expecting L-BTC, got something else
        expected_amount_sat=100_000,
    )
    assert obs is None
    assert err is not None
    assert "unexpected asset_id" in err


@pytest.mark.asyncio
async def test_returns_error_on_underpayment() -> None:
    backend = MockLiquidBackend()
    utxo, recv_priv = _build_blinded_utxo(amount_sat=50_000)  # below expected
    backend.add_utxo(_SCRIPT, utxo)
    obs, err = await observe_and_validate_credit(
        backend=backend,
        lockup_script=_SCRIPT,
        blinding_privkey=recv_priv,
        expected_asset_id=_ASSET,
        expected_amount_sat=100_000,
    )
    assert obs is None
    assert err is not None
    assert "below minimum" in err


@pytest.mark.asyncio
async def test_admits_overpayment_when_no_max_set() -> None:
    """Without ``expected_max_amount_sat``, an overpayment is admitted."""
    backend = MockLiquidBackend()
    utxo, recv_priv = _build_blinded_utxo(amount_sat=200_000)
    backend.add_utxo(_SCRIPT, utxo)
    obs, err = await observe_and_validate_credit(
        backend=backend,
        lockup_script=_SCRIPT,
        blinding_privkey=recv_priv,
        expected_asset_id=_ASSET,
        expected_amount_sat=100_000,
    )
    assert err is None
    assert obs is not None
    assert obs.unblinded.value_sat == 200_000


@pytest.mark.asyncio
async def test_returns_error_on_overpayment_when_max_set() -> None:
    backend = MockLiquidBackend()
    utxo, recv_priv = _build_blinded_utxo(amount_sat=200_000)
    backend.add_utxo(_SCRIPT, utxo)
    obs, err = await observe_and_validate_credit(
        backend=backend,
        lockup_script=_SCRIPT,
        blinding_privkey=recv_priv,
        expected_asset_id=_ASSET,
        expected_amount_sat=100_000,
        expected_max_amount_sat=150_000,
    )
    assert obs is None
    assert err is not None
    assert "above maximum" in err


# ── Wrong-blinding-key paths ───────────────────────────────────────


@pytest.mark.asyncio
async def test_skips_utxos_not_for_us_returns_none_none() -> None:
    """A UTXO at our script that's blinded for a different key is
    silently skipped (not our credit). Observer reports no credit yet
    rather than flagging an error — defends against backend
    confusion."""
    backend = MockLiquidBackend()
    # The UTXO was built for a different receiver — our priv won't unblind it.
    utxo, _recv_priv = _build_blinded_utxo(amount_sat=100_000)
    backend.add_utxo(_SCRIPT, utxo)

    # Use a different blinding privkey on the observer side.
    wrong_priv = secrets.token_bytes(32)
    obs, err = await observe_and_validate_credit(
        backend=backend,
        lockup_script=_SCRIPT,
        blinding_privkey=wrong_priv,
        expected_asset_id=_ASSET,
        expected_amount_sat=100_000,
    )
    assert obs is None
    assert err is None  # silently skip


@pytest.mark.asyncio
async def test_picks_matching_utxo_among_multiple() -> None:
    """Backend returns multiple UTXOs (e.g., dust-attack noise). The
    observer skips the non-ours and returns the one we can unblind."""
    backend = MockLiquidBackend()
    # First UTXO: not for us
    dust, _ = _build_blinded_utxo(amount_sat=1_000, seed=b"\xee" * 64)
    backend.add_utxo(_SCRIPT, dust)
    # Second UTXO: for us, with the expected amount
    real, recv_priv = _build_blinded_utxo(amount_sat=100_000, seed=b"\x42" * 64)
    backend.add_utxo(_SCRIPT, real)

    obs, err = await observe_and_validate_credit(
        backend=backend,
        lockup_script=_SCRIPT,
        blinding_privkey=recv_priv,
        expected_asset_id=_ASSET,
        expected_amount_sat=100_000,
    )
    assert err is None
    assert obs is not None
    assert obs.unblinded.value_sat == 100_000


@pytest.mark.asyncio
async def test_validation_error_surfaces_even_if_other_utxos_present() -> None:
    """If a UTXO that unblinds for us has a wrong amount, surface
    that as an error even when another (non-ours) UTXO sits next to it.
    The wrong-amount unblind is intent-for-us evidence — we don't
    want to silently miss a swap-side bug."""
    backend = MockLiquidBackend()
    # Underpayment intended for us.
    bad, recv_priv = _build_blinded_utxo(amount_sat=50_000, seed=b"\x42" * 64)
    backend.add_utxo(_SCRIPT, bad)
    # Noise UTXO not for us.
    noise, _ = _build_blinded_utxo(amount_sat=1, seed=b"\xee" * 64)
    backend.add_utxo(_SCRIPT, noise)

    obs, err = await observe_and_validate_credit(
        backend=backend,
        lockup_script=_SCRIPT,
        blinding_privkey=recv_priv,
        expected_asset_id=_ASSET,
        expected_amount_sat=100_000,
    )
    assert obs is None
    assert err is not None
    assert "below minimum" in err
