# SPDX-License-Identifier: MIT
"""Tests for the residual L-BTC scan task.

Builds synthetic blinded L-BTC outputs at the wallet's per-session
SLIP-77-derived script and runs ``scan_residual_liquid_balances``
against a ``MockLiquidBackend``. Checks both the happy path
(insertion + idempotent re-scan) and the negative paths (non-L-BTC
asset, missing seed, backend error).

Persistence is exercised via the standard ``db_session`` fixture
so the SQLAlchemy ORM + UNIQUE(txid, vout) constraints are
real.
"""

from __future__ import annotations

import secrets
from uuid import uuid4

import pytest
import wallycore as _wally
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeStatus,
    LiquidResidualOutput,
)
from app.services.anonymize.liquid_address import LiquidNetwork
from app.services.anonymize.liquid_backend import LiquidUtxo, MockLiquidBackend
from app.services.anonymize.liquid_ct import (
    LBTC_ASSET_ID_MAINNET,
    derive_slip77_master_blinding_key,
)
from app.services.anonymize.liquid_seed import (
    derive_session_liquid_output,
    encrypt_session_blinding_seed_index,
)
from app.tasks.liquid_residual_scan import (
    ResidualScanSummary,
    scan_residual_liquid_balances,
    select_residual_scan_candidates,
)

_MASTER_SEED = b"\x42" * 64
_NETWORK = LiquidNetwork.MAINNET


def _master_blinding_key() -> bytes:
    return derive_slip77_master_blinding_key(_MASTER_SEED)


def _build_blinded_utxo_for(
    *,
    script: bytes,
    receiver_pub: bytes,
    asset_id: bytes,
    amount_sat: int,
    txid: str,
    vout: int = 0,
) -> LiquidUtxo:
    """Mint a blinded UTXO addressed to ``receiver_pub`` carrying
    ``amount_sat`` of ``asset_id`` at ``script``.
    """
    sender_priv = secrets.token_bytes(32)
    abf = secrets.token_bytes(32)
    vbf = secrets.token_bytes(32)
    asset_id_le = bytes(asset_id)[::-1]
    gen = bytes(_wally.asset_generator_from_bytes(asset_id_le, abf))
    comm = bytes(_wally.asset_value_commitment(amount_sat, vbf, gen))
    proof = bytes(
        _wally.asset_rangeproof(
            amount_sat,
            receiver_pub,
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
    return LiquidUtxo(
        txid=txid,
        vout=vout,
        script_pubkey=script,
        value_commitment=comm,
        asset_commitment=gen,
        nonce_commitment=nonce,
        rangeproof=proof,
        surjectionproof=b"",
        block_height=200,
    )


def _make_session(
    *,
    derivation_index: int = 0x12_3456,
    status: str = AnonymizeStatus.AWAITING_RECONCILIATION.value,
    with_seed: bool = True,
) -> AnonymizeSession:
    seed_enc = encrypt_session_blinding_seed_index(derivation_index) if with_seed else None
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="ext-lightning",
        requested_amount_sat=100_000,
        bin_amount_sat=100_000,
        pipeline_json={"uses_liquid": True},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct" * 16,
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        liquid_blinding_seed_enc=seed_enc,
    )


# ── Happy path ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_inserts_lbtc_residual(db_session: AsyncSession) -> None:
    session = _make_session(derivation_index=42)
    db_session.add(session)
    await db_session.commit()

    master = _master_blinding_key()
    material = derive_session_liquid_output(
        master_blinding_key=master,
        session_id=session.id,
        derivation_index=42,
        network=_NETWORK,
    )
    utxo = _build_blinded_utxo_for(
        script=material.script_pubkey,
        receiver_pub=material.blinding_pubkey,
        asset_id=LBTC_ASSET_ID_MAINNET,
        amount_sat=7_500,
        txid="cafebabe" * 8,
    )
    backend = MockLiquidBackend()
    backend.add_utxo(material.script_pubkey, utxo)

    summary = await scan_residual_liquid_balances(
        db=db_session,
        backend=backend,
        candidate_sessions=[session],
        master_blinding_key=master,
        network=_NETWORK,
        lbtc_asset_id=LBTC_ASSET_ID_MAINNET,
    )
    await db_session.commit()

    assert summary.sessions_scanned == 1
    assert summary.residuals_inserted == 1
    assert summary.residuals_seen_again == 0

    row = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.session_id == session.id))
    ).scalar_one()
    assert row.value_sat == 7_500
    assert row.asset_id == LBTC_ASSET_ID_MAINNET.hex()
    assert row.recovered_at is None
    assert row.dust_acknowledged_at is None
    assert row.address == material.ct_address
    assert str(session.id) in row.derivation_path


@pytest.mark.asyncio
async def test_rescan_is_idempotent(db_session: AsyncSession) -> None:
    """A second scan over the same UTXO must NOT insert a duplicate;
    it must just refresh ``last_seen_at``."""
    session = _make_session(derivation_index=99)
    db_session.add(session)
    await db_session.commit()
    master = _master_blinding_key()
    material = derive_session_liquid_output(
        master_blinding_key=master,
        session_id=session.id,
        derivation_index=99,
        network=_NETWORK,
    )
    utxo = _build_blinded_utxo_for(
        script=material.script_pubkey,
        receiver_pub=material.blinding_pubkey,
        asset_id=LBTC_ASSET_ID_MAINNET,
        amount_sat=12_000,
        txid="deadbeef" * 8,
    )
    backend = MockLiquidBackend()
    backend.add_utxo(material.script_pubkey, utxo)

    s1 = await scan_residual_liquid_balances(
        db=db_session,
        backend=backend,
        candidate_sessions=[session],
        master_blinding_key=master,
        network=_NETWORK,
        lbtc_asset_id=LBTC_ASSET_ID_MAINNET,
    )
    await db_session.commit()
    # Re-add the UTXO since MockLiquidBackend stores by script and
    # backend.add_utxo APPENDS — a second add would cause a dup.
    # Instead, re-build a fresh backend with the same UTXO.
    backend2 = MockLiquidBackend()
    backend2.add_utxo(material.script_pubkey, utxo)
    s2 = await scan_residual_liquid_balances(
        db=db_session,
        backend=backend2,
        candidate_sessions=[session],
        master_blinding_key=master,
        network=_NETWORK,
        lbtc_asset_id=LBTC_ASSET_ID_MAINNET,
    )
    await db_session.commit()

    assert s1.residuals_inserted == 1
    assert s2.residuals_inserted == 0
    assert s2.residuals_seen_again == 1
    rows = (
        (await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.session_id == session.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 1


# ── Skip / filter paths ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_skips_session_without_seed(db_session: AsyncSession) -> None:
    session = _make_session(with_seed=False)
    db_session.add(session)
    await db_session.commit()
    backend = MockLiquidBackend()

    summary = await scan_residual_liquid_balances(
        db=db_session,
        backend=backend,
        candidate_sessions=[session],
        master_blinding_key=_master_blinding_key(),
        network=_NETWORK,
        lbtc_asset_id=LBTC_ASSET_ID_MAINNET,
    )
    assert summary.sessions_scanned == 0
    assert summary.sessions_skipped == 1


@pytest.mark.asyncio
async def test_ignores_non_lbtc_output(db_session: AsyncSession) -> None:
    """A non-L-BTC asset at the wallet address is out of scope."""
    session = _make_session(derivation_index=7)
    db_session.add(session)
    await db_session.commit()
    master = _master_blinding_key()
    material = derive_session_liquid_output(
        master_blinding_key=master,
        session_id=session.id,
        derivation_index=7,
        network=_NETWORK,
    )
    other_asset = b"\xa5" * 32  # arbitrary non-L-BTC asset id
    utxo = _build_blinded_utxo_for(
        script=material.script_pubkey,
        receiver_pub=material.blinding_pubkey,
        asset_id=other_asset,
        amount_sat=50_000,
        txid="11" * 32,
    )
    backend = MockLiquidBackend()
    backend.add_utxo(material.script_pubkey, utxo)

    summary = await scan_residual_liquid_balances(
        db=db_session,
        backend=backend,
        candidate_sessions=[session],
        master_blinding_key=master,
        network=_NETWORK,
        lbtc_asset_id=LBTC_ASSET_ID_MAINNET,
    )
    await db_session.commit()
    assert summary.utxos_observed == 1
    assert summary.residuals_inserted == 0
    rows = (await db_session.execute(select(LiquidResidualOutput))).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_skips_utxo_from_unrelated_blinding_key(
    db_session: AsyncSession,
) -> None:
    """A UTXO at the same script but blinded to a different receiver
    pubkey must not be picked up as a residual."""
    session = _make_session(derivation_index=11)
    db_session.add(session)
    await db_session.commit()
    master = _master_blinding_key()
    material = derive_session_liquid_output(
        master_blinding_key=master,
        session_id=session.id,
        derivation_index=11,
        network=_NETWORK,
    )
    foreign_recv = _wally.ec_public_key_from_private_key(b"\x55" * 32)
    utxo = _build_blinded_utxo_for(
        script=material.script_pubkey,
        receiver_pub=bytes(foreign_recv),
        asset_id=LBTC_ASSET_ID_MAINNET,
        amount_sat=12_000,
        txid="22" * 32,
    )
    backend = MockLiquidBackend()
    backend.add_utxo(material.script_pubkey, utxo)

    summary = await scan_residual_liquid_balances(
        db=db_session,
        backend=backend,
        candidate_sessions=[session],
        master_blinding_key=master,
        network=_NETWORK,
        lbtc_asset_id=LBTC_ASSET_ID_MAINNET,
    )
    await db_session.commit()
    assert summary.utxos_observed == 1
    assert summary.residuals_inserted == 0


# ── Backend error path ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_backend_error_recorded_in_summary(
    db_session: AsyncSession,
) -> None:
    session = _make_session(derivation_index=3)
    db_session.add(session)
    await db_session.commit()
    backend = MockLiquidBackend()
    backend.fail("get_address_utxos", "rpc_timeout")

    summary = await scan_residual_liquid_balances(
        db=db_session,
        backend=backend,
        candidate_sessions=[session],
        master_blinding_key=_master_blinding_key(),
        network=_NETWORK,
        lbtc_asset_id=LBTC_ASSET_ID_MAINNET,
    )
    assert summary.sessions_scanned == 1
    assert summary.residuals_inserted == 0
    assert any("rpc_timeout" in e for e in summary.backend_errors)


# ── Candidate-selection helper ─────────────────────────────────────


@pytest.mark.asyncio
async def test_candidate_selection_filters_by_status_and_seed(
    db_session: AsyncSession,
) -> None:
    """The default selector picks terminal sessions with non-NULL
    ``liquid_blinding_seed_enc`` only — in-flight sessions (including
    ``awaiting_reconciliation``, whose own recovery loop may still touch
    the same output) are excluded so a live lockup is not swept twice."""
    s_terminal_with = _make_session(
        status=AnonymizeStatus.FAILED.value,
        derivation_index=1,
    )
    s_terminal_without = _make_session(
        status=AnonymizeStatus.FAILED.value,
        with_seed=False,
    )
    s_active = _make_session(
        status=AnonymizeStatus.HOPPING.value,
        derivation_index=2,
    )
    s_reconciling = _make_session(
        status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
        derivation_index=3,
    )
    db_session.add_all([s_terminal_with, s_terminal_without, s_active, s_reconciling])
    await db_session.commit()

    candidates = await select_residual_scan_candidates(db_session)
    ids = {c.id for c in candidates}
    assert s_terminal_with.id in ids
    assert s_terminal_without.id not in ids
    assert s_active.id not in ids
    # The non-terminal ``awaiting_reconciliation`` session must be excluded
    # by the default selector.
    assert s_reconciling.id not in ids


def test_summary_is_immutable_dataclass() -> None:
    s = ResidualScanSummary(sessions_scanned=3)
    with pytest.raises(Exception):
        s.sessions_scanned = 99  # type: ignore[misc]
