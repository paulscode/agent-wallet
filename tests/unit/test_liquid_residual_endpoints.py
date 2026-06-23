# SPDX-License-Identifier: MIT
"""Tests for the residual L-BTC recovery dashboard endpoints.

Covers the four endpoints added under ``/anonymize/liquid-residuals/``:

* ``GET   /anonymize/liquid-residuals``
* ``POST  /anonymize/liquid-residuals/{id}/swap-out``
* ``POST  /anonymize/liquid-residuals/{id}/acknowledge-dust``
* ``POST  /anonymize/liquid-residuals/{id}/unacknowledge-dust``

The deps factory used by the swap-out endpoint is monkey-patched
to inject a fake ``ResidualRecoveryDeps`` so the test does not
require a live electrs-liquid or Boltz client.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

import pytest
import wallycore as _wally
from fastapi.responses import JSONResponse
from sqlalchemy import select

from app.core.config import settings
from app.dashboard import api as dash_api
from app.dashboard.api import (
    dash_anonymize_liquid_residual_acknowledge_dust,
    dash_anonymize_liquid_residual_swap_out,
    dash_anonymize_liquid_residual_unacknowledge_dust,
    dash_anonymize_liquid_residuals_list,
)
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
    LiquidResidualOutput,
)
from app.services.anonymize.liquid_address import LiquidNetwork
from app.services.anonymize.liquid_backend import LiquidUtxo, MockLiquidBackend
from app.services.anonymize.liquid_ct import (
    LBTC_ASSET_ID_MAINNET,
    derive_slip77_master_blinding_key,
)
from app.services.anonymize.liquid_lock_subprocess import (
    LiquidLockRequest,
    LiquidLockResult,
)
from app.services.anonymize.liquid_residual_recovery import (
    ResidualRecoveryDeps,
)
from app.services.anonymize.liquid_seed import (
    derive_session_liquid_output,
    encrypt_session_blinding_seed_index,
)

_MASTER_SEED = b"\x42" * 64
_NETWORK = LiquidNetwork.MAINNET


@pytest.fixture(autouse=True)
def _enable_anonymize(monkeypatch):
    monkeypatch.setattr(settings, "anonymize_enabled", True)


def _master_blinding_key() -> bytes:
    return derive_slip77_master_blinding_key(_MASTER_SEED)


def _build_blinded_utxo_for(
    *,
    script,
    receiver_pub,
    asset_id,
    amount_sat,
    txid,
    vout=0,
):
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


@dataclass
class _FakeSubmarineSwap:
    id: str
    address: str
    expected_amount_sat: int
    swap_tree: object = None
    claim_public_key_hex: str = "02" + "cc" * 32


@pytest.fixture(autouse=True)
def _stub_liquid_lockup_verifier(monkeypatch):
    """Synthetic swaps here can't satisfy the real ``boltz-core`` lockup
    verifier (covered by its own round-trip test); stub it to accept."""
    monkeypatch.setattr(
        "app.services.anonymize.liquid_residual_recovery.verify_liquid_lockup_address",
        lambda **_kw: (True, "ok"),
    )


class _FakeSubmarineClient:
    async def create_submarine_swap_from_lbtc(
        self,
        *,
        invoice: str,
        refund_public_key_hex: str,
    ) -> tuple[Any, Optional[str]]:
        return _FakeSubmarineSwap(
            id="boltz-recovery-swap",
            address="lq1lockup",
            expected_amount_sat=6_400,
        ), None


def _make_invoice_creator():
    async def _create(*, amount_sat: int, memo: str):
        return {"bolt11": "lnbc", "payment_hash": "ab" * 32}, None

    return _create


def _make_lock_runner():
    async def _run(request: LiquidLockRequest) -> LiquidLockResult:
        return LiquidLockResult(
            lock_tx_hex="deadbeef",
            txid="ee" * 32,
            raw_stdout_redacted=b"",
            raw_stderr_redacted=b"",
        )

    return _run


async def _seed(
    db_session,
    *,
    derivation_index=0xC0FFEE,
    value_sat=7_500,
    status=AnonymizeStatus.COMPLETED.value,
):
    txid = secrets.token_hex(32)
    sess = AnonymizeSession(
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
        liquid_blinding_seed_enc=encrypt_session_blinding_seed_index(
            derivation_index,
        ),
    )
    db_session.add(sess)
    await db_session.commit()

    master = _master_blinding_key()
    material = derive_session_liquid_output(
        master_blinding_key=master,
        session_id=sess.id,
        derivation_index=derivation_index,
        network=_NETWORK,
    )
    utxo = _build_blinded_utxo_for(
        script=material.script_pubkey,
        receiver_pub=material.blinding_pubkey,
        asset_id=LBTC_ASSET_ID_MAINNET,
        amount_sat=value_sat,
        txid=txid,
    )
    row = LiquidResidualOutput(
        id=uuid4(),
        session_id=sess.id,
        txid=utxo.txid,
        vout=0,
        asset_id=LBTC_ASSET_ID_MAINNET.hex(),
        value_sat=value_sat,
        address=material.ct_address,
        derivation_path=f"anonymize-liquid-spend|{sess.id}|{derivation_index}",
    )
    db_session.add(row)
    await db_session.commit()
    return sess, row, material, utxo


def _patch_deps(monkeypatch, deps_or_factory):
    """Bind the deps factory used by the swap-out endpoint."""
    if callable(deps_or_factory):
        monkeypatch.setattr(
            dash_api,
            "_residual_recovery_deps_factory",
            deps_or_factory,
        )
    else:
        monkeypatch.setattr(
            dash_api,
            "_residual_recovery_deps_factory",
            lambda: deps_or_factory,
        )


def _build_deps(material, utxo) -> ResidualRecoveryDeps:
    backend = MockLiquidBackend()
    backend.add_utxo(material.script_pubkey, utxo)
    backend.add_transaction(utxo.txid, "ca" * 100)
    return ResidualRecoveryDeps(
        backend=backend,
        submarine_client=_FakeSubmarineClient(),
        lnd_create_invoice=_make_invoice_creator(),
        run_lock_subprocess=_make_lock_runner(),
        master_blinding_key=_master_blinding_key(),
        lbtc_asset_id=LBTC_ASSET_ID_MAINNET,
        network=_NETWORK,
        boltz_url="https://boltz.example",
        fee_rate_sat_per_vb=0.1,
        operator_fee_buffer_sat=1000,
        generate_swap_keypair=lambda: ("aa" * 32, "02" + "bb" * 32),
    )


# ── GET list ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_returns_pending_and_dust_rows(db_session) -> None:
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    _, recoverable, _, _ = await _seed(
        db_session,
        derivation_index=1,
        value_sat=threshold + 100,
    )
    _, dusty, _, _ = await _seed(
        db_session,
        derivation_index=2,
        value_sat=threshold - 100,
    )
    # And one already-recovered row that must be excluded.
    _, recovered, _, _ = await _seed(
        db_session,
        derivation_index=3,
        value_sat=threshold + 200,
    )
    recovered.recovered_at = datetime.now(timezone.utc)
    recovered.recovered_swap_id = "old"
    await db_session.commit()

    payload = await dash_anonymize_liquid_residuals_list(db=db_session)
    ids = {r["id"] for r in payload["rows"]}
    assert str(recoverable.id) in ids
    assert str(dusty.id) in ids
    assert str(recovered.id) not in ids
    assert payload["recoverable_count"] == 1
    assert payload["dust_threshold_sat"] == threshold


@pytest.mark.asyncio
async def test_list_excludes_acknowledged_dust(db_session) -> None:
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    _, dusty, _, _ = await _seed(
        db_session,
        derivation_index=1,
        value_sat=threshold - 1,
    )
    dusty.dust_acknowledged_at = datetime.now(timezone.utc)
    await db_session.commit()

    payload = await dash_anonymize_liquid_residuals_list(db=db_session)
    assert payload["rows"] == []


@pytest.mark.asyncio
async def test_list_404_when_anonymize_disabled(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_enabled", False)
    resp = await dash_anonymize_liquid_residuals_list(db=db_session)
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 404


# ── POST swap-out ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_swap_out_drives_recovery_and_emits_audit_event(
    db_session,
    monkeypatch,
) -> None:
    sess, row, material, utxo = await _seed(db_session)
    _patch_deps(monkeypatch, _build_deps(material, utxo))

    payload = await dash_anonymize_liquid_residual_swap_out(
        residual_id=str(row.id),
        db=db_session,
    )
    assert payload["swap_id"] == "boltz-recovery-swap"
    assert payload["lockup_txid"] == "ee" * 32

    refreshed = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert refreshed.recovered_swap_id == "boltz-recovery-swap"

    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent)
                .where(AnonymizeSessionEvent.session_id == sess.id)
                .where(AnonymizeSessionEvent.kind == "liquid_residual_swap_out_initiated")
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].detail_json["swap_id"] == "boltz-recovery-swap"
    assert events[0].detail_json["residual_id"] == str(row.id)


@pytest.mark.asyncio
async def test_swap_out_409_when_liquid_disabled(
    db_session,
    monkeypatch,
) -> None:
    _, row, _, _ = await _seed(db_session)
    monkeypatch.setattr(
        dash_api,
        "_residual_recovery_deps_factory",
        lambda: None,
    )

    resp = await dash_anonymize_liquid_residual_swap_out(
        residual_id=str(row.id),
        db=db_session,
    )
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 409
    assert b"liquid_disabled" in resp.body


@pytest.mark.asyncio
async def test_swap_out_409_for_dust_row(
    db_session,
    monkeypatch,
) -> None:
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    _, row, material, utxo = await _seed(
        db_session,
        value_sat=threshold - 1,
    )
    _patch_deps(monkeypatch, _build_deps(material, utxo))

    resp = await dash_anonymize_liquid_residual_swap_out(
        residual_id=str(row.id),
        db=db_session,
    )
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 409
    assert b"not_eligible" in resp.body


@pytest.mark.asyncio
async def test_swap_out_404_for_unknown_residual(
    db_session,
    monkeypatch,
) -> None:
    _patch_deps(monkeypatch, _build_deps.__wrapped__ if False else None)  # noqa
    # Bind a no-op factory; the endpoint must short-circuit on the
    # 404 before consulting the deps.
    monkeypatch.setattr(
        dash_api,
        "_residual_recovery_deps_factory",
        lambda: None,
    )
    try:
        await dash_anonymize_liquid_residual_swap_out(
            residual_id=str(uuid4()),
            db=db_session,
        )
    except Exception as exc:  # HTTPException
        assert getattr(exc, "status_code", None) == 404
    else:
        pytest.fail("expected HTTPException(404)")


# ── POST acknowledge-dust / unacknowledge-dust ───────────────────────


@pytest.mark.asyncio
async def test_acknowledge_dust_stamps_row(db_session) -> None:
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    sess, row, _, _ = await _seed(db_session, value_sat=threshold - 1)

    payload = await dash_anonymize_liquid_residual_acknowledge_dust(
        residual_id=str(row.id),
        db=db_session,
    )
    assert payload["dust_acknowledged_at"] is not None

    refreshed = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert refreshed.dust_acknowledged_at is not None

    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent)
                .where(AnonymizeSessionEvent.session_id == sess.id)
                .where(AnonymizeSessionEvent.kind == "liquid_residual_dust_acknowledged")
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1


@pytest.mark.asyncio
async def test_acknowledge_dust_409_for_above_threshold(db_session) -> None:
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    _, row, _, _ = await _seed(db_session, value_sat=threshold + 1)

    resp = await dash_anonymize_liquid_residual_acknowledge_dust(
        residual_id=str(row.id),
        db=db_session,
    )
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 409
    assert b"above_threshold" in resp.body


@pytest.mark.asyncio
async def test_acknowledge_dust_409_when_already_recovered(
    db_session,
) -> None:
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    _, row, _, _ = await _seed(db_session, value_sat=threshold - 1)
    row.recovered_at = datetime.now(timezone.utc)
    row.recovered_swap_id = "old"
    await db_session.commit()

    resp = await dash_anonymize_liquid_residual_acknowledge_dust(
        residual_id=str(row.id),
        db=db_session,
    )
    assert isinstance(resp, JSONResponse)
    assert resp.status_code == 409
    assert b"already_recovered" in resp.body


@pytest.mark.asyncio
async def test_unacknowledge_dust_clears_stamp(db_session) -> None:
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    sess, row, _, _ = await _seed(db_session, value_sat=threshold - 1)
    row.dust_acknowledged_at = datetime.now(timezone.utc)
    await db_session.commit()

    payload = await dash_anonymize_liquid_residual_unacknowledge_dust(
        residual_id=str(row.id),
        db=db_session,
    )
    assert payload["dust_acknowledged_at"] is None

    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent)
                .where(AnonymizeSessionEvent.session_id == sess.id)
                .where(AnonymizeSessionEvent.kind == "liquid_residual_dust_unacknowledged")
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1


@pytest.mark.asyncio
async def test_unacknowledge_dust_is_noop_when_not_acknowledged(
    db_session,
) -> None:
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    _, row, _, _ = await _seed(db_session, value_sat=threshold - 1)

    payload = await dash_anonymize_liquid_residual_unacknowledge_dust(
        residual_id=str(row.id),
        db=db_session,
    )
    assert payload["dust_acknowledged_at"] is None
