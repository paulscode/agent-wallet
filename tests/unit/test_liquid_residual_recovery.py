# SPDX-License-Identifier: MIT
"""Tests for the residual L-BTC -> LN recovery adapter.

Drives :func:`initiate_residual_recovery` against a pre-populated
``liquid_residual_outputs`` row + a mock Liquid backend carrying a
synthetic blinded L-BTC UTXO at the per-session SLIP-77-derived
script. All Boltz / LND / subprocess dependencies are injected as
fakes via :class:`ResidualRecoveryDeps`.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Optional
from uuid import uuid4

import pytest
import wallycore as _wally
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
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
from app.services.anonymize.liquid_lock_subprocess import (
    LiquidLockRequest,
    LiquidLockResult,
    LiquidLockSubprocessError,
)
from app.services.anonymize.liquid_residual_recovery import (
    ResidualRecoveryDeps,
    ResidualRecoveryError,
    ResidualRecoveryNotEligibleError,
    ResidualRecoveryNotFoundError,
    ResidualRecoveryResult,
    finalize_residual_recovery,
    initiate_residual_recovery,
)
from app.services.anonymize.liquid_seed import (
    derive_session_liquid_output,
    encrypt_session_blinding_seed_index,
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
    derivation_index: int,
    status: str = AnonymizeStatus.COMPLETED.value,
) -> AnonymizeSession:
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
        liquid_blinding_seed_enc=encrypt_session_blinding_seed_index(
            derivation_index,
        ),
    )


# ── Fakes ──────────────────────────────────────────────────────────


@dataclass
class _FakeSubmarineSwap:
    id: str
    address: str
    expected_amount_sat: int
    # Carried so the lockup verifier (stubbed in these tests) can be
    # invoked with the same arguments the production path uses.
    swap_tree: object = None
    claim_public_key_hex: str = "02" + "cc" * 32


@pytest.fixture(autouse=True)
def _stub_liquid_lockup_verifier(monkeypatch):
    """The recovery path verifies the Liquid lockup commits to our refund
    key via ``boltz-core``; these tests use synthetic swaps, so the
    cryptographic verifier is stubbed to accept. Its correctness is
    covered by ``tests/unit/test_anonymize_liquid_lockup_verify.py``."""
    monkeypatch.setattr(
        "app.services.anonymize.liquid_residual_recovery.verify_liquid_lockup_address",
        lambda **_kw: (True, "ok"),
    )


class _FakeSubmarineClient:
    def __init__(self, *, swap: _FakeSubmarineSwap | None = None, err: str | None = None) -> None:
        self._swap = swap
        self._err = err
        self.calls: list[dict[str, str]] = []

    async def create_submarine_swap_from_lbtc(
        self,
        *,
        invoice: str,
        refund_public_key_hex: str,
    ) -> tuple[Any, Optional[str]]:
        self.calls.append(
            {"invoice": invoice, "refund_pub": refund_public_key_hex},
        )
        if self._err is not None:
            return None, self._err
        return self._swap, None


def _make_invoice_creator(
    *,
    err: str | None = None,
    bolt11: str = "lnbc1pdummy",
    payment_hash: str = "ab" * 32,
):
    async def _create(*, amount_sat: int, memo: str):
        if err is not None:
            return None, err
        return {
            "bolt11": bolt11,
            "payment_hash": payment_hash,
            "amount_sat": amount_sat,
            "memo": memo,
        }, None

    return _create


def _make_lock_runner(
    *,
    txid: str = "ee" * 32,
    exc: Exception | None = None,
    captured: list[LiquidLockRequest] | None = None,
):
    async def _run(request: LiquidLockRequest) -> LiquidLockResult:
        if captured is not None:
            captured.append(request)
        if exc is not None:
            raise exc
        return LiquidLockResult(
            lock_tx_hex="deadbeef",
            txid=txid,
            raw_stdout_redacted=b"",
            raw_stderr_redacted=b"",
        )

    return _run


def _make_lookup_invoice(*, settled: bool, err: str | None = None):
    async def _lookup(payment_hash_hex: str):
        if err is not None:
            return None, err
        return {"settled": settled}, None

    return _lookup


def _make_deps(
    *,
    backend,
    submarine_client=None,
    invoice_creator=None,
    lock_runner=None,
    lnd_lookup_invoice=None,
    operator_fee_buffer_sat: int = 1000,
    broadcast: bool = True,
    fee_rate_sat_per_vb: float | None = 0.1,
) -> ResidualRecoveryDeps:
    return ResidualRecoveryDeps(
        backend=backend,
        submarine_client=submarine_client
        or _FakeSubmarineClient(
            swap=_FakeSubmarineSwap(
                id="boltz-swap-id",
                address="lq1lockup",
                expected_amount_sat=6_400,
            ),
        ),
        lnd_create_invoice=invoice_creator or _make_invoice_creator(),
        run_lock_subprocess=lock_runner or _make_lock_runner(),
        master_blinding_key=_master_blinding_key(),
        lbtc_asset_id=LBTC_ASSET_ID_MAINNET,
        network=_NETWORK,
        boltz_url="https://boltz.example",
        fee_rate_sat_per_vb=fee_rate_sat_per_vb,
        operator_fee_buffer_sat=operator_fee_buffer_sat,
        broadcast=broadcast,
        generate_swap_keypair=lambda: ("aa" * 32, "02" + "bb" * 32),
        lnd_lookup_invoice=lnd_lookup_invoice,
    )


async def _seed_session_and_residual(
    db: AsyncSession,
    *,
    derivation_index: int = 0xDEADBE,
    value_sat: int = 7_500,
    txid: str = "ab" * 32,
    vout: int = 0,
    status: str = AnonymizeStatus.COMPLETED.value,
) -> tuple[AnonymizeSession, LiquidResidualOutput, Any]:
    session = _make_session(derivation_index=derivation_index, status=status)
    db.add(session)
    await db.commit()

    master = _master_blinding_key()
    material = derive_session_liquid_output(
        master_blinding_key=master,
        session_id=session.id,
        derivation_index=derivation_index,
        network=_NETWORK,
    )
    utxo = _build_blinded_utxo_for(
        script=material.script_pubkey,
        receiver_pub=material.blinding_pubkey,
        asset_id=LBTC_ASSET_ID_MAINNET,
        amount_sat=value_sat,
        txid=txid,
        vout=vout,
    )
    row = LiquidResidualOutput(
        id=uuid4(),
        session_id=session.id,
        txid=txid,
        vout=vout,
        asset_id=LBTC_ASSET_ID_MAINNET.hex(),
        value_sat=value_sat,
        address=material.ct_address,
        derivation_path=f"anonymize-liquid-spend|{session.id}|{derivation_index}",
    )
    db.add(row)
    await db.commit()
    return session, row, (material, utxo)


def _backend_with(material, utxo) -> MockLiquidBackend:
    backend = MockLiquidBackend()
    backend.add_utxo(material.script_pubkey, utxo)
    # The recovery adapter fetches the prevout tx hex so the lock
    # subprocess can reconstruct input commitments. The exact bytes
    # don't matter to these unit tests because the subprocess itself
    # is faked — but the backend must return *something* non-empty.
    backend.add_transaction(utxo.txid, "ca" * 100)
    return backend


# ── Tests ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_initiate_refuses_on_failed_lockup_verification(
    db_session: AsyncSession,
    monkeypatch,
) -> None:
    """If the operator-returned lockup does not commit to our refund key,
    recovery refuses before broadcasting the L-BTC lock — no funding of an
    operator-controlled address (same theft guard as the live hop)."""
    monkeypatch.setattr(
        "app.services.anonymize.liquid_residual_recovery.verify_liquid_lockup_address",
        lambda **_kw: (False, "refund_leaf_mismatch"),
    )
    session, row, (material, utxo) = await _seed_session_and_residual(db_session)
    backend = _backend_with(material, utxo)

    lock_calls: list[object] = []

    async def _spy_lock(request):  # noqa: ANN001
        lock_calls.append(request)
        raise AssertionError("lock subprocess must not run on failed verification")

    deps = _make_deps(backend=backend, lock_runner=_spy_lock)

    with pytest.raises(ResidualRecoveryError, match="lockup verification failed"):
        await initiate_residual_recovery(db=db_session, residual_id=row.id, deps=deps)
    assert lock_calls == []


@pytest.mark.asyncio
async def test_initiate_reserves_swap_id_before_broadcast(db_session: AsyncSession) -> None:
    """The swap id is committed to the row before the lock spend broadcasts,
    so a crash in that window cannot leave the residual eligible for a second
    swap-out of the same UTXO."""
    session, row, (material, utxo) = await _seed_session_and_residual(db_session)
    backend = _backend_with(material, utxo)

    observed: dict[str, object] = {}

    async def _checking_lock(request):  # noqa: ANN001
        refreshed = (
            await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
        ).scalar_one()
        observed["swap_id_at_broadcast"] = refreshed.recovered_swap_id
        return LiquidLockResult(
            lock_tx_hex="deadbeef",
            txid="ee" * 32,
            raw_stdout_redacted=b"",
            raw_stderr_redacted=b"",
        )

    deps = _make_deps(backend=backend, lock_runner=_checking_lock)
    await initiate_residual_recovery(db=db_session, residual_id=row.id, deps=deps)
    assert observed["swap_id_at_broadcast"] == "boltz-swap-id"


@pytest.mark.asyncio
async def test_initiate_clean_lock_failure_releases_reservation(db_session: AsyncSession) -> None:
    """A clean broadcast failure releases the pre-broadcast reservation so the
    residual can be retried (only a hard crash leaves it stamped)."""
    from app.services.anonymize.liquid_lock_subprocess import LiquidLockSubprocessError

    session, row, (material, utxo) = await _seed_session_and_residual(db_session)
    backend = _backend_with(material, utxo)
    deps = _make_deps(
        backend=backend,
        lock_runner=_make_lock_runner(exc=LiquidLockSubprocessError("broadcast refused")),
    )

    with pytest.raises(ResidualRecoveryError):
        await initiate_residual_recovery(db=db_session, residual_id=row.id, deps=deps)

    refreshed = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert refreshed.recovered_swap_id is None


@pytest.mark.asyncio
async def test_initiate_happy_path(db_session: AsyncSession) -> None:
    session, row, (material, utxo) = await _seed_session_and_residual(
        db_session,
    )
    backend = _backend_with(material, utxo)
    deps = _make_deps(backend=backend)

    result = await initiate_residual_recovery(
        db=db_session,
        residual_id=row.id,
        deps=deps,
    )
    await db_session.commit()

    assert isinstance(result, ResidualRecoveryResult)
    assert result.swap_id == "boltz-swap-id"
    assert result.lockup_address == "lq1lockup"
    assert result.lockup_txid == "ee" * 32
    assert result.expected_amount_sat == 6_400
    assert result.recovered_at_set is False

    refreshed = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert refreshed.recovered_swap_id == "boltz-swap-id"
    assert refreshed.recovered_at is None


@pytest.mark.asyncio
async def test_initiate_settled_invoice_stamps_recovered_at(
    db_session: AsyncSession,
) -> None:
    _, row, (material, utxo) = await _seed_session_and_residual(db_session)
    backend = _backend_with(material, utxo)
    deps = _make_deps(
        backend=backend,
        lnd_lookup_invoice=_make_lookup_invoice(settled=True),
    )

    result = await initiate_residual_recovery(
        db=db_session,
        residual_id=row.id,
        deps=deps,
    )
    await db_session.commit()

    assert result.recovered_at_set is True
    refreshed = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert refreshed.recovered_at is not None


@pytest.mark.asyncio
async def test_initiate_rejects_already_recovered(
    db_session: AsyncSession,
) -> None:
    from datetime import datetime, timezone

    _, row, (material, utxo) = await _seed_session_and_residual(db_session)
    row.recovered_at = datetime.now(timezone.utc)
    row.recovered_swap_id = "previous-swap"
    await db_session.commit()
    backend = _backend_with(material, utxo)
    deps = _make_deps(backend=backend)

    with pytest.raises(ResidualRecoveryNotEligibleError, match="already recovered"):
        await initiate_residual_recovery(
            db=db_session,
            residual_id=row.id,
            deps=deps,
        )


@pytest.mark.asyncio
async def test_initiate_rejects_below_dust_threshold(
    db_session: AsyncSession,
) -> None:
    threshold = int(settings.liquid_residual_dust_threshold_sat)
    _, row, (material, utxo) = await _seed_session_and_residual(
        db_session,
        value_sat=threshold - 1,
    )
    backend = _backend_with(material, utxo)
    deps = _make_deps(backend=backend)

    with pytest.raises(ResidualRecoveryNotEligibleError, match="dust threshold"):
        await initiate_residual_recovery(
            db=db_session,
            residual_id=row.id,
            deps=deps,
        )


@pytest.mark.asyncio
async def test_initiate_rejects_orphaned_residual(
    db_session: AsyncSession,
) -> None:
    """session_id NULL (session was retention-purged) → not eligible."""
    row = LiquidResidualOutput(
        id=uuid4(),
        session_id=None,
        txid="11" * 32,
        vout=0,
        asset_id=LBTC_ASSET_ID_MAINNET.hex(),
        value_sat=10_000,
        address="lq1orphan",
        derivation_path="anonymize-liquid-spend|?|0",
    )
    db_session.add(row)
    await db_session.commit()
    deps = _make_deps(backend=MockLiquidBackend())

    with pytest.raises(ResidualRecoveryNotEligibleError, match="session_id"):
        await initiate_residual_recovery(
            db=db_session,
            residual_id=row.id,
            deps=deps,
        )


@pytest.mark.asyncio
async def test_initiate_unknown_residual(db_session: AsyncSession) -> None:
    deps = _make_deps(backend=MockLiquidBackend())
    with pytest.raises(ResidualRecoveryNotFoundError):
        await initiate_residual_recovery(
            db=db_session,
            residual_id=uuid4(),
            deps=deps,
        )


@pytest.mark.asyncio
async def test_initiate_utxo_no_longer_on_chain(
    db_session: AsyncSession,
) -> None:
    """If the residual was spent by another flow, the backend won't
    list it — must raise without mutating the row."""
    _, row, _ = await _seed_session_and_residual(db_session)
    backend = MockLiquidBackend()  # no UTXOs registered
    deps = _make_deps(backend=backend)

    with pytest.raises(ResidualRecoveryError, match="does not list residual"):
        await initiate_residual_recovery(
            db=db_session,
            residual_id=row.id,
            deps=deps,
        )
    refreshed = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert refreshed.recovered_swap_id is None


@pytest.mark.asyncio
async def test_initiate_lock_subprocess_failure_leaves_row_unchanged(
    db_session: AsyncSession,
) -> None:
    _, row, (material, utxo) = await _seed_session_and_residual(db_session)
    backend = _backend_with(material, utxo)
    deps = _make_deps(
        backend=backend,
        lock_runner=_make_lock_runner(
            exc=LiquidLockSubprocessError("broadcast_failed"),
        ),
    )

    with pytest.raises(ResidualRecoveryError, match="broadcast_failed"):
        await initiate_residual_recovery(
            db=db_session,
            residual_id=row.id,
            deps=deps,
        )
    refreshed = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert refreshed.recovered_swap_id is None


@pytest.mark.asyncio
async def test_initiate_dry_run_skips_broadcast(
    db_session: AsyncSession,
) -> None:
    _, row, (material, utxo) = await _seed_session_and_residual(db_session)
    backend = _backend_with(material, utxo)
    captured: list[LiquidLockRequest] = []
    deps = _make_deps(
        backend=backend,
        broadcast=False,
        lock_runner=_make_lock_runner(captured=captured),
    )

    result = await initiate_residual_recovery(
        db=db_session,
        residual_id=row.id,
        deps=deps,
    )
    await db_session.commit()

    assert captured == []  # subprocess never called
    assert result.lockup_txid == ""
    refreshed = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert refreshed.recovered_swap_id == "boltz-swap-id"


@pytest.mark.asyncio
async def test_initiate_lock_request_carries_recovered_material(
    db_session: AsyncSession,
) -> None:
    """The lock subprocess request must carry the freshly-recomputed
    ABF/VBF + the per-session spending key — not whatever was on
    the row (which carries none of that)."""
    _, row, (material, utxo) = await _seed_session_and_residual(db_session)
    backend = _backend_with(material, utxo)
    captured: list[LiquidLockRequest] = []
    deps = _make_deps(
        backend=backend,
        lock_runner=_make_lock_runner(captured=captured),
    )

    await initiate_residual_recovery(
        db=db_session,
        residual_id=row.id,
        deps=deps,
    )

    assert len(captured) == 1
    req = captured[0]
    assert req.utxo_txid == row.txid
    assert req.utxo_vout == row.vout
    assert req.utxo_value_sat == row.value_sat
    assert req.spending_private_key_hex == material.spending_privkey.hex()
    assert req.utxo_script_pubkey_hex == material.script_pubkey.hex()
    assert req.destination_address == "lq1lockup"
    assert req.destination_amount_sat == 6_400
    # ABF + VBF are 32-byte hex blobs from the unblinding step.
    assert len(req.utxo_asset_blinding_factor_hex) == 64
    assert len(req.utxo_value_blinding_factor_hex) == 64


@pytest.mark.asyncio
async def test_finalize_residual_recovery_stamps_when_settled(
    db_session: AsyncSession,
) -> None:
    _, row, _ = await _seed_session_and_residual(db_session)
    row.recovered_swap_id = "boltz-swap-id"
    await db_session.commit()

    stamped = await finalize_residual_recovery(
        db=db_session,
        residual_id=row.id,
        lnd_lookup_invoice=_make_lookup_invoice(settled=True),
        payment_hash_hex="ab" * 32,
    )
    await db_session.commit()
    assert stamped is True
    refreshed = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert refreshed.recovered_at is not None


@pytest.mark.asyncio
async def test_finalize_residual_recovery_returns_false_when_unsettled(
    db_session: AsyncSession,
) -> None:
    _, row, _ = await _seed_session_and_residual(db_session)
    row.recovered_swap_id = "boltz-swap-id"
    await db_session.commit()

    stamped = await finalize_residual_recovery(
        db=db_session,
        residual_id=row.id,
        lnd_lookup_invoice=_make_lookup_invoice(settled=False),
        payment_hash_hex="ab" * 32,
    )
    assert stamped is False
    refreshed = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert refreshed.recovered_at is None


@pytest.mark.asyncio
async def test_finalize_residual_recovery_idempotent_after_recovered(
    db_session: AsyncSession,
) -> None:
    from datetime import datetime, timezone

    _, row, _ = await _seed_session_and_residual(db_session)
    original_stamp = datetime.now(timezone.utc)
    row.recovered_swap_id = "boltz-swap-id"
    row.recovered_at = original_stamp
    await db_session.commit()

    stamped = await finalize_residual_recovery(
        db=db_session,
        residual_id=row.id,
        lnd_lookup_invoice=_make_lookup_invoice(settled=False),
        payment_hash_hex="ab" * 32,
    )
    assert stamped is True  # already-recovered short-circuits to True


@pytest.mark.asyncio
async def test_initiate_requires_terminal_session(
    db_session: AsyncSession,
) -> None:
    """Recovery is only safe once the originating session is quiesced; a
    session still in flight (its own hop / recovery loop may touch the same
    L-BTC output) is refused before any swap or broadcast."""
    session, row, (material, utxo) = await _seed_session_and_residual(
        db_session,
        status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
    )
    backend = _backend_with(material, utxo)

    lock_calls: list[object] = []

    async def _spy_lock(request):  # noqa: ANN001
        lock_calls.append(request)
        raise AssertionError("must not broadcast for a non-terminal session")

    deps = _make_deps(backend=backend, lock_runner=_spy_lock)

    with pytest.raises(ResidualRecoveryNotEligibleError, match="still in flight"):
        await initiate_residual_recovery(db=db_session, residual_id=row.id, deps=deps)
    assert lock_calls == []

    refreshed = (
        await db_session.execute(select(LiquidResidualOutput).where(LiquidResidualOutput.id == row.id))
    ).scalar_one()
    assert refreshed.recovered_swap_id is None


@pytest.mark.asyncio
async def test_initiate_rejects_oversized_operator_lockup(
    db_session: AsyncSession,
) -> None:
    """The operator-returned lockup amount may not exceed the residual
    value (we cannot lock more than the UTXO holds); an out-of-range
    ``expected_amount_sat`` is refused before broadcasting."""
    session, row, (material, utxo) = await _seed_session_and_residual(
        db_session,
        value_sat=7_500,
    )
    backend = _backend_with(material, utxo)

    lock_calls: list[object] = []

    async def _spy_lock(request):  # noqa: ANN001
        lock_calls.append(request)
        raise AssertionError("must not broadcast an oversized operator lockup")

    deps = _make_deps(
        backend=backend,
        submarine_client=_FakeSubmarineClient(
            swap=_FakeSubmarineSwap(
                id="boltz-swap-id",
                address="lq1lockup",
                expected_amount_sat=8_000,  # > value_sat
            ),
        ),
        lock_runner=_spy_lock,
    )

    with pytest.raises(ResidualRecoveryError, match="out of range"):
        await initiate_residual_recovery(db=db_session, residual_id=row.id, deps=deps)
    assert lock_calls == []
