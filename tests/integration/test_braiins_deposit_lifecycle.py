# SPDX-License-Identifier: MIT
"""
End-to-end lifecycle test for a Braiins deposit (Lightning source), driven
through the real ``BraiinsDepositService.advance`` state machine one tick
at a time against in-process fakes.

This drives the full chain CREATED → SWAPPING → FUNDED → BROADCAST →
COMPLETED in a single flow — the gap the per-transition unit tests leave.
The Boltz reverse-swap completion (which has its own lifecycle E2E) is
simulated by flipping the linked swap row between ticks; everything else
runs for real: session creation, the advance() dispatch + state machine,
DB persistence, status history, and the terminal projection.
"""

from uuid import uuid4

import pytest

from app.models.boltz_swap import SwapStatus
from app.models.braiins_deposit_session import (
    BraiinsDepositSourceKind,
    BraiinsDepositStatus,
)
from app.services.braiins_deposit_service import BraiinsDepositService
from tests import helpers
from tests._fake_lnd import FakeLndService
from tests.helpers import make_boltz_swap

_FRESH = "bcrt1pfreshtaprootaddress"
_CLAIM_TXID = "cc" * 32
_SEND_TXID = "5e" * 32
_DEST = "bc1q" + "x" * 38


class _FakeBoltzForBraiins:
    """Service-level Boltz fake: creates/returns a real BoltzSwap row and
    serves pair info. The swap's own progression is simulated by the test
    (it has a dedicated lifecycle E2E)."""

    def __init__(self) -> None:
        self.created_swap = None

    async def get_reverse_pair_info(self):
        return helpers.boltz_reverse_pair_info(), None

    async def get_submarine_pair_info(self):
        return helpers.boltz_submarine_pair_info(), None

    async def create_reverse_swap(
        self, db, api_key_id, invoice_amount_sats, destination_address, outgoing_chan_id=None
    ):
        swap = make_boltz_swap(
            status=SwapStatus.CREATED,
            claim_txid=None,
            api_key_id=api_key_id,
            invoice_amount_sats=invoice_amount_sats,
            destination_address=destination_address,
        )
        db.add(swap)
        await db.commit()
        self.created_swap = swap
        return swap, None


class _FakeMempool:
    def __init__(self) -> None:
        self.confs = None  # set by the test to drive BROADCAST → COMPLETED
        self._tip = 900_000

    async def get_recommended_fees(self):
        return {"fastestFee": 20, "halfHourFee": 6, "hourFee": 2}, None

    async def optional_confirmations(self, txid):
        return self.confs

    @property
    def cached_tip_height(self):
        return self._tip


@pytest.mark.asyncio
async def test_full_lightning_deposit_reaches_completed(db_session):
    lnd = FakeLndService(fresh_address=_FRESH)
    boltz = _FakeBoltzForBraiins()
    mempool = _FakeMempool()
    svc = BraiinsDepositService(boltz_service=boltz, lnd_service=lnd, mempool_fee_service=mempool)

    # ── create ────────────────────────────────────────────────────────
    session, err = await svc.create_session(
        db_session,
        api_key_id=uuid4(),
        amount_sats=1_000_000,
        destination_address=_DEST,
        source_kind=BraiinsDepositSourceKind.LIGHTNING.value,
        include_extras=False,  # legacy exact-amount send (no dust_safe_send dep)
    )
    assert err is None and session is not None
    assert session.status == BraiinsDepositStatus.CREATED

    # ── tick 1: CREATED → SWAPPING (mint address + create reverse swap) ─
    s = await svc.advance(db_session, session.id)
    assert s.status == BraiinsDepositStatus.SWAPPING
    assert s.fresh_address == _FRESH
    assert s.boltz_swap_id == boltz.created_swap.id
    assert lnd.called("new_address")

    # Simulate the Boltz swap completing (its own lifecycle is E2E-tested
    # separately): claim broadcast on-chain to the fresh address.
    swap = boltz.created_swap
    swap.status = SwapStatus.COMPLETED
    swap.claim_txid = _CLAIM_TXID
    await db_session.commit()
    lnd.set_result(
        "list_unspent",
        [
            {
                "outpoint": {"txid_str": _CLAIM_TXID, "output_index": 0},
                "amount_sat": 1_004_000,
                "address": _FRESH,
                "address_type": "TAPROOT",
                "pk_script": "",
                "confirmations": 6,
            }
        ],
    )

    # ── tick 2: SWAPPING → FUNDED (project the claim outpoint) ──────────
    s = await svc.advance(db_session, session.id)
    assert s.status == BraiinsDepositStatus.FUNDED
    assert s.fresh_utxo_txid == _CLAIM_TXID
    assert s.fresh_utxo_vout == 0
    assert s.fresh_utxo_amount_sats == 1_004_000

    # ── tick 3: FUNDED → BROADCAST (send to Braiins) ───────────────────
    lnd.set_result("send_coins", {"txid": _SEND_TXID})
    s = await svc.advance(db_session, session.id)
    assert s.status == BraiinsDepositStatus.BROADCAST
    assert s.send_txid == _SEND_TXID
    assert lnd.called("send_coins")

    # ── tick 4: BROADCAST → COMPLETED (send tx confirms) ───────────────
    mempool.confs = {"confirmations": 1, "confirmed": True}
    s = await svc.advance(db_session, session.id)
    assert s.status == BraiinsDepositStatus.COMPLETED
    assert s.completed_at is not None

    # The status history records the full forward path.
    statuses = [e.get("status") for e in (s.status_history or [])]
    for expected in ("swapping", "funded", "broadcast", "completed"):
        assert expected in statuses


@pytest.mark.asyncio
async def test_created_fails_when_address_minting_fails(db_session):
    """A hard LND error on the first tick fails the session (not a silent
    stall)."""
    lnd = FakeLndService(fresh_address=_FRESH)
    lnd.set_error("new_address", "lnd locked")
    svc = BraiinsDepositService(
        boltz_service=_FakeBoltzForBraiins(),
        lnd_service=lnd,
        mempool_fee_service=_FakeMempool(),
    )
    session, err = await svc.create_session(
        db_session,
        api_key_id=uuid4(),
        amount_sats=500_000,
        destination_address=_DEST,
        source_kind=BraiinsDepositSourceKind.LIGHTNING.value,
        include_extras=False,
    )
    assert err is None and session is not None

    s = await svc.advance(db_session, session.id)
    assert s.status == BraiinsDepositStatus.FAILED


@pytest.mark.asyncio
async def test_swapping_to_refunded_when_boltz_refunds(db_session):
    """If the linked Boltz swap refunds, the deposit session goes REFUNDED."""
    lnd = FakeLndService(fresh_address=_FRESH)
    boltz = _FakeBoltzForBraiins()
    svc = BraiinsDepositService(
        boltz_service=boltz,
        lnd_service=lnd,
        mempool_fee_service=_FakeMempool(),
    )
    session, _ = await svc.create_session(
        db_session,
        api_key_id=uuid4(),
        amount_sats=1_000_000,
        destination_address=_DEST,
        source_kind=BraiinsDepositSourceKind.LIGHTNING.value,
        include_extras=False,
    )
    await svc.advance(db_session, session.id)  # → SWAPPING

    boltz.created_swap.status = SwapStatus.REFUNDED
    await db_session.commit()

    s = await svc.advance(db_session, session.id)
    assert s.status == BraiinsDepositStatus.REFUNDED
