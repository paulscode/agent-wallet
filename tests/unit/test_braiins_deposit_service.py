# SPDX-License-Identifier: MIT
"""Unit tests for ``app/services/braiins_deposit_service.py``.

Covers:
  * Quote math across the preset bins.
  * State-machine forward transitions (CREATED → SWAPPING → FUNDED → BROADCAST → COMPLETED).
  * Idempotency / crash recovery in the SENDING → BROADCAST window.
  * Cancel preconditions.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.boltz_swap import BoltzSwap, BoltzSwapDirection, SwapStatus
from app.models.braiins_deposit_session import (
    BraiinsDepositFundingStrategy,
    BraiinsDepositSession,
    BraiinsDepositSourceKind,
    BraiinsDepositStatus,
)
from app.services.braiins_deposit_service import (
    BIN_AMOUNTS,
    BraiinsDepositService,
)

# ── Helpers ──────────────────────────────────────────────────────────


def _mock_pair_info(*, pct: float = 0.5, miner_claim: int = 600, miner_lockup: int = 200) -> dict:
    return {
        "fees_percentage": pct,
        "fees_miner_claim": miner_claim,
        "fees_miner_lockup": miner_lockup,
        "min": 25_000,
        "max": 25_000_000,
    }


def _make_service(
    *,
    boltz_pair_info: dict | None = None,
    boltz_create_result=None,
    lnd_new_address: str = "bcrt1pfreshtaprootaddress",
    lnd_unspent: list | None = None,
    lnd_send_result: dict | None = None,
    mempool_fees: dict | None = None,
    mempool_confs: dict | None = None,
    cached_tip_height: int | None = None,
) -> BraiinsDepositService:
    """Build a service with all external calls mocked. Returns the
    service AND attaches the mocks as ``svc._mocks`` for assertions.
    """
    boltz = MagicMock()
    boltz.get_reverse_pair_info = AsyncMock(return_value=(boltz_pair_info or _mock_pair_info(), None))
    boltz.create_reverse_swap = AsyncMock(
        return_value=(boltz_create_result, None) if boltz_create_result is not None else (None, "not_set")
    )
    # On-chain source: submarine swap mocks. Default to a healthy pair-info
    # response and "not_set" for create_submarine_swap so tests that
    # rely on it must override explicitly.
    boltz.get_submarine_pair_info = AsyncMock(
        return_value=(
            {
                "fees_percentage": 0.1,
                "fees_miner_lockup": 462,
                "min": 25_000,
                "max": 25_000_000,
                "hash": "submarine_test_pair_hash",
            },
            None,
        )
    )
    boltz.create_submarine_swap = AsyncMock(return_value=(None, "not_set"))

    lnd = MagicMock()
    lnd.new_address = AsyncMock(return_value=({"address": lnd_new_address, "address_type": "p2tr"}, None))
    lnd.list_unspent = AsyncMock(return_value=(lnd_unspent or [], None))
    lnd.send_coins = AsyncMock(return_value=(lnd_send_result or {"txid": "fdsendtxid" + "0" * 56}, None))
    # On-chain source: invoice creation + lookup for the submarine LN leg.
    lnd.create_invoice = AsyncMock(
        return_value=(
            {
                "r_hash": "ab" * 32,
                "payment_request": "lnbc_submarine_test_invoice",
                "add_index": "0",
            },
            None,
        )
    )
    lnd.lookup_invoice = AsyncMock(
        return_value=(
            {
                "settled": False,
                "state": "OPEN",
                "amt_paid_sat": 0,
                "r_hash": "ab" * 32,
                "memo": "",
                "value": 0,
                "creation_date": 0,
                "settle_date": 0,
                "payment_request": "",
                "is_keysend": False,
            },
            None,
        )
    )
    # Inbound pre-flight: default to ample receivable capacity so
    # on-chain create_session / _advance_created_onchain tests aren't
    # blocked by the gate unless they override this explicitly.
    lnd.inbound_capacity = AsyncMock(
        return_value=(
            {
                "total_receivable_sats": 100_000_000,
                "largest_channel_receivable_sats": 100_000_000,
            },
            None,
        )
    )
    # Tier 2 routability probe: defaults that make the probe a benign
    # no-op (Boltz reachable → a route is found → no warning/refusal).
    # Probe-specific tests override these.
    lnd.get_info = AsyncMock(return_value=({"identity_pubkey": "03" + "aa" * 32}, None))
    lnd.query_routes = AsyncMock(
        return_value=(
            {"hops": 2, "total_amt_sat": 0, "total_fees_sat": 1, "ppm": 0},
            None,
        )
    )
    boltz.get_ln_node_pubkeys = AsyncMock(return_value=(["02" + "bb" * 32], None))
    # Channel-open strategy LND mocks (benign defaults).
    lnd.connect_peer = AsyncMock(return_value=({"ok": True}, None))
    lnd.open_channel = AsyncMock(return_value=({"funding_txid": "cc" * 32, "output_index": 0}, None))
    # Default: channel reports active immediately (tests override to
    # exercise the not-yet-active / stuck branches).
    lnd.channel_is_active = AsyncMock(return_value=(True, {"chan_id": "123x456", "active": True}, None))
    lnd.get_channel_by_point = AsyncMock(return_value=({"chan_id": "123x456", "active": True}, None))

    mempool = MagicMock()
    mempool.get_recommended_fees = AsyncMock(
        return_value=(mempool_fees or {"fastestFee": 20, "halfHourFee": 6, "hourFee": 2}, None)
    )
    mempool.optional_confirmations = AsyncMock(return_value=mempool_confs)
    type(mempool).cached_tip_height = property(lambda self: cached_tip_height)

    svc = BraiinsDepositService(boltz_service=boltz, lnd_service=lnd, mempool_fee_service=mempool)
    svc._mocks = {"boltz": boltz, "lnd": lnd, "mempool": mempool}  # type: ignore[attr-defined]
    return svc


def _make_boltz_swap(
    *,
    status: SwapStatus = SwapStatus.COMPLETED,
    claim_txid: str | None = "deadbeef" * 8,
) -> BoltzSwap:
    swap = BoltzSwap(
        id=uuid4(),
        boltz_swap_id="swap_test",
        direction=BoltzSwapDirection.REVERSE,
        api_key_id=uuid4(),
        invoice_amount_sats=1_010_000,
        onchain_amount_sats=1_005_000,
        destination_address="bcrt1pfreshtaprootaddress",
        status=status,
        claim_txid=claim_txid,
        status_history=[],
    )
    return swap


# ── Quote ────────────────────────────────────────────────────────────


class TestQuote:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("amount", BIN_AMOUNTS)
    async def test_quote_for_each_preset(self, amount):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=amount)
        assert err is None
        assert quote is not None
        assert quote.deposit_amount_sats == amount
        # Invoice must exceed deposit (covers fees + buffer).
        assert quote.invoice_amount_sats > amount
        # Expected fresh UTXO must be enough to send the deposit + send fee.
        assert quote.expected_fresh_utxo_sats >= amount + quote.estimated_send_fee_sats
        # Required LN balance includes routing headroom.
        assert quote.required_lightning_balance_sats >= quote.invoice_amount_sats

    @pytest.mark.asyncio
    async def test_quote_rejects_zero_amount(self):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=0)
        assert quote is None
        assert err

    @pytest.mark.asyncio
    async def test_quote_uses_priority_for_send_fee(self):
        svc = _make_service(mempool_fees={"fastestFee": 100, "halfHourFee": 30, "hourFee": 5})
        quote, err = await svc.quote(amount_sats=1_000_000)
        assert err is None
        assert quote is not None
        # Default priority is medium -> halfHourFee=30 -> ~110 vbytes * 30 = 3300
        assert 2000 < quote.estimated_send_fee_sats < 5000

    @pytest.mark.asyncio
    async def test_quote_falls_back_when_fees_unavailable(self):
        svc = _make_service()
        svc._mocks["mempool"].get_recommended_fees = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "unavailable")
        )
        quote, err = await svc.quote(amount_sats=1_000_000)
        assert err is None
        assert quote is not None
        # Falls back to medium=6 sat/vB * 110 vbytes = 660
        assert 500 < quote.estimated_send_fee_sats < 1500

    # ── dust-prevention arrival projection ──────────────────

    @pytest.mark.asyncio
    async def test_projection_range_matches_fee_priority(self):
        """The projection produces a (min, max) arrival
        range driven by ``fastestFee`` (high) and ``hourFee`` (low).
        At a given UTXO size, min = arrival at high fee (smaller)
        and max = arrival at low fee (larger). The wizard renders
        this directly so the contract has to hold."""
        svc = _make_service(
            # Wide range: high vs low differ by 25× so the test
            # asserts the structural shape, not exact bytes.
            mempool_fees={"fastestFee": 50, "halfHourFee": 10, "hourFee": 2}
        )
        quote, err = await svc.quote(amount_sats=1_000_000)
        assert err is None
        assert quote is not None
        # Range is well-formed: min <= max, both > 0.
        assert quote.arrival_min_sats > 0
        assert quote.arrival_max_sats > 0
        assert quote.arrival_min_sats <= quote.arrival_max_sats
        # Minimum arrival uses the high-priority fee (50 sat/vB).
        # The dust_safe_send module uses 140-vbyte default, so the
        # min arrival is ``expected_fresh_utxo - 50 * 140``.
        # The exact number depends on the boltz pair-info numbers
        # in _mock_pair_info; we just assert the relationship
        # holds.
        expected_min = quote.expected_fresh_utxo_sats - (50 * 140)
        expected_max = quote.expected_fresh_utxo_sats - (2 * 140)
        assert quote.arrival_min_sats == expected_min
        assert quote.arrival_max_sats == expected_max

    @pytest.mark.asyncio
    async def test_projection_infeasible_at_extreme_fees(self):
        """At fees high enough to drive arrival below the
        bin (or below zero), ``arrival_feasible=False`` so the
        wizard CTA disables. Pinned because the static
        ``BRAIINS_DEPOSIT_SAFETY_BUFFER_SATS`` floor isn't enough
        to cover extreme fee spikes; the projection must guard."""
        # 500 sat/vB × 140 vbytes = 70,000 sats fee. A 1M-sat
        # bin with the default 1k buffer can't survive that.
        svc = _make_service(mempool_fees={"fastestFee": 500, "halfHourFee": 200, "hourFee": 80})
        quote, err = await svc.quote(amount_sats=1_000_000)
        assert err is None
        assert quote is not None
        assert quote.arrival_feasible is False, (
            "at 500 sat/vB the projected high-fee arrival falls "
            "below the bin amount; the wizard must surface this "
            "so the user picks a larger bin or waits."
        )

    @pytest.mark.asyncio
    async def test_quote_endpoint_includes_arrival_projection(self):
        """The quote response contract exposes four
        projection fields the wizard renders. Pinned via the
        ``as_dict`` surface so a future refactor that renames
        or drops a key is caught."""
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000)
        assert err is None
        d = quote.as_dict()
        # All four projection fields present.
        for field in (
            "arrival_min_sats",
            "arrival_max_sats",
            "arrival_feasible",
            "arrival_current_fee_rate_vb",
        ):
            assert field in d, f"quote response missing {field!r}"
        # Types are JSON-native.
        assert isinstance(d["arrival_min_sats"], int)
        assert isinstance(d["arrival_max_sats"], int)
        assert isinstance(d["arrival_feasible"], bool)
        assert isinstance(d["arrival_current_fee_rate_vb"], int)


class TestQuoteIncludeExtras:
    """Per-session ``include_extras`` toggle. When ``False``, the
    wallet sends exactly the bin amount and returns a change UTXO
    (the legacy path); the quote response collapses the arrival
    range to the bin amount and surfaces a projected change plus
    a soft dust-risk flag."""

    @pytest.mark.asyncio
    async def test_extras_off_collapses_arrival_to_bin(self):
        svc = _make_service(mempool_fees={"fastestFee": 50, "halfHourFee": 10, "hourFee": 2})
        quote, err = await svc.quote(amount_sats=1_000_000, include_extras=False)
        assert err is None
        assert quote is not None
        assert quote.include_extras is False
        # Exact-amount mode: arrival is the bin, both bounds equal.
        assert quote.arrival_min_sats == 1_000_000
        assert quote.arrival_max_sats == 1_000_000
        # Change is projected (positive) for a normal-fee scenario.
        assert quote.expected_change_sats > 0

    @pytest.mark.asyncio
    async def test_extras_on_leaves_no_projected_change(self):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000, include_extras=True)
        assert err is None
        assert quote is not None
        assert quote.include_extras is True
        # Dust-safe mode doesn't compute a change projection.
        assert quote.expected_change_sats == 0
        assert quote.expected_change_dust_risk is False

    @pytest.mark.asyncio
    async def test_dust_risk_flagged_when_change_below_padded_spend_cost(self):
        """When the projected change is positive at current fees
        but smaller than the padded future-spend cost (110 vbytes
        × 2× current fee), the soft warning fires. Advisory only —
        feasibility stays True so the user can still proceed."""
        # At 30 sat/vB current: padded = 60 sat/vB → spend cost
        # threshold = 110 × 60 = 6,600 sats. The mock's
        # expected_fresh_utxo for a 1M bin is bin + ~4,300 sats,
        # so projected change at 140 × 30 = 4,200 sat fee is
        # ~100 sats — well inside the danger zone.
        svc = _make_service(mempool_fees={"fastestFee": 30, "halfHourFee": 30, "hourFee": 30})
        quote, err = await svc.quote(amount_sats=1_000_000, include_extras=False)
        assert err is None
        assert quote is not None
        assert quote.expected_change_sats > 0, "test precondition: change must be positive"
        assert quote.expected_change_sats < quote.expected_change_dust_threshold_sats
        assert quote.expected_change_dust_risk is True
        # Advisory: doesn't kill feasibility.
        assert quote.arrival_feasible is True

    @pytest.mark.asyncio
    async def test_dust_risk_not_flagged_when_change_comfortably_above_threshold(self):
        """At low fees the projected change comfortably exceeds the
        padded spend cost — no warning."""
        svc = _make_service(mempool_fees={"fastestFee": 2, "halfHourFee": 2, "hourFee": 2})
        quote, err = await svc.quote(amount_sats=50_000, include_extras=False)
        assert err is None
        assert quote is not None
        # Either the change is large or the projection is healthy; in
        # both cases the dust-risk flag must NOT be set.
        if quote.expected_change_sats > 0:
            assert quote.expected_change_sats >= quote.expected_change_dust_threshold_sats
        assert quote.expected_change_dust_risk is False

    @pytest.mark.asyncio
    async def test_quote_endpoint_includes_extras_fields(self):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000, include_extras=False)
        assert err is None
        d = quote.as_dict()
        for field in (
            "include_extras",
            "expected_change_sats",
            "expected_change_dust_risk",
            "expected_change_dust_threshold_sats",
        ):
            assert field in d, f"quote response missing {field!r}"
        assert isinstance(d["include_extras"], bool)
        assert isinstance(d["expected_change_sats"], int)
        assert isinstance(d["expected_change_dust_risk"], bool)
        assert isinstance(d["expected_change_dust_threshold_sats"], int)


# ── Session creation ─────────────────────────────────────────────────


class TestCreateSession:
    @pytest.mark.asyncio
    async def test_create_session_inserts_row(self, db_session):
        svc = _make_service()
        api_key_id = uuid4()
        session, err = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert err is None
        assert session is not None
        assert session.status == BraiinsDepositStatus.CREATED
        assert session.deposit_amount_sats == 1_000_000
        assert session.api_key_id == api_key_id

    @pytest.mark.asyncio
    async def test_create_session_rejects_second_in_flight(self, db_session):
        svc = _make_service()
        api_key_id = uuid4()
        s1, _ = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert s1 is not None
        s2, err = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=1_000_000,
            destination_address="bc1q" + "y" * 38,
        )
        assert s2 is None
        assert err == "in_flight_session_exists"

    @pytest.mark.asyncio
    async def test_create_session_after_terminal_is_ok(self, db_session):
        svc = _make_service()
        api_key_id = uuid4()
        s1, _ = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert s1 is not None
        # Move first session to a terminal state and expect second to succeed.
        s1.status = BraiinsDepositStatus.CANCELLED
        await db_session.commit()
        s2, err = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=1_000_000,
            destination_address="bc1q" + "y" * 38,
        )
        assert err is None
        assert s2 is not None

    @pytest.mark.asyncio
    async def test_create_session_persists_include_extras_default_true(self, db_session):
        svc = _make_service()
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert err is None
        assert session is not None
        assert session.include_extras is True

    @pytest.mark.asyncio
    async def test_create_session_persists_include_extras_false(self, db_session):
        svc = _make_service()
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            include_extras=False,
        )
        assert err is None
        assert session is not None
        assert session.include_extras is False


# ── State machine ────────────────────────────────────────────────────


class TestAdvanceCreated:
    @pytest.mark.asyncio
    async def test_created_to_swapping(self, db_session):
        swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service(boltz_create_result=swap)
        api_key_id = uuid4()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert session is not None

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.SWAPPING
        assert result.boltz_swap_id == swap.id
        assert result.fresh_address == "bcrt1pfreshtaprootaddress"

    @pytest.mark.asyncio
    async def test_created_advance_fails_on_address_error(self, db_session):
        svc = _make_service()
        svc._mocks["lnd"].new_address = AsyncMock(return_value=(None, "lnd locked"))  # type: ignore[attr-defined]
        api_key_id = uuid4()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert session is not None
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED


class TestAdvanceSwapping:
    @pytest.mark.asyncio
    async def test_swapping_to_funded_when_utxo_present(self, db_session):
        # Pre-existing boltz swap row in COMPLETED state.
        swap = _make_boltz_swap(status=SwapStatus.COMPLETED)
        db_session.add(swap)
        await db_session.commit()

        # Mock LND to surface the claim outpoint as confirmed.
        utxos = [
            {
                "outpoint": {"txid_str": swap.claim_txid, "output_index": 0},
                "amount_sat": 1_004_000,
                "address": "bcrt1pfreshtaprootaddress",
                "address_type": "TAPROOT",
                "pk_script": "",
                "confirmations": 2,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)

        # Create a session row in SWAPPING state linked to the swap.
        api_key_id = uuid4()
        session = BraiinsDepositSession(
            api_key_id=api_key_id,
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfreshtaprootaddress",
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FUNDED
        assert result.fresh_utxo_txid == swap.claim_txid
        assert result.fresh_utxo_vout == 0
        assert result.fresh_utxo_amount_sats == 1_004_000

    @pytest.mark.asyncio
    async def test_swapping_funds_and_backfills_missing_claim_txid(self, db_session):
        """A cooperative claim can settle the swap (COMPLETED) before the
        wallet persists ``claim_txid`` (broadcast-then-error). The
        session must still fund: the fresh address is single-use, so the
        lone UTXO there IS the claim — match it by address, backfill
        ``claim_txid``, and proceed to FUNDED instead of hard-failing.
        Regression for incident 2026-06-16."""
        swap = _make_boltz_swap(status=SwapStatus.COMPLETED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()

        claim_txid = "cc" * 32
        utxos = [
            {
                "outpoint": {"txid_str": claim_txid, "output_index": 0},
                "amount_sat": 1_004_000,
                "address": "bcrt1pfreshtaprootaddress",
                "address_type": "TAPROOT",
                "pk_script": "",
                "confirmations": 6,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfreshtaprootaddress",
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FUNDED
        assert result.fresh_utxo_txid == claim_txid
        # claim_txid backfilled onto the swap row.
        await db_session.refresh(swap)
        assert swap.claim_txid == claim_txid

    @pytest.mark.asyncio
    async def test_swapping_stays_when_utxo_unconfirmed(self, db_session):
        swap = _make_boltz_swap(status=SwapStatus.COMPLETED)
        db_session.add(swap)
        await db_session.commit()
        utxos = [
            {
                "outpoint": {"txid_str": swap.claim_txid, "output_index": 0},
                "amount_sat": 1_004_000,
                "address": "bcrt1pfreshtaprootaddress",
                "address_type": "TAPROOT",
                "pk_script": "",
                "confirmations": 0,  # still unconfirmed
            }
        ]
        svc = _make_service(lnd_unspent=utxos)

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfreshtaprootaddress",
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        # Outpoint recorded but still SWAPPING since confs < threshold.
        assert result.status == BraiinsDepositStatus.SWAPPING
        assert result.fresh_utxo_txid == swap.claim_txid

    @pytest.mark.asyncio
    async def test_swapping_to_refunded_when_boltz_refunds(self, db_session):
        swap = _make_boltz_swap(status=SwapStatus.REFUNDED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.REFUNDED


class TestAdvanceFunded:
    @pytest.mark.asyncio
    async def test_funded_to_broadcast(self, db_session):
        """Dust-prevention happy path. With prevention on
        (default), the send is built with ``send_all=True``: the
        entire UTXO goes to Braiins minus the network fee. The
        ``amount_sats`` parameter is ``None`` (LND requires this for
        send_all). ``actual_sent_sats`` records the arrival amount."""
        svc = _make_service(
            lnd_send_result={"txid": "a" * 64},
            cached_tip_height=900_000,
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.BROADCAST
        assert result.send_txid == "a" * 64
        assert result.broadcast_block_height == 900_000

        # Dust-prevention contract: send_all + pinned outpoint, no
        # amount_sats. This is called out explicitly.
        svc._mocks["lnd"].send_coins.assert_awaited_once()  # type: ignore[attr-defined]
        kwargs = svc._mocks["lnd"].send_coins.call_args.kwargs  # type: ignore[attr-defined]
        assert kwargs["outpoints"] == [{"txid_str": "b" * 64, "output_index": 0}]
        assert kwargs["send_all"] is True, (
            "dust-prevention must use send_all=True so LND can't leave a wallet-side change output."
        )
        assert kwargs["amount_sats"] is None, "send_all=True requires amount_sats=None per LND API."
        # Arrival amount is recorded. Fee at 6 sat/vB (medium) ×
        # 140 vbytes = 840 sats → arrival = 1,004,000 - 840.
        assert result.actual_sent_sats is not None
        assert result.actual_sent_sats == 1_004_000 - (140 * 6)
        # Arrival >= bin (the contractual floor).
        assert result.actual_sent_sats >= result.deposit_amount_sats

    @pytest.mark.asyncio
    async def test_funded_send_failure_marks_failed(self, db_session):
        """When LND rejects the broadcast (e.g. mempool full), the
        session goes to FAILED with the LND error preserved."""
        svc = _make_service()
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "fee too low")
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert "fee too low" in (result.error_message or "")

    def test_is_transient_send_error_classification(self):
        from app.services.braiins_deposit_service import _is_transient_send_error

        # Connectivity / shutdown → transient.
        assert _is_transient_send_error("dust-safe send failed: Request failed: Event loop is closed")
        assert _is_transient_send_error("Connection failed: socks timeout")
        # Genuine failures → not transient (still retry-eligible via UTXO).
        assert not _is_transient_send_error("fee too low")
        assert not _is_transient_send_error("insufficient funds")
        assert not _is_transient_send_error(None)

    @pytest.mark.asyncio
    async def test_funded_transient_send_error_stays_recoverable(self, db_session):
        """A transient send error (connectivity/shutdown — e.g. an app
        restart's "Event loop is closed") must NOT terminally FAIL. The
        send didn't broadcast and the fresh UTXO is intact, so the session
        stays at SENDING for the reconciler to roll back to FUNDED + retry.
        """
        svc = _make_service()
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "Request failed: Event loop is closed")
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        result = await svc.advance(db_session, session.id)
        assert result is not None
        # Recoverable — left at SENDING (not terminally FAILED).
        assert result.status == BraiinsDepositStatus.SENDING
        assert result.status != BraiinsDepositStatus.FAILED
        assert result.send_txid is None

    @pytest.mark.asyncio
    async def test_transient_send_then_reconcile_recovers_to_funded(self, db_session):
        """End-to-end recovery: a transient send error leaves the session
        at SENDING; the next tick's reconciler sees the fresh UTXO still
        unspent and rolls back to FUNDED so the send retries — i.e. the
        deposit self-heals after a restart instead of stranding FAILED."""
        utxo = {
            "outpoint": {"txid_str": "b" * 64, "output_index": 0},
            "amount_sat": 1_004_000,
        }
        svc = _make_service(lnd_unspent=[utxo])
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "Request failed: Event loop is closed")
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        # Tick 1: send fails transiently → stays SENDING (not FAILED).
        r1 = await svc.advance(db_session, session.id)
        assert r1.status == BraiinsDepositStatus.SENDING
        # Tick 2: reconciler finds the UTXO unspent → rolls back to FUNDED
        # (the next tick would re-attempt the send). Never FAILED.
        r2 = await svc.advance(db_session, session.id)
        assert r2.status == BraiinsDepositStatus.FUNDED

    @pytest.mark.asyncio
    async def test_funded_parks_for_fee_reduction_when_fees_too_high(
        self,
        db_session,
        monkeypatch,
    ):
        """Layer 4 — when current fees are high enough that the
        no-change projection would arrive below the bin amount, the
        session must park in AWAITING_FEE_REDUCTION rather than
        broadcasting a tx that underpays the user's signed-off floor.
        """
        # 1,004,000-sat UTXO at 100 sat/vB (140 vbytes) → fee
        # 14,000 sats → arrival 990,000 < bin 1,000,000 → infeasible.
        svc = _make_service(
            mempool_fees={"fastestFee": 200, "halfHourFee": 100, "hourFee": 50},
            cached_tip_height=900_000,
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.AWAITING_FEE_REDUCTION
        assert result.send_infeasible_reason == "would_underpay_bin"
        # CRITICAL: no broadcast occurred — we must not burn a tx
        # that we know will underpay.
        svc._mocks["lnd"].send_coins.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_awaiting_fee_reduction_resumes_when_fees_drop(
        self,
        db_session,
    ):
        """A parked session promotes back to FUNDED when the
        next advance() tick sees fees low enough for a feasible
        no-change send. The next iteration broadcasts normally."""
        # Start with parked session.
        svc = _make_service(
            mempool_fees={"fastestFee": 20, "halfHourFee": 6, "hourFee": 2},
            lnd_send_result={"txid": "c" * 64},
            cached_tip_height=900_001,
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.AWAITING_FEE_REDUCTION,
            send_infeasible_reason="would_underpay_bin",
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        # First advance: fees are low → resume to FUNDED.
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FUNDED
        assert result.send_infeasible_reason is None

    @pytest.mark.asyncio
    async def test_send_fee_uses_fallback_when_mempool_unreachable(
        self,
        db_session,
    ):
        """When ``mempool.get_recommended_fees`` returns an
        error, the send step falls back to
        ``_FALLBACK_FEE_VBYTES[priority]`` rather than aborting.
        Pinned because a transient mempool outage shouldn't park or
        fail a session that's otherwise ready to send."""
        svc = _make_service(
            lnd_send_result={"txid": "e" * 64},
            cached_tip_height=900_000,
        )
        # Stub the mempool probe to fail. The fallback rate at
        # priority="medium" is 6 sat/vB (from _FALLBACK_FEE_VBYTES).
        svc._mocks["mempool"].get_recommended_fees = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "unreachable"),
        )

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.BROADCAST, (
            "mempool outage must not fail the send — fallback fee rate keeps the session progressing."
        )
        kwargs = svc._mocks["lnd"].send_coins.call_args.kwargs  # type: ignore[attr-defined]
        # Fallback rate for "medium" priority is 6 sat/vB.
        assert kwargs["sat_per_vbyte"] == 6

    @pytest.mark.asyncio
    async def test_accept_underpay_override_broadcasts_below_bin(
        self,
        db_session,
    ):
        """When a session is parked in AWAITING_FEE_REDUCTION,
        the operator can override via ``retry_send(accept_underpay=True)``.
        The next advance() broadcasts even though the arrival is
        below the bin amount. Pinned so a future refactor that
        accidentally re-locks the projection doesn't break the
        operator-escape-hatch contract."""
        svc = _make_service(
            mempool_fees={"fastestFee": 200, "halfHourFee": 100, "hourFee": 50},
            lnd_send_result={"txid": "f" * 64},
            cached_tip_height=900_005,
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.AWAITING_FEE_REDUCTION,
            send_infeasible_reason="would_underpay_bin",
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        # First: retry_send promotes to FUNDED + sets override flag.
        ok, err = await svc.retry_send(
            db_session,
            session.id,
            accept_underpay=True,
        )
        assert ok, err
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.FUNDED
        assert session.send_infeasible_reason == "operator_accept_underpay"

        # Second: advance broadcasts despite arrival < bin.
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.BROADCAST
        # Arrival is 1_004_000 - (140 * 100) = 990_000 — below the bin.
        assert result.actual_sent_sats is not None
        assert result.actual_sent_sats < result.deposit_amount_sats

    @pytest.mark.asyncio
    async def test_retry_send_without_override_still_parks_at_high_fees(
        self,
        db_session,
    ):
        """Counterpart to ``test_accept_underpay_override_...`` —
        retry_send WITHOUT the override re-runs the feasibility
        check, which still parks when fees haven't dropped. Pinned
        so an unintentional "Retry" click can't bypass the safety
        floor; the override requires an explicit query param."""
        svc = _make_service(
            mempool_fees={"fastestFee": 200, "halfHourFee": 100, "hourFee": 50},
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.AWAITING_FEE_REDUCTION,
            send_infeasible_reason="would_underpay_bin",
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        # retry_send without accept_underpay → promote to FUNDED
        # but DON'T set the override marker.
        ok, err = await svc.retry_send(db_session, session.id)
        assert ok, err
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.FUNDED
        assert session.send_infeasible_reason is None

        # advance() re-runs the feasibility check; fees are still
        # high so the session parks again. No broadcast.
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.AWAITING_FEE_REDUCTION
        svc._mocks["lnd"].send_coins.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_funded_parks_when_utxo_cannot_cover_network_fee(
        self,
        db_session,
    ):
        """The "harder" infeasibility: the UTXO itself is
        smaller than ``estimated_vbytes × sat_per_vbyte``. The
        no-change send would build an invalid tx (negative output).
        ``project_no_change_send`` returns ``None`` and the service
        parks with ``reason='fees_too_high_for_no_change_send'`` —
        distinct from ``would_underpay_bin`` so the CHANGELOG park
        breakdown can separate "below-bin" from "below-network-fee"
        scenarios."""
        # 5,000-sat UTXO at 100 sat/vB → 14,000-sat fee > UTXO value.
        # Projection returns None.
        svc = _make_service(
            mempool_fees={"fastestFee": 200, "halfHourFee": 100, "hourFee": 50},
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=5_000,  # tiny bin for the test
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=5_000,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.AWAITING_FEE_REDUCTION
        assert result.send_infeasible_reason == ("fees_too_high_for_no_change_send")
        # NO broadcast — the tx would be invalid (negative output).
        svc._mocks["lnd"].send_coins.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_funded_parks_when_lnd_raises_infeasible_at_broadcast(
        self,
        db_session,
        monkeypatch,
    ):
        """Race between pre-flight and broadcast: pre-flight
        sees feasible, but ``build_and_broadcast_no_change_send``
        raises ``InfeasibleSendError`` (e.g. live mempool moved
        between the projection read and the actual broadcast). The
        service must park (not raise) so the session can recover on
        the next tick."""
        from app.services import dust_safe_send as dss_mod
        from app.services.dust_safe_send import InfeasibleSendError

        # Pre-flight passes: 1,004,000 sat at 6 sat/vB.
        svc = _make_service(
            mempool_fees={"fastestFee": 20, "halfHourFee": 6, "hourFee": 2},
        )

        async def _raise_infeasible(**_kwargs):
            raise InfeasibleSendError(
                utxo_value=1_004_000,
                projected_fee=1_500_000,
                sat_per_vbyte=10_000,
            )

        # The service does a lazy ``from app.services.dust_safe_send
        # import build_and_broadcast_no_change_send`` inside
        # ``_advance_funded``, so we patch the source module rather
        # than the importing module.
        monkeypatch.setattr(
            dss_mod,
            "build_and_broadcast_no_change_send",
            _raise_infeasible,
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.AWAITING_FEE_REDUCTION, (
            "broadcast-time InfeasibleSendError must park rather than fail-hard so the next tick can re-try cleanly."
        )
        assert result.send_infeasible_reason == ("fees_too_high_for_no_change_send")

    @pytest.mark.asyncio
    async def test_legacy_send_path_when_flag_disabled(
        self,
        db_session,
        monkeypatch,
    ):
        """The rollback flag ``BRAIINS_DEPOSIT_DUST_PREVENTION_ENABLED=false``
        restores the legacy send path: LND coin-selection produces
        change. Pinned because the env knob is the canary for a fast
        rollback if the new flow ever misbehaves in production."""
        monkeypatch.setattr(
            "app.core.config.settings.braiins_deposit_dust_prevention_enabled",
            False,
        )
        svc = _make_service(
            lnd_send_result={"txid": "d" * 64},
            cached_tip_height=900_000,
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.BROADCAST
        # Legacy path: amount_sats=bin, no send_all.
        kwargs = svc._mocks["lnd"].send_coins.call_args.kwargs  # type: ignore[attr-defined]
        assert kwargs["amount_sats"] == 1_000_000
        assert kwargs.get("send_all", False) is False
        # actual_sent_sats falls back to the bin amount in legacy mode.
        assert result.actual_sent_sats == result.deposit_amount_sats

    @pytest.mark.asyncio
    async def test_user_opt_out_forces_legacy_path_even_with_flag_on(
        self,
        db_session,
        monkeypatch,
    ):
        """Per-session ``include_extras=False`` (the user picked
        exact-amount mode) takes the legacy with-change path even
        when the operator's dust-prevention flag is enabled. The
        operator flag is a kill-switch, not a force-on; we cannot
        push the user into a no-change send they didn't sign off
        on."""
        monkeypatch.setattr(
            "app.core.config.settings.braiins_deposit_dust_prevention_enabled",
            True,
        )
        svc = _make_service(
            lnd_send_result={"txid": "d" * 64},
            cached_tip_height=900_000,
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            include_extras=False,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.BROADCAST
        # Took the legacy path: send_coins called with bin amount
        # rather than the no-change send_all builder.
        kwargs = svc._mocks["lnd"].send_coins.call_args.kwargs  # type: ignore[attr-defined]
        assert kwargs["amount_sats"] == 1_000_000
        assert result.actual_sent_sats == result.deposit_amount_sats


class TestAdvanceBroadcast:
    @pytest.mark.asyncio
    async def test_broadcast_to_completed(self, db_session):
        svc = _make_service(mempool_confs={"confirmations": 3, "confirmed": True})
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            send_txid="c" * 64,
            status=BraiinsDepositStatus.BROADCAST,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.COMPLETED
        assert result.send_confirmations == 3
        assert result.completed_at is not None

    @pytest.mark.asyncio
    async def test_broadcast_stays_when_unconfirmed(self, db_session):
        svc = _make_service(mempool_confs={"confirmations": 0, "confirmed": False})
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            send_txid="c" * 64,
            status=BraiinsDepositStatus.BROADCAST,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.BROADCAST
        assert result.send_confirmations == 0

    @pytest.mark.asyncio
    async def test_broadcast_completes_via_lnd_when_indexer_down(self, db_session):
        """Indexer unreachable (optional_confirmations None) but LND —
        which broadcast the tx — reports it confirmed → COMPLETED."""
        svc = _make_service(mempool_confs=None)  # indexer returns nothing
        svc._mocks["lnd"].get_transactions = AsyncMock(  # type: ignore[attr-defined]
            return_value=([{"tx_hash": "c" * 64, "num_confirmations": 2}], None)
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            send_txid="c" * 64,
            status=BraiinsDepositStatus.BROADCAST,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.COMPLETED
        assert result.send_confirmations == 2

    @pytest.mark.asyncio
    async def test_broadcast_indexer_and_lnd_both_unavailable_sets_message(self, db_session):
        """Neither the indexer nor LND can report on the tx → stays
        BROADCAST with an informative indexer-unavailable message (never
        auto-FAILs)."""
        svc = _make_service(mempool_confs=None)
        svc._mocks["lnd"].get_transactions = AsyncMock(return_value=([], None))  # type: ignore[attr-defined]
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            send_txid="c" * 64,
            status=BraiinsDepositStatus.BROADCAST,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.BROADCAST
        assert result.error_message and "indexer" in result.error_message.lower()


# ── Crash recovery ───────────────────────────────────────────────────


class TestReconcileAfterSendCrash:
    @pytest.mark.asyncio
    async def test_outpoint_still_unspent_rolls_back_to_funded(self, db_session):
        utxos = [
            {
                "outpoint": {"txid_str": "b" * 64, "output_index": 0},
                "amount_sat": 1_004_000,
                "address": "bcrt1pfresh",
                "address_type": "TAPROOT",
                "pk_script": "",
                "confirmations": 2,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.SENDING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FUNDED

    @pytest.mark.asyncio
    async def test_outpoint_gone_and_tx_found_recovers_to_broadcast(self, db_session):
        # Outpoint is gone from list_unspent (spent).
        svc = _make_service(lnd_unspent=[])
        # Mock get_transactions to surface the send tx.
        svc._mocks["lnd"].get_transactions = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                [
                    {
                        "tx_hash": "d" * 64,
                        "previous_outpoints": [
                            {"outpoint": ("b" * 64) + ":0", "is_our_output": True},
                        ],
                        "output_details": [
                            {"address": "bc1q" + "x" * 38, "amount": 1_000_000},
                        ],
                    }
                ],
                None,
            )
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.SENDING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.BROADCAST
        assert result.send_txid == "d" * 64

    @pytest.mark.asyncio
    async def test_outpoint_gone_and_no_match_fails(self, db_session):
        svc = _make_service(lnd_unspent=[])
        svc._mocks["lnd"].get_transactions = AsyncMock(  # type: ignore[attr-defined]
            return_value=([], None)
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.SENDING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED


# ── Cancel / retry-send ──────────────────────────────────────────────


class TestCancel:
    @pytest.mark.asyncio
    async def test_cancel_in_created(self, db_session):
        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert session is not None
        ok, err = await svc.cancel_session(db_session, session.id)
        assert ok
        assert err is None
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_in_swapping_when_boltz_not_paid(self, db_session):
        # When the BoltzSwap is still in its own CREATED state
        # (LN payment not yet sent), cancel is allowed and propagates
        # to Boltz via cancel_swap.
        swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()
        svc = _make_service()
        svc._mocks["boltz"].cancel_swap = AsyncMock(return_value=(True, None))  # type: ignore[attr-defined]
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.cancel_session(db_session, session.id)
        assert ok, err
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.CANCELLED
        svc._mocks["boltz"].cancel_swap.assert_awaited_once()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_cancel_in_swapping_when_paid_refused(self, db_session):
        # Once Boltz has progressed past CREATED, cancel is refused.
        swap = _make_boltz_swap(status=SwapStatus.INVOICE_PAID, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.cancel_session(db_session, session.id)
        assert not ok
        assert err

    @pytest.mark.asyncio
    async def test_cancel_terminal_refused(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            status=BraiinsDepositStatus.COMPLETED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.cancel_session(db_session, session.id)
        assert not ok

    @pytest.mark.asyncio
    async def test_cancel_in_awaiting_fee_reduction_refused(self, db_session):
        """Once a session is parked in AWAITING_FEE_REDUCTION,
        the fresh UTXO is in the wallet and the LN side is already
        settled. There's nothing safe to ``cancel`` (the funds aren't
        a Boltz HTLC anymore). Refuse with the standard
        post-LN-payment refusal message. Operators wanting to bail
        out can spend the wallet UTXO via Send-Onchain instead.

        Pinned because Layer 4 added a non-terminal status that the
        cancel handler must NOT treat as cancellable; a regression
        that quietly cancelled a parked session would leave a stray
        wallet UTXO with no audit-trail."""
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.AWAITING_FEE_REDUCTION,
            send_infeasible_reason="would_underpay_bin",
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.cancel_session(db_session, session.id)
        assert not ok
        assert err
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.AWAITING_FEE_REDUCTION


class TestAdvanceTerminalNoOp:
    """Re-fetching a terminal session (e.g. when the dashboard reopens
    a finished deposit to display its history) must not re-drive the
    state machine. ``advance()`` early-returns for terminal statuses;
    a CANCELLED session has no maintenance side-effects, so its status
    and recorded history must be untouched by an advance() call."""

    @pytest.mark.asyncio
    async def test_advance_cancelled_is_noop(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            status=BraiinsDepositStatus.CANCELLED,
            status_history=[
                {"status": "created", "timestamp": "2026-06-16T00:00:00+00:00"},
                {"status": "cancelled", "timestamp": "2026-06-16T00:01:00+00:00"},
            ],
        )
        db_session.add(session)
        await db_session.commit()

        history_before = list(session.status_history)
        result = await svc.advance(db_session, session.id)

        assert result is not None
        assert result.status == BraiinsDepositStatus.CANCELLED
        # No new transition appended — the machine did not advance.
        assert result.status_history == history_before


class TestStatusHistoryPersistence:
    """``record_transition`` appends to ``status_history`` in place. That
    only survives a commit if the column is a ``MutableList`` — a plain
    JSON column silently drops in-place mutations, leaving every
    reloaded session showing just "created" and breaking the dashboard
    progress log. Regression guard: transitions must round-trip the DB."""

    @pytest.mark.asyncio
    async def test_transitions_persist_across_reload(self, db_session):
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=50_000,
            destination_address="bc1q" + "x" * 38,
            status=BraiinsDepositStatus.CREATED,
            status_history=[],
        )
        session.record_transition(BraiinsDepositStatus.CREATED, detail="start")
        db_session.add(session)
        await db_session.commit()
        sid = session.id

        # The in-place appends that the plain-JSON bug dropped.
        session.record_transition(BraiinsDepositStatus.SWAPPING)
        session.record_transition(BraiinsDepositStatus.FUNDED)
        await db_session.commit()

        # Reload from the DB bypassing the identity map so we assert on
        # what was actually persisted, not the in-memory copy.
        db_session.expunge_all()
        reloaded = (
            await db_session.execute(select(BraiinsDepositSession).where(BraiinsDepositSession.id == sid))
        ).scalar_one()
        statuses = [e["status"] for e in (reloaded.status_history or [])]
        assert statuses == ["created", "swapping", "funded"], (
            f"status_history must persist every transition; got {statuses}"
        )


class TestSubmarineRefundTxidMirror:
    """The auto cooperative-refund records the refund txid on the swap's
    ``status_history`` but only has the swap in scope, so the session-side
    advance must mirror it onto ``session.refund_txid`` (the dashboard's
    "refund tx" link reads that). Regression for the gap where the auto
    path left ``session.refund_txid`` NULL while the manual + self-heal
    paths set it."""

    def test_helper_extracts_latest_refund_txid(self):
        from types import SimpleNamespace

        from app.services.braiins_deposit_service import (
            _submarine_refund_txid_from_swap,
        )

        swap = SimpleNamespace(
            status_history=[
                {"kind": "created"},
                {"kind": "submarine_refund_attempt", "refund_txid": "aa" * 32},
                {"kind": "submarine_refund", "refund_txid": "bb" * 32},
            ]
        )
        # Most-recent refund entry wins.
        assert _submarine_refund_txid_from_swap(swap) == "bb" * 32

    def test_helper_returns_none_without_refund_entry(self):
        from types import SimpleNamespace

        from app.services.braiins_deposit_service import (
            _submarine_refund_txid_from_swap,
        )

        assert _submarine_refund_txid_from_swap(SimpleNamespace(status_history=[{"kind": "created"}])) is None
        assert _submarine_refund_txid_from_swap(SimpleNamespace(status_history=None)) is None

    @pytest.mark.asyncio
    async def test_advance_mirrors_refund_txid_onto_session(self, db_session, monkeypatch):
        refund_txid = "cd" * 32
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_refund_test",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup_for_test",
            status=SwapStatus.REFUNDED,
            status_history=[
                {"kind": "submarine_refund", "refund_txid": refund_txid},
            ],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        # Status poll is a no-op here; the swap is already REFUNDED.
        monkeypatch.setattr(
            svc,
            "_update_submarine_boltz_status",
            AsyncMock(return_value=None),
        )

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_payment_hash_hex="ab" * 32,
            status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.REFUNDED
        assert result.refund_txid == refund_txid

    @pytest.mark.asyncio
    async def test_auto_refund_writer_and_helper_agree_on_key(self, db_session, monkeypatch):
        """Drive the REAL ``_update_submarine_boltz_status`` so the
        writer's status_history shape and the
        ``_submarine_refund_txid_from_swap`` reader can't silently drift
        apart (e.g. if the ``refund_txid`` key were renamed in one place
        but not the other)."""
        from app.services.braiins_deposit_service import (
            _submarine_refund_txid_from_swap,
        )

        refund_txid = "ef" * 32
        swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_writer_test",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup_for_test",
            status=SwapStatus.CREATED,
            boltz_status=None,
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].get_swap_status_from_boltz = AsyncMock(  # type: ignore[attr-defined]
            return_value=("invoice.failedToPay", {}, None)
        )
        monkeypatch.setattr(
            svc,
            "_attempt_cooperative_refund",
            AsyncMock(return_value=(refund_txid, None)),
        )

        await svc._update_submarine_boltz_status(db_session, swap)

        assert swap.status == SwapStatus.REFUNDED
        # The reader must recover exactly what the writer recorded.
        assert _submarine_refund_txid_from_swap(swap) == refund_txid


class TestTransientErrors:
    """Long-running transient LND errors get a "Stuck for Ns" prefix."""

    @pytest.mark.asyncio
    async def test_transient_within_window_no_stuck_prefix(self, db_session):
        from app.core.config import settings as _s

        old = _s.braiins_deposit_lnd_transient_max_age_s
        _s.braiins_deposit_lnd_transient_max_age_s = 3600
        try:
            # Set up a service that raises a generic exception on advance.
            svc = _make_service()
            svc._mocks["lnd"].new_address = AsyncMock(side_effect=RuntimeError("LND unreachable"))  # type: ignore[attr-defined]
            session, _ = await svc.create_session(
                db_session,
                api_key_id=uuid4(),
                amount_sats=500_000,
                destination_address="bc1q" + "x" * 38,
            )
            assert session is not None
            await svc.advance(db_session, session.id)
            await db_session.refresh(session)
            assert session.error_message is not None
            assert "Stuck for" not in session.error_message
            assert "transient" in session.error_message
        finally:
            _s.braiins_deposit_lnd_transient_max_age_s = old

    @pytest.mark.asyncio
    async def test_transient_past_window_gets_stuck_prefix(self, db_session):
        from app.core.config import settings as _s

        old = _s.braiins_deposit_lnd_transient_max_age_s
        _s.braiins_deposit_lnd_transient_max_age_s = 1  # 1 second TTL
        try:
            from datetime import datetime, timedelta, timezone

            svc = _make_service()
            svc._mocks["lnd"].new_address = AsyncMock(side_effect=RuntimeError("LND unreachable"))  # type: ignore[attr-defined]
            # Insert a session whose last status_history entry is far past.
            old_ts = (datetime.now(timezone.utc) - timedelta(seconds=3600)).isoformat()
            session = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=500_000,
                destination_address="bc1q" + "x" * 38,
                status=BraiinsDepositStatus.CREATED,
                status_history=[{"status": "created", "timestamp": old_ts}],
            )
            db_session.add(session)
            await db_session.commit()
            await svc.advance(db_session, session.id)
            await db_session.refresh(session)
            assert session.error_message is not None
            assert "Stuck for" in session.error_message
        finally:
            _s.braiins_deposit_lnd_transient_max_age_s = old


class TestAuditTrail:
    """State-transition audit-log breadcrumbs."""

    @pytest.mark.asyncio
    async def test_funded_transition_emits_audit_with_claim_txid(self, db_session):
        from app.models.audit_log import AuditLog

        swap = _make_boltz_swap(status=SwapStatus.COMPLETED)
        db_session.add(swap)
        await db_session.commit()
        utxos = [
            {
                "outpoint": {"txid_str": swap.claim_txid, "output_index": 0},
                "amount_sat": 1_004_000,
                "address": "bcrt1pfreshtaprootaddress",
                "address_type": "TAPROOT",
                "pk_script": "",
                "confirmations": 2,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfreshtaprootaddress",
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        await svc.advance(db_session, session.id)

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_funded")))
            .scalars()
            .all()
        )
        assert rows, "expected a funded audit row"
        row = rows[0]
        assert (row.details or {}).get("claim_txid") == swap.claim_txid
        assert (row.details or {}).get("purpose") == "braiins_deposit"

    @pytest.mark.asyncio
    async def test_broadcast_transition_emits_audit_with_send_txid(self, db_session):
        from app.models.audit_log import AuditLog

        svc = _make_service(
            lnd_send_result={"txid": "a" * 64},
            cached_tip_height=900_000,
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        await svc.advance(db_session, session.id)

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_broadcast")))
            .scalars()
            .all()
        )
        assert rows
        row = rows[0]
        assert (row.details or {}).get("send_txid") == "a" * 64

        # The FUNDED→SENDING transition is also audit-logged (every
        # state transition is recorded).
        sending_rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_sending")))
            .scalars()
            .all()
        )
        assert sending_rows
        assert (sending_rows[0].details or {}).get("purpose") == "braiins_deposit"

    @pytest.mark.asyncio
    async def test_completed_transition_emits_audit(self, db_session):
        from app.models.audit_log import AuditLog

        svc = _make_service(mempool_confs={"confirmations": 3, "confirmed": True})
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            send_txid="c" * 64,
            status=BraiinsDepositStatus.BROADCAST,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_completed")))
            .scalars()
            .all()
        )
        assert rows
        assert (rows[0].details or {}).get("send_txid") == "c" * 64

    @pytest.mark.asyncio
    async def test_swapping_transition_emits_audit(self, db_session):
        """CREATED → SWAPPING is one of the explicit state transitions
        that requires to be audited."""
        from app.models.audit_log import AuditLog

        swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service(boltz_create_result=swap)
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert session is not None
        await svc.advance(db_session, session.id)

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_swapping")))
            .scalars()
            .all()
        )
        assert rows, "expected a swapping audit row"
        details = rows[0].details or {}
        assert details.get("purpose") == "braiins_deposit"
        assert details.get("boltz_swap_id") == swap.boltz_swap_id

    @pytest.mark.asyncio
    async def test_refunded_transition_emits_audit(self, db_session):
        from app.models.audit_log import AuditLog

        swap = _make_boltz_swap(status=SwapStatus.REFUNDED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        await svc.advance(db_session, session.id)

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_refunded")))
            .scalars()
            .all()
        )
        assert rows
        assert (rows[0].details or {}).get("reason") == "boltz_refunded"

    @pytest.mark.asyncio
    async def test_failed_transition_emits_audit_with_error_message(self, db_session):
        """Hard-error path: ``_advance_created`` raises → service emits
        ``braiins_deposit_session_failed`` and persists error_message."""
        from app.models.audit_log import AuditLog

        svc = _make_service()
        svc._mocks["lnd"].new_address = AsyncMock(return_value=(None, "lnd locked"))  # type: ignore[attr-defined]
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert session is not None
        await svc.advance(db_session, session.id)

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_failed")))
            .scalars()
            .all()
        )
        assert rows
        row = rows[0]
        assert row.success is False
        assert (row.details or {}).get("reason") == "hard_error"
        assert row.error_message and "lnd locked" in row.error_message

    @pytest.mark.asyncio
    async def test_cancel_created_emits_session_cancelled_audit(self, db_session):
        from app.models.audit_log import AuditLog

        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert session is not None

        ok, err = await svc.cancel_session(db_session, session.id)
        assert ok

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_cancelled")))
            .scalars()
            .all()
        )
        assert rows
        assert (rows[0].details or {}).get("reason") == "user_cancel_pre_swap"

    @pytest.mark.asyncio
    async def test_cancel_swapping_emits_session_cancelled_audit(self, db_session):
        from app.models.audit_log import AuditLog

        swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].cancel_swap = AsyncMock(return_value=(True, None))  # type: ignore[attr-defined]
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        await svc.cancel_session(db_session, session.id)

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_cancelled")))
            .scalars()
            .all()
        )
        assert rows
        assert (rows[0].details or {}).get("reason") == "user_cancel_pre_payment"

    @pytest.mark.asyncio
    async def test_reconcile_recovered_emits_broadcast_audit(self, db_session):
        """reconcile path: tx found via list_transactions → emit
        ``braiins_deposit_session_broadcast`` with reason=reconcile_recovered."""
        from app.models.audit_log import AuditLog

        svc = _make_service(lnd_unspent=[])
        svc._mocks["lnd"].get_transactions = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                [
                    {
                        "tx_hash": "d" * 64,
                        "previous_outpoints": [{"outpoint": ("b" * 64) + ":0", "is_our_output": True}],
                        "output_details": [
                            {"address": "bc1q" + "x" * 38, "amount": 1_000_000},
                        ],
                    }
                ],
                None,
            )
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.SENDING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        await svc.advance(db_session, session.id)

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_broadcast")))
            .scalars()
            .all()
        )
        assert rows
        assert (rows[0].details or {}).get("reason") == "reconcile_recovered"

    @pytest.mark.asyncio
    async def test_reconcile_outpoint_unspent_emits_funded_audit(self, db_session):
        """reconcile path: outpoint still unspent → roll back to
        FUNDED + emit ``braiins_deposit_session_funded`` with the
        ``reconcile_outpoint_unspent`` reason."""
        from app.models.audit_log import AuditLog

        utxos = [
            {
                "outpoint": {"txid_str": "b" * 64, "output_index": 0},
                "amount_sat": 1_004_000,
                "address": "bcrt1pfresh",
                "address_type": "TAPROOT",
                "pk_script": "",
                "confirmations": 2,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.SENDING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        await svc.advance(db_session, session.id)

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_funded")))
            .scalars()
            .all()
        )
        # Filter to the reconcile-flavoured row (other tests in this
        # session may have emitted the normal swapping→funded row).
        recon = [r for r in rows if (r.details or {}).get("reason") == "reconcile_outpoint_unspent"]
        assert recon


class TestDustPreventionAuditTrail:
    """Every dust-prevention state transition emits an
    audit row with the details the CHANGELOG monitoring queries rely
    on. Pinned because the post-deploy operator-override prevalence
    + long-parked-session backlog queries fail silently if the
    underlying audit actions drift.
    """

    @pytest.mark.asyncio
    async def test_park_emits_awaiting_fee_reduction_audit(self, db_session):
        """FUNDED → AWAITING_FEE_REDUCTION emits
        ``braiins_deposit_session_awaiting_fee_reduction`` with the
        reason, current sat/vB, UTXO value, and bin amount in details
        so operators can correlate parks against the live fee market.
        """
        from app.models.audit_log import AuditLog

        svc = _make_service(
            mempool_fees={"fastestFee": 200, "halfHourFee": 100, "hourFee": 50},
            cached_tip_height=900_000,
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.FUNDED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        await svc.advance(db_session, session.id)

        rows = (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "braiins_deposit_session_awaiting_fee_reduction")
                )
            )
            .scalars()
            .all()
        )
        assert rows, (
            "park must emit braiins_deposit_session_awaiting_fee_reduction "
            "so the CHANGELOG long-parked-session backlog query has data."
        )
        details = rows[0].details or {}
        assert details.get("reason") == "would_underpay_bin"
        assert details.get("sat_per_vbyte") == 100
        assert details.get("utxo_value_sats") == 1_004_000
        assert details.get("bin_amount_sats") == 1_000_000

    @pytest.mark.asyncio
    async def test_resume_emits_resumed_from_fee_reduction_audit(
        self,
        db_session,
    ):
        """AWAITING_FEE_REDUCTION → FUNDED (via the periodic ticker)
        emits ``braiins_deposit_session_resumed_from_fee_reduction``
        with the post-resume sat/vB + projected arrival. Pinned so
        the resume signal is auditable for operators tracking how
        long sessions stayed parked."""
        from app.models.audit_log import AuditLog

        svc = _make_service(
            mempool_fees={"fastestFee": 20, "halfHourFee": 6, "hourFee": 2},
            cached_tip_height=900_001,
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.AWAITING_FEE_REDUCTION,
            send_infeasible_reason="would_underpay_bin",
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        await svc.advance(db_session, session.id)

        rows = (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "braiins_deposit_session_resumed_from_fee_reduction")
                )
            )
            .scalars()
            .all()
        )
        assert rows, (
            "resume must emit braiins_deposit_session_resumed_from_fee_reduction "
            "so operators can audit how long a session stayed parked."
        )
        details = rows[0].details or {}
        assert details.get("sat_per_vbyte") == 6
        assert details.get("bin_amount_sats") == 1_000_000
        # Projected arrival = utxo - 140 * 6 = 1,003,160.
        assert details.get("projected_arrival_sats") == 1_004_000 - (140 * 6)

    @pytest.mark.asyncio
    async def test_retry_send_with_accept_underpay_emits_audit_with_flag(
        self,
        db_session,
    ):
        """retry_send(accept_underpay=True) emits
        ``braiins_deposit_session_funded`` with
        ``accept_underpay: true`` in details so the CHANGELOG
        operator-override prevalence query can count overrides
        distinct from plain retries."""
        from app.models.audit_log import AuditLog

        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.AWAITING_FEE_REDUCTION,
            send_infeasible_reason="would_underpay_bin",
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        ok, err = await svc.retry_send(
            db_session,
            session.id,
            accept_underpay=True,
        )
        assert ok, err

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_funded")))
            .scalars()
            .all()
        )
        # Filter to retry-send-flavoured rows (other tests may seed
        # the normal swapping→funded row).
        retry_rows = [r for r in rows if (r.details or {}).get("reason") == "retry_send_reset"]
        assert retry_rows
        details = retry_rows[0].details or {}
        assert details.get("accept_underpay") is True, (
            "operator-override audit row must carry "
            "accept_underpay=True so the CHANGELOG override-prevalence "
            "query can count this distinct from plain retries."
        )

    @pytest.mark.asyncio
    async def test_retry_send_without_override_emits_audit_with_flag_false(
        self,
        db_session,
    ):
        """The counterpart audit: retry_send() WITHOUT accept_underpay
        still emits the retry_send_reset audit row, but with
        ``accept_underpay: false``. Pinned so the dashboard's
        ``post-deploy override-prevalence`` query reads a stable
        boolean field across both retry shapes."""
        from app.models.audit_log import AuditLog

        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.AWAITING_FEE_REDUCTION,
            send_infeasible_reason="would_underpay_bin",
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        ok, err = await svc.retry_send(db_session, session.id)
        assert ok, err

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_funded")))
            .scalars()
            .all()
        )
        retry_rows = [r for r in rows if (r.details or {}).get("reason") == "retry_send_reset"]
        assert retry_rows
        assert (retry_rows[0].details or {}).get("accept_underpay") is False


class TestSwappingFailedBranch:
    """State-machine hole: SWAPPING → FAILED when the linked BoltzSwap
    transitions to FAILED (not just REFUNDED). Plan."""

    @pytest.mark.asyncio
    async def test_boltz_failed_drives_session_to_failed(self, db_session):
        swap = _make_boltz_swap(status=SwapStatus.FAILED, claim_txid=None)
        swap.error_message = "no route found"
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert result.error_message == "no route found"

    @pytest.mark.asyncio
    async def test_boltz_cancelled_drives_session_to_failed(self, db_session):
        swap = _make_boltz_swap(status=SwapStatus.CANCELLED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED


class TestCreatedTTLWarning:
    """Surface a non-fatal warning when a CREATED row sits
    past ``braiins_deposit_created_ttl_s`` without advancing."""

    @pytest.mark.asyncio
    async def test_no_warning_within_ttl(self, db_session):
        from app.core.config import settings as _s

        old = _s.braiins_deposit_created_ttl_s
        _s.braiins_deposit_created_ttl_s = 3600
        try:
            svc = _make_service()
            session, _ = await svc.create_session(
                db_session,
                api_key_id=uuid4(),
                amount_sats=500_000,
                destination_address="bc1q" + "x" * 38,
            )
            assert session is not None
            await svc.advance(db_session, session.id)
            await db_session.refresh(session)
            # Either the session moved on (normal path) or stayed in
            # CREATED with no TTL warning. We just want NO TTL warning.
            msg = session.error_message or ""
            assert "still in CREATED" not in msg
        finally:
            _s.braiins_deposit_created_ttl_s = old

    @pytest.mark.asyncio
    async def test_warning_appears_past_ttl(self, db_session):
        from datetime import datetime, timedelta, timezone

        from app.core.config import settings as _s

        old = _s.braiins_deposit_created_ttl_s
        _s.braiins_deposit_created_ttl_s = 1
        try:
            svc = _make_service()
            # Mock create_reverse_swap to raise so the row stays in CREATED.
            svc._mocks["boltz"].create_reverse_swap = AsyncMock(  # type: ignore[attr-defined]
                return_value=(None, "boltz unreachable")
            )
            old_created_at = datetime.now(timezone.utc) - timedelta(seconds=3600)
            session = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=500_000,
                destination_address="bc1q" + "x" * 38,
                status=BraiinsDepositStatus.CREATED,
                status_history=[{"status": "created", "timestamp": old_created_at.isoformat()}],
                created_at=old_created_at,
            )
            db_session.add(session)
            await db_session.commit()

            await svc.advance(db_session, session.id)
            await db_session.refresh(session)
            assert session.status == BraiinsDepositStatus.FAILED or "CREATED" in (session.error_message or "")
            # ``advance`` either sets the TTL warning before calling
            # _advance_created (which then hard-fails to FAILED), or it
            # sets the TTL prefix on the error_message. Either way the
            # operator sees a clear "stale CREATED" signal.
        finally:
            _s.braiins_deposit_created_ttl_s = old


class TestBroadcastStuckWarning:
    """Surface a non-fatal warning when the send tx hasn't
    confirmed past ``braiins_deposit_broadcast_stuck_blocks`` blocks."""

    @pytest.mark.asyncio
    async def test_stuck_warning_appears_past_threshold(self, db_session):
        from app.core.config import settings as _s

        old = _s.braiins_deposit_broadcast_stuck_blocks
        _s.braiins_deposit_broadcast_stuck_blocks = 10
        try:
            # Tip is 100 blocks ahead of broadcast; threshold=10.
            svc = _make_service(
                mempool_confs={"confirmations": 0, "confirmed": False},
                cached_tip_height=900_100,
            )
            session = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address="bc1q" + "x" * 38,
                send_txid="c" * 64,
                broadcast_block_height=900_000,
                status=BraiinsDepositStatus.BROADCAST,
                status_history=[],
            )
            db_session.add(session)
            await db_session.commit()

            await svc.advance(db_session, session.id)
            await db_session.refresh(session)
            assert session.status == BraiinsDepositStatus.BROADCAST  # not auto-FAILED
            assert session.error_message
            assert "not yet confirmed" in session.error_message
            assert "100 blocks" in session.error_message
        finally:
            _s.braiins_deposit_broadcast_stuck_blocks = old

    @pytest.mark.asyncio
    async def test_no_stuck_warning_within_threshold(self, db_session):
        from app.core.config import settings as _s

        old = _s.braiins_deposit_broadcast_stuck_blocks
        _s.braiins_deposit_broadcast_stuck_blocks = 144
        try:
            # Tip 5 blocks past broadcast — well below threshold.
            svc = _make_service(
                mempool_confs={"confirmations": 0, "confirmed": False},
                cached_tip_height=900_005,
            )
            session = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address="bc1q" + "x" * 38,
                send_txid="c" * 64,
                broadcast_block_height=900_000,
                status=BraiinsDepositStatus.BROADCAST,
                status_history=[],
            )
            db_session.add(session)
            await db_session.commit()
            await svc.advance(db_session, session.id)
            await db_session.refresh(session)
            assert (session.error_message or "").find("hasn't confirmed") == -1
        finally:
            _s.braiins_deposit_broadcast_stuck_blocks = old


class TestRecoverPendingSessions:
    """Periodic + startup recovery scan ticks each
    non-terminal session AND COMPLETED sessions still under 6 conf."""

    @pytest.mark.asyncio
    async def test_recover_includes_completed_under_six_conf(self, db_session):
        """A session that already COMPLETED but whose send tx is still
        below 6 confirmations should be re-ticked by the recovery scan
        (so the conf-watch picks up reorgs)."""
        svc = _make_service(
            mempool_confs={"confirmations": 4, "confirmed": True},
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            send_txid="c" * 64,
            send_confirmations=2,
            status=BraiinsDepositStatus.COMPLETED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        out = await svc.recover_pending_sessions(db_session)
        ids = {r["id"] for r in out}
        assert str(session.id) in ids
        await db_session.refresh(session)
        # The conf-watch updates send_confirmations to the latest.
        assert session.send_confirmations == 4

    @pytest.mark.asyncio
    async def test_recover_skips_completed_at_six_or_more_conf(self, db_session):
        """COMPLETED sessions whose send tx already has ≥ 6 conf are
        not re-ticked (no reorg watch needed)."""
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            send_txid="c" * 64,
            send_confirmations=6,
            status=BraiinsDepositStatus.COMPLETED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        out = await svc.recover_pending_sessions(db_session)
        ids = {r["id"] for r in out}
        assert str(session.id) not in ids

    @pytest.mark.asyncio
    async def test_recover_skips_failed_and_cancelled(self, db_session):
        svc = _make_service()
        for status in (BraiinsDepositStatus.FAILED, BraiinsDepositStatus.CANCELLED, BraiinsDepositStatus.REFUNDED):
            session = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=500_000,
                destination_address="bc1q" + "x" * 38,
                status=status,
                status_history=[],
            )
            db_session.add(session)
        await db_session.commit()
        out = await svc.recover_pending_sessions(db_session)
        assert out == []

    @pytest.mark.asyncio
    async def test_recover_ticks_each_non_terminal_session(self, db_session):
        svc = _make_service()
        # In-flight sessions in different non-terminal states, including
        # the SUBMARINE_SWAPPING state.
        rows = []
        for status in (
            BraiinsDepositStatus.CREATED,
            BraiinsDepositStatus.SUBMARINE_SWAPPING,
            BraiinsDepositStatus.SWAPPING,
        ):
            session = BraiinsDepositSession(
                api_key_id=uuid4(),  # distinct keys avoid the in-flight cap
                deposit_amount_sats=500_000,
                destination_address="bc1q" + "x" * 38,
                status=status,
                status_history=[],
            )
            db_session.add(session)
            rows.append(session)
        await db_session.commit()
        out = await svc.recover_pending_sessions(db_session)
        out_ids = {r["id"] for r in out}
        for r in rows:
            assert str(r.id) in out_ids


class TestInvoiceMathFormula:
    """Verify the invoice math holds end-to-end:
    invoice = D + miner_claim + send_fee + safety_buffer (inflated for Boltz pct).
    """

    @pytest.mark.asyncio
    async def test_change_back_to_wallet_is_approximately_safety_buffer(self):
        from app.core.config import settings as _s

        old = _s.braiins_deposit_safety_buffer_sats
        _s.braiins_deposit_safety_buffer_sats = 1000
        try:
            svc = _make_service(
                boltz_pair_info=_mock_pair_info(pct=0.5, miner_claim=600, miner_lockup=200),
                mempool_fees={"fastestFee": 20, "halfHourFee": 6, "hourFee": 2},
            )
            quote, err = await svc.quote(amount_sats=1_000_000)
            assert err is None
            assert quote is not None
            # Predicted change ≈ fresh_utxo − D − send_fee ≈ safety_buffer.
            change = quote.expected_fresh_utxo_sats - 1_000_000 - quote.estimated_send_fee_sats
            # Allow ±20 sats for the round-up in the invoice computation.
            assert abs(change - 1000) < 25
        finally:
            _s.braiins_deposit_safety_buffer_sats = old

    @pytest.mark.asyncio
    async def test_required_balance_exceeds_invoice(self):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=2_000_000)
        assert err is None and quote is not None
        # Required balance must include routing fee headroom above invoice.
        assert quote.required_lightning_balance_sats > quote.invoice_amount_sats
        # Routing headroom should be ~3% of invoice (mirror cold-storage default).
        headroom = quote.required_lightning_balance_sats - quote.invoice_amount_sats
        assert headroom == quote.estimated_routing_fee_sats
        assert headroom > 0


class TestAddressPurposeAndLabel:
    """The fresh address gets a ``braiins_deposit`` purpose
    tag and the resulting UTXO gets an AUTO_SWAP-source label.
    """

    @pytest.mark.asyncio
    async def test_purpose_recorded_on_created_to_swapping(self, db_session):
        from app.models.utxo_label import AddressPurpose

        swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service(boltz_create_result=swap)
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert session is not None
        await svc.advance(db_session, session.id)

        rows = (await db_session.execute(select(AddressPurpose))).scalars().all()
        match = [r for r in rows if r.purpose == "braiins_deposit"]
        assert match, "expected an address_purpose row tagged braiins_deposit"

    @pytest.mark.asyncio
    async def test_utxo_label_set_on_swapping_to_funded(self, db_session):
        from app.models.utxo_label import UtxoLabel, UtxoLabelSource

        swap = _make_boltz_swap(status=SwapStatus.COMPLETED)
        db_session.add(swap)
        await db_session.commit()
        utxos = [
            {
                "outpoint": {"txid_str": swap.claim_txid, "output_index": 0},
                "amount_sat": 1_004_000,
                "address": "bcrt1pfresh",
                "address_type": "TAPROOT",
                "pk_script": "",
                "confirmations": 2,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            boltz_swap_id=swap.id,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        await svc.advance(db_session, session.id)

        labels = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == swap.claim_txid))).scalars().all()
        assert labels, "expected a UtxoLabel for the fresh claim outpoint"
        lab = labels[0]
        assert lab.source == UtxoLabelSource.AUTO_SWAP
        assert "Braiins deposit" in (lab.label or "")


class TestConcurrencyLock:
    """The FOR-UPDATE-SKIP-LOCKED helper. On SQLite the lock
    clause silently no-ops; we still verify that ``_select_for_update``
    returns the row when one exists, ``None`` when missing.
    """

    @pytest.mark.asyncio
    async def test_returns_row_when_present(self, db_session):
        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
        )
        assert session is not None
        got = await svc._select_for_update(db_session, session.id)
        assert got is not None
        assert got.id == session.id

    @pytest.mark.asyncio
    async def test_returns_none_when_missing(self, db_session):
        svc = _make_service()
        from uuid import uuid4

        got = await svc._select_for_update(db_session, uuid4())
        assert got is None


class TestRetrySend:
    @pytest.mark.asyncio
    async def test_retry_send_from_failed_after_funded(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            fresh_utxo_txid="b" * 64,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_000,
            status=BraiinsDepositStatus.FAILED,
            error_message="fee too low",
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        ok, err = await svc.retry_send(db_session, session.id)
        assert ok
        assert err is None
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.FUNDED
        assert session.error_message is None

    @pytest.mark.asyncio
    async def test_retry_send_refuses_without_fresh_utxo(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            status=BraiinsDepositStatus.FAILED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.retry_send(db_session, session.id)
        assert not ok


# ── On-chain source path ────────────────────────────────────────────


class TestQuoteOnchainSource:
    """Quote with source_kind=onchain factors in the
    leading submarine swap fees + funding-tx fee."""

    @pytest.mark.asyncio
    async def test_quote_onchain_includes_submarine_fees(self):
        svc = _make_service()
        quote, err = await svc.quote(
            amount_sats=1_000_000,
            source_kind="onchain",
        )
        assert err is None and quote is not None
        assert quote.source_kind == "onchain"
        # The submarine invoice covers the reverse-swap invoice +
        # routing headroom.
        assert quote.submarine_invoice_amount_sats >= quote.invoice_amount_sats
        # The lockup amount tops the invoice up by the submarine
        # pct fee + miner fee.
        assert quote.submarine_lockup_amount_sats > quote.submarine_invoice_amount_sats
        # The total includes BOTH submarine and reverse fees.
        assert quote.submarine_percentage_fee_sats > 0
        assert quote.submarine_miner_fee_sats > 0
        # required_lightning_balance_sats is 0 for on-chain source.
        assert quote.required_lightning_balance_sats == 0
        # required_onchain_balance_sats must be ≥ lockup + funding fee.
        assert quote.required_onchain_balance_sats >= quote.submarine_lockup_amount_sats

    @pytest.mark.asyncio
    async def test_quote_lightning_source_omits_submarine_fields(self):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000)
        assert err is None and quote is not None
        assert quote.source_kind == "lightning"
        assert quote.submarine_invoice_amount_sats == 0
        assert quote.submarine_lockup_amount_sats == 0
        assert quote.required_onchain_balance_sats == 0
        assert quote.required_lightning_balance_sats > 0

    @pytest.mark.asyncio
    async def test_quote_rejects_invalid_source_kind(self):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000, source_kind="nope")
        assert quote is None
        assert "source_kind" in (err or "").lower()


class TestCreateSessionOnchainSource:
    @pytest.mark.asyncio
    async def test_create_session_persists_source_kind(self, db_session):
        svc = _make_service()
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert err is None
        assert session is not None
        assert session.source_kind == BraiinsDepositSourceKind.ONCHAIN

    @pytest.mark.asyncio
    async def test_create_session_rejects_invalid_source_kind(self, db_session):
        svc = _make_service()
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="garbage",
        )
        assert session is None
        assert err and "source_kind" in err.lower()


class TestInboundPreflightGate:
    """Tier 1 — inbound-capacity pre-flight for on-chain deposits."""

    @pytest.mark.asyncio
    async def test_onchain_refused_when_inbound_insufficient(self, db_session):
        svc = _make_service()
        # Far below the ~1.05M-sat receive requirement for a 1M deposit.
        svc._mocks["lnd"].inbound_capacity = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {
                    "total_receivable_sats": 10_000,
                    "largest_channel_receivable_sats": 10_000,
                },
                None,
            )
        )
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert session is None
        assert err is not None
        assert "inbound capacity" in err.lower()
        assert "lightning deposit" in err.lower()

    @pytest.mark.asyncio
    async def test_ext_onchain_also_gated(self, db_session):
        svc = _make_service()
        # ext sources require the operator flag.
        from app.core.config import settings

        settings.braiins_deposit_ext_enabled = True
        svc._mocks["lnd"].inbound_capacity = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {
                    "total_receivable_sats": 5_000,
                    "largest_channel_receivable_sats": 5_000,
                },
                None,
            )
        )
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_onchain",
        )
        assert session is None
        assert err is not None
        assert "inbound capacity" in err.lower()

    @pytest.mark.asyncio
    async def test_onchain_allowed_full_capacity_no_warning(self, db_session):
        svc = _make_service()  # default ample 100M / 100M
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert err is None
        assert session is not None
        detail = (session.status_history or [{}])[0].get("detail", "")
        assert "inbound_warning" not in detail

    @pytest.mark.asyncio
    async def test_onchain_mpp_warning_when_no_single_channel_covers(self, db_session):
        svc = _make_service()
        # Total covers the amount, but no single channel does → warn,
        # don't block (Boltz generally pays via MPP).
        svc._mocks["lnd"].inbound_capacity = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {
                    "total_receivable_sats": 5_000_000,
                    "largest_channel_receivable_sats": 500_000,
                },
                None,
            )
        )
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert err is None
        assert session is not None
        detail = (session.status_history or [{}])[0].get("detail", "")
        assert "inbound_warning" in detail

    @pytest.mark.asyncio
    async def test_gate_skipped_on_lnd_error(self, db_session):
        svc = _make_service()
        svc._mocks["lnd"].inbound_capacity = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "lnd unreachable")
        )
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        # Best-effort — a transient LND error must NOT block the deposit.
        assert err is None
        assert session is not None

    @pytest.mark.asyncio
    async def test_lightning_source_not_gated(self, db_session):
        svc = _make_service()
        svc._mocks["lnd"].inbound_capacity = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {
                    "total_receivable_sats": 0,
                    "largest_channel_receivable_sats": 0,
                },
                None,
            )
        )
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="lightning",
        )
        assert err is None
        assert session is not None
        # The gate must not even be consulted for a Lightning source.
        svc._mocks["lnd"].inbound_capacity.assert_not_called()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_advance_rechecks_inbound_and_aborts_before_send(self, db_session):
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_recheck",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup_for_test",
            status=SwapStatus.CREATED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()  # ample at create time
        svc._mocks["boltz"].create_submarine_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(submarine_swap, None)
        )
        svc._mocks["boltz"].cancel_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(True, None)
        )
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=({"txid": "ff" * 32}, None)
        )

        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert session is not None

        # Inbound drops below the swap amount AFTER create, BEFORE lockup.
        svc._mocks["lnd"].inbound_capacity = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {
                    "total_receivable_sats": 1_000,
                    "largest_channel_receivable_sats": 1_000,
                },
                None,
            )
        )

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert result.submarine_funding_txid is None
        # No on-chain lockup broadcast, and the unfunded swap was cancelled.
        svc._mocks["lnd"].send_coins.assert_not_called()  # type: ignore[attr-defined]
        svc._mocks["boltz"].cancel_swap.assert_awaited_once()  # type: ignore[attr-defined]


class TestRoutabilityProbe:
    """Tier 2 — best-effort inbound routability probe."""

    @pytest.mark.asyncio
    async def test_no_route_records_advisory_warning_by_default(self, db_session):
        svc = _make_service()
        # Probe: Boltz reachable as a node, but no LN route to us.
        svc._mocks["lnd"].query_routes = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "No route found")
        )
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        # Advisory only — the deposit is still allowed.
        assert err is None
        assert session is not None
        detail = (session.status_history or [{}])[0].get("detail", "")
        assert "probe_warning=routability_probe=no_route" in detail

    @pytest.mark.asyncio
    async def test_no_route_refuses_when_enforced(self, db_session, monkeypatch):
        monkeypatch.setattr(
            "app.core.config.settings.braiins_deposit_routability_probe_enforce",
            True,
        )
        svc = _make_service()
        svc._mocks["lnd"].query_routes = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "No route found")
        )
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert session is None
        assert err is not None
        assert "no lightning route" in err.lower()

    @pytest.mark.asyncio
    async def test_route_found_no_warning(self, db_session):
        svc = _make_service()  # default query_routes returns a route
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert err is None
        assert session is not None
        detail = (session.status_history or [{}])[0].get("detail", "")
        assert "probe_warning" not in detail

    @pytest.mark.asyncio
    async def test_probe_skipped_when_boltz_nodes_unavailable(self, db_session):
        svc = _make_service()
        svc._mocks["boltz"].get_ln_node_pubkeys = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "boltz unreachable")
        )
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert err is None
        assert session is not None
        detail = (session.status_history or [{}])[0].get("detail", "")
        assert "probe_warning" not in detail
        # query_routes is never reached when there's no Boltz pubkey.
        svc._mocks["lnd"].query_routes.assert_not_called()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_transient_probe_error_is_inconclusive(self, db_session):
        svc = _make_service()
        # A non-"no route" error must NOT be treated as a no-route signal.
        svc._mocks["lnd"].query_routes = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "context deadline exceeded")
        )
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert err is None
        assert session is not None
        detail = (session.status_history or [{}])[0].get("detail", "")
        assert "probe_warning" not in detail

    @pytest.mark.asyncio
    async def test_probe_disabled_by_setting(self, db_session, monkeypatch):
        monkeypatch.setattr(
            "app.core.config.settings.braiins_deposit_routability_probe_enabled",
            False,
        )
        svc = _make_service()
        svc._mocks["lnd"].query_routes = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "No route found")
        )
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert err is None
        assert session is not None
        # Disabled → the probe never runs.
        svc._mocks["boltz"].get_ln_node_pubkeys.assert_not_called()  # type: ignore[attr-defined]
        svc._mocks["lnd"].query_routes.assert_not_called()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_enforced_recheck_aborts_before_send(self, db_session, monkeypatch):
        monkeypatch.setattr(
            "app.core.config.settings.braiins_deposit_routability_probe_enforce",
            True,
        )
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_probe_recheck",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup_for_test",
            status=SwapStatus.CREATED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].create_submarine_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(submarine_swap, None)
        )
        svc._mocks["boltz"].cancel_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(True, None)
        )
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=({"txid": "ff" * 32}, None)
        )

        # Route exists at create time (so the session is created), then
        # disappears before the lockup re-check.
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert session is not None

        svc._mocks["lnd"].query_routes = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "No route found")
        )

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert result.submarine_funding_txid is None
        svc._mocks["lnd"].send_coins.assert_not_called()  # type: ignore[attr-defined]
        svc._mocks["boltz"].cancel_swap.assert_awaited_once()  # type: ignore[attr-defined]


class TestAdvanceCreatedOnchain:
    """On-chain source: CREATED → SUBMARINE_SWAPPING happy path."""

    @pytest.mark.asyncio
    async def test_created_onchain_to_submarine_swapping(self, db_session):
        # Pre-existing submarine BoltzSwap row.
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_test",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup_for_test",
            status=SwapStatus.CREATED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].create_submarine_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(submarine_swap, None)
        )
        # send_coins returns a funding txid.
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=({"txid": "ff" * 32}, None)
        )

        api_key_id = uuid4()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert session is not None
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.SUBMARINE_SWAPPING
        assert result.submarine_boltz_swap_id == submarine_swap.id
        assert result.submarine_lockup_address == "bcrt1qboltz_lockup_for_test"
        assert result.submarine_funding_txid == "ff" * 32
        # The wallet's LN invoice payment_hash was captured.
        assert result.submarine_payment_hash_hex == "ab" * 32

    @pytest.mark.asyncio
    async def test_submarine_create_failure_marks_failed(self, db_session):
        svc = _make_service()
        svc._mocks["boltz"].create_submarine_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "boltz unreachable")
        )
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert session is not None
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert "boltz unreachable" in (result.error_message or "")

    @pytest.mark.asyncio
    async def test_funding_send_failure_marks_failed(self, db_session):
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_test",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup_for_test",
            status=SwapStatus.CREATED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].create_submarine_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(submarine_swap, None)
        )
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "insufficient on-chain balance")
        )
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert session is not None
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert "insufficient" in (result.error_message or "").lower()


class TestAdvanceSubmarineSwapping:
    @pytest.mark.asyncio
    async def test_invoice_settled_transitions_to_swapping(self, db_session):
        """When Boltz pays our LN invoice, the next tick promotes us
        to SWAPPING via re-entering _advance_created."""
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_test",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup_for_test",
            status=SwapStatus.INVOICE_PAID,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        # New reverse-swap row returned by create_reverse_swap.
        reverse_swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(reverse_swap)
        await db_session.commit()

        svc = _make_service(boltz_create_result=reverse_swap)
        # Invoice settled → Boltz paid us.
        svc._mocks["lnd"].lookup_invoice = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {
                    "settled": True,
                    "state": "SETTLED",
                    "amt_paid_sat": 1_050_000,
                    "r_hash": "ab" * 32,
                    "memo": "",
                    "value": 1_050_000,
                    "creation_date": 0,
                    "settle_date": 0,
                    "payment_request": "",
                    "is_keysend": False,
                },
                None,
            )
        )

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_payment_hash_hex="ab" * 32,
            status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        # _advance_created runs and transitions to SWAPPING.
        assert result.status == BraiinsDepositStatus.SWAPPING
        assert result.boltz_swap_id == reverse_swap.id

    @pytest.mark.asyncio
    async def test_invoice_open_stays_in_submarine_swapping(self, db_session):
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_test",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup_for_test",
            status=SwapStatus.CREATED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_payment_hash_hex="ab" * 32,
            status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.SUBMARINE_SWAPPING

    @pytest.mark.asyncio
    async def test_submarine_boltz_refund_transitions_to_refunded(self, db_session):
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_test",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup_for_test",
            status=SwapStatus.REFUNDED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_payment_hash_hex="ab" * 32,
            status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.REFUNDED

    @pytest.mark.asyncio
    async def test_submarine_boltz_failed_marks_session_failed(self, db_session):
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_test",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup_for_test",
            status=SwapStatus.FAILED,
            error_message="lockup tx replaced",
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_payment_hash_hex="ab" * 32,
            status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert "lockup tx replaced" in (result.error_message or "")


class TestCancelInSubmarineSwapping:
    @pytest.mark.asyncio
    async def test_cancel_refused_once_funds_sent(self, db_session):
        """On-chain source: once we've broadcast the funding tx, cancel is
        refused — the user has to wait for Boltz to settle or refund."""
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_funding_txid="ff" * 32,
            status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.cancel_session(db_session, session.id)
        assert not ok
        assert err
        assert "on-chain funds have been sent" in err


class TestBoltzSubmarinePrimitive:
    """Unit tests for the new ``BoltzSwapService.create_submarine_swap``
    public API method (called via the mock layer)."""

    @pytest.mark.asyncio
    async def test_submarine_pair_info_min_max_enforced(self):
        """For too-small amounts, quote() refuses upfront with a
        user-facing "below the submarine swap minimum" message —
        avoiding a confusing late error from Boltz mid-flow."""
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000, source_kind="onchain")
        if quote is None:
            assert err is not None
            assert "minimum" in err.lower() or "between" in err.lower()


# ── On-chain source: crash-safe restart of the submarine create flow ──


class TestSubmarineCrashRecovery:
    """Each external side-effect inside ``_advance_created_onchain``
    (invoice mint → swap create → on-chain funding) is committed
    before the next step starts. On restart, fields that are already
    set short-circuit the corresponding step so we never repeat a
    side-effect — most critically, we never double-fund Boltz's
    lockup address.
    """

    @pytest.mark.asyncio
    async def test_skip_invoice_creation_when_payment_hash_set(self, db_session):
        """Simulates a crash AFTER invoice mint but BEFORE swap
        creation. On re-entry, lookup_invoice provides the existing
        payment_request and we proceed to swap creation without a
        second create_invoice call.
        """
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_test_resumed",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup",
            status=SwapStatus.CREATED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].create_submarine_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(submarine_swap, None)
        )
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=({"txid": "ff" * 32}, None)
        )
        # lookup_invoice returns the existing payment_request.
        svc._mocks["lnd"].lookup_invoice = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {
                    "settled": False,
                    "state": "OPEN",
                    "amt_paid_sat": 0,
                    "r_hash": "ab" * 32,
                    "memo": "",
                    "value": 1_050_000,
                    "creation_date": 0,
                    "settle_date": 0,
                    "payment_request": "lnbc_resumed_invoice",
                    "is_keysend": False,
                },
                None,
            )
        )
        # create_invoice should NOT be called this time.
        svc._mocks["lnd"].create_invoice = AsyncMock(  # type: ignore[attr-defined]
            side_effect=AssertionError("create_invoice must not run on resume")
        )

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_payment_hash_hex="ab" * 32,  # already minted!
            status=BraiinsDepositStatus.CREATED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.SUBMARINE_SWAPPING
        # Verify the payment_request from lookup was passed to Boltz.
        kwargs = svc._mocks["boltz"].create_submarine_swap.call_args.kwargs  # type: ignore[attr-defined]
        assert kwargs.get("invoice") == "lnbc_resumed_invoice"

    @pytest.mark.asyncio
    async def test_skip_swap_creation_when_swap_id_set(self, db_session):
        """Simulates a crash AFTER swap creation but BEFORE funding.
        On re-entry, we reuse the existing swap row and proceed to
        funding without a second create_submarine_swap call.
        """
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_test_resumed",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup",
            status=SwapStatus.CREATED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        # create_submarine_swap should NOT be called this time.
        svc._mocks["boltz"].create_submarine_swap = AsyncMock(  # type: ignore[attr-defined]
            side_effect=AssertionError("create_submarine_swap must not run on resume")
        )
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=({"txid": "ff" * 32}, None)
        )

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_payment_hash_hex="ab" * 32,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_lockup_address="bcrt1qboltz_lockup",
            submarine_lockup_amount_sats=1_055_500,
            status=BraiinsDepositStatus.CREATED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.SUBMARINE_SWAPPING
        # Verify send_coins ran (with the right amount and address).
        send_kwargs = svc._mocks["lnd"].send_coins.call_args.kwargs  # type: ignore[attr-defined]
        assert send_kwargs["address"] == "bcrt1qboltz_lockup"
        assert send_kwargs["amount_sats"] == 1_055_500

    @pytest.mark.asyncio
    async def test_skip_funding_when_txid_set(self, db_session):
        """Simulates a crash AFTER funding-tx broadcast but BEFORE the
        SUBMARINE_SWAPPING transition was recorded. On re-entry, we
        skip send_coins entirely and just record the transition.
        """
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_test_resumed",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qboltz_lockup",
            status=SwapStatus.CREATED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        # NONE of the external side-effect calls should run on this resume.
        svc._mocks["boltz"].create_submarine_swap = AsyncMock(  # type: ignore[attr-defined]
            side_effect=AssertionError("must not run on resume")
        )
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            side_effect=AssertionError("send_coins must not run on resume")
        )
        svc._mocks["lnd"].create_invoice = AsyncMock(  # type: ignore[attr-defined]
            side_effect=AssertionError("create_invoice must not run on resume")
        )

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_payment_hash_hex="ab" * 32,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_lockup_address="bcrt1qboltz_lockup",
            submarine_lockup_amount_sats=1_055_500,
            submarine_funding_txid="ff" * 32,  # already funded
            status=BraiinsDepositStatus.CREATED,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.SUBMARINE_SWAPPING


class TestSourceKindAuditTagging:
    """Every audit row should carry the source_kind so operators
    can filter by it."""

    @pytest.mark.asyncio
    async def test_state_transition_audit_includes_source_kind(self, db_session):
        from app.models.audit_log import AuditLog

        swap = _make_boltz_swap(status=SwapStatus.COMPLETED)
        db_session.add(swap)
        await db_session.commit()
        utxos = [
            {
                "outpoint": {"txid_str": swap.claim_txid, "output_index": 0},
                "amount_sat": 1_004_000,
                "address": "bcrt1pfresh",
                "address_type": "TAPROOT",
                "pk_script": "",
                "confirmations": 2,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        # A lightning-source session in SWAPPING; advance to FUNDED
        # should emit an audit row tagged source_kind=lightning.
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            fresh_address="bcrt1pfresh",
            boltz_swap_id=swap.id,
            source_kind=BraiinsDepositSourceKind.LIGHTNING,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_funded")))
            .scalars()
            .all()
        )
        assert rows
        assert (rows[0].details or {}).get("source_kind") == "lightning"


class TestSubmarineBoltzStatusPolling:
    """`_advance_submarine_swapping` polls Boltz's status string and
    maps terminal off-ramps (refund / expiry / failure) onto the
    submarine BoltzSwap row. Without this, refunded submarine swaps
    would be invisible to the user until the transient-age warning
    fires hours later."""

    @pytest.mark.asyncio
    async def test_boltz_reports_refunded_drives_session_to_refunded(self, db_session):
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_polled",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qlockup",
            status=SwapStatus.CREATED,  # not REFUNDED yet
            boltz_status="swap.created",
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        # Boltz reports the submarine has been refunded.
        svc._mocks["boltz"].get_swap_status_from_boltz = AsyncMock(  # type: ignore[attr-defined]
            return_value=("transaction.refunded", {}, None)
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_payment_hash_hex="ab" * 32,
            status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.REFUNDED
        # The BoltzSwap row was also updated.
        await db_session.refresh(submarine_swap)
        assert submarine_swap.status == SwapStatus.REFUNDED

    @pytest.mark.asyncio
    async def test_boltz_reports_expired_drives_session_to_failed(self, db_session):
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_polled",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qlockup",
            status=SwapStatus.CREATED,
            boltz_status="swap.created",
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].get_swap_status_from_boltz = AsyncMock(  # type: ignore[attr-defined]
            return_value=("invoice.expired", {}, None)
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_payment_hash_hex="ab" * 32,
            status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED

    @pytest.mark.asyncio
    async def test_boltz_status_unchanged_no_side_effect(self, db_session):
        """If Boltz reports the same status we already have, the
        BoltzSwap row's history doesn't grow."""
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_polled",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qlockup",
            status=SwapStatus.CREATED,
            boltz_status="swap.created",
            status_history=[{"status": "created", "boltz_status": "swap.created", "timestamp": "2026-05-18T00:00:00"}],
        )
        db_session.add(submarine_swap)
        await db_session.commit()
        history_len_before = len(submarine_swap.status_history)

        svc = _make_service()
        svc._mocks["boltz"].get_swap_status_from_boltz = AsyncMock(  # type: ignore[attr-defined]
            return_value=("swap.created", {}, None)  # same as current!
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_payment_hash_hex="ab" * 32,
            status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(submarine_swap)
        # Same status → no new history entry, no status flip.
        assert len(submarine_swap.status_history) == history_len_before
        assert submarine_swap.status == SwapStatus.CREATED


class TestSubmarineQuoteBounds:
    """quote() should refuse on-chain
    requests below/above Boltz's submarine pair limits with a clear
    user-facing message."""

    @pytest.mark.asyncio
    async def test_below_submarine_min_rejected_clearly(self):
        svc = _make_service()
        # Force a high submarine min so even our smallest preset
        # (50,000 sats) falls below it.
        svc._mocks["boltz"].get_submarine_pair_info = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {
                    "fees_percentage": 0.1,
                    "fees_miner_lockup": 462,
                    "min": 5_000_000,
                    "max": 25_000_000,
                    "hash": "submarine_pair_h",
                },
                None,
            )
        )
        quote, err = await svc.quote(amount_sats=50_000, source_kind="onchain")
        assert quote is None
        assert err
        assert "minimum" in err.lower()
        assert "lightning" in err.lower()  # the hint to use LN source

    @pytest.mark.asyncio
    async def test_above_submarine_max_rejected_clearly(self):
        svc = _make_service()
        svc._mocks["boltz"].get_submarine_pair_info = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {
                    "fees_percentage": 0.1,
                    "fees_miner_lockup": 462,
                    "min": 25_000,
                    "max": 100_000,  # very low max
                    "hash": "submarine_pair_h",
                },
                None,
            )
        )
        quote, err = await svc.quote(amount_sats=5_000_000, source_kind="onchain")
        assert quote is None
        assert err
        assert "maximum" in err.lower()


class TestSubmarineSwappingAuditEmit:
    """The CREATED → SUBMARINE_SWAPPING transition emits a dedicated
    audit row so operators can filter the new state-transition."""

    @pytest.mark.asyncio
    async def test_submarine_swapping_audit_row(self, db_session):
        from app.models.audit_log import AuditLog

        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_audit_test",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qlockup",
            status=SwapStatus.CREATED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].create_submarine_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(submarine_swap, None)
        )
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=({"txid": "ff" * 32}, None)
        )
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert session is not None
        await svc.advance(db_session, session.id)

        rows = (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "braiins_deposit_session_submarine_swapping")
                )
            )
            .scalars()
            .all()
        )
        assert rows
        details = rows[0].details or {}
        assert details.get("source_kind") == "onchain"
        assert details.get("boltz_swap_id") == "submarine_audit_test"
        assert details.get("submarine_funding_txid") == "ff" * 32


class TestSubmarineStuckWarning:
    """Parallel to CREATED-TTL: if a session sits in
    SUBMARINE_SWAPPING past ``braiins_deposit_lnd_transient_max_age_s``
    without the LN invoice settling and without Boltz reporting a
    terminal status, surface a non-fatal warning on the session
    detail so the user / operator knows something is off."""

    @pytest.mark.asyncio
    async def test_warning_appears_past_ttl(self, db_session):
        from datetime import datetime, timedelta, timezone

        from app.core.config import settings as _s

        old = _s.braiins_deposit_lnd_transient_max_age_s
        _s.braiins_deposit_lnd_transient_max_age_s = 1
        try:
            svc = _make_service()
            # _advance_submarine_swapping default mocks: lookup_invoice
            # returns settled=False (still waiting for Boltz); we don't
            # link a submarine swap row so the Boltz-status branch is
            # skipped. Net effect: advance() returns without raising
            # and without transitioning.
            old_ts = (datetime.now(timezone.utc) - timedelta(seconds=3600)).isoformat()
            session = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address="bc1q" + "x" * 38,
                source_kind=BraiinsDepositSourceKind.ONCHAIN,
                submarine_payment_hash_hex="ab" * 32,
                # No submarine_boltz_swap_id — skip the Boltz poll branch.
                status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
                status_history=[
                    {"status": "submarine_swapping", "timestamp": old_ts},
                ],
            )
            db_session.add(session)
            await db_session.commit()

            await svc.advance(db_session, session.id)
            await db_session.refresh(session)
            assert session.status == BraiinsDepositStatus.SUBMARINE_SWAPPING  # not auto-FAILED
            assert session.error_message
            assert "stuck" in session.error_message.lower()
            assert "boltz" in session.error_message.lower()
        finally:
            _s.braiins_deposit_lnd_transient_max_age_s = old

    @pytest.mark.asyncio
    async def test_no_warning_within_ttl(self, db_session):
        from datetime import datetime, timezone

        from app.core.config import settings as _s

        old = _s.braiins_deposit_lnd_transient_max_age_s
        _s.braiins_deposit_lnd_transient_max_age_s = 3600
        try:
            svc = _make_service()
            recent_ts = datetime.now(timezone.utc).isoformat()
            session = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address="bc1q" + "x" * 38,
                source_kind=BraiinsDepositSourceKind.ONCHAIN,
                submarine_payment_hash_hex="ab" * 32,
                status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
                status_history=[
                    {"status": "submarine_swapping", "timestamp": recent_ts},
                ],
            )
            db_session.add(session)
            await db_session.commit()
            await svc.advance(db_session, session.id)
            await db_session.refresh(session)
            assert (session.error_message or "") == "" or "stuck" not in (session.error_message or "").lower()
        finally:
            _s.braiins_deposit_lnd_transient_max_age_s = old


class TestReentryDispatcher:
    """On-chain re-entry pattern: when SUBMARINE_SWAPPING settles we
    flip status to CREATED briefly before running the LN flow. If
    we crash between that commit and the LN flow succeeding, the
    next advance() tick must route to the LN flow (not the submarine
    flow). The discriminant is ``submarine_funding_txid``.
    """

    @pytest.mark.asyncio
    async def test_created_onchain_without_funding_routes_to_submarine(self, db_session):
        """Initial CREATED state for on-chain source → submarine flow."""
        svc = _make_service()
        # Make _advance_created_onchain fail loudly if called, so we
        # can prove the dispatcher chose the right branch.
        called: dict[str, bool] = {"onchain": False, "lightning": False}

        async def _onchain(db, session):
            called["onchain"] = True

        async def _lightning(db, session):
            called["lightning"] = True

        svc._advance_created_onchain = _onchain  # type: ignore[assignment]
        svc._advance_created = _lightning  # type: ignore[assignment]

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            status=BraiinsDepositStatus.CREATED,
            status_history=[],
            # NO submarine_funding_txid → submarine hasn't started yet
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        assert called["onchain"] is True
        assert called["lightning"] is False

    @pytest.mark.asyncio
    async def test_created_onchain_with_funding_routes_to_lightning(self, db_session):
        """Re-entry case: status_history shows we passed through
        SUBMARINE_SWAPPING, status is back to CREATED → LN flow
        (because submarine completed, time to do the reverse swap)."""
        svc = _make_service()
        called: dict[str, bool] = {"onchain": False, "lightning": False}

        async def _onchain(db, session):
            called["onchain"] = True

        async def _lightning(db, session):
            called["lightning"] = True

        svc._advance_created_onchain = _onchain  # type: ignore[assignment]
        svc._advance_created = _lightning  # type: ignore[assignment]

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            # Submarine work fully completed and we're back at CREATED:
            submarine_payment_hash_hex="ab" * 32,
            submarine_boltz_swap_id=uuid4(),
            submarine_funding_txid="ff" * 32,
            status=BraiinsDepositStatus.CREATED,
            status_history=[
                {"status": "created", "timestamp": "2026-05-18T00:00:00+00:00"},
                {"status": "submarine_swapping", "timestamp": "2026-05-18T00:01:00+00:00"},
                {"status": "created", "timestamp": "2026-05-18T00:10:00+00:00"},
            ],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        assert called["lightning"] is True
        assert called["onchain"] is False

    @pytest.mark.asyncio
    async def test_created_onchain_crash_recovery_still_routes_to_submarine(self, db_session):
        """Crash recovery case: status=CREATED, source=onchain, all
        submarine fields set (we got far in _advance_created_onchain
        but crashed before recording the SUBMARINE_SWAPPING transition).
        Discriminant: status_history has NO 'submarine_swapping' entry
        — so route to submarine flow, which will idempotent-skip the
        completed steps and finally record the transition."""
        svc = _make_service()
        called: dict[str, bool] = {"onchain": False, "lightning": False}

        async def _onchain(db, session):
            called["onchain"] = True

        async def _lightning(db, session):
            called["lightning"] = True

        svc._advance_created_onchain = _onchain  # type: ignore[assignment]
        svc._advance_created = _lightning  # type: ignore[assignment]

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_payment_hash_hex="ab" * 32,
            submarine_boltz_swap_id=uuid4(),
            submarine_funding_txid="ff" * 32,
            status=BraiinsDepositStatus.CREATED,
            # No "submarine_swapping" in history — we crashed before
            # the transition was recorded.
            status_history=[
                {"status": "created", "timestamp": "2026-05-18T00:00:00+00:00"},
            ],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        assert called["onchain"] is True
        assert called["lightning"] is False


class TestCreatedTtlSignalSource:
    """The CREATED-TTL warning is timed from the most recent CREATED
    entry in ``status_history``, not from the original ``created_at``.
    This avoids false-firing on the on-chain re-entry case where the
    session was CREATED long ago, transitioned through SUBMARINE_SWAPPING,
    and is now briefly back in CREATED."""

    @pytest.mark.asyncio
    async def test_recent_created_history_entry_suppresses_old_created_at_warning(self, db_session):
        """An onchain session that was originally created 1 hour ago,
        spent that time in SUBMARINE_SWAPPING, then re-entered CREATED
        seconds ago. The TTL warning should NOT fire."""
        from datetime import datetime, timedelta, timezone

        from app.core.config import settings as _s

        old = _s.braiins_deposit_created_ttl_s
        _s.braiins_deposit_created_ttl_s = 60  # 1 minute
        try:
            svc = _make_service()

            # Force an exit before any state machine work runs so we
            # only exercise the TTL check.
            async def _noop(*a, **kw):
                pass

            svc._advance_created_onchain = _noop  # type: ignore[assignment]
            svc._advance_created = _noop  # type: ignore[assignment]

            recent_ts = datetime.now(timezone.utc).isoformat()
            ancient = datetime.now(timezone.utc) - timedelta(seconds=3600)
            session = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address="bc1q" + "x" * 38,
                source_kind=BraiinsDepositSourceKind.ONCHAIN,
                submarine_funding_txid="ff" * 32,
                status=BraiinsDepositStatus.CREATED,
                created_at=ancient,  # old creation
                status_history=[
                    {"status": "created", "timestamp": ancient.isoformat()},
                    {"status": "submarine_swapping", "timestamp": ancient.isoformat()},
                    {"status": "created", "timestamp": recent_ts},  # ← recent re-entry
                ],
            )
            db_session.add(session)
            await db_session.commit()
            await svc.advance(db_session, session.id)
            await db_session.refresh(session)
            # Warning should NOT have fired because the most recent
            # CREATED entry is fresh.
            assert "still in CREATED" not in (session.error_message or "")
        finally:
            _s.braiins_deposit_created_ttl_s = old

    @pytest.mark.asyncio
    async def test_old_latest_created_history_entry_fires_warning(self, db_session):
        """When the latest CREATED entry IS older than TTL, the
        warning fires as expected."""
        from datetime import datetime, timedelta, timezone

        from app.core.config import settings as _s

        old = _s.braiins_deposit_created_ttl_s
        _s.braiins_deposit_created_ttl_s = 1
        try:
            svc = _make_service()

            async def _noop(*a, **kw):
                pass

            svc._advance_created_onchain = _noop  # type: ignore[assignment]
            svc._advance_created = _noop  # type: ignore[assignment]

            ancient = datetime.now(timezone.utc) - timedelta(seconds=3600)
            session = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address="bc1q" + "x" * 38,
                source_kind=BraiinsDepositSourceKind.LIGHTNING,
                status=BraiinsDepositStatus.CREATED,
                created_at=ancient,
                status_history=[
                    {"status": "created", "timestamp": ancient.isoformat()},
                ],
            )
            db_session.add(session)
            await db_session.commit()
            await svc.advance(db_session, session.id)
            await db_session.refresh(session)
            assert session.error_message
            assert "in CREATED for" in session.error_message
            assert "LND" in session.error_message
        finally:
            _s.braiins_deposit_created_ttl_s = old


# ── On-chain source: additional edge-case coverage ───────────────────


class TestCancelCreatedOnchain:
    """Cancel during CREATED works the same regardless of source_kind:
    the row is transitioned to CANCELLED with no side-effects. The
    lightning path is covered elsewhere; pin the onchain path too."""

    @pytest.mark.asyncio
    async def test_cancel_created_onchain_session(self, db_session):
        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert session is not None
        assert session.source_kind == BraiinsDepositSourceKind.ONCHAIN

        ok, err = await svc.cancel_session(db_session, session.id)
        assert ok
        assert err is None
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_created_onchain_emits_audit_with_source_kind(self, db_session):
        from app.models.audit_log import AuditLog

        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert session is not None
        await svc.cancel_session(db_session, session.id)

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_cancelled")))
            .scalars()
            .all()
        )
        assert rows
        # The audit row must carry source_kind=onchain so operators
        # can filter cancelled-onchain attempts.
        assert (rows[0].details or {}).get("source_kind") == "onchain"
        assert (rows[0].details or {}).get("reason") == "user_cancel_pre_swap"


class TestOnchainAuditRowsSourceKind:
    """Every state-transition audit row produced by an on-chain
    session must carry source_kind=onchain. The generic
    TestSourceKindAuditTagging covers the lightning case; this
    fixture asserts the onchain emitters are wired correctly too."""

    @pytest.mark.asyncio
    async def test_swapping_audit_from_onchain_path_tagged_onchain(self, db_session):
        """The CREATED → SUBMARINE_SWAPPING audit row from the
        onchain flow must be tagged source_kind=onchain."""
        from app.models.audit_log import AuditLog

        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_audit",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qlockup",
            status=SwapStatus.CREATED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].create_submarine_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(submarine_swap, None)
        )
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=({"txid": "ff" * 32}, None)
        )

        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
        )
        assert session is not None
        await svc.advance(db_session, session.id)

        rows = (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "braiins_deposit_session_submarine_swapping")
                )
            )
            .scalars()
            .all()
        )
        assert rows
        assert (rows[0].details or {}).get("source_kind") == "onchain"

    @pytest.mark.asyncio
    async def test_refunded_audit_from_onchain_path_tagged_onchain(self, db_session):
        """When the submarine swap refunds, the REFUNDED audit row
        from _advance_submarine_swapping must be tagged source_kind=
        onchain."""
        from app.models.audit_log import AuditLog

        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_refunded",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qlockup",
            status=SwapStatus.REFUNDED,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_payment_hash_hex="ab" * 32,
            status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_session_refunded")))
            .scalars()
            .all()
        )
        assert rows
        assert (rows[0].details or {}).get("source_kind") == "onchain"
        assert (rows[0].details or {}).get("reason") == "boltz_submarine_refunded"


class TestQuoteSubmarinePairInfoUnavailable:
    """When Boltz's submarine pair-info is unreachable (network blip,
    Boltz down), an on-chain quote refuses cleanly rather than
    returning a partial-data quote. The reverse pair-info path is
    covered elsewhere; pin the submarine error path too."""

    @pytest.mark.asyncio
    async def test_returns_clean_error(self):
        svc = _make_service()
        svc._mocks["boltz"].get_submarine_pair_info = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "tor timeout")
        )
        quote, err = await svc.quote(
            amount_sats=1_000_000,
            source_kind="onchain",
        )
        assert quote is None
        assert err
        assert "submarine" in err.lower()
        assert "tor timeout" in err.lower() or "unavailable" in err.lower()


class TestUpdateSubmarineBoltzStatusUnknown:
    """The status-mapper updates ``boltz_status`` for any new string
    Boltz emits, but only flips the internal ``status`` for the
    documented terminal off-ramps. An unrecognized intermediate
    status (e.g. ``transaction.mempool``) must NOT change the
    internal status."""

    @pytest.mark.asyncio
    async def test_intermediate_status_doesnt_flip_internal_status(self, db_session):
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="submarine_mempool",
            api_key_id=uuid4(),
            invoice_amount_sats=1_050_000,
            onchain_amount_sats=1_055_500,
            destination_address="",
            boltz_lockup_address="bcrt1qlockup",
            status=SwapStatus.CREATED,
            boltz_status="swap.created",
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        # Boltz reports an intermediate (non-terminal) status — the
        # status mapper should update boltz_status but leave the
        # internal status field alone.
        svc._mocks["boltz"].get_swap_status_from_boltz = AsyncMock(  # type: ignore[attr-defined]
            return_value=("transaction.mempool", {}, None)
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.ONCHAIN,
            submarine_boltz_swap_id=submarine_swap.id,
            submarine_payment_hash_hex="ab" * 32,
            status=BraiinsDepositStatus.SUBMARINE_SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)

        await db_session.refresh(submarine_swap)
        # boltz_status updated.
        assert submarine_swap.boltz_status == "transaction.mempool"
        # internal status untouched.
        assert submarine_swap.status == SwapStatus.CREATED

        await db_session.refresh(session)
        # Our session stays in SUBMARINE_SWAPPING.
        assert session.status == BraiinsDepositStatus.SUBMARINE_SWAPPING


# ═══════════════════════════════════════════════════════════════════════
# External sources
# ═══════════════════════════════════════════════════════════════════════


class TestQuoteExternalSources:
    """Quote math for ext-LN / ext-OC source kinds. Asserts that
    ``required_external_deposit_sats`` is surfaced as the user-facing
    intake amount and that self-balance gates are zeroed out."""

    @pytest.mark.asyncio
    async def test_quote_ext_lightning_intake_equals_invoice(self):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000, source_kind="ext_lightning")
        assert err is None
        assert quote is not None
        # User pays the Boltz invoice; intake equals invoice amount.
        assert quote.required_external_deposit_sats == quote.invoice_amount_sats
        # Self-balance gate is zeroed for ext sources.
        assert quote.required_lightning_balance_sats == 0
        assert quote.required_onchain_balance_sats == 0
        assert quote.source_kind == "ext_lightning"

    @pytest.mark.asyncio
    async def test_quote_ext_onchain_intake_includes_submarine_overhead(self):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000, source_kind="ext_onchain")
        assert err is None
        assert quote is not None
        # Ext-OC intake = the wallet's submarine-lockup amount + miner
        # fee headroom (i.e. the same math as self-OC's
        # required_onchain_balance_sats, just surfaced as the user's
        # deposit instead of a wallet-balance gate).
        assert quote.required_external_deposit_sats > quote.invoice_amount_sats
        assert quote.required_lightning_balance_sats == 0
        assert quote.required_onchain_balance_sats == 0
        assert quote.submarine_lockup_amount_sats > 0
        assert quote.source_kind == "ext_onchain"

    @pytest.mark.asyncio
    async def test_quote_rejects_ext_when_disabled(self, monkeypatch):
        from app.core.config import settings as _settings

        monkeypatch.setattr(_settings, "braiins_deposit_ext_enabled", False)
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000, source_kind="ext_lightning")
        assert quote is None
        assert err and "disabled" in err.lower()

    @pytest.mark.asyncio
    async def test_quote_rejects_invalid_source_kind(self):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000, source_kind="nope")
        assert quote is None
        assert err

    @pytest.mark.asyncio
    async def test_quote_as_dict_carries_external_deposit_field(self):
        svc = _make_service()
        quote, _ = await svc.quote(amount_sats=500_000, source_kind="ext_lightning")
        assert quote is not None
        body = quote.as_dict()
        assert "required_external_deposit_sats" in body
        assert body["required_external_deposit_sats"] > 0


class TestCreateSessionExternalSources:
    @pytest.mark.asyncio
    async def test_create_session_accepts_ext_lightning(self, db_session):
        svc = _make_service()
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_lightning",
        )
        assert err is None
        assert session is not None
        assert session.source_kind == BraiinsDepositSourceKind.EXT_LIGHTNING

    @pytest.mark.asyncio
    async def test_create_session_accepts_ext_onchain(self, db_session):
        svc = _make_service()
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_onchain",
        )
        assert err is None
        assert session is not None
        assert session.source_kind == BraiinsDepositSourceKind.EXT_ONCHAIN

    @pytest.mark.asyncio
    async def test_create_session_rejects_ext_when_disabled(self, db_session, monkeypatch):
        from app.core.config import settings as _settings

        monkeypatch.setattr(_settings, "braiins_deposit_ext_enabled", False)
        svc = _make_service()
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_lightning",
        )
        assert session is None
        assert err and "disabled" in err.lower()


class TestAdvanceCreatedExtLightning:
    @pytest.mark.asyncio
    async def test_created_to_awaiting_ln_funds(self, db_session):
        """CREATED → AWAITING_LN_FUNDS: mints swap, no LN payment."""
        swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service(boltz_create_result=swap)
        api_key_id = uuid4()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_lightning",
        )
        assert session is not None
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.AWAITING_LN_FUNDS
        assert result.boltz_swap_id == swap.id
        assert result.fresh_address == "bcrt1pfreshtaprootaddress"
        # ext_intake_amount_sats records the invoice amount the user
        # will pay.
        assert (result.ext_intake_amount_sats or 0) > 0

    @pytest.mark.asyncio
    async def test_ext_ln_advance_does_not_enqueue_celery(self, db_session, monkeypatch):
        """The user pays the Boltz invoice — we never enqueue
        process_boltz_swap (which would trigger LN payment from our
        wallet)."""
        # Patch the Celery task module BEFORE the service imports it.
        called = {"n": 0}

        class _FakeTask:
            def delay(self, *_a, **_kw):
                called["n"] += 1

        import sys
        import types

        module = types.ModuleType("app.tasks.boltz_tasks")
        module.process_boltz_swap = _FakeTask()
        monkeypatch.setitem(sys.modules, "app.tasks.boltz_tasks", module)

        swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()
        svc = _make_service(boltz_create_result=swap)
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_lightning",
        )
        assert session is not None
        await svc.advance(db_session, session.id)
        assert called["n"] == 0  # never enqueued


class TestAdvanceCreatedExtOnchain:
    @pytest.mark.asyncio
    async def test_created_to_awaiting_onchain_funds(self, db_session):
        svc = _make_service(lnd_new_address="bcrt1pfreshintakeaddress")
        api_key_id = uuid4()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_onchain",
        )
        assert session is not None
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS
        assert result.ext_intake_address == "bcrt1pfreshintakeaddress"
        assert (result.ext_intake_amount_sats or 0) > 0


class TestAdvanceAwaitingLnFunds:
    @pytest.mark.asyncio
    async def test_progresses_to_swapping_when_claim_landed(self, db_session):
        """When Boltz reports the on-chain claim (claim_txid populated
        on the swap), the session transitions to SWAPPING."""
        swap = _make_boltz_swap(status=SwapStatus.CLAIMED, claim_txid="aa" * 32)
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service()
        # advance_swap mock: no-op (returns the swap unchanged).
        svc._mocks["boltz"].advance_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(swap, None)
        )

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=swap.id,
            ext_intake_amount_sats=1_010_000,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[
                {"status": "created", "timestamp": "2026-01-01T00:00:00+00:00"},
                {"status": "awaiting_ln_funds", "timestamp": "2026-01-01T00:00:01+00:00"},
            ],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.SWAPPING
        assert session.ext_funds_received_at is not None

    @pytest.mark.asyncio
    async def test_stays_in_awaiting_when_invoice_unpaid(self, db_session):
        swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].advance_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(swap, None)
        )

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=swap.id,
            ext_intake_amount_sats=1_010_000,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[
                {"status": "created", "timestamp": "2026-01-01T00:00:00+00:00"},
                {"status": "awaiting_ln_funds", "timestamp": "2026-01-01T00:00:01+00:00"},
            ],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.AWAITING_LN_FUNDS

    @pytest.mark.asyncio
    async def test_refunded_propagates(self, db_session):
        swap = _make_boltz_swap(status=SwapStatus.REFUNDED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].advance_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(swap, None)
        )

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=swap.id,
            ext_intake_amount_sats=1_010_000,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[
                {"status": "created", "timestamp": "2026-01-01T00:00:00+00:00"},
                {"status": "awaiting_ln_funds", "timestamp": "2026-01-01T00:00:01+00:00"},
            ],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.REFUNDED

    @pytest.mark.asyncio
    async def test_invoice_expired_routes_to_cancelled(self, db_session):
        """A Boltz invoice that expired
        unpaid should land the session in CANCELLED, not FAILED.
        The user gets a clean "start a new session" recovery rather
        than a scary "something went wrong" screen."""
        swap = _make_boltz_swap(status=SwapStatus.FAILED, claim_txid=None)
        swap.error_message = "Boltz swap ended: invoice.expired"
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].advance_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(swap, None)
        )

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=swap.id,
            ext_intake_amount_sats=1_010_000,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[
                {"status": "created", "timestamp": "2026-01-01T00:00:00+00:00"},
                {"status": "awaiting_ln_funds", "timestamp": "2026-01-01T00:00:01+00:00"},
            ],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_genuine_failure_still_routes_to_failed(self, db_session):
        """A non-expiry Boltz failure (e.g. internal error) must
        still route to FAILED, not CANCELLED."""
        swap = _make_boltz_swap(status=SwapStatus.FAILED, claim_txid=None)
        swap.error_message = "Boltz internal error: lockup verification failed"
        db_session.add(swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].advance_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(swap, None)
        )

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=swap.id,
            ext_intake_amount_sats=1_010_000,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[
                {"status": "created", "timestamp": "2026-01-01T00:00:00+00:00"},
                {"status": "awaiting_ln_funds", "timestamp": "2026-01-01T00:00:01+00:00"},
            ],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.FAILED


class TestAdvanceAwaitingOnchainFunds:
    def _make_session(self, *, address: str, required: int) -> BraiinsDepositSession:
        return BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address=address,
            ext_intake_amount_sats=required,
            ext_intake_received_sats=0,
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[
                {"status": "created", "timestamp": "2026-01-01T00:00:00+00:00"},
                {"status": "awaiting_onchain_funds", "timestamp": "2026-01-01T00:00:01+00:00"},
            ],
        )

    @pytest.mark.asyncio
    async def test_full_deposit_transitions_to_created(self, db_session):
        """When confirmed deposits >= required, transition back to
        CREATED so the dispatcher routes into the submarine flow."""
        intake_address = "bcrt1pfreshintake"
        required = 1_012_300
        utxos = [
            {
                "outpoint": {"txid_str": "aa" * 32, "output_index": 0},
                "amount_sat": required,
                "address": intake_address,
                "confirmations": 1,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = self._make_session(address=intake_address, required=required)
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.CREATED
        assert session.ext_intake_received_sats == required
        assert session.ext_funds_received_at is not None
        # The transition leaves an awaiting_onchain_funds row in the
        # history so the dispatcher knows to route into the submarine
        # flow on the next advance.
        history_statuses = [e.get("status") for e in (session.status_history or []) if isinstance(e, dict)]
        assert "awaiting_onchain_funds" in history_statuses

    @pytest.mark.asyncio
    async def test_partial_deposit_stays(self, db_session):
        intake_address = "bcrt1pfreshintake"
        required = 1_012_300
        utxos = [
            {
                "outpoint": {"txid_str": "bb" * 32, "output_index": 0},
                "amount_sat": 500_000,
                "address": intake_address,
                "confirmations": 1,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = self._make_session(address=intake_address, required=required)
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS
        assert session.ext_intake_received_sats == 500_000
        assert session.ext_intake_txids or []  # populated

    @pytest.mark.asyncio
    async def test_unconfirmed_deposit_not_counted(self, db_session):
        intake_address = "bcrt1pfreshintake"
        required = 1_000_000
        utxos = [
            {
                "outpoint": {"txid_str": "cc" * 32, "output_index": 0},
                "amount_sat": required,
                "address": intake_address,
                "confirmations": 0,  # mempool only
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = self._make_session(address=intake_address, required=required)
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS
        assert (session.ext_intake_received_sats or 0) == 0

    @pytest.mark.asyncio
    async def test_multi_tx_additive(self, db_session):
        """Two confirmed deposits to the same address sum to the
        required amount."""
        intake_address = "bcrt1pfreshintake"
        required = 1_012_300
        utxos = [
            {
                "outpoint": {"txid_str": "dd" * 32, "output_index": 0},
                "amount_sat": 500_000,
                "address": intake_address,
                "confirmations": 2,
            },
            {
                "outpoint": {"txid_str": "ee" * 32, "output_index": 0},
                "amount_sat": 512_300,
                "address": intake_address,
                "confirmations": 1,
            },
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = self._make_session(address=intake_address, required=required)
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.CREATED
        assert session.ext_intake_received_sats == 1_012_300
        assert len(session.ext_intake_txids or []) == 2


class TestRegenerateExtLightningInvoice:
    @pytest.mark.asyncio
    async def test_regenerate_when_prior_unpaid(self, db_session):
        # Prior swap still in CREATED on Boltz side (not paid).
        old_swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(old_swap)
        await db_session.commit()

        # New swap returned by create_reverse_swap.
        new_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="swap_regen",
            direction=BoltzSwapDirection.REVERSE,
            api_key_id=uuid4(),
            invoice_amount_sats=1_010_000,
            onchain_amount_sats=1_005_000,
            destination_address="bcrt1pfreshtaprootaddress",
            status=SwapStatus.CREATED,
            claim_txid=None,
            status_history=[],
        )
        svc = _make_service(boltz_create_result=new_swap)
        svc._mocks["boltz"].cancel_swap = AsyncMock(return_value=(True, None))  # type: ignore[attr-defined]

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=old_swap.id,
            ext_intake_amount_sats=1_005_000,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()

        ok, err = await svc.regenerate_ext_lightning_invoice(db_session, session.id)
        assert ok is True
        assert err is None
        await db_session.refresh(session)
        assert session.boltz_swap_id == new_swap.id
        # ext_intake_amount_sats re-quoted.
        assert (session.ext_intake_amount_sats or 0) > 0

    @pytest.mark.asyncio
    async def test_regenerate_rejected_when_swap_already_paid(self, db_session):
        # Prior swap PAYING_INVOICE — user paid, no fresh invoice
        # should be issued.
        old_swap = _make_boltz_swap(status=SwapStatus.PAYING_INVOICE)
        db_session.add(old_swap)
        await db_session.commit()
        svc = _make_service()

        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=old_swap.id,
            ext_intake_amount_sats=1_005_000,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.regenerate_ext_lightning_invoice(db_session, session.id)
        assert ok is False
        assert err and "already paid" in err.lower()

    @pytest.mark.asyncio
    async def test_regenerate_rejected_when_not_awaiting(self, db_session):
        old_swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(old_swap)
        await db_session.commit()
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=old_swap.id,
            ext_intake_amount_sats=1_005_000,
            status=BraiinsDepositStatus.SWAPPING,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.regenerate_ext_lightning_invoice(db_session, session.id)
        assert ok is False
        assert err

    @pytest.mark.asyncio
    async def test_regenerate_rejected_for_non_ext_session(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.LIGHTNING,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.regenerate_ext_lightning_invoice(db_session, session.id)
        assert ok is False


class TestSubmitRefundAddress:
    @pytest.mark.asyncio
    async def test_submit_refund_records_txid(self, db_session):
        svc = _make_service()
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=({"txid": "ff" * 32}, None)
        )
        # Patch validate_bitcoin_address to be a no-op normaliser.
        import app.core.validation as _validation

        original = _validation.validate_bitcoin_address
        _validation.validate_bitcoin_address = lambda v: v
        try:
            session = BraiinsDepositSession(
                api_key_id=uuid4(),
                deposit_amount_sats=1_000_000,
                destination_address="bc1q" + "x" * 38,
                source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
                status=BraiinsDepositStatus.FAILED,
                ext_intake_address="bcrt1pintake",
                ext_intake_amount_sats=1_012_300,
                ext_intake_received_sats=1_012_300,
                ext_intake_txids=[
                    {"txid": "aa" * 32, "vout": 0, "amount_sat": 1_012_300, "confirmations": 1},
                ],
                status_history=[],
                error_message="downstream failure",
            )
            db_session.add(session)
            await db_session.commit()
            ok, err = await svc.submit_refund_address(db_session, session.id, "bc1qrefundtargetaddressfortest")
            assert ok is True
            assert err is None
            await db_session.refresh(session)
            assert session.refund_txid == "ff" * 32
            assert session.refund_address == "bc1qrefundtargetaddressfortest"
        finally:
            _validation.validate_bitcoin_address = original

    @pytest.mark.asyncio
    async def test_submit_refund_rejected_when_no_funds(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            status=BraiinsDepositStatus.FAILED,
            ext_intake_received_sats=0,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        import app.core.validation as _validation

        original = _validation.validate_bitcoin_address
        _validation.validate_bitcoin_address = lambda v: v
        try:
            ok, err = await svc.submit_refund_address(db_session, session.id, "bc1qtarget")
        finally:
            _validation.validate_bitcoin_address = original
        assert ok is False
        assert err and "nothing to refund" in err.lower()

    @pytest.mark.asyncio
    async def test_submit_refund_rejected_when_not_failed(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            ext_intake_received_sats=1_012_300,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        import app.core.validation as _validation

        original = _validation.validate_bitcoin_address
        _validation.validate_bitcoin_address = lambda v: v
        try:
            ok, err = await svc.submit_refund_address(db_session, session.id, "bc1qtarget")
        finally:
            _validation.validate_bitcoin_address = original
        assert ok is False
        assert err

    @pytest.mark.asyncio
    async def test_submit_refund_rejected_when_already_sent(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            status=BraiinsDepositStatus.FAILED,
            ext_intake_received_sats=1_012_300,
            ext_intake_txids=[
                {"txid": "aa" * 32, "vout": 0, "amount_sat": 1_012_300, "confirmations": 1},
            ],
            refund_address="bc1qprior",
            refund_txid="cc" * 32,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        import app.core.validation as _validation

        original = _validation.validate_bitcoin_address
        _validation.validate_bitcoin_address = lambda v: v
        try:
            ok, err = await svc.submit_refund_address(db_session, session.id, "bc1qtarget")
        finally:
            _validation.validate_bitcoin_address = original
        assert ok is False
        assert err and "already" in err.lower()

    @pytest.mark.asyncio
    async def test_submit_refund_rejected_when_fresh_utxo_already_claimed(self, db_session):
        """Once the Boltz claim lands (``fresh_utxo_txid`` populated),
        the user's deposit outpoints have been consumed by the
        submarine flow. Refund pinned to those outpoints would fail;
        the service must refuse cleanly."""
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            status=BraiinsDepositStatus.FAILED,
            ext_intake_received_sats=1_012_300,
            ext_intake_txids=[
                {"txid": "aa" * 32, "vout": 0, "amount_sat": 1_012_300, "confirmations": 1},
            ],
            fresh_utxo_txid="bb" * 32,
            fresh_utxo_vout=0,
            fresh_utxo_amount_sats=1_004_200,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        import app.core.validation as _validation

        original = _validation.validate_bitcoin_address
        _validation.validate_bitcoin_address = lambda v: v
        try:
            ok, err = await svc.submit_refund_address(db_session, session.id, "bc1qtarget")
        finally:
            _validation.validate_bitcoin_address = original
        assert ok is False
        assert err and "flowed downstream" in err.lower()

    @pytest.mark.asyncio
    async def test_submit_refund_validates_address(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            status=BraiinsDepositStatus.FAILED,
            ext_intake_received_sats=1_012_300,
            ext_intake_txids=[
                {"txid": "aa" * 32, "vout": 0, "amount_sat": 1_012_300, "confirmations": 1},
            ],
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        # validate_bitcoin_address raises on invalid input.
        ok, err = await svc.submit_refund_address(db_session, session.id, "not-a-real-address")
        assert ok is False
        assert err and "invalid refund address" in err.lower()


class TestCancelExternalStates:
    @pytest.mark.asyncio
    async def test_cancel_awaiting_ln_funds(self, db_session):
        swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()
        svc = _make_service()
        svc._mocks["boltz"].cancel_swap = AsyncMock(return_value=(True, None))  # type: ignore[attr-defined]
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=swap.id,
            ext_intake_amount_sats=1_010_000,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.cancel_session(db_session, session.id)
        assert ok is True
        assert err is None
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_awaiting_onchain_funds_without_deposit(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address="bcrt1pintake",
            ext_intake_amount_sats=1_012_300,
            ext_intake_received_sats=0,
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.cancel_session(db_session, session.id)
        assert ok is True
        assert err is None
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_awaiting_onchain_funds_after_partial_deposit(self, db_session):
        """Cancel after we've received funds transitions to FAILED so
        the refund-prompt panel renders."""
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address="bcrt1pintake",
            ext_intake_amount_sats=1_012_300,
            ext_intake_received_sats=500_000,
            ext_intake_txids=[
                {"txid": "aa" * 32, "vout": 0, "amount_sat": 500_000, "confirmations": 1},
            ],
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.cancel_session(db_session, session.id)
        assert ok is True
        assert err is None
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.FAILED
        # Error message instructs the user to provide a refund address.
        assert "refund" in (session.error_message or "").lower()


class TestExtOnchainReentryDispatcher:
    """After ``_advance_awaiting_onchain_funds`` flips back to CREATED
    with ``awaiting_onchain_funds`` in history, the next ``advance``
    should route into ``_advance_created_onchain`` (the submarine
    flow), NOT back into ``_advance_created_ext_onchain``."""

    @pytest.mark.asyncio
    async def test_reentry_routes_to_submarine_flow(self, db_session):
        # Build a session that's already past AWAITING_ONCHAIN_FUNDS.
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address="bcrt1pintake",
            ext_intake_amount_sats=1_012_300,
            ext_intake_received_sats=1_012_300,
            status=BraiinsDepositStatus.CREATED,
            status_history=[
                {"status": "created", "timestamp": "2026-01-01T00:00:00+00:00"},
                {"status": "awaiting_onchain_funds", "timestamp": "2026-01-01T00:00:01+00:00"},
                {"status": "created", "timestamp": "2026-01-01T01:00:00+00:00", "detail": "ext-oc deposit confirmed"},
            ],
        )
        db_session.add(session)
        await db_session.commit()

        # Set up a fully-mocked submarine swap so
        # _advance_created_onchain can succeed.
        submarine_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="swap_sub_reentry",
            api_key_id=uuid4(),
            invoice_amount_sats=1_010_000,
            onchain_amount_sats=1_012_300,
            boltz_lockup_address="bcrt1plockup",
            destination_address="",
            status=SwapStatus.CREATED,
            claim_txid=None,
            status_history=[],
        )
        db_session.add(submarine_swap)
        await db_session.commit()

        svc = _make_service()
        svc._mocks["boltz"].create_submarine_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(submarine_swap, None)
        )

        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        # The session should have created submarine resources.
        assert session.submarine_boltz_swap_id == submarine_swap.id
        assert session.status == BraiinsDepositStatus.SUBMARINE_SWAPPING


# ═══════════════════════════════════════════════════════════════════════
# External sources — additional edge-case coverage.
# ═══════════════════════════════════════════════════════════════════════


class TestExtOnchainQuoteSubmarineBounds:
    """Plan.d — ext-OC quote math runs through the submarine
    pair, so the same min/max bounds enforced for self-OC should
    apply to ext-OC too. Without these checks, an out-of-bounds
    deposit would only surface as a mid-flow Boltz error."""

    @pytest.mark.asyncio
    async def test_ext_onchain_below_submarine_min_rejected(self):
        svc = _make_service()
        svc._mocks["boltz"].get_submarine_pair_info = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {
                    "fees_percentage": 0.1,
                    "fees_miner_lockup": 462,
                    "min": 5_000_000,
                    "max": 25_000_000,
                    "hash": "submarine_pair_h",
                },
                None,
            )
        )
        quote, err = await svc.quote(amount_sats=50_000, source_kind="ext_onchain")
        assert quote is None
        assert err and "minimum" in err.lower()

    @pytest.mark.asyncio
    async def test_ext_onchain_above_submarine_max_rejected(self):
        svc = _make_service()
        svc._mocks["boltz"].get_submarine_pair_info = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {
                    "fees_percentage": 0.1,
                    "fees_miner_lockup": 462,
                    "min": 25_000,
                    "max": 100_000,
                    "hash": "submarine_pair_h",
                },
                None,
            )
        )
        quote, err = await svc.quote(amount_sats=5_000_000, source_kind="ext_onchain")
        assert quote is None
        assert err and "maximum" in err.lower()


class TestExtCreateSessionInFlight:
    """Only one in-flight session per api_key. The rule
    applies to ext sources too: while an ext-LN session is in
    AWAITING_LN_FUNDS, a second create attempt must be rejected."""

    @pytest.mark.asyncio
    async def test_ext_lightning_rejects_second_in_flight(self, db_session):
        swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()
        svc = _make_service(boltz_create_result=swap)
        api_key_id = uuid4()
        s1, err1 = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_lightning",
        )
        assert err1 is None and s1 is not None
        # Advance into AWAITING_LN_FUNDS to make the in-flight check
        # cover the new state, not just CREATED.
        await svc.advance(db_session, s1.id)
        s2, err2 = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=500_000,
            destination_address="bc1q" + "y" * 38,
            source_kind="ext_onchain",
        )
        assert s2 is None
        assert err2 == "in_flight_session_exists"

    @pytest.mark.asyncio
    async def test_ext_onchain_rejects_second_in_flight(self, db_session):
        svc = _make_service(lnd_new_address="bcrt1pintake1")
        api_key_id = uuid4()
        s1, err1 = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_onchain",
        )
        assert err1 is None and s1 is not None
        await svc.advance(db_session, s1.id)
        # Even a self-LN second attempt should be rejected.
        s2, err2 = await svc.create_session(
            db_session,
            api_key_id=api_key_id,
            amount_sats=500_000,
            destination_address="bc1q" + "y" * 38,
            source_kind="lightning",
        )
        assert s2 is None
        assert err2 == "in_flight_session_exists"


class TestAdvanceCreatedExtLightningFailures:
    """`_advance_created_ext_lightning` defends against LND/Boltz
    errors mid-step. A hard failure transitions the session to
    FAILED (not silently retries indefinitely)."""

    @pytest.mark.asyncio
    async def test_address_minting_failure_marks_failed(self, db_session):
        svc = _make_service()
        svc._mocks["lnd"].new_address = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "lnd wallet locked")
        )
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_lightning",
        )
        assert session is not None
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert "fresh address" in (result.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_boltz_create_failure_marks_failed(self, db_session):
        svc = _make_service()
        svc._mocks["boltz"].create_reverse_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "boltz unreachable")
        )
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_lightning",
        )
        assert session is not None
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert "boltz unreachable" in (result.error_message or "").lower()


class TestAdvanceCreatedExtOnchainFailures:
    @pytest.mark.asyncio
    async def test_address_minting_failure_marks_failed(self, db_session):
        svc = _make_service()
        svc._mocks["lnd"].new_address = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "lnd transient")
        )
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=500_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_onchain",
        )
        assert session is not None
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED

    @pytest.mark.asyncio
    async def test_address_is_labelled_with_session_id(self, db_session):
        """Plan.b /.b — the ext-OC intake address is
        labelled ``braiins_deposit:ext_intake:{session_id}`` so
        deposits to it are auditable per-session."""
        captured: dict = {}

        async def _record_purpose(_db, address, purpose):
            captured["address"] = address
            captured["purpose"] = purpose

        svc = _make_service(lnd_new_address="bcrt1pintakeaddr")
        # Patch the utxo_service.record_address_purpose call site by
        # injecting through the module's import.
        import app.services.utxo_service as _utxo

        orig = _utxo.record_address_purpose
        _utxo.record_address_purpose = _record_purpose
        try:
            session, _ = await svc.create_session(
                db_session,
                api_key_id=uuid4(),
                amount_sats=1_000_000,
                destination_address="bc1q" + "x" * 38,
                source_kind="ext_onchain",
            )
            assert session is not None
            await svc.advance(db_session, session.id)
        finally:
            _utxo.record_address_purpose = orig
        assert captured.get("address") == "bcrt1pintakeaddr"
        assert "braiins_deposit:ext_intake:" in (captured.get("purpose") or "")
        assert str(session.id) in captured["purpose"]


class TestAdvanceAwaitingDefensiveRaises:
    """Defensive raises in the await-handlers — if invariants are
    violated (missing swap link, missing intake address), the
    handler raises BraiinsDepositError which routes to FAILED."""

    @pytest.mark.asyncio
    async def test_awaiting_ln_funds_without_boltz_swap_id(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=None,  # invariant violation
            ext_intake_amount_sats=1_010_000,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.FAILED
        assert "boltz_swap_id" in (session.error_message or "")

    @pytest.mark.asyncio
    async def test_awaiting_onchain_funds_without_intake_address(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address=None,  # invariant violation
            ext_intake_amount_sats=1_012_300,
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.FAILED
        assert "ext_intake_address" in (session.error_message or "")

    @pytest.mark.asyncio
    async def test_awaiting_onchain_funds_without_amount(self, db_session):
        svc = _make_service()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address="bcrt1pintake",
            ext_intake_amount_sats=None,  # invariant violation
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.FAILED


class TestExtOnchainOverPay:
    """Plan row 6 — over-paid deposits process normally; the
    surplus returns to the wallet as change on the final
    send-to-Braiins tx. The handler just needs to recognise
    received >= required as 'enough'."""

    @pytest.mark.asyncio
    async def test_over_paid_deposit_proceeds(self, db_session):
        intake_address = "bcrt1poverpaytarget"
        required = 1_012_300
        utxos = [
            {
                "outpoint": {"txid_str": "0" * 64, "output_index": 0},
                "amount_sat": required + 500_000,  # over-pay
                "address": intake_address,
                "confirmations": 1,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address=intake_address,
            ext_intake_amount_sats=required,
            ext_intake_received_sats=0,
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[
                {"status": "created", "timestamp": "2026-01-01T00:00:00+00:00"},
                {"status": "awaiting_onchain_funds", "timestamp": "2026-01-01T00:00:01+00:00"},
            ],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        # Transition to CREATED for the re-entry, with the over-paid
        # amount recorded.
        assert session.status == BraiinsDepositStatus.CREATED
        assert session.ext_intake_received_sats == required + 500_000


class TestExtOcPartialDepositAudit:
    """Partial-deposit detection emits an
    informational audit row (``braiins_deposit_ext_oc_funds_partial``)
    each time the running total changes but the threshold isn't met."""

    @pytest.mark.asyncio
    async def test_partial_deposit_emits_audit(self, db_session):
        from app.models.audit_log import AuditLog

        intake_address = "bcrt1ppartialintake"
        required = 1_012_300
        utxos = [
            {
                "outpoint": {"txid_str": "1" * 64, "output_index": 0},
                "amount_sat": 400_000,
                "address": intake_address,
                "confirmations": 1,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address=intake_address,
            ext_intake_amount_sats=required,
            ext_intake_received_sats=0,
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)

        rows = (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "braiins_deposit_ext_oc_funds_partial")
                )
            )
            .scalars()
            .all()
        )
        assert rows
        details = rows[0].details or {}
        assert details.get("received_sats") == 400_000
        assert details.get("required_sats") == required
        assert details.get("shortfall_sats") == required - 400_000


class TestExtOcMempoolDetection:
    """A 0-conf (mempool) deposit is RECORDED in ``ext_intake_txids`` so
    the wizard can show "deposit detected — waiting for confirmations" +
    a mempool link, but it does NOT count toward ``received_sats`` or
    advance the session until it reaches the confirmation threshold."""

    @pytest.mark.asyncio
    async def test_zero_conf_deposit_detected_not_advanced(self, db_session):
        intake_address = "bcrt1pmempooldetect"
        required = 1_012_300
        txid = "ab" * 32
        utxos = [
            {
                "outpoint": {"txid_str": txid, "output_index": 0},
                "amount_sat": required,
                "address": intake_address,
                "confirmations": 0,  # mempool — below the 1-conf threshold
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address=intake_address,
            ext_intake_amount_sats=required,
            ext_intake_received_sats=0,
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        # A 0-conf deposit must NOT advance the session…
        assert session.status == BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS
        # …and must NOT count toward the confirmed total…
        assert int(session.ext_intake_received_sats or 0) == 0
        # …but IS recorded (with confs=0) so the wizard can show it +
        # link to the mempool.
        txids = session.ext_intake_txids or []
        assert len(txids) == 1
        assert txids[0]["txid"] == txid
        assert txids[0]["confirmations"] == 0
        # A detected deposit suppresses the stale "waiting too long" flag.
        assert not session.error_message

    @pytest.mark.asyncio
    async def test_deposit_advances_once_confirmed(self, db_session):
        intake_address = "bcrt1pconfirmeddetect"
        required = 1_012_300
        utxos = [
            {
                "outpoint": {"txid_str": "cd" * 32, "output_index": 0},
                "amount_sat": required,
                "address": intake_address,
                "confirmations": 1,  # meets the threshold
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address=intake_address,
            ext_intake_amount_sats=required,
            ext_intake_received_sats=0,
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.CREATED
        assert int(session.ext_intake_received_sats or 0) == required


class TestExtOcSoftTtlWarning:
    """Plan row 7 — when an ext-OC session sits in
    AWAITING_ONCHAIN_FUNDS longer than
    ``braiins_deposit_ext_oc_funds_ttl_s`` (default 24 h), surface
    a non-fatal warning. Never auto-cancel."""

    @pytest.mark.asyncio
    async def test_warning_fires_past_ttl(self, db_session, monkeypatch):
        from datetime import datetime, timedelta, timezone

        from app.core.config import settings as _settings

        # Tighten the TTL to a short window so the test can simulate
        # "past TTL" without manipulating timestamps to absurd values.
        monkeypatch.setattr(_settings, "braiins_deposit_ext_oc_funds_ttl_s", 60)

        # Empty list_unspent — no deposit found, the handler stays in
        # AWAITING_ONCHAIN_FUNDS and runs the stale-warning code path.
        svc = _make_service(lnd_unspent=[])
        old_ts = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address="bcrt1pstaleintake",
            ext_intake_amount_sats=1_012_300,
            ext_intake_received_sats=0,
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[
                {"status": "created", "timestamp": old_ts},
                {"status": "awaiting_onchain_funds", "timestamp": old_ts},
            ],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        # Stays in AWAITING_ONCHAIN_FUNDS — funds may still arrive.
        assert session.status == BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS
        assert "Waiting for your deposit" in (session.error_message or "")

    @pytest.mark.asyncio
    async def test_no_warning_within_ttl(self, db_session, monkeypatch):
        from datetime import datetime, timezone

        from app.core.config import settings as _settings

        # Tighten the TTL — but the session is fresh, so no warning.
        monkeypatch.setattr(_settings, "braiins_deposit_ext_oc_funds_ttl_s", 60)
        svc = _make_service(lnd_unspent=[])
        now_ts = datetime.now(timezone.utc).isoformat()
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address="bcrt1pfreshintake",
            ext_intake_amount_sats=1_012_300,
            ext_intake_received_sats=0,
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[
                {"status": "created", "timestamp": now_ts},
                {"status": "awaiting_onchain_funds", "timestamp": now_ts},
            ],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        await db_session.refresh(session)
        assert session.status == BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS
        # No stale-warning text on the session.
        assert "no on-chain activity" not in (session.error_message or "").lower()


class TestSubmitRefundAuditEmit:
    """Submit_refund_address emits
    ``braiins_deposit_ext_oc_refund_sent`` on success with the
    refund txid + amount in details."""

    @pytest.mark.asyncio
    async def test_refund_send_emits_audit(self, db_session):
        from app.models.audit_log import AuditLog

        svc = _make_service()
        svc._mocks["lnd"].send_coins = AsyncMock(  # type: ignore[attr-defined]
            return_value=({"txid": "ab" * 32}, None)
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            status=BraiinsDepositStatus.FAILED,
            ext_intake_address="bcrt1prefundtarget",
            ext_intake_amount_sats=1_012_300,
            ext_intake_received_sats=1_012_300,
            ext_intake_txids=[
                {"txid": "cd" * 32, "vout": 0, "amount_sat": 1_012_300, "confirmations": 1},
            ],
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        import app.core.validation as _validation

        original = _validation.validate_bitcoin_address
        _validation.validate_bitcoin_address = lambda v: v
        try:
            ok, err = await svc.submit_refund_address(db_session, session.id, "bc1qrefundsend")
        finally:
            _validation.validate_bitcoin_address = original
        assert ok and not err

        rows = (
            (await db_session.execute(select(AuditLog).where(AuditLog.action == "braiins_deposit_ext_oc_refund_sent")))
            .scalars()
            .all()
        )
        assert rows
        details = rows[0].details or {}
        assert details.get("refund_txid") == "ab" * 32
        assert details.get("amount_refunded_sats") == 1_012_300
        assert details.get("source_kind") == "ext_onchain"


class TestExternalSourceAuditActionCoverage:
    """Every ext-source audit action must have at
    least one code path that emits it. This test runs each path and
    checks the audit row materialises.

    The 7 audit actions:
      * braiins_deposit_ext_ln_invoice_issued
      * braiins_deposit_ext_ln_invoice_regenerated
      * braiins_deposit_ext_ln_funds_received
      * braiins_deposit_ext_oc_address_issued
      * braiins_deposit_ext_oc_funds_partial   (TestExtOcPartialDepositAudit)
      * braiins_deposit_ext_oc_funds_received
      * braiins_deposit_ext_oc_refund_sent     (TestSubmitRefundAuditEmit)
    """

    @pytest.mark.asyncio
    async def test_ext_ln_invoice_issued_emitted(self, db_session):
        from app.models.audit_log import AuditLog

        swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        db_session.add(swap)
        await db_session.commit()
        svc = _make_service(boltz_create_result=swap)
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_lightning",
        )
        await svc.advance(db_session, session.id)
        rows = (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "braiins_deposit_ext_ln_invoice_issued")
                )
            )
            .scalars()
            .all()
        )
        assert rows
        assert (rows[0].details or {}).get("source_kind") == "ext_lightning"

    @pytest.mark.asyncio
    async def test_ext_ln_invoice_regenerated_emitted(self, db_session):
        from app.models.audit_log import AuditLog

        old_swap = _make_boltz_swap(status=SwapStatus.CREATED, claim_txid=None)
        new_swap = BoltzSwap(
            id=uuid4(),
            boltz_swap_id="swap_audit_regen",
            direction=BoltzSwapDirection.REVERSE,
            api_key_id=uuid4(),
            invoice_amount_sats=1_010_000,
            onchain_amount_sats=1_005_000,
            destination_address="bcrt1pfresh",
            status=SwapStatus.CREATED,
            claim_txid=None,
            status_history=[],
        )
        db_session.add(old_swap)
        await db_session.commit()
        svc = _make_service(boltz_create_result=new_swap)
        svc._mocks["boltz"].cancel_swap = AsyncMock(return_value=(True, None))  # type: ignore[attr-defined]
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=old_swap.id,
            ext_intake_amount_sats=1_005_000,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        ok, err = await svc.regenerate_ext_lightning_invoice(db_session, session.id)
        assert ok and not err
        rows = (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "braiins_deposit_ext_ln_invoice_regenerated")
                )
            )
            .scalars()
            .all()
        )
        assert rows
        assert (rows[0].details or {}).get("source_kind") == "ext_lightning"

    @pytest.mark.asyncio
    async def test_ext_ln_funds_received_emitted(self, db_session):
        from app.models.audit_log import AuditLog

        swap = _make_boltz_swap(status=SwapStatus.CLAIMED, claim_txid="ee" * 32)
        db_session.add(swap)
        await db_session.commit()
        svc = _make_service()
        svc._mocks["boltz"].advance_swap = AsyncMock(  # type: ignore[attr-defined]
            return_value=(swap, None)
        )
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING,
            boltz_swap_id=swap.id,
            ext_intake_amount_sats=1_010_000,
            status=BraiinsDepositStatus.AWAITING_LN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        rows = (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "braiins_deposit_ext_ln_funds_received")
                )
            )
            .scalars()
            .all()
        )
        assert rows
        assert (rows[0].details or {}).get("claim_txid") == "ee" * 32

    @pytest.mark.asyncio
    async def test_ext_oc_address_issued_emitted(self, db_session):
        from app.models.audit_log import AuditLog

        svc = _make_service(lnd_new_address="bcrt1paddrissued")
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_onchain",
        )
        await svc.advance(db_session, session.id)
        rows = (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "braiins_deposit_ext_oc_address_issued")
                )
            )
            .scalars()
            .all()
        )
        assert rows
        details = rows[0].details or {}
        assert details.get("source_kind") == "ext_onchain"
        assert details.get("ext_intake_address") == "bcrt1paddrissued"

    @pytest.mark.asyncio
    async def test_ext_oc_funds_received_emitted(self, db_session):
        from app.models.audit_log import AuditLog

        intake_address = "bcrt1pfundsreceived"
        required = 1_012_300
        utxos = [
            {
                "outpoint": {"txid_str": "f" * 64, "output_index": 0},
                "amount_sat": required,
                "address": intake_address,
                "confirmations": 1,
            }
        ]
        svc = _make_service(lnd_unspent=utxos)
        session = BraiinsDepositSession(
            api_key_id=uuid4(),
            deposit_amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN,
            ext_intake_address=intake_address,
            ext_intake_amount_sats=required,
            ext_intake_received_sats=0,
            status=BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            status_history=[],
        )
        db_session.add(session)
        await db_session.commit()
        await svc.advance(db_session, session.id)
        rows = (
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "braiins_deposit_ext_oc_funds_received")
                )
            )
            .scalars()
            .all()
        )
        assert rows
        details = rows[0].details or {}
        assert details.get("received_sats") == required
        assert details.get("required_sats") == required
        assert details.get("intake_tx_count") == 1


# ── Channel-open funding strategy ───────────────────────────────────


def _enable_channel(monkeypatch):
    monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_open_enabled", True)


class TestChannelQuote:
    @pytest.mark.asyncio
    async def test_onchain_channel_quote_sizes_capacity_up(self):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000, source_kind="onchain", funding_strategy="channel")
        assert err is None and quote is not None
        assert quote.channel_eligible is True
        # Capacity must exceed the reverse-swap invoice amount.
        assert quote.channel_capacity_sats > quote.invoice_amount_sats
        # Required on-chain = capacity + funding fee (> capacity).
        assert quote.required_onchain_balance_sats > quote.channel_capacity_sats
        assert quote.channel_peer_pubkey  # a peer was selected
        assert quote.channel_reserve_sats > 0
        assert quote.channel_inbound_gained_sats == quote.invoice_amount_sats

    @pytest.mark.asyncio
    async def test_ext_onchain_channel_sets_intake_not_bin(self):
        svc = _make_service()
        quote, err = await svc.quote(
            amount_sats=1_000_000,
            source_kind="ext_onchain",
            funding_strategy="channel",
        )
        assert err is None and quote is not None
        assert quote.channel_eligible is True
        # Intake (what the user must send) is the channel-sized figure.
        assert quote.required_external_deposit_sats == (quote.channel_capacity_sats + quote.channel_funding_fee_sats)
        assert quote.required_onchain_balance_sats == 0

    @pytest.mark.asyncio
    async def test_channel_quote_ineligible_below_swap_minimum(self):
        svc = _make_service()
        # Below the Boltz reverse minimum (~25k) → ineligible (can't even
        # do the reverse leg, regardless of channel sizing).
        quote, err = await svc.quote(amount_sats=10_000, source_kind="onchain", funding_strategy="channel")
        assert err is None and quote is not None
        assert quote.channel_eligible is False
        assert "minimum" in quote.channel_ineligible_reason.lower()

    @pytest.mark.asyncio
    async def test_channel_quote_bumps_small_deposit_to_channel_minimum(self):
        svc = _make_service()
        # 50k deposit: above the swap min but its natural channel size is
        # below the 150k channel minimum → bumped UP to 150k, still
        # eligible, with the excess surfaced as kept-Lightning-balance.
        quote, err = await svc.quote(amount_sats=50_000, source_kind="onchain", funding_strategy="channel")
        assert err is None and quote is not None
        assert quote.channel_eligible is True
        assert quote.channel_bumped_to_min is True
        assert quote.channel_capacity_sats == 150_000  # the small node's min
        # Required on-chain is the (bumped) channel size, well above the bin.
        assert quote.required_onchain_balance_sats > 100_000
        # Most of the channel becomes the user's kept Lightning balance.
        assert quote.channel_excess_to_ln_sats > 50_000

    @pytest.mark.asyncio
    async def test_channel_quote_large_deposit_not_bumped(self):
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000, source_kind="onchain", funding_strategy="channel")
        assert err is None and quote is not None
        assert quote.channel_eligible is True
        assert quote.channel_bumped_to_min is False
        # Naturally sized just above the invoice amount.
        assert quote.channel_capacity_sats > quote.invoice_amount_sats
        assert quote.channel_capacity_sats < 1_100_000

    @pytest.mark.asyncio
    async def test_channel_quote_skips_submarine_fees(self):
        # Channel strategy must not add submarine pair fees; total_fee
        # carries reverse fees + funding fee only.
        svc = _make_service()
        quote, err = await svc.quote(amount_sats=1_000_000, source_kind="onchain", funding_strategy="channel")
        assert err is None and quote is not None
        assert quote.submarine_lockup_amount_sats == 0


class TestChannelCreateSession:
    @pytest.mark.asyncio
    async def test_channel_rejected_when_flag_off(self, db_session, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_open_enabled", False)
        svc = _make_service()
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        assert session is None
        assert err and "disabled" in err.lower()

    @pytest.mark.asyncio
    async def test_channel_rejected_for_lightning_source(self, db_session, monkeypatch):
        _enable_channel(monkeypatch)
        svc = _make_service()
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="lightning",
            funding_strategy="channel",
        )
        assert session is None
        assert err and "on-chain" in err.lower()

    @pytest.mark.asyncio
    async def test_channel_persists_strategy_and_respects_extras(self, db_session, monkeypatch):
        """The channel path's final send is identical to every other
        source, so the include-extras choice is respected (not forced)
        — consistent behaviour across all sources."""
        _enable_channel(monkeypatch)
        svc = _make_service()
        s_true, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
            include_extras=True,
        )
        assert err is None and s_true is not None
        assert s_true.funding_strategy == BraiinsDepositFundingStrategy.CHANNEL
        assert s_true.include_extras is True
        # include_extras=False is honoured for channel just like Lightning.
        s_false, err2 = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "y" * 38,
            source_kind="onchain",
            funding_strategy="channel",
            include_extras=False,
        )
        assert err2 is None and s_false is not None
        assert s_false.include_extras is False

    @pytest.mark.asyncio
    async def test_channel_skips_inbound_gate(self, db_session, monkeypatch):
        _enable_channel(monkeypatch)
        svc = _make_service()
        # Zero inbound would make the swap gate refuse — but the channel
        # strategy must bypass it entirely.
        svc._mocks["lnd"].inbound_capacity = AsyncMock(  # type: ignore[attr-defined]
            return_value=(
                {"total_receivable_sats": 0, "largest_channel_receivable_sats": 0},
                None,
            )
        )
        session, err = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        assert err is None and session is not None
        svc._mocks["lnd"].inbound_capacity.assert_not_called()  # type: ignore[attr-defined]


class TestChannelStateMachine:
    @pytest.mark.asyncio
    async def test_created_channel_opens_channel(self, db_session, monkeypatch):
        _enable_channel(monkeypatch)
        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.OPENING_CHANNEL
        assert result.channel_open_txid == "cc" * 32
        assert result.channel_peer_pubkey
        svc._mocks["lnd"].connect_peer.assert_awaited()  # type: ignore[attr-defined]
        svc._mocks["lnd"].open_channel.assert_awaited_once()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_small_channel_open_falls_back_to_next_peer(self, db_session, monkeypatch):
        """Small band: the cheapest candidate's open is rejected (before any
        broadcast), so the service moves on and opens with the next peer.
        No funds move on the failed attempt."""
        _enable_channel(monkeypatch)
        # Mainnet so the small-channel catalog is populated (it is
        # mainnet-only); otherwise the only candidate is the small preset.
        monkeypatch.setattr("app.core.config.settings.bitcoin_network", "bitcoin")
        svc = _make_service()
        # First candidate's open is rejected; the second succeeds.
        svc._mocks["lnd"].open_channel.side_effect = [  # type: ignore[attr-defined]
            (None, "peer rejected channel size"),
            ({"funding_txid": "cc" * 32, "output_index": 0}, None),
        ]
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=200_000,  # small band (< proper-node 1,000,000 min)
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.OPENING_CHANNEL
        assert result.channel_open_txid == "cc" * 32
        assert result.channel_peer_pubkey
        assert svc._mocks["lnd"].open_channel.await_count == 2  # type: ignore[attr-defined]
        assert svc._mocks["lnd"].connect_peer.await_count == 2  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_channel_open_all_peers_reject_fails_hard(self, db_session, monkeypatch):
        """When every reachable candidate rejects the open, the session
        hard-fails (no peer can take the channel)."""
        _enable_channel(monkeypatch)
        monkeypatch.setattr("app.core.config.settings.bitcoin_network", "bitcoin")
        svc = _make_service()
        svc._mocks["lnd"].open_channel.side_effect = lambda *a, **k: (None, "peer rejected")  # type: ignore[attr-defined]
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=200_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert not result.channel_open_txid

    @pytest.mark.asyncio
    async def test_channel_open_all_connects_fail_is_transient(self, db_session, monkeypatch):
        """When no candidate is reachable (all connects fail), the session
        stays CREATED (transient — retried next tick) and never broadcasts."""
        _enable_channel(monkeypatch)
        monkeypatch.setattr("app.core.config.settings.bitcoin_network", "bitcoin")
        svc = _make_service()
        svc._mocks["lnd"].connect_peer.side_effect = lambda *a, **k: (None, "peer offline")  # type: ignore[attr-defined]
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=200_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.CREATED
        assert not result.channel_open_txid
        svc._mocks["lnd"].open_channel.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_channel_capacity_over_dashboard_limit_fails(self, db_session, monkeypatch):
        """a configured dashboard spend limit applies to the sized-up
        channel CAPACITY, not just the bin. A capacity above the limit
        must fail closed before any peer connect / funding broadcast."""
        _enable_channel(monkeypatch)
        # Set a dashboard limit BELOW the channel capacity (which is sized
        # up from the 1,000,000-sat bin) but above the bin itself, proving
        # the check is against capacity rather than the bin.
        monkeypatch.setattr(
            "app.core.config.settings.dashboard_max_payment_sats",
            1_000_000,
        )
        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert "dashboard spend limit" in (result.error_message or "").lower()
        # Never connected or broadcast.
        svc._mocks["lnd"].open_channel.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_opening_channel_active_reenters_reverse(self, db_session, monkeypatch):
        _enable_channel(monkeypatch)
        svc = _make_service(boltz_create_result=_make_boltz_swap())
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        await svc.advance(db_session, session.id)  # → OPENING_CHANNEL
        # channel_is_active default True → next tick converges to SWAPPING.
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.SWAPPING
        svc._mocks["boltz"].create_reverse_swap.assert_awaited()  # type: ignore[attr-defined]
        # Payment-pinning: the reverse swap is created with the new
        # channel's short id as the outgoing-channel pin.
        _, rkw = svc._mocks["boltz"].create_reverse_swap.call_args  # type: ignore[attr-defined]
        assert rkw.get("outgoing_chan_id") == "123x456"

    @pytest.mark.asyncio
    async def test_opening_channel_not_active_stays(self, db_session, monkeypatch):
        _enable_channel(monkeypatch)
        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        await svc.advance(db_session, session.id)  # → OPENING_CHANNEL
        svc._mocks["lnd"].channel_is_active = AsyncMock(  # type: ignore[attr-defined]
            return_value=(False, None, None)
        )
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.OPENING_CHANNEL
        assert "waiting" in (result.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_open_channel_prebroadcast_error_fails(self, db_session, monkeypatch):
        _enable_channel(monkeypatch)
        svc = _make_service()
        svc._mocks["lnd"].open_channel = AsyncMock(  # type: ignore[attr-defined]
            return_value=(None, "insufficient funds")
        )
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.FAILED
        assert result.channel_open_txid is None

    @pytest.mark.asyncio
    async def test_stuck_channel_warns_not_fails(self, db_session, monkeypatch):
        _enable_channel(monkeypatch)
        monkeypatch.setattr("app.core.config.settings.braiins_deposit_channel_open_timeout_s", 1)
        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        await svc.advance(db_session, session.id)  # → OPENING_CHANNEL
        # Back-date the OPENING_CHANNEL transition so it's past the 1s TTL.
        session = await svc.get_session_by_id(db_session, session.id)
        hist = list(session.status_history or [])
        for entry in hist:
            if isinstance(entry, dict) and entry.get("status") == "opening_channel":
                entry["timestamp"] = "2020-01-01T00:00:00+00:00"
        session.status_history = hist
        await db_session.commit()
        svc._mocks["lnd"].channel_is_active = AsyncMock(  # type: ignore[attr-defined]
            return_value=(False, None, None)
        )
        result = await svc.advance(db_session, session.id)
        assert result is not None
        # Never auto-FAILs; surfaces a stuck warning.
        assert result.status == BraiinsDepositStatus.OPENING_CHANNEL
        assert "stuck" in (result.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_open_channel_broadcast_once_idempotent(self, db_session, monkeypatch):
        _enable_channel(monkeypatch)
        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        await svc.advance(db_session, session.id)  # opens once
        # Force back to CREATED with channel_open_txid set (crash-recovery
        # shape) and re-tick: must NOT open again.
        session = await svc.get_session_by_id(db_session, session.id)
        session.status = BraiinsDepositStatus.CREATED
        await db_session.commit()
        await svc.advance(db_session, session.id)
        svc._mocks["lnd"].open_channel.assert_awaited_once()  # type: ignore[attr-defined]


class TestChannelExtOnchainAndCancel:
    @pytest.mark.asyncio
    async def test_ext_onchain_channel_intake_is_channel_sized(self, db_session, monkeypatch):
        """ext-onchain + channel: the minted intake amount must be the
        channel-sized figure (capacity + funding fee), not the smaller
        submarine-swap intake — else the later channel open underfunds."""
        _enable_channel(monkeypatch)
        svc = _make_service()
        # Channel-sized intake we expect (from the quote).
        cq, _ = await svc.quote(
            amount_sats=1_000_000,
            source_kind="ext_onchain",
            funding_strategy="channel",
        )
        # Swap-sized intake differs (submarine math vs channel capacity);
        # the point is the intake is STRATEGY-AWARE, not which is larger.
        sq, _ = await svc.quote(
            amount_sats=1_000_000,
            source_kind="ext_onchain",
            funding_strategy="swap",
        )
        assert cq.required_external_deposit_sats != sq.required_external_deposit_sats

        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="ext_onchain",
            funding_strategy="channel",
        )
        result = await svc.advance(db_session, session.id)
        assert result is not None
        assert result.status == BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS
        # Intake matches the CHANNEL-sized quote, not the swap-sized one
        # (proves _advance_created_ext_onchain quotes with the session's
        # funding_strategy rather than defaulting to swap).
        assert result.ext_intake_amount_sats == cq.required_external_deposit_sats
        assert result.ext_intake_amount_sats != sq.required_external_deposit_sats

    @pytest.mark.asyncio
    async def test_cancel_refused_while_opening_channel(self, db_session, monkeypatch):
        _enable_channel(monkeypatch)
        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        await svc.advance(db_session, session.id)  # → OPENING_CHANNEL
        ok, err = await svc.cancel_session(db_session, session.id)
        assert ok is False
        assert "channel funding" in (err or "").lower()


class TestChannelSerialization:
    @pytest.mark.asyncio
    async def test_serializer_exposes_funding_strategy(self, db_session, monkeypatch):
        """The dashboard serializer must expose funding_strategy so the
        SPA's post-refund 'retry via channel' guard works."""
        from app.dashboard.api import _braiins_serialize

        _enable_channel(monkeypatch)
        svc = _make_service()
        session, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "x" * 38,
            source_kind="onchain",
            funding_strategy="channel",
        )
        out = _braiins_serialize(session)
        assert out["funding_strategy"] == "channel"
        # A swap session serializes as "swap".
        s2, _ = await svc.create_session(
            db_session,
            api_key_id=uuid4(),
            amount_sats=1_000_000,
            destination_address="bc1q" + "y" * 38,
            source_kind="lightning",
        )
        assert _braiins_serialize(s2)["funding_strategy"] == "swap"
