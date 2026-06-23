# SPDX-License-Identifier: MIT
"""Unit tests for ``app.services.utxo_service``.

Exercises label CRUD, validation, reconcile lifecycle (spent_at +
auto:receive seeding + 30-day soft-purge), and the inherit-on-spend
flow used by send-onchain and consolidate.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from app.models.utxo_label import (
    LABEL_MAX_LEN,
    AddressPurpose,
    UtxoLabel,
    UtxoLabelSource,
)
from app.services import utxo_service

TXID_A = "a" * 64
TXID_B = "b" * 64
TXID_NEW = "c" * 64


def _utxo(txid: str, vout: int, *, address: str = "bc1qabc", amount: int = 50000, conf: int = 3):
    return {
        "outpoint": {"txid_str": txid, "output_index": vout},
        "amount_sat": amount,
        "address": address,
        "address_type": "WITNESS_PUBKEY_HASH",
        "pk_script": "",
        "confirmations": conf,
    }


# ─── normalise_label ────────────────────────────────────────────────────


class TestNormaliseLabel:
    def test_strips_and_normalises(self):
        assert utxo_service.normalise_label("  hi  ") == "hi"

    def test_empty_returns_empty(self):
        assert utxo_service.normalise_label("") == ""
        assert utxo_service.normalise_label(None) == ""

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            utxo_service.normalise_label("x" * (LABEL_MAX_LEN + 1))

    def test_rejects_control_bytes(self):
        with pytest.raises(ValueError):
            utxo_service.normalise_label("hi\x01there")

    def test_rejects_del(self):
        with pytest.raises(ValueError):
            utxo_service.normalise_label("hi\x7f")

    def test_allows_tab(self):
        assert utxo_service.normalise_label("hi\tthere") == "hi\tthere"

    def test_rejects_angle_brackets(self):
        # Belt-and-suspenders against a future HTML/SVG renderer (XSS).
        for bad in ("<script>", "a>b", "x<y"):
            with pytest.raises(ValueError):
                utxo_service.normalise_label(bad)


# ─── normalise_txid ─────────────────────────────────────────────────────


class TestNormaliseTxid:
    def test_lowercases(self):
        assert utxo_service.normalise_txid("A" * 64) == "a" * 64

    def test_rejects_short(self):
        with pytest.raises(ValueError):
            utxo_service.normalise_txid("abc")

    def test_rejects_non_hex(self):
        with pytest.raises(ValueError):
            utxo_service.normalise_txid("z" * 64)


# ─── set_label / clear_label ────────────────────────────────────────────


@pytest.mark.asyncio
class TestSetLabel:
    async def test_creates_row(self, db_session):
        await utxo_service.set_label(db_session, TXID_A, 0, "Ocean payout")
        row = (
            (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_A, UtxoLabel.vout == 0)))
            .scalars()
            .first()
        )
        assert row is not None
        assert row.label == "Ocean payout"
        assert row.source == UtxoLabelSource.USER

    async def test_updates_row(self, db_session):
        await utxo_service.set_label(db_session, TXID_A, 0, "first")
        await utxo_service.set_label(db_session, TXID_A, 0, "second")
        rows = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_A))).scalars().all()
        assert len(rows) == 1
        assert rows[0].label == "second"

    async def test_user_empty_clears_row(self, db_session):
        await utxo_service.set_label(db_session, TXID_A, 0, "tmp")
        await utxo_service.set_label(db_session, TXID_A, 0, "")
        rows = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_A))).scalars().all()
        assert rows == []

    async def test_invalid_label_raises(self, db_session):
        with pytest.raises(ValueError):
            await utxo_service.set_label(db_session, TXID_A, 0, "x" * 200)


# ─── reconcile ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestReconcile:
    async def test_marks_spent(self, db_session):
        # Seed a label for an outpoint. Then call reconcile when LND
        # reports it as no longer in the unspent set.
        await utxo_service.set_label(db_session, TXID_A, 0, "Ocean payout")
        await db_session.flush()
        with patch.object(
            utxo_service.lnd_service,
            "list_unspent",
            new_callable=AsyncMock,
            return_value=([], None),
        ):
            counters = await utxo_service.reconcile(db_session)
        assert counters["spent_marked"] == 1
        row = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_A))).scalars().first()
        assert row.spent_at is not None

    async def test_seeds_auto_receive(self, db_session):
        # Record a purpose for a known address; reconcile should
        # auto-create an AUTO_RECEIVE label when that address shows up
        # in list_unspent.
        await utxo_service.record_address_purpose(db_session, "bc1qreceive", "Ocean payout")
        with patch.object(
            utxo_service.lnd_service,
            "list_unspent",
            new_callable=AsyncMock,
            return_value=([_utxo(TXID_A, 0, address="bc1qreceive")], None),
        ):
            counters = await utxo_service.reconcile(db_session)
        assert counters["auto_labelled"] == 1
        row = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_A))).scalars().first()
        assert row is not None
        assert row.label == "Ocean payout"
        assert row.source == UtxoLabelSource.AUTO_RECEIVE

        # The purpose row should be marked consumed.
        ap = (
            (await db_session.execute(select(AddressPurpose).where(AddressPurpose.address == "bc1qreceive")))
            .scalars()
            .first()
        )
        assert ap.consumed_at is not None

    async def test_purges_old_non_user(self, db_session):
        # Insert an aged AUTO_SWAP row; reconcile should delete it.
        old = datetime.now(timezone.utc) - timedelta(days=45)
        db_session.add(
            UtxoLabel(
                txid=TXID_B,
                vout=0,
                label="Loop-out: 1000 sats",
                source=UtxoLabelSource.AUTO_SWAP,
                spent_at=old,
            )
        )
        await db_session.flush()
        with patch.object(
            utxo_service.lnd_service,
            "list_unspent",
            new_callable=AsyncMock,
            return_value=([], None),
        ):
            counters = await utxo_service.reconcile(db_session)
        assert counters["purged"] == 1
        rows = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_B))).scalars().all()
        assert rows == []

    async def test_keeps_old_user_rows(self, db_session):
        old = datetime.now(timezone.utc) - timedelta(days=45)
        db_session.add(
            UtxoLabel(
                txid=TXID_B,
                vout=0,
                label="paranoid hodl",
                source=UtxoLabelSource.USER,
                spent_at=old,
            )
        )
        await db_session.flush()
        with patch.object(
            utxo_service.lnd_service,
            "list_unspent",
            new_callable=AsyncMock,
            return_value=([], None),
        ):
            counters = await utxo_service.reconcile(db_session)
        assert counters["purged"] == 0
        rows = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_B))).scalars().all()
        assert len(rows) == 1


# ─── inherit_on_spend ───────────────────────────────────────────────────


@pytest.mark.asyncio
class TestInheritOnSpend:
    async def test_consolidate_writes_synthesised_label(self, db_session):
        await utxo_service.set_label(db_session, TXID_A, 0, "first")
        await utxo_service.set_label(db_session, TXID_B, 1, "second")
        await db_session.flush()

        await utxo_service.inherit_on_spend(
            db_session,
            spent_outpoints=[
                {"txid_str": TXID_A, "output_index": 0},
                {"txid_str": TXID_B, "output_index": 1},
            ],
            new_txid=TXID_NEW,
            change_vout=0,
            consolidate=True,
        )
        row = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_NEW))).scalars().first()
        assert row is not None
        assert row.label == "Consolidated: 2 inputs"
        assert row.source == UtxoLabelSource.INHERITED

        # Parents stamped spent
        parent = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_A))).scalars().first()
        assert parent.spent_at is not None
        assert parent.spent_txid == TXID_NEW

    async def test_send_inherits_single_label(self, db_session):
        await utxo_service.set_label(db_session, TXID_A, 0, "Ocean payout")
        await db_session.flush()

        await utxo_service.inherit_on_spend(
            db_session,
            spent_outpoints=[{"txid_str": TXID_A, "output_index": 0}],
            new_txid=TXID_NEW,
            change_vout=1,
            consolidate=False,
        )
        row = (
            (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_NEW, UtxoLabel.vout == 1)))
            .scalars()
            .first()
        )
        assert row is not None
        assert row.label == "Ocean payout"
        assert row.source == UtxoLabelSource.INHERITED

    async def test_send_skips_when_no_change_vout(self, db_session):
        await utxo_service.set_label(db_session, TXID_A, 0, "Ocean payout")
        await db_session.flush()

        await utxo_service.inherit_on_spend(
            db_session,
            spent_outpoints=[{"txid_str": TXID_A, "output_index": 0}],
            new_txid=TXID_NEW,
            change_vout=None,
            consolidate=False,
        )
        rows = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_NEW))).scalars().all()
        assert rows == []


# ─── list_utxos_with_labels ─────────────────────────────────────────────


@pytest.mark.asyncio
class TestListUtxosWithLabels:
    async def test_joins_labels_and_sorts_by_amount_desc(self, db_session):
        # Seed two labels and verify the response shape + ordering
        # (largest amount first, total_sats summed).
        await utxo_service.set_label(db_session, TXID_A, 0, "small")
        await utxo_service.set_label(db_session, TXID_B, 1, "big")
        await db_session.flush()

        utxos = [
            _utxo(TXID_A, 0, amount=10_000, address="bc1qsmall"),
            _utxo(TXID_B, 1, amount=500_000, address="bc1qbig"),
        ]
        with patch.object(
            utxo_service.lnd_service,
            "list_unspent",
            new_callable=AsyncMock,
            return_value=(utxos, None),
        ):
            res = await utxo_service.list_utxos_with_labels(db_session)
        assert res["total_sats"] == 510_000
        names = [u["label"] for u in res["utxos"]]
        assert names == ["big", "small"]
        # Source surfaced as a string value, not enum.
        assert res["utxos"][0]["label_source"] == "user"
        # Key format <txid>:<vout>.
        assert res["utxos"][0]["key"] == f"{TXID_B}:1"

    async def test_search_filters_by_label_or_address(self, db_session):
        await utxo_service.set_label(db_session, TXID_A, 0, "Ocean payout")
        await utxo_service.set_label(db_session, TXID_B, 0, "ColdStorage")
        await db_session.flush()

        utxos = [
            _utxo(TXID_A, 0, address="bc1qfoo"),
            _utxo(TXID_B, 0, address="bc1qbar"),
        ]
        with patch.object(
            utxo_service.lnd_service,
            "list_unspent",
            new_callable=AsyncMock,
            return_value=(utxos, None),
        ):
            res = await utxo_service.list_utxos_with_labels(db_session, search="ocean")
        assert len(res["utxos"]) == 1
        assert res["utxos"][0]["label"] == "Ocean payout"

    async def test_error_propagates(self, db_session):
        with patch.object(
            utxo_service.lnd_service,
            "list_unspent",
            new_callable=AsyncMock,
            return_value=(None, "lnd offline"),
        ):
            res = await utxo_service.list_utxos_with_labels(db_session)
        assert res.get("error") == "lnd offline"

    async def test_unlabelled_utxos_have_null_source(self, db_session):
        utxos = [_utxo(TXID_A, 0, amount=1_000)]
        with patch.object(
            utxo_service.lnd_service,
            "list_unspent",
            new_callable=AsyncMock,
            return_value=(utxos, None),
        ):
            res = await utxo_service.list_utxos_with_labels(db_session)
        assert len(res["utxos"]) == 1
        assert res["utxos"][0]["label"] == ""
        assert res["utxos"][0]["label_source"] is None


# ─── clear_label ────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestClearLabel:
    async def test_clears_user_row(self, db_session):
        await utxo_service.set_label(db_session, TXID_A, 0, "tmp")
        await utxo_service.clear_label(db_session, TXID_A, 0)
        rows = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_A))).scalars().all()
        assert rows == []

    async def test_skips_non_user_row(self, db_session):
        # AUTO_RECEIVE rows must not be wiped by a clear call —
        # they are reconcile-managed.
        db_session.add(
            UtxoLabel(
                txid=TXID_A,
                vout=0,
                label="auto seeded",
                source=UtxoLabelSource.AUTO_RECEIVE,
            )
        )
        await db_session.flush()
        await utxo_service.clear_label(db_session, TXID_A, 0)
        row = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_A))).scalars().first()
        assert row is not None
        assert row.label == "auto seeded"

    async def test_clear_missing_is_noop(self, db_session):
        # Should not raise on a non-existent outpoint.
        await utxo_service.clear_label(db_session, TXID_A, 7)


# ─── record_address_purpose ─────────────────────────────────────────────


@pytest.mark.asyncio
class TestRecordAddressPurpose:
    async def test_creates_row(self, db_session):
        await utxo_service.record_address_purpose(db_session, "bc1qaddr", "Ocean payout")
        ap = (
            (await db_session.execute(select(AddressPurpose).where(AddressPurpose.address == "bc1qaddr")))
            .scalars()
            .first()
        )
        assert ap is not None
        assert ap.purpose == "Ocean payout"
        assert ap.consumed_at is None

    async def test_overwrite_resets_consumed_at(self, db_session):
        # Seed + mark consumed, then re-record. consumed_at should be
        # cleared so the next reconcile can re-tag a new outpoint.
        await utxo_service.record_address_purpose(db_session, "bc1qaddr", "first")
        ap = (
            (await db_session.execute(select(AddressPurpose).where(AddressPurpose.address == "bc1qaddr")))
            .scalars()
            .first()
        )
        ap.consumed_at = datetime.now(timezone.utc)
        await db_session.flush()

        await utxo_service.record_address_purpose(db_session, "bc1qaddr", "second")
        ap2 = (
            (await db_session.execute(select(AddressPurpose).where(AddressPurpose.address == "bc1qaddr")))
            .scalars()
            .first()
        )
        assert ap2.purpose == "second"
        assert ap2.consumed_at is None

    async def test_empty_inputs_are_ignored(self, db_session):
        await utxo_service.record_address_purpose(db_session, "", "x")
        await utxo_service.record_address_purpose(db_session, "bc1q", "")
        rows = (await db_session.execute(select(AddressPurpose))).scalars().all()
        assert rows == []


# ─── list_recently_spent ────────────────────────────────────────────────


@pytest.mark.asyncio
class TestListRecentlySpent:
    async def test_returns_within_window_excludes_unspent(self, db_session):
        now = datetime.now(timezone.utc)
        # Spent within window
        db_session.add(
            UtxoLabel(
                txid=TXID_A,
                vout=0,
                label="recent",
                source=UtxoLabelSource.USER,
                spent_at=now - timedelta(days=2),
                spent_txid=TXID_NEW,
            )
        )
        # Unspent (should be excluded)
        db_session.add(
            UtxoLabel(
                txid=TXID_B,
                vout=0,
                label="live",
                source=UtxoLabelSource.USER,
            )
        )
        # Spent outside window
        db_session.add(
            UtxoLabel(
                txid="d" * 64,
                vout=0,
                label="ancient",
                source=UtxoLabelSource.USER,
                spent_at=now - timedelta(days=60),
            )
        )
        await db_session.flush()

        rows = await utxo_service.list_recently_spent(db_session, days=30)
        assert len(rows) == 1
        assert rows[0]["txid"] == TXID_A
        assert rows[0]["spent_txid"] == TXID_NEW
        assert rows[0]["label"] == "recent"
        assert rows[0]["label_source"] == "user"


# ─── reconcile (additional cases) ───────────────────────────────────────


@pytest.mark.asyncio
class TestReconcileAdditional:
    async def test_error_path_returns_error_counter(self, db_session):
        with patch.object(
            utxo_service.lnd_service,
            "list_unspent",
            new_callable=AsyncMock,
            return_value=(None, "boom"),
        ):
            res = await utxo_service.reconcile(db_session)
        assert res["error"] == 1
        assert res["spent_marked"] == 0

    async def test_does_not_double_stamp(self, db_session):
        # An already-stamped row should not be re-marked or duplicated.
        old = datetime.now(timezone.utc) - timedelta(days=5)
        db_session.add(
            UtxoLabel(
                txid=TXID_A,
                vout=0,
                label="x",
                source=UtxoLabelSource.USER,
                spent_at=old,
            )
        )
        await db_session.flush()
        with patch.object(
            utxo_service.lnd_service,
            "list_unspent",
            new_callable=AsyncMock,
            return_value=([], None),
        ):
            res = await utxo_service.reconcile(db_session)
        assert res["spent_marked"] == 0
        row = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_A))).scalars().first()
        # spent_at unchanged (old value preserved). SQLite returns
        # naive datetimes so normalise both sides before comparing.
        assert row.spent_at is not None
        got = row.spent_at if row.spent_at.tzinfo else row.spent_at.replace(tzinfo=timezone.utc)
        assert abs((got - old).total_seconds()) < 5

    async def test_skip_existing_label_when_seeding(self, db_session):
        # If a USER label already exists for the outpoint, auto-receive
        # seeding must not overwrite it.
        await utxo_service.record_address_purpose(db_session, "bc1qreceive", "purpose")
        await utxo_service.set_label(db_session, TXID_A, 0, "user wins")
        await db_session.flush()

        with patch.object(
            utxo_service.lnd_service,
            "list_unspent",
            new_callable=AsyncMock,
            return_value=([_utxo(TXID_A, 0, address="bc1qreceive")], None),
        ):
            res = await utxo_service.reconcile(db_session)
        assert res["auto_labelled"] == 0
        row = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_A))).scalars().first()
        assert row.label == "user wins"
        assert row.source == UtxoLabelSource.USER


# ─── inherit_on_spend (additional cases) ────────────────────────────────


@pytest.mark.asyncio
class TestInheritOnSpendAdditional:
    async def test_send_with_multiple_labels_does_not_inherit(self, db_session):
        # Two labelled inputs → ambiguous, no auto-pick.
        await utxo_service.set_label(db_session, TXID_A, 0, "first")
        await utxo_service.set_label(db_session, TXID_B, 0, "second")
        await db_session.flush()

        await utxo_service.inherit_on_spend(
            db_session,
            spent_outpoints=[
                {"txid_str": TXID_A, "output_index": 0},
                {"txid_str": TXID_B, "output_index": 0},
            ],
            new_txid=TXID_NEW,
            change_vout=1,
            consolidate=False,
        )
        rows = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_NEW))).scalars().all()
        assert rows == []

    async def test_send_with_no_labelled_parents_is_noop(self, db_session):
        # Spending unlabelled UTXOs creates no inherited label.
        await utxo_service.inherit_on_spend(
            db_session,
            spent_outpoints=[{"txid_str": TXID_A, "output_index": 0}],
            new_txid=TXID_NEW,
            change_vout=1,
            consolidate=False,
        )
        rows = (await db_session.execute(select(UtxoLabel))).scalars().all()
        assert rows == []

    async def test_consolidate_singular_input_label(self, db_session):
        # Plural / singular grammar: 1 input → "1 input" (no s).
        await utxo_service.set_label(db_session, TXID_A, 0, "lone")
        await db_session.flush()
        await utxo_service.inherit_on_spend(
            db_session,
            spent_outpoints=[{"txid_str": TXID_A, "output_index": 0}],
            new_txid=TXID_NEW,
            change_vout=0,
            consolidate=True,
        )
        row = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == TXID_NEW))).scalars().first()
        assert row.label == "Consolidated: 1 input"

    async def test_empty_inputs_are_noop(self, db_session):
        # Defensive: caller may hand us nothing.
        await utxo_service.inherit_on_spend(
            db_session,
            spent_outpoints=[],
            new_txid=TXID_NEW,
            change_vout=0,
            consolidate=True,
        )
        rows = (await db_session.execute(select(UtxoLabel))).scalars().all()
        assert rows == []
