# SPDX-License-Identifier: MIT
"""Refund-UTXO lockdown label production wire.

The wallet's coin selector excludes UTXOs whose label matches the
documented ``auto:anonymize-*`` prefixes. The orchestrator emits
``apply_refund_lockdown_label`` after a refund-tx broadcast so the
returned UTXOs cannot accidentally fund non-anonymize wallet flows.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.utxo_label import UtxoLabel, UtxoLabelSource
from app.services.anonymize.coin_control import (
    apply_refund_lockdown_label,
    is_do_not_spend_label,
    make_refund_lockdown_label,
)

# ── is_do_not_spend_label ───────────────────────────────────────────


def test_is_do_not_spend_admits_known_labels() -> None:
    for label in (
        "auto:anonymize-refund",
        "auto:anonymize-overpad",
        "auto:anonymize-decoy",
        "auto:anonymize-change",
    ):
        assert is_do_not_spend_label(label) is True


def test_is_do_not_spend_admits_label_with_suffix() -> None:
    """Labels like ``auto:anonymize-refund:timeout`` match the prefix."""
    assert is_do_not_spend_label("auto:anonymize-refund:timeout") is True


def test_is_do_not_spend_rejects_user_labels() -> None:
    assert is_do_not_spend_label("savings cold storage") is False
    assert is_do_not_spend_label("auto:receive") is False
    assert is_do_not_spend_label("auto:swap") is False


def test_is_do_not_spend_handles_none_and_empty() -> None:
    assert is_do_not_spend_label(None) is False
    assert is_do_not_spend_label("") is False


# ── make_refund_lockdown_label (pure helper) ────────────────────────


def test_make_label_admits_documented_reasons() -> None:
    for reason in ("timeout", "operator_unreachable", "partition"):
        label = make_refund_lockdown_label(
            outpoint="abc:0",
            reason=reason,
        )
        assert label.label == "auto:anonymize-refund"
        assert label.do_not_spend is True
        assert label.reason == reason


def test_make_label_refuses_unknown_reason() -> None:
    with pytest.raises(ValueError, match="documented enum"):
        make_refund_lockdown_label(outpoint="abc:0", reason="bogus")


# ── apply_refund_lockdown_label (DB write) ──────────────────────────


@pytest.mark.asyncio
async def test_apply_writes_utxo_label_row(db_session) -> None:
    txid = "ab" * 32
    await apply_refund_lockdown_label(
        db_session,
        outpoint=f"{txid}:1",
        reason="timeout",
    )
    await db_session.commit()
    row = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == txid, UtxoLabel.vout == 1))).scalar_one()
    assert row.label == "auto:anonymize-refund"
    assert row.source == UtxoLabelSource.AUTO_SWAP
    assert (row.note or "").startswith("refund-lockdown:")
    # The label triggers the do-not-spend gate.
    assert is_do_not_spend_label(row.label) is True


@pytest.mark.asyncio
async def test_apply_records_spent_txid_when_provided(db_session) -> None:
    """The refund tx's txid is preserved on the label row so the
    audit chain can correlate the lockdown event with the broadcast."""
    refund_txid = "cd" * 32
    await apply_refund_lockdown_label(
        db_session,
        outpoint="ab" * 32 + ":0",
        reason="operator_unreachable",
        spent_txid=refund_txid,
    )
    await db_session.commit()
    row = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.label == "auto:anonymize-refund"))).scalar_one()
    assert row.spent_txid == refund_txid


@pytest.mark.asyncio
async def test_apply_rejects_malformed_outpoint(db_session) -> None:
    with pytest.raises(ValueError, match="'txid:vout'"):
        await apply_refund_lockdown_label(
            db_session,
            outpoint="not-an-outpoint",
            reason="timeout",
        )


@pytest.mark.asyncio
async def test_apply_rejects_duplicate_outpoint(db_session) -> None:
    """The UtxoLabel table's unique constraint on
    ``(txid, vout)`` prevents two labels on the same outpoint.
    The caller catches the integrity error and decides whether to
    update vs. ignore."""
    txid = "11" * 32
    await apply_refund_lockdown_label(
        db_session,
        outpoint=f"{txid}:0",
        reason="timeout",
    )
    await db_session.commit()
    # Second apply on the same outpoint hits the UNIQUE constraint.
    await apply_refund_lockdown_label(
        db_session,
        outpoint=f"{txid}:0",
        reason="timeout",
    )
    with pytest.raises(Exception):
        await db_session.commit()


@pytest.mark.asyncio
async def test_apply_admits_distinct_vout_on_same_txid(db_session) -> None:
    """Two outputs on the same refund tx are distinct outpoints +
    both should be labelable."""
    txid = "22" * 32
    await apply_refund_lockdown_label(
        db_session,
        outpoint=f"{txid}:0",
        reason="timeout",
    )
    await apply_refund_lockdown_label(
        db_session,
        outpoint=f"{txid}:1",
        reason="timeout",
    )
    await db_session.commit()
    rows = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == txid))).scalars().all()
    assert sorted(r.vout for r in rows) == [0, 1]


@pytest.mark.parametrize(
    "label",
    [
        "auto:anonymize-refund:timeout",
        "auto:anonymize-refund:operator_unreachable",
        "auto:anonymize-refund:partition",
        "auto:anonymize-overpad",
        "auto:anonymize-decoy:session-abc",
        "auto:anonymize-change",
    ],
)
def test_is_do_not_spend_admits_all_documented_label_shapes(label) -> None:
    """The coin selector refuses to spend any UTXO with a label
    matching the documented anonymize-* prefix family, including
    suffixed variants."""
    assert is_do_not_spend_label(label) is True


@pytest.mark.asyncio
async def test_apply_canonicalizes_txid_lowercase(db_session) -> None:
    """The label row stores txid in canonical lowercase even when
    the caller passes uppercase hex."""
    upper = "AB" * 32
    await apply_refund_lockdown_label(
        db_session,
        outpoint=f"{upper}:0",
        reason="timeout",
    )
    await db_session.commit()
    row = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.label == "auto:anonymize-refund"))).scalar_one()
    assert row.txid == upper.lower()
