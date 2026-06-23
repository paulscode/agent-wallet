# SPDX-License-Identifier: MIT
"""Spend-override eligibility decision.

The wallet's coin selector consults
:func:`check_anonymize_spend_eligibility` when a non-anonymize flow
selects a UTXO bearing one of the ``auto:anonymize-*`` labels. Three
outcomes:

* ``admit`` — label is non-anonymize ⇒ free to spend.
* ``refuse`` — the hard-refusal flag is on ⇒ raise.
* ``require_stepup`` — default ⇒ surface step-up re-auth.

The audit-event emitter records the override decision so the audit
chain has the spend-permit evidence.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)
from app.services.anonymize.coin_control import (
    check_anonymize_spend_eligibility,
    decoy_override_spends_refused,
    emit_spend_override_event,
    refund_override_spends_refused,
    spend_override_event_kind,
)

# ── eligibility decision ────────────────────────────────────────────


def test_eligibility_admits_unlabeled_utxo() -> None:
    assert check_anonymize_spend_eligibility(None) == "admit"
    assert check_anonymize_spend_eligibility("") == "admit"


def test_eligibility_admits_user_label() -> None:
    assert check_anonymize_spend_eligibility("savings cold storage") == "admit"
    assert check_anonymize_spend_eligibility("auto:receive") == "admit"
    assert check_anonymize_spend_eligibility("auto:swap") == "admit"


def test_eligibility_onchain_default_requires_stepup_for_refund(
    monkeypatch,
) -> None:
    """Default: refund-override gated on step-up re-auth."""
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_refund_override_spends",
        False,
    )
    assert check_anonymize_spend_eligibility("auto:anonymize-refund") == "require_stepup"
    assert check_anonymize_spend_eligibility("auto:anonymize-refund:timeout") == "require_stepup"


def test_eligibility_external_default_refuses_refund(monkeypatch) -> None:
    """Hard-refusal default: refund-override hard-refused."""
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_refund_override_spends",
        True,
    )
    assert check_anonymize_spend_eligibility("auto:anonymize-refund") == "refuse"


def test_eligibility_onchain_default_requires_stepup_for_decoy(
    monkeypatch,
) -> None:
    """Default: decoy/overpad/change override gated on step-up."""
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_decoy_override_spends",
        False,
    )
    for label in (
        "auto:anonymize-decoy",
        "auto:anonymize-overpad",
        "auto:anonymize-change",
    ):
        assert check_anonymize_spend_eligibility(label) == "require_stepup"


def test_eligibility_external_default_refuses_decoy(monkeypatch) -> None:
    """Hard-refusal default: decoy override hard-refused."""
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_decoy_override_spends",
        True,
    )
    for label in (
        "auto:anonymize-decoy",
        "auto:anonymize-overpad",
        "auto:anonymize-change",
    ):
        assert check_anonymize_spend_eligibility(label) == "refuse"


def test_eligibility_flags_independent(monkeypatch) -> None:
    """The refund + decoy flags flip independently — a deployment
    can hard-refuse decoy but keep refund on step-up (or vice versa)."""
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_refund_override_spends",
        False,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_decoy_override_spends",
        True,
    )
    assert check_anonymize_spend_eligibility("auto:anonymize-refund") == "require_stepup"
    assert check_anonymize_spend_eligibility("auto:anonymize-decoy") == "refuse"


# ── event-kind selector ─────────────────────────────────────────────


def test_event_kind_selects_refund_family() -> None:
    assert spend_override_event_kind("auto:anonymize-refund") == "anonymize_refund_spend_override"
    assert spend_override_event_kind("auto:anonymize-refund:timeout") == "anonymize_refund_spend_override"


def test_event_kind_selects_decoy_family() -> None:
    for label in (
        "auto:anonymize-decoy",
        "auto:anonymize-overpad",
        "auto:anonymize-change",
    ):
        assert spend_override_event_kind(label) == "anonymize_decoy_spend_override"


def test_event_kind_returns_none_for_non_anonymize_labels() -> None:
    assert spend_override_event_kind(None) is None
    assert spend_override_event_kind("") is None
    assert spend_override_event_kind("auto:receive") is None
    assert spend_override_event_kind("user-note") is None


# ── audit-event emission ────────────────────────────────────────────


def _session() -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.COMPLETED.value,
        source_kind="onchain-self",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )


@pytest.mark.asyncio
async def test_emit_writes_refund_override_event(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    await emit_spend_override_event(
        db_session,
        session_id=sess.id,
        outpoint="ab" * 32 + ":0",
        label="auto:anonymize-refund:timeout",
        stepup_nonce_id="nonce-xyz",
    )
    await db_session.commit()
    rows = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == sess.id,
                    AnonymizeSessionEvent.kind == "anonymize_refund_spend_override",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].detail_json["outpoint"] == "ab" * 32 + ":0"
    assert rows[0].detail_json["label"] == "auto:anonymize-refund:timeout"
    assert rows[0].detail_json["stepup_nonce_id"] == "nonce-xyz"


@pytest.mark.asyncio
async def test_emit_writes_decoy_override_event(db_session) -> None:
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    await emit_spend_override_event(
        db_session,
        session_id=sess.id,
        outpoint="cd" * 32 + ":1",
        label="auto:anonymize-decoy",
    )
    await db_session.commit()
    rows = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == sess.id,
                    AnonymizeSessionEvent.kind == "anonymize_decoy_spend_override",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_emit_noop_for_non_anonymize_label(db_session) -> None:
    """The emitter is silently no-op for labels outside the family —
    the dashboard can call it unconditionally without filtering."""
    sess = _session()
    db_session.add(sess)
    await db_session.flush()
    await emit_spend_override_event(
        db_session,
        session_id=sess.id,
        outpoint="ef" * 32 + ":0",
        label="auto:receive",
    )
    await db_session.commit()
    rows = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == sess.id,
                )
            )
        )
        .scalars()
        .all()
    )
    assert rows == []


# ── default-flag helper assertions ──────────────────────────────────


def test_refund_override_helper_reads_setting(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_refund_override_spends",
        True,
    )
    assert refund_override_spends_refused() is True
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_refund_override_spends",
        False,
    )
    assert refund_override_spends_refused() is False


def test_decoy_override_helper_reads_setting(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_decoy_override_spends",
        True,
    )
    assert decoy_override_spends_refused() is True
    monkeypatch.setattr(
        settings,
        "anonymize_refuse_decoy_override_spends",
        False,
    )
    assert decoy_override_spends_refused() is False
