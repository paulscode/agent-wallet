# SPDX-License-Identifier: MIT
"""Anonymize ext-lightning BOLT 12 deposit-offer minter.

Covers :func:`issue_ext_lightning_deposit_offer`:

* Happy path — mints a BOLT 12 offer, persists a ``bolt12_offers`` row,
  returns the canonical ``lno1...`` string + the row's ID.
* Optional BIP-353 — when a domain is configured, ALSO returns the
  ``user@domain`` handle + the zone-file TXT-record fragment. The
  ``user`` portion is fresh per call (no enumeration handle).
* Amount bounds — refuses zero / negative / oversized amounts.
* Bad BIP-353 domain — refuses on malformed labels rather than
  silently emitting an unparseable record.
"""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.api_key import APIKey
from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferSource
from app.services.anonymize.deposit_offer import (
    DepositOfferError,
    issue_ext_lightning_deposit_offer,
)


@pytest.fixture(autouse=True)
def _stub_offer_paths(monkeypatch):
    """Skip the live-gateway path for ``_build_offer_paths_for_issuance``.

    The deposit minter calls the same helper as the public ``/offers/issue``
    endpoint; without a gateway it returns ``None``. The minter handles
    ``None`` cleanly (the offer is still encodable without offer_paths
    on regtest deployments). Stub returns ``None`` here so we don't
    need to wire a fake gateway in every test.
    """
    from app.api import bolt12 as bolt12_api

    monkeypatch.setattr(
        bolt12_api,
        "_build_offer_paths_for_issuance",
        AsyncMock(return_value=None),
    )


@pytest.fixture
async def api_key_row(db_session) -> APIKey:
    """A persisted API key the minter can attribute the offer to."""
    row = APIKey(
        id=uuid4(),
        name="anonymize-deposit-test",
        key_hash="deadbeef" * 8,
        is_admin=True,
        is_active=True,
    )
    db_session.add(row)
    await db_session.commit()
    await db_session.refresh(row)
    return row


@pytest.mark.asyncio
async def test_issue_returns_bolt12_offer(
    db_session,
    api_key_row,
) -> None:
    """Happy path — minter returns a canonical ``lno1...`` string and
    persists the offer row with ``source=ISSUED``."""
    result = await issue_ext_lightning_deposit_offer(
        amount_msat=250_000 * 1000,
        description="anonymize-test",
        api_key_id=api_key_row.id,
        db=db_session,
    )
    assert result.bolt12_offer.startswith("lno1")
    assert result.offer_id  # UUID string

    # Persisted row joins back by offer_id.
    row = (await db_session.execute(select(Bolt12Offer).where(Bolt12Offer.bolt12 == result.bolt12_offer))).scalar_one()
    assert row.source == Bolt12OfferSource.ISSUED
    assert row.amount_msat == 250_000 * 1000
    assert str(row.id) == result.offer_id


@pytest.mark.asyncio
async def test_issue_without_bip353_domain_returns_no_handle(
    db_session,
    api_key_row,
) -> None:
    """With no BIP-353 domain configured the result carries only the offer."""
    result = await issue_ext_lightning_deposit_offer(
        amount_msat=250_000 * 1000,
        description="no-handle",
        api_key_id=api_key_row.id,
        db=db_session,
        bip353_domain=None,
    )
    assert result.bip353_handle is None
    assert result.bip353_txt_record is None
    assert result.bip353_user_label is None


@pytest.mark.asyncio
async def test_issue_with_bip353_domain_returns_handle(
    db_session,
    api_key_row,
) -> None:
    """With a BIP-353 domain configured, the minter ALSO returns a
    fresh per-session handle + zone-file TXT-record fragment."""
    result = await issue_ext_lightning_deposit_offer(
        amount_msat=250_000 * 1000,
        description="with-handle",
        api_key_id=api_key_row.id,
        db=db_session,
        bip353_domain="wallet.example.com",
    )
    assert result.bip353_handle is not None
    assert result.bip353_handle.endswith("@wallet.example.com")
    # 12 hex characters = 48 bits of entropy.
    assert result.bip353_user_label is not None
    assert len(result.bip353_user_label) == 12

    # The TXT record embeds the offer + uses BIP-353's
    # ``user._bitcoin-payment.<domain>`` shape.
    assert result.bip353_txt_record is not None
    assert "_bitcoin-payment.wallet.example.com" in result.bip353_txt_record
    assert result.bolt12_offer in result.bip353_txt_record


@pytest.mark.asyncio
async def test_handles_are_unique_per_call(
    db_session,
    api_key_row,
) -> None:
    """Two calls in a row yield distinct ``user`` labels — handles
    must not be enumerable from one session's row."""
    r1 = await issue_ext_lightning_deposit_offer(
        amount_msat=250_000 * 1000,
        description="a",
        api_key_id=api_key_row.id,
        db=db_session,
        bip353_domain="wallet.example.com",
    )
    r2 = await issue_ext_lightning_deposit_offer(
        amount_msat=250_000 * 1000,
        description="b",
        api_key_id=api_key_row.id,
        db=db_session,
        bip353_domain="wallet.example.com",
    )
    assert r1.bip353_user_label != r2.bip353_user_label
    assert r1.bolt12_offer != r2.bolt12_offer


@pytest.mark.asyncio
async def test_zero_amount_refused(db_session, api_key_row) -> None:
    with pytest.raises(DepositOfferError, match="positive"):
        await issue_ext_lightning_deposit_offer(
            amount_msat=0,
            description="x",
            api_key_id=api_key_row.id,
            db=db_session,
        )


@pytest.mark.asyncio
async def test_amount_above_max_refused(db_session, api_key_row) -> None:
    from app.core.config import settings

    too_big = (int(settings.anonymize_max_sat) + 1) * 1000
    with pytest.raises(DepositOfferError, match="ANONYMIZE_MAX_SAT"):
        await issue_ext_lightning_deposit_offer(
            amount_msat=too_big,
            description="x",
            api_key_id=api_key_row.id,
            db=db_session,
        )


@pytest.mark.asyncio
async def test_malformed_bip353_domain_refused(
    db_session,
    api_key_row,
) -> None:
    with pytest.raises(DepositOfferError, match="BIP-353"):
        await issue_ext_lightning_deposit_offer(
            amount_msat=250_000 * 1000,
            description="x",
            api_key_id=api_key_row.id,
            db=db_session,
            bip353_domain="not a valid domain",
        )


# ── Audit logging ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_issue_emits_audit_log(db_session, api_key_row) -> None:
    """The minter MUST mirror the public ``/offers/issue`` audit
    pattern — every per-session offer mint lands in the audit log
    with the offer id + amount."""
    from sqlalchemy import select

    from app.models.audit_log import AuditLog

    result = await issue_ext_lightning_deposit_offer(
        amount_msat=250_000 * 1000,
        description="audit-test",
        api_key_id=api_key_row.id,
        db=db_session,
    )

    audit_row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "anonymize_deposit_offer_issue",
            )
        )
    ).scalar_one()
    assert audit_row.resource == "bolt12_offer"
    assert audit_row.amount_sats == 250_000
    assert audit_row.details["offer_id"] == result.offer_id
    assert audit_row.details["has_bip353_handle"] is False


@pytest.mark.asyncio
async def test_issue_with_bip353_handle_flags_audit_row(
    db_session,
    api_key_row,
) -> None:
    """The audit row records whether a BIP-353 handle was minted
    alongside, so the operator can verify whether a DNS publish is
    required without surfacing the handle itself in the audit
    chain."""
    from sqlalchemy import select

    from app.models.audit_log import AuditLog

    await issue_ext_lightning_deposit_offer(
        amount_msat=250_000 * 1000,
        description="bip353-audit-test",
        api_key_id=api_key_row.id,
        db=db_session,
        bip353_domain="wallet.example.com",
    )
    audit_row = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "anonymize_deposit_offer_issue",
            )
        )
    ).scalar_one()
    assert audit_row.details["has_bip353_handle"] is True
    # The handle itself is NOT in the audit row — it's a DNS artifact
    # whose privacy belongs to the operator's publishing decision.
    blob = str(audit_row.details) + (audit_row.error_message or "")
    assert "@wallet.example.com" not in blob


@pytest.mark.asyncio
async def test_audit_failure_does_not_block_mint(
    db_session,
    api_key_row,
    monkeypatch,
) -> None:
    """If the audit chain raises mid-write, the offer mint still
    succeeds — the deposit path must remain available even when
    the audit chain is wedged."""
    from app.services.anonymize import deposit_offer as do_mod

    real_import = do_mod.__builtins__.get("__import__")

    # Monkeypatch the audit_service module's ``log_action`` to raise.
    import app.services.audit_service as audit_mod

    async def _boom(*_args, **_kwargs):
        raise RuntimeError("audit-chain-wedged")

    monkeypatch.setattr(audit_mod, "log_action", _boom)

    # Mint succeeds despite the audit failure.
    result = await issue_ext_lightning_deposit_offer(
        amount_msat=250_000 * 1000,
        description="audit-broken",
        api_key_id=api_key_row.id,
        db=db_session,
    )
    assert result.bolt12_offer.startswith("lno1")
    _ = real_import  # keep linters happy
