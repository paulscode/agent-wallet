# SPDX-License-Identifier: MIT
"""BOLT 12-exit hop body for BIP-353 destinations.

Covers:

* Status dispatch — only EXITING drives forward; anything else no-ops.
* Successful pay — single tick transitions EXITING → COMPLETED and
  brackets the call with hop_attempt_started + hop_attempt_completed.
* Failed pay — single tick transitions EXITING → FAILED and persists
  the failure into ``pipeline_json["bolt12_pay_outcome"]``.
* In-flight pay — tick records the outcome and idles; the per-session
  loop does NOT re-issue the invreq (that would mint a second invoice
  with a different payment_hash and risk a double-pay).
* Idempotency — a second tick on a row whose ``hop_attempt_completed``
  event is already persisted is a no-op (no re-invocation of the
  adapter).
* Defensive guards — missing offer / missing amount return ``error``
  rather than a silent no-op.
"""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)
from app.services.anonymize.hops.bolt12_pay import (
    Bolt12PayHopDeps,
    HopStepOutcome,
    execute_bolt12_pay_hop_step,
)


def _session(
    *,
    status: str = AnonymizeStatus.EXITING.value,
    offer: str | None = "lno1deadbeef",
    bin_amount: int = 250_000,
    bolt12_pay_outcome: dict | None = None,
) -> AnonymizeSession:
    pj: dict = {
        "exit": {
            "kind": "bolt12_pay",
            "destination_address": "",
            "bolt12_offer": offer,
            "bip353_handle": "alice@example.com",
        },
    }
    if bolt12_pay_outcome is not None:
        pj["bolt12_pay_outcome"] = bolt12_pay_outcome
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="ext-lightning",
        requested_amount_sat=bin_amount,
        bin_amount_sat=bin_amount,
        pipeline_json=pj,
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="bolt12",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )


def _deps(*, pay_returns=None) -> Bolt12PayHopDeps:
    return Bolt12PayHopDeps(
        pay_bolt12_offer=AsyncMock(
            return_value=pay_returns
            or (
                {
                    "status": "paid",
                    "payment_hash_hex": "aa" * 32,
                    "preimage_hex": "bb" * 32,
                    "error": None,
                },
                None,
            ),
        ),
    )


# ── Status dispatch ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_only_exiting_drives_forward(db_session) -> None:
    """Status outside EXITING is a no-op (no adapter call)."""
    deps = _deps()
    s = _session(status=AnonymizeStatus.CREATED.value)
    db_session.add(s)
    await db_session.flush()

    out = await execute_bolt12_pay_hop_step(db_session, s, deps)
    assert isinstance(out, HopStepOutcome)
    assert out.kind == "noop"
    deps.pay_bolt12_offer.assert_not_called()


# ── Successful pay path ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pay_paid_transitions_to_completed(db_session) -> None:
    """A ``status=paid`` adapter result transitions COMPLETED + skips
    CONFIRMING (BOLT 12 exit settles on LN — no on-chain confirmation)."""
    deps = _deps(
        pay_returns=(
            {
                "status": "paid",
                "payment_hash_hex": "aa" * 32,
                "preimage_hex": "bb" * 32,
                "error": None,
            },
            None,
        )
    )
    s = _session()
    db_session.add(s)
    await db_session.flush()

    out = await execute_bolt12_pay_hop_step(db_session, s, deps)
    assert out.kind == "paid"
    assert out.detail == "aa" * 32

    assert s.status == AnonymizeStatus.COMPLETED.value
    assert s.completed_at is not None
    outcome = (s.pipeline_json or {}).get("bolt12_pay_outcome")
    assert outcome is not None
    assert outcome["status"] == "paid"
    assert outcome["payment_hash_hex"] == "aa" * 32

    # Idempotency events bracket the call.
    kinds = {
        ev.kind
        for ev in (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == s.id,
                )
            )
        )
        .scalars()
        .all()
    }
    assert "hop_attempt_started" in kinds
    assert "hop_attempt_completed" in kinds


@pytest.mark.asyncio
async def test_pay_paid_adapter_called_once(db_session) -> None:
    """The adapter is invoked with the bound offer + amount_msat."""
    deps = _deps()
    s = _session(offer="lno1specific", bin_amount=100_000)
    db_session.add(s)
    await db_session.flush()

    await execute_bolt12_pay_hop_step(db_session, s, deps)

    deps.pay_bolt12_offer.assert_called_once()
    call_kwargs = deps.pay_bolt12_offer.call_args.kwargs
    assert call_kwargs["offer"] == "lno1specific"
    assert call_kwargs["amount_msat"] == 100_000 * 1000


# ── Failed pay path ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pay_returns_error_transitions_failed(db_session) -> None:
    """An adapter error → session transitions FAILED, outcome
    recorded with the error string."""
    deps = _deps(pay_returns=(None, "gateway unreachable"))
    s = _session()
    db_session.add(s)
    await db_session.flush()

    out = await execute_bolt12_pay_hop_step(db_session, s, deps)
    assert out.kind == "failed"
    assert "gateway unreachable" in out.detail

    assert s.status == AnonymizeStatus.FAILED.value
    outcome = (s.pipeline_json or {}).get("bolt12_pay_outcome")
    assert outcome["status"] == "failed"
    assert "gateway unreachable" in outcome["error"]


@pytest.mark.asyncio
async def test_pay_returns_failed_status_transitions_failed(db_session) -> None:
    """A ``status=failed`` adapter result → FAILED transition."""
    deps = _deps(
        pay_returns=(
            {
                "status": "failed",
                "payment_hash_hex": "cc" * 32,
                "preimage_hex": None,
                "error": "no route",
            },
            None,
        )
    )
    s = _session()
    db_session.add(s)
    await db_session.flush()

    out = await execute_bolt12_pay_hop_step(db_session, s, deps)
    assert out.kind == "failed"
    assert s.status == AnonymizeStatus.FAILED.value


# ── In-flight idle path ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pay_returns_in_flight_idles(db_session) -> None:
    """An in-flight result is recorded but the session stays EXITING
    and the next tick does NOT re-issue the invreq."""
    deps = _deps(
        pay_returns=(
            {
                "status": "in_flight",
                "payment_hash_hex": "dd" * 32,
                "preimage_hex": None,
                "error": None,
            },
            None,
        )
    )
    s = _session()
    db_session.add(s)
    await db_session.flush()

    out = await execute_bolt12_pay_hop_step(db_session, s, deps)
    assert out.kind == "in_flight"
    assert s.status == AnonymizeStatus.EXITING.value
    outcome = (s.pipeline_json or {}).get("bolt12_pay_outcome")
    assert outcome["status"] == "in_flight"
    assert outcome["payment_hash_hex"] == "dd" * 32

    # A second tick must NOT re-call the adapter — preventing
    # double-pay is the central correctness property here.
    deps.pay_bolt12_offer.reset_mock()
    out2 = await execute_bolt12_pay_hop_step(db_session, s, deps)
    assert out2.kind == "in_flight"
    deps.pay_bolt12_offer.assert_not_called()


# ── Idempotency on completed marker ─────────────────────────────────


@pytest.mark.asyncio
async def test_completed_outcome_idle_on_retick(db_session) -> None:
    """A row whose pipeline_json says ``status=paid`` no-ops on retick
    rather than re-calling the adapter."""
    deps = _deps()
    s = _session(
        bolt12_pay_outcome={
            "status": "paid",
            "payment_hash_hex": "ee" * 32,
        }
    )
    db_session.add(s)
    await db_session.flush()

    out = await execute_bolt12_pay_hop_step(db_session, s, deps)
    assert out.kind == "noop"
    deps.pay_bolt12_offer.assert_not_called()


# ── Defensive guards ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_missing_offer_returns_error(db_session) -> None:
    deps = _deps()
    s = _session(offer=None)
    db_session.add(s)
    await db_session.flush()

    out = await execute_bolt12_pay_hop_step(db_session, s, deps)
    assert out.kind == "error"
    assert "missing_offer" in out.detail
    deps.pay_bolt12_offer.assert_not_called()


@pytest.mark.asyncio
async def test_missing_bin_amount_returns_error(db_session) -> None:
    deps = _deps()
    s = _session(bin_amount=0)
    db_session.add(s)
    await db_session.flush()

    out = await execute_bolt12_pay_hop_step(db_session, s, deps)
    assert out.kind == "error"
    assert "missing_bin_amount" in out.detail
    deps.pay_bolt12_offer.assert_not_called()
