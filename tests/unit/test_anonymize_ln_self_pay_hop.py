# SPDX-License-Identifier: MIT
"""LN self-pay hop body unit tests.

The hop body dispatches by session status:
* ``FUNDING`` → mint the invoice + fire the circular self-payment.
* ``LN_HOLDING`` → no-op (the payment already settled to reach here).

Tests inject mocked :class:`LnSelfPayHopDeps` adapters so the body
runs entirely without a live LND.
"""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.hops.ln_self_pay import (
    LnSelfPayHopDeps,
    execute_ln_self_pay_hop_step,
)
from app.services.anonymize.self_pay_routing import SelfPayRoute


def _session(*, status: str, pj: dict | None = None) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="lightning-self",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json=pj or {},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )


def _deps(
    *,
    add_invoice_returns=None,
    send_returns=None,
    lookup_returns=None,
    route_returns=None,
) -> LnSelfPayHopDeps:
    return LnSelfPayHopDeps(
        lnd_add_invoice=AsyncMock(
            return_value=add_invoice_returns or ({"payment_request": "lnbcrt1self", "r_hash": "ab" * 32}, None),
        ),
        lnd_send_self_payment=AsyncMock(
            return_value=send_returns or ({"payment_hash": "ab" * 32, "status": "SUCCEEDED"}, None),
        ),
        lnd_lookup_invoice=AsyncMock(
            return_value=lookup_returns or ({"settled": False}, None),
        ),
        resolve_self_pay_route=AsyncMock(
            return_value=route_returns or (SelfPayRoute(mode="pinned", outgoing_chan_id="123:0:1"), None),
        ),
    )


# ── FUNDING — fire the self-payment ─────────────────────────────────


@pytest.mark.asyncio
async def test_funding_pinned_fires_self_pay_and_marks_settled(db_session) -> None:
    sess = _session(status=AnonymizeStatus.FUNDING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _deps()
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "fired_self_pay"
    assert out.detail == "pinned"
    pj = sess.pipeline_json
    assert pj["self_pay_status"] == "settled"
    assert pj["self_pay_invoice"] == "lnbcrt1self"
    assert pj["self_pay_payment_hash_hex"] == "ab" * 32
    assert pj["self_pay_mode"] == "pinned"
    assert pj["self_pay_outgoing_chan_id"] == "123:0:1"
    # Pinned mode pins one channel and does NOT split.
    _, kwargs = deps.lnd_send_self_payment.call_args
    assert kwargs["outgoing_chan_id"] == "123:0:1"
    assert kwargs["max_parts"] is None
    assert kwargs["ignored_pairs"] is None


@pytest.mark.asyncio
async def test_funding_split_fires_with_max_parts_and_ignored_pairs(db_session) -> None:
    sess = _session(status=AnonymizeStatus.FUNDING.value)
    db_session.add(sess)
    await db_session.flush()
    pairs = (("02aa", "03bb"),)
    deps = _deps(route_returns=(SelfPayRoute(mode="split", max_parts=3, ignored_pairs=pairs), None))
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "fired_self_pay"
    assert out.detail == "split"
    pj = sess.pipeline_json
    assert pj["self_pay_mode"] == "split"
    assert pj["self_pay_max_parts"] == 3
    assert "self_pay_outgoing_chan_id" not in pj
    # Split mode fans out and does NOT pin a single channel — mutual
    # exclusion enforced at the send call site.
    _, kwargs = deps.lnd_send_self_payment.call_args
    assert kwargs["outgoing_chan_id"] is None
    assert kwargs["max_parts"] == 3
    assert kwargs["ignored_pairs"] == [("02aa", "03bb")]


@pytest.mark.asyncio
async def test_funding_noop_when_already_settled(db_session) -> None:
    sess = _session(status=AnonymizeStatus.FUNDING.value, pj={"self_pay_status": "settled"})
    db_session.add(sess)
    await db_session.flush()
    deps = _deps()
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
    assert "already_settled" in out.detail
    deps.lnd_send_self_payment.assert_not_called()


@pytest.mark.asyncio
async def test_funding_rejects_zero_bin_amount(db_session) -> None:
    sess = _session(status=AnonymizeStatus.FUNDING.value)
    sess.bin_amount_sat = 0
    db_session.add(sess)
    await db_session.flush()
    deps = _deps()
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "bin_amount_sat" in out.detail


@pytest.mark.asyncio
async def test_funding_errors_on_add_invoice_failure(db_session) -> None:
    sess = _session(status=AnonymizeStatus.FUNDING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _deps(add_invoice_returns=(None, "lnd unavailable"))
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "add_invoice_failed" in out.detail


@pytest.mark.asyncio
async def test_funding_errors_when_route_unresolved(db_session) -> None:
    sess = _session(status=AnonymizeStatus.FUNDING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _deps(route_returns=(None, "insufficient_local_balance_for_self_pay"))
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "self_pay_route" in out.detail
    # No payment fired when no route resolves — no funds move.
    deps.lnd_send_self_payment.assert_not_called()


@pytest.mark.asyncio
async def test_funding_errors_on_send_failure_without_marking_settled(db_session) -> None:
    """A failed self-pay does not mark settled; the same invoice is
    reused on the next tick (LND dedups by hash)."""
    sess = _session(status=AnonymizeStatus.FUNDING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _deps(send_returns=(None, "Payment failed: NO_ROUTE"))
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "self_pay_send" in out.detail
    pj = sess.pipeline_json
    assert pj.get("self_pay_status") != "settled"
    # The minted invoice is persisted so the retry reuses it.
    assert pj["self_pay_invoice"] == "lnbcrt1self"


@pytest.mark.asyncio
async def test_funding_reuses_persisted_invoice_on_retry(db_session) -> None:
    """When an invoice was already minted, the step does not mint a
    second one — it reuses the persisted payment_request/hash."""
    sess = _session(
        status=AnonymizeStatus.FUNDING.value,
        pj={"self_pay_invoice": "lnbcrt1persisted", "self_pay_payment_hash_hex": "cd" * 32},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _deps()
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "fired_self_pay"
    deps.lnd_add_invoice.assert_not_called()
    _, kwargs = deps.lnd_send_self_payment.call_args
    assert kwargs["payment_request"] == "lnbcrt1persisted"


@pytest.mark.asyncio
async def test_funding_lookup_resolves_settled_payment_without_resending(db_session) -> None:
    """Crash-recovery: a prior tick's payment settled but the outcome
    was never recorded. ``lookup_invoice`` resolves it; the step does
    not fire a second payment."""
    sess = _session(
        status=AnonymizeStatus.FUNDING.value,
        pj={"self_pay_invoice": "lnbcrt1persisted", "self_pay_payment_hash_hex": "cd" * 32},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _deps(lookup_returns=({"settled": True}, None))
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "fired_self_pay"
    assert out.detail == "resolved_settled"
    assert sess.pipeline_json["self_pay_status"] == "settled"
    deps.lnd_send_self_payment.assert_not_called()


@pytest.mark.asyncio
async def test_funding_commits_payment_hash_before_firing(db_session, monkeypatch) -> None:
    """Crash-consistency: the minted payment hash must be durably
    committed BEFORE the self-pay fires. Otherwise a crash in the send
    window rolls back the hash, the next tick mints a fresh one, and a
    second self-payment fires (LND can only dedup a re-used hash)."""
    sess = _session(status=AnonymizeStatus.FUNDING.value)
    db_session.add(sess)
    await db_session.flush()

    commits = {"count": 0}
    orig_commit = db_session.commit

    async def _counting_commit():
        commits["count"] += 1
        await orig_commit()

    monkeypatch.setattr(db_session, "commit", _counting_commit)

    seen = {"commits_at_send": None}

    async def _send(**_kwargs):
        seen["commits_at_send"] = commits["count"]
        return ({"status": "SUCCEEDED"}, None)

    deps = _deps()
    deps.lnd_send_self_payment = AsyncMock(side_effect=_send)

    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "fired_self_pay"
    # The hash was committed before the payment was attempted.
    assert seen["commits_at_send"] is not None and seen["commits_at_send"] >= 1
    assert sess.pipeline_json["self_pay_payment_hash_hex"] == "ab" * 32


@pytest.mark.asyncio
async def test_funding_noop_when_attempt_already_completed(db_session) -> None:
    """A recorded completion marker short-circuits to settled no-op."""
    from app.services.anonymize.hop_idempotency import record_hop_attempt_completed
    from app.services.anonymize.hops.ln_self_pay import _key_for

    sess = _session(status=AnonymizeStatus.FUNDING.value)
    db_session.add(sess)
    await db_session.flush()
    key = _key_for(sess, "ln_self_pay_fire", attempt=1)
    await record_hop_attempt_completed(db_session, key=key, detail={"mode": "pinned"})
    await db_session.flush()

    deps = _deps()
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
    assert "already_completed" in out.detail
    assert sess.pipeline_json["self_pay_status"] == "settled"
    deps.lnd_send_self_payment.assert_not_called()


# ── LN_HOLDING — no-op ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ln_holding_is_noop(db_session) -> None:
    sess = _session(status=AnonymizeStatus.LN_HOLDING.value, pj={"self_pay_status": "settled"})
    db_session.add(sess)
    await db_session.flush()
    deps = _deps()
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
    deps.lnd_send_self_payment.assert_not_called()


@pytest.mark.asyncio
async def test_unhandled_status_returns_noop(db_session) -> None:
    sess = _session(status=AnonymizeStatus.EXITING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _deps()
    out = await execute_ln_self_pay_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
