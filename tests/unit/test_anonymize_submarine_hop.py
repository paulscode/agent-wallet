# SPDX-License-Identifier: MIT
"""Submarine hop body unit tests.

The hop body dispatches by session status:
* ``SOURCING`` → mint invoice + POST /swap/submarine
* ``FUNDING`` → broadcast funding tx to the lockup address
* ``LN_HOLDING`` → poll Boltz for settlement / route to refund

Tests inject mocked :class:`SubmarineHopDeps` adapters so the hop
body runs entirely without external services.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.hops.submarine import (
    SubmarineHopDeps,
    execute_submarine_hop_step,
)


def _session(*, status: str, pj: dict | None = None) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="onchain-self",
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


def _mock_swap(*, swap_id="sub-123", lockup="bcrt1qlockup", timeout=900):
    swap = MagicMock()
    swap.boltz_swap_id = swap_id
    swap.boltz_lockup_address = lockup
    swap.timeout_block_height = timeout
    return swap


_UNSET = object()


def _mock_deps(
    *,
    add_invoice_returns=None,
    create_returns=None,
    status_returns=None,
    funding_returns=None,
    refund_returns=None,
    broadcast_returns=None,
    check_inbound_returns=_UNSET,
) -> SubmarineHopDeps:
    # ``check_inbound_returns`` left unset → the dep stays None (the
    # re-check is skipped, back-compat default). Pass a refusal string
    # or None to wire an AsyncMock-backed inbound re-check.
    check_inbound = None
    if check_inbound_returns is not _UNSET:
        check_inbound = AsyncMock(return_value=check_inbound_returns)
    return SubmarineHopDeps(
        boltz_create_submarine_swap=AsyncMock(
            return_value=create_returns or (_mock_swap(), None),
        ),
        boltz_get_swap_status=AsyncMock(
            return_value=status_returns or ("transaction.mempool", {}, None),
        ),
        lnd_add_invoice=AsyncMock(
            return_value=add_invoice_returns or ({"payment_request": "lnbcrt1invoice"}, None),
        ),
        build_and_broadcast_funding_tx=AsyncMock(
            return_value=funding_returns or ({"tx_hex": "deadbeef", "txid": "ab" * 32}, None),
        ),
        run_refund_subprocess=AsyncMock(
            return_value=refund_returns or ("cafe" * 16, None),
        ),
        chain_broadcast_tx=AsyncMock(
            return_value=broadcast_returns or ("txid-1", None),
        ),
        check_inbound_sufficient=check_inbound,
    )


# ── SOURCING — issue swap ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_sourcing_mints_invoice_and_issues_swap(db_session) -> None:
    sess = _session(status=AnonymizeStatus.SOURCING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "issued_swap"
    pj = sess.pipeline_json
    assert pj["submarine_swap_id"] == "sub-123"
    assert pj["submarine_lockup_address"] == "bcrt1qlockup"
    assert pj["submarine_invoice"] == "lnbcrt1invoice"


@pytest.mark.asyncio
async def test_sourcing_noop_when_swap_already_issued(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.SOURCING.value,
        pj={"submarine_swap_id": "sub-existing"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
    assert "already_issued" in out.detail


@pytest.mark.asyncio
async def test_sourcing_returns_error_on_add_invoice_failure(db_session) -> None:
    sess = _session(status=AnonymizeStatus.SOURCING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(add_invoice_returns=(None, "lnd unavailable"))
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "add_invoice_failed" in out.detail


@pytest.mark.asyncio
async def test_sourcing_returns_error_on_submarine_create_failure(
    db_session,
) -> None:
    sess = _session(status=AnonymizeStatus.SOURCING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(create_returns=(None, "operator unreachable"))
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "submarine_create_failed" in out.detail


@pytest.mark.asyncio
async def test_sourcing_rejects_zero_bin_amount(db_session) -> None:
    sess = _session(status=AnonymizeStatus.SOURCING.value)
    sess.bin_amount_sat = 0
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "bin_amount_sat" in out.detail


# ── FUNDING — broadcast lockup funding tx ───────────────────────────


@pytest.mark.asyncio
async def test_funding_broadcasts_and_persists_funding_tx(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.FUNDING.value,
        pj={"submarine_lockup_address": "bcrt1qlockup"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "funded"
    pj = sess.pipeline_json
    assert pj["submarine_funding_tx_hex"] == "deadbeef"
    assert pj["submarine_funding_txid"] == "ab" * 32
    assert "submarine_funding_broadcast_at_ts" in pj


@pytest.mark.asyncio
async def test_funding_errors_when_lockup_address_missing(db_session) -> None:
    sess = _session(status=AnonymizeStatus.FUNDING.value, pj={})
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "missing_lockup_address" in out.detail


@pytest.mark.asyncio
async def test_funding_noop_when_already_funded(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.FUNDING.value,
        pj={
            "submarine_lockup_address": "bcrt1qlockup",
            "submarine_funding_tx_hex": "already-funded",
        },
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "noop"


@pytest.mark.asyncio
async def test_funding_started_without_completed_does_not_refund(db_session) -> None:
    """If a funding attempt was durably started but never completed (the
    process died in the broadcast window), the step must NOT build and
    broadcast a second funding tx — that would double-spend wallet
    UTXOs. It routes to reconciliation instead."""
    from app.services.anonymize.hop_idempotency import record_hop_attempt_started
    from app.services.anonymize.hops.submarine import _key_for

    sess = _session(
        status=AnonymizeStatus.FUNDING.value,
        pj={"submarine_lockup_address": "bcrt1qlockup"},
    )
    db_session.add(sess)
    await db_session.flush()

    # Simulate the durably-committed started marker with no completed.
    key = _key_for(sess, "submarine_fund_lockup", attempt=1)
    await record_hop_attempt_started(db_session, key=key, detail={"step": "fund_lockup"})
    await db_session.flush()

    deps = _mock_deps()
    out = await execute_submarine_hop_step(db_session, sess, deps)

    assert out.kind == "error"
    assert out.detail == "submarine_funding_in_doubt"
    deps.build_and_broadcast_funding_tx.assert_not_called()
    assert sess.status == AnonymizeStatus.AWAITING_RECONCILIATION.value


@pytest.mark.asyncio
async def test_funding_returns_error_on_broadcast_failure(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.FUNDING.value,
        pj={"submarine_lockup_address": "bcrt1qlockup"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(funding_returns=(None, "insufficient_funds"))
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "funding_failed" in out.detail


# ── FUNDING — pre-lockup inbound re-check ────────────────────────────


@pytest.mark.asyncio
async def test_funding_aborts_to_reconciliation_when_inbound_insufficient(
    db_session,
) -> None:
    """When the pre-lockup re-check refuses, the hop routes the session
    to AWAITING_RECONCILIATION (reason ``inbound_insufficient_at_lockup``)
    and NEVER broadcasts the on-chain funding tx — no funds move."""
    from app.services.anonymize.service import reset_anonymize_service

    reset_anonymize_service()
    sess = _session(
        status=AnonymizeStatus.FUNDING.value,
        pj={"submarine_lockup_address": "bcrt1qlockup"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(check_inbound_returns="inbound_insufficient total=10")
    out = await execute_submarine_hop_step(db_session, sess, deps)

    assert out.kind == "error"
    assert out.detail == "inbound_insufficient_at_lockup"
    # All four AR columns populated by the shared helper.
    assert sess.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
    assert sess.awaiting_reconciliation_reason == "inbound_insufficient_at_lockup"
    assert sess.pre_reconciliation_status == AnonymizeStatus.FUNDING.value
    # CRITICAL: the lockup funding tx was NOT broadcast — no funds moved.
    deps.build_and_broadcast_funding_tx.assert_not_called()
    assert "submarine_funding_tx_hex" not in (sess.pipeline_json or {})
    # A diagnostic event is emitted (write-site contract parity with the
    # reverse hop's mpp_k_floor_exhausted path).
    from sqlalchemy import select

    from app.models.anonymize_session import AnonymizeSessionEvent

    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == sess.id,
                    AnonymizeSessionEvent.kind == "inbound_insufficient_at_lockup",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    assert events[0].detail_json.get("receive_sats") == 250_000


@pytest.mark.asyncio
async def test_funding_proceeds_when_inbound_recheck_passes(db_session) -> None:
    """A passing re-check (None) lets the lockup broadcast proceed."""
    sess = _session(
        status=AnonymizeStatus.FUNDING.value,
        pj={"submarine_lockup_address": "bcrt1qlockup"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(check_inbound_returns=None)
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "funded"
    deps.check_inbound_sufficient.assert_awaited_once()
    deps.build_and_broadcast_funding_tx.assert_awaited_once()
    assert sess.pipeline_json["submarine_funding_tx_hex"] == "deadbeef"


@pytest.mark.asyncio
async def test_funding_skips_recheck_when_dep_unwired(db_session) -> None:
    """Back-compat: when the re-check dep is None the step proceeds
    exactly as before (best-effort — never blocks)."""
    sess = _session(
        status=AnonymizeStatus.FUNDING.value,
        pj={"submarine_lockup_address": "bcrt1qlockup"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()  # check_inbound_sufficient stays None
    assert deps.check_inbound_sufficient is None
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "funded"


# ── LN_HOLDING — observe settlement / refund ────────────────────────


@pytest.mark.asyncio
async def test_ln_holding_observes_settlement_when_claimed(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.LN_HOLDING.value,
        pj={"submarine_swap_id": "sub-123"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(
        status_returns=("transaction.claimed", {"any": "data"}, None),
    )
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "observed_settlement"
    assert out.detail == "transaction.claimed"


@pytest.mark.asyncio
async def test_ln_holding_routes_to_refund_when_expired(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.LN_HOLDING.value,
        pj={"submarine_swap_id": "sub-zz"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(
        status_returns=("swap.expired", {}, None),
    )
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "refund_broadcast"


@pytest.mark.asyncio
async def test_ln_holding_noop_during_in_flight_status(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.LN_HOLDING.value,
        pj={"submarine_swap_id": "sub-123"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(
        status_returns=("transaction.mempool", {}, None),
    )
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
    assert "awaiting_settlement" in out.detail


@pytest.mark.asyncio
async def test_refund_path_records_chain_broadcast_outcome(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.LN_HOLDING.value,
        pj={"submarine_swap_id": "sub-zz"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(
        status_returns=("invoice.failedToPay", {}, None),
        refund_returns=("refund-tx-hex", None),
        broadcast_returns=("refund-txid", None),
    )
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "refund_broadcast"
    assert "sub-zz" in out.detail


@pytest.mark.asyncio
async def test_refund_returns_error_when_subprocess_fails(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.LN_HOLDING.value,
        pj={"submarine_swap_id": "sub-zz"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(
        status_returns=("swap.expired", {}, None),
        refund_returns=(None, "subprocess_timeout"),
    )
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "refund_subprocess" in out.detail


@pytest.mark.asyncio
async def test_refund_subprocess_failure_does_not_persist_completion(
    db_session,
) -> None:
    """crash-consistency — when the refund subprocess fails,
    the hop returns an error WITHOUT marking the refund as
    completed, so the next tick can resume + retry."""
    from sqlalchemy import select

    from app.models.anonymize_session import AnonymizeSessionEvent

    sess = _session(
        status=AnonymizeStatus.LN_HOLDING.value,
        pj={"submarine_swap_id": "sub-crash"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(
        status_returns=("swap.expired", {}, None),
        refund_returns=(None, "subprocess_killed_oom"),
    )
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "refund_subprocess" in out.detail
    # No ``hop_attempt_completed`` for the refund key — only the
    # started marker. The next tick reruns the subprocess.
    completed = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == sess.id,
                    AnonymizeSessionEvent.kind == "hop_attempt_completed",
                )
            )
        )
        .scalars()
        .all()
    )
    assert completed == []


@pytest.mark.asyncio
async def test_refund_broadcast_failure_keeps_session_for_retry(
    db_session,
) -> None:
    """Refund subprocess returns hex, but the chain broadcast fails.
    The hop must return an error so the per-session loop retries on
    the next tick rather than silently marking the refund as done."""
    sess = _session(
        status=AnonymizeStatus.LN_HOLDING.value,
        pj={"submarine_swap_id": "sub-bc-fail"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(
        status_returns=("swap.expired", {}, None),
        refund_returns=("refund-tx-hex", None),
        broadcast_returns=(None, "chain backend down"),
    )
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "refund_broadcast" in out.detail


@pytest.mark.asyncio
async def test_settlement_status_persists_to_pipeline_json(db_session) -> None:
    """Settlement poll must persist the latest server status
    into ``pipeline_json`` so the on-chain observation collector can
    drive the dispatcher's LN_HOLDING → DELAYING transition."""
    sess = _session(
        status=AnonymizeStatus.LN_HOLDING.value,
        pj={"submarine_swap_id": "sub-state-write"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(
        status_returns=("transaction.claimed", {}, None),
    )
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "observed_settlement"
    assert sess.pipeline_json["submarine_swap_status"] == "transaction.claimed"


@pytest.mark.asyncio
async def test_unhandled_status_returns_noop(db_session) -> None:
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps()
    out = await execute_submarine_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
