# SPDX-License-Identifier: MIT
"""Reverse-swap hop body."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)
from app.services.anonymize.hops.reverse import (
    ReverseHopDeps,
    execute_reverse_hop_step,
)


@pytest.fixture(autouse=True)
def _zero_jitter(monkeypatch):
    """Disable broadcast jitter (default 3600s) so tests don't hang."""
    monkeypatch.setattr(settings, "anonymize_claim_broadcast_jitter_s", 0)


@pytest.fixture(autouse=True)
def _economy_feerate_in_band(monkeypatch):
    """Default the economy-feerate probe to a value in-band with the
    mock swap's quoted ``claimFeeRate`` so the cooperative-claim feerate
    gate passes by default. Tests exercising outlier / probe-failure
    behavior set their own ``get_anonymize_economy_feerate`` mock, which
    overrides this."""
    from app.services.anonymize import chain_egress

    async def _live_economy(**_):
        return 5.0, None

    monkeypatch.setattr(chain_egress, "get_anonymize_economy_feerate", _live_economy)


# Conformant minimal claim TX hex used in tests:
# version=2, 1 input with nSequence=0xfffffffd, 1 output, locktime=0.
_VALID_CLAIM_TX_HEX = (
    "02000000"  # nVersion=2 LE
    "01"  # input count
    + "00" * 32  # prev_hash (32 bytes)
    + "00000000"  # prev_index
    + "00"  # script_sig length (segwit empty)
    + "fdffffff"  # nSequence=0xfffffffd
    + "01"  # output count
    + "0000000000000000"  # output value (8 bytes)
    + "00"  # script length
    + "00000000"  # nLockTime
)


def _session(*, status: str = AnonymizeStatus.EXITING.value, pj=None) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json=pj
        or {
            "exit": {"destination_address": "bcrt1qtest"},
            "reverse_payment_chunks_k_requested": 3,
        },
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )


def _mock_swap(*, boltz_swap_id="swap-123", invoice="lnbcrt1invoice"):
    swap = MagicMock()
    swap.boltz_swap_id = boltz_swap_id
    # Production code reads ``boltz_invoice`` (the real BoltzSwap model
    # column name). ``invoice`` is mirrored only for legacy compat with
    # tests that still reference the old name.
    swap.boltz_invoice = invoice
    swap.invoice = invoice
    return swap


def _mock_deps(
    *,
    create_returns=None,
    status_returns=None,
    pay_returns=None,
    claim_returns=None,
    broadcast_returns=None,
):
    return ReverseHopDeps(
        boltz_create_reverse_swap=AsyncMock(
            return_value=create_returns or (_mock_swap(), None),
        ),
        boltz_get_swap_status=AsyncMock(
            return_value=status_returns
            or ("transaction.mempool", {"transaction": {"hex": "deadbeef"}, "claimFeeRate": 5.0}, None),
        ),
        lnd_send_payment=AsyncMock(
            return_value=pay_returns or ({"max_parts": 3}, None),
        ),
        run_claim_subprocess=AsyncMock(
            return_value=claim_returns or (_VALID_CLAIM_TX_HEX, None),
        ),
        chain_broadcast_tx=AsyncMock(
            return_value=broadcast_returns or ("txid-abc", None),
        ),
    )


# ── Status dispatch ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_step_noop_for_non_exit_status(db_session) -> None:
    """Sessions outside EXITING/CONFIRMING return noop."""
    s = _session(status=AnonymizeStatus.CREATED.value)
    deps = _mock_deps()
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "noop"


@pytest.mark.asyncio
async def test_step_confirming_returns_noop_waiting_for_chain_poll(
    db_session,
) -> None:
    s = _session(status=AnonymizeStatus.CONFIRMING.value)
    deps = _mock_deps()
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "noop"
    assert "chain_poll" in out.detail


# ── EXITING: issue reverse swap ──────────────────────────────────────


@pytest.mark.asyncio
async def test_exiting_first_tick_issues_swap_and_persists_id(db_session) -> None:
    s = _session()
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps()

    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "issued_swap"
    assert out.detail == "swap-123"
    # The pipeline_json carries the swap id + invoice.
    assert s.pipeline_json["reverse_swap_id"] == "swap-123"
    assert s.pipeline_json["reverse_swap_invoice"] == "lnbcrt1invoice"


@pytest.mark.asyncio
async def test_exiting_writes_hop_attempt_events_around_swap_issue(
    db_session,
) -> None:
    """Hop_attempt_started + completed bracket the swap creation."""
    s = _session()
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps()
    await execute_reverse_hop_step(db_session, s, deps)
    await db_session.commit()

    rows = (
        (await db_session.execute(select(AnonymizeSessionEvent).where(AnonymizeSessionEvent.session_id == s.id)))
        .scalars()
        .all()
    )
    kinds = sorted([r.kind for r in rows])
    assert "hop_attempt_started" in kinds
    assert "hop_attempt_completed" in kinds


@pytest.mark.asyncio
async def test_exiting_second_tick_is_idempotent(db_session) -> None:
    """Re-running after issuance is a no-op (idempotency)."""
    s = _session()
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps()
    await execute_reverse_hop_step(db_session, s, deps)
    await db_session.commit()

    deps.boltz_create_reverse_swap.reset_mock()
    out = await execute_reverse_hop_step(db_session, s, deps)
    # No second swap creation call.
    deps.boltz_create_reverse_swap.assert_not_awaited()
    # The step proceeds to poll+claim (since swap is already issued).
    assert out.kind in {"noop", "issued_swap", "claim_broadcast", "error"}


@pytest.mark.asyncio
async def test_exiting_swap_creation_error_surfaces(db_session) -> None:
    s = _session()
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(create_returns=(None, "boltz_5xx"))
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "error"
    assert "create_swap_failed" in out.detail


# ── EXITING: pay + claim + crash-consistency ───────────────────


@pytest.mark.asyncio
async def test_exiting_after_issue_pays_invoice_with_mpp_k(db_session) -> None:
    """Invoice payment uses MPP K read via resolve_mpp_k."""
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-xyz",
        "reverse_swap_invoice": "lnbcrt1xyz",
        "reverse_payment_chunks_k_requested": 4,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps()
    await execute_reverse_hop_step(db_session, s, deps)
    # The pay_invoice mock was called with max_parts=4.
    pay_kwargs = deps.lnd_send_payment.await_args.kwargs
    assert pay_kwargs["max_parts"] == 4
    assert pay_kwargs["payment_request"] == "lnbcrt1xyz"


@pytest.mark.asyncio
async def test_exiting_claim_persists_hex_before_broadcast(db_session) -> None:
    """Claim_tx_hex + claim_broadcast_at_ts are written BEFORE
    the broadcast call so a crash mid-broadcast leaves a recoverable
    crumb."""
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 1,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(
        claim_returns=(_VALID_CLAIM_TX_HEX, None),
    )
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "claim_broadcast"
    assert s.claim_tx_hex == _VALID_CLAIM_TX_HEX
    assert s.claim_broadcast_at_ts is not None


@pytest.mark.asyncio
async def test_exiting_broadcast_via_boltz_default_skips_chain_client(
    db_session,
    monkeypatch,
) -> None:
    """Default broadcast-via-Boltz; chain_broadcast_tx is not called."""
    monkeypatch.setattr(settings, "anonymize_broadcast_via", "boltz")
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 1,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps()
    await execute_reverse_hop_step(db_session, s, deps)
    deps.chain_broadcast_tx.assert_not_awaited()


@pytest.mark.asyncio
async def test_exiting_self_broadcast_when_configured(
    db_session,
    monkeypatch,
) -> None:
    """When broadcast_via=self, the chain client is called."""
    monkeypatch.setattr(settings, "anonymize_broadcast_via", "self")
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 1,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps()
    await execute_reverse_hop_step(db_session, s, deps)
    deps.chain_broadcast_tx.assert_awaited_once()


# ── EXITING: lockup not yet observed ─────────────────────────────────


@pytest.mark.asyncio
async def test_exiting_awaits_lockup_when_swap_pending(db_session) -> None:
    """A swap whose status is `swap.created` returns awaiting_lockup."""
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-pending",
        "reverse_swap_invoice": "lnbcrt1pending",
        "reverse_payment_chunks_k_requested": 1,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(
        status_returns=("swap.created", None, None),
    )
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "noop"
    assert "awaiting_lockup" in out.detail


# ── EXITING: error surfacing ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_exiting_lnd_pay_failure_surfaces(db_session) -> None:
    """Pay failure routes to K-decrement or floor-exhausted."""
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 1,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(
        pay_returns=(None, "no_route"),
    )
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "error"
    # K=1 with strict-mode fallback aborts immediately (floor=1; one
    # decrement would go to 0 which is below floor).
    assert "mpp_k_floor_exhausted" in out.detail


@pytest.mark.asyncio
async def test_exiting_lnd_pay_failure_decrements_k_when_room(
    db_session,
) -> None:
    """Pay failure with room to decrement K bumps the
    decrement counter and surfaces a retry signal."""
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 3,
        "reverse_payment_chunks_k_last_attempted": 3,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(
        pay_returns=(None, "transient_failure"),
    )
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "error"
    assert "will_retry_at_k_2" in out.detail
    # The K-decrement counter is persisted for the next tick.
    assert s.pipeline_json.get("reverse_payment_chunks_k_decrements_used") == 1
    assert s.pipeline_json.get("reverse_payment_chunks_k_last_attempted") == 2


# ── Transient pay-invoice errors must noop, not K-decrement ─────────
#
# The reverse hop's original transient check only matched the literal
# substring ``"in transition"`` (LND's 409 on a retry against an
# already-in-flight payment_hash). That left every other stream-drop
# prefix from ``send_payment_v2`` — ``Connection failed:``,
# ``Request failed:``, ``LND error (5xx):``, ``Payment did not reach
# a terminal state`` — falling through to the K-decrement
# machinery, which (in strict mode) burns through the K-floor in two
# ticks and routes the session to ``AWAITING_RECONCILIATION`` with
# ``mpp_k_floor_exhausted`` even when the original HTLC is alive at
# the destination. This was the same bug class as the 2026-05-21
# Braiins Deposit incident. The fix broadens the transient check to
# the same set ``send_payment_v2`` surfaces.


@pytest.mark.parametrize(
    "transient_err",
    [
        "payment is in transition",
        "rpc error: code = AlreadyExists desc = payment is in transition",
        "Connection failed: ProxyError: General SOCKS server failure",
        "Connection failed: ReadTimeout",
        "Request failed: socket.timeout",
        "Payment did not reach a terminal state",
        "LND error (502): bad gateway",
        "LND error (504): gateway timeout",
    ],
)
@pytest.mark.asyncio
async def test_exiting_pay_transient_error_returns_noop_no_k_decrement(db_session, transient_err) -> None:
    """A transient pay error must surface as ``noop``/``ln_payment_in_flight``
    without touching the K-fallback counter or the bounded-retry
    counter. The HTLC may still be in-flight at Boltz; the next tick
    re-polls."""
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 3,
        "reverse_payment_chunks_k_last_attempted": 3,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(pay_returns=(None, transient_err))
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "noop", (
        f"transient pay error {transient_err!r} must return noop (in-flight HTLC), not {out.kind!r}"
    )
    assert out.detail == "ln_payment_in_flight"
    # The K-fallback counter must NOT have advanced — that's the
    # whole point: transient errors don't consume the budget.
    assert s.pipeline_json.get("reverse_payment_chunks_k_decrements_used", 0) == 0
    assert s.pipeline_json.get("reverse_payment_chunks_k_last_attempted", 3) == 3


@pytest.mark.asyncio
async def test_exiting_pay_definitive_failure_still_triggers_k_decrement(
    db_session,
) -> None:
    """``Payment failed: …`` is the only LND-terminal prefix. The
    existing K-fallback machinery must still kick in for it."""
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 3,
        "reverse_payment_chunks_k_last_attempted": 3,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(
        pay_returns=(None, "Payment failed: FAILURE_REASON_NO_ROUTE"),
    )
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "error"
    assert "will_retry_at_k_2" in out.detail
    assert s.pipeline_json.get("reverse_payment_chunks_k_decrements_used") == 1


@pytest.mark.asyncio
async def test_exiting_envelope_policy_violation_refuses_broadcast(
    db_session,
) -> None:
    """A claim hex that violates the envelope policy
    (e.g., nVersion=1) hard-fails before the broadcast."""
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 1,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    # Same minimal tx but with nVersion=1 (envelope violation).
    bad_hex = "01000000" + _VALID_CLAIM_TX_HEX[8:]
    deps = _mock_deps(claim_returns=(bad_hex, None))
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "error"
    assert "envelope_policy_violation" in out.detail


@pytest.mark.asyncio
async def test_diversity_check_admits_when_circuits_distinct(
    db_session,
    monkeypatch,
) -> None:
    """On-chain pipeline reverse hop calls the diversity
    probe before issuing the swap; distinct exit fingerprints
    admit the call."""
    from app.services.anonymize.hops import reverse as reverse_mod
    from app.services.anonymize.tor import CircuitExitInfo

    async def _stub_probe(**_):
        return [
            CircuitExitInfo(
                circuit_id="1",
                exit_fingerprint="aa" * 20,
                exit_ip="1.2.3.4",
                asn="AS1",
            ),
            CircuitExitInfo(
                circuit_id="2",
                exit_fingerprint="bb" * 20,
                exit_ip="5.6.7.8",
                asn="AS2",
            ),
        ], None

    monkeypatch.setattr(
        "app.services.anonymize.tor.probe_tor_circuit_status",
        _stub_probe,
    )
    err = await reverse_mod._check_exit_relay_diversity(
        _session(pj={"exit": {"destination_address": "bcrt1qtest"}}),
    )
    assert err is None


@pytest.mark.asyncio
async def test_diversity_check_refuses_when_circuits_share_exit(
    db_session,
    monkeypatch,
) -> None:
    """Two BUILT circuits with the same exit-fingerprint
    diversity key refuse the reverse hop."""
    from app.services.anonymize.hops import reverse as reverse_mod
    from app.services.anonymize.tor import CircuitExitInfo

    shared_fp = "cc" * 20

    async def _stub_probe(**_):
        return [
            CircuitExitInfo(
                circuit_id="1",
                exit_fingerprint=shared_fp,
                exit_ip="1.2.3.4",
                asn="AS1",
            ),
            CircuitExitInfo(
                circuit_id="2",
                exit_fingerprint=shared_fp,
                exit_ip="1.2.3.4",
                asn="AS1",
            ),
        ], None

    monkeypatch.setattr(
        "app.services.anonymize.tor.probe_tor_circuit_status",
        _stub_probe,
    )
    err = await reverse_mod._check_exit_relay_diversity(
        _session(pj={"exit": {"destination_address": "bcrt1qtest"}}),
    )
    assert err is not None
    assert "exit-relay" in err or "share" in err


@pytest.mark.asyncio
async def test_diversity_check_fails_open_when_probe_unreachable(
    db_session,
    monkeypatch,
) -> None:
    """Unreachable Tor control port returns None (no error).
    The listener-pair isolation is the first-layer defense."""
    from app.services.anonymize.hops import reverse as reverse_mod

    async def _stub_unreachable(**_):
        return [], "tor control connect failed"

    monkeypatch.setattr(
        "app.services.anonymize.tor.probe_tor_circuit_status",
        _stub_unreachable,
    )
    err = await reverse_mod._check_exit_relay_diversity(
        _session(pj={"exit": {"destination_address": "bcrt1qtest"}}),
    )
    assert err is None


@pytest.mark.asyncio
async def test_diversity_check_skipped_when_single_circuit(
    db_session,
    monkeypatch,
) -> None:
    """Single circuit ⇒ no pair to compare ⇒ check passes."""
    from app.services.anonymize.hops import reverse as reverse_mod
    from app.services.anonymize.tor import CircuitExitInfo

    async def _stub_one_circuit(**_):
        return [
            CircuitExitInfo(
                circuit_id="1",
                exit_fingerprint="aa" * 20,
                exit_ip="1.2.3.4",
            ),
        ], None

    monkeypatch.setattr(
        "app.services.anonymize.tor.probe_tor_circuit_status",
        _stub_one_circuit,
    )
    err = await reverse_mod._check_exit_relay_diversity(
        _session(pj={"exit": {"destination_address": "bcrt1qtest"}}),
    )
    assert err is None


@pytest.mark.asyncio
async def test_k_floor_exhaustion_writes_event_and_reason(db_session) -> None:
    """+ recovery — when the K-floor exhausts, the
    hop body:

    * records the documented event kind
    * sets ``awaiting_reconciliation_reason`` so the classifier
      can route the row through Class B recovery
    * routes through ``transition_to_awaiting_reconciliation`` so all
      four columns are populated atomically (status → AR,
      pre_reconciliation_status snapshots EXITING)

    This locks the write-site contract for the reverse hop.
    """
    from sqlalchemy import select

    from app.models.anonymize_session import AnonymizeSessionEvent
    from app.services.anonymize.service import reset_anonymize_service

    reset_anonymize_service()
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-floor",
        "reverse_swap_invoice": "lnbcrt1floor",
        "reverse_payment_chunks_k_requested": 1,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(pay_returns=(None, "no_route"))
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "error"
    assert out.detail == "mpp_k_floor_exhausted"

    # contract: all four AR columns populated by the helper.
    assert s.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
    assert s.awaiting_reconciliation_reason == "mpp_k_floor_exhausted"
    assert s.pre_reconciliation_status == AnonymizeStatus.EXITING.value
    # Attempts and last_ts start at the DB default (0 / NULL)
    # on the first AR entry. The probe bumps them on its tick.
    assert s.reconciliation_attempts == 0
    assert s.last_reconciliation_attempt_ts is None

    # K-floor event recorded with the documented detail payload.
    events = (
        (
            await db_session.execute(
                select(AnonymizeSessionEvent).where(
                    AnonymizeSessionEvent.session_id == s.id,
                    AnonymizeSessionEvent.kind == "mpp_k_floor_exhausted",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1
    detail = events[0].detail_json
    assert detail["requested_k"] == 1
    assert detail["last_attempted_k"] == 1
    reset_anonymize_service()


@pytest.mark.asyncio
async def test_missing_claim_feerate_fails_closed(db_session) -> None:
    """An operator that omits claimFeeRate cannot bypass the feerate gate;
    the hop fails closed and routes through reconciliation."""
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 1,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(
        # No claimFeeRate in the status payload.
        status_returns=("transaction.mempool", {"transaction": {"hex": "deadbeef"}}, None),
    )
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "error"
    assert out.detail == "claim_feerate_missing"


@pytest.mark.asyncio
async def test_feerate_outlier_refuses_claim(db_session, monkeypatch) -> None:
    """Operator-quoted feerate well outside the band of the
    live economy estimate refuses the cooperative claim."""
    from app.services.anonymize import chain_egress

    async def _live_economy(**_):
        return 5.0, None  # mempool economy at 5 sat/vB

    monkeypatch.setattr(
        chain_egress,
        "get_anonymize_economy_feerate",
        _live_economy,
    )

    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 1,
    }
    s = _session(pj=pj)
    # The outlier must be attributed to the swap's real operator, not "default".
    s.reverse_operator_id = "op-real"
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(
        # Operator claims 50 sat/vB — 10x the economy estimate.
        status_returns=("transaction.mempool", {"transaction": {"hex": "deadbeef"}, "claimFeeRate": 50.0}, None),
    )

    # The feerate outlier must feed the per-operator degrade counter.
    from app.services.anonymize.hops import reverse as _reverse_mod

    recorded: list[tuple[str, str]] = []

    async def _capture(*, operator_id: str, reason: str) -> None:
        recorded.append((operator_id, reason))

    monkeypatch.setattr(_reverse_mod, "_record_reverse_operator_outlier", _capture)

    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "error"
    assert "feerate_outlier" in out.detail
    assert len(recorded) == 1
    assert recorded[0][0] == "op-real"  # attributed to the real operator
    assert "feerate_outlier" in recorded[0][1]


@pytest.mark.asyncio
async def test_feerate_probe_unavailable_refuses_claim(
    db_session,
    monkeypatch,
) -> None:
    """Two consecutive probe failures fail closed."""
    from app.services.anonymize import chain_egress

    async def _always_fail(**_):
        return None, "chain backend unreachable"

    monkeypatch.setattr(
        chain_egress,
        "get_anonymize_economy_feerate",
        _always_fail,
    )
    monkeypatch.setattr(
        "app.core.config.settings.anonymize_claim_feerate_probe_retry_delay_s",
        0,
    )

    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 1,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(
        status_returns=("transaction.mempool", {"transaction": {"hex": "deadbeef"}, "claimFeeRate": 8.0}, None),
    )
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "error"
    assert "claim_feerate_probe_unavailable" in out.detail


@pytest.mark.asyncio
async def test_exiting_claim_subprocess_failure_surfaces(db_session) -> None:
    pj = {
        "exit": {"destination_address": "bcrt1qtest"},
        "reverse_swap_id": "swap-zz",
        "reverse_swap_invoice": "lnbcrt1zz",
        "reverse_payment_chunks_k_requested": 1,
    }
    s = _session(pj=pj)
    db_session.add(s)
    await db_session.flush()
    deps = _mock_deps(
        claim_returns=(None, "musig_timeout"),
    )
    out = await execute_reverse_hop_step(db_session, s, deps)
    assert out.kind == "error"
    assert "claim_subprocess" in out.detail
