# SPDX-License-Identifier: MIT
"""Liquid hop skeleton.

The Liquid hop walks an LN balance through a Boltz LN→L-BTC chain
swap, a randomized dwell on the CT-blinded Liquid balance, and a
final Boltz L-BTC→LN chain swap back to LN.

This module verifies the step machine, dispatch by status, and the
opt-in gate. The actual Boltz chain-swap HTTP calls are injected via
``LiquidHopDeps`` so the hop body runs without a live Boltz/Liquid.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.hops.liquid import (
    LiquidHopDeps,
    execute_liquid_hop_step,
    is_liquid_hop_enabled,
    sample_liquid_dwell_s,
)


@pytest.fixture(autouse=True)
def _enable_liquid_hop(monkeypatch):
    """Liquid round-trip default-on for the test body; the gate test
    flips it off explicitly."""
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)


def _session(*, status: str, pj: dict | None = None) -> AnonymizeSession:
    # Provide a deterministic per-session Liquid blinding-seed index
    # (Fernet-wrapped) so the leg-1 initiate step doesn't trip the
    # "missing blinding_seed_enc" guard. Tests that exercise the
    # decryption path explicitly may overwrite this on the returned
    # row.
    from app.services.anonymize.liquid_seed import (
        encrypt_session_blinding_seed_index,
    )

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
        liquid_blinding_seed_enc=encrypt_session_blinding_seed_index(42),
    )


def _mock_deps(
    *,
    ln_to_lbtc_returns=None,
    pay_returns=None,
    observe_credit_returns=None,
    claim_returns=None,
    observe_wallet_credit_returns=None,
    lbtc_to_ln_returns=None,
    lock_returns=None,
    observe_settled_returns=None,
) -> LiquidHopDeps:
    return LiquidHopDeps(
        swap_state={},
        boltz_create_ln_to_lbtc_swap=AsyncMock(
            return_value=ln_to_lbtc_returns
            or (
                {"swap_id": "ln2lbtc-1", "invoice": "lnbc1...", "lbtc_address": "lq1..."},
                None,
            ),
        ),
        lnd_send_payment=AsyncMock(
            return_value=pay_returns or ({"status": "succeeded"}, None),
        ),
        liquid_observe_credit=AsyncMock(
            return_value=observe_credit_returns or ("lbtc:abcd:0", None),
        ),
        liquid_claim_lockup=AsyncMock(
            return_value=claim_returns or ("claim-tx-1", None),
        ),
        liquid_observe_wallet_credit=AsyncMock(
            return_value=observe_wallet_credit_returns or (True, None),
        ),
        boltz_create_lbtc_to_ln_swap=AsyncMock(
            return_value=lbtc_to_ln_returns
            or (
                {"swap_id": "lbtc2ln-1"},
                None,
            ),
        ),
        liquid_lock_for_submarine=AsyncMock(
            return_value=lock_returns or ("lock-tx-1", None),
        ),
        lnd_observe_invoice_settled=AsyncMock(
            return_value=observe_settled_returns or (True, None),
        ),
    )


# ── opt-in gate ─────────────────────────────────────────────────────


def test_is_liquid_hop_enabled_reads_setting(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    assert is_liquid_hop_enabled() is True
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", False)
    assert is_liquid_hop_enabled() is False


@pytest.mark.asyncio
async def test_disabled_hop_returns_noop(db_session, monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", False)
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    out = await execute_liquid_hop_step(db_session, sess, _mock_deps())
    assert out.kind == "noop"
    assert "liquid_hop_disabled" in out.detail


# ── sample_liquid_dwell_s ───────────────────────────────────────────


def test_sample_dwell_within_band(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_min_dwell_s", 3 * 3600)
    monkeypatch.setattr(settings, "anonymize_liquid_max_dwell_s", 24 * 3600)
    for _ in range(50):
        d = sample_liquid_dwell_s()
        assert 3 * 3600 <= d <= 24 * 3600


def test_sample_dwell_handles_inverted_range(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_min_dwell_s", 7200)
    monkeypatch.setattr(settings, "anonymize_liquid_max_dwell_s", 1000)
    assert sample_liquid_dwell_s() == 7200


# ── HOPPING — leg 1: LN→L-BTC ───────────────────────────────────────


@pytest.mark.asyncio
async def test_hopping_initiates_ln_to_lbtc_swap(db_session) -> None:
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    out = await execute_liquid_hop_step(db_session, sess, _mock_deps())
    assert out.kind == "ln_to_lbtc_initiated"
    assert sess.pipeline_json["liquid_ln_to_lbtc_swap_id"] == "ln2lbtc-1"


@pytest.mark.asyncio
async def test_ln_to_lbtc_error_on_create_failure(db_session) -> None:
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(ln_to_lbtc_returns=(None, "operator_outage"))
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "ln_to_lbtc_create_failed" in out.detail


@pytest.mark.asyncio
async def test_ln_to_lbtc_error_on_missing_invoice(db_session) -> None:
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(ln_to_lbtc_returns=({"swap_id": "x"}, None))
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "missing_invoice" in out.detail


@pytest.mark.asyncio
async def test_ln_to_lbtc_error_on_pay_failure(db_session) -> None:
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(pay_returns=(None, "no_route"))
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "ln_to_lbtc_pay_failed" in out.detail


# ── HOPPING — observe credit + schedule dwell ───────────────────────


@pytest.mark.asyncio
async def test_hopping_observes_lbtc_credit(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.HOPPING.value,
        pj={"liquid_ln_to_lbtc_swap_id": "ln2lbtc-1"},
    )
    db_session.add(sess)
    await db_session.flush()
    out = await execute_liquid_hop_step(db_session, sess, _mock_deps())
    assert out.kind == "lbtc_credited"
    assert sess.pipeline_json["liquid_lbtc_utxo"] == "lbtc:abcd:0"


@pytest.mark.asyncio
async def test_observe_credit_awaits_when_pending(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.HOPPING.value,
        pj={"liquid_ln_to_lbtc_swap_id": "ln2lbtc-1"},
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(observe_credit_returns=(None, None))
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
    assert "awaiting_lbtc_credit" in out.detail


@pytest.mark.asyncio
async def test_hopping_claims_lockup_after_credit(db_session) -> None:
    """After observing Boltz's lockup, the next step must broadcast
    the cooperative MuSig2 claim TX moving funds to the wallet's CT
    address."""
    sess = _session(
        status=AnonymizeStatus.HOPPING.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
        },
    )
    db_session.add(sess)
    await db_session.flush()
    out = await execute_liquid_hop_step(db_session, sess, _mock_deps())
    assert out.kind == "lbtc_claimed"
    assert sess.pipeline_json["liquid_lbtc_claim_txid"] == "claim-tx-1"


@pytest.mark.asyncio
async def test_hopping_observes_claim_confirmation_after_claim(db_session) -> None:
    """After broadcasting the claim, wait for it to confirm."""
    sess = _session(
        status=AnonymizeStatus.HOPPING.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
            "liquid_lbtc_claim_txid": "claim-tx-1",
        },
    )
    db_session.add(sess)
    await db_session.flush()
    out = await execute_liquid_hop_step(db_session, sess, _mock_deps())
    assert out.kind == "lbtc_claim_confirmed"
    assert sess.pipeline_json["liquid_lbtc_claim_confirmed"] is True


@pytest.mark.asyncio
async def test_hopping_awaits_claim_confirmation_when_pending(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.HOPPING.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
            "liquid_lbtc_claim_txid": "claim-tx-1",
        },
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(observe_wallet_credit_returns=(False, None))
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
    assert "awaiting_claim_confirmation" in out.detail


@pytest.mark.asyncio
async def test_hopping_schedules_dwell_after_claim_confirmation(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.HOPPING.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
            "liquid_lbtc_claim_txid": "claim-tx-1",
            "liquid_lbtc_claim_confirmed": True,
        },
    )
    db_session.add(sess)
    await db_session.flush()
    out = await execute_liquid_hop_step(db_session, sess, _mock_deps())
    assert out.kind == "dwell_scheduled"
    assert "liquid_dwell_until_unix_s" in sess.pipeline_json
    assert sess.pipeline_json["liquid_dwell_until_unix_s"] > (datetime.now(timezone.utc).timestamp())


# ── AWAITING_LIQUID_DWELL — leg 2: L-BTC→LN ─────────────────────────


@pytest.mark.asyncio
async def test_dwell_status_awaits_when_too_early(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.AWAITING_LIQUID_DWELL.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
            "liquid_dwell_until_unix_s": (datetime.now(timezone.utc).timestamp() + 3600),
        },
    )
    db_session.add(sess)
    await db_session.flush()
    out = await execute_liquid_hop_step(db_session, sess, _mock_deps())
    assert out.kind == "noop"
    assert "awaiting_liquid_dwell" in out.detail


@pytest.mark.asyncio
async def test_dwell_fires_lbtc_to_ln_after_elapsed(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.AWAITING_LIQUID_DWELL.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
            "liquid_dwell_until_unix_s": 0,  # in the past
        },
    )
    db_session.add(sess)
    await db_session.flush()
    out = await execute_liquid_hop_step(db_session, sess, _mock_deps())
    assert out.kind == "lbtc_to_ln_initiated"
    assert sess.pipeline_json["liquid_lbtc_to_ln_swap_id"] == "lbtc2ln-1"


@pytest.mark.asyncio
async def test_lbtc_to_ln_error_on_create_failure(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.AWAITING_LIQUID_DWELL.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
            "liquid_dwell_until_unix_s": 0,
        },
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(lbtc_to_ln_returns=(None, "operator_outage"))
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "lbtc_to_ln_create_failed" in out.detail


@pytest.mark.asyncio
async def test_dwell_locks_lbtc_after_submarine_created(db_session) -> None:
    """After the submarine swap is created, the wallet must broadcast
    the L-BTC spend funding Boltz's lockup address."""
    sess = _session(
        status=AnonymizeStatus.AWAITING_LIQUID_DWELL.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
            "liquid_dwell_until_unix_s": 0,
            "liquid_lbtc_to_ln_swap_id": "lbtc2ln-1",
        },
    )
    db_session.add(sess)
    await db_session.flush()
    out = await execute_liquid_hop_step(db_session, sess, _mock_deps())
    assert out.kind == "lbtc_locked_for_submarine"
    assert sess.pipeline_json["liquid_submarine_lock_txid"] == "lock-tx-1"


@pytest.mark.asyncio
async def test_dwell_observes_settlement_after_lock(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.AWAITING_LIQUID_DWELL.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
            "liquid_dwell_until_unix_s": 0,
            "liquid_lbtc_to_ln_swap_id": "lbtc2ln-1",
            "liquid_submarine_lock_txid": "lock-tx-1",
        },
    )
    db_session.add(sess)
    await db_session.flush()
    out = await execute_liquid_hop_step(db_session, sess, _mock_deps())
    assert out.kind == "completed"
    assert "liquid_completed_at_ts" in sess.pipeline_json


@pytest.mark.asyncio
async def test_settlement_clears_persisted_swap_state(db_session) -> None:
    """Retention hygiene: after the round-trip settles, the encrypted
    swap_state blob + in-memory cache entries for this session are
    cleared so wallet secrets don't sit in the DB indefinitely.
    """
    sess = _session(
        status=AnonymizeStatus.AWAITING_LIQUID_DWELL.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
            "liquid_dwell_until_unix_s": 0,
            "liquid_lbtc_to_ln_swap_id": "lbtc2ln-1",
            "liquid_submarine_lock_txid": "lock-tx-1",
            # Simulate a prior persist of leg-1 secrets.
            "liquid_swap_state_enc": "stale-ciphertext-blob",
        },
    )
    db_session.add(sess)
    await db_session.flush()

    deps = _mock_deps()
    # Seed in-memory swap_state for this session + a different one.
    other_sid = "0" * 32
    deps.swap_state["ln2lbtc-1"] = {"session_id": str(sess.id), "leg": "ln_to_lbtc"}
    deps.swap_state["unrelated"] = {"session_id": other_sid, "leg": "ln_to_lbtc"}

    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "completed"
    # The blob is gone from pipeline_json.
    assert "liquid_swap_state_enc" not in sess.pipeline_json
    # The session's in-memory entries are gone too.
    assert "ln2lbtc-1" not in deps.swap_state
    # Other sessions' entries are untouched.
    assert "unrelated" in deps.swap_state


@pytest.mark.asyncio
async def test_dwell_settlement_awaits_when_unsettled(db_session) -> None:
    sess = _session(
        status=AnonymizeStatus.AWAITING_LIQUID_DWELL.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
            "liquid_dwell_until_unix_s": 0,
            "liquid_lbtc_to_ln_swap_id": "lbtc2ln-1",
            "liquid_submarine_lock_txid": "lock-tx-1",
        },
    )
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(observe_settled_returns=(False, None))
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "noop"
    assert "awaiting_lbtc_to_ln_settlement" in out.detail


# ── unhandled status ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unhandled_status_returns_noop(db_session) -> None:
    sess = _session(status=AnonymizeStatus.EXITING.value)
    db_session.add(sess)
    await db_session.flush()
    out = await execute_liquid_hop_step(db_session, sess, _mock_deps())
    assert out.kind == "noop"


# ── Transient pay-invoice errors must NOT burn the session ──────────
#
# Same bug class as the 2026-05-21 Braiins Deposit incident (see
# ``app/tasks/boltz_tasks.py`` patch). LND's ``send_payment_v2``
# returns ``Payment failed: …`` for definitive terminal failures and
# other prefixes (``Connection failed:`` / ``Request failed:`` /
# ``LND error (5xx):`` / ``Payment did not reach a terminal state``)
# when the HTTP stream drops while the HTLC may still be in-flight at
# Boltz. Additionally LND returns 409 ``payment is in transition``
# from a retry attempt while a prior call's HTLC is pending. The hop
# must NOT surface a hard ``error`` outcome for any of those — that
# would burn the session-level retry budget on a connection blip and
# eventually wedge the session in AWAITING_RECONCILIATION even though
# Boltz still has the swap live.


@pytest.mark.parametrize(
    "transient_err",
    [
        "Connection failed: ProxyError: General SOCKS server failure",
        "Connection failed: ReadTimeout",
        "Request failed: socket.timeout",
        "Payment did not reach a terminal state",
        "LND error (502): bad gateway",
        "LND error (504): gateway timeout",
        "payment is in transition",
        "rpc error: code = AlreadyExists desc = payment is in transition",
    ],
)
@pytest.mark.asyncio
async def test_transient_pay_error_returns_noop(db_session, transient_err) -> None:
    """A transient error from lnd_send_payment must surface as a
    ``noop`` outcome so the per-session loop retries on the next
    tick without consuming the retry budget. The HTLC may still be
    in-flight at Boltz; the next tick's send_payment will see
    ``in transition`` (or settle/fail naturally) and the hop will
    proceed."""
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(pay_returns=(None, transient_err))
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "noop", (
        f"transient pay error {transient_err!r} must return noop, "
        f"not {out.kind!r} (would otherwise burn session retry "
        f"budget on a connection blip — 2026-05-21 regression guard)"
    )
    assert "in_flight" in out.detail.lower(), (
        "noop detail should signal the in-flight HTLC so downstream "
        "diagnostics can distinguish this from a routine wait"
    )


@pytest.mark.parametrize(
    "definitive_err",
    [
        "Payment failed: FAILURE_REASON_NO_ROUTE",
        "Payment failed: FAILURE_REASON_INSUFFICIENT_BALANCE",
        "Payment failed: FAILURE_REASON_INCORRECT_PAYMENT_DETAILS",
    ],
)
@pytest.mark.asyncio
async def test_definitive_pay_failure_returns_error(db_session, definitive_err) -> None:
    """``Payment failed: …`` is the only prefix that means LND saw a
    terminal FAILED for the payment. The hop must surface ``error``
    so the session-level loop can route to reconciliation."""
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps(pay_returns=(None, definitive_err))
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "error"
    assert "ln_to_lbtc_pay_failed" in out.detail


# ── Per-leg operator-id attribution ─────────────────────────────────


def _mock_deps_with_operators(
    *,
    ln_to_lbtc_operator_id=None,
    lbtc_to_ln_operator_id=None,
    **kw,
) -> LiquidHopDeps:
    deps = _mock_deps(**kw)
    # Re-create with the operator-id fields populated. ``replace``
    # would also work but the dataclass has many fields; mutating
    # the bound attributes is simpler and the test owns the object.
    object.__setattr__(deps, "ln_to_lbtc_operator_id", ln_to_lbtc_operator_id)
    object.__setattr__(deps, "lbtc_to_ln_operator_id", lbtc_to_ln_operator_id)
    return deps


@pytest.mark.asyncio
async def test_ln_to_lbtc_stamp_records_reverse_operator_id(
    db_session,
) -> None:
    """Leg-1 initiate stamps ``liquid_reverse_operator_id`` on the
    session at the same moment ``pipeline_json["liquid_ln_to_lbtc_swap_id"]``
    is recorded. Recovery code reads the column to attribute the
    reverse leg to a specific operator without re-deriving the
    in-process ``LiquidLegSelection``."""
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps_with_operators(
        ln_to_lbtc_operator_id="boltz-canonical",
        lbtc_to_ln_operator_id="middleway",
    )
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "ln_to_lbtc_initiated"
    assert sess.liquid_reverse_operator_id == "boltz-canonical"
    # Leg-2 hasn't run yet — its column must still be NULL.
    assert sess.liquid_submarine_operator_id is None


@pytest.mark.asyncio
async def test_lbtc_to_ln_stamp_records_submarine_operator_id(
    db_session,
) -> None:
    """Leg-2 initiate stamps ``liquid_submarine_operator_id`` at the
    same moment ``pipeline_json["liquid_lbtc_to_ln_swap_id"]`` is
    recorded."""
    sess = _session(
        status=AnonymizeStatus.AWAITING_LIQUID_DWELL.value,
        pj={
            "liquid_ln_to_lbtc_swap_id": "ln2lbtc-1",
            "liquid_lbtc_utxo": "lbtc:abcd:0",
            "liquid_dwell_until_unix_s": 0,
        },
    )
    # Pre-stamp the reverse op id as the production hop would have
    # done during leg 1 (this test starts at leg 2).
    sess.liquid_reverse_operator_id = "boltz-canonical"
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps_with_operators(
        ln_to_lbtc_operator_id="boltz-canonical",
        lbtc_to_ln_operator_id="middleway",
    )
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "lbtc_to_ln_initiated"
    assert sess.liquid_submarine_operator_id == "middleway"
    # Leg-1 column must remain untouched.
    assert sess.liquid_reverse_operator_id == "boltz-canonical"


@pytest.mark.asyncio
async def test_operator_stamp_is_noop_when_deps_unknown(
    db_session,
) -> None:
    """Env-pin-only deployments (no signed registry) may legitimately
    have ``None`` operator ids in the deps. The hop must NOT write
    ``NULL`` over a pre-existing attribution and must not raise."""
    sess = _session(status=AnonymizeStatus.HOPPING.value)
    sess.liquid_reverse_operator_id = "pre-existing-attribution"
    db_session.add(sess)
    await db_session.flush()
    deps = _mock_deps_with_operators(
        ln_to_lbtc_operator_id=None,
        lbtc_to_ln_operator_id=None,
    )
    out = await execute_liquid_hop_step(db_session, sess, deps)
    assert out.kind == "ln_to_lbtc_initiated"
    # Pre-existing attribution preserved; new None is ignored.
    assert sess.liquid_reverse_operator_id == "pre-existing-attribution"
