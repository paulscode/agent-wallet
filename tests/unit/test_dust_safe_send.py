# SPDX-License-Identifier: MIT
"""Tests for the dust-prevention design.

Tests the shared dust-safe-send module. The module is feature-
agnostic, so the tests exercise it in isolation — Braiins-Deposit
wiring is covered separately in the integration suite.

Key invariants pinned here:

* The build path produces a single-input single-output tx; the
  destination receives ``utxo_value - fee`` (no wallet-side change).
* When the UTXO can't cover the projected fee, the helper raises
  :class:`InfeasibleSendError` BEFORE touching LND, so the caller
  can route into AWAITING_FEE_REDUCTION without burning a tx.
* The dry-run projection (``project_no_change_send``) returns the
  same arithmetic as the broadcast path so wizard-time projections
  match what the broadcast actually does.
* Economic-dust threshold scales with fee rate (NOT the static 546
  sats); a regression that hard-codes the threshold would silently
  reintroduce the field-observed failure mode.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.dust_safe_send import (
    InfeasibleSendError,
    NoChangeSendResult,
    build_and_broadcast_no_change_send,
    economic_dust_threshold_sats,
    project_no_change_send,
)

# ── Dry-run projection ────────────────────────────────────────────


def test_project_no_change_send_returns_arrival_minus_fee() -> None:
    """A 100,000-sat UTXO at 10 sat/vB (140 vbytes default) → fee
    1,400 sats → arrival 98,600 sats."""
    result = project_no_change_send(
        source_value_sats=100_000,
        sat_per_vbyte=10,
    )
    assert result is not None
    assert result.estimated_fee == 140 * 10
    assert result.arrived_at_destination == 100_000 - (140 * 10)


def test_project_no_change_send_respects_estimated_vbytes() -> None:
    """An explicit ``estimated_vbytes`` overrides the default 140.
    Pinned because callers projecting a different script-type input
    must be able to model their exact tx shape."""
    result = project_no_change_send(
        source_value_sats=100_000,
        sat_per_vbyte=10,
        estimated_vbytes=200,
    )
    assert result is not None
    assert result.estimated_fee == 200 * 10


def test_project_no_change_send_returns_none_when_infeasible() -> None:
    """The dust-safe projection returns ``None`` (NOT raises) for
    infeasible cases — projecting is supposed to be a cheap dry-run
    that the wizard can call repeatedly. The exception path is
    reserved for the broadcast step."""
    # 1,000-sat UTXO at 60 sat/vB → fee 8,400 sats → can't broadcast.
    assert (
        project_no_change_send(
            source_value_sats=1_000,
            sat_per_vbyte=60,
        )
        is None
    )
    # Zero value.
    assert (
        project_no_change_send(
            source_value_sats=0,
            sat_per_vbyte=10,
        )
        is None
    )
    # Zero/negative fee rate.
    assert (
        project_no_change_send(
            source_value_sats=100_000,
            sat_per_vbyte=0,
        )
        is None
    )


# ── Economic dust threshold ───────────────────────────────────────


def test_economic_dust_threshold_scales_with_fee_rate() -> None:
    """Central insight: dust threshold = current_fee_rate
    × spend_vbytes. At 60 sat/vB a 110-vbyte spend costs 6,600 sats
    — anything below is economic dust. Hard-coding 546 sats would
    silently reintroduce the field failure."""
    # P2TR spend default 110 vbytes.
    assert economic_dust_threshold_sats(1) == 110
    assert economic_dust_threshold_sats(60) == 6_600
    assert economic_dust_threshold_sats(100) == 11_000


def test_economic_dust_threshold_respects_spend_vbytes() -> None:
    """A larger input script type (P2WPKH ~140 vbytes) shifts the
    threshold up. The caller passes ``spend_vbytes`` when projecting
    against a specific input type."""
    assert economic_dust_threshold_sats(50, spend_vbytes=200) == 10_000


def test_economic_dust_threshold_clamps_to_positive_rate() -> None:
    """Zero or negative ``sat_per_vbyte`` is nonsensical; the helper
    clamps to 1 so the returned threshold is at least the network's
    minrelay floor. Pinned because callers can pass a stale 0 from
    a missed mempool fetch."""
    assert economic_dust_threshold_sats(0) == 110  # clamped to 1 sat/vB
    assert economic_dust_threshold_sats(-5) == 110


# ── Broadcast path ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_build_and_broadcast_no_change_send_calls_lnd_send_all() -> None:
    """The broadcast path must call ``LND.send_coins`` with
    ``send_all=True`` + the pinned outpoint. This is the canonical
    LND idiom for "spend exactly this UTXO with no change output"."""
    lnd = MagicMock()
    lnd.send_coins = AsyncMock(return_value=({"txid": "abc123"}, None))

    result = await build_and_broadcast_no_change_send(
        lnd=lnd,
        source_txid="deadbeef" * 8,
        source_vout=0,
        source_value_sats=100_000,
        destination_address="bc1qexample",
        sat_per_vbyte=10,
        label="test-send",
    )

    lnd.send_coins.assert_awaited_once()
    args, kwargs = lnd.send_coins.await_args
    assert kwargs["send_all"] is True, (
        "dust-safe send must use send_all=True so LND spends the entire UTXO with no change output."
    )
    assert kwargs["amount_sats"] is None, "send_all requires amount_sats=None per LND's API contract."
    assert kwargs["outpoints"] == [
        {"txid_str": "deadbeef" * 8, "output_index": 0},
    ], "outpoint must be pinned so LND can't pick a different UTXO."
    assert kwargs["sat_per_vbyte"] == 10
    assert isinstance(result, NoChangeSendResult)
    assert result.txid == "abc123"
    assert result.arrived_at_destination == 100_000 - (140 * 10)


@pytest.mark.asyncio
async def test_build_and_broadcast_raises_infeasible_before_touching_lnd() -> None:
    """An infeasible projection must raise BEFORE calling LND. The
    caller routes into AWAITING_FEE_REDUCTION; we don't burn a tx
    attempt that we already know will fail."""
    lnd = MagicMock()
    lnd.send_coins = AsyncMock()  # should never be called

    with pytest.raises(InfeasibleSendError) as exc_info:
        await build_and_broadcast_no_change_send(
            lnd=lnd,
            source_txid="aa" * 32,
            source_vout=0,
            source_value_sats=1_000,  # tiny
            destination_address="bc1qexample",
            sat_per_vbyte=60,  # high fee
        )
    lnd.send_coins.assert_not_awaited()
    # The exception carries the precise numbers so the caller can
    # log them without re-computing.
    err = exc_info.value
    assert err.utxo_value == 1_000
    assert err.projected_fee == 140 * 60
    assert err.sat_per_vbyte == 60


@pytest.mark.asyncio
async def test_build_and_broadcast_raises_when_lnd_returns_error() -> None:
    """LND-side error (mempool full, malformed address, etc.)
    surfaces as a plain RuntimeError. The Braiins service wrapper
    re-classifies; the helper itself stays generic."""
    lnd = MagicMock()
    lnd.send_coins = AsyncMock(return_value=(None, "mempool full"))

    with pytest.raises(RuntimeError) as exc_info:
        await build_and_broadcast_no_change_send(
            lnd=lnd,
            source_txid="aa" * 32,
            source_vout=0,
            source_value_sats=100_000,
            destination_address="bc1qexample",
            sat_per_vbyte=10,
        )
    assert "mempool full" in str(exc_info.value)


@pytest.mark.asyncio
async def test_broadcast_arrived_amount_matches_projection() -> None:
    """The broadcast helper's reported arrival matches what the
    dry-run projection would have computed for the same inputs.
    Pinned because UI code uses the projection at wizard time and
    the broadcast result at session-detail time; a mismatch would
    confuse the operator."""
    lnd = MagicMock()
    lnd.send_coins = AsyncMock(return_value=({"txid": "tx"}, None))

    projected = project_no_change_send(
        source_value_sats=250_000,
        sat_per_vbyte=25,
    )
    actual = await build_and_broadcast_no_change_send(
        lnd=lnd,
        source_txid="bb" * 32,
        source_vout=1,
        source_value_sats=250_000,
        destination_address="bc1qexample",
        sat_per_vbyte=25,
    )
    assert projected is not None
    assert actual.arrived_at_destination == projected.arrived_at_destination
    assert actual.estimated_fee == projected.estimated_fee


@pytest.mark.asyncio
async def test_invalid_args_rejected() -> None:
    """Defensive args validation: zero / negative values raise
    ValueError, never reach LND."""
    lnd = MagicMock()
    lnd.send_coins = AsyncMock()

    with pytest.raises(ValueError):
        await build_and_broadcast_no_change_send(
            lnd=lnd,
            source_txid="aa" * 32,
            source_vout=0,
            source_value_sats=0,
            destination_address="bc1q",
            sat_per_vbyte=10,
        )
    with pytest.raises(ValueError):
        await build_and_broadcast_no_change_send(
            lnd=lnd,
            source_txid="aa" * 32,
            source_vout=0,
            source_value_sats=100_000,
            destination_address="bc1q",
            sat_per_vbyte=0,
        )
    lnd.send_coins.assert_not_awaited()
