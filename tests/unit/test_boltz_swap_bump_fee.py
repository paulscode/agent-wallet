# SPDX-License-Identifier: MIT
"""Tests for the BTC RBF/CPFP fee-bump path.

Covers:

* Classifier extension: ``mempool_age_seconds`` kwarg →
  ``fee_bump_recommended`` metadata + ``ACTION_BUMP_FEE`` action on
  ``AWAITING_CONFIRMATIONS`` rows.
* ``LNDService.bump_fee()`` wrapper input validation + REST body
  shape.
* ``POST /cold-storage/swaps/{id}/bump-fee`` endpoint guard rails
  (no claim_txid → 400; LND error → 502; happy path → audit + result).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from app.models.boltz_swap import BoltzSwap, BoltzSwapDirection, SwapStatus
from app.services.boltz_recovery import (
    ACTION_BUMP_FEE,
    FEE_BUMP_STALL_SECONDS,
    STATE_AWAITING_CONFIRMATIONS,
    classify_recovery_state,
)


def _make_swap_claimed(
    *,
    claim_txid: str = "ee" * 32,
) -> BoltzSwap:
    now = datetime.now(timezone.utc)
    return BoltzSwap(
        id=uuid4(),
        api_key_id=uuid4(),
        boltz_swap_id="rec-swap",
        direction=BoltzSwapDirection.REVERSE,
        status=SwapStatus.CLAIMED,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
        timeout_block_height=850_000,
        claim_txid=claim_txid,
        created_at=now,
        updated_at=now,
    )


# ── Classifier extension ─────────────────────────────────────────────


class TestClassifierMempoolAge:
    def test_no_age_no_bump_recommendation(self):
        hint = classify_recovery_state(_make_swap_claimed())
        assert hint.state == STATE_AWAITING_CONFIRMATIONS
        assert "fee_bump_recommended" not in hint.metadata
        assert ACTION_BUMP_FEE not in hint.actions

    def test_under_stall_threshold_no_bump(self):
        hint = classify_recovery_state(
            _make_swap_claimed(),
            mempool_age_seconds=FEE_BUMP_STALL_SECONDS - 60,
        )
        assert "fee_bump_recommended" not in hint.metadata
        assert ACTION_BUMP_FEE not in hint.actions

    def test_over_stall_threshold_recommends_bump(self):
        hint = classify_recovery_state(
            _make_swap_claimed(),
            mempool_age_seconds=FEE_BUMP_STALL_SECONDS + 60,
        )
        assert hint.metadata.get("fee_bump_recommended") is True
        assert ACTION_BUMP_FEE in hint.actions
        assert hint.metadata["mempool_age_seconds"] >= FEE_BUMP_STALL_SECONDS

    def test_confirmed_tx_suppresses_recommendation(self):
        """Once claim_confirmations >= 1 the bump no longer makes sense."""
        hint = classify_recovery_state(
            _make_swap_claimed(),
            claim_confirmations=1,
            mempool_age_seconds=FEE_BUMP_STALL_SECONDS + 600,
        )
        assert "fee_bump_recommended" not in hint.metadata
        assert ACTION_BUMP_FEE not in hint.actions


# ── LNDService.bump_fee wrapper ──────────────────────────────────────


class TestLndBumpFeeWrapper:
    @pytest.mark.asyncio
    async def test_requires_txid(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        result, err = await svc.bump_fee("", 0, sat_per_vbyte=5)
        assert result is None and err

    @pytest.mark.asyncio
    async def test_requires_one_of_rate_or_target(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        result, err = await svc.bump_fee("aa" * 32, 0)
        assert result is None and "required" in err

    @pytest.mark.asyncio
    async def test_rejects_both_rate_and_target(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        result, err = await svc.bump_fee(
            "aa" * 32,
            0,
            sat_per_vbyte=5,
            target_conf=6,
        )
        assert result is None and "mutually exclusive" in err

    @pytest.mark.asyncio
    async def test_happy_path_builds_correct_body(self):
        from app.services.lnd_service import LNDService

        svc = LNDService()
        captured: dict[str, Any] = {}

        async def _fake_request(method, path, **kwargs):
            captured["method"] = method
            captured["path"] = path
            captured["body"] = kwargs.get("json")
            return {}, None

        with patch.object(svc, "_request", _fake_request):
            result, err = await svc.bump_fee(
                "aa" * 32,
                1,
                sat_per_vbyte=12,
            )
        assert err is None
        assert result == {}
        assert captured["method"] == "POST"
        assert captured["path"] == "/v2/wallet/bumpfee"
        assert captured["body"]["outpoint"] == {
            "txid_str": "aa" * 32,
            "output_index": 1,
        }
        assert captured["body"]["sat_per_vbyte"] == "12"
        assert "target_conf" not in captured["body"]


# ── Bump-fee endpoint ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bump_fee_endpoint_rejects_swap_without_claim_txid(
    db_session,
    test_admin_key,
):
    from fastapi import HTTPException

    from app.api.cold_storage import bump_fee_endpoint

    api_key, _ = test_admin_key
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=api_key.id,
        boltz_swap_id="no-claim",
        direction=BoltzSwapDirection.REVERSE,
        status=SwapStatus.CLAIMING,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
        claim_txid=None,
    )
    db_session.add(swap)
    await db_session.commit()

    request = type("R", (), {"client": None})()
    with pytest.raises(HTTPException) as exc:
        await bump_fee_endpoint(
            swap_id=str(swap.id),
            request=request,
            sat_per_vbyte=10,
            api_key=api_key,
            db=db_session,
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_bump_fee_endpoint_happy_path(db_session, test_admin_key):
    from app.api.cold_storage import bump_fee_endpoint

    api_key, _ = test_admin_key
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=api_key.id,
        boltz_swap_id="happy",
        direction=BoltzSwapDirection.REVERSE,
        status=SwapStatus.CLAIMED,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
        claim_txid="fa" * 32,
    )
    db_session.add(swap)
    await db_session.commit()

    request = type("R", (), {"client": None})()
    with patch(
        "app.services.lnd_service.lnd_service.bump_fee",
        new=AsyncMock(return_value=({"replacement_txid": "fb" * 32}, None)),
    ) as bump:
        payload = await bump_fee_endpoint(
            swap_id=str(swap.id),
            request=request,
            sat_per_vbyte=15,
            api_key=api_key,
            db=db_session,
        )
    bump.assert_awaited_once()
    args, kwargs = bump.call_args
    assert kwargs["txid_str"] == "fa" * 32
    assert kwargs["sat_per_vbyte"] == 15
    assert payload["sat_per_vbyte"] == 15
    assert payload["txid"] == "fa" * 32
    assert payload["target"] == "claim"


@pytest.mark.asyncio
async def test_bump_fee_endpoint_502_on_lnd_error(
    db_session,
    test_admin_key,
):
    from fastapi import HTTPException

    from app.api.cold_storage import bump_fee_endpoint

    api_key, _ = test_admin_key
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=api_key.id,
        boltz_swap_id="lnd-err",
        direction=BoltzSwapDirection.REVERSE,
        status=SwapStatus.CLAIMED,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
        claim_txid="fc" * 32,
    )
    db_session.add(swap)
    await db_session.commit()

    request = type("R", (), {"client": None})()
    with patch(
        "app.services.lnd_service.lnd_service.bump_fee",
        new=AsyncMock(return_value=(None, "bumpfee: input not found")),
    ):
        with pytest.raises(HTTPException) as exc:
            await bump_fee_endpoint(
                swap_id=str(swap.id),
                request=request,
                sat_per_vbyte=20,
                api_key=api_key,
                db=db_session,
            )
    assert exc.value.status_code == 502


@pytest.mark.asyncio
async def test_bump_fee_endpoint_charges_spend_window(
    db_session,
    test_admin_key,
):
    """Each bump charges its bounded miner-fee budget against the
    cumulative spend window / velocity limiter, so a key that has
    exhausted its budget is refused with 429 before LND is called."""
    from fastapi import HTTPException

    from app.api.cold_storage import bump_fee_endpoint

    api_key, _ = test_admin_key
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=api_key.id,
        boltz_swap_id="cap",
        direction=BoltzSwapDirection.REVERSE,
        status=SwapStatus.CLAIMED,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
        claim_txid="fd" * 32,
    )
    db_session.add(swap)
    await db_session.commit()

    request = type("R", (), {"client": None})()
    with (
        patch(
            "app.api.cold_storage.check_payment_limits",
            new=AsyncMock(return_value=(False, "velocity limit exceeded", None)),
        ),
        patch("app.services.lnd_service.lnd_service.bump_fee", new=AsyncMock()) as bump,
    ):
        with pytest.raises(HTTPException) as exc:
            await bump_fee_endpoint(
                swap_id=str(swap.id),
                request=request,
                sat_per_vbyte=20,
                api_key=api_key,
                db=db_session,
            )
    assert exc.value.status_code == 429
    bump.assert_not_awaited()


# ── claim_broadcast_at auto-stamp event listener ─────────────────────


@pytest.mark.asyncio
async def test_claim_broadcast_at_auto_stamped_on_first_txid_assign(
    db_session,
    test_admin_key,
):
    api_key, _ = test_admin_key
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=api_key.id,
        boltz_swap_id="stamp",
        direction=BoltzSwapDirection.REVERSE,
        status=SwapStatus.CLAIMING,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
    )
    db_session.add(swap)
    await db_session.commit()
    assert swap.claim_broadcast_at is None

    swap.claim_txid = "fe" * 32
    await db_session.commit()
    assert swap.claim_broadcast_at is not None

    earlier = swap.claim_broadcast_at
    # Setting the same value again must NOT re-stamp.
    swap.claim_txid = "fe" * 32
    await db_session.commit()
    assert swap.claim_broadcast_at == earlier


# ── Submarine RBF surface (lockup_txid + lockup target) ──────────────


def _make_swap_submarine_created(
    *,
    lockup_txid: str = "ab" * 32,
) -> BoltzSwap:
    now = datetime.now(timezone.utc)
    return BoltzSwap(
        id=uuid4(),
        api_key_id=uuid4(),
        boltz_swap_id="sub-swap",
        direction=BoltzSwapDirection.REVERSE,  # default; submarine
        # rows share the enum
        status=SwapStatus.CREATED,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
        timeout_block_height=850_000,
        lockup_txid=lockup_txid,
        created_at=now,
        updated_at=now,
    )


class TestClassifierLockupMempoolAge:
    def test_no_lockup_age_no_bump(self):
        hint = classify_recovery_state(_make_swap_submarine_created())
        assert "fee_bump_recommended" not in hint.metadata
        assert ACTION_BUMP_FEE not in hint.actions

    def test_under_lockup_stall_threshold_no_bump(self):
        hint = classify_recovery_state(
            _make_swap_submarine_created(),
            lockup_mempool_age_seconds=FEE_BUMP_STALL_SECONDS - 60,
        )
        assert "fee_bump_recommended" not in hint.metadata
        assert ACTION_BUMP_FEE not in hint.actions

    def test_over_lockup_stall_threshold_recommends_bump(self):
        hint = classify_recovery_state(
            _make_swap_submarine_created(),
            lockup_mempool_age_seconds=FEE_BUMP_STALL_SECONDS + 60,
        )
        assert hint.metadata.get("fee_bump_recommended") is True
        assert ACTION_BUMP_FEE in hint.actions
        assert hint.metadata["lockup_txid"] == "ab" * 32
        assert hint.metadata["lockup_mempool_age_seconds"] >= FEE_BUMP_STALL_SECONDS

    def test_lockup_confirmed_suppresses_bump(self):
        hint = classify_recovery_state(
            _make_swap_submarine_created(),
            lockup_mempool_age_seconds=FEE_BUMP_STALL_SECONDS + 600,
            lockup_confirmations=1,
        )
        assert "fee_bump_recommended" not in hint.metadata
        assert ACTION_BUMP_FEE not in hint.actions

    def test_lockup_bump_not_applied_to_terminal_states(self):
        """A REFUNDED swap must not surface a bump-fee suggestion."""
        swap = _make_swap_submarine_created()
        swap.status = SwapStatus.REFUNDED
        hint = classify_recovery_state(
            swap,
            lockup_mempool_age_seconds=FEE_BUMP_STALL_SECONDS + 600,
        )
        assert "fee_bump_recommended" not in hint.metadata
        assert ACTION_BUMP_FEE not in hint.actions

    def test_no_lockup_txid_no_bump_even_if_age_set(self):
        """Without a stamped lockup_txid the bump can't target anything."""
        swap = _make_swap_submarine_created(lockup_txid="")
        swap.lockup_txid = None  # belt and braces — bypass the listener
        hint = classify_recovery_state(
            swap,
            lockup_mempool_age_seconds=FEE_BUMP_STALL_SECONDS + 600,
        )
        assert "fee_bump_recommended" not in hint.metadata
        assert ACTION_BUMP_FEE not in hint.actions


@pytest.mark.asyncio
async def test_lockup_broadcast_at_auto_stamped_on_first_txid_assign(
    db_session,
    test_admin_key,
):
    api_key, _ = test_admin_key
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=api_key.id,
        boltz_swap_id="lockup-stamp",
        direction=BoltzSwapDirection.REVERSE,
        status=SwapStatus.CREATED,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
    )
    db_session.add(swap)
    await db_session.commit()
    assert swap.lockup_broadcast_at is None

    swap.lockup_txid = "cd" * 32
    await db_session.commit()
    assert swap.lockup_broadcast_at is not None

    earlier = swap.lockup_broadcast_at
    # Idempotent on re-assign with the same value.
    swap.lockup_txid = "cd" * 32
    await db_session.commit()
    assert swap.lockup_broadcast_at == earlier


@pytest.mark.asyncio
async def test_bump_fee_endpoint_lockup_target_happy_path(
    db_session,
    test_admin_key,
):
    from app.api.cold_storage import bump_fee_endpoint

    api_key, _ = test_admin_key
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=api_key.id,
        boltz_swap_id="sub-happy",
        direction=BoltzSwapDirection.REVERSE,
        status=SwapStatus.CREATED,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
        lockup_txid="ad" * 32,
    )
    db_session.add(swap)
    await db_session.commit()

    request = type("R", (), {"client": None})()
    with patch(
        "app.services.lnd_service.lnd_service.bump_fee",
        new=AsyncMock(return_value=({"replacement_txid": "ae" * 32}, None)),
    ) as bump:
        payload = await bump_fee_endpoint(
            swap_id=str(swap.id),
            request=request,
            sat_per_vbyte=12,
            target="lockup",
            api_key=api_key,
            db=db_session,
        )
    bump.assert_awaited_once()
    _, kwargs = bump.call_args
    assert kwargs["txid_str"] == "ad" * 32
    assert payload["target"] == "lockup"
    assert payload["txid"] == "ad" * 32


@pytest.mark.asyncio
async def test_bump_fee_endpoint_lockup_target_400_when_no_lockup_txid(
    db_session,
    test_admin_key,
):
    from fastapi import HTTPException

    from app.api.cold_storage import bump_fee_endpoint

    api_key, _ = test_admin_key
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=api_key.id,
        boltz_swap_id="sub-missing",
        direction=BoltzSwapDirection.REVERSE,
        status=SwapStatus.CREATED,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
        # no lockup_txid
    )
    db_session.add(swap)
    await db_session.commit()

    request = type("R", (), {"client": None})()
    with pytest.raises(HTTPException) as exc:
        await bump_fee_endpoint(
            swap_id=str(swap.id),
            request=request,
            sat_per_vbyte=10,
            target="lockup",
            api_key=api_key,
            db=db_session,
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_bump_fee_endpoint_rejects_invalid_target(
    db_session,
    test_admin_key,
):
    from fastapi import HTTPException

    from app.api.cold_storage import bump_fee_endpoint

    api_key, _ = test_admin_key
    swap = BoltzSwap(
        id=uuid4(),
        api_key_id=api_key.id,
        boltz_swap_id="bad-target",
        direction=BoltzSwapDirection.REVERSE,
        status=SwapStatus.CLAIMED,
        invoice_amount_sats=100_000,
        destination_address="bc1qdest",
        claim_txid="af" * 32,
    )
    db_session.add(swap)
    await db_session.commit()

    request = type("R", (), {"client": None})()
    with pytest.raises(HTTPException) as exc:
        await bump_fee_endpoint(
            swap_id=str(swap.id),
            request=request,
            sat_per_vbyte=10,
            target="bogus",
            api_key=api_key,
            db=db_session,
        )
    assert exc.value.status_code == 400
