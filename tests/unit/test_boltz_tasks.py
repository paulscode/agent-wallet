# SPDX-License-Identifier: MIT
"""
Unit tests for app.tasks.boltz_tasks — Celery task layer.

Tests the async task implementations directly (bypassing Celery),
backoff logic, the _mark_swap_failed helper, _run_async, and
the Celery task wrappers (process_boltz_swap, recover_boltz_swaps).
"""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.models.boltz_swap import SwapStatus


def _mock_db_ctx(db_session):
    """Create an async context manager mock that yields db_session."""

    @asynccontextmanager
    async def _ctx():
        yield db_session

    return _ctx


def _fake_run_async(*return_values):
    """Build a side_effect for patched ``_run_async`` that closes the
    coroutine it receives (so it isn't reported as "never awaited") and
    returns the next configured value.

    Pass one value to mimic ``return_value=X``; pass several to mimic
    ``side_effect=[X, Y, ...]``.
    """
    values = iter(return_values)

    def _se(coro):
        try:
            coro.close()
        except AttributeError:
            pass
        return next(values)

    return _se


class TestGetBackoff:
    """Tests for _get_backoff tiered calculation."""

    def test_early_retries(self):
        from app.tasks.boltz_tasks import _get_backoff

        for i in range(10):
            assert _get_backoff(i) == 15

    def test_mid_retries(self):
        from app.tasks.boltz_tasks import _get_backoff

        for i in range(10, 30):
            assert _get_backoff(i) == 60

    def test_late_retries(self):
        from app.tasks.boltz_tasks import _get_backoff

        for i in (30, 50, 100, 200):
            assert _get_backoff(i) == 300


class TestRunProcessSwap:
    """Tests for _run_process_swap async logic."""

    def _make_mock_db(self, swap=None):
        """Create a mock DB session that returns the given swap from execute()."""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = swap
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()
        return mock_db

    @pytest.mark.asyncio
    async def test_swap_not_found(self):
        """Returns error when swap ID doesn't exist."""
        from app.tasks.boltz_tasks import _run_process_swap

        mock_db = self._make_mock_db(swap=None)
        with patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)):
            result = await _run_process_swap(str(uuid4()))

        assert result["status"] == "error"
        assert "swap_not_found" in result["detail"]

    @pytest.mark.asyncio
    async def test_already_completed(self):
        """Returns immediately for terminal-state swaps."""
        from app.tasks.boltz_tasks import _run_process_swap

        swap = MagicMock()
        swap.status = SwapStatus.COMPLETED

        mock_db = self._make_mock_db(swap=swap)
        with patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)):
            result = await _run_process_swap(str(uuid4()))

        assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_already_failed(self):
        from app.tasks.boltz_tasks import _run_process_swap

        swap = MagicMock()
        swap.status = SwapStatus.FAILED

        mock_db = self._make_mock_db(swap=swap)
        with patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)):
            result = await _run_process_swap(str(uuid4()))

        assert result["status"] == "failed"

    @pytest.mark.asyncio
    async def test_pays_invoice_on_created(self):
        """CREATED swap should attempt invoice payment and advance."""
        from app.tasks.boltz_tasks import _run_process_swap

        swap = MagicMock()
        swap.status = SwapStatus.CREATED
        swap.invoice_amount_sats = 100000
        swap.boltz_invoice = "lnbcrt1..."
        swap.status_history = []
        # Un-pinned payment (no first-hop pin) → MPP should be enabled.
        swap.outgoing_chan_id = None

        mock_db = self._make_mock_db(swap=swap)

        mock_lnd = MagicMock()
        mock_lnd.send_payment_v2 = AsyncMock(return_value=({"payment_hash": "ph1"}, None))

        mock_boltz = MagicMock()
        mock_boltz.advance_swap = AsyncMock(return_value=(swap, None))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.lnd_service.LNDService", return_value=mock_lnd),
            patch("app.services.boltz_service.BoltzSwapService", return_value=mock_boltz),
        ):
            await _run_process_swap(str(uuid4()))

        mock_lnd.send_payment_v2.assert_called_once()
        # MPP must be enabled so payments can split across small channels
        # (the no_route fix). The call is keyword-only.
        _, call_kwargs = mock_lnd.send_payment_v2.call_args
        assert int(call_kwargs.get("max_parts") or 0) > 1, "Boltz swap payment must enable MPP via max_parts>1"
        # Passes the invoice by keyword + a fee-limit cap.
        assert call_kwargs.get("payment_request") == "lnbcrt1..."
        assert int(call_kwargs.get("fee_limit_sats") or 0) > 0
        # Success branch reads ``payment_hash`` from the v2 result shape —
        # locks the contract against future send_payment_v2 changes.
        assert swap.status == SwapStatus.INVOICE_PAID
        assert swap.lnd_payment_hash == "ph1"
        mock_boltz.advance_swap.assert_called_once()

    @pytest.mark.asyncio
    async def test_pins_outgoing_chan_id_when_set(self):
        """A swap carrying ``outgoing_chan_id`` (bootstrap drain / Braiins
        channel-open pinning) must forward it to send_payment_v2 AND disable
        MPP (max_parts=1) — LND drops the pin when max_parts>1."""
        from app.tasks.boltz_tasks import _run_process_swap

        swap = MagicMock()
        swap.status = SwapStatus.CREATED
        swap.invoice_amount_sats = 100000
        swap.boltz_invoice = "lnbcrt1..."
        swap.status_history = []
        swap.outgoing_chan_id = "123x456x0"

        mock_db = self._make_mock_db(swap=swap)
        mock_lnd = MagicMock()
        mock_lnd.send_payment_v2 = AsyncMock(return_value=({"payment_hash": "ph1"}, None))
        mock_boltz = MagicMock()
        mock_boltz.advance_swap = AsyncMock(return_value=(swap, None))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.lnd_service.LNDService", return_value=mock_lnd),
            patch("app.services.boltz_service.BoltzSwapService", return_value=mock_boltz),
        ):
            await _run_process_swap(str(uuid4()))

        _, call_kwargs = mock_lnd.send_payment_v2.call_args
        assert call_kwargs.get("outgoing_chan_id") == "123x456x0"
        assert int(call_kwargs.get("max_parts") or 0) == 1, "a pinned payment must disable MPP"

    @pytest.mark.asyncio
    async def test_reattempts_payment_when_paying_invoice_has_no_live_payment(self):
        """A swap stranded in PAYING_INVOICE (interrupted before the payment
        registered in LND) must re-attempt the payment when LND confirms no
        live payment exists — otherwise it hangs at "Sending over Lightning"
        forever (Boltz never sees an HTLC, so advance_swap can't progress)."""
        from app.tasks.boltz_tasks import _run_process_swap

        swap = MagicMock()
        swap.status = SwapStatus.PAYING_INVOICE
        swap.invoice_amount_sats = 100000
        swap.boltz_invoice = "lnbcrt1..."
        swap.lnd_payment_hash = "phX"
        swap.status_history = []

        mock_db = self._make_mock_db(swap=swap)
        mock_lnd = MagicMock()
        # No live payment for this invoice → safe to (re)send.
        mock_lnd.lookup_payment = AsyncMock(
            return_value=({"status": "UNKNOWN", "payment_hash": "phX"}, None)
        )
        mock_lnd.send_payment_v2 = AsyncMock(return_value=({"payment_hash": "phX"}, None))
        mock_boltz = MagicMock()
        mock_boltz.advance_swap = AsyncMock(return_value=(swap, None))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.lnd_service.LNDService", return_value=mock_lnd),
            patch("app.services.boltz_service.BoltzSwapService", return_value=mock_boltz),
        ):
            await _run_process_swap(str(uuid4()))

        mock_lnd.lookup_payment.assert_called_once_with("phX")
        mock_lnd.send_payment_v2.assert_called_once()
        assert swap.status == SwapStatus.INVOICE_PAID

    @pytest.mark.asyncio
    async def test_does_not_repay_when_payment_in_flight(self):
        """A PAYING_INVOICE swap whose LN payment is genuinely in-flight must
        NOT be re-paid — just reconciled — so we never double-pay."""
        from app.tasks.boltz_tasks import _run_process_swap

        swap = MagicMock()
        swap.status = SwapStatus.PAYING_INVOICE
        swap.invoice_amount_sats = 100000
        swap.boltz_invoice = "lnbcrt1..."
        swap.lnd_payment_hash = "phX"
        swap.status_history = []

        mock_db = self._make_mock_db(swap=swap)
        mock_lnd = MagicMock()
        mock_lnd.lookup_payment = AsyncMock(
            return_value=({"status": "IN_FLIGHT", "payment_hash": "phX"}, None)
        )
        mock_lnd.send_payment_v2 = AsyncMock(return_value=({"payment_hash": "phX"}, None))
        mock_boltz = MagicMock()
        mock_boltz.advance_swap = AsyncMock(return_value=(swap, None))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.lnd_service.LNDService", return_value=mock_lnd),
            patch("app.services.boltz_service.BoltzSwapService", return_value=mock_boltz),
        ):
            await _run_process_swap(str(uuid4()))

        mock_lnd.send_payment_v2.assert_not_called()
        assert swap.status == SwapStatus.PAYING_INVOICE
        mock_boltz.advance_swap.assert_called_once()

    @pytest.mark.asyncio
    async def test_definitive_payment_failure_marks_failed(self):
        """``Payment failed: …`` is the only LND-terminal error prefix
        from ``send_payment_v2``. Definitive failures must mark the
        swap FAILED and short-circuit advance_swap."""
        from app.tasks.boltz_tasks import _run_process_swap

        swap = MagicMock()
        swap.status = SwapStatus.CREATED
        swap.invoice_amount_sats = 100000
        swap.boltz_invoice = "lnbcrt1..."
        swap.status_history = []

        mock_db = self._make_mock_db(swap=swap)

        mock_lnd = MagicMock()
        mock_lnd.send_payment_v2 = AsyncMock(return_value=(None, "Payment failed: FAILURE_REASON_NO_ROUTE"))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.lnd_service.LNDService", return_value=mock_lnd),
            patch("app.services.boltz_service.BoltzSwapService"),
        ):
            result = await _run_process_swap(str(uuid4()))

        assert result["status"] == "failed"
        assert "FAILURE_REASON_NO_ROUTE" in result["detail"]
        # And the swap object itself was mutated to FAILED.
        assert swap.status == SwapStatus.FAILED

    @pytest.mark.asyncio
    async def test_transient_connection_failed_stays_in_paying_invoice(self):
        """``Connection failed: …`` means the HTTP stream to LND
        dropped — but the HTLC may still be in-flight at Boltz. The
        swap must stay in PAYING_INVOICE so ``recover_pending_swaps``
        can reconcile via Boltz status. Also pin: the payment_hash
        gets persisted from the BOLT11 invoice (no LND dependency)
        so the next tick can track the HTLC.

        This is the regression guard for the 2026-05-21 incident
        where 101,920 sats sat stuck in a HOLD HTLC for 30+ minutes
        because the swap was marked FAILED on a Tor flap.
        """
        from app.tasks.boltz_tasks import _run_process_swap

        # Real BOLT11 from the incident — gives us a real
        # payment_hash without needing to mock the bolt11 helper.
        real_invoice = (
            "lnbc1019200n1p4q72m5pp5zh8f3dksgym27cgxjav2fx4zgljlvtd8r95g5lfj7nke"
            "2t08y5dsdql2djkuepqw3hjqsj5gvsxzerywfjhxuccqzylxqyp2xqsp58cj6lrx0q"
            "dgd8fwf4552gmj9wrvxdwd0jd54krq0lttxlxempg8q9qxpqysgqmf3leftwxdyu77"
            "fswnuktm5z4px3esh2kxqv2j8255k32p9r5tvrznud0acqf53pwpmgdrq8vlufeydv"
            "9gnd8v27e9exze0m0gtrpyspr8j5xh"
        )
        expected_hash = "15ce98b6d04136af61069758a49aa247e5f62da719688a7d32f4ed952de7251b"

        swap = MagicMock()
        swap.status = SwapStatus.CREATED
        swap.invoice_amount_sats = 101920
        swap.boltz_invoice = real_invoice
        swap.status_history = []
        swap.lnd_payment_hash = None

        mock_db = self._make_mock_db(swap=swap)

        mock_lnd = MagicMock()
        mock_lnd.send_payment_v2 = AsyncMock(
            return_value=(None, "Connection failed: ProxyError: General SOCKS failure")
        )

        mock_boltz = MagicMock()
        # advance_swap is expected to be called (fall-through path)
        # and will poll Boltz; for this unit test we return
        # (swap, None) to mimic a no-op tick.
        mock_boltz.advance_swap = AsyncMock(return_value=(swap, None))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.lnd_service.LNDService", return_value=mock_lnd),
            patch("app.services.boltz_service.BoltzSwapService", return_value=mock_boltz),
        ):
            result = await _run_process_swap(str(uuid4()))

        # The swap must NOT be FAILED — that's the whole point.
        assert swap.status != SwapStatus.FAILED, (
            "Connection failed: must NOT mark swap FAILED — HTLC may "
            "still be in-flight at Boltz (2026-05-21 regression guard)"
        )
        # The payment_hash decoded from the invoice must be persisted
        # so the next reconciliation tick can track the in-flight HTLC.
        assert swap.lnd_payment_hash == expected_hash, (
            "payment_hash must be decoded from boltz_invoice and persisted to lnd_payment_hash"
        )
        # advance_swap MUST be called to drive reconciliation.
        mock_boltz.advance_swap.assert_called_once()
        # Result must not include the raw BoltzSwap object (would
        # crash kombu's JSON encoder — second 2026-05-21 bug).
        assert "result" not in result or "swap" not in (result.get("result") or {})

    @pytest.mark.parametrize(
        "transient_prefix",
        [
            "Connection failed: foo",
            "Request failed: foo",
            "Payment did not reach a terminal state",
            "LND error (502): bad gateway",
            "LND error (504): timeout",
        ],
    )
    @pytest.mark.asyncio
    async def test_other_transient_prefixes_also_stay_in_paying_invoice(self, transient_prefix):
        """All non-``Payment failed:`` prefixes from send_payment_v2
        could leave an HTLC in-flight. None should mark FAILED."""
        from app.tasks.boltz_tasks import _run_process_swap

        swap = MagicMock()
        swap.status = SwapStatus.CREATED
        swap.invoice_amount_sats = 100000
        swap.boltz_invoice = "lnbcrt1..."  # decoder returns None on this — that's OK
        swap.status_history = []
        swap.lnd_payment_hash = None

        mock_db = self._make_mock_db(swap=swap)
        mock_lnd = MagicMock()
        mock_lnd.send_payment_v2 = AsyncMock(return_value=(None, transient_prefix))
        mock_boltz = MagicMock()
        mock_boltz.advance_swap = AsyncMock(return_value=(swap, None))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.lnd_service.LNDService", return_value=mock_lnd),
            patch("app.services.boltz_service.BoltzSwapService", return_value=mock_boltz),
        ):
            await _run_process_swap(str(uuid4()))

        assert swap.status != SwapStatus.FAILED, f"transient error {transient_prefix!r} must not mark FAILED"
        mock_boltz.advance_swap.assert_called_once()

    @pytest.mark.asyncio
    async def test_transient_error_populates_error_message(self):
        """Transient ``send_payment_v2`` errors must populate
        ``swap.error_message`` with a user-friendly note. Before this
        change the swap stayed in PAYING_INVOICE with an empty
        ``error_message``, so the dashboard showed the status with no
        context."""
        from app.tasks.boltz_tasks import _run_process_swap

        real_invoice = (
            "lnbc1019200n1p4q72m5pp5zh8f3dksgym27cgxjav2fx4zgljlvtd8r95g5lfj7nke"
            "2t08y5dsdql2djkuepqw3hjqsj5gvsxzerywfjhxuccqzylxqyp2xqsp58cj6lrx0q"
            "dgd8fwf4552gmj9wrvxdwd0jd54krq0lttxlxempg8q9qxpqysgqmf3leftwxdyu77"
            "fswnuktm5z4px3esh2kxqv2j8255k32p9r5tvrznud0acqf53pwpmgdrq8vlufeydv"
            "9gnd8v27e9exze0m0gtrpyspr8j5xh"
        )

        swap = MagicMock()
        swap.status = SwapStatus.CREATED
        swap.invoice_amount_sats = 101920
        swap.boltz_invoice = real_invoice
        swap.status_history = []
        swap.lnd_payment_hash = None
        swap.error_message = None

        mock_db = self._make_mock_db(swap=swap)
        mock_lnd = MagicMock()
        mock_lnd.send_payment_v2 = AsyncMock(return_value=(None, "Connection failed: ProxyError"))
        mock_boltz = MagicMock()
        mock_boltz.advance_swap = AsyncMock(return_value=(swap, None))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.lnd_service.LNDService", return_value=mock_lnd),
            patch("app.services.boltz_service.BoltzSwapService", return_value=mock_boltz),
        ):
            await _run_process_swap(str(uuid4()))

        # error_message must now describe the transient nature and
        # tell the user no action is required.
        assert swap.error_message is not None
        message = swap.error_message.lower()
        assert "transient" in message
        assert "no action required" in message
        # Must include the payment_hash for diagnostics.
        assert swap.lnd_payment_hash is not None
        assert swap.lnd_payment_hash in swap.error_message

    @pytest.mark.asyncio
    async def test_advance_result_is_json_serializable(self):
        """``process_boltz_swap`` runs inside Celery, which serializes
        return values via kombu's JSON encoder. The 2026-05-21 second
        bug: the task returned ``{"result": (BoltzSwap, error)}`` and
        kombu choked on the SQLAlchemy model, crashing the worker
        after advance_swap had already broadcast the claim but before
        ``claim_txid`` got committed. The fix is to project only the
        error string into the result — pin that here."""
        import json

        from app.tasks.boltz_tasks import _run_process_swap

        swap = MagicMock()
        swap.status = SwapStatus.INVOICE_PAID
        swap.invoice_amount_sats = 100000
        swap.boltz_invoice = "lnbcrt1..."
        swap.status_history = []

        mock_db = self._make_mock_db(swap=swap)
        mock_lnd = MagicMock()
        mock_boltz = MagicMock()
        mock_boltz.advance_swap = AsyncMock(return_value=(swap, "some error string"))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.lnd_service.LNDService", return_value=mock_lnd),
            patch("app.services.boltz_service.BoltzSwapService", return_value=mock_boltz),
        ):
            result = await _run_process_swap(str(uuid4()))

        # The result dict must round-trip through json.dumps so kombu
        # can serialize it for the Celery result backend.
        try:
            json.dumps(result)
        except TypeError as e:
            pytest.fail(f"process_boltz_swap result is not JSON-serializable: {e}; result={result!r}")
        # The error from advance_swap must be projected into the result
        # (so downstream callers can act on it) — but NOT the swap object.
        assert result.get("advance_error") == "some error string"

    @pytest.mark.asyncio
    async def test_exception_caught(self):
        """Unexpected exception returns error status."""
        from app.tasks.boltz_tasks import _run_process_swap

        swap = MagicMock()
        swap.status = SwapStatus.CREATED
        swap.invoice_amount_sats = 100000
        swap.boltz_invoice = "lnbcrt1..."
        swap.status_history = []

        mock_db = self._make_mock_db(swap=swap)

        mock_lnd = MagicMock()
        mock_lnd.send_payment_v2 = AsyncMock(side_effect=RuntimeError("unexpected"))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.lnd_service.LNDService", return_value=mock_lnd),
            patch("app.services.boltz_service.BoltzSwapService"),
        ):
            result = await _run_process_swap(str(uuid4()))

        assert result["status"] == "error"
        assert "unexpected" in result["detail"]


class TestRunRecoverSwaps:
    """Tests for _run_recover_swaps."""

    @pytest.mark.asyncio
    async def test_recover_success(self):
        from app.tasks.boltz_tasks import _run_recover_swaps

        mock_db = AsyncMock()
        mock_boltz = MagicMock()
        mock_boltz.recover_pending_swaps = AsyncMock(return_value=[{"boltz_swap_id": "s1", "status": "completed"}])

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.boltz_service.BoltzSwapService", return_value=mock_boltz),
        ):
            result = await _run_recover_swaps()

        assert "recovered" in result

    @pytest.mark.asyncio
    async def test_recover_exception(self):
        from app.tasks.boltz_tasks import _run_recover_swaps

        mock_db = AsyncMock()
        mock_boltz = MagicMock()
        mock_boltz.recover_pending_swaps = AsyncMock(side_effect=RuntimeError("db error"))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.boltz_service.BoltzSwapService", return_value=mock_boltz),
        ):
            result = await _run_recover_swaps()

        assert "error" in result


class TestMarkSwapFailed:
    """Tests for _mark_swap_failed helper."""

    @pytest.mark.asyncio
    async def test_marks_created_swap_failed(self):
        from app.tasks.boltz_tasks import _mark_swap_failed

        swap = MagicMock()
        swap.status = SwapStatus.CREATED
        swap.status_history = []

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = swap
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        with patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)):
            await _mark_swap_failed(str(uuid4()), "Max retries exceeded")

        assert swap.status == SwapStatus.FAILED
        assert swap.error_message == "Max retries exceeded"
        mock_db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_skips_already_completed(self):
        from app.tasks.boltz_tasks import _mark_swap_failed

        swap = MagicMock()
        swap.status = SwapStatus.COMPLETED

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = swap
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        with patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)):
            await _mark_swap_failed(str(uuid4()), "should not change")

        assert swap.status == SwapStatus.COMPLETED
        mock_db.commit.assert_not_called()

    @pytest.mark.asyncio
    async def test_nonexistent_swap(self):
        """Does not raise for nonexistent swap."""
        from app.tasks.boltz_tasks import _mark_swap_failed

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)

        with patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)):
            await _mark_swap_failed(str(uuid4()), "no swap")  # Should not raise


class TestRunAsync:
    """Tests for _run_async event loop management."""

    def test_run_async_returns_result(self):
        from app.tasks.boltz_tasks import _run_async

        async def simple_coro():
            return {"status": "done"}

        result = _run_async(simple_coro())
        assert result == {"status": "done"}

    def test_run_async_propagates_exception(self):
        from app.tasks.boltz_tasks import _run_async

        async def failing_coro():
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            _run_async(failing_coro())

    def test_run_async_cleans_up_pending_tasks(self):
        from app.tasks.boltz_tasks import _run_async

        bg_task_cancelled = False

        async def coro_with_bg_task():
            async def background():
                nonlocal bg_task_cancelled
                try:
                    await asyncio.sleep(100)
                except asyncio.CancelledError:
                    bg_task_cancelled = True
                    raise

            asyncio.ensure_future(background())
            return "ok"

        result = _run_async(coro_with_bg_task())
        assert result == "ok"
        assert bg_task_cancelled is True


class TestProcessBoltzSwapTask:
    """Tests for the Celery process_boltz_swap task wrapper."""

    def test_returns_terminal_result(self):
        from app.tasks.boltz_tasks import process_boltz_swap

        with patch(
            "app.tasks.boltz_tasks._run_async",
            side_effect=_fake_run_async({"status": "completed"}),
        ):
            result = process_boltz_swap.run("swap-id")
            assert result["status"] == "completed"

    def test_retries_on_non_terminal(self):
        from celery.exceptions import Retry

        from app.tasks.boltz_tasks import process_boltz_swap

        with (
            patch(
                "app.tasks.boltz_tasks._run_async",
                side_effect=_fake_run_async({"status": "claiming"}),
            ),
            patch.object(process_boltz_swap, "retry", side_effect=Retry("retry")) as mock_retry,
        ):
            process_boltz_swap.request.retries = 5
            with pytest.raises(Retry):
                process_boltz_swap.run("swap-id")

        mock_retry.assert_called_once()
        assert mock_retry.call_args.kwargs["countdown"] == 15

    def test_max_retries_exceeded(self):
        from celery.exceptions import MaxRetriesExceededError

        from app.tasks.boltz_tasks import process_boltz_swap

        with (
            patch(
                "app.tasks.boltz_tasks._run_async",
                side_effect=_fake_run_async({"status": "claiming"}, None),
            ),
            patch.object(process_boltz_swap, "retry", side_effect=MaxRetriesExceededError("max retries")),
        ):
            result = process_boltz_swap.run("swap-id")

        assert result["status"] == "failed"
        assert "max_retries" in result["detail"]


class TestRecoverBoltzSwapsTask:
    """Tests for the Celery recover_boltz_swaps task wrapper."""

    def test_calls_run_async(self):
        from app.tasks.boltz_tasks import recover_boltz_swaps

        with patch(
            "app.tasks.boltz_tasks._run_async",
            side_effect=_fake_run_async({"recovered": 3}),
        ) as mock_run:
            result = recover_boltz_swaps()

        assert result == {"recovered": 3}
        mock_run.assert_called_once()


class TestRunProcessSwapInvoicePaid:
    """Tests for _run_process_swap when swap is already in INVOICE_PAID state."""

    @pytest.mark.asyncio
    async def test_invoice_paid_skips_payment(self):
        """INVOICE_PAID swap should skip payment and go directly to advance_swap."""
        from app.tasks.boltz_tasks import _run_process_swap

        swap = MagicMock()
        swap.status = SwapStatus.INVOICE_PAID
        swap.invoice_amount_sats = 100000
        swap.boltz_invoice = "lnbcrt1..."
        swap.status_history = []

        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = swap
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()

        mock_lnd = MagicMock()
        mock_boltz = MagicMock()
        mock_boltz.advance_swap = AsyncMock(return_value=(swap, None))

        with (
            patch("app.core.database.get_db_context", _mock_db_ctx(mock_db)),
            patch("app.services.lnd_service.LNDService", return_value=mock_lnd),
            patch("app.services.boltz_service.BoltzSwapService", return_value=mock_boltz),
        ):
            await _run_process_swap(str(uuid4()))

        # Should NOT have called send_payment_v2 since already paid
        mock_lnd.send_payment_v2.assert_not_called()
        mock_boltz.advance_swap.assert_called_once()


class TestRunAsyncHelper:
    """Tests for _run_async helper."""

    def test_runs_coroutine(self):
        from app.tasks.boltz_tasks import _run_async

        async def simple():
            return 42

        assert _run_async(simple()) == 42

    def test_cleans_up_loop(self):
        from app.tasks.boltz_tasks import _run_async

        async def simple():
            return "ok"

        result = _run_async(simple())
        assert result == "ok"

    def test_propagates_exception(self):
        from app.tasks.boltz_tasks import _run_async

        async def fail():
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            _run_async(fail())

    def test_cancels_pending_tasks(self):
        """Background tasks created during coroutine are cleaned up."""
        import asyncio

        from app.tasks.boltz_tasks import _run_async

        cancelled = []

        async def background():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                cancelled.append(True)

        async def main():
            asyncio.ensure_future(background())
            return "done"

        result = _run_async(main())
        assert result == "done"
        # The pending background task should have been cancelled
        assert len(cancelled) == 1


class TestCeleryTaskEntryPoints:
    """Tests for the actual Celery task functions (process_boltz_swap, recover_boltz_swaps)."""

    def test_process_boltz_swap_terminal_status(self):
        """process_boltz_swap returns immediately for terminal-state results."""
        from app.tasks.boltz_tasks import process_boltz_swap

        with patch(
            "app.tasks.boltz_tasks._run_async",
            side_effect=_fake_run_async({"status": "completed"}),
        ):
            result = process_boltz_swap("swap-123")
        assert result["status"] == "completed"

    def test_process_boltz_swap_retries_on_non_terminal(self):
        """process_boltz_swap retries when swap is not in terminal state."""
        from celery.exceptions import Retry

        from app.tasks.boltz_tasks import process_boltz_swap

        with (
            patch(
                "app.tasks.boltz_tasks._run_async",
                side_effect=_fake_run_async({"status": "claiming"}),
            ),
            patch.object(process_boltz_swap, "retry", side_effect=Retry("retry", None)) as mock_retry,
        ):
            with pytest.raises(Retry):
                process_boltz_swap("swap-123")

        mock_retry.assert_called_once()
        call_kwargs = mock_retry.call_args[1]
        assert call_kwargs["countdown"] == 15  # first tier backoff

    def test_process_boltz_swap_max_retries_exceeded(self):
        """process_boltz_swap marks swap failed on MaxRetriesExceededError."""
        from app.tasks.boltz_tasks import process_boltz_swap

        with (
            patch(
                "app.tasks.boltz_tasks._run_async",
                side_effect=_fake_run_async({"status": "claiming"}, None),
            ),
            patch.object(process_boltz_swap, "retry", side_effect=process_boltz_swap.MaxRetriesExceededError()),
        ):
            result = process_boltz_swap("swap-123")

        assert result["status"] == "failed"
        assert "max_retries_exceeded" in result["detail"]

    def test_recover_boltz_swaps(self):
        """recover_boltz_swaps delegates to _run_async(_run_recover_swaps())."""
        from app.tasks.boltz_tasks import recover_boltz_swaps

        with patch(
            "app.tasks.boltz_tasks._run_async",
            side_effect=_fake_run_async({"recovered": 3}),
        ) as mock:
            result = recover_boltz_swaps()

        assert result["recovered"] == 3
        mock.assert_called_once()


class TestCleanupAuditLogs:
    """Retention cleanup preserves hash-chain integrity.

    The task delegates to ``audit_service.prune_audit_log``, which deletes
    aged rows, leaves the chain verifiable across the cut, and logs an
    ``audit_truncate`` anchor entry recording the retention event.
    """

    @pytest.mark.asyncio
    async def test_cleanup_invokes_prune_and_returns_metadata(self, db_session):
        from datetime import datetime, timedelta, timezone
        from uuid import uuid4

        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.api_key import APIKey
        from app.models.audit_log import AuditLog
        from app.services.audit_service import log_action
        from app.tasks.boltz_tasks import _run_cleanup_audit_logs

        # Sentinel + working API key (see test_audit_service for rationale).
        db_session.add(
            APIKey(
                id=DASHBOARD_KEY_ID,
                name="__dashboard_sentinel__",
                key_hash="__dashboard_sentinel__",
                is_admin=True,
                is_active=True,
            )
        )
        api_key = APIKey(
            id=uuid4(),
            name="cleanup-key",
            key_hash="d" * 64,
            is_admin=True,
            is_active=True,
        )
        db_session.add(api_key)
        await db_session.commit()

        for i in range(4):
            await log_action(db_session, api_key, f"a{i}", "r")

        # Backdate two rows past the retention window.
        from sqlalchemy import select, update

        old_ids = (
            (
                await db_session.execute(
                    select(AuditLog.id).order_by(AuditLog.created_at.asc(), AuditLog.id.asc()).limit(2)
                )
            )
            .scalars()
            .all()
        )
        await db_session.execute(
            update(AuditLog)
            .where(AuditLog.id.in_(old_ids))
            .values(created_at=datetime.now(timezone.utc) - timedelta(days=400))
        )
        await db_session.commit()
        # Re-anchor after the out-of-band ``created_at`` change so the
        # chain verifies before the retention cut runs.
        from app.services.audit_service import reanchor_chain

        await reanchor_chain(db_session, api_key.id, api_key.name)

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _ctx():
            yield db_session

        with patch("app.core.database.get_db_context", _ctx), patch("app.tasks.boltz_tasks.settings") as mock_settings:
            mock_settings.audit_log_retention_days = 90
            result = await _run_cleanup_audit_logs()

        assert result["deleted"] == 2
        assert result["skipped"] is False
        assert result["anchor_id"] is not None
        assert result["retention_days"] == 90

        # Anchor row must be present and chain must verify.
        from app.services.audit_service import verify_chain

        anchor = (await db_session.execute(select(AuditLog).where(AuditLog.action == "audit_truncate"))).scalar_one()
        assert anchor.details["deleted_count"] == 2
        assert anchor.api_key_name == "__retention__"

        db_session.expire_all()
        verify = await verify_chain(db_session)
        assert verify["ok"] is True, verify

    @pytest.mark.asyncio
    async def test_cleanup_disabled_when_retention_zero_still_emits_anchor(self):
        """Retention disabled (keep-forever) must NOT prune, but must still
        emit a heartbeat ``audit_anchor`` so an off-box observer keeps
        receiving signed head/count snapshots for truncation detection."""
        from unittest.mock import MagicMock

        from app.tasks.boltz_tasks import _run_cleanup_audit_logs

        emitted: list[int] = []

        async def _emit(db, *, deleted=0):
            emitted.append(deleted)
            return {"count": 0, "deleted": deleted}

        class _Ctx:
            async def __aenter__(self):
                return MagicMock()

            async def __aexit__(self, *exc):
                return False

        with (
            patch("app.tasks.boltz_tasks.settings") as mock_settings,
            patch("app.core.database.get_db_context", return_value=_Ctx()),
            patch("app.services.audit_service.emit_audit_anchor", _emit),
        ):
            mock_settings.audit_log_retention_days = 0
            result = await _run_cleanup_audit_logs()

        assert result == {"deleted": 0, "detail": "retention disabled; anchor emitted"}
        assert emitted == [0], "a heartbeat anchor (deleted=0) must be emitted when retention is disabled"


# ── BOLT 12 daily summary (T3) ──────────────────────────────────


@pytest.mark.asyncio
async def test_bolt12_daily_summary_aggregates_counts(db_session, monkeypatch):
    """The summary task counts bolt12-prefixed audit rows in the
    24 h window and writes a single ``bolt12_daily_summary`` row."""
    from datetime import datetime, timedelta, timezone

    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.audit_log import AuditLog
    from app.tasks.boltz_tasks import _run_bolt12_daily_summary

    # Seed three matching rows + one outside the window + one
    # unrelated action.
    now = datetime.now(timezone.utc)
    seeds = [
        ("bolt12_invoice_minted", now - timedelta(hours=1)),
        ("bolt12_invoice_minted", now - timedelta(hours=2)),
        ("bolt12_invoice_settle_timeout", now - timedelta(hours=3)),
        ("bolt12_invoice_minted", now - timedelta(hours=48)),  # outside
        ("unrelated_action", now - timedelta(hours=1)),
    ]
    for action, ts in seeds:
        row = AuditLog(
            api_key_id=DASHBOARD_KEY_ID,
            api_key_name="test",
            action=action,
            resource="test",
            success=True,
            created_at=ts,
        )
        db_session.add(row)
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(
        "app.core.database.get_db_context",
        _fake_ctx,
    )
    # Avoid audit emit hitting a separate session — capture & no-op.
    audit_calls: list[dict] = []

    async def _fake_audit(_factory, **kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _fake_audit,
    )

    summary = await _run_bolt12_daily_summary()
    assert summary["invoice_minted_total"] == 2
    assert summary["settle_timeout_total"] == 1
    # The audit row was emitted with the summary details.
    assert audit_calls
    assert audit_calls[0]["action"] == "bolt12_daily_summary"
