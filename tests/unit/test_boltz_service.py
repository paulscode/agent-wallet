# SPDX-License-Identifier: MIT
"""
Unit tests for the Boltz swap state machine and service.

Tests:
- Preimage generation + SHA256 hash
- Keypair generation
- Swap creation (mocked Boltz API)
- State transitions through advance_swap
- Swap cancellation rules
- Recovery logic
- Cooperative claim subprocess call
- HTTP request layer (_request, _request_clearnet)
- Tor proxy / clearnet fallback
- Service lifecycle (close)
"""

import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import httpx
import pytest

from app.models.boltz_swap import BoltzSwap, SwapStatus
from app.services.boltz_service import BoltzSwapService
from tests._bolt11_fixtures import BIND_INVOICE, BIND_INVOICE_PRINCIPAL_SATS, BIND_PAYMENT_HASH


def _patch_capped(*, return_value=None, side_effect=None):
    """Patch the boltz_service HTTP read seam.

    ``_attempt`` / ``_request_clearnet`` read the response body through
    ``request_capped`` (a streaming, size-bounded read). Tests drive the HTTP
    layer by substituting it with a return value or an exception, exactly as
    the underlying client call would surface one.
    """
    return patch(
        "app.services.boltz_service.request_capped",
        new=AsyncMock(return_value=return_value, side_effect=side_effect),
    )


def _mock_node_subprocess(
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
    communicate_side_effect=None,
):
    """Patch ``asyncio.create_subprocess_exec`` in boltz_service.

    The production code now spawns the Node.js claim / refund scripts
    via ``asyncio.create_subprocess_exec`` + ``proc.communicate`` instead
    of the blocking ``subprocess.run``. Tests stub both seams: the
    factory returns a mock ``proc`` whose ``communicate`` is an
    ``AsyncMock`` either returning ``(stdout, stderr)`` bytes or
    raising (typically ``asyncio.TimeoutError`` for the timeout path).
    """
    proc = MagicMock()
    proc.returncode = returncode
    proc.kill = MagicMock()
    proc.wait = AsyncMock(return_value=None)
    if communicate_side_effect is not None:
        proc.communicate = AsyncMock(side_effect=communicate_side_effect)
    else:
        proc.communicate = AsyncMock(return_value=(stdout.encode(), stderr.encode()))
    return patch(
        "app.services.boltz_service.asyncio.create_subprocess_exec",
        new=AsyncMock(return_value=proc),
    )


def _patch_pin_noop():
    """Skip clearnet IP-pinning DNS in tests, preserving the original URL."""
    return patch(
        "app.services.boltz_service.pin_request_args",
        new=lambda url: (url, {}, {}),
    )


class TestPreimageGeneration:
    """Tests for preimage/hash generation."""

    def test_preimage_returns_hex_pair(self):
        from app.services.boltz_service import _generate_preimage

        preimage, preimage_hash = _generate_preimage()
        assert len(preimage) == 64  # 32 bytes hex
        assert len(preimage_hash) == 64

    def test_preimage_hash_is_sha256(self):
        from app.services.boltz_service import _generate_preimage

        preimage, preimage_hash = _generate_preimage()
        expected_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
        assert preimage_hash == expected_hash

    def test_preimages_are_unique(self):
        from app.services.boltz_service import _generate_preimage

        preimages = {_generate_preimage()[0] for _ in range(50)}
        assert len(preimages) == 50


class TestKeypairGeneration:
    """Tests for EC keypair generation (mocked — Node.js not available in test env)."""

    def test_keypair_with_mocked_subprocess(self):
        from unittest.mock import MagicMock, patch

        from app.services.boltz_service import _generate_keypair

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = '{"privateKey":"aa"' + '"bb"' * 0 + '","publicKey":"02' + "cc" * 32 + '"}\n'
        # Build valid mock output
        priv_hex = "a1" * 32
        pub_hex = "02" + "b1" * 32
        mock_result.stdout = f'{{"privateKey":"{priv_hex}","publicKey":"{pub_hex}"}}\n'

        with patch("subprocess.run", return_value=mock_result):
            priv, pub = _generate_keypair()

        assert priv == priv_hex
        assert pub == pub_hex
        assert len(priv) == 64
        assert len(pub) == 66

    def test_keypair_subprocess_failure_raises(self):
        from unittest.mock import MagicMock, patch

        from app.services.boltz_service import _generate_keypair

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Module not found"

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="EC keypair generation failed"):
                _generate_keypair()

    def test_keypair_timeout_raises(self):
        import subprocess
        from unittest.mock import patch

        from app.services.boltz_service import _generate_keypair

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("node", 10)):
            with pytest.raises(RuntimeError, match="timed out"):
                _generate_keypair()

    def test_keypair_node_not_found_raises(self):
        from unittest.mock import patch

        from app.services.boltz_service import _generate_keypair

        with patch("subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(RuntimeError, match="Node.js not found"):
                _generate_keypair()


class TestSwapStatus:
    """Tests for the SwapStatus enum."""

    def test_all_statuses_defined(self):
        expected = {
            "created",
            "paying_invoice",
            "invoice_paid",
            "claiming",
            "claimed",
            "completed",
            "failed",
            "cancelled",
            "refunded",
        }
        actual = {s.value for s in SwapStatus}
        assert expected == actual

    def test_terminal_states(self):
        """Terminal states should include completed, failed, cancelled, refunded."""
        terminal = {SwapStatus.COMPLETED, SwapStatus.FAILED, SwapStatus.CANCELLED, SwapStatus.REFUNDED}
        for status in terminal:
            assert status in SwapStatus


class TestSwapCancellation:
    """Tests for swap cancellation rules."""

    @pytest.mark.asyncio
    async def test_cancel_created_swap(self, db_session):
        """A swap in CREATED state can be cancelled."""
        from app.models.boltz_swap import BoltzSwap
        from app.services.boltz_service import BoltzSwapService

        swap = BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="test-swap-cancel",
            status=SwapStatus.CREATED,
            invoice_amount_sats=100000,
            destination_address="bcrt1qtest",
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        svc = BoltzSwapService()
        success, error = await svc.cancel_swap(db_session, swap)

        assert success is True
        assert swap.status == SwapStatus.CANCELLED

    @pytest.mark.asyncio
    async def test_cancel_completed_swap_fails(self, db_session):
        """A completed swap cannot be cancelled."""
        from app.models.boltz_swap import BoltzSwap
        from app.services.boltz_service import BoltzSwapService

        swap = BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="test-swap-no-cancel",
            status=SwapStatus.COMPLETED,
            invoice_amount_sats=100000,
            destination_address="bcrt1qtest",
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        svc = BoltzSwapService()
        success, error = await svc.cancel_swap(db_session, swap)

        assert success is False
        assert "Cannot cancel" in error

    @pytest.mark.asyncio
    async def test_cancel_paid_swap_fails(self, db_session):
        """A swap where invoice was already paid cannot be cancelled."""
        from app.models.boltz_swap import BoltzSwap
        from app.services.boltz_service import BoltzSwapService

        swap = BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="test-swap-paid",
            status=SwapStatus.INVOICE_PAID,
            invoice_amount_sats=100000,
            destination_address="bcrt1qtest",
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        svc = BoltzSwapService()
        success, error = await svc.cancel_swap(db_session, swap)

        assert success is False
        assert "Cannot cancel" in error


class TestSwapStatusHistory:
    """Tests for swap status_history tracking."""

    @pytest.mark.asyncio
    async def test_cancellation_adds_history_entry(self, db_session):
        """Cancelling a swap should add a history entry."""
        from app.models.boltz_swap import BoltzSwap
        from app.services.boltz_service import BoltzSwapService

        swap = BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="test-history",
            status=SwapStatus.CREATED,
            invoice_amount_sats=50000,
            destination_address="bcrt1qtest",
            status_history=[
                {"status": "created", "timestamp": datetime.now(timezone.utc).isoformat()},
            ],
        )
        db_session.add(swap)
        await db_session.commit()

        svc = BoltzSwapService()
        await svc.cancel_swap(db_session, swap)

        assert len(swap.status_history) == 2
        assert swap.status_history[-1]["status"] == "cancelled"


class TestSwapLookup:
    """Tests for swap query helpers."""

    @pytest.mark.asyncio
    async def test_get_swap_by_id(self, db_session):
        """get_swap_by_id returns the correct swap."""
        from app.models.boltz_swap import BoltzSwap
        from app.services.boltz_service import BoltzSwapService

        swap_id = uuid4()
        swap = BoltzSwap(
            id=swap_id,
            api_key_id=uuid4(),
            boltz_swap_id="lookup-test",
            status=SwapStatus.CREATED,
            invoice_amount_sats=25000,
            destination_address="bcrt1qtest",
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        svc = BoltzSwapService()
        result = await svc.get_swap_by_id(db_session, swap_id)

        assert result is not None
        assert result.boltz_swap_id == "lookup-test"

    @pytest.mark.asyncio
    async def test_get_swap_by_id_not_found(self, db_session):
        """get_swap_by_id returns None for non-existent ID."""
        from app.services.boltz_service import BoltzSwapService

        svc = BoltzSwapService()
        result = await svc.get_swap_by_id(db_session, uuid4())
        assert result is None

    @pytest.mark.asyncio
    async def test_get_swaps_for_key(self, db_session):
        """get_swaps_for_key returns only swaps belonging to that key."""
        from app.models.boltz_swap import BoltzSwap
        from app.services.boltz_service import BoltzSwapService

        key_id = uuid4()
        other_key_id = uuid4()

        for i in range(3):
            db_session.add(
                BoltzSwap(
                    id=uuid4(),
                    api_key_id=key_id,
                    boltz_swap_id=f"my-swap-{i}",
                    status=SwapStatus.CREATED,
                    invoice_amount_sats=10000,
                    destination_address="bcrt1qtest",
                    status_history=[],
                )
            )
        db_session.add(
            BoltzSwap(
                id=uuid4(),
                api_key_id=other_key_id,
                boltz_swap_id="other-swap",
                status=SwapStatus.CREATED,
                invoice_amount_sats=10000,
                destination_address="bcrt1qtest",
                status_history=[],
            )
        )
        await db_session.commit()

        svc = BoltzSwapService()
        results = await svc.get_swaps_for_key(db_session, key_id, limit=10)

        assert len(results) == 3
        assert all(r.api_key_id == key_id for r in results)


class TestGetReversePairInfo:
    """Tests for get_reverse_pair_info including cache."""

    @pytest.mark.asyncio
    async def test_returns_parsed_info(self):
        svc = BoltzSwapService()
        boltz_response = {
            "BTC": {
                "BTC": {
                    "limits": {"minimal": 50000, "maximal": 25000000},
                    "fees": {"percentage": 0.25, "minerFees": {"lockup": 3000, "claim": 2500}},
                    "hash": "abc123",
                }
            }
        }
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(boltz_response, None)):
            info, err = await svc.get_reverse_pair_info()

        assert err is None
        assert info["min"] == 50000
        assert info["max"] == 25000000
        assert info["fees_percentage"] == 0.25
        assert info["hash"] == "abc123"

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        svc = BoltzSwapService()
        cached = {
            "min": 50000,
            "max": 25000000,
            "fees_percentage": 0.25,
            "fees_miner_lockup": 3000,
            "fees_miner_claim": 2500,
            "hash": "x",
        }
        svc._pair_info_cache = cached
        svc._pair_info_cached_at = datetime.now(timezone.utc)

        # Should return cache without calling _request
        with patch.object(svc, "_request", new_callable=AsyncMock) as mock_req:
            info, err = await svc.get_reverse_pair_info()
            mock_req.assert_not_called()

        assert info == cached

    @pytest.mark.asyncio
    async def test_cache_expired(self):
        svc = BoltzSwapService()
        svc._pair_info_cache = {"min": 1}
        svc._pair_info_cached_at = datetime.now(timezone.utc) - timedelta(seconds=120)

        boltz_response = {
            "BTC": {
                "BTC": {
                    "limits": {"minimal": 60000, "maximal": 20000000},
                    "fees": {"percentage": 0.3, "minerFees": {"lockup": 3000, "claim": 2500}},
                    "hash": "new",
                }
            }
        }
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(boltz_response, None)):
            info, err = await svc.get_reverse_pair_info()

        assert info["min"] == 60000  # Fresh data

    @pytest.mark.asyncio
    async def test_btc_pair_missing(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"ETH": {}}, None)):
            info, err = await svc.get_reverse_pair_info()
        assert info is None
        assert "not found" in err

    @pytest.mark.asyncio
    async def test_request_error_propagated(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "timeout")):
            info, err = await svc.get_reverse_pair_info()
        assert info is None
        assert "timeout" in err


class TestGetLnNodePubkeys:
    """Tests for get_ln_node_pubkeys (``/v2/nodes``)."""

    @pytest.mark.asyncio
    async def test_parses_and_dedupes_pubkeys(self):
        svc = BoltzSwapService()
        response = {
            "BTC": {
                "LND": {"publicKey": "02" + "AB" * 32, "uris": ["x"]},
                "CLN": {"publicKey": "03" + "cd" * 32, "uris": ["y"]},
                # Duplicate (different case) must collapse.
                "LND2": {"publicKey": "02" + "ab" * 32},
            }
        }
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(response, None)):
            pubkeys, err = await svc.get_ln_node_pubkeys()
        assert err is None
        # Lowercased + deduped.
        assert pubkeys == ["02" + "ab" * 32, "03" + "cd" * 32]

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        svc = BoltzSwapService()
        svc._nodes_cache = ["02" + "ee" * 32]
        svc._nodes_cached_at = datetime.now(timezone.utc)
        with patch.object(svc, "_request", new_callable=AsyncMock) as mock_req:
            pubkeys, err = await svc.get_ln_node_pubkeys()
            mock_req.assert_not_called()
        assert pubkeys == ["02" + "ee" * 32]

    @pytest.mark.asyncio
    async def test_serves_stale_on_error(self):
        svc = BoltzSwapService()
        svc._nodes_stale = ["02" + "ff" * 32]
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "tor down")):
            pubkeys, err = await svc.get_ln_node_pubkeys()
        assert err is None
        assert pubkeys == ["02" + "ff" * 32]

    @pytest.mark.asyncio
    async def test_error_propagated_without_stale(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "timeout")):
            pubkeys, err = await svc.get_ln_node_pubkeys()
        assert pubkeys is None
        assert "timeout" in err

    @pytest.mark.asyncio
    async def test_no_pubkeys_in_response(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"BTC": {}}, None)):
            pubkeys, err = await svc.get_ln_node_pubkeys()
        assert pubkeys is None
        assert err is not None


# ─── create_reverse_swap ──────────────────────────────────────────────


class TestCreateReverseSwap:
    """Tests for create_reverse_swap."""

    @pytest.mark.asyncio
    async def test_success(self, db_session):
        svc = BoltzSwapService()
        pair_info = {
            "min": 25000,
            "max": 25000000,
            "fees_percentage": 0.25,
            "fees_miner_lockup": 3000,
            "fees_miner_claim": 2500,
            "hash": "h1",
        }
        boltz_create_response = {
            "id": "boltz-swap-123",
            "invoice": BIND_INVOICE,
            "lockupAddress": "bcrt1qlock...",
            "refundPublicKey": "02" + "ff" * 32,
            "swapTree": {"claimLeaf": {}},
            "timeoutBlockHeight": 900000,
            "onchainAmount": 100000,
        }

        with (
            patch.object(svc, "get_reverse_pair_info", new_callable=AsyncMock, return_value=(pair_info, None)),
            patch("app.services.boltz_service._generate_preimage", return_value=("aa" * 32, BIND_PAYMENT_HASH)),
            patch("app.services.boltz_service._generate_keypair", return_value=("cc" * 32, "02" + "dd" * 32)),
            patch(
                "app.services.boltz_service.verify_reverse_lockup_address",
                return_value=(True, "ok"),
            ),
            patch.object(svc, "_request", new_callable=AsyncMock, return_value=(boltz_create_response, None)),
        ):
            swap, err = await svc.create_reverse_swap(
                db_session, uuid4(), BIND_INVOICE_PRINCIPAL_SATS, "bcrt1qdestination"
            )

        assert err is None
        assert swap is not None
        assert swap.boltz_swap_id == "boltz-swap-123"
        assert swap.status == SwapStatus.CREATED
        assert swap.invoice_amount_sats == BIND_INVOICE_PRINCIPAL_SATS
        # Default: no outgoing-channel pin.
        assert swap.outgoing_chan_id is None

    @pytest.mark.asyncio
    async def test_stores_outgoing_chan_id_when_provided(self, db_session):
        svc = BoltzSwapService()
        pair_info = {
            "min": 25000,
            "max": 25000000,
            "fees_percentage": 0.25,
            "fees_miner_lockup": 3000,
            "fees_miner_claim": 2500,
            "hash": "h1",
        }
        resp = {"id": "swap-pin", "invoice": BIND_INVOICE, "lockupAddress": "bcrt1q...", "onchainAmount": 100000}
        with (
            patch.object(svc, "get_reverse_pair_info", new_callable=AsyncMock, return_value=(pair_info, None)),
            patch("app.services.boltz_service._generate_preimage", return_value=("aa" * 32, BIND_PAYMENT_HASH)),
            patch("app.services.boltz_service._generate_keypair", return_value=("cc" * 32, "02" + "dd" * 32)),
            patch(
                "app.services.boltz_service.verify_reverse_lockup_address",
                return_value=(True, "ok"),
            ),
            patch.object(svc, "_request", new_callable=AsyncMock, return_value=(resp, None)),
        ):
            swap, err = await svc.create_reverse_swap(
                db_session, uuid4(), BIND_INVOICE_PRINCIPAL_SATS, "bcrt1qdest", outgoing_chan_id="123x456x0"
            )
        assert err is None and swap is not None
        assert swap.outgoing_chan_id == "123x456x0"

    @pytest.mark.asyncio
    async def test_amount_below_min(self, db_session):
        svc = BoltzSwapService()
        pair_info = {
            "min": 50000,
            "max": 25000000,
            "fees_percentage": 0.25,
            "fees_miner_lockup": 3000,
            "fees_miner_claim": 2500,
            "hash": "",
        }
        with patch.object(svc, "get_reverse_pair_info", new_callable=AsyncMock, return_value=(pair_info, None)):
            swap, err = await svc.create_reverse_swap(db_session, uuid4(), 10000, "bcrt1qdest")
        assert swap is None
        assert "between" in err

    @pytest.mark.asyncio
    async def test_amount_above_max(self, db_session):
        svc = BoltzSwapService()
        pair_info = {
            "min": 25000,
            "max": 100000,
            "fees_percentage": 0.25,
            "fees_miner_lockup": 3000,
            "fees_miner_claim": 2500,
            "hash": "",
        }
        with patch.object(svc, "get_reverse_pair_info", new_callable=AsyncMock, return_value=(pair_info, None)):
            swap, err = await svc.create_reverse_swap(db_session, uuid4(), 999999, "bcrt1qdest")
        assert swap is None
        assert "between" in err

    @pytest.mark.asyncio
    async def test_pair_info_error(self, db_session):
        svc = BoltzSwapService()
        with patch.object(svc, "get_reverse_pair_info", new_callable=AsyncMock, return_value=(None, "Tor timeout")):
            swap, err = await svc.create_reverse_swap(db_session, uuid4(), 100000, "bcrt1qdest")
        assert swap is None
        assert "Tor timeout" in err

    @pytest.mark.asyncio
    async def test_keypair_generation_fails(self, db_session):
        svc = BoltzSwapService()
        pair_info = {
            "min": 25000,
            "max": 25000000,
            "fees_percentage": 0.25,
            "fees_miner_lockup": 3000,
            "fees_miner_claim": 2500,
            "hash": "",
        }
        with (
            patch.object(svc, "get_reverse_pair_info", new_callable=AsyncMock, return_value=(pair_info, None)),
            patch("app.services.boltz_service._generate_preimage", return_value=("aa" * 32, "bb" * 32)),
            patch("app.services.boltz_service._generate_keypair", side_effect=RuntimeError("Node.js not found")),
        ):
            swap, err = await svc.create_reverse_swap(db_session, uuid4(), 100000, "bcrt1qdest")
        assert swap is None
        assert "Node.js not found" in err

    @pytest.mark.asyncio
    async def test_boltz_api_error(self, db_session):
        svc = BoltzSwapService()
        pair_info = {
            "min": 25000,
            "max": 25000000,
            "fees_percentage": 0.25,
            "fees_miner_lockup": 3000,
            "fees_miner_claim": 2500,
            "hash": "",
        }
        with (
            patch.object(svc, "get_reverse_pair_info", new_callable=AsyncMock, return_value=(pair_info, None)),
            patch("app.services.boltz_service._generate_preimage", return_value=("aa" * 32, "bb" * 32)),
            patch("app.services.boltz_service._generate_keypair", return_value=("cc" * 32, "02" + "dd" * 32)),
            patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "503: Service Unavailable")),
        ):
            swap, err = await svc.create_reverse_swap(db_session, uuid4(), 100000, "bcrt1qdest")
        assert swap is None
        assert "503" in err


# ─── advance_swap ─────────────────────────────────────────────────────


class TestAdvanceSwap:
    """Tests for advance_swap state machine transitions."""

    def _make_swap(self, status=SwapStatus.INVOICE_PAID, boltz_status="swap.created"):
        return BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="test-advance",
            status=status,
            boltz_status=boltz_status,
            invoice_amount_sats=100000,
            destination_address="bcrt1qdest",
            status_history=[],
            preimage_hex="encrypted_preimage",
            claim_private_key_hex="encrypted_key",
            boltz_refund_public_key_hex="02" + "ff" * 32,
            boltz_swap_tree_json={"claimLeaf": {}},
        )

    @pytest.mark.asyncio
    async def test_invoice_expired_marks_failed(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap()
        db_session.add(swap)
        await db_session.commit()

        with patch.object(
            svc, "get_swap_status_from_boltz", new_callable=AsyncMock, return_value=("invoice.expired", {}, None)
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert err is None
        assert result_swap.status == SwapStatus.FAILED
        assert result_swap.completed_at is not None

    @pytest.mark.asyncio
    async def test_swap_expired_marks_failed(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap()
        db_session.add(swap)
        await db_session.commit()

        with patch.object(
            svc, "get_swap_status_from_boltz", new_callable=AsyncMock, return_value=("swap.expired", {}, None)
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert result_swap.status == SwapStatus.FAILED

    @pytest.mark.asyncio
    async def test_transaction_refunded(self, db_session, caplog):
        """REVERSE-swap transaction.refunded is downgraded from CRITICAL.

        Regression: prior code emitted ``logger.error("CRITICAL: ...")``
        and a misleading "Lightning funds were paid but on-chain funds
        were not received" message. In reality, for a reverse swap the
        hold-invoice only settles on preimage reveal — if Boltz refunded
        the on-chain lockup it means the preimage was never revealed,
        the wallet's LN HTLC will be cancelled, and the user's sats
        remain liquid. No alarm warranted.
        """
        import logging

        svc = BoltzSwapService()
        swap = self._make_swap()
        db_session.add(swap)
        await db_session.commit()

        with caplog.at_level(logging.WARNING, logger="app.services.boltz_service"):
            with patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.refunded", {}, None),
            ):
                result_swap, err = await svc.advance_swap(db_session, swap)

        assert result_swap.status == SwapStatus.REFUNDED
        # The new message must reassure the operator that their LN
        # sats are safe and explain the HTLC will auto-cancel.
        message = result_swap.error_message.lower()
        assert "lightning htlc will be cancelled" in message
        assert "no further action required" in message
        # And it must NOT contain the old alarmist phrasing.
        assert "lightning funds were paid" not in message
        # The legacy `logger.error("CRITICAL: ...")` line must be gone.
        for record in caplog.records:
            assert "CRITICAL:" not in record.getMessage(), (
                f"alarmist CRITICAL log re-introduced: {record.getMessage()!r}"
            )

    @pytest.mark.asyncio
    async def test_invoice_settled_marks_completed(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap()
        db_session.add(swap)
        await db_session.commit()

        with patch.object(
            svc, "get_swap_status_from_boltz", new_callable=AsyncMock, return_value=("invoice.settled", {}, None)
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert result_swap.status == SwapStatus.COMPLETED
        assert result_swap.completed_at is not None

    @pytest.mark.asyncio
    async def test_transaction_mempool_persists_lockup_txid(self, db_session):
        """2026-06-27: when Boltz reports the lockup tx via
        ``transaction.mempool``, persist the txid on the swap row so the
        dashboard can surface a Mempool link while the user waits for
        the lockup to confirm. Prior to this commit the field was only
        used for the address-verification check and was never written
        to the DB for reverse swaps."""
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.INVOICE_PAID)
        swap.boltz_lockup_address = "bcrt1qexpected_lockup"
        db_session.add(swap)
        await db_session.commit()

        lockup_id = "ab" * 32
        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.mempool", {"transaction": {"id": lockup_id}}, None),
            ),
            # Make optional_verify_tx return None so the address-mismatch
            # branch doesn't fire — we only want to verify the persist.
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.optional_verify_tx",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch.object(
                svc, "get_lockup_transaction",
                new_callable=AsyncMock, return_value=(None, "skip claim path"),
            ),
        ):
            result_swap, _err = await svc.advance_swap(db_session, swap)

        assert result_swap.lockup_txid == lockup_id, (
            "lockup_txid must be persisted the first time the "
            "transaction.mempool event reports it so the UI can render "
            "a working Mempool link during the lockup-confirm wait."
        )

    @pytest.mark.asyncio
    async def test_transaction_mempool_does_not_overwrite_existing_lockup_txid(
        self, db_session,
    ):
        """Idempotence: if the swap row already has a lockup_txid (e.g.
        from a previous tick), a subsequent tick must NOT overwrite it.
        Boltz may rotate the reported txid during RBF; we keep the first
        observation as the canonical id so the UI's Mempool link stays
        stable for the user."""
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.INVOICE_PAID)
        swap.boltz_lockup_address = "bcrt1qexpected_lockup"
        original_txid = "cd" * 32
        swap.lockup_txid = original_txid
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.mempool", {"transaction": {"id": "ef" * 32}}, None),
            ),
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.optional_verify_tx",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch.object(
                svc, "get_lockup_transaction",
                new_callable=AsyncMock, return_value=(None, "skip claim path"),
            ),
        ):
            result_swap, _err = await svc.advance_swap(db_session, swap)

        assert result_swap.lockup_txid == original_txid

    @pytest.mark.asyncio
    async def test_lockup_address_mismatch_withholds_claim(self, db_session):
        """When the independent electrs check is reachable and the lockup
        tx does NOT pay the address committed at swap creation, the claim
        is withheld for that tick and surfaced for operator review."""
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.INVOICE_PAID)
        swap.boltz_lockup_address = "bcrt1qexpected_lockup"
        db_session.add(swap)
        await db_session.commit()

        lockup_id = "ab" * 32
        # The verified tx pays a DIFFERENT address than the one committed
        # at swap creation. Use the REAL ``_tx_pays_address`` (not a stub)
        # against the backend's actual vout shape (``scriptpubkey_address``).
        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.mempool", {"transaction": {"id": lockup_id}}, None),
            ),
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.optional_verify_tx",
                new_callable=AsyncMock,
                return_value={"vout": [{"scriptpubkey_address": "bcrt1qattacker", "value": 100_000}]},
            ),
            patch.object(svc, "get_lockup_transaction", new_callable=AsyncMock) as mock_get_lockup,
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert "withheld" in (err or "")
        assert result_swap.claim_txid is None
        # The claim path (which would fetch the lockup tx to spend) is
        # never reached.
        mock_get_lockup.assert_not_awaited()

    def test_tx_pays_address_reads_backend_vout_shape(self):
        """``_tx_pays_address`` must read the ``scriptpubkey_address`` key
        the Electrum / mempool backends actually emit — otherwise the F11
        check would treat every legitimate lockup as a mismatch and
        withhold the claim."""
        from app.services.boltz_service import _tx_pays_address

        tx = {"vout": [{"scriptpubkey_address": "bcrt1qexpected", "value": 100_000}]}
        assert _tx_pays_address(tx, "bcrt1qexpected") is True
        assert _tx_pays_address(tx, "bcrt1qother") is False
        # A bare ``address`` key is also accepted for any other shape.
        assert _tx_pays_address({"vout": [{"address": "bcrt1qexpected"}]}, "bcrt1qexpected") is True

    @pytest.mark.asyncio
    async def test_invoice_settled_backfills_missing_claim_txid(self, db_session):
        """A cooperative claim can settle the swap before ``claim_txid``
        is persisted (the claim broadcasts, then the subprocess errors).
        On ``invoice.settled`` with no claim_txid, advance_swap backfills
        it from the wallet UTXO sitting at the swap's destination address.
        Regression for incident 2026-06-16."""
        svc = BoltzSwapService()
        swap = self._make_swap()  # claim_txid None, dest bcrt1qdest
        swap.onchain_amount_sats = 99000
        db_session.add(swap)
        await db_session.commit()

        fake_utxos = [
            {"address": "bcrt1qother", "amount_sat": 1234, "outpoint": {"txid_str": "nope", "output_index": 0}},
            {"address": "bcrt1qdest", "amount_sat": 99000, "outpoint": {"txid_str": "f6" * 32, "output_index": 0}},
        ]
        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("invoice.settled", {}, None),
            ),
            patch(
                "app.services.lnd_service.lnd_service.list_unspent",
                new_callable=AsyncMock,
                return_value=(fake_utxos, None),
            ),
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert result_swap.status == SwapStatus.COMPLETED
        assert result_swap.claim_txid == "f6" * 32
        assert result_swap.claim_broadcast_at is not None

    @pytest.mark.asyncio
    async def test_invoice_settled_backfill_noop_external_destination(self, db_session):
        """When the claim went to an external (non-wallet) destination —
        cold storage — there's no wallet UTXO to recover from; the swap
        still completes cleanly, just without a backfilled claim_txid."""
        svc = BoltzSwapService()
        swap = self._make_swap()
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("invoice.settled", {}, None),
            ),
            patch(
                "app.services.lnd_service.lnd_service.list_unspent",
                new_callable=AsyncMock,
                return_value=([], None),
            ),
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert result_swap.status == SwapStatus.COMPLETED
        assert result_swap.claim_txid is None

    @pytest.mark.asyncio
    async def test_transaction_mempool_triggers_claim(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.INVOICE_PAID)
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.mempool", {}, None),
            ),
            patch.object(svc, "get_lockup_transaction", new_callable=AsyncMock, return_value=("0200000001...", None)),
            patch.object(svc, "cooperative_claim", new_callable=AsyncMock, return_value=("claim_txid_abc", None)),
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert err is None
        assert result_swap.status == SwapStatus.CLAIMED
        assert result_swap.claim_txid == "claim_txid_abc"

    @pytest.mark.asyncio
    async def test_advance_clears_transient_pay_invoice_error(self, db_session):
        """Stale transient pay-invoice copy gets cleared once the swap
        visibly advances past PAYING_INVOICE on the Boltz side.

        Regression guard: without this clear, the dashboard would keep
        showing "Payment attempt encountered a transient network
        error…" even after the swap moved on to CLAIMING / COMPLETED.
        """
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.PAYING_INVOICE)
        swap.error_message = (
            "Payment attempt encountered a transient network error "
            "and is being retried automatically. Payment hash: deadbeef. "
            "No action required — the next reconciliation tick will resume."
        )
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.mempool", {}, None),
            ),
            patch.object(svc, "get_lockup_transaction", new_callable=AsyncMock, return_value=("0200000001...", None)),
            patch.object(svc, "cooperative_claim", new_callable=AsyncMock, return_value=("claim_txid_xyz", None)),
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert err is None
        assert result_swap.status == SwapStatus.CLAIMED
        assert result_swap.error_message is None, (
            "stale transient pay-invoice copy was not cleared on advance to CLAIMING"
        )

    @pytest.mark.asyncio
    async def test_invoice_settled_clears_transient_pay_invoice_error(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.PAYING_INVOICE)
        swap.error_message = "Payment attempt encountered a transient network error and is being retried automatically."
        db_session.add(swap)
        await db_session.commit()

        with patch.object(
            svc, "get_swap_status_from_boltz", new_callable=AsyncMock, return_value=("invoice.settled", {}, None)
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert result_swap.status == SwapStatus.COMPLETED
        assert result_swap.error_message is None

    @pytest.mark.asyncio
    async def test_claim_failure_increments_recovery(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.INVOICE_PAID)
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.confirmed", {}, None),
            ),
            patch.object(svc, "get_lockup_transaction", new_callable=AsyncMock, return_value=("0200000001...", None)),
            patch.object(svc, "cooperative_claim", new_callable=AsyncMock, return_value=(None, "claim script failed")),
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert "claim script failed" in err
        assert result_swap.recovery_count == 1

    @pytest.mark.asyncio
    async def test_lockup_fetch_failure(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.INVOICE_PAID)
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.mempool", {}, None),
            ),
            patch.object(svc, "get_lockup_transaction", new_callable=AsyncMock, return_value=(None, "404 not found")),
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert "404" in err

    @pytest.mark.asyncio
    async def test_boltz_status_check_error(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap()
        db_session.add(swap)
        await db_session.commit()

        with patch.object(
            svc, "get_swap_status_from_boltz", new_callable=AsyncMock, return_value=(None, None, "connection timeout")
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert "connection timeout" in err

    @pytest.mark.asyncio
    async def test_status_history_updated_on_change(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap(boltz_status="swap.created")
        db_session.add(swap)
        await db_session.commit()

        with patch.object(
            svc, "get_swap_status_from_boltz", new_callable=AsyncMock, return_value=("invoice.settled", {}, None)
        ):
            await svc.advance_swap(db_session, swap)

        assert len(swap.status_history) == 1
        assert swap.status_history[0]["boltz_status"] == "invoice.settled"


# ─── cooperative_claim ────────────────────────────────────────────────


class TestCooperativeClaim:
    """Tests for cooperative_claim subprocess execution."""

    def _make_swap(self):
        swap = MagicMock()
        swap.boltz_swap_id = "claim-test"
        swap.preimage_hex = "encrypted_preimage"
        swap.claim_private_key_hex = "encrypted_key"
        swap.boltz_refund_public_key_hex = "02" + "ff" * 32
        swap.boltz_swap_tree_json = {"claimLeaf": {}}
        swap.destination_address = "bcrt1qdest"
        return swap

    @pytest.mark.asyncio
    async def test_claim_success(self):
        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: f"decrypted_{x}"),
            _mock_node_subprocess(returncode=0, stdout='{"txid": "abcdef1234567890"}\n'),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_claim(swap, "0200000001...")

        assert err is None
        assert txid == "abcdef1234567890"

    @pytest.mark.asyncio
    async def test_claim_script_not_found(self):
        svc = BoltzSwapService()
        swap = self._make_swap()

        with patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path:
            mock_path.exists.return_value = False
            txid, err = await svc.cooperative_claim(swap, "0200000001...")

        assert txid is None
        assert "not found" in err

    @pytest.mark.asyncio
    async def test_claim_script_nonzero_exit(self):
        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            _mock_node_subprocess(returncode=1, stderr="Error: invalid preimage"),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_claim(swap, "0200000001...")

        assert txid is None
        assert "Claim script failed" in err

    @pytest.mark.asyncio
    async def test_claim_script_timeout(self):
        import asyncio as _asyncio

        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            _mock_node_subprocess(communicate_side_effect=_asyncio.TimeoutError()),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_claim(swap, "0200000001...")

        assert txid is None
        assert "timed out" in err

    @pytest.mark.asyncio
    async def test_claim_script_invalid_json(self):
        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            _mock_node_subprocess(returncode=0, stdout="not valid json"),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_claim(swap, "0200000001...")

        assert txid is None
        assert "invalid JSON" in err

    @pytest.mark.asyncio
    async def test_claim_script_no_txid(self):
        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            _mock_node_subprocess(returncode=0, stdout='{"result": "ok"}\n'),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_claim(swap, "0200000001...")

        assert txid is None
        assert "no txid" in err

    @pytest.mark.asyncio
    async def test_claim_node_not_found(self):
        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            patch(
                "app.services.boltz_service.asyncio.create_subprocess_exec",
                new=AsyncMock(side_effect=FileNotFoundError),
            ),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_claim(swap, "0200000001...")

        assert txid is None
        assert "Node.js not found" in err


# ─── broadcast_transaction ────────────────────────────────────────────


class TestBroadcastTransaction:
    """Tests for broadcast_transaction."""

    @pytest.mark.asyncio
    async def test_broadcast_success(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"id": "tx123"}, None)):
            txid, err = await svc.broadcast_transaction("0200000001...")
        assert txid == "tx123"
        assert err is None

    @pytest.mark.asyncio
    async def test_broadcast_error(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "invalid tx")):
            txid, err = await svc.broadcast_transaction("invalid")
        assert txid is None
        assert "invalid tx" in err


# ─── recover_pending_swaps ────────────────────────────────────────────


class TestRecoverPendingSwaps:
    """Tests for recover_pending_swaps."""

    @pytest.mark.asyncio
    async def test_no_pending_swaps(self, db_session):
        svc = BoltzSwapService()
        results = await svc.recover_pending_swaps(db_session)
        assert results == []

    @pytest.mark.asyncio
    async def test_recovers_pending_swaps(self, db_session):
        svc = BoltzSwapService()
        swap = BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="recover-test",
            status=SwapStatus.INVOICE_PAID,
            invoice_amount_sats=100000,
            destination_address="bcrt1qdest",
            status_history=[],
            preimage_hex="enc",
            claim_private_key_hex="enc",
        )
        db_session.add(swap)
        await db_session.commit()

        with patch.object(svc, "advance_swap", new_callable=AsyncMock, return_value=(swap, None)):
            results = await svc.recover_pending_swaps(db_session)

        assert len(results) == 1
        assert results[0]["boltz_swap_id"] == "recover-test"

    @pytest.mark.asyncio
    async def test_recovery_handles_exception(self, db_session):
        svc = BoltzSwapService()
        swap = BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="recover-fail",
            status=SwapStatus.CLAIMING,
            invoice_amount_sats=100000,
            destination_address="bcrt1qdest",
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        with patch.object(svc, "advance_swap", new_callable=AsyncMock, side_effect=RuntimeError("boom")):
            results = await svc.recover_pending_swaps(db_session)

        assert len(results) == 1
        assert "boom" in results[0]["error"]

    @pytest.mark.asyncio
    async def test_paying_invoice_requeued_to_process_task(self, db_session):
        """A pre-payment swap (PAYING_INVOICE) must be re-enqueued through
        process_boltz_swap — which has the re-entrant pay step — rather than
        only reconciled via advance_swap (which can't (re)send the payment)."""
        svc = BoltzSwapService()
        swap = BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="stuck-paying",
            status=SwapStatus.PAYING_INVOICE,
            invoice_amount_sats=100000,
            destination_address="bcrt1qdest",
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(svc, "advance_swap", new_callable=AsyncMock) as adv,
            patch("app.tasks.boltz_tasks.process_boltz_swap") as proc,
        ):
            results = await svc.recover_pending_swaps(db_session)

        proc.delay.assert_called_once_with(str(swap.id))
        adv.assert_not_called()
        assert len(results) == 1
        assert results[0].get("requeued") is True

    @pytest.mark.asyncio
    async def test_ignores_terminal_states(self, db_session):
        """Completed/failed/cancelled swaps should not be recovered."""
        svc = BoltzSwapService()
        for status in (SwapStatus.COMPLETED, SwapStatus.FAILED, SwapStatus.CANCELLED, SwapStatus.REFUNDED):
            db_session.add(
                BoltzSwap(
                    id=uuid4(),
                    api_key_id=uuid4(),
                    boltz_swap_id=f"terminal-{status.value}",
                    status=status,
                    invoice_amount_sats=100000,
                    destination_address="bcrt1qdest",
                    status_history=[],
                )
            )
        await db_session.commit()

        results = await svc.recover_pending_swaps(db_session)
        assert results == []


# ─── advance_swap additional edge cases ───────────────────────────────


class TestAdvanceSwapAdditional:
    """Additional tests for advance_swap edge cases."""

    def _make_swap(self, status=SwapStatus.INVOICE_PAID, boltz_status="swap.created"):
        return BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="test-advance-extra",
            status=status,
            boltz_status=boltz_status,
            invoice_amount_sats=100000,
            destination_address="bcrt1qdest",
            status_history=[],
            preimage_hex="encrypted_preimage",
            claim_private_key_hex="encrypted_key",
            boltz_refund_public_key_hex="02" + "ff" * 32,
            boltz_swap_tree_json={"claimLeaf": {}},
        )

    @pytest.mark.asyncio
    async def test_transaction_failed_marks_failed(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap()
        db_session.add(swap)
        await db_session.commit()

        with patch.object(
            svc, "get_swap_status_from_boltz", new_callable=AsyncMock, return_value=("transaction.failed", {}, None)
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert result_swap.status == SwapStatus.FAILED
        assert "transaction.failed" in result_swap.error_message

    @pytest.mark.asyncio
    async def test_already_claimed_swap_not_reclaimed(self, db_session):
        """If claim_txid is already set, cooperative_claim should not be called again."""
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.CLAIMING)
        swap.claim_txid = "already_claimed_txid"
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.confirmed", {}, None),
            ),
            patch.object(svc, "cooperative_claim", new_callable=AsyncMock) as mock_claim,
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        mock_claim.assert_not_called()

    @pytest.mark.asyncio
    async def test_created_status_transitions_to_claiming(self, db_session):
        """CREATED swap with transaction.mempool transitions to CLAIMING."""
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.CREATED)
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.mempool", {}, None),
            ),
            patch.object(svc, "get_lockup_transaction", new_callable=AsyncMock, return_value=("0200000001...", None)),
            patch.object(svc, "cooperative_claim", new_callable=AsyncMock, return_value=("claim_txid_abc", None)),
        ):
            result_swap, err = await svc.advance_swap(db_session, swap)

        assert result_swap.status == SwapStatus.CLAIMED

    @pytest.mark.asyncio
    async def test_no_status_change_skips_history(self, db_session):
        """No history entry added when boltz_status hasn't changed."""
        svc = BoltzSwapService()
        swap = self._make_swap(boltz_status="invoice.settled")
        db_session.add(swap)
        await db_session.commit()

        with patch.object(
            svc, "get_swap_status_from_boltz", new_callable=AsyncMock, return_value=("invoice.settled", {}, None)
        ):
            await svc.advance_swap(db_session, swap)

        assert len(swap.status_history) == 0

    @pytest.mark.asyncio
    async def test_recovery_multiple_pending_states(self, db_session):
        """recover_pending_swaps processes multiple swaps in different states."""
        svc = BoltzSwapService()

        for status in (
            SwapStatus.CREATED,
            SwapStatus.PAYING_INVOICE,
            SwapStatus.INVOICE_PAID,
            SwapStatus.CLAIMING,
            SwapStatus.CLAIMED,
        ):
            db_session.add(
                BoltzSwap(
                    id=uuid4(),
                    api_key_id=uuid4(),
                    boltz_swap_id=f"multi-{status.value}",
                    status=status,
                    invoice_amount_sats=100000,
                    destination_address="bcrt1qdest",
                    status_history=[],
                )
            )
        await db_session.commit()

        with patch.object(
            svc,
            "advance_swap",
            new_callable=AsyncMock,
            return_value=(MagicMock(status=SwapStatus.COMPLETED, boltz_swap_id="x"), None),
        ):
            results = await svc.recover_pending_swaps(db_session)

        assert len(results) == 5


# ─── _request layer ──────────────────────────────────────────────────


class TestBoltzServiceRequest:
    """Tests for _request HTTP layer including Tor fallback."""

    @pytest.mark.asyncio
    async def test_request_success(self):
        svc = BoltzSwapService()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with _patch_capped(return_value=mock_response):
            data, err = await svc._request("GET", "/test")
        assert data == {"status": "ok"}
        assert err is None

    @pytest.mark.asyncio
    async def test_request_http_status_error(self):
        svc = BoltzSwapService()
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "bad request"
        mock_resp.json.return_value = {"error": "invalid amount"}

        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with _patch_capped(side_effect=httpx.HTTPStatusError("error", request=MagicMock(), response=mock_resp)):
            data, err = await svc._request("GET", "/test")
        assert data is None
        assert "400" in err
        assert "invalid amount" in err

    @pytest.mark.asyncio
    async def test_request_http_status_error_no_json(self):
        svc = BoltzSwapService()
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "internal error"
        mock_resp.json.side_effect = Exception("not json")

        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with _patch_capped(side_effect=httpx.HTTPStatusError("error", request=MagicMock(), response=mock_resp)):
            data, err = await svc._request("GET", "/test")
        assert data is None
        assert "500" in err

    @pytest.mark.asyncio
    async def test_request_connect_error_no_fallback(self):
        svc = BoltzSwapService()
        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with (
            patch("app.services.boltz_service.settings") as mock_settings,
            _patch_capped(side_effect=httpx.ConnectError("refused")),
        ):
            mock_settings.boltz_fallback_clearnet = False
            mock_settings.boltz_use_tor = False
            mock_settings.boltz_api_url = "https://api.boltz.exchange"
            mock_settings.lnd_tor_proxy = None
            data, err = await svc._request("GET", "/test")

        assert data is None
        assert "ConnectError" in err

    @pytest.mark.asyncio
    async def test_request_connect_error_with_fallback(self):
        svc = BoltzSwapService()
        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with (
            patch("app.services.boltz_service.settings") as mock_settings,
            _patch_capped(side_effect=httpx.ConnectError("tor failed")),
            patch.object(
                svc, "_request_clearnet", new_callable=AsyncMock, return_value=({"ok": True}, None)
            ) as mock_clearnet,
        ):
            mock_settings.boltz_fallback_clearnet = True
            mock_settings.boltz_use_tor = True
            mock_settings.boltz_onion_url = "http://boltz.onion"
            mock_settings.lnd_tor_proxy = "socks5://proxy:9050"
            data, err = await svc._request("GET", "/test")

        assert data == {"ok": True}
        mock_clearnet.assert_called_once()

    @pytest.mark.asyncio
    async def test_request_no_clearnet_fallback_for_address_bearing_call(self):
        """A call that opts out of clearnet fallback surfaces the Tor
        error rather than re-sending the (address-bearing) body over
        clearnet, so the withdrawal destination is never correlated with
        the wallet's public IP."""
        svc = BoltzSwapService()
        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with (
            patch("app.services.boltz_service.settings") as mock_settings,
            _patch_capped(side_effect=httpx.ConnectError("tor failed")),
            patch.object(svc, "_request_clearnet", new_callable=AsyncMock) as mock_clearnet,
        ):
            mock_settings.boltz_fallback_clearnet = True
            mock_settings.boltz_use_tor = True
            mock_settings.boltz_onion_url = "http://boltz.onion"
            mock_settings.lnd_tor_proxy = "socks5://proxy:9050"
            data, err = await svc._request(
                "POST",
                "/swap/reverse",
                {"claimAddress": "bc1qsecret"},
                allow_clearnet_fallback=False,
            )

        assert data is None
        assert err is not None
        mock_clearnet.assert_not_called()

    @pytest.mark.asyncio
    async def test_request_proxy_error_with_fallback(self):
        svc = BoltzSwapService()
        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with (
            patch("app.services.boltz_service.settings") as mock_settings,
            _patch_capped(side_effect=httpx.ProxyError("proxy down")),
            patch.object(svc, "_request_clearnet", new_callable=AsyncMock, return_value=({"ok": True}, None)),
        ):
            mock_settings.boltz_fallback_clearnet = True
            mock_settings.boltz_use_tor = True
            mock_settings.boltz_onion_url = "http://boltz.onion"
            mock_settings.lnd_tor_proxy = "socks5://proxy:9050"
            data, err = await svc._request("GET", "/test")

        assert data == {"ok": True}

    @pytest.mark.asyncio
    async def test_request_read_timeout_with_fallback(self):
        svc = BoltzSwapService()
        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with (
            patch("app.services.boltz_service.settings") as mock_settings,
            _patch_capped(side_effect=httpx.ReadTimeout("timeout")),
            patch.object(svc, "_request_clearnet", new_callable=AsyncMock, return_value=({"ok": True}, None)),
        ):
            mock_settings.boltz_fallback_clearnet = True
            mock_settings.boltz_use_tor = True
            mock_settings.boltz_onion_url = "http://boltz.onion"
            mock_settings.lnd_tor_proxy = "socks5://proxy:9050"
            data, err = await svc._request("GET", "/test")

        assert data == {"ok": True}

    @pytest.mark.asyncio
    async def test_request_generic_exception(self):
        svc = BoltzSwapService()
        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with _patch_capped(side_effect=RuntimeError("unexpected")):
            data, err = await svc._request("GET", "/test")
        assert data is None
        assert "unexpected" in err


class TestBoltzServiceRequestClearnet:
    """Tests for _request_clearnet fallback."""

    @pytest.mark.asyncio
    async def test_clearnet_success(self):
        svc = BoltzSwapService()
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "clearnet_ok"}
        mock_response.raise_for_status = MagicMock()

        with _patch_pin_noop(), _patch_capped(return_value=mock_response):
            data, err = await svc._request_clearnet("GET", "/test")

        assert data == {"status": "clearnet_ok"}
        assert err is None

    @pytest.mark.asyncio
    async def test_clearnet_http_error(self):
        svc = BoltzSwapService()
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.text = "unavailable"
        mock_resp.json.return_value = {"error": "maintenance"}

        with (
            _patch_pin_noop(),
            _patch_capped(side_effect=httpx.HTTPStatusError("err", request=MagicMock(), response=mock_resp)),
        ):
            data, err = await svc._request_clearnet("GET", "/test")

        assert data is None
        assert "503" in err

    @pytest.mark.asyncio
    async def test_clearnet_generic_exception(self):
        svc = BoltzSwapService()

        with _patch_pin_noop(), _patch_capped(side_effect=RuntimeError("dns failed")):
            data, err = await svc._request_clearnet("GET", "/test")

        assert data is None
        assert "dns failed" in err


class TestBoltzServiceClient:
    """Tests for _get_client and close."""

    @pytest.mark.asyncio
    async def test_get_client_creates_client(self):
        svc = BoltzSwapService()
        assert svc._client is None
        client = await svc._get_client()
        assert client is not None
        await svc.close()

    @pytest.mark.asyncio
    async def test_get_client_reuses_open_client(self):
        svc = BoltzSwapService()
        client1 = await svc._get_client()
        client2 = await svc._get_client()
        assert client1 is client2
        await svc.close()

    @pytest.mark.asyncio
    async def test_close_noop_when_none(self):
        svc = BoltzSwapService()
        await svc.close()  # should not raise

    @pytest.mark.asyncio
    async def test_close_closes_client(self):
        svc = BoltzSwapService()
        await svc._get_client()
        assert svc._client is not None
        await svc.close()
        assert svc._client is None

    @pytest.mark.asyncio
    async def test_get_client_recreates_after_close(self):
        svc = BoltzSwapService()
        client1 = await svc._get_client()
        await svc.close()
        client2 = await svc._get_client()
        assert client1 is not client2
        await svc.close()


class TestBoltzServiceProperties:
    """Tests for _boltz_url and _proxy properties."""

    def test_boltz_url_clearnet(self):
        svc = BoltzSwapService()
        with patch("app.services.boltz_service.settings") as mock_settings:
            mock_settings.boltz_use_tor = False
            mock_settings.boltz_api_url = "https://api.boltz.exchange"
            assert svc._boltz_url == "https://api.boltz.exchange"

    def test_boltz_url_tor(self):
        svc = BoltzSwapService()
        with patch("app.services.boltz_service.settings") as mock_settings:
            mock_settings.boltz_use_tor = True
            mock_settings.lnd_tor_proxy = "socks5://proxy:9050"
            mock_settings.boltz_onion_url = "http://boltz.onion"
            assert svc._boltz_url == "http://boltz.onion"

    def test_proxy_none_when_clearnet(self):
        svc = BoltzSwapService()
        with patch("app.services.boltz_service.settings") as mock_settings:
            mock_settings.boltz_use_tor = False
            assert svc._proxy is None

    def test_proxy_set_when_tor(self):
        svc = BoltzSwapService()
        with patch("app.services.boltz_service.settings") as mock_settings:
            mock_settings.boltz_use_tor = True
            mock_settings.lnd_tor_proxy = "socks5://proxy:9050"
            # Normalized to socks5h so the destination resolves at the proxy.
            assert svc._proxy == "socks5h://proxy:9050"


class TestGetSwapStatusFromBoltz:
    """Tests for get_swap_status_from_boltz."""

    @pytest.mark.asyncio
    async def test_success(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"status": "invoice.settled"}, None)):
            status, data, err = await svc.get_swap_status_from_boltz("swap-123")
        assert status == "invoice.settled"
        assert err is None

    @pytest.mark.asyncio
    async def test_error(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "not found")):
            status, data, err = await svc.get_swap_status_from_boltz("swap-123")
        assert status is None
        assert "not found" in err


class TestGetLockupTransaction:
    """Tests for get_lockup_transaction."""

    @pytest.mark.asyncio
    async def test_success(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"hex": "020000..."}, None)):
            tx_hex, err = await svc.get_lockup_transaction("swap-123")
        assert tx_hex == "020000..."
        assert err is None

    @pytest.mark.asyncio
    async def test_error(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "timeout")):
            tx_hex, err = await svc.get_lockup_transaction("swap-123")
        assert tx_hex is None
        assert "timeout" in err


# ─── _request / Tor / clearnet fallback ───────────────────────────────


class TestBoltzRequest:
    """Tests for the _request method with Tor/clearnet fallback."""

    @pytest.mark.asyncio
    async def test_request_success(self):
        svc = BoltzSwapService()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with _patch_capped(return_value=mock_response):
            data, err = await svc._request("GET", "/test")
        assert data == {"status": "ok"}
        assert err is None

    @pytest.mark.asyncio
    async def test_request_http_status_error(self):
        import httpx as _httpx

        svc = BoltzSwapService()
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "bad request"
        mock_response.json.return_value = {"error": "invalid amount"}

        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with _patch_capped(side_effect=_httpx.HTTPStatusError("err", request=MagicMock(), response=mock_response)):
            data, err = await svc._request("GET", "/test")
        assert data is None
        assert "400" in err
        assert "invalid amount" in err

    @pytest.mark.asyncio
    async def test_request_connect_error_no_fallback(self):
        import httpx as _httpx

        svc = BoltzSwapService()

        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with (
            patch("app.services.boltz_service.settings") as mock_settings,
            _patch_capped(side_effect=_httpx.ConnectError("conn refused")),
        ):
            mock_settings.boltz_fallback_clearnet = False
            mock_settings.boltz_use_tor = True
            mock_settings.boltz_api_url = "https://api.boltz.exchange/v2"
            mock_settings.boltz_onion_url = "http://boltz.onion/api/v2"
            mock_settings.lnd_tor_proxy = "socks5://tor:9050"
            data, err = await svc._request("GET", "/test")

        assert data is None
        assert "Connection failed" in err

    @pytest.mark.asyncio
    async def test_request_connect_error_with_clearnet_fallback(self):
        import httpx as _httpx

        svc = BoltzSwapService()

        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with (
            patch("app.services.boltz_service.settings") as mock_settings,
            _patch_capped(side_effect=_httpx.ConnectError("conn refused")),
            patch.object(
                svc, "_request_clearnet", new_callable=AsyncMock, return_value=({"ok": True}, None)
            ) as mock_clearnet,
        ):
            mock_settings.boltz_fallback_clearnet = True
            mock_settings.boltz_use_tor = True
            mock_settings.boltz_api_url = "https://api.boltz.exchange/v2"
            mock_settings.boltz_onion_url = "http://boltz.onion/api/v2"
            mock_settings.lnd_tor_proxy = "socks5://tor:9050"
            data, err = await svc._request("GET", "/test")

        assert data == {"ok": True}
        mock_clearnet.assert_called_once()

    @pytest.mark.asyncio
    async def test_request_clearnet_success(self):
        svc = BoltzSwapService()

        mock_response = MagicMock()
        mock_response.json.return_value = {"result": "ok"}
        mock_response.raise_for_status = MagicMock()

        with _patch_pin_noop(), _patch_capped(return_value=mock_response):
            data, err = await svc._request_clearnet("GET", "/test")

        assert data == {"result": "ok"}
        assert err is None

    @pytest.mark.asyncio
    async def test_request_clearnet_http_error(self):
        import httpx as _httpx

        svc = BoltzSwapService()

        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.text = "Service Unavailable"
        mock_response.json.side_effect = Exception("not json")

        with (
            _patch_pin_noop(),
            _patch_capped(side_effect=_httpx.HTTPStatusError("err", request=MagicMock(), response=mock_response)),
        ):
            data, err = await svc._request_clearnet("GET", "/test")

        assert data is None
        assert "503" in err

    @pytest.mark.asyncio
    async def test_request_generic_exception(self):
        svc = BoltzSwapService()

        mock_client = AsyncMock()
        mock_client.is_closed = False
        svc._client = mock_client

        with _patch_capped(side_effect=RuntimeError("unexpected")):
            data, err = await svc._request("GET", "/test")
        assert data is None
        assert "unexpected" in err


# ─── get_swap_status_from_boltz / get_lockup_transaction ──────────────


class TestBoltzHelpers:
    """Tests for helper methods that call the Boltz API."""

    @pytest.mark.asyncio
    async def test_get_swap_status_from_boltz_success(self):
        svc = BoltzSwapService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"status": "transaction.mempool", "extra": "data"}, None),
        ):
            status, data, err = await svc.get_swap_status_from_boltz("swap-123")
        assert status == "transaction.mempool"
        assert data["extra"] == "data"
        assert err is None

    @pytest.mark.asyncio
    async def test_get_swap_status_from_boltz_error(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "timeout")):
            status, data, err = await svc.get_swap_status_from_boltz("swap-123")
        assert status is None
        assert err == "timeout"

    @pytest.mark.asyncio
    async def test_get_swap_status_url_encodes_swap_id(self):
        """Defence-in-depth: a malicious Boltz id must not break out of the URL path."""
        svc = BoltzSwapService()
        captured = {}

        async def _capture(method, path, *args, **kwargs):
            captured["path"] = path
            return ({"status": "x"}, None)

        with patch.object(svc, "_request", side_effect=_capture):
            await svc.get_swap_status_from_boltz("../../etc/passwd")
        assert captured["path"] == "/swap/..%2F..%2Fetc%2Fpasswd"

    @pytest.mark.asyncio
    async def test_get_lockup_transaction_url_encodes_swap_id(self):
        svc = BoltzSwapService()
        captured = {}

        async def _capture(method, path, *args, **kwargs):
            captured["path"] = path
            return ({"hex": "00"}, None)

        with patch.object(svc, "_request", side_effect=_capture):
            await svc.get_lockup_transaction("a/b?c#d")
        assert captured["path"] == "/swap/reverse/a%2Fb%3Fc%23d/transaction"

    @pytest.mark.asyncio
    async def test_get_lockup_transaction_success(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"hex": "0200000001..."}, None)):
            tx_hex, err = await svc.get_lockup_transaction("swap-123")
        assert tx_hex == "0200000001..."
        assert err is None

    @pytest.mark.asyncio
    async def test_get_lockup_transaction_fallback_key(self):
        svc = BoltzSwapService()
        with patch.object(
            svc, "_request", new_callable=AsyncMock, return_value=({"transactionHex": "fallback_hex"}, None)
        ):
            tx_hex, err = await svc.get_lockup_transaction("swap-123")
        assert tx_hex == "fallback_hex"

    @pytest.mark.asyncio
    async def test_get_lockup_transaction_error(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "not found")):
            tx_hex, err = await svc.get_lockup_transaction("swap-123")
        assert tx_hex is None
        assert "not found" in err


class TestAdvanceSwapOnChainCompletionFallback:
    """Bug 6: if Boltz never reports ``invoice.settled`` but our
    claim transaction has confirmed on-chain, ``advance_swap`` should
    still promote the swap to ``COMPLETED``. Without this, a Boltz
    status-feed outage could leave a successful swap stuck in
    ``CLAIMED`` until max-retries marks it FAILED — even though the
    user already has the on-chain funds."""

    @pytest.mark.asyncio
    async def test_claimed_with_three_confirmations_completes(self, db_session):
        """Once the on-chain claim hits 3+ confirmations, the swap
        is considered complete regardless of Boltz's status feed."""
        swap = BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="boltz-stuck-claimed",
            status=SwapStatus.CLAIMED,
            boltz_status="transaction.confirmed",
            claim_txid="a" * 64,
            invoice_amount_sats=100_000,
            destination_address="bcrt1qtest",
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        svc = BoltzSwapService()
        # Boltz keeps returning the same non-terminal status — Boltz
        # is alive enough to respond but its settlement feed is
        # behind.
        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.confirmed", {}, None),
            ),
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.optional_confirmations",
                new_callable=AsyncMock,
                return_value={"confirmations": 3, "confirmed": True},
            ),
        ):
            updated, err = await svc.advance_swap(db_session, swap)

        assert err is None
        assert updated.status == SwapStatus.COMPLETED
        assert updated.completed_at is not None

    @pytest.mark.asyncio
    async def test_claimed_below_threshold_stays_claimed(self, db_session):
        """Two confirmations isn't enough — keep waiting."""
        swap = BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="boltz-only-two-confs",
            status=SwapStatus.CLAIMED,
            boltz_status="transaction.confirmed",
            claim_txid="b" * 64,
            invoice_amount_sats=100_000,
            destination_address="bcrt1qtest",
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        svc = BoltzSwapService()
        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.confirmed", {}, None),
            ),
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.optional_confirmations",
                new_callable=AsyncMock,
                return_value={"confirmations": 2, "confirmed": True},
            ),
        ):
            updated, err = await svc.advance_swap(db_session, swap)

        assert err is None
        # Still CLAIMED — wait for the third confirmation.
        assert updated.status == SwapStatus.CLAIMED
        assert updated.completed_at is None

    @pytest.mark.asyncio
    async def test_claimed_with_unavailable_confirmation_check_stays_claimed(self, db_session):
        """If Electrum isn't available, ``optional_confirmations``
        returns ``None`` — fall through and keep waiting on Boltz."""
        swap = BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="boltz-no-electrum",
            status=SwapStatus.CLAIMED,
            boltz_status="transaction.confirmed",
            claim_txid="c" * 64,
            invoice_amount_sats=100_000,
            destination_address="bcrt1qtest",
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        svc = BoltzSwapService()
        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.confirmed", {}, None),
            ),
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.optional_confirmations",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            updated, err = await svc.advance_swap(db_session, swap)

        # No error — the check is best-effort. Status unchanged.
        assert err is None
        assert updated.status == SwapStatus.CLAIMED

    @pytest.mark.asyncio
    async def test_invoice_settled_still_wins_over_confirmation_check(self, db_session):
        """The Boltz ``invoice.settled`` branch is the primary path;
        the on-chain confirmation fallback only triggers when Boltz
        is silent. Pin that ``invoice.settled`` short-circuits the
        defensive branch."""
        swap = BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="boltz-normal-settled",
            status=SwapStatus.CLAIMED,
            boltz_status="transaction.confirmed",
            claim_txid="d" * 64,
            invoice_amount_sats=100_000,
            destination_address="bcrt1qtest",
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        svc = BoltzSwapService()
        # If Boltz reports invoice.settled, we should complete via
        # the primary path WITHOUT hitting the optional_confirmations
        # call (no Electrum round-trip needed).
        confs_mock = AsyncMock(return_value=None)
        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("invoice.settled", {}, None),
            ),
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.optional_confirmations",
                confs_mock,
            ),
        ):
            updated, err = await svc.advance_swap(db_session, swap)

        assert err is None
        assert updated.status == SwapStatus.COMPLETED
        # The defensive on-chain confirmation branch must NOT have
        # been invoked — the primary settlement path took precedence.
        confs_mock.assert_not_called()


class TestAdvanceSwapConcurrentClaimRace:
    """Bug 7: ``advance_swap`` can be invoked concurrently by the
    user-driven ``process_boltz_swap`` retry path and the periodic
    ``recover_boltz_swaps`` task. Both could pass the earlier
    ``status == CLAIMING`` gate using the in-memory ``swap`` object
    loaded at the top of advance_swap. The defensive ``db.refresh``
    just before ``cooperative_claim`` narrows the race window."""

    @pytest.mark.asyncio
    async def test_aborts_when_another_worker_already_claimed(self, db_session):
        """Simulate the race: between the early gate and the refresh,
        another worker writes the claim_txid. The current worker
        sees the change after refresh and aborts without re-running
        ``cooperative_claim``."""
        swap_id = uuid4()
        swap = BoltzSwap(
            id=swap_id,
            api_key_id=uuid4(),
            boltz_swap_id="boltz-race-test",
            status=SwapStatus.CLAIMING,
            boltz_status="transaction.mempool",
            invoice_amount_sats=100_000,
            destination_address="bcrt1qtest",
            boltz_lockup_address="bcrt1qlockup",
            preimage_hex="encrypted_dummy_preimage",
            claim_private_key_hex="encrypted_dummy_key",
            claim_public_key_hex="04abcd",
            boltz_refund_public_key_hex="04ef00",
            boltz_swap_tree_json={},
            status_history=[],
        )
        db_session.add(swap)
        await db_session.commit()

        svc = BoltzSwapService()
        # Simulate the concurrent worker by patching ``db.execute``
        # so the FIRST SELECT-on-claim_txid (the pre-claim guard)
        # returns a value as if another transaction had committed
        # it. All other ``execute`` calls pass through unchanged so
        # the rest of advance_swap behaves normally. Setting up two
        # real sessions to drive this is awkward and tied to
        # SQLAlchemy's ``expire_on_commit`` defaults, so a targeted
        # patch is the cleanest unit-test shape.
        cooperative_claim_mock = AsyncMock()
        original_execute = db_session.execute
        winning_txid = "winning-other-worker-txid"
        select_calls = {"count": 0}

        async def _execute_intercept(stmt, *args, **kwargs):
            # The pre-claim guard SELECT is the first SELECT issued
            # specifically against ``BoltzSwap.claim_txid``. Intercept
            # that one shot; everything else (commits, audit reads,
            # etc.) flows through.
            sql_text = str(stmt).lower()
            if "claim_txid" in sql_text and "select" in sql_text:
                select_calls["count"] += 1
                if select_calls["count"] == 1:
                    result = MagicMock()
                    result.scalar = MagicMock(return_value=winning_txid)
                    return result
            return await original_execute(stmt, *args, **kwargs)

        # ``advance_swap`` calls ``mempool_fee_service.optional_verify_tx``
        # on the lockup id (defence-in-depth electrum probe) BEFORE
        # the race-abort guard runs. Without a mock here, that hits
        # the real electrum client — which may have been instantiated
        # in a different event loop by an earlier test in the suite,
        # leaving an unclosed StreamWriter for pytest's unraisable-
        # warning collector to attribute to this test's teardown.
        with (
            patch.object(
                svc,
                "get_swap_status_from_boltz",
                new_callable=AsyncMock,
                return_value=("transaction.mempool", {"transaction": {"id": "x" * 64}}, None),
            ),
            patch.object(
                svc,
                "get_lockup_transaction",
                new_callable=AsyncMock,
                return_value=("0200000001...", None),
            ),
            patch.object(svc, "cooperative_claim", cooperative_claim_mock),
            patch.object(db_session, "execute", side_effect=_execute_intercept),
            patch(
                "app.services.mempool_fee_service.mempool_fee_service.optional_verify_tx",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            updated, err = await svc.advance_swap(db_session, swap)

        # We must have bailed out before broadcasting our own claim.
        cooperative_claim_mock.assert_not_called()
        # And we must NOT have overwritten the other worker's txid;
        # the in-memory swap is promoted to match the DB.
        assert updated.claim_txid == winning_txid
        assert updated.status == SwapStatus.CLAIMED
        assert err is None
        # Sanity: the guard SELECT must have actually fired.
        assert select_calls["count"] >= 1


# ─── submarine swap primitive ──────────────────────────────


class TestGetSubmarinePairInfo:
    """``BoltzSwapService.get_submarine_pair_info`` is the on-chain →
    Lightning equivalent of ``get_reverse_pair_info``."""

    @pytest.mark.asyncio
    async def test_returns_parsed_info(self):
        svc = BoltzSwapService()
        boltz_response = {
            "BTC": {
                "BTC": {
                    "limits": {"minimal": 50000, "maximal": 25000000},
                    "fees": {"percentage": 0.1, "minerFees": {"lockup": 462}},
                    "hash": "sub-hash-123",
                }
            }
        }
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(boltz_response, None)):
            info, err = await svc.get_submarine_pair_info()

        assert err is None
        assert info["min"] == 50000
        assert info["max"] == 25000000
        assert info["fees_percentage"] == 0.1
        assert info["hash"] == "sub-hash-123"

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        svc = BoltzSwapService()
        cached = {"min": 50000, "max": 25000000, "fees_percentage": 0.1, "hash": "x"}
        svc._submarine_pair_info_cache = cached
        svc._submarine_pair_info_cached_at = datetime.now(timezone.utc)

        with patch.object(svc, "_request", new_callable=AsyncMock) as mock_req:
            info, err = await svc.get_submarine_pair_info()
            mock_req.assert_not_called()
        assert info == cached

    @pytest.mark.asyncio
    async def test_falls_back_to_stale_cache_on_error(self):
        svc = BoltzSwapService()
        stale = {"min": 50000, "max": 25000000, "fees_percentage": 0.1, "hash": "old"}
        svc._submarine_pair_info_stale = stale
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "timeout")):
            info, err = await svc.get_submarine_pair_info()
        assert err is None
        assert info["stale"] is True
        assert info["min"] == 50000


class TestCreateSubmarineSwap:
    """Tests for ``BoltzSwapService.create_submarine_swap`` — the
    public-API method that the Braiins-Deposit service uses
    for the on-chain → Lightning leg."""

    @pytest.fixture(autouse=True)
    def _stub_invoice_principal(self):
        """Map each test's placeholder invoice to the principal it
        represents so the principal-binding guard sees a matching amount.
        Real callers pass a genuine BOLT11 whose encoded amount equals
        ``invoice_amount_sats``; these unit tests use placeholders."""
        mapping = {
            "lnbcrt1m...": 1_000_000,
            "lnbcrt100u...": 10_000,
            "lnbcrt...": 500_000,
        }
        with patch(
            "app.core.bolt11.principal_sats_from_bolt11",
            side_effect=lambda inv: mapping.get(inv),
        ):
            yield

    @pytest.mark.asyncio
    async def test_success(self, db_session):
        svc = BoltzSwapService()
        pair_info = {
            "min": 25000,
            "max": 25000000,
            "fees_percentage": 0.1,
            "fees_miner_lockup": 462,
            "hash": "h1",
        }
        boltz_response = {
            "id": "boltz-submarine-123",
            "address": "bcrt1qlockup_for_submarine",
            "expectedAmount": 1_005_500,
            "swapTree": {"refundLeaf": {}},
            "timeoutBlockHeight": 900_000,
        }
        with (
            patch.object(
                svc,
                "get_submarine_pair_info",
                new_callable=AsyncMock,
                return_value=(pair_info, None),
            ),
            patch(
                "app.services.boltz_service._generate_keypair",
                return_value=("cc" * 32, "02" + "dd" * 32),
            ),
            patch(
                "app.services.boltz_service.verify_submarine_lockup_address",
                return_value=(True, "ok"),
            ),
            patch.object(
                svc,
                "_request",
                new_callable=AsyncMock,
                return_value=(boltz_response, None),
            ),
        ):
            swap, err = await svc.create_submarine_swap(
                db=db_session,
                api_key_id=uuid4(),
                invoice="lnbcrt1m...",
                invoice_amount_sats=1_000_000,
            )
        assert err is None
        assert swap is not None
        assert swap.boltz_swap_id == "boltz-submarine-123"
        assert swap.boltz_lockup_address == "bcrt1qlockup_for_submarine"
        assert swap.onchain_amount_sats == 1_005_500
        assert swap.invoice_amount_sats == 1_000_000
        assert swap.boltz_invoice == "lnbcrt1m..."
        assert swap.status == SwapStatus.CREATED

    @pytest.mark.asyncio
    async def test_rejects_unverified_lockup_address(self, db_session):
        """a lockup address that does not commit to the swap tree +
        our refund key is rejected BEFORE any swap row is persisted, so
        the deposit flow never funds an unrecoverable destination."""
        svc = BoltzSwapService()
        pair_info = {
            "min": 25000,
            "max": 25000000,
            "fees_percentage": 0.1,
            "fees_miner_lockup": 462,
            "hash": "h1",
        }
        boltz_response = {
            "id": "boltz-submarine-evil",
            "address": "bcrt1qattacker_controlled",
            "expectedAmount": 1_005_500,
            "swapTree": {"refundLeaf": {}},
            "timeoutBlockHeight": 900_000,
        }
        with (
            patch.object(
                svc,
                "get_submarine_pair_info",
                new_callable=AsyncMock,
                return_value=(pair_info, None),
            ),
            patch(
                "app.services.boltz_service._generate_keypair",
                return_value=("cc" * 32, "02" + "dd" * 32),
            ),
            patch(
                "app.services.boltz_service.verify_submarine_lockup_address",
                return_value=(False, "address_mismatch"),
            ),
            patch.object(
                svc,
                "_request",
                new_callable=AsyncMock,
                return_value=(boltz_response, None),
            ),
        ):
            swap, err = await svc.create_submarine_swap(
                db=db_session,
                api_key_id=uuid4(),
                invoice="lnbcrt1m...",
                invoice_amount_sats=1_000_000,
            )
        assert swap is None
        assert "verification" in (err or "")
        assert "address_mismatch" in (err or "")

    @pytest.mark.asyncio
    async def test_rejects_inflated_expected_amount(self, db_session):
        """an ``expectedAmount`` well above the locally-computed fair
        lockup (invoice + pct fee + miner fee + slack) is rejected even
        when the address itself verifies, so a hostile Boltz can't make
        us silently over-fund."""
        svc = BoltzSwapService()
        pair_info = {
            "min": 25000,
            "max": 25000000,
            "fees_percentage": 0.1,
            "fees_miner_lockup": 462,
            "hash": "h1",
        }
        boltz_response = {
            "id": "boltz-submarine-inflated",
            "address": "bcrt1qlockup_for_submarine",
            # invoice 1_000_000 → fair lockup ≈ 1_001_462, slack 10_000;
            # 2x is far above the bound.
            "expectedAmount": 2_000_000,
            "swapTree": {"refundLeaf": {}},
            "timeoutBlockHeight": 900_000,
        }
        with (
            patch.object(
                svc,
                "get_submarine_pair_info",
                new_callable=AsyncMock,
                return_value=(pair_info, None),
            ),
            patch(
                "app.services.boltz_service._generate_keypair",
                return_value=("cc" * 32, "02" + "dd" * 32),
            ),
            patch(
                "app.services.boltz_service.verify_submarine_lockup_address",
                return_value=(True, "ok"),
            ),
            patch.object(
                svc,
                "_request",
                new_callable=AsyncMock,
                return_value=(boltz_response, None),
            ),
        ):
            swap, err = await svc.create_submarine_swap(
                db=db_session,
                api_key_id=uuid4(),
                invoice="lnbcrt1m...",
                invoice_amount_sats=1_000_000,
            )
        assert swap is None
        assert "expectedAmount" in (err or "")

    @pytest.mark.asyncio
    async def test_amount_below_min_rejected(self, db_session):
        svc = BoltzSwapService()
        pair_info = {
            "min": 50000,
            "max": 25000000,
            "fees_percentage": 0.1,
            "fees_miner_lockup": 462,
            "hash": "",
        }
        with patch.object(
            svc,
            "get_submarine_pair_info",
            new_callable=AsyncMock,
            return_value=(pair_info, None),
        ):
            swap, err = await svc.create_submarine_swap(
                db=db_session,
                api_key_id=uuid4(),
                invoice="lnbcrt100u...",
                invoice_amount_sats=10_000,
            )
        assert swap is None
        assert "between" in (err or "")

    @pytest.mark.asyncio
    async def test_zero_amount_rejected(self, db_session):
        svc = BoltzSwapService()
        swap, err = await svc.create_submarine_swap(
            db=db_session,
            api_key_id=uuid4(),
            invoice="lnbcrt...",
            invoice_amount_sats=0,
        )
        assert swap is None
        assert "positive" in (err or "")

    @pytest.mark.asyncio
    async def test_boltz_response_missing_id(self, db_session):
        svc = BoltzSwapService()
        pair_info = {
            "min": 25000,
            "max": 25000000,
            "fees_percentage": 0.1,
            "fees_miner_lockup": 462,
            "hash": "",
        }
        with (
            patch.object(
                svc,
                "get_submarine_pair_info",
                new_callable=AsyncMock,
                return_value=(pair_info, None),
            ),
            patch(
                "app.services.boltz_service._generate_keypair",
                return_value=("cc" * 32, "02" + "dd" * 32),
            ),
            patch.object(
                svc,
                "_request",
                new_callable=AsyncMock,
                return_value=({"address": "x"}, None),  # missing 'id'!
            ),
        ):
            swap, err = await svc.create_submarine_swap(
                db=db_session,
                api_key_id=uuid4(),
                invoice="lnbcrt...",
                invoice_amount_sats=500_000,
            )
        assert swap is None
        assert "'id'" in (err or "")

    @pytest.mark.asyncio
    async def test_rejects_invoice_principal_mismatch(self, db_session):
        """The BOLT11 principal Boltz will settle must equal the requested
        amount; a divergence is refused before any swap is created."""
        svc = BoltzSwapService()
        # "lnbcrt1m..." maps to a 1_000_000-sat principal via the fixture.
        swap, err = await svc.create_submarine_swap(
            db=db_session,
            api_key_id=uuid4(),
            invoice="lnbcrt1m...",
            invoice_amount_sats=999_999,
        )
        assert swap is None
        assert "does not match" in (err or "")

    @pytest.mark.asyncio
    async def test_rejects_amountless_invoice(self, db_session):
        """An amountless invoice cannot be priced and is refused."""
        svc = BoltzSwapService()
        # An unmapped placeholder → stubbed principal is None.
        swap, err = await svc.create_submarine_swap(
            db=db_session,
            api_key_id=uuid4(),
            invoice="lnbcrt-amountless",
            invoice_amount_sats=500_000,
        )
        assert swap is None
        assert "does not encode an amount" in (err or "")


# ─── retry_cooperative_claim / retry_unilateral_claim ─────────────────


class TestRetryCooperativeClaim:
    """Tests for the operator-driven cooperative-claim retry helper."""

    def _make_swap(
        self,
        *,
        status=SwapStatus.CLAIMING,
        claim_txid=None,
        timeout_block_height=900_000,
    ):
        return BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="retry-coop",
            status=status,
            invoice_amount_sats=100_000,
            destination_address="bcrt1qdest",
            timeout_block_height=timeout_block_height,
            claim_txid=claim_txid,
            preimage_hex="encrypted_preimage",
            claim_private_key_hex="encrypted_key",
            boltz_refund_public_key_hex="02" + "ff" * 32,
            boltz_swap_tree_json={"claimLeaf": {}},
        )

    @pytest.mark.asyncio
    async def test_already_has_claim_txid_no_op(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap(claim_txid="existing_txid")
        db_session.add(swap)
        await db_session.commit()

        with patch.object(svc, "get_lockup_transaction", new_callable=AsyncMock) as mock_lockup:
            txid, err = await svc.retry_cooperative_claim(db_session, swap)
        assert err is None
        assert txid == "existing_txid"
        mock_lockup.assert_not_called()

    @pytest.mark.asyncio
    async def test_wrong_status_rejected(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.PAYING_INVOICE)
        db_session.add(swap)
        await db_session.commit()

        txid, err = await svc.retry_cooperative_claim(db_session, swap)
        assert txid is None
        assert "only valid" in err

    @pytest.mark.asyncio
    async def test_success_clears_error_and_advances(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap()
        swap.error_message = "Prior failure"
        swap.recovery_count = 2
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(
                svc,
                "get_lockup_transaction",
                new_callable=AsyncMock,
                return_value=("020000...", None),
            ),
            patch.object(
                svc,
                "cooperative_claim",
                new_callable=AsyncMock,
                return_value=("new_claim_txid", None),
            ),
        ):
            txid, err = await svc.retry_cooperative_claim(db_session, swap)

        assert err is None
        assert txid == "new_claim_txid"
        assert swap.claim_txid == "new_claim_txid"
        assert swap.status == SwapStatus.CLAIMED
        assert swap.error_message is None

    @pytest.mark.asyncio
    async def test_failure_increments_recovery_count(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap()
        swap.recovery_count = 1
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(
                svc,
                "get_lockup_transaction",
                new_callable=AsyncMock,
                return_value=("020000...", None),
            ),
            patch.object(
                svc,
                "cooperative_claim",
                new_callable=AsyncMock,
                return_value=(None, "Boltz refused"),
            ),
        ):
            txid, err = await svc.retry_cooperative_claim(db_session, swap)

        assert txid is None
        assert err == "Boltz refused"
        assert swap.recovery_count == 2
        assert swap.error_message == "Boltz refused"


class TestRetryUnilateralClaim:
    """Tests for the operator-driven unilateral-claim helper."""

    def _make_swap(
        self,
        *,
        status=SwapStatus.CLAIMING,
        claim_txid=None,
        timeout_block_height=800_000,
    ):
        return BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="retry-uni",
            status=status,
            invoice_amount_sats=100_000,
            destination_address="bcrt1qdest",
            timeout_block_height=timeout_block_height,
            claim_txid=claim_txid,
            preimage_hex="encrypted_preimage",
            claim_private_key_hex="encrypted_key",
            boltz_refund_public_key_hex="02" + "ff" * 32,
            boltz_swap_tree_json={"claimLeaf": {}},
        )

    @pytest.mark.asyncio
    async def test_refuses_when_timeout_not_passed(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap(timeout_block_height=800_100)
        db_session.add(swap)
        await db_session.commit()

        with patch.object(svc, "get_lockup_transaction", new_callable=AsyncMock) as mock_lockup:
            txid, err = await svc.retry_unilateral_claim(
                db_session,
                swap,
                btc_tip_height=800_000,
            )
        assert txid is None
        assert "timeout has not passed" in err
        mock_lockup.assert_not_called()

    @pytest.mark.asyncio
    async def test_success_post_timeout(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap(timeout_block_height=800_000)
        db_session.add(swap)
        await db_session.commit()

        with (
            patch.object(
                svc,
                "get_lockup_transaction",
                new_callable=AsyncMock,
                return_value=("020000...", None),
            ),
            patch.object(
                svc,
                "unilateral_claim",
                new_callable=AsyncMock,
                return_value=("uni_txid", None),
            ),
        ):
            txid, err = await svc.retry_unilateral_claim(
                db_session,
                swap,
                btc_tip_height=800_001,
            )

        assert err is None
        assert txid == "uni_txid"
        assert swap.status == SwapStatus.CLAIMED

    @pytest.mark.asyncio
    async def test_wrong_status_rejected(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap(status=SwapStatus.COMPLETED)
        db_session.add(swap)
        await db_session.commit()

        txid, err = await svc.retry_unilateral_claim(
            db_session,
            swap,
            btc_tip_height=900_000,
        )
        assert txid is None
        assert "only valid" in err

    @pytest.mark.asyncio
    async def test_missing_timeout_height_rejected(self, db_session):
        svc = BoltzSwapService()
        swap = self._make_swap(timeout_block_height=None)
        db_session.add(swap)
        await db_session.commit()

        txid, err = await svc.retry_unilateral_claim(
            db_session,
            swap,
            btc_tip_height=900_000,
        )
        assert txid is None
        assert "no recorded timeout" in err

    @pytest.mark.asyncio
    async def test_missing_tip_height_fails_closed(self, db_session):
        """a None chain tip can't verify the timeout has passed, so
        the unilateral claim must be refused (fail closed) rather than
        silently bypassing the timeout guard."""
        svc = BoltzSwapService()
        swap = self._make_swap(timeout_block_height=800_000)
        db_session.add(swap)
        await db_session.commit()

        with patch.object(svc, "get_lockup_transaction", new_callable=AsyncMock) as mock_lockup:
            txid, err = await svc.retry_unilateral_claim(
                db_session,
                swap,
                btc_tip_height=None,
            )
        assert txid is None
        assert "tip is unavailable" in err.lower()
        mock_lockup.assert_not_called()


class TestUnilateralRefundSubmarine:
    """Post-timeout unilateral (script-path) submarine refund.

    The timeout guard is safety-critical: broadcasting before the lockup's
    CHECKLOCKTIMEVERIFY would be rejected as non-final and waste fees, so the
    method must refuse until the chain tip passes the timeout.
    """

    def _make_swap(self, *, timeout_block_height=800_000):
        return BoltzSwap(
            id=uuid4(),
            api_key_id=uuid4(),
            boltz_swap_id="uni-refund",
            status=SwapStatus.FAILED,
            invoice_amount_sats=100_000,
            destination_address="bcrt1qdest",
            timeout_block_height=timeout_block_height,
            claim_private_key_hex="encrypted_key",
            claim_public_key_hex="02" + "ab" * 32,
            boltz_swap_tree_json={"refundLeaf": {}, "claimLeaf": {}},
        )

    @pytest.mark.asyncio
    async def test_refuses_before_timeout(self):
        svc = BoltzSwapService()
        swap = self._make_swap(timeout_block_height=800_100)
        with patch.object(svc, "get_submarine_lockup_transaction", new_callable=AsyncMock) as mock_lockup:
            txid, err = await svc.unilateral_refund_submarine(
                swap, refund_address="bcrt1qrefund", btc_tip_height=800_000
            )
        assert txid is None
        assert "timeout has not passed" in err
        mock_lockup.assert_not_called()

    @pytest.mark.asyncio
    async def test_refuses_when_tip_unavailable(self):
        svc = BoltzSwapService()
        swap = self._make_swap()
        with patch.object(svc, "get_submarine_lockup_transaction", new_callable=AsyncMock) as mock_lockup:
            txid, err = await svc.unilateral_refund_submarine(
                swap, refund_address="bcrt1qrefund", btc_tip_height=None
            )
        assert txid is None
        assert "tip is unavailable" in err.lower()
        mock_lockup.assert_not_called()

    @pytest.mark.asyncio
    async def test_refuses_when_no_timeout_height(self):
        svc = BoltzSwapService()
        swap = self._make_swap(timeout_block_height=None)
        with patch.object(svc, "get_submarine_lockup_transaction", new_callable=AsyncMock) as mock_lockup:
            txid, err = await svc.unilateral_refund_submarine(
                swap, refund_address="bcrt1qrefund", btc_tip_height=900_000
            )
        assert txid is None
        assert "no recorded timeout" in err
        mock_lockup.assert_not_called()

    @pytest.mark.asyncio
    async def test_broadcasts_post_timeout(self):
        svc = BoltzSwapService()
        swap = self._make_swap(timeout_block_height=800_000)
        with (
            patch.object(
                svc,
                "get_submarine_lockup_transaction",
                new_callable=AsyncMock,
                return_value=("020000...", None),
            ),
            patch("app.services.boltz_service.decrypt_field", return_value="aa" * 32),
            _mock_node_subprocess(returncode=0, stdout='{"txid": "refund_txid_abc"}'),
        ):
            txid, err = await svc.unilateral_refund_submarine(
                swap, refund_address="bcrt1qrefund", btc_tip_height=800_001
            )
        assert err is None
        assert txid == "refund_txid_abc"


class TestUnilateralClaimSubprocess:
    """Tests for the unilateral_claim subprocess wrapper."""

    def _make_swap(self):
        swap = MagicMock()
        swap.boltz_swap_id = "uni-test"
        swap.preimage_hex = "encrypted_preimage"
        swap.claim_private_key_hex = "encrypted_key"
        swap.boltz_refund_public_key_hex = "02" + "ff" * 32
        swap.boltz_swap_tree_json = {"claimLeaf": {}}
        swap.destination_address = "bcrt1qdest"
        return swap

    @pytest.mark.asyncio
    async def test_passes_mode_unilateral(self):
        svc = BoltzSwapService()
        swap = self._make_swap()
        captured = {}

        # Capture the stdin payload passed to communicate(). The
        # production path now drives the subprocess via
        # ``asyncio.create_subprocess_exec`` + ``proc.communicate``;
        # the mock here records what bytes would have been sent.
        proc = MagicMock()
        proc.returncode = 0
        proc.kill = MagicMock()
        proc.wait = AsyncMock(return_value=None)

        async def _capture(input=None):
            captured["input"] = input.decode() if input is not None else None
            return (
                b'{"event": "claim_broadcast_complete", "txid": "uni_abc", "mode": "unilateral"}\n',
                b"",
            )

        proc.communicate = AsyncMock(side_effect=_capture)
        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: f"decrypted_{x}"),
            patch(
                "app.services.boltz_service.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=proc),
            ),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.unilateral_claim(swap, "0200000001...")

        assert err is None
        assert txid == "uni_abc"
        payload = json.loads(captured["input"])
        assert payload["mode"] == "unilateral"

    @pytest.mark.asyncio
    async def test_nonzero_exit_returns_error(self):
        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: f"decrypted_{x}"),
            _mock_node_subprocess(returncode=1, stderr="script blew up"),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.unilateral_claim(swap, "0200000001...")

        assert txid is None
        assert "Unilateral claim script failed" in err

    @pytest.mark.asyncio
    async def test_missing_claim_script_surfaces_path(self):
        """When the claim script is absent the wrapper fails closed with
        the missing-path error rather than spawning Node."""
        svc = BoltzSwapService()
        swap = self._make_swap()

        spawn_mock = AsyncMock()
        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch(
                "app.services.boltz_service.asyncio.create_subprocess_exec",
                new=spawn_mock,
            ),
        ):
            mock_path.exists.return_value = False
            txid, err = await svc.unilateral_claim(swap, "0200000001...")

        assert txid is None
        assert "Claim script not found" in err
        spawn_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_txid_event_returns_error(self):
        """A stdout stream that never yields an event with a ``txid``
        is reported as a no-txid failure (not silently treated as a
        successful broadcast)."""
        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: f"decrypted_{x}"),
            _mock_node_subprocess(
                returncode=0,
                # Two well-formed JSON lines, neither carrying a txid.
                stdout='{"event": "progress"}\n{"event": "almost"}\n',
            ),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.unilateral_claim(swap, "0200000001...")

        assert txid is None
        assert "no txid" in err

    @pytest.mark.asyncio
    async def test_timeout_returns_error(self):
        import asyncio as _asyncio

        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            _mock_node_subprocess(communicate_side_effect=_asyncio.TimeoutError()),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.unilateral_claim(swap, "0200000001...")

        assert txid is None
        assert "timed out" in err

    @pytest.mark.asyncio
    async def test_node_not_found_returns_error(self):
        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.CLAIM_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            patch(
                "app.services.boltz_service.asyncio.create_subprocess_exec",
                new=AsyncMock(side_effect=FileNotFoundError),
            ),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.unilateral_claim(swap, "0200000001...")

        assert txid is None
        assert "Node.js not found" in err


# ─── claim-pubkey extraction from a persisted swap tree ────────────────


class TestExtractClaimPubkeyFromSwapTree:
    """``_extract_claim_pubkey_from_swap_tree`` parses Boltz's fixed
    submarine claim-leaf template to recover the x-only claim pubkey
    when a legacy row never persisted it. Malformed inputs must return
    ``None`` so the refund flow falls through to its other backfill
    sources rather than crashing or trusting a garbage key."""

    def _valid_claim_leaf_output(self) -> str:
        # a914 <20-byte hash> 88 20 <32-byte x-only pubkey> ac
        pubkey = "ab" * 32
        return "a9" + "14" + ("11" * 20) + "88" + "20" + pubkey + "ac"

    def test_extracts_pubkey_from_well_formed_template(self):
        from app.services.boltz_service import _extract_claim_pubkey_from_swap_tree

        tree = {"claimLeaf": {"output": self._valid_claim_leaf_output()}}
        assert _extract_claim_pubkey_from_swap_tree(tree) == "ab" * 32

    @pytest.mark.parametrize(
        "tree",
        [
            None,
            "not-a-dict",
            {},  # no claimLeaf
            {"claimLeaf": "not-a-dict"},
            {"claimLeaf": {}},  # no output
            {"claimLeaf": {"output": 1234}},  # output not a str
            {"claimLeaf": {"output": "zz"}},  # not valid hex
            {"claimLeaf": {"output": "a914" + "11" * 4}},  # wrong length
        ],
    )
    def test_returns_none_for_malformed_tree(self, tree):
        from app.services.boltz_service import _extract_claim_pubkey_from_swap_tree

        assert _extract_claim_pubkey_from_swap_tree(tree) is None

    def test_returns_none_when_opcodes_do_not_match_template(self):
        """A 57-byte script with the right length but wrong opcodes is
        rejected — the offset slice would otherwise yield a bogus key."""
        from app.services.boltz_service import _extract_claim_pubkey_from_swap_tree

        # Right length (57 bytes) but the leading opcode is OP_DUP, not
        # OP_HASH160.
        bad = "76" + "14" + ("11" * 20) + "88" + "20" + ("cd" * 32) + "ac"
        tree = {"claimLeaf": {"output": bad}}
        assert _extract_claim_pubkey_from_swap_tree(tree) is None


# ─── submarine lockup / swap-info helpers ──────────────────────────────


class TestGetSubmarineLockupTransaction:
    """``get_submarine_lockup_transaction`` hits the submarine-specific
    transaction endpoint and propagates the ``(None, error)`` contract."""

    @pytest.mark.asyncio
    async def test_success_prefers_hex_key(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"hex": "0200dead"}, None)):
            tx_hex, err = await svc.get_submarine_lockup_transaction("sub-1")
        assert tx_hex == "0200dead"
        assert err is None

    @pytest.mark.asyncio
    async def test_falls_back_to_transaction_hex_key(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=({"transactionHex": "0200beef"}, None)):
            tx_hex, err = await svc.get_submarine_lockup_transaction("sub-1")
        assert tx_hex == "0200beef"

    @pytest.mark.asyncio
    async def test_error_propagated(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "404 not found")):
            tx_hex, err = await svc.get_submarine_lockup_transaction("sub-1")
        assert tx_hex is None
        assert "404" in err

    @pytest.mark.asyncio
    async def test_url_encodes_swap_id(self):
        svc = BoltzSwapService()
        captured = {}

        async def _capture(method, path, *args, **kwargs):
            captured["path"] = path
            return ({"hex": "00"}, None)

        with patch.object(svc, "_request", side_effect=_capture):
            await svc.get_submarine_lockup_transaction("a/b")
        assert captured["path"] == "/swap/submarine/a%2Fb/transaction"


class TestGetSubmarineSwapInfo:
    """``get_submarine_swap_info`` fetches the type-agnostic status row
    used to backfill ``claimPublicKey`` for legacy rows."""

    @pytest.mark.asyncio
    async def test_success(self):
        svc = BoltzSwapService()
        with patch.object(
            svc, "_request", new_callable=AsyncMock, return_value=({"claimPublicKey": "02" + "aa" * 32}, None)
        ):
            info, err = await svc.get_submarine_swap_info("sub-1")
        assert err is None
        assert info["claimPublicKey"] == "02" + "aa" * 32

    @pytest.mark.asyncio
    async def test_error_propagated(self):
        svc = BoltzSwapService()
        with patch.object(svc, "_request", new_callable=AsyncMock, return_value=(None, "tor down")):
            info, err = await svc.get_submarine_swap_info("sub-1")
        assert info is None
        assert "tor down" in err


# ─── cooperative_refund_submarine ──────────────────────────────────────


class TestCooperativeRefundSubmarine:
    """The submarine refund path is the failure twin of the claim path:
    it returns locked on-chain funds to the wallet when the LN leg can't
    settle. Each precondition failure must fail closed with a specific
    error rather than spawning the refund subprocess against incomplete
    state."""

    def _make_swap(self, **overrides):
        swap = MagicMock()
        swap.boltz_swap_id = "refund-test"
        swap.claim_private_key_hex = "encrypted_refund_key"
        swap.claim_public_key_hex = "02" + "ee" * 32
        swap.boltz_swap_tree_json = {"claimLeaf": {"output": "a9"}}
        swap.boltz_claim_public_key_hex = "02" + "aa" * 32
        swap.timeout_block_height = 800_000
        swap.onchain_amount_sats = 100_000
        for k, v in overrides.items():
            setattr(swap, k, v)
        return swap

    @pytest.mark.asyncio
    async def test_missing_refund_script_fails_closed(self):
        svc = BoltzSwapService()
        swap = self._make_swap()
        with patch("app.services.boltz_service.REFUND_SCRIPT_PATH") as mock_path:
            mock_path.exists.return_value = False
            txid, err = await svc.cooperative_refund_submarine(swap, "bcrt1qrefund")
        assert txid is None
        assert "Refund script not found" in err

    @pytest.mark.asyncio
    async def test_missing_refund_private_key_rejected(self):
        svc = BoltzSwapService()
        swap = self._make_swap(claim_private_key_hex=None)
        with patch("app.services.boltz_service.REFUND_SCRIPT_PATH") as mock_path:
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_refund_submarine(swap, "bcrt1qrefund")
        assert txid is None
        assert "refund private key" in err

    @pytest.mark.asyncio
    async def test_missing_swap_tree_rejected(self):
        svc = BoltzSwapService()
        swap = self._make_swap(boltz_swap_tree_json=None)
        with patch("app.services.boltz_service.REFUND_SCRIPT_PATH") as mock_path:
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_refund_submarine(swap, "bcrt1qrefund")
        assert txid is None
        assert "swap tree" in err

    @pytest.mark.asyncio
    async def test_undeterminable_claim_pubkey_rejected(self):
        """When the claim pubkey is on neither the row nor Boltz's status
        endpoint, and can't be extracted from the swap tree, the refund
        is refused rather than signing against a missing key."""
        svc = BoltzSwapService()
        swap = self._make_swap(boltz_claim_public_key_hex=None)
        with (
            patch("app.services.boltz_service.REFUND_SCRIPT_PATH") as mock_path,
            patch.object(svc, "get_submarine_swap_info", new_callable=AsyncMock, return_value=({}, None)),
            patch(
                "app.services.boltz_service._extract_claim_pubkey_from_swap_tree",
                return_value=None,
            ),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_refund_submarine(swap, "bcrt1qrefund")
        assert txid is None
        assert "claim public key" in err

    @pytest.mark.asyncio
    async def test_lockup_fetch_failure_rejected(self):
        """The refund needs the lockup tx to rebuild its input; a fetch
        failure surfaces the lookup error and never spawns the script."""
        svc = BoltzSwapService()
        swap = self._make_swap()
        spawn_mock = AsyncMock()
        with (
            patch("app.services.boltz_service.REFUND_SCRIPT_PATH") as mock_path,
            patch.object(
                svc,
                "get_submarine_lockup_transaction",
                new_callable=AsyncMock,
                return_value=(None, "lockup 404"),
            ),
            patch(
                "app.services.boltz_service.asyncio.create_subprocess_exec",
                new=spawn_mock,
            ),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_refund_submarine(swap, "bcrt1qrefund")
        assert txid is None
        assert "lockup 404" in err
        spawn_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_backfills_claim_pubkey_from_boltz_status(self):
        """When the row lacks the Boltz claim pubkey, the refund flow
        recovers it from the type-agnostic status endpoint and proceeds
        to broadcast."""
        svc = BoltzSwapService()
        swap = self._make_swap(boltz_claim_public_key_hex=None)

        with (
            patch("app.services.boltz_service.REFUND_SCRIPT_PATH") as mock_path,
            patch.object(
                svc,
                "get_submarine_swap_info",
                new_callable=AsyncMock,
                return_value=({"claimPublicKey": "02" + "bc" * 32}, None),
            ),
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            _mock_node_subprocess(returncode=0, stdout='{"txid": "refund_via_status"}\n'),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_refund_submarine(
                swap,
                "bcrt1qrefund",
                lockup_tx_hex="0200lockup",
            )
        assert err is None
        assert txid == "refund_via_status"

    @pytest.mark.asyncio
    async def test_clamps_forwarded_feerate_into_refund_input(self):
        """A caller-supplied feerate is clamped to the on-chain ceiling
        before it reaches the refund subprocess, so an untrusted feerate
        can't inflate the miner fee and burn the locked funds."""
        svc = BoltzSwapService()
        swap = self._make_swap()
        captured = {}

        proc = MagicMock()
        proc.returncode = 0
        proc.kill = MagicMock()
        proc.wait = AsyncMock(return_value=None)

        async def _capture(input=None):
            captured["input"] = input.decode() if input is not None else None
            return (b'{"txid": "refund_clamped"}\n', b"")

        proc.communicate = AsyncMock(side_effect=_capture)
        with (
            patch("app.services.boltz_service.REFUND_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            patch(
                "app.services.chain.backend.clamp_feerate_sat_per_vb",
                return_value=42.0,
            ),
            patch(
                "app.services.boltz_service.asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=proc),
            ),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_refund_submarine(
                swap,
                "bcrt1qrefund",
                lockup_tx_hex="0200lockup",
                fee_rate_sat_vb=10_000.0,
            )
        assert err is None
        assert txid == "refund_clamped"
        payload = json.loads(captured["input"])
        assert payload["feeRate"] == 42.0

    @pytest.mark.asyncio
    async def test_success_returns_broadcast_txid(self):
        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.REFUND_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: f"decrypted_{x}"),
            _mock_node_subprocess(
                returncode=0,
                stdout='{"event": "progress"}\n{"txid": "refund_txid_abc"}\n',
            ),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_refund_submarine(
                swap,
                "bcrt1qrefund",
                lockup_tx_hex="0200lockup",
            )
        assert err is None
        assert txid == "refund_txid_abc"

    @pytest.mark.asyncio
    async def test_script_nonzero_exit_returns_error(self):
        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.REFUND_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            _mock_node_subprocess(returncode=2, stderr="musig2 aggregation failed"),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_refund_submarine(
                swap,
                "bcrt1qrefund",
                lockup_tx_hex="0200lockup",
            )
        assert txid is None
        assert "Refund script failed (exit 2)" in err

    @pytest.mark.asyncio
    async def test_script_no_txid_returns_error(self):
        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.REFUND_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            _mock_node_subprocess(returncode=0, stdout='{"result": "ok"}\n'),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_refund_submarine(
                swap,
                "bcrt1qrefund",
                lockup_tx_hex="0200lockup",
            )
        assert txid is None
        assert "no txid" in err

    @pytest.mark.asyncio
    async def test_script_timeout_returns_error(self):
        import asyncio as _asyncio

        svc = BoltzSwapService()
        swap = self._make_swap()

        with (
            patch("app.services.boltz_service.REFUND_SCRIPT_PATH") as mock_path,
            patch("app.services.boltz_service.decrypt_field", side_effect=lambda x: x),
            _mock_node_subprocess(communicate_side_effect=_asyncio.TimeoutError()),
        ):
            mock_path.exists.return_value = True
            txid, err = await svc.cooperative_refund_submarine(
                swap,
                "bcrt1qrefund",
                lockup_tx_hex="0200lockup",
            )
        assert txid is None
        assert "timed out" in err


# ─── _verify_claim_output cross-check ──────────────────────────────────


class TestVerifyClaimOutput:
    """``_verify_claim_output`` is the defence-in-depth guard that a
    broadcast claim pays the swap's own destination. It must fail open
    (skip) when the expected script can't be derived, and fail closed
    (return an error) when the validator rejects the tx."""

    def _make_swap(self):
        swap = MagicMock()
        swap.boltz_swap_id = "verify-test"
        swap.destination_address = "bcrt1qdest"
        swap.onchain_amount_sats = 99_000
        return swap

    @pytest.mark.asyncio
    async def test_skips_when_script_underivable(self):
        """An address the backend can't convert to a scriptPubKey skips
        the cross-check (returns None) rather than failing a good claim."""
        svc = BoltzSwapService()
        swap = self._make_swap()
        with patch(
            "app.services.chain.electrum_protocol.address_to_script_pubkey",
            side_effect=ValueError("bad address"),
        ):
            result = await svc._verify_claim_output(swap, "0200claim")
        assert result is None

    @pytest.mark.asyncio
    async def test_passes_when_validator_accepts(self):
        svc = BoltzSwapService()
        swap = self._make_swap()
        with (
            patch(
                "app.services.chain.electrum_protocol.address_to_script_pubkey",
                return_value=bytes.fromhex("0014" + "11" * 20),
            ),
            patch(
                "app.services.anonymize.cooperative_claim.validate_cooperative_claim_tx",
                return_value=None,
            ),
        ):
            result = await svc._verify_claim_output(swap, "0200claim")
        assert result is None

    @pytest.mark.asyncio
    async def test_rejects_misaddressed_claim_and_alerts(self):
        """A claim whose output script doesn't match the destination is
        rejected with a validation error, and an operator alert fires."""
        from app.services.anonymize.cooperative_claim import ClaimTxValidationError

        svc = BoltzSwapService()
        swap = self._make_swap()
        alert = AsyncMock()
        with (
            patch(
                "app.services.chain.electrum_protocol.address_to_script_pubkey",
                return_value=bytes.fromhex("0014" + "11" * 20),
            ),
            patch(
                "app.services.anonymize.cooperative_claim.validate_cooperative_claim_tx",
                side_effect=ClaimTxValidationError("output script mismatch"),
            ),
            patch("app.services.alert_service.send_alert", alert),
        ):
            result = await svc._verify_claim_output(swap, "0200claim")
        assert result is not None
        assert "claim output validation failed" in result
        assert "output script mismatch" in result
        alert.assert_awaited_once()
