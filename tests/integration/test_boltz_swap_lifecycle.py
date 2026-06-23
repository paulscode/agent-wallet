# SPDX-License-Identifier: MIT
"""
End-to-end lifecycle test for a Boltz reverse swap (the cold-storage
withdrawal path), driven through the real ``BoltzSwapService.advance_swap``
state machine against an in-process fake Boltz API.

What this exercises for real: the HTTP layer (``_request`` → ``request_capped``
→ retry/breaker → injected MockTransport), the swap status state machine,
the cooperative-claim flow (minus the Node crypto subprocess, which is
stubbed), DB persistence, UTXO auto-labelling, and the model's
``claim_broadcast_at`` auto-stamp event. The Node crypto and the
create-time cryptographic gates (preimage binding, lockup-address
verification) are covered by their own unit tests; this test owns the
multi-step lifecycle the unit tests can't.
"""

import json
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.models.boltz_swap import SwapStatus
from app.models.utxo_label import UtxoLabel
from app.services.boltz_service import BoltzSwapService
from tests._fake_boltz import FakeBoltzServer
from tests.helpers import make_boltz_swap

_CLAIM_TXID = "ce" * 32


@pytest.fixture(autouse=True)
def _reset_boltz_breaker():
    """The Boltz circuit breaker is a module-level singleton; reset it around
    each test so the 5xx-failure case can't open it for an unrelated test
    under parallel/randomized ordering."""
    import app.services.boltz_service as bs

    bs._BOLTZ_BREAKER.reset()
    yield
    bs._BOLTZ_BREAKER.reset()


@pytest_asyncio.fixture
async def service(monkeypatch):
    svc = BoltzSwapService()
    fake = FakeBoltzServer()
    fake.install(svc, monkeypatch)
    svc._fake = fake  # handle for the test body
    yield svc
    # Close the injected MockTransport client so it isn't GC'd unclosed
    # (an unclosed httpx.AsyncClient warning would surface as an error on
    # an unrelated test under the suite's warnings-as-errors policy).
    await svc.close()


def _stub_node_claim(monkeypatch, *, returncode: int = 0, txid: str | None = _CLAIM_TXID):
    """Stub the Node claim subprocess (no real secp256k1 / boltz-core)."""

    def _fake_run(cmd, *args, **kwargs):
        result = MagicMock()
        result.returncode = returncode
        # Emit only a txid (no txHex) so the claim-output cross-check is
        # skipped — building a real spendable tx is the Node script's job.
        result.stdout = json.dumps({"txid": txid}) if returncode == 0 else ""
        result.stderr = "" if returncode == 0 else "claim script boom"
        return result

    monkeypatch.setattr("subprocess.run", _fake_run)


async def _persist(db, swap):
    db.add(swap)
    await db.commit()
    return swap


@pytest.mark.asyncio
async def test_reverse_swap_claims_then_completes(service, db_session, monkeypatch):
    """mempool → CLAIMING → CLAIMED (claim broadcast) → COMPLETED."""
    _stub_node_claim(monkeypatch)
    swap = await _persist(db_session, make_boltz_swap(status=SwapStatus.INVOICE_PAID))

    # Phase 1: Boltz reports the on-chain lockup is in the mempool.
    service._fake.swap_status = "transaction.mempool"
    swap, err = await service.advance_swap(db_session, swap)
    assert err is None
    assert swap.status == SwapStatus.CLAIMED
    assert swap.claim_txid == _CLAIM_TXID
    assert swap.claim_broadcast_at is not None  # auto-stamped on first txid

    # The claim swept to a single output that gets auto-labelled.
    label = (await db_session.execute(select(UtxoLabel).where(UtxoLabel.txid == _CLAIM_TXID))).scalar_one_or_none()
    assert label is not None and label.vout == 0

    # Phase 2: Boltz settles the hold invoice → swap completes.
    service._fake.swap_status = "invoice.settled"
    swap, err = await service.advance_swap(db_session, swap)
    assert err is None
    assert swap.status == SwapStatus.COMPLETED
    assert swap.completed_at is not None

    # The lifecycle hit Boltz for status and the lockup transaction.
    assert any(p.endswith("/transaction") for p in service._fake.paths("GET"))


@pytest.mark.asyncio
async def test_reverse_swap_refunded_marks_refunded(service, db_session):
    """Boltz refunding the on-chain lockup → REFUNDED (LN HTLC auto-cancels)."""
    swap = await _persist(db_session, make_boltz_swap(status=SwapStatus.INVOICE_PAID))

    service._fake.swap_status = "transaction.refunded"
    swap, err = await service.advance_swap(db_session, swap)
    assert err is None
    assert swap.status == SwapStatus.REFUNDED
    assert swap.completed_at is not None
    assert swap.error_message and "refunded" in swap.error_message.lower()


@pytest.mark.asyncio
async def test_reverse_swap_terminal_failure(service, db_session):
    """A Boltz-reported expiry is a terminal FAILED state."""
    swap = await _persist(db_session, make_boltz_swap(status=SwapStatus.INVOICE_PAID))

    service._fake.swap_status = "swap.expired"
    swap, err = await service.advance_swap(db_session, swap)
    assert err is None
    assert swap.status == SwapStatus.FAILED
    assert swap.completed_at is not None


@pytest.mark.asyncio
async def test_failed_claim_keeps_claiming_and_counts_retry(service, db_session, monkeypatch):
    """A failing claim subprocess leaves the swap recoverable: still
    CLAIMING, no txid, with the retry counter advanced."""
    _stub_node_claim(monkeypatch, returncode=1, txid=None)
    swap = await _persist(db_session, make_boltz_swap(status=SwapStatus.INVOICE_PAID))

    service._fake.swap_status = "transaction.mempool"
    swap, err = await service.advance_swap(db_session, swap)

    assert err is not None  # the claim error is surfaced
    assert swap.status == SwapStatus.CLAIMING
    assert swap.claim_txid is None
    assert swap.recovery_count == 1


@pytest.mark.asyncio
async def test_status_query_failure_is_surfaced(service, db_session):
    """If the Boltz status query fails, advance_swap reports the error and
    does not advance the swap."""
    service._fake.force_status_code = 500
    swap = await _persist(db_session, make_boltz_swap(status=SwapStatus.INVOICE_PAID))

    swap, err = await service.advance_swap(db_session, swap)
    assert err is not None
    assert swap.status == SwapStatus.INVOICE_PAID  # unchanged
