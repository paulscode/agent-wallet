# SPDX-License-Identifier: MIT
"""Tests for the BOLT 12 LND settlement subscriber and its shared
transport-recovery helpers.

These pin the settlement-projection and stream-decode branches that
are only reached when a real LND stream feeds the subscriber:

* ``app/services/bolt12/settlement_subscriber.py`` — the
  ``_stream_once`` decode loop, ``_handle_invoice_update`` state
  routing, ``_project_settled`` idempotency / preimage handling, and
  the disabled / polling-summary entrypoints.
* ``app/services/bolt12/subscriber_recovery.py`` — the NEWNYM
  throttle gate and the warmup-probe timeout / exception fallbacks.

They drive the code with in-process fakes (a scripted httpx stream, a
patched ``get_db_context`` returning the test session) rather than a
live LND or Tor control port, so they stay deterministic under
``pytest -n auto``. Spec vectors under ``tests/vectors/bolt12`` are
not reused here: those encode BOLT 12 *wire* objects (offers /
signatures), whereas the subscriber's inputs are LND REST invoice
dicts, which have no spec-vector counterpart.
"""

from __future__ import annotations

import asyncio
import base64
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.bolt12_invoice import (
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceRequest,
    Bolt12InvoiceRequestStatus,
    Bolt12InvoiceStatus,
)


@pytest.fixture(autouse=True)
def _disable_warmup_and_onion_detect(monkeypatch):
    """The supervisor loop does a warmup probe + onion-only detect
    before each reconnect, both of which call ``get_info`` with a
    10 s timeout. Tests here stub ``_stream_once`` directly and must
    not block on those probes — disable them globally for this file
    (their own behaviour is pinned elsewhere)."""
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_warmup_probe_enabled",
        False,
    )

    async def _no_auto_polling():
        return False

    monkeypatch.setattr(
        "app.services.bolt12.onion_only_detect.detect_onion_only",
        _no_auto_polling,
    )


async def _seed_open(db, payment_hash_hex):
    """Seed a minimal OPEN inbound BOLT 12 invoice and return it."""
    invreq = Bolt12InvoiceRequest(
        api_key_id=uuid4(),
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=1000,
    )
    db.add(invreq)
    await db.flush()
    inv = Bolt12Invoice(
        api_key_id=invreq.api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=1000,
        payment_hash_hex=payment_hash_hex,
        status=Bolt12InvoiceStatus.OPEN,
    )
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    return inv


# ── Entrypoint guards ────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_settlement_subscriber_disabled_returns_immediately(monkeypatch):
    """The kill switch must short-circuit before any stream/probe
    work — a disabled subscriber returns without touching LND."""
    from app.services.bolt12 import settlement_subscriber as sub

    monkeypatch.setattr(sub.settings, "bolt12_settlement_subscriber_enabled", False)

    async def _explode(*args, **kwargs):
        raise AssertionError("disabled subscriber must not open a stream")

    monkeypatch.setattr(sub, "_stream_once", _explode)

    stop = asyncio.Event()
    await asyncio.wait_for(sub.run_settlement_subscriber(stop), timeout=2.0)


@pytest.mark.asyncio
async def test_polling_mode_logs_summary_when_rows_change(monkeypatch, caplog):
    """Polling mode logs the reconcile summary only when there is
    something to report (paid or errored > 0). Pins the conditional
    summary log so a silent tick stays silent."""
    from app.services.bolt12 import settlement_subscriber as sub
    from app.services.bolt12.reconcile import ReconcileSummary

    monkeypatch.setattr(sub.settings, "bolt12_settlement_subscriber_enabled", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_polling_mode_enabled", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_polling_interval_s", 1)

    @asynccontextmanager
    async def _noop_ctx():
        yield object()

    monkeypatch.setattr(sub, "get_db_context", _noop_ctx)

    stop = asyncio.Event()

    async def _reconcile(db, lnd):
        # Report a paid row so the summary-log branch is taken, then
        # stop the loop on the next stop_event check.
        stop.set()
        return ReconcileSummary(scanned=3, paid=2, expired=1, failed=0, errored=0)

    import app.services.bolt12.reconcile as reconcile_mod

    monkeypatch.setattr(reconcile_mod, "reconcile_open_invoices", _reconcile)

    caplog.set_level("INFO", logger=sub.logger.name)
    await asyncio.wait_for(sub.run_settlement_subscriber(stop), timeout=2.0)

    summary_logs = [r.getMessage() for r in caplog.records if "paid=2" in r.getMessage()]
    assert summary_logs, "expected the polling summary log when paid>0"


@pytest.mark.asyncio
async def test_polling_mode_continues_after_tick_exception(monkeypatch, caplog):
    """A reconcile exception during a polling tick must be swallowed
    and logged, not propagated — the loop keeps polling."""
    from app.services.bolt12 import settlement_subscriber as sub

    monkeypatch.setattr(sub.settings, "bolt12_settlement_subscriber_enabled", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_polling_mode_enabled", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_polling_interval_s", 1)

    @asynccontextmanager
    async def _noop_ctx():
        yield object()

    monkeypatch.setattr(sub, "get_db_context", _noop_ctx)

    stop = asyncio.Event()
    calls = {"n": 0}

    async def _reconcile(db, lnd):
        calls["n"] += 1
        stop.set()
        raise RuntimeError("simulated reconcile blip")

    import app.services.bolt12.reconcile as reconcile_mod

    monkeypatch.setattr(reconcile_mod, "reconcile_open_invoices", _reconcile)

    caplog.set_level("ERROR", logger=sub.logger.name)
    # Must not raise even though the tick raised.
    await asyncio.wait_for(sub.run_settlement_subscriber(stop), timeout=2.0)

    assert calls["n"] == 1
    assert any("tick failed" in r.getMessage() for r in caplog.records)


# ── _handle_invoice_update routing ───────────────────────────


@pytest.mark.asyncio
async def test_handle_invoice_update_non_settled_returns_index_without_projecting(monkeypatch):
    """OPEN/ACCEPTED states are owned by the reconcile loop. The
    handler must return the update's settle_index for resume-point
    tracking but must NOT attempt a SETTLED projection."""
    from app.services.bolt12 import settlement_subscriber as sub

    async def _explode(*args, **kwargs):
        raise AssertionError("non-SETTLED update must not project")

    monkeypatch.setattr(sub, "_project_settled", _explode)

    idx = await sub._handle_invoice_update({"state": "OPEN", "settle_index": "7"})
    assert idx == 7


@pytest.mark.asyncio
async def test_handle_invoice_update_settled_without_r_hash_returns_index(monkeypatch):
    """A SETTLED update missing an ``r_hash`` can't be matched to a
    row; the handler returns the index and skips projection."""
    from app.services.bolt12 import settlement_subscriber as sub

    async def _explode(*args, **kwargs):
        raise AssertionError("missing r_hash must not reach projection")

    monkeypatch.setattr(sub, "_project_settled", _explode)

    idx = await sub._handle_invoice_update({"state": "SETTLED", "settle_index": "9", "r_hash": ""})
    assert idx == 9


@pytest.mark.asyncio
async def test_handle_invoice_update_non_numeric_index_falls_back_to_zero(monkeypatch):
    """A non-numeric ``settle_index`` must not crash the decode loop;
    it falls back to 0 so the resume pointer never regresses on a
    malformed field."""
    from app.services.bolt12 import settlement_subscriber as sub

    async def _explode(*args, **kwargs):
        raise AssertionError("OPEN update must not project")

    monkeypatch.setattr(sub, "_project_settled", _explode)

    idx = await sub._handle_invoice_update({"state": "OPEN", "settle_index": "not-a-number"})
    assert idx == 0


@pytest.mark.asyncio
async def test_handle_invoice_update_swallows_projection_error(monkeypatch, caplog):
    """If projection raises, the handler still returns the index so
    the stream advances — a projection bug must not wedge the
    resume pointer or kill the stream."""
    from app.services.bolt12 import settlement_subscriber as sub

    raw = bytes.fromhex("ab" * 32)

    async def _boom(invoice, r_hash_hex):
        raise RuntimeError("projection exploded")

    monkeypatch.setattr(sub, "_project_settled", _boom)

    caplog.set_level("ERROR", logger=sub.logger.name)
    idx = await sub._handle_invoice_update(
        {
            "state": "SETTLED",
            "settle_index": "12",
            "r_hash": base64.b64encode(raw).decode(),
        }
    )
    assert idx == 12
    assert any("failed to project SETTLED" in r.getMessage() for r in caplog.records)


# ── _stream_once decode loop ─────────────────────────────────


class _FakeStreamResponse:
    """Async-context-manager double for an httpx streaming response.

    Yields the scripted ``lines`` from ``aiter_lines`` and reports
    ``status_code``. ``aread`` returns the error body for the >=400
    branch.
    """

    def __init__(self, *, status_code=200, lines=None, body=b""):
        self.status_code = status_code
        self._lines = lines or []
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def aread(self):
        return self._body

    async def aiter_lines(self):
        for line in self._lines:
            yield line


class _FakeClient:
    """httpx client double whose ``stream`` returns a scripted
    response. Records the params it was called with."""

    def __init__(self, response):
        self._response = response
        self.stream_calls = []

    def stream(self, method, url, **kwargs):
        self.stream_calls.append((method, url, kwargs))
        return self._response


@pytest.mark.asyncio
async def test_stream_once_projects_settled_and_returns_highest_index(monkeypatch, db_session):
    """The decode loop must ignore non-JSON / blank lines, project the
    SETTLED row, and return the highest ``settle_index`` seen so the
    supervisor can resume from it."""
    from app.services.bolt12 import settlement_subscriber as sub

    inv = await _seed_open(db_session, "ab" * 32)

    raw = bytes.fromhex("ab" * 32)
    lines = [
        "",  # blank → skipped
        "not-json",  # JSONDecodeError → skipped
        json.dumps({"result": {"state": "OPEN", "settle_index": "4"}}),
        json.dumps(
            {
                "result": {
                    "state": "SETTLED",
                    "settle_index": "6",
                    "r_hash": base64.b64encode(raw).decode(),
                    "settle_date": 1_700_000_000,
                    "r_preimage": "cd" * 32,
                }
            }
        ),
    ]
    client = _FakeClient(_FakeStreamResponse(lines=lines))

    async def _get_client():
        return client

    monkeypatch.setattr(sub.lnd_service, "_get_client", _get_client)

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    stop = asyncio.Event()
    last_index = await sub._stream_once(0, stop)

    assert last_index == 6
    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.PAID
    # Index 0 means no resume param was sent.
    assert client.stream_calls[0][2]["params"] is None


@pytest.mark.asyncio
async def test_stream_once_passes_resume_index_param(monkeypatch, db_session):
    """A non-zero starting index must be sent as the ``settle_index``
    query param so LND resumes after the gap."""
    from app.services.bolt12 import settlement_subscriber as sub

    client = _FakeClient(_FakeStreamResponse(lines=[]))

    async def _get_client():
        return client

    monkeypatch.setattr(sub.lnd_service, "_get_client", _get_client)

    stop = asyncio.Event()
    result = await sub._stream_once(42, stop)

    assert result == 42  # no settlements arrived → unchanged
    assert client.stream_calls[0][2]["params"] == {"settle_index": "42"}


@pytest.mark.asyncio
async def test_stream_once_raises_on_http_error_status(monkeypatch):
    """A >=400 status from the subscribe endpoint must raise so the
    supervisor backs off; the error body is surfaced in the message."""
    from app.services.bolt12 import settlement_subscriber as sub

    client = _FakeClient(_FakeStreamResponse(status_code=503, body=b"upstream unavailable"))

    async def _get_client():
        return client

    monkeypatch.setattr(sub.lnd_service, "_get_client", _get_client)

    stop = asyncio.Event()
    with pytest.raises(RuntimeError, match="503"):
        await sub._stream_once(0, stop)


@pytest.mark.asyncio
async def test_stream_once_raises_on_envelope_error(monkeypatch):
    """A gRPC-gateway ``{"error": {...}}`` envelope must raise with
    the embedded message so the supervisor treats it as a stream
    failure, not a silent skip."""
    from app.services.bolt12 import settlement_subscriber as sub

    lines = [json.dumps({"error": {"message": "lnd is shutting down"}})]
    client = _FakeClient(_FakeStreamResponse(lines=lines))

    async def _get_client():
        return client

    monkeypatch.setattr(sub.lnd_service, "_get_client", _get_client)

    stop = asyncio.Event()
    with pytest.raises(RuntimeError, match="lnd is shutting down"):
        await sub._stream_once(0, stop)


@pytest.mark.asyncio
async def test_stream_once_breaks_when_stop_event_set(monkeypatch):
    """A set ``stop_event`` must break the decode loop before
    processing further lines so shutdown is prompt."""
    from app.services.bolt12 import settlement_subscriber as sub

    stop = asyncio.Event()
    stop.set()

    processed = {"n": 0}

    async def _count(_invoice):
        processed["n"] += 1
        return 1

    monkeypatch.setattr(sub, "_handle_invoice_update", _count)

    lines = [json.dumps({"result": {"state": "SETTLED", "settle_index": "1"}})]
    client = _FakeClient(_FakeStreamResponse(lines=lines))

    async def _get_client():
        return client

    monkeypatch.setattr(sub.lnd_service, "_get_client", _get_client)

    result = await sub._stream_once(0, stop)
    assert result == 0
    assert processed["n"] == 0


# ── _project_settled branches ────────────────────────────────


@pytest.mark.asyncio
async def test_project_settled_uses_now_when_settle_date_missing(monkeypatch, db_session):
    """When LND omits / zeroes ``settle_date``, ``paid_at`` falls
    back to the current time so the row never lands with a null
    paid timestamp."""
    from app.services.bolt12 import settlement_subscriber as sub

    inv = await _seed_open(db_session, "1a" * 32)

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    before = datetime.now(timezone.utc)
    await sub._project_settled({"state": "SETTLED", "settle_date": "0"}, "1a" * 32)

    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.PAID
    assert refreshed.paid_at is not None
    assert refreshed.paid_at >= before.replace(microsecond=0)


@pytest.mark.asyncio
async def test_project_settled_non_numeric_settle_date_falls_back_to_now(monkeypatch, db_session):
    """A garbage ``settle_date`` must not crash projection — it falls
    back to wall-clock now."""
    from app.services.bolt12 import settlement_subscriber as sub

    inv = await _seed_open(db_session, "2b" * 32)

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    await sub._project_settled({"state": "SETTLED", "settle_date": "bogus"}, "2b" * 32)

    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.PAID
    assert refreshed.paid_at is not None


@pytest.mark.asyncio
async def test_project_settled_persists_decoded_preimage(monkeypatch, db_session):
    """A base64 ``r_preimage`` is normalised to hex and stored
    (encrypted) on a row that had none. Verifies the preimage round-
    trips to the persisted, decryptable field."""
    from app.core.encryption import decrypt_field
    from app.services.bolt12 import settlement_subscriber as sub

    inv = await _seed_open(db_session, "3c" * 32)
    assert inv.encrypted_preimage is None

    raw_preimage = bytes.fromhex("cd" * 32)

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    await sub._project_settled(
        {
            "state": "SETTLED",
            "settle_date": 1_700_000_000,
            "r_preimage": base64.b64encode(raw_preimage).decode(),
        },
        "3c" * 32,
    )

    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.encrypted_preimage is not None
    assert decrypt_field(refreshed.encrypted_preimage) == "cd" * 32


@pytest.mark.asyncio
async def test_project_settled_feeds_path_breaker_success(monkeypatch, db_session):
    """On a successful settle, every intro in the row's
    ``blinded_paths_summary`` gets its breaker closed — mirrors the
    reconcile loop so streamed settles also reset path health."""
    from app.services.bolt12 import settlement_subscriber as sub
    from app.services.bolt12.path_postprocess import get_path_breaker

    monkeypatch.setattr("app.core.config.settings.bolt12_path_breaker_enabled", True)
    monkeypatch.setattr("app.core.config.settings.bolt12_path_breaker_failures_to_open", 1)

    breaker = get_path_breaker()
    breaker.reset_for_tests()
    intro = "02" + "aa" * 32
    breaker.record_failure(intro)
    assert breaker.is_open(intro)

    inv = await _seed_open(db_session, "4d" * 32)
    inv.blinded_paths_summary = {"paths": [{"intro_pubkey": intro, "real_hops": 1}]}
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    await sub._project_settled({"state": "SETTLED", "settle_date": 1_700_000_000}, "4d" * 32)

    assert not breaker.is_open(intro)
    breaker.reset_for_tests()


@pytest.mark.asyncio
async def test_project_settled_rolls_back_on_commit_failure(monkeypatch, db_session):
    """A commit failure must be caught, rolled back, and returned
    cleanly (no raise) so the stream survives a transient DB error."""
    from sqlalchemy.exc import SQLAlchemyError

    from app.services.bolt12 import settlement_subscriber as sub

    await _seed_open(db_session, "5e" * 32)

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    rolled_back = {"n": 0}
    real_rollback = db_session.rollback

    async def _flaky_commit():
        raise SQLAlchemyError("simulated commit failure")

    async def _track_rollback():
        rolled_back["n"] += 1
        return await real_rollback()

    monkeypatch.setattr(db_session, "commit", _flaky_commit)
    monkeypatch.setattr(db_session, "rollback", _track_rollback)

    # Must not raise — the commit failure is caught internally.
    await sub._project_settled(
        {"state": "SETTLED", "settle_date": 1_700_000_000, "r_preimage": "cd" * 32},
        "5e" * 32,
    )

    # Recovery path ran: the failed commit was followed by a rollback
    # so the session is left clean rather than wedged in a pending-
    # rollback state.
    assert rolled_back["n"] == 1
    # A fresh read confirms the row never reached PAID — the failed
    # settle did not persist a half-applied state.
    refreshed = (
        await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.payment_hash_hex == "5e" * 32))
    ).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.OPEN


# ── _normalize_preimage / _extract_r_hash_hex edge cases ─────


def test_normalize_preimage_accepts_hex_and_base64_and_passthrough():
    """Hex stays hex; base64 decodes to hex; an undecodable token is
    returned verbatim (last-resort passthrough)."""
    from app.services.bolt12.settlement_subscriber import _normalize_preimage

    raw = bytes.fromhex("ab" * 32)
    assert _normalize_preimage("AB" * 32) == "ab" * 32  # hex path, lowercased
    assert _normalize_preimage(base64.b64encode(raw).decode()) == "ab" * 32
    # Neither valid hex nor valid base64 → returned unchanged.
    assert _normalize_preimage("!!notb64!!") == "!!notb64!!"
    # A 64-char string that fails the hex parse (non-hex digits)
    # falls through to the base64 branch and is decoded there.
    assert _normalize_preimage("z" * 64) == base64.b64decode("z" * 64).hex()


def test_extract_r_hash_hex_rejects_non_hex_64_char_string():
    """A 64-char string that isn't valid hex must fall through to the
    base64 branch and be rejected, returning None."""
    from app.services.bolt12.settlement_subscriber import _extract_r_hash_hex

    # 64 'z' chars: len==64 but not hex, and not valid base64 either.
    assert _extract_r_hash_hex({"r_hash": "z" * 64}) is None


# ── subscriber_recovery: NEWNYM throttle ─────────────────────


@pytest.mark.asyncio
async def test_try_newnym_throttled_skips_within_interval(monkeypatch):
    """Two NEWNYM attempts inside the min-interval window must fire
    the signal at most once — the second is throttled and returns
    False without touching Tor again."""
    from app.services.bolt12 import subscriber_recovery as rec

    rec._reset_throttle_for_tests()
    monkeypatch.setattr("app.core.config.settings.tor_newnym_min_interval_s", 9999.0)

    signal_calls = {"n": 0}

    async def _fake_signal(timeout_s=3.0):
        signal_calls["n"] += 1
        return True, None

    monkeypatch.setattr("app.services.anonymize.tor.signal_newnym", _fake_signal)

    first = await rec.try_newnym_throttled()
    second = await rec.try_newnym_throttled()

    assert first is True
    assert second is False
    assert signal_calls["n"] == 1
    rec._reset_throttle_for_tests()


@pytest.mark.asyncio
async def test_try_newnym_throttled_returns_false_when_tor_rejects(monkeypatch):
    """When the Tor control port rejects the signal, the helper
    returns False (and doesn't raise) so callers can log it."""
    from app.services.bolt12 import subscriber_recovery as rec

    rec._reset_throttle_for_tests()
    monkeypatch.setattr("app.core.config.settings.tor_newnym_min_interval_s", 10.0)

    async def _reject(timeout_s=3.0):
        return False, "control port busy"

    monkeypatch.setattr("app.services.anonymize.tor.signal_newnym", _reject)

    assert await rec.try_newnym_throttled() is False
    rec._reset_throttle_for_tests()


@pytest.mark.asyncio
async def test_try_newnym_throttled_returns_false_when_helper_raises(monkeypatch):
    """An exception inside the signal helper is swallowed — NEWNYM is
    best-effort and must never propagate into the recovery loop."""
    from app.services.bolt12 import subscriber_recovery as rec

    rec._reset_throttle_for_tests()
    monkeypatch.setattr("app.core.config.settings.tor_newnym_min_interval_s", 10.0)

    async def _raise(timeout_s=3.0):
        raise RuntimeError("tor control unreachable")

    monkeypatch.setattr("app.services.anonymize.tor.signal_newnym", _raise)

    assert await rec.try_newnym_throttled() is False
    rec._reset_throttle_for_tests()


def test_newnym_min_interval_never_below_tor_floor(monkeypatch):
    """Even if an operator sets a sub-10s interval, the helper floors
    it at 10 s (Tor's own NEWNYM rate limit)."""
    from app.services.bolt12 import subscriber_recovery as rec

    monkeypatch.setattr("app.core.config.settings.tor_newnym_min_interval_s", 1.0)
    assert rec._newnym_min_interval_s() == 10.0


# ── subscriber_recovery: warmup probe error paths ────────────


@pytest.mark.asyncio
async def test_warmup_probe_returns_false_on_timeout(monkeypatch):
    """A hung ``get_info`` must surface as a timed-out probe (False),
    not block the reconnect loop past the internal 10 s bound."""
    from app.services.bolt12 import subscriber_recovery as rec

    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_warmup_probe_enabled",
        True,
    )

    async def _hang():
        # Sleep well past the probe's internal 10 s wait_for bound;
        # the probe should give up and report a timeout long before
        # this resolves.
        await asyncio.sleep(3600)
        return object(), None

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_info", _hang)
    # Shrink the wait_for so the test stays fast while still
    # exercising the TimeoutError branch.
    real_wait_for = asyncio.wait_for

    async def _short_wait_for(aw, timeout):
        return await real_wait_for(aw, timeout=0.05)

    monkeypatch.setattr(asyncio, "wait_for", _short_wait_for)

    assert await rec.warmup_probe(subscriber_name="settlement") is False


@pytest.mark.asyncio
async def test_warmup_probe_returns_false_when_get_info_raises(monkeypatch):
    """An unexpected exception from ``get_info`` is caught and
    reported as a failed probe, not propagated."""
    from app.services.bolt12 import subscriber_recovery as rec

    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_warmup_probe_enabled",
        True,
    )

    async def _raise():
        raise RuntimeError("pool exhausted")

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_info", _raise)

    assert await rec.warmup_probe(subscriber_name="settlement") is False


@pytest.mark.asyncio
async def test_warmup_probe_returns_true_on_success(monkeypatch):
    """A clean ``get_info`` (info, no error) means the pooled
    connection is alive → probe succeeds."""
    from app.services.bolt12 import subscriber_recovery as rec

    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_warmup_probe_enabled",
        True,
    )

    async def _ok():
        return object(), None

    monkeypatch.setattr("app.services.lnd_service.lnd_service.get_info", _ok)

    assert await rec.warmup_probe(subscriber_name="settlement") is True
