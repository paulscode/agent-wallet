# SPDX-License-Identifier: MIT
"""Tests for ``Bolt12Service`` orchestration.

The orchestrator is exercised against a fake ``Bolt12GatewayClient``
that lets us control inbound delivery deterministically. The real
gateway client is exercised separately (``test_bolt12_gateway_client``).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import pytest

from app.services.bolt12 import (
    Bolt12Codec,
    Bolt12Service,
    Bolt12ServiceError,
    Bolt12String,
    InboundInvreqContext,
    InvoiceRequestTimeoutError,
    InvreqBuildContext,
    ReplyPathSpec,
    SendDestination,
    SendPlan,
    ServiceNotRunningError,
    TLVRecord,
    encode,
)
from app.services.bolt12.orchestrator import TLV_INVOICE, TLV_INVOICE_REQUEST
from app.services.bolt12_gateway import (
    GatewayUnavailableError,
    InboundMessage,
)

# ── fake gateway ─────────────────────────────────────────────────


@dataclass
class _SendCall:
    payload: bytes
    payload_tlv_type: int
    direct_node_id: bytes | None
    blinded_path: bytes | None
    reply_path: bytes | None


@dataclass
class _CreatePathCall:
    candidates: tuple[bytes, ...]
    dummy_hops: int
    context: bytes


class FakeGateway:
    """Stand-in for ``Bolt12GatewayClient``.

    Records every call and exposes an inbound-message queue that
    tests pump directly. The orchestrator only depends on the
    duck-typed surface (connect / close / create_blinded_path /
    send_onion_message / stream_inbound), so a Protocol match isn't
    necessary.
    """

    def __init__(self) -> None:
        self.send_calls: list[_SendCall] = []
        self.create_calls: list[_CreatePathCall] = []
        self.connected = False
        self.closed = False
        self.inbound: asyncio.Queue[InboundMessage] = asyncio.Queue()
        # When set, create_blinded_path returns this exact bytes;
        # otherwise it returns ``b"reply_path:<context-hex>"``.
        self.reply_path_override: bytes | None = None
        # When set, send_onion_message raises this.
        self.send_error: Exception | None = None

    async def connect(self) -> None:
        self.connected = True

    async def close(self) -> None:
        self.closed = True

    async def create_blinded_path(
        self,
        *,
        introduction_node_candidates,
        dummy_hops: int = 0,
        context: bytes = b"",
    ) -> bytes:
        candidates = tuple(bytes(c) for c in introduction_node_candidates)
        self.create_calls.append(_CreatePathCall(candidates, dummy_hops, context))
        if self.reply_path_override is not None:
            return self.reply_path_override
        return b"reply_path:" + context.hex().encode()

    async def send_onion_message(
        self,
        *,
        payload: bytes,
        payload_tlv_type: int,
        direct_node_id: bytes | None = None,
        blinded_path: bytes | None = None,
        reply_path: bytes | None = None,
    ) -> None:
        if self.send_error is not None:
            raise self.send_error
        self.send_calls.append(_SendCall(payload, payload_tlv_type, direct_node_id, blinded_path, reply_path))

    @asynccontextmanager
    async def stream_inbound(self) -> AsyncIterator[AsyncIterator[InboundMessage]]:
        async def gen() -> AsyncIterator[InboundMessage]:
            while True:
                msg = await self.inbound.get()
                yield msg

        yield gen()


# ── helpers ──────────────────────────────────────────────────────


def _minimal_offer() -> Bolt12String:
    """Return a syntactically-valid offer with a single TLV."""
    # The first valid vector from the spec: just an offer_issuer_id.
    return Bolt12String(
        hrp="lno",
        records=(
            TLVRecord(
                type=22,
                value=bytes.fromhex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"),
            ),
        ),
    )


def _send_plan_blinded(blinded_path: bytes = b"path-to-merchant") -> SendPlan:
    return SendPlan(
        destination=SendDestination(blinded_path=blinded_path),
        reply_path=ReplyPathSpec(
            introduction_node_candidates=(b"\x02" + b"\xab" * 32,),
            dummy_hops=2,
        ),
    )


def _send_plan_direct(node_id: bytes | None = None) -> SendPlan:
    return SendPlan(
        destination=SendDestination(direct_node_id=node_id or b"\x02" + b"\xcd" * 32),
        reply_path=ReplyPathSpec(introduction_node_candidates=(b"\x02" + b"\xab" * 32,)),
    )


async def _build_invreq(ctx: InvreqBuildContext) -> bytes:
    """Test invreq builder — concatenates a marker + the reply_path."""
    return b"INVREQ:" + ctx.reply_path


# ── dataclass invariants ─────────────────────────────────────────


def test_send_destination_requires_exactly_one() -> None:
    with pytest.raises(ValueError):
        SendDestination()
    with pytest.raises(ValueError):
        SendDestination(direct_node_id=b"\x02" + b"\x00" * 32, blinded_path=b"\x01")
    with pytest.raises(ValueError):
        SendDestination(direct_node_id=b"\x02")  # too short


def test_reply_path_spec_validates() -> None:
    ok = (b"\x02" + b"\x33" * 32,)
    with pytest.raises(ValueError):
        ReplyPathSpec(introduction_node_candidates=())
    with pytest.raises(ValueError):
        ReplyPathSpec(introduction_node_candidates=(b"\x02",))
    with pytest.raises(ValueError):
        ReplyPathSpec(introduction_node_candidates=ok, dummy_hops=8)


# ── lifecycle ────────────────────────────────────────────────────


async def test_start_stop_idempotent() -> None:
    gw = FakeGateway()
    svc = Bolt12Service(gw)  # type: ignore[arg-type]
    await svc.start()
    assert gw.connected
    await svc.start()  # second is a no-op
    await svc.stop()
    assert gw.closed
    await svc.stop()  # idempotent


async def test_request_invoice_requires_running() -> None:
    gw = FakeGateway()
    svc = Bolt12Service(gw)  # type: ignore[arg-type]
    with pytest.raises(ServiceNotRunningError):
        await svc.request_invoice(
            offer=_minimal_offer(),
            build_invreq=_build_invreq,
            destination=lambda _: _send_plan_direct(),
        )


async def test_async_context_manager() -> None:
    gw = FakeGateway()
    async with Bolt12Service(gw) as svc:  # type: ignore[arg-type]
        assert gw.connected
        assert svc.pending_request_count == 0
    assert gw.closed


# ── sender flow ──────────────────────────────────────────────────


async def test_request_invoice_happy_path() -> None:
    gw = FakeGateway()
    async with Bolt12Service(gw) as svc:  # type: ignore[arg-type]
        offer = _minimal_offer()

        async def race() -> bytes:
            return await svc.request_invoice(
                offer=offer,
                build_invreq=_build_invreq,
                destination=lambda _: _send_plan_blinded(),
                amount_msat=12345,
            )

        # Kick the sender, then deliver the matching invoice once we
        # know the correlation token.
        task = asyncio.create_task(race())

        # Wait for create_blinded_path to record its call so we know
        # the correlation token.
        for _ in range(50):
            if gw.create_calls:
                break
            await asyncio.sleep(0)
        assert gw.create_calls, "orchestrator did not call create_blinded_path"
        ctx = gw.create_calls[0].context
        assert len(ctx) == 16  # _CORRELATION_BYTES

        # Wait for the send to happen too.
        for _ in range(50):
            if gw.send_calls:
                break
            await asyncio.sleep(0)
        sent = gw.send_calls[0]
        assert sent.payload_tlv_type == TLV_INVOICE_REQUEST
        assert sent.blinded_path == b"path-to-merchant"
        assert sent.reply_path is not None
        assert sent.payload == b"INVREQ:" + sent.reply_path

        # Deliver the invoice with the matching correlation.
        await gw.inbound.put(
            InboundMessage(
                recv_id="r1",
                payload_tlv_type=TLV_INVOICE,
                payload=b"INVOICE-BYTES",
                reply_path=None,
                received_at_ms=0,
                inbound_context=ctx,
            )
        )

        result = await asyncio.wait_for(task, timeout=2.0)
        assert result == b"INVOICE-BYTES"
        assert svc.pending_request_count == 0


async def test_request_invoice_timeout() -> None:
    gw = FakeGateway()
    async with Bolt12Service(gw) as svc:  # type: ignore[arg-type]
        with pytest.raises(InvoiceRequestTimeoutError):
            await svc.request_invoice(
                offer=_minimal_offer(),
                build_invreq=_build_invreq,
                destination=lambda _: _send_plan_direct(),
                timeout_seconds=0.05,
            )
        assert svc.pending_request_count == 0


async def test_request_invoice_propagates_send_error() -> None:
    gw = FakeGateway()
    gw.send_error = GatewayUnavailableError("simulated peer down")
    async with Bolt12Service(gw) as svc:  # type: ignore[arg-type]
        with pytest.raises(GatewayUnavailableError, match="peer down"):
            await svc.request_invoice(
                offer=_minimal_offer(),
                build_invreq=_build_invreq,
                destination=lambda _: _send_plan_direct(),
            )
        assert svc.pending_request_count == 0


async def test_unmatched_invoice_is_dropped() -> None:
    gw = FakeGateway()
    async with Bolt12Service(gw) as svc:  # type: ignore[arg-type]
        # No pending request → orchestrator must log+drop, not crash.
        await gw.inbound.put(
            InboundMessage(
                recv_id="rogue",
                payload_tlv_type=TLV_INVOICE,
                payload=b"x",
                reply_path=None,
                received_at_ms=0,
                inbound_context=b"\x99" * 16,
            )
        )
        # Allow the dispatcher to drain.
        await asyncio.sleep(0.05)
        assert svc.pending_request_count == 0


async def test_stop_fails_pending_requests() -> None:
    gw = FakeGateway()
    svc = Bolt12Service(gw)  # type: ignore[arg-type]
    await svc.start()

    async def slow() -> bytes:
        return await svc.request_invoice(
            offer=_minimal_offer(),
            build_invreq=_build_invreq,
            destination=lambda _: _send_plan_direct(),
            timeout_seconds=10.0,
        )

    task = asyncio.create_task(slow())
    # Wait until the request is actually pending.
    for _ in range(50):
        if svc.pending_request_count == 1:
            break
        await asyncio.sleep(0)

    await svc.stop()

    with pytest.raises(GatewayUnavailableError):
        await task


# ── receiver flow ────────────────────────────────────────────────


async def test_inbound_invreq_invokes_responder_and_replies() -> None:
    received: list[InboundInvreqContext] = []

    async def responder(ctx: InboundInvreqContext) -> bytes | None:
        received.append(ctx)
        return b"INVOICE-FOR:" + ctx.invreq_payload

    gw = FakeGateway()
    async with Bolt12Service(gw, invoice_responder=responder):  # type: ignore[arg-type]
        await gw.inbound.put(
            InboundMessage(
                recv_id="rcv-1",
                payload_tlv_type=TLV_INVOICE_REQUEST,
                payload=b"REMOTE-INVREQ",
                reply_path=b"path-back",
                received_at_ms=0,
                inbound_context=b"",
            )
        )
        # Allow dispatch.
        for _ in range(50):
            if gw.send_calls:
                break
            await asyncio.sleep(0)

    assert len(received) == 1
    assert received[0].invreq_payload == b"REMOTE-INVREQ"
    assert received[0].reply_path == b"path-back"

    assert len(gw.send_calls) == 1
    sent = gw.send_calls[0]
    assert sent.payload == b"INVOICE-FOR:REMOTE-INVREQ"
    assert sent.payload_tlv_type == TLV_INVOICE
    assert sent.blinded_path == b"path-back"


async def test_inbound_invreq_dropped_when_no_responder() -> None:
    gw = FakeGateway()
    async with Bolt12Service(gw):  # type: ignore[arg-type]
        await gw.inbound.put(
            InboundMessage(
                recv_id="rcv-2",
                payload_tlv_type=TLV_INVOICE_REQUEST,
                payload=b"x",
                reply_path=b"path",
                received_at_ms=0,
                inbound_context=b"",
            )
        )
        await asyncio.sleep(0.05)
    assert gw.send_calls == []


async def test_inbound_invreq_dropped_when_no_reply_path() -> None:
    called = False

    async def responder(ctx: InboundInvreqContext) -> bytes | None:
        nonlocal called
        called = True
        return b"x"

    gw = FakeGateway()
    async with Bolt12Service(gw, invoice_responder=responder):  # type: ignore[arg-type]
        await gw.inbound.put(
            InboundMessage(
                recv_id="rcv-3",
                payload_tlv_type=TLV_INVOICE_REQUEST,
                payload=b"x",
                reply_path=None,
                received_at_ms=0,
                inbound_context=b"",
            )
        )
        await asyncio.sleep(0.05)
    assert not called
    assert gw.send_calls == []


async def test_responder_returning_none_does_not_send() -> None:
    async def decline(ctx: InboundInvreqContext) -> bytes | None:
        return None

    gw = FakeGateway()
    async with Bolt12Service(gw, invoice_responder=decline):  # type: ignore[arg-type]
        await gw.inbound.put(
            InboundMessage(
                recv_id="rcv-4",
                payload_tlv_type=TLV_INVOICE_REQUEST,
                payload=b"x",
                reply_path=b"path",
                received_at_ms=0,
                inbound_context=b"",
            )
        )
        await asyncio.sleep(0.05)
    assert gw.send_calls == []


async def test_unknown_payload_type_is_dropped() -> None:
    gw = FakeGateway()
    async with Bolt12Service(gw):  # type: ignore[arg-type]
        await gw.inbound.put(
            InboundMessage(
                recv_id="other",
                payload_tlv_type=999,
                payload=b"x",
                reply_path=None,
                received_at_ms=0,
                inbound_context=b"",
            )
        )
        await asyncio.sleep(0.05)
    assert gw.send_calls == []


# ── codec interop sanity ─────────────────────────────────────────


def test_orchestrator_uses_real_codec_decoded_offers() -> None:
    """The orchestrator's public API takes a real ``Bolt12String``.

    Confirm that what comes out of ``decode()`` is the same shape the
    orchestrator expects so the sender-flow doesn't need any
    intermediate adapter layer.
    """
    offer = _minimal_offer()
    s = encode(offer)
    rt = Bolt12Codec.decode(s)
    assert rt.hrp == "lno"
    assert tuple(rt.records) == offer.records


# ── hardening: pending-capacity cap ─────────────────────────


async def test_request_invoice_rejects_when_pending_cap_reached(monkeypatch) -> None:
    """Once ``bolt12_max_pending_requests`` slots are in use, new
    senders must fail fast with ``Bolt12ServiceError`` rather than
    queueing — this is the back-pressure guard against in-flight
    flooding.
    """
    from app.core import config as _cfg

    # Cap the in-flight map at 1 so the second sender is rejected.
    monkeypatch.setattr(_cfg.settings, "bolt12_max_pending_requests", 1)

    gw = FakeGateway()
    async with Bolt12Service(gw) as svc:  # type: ignore[arg-type]
        # First sender: kick it off and wait until it's parked
        # (its future has been registered in ``_pending``).
        async def _slow() -> bytes:
            return await svc.request_invoice(
                offer=_minimal_offer(),
                build_invreq=_build_invreq,
                destination=lambda _: _send_plan_direct(),
                timeout_seconds=10.0,
            )

        first = asyncio.create_task(_slow())
        for _ in range(50):
            if svc.pending_request_count == 1:
                break
            await asyncio.sleep(0)
        assert svc.pending_request_count == 1

        # Second sender must hit the cap and fail synchronously
        # (before any reply-path is built).
        with pytest.raises(Bolt12ServiceError, match="too many in-flight"):
            await svc.request_invoice(
                offer=_minimal_offer(),
                build_invreq=_build_invreq,
                destination=lambda _: _send_plan_direct(),
                timeout_seconds=1.0,
            )

        # The bookkeeping counter incremented and the first sender's
        # slot is still held (cap rejection must not pop a real slot).
        assert svc.metrics.pending_capacity_exceeded_total == 1
        assert svc.pending_request_count == 1

        # Tear down the parked sender so the test exits cleanly.
        first.cancel()
        try:
            await first
        except (asyncio.CancelledError, GatewayUnavailableError):
            pass


# ── hardening: oversized inbound payload ────────────────────


async def test_inbound_invoice_oversized_payload_drops_and_records(
    monkeypatch,
) -> None:
    """An inbound invoice payload larger than
    ``bolt12_max_payload_bytes`` must be dropped at the dispatcher
    boundary — never reaching the per-request future.
    """
    from app.core import config as _cfg

    monkeypatch.setattr(_cfg.settings, "bolt12_max_payload_bytes", 16)

    gw = FakeGateway()
    async with Bolt12Service(gw) as svc:  # type: ignore[arg-type]

        async def _send() -> bytes:
            return await svc.request_invoice(
                offer=_minimal_offer(),
                build_invreq=_build_invreq,
                destination=lambda _: _send_plan_direct(),
                timeout_seconds=2.0,
            )

        task = asyncio.create_task(_send())

        # Wait for the sender to register a pending future and
        # capture its correlation token.
        for _ in range(50):
            if gw.create_calls:
                break
            await asyncio.sleep(0)
        assert gw.create_calls, "sender did not register"
        ctx = gw.create_calls[0].context

        # Deliver a payload that exceeds the cap.
        oversized = b"X" * 64
        await gw.inbound.put(
            InboundMessage(
                recv_id="big",
                payload_tlv_type=TLV_INVOICE,
                payload=oversized,
                reply_path=None,
                received_at_ms=0,
                inbound_context=ctx,
            )
        )

        # The sender's future must be failed with a service error
        # (not silently satisfied with the oversized bytes).
        with pytest.raises(Bolt12ServiceError, match="exceeds size cap"):
            await task

        assert svc.metrics.inbound_oversized_payload_total == 1
