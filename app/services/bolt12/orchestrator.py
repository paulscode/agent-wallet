# SPDX-License-Identifier: MIT
"""BOLT 12 orchestration service.

Glues three independent components together:

* ``Bolt12GatewayClient`` — gRPC transport to the bare-LDK Rust
  gateway daemon (sends/receives raw onion-message bytes).
* ``Bolt12Codec`` — pure-Python TLV/bech32/merkle codec.
* Pluggable *field-level* builder + destination-resolver callbacks
  injected by the caller. These own the BOLT 12 semantics
  (constructing an ``invoice_request`` TLV stream, picking which
  blinded path to route through, etc.). They land as a separate
  module — keeping them out of this orchestrator means the
  orchestrator has zero knowledge of BOLT 12 field types and is
  therefore trivially testable with raw bytes.

What this module *does* own:

* A long-lived dispatcher task that demuxes inbound onion messages
  to either the receive handler (invreq → invoice reply) or to a
  pending sender-flow ``Future`` keyed on the gateway's
  ``inbound_context``.
* The correlation map between outbound ``invoice_request`` and
  inbound ``invoice``. Correlation is *transport-level*: the sender
  asks the gateway for a fresh blinded reply-path bound to a random
  context token, the recipient bounces the invoice back along that
  reply-path, and the gateway echoes the context token back to us
  on inbound. We never have to parse the BOLT 12 payload to match
  request to reply.

Cancellation / shutdown is fully cooperative: ``stop()`` cancels the
dispatcher task and fails every in-flight ``request_invoice`` with
``GatewayUnavailableError``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from types import TracebackType
from typing import Self

from app.services.bolt12.codec import Bolt12String
from app.services.bolt12_gateway import (
    Bolt12GatewayClient,
    GatewayError,
    GatewayUnavailableError,
    InboundMessage,
)

_log = logging.getLogger(__name__)

# ── BOLT 4 inner-TLV types (see BOLT 12 §"Onion Messaging Formats"). ──
TLV_INVOICE_REQUEST: int = 64
TLV_INVOICE: int = 66

# Default correlation-token length. 16 bytes ≈ 2^128 collision space —
# more than enough for the in-process pending map.
_CORRELATION_BYTES = 16

# Default per-request timeout for `request_invoice`.
_DEFAULT_REQUEST_TIMEOUT_S = 30.0


# ── public dataclasses ────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SendDestination:
    """Where a sender flow should route an ``invoice_request``.

    Exactly one of ``direct_node_id`` (33-byte compressed pubkey) or
    ``blinded_path`` (serialized BOLT 12 ``BlindedPath``) must be
    set.
    """

    direct_node_id: bytes | None = None
    blinded_path: bytes | None = None

    def __post_init__(self) -> None:
        if (self.direct_node_id is None) == (self.blinded_path is None):
            raise ValueError("SendDestination requires exactly one of direct_node_id or blinded_path")
        if self.direct_node_id is not None and len(self.direct_node_id) != 33:
            raise ValueError("direct_node_id must be 33 bytes (compressed pubkey)")


@dataclass(frozen=True, slots=True)
class ReplyPathSpec:
    """Specification for the blinded reply-path the gateway should build.

    The ``introduction_node_candidates`` are public node-ids the
    gateway can use as the path's first hop. They must be peers of
    the gateway. ``dummy_hops`` adds privacy padding (0–7).
    """

    introduction_node_candidates: tuple[bytes, ...]
    dummy_hops: int = 0

    def __post_init__(self) -> None:
        if not self.introduction_node_candidates:
            raise ValueError("introduction_node_candidates must be non-empty")
        for c in self.introduction_node_candidates:
            if len(c) != 33:
                raise ValueError("each introduction-node candidate must be 33 bytes")
        if self.dummy_hops < 0 or self.dummy_hops > 7:
            raise ValueError("dummy_hops must be in [0, 7]")


# ── injection points ──────────────────────────────────────────────

# Build an invoice_request TLV stream for an offer. Receives the
# decoded offer plus user-supplied parameters and returns raw bytes.
# The orchestrator does NOT inspect the bytes — it only forwards them
# to the gateway.
InvreqBuilder = Callable[
    ["InvreqBuildContext"],
    Awaitable[bytes],
]


@dataclass(frozen=True, slots=True)
class InvreqBuildContext:
    """Context passed to an ``InvreqBuilder``."""

    offer: Bolt12String
    amount_msat: int | None
    payer_note: str | None
    quantity: int | None
    reply_path: bytes
    """The blinded reply-path the gateway built for us. The builder
    must embed this in the invreq's ``invreq_paths`` field so the
    recipient knows where to send the invoice back."""


# Resolve where the orchestrator should send an invreq for the given
# offer. Typically returns one of the offer's ``offer_paths`` blinded
# paths (preferred) or falls back to ``offer_issuer_id`` for direct
# delivery.
DestinationResolver = Callable[[Bolt12String], "SendPlan"]


@dataclass(frozen=True, slots=True)
class SendPlan:
    """How and where to send an invreq for a given offer."""

    destination: SendDestination
    reply_path: ReplyPathSpec


# Receive an inbound invreq and produce an invoice TLV stream to
# reply with (or None to drop the message). The handler is opaque to
# the orchestrator — same `bytes in, bytes out` contract as the
# builder above.
InvoiceResponder = Callable[
    ["InboundInvreqContext"],
    Awaitable[bytes | None],
]


@dataclass(frozen=True, slots=True)
class InboundInvreqContext:
    """Context handed to an ``InvoiceResponder``."""

    invreq_payload: bytes
    reply_path: bytes | None
    """The blinded path the recipient included in their invreq for
    us to send the invoice back along. Required for a reply; if
    None, we cannot respond and the responder should return None."""

    inbound_context: bytes
    recv_id: str


# ── exceptions ────────────────────────────────────────────────────


class Bolt12ServiceError(Exception):
    """Base class for orchestrator errors."""


class InvoiceRequestTimeoutError(Bolt12ServiceError):
    """Awaiting an invoice reply exceeded the timeout."""


class ServiceNotRunningError(Bolt12ServiceError):
    """Operation requires ``start()`` to have been called."""


# ── metrics ───────────────────────────────────────────────────────


@dataclasses.dataclass
class Bolt12ServiceMetrics:
    """Mutable counters surfaced via the runtime status endpoint.

    These are advisory only — there is no atomic ordering guarantee
    across counters and a status snapshot. They are intended for
    operator dashboards / regtest validation, not billing.
    """

    outbound_invreq_sent_total: int = 0
    """``send_onion_message`` calls that returned successfully for an
    outbound ``invoice_request`` payload."""

    inbound_invoice_received_total: int = 0
    """Inbound stream messages dispatched as a paying-invoice reply
    to a pending request."""

    inbound_invreq_received_total: int = 0
    """Inbound stream messages routed to the configured
    :class:`InvoiceResponder`."""

    invoice_request_timeout_total: int = 0
    """``request_invoice`` calls that exited via
    :class:`InvoiceRequestTimeoutError`."""

    gateway_send_failure_total: int = 0
    """``send_onion_message`` errors raised by the gateway client."""

    inbound_unmatched_total: int = 0
    """Inbound invoices we received that did not match any in-flight
    correlation token (likely stale / duplicate / spoofed)."""

    inbound_dropped_no_responder_total: int = 0
    """Inbound invreqs dropped because no responder is configured."""

    pending_capacity_exceeded_total: int = 0
    """``request_invoice`` calls rejected because the in-flight cap
    (``settings.bolt12_max_pending_requests``) was reached. Tracked
    separately from gateway errors so operators can size the cap."""

    inbound_oversized_payload_total: int = 0
    """Inbound onion-message payloads dropped pre-decode because they
    exceeded ``settings.bolt12_max_payload_bytes``."""

    inbound_dropped_no_reply_path_total: int = 0
    """Inbound invreqs dropped because the gateway's
    :class:`InboundMessage` carried no ``reply_path``. The most common
    cause is the gateway's reply-path extractor returning ``None`` for
    a real Responder (e.g. an LDK serialization change). Without a
    reply_path we cannot send the invoice back."""

    pending_request_orphaned_total: int = 0
    """Entries in the in-flight ``_pending`` map discarded by the
    background sweeper because they outlived ``2 * request_timeout``
   . Indicates a Future that didn't complete via the normal
    timeout / reply path — e.g. a coroutine cancelled before its
    ``finally`` block could pop it."""

    inbound_concurrent_mint_throttled_total: int = 0
    """Inbound invreqs rejected because the concurrent-mint semaphore
    was saturated for ``bolt12_inbound_mint_acquire_timeout_s``.
    Indicates either burst traffic exceeding the cap, or LND-side
    minting slowness causing a backlog. Counted separately from
    rate-limit drops so operators can disambiguate the two.
    """

    inbound_rate_limit_drops_total: int = 0
    """Inbound invreqs dropped by the per-peer + global rate limiter
    (any cap). The audit row records which cap fired (``per_peer`` /
    ``global`` / ``backend``); this counter is the aggregate so
    operators have one number to graph against. A non-zero rate
    here while inbound mints stay flat is the canonical "we're
    shedding load" signal."""

    inbound_invoice_replied_total: int = 0
    """Telemetry #6: outbound invoice replies the gateway accepted
    for transmission to the requesting peer. Distinguishes "we
    minted an invoice" (responder's ``last_inbound_mint_at``) from
    "we sent it back over the wire to the payer". A gap between
    mint count and replied count means the responder is producing
    bytes but the gateway is rejecting / failing the send — the
    payer never sees our reply, so they will never pay."""

    inbound_adaptive_depth_flips_total: int = 0
    """Option B-adaptive (2026-06-08): mints where the
    responder's primary-depth result had ALL intros opened by
    the breaker, triggering a second mint at the alternative
    depth. A non-zero rate here means the topology has
    consistently degraded for one of the depths and the
    responder is actively routing around it."""

    def to_dict(self) -> dict[str, int]:
        return dataclasses.asdict(self)


# ── orchestrator ──────────────────────────────────────────────────


class Bolt12Service:
    """Orchestrate sender + receiver flows over the gateway transport.

    Lifecycle:

        async with Bolt12Service(gateway) as svc:
            invoice_bytes = await svc.request_invoice(
                offer=decoded_offer,
                build_invreq=my_invreq_builder,
                destination=my_destination_resolver,
            )
    """

    def __init__(
        self,
        gateway: Bolt12GatewayClient,
        *,
        invoice_responder: InvoiceResponder | None = None,
        request_timeout_seconds: float = _DEFAULT_REQUEST_TIMEOUT_S,
    ) -> None:
        self._gateway = gateway
        self._invoice_responder = invoice_responder
        self._request_timeout = request_timeout_seconds
        self._pending: dict[bytes, asyncio.Future[bytes]] = {}
        # Track creation time per pending entry so a background
        # sweeper can discard orphaned entries (e.g. from a coroutine
        # cancelled before its ``finally`` block ran). Monotonic.
        self._pending_created_at: dict[bytes, float] = {}
        self._sweeper_task: asyncio.Task[None] | None = None
        self._stream_task: asyncio.Task[None] | None = None
        self._stream_ready = asyncio.Event()
        self._stop_requested = False
        # ── delivery-rate counters ──
        self._metrics = Bolt12ServiceMetrics()
        # Per-process concurrency cap on inbound LND mints. Created
        # lazily on first inbound invreq so tests that don't import
        # settings don't pay the cost. The semaphore is bound to the
        # event loop the first time it's acquired; recreating it on
        # loop change is safe because the loop is single-threaded.
        self._mint_sem: asyncio.Semaphore | None = None
        self._mint_sem_loop: asyncio.AbstractEventLoop | None = None

    # ── lifecycle ────────────────────────────────────────────────

    async def start(self) -> None:
        """Connect the gateway and start the inbound dispatcher.

        Idempotent. Returns once the stream is ready to receive.
        """
        if self._stream_task is not None:
            return
        await self._gateway.connect()
        self._stop_requested = False
        self._stream_ready.clear()
        self._stream_task = asyncio.create_task(self._stream_loop(), name="bolt12-inbound-dispatcher")
        # Wait until the stream-loop has actually opened the underlying
        # call so the first request_invoice is guaranteed to race-free.
        await self._stream_ready.wait()
        # Start orphan sweeper alongside the stream loop.
        if self._sweeper_task is None or self._sweeper_task.done():
            self._sweeper_task = asyncio.create_task(self._sweep_loop(), name="bolt12-pending-sweeper")

    async def stop(self) -> None:
        """Stop the dispatcher, fail in-flight requests, close gateway."""
        self._stop_requested = True
        task = self._stream_task
        self._stream_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

        # Cancel the orphan sweeper too.
        sweeper = self._sweeper_task
        self._sweeper_task = None
        if sweeper is not None:
            sweeper.cancel()
            try:
                await sweeper
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

        # Fail all in-flight requests with a clear, typed exception.
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(GatewayUnavailableError("Bolt12Service stopped before reply arrived"))
        self._pending.clear()
        self._pending_created_at.clear()

        await self._gateway.close()

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.stop()

    # ── sender flow ──────────────────────────────────────────────

    async def request_invoice(
        self,
        *,
        offer: Bolt12String,
        build_invreq: InvreqBuilder,
        destination: DestinationResolver,
        amount_msat: int | None = None,
        payer_note: str | None = None,
        quantity: int | None = None,
        timeout_seconds: float | None = None,
    ) -> bytes:
        """Pay-offer flow: send an ``invreq``, await the matching invoice.

        Returns the raw invoice TLV bytes. Validation (signature,
        mirror, amount) is the caller's responsibility — this layer
        is transport-level only.
        """
        self._require_running()

        # Cap concurrent in-flight requests. Each slot holds a Future
        # plus the caller's builder closure; without a cap, a sustained
        # flood (or a slow recipient) pins memory until per-call
        # timeouts elapse. Overflow surfaces as 503 at the REST layer.
        from app.core.config import settings as _settings  # avoid circular at import time

        cap = _settings.bolt12_max_pending_requests
        if cap > 0 and len(self._pending) >= cap:
            self._metrics.pending_capacity_exceeded_total += 1
            raise Bolt12ServiceError(f"too many in-flight invoice requests ({len(self._pending)} \u2265 cap {cap})")

        plan = destination(offer)

        # Build the blinded reply-path with a unique correlation token.
        correlation = secrets.token_bytes(_CORRELATION_BYTES)
        reply_path = await self._gateway.create_blinded_path(
            introduction_node_candidates=plan.reply_path.introduction_node_candidates,
            dummy_hops=plan.reply_path.dummy_hops,
            context=correlation,
        )

        invreq_bytes = await build_invreq(
            InvreqBuildContext(
                offer=offer,
                amount_msat=amount_msat,
                payer_note=payer_note,
                quantity=quantity,
                reply_path=reply_path,
            )
        )

        # Register the pending future BEFORE sending so we cannot
        # miss a fast reply.
        loop = asyncio.get_running_loop()
        future: asyncio.Future[bytes] = loop.create_future()
        if correlation in self._pending:  # pragma: no cover — 128-bit collision
            raise Bolt12ServiceError("correlation token collision; refusing to send")
        self._pending[correlation] = future
        self._pending_created_at[correlation] = asyncio.get_running_loop().time()

        try:
            await self._gateway.send_onion_message(
                payload=invreq_bytes,
                payload_tlv_type=TLV_INVOICE_REQUEST,
                direct_node_id=plan.destination.direct_node_id,
                blinded_path=plan.destination.blinded_path,
                reply_path=reply_path,
            )
            self._metrics.outbound_invreq_sent_total += 1

            timeout = self._request_timeout if timeout_seconds is None else timeout_seconds
            try:
                return await asyncio.wait_for(future, timeout=timeout)
            except asyncio.TimeoutError as e:
                self._metrics.invoice_request_timeout_total += 1
                raise InvoiceRequestTimeoutError(f"no invoice reply within {timeout}s") from e
        except GatewayError:
            self._metrics.gateway_send_failure_total += 1
            raise
        finally:
            # Whatever the outcome, drop the correlation entry.
            self._pending.pop(correlation, None)
            self._pending_created_at.pop(correlation, None)

    # ── orphan sweeper ───────────────────────────────────────────

    async def _sweep_loop(self) -> None:
        """Periodically discard orphaned ``_pending`` entries.

        Normal flow pops a correlation in the ``request_invoice``
        ``finally`` block, so a leak only happens if a coroutine is
        cancelled before its finally runs (rare but possible) or if
        a future code path forgets to clean up. The sweeper bounds
        the worst-case map size at ~``cap`` entries even in that
        case, and surfaces the leak via
        ``pending_request_orphaned_total``.
        """
        # Sweep at half the request timeout so an entry that *just*
        # missed its own timeout is reaped within one cycle.
        interval = max(5.0, self._request_timeout / 2.0)
        ttl = max(2.0 * self._request_timeout, 60.0)
        try:
            while not self._stop_requested:
                await asyncio.sleep(interval)
                if not self._pending_created_at:
                    continue
                try:
                    now = asyncio.get_running_loop().time()
                except RuntimeError:  # pragma: no cover — loop gone
                    return
                stale: list[bytes] = [cid for cid, created in self._pending_created_at.items() if (now - created) > ttl]
                for cid in stale:
                    fut = self._pending.pop(cid, None)
                    self._pending_created_at.pop(cid, None)
                    if fut is not None and not fut.done():
                        fut.set_exception(InvoiceRequestTimeoutError("pending request orphaned by sweeper"))
                    self._metrics.pending_request_orphaned_total += 1
                if stale:
                    _log.warning(
                        "bolt12: sweeper discarded %d orphaned pending entries",
                        len(stale),
                    )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — never tear down the service
            _log.exception("bolt12: pending sweeper crashed")

    # ── inbound dispatcher ───────────────────────────────────────

    async def _stream_loop(self) -> None:
        """Long-lived task: consume the gateway's inbound stream."""
        try:
            async with self._gateway.stream_inbound() as stream:
                # Signal start() that we're hot.
                self._stream_ready.set()
                async for msg in stream:
                    try:
                        await self._dispatch(msg)
                    except Exception:  # noqa: BLE001
                        _log.exception("bolt12: dispatcher error for recv_id=%s", msg.recv_id)
        except asyncio.CancelledError:
            raise
        except GatewayError as e:
            _log.error("bolt12: inbound stream error: %s", e)
        except Exception:  # noqa: BLE001
            _log.exception("bolt12: inbound stream crashed")
        finally:
            # Ensure start() never blocks forever even if the stream
            # failed before becoming ready.
            self._stream_ready.set()

    async def _dispatch(self, msg: InboundMessage) -> None:
        if msg.payload_tlv_type == TLV_INVOICE:
            self._handle_invoice_reply(msg)
        elif msg.payload_tlv_type == TLV_INVOICE_REQUEST:
            await self._handle_inbound_invreq(msg)
        else:
            _log.debug(
                "bolt12: dropping inbound message recv_id=%s type=%d (not invreq/invoice)",
                msg.recv_id,
                msg.payload_tlv_type,
            )

    def _handle_invoice_reply(self, msg: InboundMessage) -> None:
        future = self._pending.get(msg.inbound_context)
        if future is None:
            self._metrics.inbound_unmatched_total += 1
            _log.warning(
                "bolt12: inbound invoice has no matching pending request (recv_id=%s, ctx=%s) — dropping",
                msg.recv_id,
                msg.inbound_context.hex() if msg.inbound_context else "<empty>",
            )
            return
        if future.done():
            return
        # Defence-in-depth: drop oversized payloads before they reach
        # the caller's TLV decoder. Even though the reply was delivered
        # to a correlation token *we* generated, a hostile recipient
        # can still spray a giant payload at our slot.
        from app.core.config import settings as _settings

        cap = _settings.bolt12_max_payload_bytes
        if cap > 0 and len(msg.payload) > cap:
            self._metrics.inbound_oversized_payload_total += 1
            _log.warning(
                "bolt12: oversized invoice reply (recv_id=%s size=%d cap=%d) \u2014 failing future",
                msg.recv_id,
                len(msg.payload),
                cap,
            )
            future.set_exception(Bolt12ServiceError(f"invoice reply exceeds size cap ({len(msg.payload)} > {cap})"))
            return
        self._metrics.inbound_invoice_received_total += 1
        future.set_result(msg.payload)

    async def _handle_inbound_invreq(self, msg: InboundMessage) -> None:
        responder = self._invoice_responder
        if responder is None:
            self._metrics.inbound_dropped_no_responder_total += 1
            _log.info(
                "bolt12: dropping inbound invreq recv_id=%s (no responder configured)",
                msg.recv_id,
            )
            return
        if msg.reply_path is None:
            self._metrics.inbound_dropped_no_reply_path_total += 1
            _log.warning(
                "bolt12: dropping inbound invreq recv_id=%s (no reply_path)",
                msg.recv_id,
            )
            # Persist an audit-log row so post-mortems of "peer timed
            # out paying our offer" can be reconstructed from the DB.
            # This drop happens *before* the responder runs, so the
            # responder's own audit hooks would otherwise miss it.
            # Best-effort: any exception is swallowed inside
            # ``_audit_inbound``.
            try:
                from app.core.database import get_db_context
                from app.services.bolt12.responder import _audit_inbound

                await _audit_inbound(
                    get_db_context,
                    action="bolt12_invreq_no_reply_path",
                    success=False,
                    error_message="gateway_supplied_no_reply_path",
                    details={
                        "recv_id": msg.recv_id,
                        "payload_size": len(msg.payload),
                        "payload_tlv_type": msg.payload_tlv_type,
                    },
                )
            except Exception:  # noqa: BLE001 — never block dispatch
                _log.exception("bolt12: audit-log emit failed for no-reply-path drop")
            return

        self._metrics.inbound_invreq_received_total += 1

        # Cap concurrent LND mints across the process. Without this,
        # a burst of distinct invreqs (different payer_ids, each
        # within its per-peer rate-limit budget) can fan out unbounded
        # calls into LND's /v1/invoices endpoint and saturate the
        # node. The semaphore lives on the orchestrator, not the
        # responder, so the metric counter and the budgeted-wait
        # behaviour are observable from one place.
        from app.core.config import settings as _settings

        sem = self._get_mint_semaphore()
        acquire_timeout = _settings.bolt12_inbound_mint_acquire_timeout_s
        try:
            await asyncio.wait_for(sem.acquire(), timeout=acquire_timeout)
        except asyncio.TimeoutError:
            self._metrics.inbound_concurrent_mint_throttled_total += 1
            _log.warning(
                "bolt12: dropping inbound invreq recv_id=%s (mint semaphore saturated, waited %.1fs)",
                msg.recv_id,
                acquire_timeout,
            )
            try:
                from app.core.database import get_db_context
                from app.services.bolt12.responder import _audit_inbound

                await _audit_inbound(
                    get_db_context,
                    action="bolt12_invreq_concurrency_rejected",
                    success=False,
                    error_message="mint_semaphore_saturated",
                    details={
                        "recv_id": msg.recv_id,
                        "wait_timeout_s": acquire_timeout,
                        "cap": _settings.bolt12_inbound_max_concurrent_mints,
                    },
                )
            except Exception:  # noqa: BLE001 — never block dispatch
                _log.exception("bolt12: audit-log emit failed for concurrency-reject drop")
            try:
                from app.services.bolt12.runtime import mark_inbound_error

                mark_inbound_error("concurrency_rejected")
            except Exception:  # noqa: BLE001
                pass
            return

        try:
            invoice_bytes = await responder(
                InboundInvreqContext(
                    invreq_payload=msg.payload,
                    reply_path=msg.reply_path,
                    inbound_context=msg.inbound_context,
                    recv_id=msg.recv_id,
                )
            )
        finally:
            sem.release()

        if invoice_bytes is None:
            _log.info("bolt12: responder declined invreq recv_id=%s", msg.recv_id)
            return

        try:
            await self._gateway.send_onion_message(
                payload=invoice_bytes,
                payload_tlv_type=TLV_INVOICE,
                blinded_path=msg.reply_path,
            )
        except GatewayError:
            self._metrics.gateway_send_failure_total += 1
            raise
        # Telemetry #6: wire-send acknowledged by the gateway. The
        # invoice bytes are now on their way to the requesting
        # peer. A widening gap between
        # ``last_inbound_mint_at`` (responder side) and this
        # counter is the canonical "the payer never sees our
        # invoice" signal.
        self._metrics.inbound_invoice_replied_total += 1
        try:
            from app.core.database import get_db_context
            from app.services.bolt12.responder import _audit_inbound

            await _audit_inbound(
                get_db_context,
                action="bolt12_invoice_sent_to_peer",
                success=True,
                details={
                    "recv_id": msg.recv_id,
                    "invoice_bytes_len": len(invoice_bytes),
                },
            )
        except Exception:  # noqa: BLE001
            _log.exception(
                "bolt12: wire-send audit emit failed for recv_id=%s",
                msg.recv_id,
            )

    # ── helpers ──────────────────────────────────────────────────

    def _get_mint_semaphore(self) -> asyncio.Semaphore:
        """Lazily create + return the inbound-mint semaphore bound to
        the current event loop.

        Created the first time an inbound invreq arrives so unit-test
        constructions of ``Bolt12Service`` that never touch the
        inbound path don't pay the cost. Re-created on loop change
        (pytest fixtures often spin up a new loop per test) — safe
        because the previous semaphore is referenced only by the
        prior loop's coroutines, which are guaranteed not to be
        running concurrently with the new loop.
        """
        from app.core.config import settings as _settings

        loop = asyncio.get_running_loop()
        if self._mint_sem is None or self._mint_sem_loop is not loop:
            self._mint_sem = asyncio.Semaphore(_settings.bolt12_inbound_max_concurrent_mints)
            self._mint_sem_loop = loop
        return self._mint_sem

    def _require_running(self) -> None:
        if self._stream_task is None or self._stop_requested:
            raise ServiceNotRunningError("Bolt12Service not started; call start() first")

    @property
    def inbound_stream_alive(self) -> bool:
        """Whether the inbound dispatch stream task is running.

        The runtime supervisor consults this so an ended stream (the
        gateway went silent and the idle watchdog tore the call down)
        triggers a reconnect instead of halting inbound processing while
        the channel still answers liveness probes.
        """
        return self._stream_task is not None and not self._stream_task.done()

    @property
    def pending_request_count(self) -> int:
        """Diagnostic: number of in-flight ``request_invoice`` calls."""
        return len(self._pending)

    @property
    def metrics(self) -> Bolt12ServiceMetrics:
        """Live counters for outbound/inbound delivery rates.

        Returned by reference — callers should treat fields as
        read-only. Snapshots can be taken via :meth:`Bolt12ServiceMetrics.to_dict`.
        """
        return self._metrics
