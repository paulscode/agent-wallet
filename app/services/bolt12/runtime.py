# SPDX-License-Identifier: MIT
"""Process-wide BOLT 12 runtime singleton.

Owns the lifecycle of the gateway client + orchestrator service:

* :func:`start_bolt12_runtime` — called from the FastAPI lifespan.
  Connects to the gateway and starts the inbound dispatcher. If
  BOLT 12 is disabled (``settings.bolt12_enabled=false`` or empty
  ``bolt12_gateway_grpc``), it is a no-op.
* :func:`stop_bolt12_runtime` — graceful shutdown. Always safe to
  call.
* :func:`get_bolt12_service` — FastAPI dependency for endpoints
  that require an actively-running orchestrator. Raises 503 with a
  clear message if BOLT 12 is disabled or the gateway is
  unreachable.
* :func:`get_bolt12_runtime_state` — read-only diagnostic snapshot
  for the ``/status`` endpoint.

Startup is **best-effort**: if the gateway is down at boot we log
loudly but the API still serves. This matches how every other
external dependency behaves (LND, Boltz, mempool) — the operator
shouldn't lose unrelated functionality because BOLT 12 is sick.

A background **health probe** task pings the gateway's ``GetIdentity``
once per ``HEALTH_PROBE_INTERVAL_S`` seconds. The most recent
successful probe time + connected-peer count + last error are
exposed on ``/v1/bolt12/status`` so operators can detect a flatlined
gateway without inspecting logs.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final

from fastapi import HTTPException, status

from app.core.config import settings
from app.services.bolt12.orchestrator import Bolt12Service
from app.services.bolt12.responder import make_invreq_responder
from app.services.bolt12_gateway import (
    Bolt12GatewayClient,
    GatewayError,
)
from app.services.health import register_health

logger = logging.getLogger(__name__)

# Unified health surface. The BOLT 12 runtime has its own
# supervisor + dedicated /v1/bolt12/status endpoint; this mirror is
# what the cross-service /v1/status/services aggregator reads.
# The runtime's enabled flag is dynamic (depends on settings), so
# we register once and let the probe loop refresh it.
_BOLT12_HEALTH = register_health("bolt12_gateway")

HEALTH_PROBE_INTERVAL_S: float = 30.0

# Reconnect backoff bounds for the self-healing probe loop. We use
# exponential backoff capped at RECONNECT_BACKOFF_MAX_S so a long
# gateway outage doesn't bury us in an O(uptime) reconnect storm,
# while a transient blip recovers within seconds.
RECONNECT_BACKOFF_MIN_S: float = 2.0
RECONNECT_BACKOFF_MAX_S: float = 60.0

# After this many consecutive probe failures we assume the gateway
# connection is wedged (TLS half-open, broken HTTP/2 stream, peer
# rebooted, etc.) and tear down so the probe loop can reconnect on
# its next iteration. Tuned to ~2 minutes at 30s probe interval so
# transient packet loss doesn't trigger a needless reconnect.
PROBE_FAILURES_BEFORE_RESET: int = 4


@dataclass(frozen=True, slots=True)
class Bolt12RuntimeState:
    """Snapshot of runtime status for ``/status`` endpoints."""

    enabled: bool
    """``settings.bolt12_enabled`` AND a non-empty gateway target."""

    running: bool
    """The orchestrator + gateway client are connected and dispatching."""

    target: str
    """The configured gateway gRPC target (may be empty)."""

    last_error: str | None
    """Most recent start/dispatch error, if any."""

    last_probe_at: datetime | None = None
    """When the most recent successful health probe completed."""

    last_probe_peer_count: int | None = None
    """Connected-peer count from the most recent successful probe."""

    last_probe_node_id_hex: str | None = None
    """33-byte gateway node-id from the most recent successful probe."""

    consecutive_probe_failures: int = 0
    """Strict counter: incremented on probe failure, reset on success."""

    metrics: dict[str, int] | None = None
    """Snapshot of orchestrator delivery counters; ``None`` when the
    runtime is not running."""

    permanently_disabled: bool = False
    """True when the runtime has hit a non-recoverable error
    (network mismatch, missing gateway network field) and the probe
    loop has stopped attempting auto-reconnect. Cleared only by a
    full ``stop_bolt12_runtime`` + ``start_bolt12_runtime`` cycle
    (i.e. a process or admin-triggered restart)."""

    reconnect_count: int = 0
    """Monotonic count of successful auto-reconnects since process
    start. A non-zero value means the gateway dropped at least once
    and we recovered — useful for spotting flapping connections."""

    last_inbound_mint_at: datetime | None = None
    """When the responder most recently minted an inbound BOLT 12
    invoice (offer-bound or offer-less). ``None`` means no invreq
    has reached a successful mint since process start. A stale value
    while ``metrics.inbound_invreq_received_total`` keeps climbing
    indicates the responder is dropping invreqs (rate limit,
    concurrency cap, validation failure)."""

    last_inbound_error: str | None = None
    """Most recent receive-path failure reason. Captured both for
    silent-drop branches (e.g. rate-limit, concurrency-rejected)
    and mint failures (e.g. LND error). Distinct from
    ``last_error`` (which is the orchestrator/gateway connect path
    error) so operators don't confuse a sender-side reconnect
    blip with a receiver-side drop."""

    last_inbound_error_at: datetime | None = None
    """When ``last_inbound_error`` was last set. Lets operators
    distinguish a long-stale failure (last error was hours ago,
    receive path now healthy) from a live incident."""

    node_address_cache_size: int | None = None
    """Number of entries the gateway reports it currently has in
    its address cache after the most recent push. Today this is
    populated from the gateway's ``accepted_count`` response
    (= entries that survived dedup against the prior cache). A
    future RPC could replace this with the true post-push cache
    size; the field name is kept stable so dashboards don't
    have to change. ``None`` until the first push completes."""

    node_address_last_push_at: datetime | None = None
    """When the address-pusher last completed a push. Combined with
    the configured refresh interval, operators can see at a glance
    whether the pusher loop is healthy."""

    node_address_last_push_accepted: int | None = None
    """Count returned by the gateway's ``accepted_count`` field on
    the most recent push — i.e. the number of *new* address entries
    accepted (not the cache total). Watching this go to 0 while
    pushes keep happening is the canonical "LND graph cache is
    stuck" symptom: every push is a duplicate of the prior one."""


_DISABLED_DETAIL: Final = "BOLT 12 is disabled. Set BOLT12_ENABLED=true and BOLT12_GATEWAY_GRPC to enable."
_NOT_RUNNING_DETAIL: Final = (
    "BOLT 12 runtime is not running (gateway unreachable or not started). Check gateway logs and /v1/bolt12/status."
)


class _Runtime:
    """Module-private holder. Use the module-level helpers, not this class."""

    def __init__(self) -> None:
        self.client: Bolt12GatewayClient | None = None
        self.service: Bolt12Service | None = None
        self.last_error: str | None = None
        self.last_probe_at: datetime | None = None
        self.last_probe_peer_count: int | None = None
        self.last_probe_node_id_hex: str | None = None
        self.consecutive_probe_failures: int = 0
        self.probe_task: asyncio.Task[None] | None = None
        # When True, the probe loop will not attempt to reconnect.
        # Set on unrecoverable misconfiguration (network mismatch,
        # missing gateway network field) where blindly retrying
        # would just re-tear-down on every iteration. Cleared by
        # ``stop_bolt12_runtime`` so an operator who fixes config
        # and restarts the API recovers cleanly.
        self.permanently_disabled: bool = False
        # Current reconnect backoff (seconds). Reset on every
        # successful connect; doubled (capped) on every failure.
        self.reconnect_backoff_s: float = RECONNECT_BACKOFF_MIN_S
        # Monotonic count of successful auto-reconnects since
        # process start. Surfaced on /status for operators.
        self.reconnect_count: int = 0
        # Background task that periodically pushes the LND-known
        # peer-address set to the gateway's address cache (load-
        # bearing for ConnectionNeeded recovery on outbound onion
        # replies). Its own stop_event is wired through
        # ``stop_bolt12_runtime`` for clean shutdown.
        self.node_address_pusher_task: asyncio.Task[None] | None = None
        self.node_address_pusher_stop: asyncio.Event | None = None
        # ── Settlement subscriber (Item 13) ─────────────────────
        # Streams LND ``/v2/invoices/subscribe`` so SETTLED rows are
        # projected onto our BOLT 12 invoices within ms, not within
        # one reconcile-poll cadence. Idempotent — the reconcile
        # loop still runs as a catch-up worker.
        self.settlement_subscriber_task: asyncio.Task[None] | None = None
        self.settlement_subscriber_stop: asyncio.Event | None = None
        # ── HTLC event subscriber (Telemetry #1) ────────────────
        # Streams LND ``/v2/router/subscribehtlcs`` and emits
        # structured audit rows for HTLC events matching one of
        # our minted payment_hashes. Distinguishes "HTLC arrived
        # but failed at our LND" from "HTLC died upstream and
        # never reached us".
        self.htlc_event_subscriber_task: asyncio.Task[None] | None = None
        self.htlc_event_subscriber_stop: asyncio.Event | None = None
        # ── Subscriber heartbeat (T5, 2026-06-12) ────────────────
        # Periodic ``bolt12_subscriber_heartbeat`` audit row so the
        # absence of events is itself diagnostic.
        self.subscriber_heartbeat_task: asyncio.Task[None] | None = None
        self.subscriber_heartbeat_stop: asyncio.Event | None = None
        # ── Settle watchdog (moved from Celery 2026-06-06) ──────
        # Was a Celery beat task; moved here so its breaker
        # ``record_failure`` calls reach the SAME breaker the
        # responder reads from (the breaker is process-local).
        self.settle_watchdog_task: asyncio.Task[None] | None = None
        self.settle_watchdog_stop: asyncio.Event | None = None
        # ── Receive-side observability (Item 12) ────────────────
        # Mutated from callbacks invoked by the responder + the
        # node-address pusher. Never read on the hot path; only
        # surfaced via /v1/bolt12/status. Mutations are bare-int /
        # bare-datetime assignments under the asyncio loop so no
        # locking is required.
        self.last_inbound_mint_at: datetime | None = None
        self.last_inbound_error: str | None = None
        self.last_inbound_error_at: datetime | None = None
        self.node_address_cache_size: int | None = None
        self.node_address_last_push_at: datetime | None = None
        self.node_address_last_push_accepted: int | None = None

    @property
    def running(self) -> bool:
        return self.service is not None


_runtime = _Runtime()


def _is_enabled() -> bool:
    return bool(settings.bolt12_enabled) and bool(settings.bolt12_gateway_grpc)


async def _probe_loop(interval: float = HEALTH_PROBE_INTERVAL_S) -> None:
    """Self-healing supervisor loop for the BOLT 12 runtime.

    Three responsibilities, in priority order:

    1. **Reconnect** when the runtime is enabled but not running.
       Used both for "first start failed" (gateway down at API
       boot) and "we tore the connection down" (see #3). Uses
       exponential backoff capped at ``RECONNECT_BACKOFF_MAX_S`` so
       a long outage doesn't pin a CPU on dial attempts.
    2. **Probe** liveness via ``GetIdentity`` once the runtime is
       running. Updates ``last_probe_*`` fields surfaced on
       ``/status``.
    3. **Tear down** when probe failures cross
       ``PROBE_FAILURES_BEFORE_RESET`` — a wedged HTTP/2 stream or
       half-open TLS session won't recover on its own. After
       teardown the next loop iteration falls through to #1.

    Cancellation-safe. Never raises (besides ``CancelledError``
    propagated to ``stop_bolt12_runtime``).
    """
    while True:
        try:
            # ── 1. Reconnect path ──────────────────────────────
            if not _runtime.running:
                if _runtime.permanently_disabled or not _is_enabled():
                    # Nothing to do, but keep the loop alive so an
                    # operator who fixes config can recover via a
                    # process restart without state-flicker.
                    await asyncio.sleep(interval)
                    continue
                ok = await _attempt_connect()
                if ok:
                    _runtime.reconnect_backoff_s = RECONNECT_BACKOFF_MIN_S
                    _runtime.reconnect_count += 1
                    logger.info(
                        "BOLT 12 runtime reconnected (#%d, target=%s)",
                        _runtime.reconnect_count,
                        settings.bolt12_gateway_grpc,
                    )
                    # Fall through to probe immediately so the new
                    # connection's first liveness check lands fast.
                    continue
                # Backoff before the next dial attempt. Doubled
                # each failure, capped, with a small jitter so
                # multiple wallets pointing at the same gateway
                # don't herd-restart in lockstep.
                jitter = 0.5 + (_runtime.consecutive_probe_failures % 7) * 0.1
                await asyncio.sleep(_runtime.reconnect_backoff_s * jitter)
                _runtime.reconnect_backoff_s = min(
                    RECONNECT_BACKOFF_MAX_S,
                    _runtime.reconnect_backoff_s * 2,
                )
                continue

            # ── 2. Probe path ──────────────────────────────────
            await asyncio.sleep(interval)
            client = _runtime.client
            if client is None:
                # Race: stop_bolt12_runtime() cleared client between
                # checks. Skip and let the next iteration handle it.
                continue
            # A dead inbound dispatch stream won't recover on its own and
            # may not show up as a probe failure (the channel can still
            # answer GetIdentity). Tear down so the reconnect path on the
            # next iteration restarts the service.
            service = _runtime.service
            if service is not None and not service.inbound_stream_alive:
                _runtime.last_error = "inbound stream not running"
                _BOLT12_HEALTH.record_failure(_runtime.last_error)
                logger.error("BOLT 12 runtime: inbound stream not running, tearing down for reconnect")
                await _teardown_connection()
                continue
            try:
                ident = await client.get_identity()
            except (GatewayError, Exception) as exc:  # noqa: BLE001
                _runtime.consecutive_probe_failures += 1
                _runtime.last_error = f"probe: {type(exc).__name__}: {exc}"
                _BOLT12_HEALTH.record_failure(_runtime.last_error)
                logger.warning(
                    "BOLT 12 health probe failed (#%d): %s",
                    _runtime.consecutive_probe_failures,
                    _runtime.last_error,
                )
                # ── 3. Teardown path ───────────────────────────
                if _runtime.consecutive_probe_failures >= PROBE_FAILURES_BEFORE_RESET:
                    logger.error(
                        "BOLT 12 runtime: %d consecutive probe failures, tearing down for reconnect",
                        _runtime.consecutive_probe_failures,
                    )
                    await _teardown_connection()
                continue
            _runtime.last_probe_at = datetime.now(timezone.utc)
            _runtime.last_probe_peer_count = ident.connected_peers
            _runtime.last_probe_node_id_hex = ident.node_id.hex()
            if _runtime.consecutive_probe_failures > 0:
                logger.info(
                    "BOLT 12 health probe recovered after %d failures",
                    _runtime.consecutive_probe_failures,
                )
            _runtime.consecutive_probe_failures = 0
            _BOLT12_HEALTH.record_success()
            _BOLT12_HEALTH.extra.update(
                {
                    "connected_peers": ident.connected_peers,
                    "reconnect_count": _runtime.reconnect_count,
                    "permanently_disabled": _runtime.permanently_disabled,
                }
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — supervisor must never die
            logger.exception("BOLT 12 probe loop iteration crashed; continuing")
            await asyncio.sleep(interval)


async def _teardown_connection() -> None:
    """Tear down the running client + service so the probe loop
    will reconnect on the next iteration. Best-effort; never raises.

    This is the gentle counterpart to ``_shutdown_unhealthy`` —
    we *want* to retry, so we don't set ``permanently_disabled``.
    """
    service = _runtime.service
    client = _runtime.client
    _runtime.service = None
    _runtime.client = None
    if service is not None:
        try:
            await service.stop()
        except Exception:  # noqa: BLE001
            logger.exception("BOLT 12 teardown: service.stop() failed")
    if client is not None:
        try:
            await client.close()
        except Exception:  # noqa: BLE001
            logger.exception("BOLT 12 teardown: client.close() failed")


async def _shutdown_unhealthy(client: "Bolt12GatewayClient", service: "Bolt12Service") -> None:
    """Tear down a partially-started runtime after a fatal sanity
    check failure (e.g. network mismatch).

    Clears ``_runtime.client`` / ``_runtime.service`` so callers see
    the runtime as not-running and so a later ``start_bolt12_runtime``
    invocation can retry cleanly once the operator fixes the config.
    Best-effort — never raises.
    """
    try:
        await service.stop()
    except Exception:  # noqa: BLE001
        logger.exception("BOLT 12 runtime: failed to stop service during teardown")
    try:
        await client.close()
    except Exception:  # noqa: BLE001
        logger.exception("BOLT 12 runtime: failed to close client during teardown")
    _runtime.client = None
    _runtime.service = None


async def _check_offerless_invreq_sentinel() -> None:
    """Sanity-check the dashboard sentinel API key when offer-less
    invreqs are enabled. Logs loudly if missing; never raises.

    Extracted from ``start_bolt12_runtime`` so we don't repeat the
    DB query on every reconnect — the sentinel check fires at most
    once per process via ``_sentinel_checked``.
    """
    if _sentinel_checked["done"]:
        return
    _sentinel_checked["done"] = True
    logger.warning(
        "BOLT 12: accepting offer-less invreqs is ENABLED — "
        "any onion-message peer can request invoices for "
        "arbitrary amounts. Inbound payments are attributed to "
        "the dashboard sentinel API key."
    )
    try:
        from sqlalchemy import select

        from app.core.database import get_db_context
        from app.dashboard import DASHBOARD_KEY_ID
        from app.models.api_key import APIKey

        async with get_db_context() as _db:
            _row = (await _db.execute(select(APIKey.id).where(APIKey.id == DASHBOARD_KEY_ID))).scalar_one_or_none()
        if _row is None:
            logger.error(
                "BOLT 12: bolt12_accept_offerless_invreqs=true but the "
                "dashboard sentinel API key is missing. Run "
                "`alembic upgrade head` to install migration 002. "
                "Offer-less invreqs will fail to persist until fixed."
            )
    except Exception:  # noqa: BLE001 — sanity check, never fatal
        logger.exception("BOLT 12: sentinel-key sanity check failed")


_sentinel_checked: dict[str, bool] = {"done": False}


async def _attempt_connect() -> bool:
    """Try to establish a single gateway client + orchestrator.

    Returns True on success (``_runtime.running`` is now True),
    False on transient failure (caller should back off and retry).
    Sets ``_runtime.permanently_disabled`` on unrecoverable
    misconfiguration (network mismatch, missing gateway network) so
    the probe loop stops retrying.

    Always called from a single coroutine (the probe loop or the
    initial start), so no internal locking is needed.
    """
    if _runtime.running:
        return True
    if not _is_enabled():
        return False

    # Refuse to dial
    # the gateway when BOLT12_ENABLED=true but no auth token is set
    # outside of debug/regtest. The gateway will itself bail out in
    # production, but failing here as well surfaces the
    # misconfiguration in api logs rather than as a cryptic transport
    # error.
    if not settings.debug and not (settings.bolt12_gateway_token or "").strip():
        _runtime.permanently_disabled = True
        _runtime.last_error = (
            "BOLT12_GATEWAY_TOKEN must be set when BOLT12_ENABLED=true "
            "and DEBUG=false; refusing to dial unauthenticated gateway."
        )
        logger.error("%s", _runtime.last_error)
        return False

    target = settings.bolt12_gateway_grpc
    timeout = settings.bolt12_gateway_timeout_seconds
    # Fail fast on a half-configured TLS triple — Bolt12GatewayClient
    # rejects partial configs in its constructor with a ValueError,
    # so the operator sees the error in api logs at runtime start
    # rather than as a confusing handshake failure on the first RPC.
    try:
        client = Bolt12GatewayClient(
            target,
            timeout=timeout,
            auth_token=settings.bolt12_gateway_token or None,
            tls_ca_cert_path=settings.bolt12_gateway_tls_ca_cert or None,
            tls_client_cert_path=settings.bolt12_gateway_tls_client_cert or None,
            tls_client_key_path=settings.bolt12_gateway_tls_client_key or None,
            tls_server_name=settings.bolt12_gateway_tls_server_name or None,
        )
    except ValueError as exc:
        _runtime.permanently_disabled = True
        _runtime.last_error = f"BOLT 12 gateway TLS misconfigured: {exc}"
        logger.error("%s", _runtime.last_error)
        return False
    service = Bolt12Service(client, invoice_responder=make_invreq_responder())
    if settings.bolt12_accept_offerless_invreqs:
        await _check_offerless_invreq_sentinel()
    try:
        await service.start()
    except (GatewayError, Exception) as exc:  # noqa: BLE001
        _runtime.last_error = f"{type(exc).__name__}: {exc}"
        logger.warning(
            "BOLT 12 runtime connect failed (target=%s): %s",
            target,
            _runtime.last_error,
        )
        try:
            await client.close()
        except Exception:  # noqa: BLE001
            pass
        return False

    _runtime.client = client
    _runtime.service = service
    _runtime.last_error = None
    _runtime.consecutive_probe_failures = 0

    # Network sanity: refuse to keep running if the gateway is
    # configured for a different chain than the wallet. A mismatch
    # would silently mint mainnet-tagged invoices on a regtest
    # gateway (or vice versa) and leak funds onto the wrong network.
    try:
        ident = await client.get_identity()
    except Exception as exc:  # noqa: BLE001
        # Identity probe failed but service.start() succeeded — log
        # and let the probe loop retry. Do NOT mark permanently
        # disabled (we don't know if it was a misconfig or a blip).
        _runtime.last_error = f"identity: {type(exc).__name__}: {exc}"
        logger.warning(
            "BOLT 12 runtime: gateway identity probe failed: %s",
            _runtime.last_error,
        )
        return True

    gw_net = (ident.network or "").strip().lower()
    our_net = (settings.bitcoin_network or "").strip().lower()
    # Normalize aliases. Both ends accept "bitcoin" / "mainnet" as
    # equivalent (and "testnet" / "testnet3"), but the gateway's
    # GetIdentity response stringifies its parsed bitcoin::Network
    # via a fixed mapping so the wire value can differ from what
    # the operator typed in BITCOIN_NETWORK on the wallet side.
    _network_aliases = {
        "bitcoin": "mainnet",
        "mainnet": "mainnet",
        "testnet": "testnet",
        "testnet3": "testnet",
        "testnet4": "testnet4",
        "signet": "signet",
        "regtest": "regtest",
    }
    gw_canon = _network_aliases.get(gw_net, gw_net)
    our_canon = _network_aliases.get(our_net, our_net)
    if not gw_net:
        _runtime.last_error = "gateway did not report a network field"
        logger.error(
            "BOLT 12 runtime: gateway reported empty network — "
            "rebuild the gateway against the current proto and "
            "set BOLT12_GATEWAY_NETWORK. Refusing to keep runtime "
            "active to avoid cross-chain fund loss."
        )
        await _shutdown_unhealthy(client, service)
        _runtime.permanently_disabled = True
        return False
    if gw_canon != our_canon:
        _runtime.last_error = f"network mismatch: wallet={our_net} gateway={gw_net}"
        logger.error(
            "BOLT 12 runtime: network mismatch (wallet=%s, gateway=%s). "
            "Refusing to keep runtime active — set BOLT12_GATEWAY_NETWORK "
            "to %s on the gateway, or BITCOIN_NETWORK to %s on the wallet.",
            our_net,
            gw_net,
            our_net,
            gw_net,
        )
        await _shutdown_unhealthy(client, service)
        _runtime.permanently_disabled = True
        return False
    return True


async def start_bolt12_runtime() -> None:
    """Start the gateway client + orchestrator + supervisor loop.

    Called from the FastAPI lifespan. Idempotent. Best-effort: a
    failed initial connect is logged but does not raise — the
    supervisor loop will keep retrying in the background so the
    wallet recovers automatically when the gateway comes back.
    """
    _BOLT12_HEALTH.enabled = _is_enabled()
    if _runtime.running:
        return
    if not _is_enabled():
        logger.info(
            "BOLT 12 runtime disabled (enabled=%s, target=%r) — skipping start",
            settings.bolt12_enabled,
            settings.bolt12_gateway_grpc,
        )
        return

    # Fresh boot: clear permanently_disabled so an operator who
    # restarted the API after fixing config gets a clean attempt.
    _runtime.permanently_disabled = False
    _runtime.reconnect_backoff_s = RECONNECT_BACKOFF_MIN_S

    target = settings.bolt12_gateway_grpc
    ok = await _attempt_connect()
    if ok:
        logger.info("BOLT 12 runtime started (target=%s)", target)
    elif _runtime.permanently_disabled:
        logger.error("BOLT 12 runtime start aborted: permanently disabled (see prior error).")
    else:
        logger.warning(
            "BOLT 12 runtime initial connect failed (target=%s); supervisor will retry in the background",
            target,
        )

    # Always start the supervisor — it handles both first-connect
    # retry (when ok=False) and ongoing health/reconnect (when ok=True).
    if _runtime.probe_task is None or _runtime.probe_task.done():
        _runtime.probe_task = asyncio.create_task(_probe_loop(), name="bolt12-health-probe")

    # Periodic node-address pusher — feeds the gateway's
    # ConnectionNeeded address cache. Idempotent: skipped when
    # disabled via interval=0 or when a previous task is still
    # running. Cooperates with the reconnect flow by looking up
    # ``_runtime.client`` each tick.
    interval = int(settings.bolt12_gateway_node_address_refresh_interval_s)
    max_nodes = int(settings.bolt12_gateway_node_address_max_nodes)
    if interval > 0 and (_runtime.node_address_pusher_task is None or _runtime.node_address_pusher_task.done()):
        from app.services.bolt12.node_address_pusher import (
            run_node_address_pusher,
        )

        _runtime.node_address_pusher_stop = asyncio.Event()
        _runtime.node_address_pusher_task = asyncio.create_task(
            run_node_address_pusher(
                lambda: _runtime.client,
                _runtime.node_address_pusher_stop,
                interval_s=interval,
                max_nodes=max_nodes,
            ),
            name="bolt12-node-address-pusher",
        )

    # Item 13: LND settlement subscriber. Subscribes to
    # ``/v2/invoices/subscribe`` so SETTLED rows project onto our
    # BOLT 12 invoices in ms instead of waiting for the next
    # reconcile pass. Gated on its own setting so operators who
    # can't reach LND from this process (e.g. a split-mode
    # deployment where LND lives in a separate container) can
    # disable it without affecting the rest of the runtime.
    if settings.bolt12_settlement_subscriber_enabled and (
        _runtime.settlement_subscriber_task is None or _runtime.settlement_subscriber_task.done()
    ):
        from app.services.bolt12.settlement_subscriber import (
            run_settlement_subscriber,
        )

        _runtime.settlement_subscriber_stop = asyncio.Event()
        _runtime.settlement_subscriber_task = asyncio.create_task(
            run_settlement_subscriber(_runtime.settlement_subscriber_stop),
            name="bolt12-settlement-subscriber",
        )

    # Telemetry #1: HTLC event subscriber. Same lifecycle pattern
    # as the settlement subscriber — gated on its own setting,
    # restarts cleanly across runtime stop/start cycles.
    if settings.bolt12_htlc_event_subscriber_enabled and (
        _runtime.htlc_event_subscriber_task is None or _runtime.htlc_event_subscriber_task.done()
    ):
        from app.services.bolt12.htlc_event_subscriber import (
            run_htlc_event_subscriber,
        )

        _runtime.htlc_event_subscriber_stop = asyncio.Event()
        _runtime.htlc_event_subscriber_task = asyncio.create_task(
            run_htlc_event_subscriber(_runtime.htlc_event_subscriber_stop),
            name="bolt12-htlc-event-subscriber",
        )

    # T5 (2026-06-12): periodic subscriber heartbeat audit row so
    # a silently-broken subscriber is distinguishable from "no
    # events to report". Single loop emits a heartbeat for each
    # currently-active subscriber on the configured interval.
    if settings.bolt12_subscriber_heartbeat_interval_s > 0 and (
        _runtime.subscriber_heartbeat_task is None or _runtime.subscriber_heartbeat_task.done()
    ):
        from app.services.bolt12.subscriber_metrics import (
            run_heartbeat_loop,
        )

        _runtime.subscriber_heartbeat_stop = asyncio.Event()

        async def _spawn_heartbeats(stop_ev: asyncio.Event) -> None:
            # Run a heartbeat loop per active subscriber. Each is a
            # cheap timer that writes an audit row; they share the
            # same stop event for clean shutdown.
            tasks = []
            interval = float(settings.bolt12_subscriber_heartbeat_interval_s)
            if settings.bolt12_settlement_subscriber_enabled:
                tasks.append(
                    asyncio.create_task(
                        run_heartbeat_loop(
                            stop_ev,
                            subscriber_name="settlement",
                            interval_s=interval,
                        ),
                        name="bolt12-heartbeat-settlement",
                    )
                )
            if settings.bolt12_htlc_event_subscriber_enabled:
                tasks.append(
                    asyncio.create_task(
                        run_heartbeat_loop(
                            stop_ev,
                            subscriber_name="htlc_event",
                            interval_s=interval,
                        ),
                        name="bolt12-heartbeat-htlc-event",
                    )
                )
            if not tasks:
                return
            await asyncio.gather(*tasks, return_exceptions=True)

        _runtime.subscriber_heartbeat_task = asyncio.create_task(
            _spawn_heartbeats(_runtime.subscriber_heartbeat_stop),
            name="bolt12-subscriber-heartbeat",
        )

    # Settle watchdog — runs every 60s in this process so its
    # breaker ``record_failure`` calls land in the same registry
    # the responder reads from. No setting gates this beyond
    # ``BOLT12_INVOICE_SETTLE_WATCHDOG_MINUTES`` (which the tick
    # itself honours).
    if _runtime.settle_watchdog_task is None or _runtime.settle_watchdog_task.done():
        from app.services.bolt12.settle_watchdog import (
            run_settle_watchdog,
        )

        _runtime.settle_watchdog_stop = asyncio.Event()
        _runtime.settle_watchdog_task = asyncio.create_task(
            run_settle_watchdog(_runtime.settle_watchdog_stop),
            name="bolt12-settle-watchdog",
        )


async def stop_bolt12_runtime() -> None:
    """Stop the orchestrator + gateway. Idempotent and exception-safe."""
    # Stop the node-address pusher first so it stops trying to call
    # the client we're about to tear down.
    pusher_stop = _runtime.node_address_pusher_stop
    pusher_task = _runtime.node_address_pusher_task
    _runtime.node_address_pusher_stop = None
    _runtime.node_address_pusher_task = None
    if pusher_stop is not None:
        pusher_stop.set()
    if pusher_task is not None:
        try:
            await asyncio.wait_for(pusher_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
            pusher_task.cancel()
            try:
                await pusher_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    # Item 13: settlement subscriber.
    sub_stop = _runtime.settlement_subscriber_stop
    sub_task = _runtime.settlement_subscriber_task
    _runtime.settlement_subscriber_stop = None
    _runtime.settlement_subscriber_task = None
    if sub_stop is not None:
        sub_stop.set()
    if sub_task is not None:
        try:
            await asyncio.wait_for(sub_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
            sub_task.cancel()
            try:
                await sub_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    # Settle watchdog (2026-06-06 move).
    sw_stop = _runtime.settle_watchdog_stop
    sw_task = _runtime.settle_watchdog_task
    _runtime.settle_watchdog_stop = None
    _runtime.settle_watchdog_task = None
    if sw_stop is not None:
        sw_stop.set()
    if sw_task is not None:
        try:
            await asyncio.wait_for(sw_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
            sw_task.cancel()
            try:
                await sw_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    # Telemetry #1: HTLC event subscriber.
    hes_stop = _runtime.htlc_event_subscriber_stop
    hes_task = _runtime.htlc_event_subscriber_task
    _runtime.htlc_event_subscriber_stop = None
    _runtime.htlc_event_subscriber_task = None
    if hes_stop is not None:
        hes_stop.set()
    if hes_task is not None:
        try:
            await asyncio.wait_for(hes_task, timeout=5.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
            hes_task.cancel()
            try:
                await hes_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    # Subscriber heartbeat (T5).
    hb_stop = _runtime.subscriber_heartbeat_stop
    hb_task = _runtime.subscriber_heartbeat_task
    _runtime.subscriber_heartbeat_stop = None
    _runtime.subscriber_heartbeat_task = None
    if hb_stop is not None:
        hb_stop.set()
    if hb_task is not None:
        try:
            await asyncio.wait_for(hb_task, timeout=3.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
            hb_task.cancel()
            try:
                await hb_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    probe = _runtime.probe_task
    _runtime.probe_task = None
    if probe is not None:
        probe.cancel()
        try:
            await probe
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass

    service = _runtime.service
    client = _runtime.client
    _runtime.service = None
    _runtime.client = None
    # Clear permanently_disabled on a clean stop so the next
    # start_bolt12_runtime() (e.g. after the operator fixes config
    # and restarts) doesn't inherit a sticky abort flag.
    _runtime.permanently_disabled = False
    _runtime.reconnect_backoff_s = RECONNECT_BACKOFF_MIN_S
    if service is not None:
        try:
            await service.stop()
        except Exception:  # noqa: BLE001
            logger.exception("error stopping BOLT 12 runtime service")
    if client is not None:
        try:
            await client.close()
        except Exception:  # noqa: BLE001
            logger.exception("error closing BOLT 12 gateway client")
    if service is not None or client is not None:
        logger.info("BOLT 12 runtime stopped")


def get_bolt12_runtime_state() -> Bolt12RuntimeState:
    """Read-only snapshot for status endpoints. Never raises."""
    metrics_snapshot: dict[str, int] | None = None
    if _runtime.service is not None:
        try:
            metrics_snapshot = _runtime.service.metrics.to_dict()
        except Exception:  # noqa: BLE001 — never fail a status read
            metrics_snapshot = None
    return Bolt12RuntimeState(
        enabled=_is_enabled(),
        running=_runtime.running,
        target=settings.bolt12_gateway_grpc,
        last_error=_runtime.last_error,
        last_probe_at=_runtime.last_probe_at,
        last_probe_peer_count=_runtime.last_probe_peer_count,
        last_probe_node_id_hex=_runtime.last_probe_node_id_hex,
        consecutive_probe_failures=_runtime.consecutive_probe_failures,
        metrics=metrics_snapshot,
        permanently_disabled=_runtime.permanently_disabled,
        reconnect_count=_runtime.reconnect_count,
        last_inbound_mint_at=_runtime.last_inbound_mint_at,
        last_inbound_error=_runtime.last_inbound_error,
        last_inbound_error_at=_runtime.last_inbound_error_at,
        node_address_cache_size=_runtime.node_address_cache_size,
        node_address_last_push_at=_runtime.node_address_last_push_at,
        node_address_last_push_accepted=_runtime.node_address_last_push_accepted,
    )


def mark_inbound_mint_success() -> None:
    """Receive-path: responder finished minting an inbound invoice.

    Called by the responder once the LND ``add_blinded_invoice``
    call, encode, and DB persist all succeeded — i.e. before the
    invoice bytes are handed back to the orchestrator for wire
    send. The wire send itself is best-effort from this field's
    perspective; if the gateway-side send subsequently fails the
    orchestrator's send-failure metric counter
    (``gateway_send_failure_total``) is the canonical signal.

    Clears ``last_inbound_error`` + ``last_inbound_error_at`` so a
    healthy recovery isn't visually masked by a stale error from
    the prior drop. Idempotent; safe to call from any task on the
    asyncio loop.
    """
    _runtime.last_inbound_mint_at = datetime.now(timezone.utc)
    _runtime.last_inbound_error = None
    _runtime.last_inbound_error_at = None


def mark_inbound_error(reason: str) -> None:
    """Receive-path: an inbound invreq was dropped or failed to mint.

    ``reason`` is a short, structured string suitable for surfacing
    in a JSON status response (e.g. ``"rate_limit:per_peer"``,
    ``"concurrency_rejected"``, ``"lnd_mint_failed"``).

    Reasons that start with ``"rate_limit:"`` also bump the
    orchestrator's ``inbound_rate_limit_drops_total`` counter so
    a Prometheus scrape sees the load-shedding signal alongside
    the snapshot ``last_inbound_error`` field. Best-effort —
    silent no-op if the orchestrator isn't running (e.g. unit
    test exercising the responder in isolation).
    """
    _runtime.last_inbound_error = reason
    _runtime.last_inbound_error_at = datetime.now(timezone.utc)
    if reason.startswith("rate_limit:") and _runtime.service is not None:
        try:
            _runtime.service.metrics.inbound_rate_limit_drops_total += 1
        except Exception:  # noqa: BLE001 — never block the drop path
            pass


def mark_adaptive_depth_flip() -> None:
    """Option B-adaptive (2026-06-08): responder swapped from
    primary num_hops to alternative because the breaker marked
    every primary-depth intro as ``open``. Bumps the
    orchestrator counter so operators can see how often the
    adaptive fallback fires."""
    svc = _runtime.service
    if svc is None:
        return
    try:
        svc.metrics.inbound_adaptive_depth_flips_total += 1
    except Exception:  # noqa: BLE001 — never block the mint
        pass


def mark_node_address_push(accepted_count: int) -> None:
    """Address-pusher: a push completed.

    ``accepted_count`` is the gateway's ``accepted_count`` from the
    push response — the number of new entries it accepted into its
    cache (i.e. excluding duplicates of prior cache entries).
    Mirrored onto both ``node_address_cache_size`` (legacy field
    kept for dashboard compatibility) and
    ``node_address_last_push_accepted`` (the operationally precise
    name).
    """
    count = int(accepted_count)
    _runtime.node_address_cache_size = count
    _runtime.node_address_last_push_accepted = count
    _runtime.node_address_last_push_at = datetime.now(timezone.utc)


def get_bolt12_service() -> Bolt12Service:
    """FastAPI dependency: yield the running service or 503.

    Use as ``Depends(get_bolt12_service)`` in routes that need to
    actually send/receive onion messages. Read/decode-only routes
    do not need this.
    """
    if not _is_enabled():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_DISABLED_DETAIL,
        )
    if _runtime.service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_NOT_RUNNING_DETAIL,
        )
    return _runtime.service


# ── Test-only helpers ────────────────────────────────────────────


# Every background task the runtime tracks, paired with its stop
# event attribute (``None`` when the task has no stop event). Kept
# as a single source of truth so ``_reset_for_tests`` cancels ALL
# of them — a leaked task from a prior test that only cleared
# ``probe_task`` would otherwise keep firing into out-of-scope
# mocks on its next tick, breaking test isolation.
_TRACKED_TASK_ATTRS: Final = (
    ("probe_task", None),
    ("node_address_pusher_task", "node_address_pusher_stop"),
    ("settlement_subscriber_task", "settlement_subscriber_stop"),
    ("htlc_event_subscriber_task", "htlc_event_subscriber_stop"),
    ("subscriber_heartbeat_task", "subscriber_heartbeat_stop"),
    ("settle_watchdog_task", "settle_watchdog_stop"),
)


def _reset_for_tests() -> None:
    """Drop any singleton state. Tests only.

    Best-effort cancels EVERY orphaned background task so a leaked
    supervisor / subscriber / watchdog from a previous test doesn't
    keep firing into out-of-scope mocks. Cancellation is
    fire-and-forget — async tests that need to *await* a clean
    shutdown should call ``stop_bolt12_runtime`` in their own
    teardown.
    """
    for task_attr, stop_attr in _TRACKED_TASK_ATTRS:
        task = getattr(_runtime, task_attr, None)
        if task is not None and not task.done():
            task.cancel()
        setattr(_runtime, task_attr, None)
        # Drop the matching stop event so the next test gets a fresh
        # one rather than inheriting a leaked, already-set event.
        if stop_attr is not None:
            setattr(_runtime, stop_attr, None)
    _runtime.client = None
    _runtime.service = None
    _runtime.last_error = None
    _runtime.last_probe_at = None
    _runtime.last_probe_peer_count = None
    _runtime.last_probe_node_id_hex = None
    _runtime.consecutive_probe_failures = 0
    _runtime.permanently_disabled = False
    _runtime.reconnect_backoff_s = RECONNECT_BACKOFF_MIN_S
    _runtime.reconnect_count = 0
    _runtime.last_inbound_mint_at = None
    _runtime.last_inbound_error = None
    _runtime.last_inbound_error_at = None
    _runtime.node_address_cache_size = None
    _runtime.node_address_last_push_at = None
    _runtime.node_address_last_push_accepted = None
    _sentinel_checked["done"] = False


def _inject_for_tests(service: Bolt12Service | None) -> None:
    """Inject a (mock) service for endpoint tests. Tests only."""
    _runtime.service = service
    _runtime.client = None  # type: ignore[assignment]
    _runtime.last_error = None
