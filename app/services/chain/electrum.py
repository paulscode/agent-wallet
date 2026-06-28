# SPDX-License-Identifier: MIT
"""Electrum protocol client + ``ChainBackend`` adapter.

* :class:`ElectrumClient` — long-lived TCP/SSL connection that
  speaks newline-delimited JSON-RPC, owns request/response
  correlation, dispatches subscription notifications, and reconnects
  with exponential backoff.
* :class:`ElectrumChainBackend` — thin adapter on top of
  ``ElectrumClient`` that produces the same return shapes as
  :class:`MempoolHttpBackend`.

The client is **lazy-started** by
:func:`ElectrumChainBackend.ensure_started` rather than by import side
effects. When ``LND_ELECTRUM_URL`` is unset the backend is never
instantiated at all; when it is set, startup is supervised by the
wallet's lifespan handler so connection failures fail loud (in
``electrum`` mode) or fall back gracefully (in ``auto`` mode).
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
import random
import struct
import time
from typing import Any, Awaitable, Callable, Optional

from app.core.config import settings
from app.core.resilience import BreakerOpenError, CircuitBreaker, with_retry
from app.services.chain.backend import MAX_SANE_FEERATE_SAT_PER_VB
from app.services.chain.electrum_protocol import (
    ElectrumUrl,
    address_to_scripthash,
    open_electrum_transport,
)
from app.services.health import register_health

logger = logging.getLogger(__name__)


# ─── Cache TTLs (mirror MempoolHttpBackend) ──────────────────────────────

_CACHE_TTL_SECONDS = 60
_MEMPOOL_STATS_CACHE_TTL = 30

# Maximum line length we'll accept from the server. Scripthash
# histories on heavily-used addresses can reach a few hundred KB; 16
# MiB is a defensive cap against runaway / hostile servers.
_MAX_LINE_BYTES = 16 * 1024 * 1024


PRIORITY_TARGET_BLOCKS = {
    "low": 144,
    "medium": 6,
    "high": 1,
}

PRIORITY_MAP_KEY = {
    "low": "hourFee",
    "medium": "halfHourFee",
    "high": "fastestFee",
}


# ─── Errors ──────────────────────────────────────────────────────────────


class ElectrumError(RuntimeError):
    """Base for transport / protocol errors."""


class ElectrumProtocolError(ElectrumError):
    """Server returned a JSON-RPC error response."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"electrum {code}: {message}")
        self.code = code
        self.message = message


class ElectrumDisconnectedError(ElectrumError):
    """Connection dropped while a request was in flight."""


# ─── Client ──────────────────────────────────────────────────────────────


# Module-level breaker so the supervisor and adapter share state
# even if the backend is reinstantiated (e.g. test reload).
_ELECTRUM_BREAKER = CircuitBreaker(
    name="electrum",
    failure_threshold=8,
    open_duration_s=30.0,
)
_ELECTRUM_HEALTH = register_health("electrum", enabled=False, breaker=_ELECTRUM_BREAKER)


class ElectrumClient:
    """One supervised TCP/SSL connection to an Electrum server."""

    SCRIPTHASH_NOTIFICATION = "blockchain.scripthash.subscribe"
    HEADERS_NOTIFICATION = "blockchain.headers.subscribe"

    def __init__(
        self,
        url: str,
        *,
        tls_verify: bool = True,
        ca_cert: str = "",
        tor_proxy: str = "",
        force_tor: bool = False,
        connect_timeout_s: float = 10.0,
        request_timeout_s: float = 8.0,
        ping_interval_s: float = 30.0,
        max_subscriptions: int = 256,
        client_id: str = "agent-wallet/0.1.0",
        protocol_version: str = "1.4",
    ) -> None:
        self._url = ElectrumUrl.parse(url)
        self._tls_verify = tls_verify
        self._ca_cert = ca_cert
        self._tor_proxy = tor_proxy
        self._force_tor = force_tor
        self._connect_timeout_s = connect_timeout_s
        self._request_timeout_s = request_timeout_s
        self._ping_interval_s = ping_interval_s
        self._max_subscriptions = max_subscriptions
        self._client_id = client_id
        self._protocol_version = protocol_version

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._supervisor_task: Optional[asyncio.Task[None]] = None
        self._ping_task: Optional[asyncio.Task[None]] = None
        self._next_id = itertools.count(1)
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._connected = asyncio.Event()
        self._handshake_done = asyncio.Event()
        self._stop = False
        self._write_lock = asyncio.Lock()
        # The event loop this client's asyncio state (Events, Locks,
        # Futures, supervisor/transport) is bound to. The client is a
        # process-wide singleton, but Celery runs each task on a fresh,
        # throwaway loop — reusing loop-bound state across loops raises
        # "bound to a different event loop". ``_rebind_loop_if_changed``
        # rebuilds the state on the current loop when this differs.
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Subscription state.
        self._scripthash_subs: dict[str, list[Callable[[str, str | None], Awaitable[None]]]] = {}
        self._tip: Optional[dict[str, Any]] = None  # {"height": int, "hex": str}
        self._tip_lock = asyncio.Lock()

        # Reconnect-log throttling. The supervisor retries forever
        # while the backend (e.g. electrs-liquid during Liquid IBD)
        # is unreachable, which would otherwise emit two log lines
        # every ~30s indefinitely and bury other diagnostics. We
        # log the *first* failure of a streak at WARNING, identical
        # subsequent failures at DEBUG, an occasional WARNING
        # summary every ``_failure_log_every`` attempts, and an
        # INFO line on recovery. ``_last_failure_sig`` collapses
        # repeated identical errors; a change in error class still
        # surfaces immediately.
        self._consecutive_failures: int = 0
        self._last_failure_sig: Optional[str] = None
        self._failure_log_every: int = 20

    # ── Public lifecycle ────────────────────────────────────────────

    async def start(self, *, wait_for_connect: bool = True) -> None:
        # Record the loop we're building state on so the connection's own
        # internal ``request()`` calls (handshake, ping) don't see a loop
        # change and tear themselves down. ``_rebind_loop_if_changed``
        # only acts when the running loop actually differs from this.
        self._rebind_loop_if_changed()
        if self._supervisor_task is not None:
            return
        self._stop = False
        self._supervisor_task = asyncio.create_task(self._supervise(), name=f"electrum-{self._url.host}")
        if wait_for_connect:
            try:
                await asyncio.wait_for(
                    self._handshake_done.wait(),
                    timeout=self._connect_timeout_s * 3,
                )
            except asyncio.TimeoutError:
                # Don't tear down — supervisor keeps trying. Caller decides.
                raise ConnectionError(
                    f"electrum: failed to connect to {self._url.host}:{self._url.port} "
                    f"within {self._connect_timeout_s * 3:.0f}s"
                )

    async def close(self) -> None:
        self._stop = True
        self._connected.clear()
        self._handshake_done.clear()
        if self._ping_task is not None:
            self._ping_task.cancel()
            try:
                await self._ping_task
            except (asyncio.CancelledError, Exception):
                pass
            self._ping_task = None
        if self._supervisor_task is not None:
            self._supervisor_task.cancel()
            try:
                await self._supervisor_task
            except (asyncio.CancelledError, Exception):
                pass
            self._supervisor_task = None
        await self._teardown_connection(reason="close")

    @property
    def is_connected(self) -> bool:
        return self._connected.is_set()

    # ── Public RPC ──────────────────────────────────────────────────

    async def request(
        self,
        method: str,
        params: list[Any] | None = None,
        *,
        timeout: Optional[float] = None,
    ) -> Any:
        """Issue a JSON-RPC request; return the parsed ``result``."""
        # Rebuild loop-bound state if we're running on a different event
        # loop than last time (e.g. a fresh Celery per-task loop), so we
        # never touch an Event/Future bound to a dead loop.
        self._rebind_loop_if_changed()
        if not self.is_connected:
            # If the supervisor task has died silently (e.g. an
            # unhandled exception during reconnect), respawn it before
            # waiting — otherwise we'd time out 10 s every call forever.
            self._ensure_supervisor_alive()
            # Wait briefly for an in-progress reconnect; fail fast otherwise.
            try:
                await asyncio.wait_for(
                    self._connected.wait(),
                    timeout=self._connect_timeout_s,
                )
            except asyncio.TimeoutError:
                raise ElectrumDisconnectedError(f"electrum: not connected to {self._url.host}")

        rid = next(self._next_id)
        fut: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
        self._pending[rid] = fut
        payload = (
            json.dumps(
                {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or []},
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )

        writer = self._writer
        if writer is None:
            self._pending.pop(rid, None)
            raise ElectrumDisconnectedError("electrum: writer not available")

        # Bound ``writer.drain()`` so a dead Tor circuit (TCP still
        # ESTABLISHED until the 2-hour kernel keepalive) can't park
        # the write side indefinitely and wedge the supervisor.
        write_budget = timeout or self._request_timeout_s
        async with self._write_lock:
            try:
                writer.write(payload)
                await asyncio.wait_for(writer.drain(), timeout=write_budget)
            except asyncio.TimeoutError as e:
                self._pending.pop(rid, None)
                # Force the read side to surface EOF so the supervisor
                # can recycle the connection instead of waiting on a
                # silently-dead transport.
                try:
                    writer.close()
                except Exception:  # noqa: BLE001
                    pass
                raise ElectrumDisconnectedError(f"electrum: write drain timed out after {write_budget:.1f}s") from e
            except (ConnectionError, OSError) as e:
                self._pending.pop(rid, None)
                raise ElectrumDisconnectedError(f"electrum: write failed: {e}") from e

        try:
            return await asyncio.wait_for(fut, timeout=timeout or self._request_timeout_s)
        finally:
            self._pending.pop(rid, None)

    def _rebind_loop_if_changed(self) -> None:
        """Rebuild loop-bound state when the running loop has changed.

        Must be called from a running loop, before touching any asyncio
        state. The client is a process-wide singleton; under Celery each
        task runs on its own throwaway event loop (created then closed
        per task), so the ``asyncio.Event``/``Lock``/``Future`` objects
        and the supervisor/transport — all bound to the loop that made
        them — cannot be reused from another loop ("bound to a different
        event loop" / "Event loop is closed").

        On a loop change we abandon the old (now-dead-loop) state and
        recreate a fresh, disconnected state on the current loop. We do
        NOT cancel the old supervisor/ping tasks: their loop is already
        closed, so the references are simply dropped. The normal
        ``request()`` → ``_ensure_supervisor_alive`` → connect path then
        re-establishes the connection on the current loop.

        On the long-lived main loop (uvicorn) this is a no-op after the
        first call, so the persistent connection is preserved there.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._loop is loop:
            return
        self._loop = loop
        self._reader = None
        self._writer = None
        self._supervisor_task = None
        self._ping_task = None
        self._pending = {}
        self._connected = asyncio.Event()
        self._handshake_done = asyncio.Event()
        self._write_lock = asyncio.Lock()
        self._tip_lock = asyncio.Lock()
        self._consecutive_failures = 0
        self._last_failure_sig = None

    def _ensure_supervisor_alive(self) -> None:
        """Respawn the supervisor if it died silently.

        The supervisor task can exit early on an unhandled exception
        (rare, but seen after long Tor uptimes when an asyncio internal
        leaks out of the connect/teardown path). Without this guard the
        connection stays down until process restart.
        """
        if self._stop:
            return
        sup = self._supervisor_task
        if sup is None or sup.done():
            if sup is not None and sup.done() and not sup.cancelled():
                try:
                    exc = sup.exception()
                except (asyncio.CancelledError, asyncio.InvalidStateError):
                    exc = None
                if exc is not None:
                    logger.warning(
                        "electrum supervisor died with %s: %s — respawning",
                        type(exc).__name__,
                        exc,
                    )
                else:
                    logger.warning("electrum supervisor exited without error — respawning")
            self._supervisor_task = asyncio.create_task(self._supervise(), name=f"electrum-{self._url.host}")

    @property
    def cached_tip_height(self) -> Optional[int]:
        if self._tip is None:
            return None
        h = self._tip.get("height")
        return int(h) if isinstance(h, int) else None

    # ── Subscriptions ───────────────────────────────────────────────

    async def subscribe_scripthash(
        self,
        scripthash: str,
        callback: Callable[[str, str | None], Awaitable[None]],
    ) -> None:
        """Subscribe to scripthash notifications. Idempotent."""
        if len(self._scripthash_subs) >= self._max_subscriptions and (scripthash not in self._scripthash_subs):
            logger.warning(
                "electrum: refusing scripthash subscription, cap %d reached",
                self._max_subscriptions,
            )
            raise RuntimeError("electrum subscription cap reached")
        callbacks = self._scripthash_subs.setdefault(scripthash, [])
        if callback not in callbacks:
            callbacks.append(callback)
        # Send the subscribe RPC if connected; on reconnect they get replayed.
        if self.is_connected:
            try:
                await self.request("blockchain.scripthash.subscribe", [scripthash])
            except Exception as e:
                logger.warning("electrum: subscribe %s failed: %s", scripthash, e)

    async def unsubscribe_scripthash(
        self,
        scripthash: str,
        callback: Optional[Callable[[str, str | None], Awaitable[None]]] = None,
    ) -> None:
        callbacks = self._scripthash_subs.get(scripthash, [])
        if callback is None:
            self._scripthash_subs.pop(scripthash, None)
        else:
            try:
                callbacks.remove(callback)
            except ValueError:
                pass
            if not callbacks:
                self._scripthash_subs.pop(scripthash, None)
        if not self._scripthash_subs.get(scripthash) and self.is_connected:
            try:
                await self.request("blockchain.scripthash.unsubscribe", [scripthash])
            except Exception:
                pass  # Some servers don't implement; ignore.

    # ── Supervisor / connect loop ───────────────────────────────────

    async def _supervise(self) -> None:
        backoff = 1.0
        try:
            while not self._stop:
                try:
                    await self._connect_once()
                    if self._consecutive_failures > 0:
                        logger.info(
                            "electrum: connection to %s recovered after %d failed attempt(s)",
                            self._url.host,
                            self._consecutive_failures,
                        )
                    self._consecutive_failures = 0
                    self._last_failure_sig = None
                    backoff = 1.0  # reset on graceful disconnect after success
                except asyncio.CancelledError:
                    return
                except Exception as e:
                    _ELECTRUM_HEALTH.record_failure(f"{type(e).__name__}: {e}")
                    # ``asyncio.TimeoutError`` stringifies to '', so fall
                    # back to the class name when the message is empty.
                    err_str = str(e) if str(e) else type(e).__name__
                    sig = f"{type(e).__name__}:{err_str}"
                    self._consecutive_failures += 1

                    # Throttle: first failure of a streak, or a change in
                    # error signature, logs at WARNING. Identical repeats
                    # log at DEBUG, with a periodic WARNING summary every
                    # ``_failure_log_every`` attempts so operators still
                    # see the issue without being drowned in it.
                    is_new_streak = self._last_failure_sig != sig
                    is_periodic_summary = self._consecutive_failures % self._failure_log_every == 0
                    if is_new_streak:
                        logger.warning(
                            "electrum: connection to %s failed: %s; retry in ~%.1fs",
                            self._url.host,
                            err_str,
                            backoff,
                        )
                    elif is_periodic_summary:
                        logger.warning(
                            "electrum: connection to %s still failing after %d attempts: %s",
                            self._url.host,
                            self._consecutive_failures,
                            err_str,
                        )
                    else:
                        logger.debug(
                            "electrum: connection to %s failed (attempt %d): %s; retry in ~%.1fs",
                            self._url.host,
                            self._consecutive_failures,
                            err_str,
                            backoff,
                        )
                    self._last_failure_sig = sig
                if self._stop:
                    return
                jitter = backoff * 0.25 * (2 * random.random() - 1)
                try:
                    await asyncio.sleep(min(30.0, max(0.5, backoff + jitter)))
                except asyncio.CancelledError:
                    return
                backoff = min(30.0, backoff * 2)
        except BaseException as e:
            # Anything that escapes the while loop is a bug — log it
            # explicitly so ``_ensure_supervisor_alive`` has a diagnostic
            # trail rather than a silent death.
            if not isinstance(e, asyncio.CancelledError):
                logger.exception(
                    "electrum supervisor for %s exiting on unhandled %s",
                    self._url.host,
                    type(e).__name__,
                )
            raise

    async def _connect_once(self) -> None:
        # First attempt of a streak logs at INFO; subsequent retries
        # while the backend is unreachable are demoted to DEBUG so
        # the supervisor doesn't spam two log lines per ~30s during
        # extended outages (e.g. electrs-liquid during Liquid IBD).
        connect_log = logger.info if self._consecutive_failures == 0 else logger.debug
        connect_log(
            "electrum: connecting to %s://%s:%d",
            self._url.scheme,
            self._url.host,
            self._url.port,
        )
        reader, writer = await open_electrum_transport(
            self._url,
            tls_verify=self._tls_verify,
            ca_cert=self._ca_cert,
            tor_proxy=self._tor_proxy,
            force_tor=self._force_tor,
            connect_timeout=self._connect_timeout_s,
        )
        self._reader = reader
        self._writer = writer

        # Spawn the read loop FIRST so handshake responses get
        # dispatched into futures via ``request()``.
        read_task = asyncio.create_task(self._read_loop(reader), name=f"electrum-read-{self._url.host}")

        try:
            # Set ``_connected`` *before* the handshake — otherwise
            # ``request()`` would block waiting for the gate it itself
            # is supposed to open.
            self._connected.set()
            await self._handshake()
            self._handshake_done.set()
            _ELECTRUM_HEALTH.record_success()
            logger.info(
                "electrum: connected to %s (tip=%s)",
                self._url.host,
                self.cached_tip_height,
            )
            # Replay any active subscriptions.
            await self._replay_subscriptions()
            # Background ping loop.
            self._ping_task = asyncio.create_task(self._ping_loop(), name=f"electrum-ping-{self._url.host}")
            # Wait for the read loop to exit (= connection dropped).
            await read_task
        finally:
            self._connected.clear()
            self._handshake_done.clear()
            if self._ping_task is not None:
                self._ping_task.cancel()
                try:
                    await self._ping_task
                except (asyncio.CancelledError, Exception):
                    pass
                self._ping_task = None
            await self._teardown_connection(reason="reader-exit")
            # Cancel any pending requests with disconnect.
            for rid, fut in list(self._pending.items()):
                if not fut.done():
                    fut.set_exception(ElectrumDisconnectedError("electrum: connection closed"))
            self._pending.clear()

    async def _handshake(self) -> None:
        """Run server.version + headers.subscribe."""
        await self.request(
            "server.version",
            [self._client_id, self._protocol_version],
            timeout=self._connect_timeout_s,
        )
        tip = await self.request(
            "blockchain.headers.subscribe",
            [],
            timeout=self._connect_timeout_s,
        )
        if isinstance(tip, dict) and "height" in tip:
            self._tip = {
                "height": int(tip["height"]),
                "hex": tip.get("hex", ""),
            }

    async def _replay_subscriptions(self) -> None:
        for scripthash in list(self._scripthash_subs.keys()):
            try:
                await self.request("blockchain.scripthash.subscribe", [scripthash])
            except Exception as e:
                logger.warning(
                    "electrum: replay scripthash subscribe %s failed: %s",
                    scripthash,
                    e,
                )

    async def _ping_loop(self) -> None:
        try:
            while self.is_connected:
                await asyncio.sleep(self._ping_interval_s)
                if not self.is_connected:
                    return
                try:
                    await self.request("server.ping", [], timeout=self._request_timeout_s)
                except Exception as e:
                    # ``asyncio.TimeoutError`` stringifies to '', so use
                    # ``repr`` for a non-empty diagnostic.
                    logger.warning(
                        "electrum: ping failed (%s); forcing transport close to trigger supervisor reconnect",
                        e if str(e) else type(e).__name__,
                    )
                    # Force the read_task to unblock. A silently-dead
                    # Tor circuit may leave ``reader.readuntil`` parked
                    # for hours (Linux SO_KEEPALIVE default is 2 h
                    # before the first probe), so we close the writer
                    # explicitly to surface EOF on the reader side and
                    # let the supervisor's ``await read_task`` exit.
                    writer = self._writer
                    if writer is not None:
                        try:
                            writer.close()
                        except Exception:  # noqa: BLE001
                            pass
                    return
        except asyncio.CancelledError:
            return

    async def _teardown_connection(self, *, reason: str) -> None:
        writer = self._writer
        self._reader = None
        self._writer = None
        if writer is not None:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                # Cap wait_closed at 3 s — a silently-dead Tor circuit
                # can leave the TLS-shutdown handshake parked forever,
                # which would block the supervisor's reconnect cycle.
                await asyncio.wait_for(writer.wait_closed(), timeout=3.0)
            except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                pass
        logger.debug("electrum: torn down (%s)", reason)

    # ── Read loop / dispatch ────────────────────────────────────────

    async def _read_loop(self, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                line = await reader.readuntil(b"\n")
                if len(line) > _MAX_LINE_BYTES:
                    logger.warning("electrum: oversize frame (%d B); dropping", len(line))
                    return
                try:
                    msg = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as e:
                    logger.warning("electrum: bad JSON frame: %s", e)
                    continue
                self._dispatch(msg)
        except asyncio.IncompleteReadError:
            return
        except asyncio.LimitOverrunError as e:
            logger.warning("electrum: stream limit overrun: %s", e)
            return
        except (ConnectionError, OSError) as e:
            logger.info("electrum: read loop error: %s", e)
            return

    def _dispatch(self, msg: dict[str, Any]) -> None:
        if not isinstance(msg, dict):
            return
        if "id" in msg and msg["id"] is not None:
            try:
                rid = int(msg["id"])
            except (TypeError, ValueError):
                return
            fut = self._pending.get(rid)
            if fut is None or fut.done():
                return
            if "error" in msg and msg["error"]:
                err = msg["error"]
                if isinstance(err, dict):
                    fut.set_exception(
                        ElectrumProtocolError(
                            int(err.get("code", -1)),
                            str(err.get("message", "unknown")),
                        )
                    )
                else:
                    fut.set_exception(ElectrumProtocolError(-1, str(err)))
            else:
                fut.set_result(msg.get("result"))
            return

        # Notification.
        method = msg.get("method")
        params = msg.get("params") or []
        if method == self.HEADERS_NOTIFICATION:
            tip = params[0] if params else None
            if isinstance(tip, dict) and "height" in tip:
                self._tip = {
                    "height": int(tip["height"]),
                    "hex": tip.get("hex", ""),
                }
        elif method == self.SCRIPTHASH_NOTIFICATION:
            if len(params) >= 1:
                scripthash = params[0]
                status = params[1] if len(params) > 1 else None
                callbacks = list(self._scripthash_subs.get(scripthash, []))
                for cb in callbacks:
                    asyncio.create_task(self._safe_callback(cb, scripthash, status))

    @staticmethod
    async def _safe_callback(
        cb: Callable[[str, str | None], Awaitable[None]],
        scripthash: str,
        status: str | None,
    ) -> None:
        try:
            await cb(scripthash, status)
        except Exception as e:  # noqa: BLE001
            logger.warning("electrum: scripthash callback raised: %s", e)


# ─── Adapter ─────────────────────────────────────────────────────────────


def _btc_per_kb_to_sat_per_vb(rate: float) -> int:
    """Convert ``estimatefee`` BTC/kB → sat/vB (1 vB = 1 weight unit / 4).

    Raises ``ValueError`` when ``rate`` is non-positive. Bitcoin Core's
    ``estimatesmartfee`` / Electrum's ``blockchain.estimatefee`` returns
    ``-1`` to signal "no estimate available for this target" — this is
    very common on a quiet mempool for the 3-block (halfHourFee) and
    6-block (hourFee) targets. Callers MUST treat this as a failure
    and fall back to a different fee source rather than silently
    pinning the priority to 1 sat/vB (which produced the visible bug
    where Low/Med displayed as 1 while High was 5).
    """
    if rate is None or rate <= 0:
        raise ValueError(f"estimatefee unavailable (rate={rate!r})")
    sats_per_kvb = int(round(rate * 100_000_000.0 / 1000.0))
    # ``estimatefee`` is sat/kB but sat/vB == sat/kvB only for legacy.
    # For SegWit we should divide weight by 4 — but at the public-API
    # level mempool.space already publishes sat/vB directly. Emulate
    # the sat/vB shape by treating sat/kB as sat/kvB (the standard
    # convention used by Electrum clients).
    return max(1, sats_per_kvb)


def _decode_block_header(hex_header: str) -> dict[str, Any]:
    """Decode an 80-byte Bitcoin block header from hex.

    Returns the fields the wallet's mempool-shape exposes: ``hash``,
    ``timestamp``, ``previous_block_hash``. Other fields
    (``tx_count`` / ``size`` / ``weight`` / ``difficulty``) are not
    available from the header alone.
    """
    raw = bytes.fromhex(hex_header)
    if len(raw) != 80:
        raise ValueError(f"block header must be 80 bytes (got {len(raw)})")
    import hashlib

    block_hash = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
    prev_hash = raw[4:36][::-1].hex()
    timestamp = struct.unpack("<I", raw[68:72])[0]
    return {
        "hash": block_hash,
        "timestamp": int(timestamp),
        "previous_block_hash": prev_hash,
    }


class ElectrumChainBackend:
    """``ChainBackend`` adapter on top of :class:`ElectrumClient`."""

    name = "electrum"

    def __init__(
        self,
        client: Optional[ElectrumClient] = None,
        *,
        network: Optional[str] = None,
    ) -> None:
        self._client = client
        self._network = network or settings.bitcoin_network
        self._fee_cache: Optional[dict[str, Any]] = None
        self._fee_cache_time: float = 0.0
        self._mempool_stats_cache: Optional[dict[str, Any]] = None
        self._mempool_stats_cache_time: float = 0.0

    @classmethod
    def from_settings(cls) -> "ElectrumChainBackend":
        client = ElectrumClient(
            url=settings.lnd_electrum_url,
            tls_verify=settings.lnd_electrum_tls_verify,
            ca_cert=settings.lnd_electrum_ca_cert,
            tor_proxy=settings.lnd_tor_proxy,
            force_tor=settings.chain_backend_force_tor_enabled(),
            connect_timeout_s=settings.lnd_electrum_connect_timeout_s,
            request_timeout_s=settings.lnd_electrum_request_timeout_s,
            ping_interval_s=settings.lnd_electrum_ping_interval_s,
            max_subscriptions=settings.lnd_electrum_max_subscriptions,
        )
        return cls(client=client)

    @property
    def client(self) -> Optional[ElectrumClient]:
        return self._client

    async def ensure_started(self, *, wait_for_connect: bool = True) -> None:
        if self._client is not None:
            await self._client.start(wait_for_connect=wait_for_connect)
            _ELECTRUM_HEALTH.enabled = True

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()

    # ── Internal helpers ────────────────────────────────────────────

    async def _request(self, method: str, params: list[Any] | None = None) -> Any:
        if self._client is None:
            raise ElectrumError("electrum client not initialised")

        async def _attempt() -> Any:
            assert self._client is not None
            return await self._client.request(method, params)

        result = await with_retry(
            _attempt,
            retryable=(ElectrumDisconnectedError, asyncio.TimeoutError),
            backoff_s=(0.25,),
            breaker=_ELECTRUM_BREAKER,
            op_name=f"electrum {method}",
        )
        _ELECTRUM_HEALTH.record_success()
        return result

    async def _request_or_error(self, method: str, params: list[Any] | None = None) -> tuple[Any, Optional[str]]:
        try:
            result = await self._request(method, params)
            return result, None
        except BreakerOpenError as e:
            _ELECTRUM_HEALTH.record_failure(str(e))
            return None, f"electrum unavailable (breaker open): {e}"
        except Exception as e:
            logger.warning("electrum %s failed: %s", method, e)
            _ELECTRUM_HEALTH.record_failure(f"{type(e).__name__}: {e}")
            return None, f"electrum {method} failed: {type(e).__name__}: {e}"

    # ── ChainBackend surface ────────────────────────────────────────

    async def get_recommended_fees(
        self,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        now = time.time()
        if self._fee_cache and (now - self._fee_cache_time) < _CACHE_TTL_SECONDS:
            return self._fee_cache, None

        # Issue four estimatefee calls. Any failure = fall back to stale.
        targets = {"fastestFee": 1, "halfHourFee": 3, "hourFee": 6, "economyFee": 36, "minimumFee": 144}
        results: dict[str, int] = {}
        last_error: Optional[str] = None
        for label, blocks in targets.items():
            res, err = await self._request_or_error("blockchain.estimatefee", [blocks])
            if err is not None or res is None:
                last_error = err or "estimatefee returned null"
                break
            try:
                results[label] = _btc_per_kb_to_sat_per_vb(float(res))
            except (TypeError, ValueError) as e:
                # ``estimatefee`` returns -1 when Core has no estimate
                # for that target — common on quiet mempools for the
                # 3- / 6-block windows. Bail so the caller falls back
                # to the Mempool HTTP backend (which derives its
                # Low/Med/High from observed mempool block templates
                # rather than ``estimatesmartfee``).
                last_error = f"estimatefee {blocks}: {e}"
                break

        if last_error is not None:
            if self._fee_cache is not None:
                stale = dict(self._fee_cache)
                stale["stale"] = True
                stale["cache_age_s"] = int(now - self._fee_cache_time)
                return stale, None
            return None, last_error

        # Sanity ordering: hourFee <= halfHourFee <= fastestFee, etc.
        # estimatefee can be inconsistent at low congestion; clamp.
        # Also clamp the top rate to a sane ceiling so a malicious/
        # compromised server can't feed an enormous feerate that an
        # automated send would burn as miner fee — clamping ``ff`` bounds
        # the whole cascade since each lower tier is min'd against it.
        raw_ff = max(int(results["fastestFee"]), 1)
        ff = min(raw_ff, MAX_SANE_FEERATE_SAT_PER_VB)
        if raw_ff > MAX_SANE_FEERATE_SAT_PER_VB:
            logger.warning(
                "electrum fastestFee %d sat/vB exceeds sane ceiling %d; clamping",
                raw_ff,
                MAX_SANE_FEERATE_SAT_PER_VB,
            )
        hhf = max(min(results["halfHourFee"], ff), 1)
        hf = max(min(results["hourFee"], hhf), 1)
        ef = max(min(results["economyFee"], hf), 1)
        mf = max(min(results["minimumFee"], ef), 1)
        out: dict[str, Any] = {
            "fastestFee": ff,
            "halfHourFee": hhf,
            "hourFee": hf,
            "economyFee": ef,
            "minimumFee": mf,
        }
        self._fee_cache = out
        self._fee_cache_time = now
        return out, None

    async def get_fee_for_priority(self, priority: str = "medium") -> Optional[int]:
        priority = priority.lower()
        if priority not in PRIORITY_MAP_KEY:
            priority = "medium"
        fees, _ = await self.get_recommended_fees()
        if not fees:
            return None
        rate = fees.get(PRIORITY_MAP_KEY[priority])
        if rate is None:
            return None
        return max(1, int(rate))

    async def get_transaction(self, txid: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        data, err = await self._request_or_error("blockchain.transaction.get", [txid, True])
        if err is not None:
            return None, err
        if not isinstance(data, dict):
            return None, "electrum: malformed transaction response"

        confirmations = int(data.get("confirmations") or 0)
        confirmed = confirmations > 0
        block_hash = data.get("blockhash")
        block_time = data.get("blocktime") or data.get("time")
        block_height: Optional[int] = None
        if confirmed and self._client is not None:
            tip = self._client.cached_tip_height
            if tip is not None:
                block_height = tip - confirmations + 1

        vouts: list[dict[str, Any]] = []
        for v in data.get("vout", []):
            spk = (v or {}).get("scriptPubKey") or {}
            addr = spk.get("address")
            if not addr:
                addrs = spk.get("addresses") or []
                addr = addrs[0] if addrs else None
            if addr:
                # ``value`` in verbose response is BTC; convert to sats.
                btc_val = v.get("value")
                try:
                    sats = int(round(float(btc_val) * 100_000_000)) if btc_val is not None else None
                except (TypeError, ValueError):
                    sats = None
                vouts.append({"scriptpubkey_address": addr, "value": sats})

        # ``fee`` is BTC in verbose response; convert to sats when present.
        fee_sats: Optional[int] = None
        fee_btc = data.get("fee")
        if fee_btc is not None:
            try:
                fee_sats = int(round(float(fee_btc) * 100_000_000))
            except (TypeError, ValueError):
                fee_sats = None

        return {
            "txid": data.get("txid"),
            "confirmed": confirmed,
            "block_height": block_height,
            "block_hash": block_hash,
            "block_time": block_time,
            "fee": fee_sats,
            "size": data.get("size"),
            "weight": data.get("weight"),
            "version": data.get("version"),
            "locktime": data.get("locktime"),
            "vin_count": len(data.get("vin", [])),
            "vout_count": len(data.get("vout", [])),
            "vout": vouts,
        }, None

    async def get_transaction_confirmations(self, txid: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        tx, err = await self.get_transaction(txid)
        if err is not None:
            return None, err
        assert tx is not None
        if not tx["confirmed"]:
            return {
                "txid": txid,
                "confirmed": False,
                "confirmations": 0,
                "block_height": None,
            }, None
        # Use cached tip rather than re-deriving from confirmations.
        tip_height: Optional[int] = self._client.cached_tip_height if self._client is not None else None
        block_height = tx.get("block_height")
        confirmations = 0
        if tip_height is not None and block_height is not None:
            confirmations = max(0, tip_height - block_height + 1)
        return {
            "txid": txid,
            "confirmed": True,
            "confirmations": confirmations,
            "block_height": block_height,
            "block_time": tx.get("block_time"),
        }, None

    async def get_address(self, address: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        try:
            sh = address_to_scripthash(address, self._network)
        except ValueError as e:
            return None, f"electrum: {e}"

        balance, err = await self._request_or_error("blockchain.scripthash.get_balance", [sh])
        if err is not None or not isinstance(balance, dict):
            return None, err or "electrum: malformed get_balance response"

        history, err = await self._request_or_error("blockchain.scripthash.get_history", [sh])
        if err is not None or not isinstance(history, list):
            return None, err or "electrum: malformed get_history response"

        confirmed_tx = sum(1 for h in history if isinstance(h, dict) and (h.get("height") or 0) > 0)
        unconfirmed_tx = sum(1 for h in history if isinstance(h, dict) and (h.get("height") or 0) <= 0)

        confirmed_sats = int(balance.get("confirmed") or 0)
        unconfirmed_sats = int(balance.get("unconfirmed") or 0)

        return {
            "address": address,
            "confirmed_balance_sats": confirmed_sats,
            "unconfirmed_balance_sats": unconfirmed_sats,
            "total_balance_sats": confirmed_sats + unconfirmed_sats,
            "confirmed_tx_count": confirmed_tx,
            "unconfirmed_tx_count": unconfirmed_tx,
            # Not derivable from electrum without per-output bookkeeping.
            "funded_txo_count": None,
            "spent_txo_count": None,
        }, None

    async def get_address_utxos(self, address: str) -> tuple[Optional[list[dict[str, Any]]], Optional[str]]:
        try:
            sh = address_to_scripthash(address, self._network)
        except ValueError as e:
            return None, f"electrum: {e}"

        data, err = await self._request_or_error("blockchain.scripthash.listunspent", [sh])
        if err is not None:
            return None, err
        if not isinstance(data, list):
            return None, "electrum: malformed listunspent response"
        return [
            {
                "txid": u.get("tx_hash"),
                "vout": u.get("tx_pos"),
                "value_sats": u.get("value"),
                "confirmed": (u.get("height") or 0) > 0,
                "block_height": u.get("height") if (u.get("height") or 0) > 0 else None,
            }
            for u in data
            if isinstance(u, dict)
        ], None

    async def get_mempool_stats(
        self,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        now = time.time()
        if self._mempool_stats_cache and (now - self._mempool_stats_cache_time) < _MEMPOOL_STATS_CACHE_TTL:
            return self._mempool_stats_cache, None

        data, err = await self._request_or_error("mempool.get_fee_histogram", [])
        if err is not None:
            return None, err
        if not isinstance(data, list):
            return None, "electrum: malformed fee histogram response"
        # Histogram entries are [fee_rate_sat_vb, vsize] pairs.
        result = {
            # ``tx_count`` / ``total_vsize`` / ``total_fee_btc`` are
            # not exposed by electrum; keep the keys present (clients
            # tolerate ``None``) but don't fabricate numbers.
            "tx_count": None,
            "total_vsize": None,
            "total_fee_btc": None,
            "fee_histogram": data,
        }
        self._mempool_stats_cache = result
        self._mempool_stats_cache_time = now
        return result, None

    async def get_block_tip_height(self) -> tuple[Optional[int], Optional[str]]:
        # Prefer the pushed cache.
        if self._client is not None and self._client.cached_tip_height is not None:
            _ELECTRUM_HEALTH.record_success()
            return self._client.cached_tip_height, None
        # Fallback: re-subscribe (no-op if already subscribed; returns current tip).
        data, err = await self._request_or_error("blockchain.headers.subscribe", [])
        if err is not None:
            return None, err
        if isinstance(data, dict) and "height" in data:
            return int(data["height"]), None
        return None, "electrum: malformed headers.subscribe response"

    async def get_block_by_height(self, height: int) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        data, err = await self._request_or_error("blockchain.block.header", [height])
        if err is not None:
            return None, err
        if not isinstance(data, str):
            return None, "electrum: malformed block.header response"
        try:
            decoded = _decode_block_header(data)
        except ValueError as e:
            return None, f"electrum: {e}"
        return {
            "hash": decoded["hash"],
            "height": int(height),
            "timestamp": decoded["timestamp"],
            "previous_block_hash": decoded["previous_block_hash"],
            # Not derivable from header alone.
            "tx_count": None,
            "size": None,
            "weight": None,
            "difficulty": None,
        }, None
