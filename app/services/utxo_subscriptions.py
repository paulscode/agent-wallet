# SPDX-License-Identifier: MIT
"""Receive-address subscription manager.

When the Electrum backend is active, this module subscribes to
scripthash notifications for every ``auto:receive`` address the
wallet has issued (i.e. every :class:`AddressPurpose` row). On a
push notification, it schedules a debounced
:func:`app.services.utxo_service.reconcile` so freshly-arrived
funds are picked up in seconds rather than at the next 5-min poll.

Strict design constraints:

* Best-effort. The 5-min reconcile poll keeps running and is the
  source of truth. Subscriptions only *accelerate* it.
* Bounded. We never enumerate every change address — only the
  receive addresses we explicitly issued. The per-client
  ``lnd_electrum_max_subscriptions`` cap (default 256) is the
  hard ceiling.
* Silently degrades. If Electrum is absent / the breaker is open
  / a subscribe RPC fails, the manager logs and moves on.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from sqlalchemy import select

from app.core.config import settings
from app.core.database import get_db_context
from app.models.utxo_label import AddressPurpose
from app.services.chain.electrum_protocol import address_to_scripthash

logger = logging.getLogger(__name__)


class ReceiveAddressSubscriber:
    """Singleton owning scripthash subscriptions for receive addresses.

    All public methods are no-ops when Electrum is not configured.
    """

    def __init__(self) -> None:
        # ``scripthash -> address`` so notifications can be
        # debug-logged with the human-readable address.
        self._sh_to_address: dict[str, str] = {}
        self._reconcile_task: Optional[asyncio.Task] = None
        self._reconcile_pending: bool = False
        self._lock = asyncio.Lock()
        self._started = False

    # ── Lifecycle ───────────────────────────────────────────────

    async def start(self) -> None:
        """Load every receive address from the DB and subscribe.

        Called from app lifespan after :func:`mempool_fee_service.start`.
        Safe to call when Electrum is not configured (no-op).
        """
        from app.services.mempool_fee_service import mempool_fee_service

        if self._started:
            return
        if not mempool_fee_service.has_electrum:
            return
        client = self._client()
        if client is None:
            return

        async with get_db_context() as db:
            rows = (await db.execute(select(AddressPurpose))).scalars().all()
        addresses = [r.address for r in rows if r.address]
        logger.info(
            "electrum receive subs: subscribing %d address(es) at startup",
            len(addresses),
        )
        for addr in addresses:
            await self._subscribe(addr)
        self._started = True

    async def stop(self) -> None:
        """Cancel any pending debounced reconcile. Subscriptions are
        torn down implicitly when the Electrum client closes."""
        if self._reconcile_task is not None and not self._reconcile_task.done():
            self._reconcile_task.cancel()
        self._reconcile_task = None
        self._reconcile_pending = False
        self._sh_to_address.clear()
        self._started = False

    # ── Subscription primitive ─────────────────────────────────

    async def subscribe(self, address: str) -> None:
        """Subscribe to ``address``. Idempotent and best-effort.

        Called from :func:`utxo_service.record_address_purpose` so
        newly-issued addresses get coverage without waiting for the
        next ``start()``.
        """
        await self._subscribe(address)

    async def _subscribe(self, address: str) -> None:
        from app.services.mempool_fee_service import mempool_fee_service

        if not mempool_fee_service.has_electrum:
            return
        client = self._client()
        if client is None:
            return
        try:
            scripthash = address_to_scripthash(address, settings.bitcoin_network)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "electrum receive subs: skipping %s (decode failed: %s)",
                address,
                exc,
            )
            return
        self._sh_to_address[scripthash] = address
        try:
            await client.subscribe_scripthash(scripthash, self._on_notification)
        except Exception as exc:  # noqa: BLE001
            # Cap reached, RPC failure, etc. Logged at DEBUG —
            # the 5-min poll keeps reconcile correct regardless.
            logger.debug(
                "electrum receive subs: subscribe %s failed: %s",
                address,
                exc,
            )

    def _client(self):  # type: ignore[no-untyped-def]
        from app.services.mempool_fee_service import mempool_fee_service

        electrum = mempool_fee_service._electrum  # type: ignore[attr-defined]
        return electrum.client if electrum is not None else None

    # ── Notification handler ───────────────────────────────────

    async def _on_notification(self, scripthash: str, status: Optional[str]) -> None:
        """Push handler: schedule a debounced reconcile.

        Multiple notifications within the debounce window coalesce
        into a single reconcile call.
        """
        addr = self._sh_to_address.get(scripthash, scripthash[:12] + "…")
        logger.debug(
            "electrum receive subs: notification for %s (status=%s)",
            addr,
            status,
        )
        async with self._lock:
            if self._reconcile_task is not None and not self._reconcile_task.done():
                # Already scheduled — let it run; coalesce.
                self._reconcile_pending = True
                return
            self._reconcile_task = asyncio.create_task(self._debounced_reconcile())

    async def _debounced_reconcile(self) -> None:
        try:
            # Coalesce a burst of notifications into one reconcile.
            await asyncio.sleep(2.0)
            while True:
                async with self._lock:
                    pending = self._reconcile_pending
                    self._reconcile_pending = False
                if not pending:
                    break
                await asyncio.sleep(2.0)
            await self._run_reconcile()
        except asyncio.CancelledError:
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning("electrum receive subs: reconcile after push failed: %s", exc)

    async def _run_reconcile(self) -> None:
        # Imported here to avoid a circular import at module load.
        from app.services import utxo_service

        async with get_db_context() as db:
            counters = await utxo_service.reconcile(db)
            await db.commit()
        logger.info(
            "electrum receive subs: reconcile (push) auto_labelled=%d spent=%d",
            counters.get("auto_labelled", 0),
            counters.get("spent_marked", 0),
        )


receive_address_subscriber = ReceiveAddressSubscriber()
