# SPDX-License-Identifier: MIT
"""Public chain-state service — facade over a ``ChainBackend``.

Historical name; kept so call sites and tests across the codebase
don't churn. The actual implementations live in
:mod:`app.services.chain`:

* :class:`MempoolHttpBackend` — Mempool Explorer REST (default).
* :class:`ElectrumChainBackend` — electrs over the Electrum protocol.

Selection is driven by ``CHAIN_BACKEND`` and ``LND_ELECTRUM_URL``
(see :class:`app.core.config.Settings`):

* ``chain_backend="electrum"`` — Electrum only; fail loud if it can't
  connect.
* ``chain_backend="mempool"`` — Mempool HTTP only.
* ``chain_backend="auto"`` (default) — when ``LND_ELECTRUM_URL`` is
  set, Electrum is **primary** and Mempool HTTP is the **fallback**
  used while the Electrum breaker is open. When the URL is unset the
  facade behaves identically to a plain Mempool HTTP backend.

``MempoolFeeService`` *inherits from* :class:`MempoolHttpBackend` so
the legacy internal surface (``_fee_cache``, ``_request``,
``_get_client``, ``_verify_tls`` …) remains available unchanged.
When Electrum is configured, public methods are overridden to dispatch
through :class:`ElectrumChainBackend` first and fall back to the
inherited HTTP implementation on error.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Optional, cast

from app.core.config import settings
from app.services.chain.mempool_http import (
    PRIORITY_MAP,
    PRIORITY_TARGET_CONF,
    MempoolHttpBackend,
)

if TYPE_CHECKING:
    from app.services.chain.electrum import ElectrumChainBackend

logger = logging.getLogger(__name__)

__all__ = [
    "PRIORITY_MAP",
    "PRIORITY_TARGET_CONF",
    "MempoolFeeService",
    "mempool_fee_service",
]


class MempoolFeeService(MempoolHttpBackend):
    """Routes chain queries to the configured backend(s).

    Inherits the full Mempool-HTTP surface so tests / call sites that
    poke private fields (``_fee_cache``, ``_request``, ``_client`` …)
    continue to work. When ``LND_ELECTRUM_URL`` is set we additionally
    spin up an :class:`ElectrumChainBackend` and override the public
    chain methods to try Electrum first.
    """

    def __init__(self) -> None:
        super().__init__()
        self._mode = settings.chain_backend
        self._electrum: Optional["ElectrumChainBackend"] = None
        url = (settings.lnd_electrum_url or "").strip()
        if self._mode == "electrum" or (self._mode == "auto" and url):
            from app.services.chain.electrum import ElectrumChainBackend

            self._electrum = ElectrumChainBackend.from_settings()

    # ── Lifecycle ───────────────────────────────────────────────────

    @property
    def has_electrum(self) -> bool:
        return self._electrum is not None

    @property
    def has_fallback(self) -> bool:
        # In strict ``electrum`` mode we never fall back.
        return self._electrum is not None and self._mode != "electrum"

    @property
    def primary_backend_name(self) -> str:
        return "electrum" if self._electrum is not None else "mempool"

    async def start(self) -> None:
        """Bring up the Electrum client (if configured)."""
        if self._electrum is None:
            return
        wait = self._mode == "electrum"  # only fail loud in strict mode
        try:
            await self._electrum.ensure_started(wait_for_connect=wait)
        except Exception as e:  # noqa: BLE001
            if self._mode == "electrum":
                raise
            logger.warning(
                "electrum: initial connection failed (%s) — operating with "
                "mempool HTTP fallback while supervisor retries.",
                e,
            )

    async def close(self) -> None:
        if self._electrum is not None:
            await self._electrum.close()
        await super().close()

    # ── Optional layer ─────────────────────────────────────────
    #
    # Helpers that return ``None`` whenever Electrum is absent or its
    # breaker is open. Callers use them as best-effort enrichment that
    # silently degrades — never as a load-bearing dependency.

    def _electrum_available(self) -> bool:
        """True when an Electrum backend exists and its breaker is closed."""
        if self._electrum is None:
            return False
        from app.services.chain.electrum import _ELECTRUM_BREAKER

        return _ELECTRUM_BREAKER.state != "open"

    @property
    def cached_tip_height(self) -> Optional[int]:
        """Pushed tip height from ``headers.subscribe`` (no RPC).

        Returns ``None`` when Electrum is absent / disconnected. Used
        for cheap urgency calculations (e.g. Boltz timeout countdown).
        """
        if self._electrum is None or self._electrum.client is None:
            return None
        return self._electrum.client.cached_tip_height

    async def optional_verify_tx(self, txid: str) -> Optional[dict[str, Any]]:
        """Best-effort independent verification that ``txid`` exists.

        Returns the verbose transaction dict (Electrum shape) when
        Electrum is healthy, else ``None``. Callers MUST treat
        ``None`` as "no information"; they MUST NOT fail their flow
        if this returns ``None``.
        """
        if not self._electrum_available():
            return None
        try:
            data, error = await self._electrum.get_transaction(txid)  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            return None
        if error is not None:
            return None
        return data

    async def optional_confirmations(self, txid: str) -> Optional[dict[str, Any]]:
        """Best-effort confirmation count via the active chain backend.

        Unlike :meth:`get_transaction_confirmations` (which raises /
        returns errors), this returns ``None`` on any failure so
        callers can omit the field cleanly.
        """
        try:
            data, error = await self.get_transaction_confirmations(txid)
        except Exception:  # noqa: BLE001
            return None
        if error is not None:
            return None
        return data

    # ── Routing helper ──────────────────────────────────────────────

    async def _dispatch(
        self,
        method_name: str,
        *args: Any,
    ) -> tuple[Any, Optional[str]]:
        """Try electrum first; on error fall back to inherited HTTP."""
        if self._electrum is not None:
            method = getattr(self._electrum, method_name)
            data, error = await method(*args)
            if error is None:
                return data, None
            if self._mode == "electrum":
                # Strict mode: no fallback.
                return None, error
            logger.info(
                "chain: electrum %s failed (%s) — falling back to mempool HTTP",
                method_name,
                error,
            )
        return cast(
            "tuple[Any, Optional[str]]",
            await getattr(MempoolHttpBackend, method_name)(self, *args),
        )

    # ── Public chain surface ────────────────────────────────────────
    #
    # Each override only takes effect when Electrum is configured;
    # otherwise we delegate straight back to ``super()`` so the legacy
    # behaviour (and patch points like ``self._request``) are
    # preserved bit-for-bit.

    async def get_recommended_fees(
        self,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        # Recommended-fee display is intentionally Mempool-HTTP-first
        # even when Electrum is configured. Electrum's
        # ``estimatesmartfee`` answers a different question (Core's
        # conservative historical-confirmation model) than the
        # mempool.space ``/api/v1/fees/recommended`` engine, which
        # derives Low/Med/High from observed mempool block templates.
        # Operators who self-host a mempool instance expect the
        # dashboard to match that UI; surfacing Electrum's numbers
        # here led to user-visible disagreement (e.g. dashboard 2/3/5
        # vs. mempool 1/1/1 at the same instant). Strict
        # ``chain_backend="electrum"`` mode is the one exception —
        # operators in strict mode have explicitly opted out of any
        # HTTP fallback, so we honour that and route through Electrum.
        # Other chain methods (verify_tx, address/utxo lookups,
        # confirmations) still prefer Electrum since correctness, not
        # display parity, is the goal there.
        if self._electrum is None or self._mode != "electrum":
            data, error = await super().get_recommended_fees()
            if error is None:
                return data, None
            # HTTP failed: fall back to Electrum if we have it.
            if self._electrum is not None:
                logger.info(
                    "chain: mempool HTTP get_recommended_fees failed (%s) — falling back to electrum estimatesmartfee",
                    error,
                )
                e_data, e_error = await self._electrum.get_recommended_fees()
                if e_error is None:
                    return e_data, None
            return None, error
        # Strict electrum mode: no HTTP fallback at all.
        return await self._electrum.get_recommended_fees()

    async def get_fee_for_priority(self, priority: str = "medium") -> Optional[int]:
        if self._electrum is None:
            return await super().get_fee_for_priority(priority)
        try:
            rate = await self._electrum.get_fee_for_priority(priority)
        except Exception as e:  # noqa: BLE001
            logger.warning("electrum get_fee_for_priority failed: %s", e)
            rate = None
        if rate is not None:
            return rate
        if self._mode == "electrum":
            return None
        return await super().get_fee_for_priority(priority)

    def get_target_conf_for_priority(self, priority: str = "medium") -> int:
        return PRIORITY_TARGET_CONF.get(priority.lower(), 6)

    async def get_transaction(self, txid: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        if self._electrum is None:
            return await super().get_transaction(txid)
        return await self._dispatch("get_transaction", txid)

    async def get_transaction_confirmations(self, txid: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        if self._electrum is None:
            return await super().get_transaction_confirmations(txid)
        return await self._dispatch("get_transaction_confirmations", txid)

    async def get_address(self, address: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        if self._electrum is None:
            return await super().get_address(address)
        return await self._dispatch("get_address", address)

    async def get_address_utxos(self, address: str) -> tuple[Optional[list[dict[str, Any]]], Optional[str]]:
        if self._electrum is None:
            return await super().get_address_utxos(address)
        return await self._dispatch("get_address_utxos", address)

    async def get_mempool_stats(
        self,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        if self._electrum is None:
            return await super().get_mempool_stats()
        return await self._dispatch("get_mempool_stats")

    async def get_block_tip_height(self) -> tuple[Optional[int], Optional[str]]:
        if self._electrum is None:
            return await super().get_block_tip_height()
        return await self._dispatch("get_block_tip_height")

    async def get_block_by_height(self, height: int) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        if self._electrum is None:
            return await super().get_block_by_height(height)
        return await self._dispatch("get_block_by_height", height)


mempool_fee_service = MempoolFeeService()
