# SPDX-License-Identifier: MIT
"""In-process fake of ``lnd_service`` (the LND REST client singleton).

A faithful stand-in for the methods the wallet's flows call, returning the
real ``(data, error)`` tuple contract — success ``(data, None)``, failure
``(None, "message")`` — with response shapes from ``tests.helpers``.
Every call is recorded for assertions, and any method's result can be
overridden per test via :meth:`set_result` / :meth:`set_error`.

Inject it wherever ``lnd_service`` is consumed:

* constructor-injected services (e.g. ``BraiinsDepositService(lnd_service=fake)``)
* module singletons: ``monkeypatch.setattr("app.services.lnd_service.lnd_service", fake)``
"""

from __future__ import annotations

from typing import Any

from tests.helpers import lnd_channel, lnd_get_info, lnd_invoice, lnd_wallet_balance

__all__ = ["FakeLndService"]


class FakeLndService:
    def __init__(self, *, fresh_address: str = "bcrt1pfreshtaprootaddress") -> None:
        self.fresh_address = fresh_address
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._results: dict[str, tuple[Any, Any]] = {}

    # ── per-test configuration ────────────────────────────────────────
    def set_result(self, method: str, data: Any) -> None:
        """Force ``method`` to return ``(data, None)``."""
        self._results[method] = (data, None)

    def set_error(self, method: str, message: str) -> None:
        """Force ``method`` to return ``(None, message)``."""
        self._results[method] = (None, message)

    def _ret(self, method: str, default: Any, **kwargs: Any) -> tuple[Any, Any]:
        self.calls.append((method, kwargs))
        return self._results.get(method, (default, None))

    def called(self, method: str) -> bool:
        return any(m == method for m, _ in self.calls)

    # ── wallet / node ─────────────────────────────────────────────────
    async def get_info(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret("get_info", lnd_get_info())

    async def get_wallet_balance(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret("get_wallet_balance", lnd_wallet_balance())

    async def new_address(self, address_type: str = "p2tr", *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret(
            "new_address",
            {"address": self.fresh_address, "address_type": address_type},
            address_type=address_type,
        )

    async def inbound_capacity(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret(
            "inbound_capacity",
            {"total_receivable_sats": 100_000_000, "largest_channel_receivable_sats": 100_000_000},
        )

    # ── invoices ──────────────────────────────────────────────────────
    async def create_invoice(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret("create_invoice", lnd_invoice(), **kwargs)

    async def lookup_invoice(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret("lookup_invoice", {"settled": True, "state": "SETTLED", "amt_paid_sat": 0})

    # ── channels / routing ────────────────────────────────────────────
    async def get_channels(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret("get_channels", [lnd_channel()])

    async def query_routes(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret("query_routes", {"hops": 1, "total_amt_sat": 0, "total_fees_sat": 0})

    async def connect_peer(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret("connect_peer", {"ok": True})

    async def open_channel(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret("open_channel", {"funding_txid": "ab" * 32, "output_index": 0})

    # ── on-chain ──────────────────────────────────────────────────────
    async def send_coins(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret("send_coins", {"txid": "fd" + "0" * 62}, **kwargs)

    async def list_unspent(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret("list_unspent", [], **kwargs)

    async def get_transactions(self, *args: Any, **kwargs: Any) -> tuple[Any, Any]:
        return self._ret("get_transactions", [])
