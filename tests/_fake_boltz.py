# SPDX-License-Identifier: MIT
"""In-process fake of the Boltz REST API.

``BoltzSwapService`` reaches Boltz over HTTP through an injectable
``httpx.AsyncClient`` (``service._client``). This fake backs that client
with an ``httpx.MockTransport`` that speaks the subset of the Boltz v2 API
the swap lifecycle uses, records every request for contract assertions,
and lets a test drive the reported swap status across lifecycle phases —
all without a network or a real Boltz.

Usage::

    fake = FakeBoltzServer()
    service = BoltzSwapService()
    fake.install(service, monkeypatch)
    fake.swap_status = "transaction.mempool"
    swap, err = await service.advance_swap(db, swap)
"""

from __future__ import annotations

import json
from typing import Any

import httpx

__all__ = ["FakeBoltzServer"]


class FakeBoltzServer:
    """Programmable MockTransport-backed Boltz API."""

    def __init__(self) -> None:
        # Recorded (method, path, json_body) for every request.
        self.requests: list[tuple[str, str, Any]] = []
        # The status the next GET /swap/{id} reports — a test flips this
        # between calls to drive the lifecycle.
        self.swap_status: str = "swap.created"
        # The lockup-transaction hex returned by GET .../{id}/transaction.
        self.lockup_tx_hex: str = "02000000" + "00" * 40
        # Response payloads for the create / pair-info routes.
        self.reverse_pair_info: dict[str, Any] = {
            "BTC": {
                "BTC": {
                    "limits": {"minimal": 25_000, "maximal": 25_000_000},
                    "fees": {"percentage": 0.5, "minerFees": {"lockup": 200, "claim": 600}},
                    "hash": "pairhash",
                }
            }
        }
        self.reverse_create: dict[str, Any] = {}
        # When set, every route returns this HTTP status (drives the
        # error/5xx path without a second client).
        self.force_status_code: int | None = None

    # ── request routing ───────────────────────────────────────────────
    def _handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        body = json.loads(request.content) if request.content else None
        self.requests.append((method, path, body))

        if self.force_status_code is not None:
            return httpx.Response(self.force_status_code, json={"error": "forced"})

        if method == "GET" and path.endswith("/swap/reverse"):
            return httpx.Response(200, json=self.reverse_pair_info)
        if method == "POST" and path.endswith("/swap/reverse"):
            return httpx.Response(200, json=self.reverse_create)
        if method == "GET" and path.endswith("/transaction"):
            return httpx.Response(200, json={"hex": self.lockup_tx_hex})
        if method == "GET" and "/swap/" in path:
            swap_id = path.rsplit("/", 1)[-1]
            return httpx.Response(200, json={"id": swap_id, "status": self.swap_status})
        return httpx.Response(404, json={"error": f"unrouted {method} {path}"})

    # ── installation ──────────────────────────────────────────────────
    def install(self, service: Any, monkeypatch: Any) -> "FakeBoltzServer":
        """Point ``service`` at this fake: inject a MockTransport client and
        pin the Boltz URL to a clearnet host so requests route here."""
        from app.core.config import settings

        monkeypatch.setattr(settings, "boltz_use_tor", False)
        monkeypatch.setattr(settings, "boltz_api_url", "https://boltz.test/v2")
        service._client = httpx.AsyncClient(transport=httpx.MockTransport(self._handler))
        return self

    # ── assertion helpers ─────────────────────────────────────────────
    def paths(self, method: str | None = None) -> list[str]:
        """Recorded request paths, optionally filtered by HTTP method."""
        return [p for (m, p, _b) in self.requests if method is None or m == method]
