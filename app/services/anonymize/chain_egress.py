# SPDX-License-Identifier: MIT
"""Anonymize-stack-direct chain-backend client.

The general-wallet ``mempool_fee_service`` shares one chain backend
connection across every wallet caller; an anonymize-stack
confirmation poll routed through it would let the chain-backend
operator correlate anonymize lookups with the wallet's general
activity. specifies a *dedicated* chain client whose only
caller is the anonymize stack, routed through its own SOCKS
listener so circuit isolation holds.

This module ships:

* :func:`get_anonymize_tx_confirmations` — read confirmation depth
  for a txid. The reorg-aware completion path consumes this.
* :func:`anonymize_broadcast_tx` — POST a raw tx hex to the chain
  backend. The self-broadcast fallback consumes this.

Both helpers wrap :func:`get_anonymize_client` with the
``chain_backend_anonymize`` call-site so they:

* go through the dedicated SOCKS listener (listener
  separation),
* mint a fresh SOCKS auth pair per call (stream isolation),
* count against the circuit-rebuild budget,
* emit only the pinned header set.

The backend URL is resolved via :func:`chain.get_anonymize_chain_client_spec`
so the configuration knob lives in one place. Unset / empty backend
URLs short-circuit to a structured error rather than an unhandled
exception — the orchestrator routes the session through
reconciliation when the chain backend is unreachable.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.core.http_limits import request_capped

from .chain import (
    ChainBackendError,
    assert_txid_query_allowed,
    get_anonymize_chain_client_spec,
)
from .http import get_anonymize_client
from .metadata import ANONYMIZE_LOGGER_NAME
from .tor import resolve_socks_host, resolve_socks_port

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


_CALL_SITE = "chain_backend_anonymize"


def _resolved_socks_port() -> int:
    return resolve_socks_port(_CALL_SITE)


def _resolved_socks_host() -> str:
    return resolve_socks_host()


def _resolved_base_url() -> str:
    spec = get_anonymize_chain_client_spec()
    return (spec.backend_url or "").rstrip("/")


async def get_anonymize_tx_confirmations(
    txid: str,
    *,
    base_url: str | None = None,
    socks_host: str | None = None,
    socks_port: int | None = None,
    timeout_s: float = 30.0,
) -> tuple[dict[str, Any] | None, str | None]:
    """Read confirmation depth for ``txid`` through the
    dedicated anonymize chain client.

    Returns ``({txid, confirmed, confirmations, block_height}, None)``
    on success or ``(None, error)`` on failure. The shape matches the
    wallet's ``get_transaction_confirmations`` so the per-session
    reverse-exit observer can consume either client transparently.

    The endpoint shape is the mempool.space HTTP API (also implemented
    by electrs's ``--http-addr`` REST adapter); operators who run an
    Electrum-RPC-only backend are degraded to ``[~]`` and configure
    the HTTP-shaped electrs adapter instead.
    """
    canonical_txid = assert_txid_query_allowed(txid)

    resolved_base = (base_url or _resolved_base_url()).rstrip("/")
    if not resolved_base:
        return None, "anonymize chain backend URL not configured"
    resolved_host = socks_host or _resolved_socks_host()
    resolved_port = socks_port if socks_port is not None else _resolved_socks_port()

    tx_url = f"{resolved_base}/api/tx/{canonical_txid}"
    tip_url = f"{resolved_base}/api/blocks/tip/height"

    try:
        async with get_anonymize_client(
            call_site=_CALL_SITE,
            socks_host=resolved_host,
            socks_port=resolved_port,
            timeout_s=timeout_s,
        ) as client:
            tx_resp = await request_capped(client, "GET", tx_url)
            if tx_resp.status_code == 404:
                return {
                    "txid": canonical_txid,
                    "confirmed": False,
                    "confirmations": 0,
                    "block_height": None,
                }, None
            tx_resp.raise_for_status()
            tx_data = tx_resp.json()
    except httpx.HTTPStatusError as exc:
        return None, (f"anonymize chain tx query failed: {exc.response.status_code}: {exc.response.text[:200]}")
    except Exception as exc:  # noqa: BLE001
        return None, f"anonymize chain tx query failed: {exc}"

    status = tx_data.get("status", {}) if isinstance(tx_data, dict) else {}
    if not status.get("confirmed"):
        return {
            "txid": canonical_txid,
            "confirmed": False,
            "confirmations": 0,
            "block_height": None,
        }, None

    block_height = status.get("block_height")
    if block_height is None:
        return None, "anonymize chain tx response missing block_height"

    # Tip-height query goes through a fresh anonymize client so the
    # SOCKS auth (and therefore the Tor circuit) rotates between the
    # two HTTP calls — defeats a passive observer that would otherwise
    # see two requests on the same circuit and learn they're paired.
    try:
        async with get_anonymize_client(
            call_site=_CALL_SITE,
            socks_host=resolved_host,
            socks_port=resolved_port,
            timeout_s=timeout_s,
        ) as client:
            tip_resp = await request_capped(client, "GET", tip_url)
            tip_resp.raise_for_status()
            tip_height = int(tip_resp.text.strip())
    except Exception as exc:  # noqa: BLE001
        return None, f"anonymize chain tip query failed: {exc}"

    confs = max(0, tip_height - int(block_height) + 1)
    return {
        "txid": canonical_txid,
        "confirmed": True,
        "confirmations": confs,
        "block_height": int(block_height),
    }, None


async def anonymize_broadcast_tx(
    tx_hex: str,
    *,
    base_url: str | None = None,
    socks_host: str | None = None,
    socks_port: int | None = None,
    timeout_s: float = 30.0,
) -> tuple[str | None, str | None]:
    """POST a raw tx hex to the dedicated chain backend.

    Returns ``(txid, None)`` on success or ``(None, error)`` on
    failure. The mempool.space + electrs REST shape is
    ``POST /api/tx`` with the hex as the request body; the response
    body is the broadcast txid.
    """
    if not isinstance(tx_hex, str) or not tx_hex.strip():
        return None, "tx_hex must be a non-empty string"

    resolved_base = (base_url or _resolved_base_url()).rstrip("/")
    if not resolved_base:
        return None, "anonymize chain backend URL not configured"
    resolved_host = socks_host or _resolved_socks_host()
    resolved_port = socks_port if socks_port is not None else _resolved_socks_port()

    url = f"{resolved_base}/api/tx"
    try:
        async with get_anonymize_client(
            call_site=_CALL_SITE,
            socks_host=resolved_host,
            socks_port=resolved_port,
            timeout_s=timeout_s,
        ) as client:
            response = await request_capped(
                client,
                "POST",
                url,
                content=tx_hex.strip().encode("ascii"),
            )
            response.raise_for_status()
            txid = response.text.strip()
    except httpx.HTTPStatusError as exc:
        return None, (f"anonymize chain broadcast failed: {exc.response.status_code}: {exc.response.text[:200]}")
    except Exception as exc:  # noqa: BLE001
        return None, f"anonymize chain broadcast failed: {exc}"

    # The mempool.space API returns the raw txid as the body; sanity
    # check the shape so a misbehaving operator can't write a stale
    # confirmation marker.
    try:
        return assert_txid_query_allowed(txid), None
    except ChainBackendError as exc:
        return None, f"anonymize chain backend returned invalid txid: {exc}"


async def get_anonymize_economy_feerate(
    *,
    base_url: str | None = None,
    socks_host: str | None = None,
    socks_port: int | None = None,
    timeout_s: float = 30.0,
) -> tuple[float | None, str | None]:
    """Read the current mempool economy feerate.

    The cooperative-claim feerate sanity gate compares the
    operator's quoted ``swap.claimFeeRate`` against this estimate
    multiplied by the configured tolerance band; outliers refuse
    the claim.

    Returns ``(sat_per_vb, None)`` on success or ``(None, error)``
    on failure. The mempool.space JSON shape returns several
    priority levels under ``{"fastestFee", "halfHourFee", "hourFee",
    "economyFee", "minimumFee"}``; we read ``economyFee`` (rounded
    sat/vB integer per mempool.space; we cast to float).
    """
    resolved_base = (base_url or _resolved_base_url()).rstrip("/")
    if not resolved_base:
        return None, "anonymize chain backend URL not configured"
    resolved_host = socks_host or _resolved_socks_host()
    resolved_port = socks_port if socks_port is not None else _resolved_socks_port()

    url = f"{resolved_base}/api/v1/fees/recommended"
    try:
        async with get_anonymize_client(
            call_site=_CALL_SITE,
            socks_host=resolved_host,
            socks_port=resolved_port,
            timeout_s=timeout_s,
        ) as client:
            response = await request_capped(client, "GET", url)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as exc:
        return None, (f"anonymize chain feerate query failed: {exc.response.status_code}: {exc.response.text[:200]}")
    except Exception as exc:  # noqa: BLE001
        return None, f"anonymize chain feerate query failed: {exc}"

    if not isinstance(data, dict):
        return None, "anonymize chain feerate response was not a JSON object"
    economy = data.get("economyFee")
    if economy is None:
        # Fall back to minimumFee if economy missing (some backends).
        economy = data.get("minimumFee")
    if economy is None:
        return None, "anonymize chain feerate response missing economyFee"
    try:
        return float(economy), None
    except (TypeError, ValueError):
        return None, "anonymize chain feerate response had non-numeric value"


__all__ = [
    "get_anonymize_tx_confirmations",
    "anonymize_broadcast_tx",
    "get_anonymize_economy_feerate",
]
