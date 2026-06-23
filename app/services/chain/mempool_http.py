# SPDX-License-Identifier: MIT
"""Mempool Explorer HTTP backend.

Originally lived as ``MempoolFeeService`` in
``app/services/mempool_fee_service.py``; extracted here to fit the
``ChainBackend`` protocol so we can ship an alternative Electrum
backend alongside it.

Wraps the Mempool Explorer REST API for:

* Fee estimation (cached 60s)
* Transaction lookup and confirmation tracking
* Address balance/UTXO queries
* Mempool congestion statistics
* Block-height queries

All endpoints are configurable via ``LND_MEMPOOL_URL`` (default:
``https://mempool.space``). TLS verification is auto-adjusted: enabled
for public mempool.space, disabled for ``.onion``. Tor/SOCKS proxy is
auto-configured for ``.onion`` and ``.local`` URLs via
``LND_TOR_PROXY``.
"""

from __future__ import annotations

import ipaddress
import logging
import ssl
import time
from typing import Any, Optional, Union, cast
from urllib.parse import quote, urlparse, urlunparse

import httpx

from app.core.config import settings
from app.core.http_limits import request_capped
from app.core.resilience import (
    BreakerOpenError,
    CircuitBreaker,
    with_retry,
)
from app.core.tls import load_pinned_ca_context
from app.core.utils import force_remote_dns_socks
from app.services.chain.backend import clamp_feerate_sat_per_vb
from app.services.health import register_health

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 60
_MEMPOOL_STATS_CACHE_TTL = 30


# Retry + circuit breaker. Mempool is non-critical: fee estimation
# falls back gracefully to LND's own estimator and the on-chain views
# are mostly informational. The breaker is permissive but the stale
# fallback lets us serve last-known fees when the upstream is
# briefly down.
_MEMPOOL_BREAKER = CircuitBreaker(
    name="mempool",
    failure_threshold=8,
    open_duration_s=30.0,
)
_MEMPOOL_HEALTH = register_health("mempool", breaker=_MEMPOOL_BREAKER)

_MEMPOOL_RETRYABLE_EXC: tuple[type[BaseException], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.RemoteProtocolError,
    httpx.PoolTimeout,
    httpx.ProxyError,
)


class _MempoolRetryable5xxError(Exception):
    def __init__(self, status_code: int, body: str) -> None:
        super().__init__(f"mempool {status_code}: {body}")
        self.status_code = status_code
        self.body = body


PRIORITY_MAP = {
    "low": "hourFee",
    "medium": "halfHourFee",
    "high": "fastestFee",
}

PRIORITY_TARGET_CONF = {
    "low": 144,
    "medium": 6,
    "high": 1,
}


class MempoolHttpBackend:
    """Mempool Explorer REST backend implementing :class:`ChainBackend`."""

    name = "mempool"

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None
        self._fee_cache: Optional[dict[str, Any]] = None
        self._fee_cache_time: float = 0
        self._mempool_stats_cache: Optional[dict[str, Any]] = None
        self._mempool_stats_cache_time: float = 0
        # Hostname to present for SNI / cert verification when the client
        # connects to a pinned IP literal; ``None`` when not pinning.
        self._pin_sni: Optional[str] = None

    def _get_base_url(self) -> str:
        return settings.lnd_mempool_url.rstrip("/")

    def _verify_tls(self) -> bool:
        return settings.mempool_tls_verify

    def _build_verify(self) -> Union[bool, ssl.SSLContext]:
        """Resolve the ``verify=`` value for ``httpx.AsyncClient``.

        Precedence:
        * ``.onion`` hosts → ``False`` (onion address authenticates the peer).
        * ``MEMPOOL_CA_CERT`` set → pinned ``SSLContext`` trusting only that PEM.
        * Otherwise → ``settings.mempool_tls_verify`` (bool).
        """
        hostname = urlparse(self._get_base_url()).hostname or ""
        if hostname.endswith(".onion"):
            return False
        if settings.mempool_ca_cert:
            ctx = load_pinned_ca_context(settings.mempool_ca_cert)
            if ctx is not None:
                return ctx
            # Fall through to the configured bool when the PEM is unparseable;
            # load_pinned_ca_context already logged the warning. Critically we
            # do NOT silently weaken verify to False here.
        return settings.mempool_tls_verify

    def _needs_proxy(self) -> bool:
        """Check if the mempool URL should use a SOCKS proxy.

        ``.onion``/``.local`` hosts always proxy. Clearnet hosts proxy when
        the chain-backend force-Tor policy is in effect, so the host IP and
        the queried addresses are not exposed on a clearnet path; the proxy
        resolves the hostname remotely.
        """
        try:
            hostname = urlparse(settings.lnd_mempool_url).hostname or ""
        except Exception:
            return False
        if hostname.endswith(".onion") or hostname.endswith(".local"):
            return True
        return settings.chain_backend_force_tor_enabled()

    def _get_proxy(self) -> Optional[str]:
        """Get SOCKS5 proxy URL if the mempool URL needs one."""
        if self._needs_proxy():
            proxy = force_remote_dns_socks(settings.lnd_tor_proxy)
            if proxy:
                logger.info("Mempool URL requires proxy — routing via %s", proxy)
                return proxy
            else:
                logger.warning(
                    "Mempool URL (%s) needs a proxy but LND_TOR_PROXY is not set. Requests will likely fail.",
                    settings.lnd_mempool_url,
                )
        return None

    def _assert_base_url_routable(self) -> None:
        """Re-validate the configured host on every client (re)creation.

        The startup guard validates the host once at boot; this re-runs
        the same policy when a client is built so a host whose DNS later
        flips to an internal address (rebinding / TTL expiry) is refused
        rather than connected to. ``.onion`` routes via Tor (no DNS
        rebinding) and ``.local`` is a deliberate self-hosted form, both
        exempt — and operators with a genuine internal backend opt in via
        ``MEMPOOL_ALLOW_INTERNAL``.
        """
        if settings.mempool_allow_internal:
            return
        hostname = (urlparse(self._get_base_url()).hostname or "").lower()
        if not hostname or hostname.endswith(".onion") or hostname.endswith(".local"):
            return
        from app.core.net_guard import host_resolves_to_blocked

        if host_resolves_to_blocked(hostname):
            raise RuntimeError(
                f"mempool backend host {hostname!r} is unresolvable or resolves "
                "to a non-routable address; refusing to connect"
            )

    def _resolve_pinned_target(self, needs_proxy: bool) -> tuple[str, dict[str, str], Optional[str]]:
        """Resolve the connect target, pinning the IP for clearnet hosts.

        Returns ``(base_url, default_headers, sni_hostname)``. For a
        clearnet hostname the base URL's host is replaced by a validated
        IP literal, the original host is carried in a default ``Host``
        header, and the hostname is returned for per-request SNI — so the
        address the routability check validated is exactly the address the
        socket connects to (no DNS-rebind window between check and use).
        This mirrors :func:`app.core.net_guard.pin_request_args`, used by
        every other clearnet egress path.

        Pinning is skipped — and the bare hostname kept — for the proxied
        (Tor resolves remotely), ``.onion``/``.local``, bare-IP, and
        ``MEMPOOL_ALLOW_INTERNAL`` cases, matching ``_assert_base_url_routable``.
        """
        base = self._get_base_url()
        parsed = urlparse(base)
        host = (parsed.hostname or "").lower()
        if (
            needs_proxy
            or settings.mempool_allow_internal
            or not host
            or host.endswith(".onion")
            or host.endswith(".local")
        ):
            return base, {}, None
        try:
            ipaddress.ip_address(host)
            return base, {}, None  # already an IP literal — nothing to rebind
        except ValueError:
            pass

        from app.core.net_guard import resolve_pinned_ip

        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port or default_port
        pinned_ip = resolve_pinned_ip(host, port)
        ip_literal = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
        pinned_base = urlunparse(parsed._replace(netloc=f"{ip_literal}:{port}"))
        host_header = host if parsed.port is None else f"{host}:{parsed.port}"
        return pinned_base, {"Host": host_header}, host

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the persistent HTTP client."""
        if self._client is None or self._client.is_closed:
            self._assert_base_url_routable()
            proxy = self._get_proxy()
            needs_proxy = self._needs_proxy()
            base_url, default_headers, sni = self._resolve_pinned_target(needs_proxy)
            self._pin_sni = sni
            self._client = httpx.AsyncClient(
                base_url=base_url,
                headers=default_headers,
                timeout=httpx.Timeout(15.0, connect=10.0) if needs_proxy else httpx.Timeout(10.0),
                verify=self._build_verify(),
                proxy=proxy,
                # Never chase a redirect off the configured backend — a
                # 30x must not be able to bounce a chain query elsewhere.
                follow_redirects=False,
            )
        return self._client

    async def _client_get(self, client: httpx.AsyncClient, path: str) -> httpx.Response:
        """GET ``path`` on ``client``, applying the pinned SNI when set.

        The body is read under ``outbound_max_response_bytes`` so a
        misbehaving explorer cannot stream an unbounded response into the
        fee/tx-status path.
        """
        if self._pin_sni is not None:
            return await request_capped(client, "GET", path, extensions={"sni_hostname": self._pin_sni})
        return await request_capped(client, "GET", path)

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _request(self, path: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """GET ``path``; returns ``(data, error)``.

        Retried via :func:`with_retry` against the module-level circuit
        breaker so transient blips don't fail fee-dependent endpoints.
        The breaker is exposed on ``/v1/status/services``.
        """

        async def _attempt() -> dict[str, Any]:
            client = await self._get_client()
            response = await self._client_get(client, path)
            if 500 <= response.status_code < 600:
                raise _MempoolRetryable5xxError(response.status_code, response.text)
            response.raise_for_status()
            return response.json()  # type: ignore[no-any-return]

        try:
            data = await with_retry(
                _attempt,
                retryable=_MEMPOOL_RETRYABLE_EXC + (_MempoolRetryable5xxError,),
                backoff_s=(0.25, 0.75),
                breaker=_MEMPOOL_BREAKER,
                op_name=f"mempool GET {path}",
            )
            _MEMPOOL_HEALTH.record_success()
            return data, None
        except BreakerOpenError as e:
            _MEMPOOL_HEALTH.record_failure(str(e))
            return None, "Mempool temporarily unavailable (circuit breaker open)"
        except Exception as e:
            error_msg = f"Mempool API request failed ({self._get_base_url()}{path}): {e}"
            logger.warning("%s", error_msg)
            _MEMPOOL_HEALTH.record_failure(f"{type(e).__name__}: {e}")
            return None, error_msg

    async def get_recommended_fees(
        self,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Fetch recommended fees from Mempool, with caching + stale fallback."""
        now = time.time()
        if self._fee_cache and (now - self._fee_cache_time) < _CACHE_TTL_SECONDS:
            return self._fee_cache, None

        data, error = await self._request("/api/v1/fees/recommended")
        if error:
            if self._fee_cache is not None:
                logger.warning(
                    "Mempool fee fetch failed (%s) — serving stale cache (age=%.0fs)",
                    error,
                    now - self._fee_cache_time,
                )
                stale = dict(self._fee_cache)
                stale["stale"] = True
                stale["cache_age_s"] = int(now - self._fee_cache_time)
                return stale, None
            return None, error
        assert data is not None

        required = ["fastestFee", "halfHourFee", "hourFee", "economyFee", "minimumFee"]
        if not all(k in data for k in required):
            logger.warning("Mempool fee response missing fields: %s", data)
            return None, "Mempool fee response missing required fields"

        # Validate + clamp every untrusted feerate. A string / null / NaN /
        # negative value is a malformed response (reject → fall back); a
        # numeric value above the sane ceiling is clamped so a malicious
        # server can't drive an automated send into burning a UTXO as fee.
        sanitized: dict[str, Any] = dict(data)
        for field in required:
            clamped = clamp_feerate_sat_per_vb(data.get(field))
            if clamped is None:
                logger.warning("Mempool fee field %r is not a usable feerate: %r", field, data.get(field))
                return None, f"Mempool fee response has invalid {field}"
            sanitized[field] = clamped

        self._fee_cache = sanitized
        self._fee_cache_time = now
        return sanitized, None

    async def get_fee_for_priority(self, priority: str = "medium") -> Optional[int]:
        """Get the sat/vByte fee rate for a given priority level."""
        priority = priority.lower()
        if priority not in PRIORITY_MAP:
            priority = "medium"
        fees, _ = await self.get_recommended_fees()
        if not fees:
            return None
        fee_rate = fees.get(PRIORITY_MAP[priority])
        if fee_rate is not None and fee_rate < 1:
            fee_rate = 1
        return fee_rate

    # ─── Transaction Lookup ───────────────────────────────────────────

    async def get_transaction(self, txid: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        data, error = await self._request(f"/api/tx/{quote(txid, safe='')}")
        if error:
            return None, error
        assert data is not None

        status = data.get("status", {})
        return {
            "txid": data.get("txid"),
            "confirmed": status.get("confirmed", False),
            "block_height": status.get("block_height"),
            "block_hash": status.get("block_hash"),
            "block_time": status.get("block_time"),
            "fee": data.get("fee"),
            "size": data.get("size"),
            "weight": data.get("weight"),
            "version": data.get("version"),
            "locktime": data.get("locktime"),
            "vin_count": len(data.get("vin", [])),
            "vout_count": len(data.get("vout", [])),
            "vout": [
                {
                    "scriptpubkey_address": v.get("scriptpubkey_address"),
                    "value": v.get("value"),
                }
                for v in data.get("vout", [])
                if v.get("scriptpubkey_address")
            ],
        }, None

    async def get_transaction_confirmations(self, txid: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        tx, error = await self.get_transaction(txid)
        if error:
            return None, error
        assert tx is not None

        if not tx["confirmed"]:
            return {
                "txid": txid,
                "confirmed": False,
                "confirmations": 0,
                "block_height": None,
            }, None

        tip_height, _ = await self.get_block_tip_height()
        confirmations = 0
        if tip_height is not None and tx["block_height"] is not None:
            confirmations = max(0, tip_height - tx["block_height"] + 1)

        return {
            "txid": txid,
            "confirmed": True,
            "confirmations": confirmations,
            "block_height": tx["block_height"],
            "block_time": tx.get("block_time"),
        }, None

    # ─── Address Lookup ───────────────────────────────────────────────

    async def get_address(self, address: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        data, error = await self._request(f"/api/address/{quote(address, safe='')}")
        if error:
            return None, error
        assert data is not None

        chain_stats = data.get("chain_stats", {})
        mempool_stats = data.get("mempool_stats", {})

        funded_sats = chain_stats.get("funded_txo_sum", 0)
        spent_sats = chain_stats.get("spent_txo_sum", 0)
        mempool_funded = mempool_stats.get("funded_txo_sum", 0)
        mempool_spent = mempool_stats.get("spent_txo_sum", 0)

        return {
            "address": data.get("address"),
            "confirmed_balance_sats": funded_sats - spent_sats,
            "unconfirmed_balance_sats": mempool_funded - mempool_spent,
            "total_balance_sats": (funded_sats - spent_sats) + (mempool_funded - mempool_spent),
            "confirmed_tx_count": chain_stats.get("tx_count", 0),
            "unconfirmed_tx_count": mempool_stats.get("tx_count", 0),
            "funded_txo_count": chain_stats.get("funded_txo_count", 0),
            "spent_txo_count": chain_stats.get("spent_txo_count", 0),
        }, None

    async def get_address_utxos(self, address: str) -> tuple[Optional[list[dict[str, Any]]], Optional[str]]:
        data, error = await self._request(f"/api/address/{quote(address, safe='')}/utxo")
        if error:
            return None, error
        assert data is not None

        # This endpoint returns a JSON array; ``_request`` types the parsed
        # payload as a dict for the (common) object-returning endpoints.
        utxos: list[dict[str, Any]] = cast(list[dict[str, Any]], data)
        return [
            {
                "txid": utxo.get("txid"),
                "vout": utxo.get("vout"),
                "value_sats": utxo.get("value"),
                "confirmed": utxo.get("status", {}).get("confirmed", False),
                "block_height": utxo.get("status", {}).get("block_height"),
            }
            for utxo in utxos
        ], None

    # ─── Mempool Statistics ───────────────────────────────────────────

    async def get_mempool_stats(
        self,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        now = time.time()
        if self._mempool_stats_cache and (now - self._mempool_stats_cache_time) < _MEMPOOL_STATS_CACHE_TTL:
            return self._mempool_stats_cache, None

        data, error = await self._request("/api/mempool")
        if error:
            return None, error
        assert data is not None

        result = {
            "tx_count": data.get("count", 0),
            "total_vsize": data.get("vsize", 0),
            "total_fee_btc": data.get("total_fee", 0),
            "fee_histogram": data.get("fee_histogram", []),
        }

        self._mempool_stats_cache = result
        self._mempool_stats_cache_time = now
        return result, None

    # ─── Block Height ─────────────────────────────────────────────────

    async def get_block_tip_height(self) -> tuple[Optional[int], Optional[str]]:
        try:
            client = await self._get_client()
            response = await self._client_get(client, "/api/blocks/tip/height")
            response.raise_for_status()
            return int(response.text.strip()), None
        except Exception as e:
            logger.warning("Mempool block tip height request failed: %s", e)
            return None, f"Block tip height request failed: {e}"

    async def get_block_by_height(self, height: int) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        # First get the block hash at this height
        try:
            client = await self._get_client()
            response = await self._client_get(client, f"/api/block-height/{quote(str(height), safe='')}")
            response.raise_for_status()
            block_hash = response.text.strip()
        except Exception as e:
            logger.warning("Mempool block-height lookup failed for height %d: %s", height, e)
            return None, f"Block-height lookup failed for height {height}: {e}"

        # Then get the block details
        block_data, error = await self._request(f"/api/block/{quote(block_hash, safe='')}")
        if error:
            return None, error
        assert block_data is not None

        return {
            "hash": block_data.get("id"),
            "height": block_data.get("height"),
            "timestamp": block_data.get("timestamp"),
            "tx_count": block_data.get("tx_count"),
            "size": block_data.get("size"),
            "weight": block_data.get("weight"),
            "difficulty": block_data.get("difficulty"),
            "previous_block_hash": block_data.get("previousblockhash"),
        }, None
