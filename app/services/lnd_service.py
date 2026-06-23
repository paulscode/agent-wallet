# SPDX-License-Identifier: MIT
"""
LND Lightning Node Service

Communicates with an LND node via its REST API to provide:
- Wallet balance (on-chain + lightning)
- Channel management (list, open, pending)
- Address generation
- Invoice creation and payment
- On-chain transactions
- Fee estimation

Authentication: hex-encoded macaroon in Grpc-Metadata-macaroon header
TLS: self-signed cert support (verification configurable)
Tor: .onion addresses routed via SOCKS5 proxy (tor-proxy container)
"""

import asyncio
import base64
import json
import logging
import ssl
import time
from typing import Any, Optional
from urllib.parse import quote, urlparse

import httpx

from app.core.config import settings
from app.core.resilience import (
    BreakerOpenError,
    CircuitBreaker,
    with_retry,
)
from app.core.utils import b64_to_hex
from app.services.health import register_health
from app.services.lnd_types import (
    BlindedInvoiceResult,
    ChannelBalance,
    ChannelInfo,
    DecodedPayReq,
    EstimateFeeResult,
    InvoiceInfo,
    InvoiceResult,
    NewAddressResult,
    NodeInfo,
    OnchainTransaction,
    OpenChannelResult,
    Outpoint,
    PaymentInfo,
    PaymentLookup,
    PendingChannelsSummary,
    RebalanceResult,
    RouteQuote,
    SendCoinsResult,
    SendPaymentResult,
    SignAddrResult,
    SignNodeResult,
    Utxo,
    VerifyAddrResult,
    VerifyNodeResult,
    WalletBalance,
    WalletSummary,
)

logger = logging.getLogger(__name__)


# ─── Retry + circuit-breaker for LND HTTP calls ─────────────────────────
#
# LND is the synchronous critical path for nearly every wallet
# operation. A 200 ms GC pause or a brief container-network blip
# would otherwise surface as a 5xx to the caller. We retry idempotent
# read calls a few times (httpx connect/read timeouts + 5xx) and
# fast-fail when the breaker is open so callers don't pile up on a
# wedged dependency.
#
# The breaker is shared across every method and exposed on
# ``/v1/status/services``.

_LND_BREAKER = CircuitBreaker(name="lnd")
_LND_HEALTH = register_health("lnd", breaker=_LND_BREAKER)

# Two-tier breaker. When the upstream failure is the Tor
# circuit between us and LND (proxy errors, SOCKS handshake
# failures, "TTL expired", etc.), incrementing only the LND breaker
# misattributes the cause and confuses the operator. The Tor breaker
# below tracks the same failures the LND breaker counts BUT only
# the Tor-classified ones (see ``_classify_tor_failure`` below).
# A single failure increments BOTH breakers (so the LND-side
# downstream behaviour is unchanged); the Tor breaker just gives
# the watchdog and the dashboard panel a distinct
# signal for "Tor itself is unhealthy."
_TOR_BREAKER = CircuitBreaker(
    name="tor",
    failure_threshold=int(settings.tor_breaker_failure_threshold),
)
_TOR_HEALTH = register_health("tor", breaker=_TOR_BREAKER)

# LND-pool Tor breaker. In single mode this is unused and
# the existing ``_TOR_BREAKER`` carries every Tor-attributable
# failure. In split mode (``settings.tor_split_mode``), the LND
# service routes Tor failures here so the dashboard can show which
# pool is wedged. The breaker name + registry entry exist
# unconditionally so the health endpoint shape is stable across
# modes (the entry is just always-closed when split-mode is off).
_TOR_LND_BREAKER = CircuitBreaker(
    name="tor-lnd",
    failure_threshold=int(settings.tor_breaker_failure_threshold),
)
_TOR_LND_HEALTH = register_health("tor-lnd", breaker=_TOR_LND_BREAKER)


def _record_tor_failure_for_lnd_path(err_str: str) -> None:
    """Route an LND-path Tor failure into the right breaker.

    In single mode (default) both Tors are the same process so we
    bump the shared ``_TOR_BREAKER`` — the watchdog reads it.

    In split mode the LND-pool watchdog reads ``_TOR_LND_BREAKER``;
    bumping ``_TOR_BREAKER`` here would mis-attribute the failure
    to the anonymize pool and cause the watchdog to fire NEWNYM
    on the wrong Tor process.
    """
    if getattr(settings, "tor_split_mode", False):
        _TOR_LND_BREAKER.record_failure(err_str)
        _TOR_LND_HEALTH.record_failure(err_str)
    else:
        _TOR_BREAKER.record_failure(err_str)
        _TOR_HEALTH.record_failure(err_str)


def _record_tor_success_for_lnd_path() -> None:
    """Mirror of :func:`_record_tor_failure_for_lnd_path` for the
    success side. A successful LND call resets the LND-pool Tor
    breaker so a historical flap doesn't keep it open forever."""
    if getattr(settings, "tor_split_mode", False):
        _TOR_LND_BREAKER.record_success()
        _TOR_LND_HEALTH.record_success()
    else:
        _TOR_BREAKER.record_success()
        _TOR_HEALTH.record_success()


_LND_PREFIX_EXCLUSIONS: tuple[str, ...] = (
    # Our own _Retryable5xxError → f"LND {status_code}: {body}" — leading
    # token is "LND" + numeric status, body is whatever LND returned.
    # If LND's 500-body text happens to contain "socks", the naive
    # substring scan below would false-positive. Detect by leading
    # prefix instead.
    "lnd ",
    "lnd error",
    # httpx HTTP status errors arrive as "HTTPStatusError: <status>:
    # <body>". The body is server-supplied; same risk.
    "httpstatuserror",
    # _Retryable5xxError's class name when wrapped: "_Retryable5xxError: LND 500: ..."
    # The shorter prefix is deliberate — it matches the wrapped name via
    # startswith regardless of the trailing "error" suffix.
    "_retryable5xx",
    # bolt12 / boltz upstream errors come through with a "Boltz" /
    # "Bolt12" prefix when they're not network-level.
    "boltz ",
    "bolt12 ",
)


def _classify_tor_failure(exc_or_msg: str) -> bool:
    """Return True iff the failure looks like a Tor-side fault
    (SOCKS handshake error, proxy error, circuit timeout, etc.) as
    opposed to an LND-side fault (HTTP 5xx, semantic 4xx, etc.).

    Used to decide whether to also bump the Tor breaker on a
    transient failure. The classification is intentionally
    permissive — when in doubt, attribute to Tor, because a
    misclassified Tor failure is a cosmetic issue (Tor breaker
    fires when LND was actually the upstream cause) whereas a
    missed Tor failure is the actual bug we're trying to surface.

    PERMISSIVE BUT NOT NAIVE: substring matching for "socks" /
    "proxyerror" etc. would otherwise false-positive on LND-shaped
    errors whose body text happens to contain those substrings
    (e.g. ``LND 500: socks daemon crashed``). The
    ``_LND_PREFIX_EXCLUSIONS`` list short-circuits the substring
    check when the leading token of the error string clearly
    identifies it as an LND-side failure.
    """
    if not exc_or_msg:
        return False
    s = exc_or_msg.lower()
    # LND-prefix exclusion: if the error string clearly starts with
    # an LND-side marker, treat as LND regardless of body content.
    # Substring matches below would otherwise false-positive on
    # bodies that legitimately mention "socks" while describing an
    # LND-side problem.
    if any(s.startswith(pfx) for pfx in _LND_PREFIX_EXCLUSIONS):
        return False
    return any(
        needle in s
        for needle in (
            "proxyerror",
            "proxy error",
            "socks",
            "ttl expired",
            "general socks server failure",
            "host unreachable",
            "connection refused",  # the Tor SOCKS port refused
            "connecttimeout",
            "readtimeout",  # often Tor-side when targeting an .onion
        )
    )


# Exceptions we treat as transient. A 5xx from LND is not its own
# exception type in httpx — we map it via a wrapper below.
_RETRYABLE_HTTPX_EXC: tuple[type[BaseException], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.RemoteProtocolError,
    httpx.PoolTimeout,
)


class _Retryable5xxError(Exception):
    """Internal sentinel — a 5xx response we want the retry loop to see."""

    def __init__(self, status_code: int, body: str) -> None:
        super().__init__(f"LND {status_code}: {body}")
        self.status_code = status_code
        self.body = body


def _is_onion_url(url: str) -> bool:
    """Check if the URL is a Tor .onion address."""
    try:
        parsed = urlparse(url)
        return parsed.hostname.endswith(".onion") if parsed.hostname else False
    except Exception:
        return False


class LNDService:
    """Service for communicating with LND REST API."""

    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None

    def _get_headers(self) -> dict:
        """Build authentication headers for LND REST API."""
        headers: dict[str, str] = {}
        if settings.lnd_macaroon_hex:
            headers["Grpc-Metadata-macaroon"] = settings.lnd_macaroon_hex
        return headers

    def _get_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Build SSL context for TLS certificate verification."""
        if settings.lnd_tls_cert:
            try:
                cert_pem = base64.b64decode(settings.lnd_tls_cert).decode("utf-8")
                ctx = ssl.create_default_context()
                ctx.load_verify_locations(cadata=cert_pem)
                return ctx
            except Exception as e:
                logger.warning("Failed to load LND TLS cert: %s", e)
                return None
        return None

    def _get_tor_proxy(self) -> Optional[str]:
        """Get SOCKS5 proxy URL for Tor routing."""
        if _is_onion_url(settings.lnd_rest_url):
            proxy = settings.lnd_tor_proxy
            if proxy:
                logger.info("LND .onion address detected \u2014 routing via Tor proxy: %s", proxy)
                return proxy
            else:
                logger.warning(
                    "LND REST URL is a .onion address but LND_TOR_PROXY is not set. "
                    "Connections will fail. Set LND_TOR_PROXY=socks5://tor-proxy:9050"
                )
        return None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None or self._client.is_closed:
            is_onion = _is_onion_url(settings.lnd_rest_url)

            if is_onion:
                # Still use TLS cert verification for .onion if cert is available
                ssl_ctx = self._get_ssl_context()
                verify: bool | ssl.SSLContext = ssl_ctx if ssl_ctx else False
            else:
                verify = settings.lnd_tls_verify
                if settings.lnd_tls_cert and not settings.lnd_tls_verify:
                    ssl_ctx = self._get_ssl_context()
                    if ssl_ctx:
                        verify = ssl_ctx

            proxy = self._get_tor_proxy()

            self._client = httpx.AsyncClient(
                base_url=settings.lnd_rest_url.rstrip("/"),
                headers=self._get_headers(),
                verify=verify,
                proxy=proxy,
                timeout=httpx.Timeout(30.0, connect=20.0) if is_onion else httpx.Timeout(15.0, connect=10.0),
                # Never chase a redirect off the configured LND endpoint —
                # the admin macaroon rides every request and must not be
                # replayed to a host an upstream 30x points at.
                follow_redirects=False,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        idempotent: bool | None = None,
        **kwargs: Any,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Make an authenticated request to LND REST API.

        Returns ``(data, error)``. On success ``error`` is ``None``;
        on failure ``data`` is ``None`` and ``error`` is a descriptive
        message.

        Retry / breaker:

        * GET requests (and any caller passing ``idempotent=True``)
          are wrapped in :func:`with_retry` against the
          module-level circuit breaker so a transient blip on LND
          doesn't fail user requests.
        * Mutating calls (POST/PUT/DELETE) execute exactly once and
          only consult the breaker for fast-fail. They are **not**
          retried — see R13 (idempotency keys) before adding retry
          to mutating paths.
        """
        if idempotent is None:
            idempotent = method.upper() == "GET"

        async def _attempt() -> dict[str, Any]:
            client = await self._get_client()
            response = await client.request(method, path, **kwargs)
            if 500 <= response.status_code < 600:
                raise _Retryable5xxError(response.status_code, response.text)
            response.raise_for_status()
            return response.json()  # type: ignore[no-any-return]

        # Translate framework-level exceptions into the (data, error)
        # shape the rest of the codebase expects. Note that we only
        # *retry* connect/read/timeout/5xx — semantic 4xx errors
        # (e.g. invoice-not-found) flow straight through.
        try:
            if idempotent:
                data = await with_retry(
                    _attempt,
                    retryable=_RETRYABLE_HTTPX_EXC + (_Retryable5xxError,),
                    breaker=_LND_BREAKER,
                    op_name=f"lnd {method} {path}",
                )
            else:
                # Mutating: still consult breaker for fast-fail.
                await _LND_BREAKER.before_call()
                try:
                    data = await _attempt()
                except BaseException as e:
                    # Only connection errors and 5xx count as service-health
                    # failures. Semantic 4xx (e.g. 409 "payment in transition")
                    # means the service is working; counting them as breaker
                    # failures will trip the LND breaker on user-error paths
                    # and take down the rest of the dashboard.
                    if isinstance(e, (_Retryable5xxError, *_RETRYABLE_HTTPX_EXC)):
                        err_str = f"{type(e).__name__}: {e}"
                        _LND_BREAKER.record_failure(err_str)
                    # The Tor breaker bump (when the failure is
                    # Tor-shaped) happens in the unified outer-except
                    # block below, so the idempotent path — which
                    # goes through ``with_retry`` and never reaches
                    # this inner except — gets the same treatment.
                    # This guards against the 2026-06-01 incident where
                    # this asymmetry hid the failure from tor_watchdog.
                    raise
                else:
                    _LND_BREAKER.record_success()
            # Success path (both idempotent and non-idempotent).
            _LND_HEALTH.record_success()
            # Reset the LND-pool Tor breaker on success. Used to be
            # called from inside the non-idempotent branch only — so
            # idempotent GETs (including the keepalive's /v1/getinfo)
            # never cleared a historical Tor flap from the breaker
            # counter.
            _record_tor_success_for_lnd_path()
            return data, None
        except BreakerOpenError as e:
            logger.warning("LND breaker is open: %s", e)
            _LND_HEALTH.record_failure(str(e))
            return None, "LND temporarily unavailable (circuit breaker open)"
        except _Retryable5xxError as e:
            logger.error("LND API error %s: %s", e.status_code, e.body)
            _LND_HEALTH.record_failure(f"5xx: {e.status_code}")
            return None, f"LND error ({e.status_code}): {e.body}"
        except httpx.HTTPStatusError as e:
            error_text = e.response.text
            try:
                error_json = e.response.json()
                error_text = error_json.get("message", error_json.get("error", error_text))
            except Exception:
                pass
            logger.error("LND API error %s: %s", e.response.status_code, error_text)
            _LND_HEALTH.record_failure(f"{e.response.status_code}: {error_text[:120]}")
            return None, f"LND error ({e.response.status_code}): {error_text}"
        except _RETRYABLE_HTTPX_EXC as e:  # type: ignore[misc]
            logger.error("LND connection error: %s", e)
            err_str = f"{type(e).__name__}: {e}"
            _LND_HEALTH.record_failure(err_str)
            # Bump the LND-pool Tor breaker too when the failure
            # looks Tor-shaped. Both the idempotent (with_retry) and
            # non-idempotent paths funnel into here on the final
            # failure, so this is the single place we need it.
            if _classify_tor_failure(err_str):
                _record_tor_failure_for_lnd_path(err_str)
            return None, f"Connection failed: {e}"
        except Exception as e:
            logger.error("LND request failed: %s", e)
            err_str = f"{type(e).__name__}: {e}"
            _LND_HEALTH.record_failure(err_str)
            # Catch-all defensive bump — some SOCKS-layer errors
            # don't subclass _RETRYABLE_HTTPX_EXC but still appear
            # with "proxyerror" / "socks" / "general socks server
            # failure" in their str().
            if _classify_tor_failure(err_str):
                _record_tor_failure_for_lnd_path(err_str)
            return None, f"Request failed: {e}"

    # ─── Node Info ────────────────────────────────────────────────────

    async def get_info(self) -> tuple[Optional[NodeInfo], Optional[str]]:
        """Get node info (alias, pubkey, synced status, etc)."""
        data, error = await self._request("GET", "/v1/getinfo")
        if error:
            return None, error
        assert data is not None
        info: NodeInfo = {
            "alias": data.get("alias", ""),
            "identity_pubkey": data.get("identity_pubkey", ""),
            "num_active_channels": data.get("num_active_channels", 0),
            "num_inactive_channels": data.get("num_inactive_channels", 0),
            "num_pending_channels": data.get("num_pending_channels", 0),
            "num_peers": data.get("num_peers", 0),
            "block_height": data.get("block_height", 0),
            "synced_to_chain": data.get("synced_to_chain", False),
            "synced_to_graph": data.get("synced_to_graph", False),
            "version": data.get("version", ""),
            "commit_hash": data.get("commit_hash", ""),
            "uris": data.get("uris", []),
        }
        # Surface a few hand-picked fields on the health snapshot so
        # operators can spot a stuck/unsynced LND from /v1/status/services
        # without an extra round-trip.
        _LND_HEALTH.extra.update(
            {
                "synced_to_chain": info["synced_to_chain"],
                "block_height": info["block_height"],
                "num_active_channels": info["num_active_channels"],
            }
        )
        return info, None

    # ─── Balances ─────────────────────────────────────────────────────

    async def get_wallet_balance(self) -> tuple[Optional[WalletBalance], Optional[str]]:
        """Get on-chain wallet balance."""
        data, error = await self._request("GET", "/v1/balance/blockchain")
        if error:
            return None, error
        assert data is not None
        return {
            "total_balance": int(data.get("total_balance", 0)),
            "confirmed_balance": int(data.get("confirmed_balance", 0)),
            "unconfirmed_balance": int(data.get("unconfirmed_balance", 0)),
            "locked_balance": int(data.get("locked_balance", 0)),
            "reserved_balance_anchor_chan": int(data.get("reserved_balance_anchor_chan", 0)),
        }, None

    async def get_channel_balance(self) -> tuple[Optional[ChannelBalance], Optional[str]]:
        """Get lightning channel balance."""
        data, error = await self._request("GET", "/v1/balance/channels")
        if error:
            return None, error
        assert data is not None
        local_balance = data.get("local_balance", {})
        remote_balance = data.get("remote_balance", {})
        return {
            "local_balance_sat": int(local_balance.get("sat", 0)),
            "remote_balance_sat": int(remote_balance.get("sat", 0)),
            "pending_open_local_sat": int(data.get("pending_open_local_balance", {}).get("sat", 0)),
            "pending_open_remote_sat": int(data.get("pending_open_remote_balance", {}).get("sat", 0)),
            "unsettled_local_sat": int(data.get("unsettled_local_balance", {}).get("sat", 0)),
            "unsettled_remote_sat": int(data.get("unsettled_remote_balance", {}).get("sat", 0)),
        }, None

    async def get_wallet_summary(self) -> tuple[Optional[WalletSummary], Optional[str]]:
        """Get combined wallet summary (balances + node info in parallel)."""
        (info, info_err), (wallet, wallet_err), (channel, chan_err), (pending, _) = await asyncio.gather(
            self.get_info(),
            self.get_wallet_balance(),
            self.get_channel_balance(),
            self.get_pending_channels(),
        )
        if not any([info, wallet, channel]):
            # Return the first available error for diagnostics
            first_error = info_err or wallet_err or chan_err or "Unable to connect to LND node"
            return None, first_error

        onchain_sats = wallet.get("confirmed_balance", 0) if wallet else 0
        lightning_local_sats = channel.get("local_balance_sat", 0) if channel else 0
        lightning_remote_sats = channel.get("remote_balance_sat", 0) if channel else 0

        return {
            "connected": True,
            "node_info": info,
            "onchain": wallet,
            "lightning": channel,
            "pending_channels": pending,
            "totals": {
                "total_balance_sats": onchain_sats + lightning_local_sats,
                "onchain_sats": onchain_sats,
                "lightning_local_sats": lightning_local_sats,
                "lightning_remote_sats": lightning_remote_sats,
                "unconfirmed_sats": wallet.get("unconfirmed_balance", 0) if wallet else 0,
                "num_active_channels": info.get("num_active_channels", 0) if info else 0,
                "num_pending_channels": info.get("num_pending_channels", 0) if info else 0,
                "synced": info.get("synced_to_chain", False) if info else False,
            },
        }, None

    # ─── Channels ─────────────────────────────────────────────────────

    async def get_channels(self) -> tuple[Optional[list[ChannelInfo]], Optional[str]]:
        """Get list of open channels.

        ``peer_alias_lookup=true`` asks lnd to resolve each peer's gossip
        alias and include it as ``peer_alias``. Without this flag the
        field is always empty and the dashboard falls back to the raw
        hex pubkey, which looks like a meaningless number to humans.
        """
        data, error = await self._request("GET", "/v1/channels", params={"peer_alias_lookup": "true"})
        if error:
            return None, error
        assert data is not None
        channels: list[ChannelInfo] = []
        for ch in data.get("channels", []):
            channels.append(
                {
                    "chan_id": ch.get("chan_id", ""),
                    "remote_pubkey": ch.get("remote_pubkey", ""),
                    "channel_point": ch.get("channel_point", ""),
                    "capacity": int(ch.get("capacity", 0)),
                    "local_balance": int(ch.get("local_balance", 0)),
                    "remote_balance": int(ch.get("remote_balance", 0)),
                    "commit_fee": int(ch.get("commit_fee", 0)),
                    "total_satoshis_sent": int(ch.get("total_satoshis_sent", 0)),
                    "total_satoshis_received": int(ch.get("total_satoshis_received", 0)),
                    "num_updates": int(ch.get("num_updates", 0)),
                    "active": ch.get("active", False),
                    "private": ch.get("private", False),
                    "initiator": ch.get("initiator", False),
                    "peer_alias": ch.get("peer_alias", ""),
                    "uptime": int(ch.get("uptime", 0)),
                    "lifetime": int(ch.get("lifetime", 0)),
                    "local_chan_reserve_sat": int(ch.get("local_chan_reserve_sat", 0)),
                    "remote_chan_reserve_sat": int(ch.get("remote_chan_reserve_sat", 0)),
                    "unsettled_balance": int(ch.get("unsettled_balance", 0)),
                }
            )
        return channels, None

    async def get_channel_by_point(self, channel_point: str) -> tuple[Optional[ChannelInfo], Optional[str]]:
        """Return the open channel whose ``channel_point`` (``txid:vout``)
        matches, or ``(None, None)`` if no such *active-or-inactive* open
        channel exists yet (e.g. funding still pending). ``(None, err)`` on
        an LND error.

        Used by the Braiins channel-open flow to detect activation
        (callers check the returned dict's ``active`` flag) and to resolve
        the channel's short ``chan_id`` for pinning the reverse-swap
        payment's outgoing channel.
        """
        channels, error = await self.get_channels()
        if error is not None:
            return None, error
        for ch in channels or []:
            if ch.get("channel_point") == channel_point:
                return ch, None
        return None, None

    async def channel_is_active(self, channel_point: str) -> tuple[bool, Optional[ChannelInfo], Optional[str]]:
        """Convenience wrapper: ``(is_active, channel_or_None, err)``.

        ``is_active`` is True only when the channel is open AND its
        ``active`` flag is set. Best-effort: on an LND error returns
        ``(False, None, err)`` so the caller can stay in OPENING_CHANNEL
        and retry rather than fail.
        """
        ch, error = await self.get_channel_by_point(channel_point)
        if error is not None:
            return False, None, error
        if ch is None:
            return False, None, None
        return bool(ch.get("active")), ch, None

    async def inbound_capacity(self) -> tuple[Optional[dict], Optional[str]]:
        """Estimate how much the node can currently RECEIVE over Lightning.

        ``total_receivable_sats`` sums, over active channels, each
        channel's ``remote_balance`` minus the remote's channel reserve
        and a small commitment/HTLC buffer — a conservative floor on
        what the peer can push to us (assumes the sender can MPP across
        channels). ``largest_channel_receivable_sats`` is the most a
        single channel can take (the worst case when the sender does not
        split the payment).

        Best-effort: returns ``(None, err)`` when ``get_channels`` fails
        so callers can skip an inbound gate rather than refuse on a
        transient LND error.
        """
        # Per-channel headroom the remote needs beyond their reserve to
        # add the inbound HTLC (commitment-fee / dust slack). Small and
        # conservative — the gate also leaves the amount-margin to the
        # caller.
        receive_buffer_sats = 350
        channels, error = await self.get_channels()
        if error is not None:
            return None, error
        total = 0
        largest = 0
        for ch in channels or []:
            if not ch.get("active"):
                continue
            remote = int(ch.get("remote_balance", 0) or 0)
            reserve = int(ch.get("remote_chan_reserve_sat", 0) or 0)
            recv = remote - reserve - receive_buffer_sats
            if recv <= 0:
                continue
            total += recv
            largest = max(largest, recv)
        return {
            "total_receivable_sats": total,
            "largest_channel_receivable_sats": largest,
        }, None

    async def get_channel_edge(
        self,
        chan_id: str,
    ) -> tuple[Optional[dict], Optional[str]]:
        """Fetch the gossiped policy + node-pair for a single channel.

        LND's ``/v1/graph/edge/{chan_id}`` returns:

        * ``node1_pub``, ``node2_pub`` — sorted lexicographically.
        * ``node1_policy`` — the policy node1 advertises for HTLCs
          flowing OUT of node1 toward node2 (so consumers reading
          node1_policy.max_htlc_msat see "node1 will forward up to
          X to node2").
        * ``node2_policy`` — the mirror direction.
        * ``capacity``, ``last_update``, ``chan_point``.

        Used by the BOLT 12 htlc_max-drift check to compare the
        gossiped inbound-policy ``max_htlc_msat`` (the side from
        our peer to us) against the live ``remote_balance``.
        """
        data, error = await self._request("GET", f"/v1/graph/edge/{chan_id}")
        if error:
            return None, error
        return data, None

    async def describe_graph(
        self,
        include_unannounced: bool = False,
    ) -> tuple[Optional[dict], Optional[str]]:
        """Fetch the LN gossip graph snapshot.

        Returns the LND ``DescribeGraph`` response as a dict with
        ``nodes`` and ``edges`` lists (the wire shape). The dashboard
        peer-selection helper consumes ``edges`` to compute a coarse
        capacity-weighted centrality.

        ``include_unannounced=False`` (default) excludes private
        channels — the anonymize-stack peer selection only considers
        publicly-known well-connected nodes.
        """
        params = {"include_unannounced": "true" if include_unannounced else "false"}
        data, error = await self._request("GET", "/v1/graph", params=params)
        if error:
            return None, error
        return data, None

    async def get_pending_channels(self) -> tuple[Optional[PendingChannelsSummary], Optional[str]]:
        """Get pending channels summary."""
        data, error = await self._request("GET", "/v1/channels/pending")
        if error:
            return None, error
        assert data is not None
        return {
            "pending_open_channels": len(data.get("pending_open_channels", [])),
            "pending_closing_channels": len(data.get("pending_closing_channels", [])),
            "pending_force_closing_channels": len(data.get("pending_force_closing_channels", [])),
            "waiting_close_channels": len(data.get("waiting_close_channels", [])),
            "total_limbo_balance": int(data.get("total_limbo_balance", 0)),
        }, None

    async def get_pending_channels_detail(self) -> tuple[Optional[list], Optional[str]]:
        """Get detailed pending channel info."""
        data, error = await self._request("GET", "/v1/channels/pending")
        if error:
            return None, error
        assert data is not None

        result = []
        for pch in data.get("pending_open_channels", []):
            ch = pch.get("channel", {})
            result.append(
                {
                    "type": "pending_open",
                    "remote_node_pub": ch.get("remote_node_pub", ""),
                    "channel_point": ch.get("channel_point", ""),
                    "capacity": int(ch.get("capacity", 0)),
                    "local_balance": int(ch.get("local_balance", 0)),
                    "remote_balance": int(ch.get("remote_balance", 0)),
                    "commit_fee": int(pch.get("commit_fee", 0)),
                    "confirmation_height": int(pch.get("confirmation_height", 0)),
                }
            )
        # Channels whose close has been initiated but whose closing tx has
        # not yet been broadcast/confirmed. LND nests the channel under
        # ``channel`` and may not yet have a closing txid.
        for pch in data.get("waiting_close_channels", []):
            ch = pch.get("channel", {})
            result.append(
                {
                    "type": "waiting_close",
                    "remote_node_pub": ch.get("remote_node_pub", ""),
                    "channel_point": ch.get("channel_point", ""),
                    "capacity": int(ch.get("capacity", 0)),
                    "local_balance": int(ch.get("local_balance", 0)),
                    "remote_balance": int(ch.get("remote_balance", 0)),
                    # The broadcast closing tx, present once LND has published
                    # it (a force close publishes the commitment immediately;
                    # the channel then sits here until that tx confirms).
                    "closing_txid": pch.get("closing_txid", ""),
                    "limbo_balance": int(pch.get("limbo_balance", 0)),
                }
            )
        for pch in data.get("pending_closing_channels", []):
            ch = pch.get("channel", {})
            result.append(
                {
                    "type": "pending_close",
                    "remote_node_pub": ch.get("remote_node_pub", ""),
                    "channel_point": ch.get("channel_point", ""),
                    "capacity": int(ch.get("capacity", 0)),
                    "local_balance": int(ch.get("local_balance", 0)),
                    "remote_balance": int(ch.get("remote_balance", 0)),
                    "closing_txid": pch.get("closing_txid", ""),
                    "limbo_balance": int(pch.get("limbo_balance", 0)),
                }
            )
        for pch in data.get("pending_force_closing_channels", []):
            ch = pch.get("channel", {})
            result.append(
                {
                    "type": "force_closing",
                    "remote_node_pub": ch.get("remote_node_pub", ""),
                    "channel_point": ch.get("channel_point", ""),
                    "capacity": int(ch.get("capacity", 0)),
                    "local_balance": int(ch.get("local_balance", 0)),
                    "remote_balance": int(ch.get("remote_balance", 0)),
                    "closing_txid": pch.get("closing_txid", ""),
                    "blocks_til_maturity": int(pch.get("blocks_til_maturity", 0)),
                    "maturity_height": int(pch.get("maturity_height", 0)),
                    "limbo_balance": int(pch.get("limbo_balance", 0)),
                    "recovered_balance": int(pch.get("recovered_balance", 0)),
                }
            )
        return result, None

    # ─── Channel activity (last-used timestamps) ─────────────────────
    #
    # LND's ListChannels does not expose a "last activity" timestamp, so
    # we synthesise one by combining three sources:
    #
    #   1. ForwardingHistory  — HTLCs we routed for others
    #      (chan_id_in / chan_id_out, timestamp).
    #   2. ListPayments       — HTLCs we sent
    #      (route.hops[0].chan_id is the outgoing channel,
    #      htlc.resolve_time_ns is when it settled / failed).
    #   3. ListInvoices       — HTLCs we received and settled
    #      (htlcs[].chan_id, htlcs[].resolve_time).
    #
    # The result is a chan_id → unix-seconds map of the most recent
    # successful sat flow in either direction. Cached in-process for
    # ~30 s because the dashboard polls /channels every 60 s.
    _last_used_cache: tuple[float, dict[str, int]] = (0.0, {})
    _LAST_USED_TTL_S = 30
    # Look-back window in days. 90 days covers nearly all "is this
    # channel actually being used" questions while keeping each LND
    # response bounded.
    _LAST_USED_LOOKBACK_DAYS = 90

    async def get_channel_last_used(self) -> dict[str, int]:
        """Return ``{chan_id: unix_seconds_of_last_activity}``.

        Best-effort: any source that errors is silently skipped — a
        partial answer is far more useful than none, and the caller
        treats a missing entry as "no recent activity / unknown".
        """
        now = time.time()
        cached_at, cached = self._last_used_cache
        if now - cached_at < self._LAST_USED_TTL_S:
            return cached

        start_unix = int(now) - self._LAST_USED_LOOKBACK_DAYS * 86400

        async def _forwards() -> dict[str, int]:
            data, error = await self._request(
                "POST",
                "/v1/switch",
                json={
                    "start_time": str(start_unix),
                    "end_time": "0",
                    "index_offset": 0,
                    "num_max_events": 1000,
                },
            )
            out: dict[str, int] = {}
            if error or not data:
                return out
            for ev in data.get("forwarding_events", []) or []:
                ts = int(ev.get("timestamp") or 0)
                if not ts:
                    ts_ns = int(ev.get("timestamp_ns") or 0)
                    ts = ts_ns // 1_000_000_000 if ts_ns else 0
                if not ts:
                    continue
                for key in ("chan_id_in", "chan_id_out"):
                    cid = ev.get(key)
                    if cid and ts > out.get(cid, 0):
                        out[cid] = ts
            return out

        async def _payments() -> dict[str, int]:
            # Pull recent HTLCs only — a 200-record window is plenty
            # to surface "last used" without scanning full history.
            data, error = await self._request(
                "GET",
                "/v1/payments",
                params={
                    "reversed": "true",
                    "max_payments": "200",
                    "include_incomplete": "false",
                },
            )
            out: dict[str, int] = {}
            if error or not data:
                return out
            for p in data.get("payments", []) or []:
                for htlc in p.get("htlcs", []) or []:
                    if htlc.get("status") != "SUCCEEDED":
                        continue
                    hops = (htlc.get("route") or {}).get("hops") or []
                    if not hops:
                        continue
                    cid = hops[0].get("chan_id")
                    if not cid:
                        continue
                    ts_ns = int(htlc.get("resolve_time_ns") or htlc.get("attempt_time_ns") or 0)
                    ts = ts_ns // 1_000_000_000 if ts_ns else int(p.get("creation_date") or 0)
                    if ts and ts > out.get(cid, 0):
                        out[cid] = ts
            return out

        async def _invoices() -> dict[str, int]:
            data, error = await self._request(
                "GET",
                "/v1/invoices",
                params={"reversed": "true", "num_max_invoices": "200"},
            )
            out: dict[str, int] = {}
            if error or not data:
                return out
            for inv in data.get("invoices", []) or []:
                if not inv.get("settled") and inv.get("state") != "SETTLED":
                    continue
                settle_ts = int(inv.get("settle_date") or 0)
                for htlc in inv.get("htlcs", []) or []:
                    cid = htlc.get("chan_id")
                    if not cid:
                        continue
                    ts = int(htlc.get("resolve_time") or 0) or settle_ts
                    if ts and ts > out.get(cid, 0):
                        out[cid] = ts
            return out

        try:
            fwd_map, pay_map, inv_map = await asyncio.gather(_forwards(), _payments(), _invoices())
        except Exception as e:  # defensive — never let this break /channels
            logger.warning("get_channel_last_used failed: %s", e)
            return cached

        merged: dict[str, int] = dict(fwd_map)
        for src in (pay_map, inv_map):
            for cid, ts in src.items():
                if ts > merged.get(cid, 0):
                    merged[cid] = ts

        self._last_used_cache = (now, merged)
        return merged

    # ─── Addresses ────────────────────────────────────────────────────

    async def new_address(self, address_type: str = "p2tr") -> tuple[Optional[NewAddressResult], Optional[str]]:
        """Generate a new on-chain receive address."""
        type_map = {"p2wkh": "0", "np2wkh": "1", "p2tr": "4"}
        lnd_type = type_map.get(address_type, "4")
        data, error = await self._request("GET", "/v1/newaddress", params={"type": lnd_type})
        if error:
            return None, error
        assert data is not None
        return {"address": data.get("address", ""), "address_type": address_type}, None

    # ─── Transactions & Payments ──────────────────────────────────────

    async def get_recent_payments(self, max_payments: int = 20) -> tuple[Optional[list[PaymentInfo]], Optional[str]]:
        """Get recent outgoing lightning payments."""
        data, error = await self._request(
            "GET",
            "/v1/payments",
            params={"reversed": "true", "max_payments": str(max_payments), "include_incomplete": "true"},
        )
        if error:
            return None, error
        assert data is not None
        payments: list[PaymentInfo] = []
        for p in data.get("payments", []):
            payments.append(
                {
                    "payment_hash": p.get("payment_hash", ""),
                    "value_sat": int(p.get("value_sat", 0)),
                    "fee_sat": int(p.get("fee_sat", 0)),
                    "status": p.get("status", "UNKNOWN"),
                    "creation_date": int(p.get("creation_date", 0)),
                    "payment_request": p.get("payment_request", ""),
                    "failure_reason": p.get("failure_reason", ""),
                }
            )
        return payments, None

    async def get_recent_invoices(
        self, num_max_invoices: int = 20
    ) -> tuple[Optional[list[InvoiceInfo]], Optional[str]]:
        """Get recent incoming lightning invoices."""
        data, error = await self._request(
            "GET", "/v1/invoices", params={"reversed": "true", "num_max_invoices": str(num_max_invoices)}
        )
        if error:
            return None, error
        assert data is not None
        invoices: list[InvoiceInfo] = []
        for inv in data.get("invoices", []):
            invoices.append(
                {
                    "memo": inv.get("memo", ""),
                    "r_hash": inv.get("r_hash", ""),
                    "value": int(inv.get("value", 0)),
                    "settled": inv.get("settled", False),
                    "creation_date": int(inv.get("creation_date", 0)),
                    "settle_date": int(inv.get("settle_date", 0)),
                    "amt_paid_sat": int(inv.get("amt_paid_sat", 0)),
                    "state": inv.get("state", "OPEN"),
                    "is_keysend": inv.get("is_keysend", False),
                    "payment_request": inv.get("payment_request", ""),
                }
            )
        return invoices, None

    async def get_onchain_transactions(
        self, max_txns: int = 20
    ) -> tuple[Optional[list[OnchainTransaction]], Optional[str]]:
        """Get recent on-chain transactions."""
        data, error = await self._request("GET", "/v1/transactions")
        if error:
            return None, error
        assert data is not None
        txns: list[OnchainTransaction] = []
        for tx in data.get("transactions", [])[:max_txns]:
            txns.append(
                {
                    "tx_hash": tx.get("tx_hash", ""),
                    "amount": int(tx.get("amount", 0)),
                    "num_confirmations": int(tx.get("num_confirmations", 0)),
                    "block_height": int(tx.get("block_height", 0)),
                    "time_stamp": int(tx.get("time_stamp", 0)),
                    "total_fees": int(tx.get("total_fees", 0)),
                    "label": tx.get("label", ""),
                }
            )
        return txns, None

    # ─── Invoice & Payment Operations ─────────────────────────────────

    async def create_invoice(
        self,
        amount_sats: int,
        memo: str = "",
        expiry: int = 3600,
    ) -> tuple[Optional[InvoiceResult], Optional[str]]:
        """Create a Lightning invoice (BOLT11 payment request)."""
        body = {"value": str(amount_sats), "memo": memo, "expiry": str(expiry)}
        data, error = await self._request("POST", "/v1/invoices", json=body)
        if error:
            return None, error
        assert data is not None

        return {
            "r_hash": b64_to_hex(data.get("r_hash", "")),
            "payment_request": data.get("payment_request", ""),
            "add_index": data.get("add_index", ""),
        }, None

    async def add_blinded_invoice(
        self,
        amount_msat: int,
        *,
        memo: str = "",
        expiry: int = 3600,
        num_hops: int = 1,
        max_num_paths: int = 2,
        node_omission_pubkeys: Optional[list[bytes]] = None,
        description_hash: Optional[bytes] = None,
    ) -> tuple[Optional[BlindedInvoiceResult], Optional[str]]:
        """Create a *blinded* BOLT 11 invoice via LND ``AddInvoice``.

        LND advertises blinded routes inside the BOLT 11 string when
        ``is_blinded=true``; the resulting paths are the raw material
        the BOLT 12 codec needs to populate ``invoice_paths`` and
        ``invoice_blindedpay`` on a BOLT 12 invoice.

        ``num_hops`` and ``max_num_paths`` are passed through to
        ``blinded_path_config``. The right values are
        topology-dependent; the BOLT 12 responder reads them from
        :data:`settings.bolt12_blinded_path_min_real_hops` /
        :data:`settings.bolt12_blinded_path_max_paths` (defaults 2/4)
        and falls back to ``num_hops=1`` when LND can't build any
        path at the requested length. Callers outside the BOLT 12
        flow (e.g. anonymize ext-lightning deposits) may legitimately
        pin different values.

        ``node_omission_pubkeys`` (33-byte compressed pubkeys) is passed
        through as ``node_omission_list``. LND refuses to use any of
        those nodes as an intermediate (introduction node or otherwise)
        in any blinded path it builds for this invoice — the
        receive-side counterpart to mission-control exclusions on send.
        """
        if amount_msat <= 0:
            return None, "amount_msat must be positive"
        if num_hops < 0 or num_hops > 8:
            return None, "num_hops must be in [0, 8]"
        if max_num_paths < 1 or max_num_paths > 8:
            return None, "max_num_paths must be in [1, 8]"
        for pk in node_omission_pubkeys or ():
            if len(pk) != 33:
                return None, "node_omission_pubkeys entries must be 33-byte pubkeys"

        blinded_path_config: dict[str, Any] = {
            "min_num_real_hops": num_hops,
            "num_hops": num_hops,
            "max_num_paths": max_num_paths,
        }
        if node_omission_pubkeys:
            blinded_path_config["node_omission_list"] = [
                base64.b64encode(pk).decode("ascii") for pk in node_omission_pubkeys
            ]

        body: dict[str, Any] = {
            "value_msat": str(amount_msat),
            "memo": memo,
            "expiry": str(expiry),
            "is_blinded": True,
            "blinded_path_config": blinded_path_config,
        }
        if description_hash is not None:
            if len(description_hash) != 32:
                return None, "description_hash must be 32 bytes"
            body["description_hash"] = base64.b64encode(description_hash).decode("ascii")

        data, error = await self._request("POST", "/v1/invoices", json=body)
        if error:
            return None, error
        assert data is not None

        payment_request = data.get("payment_request", "")

        # LND's AddInvoiceResponse does NOT include the structured
        # blinded_paths — only the BOLT 11 string (which embeds them
        # opaquely). We need them in raw form to mint the BOLT 12
        # invoice, so round-trip through DecodePayReq which exposes
        # the BlindedPaymentPath objects unchanged.
        blinded: list = []
        if payment_request:
            pay_req_encoded = quote(payment_request, safe="")
            decoded, decode_err = await self._request("GET", f"/v1/payreq/{pay_req_encoded}")
            if decode_err:
                return None, f"decode_payreq_failed: {decode_err}"
            if decoded is not None:
                raw = decoded.get("blinded_paths")
                if isinstance(raw, list):
                    blinded = raw

        return {
            "r_hash": b64_to_hex(data.get("r_hash", "")),
            "payment_request": payment_request,
            "add_index": data.get("add_index", ""),
            "payment_addr": b64_to_hex(data.get("payment_addr", "")),
            "blinded_paths": blinded,
        }, None

    async def decode_payment_request(self, payment_request: str) -> tuple[Optional[DecodedPayReq], Optional[str]]:
        """Decode a BOLT11 Lightning payment request."""
        pay_req_encoded = quote(payment_request, safe="")
        data, error = await self._request("GET", f"/v1/payreq/{pay_req_encoded}")
        if error:
            return None, error
        assert data is not None
        return {
            "destination": data.get("destination", ""),
            "payment_hash": data.get("payment_hash", ""),
            "num_satoshis": int(data.get("num_satoshis", 0)),
            "timestamp": int(data.get("timestamp", 0)),
            "expiry": int(data.get("expiry", 0)),
            "description": data.get("description", ""),
            "description_hash": data.get("description_hash", ""),
            "cltv_expiry": int(data.get("cltv_expiry", 0)),
            "num_msat": int(data.get("num_msat", 0)),
            "features": data.get("features", {}),
        }, None

    async def send_payment_sync(
        self,
        payment_request: str,
        fee_limit_sats: Optional[int] = None,
        timeout_seconds: int = 60,
    ) -> tuple[Optional[SendPaymentResult], Optional[str]]:
        """Pay a Lightning invoice (synchronous — blocks until settled or failed).

        For hold invoices (e.g., Boltz swaps), this blocks until the payee
        settles, which can take minutes.
        """
        body: dict = {"payment_request": payment_request}
        if fee_limit_sats is not None:
            body["fee_limit"] = {"fixed": str(fee_limit_sats)}

        data, error = await self._request(
            "POST",
            "/v1/channels/transactions",
            json=body,
            timeout=float(timeout_seconds),
        )
        if error:
            return None, error
        assert data is not None

        payment_error = data.get("payment_error", "")
        if payment_error:
            return None, f"Payment failed: {payment_error}"

        return {
            "payment_hash": b64_to_hex(data.get("payment_hash", "")),
            "payment_preimage": b64_to_hex(data.get("payment_preimage", "")),
            "payment_route": {
                "total_amt": int(data.get("payment_route", {}).get("total_amt", 0)),
                "total_fees": int(data.get("payment_route", {}).get("total_fees", 0)),
                "total_amt_msat": int(data.get("payment_route", {}).get("total_amt_msat", 0)),
                "total_fees_msat": int(data.get("payment_route", {}).get("total_fees_msat", 0)),
                "hops": len(data.get("payment_route", {}).get("hops", [])),
            }
            if data.get("payment_route")
            else None,
        }, None

    # ─── Rebalance / Routing ──────────────────────────────────────────

    async def query_routes(
        self,
        *,
        dest_pubkey_hex: str,
        amount_sats: int,
        outgoing_chan_id: Optional[str] = None,
        last_hop_pubkey_hex: Optional[str] = None,
        source_pubkey_hex: Optional[str] = None,
        fee_limit_sats: Optional[int] = None,
        final_cltv_delta: int = 144,
    ) -> tuple[Optional[RouteQuote], Optional[str]]:
        """Probe for a route via LND ``QueryRoutes`` (no HTLCs sent).

        Used by the rebalance UI to surface fee/hop estimates before
        the user commits to a real circular self-payment. Setting
        ``outgoing_chan_id`` pins the first hop; ``last_hop_pubkey_hex``
        pins the peer of the channel that must deliver the final HTLC.

        ``source_pubkey_hex`` overrides the route's *origin* (default is
        our own node). Passing it lets us ask "is there a route from
        some OTHER node → ``dest_pubkey_hex``?" — used by the on-chain
        deposit routability probe to test Boltz → us inbound.
        """
        if amount_sats <= 0:
            return None, "amount_sats must be positive"

        params: dict[str, Any] = {"final_cltv_delta": str(final_cltv_delta)}
        if outgoing_chan_id:
            params["outgoing_chan_id"] = outgoing_chan_id
        if source_pubkey_hex:
            # ``source_pub_key`` is a hex string field on QueryRoutesRequest
            # (unlike ``last_hop_pubkey``, which is bytes/base64).
            try:
                bytes.fromhex(source_pubkey_hex)
            except ValueError:
                return None, "source_pubkey_hex must be a hex string"
            params["source_pub_key"] = source_pubkey_hex
        if last_hop_pubkey_hex:
            try:
                params["last_hop_pubkey"] = base64.b64encode(bytes.fromhex(last_hop_pubkey_hex)).decode("ascii")
            except ValueError:
                return None, "last_hop_pubkey must be a hex string"
        if fee_limit_sats is not None and fee_limit_sats >= 0:
            # LND accepts the fee_limit as a flat field on the GET form.
            params["fee_limit.fixed"] = str(fee_limit_sats)

        path = f"/v1/graph/routes/{dest_pubkey_hex}/{amount_sats}"
        data, error = await self._request("GET", path, params=params)
        if error:
            return None, error
        assert data is not None

        routes = data.get("routes") or []
        if not routes:
            return None, "No route found"
        # LND already returns the best route first.
        best = routes[0]
        total_amt_msat = int(best.get("total_amt_msat", 0))
        total_fees_msat = int(best.get("total_fees_msat", 0))
        amt_for_ppm = max(amount_sats, 1)
        ppm = (total_fees_msat // 1000) * 1_000_000 // amt_for_ppm
        return {
            "hops": len(best.get("hops", [])),
            "total_amt_sat": int(best.get("total_amt", 0)),
            "total_fees_sat": int(best.get("total_fees", 0)),
            "total_amt_msat": total_amt_msat,
            "total_fees_msat": total_fees_msat,
            "total_time_lock": int(best.get("total_time_lock", 0)),
            "ppm": int(ppm),
        }, None

    async def send_payment_v2(
        self,
        *,
        payment_request: str,
        outgoing_chan_id: Optional[str] = None,
        last_hop_pubkey_hex: Optional[str] = None,
        fee_limit_sats: int = 5000,
        timeout_seconds: int = 60,
        allow_self_payment: bool = True,
        max_parts: Optional[int] = None,
        ignored_pairs: Optional[list[tuple[str, str]]] = None,
    ) -> tuple[Optional[RebalanceResult], Optional[str]]:
        """Send via the router subserver streaming endpoint.

        Unlike :meth:`send_payment_sync`, this consumes
        ``/v2/router/send`` so we can pin ``outgoing_chan_id`` and
        ``last_hop_pubkey`` — the two routing constraints required for
        a circular rebalance. The streamed updates are reduced to a
        single terminal result.

        ``max_parts`` enables MPP (multi-path payment) splitting up to
        N parts. The anonymize stack uses this for
        bounded-K reverse-swap payments where chunking improves
        routing probability and privacy. Default ``None`` leaves the
        decision to LND (no MPP cap).

        ``ignored_pairs`` excludes directed ``(from_pubkey, to_pubkey)``
        edges from path-finding (each pubkey a 33-byte hex string). The
        self-pay source hop passes ``(our_pubkey, peer)`` first-hop
        edges so an MPP-split self-payment steers away from chosen
        peers without forbidding them as intermediate hops elsewhere.

        ``fee_limit_sats`` defaults to 5000 — generous enough for
        normal LN routing without leaving the cap unlimited. Callers
        that need tighter or looser limits should pass an explicit
        value.
        """
        body: dict[str, Any] = {
            "payment_request": payment_request,
            "fee_limit_sat": str(fee_limit_sats),
            "timeout_seconds": int(timeout_seconds),
            "allow_self_payment": bool(allow_self_payment),
            "no_inflight_updates": True,
        }
        if max_parts is not None and int(max_parts) > 0:
            body["max_parts"] = int(max_parts)
        if outgoing_chan_id:
            body["outgoing_chan_id"] = outgoing_chan_id
        if ignored_pairs:
            encoded_pairs: list[dict[str, str]] = []
            for from_hex, to_hex in ignored_pairs:
                try:
                    encoded_pairs.append(
                        {
                            "from": base64.b64encode(bytes.fromhex(from_hex)).decode("ascii"),
                            "to": base64.b64encode(bytes.fromhex(to_hex)).decode("ascii"),
                        }
                    )
                except ValueError:
                    return None, "ignored_pairs entries must be hex pubkeys"
            if encoded_pairs:
                body["ignored_pairs"] = encoded_pairs
        if last_hop_pubkey_hex:
            try:
                body["last_hop_pubkey"] = base64.b64encode(bytes.fromhex(last_hop_pubkey_hex)).decode("ascii")
            except ValueError:
                return None, "last_hop_pubkey must be a hex string"

        # Consult the breaker for fast-fail but do not retry — this is
        # a mutating operation.
        try:
            await _LND_BREAKER.before_call()
        except BreakerOpenError as e:
            logger.warning("LND breaker is open: %s", e)
            _LND_HEALTH.record_failure(str(e))
            return None, "LND temporarily unavailable (circuit breaker open)"

        # Slightly longer wall-clock than ``timeout_seconds`` so LND has
        # a chance to surface a final FAILED before our HTTP times out.
        http_timeout = httpx.Timeout(float(timeout_seconds + 30), connect=20.0)
        client = await self._get_client()

        start = time.monotonic()
        terminal: Optional[dict[str, Any]] = None
        last_error: Optional[str] = None

        try:
            async with client.stream(
                "POST",
                "/v2/router/send",
                json=body,
                timeout=http_timeout,
            ) as response:
                if response.status_code >= 400:
                    text = await response.aread()
                    msg = text.decode("utf-8", errors="replace")[:500]
                    _LND_BREAKER.record_failure(f"http {response.status_code}")
                    _LND_HEALTH.record_failure(f"{response.status_code}: {msg[:120]}")
                    return None, f"LND error ({response.status_code}): {msg}"

                async for line in response.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload: dict[str, Any] = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # gRPC-gateway envelopes each message as
                    # {"result": {...}} on success or {"error": {...}}
                    # on transport-level errors.
                    if "error" in payload and payload["error"]:
                        last_error = str(payload["error"].get("message") or payload["error"])
                        break
                    result = payload.get("result") or payload
                    status = result.get("status")
                    if status in ("SUCCEEDED", "FAILED"):
                        terminal = result
                        break
        except _RETRYABLE_HTTPX_EXC as e:  # type: ignore[misc]
            err_str = f"{type(e).__name__}: {e}"
            _LND_BREAKER.record_failure(err_str)
            _LND_HEALTH.record_failure(err_str)
            # Same Tor-shape classification as the
            # GET path; split mode routes into the LND-pool breaker.
            if _classify_tor_failure(err_str):
                _record_tor_failure_for_lnd_path(err_str)
            return None, f"Connection failed: {e}"
        except Exception as e:
            err_str = f"{type(e).__name__}: {e}"
            _LND_BREAKER.record_failure(err_str)
            _LND_HEALTH.record_failure(err_str)
            if _classify_tor_failure(err_str):
                _record_tor_failure_for_lnd_path(err_str)
            return None, f"Request failed: {e}"

        duration_ms = int((time.monotonic() - start) * 1000)

        if terminal is None:
            # The stream ended without a terminal SUCCEEDED/FAILED.
            # If LND surfaced an inline ``error`` envelope (e.g. no
            # route, invalid request) the request itself completed
            # successfully — it's a routing/semantic outcome, not an
            # upstream fault. Record breaker SUCCESS so a routing
            # failure on a single rebalance doesn't open the breaker
            # and 502 every other endpoint. Reserve breaker failures
            # for the real network/5xx paths handled in the except
            # blocks above.
            _LND_BREAKER.record_success()
            _LND_HEALTH.record_success()
            return None, last_error or "Payment did not reach a terminal state"

        if terminal.get("status") != "SUCCEEDED":
            _LND_BREAKER.record_success()
            _LND_HEALTH.record_success()
            reason = terminal.get("failure_reason") or "FAILED"
            return None, f"Payment failed: {reason}"

        _LND_BREAKER.record_success()
        _LND_HEALTH.record_success()

        # Pull fee/hop info from the most recent attempted route.
        htlcs = terminal.get("htlcs") or []
        succeeded = [h for h in htlcs if h.get("status") == "SUCCEEDED"]
        chosen = succeeded[-1] if succeeded else (htlcs[-1] if htlcs else {})
        route = chosen.get("route") or {}
        hops = len(route.get("hops") or [])
        fee_msat = int(terminal.get("fee_msat") or route.get("total_fees_msat") or 0)
        fee_sat = fee_msat // 1000
        value_sat = int(terminal.get("value_sat") or 0)

        return {
            "payment_hash": terminal.get("payment_hash", ""),
            "payment_preimage": terminal.get("payment_preimage", ""),
            "amount_sats": value_sat,
            "fee_sats": fee_sat,
            "fee_msat": fee_msat,
            "hops": hops,
            "duration_ms": duration_ms,
        }, None

    async def query_routes_with_blinded_paths(
        self,
        *,
        amount_msat: int,
        blinded_payment_paths: list[dict[str, Any]],
        final_cltv_delta: int | None = None,
        fee_limit_msat: int | None = None,
        cltv_limit: int | None = None,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Query LND for a route that terminates at a blinded path.

        Wraps the ``POST /v1/graph/routes/{pub_key}/{amt}`` REST
        gateway binding (the ``additional_bindings`` POST mapping for
        ``Lightning.QueryRoutes`` — see ``lnrpc/lightning.yaml``).
        The amount + introduction-node pubkey would normally go in
        the URL path, but for a blinded payment they're already
        encoded inside ``blinded_payment_paths``; the URL path
        receives placeholder values that LND ignores.

        Per ``lightning.proto``'s ``QueryRoutesRequest`` documentation
        (-3219), when ``blinded_payment_paths`` is non-empty,
        ``final_cltv_delta`` and the destination features come from
        the aggregate parameters inside the blinded paths and MUST
        NOT be set on the request. We expose ``final_cltv_delta`` as
        an opt-in kwarg for non-blinded callers but skip it here when
        blinded paths are supplied.

        Returns the raw ``QueryRoutesResponse`` JSON on success:
        ``{"routes": [{...}], "success_prob": <float>}``. The first
        (and typically only) route is what
        :meth:`send_to_route_v2` consumes.
        """
        if amount_msat <= 0:
            return None, "amount_msat must be positive"
        if not blinded_payment_paths:
            return None, "blinded_payment_paths must be non-empty"
        body: dict[str, Any] = {
            "amt_msat": str(int(amount_msat)),
            "blinded_payment_paths": blinded_payment_paths,
        }
        if final_cltv_delta is not None:
            # MUST NOT be set per the proto comment, but expose for
            # tests that intentionally exercise the failure path.
            body["final_cltv_delta"] = int(final_cltv_delta)
        if fee_limit_msat is not None:
            body["fee_limit"] = {"fixed_msat": str(int(fee_limit_msat))}
        if cltv_limit is not None:
            body["cltv_limit"] = int(cltv_limit)

        # The pubkey + amt in the URL path are positional placeholders;
        # LND ignores them when ``blinded_payment_paths`` is present
        # (the introduction node + amount come from the blob). Pin to
        # 02..02 (a valid-shape compressed pubkey) + the same amount
        # for consistency with the request body.
        placeholder_pub = "02" + "00" * 32
        data, error = await self._request(
            "POST",
            f"/v1/graph/routes/{placeholder_pub}/{int(amount_msat) // 1000}",
            json=body,
            idempotent=True,  # read-only routing query
        )
        if error:
            return None, error
        assert data is not None
        return data, None

    async def send_to_route_v2(
        self,
        *,
        payment_hash_hex: str,
        route: dict[str, Any],
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Execute a payment over a route returned by
        :meth:`query_routes_with_blinded_paths`.

        Wraps ``POST /v2/router/route/send`` → ``routerrpc.SendToRouteV2``.
        This is a single-shot send (NOT MPP-split); for BOLT 12 payments
        the blinded route is already the full path, so MPP-style splitting
        across multiple routes isn't applicable.

        Returns the raw ``lnrpc.HTLCAttempt`` JSON on success. The
        caller inspects ``status`` (``IN_FLIGHT`` / ``SUCCEEDED`` /
        ``FAILED``) and ``failure`` to decide the next move.
        """
        if not payment_hash_hex:
            return None, "payment_hash_hex must be non-empty"
        try:
            payment_hash = bytes.fromhex(payment_hash_hex)
        except ValueError:
            return None, "payment_hash_hex must be valid hex"
        if len(payment_hash) != 32:
            return None, "payment_hash must be 32 bytes"

        body = {
            "payment_hash": base64.b64encode(payment_hash).decode("ascii"),
            "route": route,
        }
        # Mutating call: ``_request`` consults the breaker for fast-
        # fail and runs the request exactly once (no retries — the
        # in-flight HTLC outlives the HTTP timeout, so retrying could
        # produce a stuck double-spend on the same payment_hash).
        data, error = await self._request(
            "POST",
            "/v2/router/route/send",
            json=body,
        )
        if error:
            return None, error
        assert data is not None
        return data, None

    async def lookup_payment(self, payment_hash_hex: str) -> tuple[Optional[PaymentLookup], Optional[str]]:
        """Look up an outgoing payment by its payment hash."""
        data, error = await self._request(
            "GET",
            "/v1/payments",
            params={"include_incomplete": "true", "max_payments": "100", "reversed": "true"},
        )
        if error:
            return None, error
        assert data is not None
        if data and "payments" in data:
            for p in data["payments"]:
                if p.get("payment_hash") == payment_hash_hex:
                    return {
                        "status": p.get("status", "UNKNOWN"),
                        "payment_hash": payment_hash_hex,
                        "fee_sat": int(p.get("fee_sat", 0)),
                        "payment_preimage": p.get("payment_preimage", ""),
                        "value_sat": int(p.get("value_sat", 0)),
                    }, None
            not_found: PaymentLookup = {
                "status": "UNKNOWN",
                "payment_hash": payment_hash_hex,
                "fee_sat": 0,
                "payment_preimage": "",
                "value_sat": 0,
            }
            return not_found, None
        return None, "Failed to query payments from LND"

    async def cancel_invoice(self, r_hash_hex: str) -> tuple[bool, Optional[str]]:
        """Cancel an unsettled invoice via ``invoicesrpc`` ``CancelInvoice``.

        Used by the BOLT 12 responder when a concurrent invreq race
        leaves an orphan LND invoice (this process minted it, the DB
        partial unique index then refused the row in favour of the
        winning peer). Best-effort: if LND rejects the cancel (e.g.
        invoice already settled, already canceled, or LND doesn't
        permit the operation on regular non-hold invoices), the
        caller logs and continues — the invoice will expire on its
        own TTL.

        Returns ``(True, None)`` on success or ``(False, reason)``
        on failure. Never raises.
        """
        import base64

        try:
            r_hash = bytes.fromhex(r_hash_hex)
        except ValueError as exc:
            return False, f"invalid r_hash hex: {exc}"
        r_hash_b64 = base64.b64encode(r_hash).decode("ascii")
        data, error = await self._request(
            "POST",
            "/v2/invoices/cancel",
            json={"payment_hash": r_hash_b64},
        )
        if error:
            return False, error
        # Successful CancelInvoice returns ``{}`` per the proto.
        _ = data
        return True, None

    async def lookup_invoice(self, r_hash_hex: str) -> tuple[Optional[InvoiceInfo], Optional[str]]:
        """Look up a specific invoice by its payment hash."""
        data, error = await self._request("GET", f"/v1/invoice/{r_hash_hex}")
        if error:
            return None, error
        assert data is not None
        return {
            "memo": data.get("memo", ""),
            "r_hash": r_hash_hex,
            "value": int(data.get("value", 0)),
            "settled": data.get("settled", False),
            "creation_date": int(data.get("creation_date", 0)),
            "settle_date": int(data.get("settle_date", 0)),
            "amt_paid_sat": int(data.get("amt_paid_sat", 0)),
            "state": data.get("state", "OPEN"),
            "payment_request": data.get("payment_request", ""),
            "is_keysend": data.get("is_keysend", False),
        }, None

    async def send_coins(
        self,
        address: str,
        amount_sats: Optional[int],
        sat_per_vbyte: Optional[int] = None,
        label: str = "",
        *,
        outpoints: Optional[list[Outpoint]] = None,
        send_all: bool = False,
        min_confs: int = 1,
    ) -> tuple[Optional[SendCoinsResult], Optional[str]]:
        """Send on-chain Bitcoin to an address.

        ``outpoints`` pins the input set (coin-control); empty/None lets
        LND pick. ``send_all=True`` is used for consolidate / sweep —
        ``amount_sats`` MUST be ``None`` in that case (LND rejects the
        request otherwise).
        """
        body: dict = {"addr": address, "label": label}
        if send_all:
            body["send_all"] = True
        else:
            if amount_sats is None:
                return None, "amount_sats is required when send_all=False"
            body["amount"] = str(amount_sats)
        if sat_per_vbyte is not None:
            body["sat_per_vbyte"] = str(sat_per_vbyte)
        if min_confs is not None:
            body["min_confs"] = int(min_confs)
        if outpoints:
            # LND REST takes outpoints as JSON objects (txid_str + output_index).
            body["outpoints"] = [
                {"txid_str": op["txid_str"], "output_index": int(op["output_index"])} for op in outpoints
            ]
        data, error = await self._request("POST", "/v1/transactions", json=body)
        if error:
            return None, error
        assert data is not None
        return {"txid": data.get("txid", "")}, None

    async def send_outputs(
        self,
        outputs: list[dict],
        *,
        sat_per_vbyte: Optional[int] = None,
        label: str = "",
        min_confs: int = 1,
    ) -> tuple[Optional[dict], Optional[str]]:
        """Broadcast a multi-output transaction via WalletKit
        ``SendOutputs``.

        ``outputs`` is a list of ``{"address": <str>, "amount": <sat>}``
        dicts. LND builds + signs + broadcasts atomically; the response
        carries the raw tx hex. Used by the decoy-consolidation
        flow to emit the (overpad, decoy) two-output tx in a single
        on-chain footprint.
        """
        if not outputs:
            return None, "send_outputs requires at least one output"
        # WalletKit SendOutputs takes a TxOut list (``script + value``).
        # The REST shim accepts ``AddrToAmount`` for convenience; we
        # use that to avoid pulling in script-encoding here.
        addr_to_amount: dict[str, str] = {}
        for o in outputs:
            addr = str(o.get("address", "")).strip()
            amt = int(o.get("amount", 0))
            if not addr or amt <= 0:
                return None, f"malformed output: {o!r}"
            addr_to_amount[addr] = str(amt)
        body: dict = {
            "AddrToAmount": addr_to_amount,
            "min_confs": int(min_confs),
            "spend_unconfirmed": False,
            "label": label,
        }
        if sat_per_vbyte is not None:
            body["sat_per_vbyte"] = str(sat_per_vbyte)
        data, error = await self._request(
            "POST",
            "/v2/wallet/sendoutputs",
            json=body,
        )
        if error:
            return None, error
        return data or {}, None

    async def bump_fee(
        self,
        txid_str: str,
        output_index: int,
        *,
        sat_per_vbyte: Optional[int] = None,
        target_conf: Optional[int] = None,
        force: bool = False,
    ) -> tuple[Optional[dict], Optional[str]]:
        """Bump the fee of a stuck on-chain transaction via WalletKit
        ``BumpFee`` (``POST /v2/wallet/bumpfee``).

        Direction is determined by the outpoint identity:

        * If ``(txid_str, output_index)`` is a wallet-owned UTXO,
          LND emits a CPFP child paying ``sat_per_vbyte`` so the
          parent (which we DO NOT own) is dragged in alongside it.
          This is the path used to bump a Boltz-broadcast reverse-
          claim that's stuck in our mempool.
        * If the outpoint refers to a wallet-broadcast lockup we
          DO control, LND performs an RBF replacement.

        ``sat_per_vbyte`` and ``target_conf`` are mutually exclusive;
        callers should pass exactly one. ``force=True`` opts the bump
        out of LND's anchor-channel safety check (do NOT set this
        unless you know the outpoint is unrelated to any LN channel).

        Returns ``({}, None)`` on success — WalletKit ``BumpFee`` has
        an empty success body — or ``(None, <error>)`` on failure.
        """
        if not txid_str:
            return None, "txid_str is required"
        if sat_per_vbyte is None and target_conf is None:
            return None, "one of sat_per_vbyte or target_conf is required"
        if sat_per_vbyte is not None and target_conf is not None:
            return None, "sat_per_vbyte and target_conf are mutually exclusive"
        body: dict = {
            "outpoint": {
                "txid_str": str(txid_str),
                "output_index": int(output_index),
            },
            "force": bool(force),
        }
        if sat_per_vbyte is not None:
            body["sat_per_vbyte"] = str(int(sat_per_vbyte))
        if target_conf is not None:
            body["target_conf"] = int(target_conf)
        data, error = await self._request(
            "POST",
            "/v2/wallet/bumpfee",
            json=body,
        )
        if error:
            return None, error
        return data or {}, None

    async def estimate_fee(
        self,
        address: str,
        amount_sats: int,
        target_conf: int = 6,
        *,
        outpoints: Optional[list[Outpoint]] = None,
        min_confs: int = 1,
    ) -> tuple[Optional[EstimateFeeResult], Optional[str]]:
        """Estimate on-chain transaction fee.

        When ``outpoints`` is supplied LND restricts coin selection to
        the pinned set, so the returned fee accurately reflects the
        coin-control input count.
        """
        params: dict[str, str] = {
            f"AddrToAmount[{address}]": str(amount_sats),
            "target_conf": str(target_conf),
            "min_confs": str(min_confs),
        }
        # /v1/transactions/fee is GET, but its OpenAPI shim accepts
        # repeated `outpoints` query params encoded as ``txid:vout``.
        # Falling back to a POST is unnecessary since LND parses the
        # repeated form correctly.
        if outpoints:
            # httpx serialises lists into repeated query keys.
            params_list: list[tuple[str, str]] = list(params.items())
            for op in outpoints:
                params_list.append(
                    ("outpoints[].txid_str", op["txid_str"]),
                )
                params_list.append(
                    ("outpoints[].output_index", str(int(op["output_index"]))),
                )
            data, error = await self._request("GET", "/v1/transactions/fee", params=params_list)
        else:
            data, error = await self._request("GET", "/v1/transactions/fee", params=params)
        if error:
            return None, error
        assert data is not None
        return {
            "fee_sat": int(data.get("fee_sat", 0)),
            "feerate_sat_per_byte": int(data.get("feerate_sat_per_byte", 0)),
            "sat_per_vbyte": int(data.get("sat_per_vbyte", 0)),
        }, None

    async def list_unspent(
        self,
        *,
        min_confs: int = 0,
        max_confs: int = 0x7FFFFFFF,
        account: str = "default",
    ) -> tuple[Optional[list[Utxo]], Optional[str]]:
        """Return the wallet's spendable UTXO set via WalletKit ListUnspent.

        ``min_confs=0`` includes mempool outputs; raise to 1 to exclude
        unconfirmed inputs from coin-control selection. The default
        ``account`` matches LND's default on-chain wallet account.

        LND returns the txid as both the wire-format ``outpoint.txid_bytes``
        (little-endian base64) and the human-readable
        ``outpoint.txid_str`` (big-endian hex). We always emit the hex.
        """
        params = {
            "min_confs": int(min_confs),
            "max_confs": int(max_confs),
            "account": account,
        }
        # WalletKit.ListUnspent is exposed as ``POST /v2/wallet/utxos``
        # in LND's REST gateway (GET returns 501 "Method Not Allowed").
        # The request body carries min/max confs + account; treat as
        # idempotent so a transient blip is retried like a GET.
        data, error = await self._request(
            "POST",
            "/v2/wallet/utxos",
            json=params,
            idempotent=True,
        )
        if error:
            return None, error
        assert data is not None
        out: list[Utxo] = []
        for u in data.get("utxos", []):
            op = u.get("outpoint", {}) or {}
            txid_str = op.get("txid_str") or ""
            if not txid_str and op.get("txid_bytes"):
                # Fallback for older LND builds: derive hex from the
                # base64 little-endian wire bytes.
                try:
                    txid_str = base64.b64decode(op["txid_bytes"])[::-1].hex()
                except Exception:
                    txid_str = ""
            out.append(
                {
                    "outpoint": {
                        "txid_str": txid_str,
                        "output_index": int(op.get("output_index", 0)),
                    },
                    "amount_sat": int(u.get("amount_sat", 0)),
                    "address": u.get("address", ""),
                    "address_type": u.get("address_type", "UNKNOWN"),
                    "pk_script": u.get("pk_script", ""),
                    "confirmations": int(u.get("confirmations", 0)),
                }
            )
        return out, None

    async def get_transactions(
        self,
        *,
        start_height: int = 0,
        end_height: int = -1,
        account: str = "",
    ) -> tuple[Optional[list[dict]], Optional[str]]:
        """Return the wallet's on-chain transaction history (LND
        ``GetTransactions``).

        Each entry surfaces ``tx_hash``, ``num_confirmations``,
        ``output_details`` (outputs the wallet sees, including
        ``address`` + ``amount``), and ``previous_outpoints`` (input
        outpoints in ``txid:vout`` form). Used by the Braiins-Deposit
        crash-recovery path to reconcile a
        send tx that landed on chain just before the process died.
        """
        params: dict[str, str] = {
            "start_height": str(int(start_height)),
            "end_height": str(int(end_height)),
        }
        if account:
            params["account"] = account
        data, error = await self._request("GET", "/v1/transactions", params=params, idempotent=True)
        if error:
            return None, error
        assert data is not None
        return list(data.get("transactions") or []), None

    # ─── Channel Management ──────────────────────────────────────────

    async def connect_peer(self, pubkey: str, host: str) -> tuple[Optional[dict], Optional[str]]:
        """Connect to a Lightning Network peer."""
        body = {"addr": {"pubkey": pubkey, "host": host}, "perm": True}
        data, error = await self._request("POST", "/v1/peers", json=body)
        if error:
            if "already connected" in (error or "").lower():
                return {}, None
            return None, error
        return data or {}, None

    async def open_channel(
        self,
        node_pubkey_hex: str,
        local_funding_amount: int,
        sat_per_vbyte: Optional[int] = None,
        push_sat: int = 0,
        private: bool = False,
    ) -> tuple[Optional[OpenChannelResult], Optional[str]]:
        """Open a new Lightning channel."""
        pubkey_bytes = bytes.fromhex(node_pubkey_hex)
        pubkey_b64 = base64.b64encode(pubkey_bytes).decode()

        body: dict = {
            "node_pubkey": pubkey_b64,
            "local_funding_amount": str(local_funding_amount),
            "push_sat": str(push_sat),
            "private": private,
            "spend_unconfirmed": False,
        }
        if sat_per_vbyte is not None:
            body["sat_per_vbyte"] = str(sat_per_vbyte)

        data, error = await self._request("POST", "/v1/channels", json=body)
        if error:
            return None, error
        assert data is not None

        funding_txid_bytes_b64 = data.get("funding_txid_bytes", "")
        try:
            txid_bytes = base64.b64decode(funding_txid_bytes_b64)
            funding_txid = txid_bytes[::-1].hex()
        except Exception:
            funding_txid = data.get("funding_txid_str", "")

        return {"funding_txid": funding_txid, "output_index": data.get("output_index", 0)}, None

    async def close_channel(
        self,
        funding_txid: str,
        output_index: int,
        *,
        force: bool = False,
        sat_per_vbyte: Optional[int] = None,
    ) -> tuple[Optional[dict], Optional[str]]:
        """Close a Lightning channel.

        ``force=False`` (the default) requests a cooperative close;
        ``force=True`` broadcasts our commitment (for an offline peer).

        LND's ``CloseChannel`` REST endpoint *streams* updates
        (``close_pending`` → ``chan_close``) and holds the connection
        open until the closing tx confirms. We return as soon as the
        first ``close_pending``/``chan_close`` arrives — i.e. the close
        is accepted and the closing tx is broadcasting — because callers
        track the rest via the pending-channels list. Reading the whole
        stream would otherwise block for minutes and, over Tor, surface a
        spurious connection error even though the close was accepted.
        """
        params: dict[str, str] = {}
        if force:
            params["force"] = "true"
        if sat_per_vbyte is not None:
            params["sat_per_vbyte"] = str(sat_per_vbyte)
        path = f"/v1/channels/{funding_txid}/{int(output_index)}"
        if params:
            from urllib.parse import urlencode

            path = path + "?" + urlencode(params)

        # Mutating op — consult the breaker for fast-fail, no retry.
        try:
            await _LND_BREAKER.before_call()
        except BreakerOpenError as e:
            logger.warning("LND breaker is open: %s", e)
            _LND_HEALTH.record_failure(str(e))
            return None, "LND temporarily unavailable (circuit breaker open)"

        http_timeout = httpx.Timeout(120.0, connect=20.0)
        client = await self._get_client()
        try:
            async with client.stream("DELETE", path, timeout=http_timeout) as response:
                if response.status_code >= 400:
                    text = await response.aread()
                    msg = text.decode("utf-8", errors="replace")[:500]
                    _LND_BREAKER.record_failure(f"http {response.status_code}")
                    _LND_HEALTH.record_failure(f"{response.status_code}: {msg[:120]}")
                    return None, f"LND error ({response.status_code}): {msg}"
                async for line in response.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload: dict[str, Any] = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # gRPC-gateway envelopes messages as {"result": {...}}
                    # on success or {"error": {...}} on a semantic error.
                    if "error" in payload and payload["error"]:
                        # A semantic rejection (e.g. active HTLCs) — the
                        # request itself completed, so don't trip the breaker.
                        _LND_BREAKER.record_success()
                        _LND_HEALTH.record_success()
                        err = payload["error"]
                        return None, str(err.get("message") or err) if isinstance(err, dict) else str(err)
                    result = payload.get("result") or payload
                    if "close_pending" in result or "chan_close" in result:
                        _LND_BREAKER.record_success()
                        _LND_HEALTH.record_success()
                        return result, None
        except _RETRYABLE_HTTPX_EXC as e:  # type: ignore[misc]
            err_str = f"{type(e).__name__}: {e}"
            _LND_BREAKER.record_failure(err_str)
            _LND_HEALTH.record_failure(err_str)
            if _classify_tor_failure(err_str):
                _record_tor_failure_for_lnd_path(err_str)
            return None, f"Connection failed: {e}"
        except Exception as e:
            err_str = f"{type(e).__name__}: {e}"
            _LND_BREAKER.record_failure(err_str)
            _LND_HEALTH.record_failure(err_str)
            if _classify_tor_failure(err_str):
                _record_tor_failure_for_lnd_path(err_str)
            return None, f"Request failed: {e}"

        # Stream ended without a recognizable close update.
        _LND_BREAKER.record_success()
        _LND_HEALTH.record_success()
        return None, "Close did not return a confirmation"

    # ─── Sign / Verify Message ────────────────────────────────────────

    async def sign_message_with_address(
        self, address: str, message: str
    ) -> tuple[Optional[SignAddrResult], Optional[str]]:
        """Sign an arbitrary message with the private key of an on-chain address.

        Uses LND's `SignMessageWithAddr` (BIP-322 simple for SegWit /
        Taproot, BIP-137 for legacy P2PKH and P2SH-P2WKH). The message
        bytes are sent base64-encoded; the returned signature is base64.
        """
        msg_b64 = base64.b64encode(message.encode("utf-8")).decode("ascii")
        body = {"msg": msg_b64, "addr": address}
        data, error = await self._request("POST", "/v2/wallet/address/signmessage", json=body)
        if error:
            return None, error
        assert data is not None
        signature = data.get("signature", "")
        addr_type = _classify_address_type(address)
        sig_format = "BIP-322" if addr_type in ("p2wkh", "p2tr", "p2wsh") else "BIP-137"
        return {
            "address": address,
            "address_type": addr_type,
            "signature": signature,
            "format": sig_format,
        }, None

    async def verify_message_with_address(
        self, address: str, message: str, signature: str
    ) -> tuple[Optional[VerifyAddrResult], Optional[str]]:
        """Verify a signature against an on-chain address."""
        msg_b64 = base64.b64encode(message.encode("utf-8")).decode("ascii")
        body = {"msg": msg_b64, "signature": signature, "addr": address}
        data, error = await self._request("POST", "/v2/wallet/address/verifymessage", json=body)
        if error:
            return None, error
        assert data is not None
        valid = bool(data.get("valid", False))
        # LND returns the recovered pubkey as base64 raw bytes
        pubkey_b64 = data.get("pubkey", "")
        pubkey_hex: Optional[str]
        if pubkey_b64:
            try:
                pubkey_hex = base64.b64decode(pubkey_b64).hex()
            except Exception:
                pubkey_hex = None
        else:
            pubkey_hex = None
        return {"valid": valid, "pubkey": pubkey_hex if valid else None}, None

    async def sign_message_node(self, message: str) -> tuple[Optional[SignNodeResult], Optional[str]]:
        """Sign a message with the node identity key (zbase32 output)."""
        msg_b64 = base64.b64encode(message.encode("utf-8")).decode("ascii")
        body = {"msg": msg_b64}
        data, error = await self._request("POST", "/v1/signmessage", json=body)
        if error:
            return None, error
        assert data is not None
        # Get node pubkey from getinfo (cheap and cached by LND)
        info, info_err = await self.get_info()
        node_pubkey = info["identity_pubkey"] if info else ""
        if info_err:
            logger.warning("sign_message_node: could not fetch node pubkey: %s", info_err)
        return {
            "signature": data.get("signature", ""),
            "node_pubkey": node_pubkey,
        }, None

    async def verify_message_node(
        self, message: str, signature: str
    ) -> tuple[Optional[VerifyNodeResult], Optional[str]]:
        """Verify a zbase32 signature against the LN node-identity scheme."""
        msg_b64 = base64.b64encode(message.encode("utf-8")).decode("ascii")
        body = {"msg": msg_b64, "signature": signature}
        data, error = await self._request("POST", "/v1/verifymessage", json=body)
        if error:
            return None, error
        assert data is not None
        valid = bool(data.get("valid", False))
        pubkey = data.get("pubkey") if valid else None
        return {"valid": valid, "pubkey": pubkey}, None


def _classify_address_type(address: str) -> str:
    """Best-effort classification of a Bitcoin address into a label.

    Returns one of: "p2tr" (Taproot, bech32m v1), "p2wkh"/"p2wsh"
    (Native SegWit v0 bech32, by program length), "p2sh-p2wkh" (legacy
    base58 starting with 3/2), "p2pkh" (legacy base58 starting with
    1/m/n), or "unknown".
    """
    a = address.strip()
    lower = a.lower()
    # bech32 / bech32m
    for hrp in ("bc1", "tb1", "bcrt1"):
        if lower.startswith(hrp):
            # First data char after the separator '1' encodes the witness version
            sep = lower.rfind("1")
            if sep == -1 or sep + 1 >= len(lower):
                return "unknown"
            ver_char = lower[sep + 1]
            charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
            ver = charset.find(ver_char)
            if ver == 1:
                return "p2tr"
            if ver == 0:
                # v0: 20-byte program → p2wkh, 32-byte → p2wsh
                # Data section length minus version (1) minus checksum (6)
                data_len = len(lower) - sep - 1 - 1 - 6
                # 20 bytes → 32 chars in 5-bit groups; 32 bytes → 52 chars
                if data_len == 32:
                    return "p2wkh"
                if data_len == 52:
                    return "p2wsh"
                return "p2w-unknown"
            return f"p2w-v{ver}" if ver >= 0 else "unknown"
    # legacy
    if a and a[0] in ("3", "2"):
        return "p2sh-p2wkh"  # heuristic: most p2sh are wrapped segwit
    if a and a[0] in ("1", "m", "n"):
        return "p2pkh"
    return "unknown"


# Singleton instance
lnd_service = LNDService()
