# SPDX-License-Identifier: MIT
"""LNURL-pay and Lightning Address resolution service.

Implements the small subset of LUD-01 / LUD-06 / LUD-12 / LUD-16 we
need to *send* payments to Lightning Addresses and LNURL-pay endpoints
from the dashboard, with strict SSRF / phishing / desc-hash protection.

Public API:

    resolve_recipient(text: str) -> tuple[ResolveResult|None, str|None]
        Accepts either an ``lnurl1...`` bech32 string or a Lightning
        Address (``user@host``) and returns the validated LNURL-pay
        params plus an opaque server-side handle.

    request_invoice(handle, amount_sats, comment) -> tuple[InvoiceResult|None, str|None]
        Calls the recipient's callback to mint a BOLT11 invoice for
        the chosen amount, validates ``description_hash`` /
        ``num_satoshis`` / expiry against LUD-06, and returns the
        BOLT11 plus a sanitised ``success_action`` for display.

The service is intentionally stateful (a singleton): it owns the
short-lived handle store, the invoice idempotency cache, and a
recycled ``httpx.AsyncClient`` for outbound requests. All outbound
HTTP is hardened against SSRF (no redirects, private-host block,
strict TLS, response-size cap, optional Tor routing).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Optional, TypedDict
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

import httpx

from app.core.bech32_lnurl import decode_lnurl
from app.core.config import settings
from app.core.net_guard import BlockedHostError, host_resolves_to_blocked, is_blocked_ip, pin_request_args
from app.core.utils import force_remote_dns_socks

logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────

# LUD-16 Lightning Address grammar.
# Local part is restricted per LUD-16 to lowercase ``a-z0-9-_.``, with dots
# only as internal separators (no leading, trailing, or consecutive dots),
# so a ``.well-known`` path component can never collapse to ``.`` or ``..``.
# The domain part follows standard host rules.
_LN_ADDRESS_RE = re.compile(
    r"^(?P<user>[a-z0-9_-]+(?:\.[a-z0-9_-]+)*)@(?P<host>[a-z0-9.-]{1,253}\.[a-z]{2,})$"
)

# Cap on metadata bytes (LUD-06). 32 KB is well above any sane vendor
# response and below the per-response cap.
_MAX_METADATA_BYTES = 32_768

# Recipient comment cap. We further clamp by ``commentAllowed``; this
# is a hard upper bound so a malicious recipient cannot trick us into
# proxying a multi-MB comment.
_MAX_COMMENT_CHARS = 280

# Max bytes accepted for a single inline metadata image. ~100 KB after
# base64 decoding (≈ 76 KB raw); larger images are stripped.
_MAX_IMAGE_DATA_URI_LEN = 140_000

# Strict allow-list for inline image data URIs. SVG is excluded
# because rendering arbitrary SVG inline is an XSS vector.
_IMAGE_DATA_URI_RE = re.compile(r"^data:image/(png|jpeg);base64,[A-Za-z0-9+/=]{1,140000}$")


# ── Types ────────────────────────────────────────────────────────────


class LnurlPayParams(TypedDict, total=False):
    """Server-side cached LNURL-pay params for a single recipient."""

    # Original source the user typed/pasted (Lightning Address or LNURL).
    source_kind: str  # "lightning_address" | "lnurl"
    source_input: str
    # Resolved HTTPS callback URL.
    callback: str
    callback_host: str
    # Min/max sendable in millisats (recipient declares both).
    min_sendable_msat: int
    max_sendable_msat: int
    # Original metadata JSON string — needed to compute description_hash.
    metadata_raw: str
    metadata_text: str
    metadata_long: Optional[str]
    metadata_image_data_uri: Optional[str]
    # Comment-allowed length (LUD-12). 0 = comments not supported.
    comment_allowed: int


class ResolveResult(TypedDict):
    """Sanitised payload returned to the dashboard frontend."""

    handle: str
    source_kind: str
    source_input: str
    callback_host: str
    min_sendable_sats: int
    max_sendable_sats: int
    metadata_text: str
    metadata_long: Optional[str]
    metadata_image_data_uri: Optional[str]
    comment_allowed: int


class SuccessAction(TypedDict, total=False):
    tag: str  # "message" | "url" | "aes" | "noop"
    message: Optional[str]
    description: Optional[str]
    url: Optional[str]


class InvoiceResult(TypedDict):
    """Result of calling the LNURL-pay callback."""

    payment_request: str
    payment_hash: str
    amount_sats: int
    description: str  # plain text from metadata (for display)
    expiry_seconds: int
    success_action: Optional[SuccessAction]
    cache_hit: bool


# ── Internal stores ─────────────────────────────────────────────────


@dataclass
class _HandleEntry:
    params: LnurlPayParams
    expires_at: float


@dataclass
class _InvoiceCacheEntry:
    result: InvoiceResult
    expires_at: float


class _LnurlHandleStore:
    """In-memory TTL+LRU store mapping opaque handles → LnurlPayParams.

    Single-process only; this is intentional. The dashboard runs as a
    single uvicorn worker for the operator's wallet, and the data is
    short-lived (5 min) and recoverable (the user can re-resolve).
    """

    _MAX_ENTRIES = 256

    def __init__(self) -> None:
        self._entries: dict[str, _HandleEntry] = {}
        self._lock = asyncio.Lock()

    async def put(self, params: LnurlPayParams) -> str:
        ttl = settings.lnurl_handle_ttl_seconds
        async with self._lock:
            self._purge_locked()
            handle = secrets.token_hex(16)
            self._entries[handle] = _HandleEntry(
                params=params,
                expires_at=time.monotonic() + ttl,
            )
            # LRU eviction: oldest entries first.
            while len(self._entries) > self._MAX_ENTRIES:
                self._entries.pop(next(iter(self._entries)))
        return handle

    async def get(self, handle: str) -> Optional[LnurlPayParams]:
        async with self._lock:
            self._purge_locked()
            entry = self._entries.get(handle)
            if entry is None:
                return None
            # Re-insert at end so recently-accessed items are kept.
            self._entries.pop(handle)
            self._entries[handle] = entry
            return entry.params

    def _purge_locked(self) -> None:
        now = time.monotonic()
        expired = [h for h, e in self._entries.items() if e.expires_at <= now]
        for h in expired:
            self._entries.pop(h, None)


class _LnurlInvoiceCache:
    """Per-(handle, amount, comment) idempotency cache.

    Prevents an accidental double-click on the dashboard's Continue
    button from minting two invoices on the recipient. Failures are
    NEVER cached, so a transient recipient error can be retried
    immediately. TTL is short (default 30 s).
    """

    _MAX_ENTRIES = 64

    def __init__(self) -> None:
        self._entries: dict[tuple[str, int, str], _InvoiceCacheEntry] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: tuple[str, int, str]) -> Optional[InvoiceResult]:
        ttl = settings.lnurl_invoice_cache_ttl_seconds
        if ttl <= 0:
            return None
        async with self._lock:
            self._purge_locked()
            entry = self._entries.get(key)
            return entry.result if entry else None

    async def put(self, key: tuple[str, int, str], result: InvoiceResult) -> None:
        ttl = settings.lnurl_invoice_cache_ttl_seconds
        if ttl <= 0:
            return
        async with self._lock:
            self._purge_locked()
            self._entries[key] = _InvoiceCacheEntry(
                result=result,
                expires_at=time.monotonic() + ttl,
            )
            while len(self._entries) > self._MAX_ENTRIES:
                self._entries.pop(next(iter(self._entries)))

    def _purge_locked(self) -> None:
        now = time.monotonic()
        expired = [k for k, e in self._entries.items() if e.expires_at <= now]
        for k in expired:
            self._entries.pop(k, None)


# ── SSRF / URL hardening ────────────────────────────────────────────


def _is_onion_host(host: str) -> bool:
    return host.lower().endswith(".onion")


def _host_is_private(host: str) -> bool:
    """Return True when ``host`` is (or resolves to) a non-routable address.

    Thin wrapper over the shared egress guard so the resolve-time check and
    the connection-time pin enforce one identical policy.
    """
    return host_resolves_to_blocked(host)


def _ip_is_private(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return is_blocked_ip(ip)


def _validate_target_url(url: str, *, context: str) -> tuple[str, Optional[str]]:
    """Return (normalised_url, None) on success, (url, error) on failure.

    ``context`` is used in the error string ("resolve" / "callback").
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return url, f"{context}: invalid URL"
    if parsed.scheme not in ("http", "https"):
        return url, f"{context}: only http/https URLs are accepted"
    host = (parsed.hostname or "").lower()
    if not host:
        return url, f"{context}: missing host"
    is_onion = _is_onion_host(host)
    if parsed.scheme == "http" and not is_onion and not settings.lnurl_allow_http:
        return url, (
            f"{context}: plain http:// not allowed for clearnet hosts. Set LNURL_ALLOW_HTTP=true only for testing."
        )
    if not settings.lnurl_allow_private_hosts and _host_is_private(host):
        return url, f"{context}: refusing to connect to private/loopback host"
    return url, None


# ── HTTP client ─────────────────────────────────────────────────────


def _should_use_tor() -> bool:
    """Decide whether outbound LNURL HTTP should route via the Tor proxy."""
    mode = settings.lnurl_force_tor
    if mode == "true":
        return True
    if mode == "false":
        return False
    # auto: use Tor iff LND_REST_URL is .onion
    try:
        host = (urlparse(settings.lnd_rest_url).hostname or "").lower()
    except Exception:
        return False
    return _is_onion_host(host)


# ── Service ─────────────────────────────────────────────────────────


class LnurlService:
    def __init__(self) -> None:
        self._client: Optional[httpx.AsyncClient] = None
        self._client_uses_tor: Optional[bool] = None
        self._handle_store = _LnurlHandleStore()
        self._invoice_cache = _LnurlInvoiceCache()

    async def _get_client(self, *, target_is_onion: bool) -> tuple[httpx.AsyncClient, bool]:
        """Lazily create / recycle the outbound HTTP client.

        We use Tor when either the global force-tor toggle says so or
        the specific target is .onion (and a Tor proxy is configured).
        Returns the client together with the ``use_tor`` decision so the
        caller resolves the destination at the SOCKS proxy (remotely)
        rather than locally whenever traffic egresses through Tor.
        """
        force = _should_use_tor()
        use_tor = force or target_is_onion
        if use_tor and not settings.lnd_tor_proxy:
            if target_is_onion:
                raise RuntimeError("LNURL target is a .onion host but LND_TOR_PROXY is not set.")
            # Force-tor requested but no proxy: fall back to a direct connection.
            use_tor = False

        if self._client is None or self._client.is_closed or self._client_uses_tor != use_tor:
            if self._client is not None and not self._client.is_closed:
                await self._client.aclose()
            kwargs: dict[str, Any] = {
                "timeout": httpx.Timeout(settings.lnurl_resolve_timeout_seconds),
                "follow_redirects": False,
                "headers": {"User-Agent": "agent-wallet-lnurl/1.0"},
            }
            if use_tor:
                kwargs["proxy"] = force_remote_dns_socks(settings.lnd_tor_proxy)
            self._client = httpx.AsyncClient(**kwargs)
            self._client_uses_tor = use_tor
        return self._client, use_tor

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    # ── Public API ───────────────────────────────────────────────────

    async def resolve_recipient(self, text: str) -> tuple[Optional[ResolveResult], Optional[str]]:
        """Resolve a Lightning Address or LNURL string to validated params."""
        if not text or not isinstance(text, str):
            return None, "empty input"
        cleaned = text.strip()
        # Tolerate "lightning:" scheme prefix (LUD-17).
        if cleaned.lower().startswith("lightning:"):
            cleaned = cleaned[len("lightning:") :]
        # Try Lightning Address first (LUD-16).
        if "@" in cleaned:
            return await self._resolve_lightning_address(cleaned)
        # Otherwise try LNURL bech32 (LUD-01).
        if cleaned.lower().startswith("lnurl"):
            return await self._resolve_lnurl_bech32(cleaned)
        return None, "Not a Lightning Address or LNURL string"

    async def request_invoice(
        self,
        handle: str,
        amount_sats: int,
        comment: str,
    ) -> tuple[Optional[InvoiceResult], Optional[str]]:
        params = await self._handle_store.get(handle)
        if params is None:
            return None, "LNURL handle not found or expired. Please re-resolve."
        if amount_sats <= 0:
            return None, "amount must be positive"
        amount_msat = amount_sats * 1000
        min_msat = params.get("min_sendable_msat", 0)
        max_msat = params.get("max_sendable_msat", 0)
        if amount_msat < min_msat or amount_msat > max_msat:
            return None, (
                f"amount {amount_sats} sats outside recipient's {min_msat // 1000}-{max_msat // 1000} sat range"
            )

        comment_allowed = int(params.get("comment_allowed", 0))
        # Hard clamp regardless of recipient's declared cap.
        max_comment = min(max(comment_allowed, 0), _MAX_COMMENT_CHARS)
        if comment and len(comment) > max_comment:
            return None, (f"comment too long: {len(comment)} > {max_comment} chars")

        cache_key = (handle, amount_sats, comment or "")
        cached = await self._invoice_cache.get(cache_key)
        if cached is not None:
            return {**cached, "cache_hit": True}, None

        result, err = await self._call_callback(params, amount_msat, comment)
        if err is not None:
            return None, err
        assert result is not None
        await self._invoice_cache.put(cache_key, result)
        return result, None

    # ── Lightning Address ────────────────────────────────────────────

    async def _resolve_lightning_address(self, addr: str) -> tuple[Optional[ResolveResult], Optional[str]]:
        normalised = addr.lower()
        m = _LN_ADDRESS_RE.match(normalised)
        if m is None:
            return None, "Invalid Lightning Address format"
        user = m.group("user")
        host = m.group("host")
        if len(user) > 64:
            return None, "Invalid Lightning Address format"
        # Onion hosts use http://, clearnet uses https://.
        scheme = "http" if _is_onion_host(host) else "https"
        url = f"{scheme}://{host}/.well-known/lnurlp/{quote(user, safe='')}"
        return await self._fetch_pay_params(url, source_kind="lightning_address", source_input=normalised)

    # ── LNURL bech32 ────────────────────────────────────────────────

    async def _resolve_lnurl_bech32(self, lnurl: str) -> tuple[Optional[ResolveResult], Optional[str]]:
        decoded = decode_lnurl(lnurl)
        if decoded is None:
            return None, "Invalid LNURL bech32 string"
        return await self._fetch_pay_params(decoded, source_kind="lnurl", source_input=lnurl.lower())

    # ── Resolve params ──────────────────────────────────────────────

    async def _fetch_pay_params(
        self, url: str, *, source_kind: str, source_input: str
    ) -> tuple[Optional[ResolveResult], Optional[str]]:
        url, err = _validate_target_url(url, context="resolve")
        if err is not None:
            return None, err
        host = (urlparse(url).hostname or "").lower()
        body, err = await self._http_get_json(url, target_is_onion=_is_onion_host(host))
        if err is not None:
            return None, err
        assert body is not None

        # LNURL spec: errors look like {"status": "ERROR", "reason": "..."}.
        if isinstance(body, dict) and str(body.get("status", "")).upper() == "ERROR":
            reason = str(body.get("reason", "unspecified")).strip()[:200]
            return None, f"recipient refused: {reason}"

        if not isinstance(body, dict):
            return None, "resolve: response was not a JSON object"
        if str(body.get("tag", "")) != "payRequest":
            return None, "resolve: only LNURL-pay (tag=payRequest) is supported"
        callback = str(body.get("callback", ""))
        cb_url, err = _validate_target_url(callback, context="callback")
        if err is not None:
            return None, err
        cb_host = (urlparse(cb_url).hostname or "").lower()
        # Cross-host callbacks are explicitly permitted: LUD-06 only
        # recommends same-origin, and the redirect pattern (e.g. a static
        # ``.well-known/lnurlp/<name>`` file on a personal domain pointing
        # at an Alby / LNbits / Phoenix callback) is in widespread use.
        # The callback URL is independently validated above (HTTPS unless
        # ``LNURL_ALLOW_HTTP``, SSRF guard, no private hosts) and its
        # onion-ness is decided per-target when the request is made, so
        # cross-host is safe.

        try:
            min_msat = int(body.get("minSendable", 0))
            max_msat = int(body.get("maxSendable", 0))
        except (TypeError, ValueError):
            return None, "resolve: invalid min/maxSendable"
        if not (0 < min_msat <= max_msat):
            return None, "resolve: invalid min/maxSendable range"

        metadata_raw = body.get("metadata", "")
        if not isinstance(metadata_raw, str) or len(metadata_raw.encode("utf-8")) > _MAX_METADATA_BYTES:
            return None, "resolve: metadata missing or too large"
        meta_text, meta_long, meta_image = _parse_metadata(metadata_raw)
        if meta_text is None:
            return None, "resolve: metadata missing required text/plain entry"

        comment_allowed = int(body.get("commentAllowed", 0) or 0)
        if comment_allowed < 0:
            comment_allowed = 0
        if comment_allowed > _MAX_COMMENT_CHARS:
            comment_allowed = _MAX_COMMENT_CHARS

        params: LnurlPayParams = {
            "source_kind": source_kind,
            "source_input": source_input,
            "callback": cb_url,
            "callback_host": cb_host,
            "min_sendable_msat": min_msat,
            "max_sendable_msat": max_msat,
            "metadata_raw": metadata_raw,
            "metadata_text": meta_text,
            "metadata_long": meta_long,
            "metadata_image_data_uri": meta_image,
            "comment_allowed": comment_allowed,
        }
        handle = await self._handle_store.put(params)
        return {
            "handle": handle,
            "source_kind": source_kind,
            "source_input": source_input,
            "callback_host": cb_host,
            "min_sendable_sats": min_msat // 1000,
            "max_sendable_sats": max_msat // 1000,
            "metadata_text": meta_text,
            "metadata_long": meta_long,
            "metadata_image_data_uri": meta_image,
            "comment_allowed": comment_allowed,
        }, None

    # ── Callback / invoice ─────────────────────────────────────────

    async def _call_callback(
        self,
        params: LnurlPayParams,
        amount_msat: int,
        comment: str,
    ) -> tuple[Optional[InvoiceResult], Optional[str]]:
        # Re-validate the cached callback URL (settings could have changed).
        cb = params["callback"]
        cb, err = _validate_target_url(cb, context="callback")
        if err is not None:
            return None, err
        host = (urlparse(cb).hostname or "").lower()

        # LUD-06 requires re-using the callback URL, which may already
        # carry query params. Preserve those, but make our own keys
        # authoritative so a recipient that pre-populated ``amount`` /
        # ``comment`` can't end up with duplicate, conflicting params.
        parsed = urlparse(cb)
        merged_pairs = [
            (k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k not in ("amount", "comment")
        ]
        merged_pairs.append(("amount", str(amount_msat)))
        if comment and params.get("comment_allowed", 0) > 0:
            merged_pairs.append(("comment", comment))
        request_url = urlunparse(parsed._replace(query=urlencode(merged_pairs)))

        body, err = await self._http_get_json(request_url, target_is_onion=_is_onion_host(host))
        if err is not None:
            return None, err
        assert body is not None
        if isinstance(body, dict) and str(body.get("status", "")).upper() == "ERROR":
            reason = str(body.get("reason", "unspecified")).strip()[:200]
            return None, f"recipient refused: {reason}"
        if not isinstance(body, dict):
            return None, "callback: response was not a JSON object"
        pr = body.get("pr", "")
        if not isinstance(pr, str) or not pr:
            return None, "callback: missing 'pr' (payment request)"
        # Decode + validate the BOLT11 against LUD-06 invariants.
        try:
            decoded = _decode_bolt11_minimal(pr)
        except _Bolt11Error as exc:
            return None, f"callback: bolt11 decode failed: {exc}"
        # Description hash MUST equal sha256(metadata).
        expected_hash = hashlib.sha256(params["metadata_raw"].encode("utf-8")).digest()
        if decoded.description_hash != expected_hash:
            return None, "callback: BOLT11 description_hash does not match metadata"
        # Amount must match the requested amount (LUD-06).
        if decoded.amount_msat is None:
            return None, "callback: BOLT11 has no amount"
        if decoded.amount_msat != amount_msat:
            return None, (f"callback: BOLT11 amount {decoded.amount_msat} msat != requested {amount_msat} msat")
        # Reject expired or near-expiring invoices (<60s left).
        now = int(time.time())
        seconds_left = decoded.timestamp + decoded.expiry_seconds - now
        if seconds_left < 60:
            return None, (f"callback: BOLT11 expires too soon ({seconds_left}s left)")

        success_action = _sanitise_success_action(body.get("successAction"))

        return {
            "payment_request": pr,
            "payment_hash": decoded.payment_hash_hex,
            "amount_sats": amount_msat // 1000,
            "description": params["metadata_text"],
            "expiry_seconds": seconds_left,
            "success_action": success_action,
            "cache_hit": False,
        }, None

    # ── Low-level HTTP ──────────────────────────────────────────────

    async def _http_get_json(self, url: str, *, target_is_onion: bool) -> tuple[Optional[Any], Optional[str]]:
        client, use_tor = await self._get_client(target_is_onion=target_is_onion)
        max_bytes = settings.lnurl_max_response_bytes

        # Direct (non-Tor) requests connect to a freshly-validated, pinned IP
        # so the address that passed the SSRF guard is the address the socket
        # lands on. When the request egresses through Tor the destination is
        # resolved at the SOCKS proxy: we keep the hostname in the URL and do
        # not perform a local DNS lookup, so the recipient host is never
        # resolved on this machine.
        request_url = url
        headers: dict[str, str] = {}
        extensions: dict[str, str] = {}
        if not use_tor:
            try:
                request_url, headers, extensions = pin_request_args(url)
            except BlockedHostError as exc:
                return None, f"refusing to connect: {exc}"
            except ValueError:
                request_url = url

        try:
            async with client.stream("GET", request_url, headers=headers, extensions=extensions) as resp:
                if resp.status_code != 200:
                    return None, f"HTTP {resp.status_code} from recipient"
                buf = bytearray()
                async for chunk in resp.aiter_bytes():
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        return None, (f"response exceeded {max_bytes} byte cap")
        except httpx.HTTPError as exc:
            return None, f"HTTP error: {exc.__class__.__name__}"
        except RuntimeError as exc:
            return None, str(exc)
        try:
            return json.loads(buf.decode("utf-8")), None
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, "response was not valid JSON"


# ── Metadata parsing ────────────────────────────────────────────────


def _parse_metadata(
    raw: str,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract (text, long_text, image_data_uri) from the metadata array.

    Returns (None, None, None) only when the required ``text/plain``
    entry is missing or malformed. Image entries that fail the strict
    allow-list are silently dropped (returned as None) rather than
    failing the whole resolve.
    """
    try:
        meta = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None, None, None
    if not isinstance(meta, list):
        return None, None, None
    text: Optional[str] = None
    long_text: Optional[str] = None
    image: Optional[str] = None
    for entry in meta:
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        kind, value = entry[0], entry[1]
        if not isinstance(kind, str) or not isinstance(value, str):
            continue
        if kind == "text/plain" and text is None:
            text = value[:512]
        elif kind == "text/long-desc" and long_text is None:
            long_text = value[:2048]
        elif kind in ("image/png;base64", "image/jpeg;base64") and image is None:
            mime = "image/png" if kind.startswith("image/png") else "image/jpeg"
            data_uri = f"data:{mime};base64,{value}"
            if len(data_uri) <= _MAX_IMAGE_DATA_URI_LEN and _IMAGE_DATA_URI_RE.match(data_uri):
                image = data_uri
    return text, long_text, image


# ── Success-action sanitisation ─────────────────────────────────────


def _sanitise_success_action(raw: Any) -> Optional[SuccessAction]:
    if not isinstance(raw, dict):
        return None
    tag = raw.get("tag")
    if not isinstance(tag, str):
        return None
    if tag == "message":
        msg = raw.get("message")
        if not isinstance(msg, str):
            return None
        # LUD-09 caps message at 144 chars.
        return {"tag": "message", "message": msg[:144]}
    if tag == "url":
        url = raw.get("url")
        desc = raw.get("description", "")
        if not isinstance(url, str) or not isinstance(desc, str):
            return None
        # Only http/https; truncate aggressively. We display this URL
        # as non-clickable text on the frontend, so we don't enforce
        # SSRF rules on it — but we still refuse non-http schemes.
        try:
            scheme = urlparse(url).scheme.lower()
        except Exception:
            return None
        if scheme not in ("http", "https"):
            return None
        return {"tag": "url", "description": desc[:144], "url": url[:512]}
    if tag == "aes":
        return {"tag": "aes"}
    return None


# ── Minimal BOLT11 decoder ──────────────────────────────────────────
#
# We need three fields from the recipient's invoice to satisfy LUD-06:
#   * description_hash  — must equal sha256(metadata_raw)
#   * amount (msat)     — must equal the amount we asked for
#   * timestamp + expiry — to refuse expired invoices
# Everything else (signature recovery, route hints, payee verification)
# is left to LND when the user actually pays.
#
# bolt11 format recap:
#   hrp    = "ln" + bc/tb/bcrt/sb + amount-with-multiplier
#   data   = 35-byte timestamp (7 × 5-bit) + tagged fields + signature (65 B)
#   bech32 lower-case, no length cap

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class _Bolt11Error(ValueError):
    pass


@dataclass
class _Bolt11Decoded:
    timestamp: int
    expiry_seconds: int
    amount_msat: Optional[int]
    description_hash: Optional[bytes]
    payment_hash_hex: str


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_decode_unrestricted(s: str) -> tuple[str, list[int]]:
    if s.lower() != s and s.upper() != s:
        raise _Bolt11Error("mixed case")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        raise _Bolt11Error("malformed bech32")
    hrp = s[:pos]
    data: list[int] = []
    for c in s[pos + 1 :]:
        idx = _BECH32_CHARSET.find(c)
        if idx == -1:
            raise _Bolt11Error("invalid bech32 char")
        data.append(idx)
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        raise _Bolt11Error("checksum failed")
    return hrp, data[:-6]


def _u5_to_u8(data: list[int]) -> bytes:
    """Convert a list of 5-bit groups into bytes, dropping any trailing
    bits that don't form a full byte. Used for tagged-field payloads
    that carry byte data (description_hash, payment_hash, etc.)."""
    acc = 0
    bits = 0
    out = bytearray()
    for v in data:
        if v < 0 or v > 31:
            raise _Bolt11Error("invalid 5-bit value")
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)


# BOLT11 HRP network prefixes per configured ``bitcoin_network``. Longest
# match wins (see ``_NETWORK_PREFIX_ORDER``) so signet's "tbs" is not
# shadowed by testnet's "tb".
_NETWORK_HRP_PREFIXES: dict[str, tuple[str, ...]] = {
    "bitcoin": ("bc",),
    "testnet": ("tb",),
    "signet": ("tbs", "sb"),
    "regtest": ("bcrt",),
}
_NETWORK_PREFIX_ORDER = ("bcrt", "tbs", "tb", "bc", "sb")
# 21e6 BTC expressed in msat — the protocol maximum.
_MAX_BOLT11_MSAT = 21_000_000 * 100_000_000_000


def _validate_bolt11_network(hrp: str) -> None:
    """Require the HRP's network prefix to match the configured network."""
    rest = hrp[2:] if hrp.startswith("ln") else hrp
    for prefix in _NETWORK_PREFIX_ORDER:
        if rest.startswith(prefix):
            if prefix not in _NETWORK_HRP_PREFIXES.get(settings.bitcoin_network, ()):
                raise _Bolt11Error(
                    f"BOLT11 network prefix '{prefix}' does not match configured network "
                    f"'{settings.bitcoin_network}'"
                )
            return
    raise _Bolt11Error("BOLT11 HRP missing a recognized network prefix")


def _parse_bolt11_amount(hrp: str) -> Optional[int]:
    """Extract amount (msat) from the BOLT11 HRP. Returns None when no
    amount is present (amount-less invoices are rejected upstream)."""
    # hrp = "ln" + prefix(bc/tb/bcrt/sb) + amount + multiplier
    if not hrp.startswith("ln"):
        raise _Bolt11Error("HRP missing 'ln' prefix")
    rest = hrp[2:]
    # Strip known network prefixes.
    for prefix in _NETWORK_PREFIX_ORDER:
        if rest.startswith(prefix):
            rest = rest[len(prefix) :]
            break
    if not rest:
        return None
    # Multiplier (m / u / n / p) is optional and always last.
    multiplier = ""
    if rest[-1] in "munp":
        multiplier = rest[-1]
        rest = rest[:-1]
    if not rest.isdigit():
        raise _Bolt11Error("invalid amount in HRP")
    # Bound the digit count so an absurdly long HRP can't drive unbounded
    # bigint work; the protocol maximum needs far fewer than this.
    if len(rest) > 14:
        raise _Bolt11Error("BOLT11 amount has too many digits")
    btc = int(rest)
    # value is BTC / factor; msat = value * 10^11 if multiplier == "p" needs care.
    # bolt11 spec: amount is BTC × 10^(-multiplier_exp), msat = amount × 10^11.
    # Use exact integer math to avoid float rounding.
    if multiplier == "":
        msat = btc * 100_000_000_000  # 10^11
    elif multiplier == "m":
        msat = btc * 100_000_000  # 10^8
    elif multiplier == "u":
        msat = btc * 100_000  # 10^5
    elif multiplier == "n":
        msat = btc * 100  # 10^2
    else:  # "p"
        # 1 picobtc = 0.1 msat. Per BOLT11 the value MUST be a multiple of 10.
        if btc % 10 != 0:
            raise _Bolt11Error("p-multiplier amount not a multiple of 10")
        msat = btc // 10
    if msat > _MAX_BOLT11_MSAT:
        raise _Bolt11Error("BOLT11 amount exceeds the protocol maximum")
    return msat


def _decode_bolt11_minimal(invoice: str) -> _Bolt11Decoded:
    hrp, data = _bech32_decode_unrestricted(invoice)
    _validate_bolt11_network(hrp)
    amount_msat = _parse_bolt11_amount(hrp)
    if len(data) < 7 + 104:
        raise _Bolt11Error("payload too short")
    timestamp = 0
    for v in data[:7]:
        timestamp = (timestamp << 5) | v
    # Strip 7-group timestamp prefix and 104-group sig suffix (520 bits = 65 B).
    body = data[7:-104]

    expiry_seconds = 3600  # bolt11 default
    description_hash: Optional[bytes] = None
    payment_hash: Optional[bytes] = None
    i = 0
    while i + 3 <= len(body):
        tag = body[i]
        length = (body[i + 1] << 5) | body[i + 2]
        i += 3
        if i + length > len(body):
            raise _Bolt11Error("truncated tagged field")
        payload = body[i : i + length]
        i += length
        # Tag values per BOLT11:
        #   p (1)  → payment_hash, 52 5-bit groups (32 bytes)
        #   h (23) → description_hash, 52 5-bit groups
        #   x (6)  → expiry seconds (variable length, big-endian)
        if tag == 1 and length == 52:
            payment_hash = _u5_to_u8(payload)[:32]
        elif tag == 23 and length == 52:
            description_hash = _u5_to_u8(payload)[:32]
        elif tag == 6:
            v = 0
            for g in payload:
                v = (v << 5) | g
            expiry_seconds = v
    if payment_hash is None:
        raise _Bolt11Error("missing payment_hash")
    return _Bolt11Decoded(
        timestamp=timestamp,
        expiry_seconds=expiry_seconds,
        amount_msat=amount_msat,
        description_hash=description_hash,
        payment_hash_hex=payment_hash.hex(),
    )


# ── Singleton ───────────────────────────────────────────────────────


_lnurl_service: Optional[LnurlService] = None


def get_lnurl_service() -> LnurlService:
    global _lnurl_service
    if _lnurl_service is None:
        _lnurl_service = LnurlService()
    return _lnurl_service
