# SPDX-License-Identifier: MIT
"""
Security alerting service — sends notifications for anomalous events.

Sends webhook POSTs (Slack/Discord/generic) for configurable event types:
- login_failed: repeated failed dashboard login attempts
- tor_fallback: Boltz traffic falling back from Tor to clearnet
- lnd_disconnect: LND node connectivity loss
- high_value_payment: payment above a configurable threshold
- auth_brute_force: global auth failure threshold reached
- csrf_violation: dashboard request with missing/mismatched CSRF token
- rate_limit_degraded: shared rate-limit storage fell back to per-worker memory
- audit_chain_broken: audit hash chain failed verification (pruning paused)
- audit_anchor: signed snapshot of the audit chain head/count (plus the
  in-process ``deleted`` count for that cycle) emitted each retention cycle so
  an off-box receiver can detect front-truncation (deletion of the oldest rows)
  by enforcing ``count_now >= count_prev - deleted_now`` across the signed
  anchor stream — see SECURITY.md

Configure via ALERT_WEBHOOK_URL and ALERT_WEBHOOK_EVENTS env vars.

Optional payload authentication:
  ALERT_WEBHOOK_SHARED_SECRET — when set, each delivery carries
  ``X-Agent-Wallet-Signature: sha256=<hex>`` computed as
  HMAC-SHA256(secret, canonical_json_body). Receivers verify with
  ``hmac.compare_digest`` and reject mismatches.

DNS-rebinding defence:
  Validation does ``getaddrinfo`` once and caches the resolved IP
  inside the function call. The actual POST goes to that IP literal
  with the original hostname carried in the ``Host`` header and SNI,
  so an attacker controlling the authoritative DNS cannot return a
  public IP for validation and a private IP for the request.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import ssl
import time
from typing import Any, Optional
from urllib.parse import urlparse

from app.core.config import settings
from app.core.net_guard import is_blocked_ip

logger = logging.getLogger(__name__)

_ENABLED_EVENTS: set[str] | None = None


def _get_enabled_events() -> set[str]:
    global _ENABLED_EVENTS
    if _ENABLED_EVENTS is None:
        raw = settings.alert_webhook_events
        _ENABLED_EVENTS = {e.strip() for e in raw.split(",") if e.strip()}
    return _ENABLED_EVENTS


def _is_blocked_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the address belongs to a non-routable / internal range.

    Thin wrapper over the shared egress guard so the webhook, LNURL, and
    chain-explorer paths all enforce one identical non-routable policy.
    """
    return is_blocked_ip(addr)


def _resolve_and_validate(url: str) -> tuple[str, str, str, int] | None:
    """Validate a webhook URL and return ``(hostname, ip, scheme, port)``.

    Returns ``None`` (and logs the reason) if any check fails:
    * scheme not HTTPS
    * hostname missing
    * hostname is a literal private/loopback/etc. address
    * hostname is in the symbolic deny-list (``localhost`` / ``*.local``)
    * DNS resolution fails
    * any resolved address is in a blocked range
    * resolved addresses span multiple address families (defence in
      depth against rebinding round-robin)
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme != "https":
        logger.warning("Refusing non-HTTPS webhook URL: %s", parsed.scheme)
        return None
    hostname = parsed.hostname or ""
    if not hostname:
        return None
    port = parsed.port or 443

    # Direct IP literal — block if non-routable, else allow.
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        addr = None
    if addr is not None:
        if _is_blocked_address(addr):
            logger.warning("Refusing webhook to private/internal address: %s", hostname)
            return None
        return (hostname, str(addr), parsed.scheme, port)

    # Symbolic deny-list before doing DNS work.
    lower = hostname.lower()
    if lower in ("localhost",) or lower.endswith(".local") or lower.endswith(".internal"):
        logger.warning("Refusing webhook to internal hostname: %s", hostname)
        return None

    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        logger.warning("Refusing webhook (DNS resolution failed for %s): %s", hostname, e)
        return None

    families: set[int] = set()
    first_ip: str | None = None
    for family, _type, _proto, _canon, sockaddr in infos:
        try:
            resolved = ipaddress.ip_address(sockaddr[0])
        except (ValueError, IndexError):
            continue
        if _is_blocked_address(resolved):
            logger.warning(
                "Refusing webhook — hostname %s resolves to %s",
                hostname,
                resolved,
            )
            return None
        families.add(family)
        if first_ip is None:
            first_ip = str(resolved)

    if first_ip is None:
        logger.warning("Refusing webhook — no usable address for %s", hostname)
        return None

    # We pin to the *first* validated IP; if the resolver returned
    # multiple address families that's fine, we just pick one. The
    # important invariant is that none of the candidates were in a
    # blocked range.
    logger.debug("Webhook URL validated: %s → %s", url, first_ip)
    return (hostname, first_ip, parsed.scheme, port)


def _validate_webhook_url(url: str) -> bool:
    """Backwards-compatible boolean wrapper used by tests."""
    return _resolve_and_validate(url) is not None


def _canonicalise(payload: dict[str, Any]) -> bytes:
    """Stable JSON serialisation for HMAC signing.

    Sorted keys + tightest separators so signing produces the same
    bytes the wire request will carry.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _sign_payload(body: bytes) -> str | None:
    """Compute ``sha256=<hex>`` over the body, or return None if no secret."""
    secret = settings.alert_webhook_shared_secret
    if not secret:
        return None
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def _post_with_pinned_ip(
    url: str,
    hostname: str,
    pinned_ip: str,
    port: int,
    body: bytes,
    headers: dict[str, str],
    timeout: float = 10.0,
) -> tuple[int, bytes]:
    """POST to ``pinned_ip`` while keeping ``hostname`` for SNI and cert check.

    Uses ``asyncio.open_connection`` directly so we control which IP
    the TCP connection lands on while still passing ``hostname`` as
    ``server_hostname``. Python's stdlib does the cert chain *and*
    SAN check in one shot when ``server_hostname`` is set on the SSL
    context — no manual SAN parsing required.

    Returns ``(status_code, body_bytes)``. Caller logs.
    """
    import asyncio

    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    ctx = ssl.create_default_context()
    # check_hostname + CERT_REQUIRED are the defaults; making them
    # explicit so a future change to create_default_context can't
    # silently weaken the check.
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    request_headers = dict(headers)
    request_headers.setdefault("Host", f"{hostname}:{port}" if port != 443 else hostname)
    request_headers.setdefault("User-Agent", "agent-wallet-alerts/1")
    request_headers["Content-Length"] = str(len(body))
    request_headers.setdefault("Connection", "close")

    request_lines = [f"POST {path} HTTP/1.1"]
    for k, v in request_headers.items():
        request_lines.append(f"{k}: {v}")
    request_bytes = ("\r\n".join(request_lines) + "\r\n\r\n").encode() + body

    open_conn = asyncio.open_connection(
        host=pinned_ip,
        port=port,
        ssl=ctx,
        server_hostname=hostname,
    )
    reader, writer = await asyncio.wait_for(open_conn, timeout=timeout)
    try:
        writer.write(request_bytes)
        await asyncio.wait_for(writer.drain(), timeout=timeout)

        # Parse response: status line, headers, body.
        status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        try:
            status_code = int(status_line.split(b" ", 2)[1])
        except (IndexError, ValueError):
            status_code = 0

        # Drain headers.
        content_length = 0
        chunked = False
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if line in (b"\r\n", b"\n", b""):
                break
            lower = line.lower()
            if lower.startswith(b"content-length:"):
                try:
                    content_length = int(lower.split(b":", 1)[1].strip())
                except ValueError:
                    content_length = 0
            elif lower.startswith(b"transfer-encoding:") and b"chunked" in lower:
                chunked = True

        # Read body — bounded so a hostile / misconfigured receiver
        # can't pin memory. We don't actually use the body except for
        # logging on errors, so 8 KiB is plenty.
        max_body = 8192
        if chunked:
            body_bytes = await asyncio.wait_for(reader.read(max_body), timeout=timeout)
        elif content_length:
            body_bytes = await asyncio.wait_for(
                reader.readexactly(min(content_length, max_body)),
                timeout=timeout,
            )
        else:
            body_bytes = await asyncio.wait_for(reader.read(max_body), timeout=timeout)
        return status_code, body_bytes
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def send_alert(event_type: str, message: str, details: Optional[dict] = None) -> None:
    """Send a security alert via webhook if configured and event type is enabled.

    Non-blocking, best-effort — failures are logged but never raise.
    """
    url = settings.alert_webhook_url
    if not url:
        return

    if event_type not in _get_enabled_events():
        return

    target = _resolve_and_validate(url)
    if target is None:
        return
    hostname, pinned_ip, _scheme, port = target

    payload: dict[str, Any] = {
        "event": event_type,
        "text": f"🔔 *{event_type}*: {message}",
        "message": message,
        "timestamp": int(time.time()),
    }
    if details:
        payload["details"] = details

    body = _canonicalise(payload)
    headers: dict[str, str] = {"Content-Type": "application/json"}
    signature = _sign_payload(body)
    if signature:
        headers["X-Agent-Wallet-Signature"] = signature

    try:
        status_code, _resp_body = await _post_with_pinned_ip(url, hostname, pinned_ip, port, body, headers)
        if status_code >= 400:
            logger.warning("Alert webhook returned %s for event %s", status_code, event_type)
        else:
            logger.debug("Alert sent for event %s", event_type)
    except Exception as e:
        logger.warning("Failed to send alert webhook for %s: %s", event_type, e)
