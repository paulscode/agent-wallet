# SPDX-License-Identifier: MIT
"""
Shared utility functions used across the application.
"""

import base64
import logging
import re

_logger = logging.getLogger(__name__)

_HEX64_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def sanitize_upstream_error(error: str, service: str = "upstream") -> str:
    """Return a generic client-safe error, logging the full detail server-side."""
    _logger.error("Upstream %s error: %s", service, error)
    return f"{service} service error — see server logs for details."


def lnd_broadcast_outcome_unknown(error: str | None) -> bool:
    """True when an LND on-chain error leaves the broadcast state unknown.

    A timeout, dropped connection, generic request failure, or 5xx ends the
    HTTP call without LND confirming whether the transaction was broadcast —
    a retry could select different inputs and pay twice. A circuit-breaker
    rejection means the request never reached LND, and a 4xx is a definitive
    pre-broadcast reject; both are safe to retry immediately. Shared by the
    on-chain send and channel-open paths so a money-moving retry on an unknown
    outcome is held rather than re-broadcast.
    """
    if not error:
        return False
    if error.startswith("LND temporarily unavailable"):
        return False  # breaker open — the request never left the process
    if error.startswith("LND error ("):
        # ``LND error (5xx): …`` leaves the broadcast state unknown;
        # a 4xx is a definitive reject with no broadcast.
        return "(5" in error[:14]
    return error.startswith(("Connection failed", "Request failed"))


def force_remote_dns_socks(proxy: str | None) -> str:
    """Upgrade a ``socks5://`` proxy URL to ``socks5h://``.

    The ``h`` variant resolves the destination hostname at the proxy (Tor),
    never on the local host — so a hostname can never leak to a local resolver.
    The pinned httpx/socksio stack already forwards the hostname for both
    schemes, but pinning ``socks5h`` makes that guarantee explicit rather than
    riding on undocumented client behaviour. No-op for already-``socks5h`` or
    non-SOCKS values (including the empty string).
    """
    p = (proxy or "").strip()
    if p.lower().startswith("socks5://"):
        return "socks5h://" + p[len("socks5://") :]
    return p


def b64_to_hex(value: str) -> str:
    """Decode a base64-encoded string to its hex representation.

    Falls back to returning the original value if decoding fails
    (some LND responses may already be in hex format).
    """
    if not value:
        return ""
    try:
        return base64.b64decode(value).hex()
    except Exception:
        return value
