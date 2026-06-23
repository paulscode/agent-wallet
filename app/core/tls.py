# SPDX-License-Identifier: MIT
"""TLS helpers shared across chain/node clients.

Centralises the "operator-supplied PEM" pattern used by the LND, electrum and
mempool clients so all three resolve trust roots the same way and a future
auditor only has to read one routine.

The supported input formats for an operator PEM (in order of precedence):
1. Filesystem path to a PEM file.
2. Base64-encoded PEM blob (single line in env vars).
3. Raw PEM text containing ``-----BEGIN CERTIFICATE-----``.
"""

from __future__ import annotations

import base64
import logging
import os
import ssl
from typing import Optional

logger = logging.getLogger(__name__)


def _decode_pem(value: str) -> Optional[str]:
    """Return PEM text from ``value`` (path, base64 PEM or raw PEM), or None."""
    if not isinstance(value, str) or not value:
        return None
    if os.path.isfile(value):
        try:
            with open(value, "r", encoding="utf-8") as f:
                return f.read()
        except OSError as exc:
            logger.warning("failed to read CA cert from %s: %s", value, exc)
            return None
    if "BEGIN CERTIFICATE" in value:
        return value
    try:
        decoded = base64.b64decode(value, validate=False).decode("utf-8")
    except Exception:
        return None
    if "BEGIN CERTIFICATE" in decoded:
        return decoded
    return None


def load_pinned_ca_context(value: str) -> Optional[ssl.SSLContext]:
    """Build an SSLContext that trusts *only* the operator-supplied PEM.

    Returns ``None`` when ``value`` is empty or can't be parsed as a PEM.
    Callers should fall back to ``verify=True/False`` per their config in that
    case; an unparseable PEM must never silently weaken to ``verify=False``.
    """
    pem = _decode_pem(value)
    if pem is None:
        if isinstance(value, str) and value:
            logger.warning(
                "ignoring CA cert input: not a valid path / base64 PEM / raw PEM",
            )
        return None
    ctx = ssl.create_default_context()
    try:
        ctx.load_verify_locations(cadata=pem)
    except ssl.SSLError as exc:
        logger.warning("failed to load operator CA cert: %s", exc)
        return None
    return ctx


__all__ = ["load_pinned_ca_context"]
