# SPDX-License-Identifier: MIT
"""
Validation helpers for the Sign / Verify Message feature.

Keeps message and signature validation in one place so it can be reused
between the public API (`app/api/sign.py`) and the dashboard API
(`app/dashboard/api.py`).
"""

import hashlib
import re
from typing import Final

from app.core.config import settings

# Allowed control bytes inside a message (everything else is rejected).
_ALLOWED_CONTROL: Final[frozenset[int]] = frozenset((0x09, 0x0A, 0x0D))  # \t \n \r

# Base64 / zbase32 / ASCII-armor characters all live in this superset.
_SIG_ALPHABET_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9+/=_\-]+$")


def normalise_message(message: str) -> str:
    """Strip BOM and validate the message bytes for signing.

    Raises `ValueError` for empty messages, messages exceeding
    `SIGN_MESSAGE_MAX_CHARS`, or messages containing control bytes
    other than tab / newline / carriage-return. Does **not** otherwise
    mutate the message — third-party verifiers are byte-sensitive.
    """
    if message is None:
        raise ValueError("message must be provided")
    # Strip a single leading BOM if present
    if message.startswith("\ufeff"):
        message = message.lstrip("\ufeff")
    if not message:
        raise ValueError("message must not be empty")
    max_chars = settings.sign_message_max_chars
    if len(message) > max_chars:
        raise ValueError(f"message exceeds maximum length ({max_chars} characters)")
    for ch in message:
        cp = ord(ch)
        if cp < 0x20 and cp not in _ALLOWED_CONTROL:
            raise ValueError(f"message contains disallowed control byte (codepoint {cp:#04x})")
        if cp == 0x7F:
            raise ValueError("message contains DEL control byte (0x7f)")
    return message


def validate_signature(signature: str, *, max_len: int = 256) -> str:
    """Lightweight signature shape check (alphabet + length).

    The cryptographic check happens at LND. We only reject obvious junk
    here so we don't waste an upstream round-trip on, e.g., a pasted
    HTML fragment.
    """
    if not signature:
        raise ValueError("signature must not be empty")
    sig = signature.strip()
    if len(sig) > max_len:
        raise ValueError(f"signature exceeds maximum length ({max_len} characters)")
    if not _SIG_ALPHABET_RE.match(sig):
        raise ValueError("signature contains characters outside the expected alphabet")
    return sig


def message_sha256_hex(message: str) -> str:
    """Stable SHA-256 hex digest of the message bytes (UTF-8)."""
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def audit_message_details(message: str) -> dict[str, str | int]:
    """Build a `details` dict for `log_action`/`log_dashboard_action`.

    Always includes `message_sha256` and `message_length`. Includes the
    raw message **only** when `SIGN_AUDIT_RECORD_MESSAGE=true`.
    """
    details: dict[str, str | int] = {
        "message_sha256": message_sha256_hex(message),
        "message_length": len(message),
    }
    if settings.sign_audit_record_message:
        details["message"] = message
    return details
