# SPDX-License-Identifier: MIT
"""
Render and parse the export formats supported by the Sign / Verify
Message UI.

Three formats are emittable for an address-signed message:

- ``json``      — the project's canonical machine-readable shape
- ``sparrow``   — three-line plaintext (address, message, signature)
                  matching the format Sparrow / Bitcoin Core expect
                  (`bitcoin-cli verifymessage`).
- ``ascii``     — RFC2440-style ASCII-armored block.

For node-identity signatures only ``json`` and ``signature`` (raw
zbase32) are supported — the address-bound formats don't apply.

The parser auto-detects which of those formats a pasted blob is in and
returns a normalised ``ParsedSignedMessage`` that the UI can use to
populate its Verify form.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Final, Literal, Optional

AddressFormat = Literal["json", "sparrow", "ascii"]
NodeFormat = Literal["json", "signature"]

_ASCII_BEGIN: Final = "-----BEGIN BITCOIN SIGNED MESSAGE-----"
_ASCII_SIG_BEGIN: Final = "-----BEGIN BITCOIN SIGNATURE-----"
_ASCII_SIG_END: Final = "-----END BITCOIN SIGNATURE-----"


@dataclass(frozen=True)
class ParsedSignedMessage:
    """A parsed signed-message blob, ready to verify."""

    identity: Literal["address", "node"]
    address: Optional[str]
    message: str
    signature: str


# ─── Renderers ──────────────────────────────────────────────────────


def render_address_signed(
    *,
    address: str,
    message: str,
    signature: str,
    sig_format: str,
    fmt: AddressFormat,
) -> str:
    """Render an address-signed message in the requested export format."""
    if fmt == "json":
        return json.dumps(
            {
                "address": address,
                "message": message,
                "signature": signature,
                "format": sig_format,
            },
            indent=2,
            ensure_ascii=False,
        )
    if fmt == "sparrow":
        # Three lines: address, message, signature. The Bitcoin Core /
        # Sparrow convention is that the message is a single logical
        # block; preserve embedded newlines verbatim.
        return f"{address}\n{message}\n{signature}\n"
    if fmt == "ascii":
        return (
            f"{_ASCII_BEGIN}\n"
            f"{message}\n"
            f"{_ASCII_SIG_BEGIN}\n"
            f"Address: {address}\n"
            f"Format: {sig_format}\n"
            f"\n"
            f"{signature}\n"
            f"{_ASCII_SIG_END}\n"
        )
    raise ValueError(f"unknown address export format: {fmt!r}")


def render_node_signed(
    *,
    message: str,
    signature: str,
    node_pubkey: str,
    fmt: NodeFormat,
) -> str:
    """Render a node-identity signed message."""
    if fmt == "json":
        return json.dumps(
            {
                "node_pubkey": node_pubkey,
                "message": message,
                "signature": signature,
            },
            indent=2,
            ensure_ascii=False,
        )
    if fmt == "signature":
        return f"{signature}\n"
    raise ValueError(f"unknown node export format: {fmt!r}")


# ─── Parser ──────────────────────────────────────────────────────────


_SIG_LINE_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{40,200}$")


def parse_signed_message(blob: str) -> ParsedSignedMessage:
    """Auto-detect format and parse a pasted signed-message blob.

    Tries, in order: JSON object, ASCII-armored block, three-line
    Sparrow form. Raises ``ValueError`` if none match.
    """
    if blob is None:
        raise ValueError("empty signed-message blob")
    text = blob.strip()
    if not text:
        raise ValueError("empty signed-message blob")

    # ── 1. JSON object ─────────────────────────────────────────────
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"invalid JSON: {e}") from e
        if not isinstance(obj, dict):
            raise ValueError("expected a JSON object at the top level")
        message = obj.get("message")
        signature = obj.get("signature")
        if not isinstance(message, str) or not isinstance(signature, str):
            raise ValueError("JSON must include string 'message' and 'signature'")
        address = obj.get("address")
        node_pubkey = obj.get("node_pubkey")
        if isinstance(address, str) and address:
            return ParsedSignedMessage(
                identity="address",
                address=address,
                message=message,
                signature=signature,
            )
        if isinstance(node_pubkey, str) and node_pubkey:
            return ParsedSignedMessage(
                identity="node",
                address=None,
                message=message,
                signature=signature,
            )
        # Bare {message, signature} → assume node identity
        return ParsedSignedMessage(
            identity="node",
            address=None,
            message=message,
            signature=signature,
        )

    # ── 2. ASCII armor ─────────────────────────────────────────────
    if _ASCII_BEGIN in text and _ASCII_SIG_BEGIN in text and _ASCII_SIG_END in text:
        try:
            after_begin = text.split(_ASCII_BEGIN, 1)[1]
            message_part, after_msg = after_begin.split(_ASCII_SIG_BEGIN, 1)
            sig_block, _ = after_msg.split(_ASCII_SIG_END, 1)
        except ValueError as e:
            raise ValueError(f"malformed ASCII-armored block: {e}") from e
        message = message_part.strip("\n")
        # Strip a trailing single newline that we add when rendering.
        if message.endswith("\n"):
            message = message[:-1]
        # Header lines (Address:, Format:) precede a blank line, then sig.
        sig_lines = []
        in_sig = False
        seen_header = False
        armor_address: Optional[str] = None
        for line in sig_block.splitlines():
            stripped = line.strip()
            if not in_sig:
                if not stripped:
                    # A blank line before any header is just leading
                    # whitespace from the rendered \n; only treat the
                    # blank as the header/sig separator once we've
                    # actually parsed a header line.
                    if seen_header:
                        in_sig = True
                    continue
                if stripped.lower().startswith("address:"):
                    armor_address = stripped.split(":", 1)[1].strip()
                    seen_header = True
                    continue
                if stripped.lower().startswith("format:"):
                    seen_header = True
                    continue
                # Non-header non-blank line before separator → assume
                # this block has no headers and we're already in the
                # signature.
                in_sig = True
                sig_lines.append(stripped)
                continue
            if stripped:
                sig_lines.append(stripped)
        signature = "".join(sig_lines)
        if not signature:
            raise ValueError("ASCII-armored block is missing a signature")
        if armor_address:
            return ParsedSignedMessage(
                identity="address",
                address=armor_address,
                message=message,
                signature=signature,
            )
        return ParsedSignedMessage(
            identity="node",
            address=None,
            message=message,
            signature=signature,
        )

    # ── 3. Sparrow / Bitcoin Core 3-line form ──────────────────────
    # Heuristic: at least three lines; first looks like an address; last
    # looks like a signature; middle lines (1..n-2) are the message.
    lines = text.splitlines()
    if len(lines) >= 3:
        addr_candidate = lines[0].strip()
        sig_candidate = lines[-1].strip()
        if _looks_like_address(addr_candidate) and _SIG_LINE_RE.match(sig_candidate):
            message = "\n".join(lines[1:-1])
            return ParsedSignedMessage(
                identity="address",
                address=addr_candidate,
                message=message,
                signature=sig_candidate,
            )

    raise ValueError(
        "could not detect a supported signed-message format (expected JSON, ASCII-armored, or 3-line Sparrow form)"
    )


def _looks_like_address(s: str) -> bool:
    """Cheap shape check — full validation happens at the API boundary."""
    if not s or len(s) < 14 or len(s) > 100:
        return False
    if s.lower().startswith(("bc1", "tb1", "bcrt1")):
        return True
    return bool(s and s[0] in ("1", "3", "m", "n", "2"))
