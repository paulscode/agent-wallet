# SPDX-License-Identifier: MIT
"""
Shared validation utilities for Bitcoin address formats.

Performs both format (regex) and checksum (Bech32/Bech32m/Base58Check)
validation to catch typos before funds are sent to invalid addresses.
"""

import hashlib
import re

from app.core.config import settings

# ── On-chain fee-rate bounds ────────────────────────────────────────
#
# Upper bound on any caller-supplied on-chain fee rate (sat/vB). Without a
# ceiling, a caller could pair a tiny amount (which passes the spend cap) with
# an enormous ``sat_per_vbyte`` and drain wallet UTXOs as miner fee that no cap
# accounts for. 1000 sat/vB matches the cold-storage bump-fee ceiling and is
# already far above any realistic mainnet fee market. Shared across every
# on-chain send path (send-onchain, channel open/close, consolidate) so the
# bound is enforced consistently.
MAX_SAT_PER_VBYTE = 1000

# Representative virtual size (vB) used to translate a caller-supplied fee rate
# into a sats fee budget charged against the cumulative spend window. A typical
# 2-in/2-out segwit send is ~150–250 vB; 250 keeps the estimate realistic. This
# is a cap-accounting safeguard, not a fee predictor.
ONCHAIN_TX_VBYTE_ESTIMATE = 250


# ── Bech32 / Bech32m checksum validation (BIP-173, BIP-350) ─────────

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


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


def _bech32_verify_checksum(hrp: str, data: list[int]) -> int | None:
    """Returns the Bech32 encoding constant if checksum is valid, else None."""
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if polymod == _BECH32_CONST:
        return _BECH32_CONST
    if polymod == _BECH32M_CONST:
        return _BECH32M_CONST
    return None


def _bech32_decode(addr: str) -> tuple[str, list[int], int] | None:
    """Decode a Bech32/Bech32m address. Returns (hrp, data, encoding) or None."""
    if addr.lower() != addr and addr.upper() != addr:
        return None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return None
    hrp = addr[:pos]
    data = []
    for c in addr[pos + 1 :]:
        idx = _BECH32_CHARSET.find(c)
        if idx == -1:
            return None
        data.append(idx)
    encoding = _bech32_verify_checksum(hrp, data)
    if encoding is None:
        return None
    return hrp, data[:-6], encoding


def _convertbits(data: list[int], frombits: int, tobits: int, pad: bool = True) -> list[int] | None:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def _validate_segwit_address(hrp: str, addr: str) -> bool:
    """Validate a segwit (Bech32/Bech32m) address with checksum."""
    decoded = _bech32_decode(addr)
    if decoded is None:
        return False
    dec_hrp, data, encoding = decoded
    if dec_hrp != hrp:
        return False
    if len(data) < 1:
        return False
    witness_version = data[0]
    witness_program = _convertbits(data[1:], 5, 8, False)
    if witness_program is None:
        return False
    prog_len = len(witness_program)
    if prog_len < 2 or prog_len > 40:
        return False
    if witness_version == 0 and prog_len != 20 and prog_len != 32:
        return False
    if witness_version == 0 and encoding != _BECH32_CONST:
        return False
    if witness_version >= 1 and encoding != _BECH32M_CONST:
        return False
    if witness_version > 16:
        return False
    return True


# ── Base58Check checksum validation ──────────────────────────────────

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58decode(v: str) -> bytes | None:
    """Decode a Base58-encoded string to bytes.

    Each leading ``1`` maps to one leading ``0x00`` byte; the remainder is a
    base-58 big-endian integer rendered to its minimal byte length. Returns
    ``None`` on any non-alphabet character.
    """
    if not v:
        return None
    v_bytes = v.encode("ascii")
    acc = 0
    for c in v_bytes:
        idx = _B58_ALPHABET.find(c)
        if idx == -1:
            return None
        acc = acc * 58 + idx
    # Count leading '1's → that many leading zero bytes.
    pad = 0
    for c in v_bytes:
        if c == _B58_ALPHABET[0]:
            pad += 1
        else:
            break
    body = acc.to_bytes((acc.bit_length() + 7) // 8, "big") if acc else b""
    return b"\x00" * pad + body


def _validate_base58check(addr: str) -> bool:
    """Validate a Base58Check address (P2PKH / P2SH)."""
    try:
        raw = _b58decode(addr)
        if raw is None or len(raw) != 25:
            return False
        payload, checksum = raw[:-4], raw[-4:]
        expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return checksum == expected
    except Exception:
        return False


# ── Public API ───────────────────────────────────────────────────────


def validate_bitcoin_address(address: str) -> str:
    """Validate Bitcoin address format AND checksum based on configured network.

    Returns the address if valid, raises ValueError otherwise.
    """
    network = settings.bitcoin_network

    if network == "bitcoin":
        # Mainnet segwit: bc1...
        if re.match(r"^bc1[a-zA-HJ-NP-Z0-9]{25,87}$", address):
            if _validate_segwit_address("bc", address):
                return address
            raise ValueError("Invalid Bitcoin mainnet address (bad checksum)")
        # Mainnet P2PKH (1...) / P2SH (3...)
        if re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", address):
            if _validate_base58check(address):
                return address
            raise ValueError("Invalid Bitcoin mainnet address (bad checksum)")
        raise ValueError("Invalid Bitcoin mainnet address (must start with bc1, 1, or 3)")

    elif network in ("testnet", "signet"):
        if re.match(r"^tb1[a-zA-HJ-NP-Z0-9]{25,87}$", address):
            if _validate_segwit_address("tb", address):
                return address
            raise ValueError("Invalid testnet/signet address (bad checksum)")
        if re.match(r"^[mn2][a-km-zA-HJ-NP-Z1-9]{25,34}$", address):
            if _validate_base58check(address):
                return address
            raise ValueError("Invalid testnet/signet address (bad checksum)")
        raise ValueError("Invalid testnet/signet address (must start with tb1, m, n, or 2)")

    elif network == "regtest":
        if re.match(r"^bcrt1[a-zA-HJ-NP-Z0-9]{25,87}$", address):
            if _validate_segwit_address("bcrt", address):
                return address
            raise ValueError("Invalid regtest address (bad checksum)")
        if re.match(r"^[mn2][a-km-zA-HJ-NP-Z1-9]{25,34}$", address):
            if _validate_base58check(address):
                return address
            raise ValueError("Invalid regtest address (bad checksum)")
        raise ValueError("Invalid regtest address (must start with bcrt1, m, n, or 2)")

    # Unknown network — accept any plausible format
    return address
