# SPDX-License-Identifier: MIT
"""Unit tests for :mod:`app.core.validation` address checks.

Drives :func:`validate_bitcoin_address` and its Bech32/Bech32m and
Base58Check helpers through their rejection branches: format misses,
checksum failures, mixed-case Bech32, malformed separators, and the
per-network prefix gates. The companion ``test_address_validation``
suite covers the request-model wrapper with valid vectors; this file
pins the lower-level rejection paths that a typo'd address must hit
before funds leave the wallet.

Each test sets ``settings.bitcoin_network`` explicitly so the network
gate under test is unambiguous and the suite is order-independent
under ``pytest -n auto``.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.core import validation
from app.core.validation import validate_bitcoin_address

# Known-good vectors (BIP-173/-350 test data) used to confirm the
# *accept* side of each network gate before probing rejections.
VALID_MAINNET_BECH32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
VALID_MAINNET_TAPROOT = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"
VALID_MAINNET_P2PKH = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
VALID_MAINNET_P2SH = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
VALID_TESTNET_BECH32 = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
VALID_TESTNET_P2PKH = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
VALID_REGTEST_BECH32 = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"


def _network(name: str):
    return patch.object(validation.settings, "bitcoin_network", name)


# ── mainnet network gate ───────────────────────────────────────────


def test_mainnet_accepts_valid_bech32() -> None:
    """A correctly-checksummed mainnet segwit address is returned as-is."""
    with _network("bitcoin"):
        assert validate_bitcoin_address(VALID_MAINNET_BECH32) == VALID_MAINNET_BECH32


def test_mainnet_accepts_valid_taproot() -> None:
    """A Bech32m (witness v1) mainnet address passes the v1+ encoding gate."""
    with _network("bitcoin"):
        assert validate_bitcoin_address(VALID_MAINNET_TAPROOT) == VALID_MAINNET_TAPROOT


def test_mainnet_accepts_base58check_p2pkh_and_p2sh() -> None:
    """Valid Base58Check P2PKH/P2SH mainnet addresses are accepted."""
    with _network("bitcoin"):
        assert validate_bitcoin_address(VALID_MAINNET_P2PKH) == VALID_MAINNET_P2PKH
        assert validate_bitcoin_address(VALID_MAINNET_P2SH) == VALID_MAINNET_P2SH


def test_mainnet_rejects_bech32_with_bad_checksum() -> None:
    """A mainnet bech32 that matches the format regex but fails the
    Bech32 checksum is rejected, not silently accepted."""
    bad = VALID_MAINNET_BECH32[:-1] + ("q" if VALID_MAINNET_BECH32[-1] != "q" else "p")
    with _network("bitcoin"), pytest.raises(ValueError, match="bad checksum"):
        validate_bitcoin_address(bad)


def test_mainnet_rejects_base58check_with_bad_checksum() -> None:
    """A mainnet P2PKH whose Base58Check trailer is corrupted is rejected."""
    bad = VALID_MAINNET_P2PKH[:-1] + ("a" if VALID_MAINNET_P2PKH[-1] != "a" else "b")
    with _network("bitcoin"), pytest.raises(ValueError, match="bad checksum"):
        validate_bitcoin_address(bad)


def test_mainnet_rejects_wrong_prefix() -> None:
    """An address that doesn't start with bc1/1/3 fails the mainnet gate."""
    with _network("bitcoin"), pytest.raises(ValueError, match="must start with"):
        validate_bitcoin_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")


# ── testnet / signet gate ──────────────────────────────────────────


def test_testnet_accepts_valid_bech32_and_base58() -> None:
    with _network("testnet"):
        assert validate_bitcoin_address(VALID_TESTNET_BECH32) == VALID_TESTNET_BECH32
        assert validate_bitcoin_address(VALID_TESTNET_P2PKH) == VALID_TESTNET_P2PKH


def test_signet_uses_testnet_gate() -> None:
    """``signet`` shares the testnet prefix/checksum gate."""
    with _network("signet"):
        assert validate_bitcoin_address(VALID_TESTNET_BECH32) == VALID_TESTNET_BECH32


def test_testnet_rejects_bech32_bad_checksum() -> None:
    bad = VALID_TESTNET_BECH32[:-1] + ("q" if VALID_TESTNET_BECH32[-1] != "q" else "p")
    with _network("testnet"), pytest.raises(ValueError, match="bad checksum"):
        validate_bitcoin_address(bad)


def test_testnet_rejects_base58_bad_checksum() -> None:
    bad = VALID_TESTNET_P2PKH[:-1] + ("a" if VALID_TESTNET_P2PKH[-1] != "a" else "b")
    with _network("testnet"), pytest.raises(ValueError, match="bad checksum"):
        validate_bitcoin_address(bad)


def test_testnet_rejects_wrong_prefix() -> None:
    with _network("testnet"), pytest.raises(ValueError, match="must start with"):
        validate_bitcoin_address(VALID_MAINNET_BECH32)


# ── regtest gate ───────────────────────────────────────────────────


def test_regtest_accepts_valid_bech32() -> None:
    with _network("regtest"):
        assert validate_bitcoin_address(VALID_REGTEST_BECH32) == VALID_REGTEST_BECH32


def test_regtest_rejects_bech32_bad_checksum() -> None:
    bad = VALID_REGTEST_BECH32[:-1] + ("q" if VALID_REGTEST_BECH32[-1] != "q" else "p")
    with _network("regtest"), pytest.raises(ValueError, match="bad checksum"):
        validate_bitcoin_address(bad)


def test_regtest_rejects_base58_bad_checksum() -> None:
    bad = VALID_TESTNET_P2PKH[:-1] + ("a" if VALID_TESTNET_P2PKH[-1] != "a" else "b")
    with _network("regtest"), pytest.raises(ValueError, match="bad checksum"):
        validate_bitcoin_address(bad)


def test_regtest_rejects_wrong_prefix() -> None:
    with _network("regtest"), pytest.raises(ValueError, match="must start with"):
        validate_bitcoin_address(VALID_MAINNET_BECH32)


def test_unknown_network_accepts_any() -> None:
    """An unrecognised network short-circuits to pass-through so a
    Liquid/exotic address isn't rejected by a Bitcoin-only gate."""
    with _network("liquidv1"):
        assert validate_bitcoin_address(VALID_MAINNET_BECH32) == VALID_MAINNET_BECH32


# ── Bech32 decoder rejection branches ──────────────────────────────


def test_bech32_decode_rejects_mixed_case() -> None:
    """BIP-173 forbids mixed-case bech32; the decoder returns ``None``."""
    mixed = "Bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert validation._bech32_decode(mixed) is None


def test_bech32_decode_rejects_missing_separator() -> None:
    """A string with no usable ``1`` separator position decodes to None."""
    assert validation._bech32_decode("bcqqqqqqqqqqqqqqqq") is None


def test_bech32_decode_rejects_out_of_charset_char() -> None:
    """A data character outside the Bech32 charset (e.g. 'b') fails."""
    # 'b' is not in the Bech32 charset.
    assert validation._bech32_decode("bc1bbbbbbbbbbbbbbbb") is None


def test_bech32_decode_rejects_overlong_address() -> None:
    """Bech32 strings longer than 90 chars are rejected outright."""
    assert validation._bech32_decode("bc1" + "q" * 100) is None


def test_segwit_rejects_hrp_mismatch() -> None:
    """A correctly-checksummed testnet address fails when validated
    against the mainnet HRP."""
    assert validation._validate_segwit_address("bc", VALID_TESTNET_BECH32) is False


def test_segwit_rejects_undecodable_address() -> None:
    """A garbage address that fails decode yields ``False`` from the
    segwit validator (the ``decoded is None`` guard)."""
    assert validation._validate_segwit_address("bc", "not-an-address") is False


# ── Base58 decoder rejection branches ──────────────────────────────


def test_b58decode_rejects_non_alphabet_char() -> None:
    """A character outside the Base58 alphabet (e.g. '0') returns None."""
    assert validation._b58decode("0OIl") is None


def test_b58decode_empty_returns_none() -> None:
    assert validation._b58decode("") is None


def test_base58check_rejects_wrong_length() -> None:
    """A Base58 string that decodes to other than 25 bytes is rejected."""
    # '1' decodes to a single zero byte — far short of 25.
    assert validation._validate_base58check("1") is False


def test_base58check_rejects_non_base58_input() -> None:
    """Non-alphabet input makes ``_b58decode`` return None, which the
    Base58Check validator treats as invalid."""
    assert validation._validate_base58check("0OIl0OIl") is False


def test_base58check_swallows_decode_exception() -> None:
    """An input that makes the inner decode raise is caught and reported as
    invalid (the bare ``except`` guard) rather than propagating."""
    with patch.object(validation, "_b58decode", side_effect=ValueError("boom")):
        assert validation._validate_base58check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") is False


def test_regtest_rejects_base58_wrong_prefix() -> None:
    """On regtest, a mainnet '1...' Base58 address fails the prefix gate
    (regtest accepts m/n/2, not 1/3)."""
    with _network("regtest"), pytest.raises(ValueError, match="must start with"):
        validate_bitcoin_address(VALID_MAINNET_P2PKH)


# ── _convertbits rejection branches ────────────────────────────────


def test_convertbits_rejects_out_of_range_value() -> None:
    """A value wider than ``frombits`` (here 5) yields ``None``."""
    assert validation._convertbits([32], 5, 8, False) is None


def test_convertbits_rejects_negative_value() -> None:
    assert validation._convertbits([-1], 5, 8, True) is None


def test_convertbits_pads_when_requested() -> None:
    """With ``pad=True`` the trailing partial group is emitted."""
    out = validation._convertbits([1], 5, 8, True)
    assert out is not None and len(out) == 1


def test_convertbits_rejects_invalid_padding_when_not_padding() -> None:
    """With ``pad=False`` leftover non-zero bits make the conversion invalid."""
    # 5-bit value 1 leaves 5 leftover bits with a set bit → invalid.
    assert validation._convertbits([1], 5, 8, False) is None


# ── segwit witness-program validation branches ─────────────────────


def _segwit_addr(hrp: str, witver: int, program: list[int]) -> str:
    """Build a Bech32/Bech32m segwit address from a witness version and
    program bytes so the witness-length/version branches can be driven
    directly. Mirrors the BIP-173/-350 encode path."""
    data = [witver] + (validation._convertbits(program, 8, 5, True) or [])
    const = validation._BECH32_CONST if witver == 0 else validation._BECH32M_CONST
    values = validation._bech32_hrp_expand(hrp) + data
    polymod = validation._bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(validation._BECH32_CHARSET[d] for d in data + checksum)


def test_segwit_rejects_program_too_long() -> None:
    """A witness program longer than 40 bytes is rejected."""
    addr = _segwit_addr("bc", 1, list(range(41)))
    assert validation._validate_segwit_address("bc", addr) is False


def test_segwit_rejects_program_too_short() -> None:
    """A witness program shorter than 2 bytes is rejected."""
    addr = _segwit_addr("bc", 1, [0])
    assert validation._validate_segwit_address("bc", addr) is False


def test_segwit_rejects_v0_with_wrong_program_length() -> None:
    """Witness v0 must be exactly 20 or 32 bytes; 22 bytes is rejected."""
    addr = _segwit_addr("bc", 0, list(range(22)))
    assert validation._validate_segwit_address("bc", addr) is False


def test_segwit_rejects_v0_encoded_as_bech32m() -> None:
    """Witness v0 encoded with the Bech32m constant (instead of Bech32) is
    rejected — v0 must use plain Bech32."""
    # Build a v0 program but stamp the Bech32m checksum.
    hrp = "bc"
    program = list(range(20))
    data = [0] + (validation._convertbits(program, 8, 5, True) or [])
    values = validation._bech32_hrp_expand(hrp) + data
    polymod = validation._bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ validation._BECH32M_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    addr = hrp + "1" + "".join(validation._BECH32_CHARSET[d] for d in data + checksum)
    assert validation._validate_segwit_address("bc", addr) is False


def test_segwit_rejects_v1_encoded_as_bech32() -> None:
    """Witness v1+ must use Bech32m; a v1 program stamped with the plain
    Bech32 constant is rejected."""
    hrp = "bc"
    program = list(range(32))
    data = [1] + (validation._convertbits(program, 8, 5, True) or [])
    values = validation._bech32_hrp_expand(hrp) + data
    polymod = validation._bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ validation._BECH32_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    addr = hrp + "1" + "".join(validation._BECH32_CHARSET[d] for d in data + checksum)
    assert validation._validate_segwit_address("bc", addr) is False


def test_segwit_accepts_valid_v0_built_program() -> None:
    """The encoder helper round-trips: a freshly-built valid v0 program
    passes the segwit validator (guards the rejection tests above against
    a broken builder)."""
    addr = _segwit_addr("bc", 0, list(range(20)))
    assert validation._validate_segwit_address("bc", addr) is True


def test_regtest_accepts_valid_base58() -> None:
    """A valid m/n-prefixed Base58 address is accepted on regtest."""
    with _network("regtest"):
        assert validate_bitcoin_address(VALID_TESTNET_P2PKH) == VALID_TESTNET_P2PKH


def test_segwit_rejects_program_with_invalid_bit_packing() -> None:
    """When the witness data after the version byte does not convert back to
    whole bytes (5→8 with bad padding), the segwit validator rejects it."""
    # data[0]=witver(1); data[1:] packs to leftover non-zero bits → None.
    hrp = "bc"
    data = [1, 1]  # one 5-bit data symbol with a set low bit → invalid pad
    values = validation._bech32_hrp_expand(hrp) + data
    polymod = validation._bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ validation._BECH32M_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    addr = hrp + "1" + "".join(validation._BECH32_CHARSET[d] for d in data + checksum)
    assert validation._validate_segwit_address("bc", addr) is False


def test_segwit_rejects_witness_version_above_16() -> None:
    """A witness version greater than 16 is rejected even with a valid
    Bech32m checksum."""
    hrp = "bc"
    program = list(range(2))
    data = [17] + (validation._convertbits(program, 8, 5, True) or [])
    values = validation._bech32_hrp_expand(hrp) + data
    polymod = validation._bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ validation._BECH32M_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    addr = hrp + "1" + "".join(validation._BECH32_CHARSET[d] for d in data + checksum)
    assert validation._validate_segwit_address("bc", addr) is False


def test_segwit_rejects_empty_data() -> None:
    """A decoded payload with no witness-version byte is rejected (the
    ``len(data) < 1`` guard)."""
    # An hrp followed only by the 6-char checksum group decodes to empty data.
    hrp = "bc"
    values = validation._bech32_hrp_expand(hrp)
    polymod = validation._bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ validation._BECH32_CONST
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    addr = hrp + "1" + "".join(validation._BECH32_CHARSET[d] for d in checksum)
    assert validation._validate_segwit_address("bc", addr) is False
