# SPDX-License-Identifier: MIT
"""Tests for the pure-Python BOLT11 payment_hash extractor.

The wallet uses LND's ``/v1/payreq/{invoice}`` endpoint for normal
invoice decoding, but recovery paths need the payment_hash precisely
when LND is unreachable (Tor circuit flap, container restart). This
module gives them a no-dependency way to extract it.

The reference case (2026-05-21 manual recovery) is pinned below so a
future refactor that drops the extractor or changes its output shape
fails this test before the next outage.
"""

from __future__ import annotations

from app.core.bolt11 import payment_hash_from_bolt11

# Real invoice from the 2026-05-21 incident — the one that hung as
# IN_FLIGHT during the Tor flap and that we recovered by decoding the
# payment_hash from this string alone (no LND needed).
_INCIDENT_INVOICE = (
    "lnbc1019200n1p4q72m5pp5zh8f3dksgym27cgxjav2fx4zgljlvtd8r95g5lfj7nke2t08y5d"
    "sdql2djkuepqw3hjqsj5gvsxzerywfjhxuccqzylxqyp2xqsp58cj6lrx0qdgd8fwf4552gmj"
    "9wrvxdwd0jd54krq0lttxlxempg8q9qxpqysgqmf3leftwxdyu77fswnuktm5z4px3esh2kxq"
    "v2j8255k32p9r5tvrznud0acqf53pwpmgdrq8vlufeydv9gnd8v27e9exze0m0gtrpyspr8j5xh"
)
_INCIDENT_PAYMENT_HASH = "15ce98b6d04136af61069758a49aa247e5f62da719688a7d32f4ed952de7251b"


def test_extracts_payment_hash_from_real_incident_invoice() -> None:
    """The 2026-05-21 recovery used this exact decoder against this
    exact invoice. Pin it so a regression here is loud."""
    assert payment_hash_from_bolt11(_INCIDENT_INVOICE) == _INCIDENT_PAYMENT_HASH


def test_case_insensitive() -> None:
    """BOLT11 invoices are lowercase by convention but the decoder
    must accept mixed-case in case a caller has uppercased it."""
    upper = _INCIDENT_INVOICE.upper()
    assert payment_hash_from_bolt11(upper) == _INCIDENT_PAYMENT_HASH


def test_returns_none_on_empty_string() -> None:
    assert payment_hash_from_bolt11("") is None


def test_returns_none_on_non_string() -> None:
    # Recovery paths should never raise. Pass through obvious junk.
    assert payment_hash_from_bolt11(None) is None  # type: ignore[arg-type]
    assert payment_hash_from_bolt11(12345) is None  # type: ignore[arg-type]


def test_returns_none_on_invoice_without_separator() -> None:
    assert payment_hash_from_bolt11("lnbcnoseparator") is None


def test_returns_none_on_too_short_data_part() -> None:
    # "1xx" is shorter than 6-char checksum + 7-char timestamp.
    assert payment_hash_from_bolt11("lnbc1xxx") is None


def test_returns_none_on_invalid_bech32_chars() -> None:
    # Inject characters not in the bech32 charset.
    assert payment_hash_from_bolt11("lnbc1" + "B" * 50) is None


def test_returns_none_on_truncated_invoice() -> None:
    """An invoice cut off mid-tag should not raise — just return None
    (the recovery path tries the helper before any other action)."""
    truncated = _INCIDENT_INVOICE[: len("lnbc1019200n1p4q72m5") + 20]
    assert payment_hash_from_bolt11(truncated) is None


def test_handles_invoice_with_leading_trailing_whitespace() -> None:
    padded = "  " + _INCIDENT_INVOICE + "\n"
    assert payment_hash_from_bolt11(padded) == _INCIDENT_PAYMENT_HASH


# ── Principal (HRP amount) decoder ───────────────────────────────────

from app.core.bolt11 import principal_sats_from_bolt11  # noqa: E402


def test_principal_from_real_incident_invoice() -> None:
    """The incident invoice encodes 1019200n BTC = 101_920 sats."""
    assert principal_sats_from_bolt11(_INCIDENT_INVOICE) == 101_920


def test_principal_micro_btc() -> None:
    # 2500u BTC = 250_000 sats.
    assert principal_sats_from_bolt11("lnbc2500u1pvjluezpp5qqqsyqcyq") == 250_000


def test_principal_milli_btc() -> None:
    # 1m BTC = 100_000 sats.
    assert principal_sats_from_bolt11("lnbc1m1pabcdefqqqsyq") == 100_000


def test_principal_regtest_prefix() -> None:
    # bcrt currency prefix, 500n BTC = 50 sats.
    assert principal_sats_from_bolt11("lnbcrt500n1pabcdefqqqsyq") == 50


def test_principal_amountless_is_none() -> None:
    """An amountless invoice has no HRP digit run; a caller comparing to
    an expected amount must treat this as a refusal, not zero."""
    assert principal_sats_from_bolt11("lnbc1pvjluezqqqsyq") is None


def test_principal_case_insensitive() -> None:
    assert principal_sats_from_bolt11(_INCIDENT_INVOICE.upper()) == 101_920


def test_principal_garbage_is_none() -> None:
    assert principal_sats_from_bolt11("not-an-invoice") is None
    assert principal_sats_from_bolt11("") is None
    assert principal_sats_from_bolt11(None) is None  # type: ignore[arg-type]


def test_principal_sub_satoshi_pico_is_none() -> None:
    # 1p BTC = 0.1 msat — not a whole number of sats → refuse.
    assert principal_sats_from_bolt11("lnbc1p1pabcdefqqqsyq") is None
