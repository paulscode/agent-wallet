# SPDX-License-Identifier: MIT
"""Pinned Boltz create-swap request shape.

Asserts ``make_create_swap_request()`` admits only the documented
fields and refuses any extras (no ``referralId``, no internal IDs,
no custom preimage-hash algorithm).
"""

from __future__ import annotations

import pytest

from app.services.anonymize.http import EgressFingerprintError
from app.services.anonymize.operators import make_create_swap_request


def _valid_reverse_fields() -> dict:
    return {
        "type": "reversesubmarine",
        "pairId": "BTC/BTC",
        "orderSide": "buy",
        "invoiceAmount": 250_000,
        "preimageHash": "00" * 32,
        "claimPublicKey": "02" + "00" * 32,
        "pairHash": "abcd",
    }


def test_reverse_swap_accepts_documented_fields() -> None:
    body = make_create_swap_request(swap_type="reverse", fields=_valid_reverse_fields())
    assert body["type"] == "reversesubmarine"
    assert body["invoiceAmount"] == 250_000


def test_reverse_swap_rejects_referral_id() -> None:
    fields = _valid_reverse_fields()
    fields["referralId"] = "anonymize-wallet"
    with pytest.raises(EgressFingerprintError, match="extra field"):
        make_create_swap_request(swap_type="reverse", fields=fields)


def test_reverse_swap_rejects_internal_id_egress() -> None:
    fields = _valid_reverse_fields()
    fields["session_id"] = "abc-123"
    with pytest.raises(EgressFingerprintError):
        make_create_swap_request(swap_type="reverse", fields=fields)


def test_submarine_swap_accepts_documented_fields() -> None:
    body = make_create_swap_request(
        swap_type="submarine",
        fields={
            "type": "submarine",
            "pairId": "BTC/BTC",
            "orderSide": "sell",
            "invoice": "lnbcrt...",
            "refundPublicKey": "03" + "00" * 32,
            "pairHash": "abcd",
        },
    )
    assert body["type"] == "submarine"


def test_unknown_swap_type_rejected() -> None:
    with pytest.raises(ValueError, match="unknown swap_type"):
        make_create_swap_request(swap_type="bogus", fields={})  # type: ignore[arg-type]


def test_returned_dict_is_independent_of_input() -> None:
    fields = _valid_reverse_fields()
    body = make_create_swap_request(swap_type="reverse", fields=fields)
    body["pairHash"] = "mutated"
    assert fields["pairHash"] == "abcd"  # original unchanged
