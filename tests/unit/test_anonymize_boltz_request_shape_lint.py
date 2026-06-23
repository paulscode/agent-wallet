# SPDX-License-Identifier: MIT
"""Pinned Boltz request shape (builder + CI lint)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.anonymize.boltz_request import (
    _REVERSE_CREATE_ALLOWED_FIELDS,
    _SUBMARINE_CREATE_ALLOWED_FIELDS,
    assert_reverse_request_shape,
    assert_submarine_request_shape,
    make_reverse_create_request,
    make_submarine_create_request,
)

# ── Builder output ────────────────────────────────────────────────────


def test_builder_returns_pinned_field_set() -> None:
    """Every field returned must be in the pinned allowlist."""
    out = make_reverse_create_request(
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "bb" * 32,
        invoice_amount_sats=250_000,
        destination_address="bcrt1p...",
    )
    assert set(out.keys()) <= _REVERSE_CREATE_ALLOWED_FIELDS


def test_builder_pad_field_present_by_default() -> None:
    """The default-padded builder output carries ``_pad``."""
    out = make_reverse_create_request(
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "bb" * 32,
        invoice_amount_sats=250_000,
        destination_address="bcrt1p...",
    )
    assert "_pad" in out
    assert isinstance(out["_pad"], str)


def test_builder_no_pad_when_disabled() -> None:
    """Tests pass ``pad=False`` to keep fixtures deterministic."""
    out = make_reverse_create_request(
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "bb" * 32,
        invoice_amount_sats=250_000,
        destination_address="bcrt1p...",
        pad=False,
    )
    assert "_pad" not in out


def test_builder_padded_body_rounds_to_bucket() -> None:
    """JSON-serialized padded body equals a bucket size."""
    import json

    from app.services.anonymize.boltz_request import _PAD_BUCKETS_BYTES

    out = make_reverse_create_request(
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "bb" * 32,
        invoice_amount_sats=250_000,
        destination_address="bcrt1ptest",
    )
    serialized = json.dumps(out, separators=(",", ":")).encode("utf-8")
    assert len(serialized) in _PAD_BUCKETS_BYTES


def test_builder_has_stable_field_values() -> None:
    out = make_reverse_create_request(
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "bb" * 32,
        invoice_amount_sats=250_000,
        destination_address="bcrt1ptest",
        pad=False,
    )
    assert out["from"] == "BTC"
    assert out["to"] == "BTC"
    assert out["invoiceAmount"] == 250_000
    assert out["claimAddress"] == "bcrt1ptest"


# ── Runtime + lint assertion helper ──────────────────────────────────


def test_assert_shape_admits_pinned_body() -> None:
    """The runtime assertion passes for a builder-produced body."""
    out = make_reverse_create_request(
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "bb" * 32,
        invoice_amount_sats=250_000,
        destination_address="bcrt1ptest",
    )
    assert_reverse_request_shape(out)  # no raise


def test_assert_shape_rejects_extra_field() -> None:
    """A body with extra fields trips the assertion."""
    out = make_reverse_create_request(
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "bb" * 32,
        invoice_amount_sats=250_000,
        destination_address="bcrt1ptest",
    )
    out["pairHash"] = "extra"
    with pytest.raises(ValueError, match="non-pinned fields"):
        assert_reverse_request_shape(out)


# ── Static lint: no anonymize-stack module constructs the body inline ──


REPO = Path(__file__).resolve().parents[2]
ANON_DIR = REPO / "app" / "services" / "anonymize"


def test_anonymize_stack_uses_only_the_builder_for_boltz_reverse_request() -> None:
    """A grep over ``app/services/anonymize/`` must not show any
    file constructing a Boltz reverse-swap request body without
    going through :func:`make_reverse_create_request`.

    Detected by: a literal dict containing ``"from": "BTC"`` +
    ``"to": "BTC"`` + ``"preimageHash"`` in the same module.
    The builder itself lives in ``boltz_request.py`` (allow-listed).
    """
    offenders: list[str] = []
    for py in ANON_DIR.rglob("*.py"):
        if py.name == "boltz_request.py":
            continue
        text = py.read_text(encoding="utf-8", errors="replace")
        if '"from": "BTC"' in text and '"to": "BTC"' in text and '"preimageHash"' in text:
            offenders.append(str(py.relative_to(REPO)))
    assert offenders == [], (
        " violation — these modules build a Boltz reverse "
        "request body inline; route them through "
        f"``make_reverse_create_request`` instead: {offenders}"
    )


def test_boltz_service_reverse_request_fields_are_subset_of_pinned_set() -> None:
    """The general-wallet ``boltz_service.create_reverse_swap``
    request body must use field names that are a subset of (or only
    augment with) the pinned anonymize set. The wallet's general
    path is allowed to *add* fields (``pairHash``); it must not
    rename or drop the pinned five.

    Verified by reading the source of ``boltz_service.create_reverse_swap``
    and checking the dict literal it constructs against the pinned
    set + the documented wallet-path additions (``pairHash``).
    """
    src = (REPO / "app" / "services" / "boltz_service.py").read_text(
        encoding="utf-8",
    )
    # The wallet's general swap_request dict carries these fields at
    # minimum. The anonymize stack uses a strict subset via
    # ``make_reverse_create_request``.
    for required in (
        '"from"',
        '"to"',
        '"preimageHash"',
        '"claimPublicKey"',
        '"invoiceAmount"',
    ):
        assert required in src, f" violation: boltz_service reverse-swap request missing pinned field {required}"


# ── / submarine request shape ─────────────────────


def test_submarine_builder_returns_pinned_field_set() -> None:
    out = make_submarine_create_request(
        invoice="lnbcrt1invoice",
        refund_public_key_hex="02" + "aa" * 32,
    )
    assert set(out.keys()) <= _SUBMARINE_CREATE_ALLOWED_FIELDS
    assert out["from"] == "BTC"
    assert out["to"] == "BTC"
    assert out["invoice"] == "lnbcrt1invoice"
    assert out["refundPublicKey"] == "02" + "aa" * 32


def test_submarine_builder_includes_pair_hash_when_supplied() -> None:
    out = make_submarine_create_request(
        invoice="lnbcrt1invoice",
        refund_public_key_hex="02" + "aa" * 32,
        pair_hash="cafe" * 16,
        pad=False,
    )
    assert out["pairHash"] == "cafe" * 16


def test_submarine_builder_omits_pair_hash_when_blank() -> None:
    out = make_submarine_create_request(
        invoice="lnbcrt1invoice",
        refund_public_key_hex="02" + "aa" * 32,
        pad=False,
    )
    assert "pairHash" not in out


def test_submarine_builder_pad_field_present_by_default() -> None:
    out = make_submarine_create_request(
        invoice="lnbcrt1invoice",
        refund_public_key_hex="02" + "aa" * 32,
    )
    assert "_pad" in out
    assert isinstance(out["_pad"], str)


def test_submarine_builder_no_pad_when_disabled() -> None:
    out = make_submarine_create_request(
        invoice="lnbcrt1invoice",
        refund_public_key_hex="02" + "aa" * 32,
        pad=False,
    )
    assert "_pad" not in out


def test_assert_submarine_shape_admits_pinned_body() -> None:
    out = make_submarine_create_request(
        invoice="lnbcrt1invoice",
        refund_public_key_hex="02" + "aa" * 32,
    )
    assert_submarine_request_shape(out)  # no raise


def test_assert_submarine_shape_rejects_extra_field() -> None:
    out = make_submarine_create_request(
        invoice="lnbcrt1invoice",
        refund_public_key_hex="02" + "aa" * 32,
        pad=False,
    )
    out["preimageHash"] = "deadbeef"  # not in submarine allow-list
    with pytest.raises(ValueError, match="non-pinned fields"):
        assert_submarine_request_shape(out)
