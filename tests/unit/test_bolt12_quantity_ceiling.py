# SPDX-License-Identifier: MIT
"""Hard quantity ceiling on inbound BOLT 12 mints.

A fixed-price offer with no ``quantity_max`` mints ``pinned * quantity``,
bounded only by the ``bolt12_inbound_max_amount_msat`` cap — which an
operator can disable by setting it to 0. ``_validate_quantity`` applies a
hard ceiling so a peer can't drive an unbounded mint via quantity even
when the amount cap is off.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.services.bolt12.responder import _HARD_QUANTITY_MAX, _validate_quantity


def _invreq(quantity):
    return SimpleNamespace(quantity=quantity)


def _offer(quantity_max):
    return SimpleNamespace(quantity_max=quantity_max)


def test_quantity_above_hard_ceiling_rejected_even_without_quantity_max():
    # Offer pins no quantity_max → without the hard ceiling this would pass.
    assert _validate_quantity(_invreq(_HARD_QUANTITY_MAX + 1), _offer(None)) is False


def test_quantity_at_ceiling_allowed():
    assert _validate_quantity(_invreq(_HARD_QUANTITY_MAX), _offer(None)) is True


def test_zero_and_negative_quantity_rejected():
    assert _validate_quantity(_invreq(0), _offer(None)) is False
    assert _validate_quantity(_invreq(-1), _offer(None)) is False


def test_none_quantity_allowed():
    assert _validate_quantity(_invreq(None), _offer(None)) is True


def test_offer_quantity_max_still_enforced_below_hard_ceiling():
    assert _validate_quantity(_invreq(5), _offer(3)) is False
    assert _validate_quantity(_invreq(3), _offer(3)) is True
