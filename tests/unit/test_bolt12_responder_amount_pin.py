# SPDX-License-Identifier: MIT
"""Regression tests for the BOLT 12 responder price pin (security H2).

The mirrored ``offer`` fields inside an invoice_request are signed only
by the peer's transient payer key, so the responder must take the pinned
price from the trusted DB offer row — never from the wire — and must
charge ``price * quantity``.
"""

from types import SimpleNamespace

from app.services.bolt12.responder import _resolve_amount


def _invreq(*, amount=None, quantity=None, offer_amount=None):
    return SimpleNamespace(
        amount=amount,
        quantity=quantity,
        offer=SimpleNamespace(amount=offer_amount),
    )


def _offer(*, amount_msat=None, quantity_max=None):
    return SimpleNamespace(amount_msat=amount_msat, quantity_max=quantity_max)


def test_fixed_price_ignores_wire_offer_amount():
    # Peer mirrors a bogus offer_amount and invreq_amount; the DB pin wins.
    inv = _invreq(amount=5, quantity=None, offer_amount=5)
    row = _offer(amount_msat=1000)
    assert _resolve_amount(inv, row) is None  # 5 != pinned 1000 → reject


def test_fixed_price_uses_db_pin_when_invreq_omits_amount():
    inv = _invreq(amount=None, quantity=None, offer_amount=999999)
    row = _offer(amount_msat=1000)
    assert _resolve_amount(inv, row) == 1000


def test_fixed_price_multiplies_quantity():
    inv = _invreq(amount=None, quantity=3, offer_amount=None)
    row = _offer(amount_msat=1000)
    assert _resolve_amount(inv, row) == 3000


def test_fixed_price_invreq_amount_must_equal_total():
    inv = _invreq(amount=3000, quantity=3, offer_amount=None)
    row = _offer(amount_msat=1000)
    assert _resolve_amount(inv, row) == 3000

    inv_bad = _invreq(amount=1000, quantity=3, offer_amount=None)
    assert _resolve_amount(inv_bad, row) is None  # underpay rejected


def test_open_amount_offer_requires_invreq_amount():
    row = _offer(amount_msat=None)
    assert _resolve_amount(_invreq(amount=None), row) is None
    assert _resolve_amount(_invreq(amount=0), row) is None
    assert _resolve_amount(_invreq(amount=2500), row) == 2500


def test_quantity_below_one_rejected_on_fixed_price():
    inv = _invreq(amount=None, quantity=0, offer_amount=None)
    row = _offer(amount_msat=1000)
    assert _resolve_amount(inv, row) is None
