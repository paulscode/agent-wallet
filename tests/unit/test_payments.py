# SPDX-License-Identifier: MIT
"""Tests for app.api.payments — payment caps and fee guards."""

from __future__ import annotations

import pytest


class TestFeeLimitIncludedInPaymentCap:
    """A user-supplied ``fee_limit_sats`` must be bounded by the same
    Pydantic constraints as the routed amount; otherwise an outsized
    fee would let a request slip past per-transaction or aggregate
    spend caps that are computed against ``amount + fee_limit_sats``.
    """

    def test_pay_invoice_request_rejects_huge_fee_limit(self):
        from app.api.payments import PayInvoiceRequest

        with pytest.raises(Exception):
            PayInvoiceRequest(invoice="lnbc1...", fee_limit_sats=10_000_000)

    def test_dashboard_pay_request_rejects_huge_fee_limit(self):
        from app.dashboard.api import PayRequest

        with pytest.raises(Exception):
            PayRequest(payment_request="lnbc1...", fee_limit_sats=10_000_000)

    def test_dashboard_pay_request_default_fee_limit(self):
        from app.dashboard.api import PayRequest

        req = PayRequest(payment_request="lnbc1...")
        assert req.fee_limit_sats == 100
