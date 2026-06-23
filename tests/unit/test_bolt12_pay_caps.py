# SPDX-License-Identifier: MIT
"""Regression tests for BOLT 12 /pay payment caps (security H1).

``POST /v1/bolt12/pay`` settles real funds, so API-key callers must be
bounded by LND_MAX_PAYMENT_SATS / cumulative-spend / velocity limits like
every other fund-moving endpoint. The dashboard sentinel key bypasses
them by design (human operator / anonymize hop with its own caps).
"""

from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

import app.api.bolt12 as bolt12
from app.core.config import settings
from app.dashboard import DASHBOARD_KEY_ID


def test_check_bolt12_payment_limit_rejects_over_cap(monkeypatch):
    monkeypatch.setattr(settings, "lnd_max_payment_sats", 10_000)
    with pytest.raises(HTTPException) as ei:
        bolt12._check_bolt12_payment_limit(10_001)
    assert ei.value.status_code == 400
    assert "exceeds safety limit" in ei.value.detail


def test_check_bolt12_payment_limit_allows_under_cap(monkeypatch):
    monkeypatch.setattr(settings, "lnd_max_payment_sats", 10_000)
    bolt12._check_bolt12_payment_limit(10_000)  # no raise


def test_check_bolt12_payment_limit_disabled(monkeypatch):
    monkeypatch.setattr(settings, "lnd_max_payment_sats", -1)
    bolt12._check_bolt12_payment_limit(10_000_000_000)  # no raise


def test_bolt12_settled_sats_prefers_route_total():
    htlc = {"route": {"total_amt": "12345"}}
    assert bolt12._bolt12_settled_sats(htlc, 100) == 12345


def test_bolt12_settled_sats_falls_back():
    assert bolt12._bolt12_settled_sats(None, 777) == 777
    assert bolt12._bolt12_settled_sats({"route": {}}, 777) == 777
    assert bolt12._bolt12_settled_sats({"route": {"total_amt": "x"}}, 777) == 777


@pytest.mark.asyncio
async def test_pay_offer_rejects_over_cap_for_api_key(monkeypatch):
    """A real API-key caller over LND_MAX_PAYMENT_SATS is refused 400
    before any gateway/LND interaction."""
    monkeypatch.setattr(settings, "lnd_max_payment_sats", 10_000)
    # Fake offer: payable (issuer_id present), no blinded paths.
    fake_offer = SimpleNamespace(issuer_id=b"\x02" * 33, paths=None)
    monkeypatch.setattr(bolt12, "_decode_offer_or_400", lambda _s: fake_offer)
    monkeypatch.setattr(bolt12, "_resolve_pay_amount", lambda _o, _a: 50_000_000)  # 50k sats msat

    def _boom():  # gateway must NOT be reached
        raise AssertionError("cap check should fire before gateway lookup")

    monkeypatch.setattr(bolt12, "get_bolt12_service", _boom)

    req = bolt12.PayOfferRequest(offer="lno1xxx", amount_msat=50_000_000)
    api_key = SimpleNamespace(id=uuid4(), is_admin=True)

    with pytest.raises(HTTPException) as ei:
        await bolt12._perform_pay_offer(req, api_key=api_key, db=None, ip=None)
    assert ei.value.status_code == 400
    assert "exceeds safety limit" in ei.value.detail


@pytest.mark.asyncio
async def test_pay_offer_dashboard_sentinel_bypasses_cap(monkeypatch):
    """The dashboard sentinel key is NOT subject to the per-payment cap;
    it proceeds past the cap check (and then fails later for an unrelated
    reason — gateway not running — which proves the cap did not fire)."""
    monkeypatch.setattr(settings, "lnd_max_payment_sats", 10_000)
    fake_offer = SimpleNamespace(issuer_id=b"\x02" * 33, paths=None)
    monkeypatch.setattr(bolt12, "_decode_offer_or_400", lambda _s: fake_offer)
    monkeypatch.setattr(bolt12, "_resolve_pay_amount", lambda _o, _a: 50_000_000)

    monkeypatch.setattr(
        bolt12,
        "get_bolt12_service",
        lambda: (_ for _ in ()).throw(HTTPException(status_code=503, detail="not running")),
    )

    req = bolt12.PayOfferRequest(offer="lno1xxx", amount_msat=50_000_000)
    api_key = SimpleNamespace(id=DASHBOARD_KEY_ID, is_admin=True)

    with pytest.raises(HTTPException) as ei:
        await bolt12._perform_pay_offer(req, api_key=api_key, db=None, ip=None)
    # Past the cap (would be 400); fails at the gateway instead.
    assert ei.value.status_code == 503
    assert "exceeds safety limit" not in str(ei.value.detail)
