# SPDX-License-Identifier: MIT
"""Blinded-path BOLT11 invoice helper."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import settings
from app.services.anonymize.deposit_invoice import (
    DepositInvoiceError,
    DepositInvoiceResult,
    issue_ext_lightning_deposit_invoice,
)


def _mock_lnd(*, payment_request: str = "lnbcrt1blinded", err: str | None = None) -> MagicMock:
    # Mirror the real BlindedInvoiceResult TypedDict shape add_blinded_invoice
    # returns (a dict), not an attribute object — r_hash is the hex payment
    # hash; blinded_paths is the raw per-path list (count = len).
    result = {
        "r_hash": "ab" * 32,
        "payment_request": payment_request,
        "add_index": "1",
        "payment_addr": "cd" * 32,
        "blinded_paths": [{}, {}],
    }
    lnd = MagicMock()
    lnd.add_blinded_invoice = AsyncMock(return_value=(None if err else result, err))
    return lnd


@pytest.mark.asyncio
async def test_issue_returns_payment_request() -> None:
    lnd = _mock_lnd()
    out = await issue_ext_lightning_deposit_invoice(
        amount_msat=250_000_000,
        lnd_client=lnd,
    )
    assert isinstance(out, DepositInvoiceResult)
    assert out.payment_request == "lnbcrt1blinded"
    assert out.blinded_paths_count == 2


@pytest.mark.asyncio
async def test_issue_pins_default_blinded_path_config() -> None:
    """num_hops=1, max_num_paths=2 — the conservative defaults."""
    lnd = _mock_lnd()
    await issue_ext_lightning_deposit_invoice(
        amount_msat=250_000_000,
        lnd_client=lnd,
    )
    call_kwargs = lnd.add_blinded_invoice.await_args.kwargs
    assert call_kwargs["num_hops"] == 1
    assert call_kwargs["max_num_paths"] == 2


@pytest.mark.asyncio
async def test_issue_rejects_nonpositive_amount() -> None:
    with pytest.raises(DepositInvoiceError, match="amount_msat must be positive"):
        await issue_ext_lightning_deposit_invoice(
            amount_msat=0,
            lnd_client=_mock_lnd(),
        )


@pytest.mark.asyncio
async def test_issue_rejects_amount_above_max(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_max_sat", 1_000_000)
    with pytest.raises(DepositInvoiceError, match="ANONYMIZE_MAX_SAT"):
        await issue_ext_lightning_deposit_invoice(
            amount_msat=2_000_000 * 1000,
            lnd_client=_mock_lnd(),
        )


@pytest.mark.asyncio
async def test_issue_rejects_nonpositive_expiry() -> None:
    with pytest.raises(DepositInvoiceError, match="expiry_seconds must be positive"):
        await issue_ext_lightning_deposit_invoice(
            amount_msat=100_000_000,
            expiry_seconds=0,
            lnd_client=_mock_lnd(),
        )


@pytest.mark.asyncio
async def test_issue_surfaces_lnd_error() -> None:
    lnd = _mock_lnd(err="no inbound liquidity")
    with pytest.raises(DepositInvoiceError, match="no inbound liquidity"):
        await issue_ext_lightning_deposit_invoice(
            amount_msat=100_000_000,
            lnd_client=lnd,
        )


@pytest.mark.asyncio
async def test_issue_passes_memo_and_expiry_through() -> None:
    lnd = _mock_lnd()
    await issue_ext_lightning_deposit_invoice(
        amount_msat=100_000_000,
        memo="anonymize ext-lightning deposit",
        expiry_seconds=7_200,
        lnd_client=lnd,
    )
    kw = lnd.add_blinded_invoice.await_args.kwargs
    assert kw["memo"] == "anonymize ext-lightning deposit"
    assert kw["expiry"] == 7_200
