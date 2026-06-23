# SPDX-License-Identifier: MIT
"""Submarine refund wiring.

The production refund adapter must pass a wallet-controlled change
address — previously it sent an empty string so the refund script aborted
before broadcasting and locked funds couldn't be auto-refunded — and
use the temp-file out-of-band transport so the refund-tx hex is
captured reliably (the legacy fd transport mismatched the wrapper's fd).
"""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.core.encryption import encrypt_field
from app.models.boltz_swap import BoltzSwap, SwapStatus
from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps


@pytest.mark.asyncio
async def test_refund_subprocess_derives_change_address_and_uses_file_transport(db_session, monkeypatch):
    swap = BoltzSwap(
        boltz_swap_id="sub-refund-1",
        api_key_id=uuid4(),
        invoice_amount_sats=0,
        destination_address="bcrt1qexample",
        fee_percentage="0",
        miner_fee_sats=0,
        preimage_hex=encrypt_field("00" * 32),
        preimage_hash_hex="00" * 32,
        claim_private_key_hex=encrypt_field("11" * 32),
        claim_public_key_hex="02" + "22" * 32,
        boltz_invoice="lnbc1xxx",
        boltz_lockup_address="bcrt1qlockup",
        boltz_swap_tree_json={"claimLeaf": {}, "refundLeaf": {}},
        timeout_block_height=900000,
        status=SwapStatus.CREATED,
        boltz_status="swap.created",
    )
    db_session.add(swap)
    await db_session.commit()

    # The dispatcher loads the swap via its own session maker; point it
    # at the test session.
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _fake_session_maker_cm():
        yield db_session

    def _fake_get_session_maker():
        return lambda: _fake_session_maker_cm()

    monkeypatch.setattr("app.core.database.get_session_maker", _fake_get_session_maker)

    # Derive a wallet change address.
    new_address_mock = AsyncMock(return_value=({"address": "bcrt1qchange-addr"}, None))
    monkeypatch.setattr("app.services.lnd_service.lnd_service.new_address", new_address_mock)

    captured: dict = {}

    async def _fake_run_boltz_claim_js(*, args, cwd, stdin_payload=None, use_tx_out_file=False, **kw):
        import json as _json

        captured["args"] = args
        captured["use_tx_out_file"] = use_tx_out_file
        captured["payload"] = _json.loads(stdin_payload.decode("utf-8"))

        class _Hex:
            value = "deadbeef"

        class _Result:
            returncode = 0
            claim_tx_hex = _Hex()

        return _Result()

    monkeypatch.setattr(
        "app.services.anonymize.subprocess.run_boltz_claim_js",
        _fake_run_boltz_claim_js,
    )

    deps = build_default_submarine_hop_deps()
    hex_value, err = await deps.run_refund_subprocess(swap_id="sub-refund-1", session=object())

    assert err is None
    assert hex_value == "deadbeef"
    # M5 — a real wallet change address was passed, not "".
    assert captured["payload"]["refundAddress"] == "bcrt1qchange-addr"
    new_address_mock.assert_awaited_once()
    # M6 — the temp-file transport is used.
    assert captured["use_tx_out_file"] is True


@pytest.mark.asyncio
async def test_refund_subprocess_fails_when_no_change_address(db_session, monkeypatch):
    swap = BoltzSwap(
        boltz_swap_id="sub-refund-2",
        api_key_id=uuid4(),
        invoice_amount_sats=0,
        destination_address="bcrt1qexample",
        fee_percentage="0",
        miner_fee_sats=0,
        preimage_hex=encrypt_field("00" * 32),
        preimage_hash_hex="00" * 32,
        claim_private_key_hex=encrypt_field("11" * 32),
        claim_public_key_hex="02" + "22" * 32,
        boltz_invoice="lnbc1xxx",
        boltz_lockup_address="bcrt1qlockup",
        boltz_swap_tree_json={"claimLeaf": {}, "refundLeaf": {}},
        timeout_block_height=900000,
        status=SwapStatus.CREATED,
        boltz_status="swap.created",
    )
    db_session.add(swap)
    await db_session.commit()

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _fake_session_maker_cm():
        yield db_session

    monkeypatch.setattr("app.core.database.get_session_maker", lambda: (lambda: _fake_session_maker_cm()))
    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service.new_address",
        AsyncMock(return_value=(None, "lnd down")),
    )

    deps = build_default_submarine_hop_deps()
    hex_value, err = await deps.run_refund_subprocess(swap_id="sub-refund-2", session=object())
    assert hex_value is None
    assert err is not None and "change address" in err
