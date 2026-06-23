# SPDX-License-Identifier: MIT
"""Regression tests for the reverse-swap payment_hash binding (security C1).

A Boltz reverse swap is only trustless if the hold-invoice the wallet
pays commits to ``sha256(preimage)`` the wallet generated. Without this
check a malicious operator can return an invoice whose payment hash it
already knows the preimage for, settle the HTLC to take the wallet's LN
funds, and never reveal the preimage the wallet needs to claim the
on-chain lockup. These tests pin the equality gate on every reverse path.
"""

import pytest

import app.services.boltz_service as boltz_module
from app.services.boltz_service import boltz_service

# Real invoice + its decoded payment hash (shared with test_bolt11_payment_hash).
_INVOICE = (
    "lnbc1019200n1p4q72m5pp5zh8f3dksgym27cgxjav2fx4zgljlvtd8r95g5lfj7nke2t08y5d"
    "sdql2djkuepqw3hjqsj5gvsxzerywfjhxuccqzylxqyp2xqsp58cj6lrx0qdgd8fwf4552gmj"
    "9wrvxdwd0jd54krq0lttxlxempg8q9qxpqysgqmf3leftwxdyu77fswnuktm5z4px3esh2kxq"
    "v2j8255k32p9r5tvrznud0acqf53pwpmgdrq8vlufeydv9gnd8v27e9exze0m0gtrpyspr8j5xh"
)
_INVOICE_PAYMENT_HASH = "15ce98b6d04136af61069758a49aa247e5f62da719688a7d32f4ed952de7251b"

_BOLTZ_RESPONSE = {
    "id": "swap-test-1",
    "invoice": _INVOICE,
    "onchainAmount": 101_000,
    "lockupAddress": "bc1qexampleexampleexampleexampleexampleex",
    "refundPublicKey": "02" + "11" * 32,
    "swapTree": {"claimLeaf": {}, "refundLeaf": {}},
    "timeoutBlockHeight": 800_000,
    "blindingKey": None,
}


def _patch_common(monkeypatch, *, preimage_hash: str) -> None:
    async def _fake_pair_info(self):
        return {
            "min": 1,
            "max": 10_000_000,
            "hash": "deadbeef",
            "fees_percentage": 0.5,
            "fees_miner_lockup": 100,
            "fees_miner_claim": 100,
        }, None

    async def _fake_request(self, method, path, body=None, **_kw):
        return dict(_BOLTZ_RESPONSE), None

    monkeypatch.setattr(boltz_module.BoltzSwapService, "get_reverse_pair_info", _fake_pair_info)
    monkeypatch.setattr(boltz_module.BoltzSwapService, "_request", _fake_request)
    monkeypatch.setattr(boltz_module, "_generate_preimage", lambda: ("ab" * 32, preimage_hash))
    monkeypatch.setattr(boltz_module, "_generate_keypair", lambda: ("cd" * 32, "02" + "ef" * 32))
    # The synthetic Boltz response carries no real taproot swap tree, so
    # stub the lockup reconstruction (exercised on its own below).
    monkeypatch.setattr(boltz_module, "verify_reverse_lockup_address", lambda **_kw: (True, "ok"))


@pytest.mark.asyncio
async def test_reverse_swap_rejects_mismatched_payment_hash(monkeypatch, db_session) -> None:
    """A returned invoice whose payment hash != our preimage hash is refused."""
    _patch_common(monkeypatch, preimage_hash="ff" * 32)  # != invoice's hash

    swap, error = await boltz_service.create_reverse_swap(
        db_session,
        api_key_id=__import__("uuid").uuid4(),
        invoice_amount_sats=101_920,
        destination_address="bc1qdestdestdestdestdestdestdestdestdes",
    )
    assert swap is None
    assert error is not None
    assert "payment_hash" in error


@pytest.mark.asyncio
async def test_reverse_swap_rejects_unfair_onchain_amount(monkeypatch, db_session) -> None:
    """A returned onchainAmount far below (invoice − fees) is refused."""
    _patch_common(monkeypatch, preimage_hash=_INVOICE_PAYMENT_HASH)
    # Override the response with a grossly under-delivering onchainAmount.
    unfair = dict(_BOLTZ_RESPONSE)
    unfair["onchainAmount"] = 50_000  # invoice principal is 101_920; ~50% haircut

    async def _fake_request(self, method, path, body=None, **_kw):
        return unfair, None

    monkeypatch.setattr(boltz_module.BoltzSwapService, "_request", _fake_request)

    swap, error = await boltz_service.create_reverse_swap(
        db_session,
        api_key_id=__import__("uuid").uuid4(),
        invoice_amount_sats=101_920,
        destination_address="bc1qdestdestdestdestdestdestdestdestdes",
    )
    assert swap is None
    assert error is not None and "fair minimum" in error


@pytest.mark.asyncio
async def test_reverse_swap_accepts_matching_payment_hash(monkeypatch, db_session) -> None:
    """A returned invoice that commits to our preimage hash is accepted."""
    _patch_common(monkeypatch, preimage_hash=_INVOICE_PAYMENT_HASH)

    swap, error = await boltz_service.create_reverse_swap(
        db_session,
        api_key_id=__import__("uuid").uuid4(),
        invoice_amount_sats=101_920,
        destination_address="bc1qdestdestdestdestdestdestdestdestdes",
    )
    assert error is None
    assert swap is not None
    assert swap.boltz_swap_id == "swap-test-1"
    assert swap.preimage_hash_hex == _INVOICE_PAYMENT_HASH


@pytest.mark.asyncio
async def test_reverse_swap_rejects_lockup_not_committing_to_claim_key(monkeypatch, db_session) -> None:
    """A lockup whose claim leaf does not commit to our claim key is refused."""
    _patch_common(monkeypatch, preimage_hash=_INVOICE_PAYMENT_HASH)
    # The reconstruction reports the claim leaf does not match our key.
    monkeypatch.setattr(
        boltz_module,
        "verify_reverse_lockup_address",
        lambda **_kw: (False, "claim_leaf_mismatch"),
    )

    swap, error = await boltz_service.create_reverse_swap(
        db_session,
        api_key_id=__import__("uuid").uuid4(),
        invoice_amount_sats=101_920,
        destination_address="bc1qdestdestdestdestdestdestdestdestdes",
    )
    assert swap is None
    assert error is not None and "lockup address failed verification" in error
