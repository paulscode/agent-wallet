# SPDX-License-Identifier: MIT
"""Liquid swap client (reverse + submarine).

**This replaces ``test_anonymize_liquid_chain_swap.py``** — the chain
endpoint was the wrong product. The wallet's Liquid hop uses:

* ``POST /v2/swap/reverse`` with ``to: L-BTC`` for the LN→L-BTC leg.
* ``POST /v2/swap/submarine`` with ``from: L-BTC`` for L-BTC→LN.

Test fixtures are pinned against real responses captured from the
[BoltzExchange/regtest](https://github.com/BoltzExchange/regtest)
harness running locally; the wire shape is exact.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
import pytest

from app.services.anonymize import liquid_swap
from app.services.anonymize.liquid_swap import (
    LiquidReverseSwap,
    LiquidSubmarineSwap,
    LiquidSwapClient,
    generate_preimage_and_hash,
    generate_swap_keypair,
)

# Real response fixtures captured against the regtest harness.
# Source: localhost:9001/v2/swap/{reverse,submarine} via boltz-backend
# 3.13.0-e6397e9a on 2026-05-12.

_REVERSE_RESPONSE = {
    "id": "LIB8GwoL2Kgw",
    "swapTree": {
        "claimLeaf": {
            "version": 196,
            "output": (
                "82012088a914611ba367bee732e7beae1c50a5c3e990b53df184"
                "8820b32559b0a9579770ec3a6a048870a41d14fa79edbc27035b3"
                "efabc3c3734eaeaac"
            ),
        },
        "refundLeaf": {
            "version": 196,
            "output": ("20c4b06805b2103b001673228719c7605d12072d2eaee379b7403f4cd81c2202fbad023706b1"),
        },
    },
    "blindingKey": "844cfd754cbfde0b50c1139091782ef7e43b9f09bcd15f331f855f77794bf6f5",
    "lockupAddress": (
        "el1pq2tyft5qh00f3cpv55fxxksmczyvly7wh8mgnv0ytpw38pagfmtzyen"
        "mlf55dyu32y0wzrvymavfxtvyx0wwyxxmy8w2mdwd4gywtgnlsc4fp6e6tnj7"
    ),
    "refundPublicKey": "02c4b06805b2103b001673228719c7605d12072d2eaee379b7403f4cd81c2202fb",
    "timeoutBlockHeight": 1591,
    "invoice": (
        "lnbcrt1m1p4q9g67sp5ca7jc478pa9dpztjp90hulzacm63uxx0ga37rysrxad"
        "qxa0k9lrspp5sm946wkvgueq2pe2thre0ckupwcs0zte0wpc5mjngavv9mjz4xu"
        "sdpz2djkuepqw3hjqnpdgf2yxgrpv3j8yetnwvxqyp2xqcqz959qyysgqq6hh42"
        "8w5xh63u4yke2jlaa9sdcxcwnq440ffncka49r5s68eczjg6apfwvkl2pgdjlhu"
        "2fd08r3vghkgj98qyf6zutwu76p72kapxgq49h057"
    ),
    "onchainAmount": 99723,
}

_SUBMARINE_RESPONSE = {
    "id": "6NzIDgoB49zt",
    "swapTree": {
        "claimLeaf": {
            "version": 196,
            "output": (
                "a914f946d16e572f3b479f77c75ed9c20cf86c83c8e38820419dff"
                "98ab172396f12e487c02433646e703ddc7d4b3a07b97c777a131df51b9ac"
            ),
        },
        "refundLeaf": {
            "version": 196,
            "output": ("20b67f6b4e1ba2e9e79c05a7715aa434c8f668073582c0450d2262329e966d6b67ad02f727b1"),
        },
    },
    "blindingKey": "730faa2d4e80e4ea73384487cd6fd6af8f5fca8990f6f7b53293f56381ac3e96",
    "address": (
        "el1pqd07rxdvtd9flna86004pwa9603l9v6wrpxlshdwslekdz6vprcj8fw4"
        "fxfm9k62pkgqyqmmkskz3sxaudlewceav8kcpzqct9lm9uya3za8ue9lp6nx"
    ),
    "claimPublicKey": "03419dff98ab172396f12e487c02433646e703ddc7d4b3a07b97c777a131df51b9",
    "expectedAmount": 120,
    "timeoutBlockHeight": 10231,
    "acceptZeroConf": True,
    "bip21": (
        "liquidnetwork:el1pqd07rxdvtd9flna86004pwa9603l9v6wrpxlshdwsle"
        "kdz6vprcj8fw4fxfm9k62pkgqyqmmkskz3sxaudlewceav8kcpzqct9lm9uya"
        "3za8ue9lp6nx?amount=0.0000012&label=Send%20to%20BTC%20lightning"
        "&assetid=5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"
    ),
}


@dataclass
class _ClientCall:
    call_site: str
    requests: list[httpx.Request]


def _install_mock_client(monkeypatch, handler) -> list[_ClientCall]:
    captured: list[_ClientCall] = []

    @asynccontextmanager
    async def _factory(*, call_site, socks_host, socks_port, timeout_s=30.0):
        call = _ClientCall(call_site=call_site, requests=[])
        captured.append(call)

        def _wrapped(request: httpx.Request) -> httpx.Response:
            call.requests.append(request)
            return handler(request)

        transport = httpx.MockTransport(_wrapped)
        async with httpx.AsyncClient(transport=transport) as client:
            yield client

    monkeypatch.setattr(liquid_swap, "get_anonymize_client", _factory)
    return captured


# ── Helper smoke tests ─────────────────────────────────────────────


def test_generate_preimage_returns_32_byte_hex_pair() -> None:
    import hashlib

    preimage, h = generate_preimage_and_hash()
    assert len(preimage) == 64
    assert len(h) == 64
    assert hashlib.sha256(bytes.fromhex(preimage)).hexdigest() == h


def test_generate_keypair_returns_secp256k1_shape() -> None:
    priv, pub = generate_swap_keypair()
    assert len(priv) == 64
    assert len(pub) == 66
    assert pub.startswith(("02", "03"))


def test_client_refuses_empty_base_url() -> None:
    with pytest.raises(ValueError):
        LiquidSwapClient(base_url="")


# ── create_reverse_swap_to_lbtc ────────────────────────────────────


@pytest.mark.asyncio
async def test_reverse_swap_uses_liquid_listener_and_correct_endpoint(
    monkeypatch,
) -> None:
    def _handler(request):
        return httpx.Response(200, json=_REVERSE_RESPONSE)

    captured = _install_mock_client(monkeypatch, _handler)
    client = LiquidSwapClient(
        base_url="https://boltz.invalid",
        socks_port=9052,
    )
    swap, err = await client.create_reverse_swap_to_lbtc(
        invoice_amount_sat=100_000,
        # Must equal the payment hash of _REVERSE_RESPONSE["invoice"] so the
        # reverse-swap binding (security C1) accepts the response.
        preimage_hash_hex="86cb5d3acc473205072a5dc797e2dc0bb10789797b838a6e534758c2ee42a9b9",
        claim_public_key_hex="02" + "cc" * 32,
    )
    assert err is None
    assert isinstance(swap, LiquidReverseSwap)
    assert swap.id == _REVERSE_RESPONSE["id"]
    assert swap.blinding_key_hex == _REVERSE_RESPONSE["blindingKey"]
    assert swap.lockup_address == _REVERSE_RESPONSE["lockupAddress"]
    assert swap.refund_public_key_hex == _REVERSE_RESPONSE["refundPublicKey"]
    assert swap.timeout_block_height == _REVERSE_RESPONSE["timeoutBlockHeight"]
    assert swap.invoice == _REVERSE_RESPONSE["invoice"]
    assert swap.onchain_amount_sat == _REVERSE_RESPONSE["onchainAmount"]
    assert swap.swap_tree.claim_leaf.version == 196
    assert swap.swap_tree.refund_leaf.version == 196

    # Liquid listener + correct path
    assert len(captured) == 1
    assert captured[0].call_site == "liquid"
    req = captured[0].requests[0]
    assert req.method == "POST"
    assert str(req.url).endswith("/v2/swap/reverse")


@pytest.mark.asyncio
async def test_reverse_swap_body_shape_matches_boltz_contract(monkeypatch) -> None:
    """The body MUST include from/to/invoiceAmount/preimageHash/claimPublicKey."""
    import json as _json

    captured_body: dict = {}

    def _handler(request):
        nonlocal captured_body
        captured_body = _json.loads(request.content)
        return httpx.Response(200, json=_REVERSE_RESPONSE)

    _install_mock_client(monkeypatch, _handler)
    client = LiquidSwapClient(
        base_url="https://boltz.invalid",
        socks_port=9052,
    )
    await client.create_reverse_swap_to_lbtc(
        invoice_amount_sat=100_000,
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "cc" * 32,
    )
    assert captured_body == {
        "from": "BTC",
        "to": "L-BTC",
        "invoiceAmount": 100_000,
        "preimageHash": "aa" * 32,
        "claimPublicKey": "02" + "cc" * 32,
    }


@pytest.mark.asyncio
async def test_reverse_swap_rejects_non_positive_amount(monkeypatch) -> None:
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)
    swap, err = await client.create_reverse_swap_to_lbtc(
        invoice_amount_sat=0,
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "cc" * 32,
    )
    assert swap is None
    assert "positive" in (err or "")


@pytest.mark.asyncio
async def test_reverse_swap_rejects_wrong_preimage_hash(monkeypatch) -> None:
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)
    swap, err = await client.create_reverse_swap_to_lbtc(
        invoice_amount_sat=100_000,
        preimage_hash_hex="aa" * 16,
        claim_public_key_hex="02" + "cc" * 32,
    )
    assert swap is None
    assert "64 chars" in (err or "")


@pytest.mark.asyncio
async def test_reverse_swap_handles_http_error(monkeypatch) -> None:
    def _handler(request):
        return httpx.Response(400, json={"error": "Invalid pair"})

    _install_mock_client(monkeypatch, _handler)
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)
    swap, err = await client.create_reverse_swap_to_lbtc(
        invoice_amount_sat=100_000,
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "cc" * 32,
    )
    assert swap is None
    assert "Invalid pair" in (err or "")
    assert "400" in (err or "")


@pytest.mark.asyncio
async def test_reverse_swap_handles_missing_blinding_key(monkeypatch) -> None:
    """A BTC-side reverse swap won't have a blindingKey; we should
    refuse rather than silently produce a half-built object."""
    bad = dict(_REVERSE_RESPONSE)
    del bad["blindingKey"]

    def _handler(request):
        return httpx.Response(200, json=bad)

    _install_mock_client(monkeypatch, _handler)
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)
    swap, err = await client.create_reverse_swap_to_lbtc(
        invoice_amount_sat=100_000,
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "cc" * 32,
    )
    assert swap is None
    assert "blindingKey" in (err or "")


# ── create_submarine_swap_from_lbtc ────────────────────────────────


@pytest.mark.asyncio
async def test_submarine_swap_uses_liquid_listener_and_correct_endpoint(
    monkeypatch,
) -> None:
    def _handler(request):
        return httpx.Response(200, json=_SUBMARINE_RESPONSE)

    captured = _install_mock_client(monkeypatch, _handler)
    client = LiquidSwapClient(
        base_url="https://boltz.invalid",
        socks_port=9052,
    )
    swap, err = await client.create_submarine_swap_from_lbtc(
        invoice="lnbcrt1u1p4q9gld...",
        refund_public_key_hex="02" + "dd" * 32,
    )
    assert err is None
    assert isinstance(swap, LiquidSubmarineSwap)
    assert swap.id == _SUBMARINE_RESPONSE["id"]
    assert swap.blinding_key_hex == _SUBMARINE_RESPONSE["blindingKey"]
    assert swap.address == _SUBMARINE_RESPONSE["address"]
    assert swap.claim_public_key_hex == _SUBMARINE_RESPONSE["claimPublicKey"]
    assert swap.expected_amount_sat == _SUBMARINE_RESPONSE["expectedAmount"]
    assert swap.timeout_block_height == _SUBMARINE_RESPONSE["timeoutBlockHeight"]
    assert swap.accept_zero_conf is True
    assert swap.bip21.startswith("liquidnetwork:")

    assert len(captured) == 1
    assert captured[0].call_site == "liquid"
    req = captured[0].requests[0]
    assert req.method == "POST"
    assert str(req.url).endswith("/v2/swap/submarine")


@pytest.mark.asyncio
async def test_submarine_swap_body_shape_matches_boltz_contract(
    monkeypatch,
) -> None:
    import json as _json

    captured_body: dict = {}

    def _handler(request):
        nonlocal captured_body
        captured_body = _json.loads(request.content)
        return httpx.Response(200, json=_SUBMARINE_RESPONSE)

    _install_mock_client(monkeypatch, _handler)
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)
    await client.create_submarine_swap_from_lbtc(
        invoice="lnbcrt...",
        refund_public_key_hex="02" + "dd" * 32,
    )
    assert captured_body == {
        "from": "L-BTC",
        "to": "BTC",
        "invoice": "lnbcrt...",
        "refundPublicKey": "02" + "dd" * 32,
    }


@pytest.mark.asyncio
async def test_submarine_swap_rejects_empty_invoice(monkeypatch) -> None:
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)
    swap, err = await client.create_submarine_swap_from_lbtc(
        invoice="",
        refund_public_key_hex="02" + "dd" * 32,
    )
    assert swap is None
    assert "invoice" in (err or "")


@pytest.mark.asyncio
async def test_submarine_swap_rejects_empty_refund_pubkey(monkeypatch) -> None:
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)
    swap, err = await client.create_submarine_swap_from_lbtc(
        invoice="lnbcrt...",
        refund_public_key_hex="",
    )
    assert swap is None
    assert "refund_public_key_hex" in (err or "")


@pytest.mark.asyncio
async def test_submarine_swap_handles_missing_address(monkeypatch) -> None:
    bad = dict(_SUBMARINE_RESPONSE)
    del bad["address"]

    def _handler(request):
        return httpx.Response(200, json=bad)

    _install_mock_client(monkeypatch, _handler)
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)
    swap, err = await client.create_submarine_swap_from_lbtc(
        invoice="lnbcrt...",
        refund_public_key_hex="02" + "dd" * 32,
    )
    assert swap is None
    assert "address" in (err or "")


# ── get_swap_status ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_swap_status_happy_path(monkeypatch) -> None:
    def _handler(request):
        return httpx.Response(
            200,
            json={
                "status": "transaction.mempool",
                "transaction": {"hex": "020000..."},
            },
        )

    captured = _install_mock_client(monkeypatch, _handler)
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)
    data, err = await client.get_swap_status("LIB8GwoL2Kgw")
    assert err is None
    assert data["status"] == "transaction.mempool"
    assert str(captured[0].requests[0].url).endswith("/swap/LIB8GwoL2Kgw")


@pytest.mark.asyncio
async def test_get_swap_status_url_encodes_id(monkeypatch) -> None:
    captured_urls: list[str] = []

    def _handler(request):
        captured_urls.append(str(request.url))
        return httpx.Response(200, json={"status": "x"})

    _install_mock_client(monkeypatch, _handler)
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)
    await client.get_swap_status("swap/with/slash")
    assert "swap%2Fwith%2Fslash" in captured_urls[0]


@pytest.mark.asyncio
async def test_get_swap_status_rejects_empty_id(monkeypatch) -> None:
    client = LiquidSwapClient(base_url="https://boltz.invalid", socks_port=9052)
    data, err = await client.get_swap_status("")
    assert data is None
    assert "non-empty" in (err or "")


# ── Trailing-slash normalisation ───────────────────────────────────


@pytest.mark.asyncio
async def test_base_url_trailing_slash_normalised(monkeypatch) -> None:
    captured_urls: list[str] = []

    def _handler(request):
        captured_urls.append(str(request.url))
        return httpx.Response(200, json=_REVERSE_RESPONSE)

    _install_mock_client(monkeypatch, _handler)
    client = LiquidSwapClient(base_url="https://boltz.invalid/", socks_port=9052)
    await client.create_reverse_swap_to_lbtc(
        invoice_amount_sat=100_000,
        preimage_hash_hex="aa" * 32,
        claim_public_key_hex="02" + "cc" * 32,
    )
    assert captured_urls[0] == "https://boltz.invalid/v2/swap/reverse"
