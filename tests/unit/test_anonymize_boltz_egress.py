# SPDX-License-Identifier: MIT
"""Anonymize-stack-direct
Boltz HTTP egress.

The anonymize stack must NOT delegate Boltz reverse-swap calls to the
wallet's general ``boltz_service``; that client routes through the
shared LND Tor proxy with the default httpx ClientHello + header set.
:class:`AnonymizeBoltzClient` wraps every call in
:func:`get_anonymize_client` so:

* each call gets a fresh ``IsolateSOCKSAuth`` SOCKS auth pair → fresh
  Tor circuit,
* the dedicated ``boltz_reverse`` SOCKS listener is used,
* pinned headers + ClientHello apply,
* the request body is the padded pinned shape, and
* the circuit-rebuild budget counts the call.

These tests mock :func:`get_anonymize_client` to capture the call
parameters + the request shape; they never hit the network.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from uuid import uuid4

import httpx
import pytest

from app.services.anonymize import boltz_egress
from app.services.anonymize.boltz_egress import AnonymizeBoltzClient
from app.services.anonymize.boltz_request import _PAD_BUCKETS_BYTES
from tests._bolt11_fixtures import BIND_INVOICE, BIND_INVOICE_PRINCIPAL_SATS, BIND_PAYMENT_HASH


@dataclass
class _ClientCall:
    """One captured call into :func:`get_anonymize_client`."""

    call_site: str
    socks_host: str
    socks_port: int
    timeout_s: float
    requests: list[httpx.Request]


def _install_mock_anonymize_client(
    monkeypatch: pytest.MonkeyPatch,
    handler,
) -> list[_ClientCall]:
    """Replace ``get_anonymize_client`` with a MockTransport client.

    Returns the list of captured calls — each entry includes the
    call-site, SOCKS host/port, and the list of HTTP requests issued
    inside that ``async with`` block.
    """
    captured: list[_ClientCall] = []

    @asynccontextmanager
    async def _factory(*, call_site, socks_host, socks_port, timeout_s=30.0):
        call = _ClientCall(
            call_site=call_site,
            socks_host=socks_host,
            socks_port=socks_port,
            timeout_s=timeout_s,
            requests=[],
        )
        captured.append(call)

        def _wrapped(request: httpx.Request) -> httpx.Response:
            call.requests.append(request)
            return handler(request)

        transport = httpx.MockTransport(_wrapped)
        async with httpx.AsyncClient(transport=transport) as client:
            yield client

    monkeypatch.setattr(boltz_egress, "get_anonymize_client", _factory)
    return captured


def _install_mock_keypair(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the Node-spawned keypair generator with a stub so the
    tests don't require ``node`` + boltz-core on the test host."""
    monkeypatch.setattr(
        boltz_egress,
        "_generate_keypair",
        lambda: ("11" * 32, "02" + "22" * 32),
    )


# ── Reverse-swap creation ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_reverse_swap_uses_boltz_reverse_listener(
    db_session,
    monkeypatch,
) -> None:
    """The wrapper must select the ``boltz_reverse`` SOCKS listener."""

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "swap-xyz",
                "invoice": BIND_INVOICE,
                "onchainAmount": 100_000,
                "lockupAddress": "bcrt1...",
                "refundPublicKey": "03abc...",
                "swapTree": {"claimLeaf": {}, "refundLeaf": {}},
                "timeoutBlockHeight": 1_000,
            },
        )

    captured = _install_mock_anonymize_client(monkeypatch, _handler)
    _install_mock_keypair(monkeypatch)
    # The returned invoice must commit to our preimage hash (security C1).
    monkeypatch.setattr(
        "app.services.anonymize.boltz_egress._generate_preimage",
        lambda: ("ab" * 32, BIND_PAYMENT_HASH),
    )
    # Reverse lockup-address verification is exercised elsewhere; stub it
    # here so this listener-selection test isn't gated on the node verifier.
    monkeypatch.setattr(
        "app.services.anonymize.boltz_egress.verify_reverse_lockup_address",
        lambda **_kw: (True, "ok"),
    )

    client = AnonymizeBoltzClient(
        base_url="https://boltz.invalid/api",
        socks_host="127.0.0.1",
        socks_port=9051,
    )
    swap, err = await client.create_reverse_swap(
        db_session,
        api_key_id=uuid4(),
        invoice_amount_sats=BIND_INVOICE_PRINCIPAL_SATS,
        destination_address="bcrt1ptest",
    )
    assert err is None
    assert swap is not None
    assert swap.boltz_swap_id == "swap-xyz"
    assert len(captured) == 1
    assert captured[0].call_site == "boltz_reverse"
    assert captured[0].socks_port == 9051


@pytest.mark.asyncio
async def test_create_reverse_swap_posts_pinned_padded_body(
    db_session,
    monkeypatch,
) -> None:
    """The outbound request body must use the pinned shape +
    ``_pad`` rounding to a fixed bucket."""

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "swap-id"})

    captured = _install_mock_anonymize_client(monkeypatch, _handler)
    _install_mock_keypair(monkeypatch)

    client = AnonymizeBoltzClient(
        base_url="https://boltz.invalid/api",
        socks_host="127.0.0.1",
        socks_port=9051,
    )
    await client.create_reverse_swap(
        db_session,
        api_key_id=uuid4(),
        invoice_amount_sats=BIND_INVOICE_PRINCIPAL_SATS,
        destination_address="bcrt1ptest",
    )

    [req] = captured[0].requests
    assert req.method == "POST"
    assert req.url.path.endswith("/swap/reverse")
    body = json.loads(req.content.decode("utf-8"))
    # Pinned fields only.
    assert set(body.keys()) <= {
        "from",
        "to",
        "preimageHash",
        "claimPublicKey",
        "invoiceAmount",
        "claimAddress",
        "_pad",
    }
    # padding present + serialized body lands in a fixed bucket.
    assert "_pad" in body
    serialized = json.dumps(body, separators=(",", ":")).encode("utf-8")
    assert len(serialized) in _PAD_BUCKETS_BYTES


@pytest.mark.asyncio
async def test_create_reverse_swap_propagates_5xx_as_error(
    db_session,
    monkeypatch,
) -> None:
    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream down")

    _install_mock_anonymize_client(monkeypatch, _handler)
    _install_mock_keypair(monkeypatch)

    client = AnonymizeBoltzClient(
        base_url="https://boltz.invalid/api",
        socks_host="127.0.0.1",
        socks_port=9051,
    )
    swap, err = await client.create_reverse_swap(
        db_session,
        api_key_id=uuid4(),
        invoice_amount_sats=BIND_INVOICE_PRINCIPAL_SATS,
        destination_address="bcrt1ptest",
    )
    assert swap is None
    assert err is not None
    assert "503" in err


@pytest.mark.asyncio
async def test_create_reverse_swap_rejects_short_onchain_amount(
    db_session,
    monkeypatch,
) -> None:
    """An on-chain amount below (invoice − fee ceiling) is refused before
    the swap row is persisted."""

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "swap-short",
                "invoice": BIND_INVOICE,
                # invoice 101_920, 5% ceiling ⇒ fair_min ~96_824; this is well under.
                "onchainAmount": 50_000,
                "lockupAddress": "bcrt1...",
                "timeoutBlockHeight": 1_000,
            },
        )

    _install_mock_anonymize_client(monkeypatch, _handler)
    _install_mock_keypair(monkeypatch)
    monkeypatch.setattr(
        "app.services.anonymize.boltz_egress._generate_preimage",
        lambda: ("ab" * 32, BIND_PAYMENT_HASH),
    )

    client = AnonymizeBoltzClient(
        base_url="https://boltz.invalid/api",
        socks_host="127.0.0.1",
        socks_port=9051,
    )
    swap, err = await client.create_reverse_swap(
        db_session,
        api_key_id=uuid4(),
        invoice_amount_sats=BIND_INVOICE_PRINCIPAL_SATS,
        destination_address="bcrt1ptest",
    )
    assert swap is None
    assert err is not None
    assert "fair minimum" in err


@pytest.mark.asyncio
async def test_create_reverse_swap_accepts_amount_within_fee_ceiling(
    db_session,
    monkeypatch,
) -> None:
    """An on-chain amount within the fee ceiling is accepted."""

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "swap-fair",
                "invoice": BIND_INVOICE,
                "onchainAmount": 98_000,  # within 5% of 101_920
                "lockupAddress": "bcrt1...",
                "swapTree": {"claimLeaf": {}, "refundLeaf": {}},
                "timeoutBlockHeight": 1_000,
            },
        )

    _install_mock_anonymize_client(monkeypatch, _handler)
    _install_mock_keypair(monkeypatch)
    monkeypatch.setattr(
        "app.services.anonymize.boltz_egress._generate_preimage",
        lambda: ("ab" * 32, BIND_PAYMENT_HASH),
    )
    monkeypatch.setattr(
        "app.services.anonymize.boltz_egress.verify_reverse_lockup_address",
        lambda **_kw: (True, "ok"),
    )

    client = AnonymizeBoltzClient(
        base_url="https://boltz.invalid/api",
        socks_host="127.0.0.1",
        socks_port=9051,
    )
    swap, err = await client.create_reverse_swap(
        db_session,
        api_key_id=uuid4(),
        invoice_amount_sats=BIND_INVOICE_PRINCIPAL_SATS,
        destination_address="bcrt1ptest",
    )
    assert err is None
    assert swap is not None
    assert swap.boltz_swap_id == "swap-fair"


@pytest.mark.asyncio
async def test_create_reverse_swap_rejects_unverifiable_lockup(
    db_session,
    monkeypatch,
) -> None:
    """A reverse lockup that fails address verification is refused BEFORE the
    hold invoice is paid — a malicious operator must not be able to lock funds
    to a claim leaf the wallet can't spend with its preimage."""

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "swap-evil",
                "invoice": BIND_INVOICE,
                "onchainAmount": 100_000,
                "lockupAddress": "bcrt1qattacker",
                "swapTree": {"claimLeaf": {}, "refundLeaf": {}},
                "timeoutBlockHeight": 1_000,
            },
        )

    _install_mock_anonymize_client(monkeypatch, _handler)
    _install_mock_keypair(monkeypatch)
    monkeypatch.setattr(
        "app.services.anonymize.boltz_egress._generate_preimage",
        lambda: ("ab" * 32, BIND_PAYMENT_HASH),
    )
    monkeypatch.setattr(
        "app.services.anonymize.boltz_egress.verify_reverse_lockup_address",
        lambda **_kw: (False, "claim_leaf_mismatch"),
    )

    client = AnonymizeBoltzClient(
        base_url="https://boltz.invalid/api",
        socks_host="127.0.0.1",
        socks_port=9051,
    )
    swap, err = await client.create_reverse_swap(
        db_session,
        api_key_id=uuid4(),
        invoice_amount_sats=BIND_INVOICE_PRINCIPAL_SATS,
        destination_address="bcrt1ptest",
    )
    assert swap is None
    assert err is not None
    assert "lockup address verification failed" in err


@pytest.mark.asyncio
async def test_create_reverse_swap_rejects_inflated_invoice_principal(
    db_session,
    monkeypatch,
) -> None:
    """A hold invoice whose principal exceeds the requested send amount
    is refused before it is paid — the operator cannot over-charge on
    Lightning by inflating the invoice while the on-chain fairness floor
    (which keys off the requested amount) still passes."""

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "swap-inflated",
                # BIND_INVOICE encodes a 101_920-sat principal; we request
                # only 50_000, so the principal does not match.
                "invoice": BIND_INVOICE,
                "onchainAmount": 49_000,
                "lockupAddress": "bcrt1...",
                "timeoutBlockHeight": 1_000,
            },
        )

    _install_mock_anonymize_client(monkeypatch, _handler)
    _install_mock_keypair(monkeypatch)
    monkeypatch.setattr(
        "app.services.anonymize.boltz_egress._generate_preimage",
        lambda: ("ab" * 32, BIND_PAYMENT_HASH),
    )

    client = AnonymizeBoltzClient(
        base_url="https://boltz.invalid/api",
        socks_host="127.0.0.1",
        socks_port=9051,
    )
    swap, err = await client.create_reverse_swap(
        db_session,
        api_key_id=uuid4(),
        invoice_amount_sats=50_000,
        destination_address="bcrt1ptest",
    )
    assert swap is None
    assert err is not None
    assert "principal" in err


# ── Swap-status polling ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_swap_status_routes_through_anonymize_wrapper(
    monkeypatch,
) -> None:
    """GET /swap/{id} must also go through the anonymize wrapper."""

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(
            200,
            json={"status": "transaction.mempool", "transaction": {"hex": "ff"}},
        )

    captured = _install_mock_anonymize_client(monkeypatch, _handler)

    client = AnonymizeBoltzClient(
        base_url="https://boltz.invalid/api",
        socks_host="127.0.0.1",
        socks_port=9051,
    )
    status, data, err = await client.get_swap_status("swap-id-123")
    assert err is None
    assert status == "transaction.mempool"
    assert data == {"status": "transaction.mempool", "transaction": {"hex": "ff"}}
    assert captured[0].call_site == "boltz_reverse"
    assert captured[0].requests[0].url.path.endswith("/swap/swap-id-123")


# ── No forbidden fields on the wire ─────────────────────────────────


@pytest.mark.asyncio
async def test_outbound_body_contains_no_forbidden_internal_ids(
    db_session,
    monkeypatch,
) -> None:
    """The wire body must not carry any internal-ID name."""
    from app.services.anonymize.metadata import (
        ANONYMIZE_FORBIDDEN_EGRESS_FIELDS,
    )

    def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "swap-id"})

    captured = _install_mock_anonymize_client(monkeypatch, _handler)
    _install_mock_keypair(monkeypatch)

    client = AnonymizeBoltzClient(
        base_url="https://boltz.invalid/api",
        socks_host="127.0.0.1",
        socks_port=9051,
    )
    await client.create_reverse_swap(
        db_session,
        api_key_id=uuid4(),
        invoice_amount_sats=BIND_INVOICE_PRINCIPAL_SATS,
        destination_address="bcrt1ptest",
    )

    [req] = captured[0].requests
    body = json.loads(req.content.decode("utf-8"))
    forbidden_in_body = set(body.keys()) & ANONYMIZE_FORBIDDEN_EGRESS_FIELDS
    assert forbidden_in_body == set(), forbidden_in_body


# ── Response-signature verification fails closed on registry load error ──


def test_verify_response_signature_fails_closed_when_registry_load_raises(
    monkeypatch,
) -> None:
    """When a session is bound to a specific operator_id but the signed
    registry raises on load, verification must return an error (so the
    hop routes through reconciliation) rather than silently skipping it.
   """

    def _boom(*_a, **_k):
        raise RuntimeError("operators.sig corrupted")

    monkeypatch.setattr(
        "app.services.anonymize.operators.load_signed_operator_registry",
        _boom,
    )

    client = AnonymizeBoltzClient(
        base_url="https://boltz.invalid/api",
        socks_host="127.0.0.1",
        socks_port=9051,
    )
    response = httpx.Response(200, headers={"X-Operator-Signature": "00ff"})
    err = client._verify_response_signature(
        response=response,
        response_body=b"{}",
        operator_id="boltz-exchange-2026",
    )
    assert err is not None
    assert "registry unavailable" in err


def test_verify_response_signature_skips_when_no_operator_id(monkeypatch) -> None:
    """Single-operator deployments (operator_id is None) still skip
    verification even if the registry would raise — the bind doesn't
    apply."""

    def _boom(*_a, **_k):
        raise RuntimeError("should not be called")

    monkeypatch.setattr(
        "app.services.anonymize.operators.load_signed_operator_registry",
        _boom,
    )
    client = AnonymizeBoltzClient(
        base_url="https://boltz.invalid/api",
        socks_host="127.0.0.1",
        socks_port=9051,
    )
    response = httpx.Response(200)
    err = client._verify_response_signature(
        response=response,
        response_body=b"{}",
        operator_id=None,
    )
    assert err is None
