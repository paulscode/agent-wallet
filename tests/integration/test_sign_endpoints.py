# SPDX-License-Identifier: MIT
"""Integration tests for the Sign / Verify Message public API.

The sign endpoints are gated on env flags read at import-time, so for
these tests we mount the routers explicitly on the already-imported
FastAPI app rather than relying on env vars taking effect.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture(autouse=True)
def _mount_sign_routers():
    """Ensure all sign/verify routers are mounted for these tests.

    Idempotent — re-mounting an already-mounted router just appends
    duplicate routes, but FastAPI's first match wins so behaviour is
    identical.
    """
    from app.api.sign import (
        sign_address_router,
        sign_node_router,
        verify_router,
    )
    from app.main import app

    paths = {getattr(r, "path", "") for r in app.routes}
    if "/v1/wallet/sign/address" not in paths:
        app.include_router(sign_address_router)
    if "/v1/wallet/sign/node" not in paths:
        app.include_router(sign_node_router)
    if "/v1/wallet/verify/address" not in paths:
        app.include_router(verify_router)
    yield


@pytest.fixture
def _no_rate_limit():
    """Patch the sign rate limiter to always allow."""
    with patch(
        "app.api.sign.check_sign_rate_limit",
        new=AsyncMock(return_value=(True, None)),
    ):
        yield


# ─── Sign with address ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sign_address_requires_auth(client):
    res = await client.post(
        "/v1/wallet/sign/address",
        json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "message": "hi"},
    )
    assert res.status_code in (401, 403)


@pytest.mark.asyncio
async def test_sign_address_requires_admin(client, test_api_key):
    """A read-only API key cannot sign."""
    _, raw_key = test_api_key
    res = await client.post(
        "/v1/wallet/sign/address",
        json={"address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "message": "hi"},
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_sign_address_success(authed_client, _no_rate_limit):
    client, _, _ = authed_client
    fake = {
        "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
        "address_type": "p2wkh",
        "signature": "AAAA",
        "format": "BIP-322",
    }
    with patch(
        "app.api.sign.lnd_service.sign_message_with_address",
        new=AsyncMock(return_value=(fake, None)),
    ):
        res = await client.post(
            "/v1/wallet/sign/address",
            json={
                "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                "message": "hello",
            },
        )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["signature"] == "AAAA"
    assert body["format"] == "BIP-322"


@pytest.mark.asyncio
async def test_sign_address_lnd_error(authed_client, _no_rate_limit):
    client, _, _ = authed_client
    with patch(
        "app.api.sign.lnd_service.sign_message_with_address",
        new=AsyncMock(return_value=(None, "address not owned by wallet")),
    ):
        res = await client.post(
            "/v1/wallet/sign/address",
            json={
                "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                "message": "hi",
            },
        )
    assert res.status_code == 502


@pytest.mark.asyncio
async def test_sign_address_rejects_control_bytes(authed_client, _no_rate_limit):
    client, _, _ = authed_client
    res = await client.post(
        "/v1/wallet/sign/address",
        json={
            "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            "message": "hello\x00world",
        },
    )
    assert res.status_code == 422


# ─── Verify address ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_address_with_read_key(client, test_api_key):
    _, raw_key = test_api_key
    with patch(
        "app.api.sign.lnd_service.verify_message_with_address",
        new=AsyncMock(return_value=({"valid": True, "pubkey": "abcd"}, None)),
    ):
        res = await client.post(
            "/v1/wallet/verify/address",
            json={
                "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                "message": "hi",
                "signature": "abcdEFGH",
            },
            headers={"Authorization": f"Bearer {raw_key}"},
        )
    assert res.status_code == 200
    assert res.json() == {"valid": True, "pubkey": "abcd"}


@pytest.mark.asyncio
async def test_verify_address_invalid(client, test_api_key):
    _, raw_key = test_api_key
    with patch(
        "app.api.sign.lnd_service.verify_message_with_address",
        new=AsyncMock(return_value=({"valid": False, "pubkey": None}, None)),
    ):
        res = await client.post(
            "/v1/wallet/verify/address",
            json={
                "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                "message": "hi",
                "signature": "abcdEFGH",
            },
            headers={"Authorization": f"Bearer {raw_key}"},
        )
    assert res.status_code == 200
    body = res.json()
    assert body["valid"] is False
    assert body["pubkey"] is None


# ─── Sign / verify node identity ──────────────────────────────────────


@pytest.mark.asyncio
async def test_sign_node_admin(authed_client, _no_rate_limit):
    client, _, _ = authed_client
    with patch(
        "app.api.sign.lnd_service.sign_message_node",
        new=AsyncMock(
            return_value=(
                {"signature": "zbase32sig", "node_pubkey": "02" + "f" * 64},
                None,
            )
        ),
    ):
        res = await client.post(
            "/v1/wallet/sign/node",
            json={"message": "i am node"},
        )
    assert res.status_code == 200
    body = res.json()
    assert body["signature"] == "zbase32sig"
    assert body["node_pubkey"].startswith("02")


@pytest.mark.asyncio
async def test_verify_node_with_read_key(client, test_api_key):
    _, raw_key = test_api_key
    with patch(
        "app.api.sign.lnd_service.verify_message_node",
        new=AsyncMock(return_value=({"valid": True, "pubkey": "02deadbeef"}, None)),
    ):
        res = await client.post(
            "/v1/wallet/verify/node",
            json={"message": "hi", "signature": "zsig"},
            headers={"Authorization": f"Bearer {raw_key}"},
        )
    assert res.status_code == 200
    assert res.json()["valid"] is True


# ─── Rate limit ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sign_rate_limited(authed_client):
    client, _, _ = authed_client
    with patch(
        "app.api.sign.check_sign_rate_limit",
        new=AsyncMock(return_value=(False, "Too many sign requests")),
    ):
        res = await client.post(
            "/v1/wallet/sign/address",
            json={
                "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                "message": "hi",
            },
        )
    assert res.status_code == 429
