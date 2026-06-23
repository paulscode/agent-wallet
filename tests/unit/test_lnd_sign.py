# SPDX-License-Identifier: MIT
"""Unit tests for LNDService sign/verify methods and address classifier."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, patch

import pytest

from app.services.lnd_service import LNDService, _classify_address_type


class TestClassifyAddressType:
    def test_taproot(self):
        # Taproot: bech32m, witness version 1 (first data char 'p' → ver=1)
        assert _classify_address_type("bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297") == "p2tr"

    def test_native_segwit_p2wkh(self):
        # bech32 v0, 20-byte program (32 chars after version)
        assert _classify_address_type("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == "p2wkh"

    def test_p2sh_wrapped(self):
        assert _classify_address_type("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") == "p2sh-p2wkh"

    def test_p2pkh(self):
        assert _classify_address_type("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") == "p2pkh"

    def test_unknown(self):
        assert _classify_address_type("garbage") == "unknown"

    def test_testnet_p2wkh(self):
        assert _classify_address_type("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx") == "p2wkh"


class TestSignMessageWithAddress:
    @pytest.mark.asyncio
    async def test_sends_base64_message(self):
        svc = LNDService()
        captured: dict = {}

        async def fake_request(method, path, **kwargs):
            captured["method"] = method
            captured["path"] = path
            captured["body"] = kwargs.get("json")
            return ({"signature": "AAAA"}, None)

        with patch.object(svc, "_request", side_effect=fake_request):
            result, error = await svc.sign_message_with_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "hello")

        assert error is None
        assert result is not None
        assert result["signature"] == "AAAA"
        assert result["address_type"] == "p2wkh"
        assert result["format"] == "BIP-322"
        assert captured["path"].endswith("/v2/wallet/address/signmessage")
        # Message must be base64-encoded UTF-8
        sent = captured["body"]
        assert sent["addr"] == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        assert base64.b64decode(sent["msg"]).decode() == "hello"

    @pytest.mark.asyncio
    async def test_legacy_address_uses_bip137(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"signature": "X"}, None),
        ):
            result, _ = await svc.sign_message_with_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "hi")
        assert result is not None
        assert result["format"] == "BIP-137"
        assert result["address_type"] == "p2pkh"

    @pytest.mark.asyncio
    async def test_propagates_error(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=(None, "address not owned"),
        ):
            result, error = await svc.sign_message_with_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "hi")
        assert result is None
        assert error == "address not owned"


class TestVerifyMessageWithAddress:
    @pytest.mark.asyncio
    async def test_valid_returns_pubkey_hex(self):
        svc = LNDService()
        pub_bytes = bytes.fromhex("02" + "ab" * 32)
        pub_b64 = base64.b64encode(pub_bytes).decode()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"valid": True, "pubkey": pub_b64}, None),
        ):
            result, _ = await svc.verify_message_with_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "hi", "sig")
        assert result is not None
        assert result["valid"] is True
        assert result["pubkey"] == pub_bytes.hex()

    @pytest.mark.asyncio
    async def test_invalid_does_not_leak_pubkey(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"valid": False, "pubkey": "abc"}, None),
        ):
            result, _ = await svc.verify_message_with_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "hi", "sig")
        assert result is not None
        assert result["valid"] is False
        assert result["pubkey"] is None


class TestSignMessageNode:
    @pytest.mark.asyncio
    async def test_includes_node_pubkey(self):
        svc = LNDService()
        info = {
            "alias": "n",
            "identity_pubkey": "02" + "c" * 64,
            "synced_to_chain": True,
            "block_height": 1,
            "version": "v",
            "num_active_channels": 0,
            "num_peers": 0,
        }
        with (
            patch.object(
                svc,
                "_request",
                new_callable=AsyncMock,
                return_value=({"signature": "zbase32sig"}, None),
            ),
            patch.object(
                svc,
                "get_info",
                new_callable=AsyncMock,
                return_value=(info, None),
            ),
        ):
            result, error = await svc.sign_message_node("hello")

        assert error is None
        assert result is not None
        assert result["signature"] == "zbase32sig"
        assert result["node_pubkey"] == "02" + "c" * 64

    @pytest.mark.asyncio
    async def test_handles_get_info_failure(self):
        svc = LNDService()
        with (
            patch.object(
                svc,
                "_request",
                new_callable=AsyncMock,
                return_value=({"signature": "z"}, None),
            ),
            patch.object(
                svc,
                "get_info",
                new_callable=AsyncMock,
                return_value=(None, "boom"),
            ),
        ):
            result, error = await svc.sign_message_node("hi")
        assert error is None
        assert result is not None
        assert result["signature"] == "z"
        assert result["node_pubkey"] == ""


class TestVerifyMessageNode:
    @pytest.mark.asyncio
    async def test_valid(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"valid": True, "pubkey": "02deadbeef"}, None),
        ):
            result, _ = await svc.verify_message_node("hi", "sig")
        assert result is not None
        assert result["valid"] is True
        assert result["pubkey"] == "02deadbeef"

    @pytest.mark.asyncio
    async def test_invalid(self):
        svc = LNDService()
        with patch.object(
            svc,
            "_request",
            new_callable=AsyncMock,
            return_value=({"valid": False, "pubkey": "x"}, None),
        ):
            result, _ = await svc.verify_message_node("hi", "sig")
        assert result is not None
        assert result["valid"] is False
        assert result["pubkey"] is None
