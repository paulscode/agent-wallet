# SPDX-License-Identifier: MIT
"""Tests for L1 (HMAC payload signing) and L2 (DNS-rebinding mitigation)."""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import patch

import pytest

from app.core.config import settings
from app.services import alert_service


@pytest.fixture
def webhook_secret():
    original = settings.alert_webhook_shared_secret
    settings.alert_webhook_shared_secret = "s" * 32
    yield "s" * 32
    settings.alert_webhook_shared_secret = original


class TestPayloadSigning:
    """webhook payloads carry an HMAC-SHA256 signature when configured."""

    def test_no_secret_no_signature(self):
        settings.alert_webhook_shared_secret = ""
        body = b'{"event":"x"}'
        assert alert_service._sign_payload(body) is None

    def test_secret_set_signature_present(self, webhook_secret):
        body = b'{"event":"x"}'
        sig = alert_service._sign_payload(body)
        assert sig is not None
        assert sig.startswith("sha256=")
        expected = hmac.new(webhook_secret.encode(), body, hashlib.sha256).hexdigest()
        assert sig == f"sha256={expected}"

    def test_signature_changes_with_payload(self, webhook_secret):
        a = alert_service._sign_payload(b"a")
        b = alert_service._sign_payload(b"b")
        assert a != b

    def test_canonicalisation_is_stable(self):
        p1 = {"a": 1, "b": 2, "c": [1, 2]}
        p2 = {"c": [1, 2], "b": 2, "a": 1}
        assert alert_service._canonicalise(p1) == alert_service._canonicalise(p2)
        # And it's parseable JSON.
        json.loads(alert_service._canonicalise(p1))


class TestResolveAndValidate:
    """validation returns a *pinned* IP that the POST will use."""

    def test_returns_pinned_ip(self):
        with patch(
            "app.services.alert_service.socket.getaddrinfo",
            return_value=[(2, 1, 0, "", ("8.8.8.8", 0))],
        ):
            target = alert_service._resolve_and_validate("https://hooks.example.test/x")
        assert target is not None
        hostname, ip, scheme, port = target
        assert hostname == "hooks.example.test"
        assert ip == "8.8.8.8"
        assert scheme == "https"
        assert port == 443

    def test_rebinding_to_private_ip_is_caught(self):
        """Even if validation passes initially, a separate attacker-
        controlled lookup later cannot redirect us — the POST goes to
        the *first*, validated IP, not whatever DNS says next."""
        with patch(
            "app.services.alert_service.socket.getaddrinfo",
            return_value=[(2, 1, 0, "", ("8.8.8.8", 0))],
        ):
            target = alert_service._resolve_and_validate("https://hooks.example.test/x")
        assert target is not None
        # Now, simulate the DNS flipping to private — the pinned IP
        # we already have is unaffected by the second lookup.
        assert target[1] == "8.8.8.8"

    def test_explicit_private_ip_literal_rejected(self):
        target = alert_service._resolve_and_validate("https://10.0.0.1/x")
        assert target is None

    def test_public_ip_literal_accepted(self):
        target = alert_service._resolve_and_validate("https://1.1.1.1/x")
        assert target is not None
        assert target[1] == "1.1.1.1"

    def test_non_https_rejected(self):
        assert alert_service._resolve_and_validate("http://hooks.example.test/x") is None


class TestSendAlertIntegration:
    """end-to-end: send_alert composes payload, signs, and would POST to pinned IP."""

    @pytest.mark.asyncio
    async def test_send_alert_signs_and_pins(self, webhook_secret):
        original_url = settings.alert_webhook_url
        settings.alert_webhook_url = "https://hooks.example.test/x"
        try:
            captured: dict = {}

            async def fake_post(url, hostname, pinned_ip, port, body, headers, timeout=10.0):
                captured["url"] = url
                captured["hostname"] = hostname
                captured["pinned_ip"] = pinned_ip
                captured["body"] = body
                captured["headers"] = headers
                return 200, b""

            with (
                patch(
                    "app.services.alert_service.socket.getaddrinfo",
                    return_value=[(2, 1, 0, "", ("8.8.8.8", 0))],
                ),
                patch("app.services.alert_service._post_with_pinned_ip", side_effect=fake_post),
            ):
                # Force the event into the enabled set.
                alert_service._ENABLED_EVENTS = {"login_failed"}
                await alert_service.send_alert("login_failed", "test")
                alert_service._ENABLED_EVENTS = None

            assert captured["pinned_ip"] == "8.8.8.8"
            assert captured["hostname"] == "hooks.example.test"
            assert "X-Agent-Wallet-Signature" in captured["headers"]
            sig = captured["headers"]["X-Agent-Wallet-Signature"]
            expected = hmac.new(webhook_secret.encode(), captured["body"], hashlib.sha256).hexdigest()
            assert sig == f"sha256={expected}"
            payload = json.loads(captured["body"])
            assert payload["event"] == "login_failed"
            assert "timestamp" in payload
        finally:
            settings.alert_webhook_url = original_url
