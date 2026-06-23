# SPDX-License-Identifier: MIT
"""Tests for app.services.alert_service webhook URL handling."""

from __future__ import annotations

import socket
from unittest.mock import patch

from app.services import alert_service


class TestAuditAnchorEventEnabled:
    """``audit_anchor`` must ship by default — it carries the signed head/count
    snapshot the off-box receiver needs for front-truncation detection. If it
    were dropped from the default allowlist, ``_get_enabled_events`` would
    silently discard every anchor in production while tests that monkeypatch
    ``send_alert`` directly would still pass."""

    def test_audit_anchor_in_default_enabled_events(self):
        """Assert the shipped default (the Settings field default), not the
        test-environment-overridden runtime value."""
        from app.core.config import Settings

        default = Settings.model_fields["alert_webhook_events"].default
        enabled = {e.strip() for e in default.split(",") if e.strip()}
        assert "audit_anchor" in enabled
        assert "audit_chain_broken" in enabled

    def test_audit_anchor_passes_the_enabled_events_gate(self):
        """Drive the real ``_get_enabled_events`` memoised gate."""
        with patch.object(alert_service.settings, "alert_webhook_events", "audit_anchor,login_failed"):
            alert_service._ENABLED_EVENTS = None  # reset memoisation
            try:
                assert "audit_anchor" in alert_service._get_enabled_events()
            finally:
                alert_service._ENABLED_EVENTS = None  # don't leak to other tests


class TestWebhookUrlPrivateAddressGuard:
    """Webhook URLs must resolve to a public IP at delivery time. A URL
    whose hostname resolves to RFC1918 / loopback / link-local space is
    rejected so that an attacker cannot use the alert hook as a
    server-side request forge against internal services."""

    def setup_method(self):
        # Cache was removed — kept import for backwards compat in
        # case downstream forks still reference it.
        pass

    def test_rejects_url_resolving_to_private_ip(self):
        url = "https://malicious.example.test/hook"
        with patch(
            "app.services.alert_service.socket.getaddrinfo",
            return_value=[(None, None, None, "", ("10.0.0.5", 0))],
        ):
            assert alert_service._validate_webhook_url(url) is False

    def test_accepts_url_resolving_to_public_ip(self):
        url = "https://hooks.example.test/path"
        with patch(
            "app.services.alert_service.socket.getaddrinfo",
            return_value=[(None, None, None, "", ("8.8.8.8", 0))],
        ):
            assert alert_service._validate_webhook_url(url) is True

    def test_dns_failure_fails_closed(self):
        url = "https://nonexistent.example.test/x"
        with patch(
            "app.services.alert_service.socket.getaddrinfo",
            side_effect=socket.gaierror("nope"),
        ):
            assert alert_service._validate_webhook_url(url) is False

    def test_validation_is_not_cached(self):
        """caching the validation verdict widens the
        DNS-rebind window from "validate→connect" to the cache TTL.
        Each call must re-resolve, so a hostname that flips from
        public to private between two calls is rejected on the second.
        """
        url = "https://rebind.example.test/path"
        public = [(None, None, None, "", ("1.1.1.1", 0))]
        private = [(None, None, None, "", ("10.0.0.1", 0))]
        results: list[bool] = []
        sequence = iter([public, private])

        def fake_resolve(*args, **kwargs):
            return next(sequence)

        with patch(
            "app.services.alert_service.socket.getaddrinfo",
            side_effect=fake_resolve,
        ):
            results.append(alert_service._validate_webhook_url(url))
            results.append(alert_service._validate_webhook_url(url))

        assert results == [True, False]
