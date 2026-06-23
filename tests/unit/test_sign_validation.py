# SPDX-License-Identifier: MIT
"""Unit tests for app.core.sign_validation."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.core.sign_validation import (
    audit_message_details,
    message_sha256_hex,
    normalise_message,
    validate_signature,
)


class TestNormaliseMessage:
    def test_strips_bom(self):
        assert normalise_message("\ufeffhello") == "hello"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            normalise_message("")
        with pytest.raises(ValueError):
            normalise_message("\ufeff")

    def test_rejects_oversized(self):
        with patch("app.core.sign_validation.settings") as s:
            s.sign_message_max_chars = 16
            with pytest.raises(ValueError):
                normalise_message("a" * 17)

    def test_rejects_control_bytes(self):
        with pytest.raises(ValueError):
            normalise_message("hello\x00world")
        with pytest.raises(ValueError):
            normalise_message("hello\x7fworld")
        with pytest.raises(ValueError):
            normalise_message("hello\x01world")

    def test_allows_tab_newline_cr(self):
        assert normalise_message("a\tb\nc\r") == "a\tb\nc\r"

    def test_passthrough_unicode(self):
        assert normalise_message("café 🟧") == "café 🟧"


class TestValidateSignature:
    def test_accepts_alphabet(self):
        assert validate_signature("AbCdEf123+/=_-") == "AbCdEf123+/=_-"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_signature("")

    def test_rejects_bad_chars(self):
        with pytest.raises(ValueError):
            validate_signature("abcd!ef")
        with pytest.raises(ValueError):
            validate_signature("abc def")

    def test_rejects_oversized(self):
        with pytest.raises(ValueError):
            validate_signature("a" * 257)

    def test_strips_whitespace(self):
        assert validate_signature("  abcd  ") == "abcd"


class TestMessageSha256:
    def test_hex_length(self):
        h = message_sha256_hex("hello")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic(self):
        assert message_sha256_hex("x") == message_sha256_hex("x")

    def test_utf8_bytes(self):
        # Known vector: sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert message_sha256_hex("hello").startswith("2cf24dba")


class TestAuditMessageDetails:
    def test_default_does_not_include_message(self):
        with patch("app.core.sign_validation.settings") as s:
            s.sign_audit_record_message = False
            d = audit_message_details("hello")
        assert "message" not in d
        assert d["message_length"] == 5
        assert len(d["message_sha256"]) == 64

    def test_opt_in_includes_message(self):
        with patch("app.core.sign_validation.settings") as s:
            s.sign_audit_record_message = True
            d = audit_message_details("hello")
        assert d["message"] == "hello"
