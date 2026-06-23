# SPDX-License-Identifier: MIT
"""Quote-token HMAC keyset loader + startup canary."""

from __future__ import annotations

import base64

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.services.anonymize.quote_token import (
    QuoteTokenKeySet,
    QuoteTokenKeysetUnconfiguredError,
    assert_quote_token_keyset_loadable,
    load_quote_token_keyset,
)


def _fernet_key_str() -> str:
    """Return a fresh urlsafe-base64 Fernet key as a string."""
    return Fernet.generate_key().decode("ascii")


# ── load_quote_token_keyset ──────────────────────────────────────────


def test_load_returns_none_when_unset(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_fernet", "")
    assert load_quote_token_keyset() is None


def test_load_returns_none_when_whitespace(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        "   ",
    )
    assert load_quote_token_keyset() is None


def test_load_returns_keyset_with_single_key(monkeypatch) -> None:
    key = _fernet_key_str()
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        key,
    )
    ks = load_quote_token_keyset()
    assert isinstance(ks, QuoteTokenKeySet)
    assert len(ks.keys) == 1
    # Round-trip: the loaded key bytes equal the base64-decoded value.
    assert ks.keys[0] == base64.urlsafe_b64decode(key)
    assert ks.active_generation == 0


def test_load_returns_keyset_with_multiple_keys(monkeypatch) -> None:
    a = _fernet_key_str()
    b = _fernet_key_str()
    c = _fernet_key_str()
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        f"{a},{b},{c}",
    )
    ks = load_quote_token_keyset()
    assert ks is not None
    assert len(ks.keys) == 3
    # Order preserved — active key is the first entry.
    assert ks.keys[0] == base64.urlsafe_b64decode(a)
    assert ks.keys[1] == base64.urlsafe_b64decode(b)
    assert ks.keys[2] == base64.urlsafe_b64decode(c)


def test_load_rejects_non_base64(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        "this-is-not-base64!!",
    )
    with pytest.raises(QuoteTokenKeysetUnconfiguredError, match="valid base64"):
        load_quote_token_keyset()


def test_load_rejects_wrong_length_key(monkeypatch) -> None:
    """A correctly-base64 string that decodes to <32 bytes is rejected."""
    short = base64.urlsafe_b64encode(b"short").decode("ascii")
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        short,
    )
    with pytest.raises(QuoteTokenKeysetUnconfiguredError, match="32 bytes"):
        load_quote_token_keyset()


def test_load_skips_blank_entries_in_comma_list(monkeypatch) -> None:
    """Whitespace / empty entries in the list are tolerated."""
    a = _fernet_key_str()
    b = _fernet_key_str()
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        f"{a}, , {b},",
    )
    ks = load_quote_token_keyset()
    assert ks is not None
    assert len(ks.keys) == 2


# ── assert_quote_token_keyset_loadable ──────────────────────────────


def test_assert_raises_when_unset(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_fernet", "")
    with pytest.raises(QuoteTokenKeysetUnconfiguredError, match="ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET"):
        assert_quote_token_keyset_loadable()


def test_assert_returns_keyset_when_configured(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        _fernet_key_str(),
    )
    ks = assert_quote_token_keyset_loadable()
    assert isinstance(ks, QuoteTokenKeySet)


def test_assert_propagates_malformed_error(monkeypatch) -> None:
    """Malformed base64 surfaces the QuoteTokenKeysetUnconfiguredError chain."""
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        "***",
    )
    with pytest.raises(QuoteTokenKeysetUnconfiguredError):
        assert_quote_token_keyset_loadable()


# ── Smoke: keyset signs + verifies via the loaded bundle ─────────────


def test_loaded_keyset_round_trips_a_token(monkeypatch) -> None:
    """End-to-end: load → sign → verify against the same keyset."""
    from app.services.anonymize.quote_token import (
        QuoteTokenPayload,
        sign_quote_token,
        verify_quote_token,
    )

    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        _fernet_key_str(),
    )
    ks = assert_quote_token_keyset_loadable()
    payload = QuoteTokenPayload(
        canonical_pipeline_json=b'{"x":1}',
        bin_amount_sat=250_000,
        submarine_operator_id="op-s",
        reverse_operator_id="op-r",
        delay_min_s=10,
        delay_max_s=60,
        inter_leg_min_s=None,
        inter_leg_max_s=None,
        requested_mpp_k=3,
        issued_at_unix_s=1_000_000,
        ttl_s=300,
    )
    token = sign_quote_token(payload, keyset=ks)
    # No raise.
    verify_quote_token(
        token,
        keyset=ks,
        candidate=payload,
        now_unix_s=1_000_010,
    )
