# SPDX-License-Identifier: MIT
"""HMAC sign/verify on quote-cache entries.

Sign/verify must reject a cache line whose signature doesn't match the
configured HMAC key. Configurations without a key fall through —
that's the legacy startup path before the operator wires the
``ANONYMIZE_QUOTE_CACHE_SIGNING_KEY_FERNET`` setting.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.services.anonymize.quote_cache import (
    CacheEntry,
    CacheKey,
    sign_cache_entry,
    verify_cache_entry,
)


@pytest.fixture
def signing_key(monkeypatch):
    """Configure a real Fernet-formatted signing key for HMAC."""
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(
        settings,
        "anonymize_quote_cache_signing_key_fernet",
        key,
    )
    return key


def _entry(*, payload, sig=None, gen=0, t=1_000.0) -> CacheEntry:
    return CacheEntry(
        key=CacheKey(operator_id="op-a", pair="BTC/BTC", asset="BTC"),
        payload=payload,
        fetched_at_unix_s=t,
        operator_signature=sig,
        signing_key_generation=gen,
    )


def test_sign_returns_none_when_no_key_configured(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_quote_cache_signing_key_fernet",
        "",
    )
    sig = sign_cache_entry(
        key=CacheKey(operator_id="op", pair="BTC/BTC", asset="BTC"),
        payload={"fee": 1},
        fetched_at_unix_s=1_000.0,
        signing_key_generation=0,
    )
    assert sig is None


def test_sign_then_verify_round_trip(signing_key) -> None:
    payload = {"fee_floor_sat_per_vb": 1.5}
    sig = sign_cache_entry(
        key=CacheKey(operator_id="op-a", pair="BTC/BTC", asset="BTC"),
        payload=payload,
        fetched_at_unix_s=1_000.0,
        signing_key_generation=0,
    )
    assert sig is not None
    entry = _entry(payload=payload, sig=sig)
    assert verify_cache_entry(entry) is True


def test_verify_rejects_tampered_payload(signing_key) -> None:
    payload = {"fee": 1}
    sig = sign_cache_entry(
        key=CacheKey(operator_id="op-a", pair="BTC/BTC", asset="BTC"),
        payload=payload,
        fetched_at_unix_s=1_000.0,
        signing_key_generation=0,
    )
    # Tamper with the payload after signing.
    tampered = _entry(payload={"fee": 999}, sig=sig)
    assert verify_cache_entry(tampered) is False


def test_verify_rejects_unsigned_entry_when_key_configured(signing_key) -> None:
    """A configured signing key + missing sig is an integrity gap."""
    entry = _entry(payload={"fee": 1}, sig=None)
    assert verify_cache_entry(entry) is False


def test_verify_passes_unsigned_entry_when_no_key_configured(monkeypatch) -> None:
    """Legacy startup before the operator wires a key."""
    monkeypatch.setattr(
        settings,
        "anonymize_quote_cache_signing_key_fernet",
        "",
    )
    entry = _entry(payload={"fee": 1}, sig=None)
    assert verify_cache_entry(entry) is True


def test_verify_rejects_wrong_key(monkeypatch, signing_key) -> None:
    payload = {"fee": 1}
    sig = sign_cache_entry(
        key=CacheKey(operator_id="op-a", pair="BTC/BTC", asset="BTC"),
        payload=payload,
        fetched_at_unix_s=1_000.0,
        signing_key_generation=0,
    )
    # Rotate the configured signing key — old signatures must now fail.
    monkeypatch.setattr(
        settings,
        "anonymize_quote_cache_signing_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )
    entry = _entry(payload=payload, sig=sig)
    assert verify_cache_entry(entry) is False
