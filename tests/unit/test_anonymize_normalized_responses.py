# SPDX-License-Identifier: MIT
"""/ items 20, 59, 96 — normalized responses.

Pin the exact bytes so a future serializer change can't introduce
a key-order or whitespace difference that would create a side
channel between rejection classes.
"""

from __future__ import annotations

import hashlib

from app.services.anonymize.responses import (
    creation_unavailable_body_bytes,
    creation_unavailable_response,
    destination_rejected_body_bytes,
    destination_rejected_response,
    quote_cache_stale_body_bytes,
    quote_cache_stale_response,
    quote_expired_body_bytes,
    quote_expired_response,
    quote_token_verify_unavailable_body_bytes,
    quote_token_verify_unavailable_response,
)

# ── Hash-pinned literals — a regression that mutates these is a
# side-channel introduction and should fail loudly. ────────────────


_DESTINATION_REJECTED_SHA256 = hashlib.sha256(b'{"code":"destination_rejected"}').hexdigest()
_CREATION_UNAVAILABLE_SHA256 = hashlib.sha256(b'{"code":"creation_unavailable","retry_after":null}').hexdigest()
_QUOTE_CACHE_STALE_SHA256 = hashlib.sha256(b'{"code":"quote_cache_stale"}').hexdigest()


def test_destination_rejected_body_is_pinned() -> None:
    body = destination_rejected_body_bytes()
    assert hashlib.sha256(body).hexdigest() == _DESTINATION_REJECTED_SHA256
    assert body == b'{"code":"destination_rejected"}'


def test_creation_unavailable_body_is_pinned() -> None:
    body = creation_unavailable_body_bytes()
    assert hashlib.sha256(body).hexdigest() == _CREATION_UNAVAILABLE_SHA256
    # Critically: ``retry_after: null`` and the key order are part of
    # the contract; the test passes only when the bytes match exactly.
    assert b'"retry_after":null' in body


def test_quote_cache_stale_body_is_pinned() -> None:
    body = quote_cache_stale_body_bytes()
    assert hashlib.sha256(body).hexdigest() == _QUOTE_CACHE_STALE_SHA256


def test_quote_token_verify_unavailable_body_distinct_from_cache_stale() -> None:
    """Distinct bodies prevent rotation-window probing."""
    a = quote_cache_stale_body_bytes()
    b = quote_token_verify_unavailable_body_bytes()
    assert a != b


def test_quote_expired_body_distinct_from_verify_unavailable() -> None:
    """TTL expiry has its own pinned body."""
    a = quote_expired_body_bytes()
    b = quote_token_verify_unavailable_body_bytes()
    assert a != b


def test_destination_rejected_response_shape() -> None:
    resp = destination_rejected_response()
    assert resp.status_code == 422
    assert resp.media_type == "application/json"
    assert resp.body == destination_rejected_body_bytes()
    # No Retry-After.
    assert "retry-after" not in {h.lower() for h in resp.headers.keys()}


def test_creation_unavailable_response_shape() -> None:
    resp = creation_unavailable_response()
    assert resp.status_code == 429
    assert resp.body == creation_unavailable_body_bytes()
    assert "retry-after" not in {h.lower() for h in resp.headers.keys()}


def test_quote_cache_stale_response_status() -> None:
    resp = quote_cache_stale_response()
    assert resp.status_code == 503


def test_quote_token_verify_unavailable_response_status() -> None:
    resp = quote_token_verify_unavailable_response()
    assert resp.status_code == 503


def test_quote_expired_response_status() -> None:
    resp = quote_expired_response()
    assert resp.status_code == 409
