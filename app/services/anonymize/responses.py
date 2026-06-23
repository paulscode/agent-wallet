# SPDX-License-Identifier: MIT
"""Normalized response-body builders for the anonymize endpoints.

 / items 20, 59, 96 — every
4xx/5xx response from ``/anonymize/*`` MUST be byte-identical across
its rejection class so an external attacker can't pivot from
response-body shape into a side channel:

* ``422 destination_rejected`` — same body for malformed-script,
  URI-wrapped, reuse-match, and any future destination-validation
  failure. The *front-end* re-runs its own
  client-side validation to discriminate; the server response is
  opaque.

* ``429 creation_unavailable`` — same body for tier-cap rejection,
  sliding-window creation-rate, advisory-lock contention, and
  reconciliation-queue saturation.

* ``503 quote_cache_stale`` — same body for cache-miss, key-rotation
  block, and any future cache-unavailable case.

The response *bytes* are pinned by hash-test; a regression that
serializes a Pydantic model with fluctuating key order would defeat
the byte-identity property. We therefore emit the body via a
``bytes`` literal rather than ``JSONResponse(content=...)``.
"""

from __future__ import annotations

from fastapi.responses import Response

# Single byte-pinned body for every destination-rejected case.
_DESTINATION_REJECTED_BODY: bytes = b'{"code":"destination_rejected"}'

# Single byte-pinned body for every create-unavailable case.
_CREATION_UNAVAILABLE_BODY: bytes = b'{"code":"creation_unavailable","retry_after":null}'

# Single byte-pinned body for every cache-stale case.
_QUOTE_CACHE_STALE_BODY: bytes = b'{"code":"quote_cache_stale"}'

# Quote-token verify unavailable; byte-pinned.
_QUOTE_TOKEN_VERIFY_UNAVAILABLE_BODY: bytes = b'{"code":"quote_token_verify_unavailable"}'

# Quote token expired; byte-pinned and distinct from
# quote_token_verify_unavailable so legitimate expiry can be
# distinguished from rotation-window verify failures.
_QUOTE_EXPIRED_BODY: bytes = b'{"code":"quote_expired"}'


def destination_rejected_response() -> Response:
    """normalized 422.

    The body is byte-identical regardless of *why* the destination
    was rejected. The dashboard SPA re-runs its client-side validation
    to discriminate.
    """
    return Response(
        content=_DESTINATION_REJECTED_BODY,
        status_code=422,
        media_type="application/json",
    )


def creation_unavailable_response() -> Response:
    """normalized 429 for every cap-class rejection.

    The body has no ``Retry-After`` header
    and a stable JSON shape with ``retry_after: null``.
    """
    return Response(
        content=_CREATION_UNAVAILABLE_BODY,
        status_code=429,
        media_type="application/json",
    )


def quote_cache_stale_response() -> Response:
    """byte-pinned 503 for every cache-stale case."""
    return Response(
        content=_QUOTE_CACHE_STALE_BODY,
        status_code=503,
        media_type="application/json",
    )


def quote_token_verify_unavailable_response() -> Response:
    """byte-pinned 503 — distinct from cache-stale and from quote_expired."""
    return Response(
        content=_QUOTE_TOKEN_VERIFY_UNAVAILABLE_BODY,
        status_code=503,
        media_type="application/json",
    )


def quote_expired_response() -> Response:
    """byte-pinned 409 — TTL or rotation-purge."""
    return Response(
        content=_QUOTE_EXPIRED_BODY,
        status_code=409,
        media_type="application/json",
    )


# Frozen-bytes accessors so tests can hash-pin the literals.
def destination_rejected_body_bytes() -> bytes:
    return _DESTINATION_REJECTED_BODY


def creation_unavailable_body_bytes() -> bytes:
    return _CREATION_UNAVAILABLE_BODY


def quote_cache_stale_body_bytes() -> bytes:
    return _QUOTE_CACHE_STALE_BODY


def quote_token_verify_unavailable_body_bytes() -> bytes:
    return _QUOTE_TOKEN_VERIFY_UNAVAILABLE_BODY


def quote_expired_body_bytes() -> bytes:
    return _QUOTE_EXPIRED_BODY


__all__ = [
    "destination_rejected_response",
    "creation_unavailable_response",
    "quote_cache_stale_response",
    "quote_token_verify_unavailable_response",
    "quote_expired_response",
    "destination_rejected_body_bytes",
    "creation_unavailable_body_bytes",
    "quote_cache_stale_body_bytes",
    "quote_token_verify_unavailable_body_bytes",
    "quote_expired_body_bytes",
]
