# SPDX-License-Identifier: MIT
"""Quote-token HMAC binding.

The quote endpoint returns a token that binds the canonical pipeline
JSON, the per-session sampled operator pair, the binned amount, the
timing bands, and the chosen MPP-K. Mutation of any of these fields
between ``POST /quote`` and ``POST /sessions`` causes the create
endpoint to reject with 422.

This module ships the binding helpers:

* :func:`canonical_quote_payload` — sorted-keys JSON of the bound
  fields, used as the HMAC input.
* :func:`sign_quote_token` — HMAC-SHA256 over the canonical payload
  using the active key from ``ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET``.
* :func:`verify_quote_token` — verify a token against a candidate
  pipeline payload + load every loaded key generation (so a token
  signed under a rotated-out key still verifies during the
  retention window).

The TTL gate, rotation-window 503 fallback, and audit-event wiring
are filled in alongside the create endpoint.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class QuoteTokenKeySet:
    """Ordered HMAC-SHA256 key set for quote tokens."""

    keys: tuple[bytes, ...]
    active_generation: int

    def __post_init__(self) -> None:
        if not self.keys:
            raise ValueError("at least one quote-token HMAC key is required")
        for i, k in enumerate(self.keys):
            if len(k) != 32:
                raise ValueError(f"quote-token HMAC key #{i} must be 32 bytes")

    @property
    def active_key(self) -> bytes:
        return self.keys[0]


@dataclass(frozen=True)
class QuoteTokenPayload:
    """The fields the quote token binds (+ item 7 OWASP A01/A03).

    The item 7 binding adds:

    * ``cookie_subject_hmac`` — HMAC of the session-cookie subject so
      a token issued for one dashboard session cannot be replayed by
      another (defeats cookie-rotation evasion).
    * ``canonical_request_body_hash`` — sha256 of the canonical
      request body so any in-flight mutation of the body fails the
      bind. Operators, bin amount, and timing bands continue to be
      bound directly (already present below) — they are *also* in
      the canonical body, but binding them explicitly keeps the
      mismatch error specific.
    """

    canonical_pipeline_json: bytes
    bin_amount_sat: int
    submarine_operator_id: str | None
    reverse_operator_id: str | None
    delay_min_s: int
    delay_max_s: int
    inter_leg_min_s: int | None
    inter_leg_max_s: int | None
    requested_mpp_k: int
    issued_at_unix_s: int
    ttl_s: int
    # item 7 OWASP bindings — defaulted so existing callers compile.
    cookie_subject_hmac: bytes = b""
    canonical_request_body_hash: bytes = b""
    # Option C — bound into the token so a token issued for a
    # Liquid-opt-in quote cannot be replayed against the LN-only path
    # (and vice versa). Defaulted so existing callers compile.
    uses_liquid: bool = False
    # Chain-walk
    # outcome the session-create handler emits into the per-session
    # audit row. Empty for LN-only quotes (no chain walk happens).
    # The token doesn't enforce this field cryptographically beyond
    # the canonical-body hash, so it's informational about how the
    # selection landed.
    selection_source: str = ""


def canonical_quote_payload(p: QuoteTokenPayload) -> bytes:
    """Return the sorted-keys JSON of the bound fields."""
    import base64

    obj = {
        "canonical_pipeline_json": p.canonical_pipeline_json.decode("utf-8"),
        "bin_amount_sat": int(p.bin_amount_sat),
        "submarine_operator_id": p.submarine_operator_id,
        "reverse_operator_id": p.reverse_operator_id,
        "delay_min_s": int(p.delay_min_s),
        "delay_max_s": int(p.delay_max_s),
        "inter_leg_min_s": (None if p.inter_leg_min_s is None else int(p.inter_leg_min_s)),
        "inter_leg_max_s": (None if p.inter_leg_max_s is None else int(p.inter_leg_max_s)),
        "requested_mpp_k": int(p.requested_mpp_k),
        "issued_at_unix_s": int(p.issued_at_unix_s),
        "ttl_s": int(p.ttl_s),
        # Bind cookie subject + canonical body hash.
        "cookie_subject_hmac": base64.b64encode(p.cookie_subject_hmac).decode("ascii"),
        "canonical_request_body_hash": base64.b64encode(p.canonical_request_body_hash).decode("ascii"),
        # Option C
        "uses_liquid": bool(p.uses_liquid),
        # Chain-walk outcome (informational; bound to deny
        # post-hoc swap of the audit-row source attribution).
        "selection_source": str(p.selection_source or ""),
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_quote_token(payload: QuoteTokenPayload, *, keyset: QuoteTokenKeySet) -> str:
    """Return ``"<gen>.<canonical_b64>.<mac_hex>"``.

    The token shape is intentionally simple: three dot-separated
    parts, each base64url / hex / int. Verification re-canonicalizes
    the payload from the create-endpoint body and compares HMACs.
    """
    import base64

    canonical = canonical_quote_payload(payload)
    mac = hmac.new(keyset.active_key, canonical, hashlib.sha256).hexdigest()
    return ".".join(
        [
            str(keyset.active_generation),
            base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii"),
            mac,
        ]
    )


class QuoteTokenError(ValueError):
    """Raised on token shape errors / signature mismatch / TTL expiry."""


def decode_quote_token(
    token: str,
    *,
    keyset: QuoteTokenKeySet,
    expected_cookie_subject_hmac: bytes | None = None,
    now_unix_s: float | None = None,
) -> dict:
    """Verify ``token`` shape + MAC + TTL and return the bound payload.

    The create endpoint calls this with the request's quote_token
    and the freshly-computed cookie-subject HMAC; on success the
    returned dict carries every field the orchestrator needs to
    persist the session row.

    Raises :class:`QuoteTokenError` on:
    * malformed token shape
    * unknown / rotated-out key generation past retention
    * HMAC mismatch
    * TTL expiry
    * ``cookie_subject_hmac`` mismatch (when caller passes one)

    Does NOT re-derive a candidate from the request body — that's
    the verify_quote_token path used by tests + the cancel endpoint.
    The create endpoint trusts the bound payload (since the MAC
    covers it) as the authoritative pipeline.
    """
    import base64

    try:
        gen_str, b64_canonical, mac_hex = token.split(".")
    except ValueError:
        raise QuoteTokenError("malformed quote token") from None
    try:
        gen = int(gen_str)
    except ValueError:
        raise QuoteTokenError("invalid quote-token generation") from None
    if gen < 0 or gen >= len(keyset.keys):
        raise QuoteTokenError("unknown quote-token key generation") from None

    pad = b"=" * (-len(b64_canonical) % 4)
    try:
        bound_canonical = base64.urlsafe_b64decode(b64_canonical.encode("ascii") + pad)
    except Exception as exc:  # noqa: BLE001
        raise QuoteTokenError(f"invalid base64 in quote token: {exc}") from None

    expected = hmac.new(keyset.keys[gen], bound_canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac_hex):
        raise QuoteTokenError("quote-token HMAC mismatch")

    bound = cast(dict, json.loads(bound_canonical))

    issued = int(bound.get("issued_at_unix_s", 0))
    ttl = int(bound.get("ttl_s", 0))
    now = now_unix_s if now_unix_s is not None else time.time()
    if issued + ttl < now:
        raise QuoteTokenError("quote token expired")

    if expected_cookie_subject_hmac is not None:
        bound_cookie_b64 = bound.get("cookie_subject_hmac", "")
        try:
            bound_cookie = base64.b64decode(bound_cookie_b64 or "")
        except Exception:  # noqa: BLE001
            raise QuoteTokenError("invalid cookie binding in token") from None
        if not hmac.compare_digest(bound_cookie, expected_cookie_subject_hmac):
            raise QuoteTokenError("quote token bound to a different cookie")

    return bound


_SINGLE_USE_PREFIX = "lwa:quote_jti:"


def _token_single_use_id(token: str) -> str | None:
    """The token's MAC (its last dot-part) — a unique single-use id.

    The MAC covers the full bound payload incl. the cookie binding and
    ``issued_at_unix_s``, so it is unique per issued token. Returns
    ``None`` for a malformed token.
    """
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return None
    return parts[2]


async def consume_quote_token_single_use(token: str, *, ttl_s: int) -> bool:
    """Atomically mark ``token`` consumed; return ``True`` on first use.

    A quote token authorizes exactly one session create. Without this a
    valid token could be replayed within its TTL to create multiple
    sessions from one quote. Uses a Redis ``SET NX EX`` keyed on the
    token's MAC.

    When Redis is unavailable the result follows ``RATE_LIMIT_FAIL_POLICY``:
    ``closed`` (the production default) refuses the use so a replay cannot
    slip past the single-use guard during an outage; ``open`` allows it,
    relying on the token's MAC, TTL and cookie binding plus the serialized
    admission gate as the remaining controls.
    """
    jti = _token_single_use_id(token)
    if jti is None:
        return False
    try:
        from app.core.rate_limit import get_redis

        r = await get_redis()
        # ``set(..., nx=True)`` returns truthy only if the key did not
        # already exist — i.e. this is the first use.
        first = await r.set(f"{_SINGLE_USE_PREFIX}{jti}", "1", ex=max(60, int(ttl_s)), nx=True)
        return bool(first)
    except Exception:
        import logging

        from app.core.config import settings

        if (settings.rate_limit_fail_policy or "").strip().lower() != "open":
            logging.getLogger(__name__).warning("quote-token single-use store unavailable; refusing (fail-closed)")
            return False
        logging.getLogger(__name__).warning("quote-token single-use store unavailable; allowing (fail-open)")
        return True


def verify_quote_token(
    token: str,
    *,
    keyset: QuoteTokenKeySet,
    candidate: QuoteTokenPayload,
    now_unix_s: float | None = None,
) -> None:
    """Verify ``token`` against ``candidate``.

    Wraps :func:`decode_quote_token` and additionally asserts the
    bound canonical bytes match what re-canonicalising ``candidate``
    produces — i.e., every field the SPA sent in the create-endpoint
    body equals what the quote endpoint signed.

    Raises :class:`QuoteTokenError` on the same conditions as
    :func:`decode_quote_token`, plus the bound-payload mismatch.
    """
    import base64

    # Decode + validate MAC + TTL + (no) cookie binding.
    bound = decode_quote_token(
        token,
        keyset=keyset,
        now_unix_s=now_unix_s,
    )

    # Re-canonicalise the candidate and compare bytes.
    candidate_canonical = canonical_quote_payload(candidate)
    # Re-extract the bound canonical from the token for the byte compare.
    gen_str, b64_canonical, _mac_hex = token.split(".")
    pad = b"=" * (-len(b64_canonical) % 4)
    bound_canonical = base64.urlsafe_b64decode(b64_canonical.encode("ascii") + pad)
    if bound_canonical != candidate_canonical:
        raise QuoteTokenError("quote-token bound payload differs from request")
    # Touch ``bound`` so static analysers don't flag the variable.
    _ = bound


# --------------------------------------------------------------------
# Cross-replica key handoff decision.
# --------------------------------------------------------------------


from typing import Literal

from app.core.config import settings

VerifyAction = Literal[
    "verify_in_memory",  # generation is known to this replica; do the HMAC check.
    "wait_for_propagation",  # generation is unknown but rotation may still be in flight.
    "fallback_db_read",  # propagation window elapsed; do a synchronous DB lookup.
    "unavailable_503",  # DB fallback exceeded its budget; surface 503.
]


def decide_quote_token_verify_action(
    *,
    token_generation: int,
    in_memory_generations: tuple[int, ...],
    rotation_started_at_unix_s: float | None,
    db_fallback_started_at_unix_s: float | None = None,
    now_unix_s: float | None = None,
) -> VerifyAction:
    """Pick the next verify-path action given the current state.

    The replica's verify path is a small state machine:

    * If the token's generation is loaded in memory ⇒ ``verify_in_memory``.
    * If a rotation was inserted *recently* (within the propagation
      window) but this replica hasn't refreshed yet ⇒ ``wait_for_propagation``.
    * Past the propagation window ⇒ ``fallback_db_read``, which does a
      synchronous read against the replica's primary; bounded by
      ``ANONYMIZE_QUOTE_TOKEN_VERIFY_DB_FALLBACK_TIMEOUT_S``.
    * If the DB fallback also exceeds its budget ⇒ ``unavailable_503``.
    """
    if token_generation in in_memory_generations:
        return "verify_in_memory"

    now = now_unix_s if now_unix_s is not None else time.time()

    if rotation_started_at_unix_s is not None:
        propagation_s = float(settings.anonymize_quote_token_key_rotation_propagation_s)
        if propagation_s > 0 and (now - rotation_started_at_unix_s) < propagation_s:
            return "wait_for_propagation"

    if db_fallback_started_at_unix_s is None:
        return "fallback_db_read"

    timeout_s = float(settings.anonymize_quote_token_verify_db_fallback_timeout_s)
    if (now - db_fallback_started_at_unix_s) >= timeout_s:
        return "unavailable_503"
    return "fallback_db_read"


# --------------------------------------------------------------------
# Quote-token keyset loader + startup canary.
# --------------------------------------------------------------------


import base64 as _b64


class QuoteTokenKeysetUnconfiguredError(RuntimeError):
    """Raised when the HMAC key bundle is missing or malformed at startup."""


def load_quote_token_keyset() -> "QuoteTokenKeySet | None":
    """Decode ``ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET`` into a keyset.

    The setting holds one or more 44-character urlsafe-base64 entries
    (the same format ``cryptography.fernet.Fernet.generate_key()``
    produces). We base64-decode each to a 32-byte raw HMAC-SHA256
    key — using the Fernet key tooling for rotation hygiene without
    needing Fernet's encrypt-then-MAC machinery for the HMAC itself.

    Returns ``None`` when the setting is unset/blank — the caller
    decides whether to refuse to start.
    """
    from .crypto import parse_fernet_bundle_config

    raw = str(settings.anonymize_quote_token_hmac_key_fernet or "").strip()
    if not raw:
        return None
    encoded = parse_fernet_bundle_config(raw)
    if not encoded:
        return None
    decoded: list[bytes] = []
    for entry in encoded:
        try:
            material = _b64.urlsafe_b64decode(entry)
        except Exception as exc:  # noqa: BLE001
            raise QuoteTokenKeysetUnconfiguredError(
                f"ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET entry is not valid base64: {exc}"
            ) from exc
        if len(material) != 32:
            raise QuoteTokenKeysetUnconfiguredError(
                f"each quote-token HMAC key must decode to 32 bytes; got {len(material)}"
            )
        decoded.append(material)
    return QuoteTokenKeySet(
        keys=tuple(decoded),
        active_generation=0,
    )


def assert_quote_token_keyset_loadable() -> QuoteTokenKeySet:
    """Startup gate.

    Refuses to start when the quote-token HMAC key is unset or
    malformed: no quote endpoint can sign tokens without it, so the
    failure mode is "every request 503s" rather than "starts up but
    can't sign". Returns the loaded keyset on success.
    """
    keyset = load_quote_token_keyset()
    if keyset is None:
        raise QuoteTokenKeysetUnconfiguredError(
            "ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET is unset. Generate "
            "one with cryptography.fernet.Fernet.generate_key() and "
            "set the env var to the base64 value (or a comma-separated "
            "list during rotation)."
        )
    return keyset


# --------------------------------------------------------------------
# Key-generations DB index + cross-replica fallback.
# --------------------------------------------------------------------


def _fingerprint_key_material(key_bytes: bytes) -> str:
    """Return SHA-256 hex fingerprint of an HMAC key.

    The fingerprint is what the ``anonymize_quote_token_key_generations``
    table stores; the raw key material never reaches the DB.
    """
    import hashlib

    return hashlib.sha256(bytes(key_bytes)).hexdigest()


async def register_quote_token_generation(
    db: AsyncSession,
    *,
    generation: int,
    key_bytes: bytes,
) -> None:
    """Upsert a row in ``anonymize_quote_token_key_generations``.

    Called by the rotation tick when the quote-token HMAC key
    rotates so other replicas can resolve the new generation via
    :func:`lookup_key_generation_via_db`.

    The schema enforces ``UNIQUE(key_fingerprint_hex)`` — one row per
    key material, regardless of how many "rotation events" reference
    it. The recurring rotation tick fires every cadence interval
    even when the operator hasn't actually rotated the underlying
    Fernet bundle (the tick only records the *event*; the key swap
    is the operator's job). To stay idempotent across those no-op
    rotation events, we check the fingerprint first: if it's
    already registered, the rotation is a no-op for this table.
    """
    from sqlalchemy import select

    from app.models.anonymize_session import (
        AnonymizeQuoteTokenKeyGeneration,
    )

    fingerprint = _fingerprint_key_material(key_bytes)
    # Fingerprint-first lookup. If the same key material is already
    # registered under any generation, nothing to do — the replica
    # verify path resolves the in-memory key against that prior
    # generation row just fine.
    stmt = select(AnonymizeQuoteTokenKeyGeneration).where(
        AnonymizeQuoteTokenKeyGeneration.key_fingerprint_hex == fingerprint,
    )
    by_fingerprint = (await db.execute(stmt)).scalar_one_or_none()
    if by_fingerprint is not None:
        return

    # Fingerprint is new (genuine rotation event). Reconcile against
    # any pre-existing row at the same generation number (extremely
    # unlikely — generation is ``int(time.time())`` from the tick).
    stmt = select(AnonymizeQuoteTokenKeyGeneration).where(
        AnonymizeQuoteTokenKeyGeneration.generation == generation,
    )
    by_generation = (await db.execute(stmt)).scalar_one_or_none()
    if by_generation is None:
        db.add(
            AnonymizeQuoteTokenKeyGeneration(
                generation=generation,
                key_fingerprint_hex=fingerprint,
            )
        )
    else:
        by_generation.key_fingerprint_hex = fingerprint


async def lookup_key_generation_via_db(
    db: AsyncSession,
    *,
    generation: int,
) -> str | None:
    """Return the registered fingerprint for ``generation``.

    Used by the replica's verify path when the in-memory keyset
    doesn't carry the token's generation: the synchronous DB read
    confirms the generation exists, the local Fernet bundle then
    decides whether it has the matching key. Returns ``None`` when
    the generation is unknown to the deployment (the verify path
    surfaces 503 quote_token_verify_unavailable).
    """
    from sqlalchemy import select

    from app.models.anonymize_session import (
        AnonymizeQuoteTokenKeyGeneration,
    )

    stmt = select(AnonymizeQuoteTokenKeyGeneration).where(
        AnonymizeQuoteTokenKeyGeneration.generation == generation,
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        return None
    return row.key_fingerprint_hex


__all__ = [
    "QuoteTokenKeySet",
    "QuoteTokenPayload",
    "QuoteTokenError",
    "QuoteTokenKeysetUnconfiguredError",
    "VerifyAction",
    "canonical_quote_payload",
    "sign_quote_token",
    "verify_quote_token",
    "consume_quote_token_single_use",
    "register_quote_token_generation",
    "lookup_key_generation_via_db",
    "decode_quote_token",
    "decide_quote_token_verify_action",
    "load_quote_token_keyset",
    "assert_quote_token_keyset_loadable",
]
