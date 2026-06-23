# SPDX-License-Identifier: MIT
"""Destination-reuse detection — keyed-BLAKE2b survives redaction.

 (initial design) (response normalization +
rate-limit) (bounded-retention key set) (sentinel
internal-consistency).

The hash is non-reversible without the key, so a DB leak alone does
not let an attacker test arbitrary candidate addresses against the
historical set. Rotated-out keys are purged on schedule so
historical hashes become uncomputable past retention.
"""

from __future__ import annotations

import hashlib
import hmac

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import AnonymizeSession

from .metadata import REUSE_DETECTION_SENTINEL


class ReuseDetectionKeySet:
    """Ordered set of reuse-detection keys.

    Index 0 is the active (signing) key. Lookups try every key in
    order so historical hashes remain matchable until their key is
    purged. ``generation`` is the small integer recorded per row in
    ``destination_reuse_key_generation`` so the purge pass can target
    columns whose generating key has been retired.
    """

    def __init__(self, keys: list[bytes], active_generation: int = 0) -> None:
        if not keys:
            raise ValueError("at least one reuse-detection key is required")
        for i, k in enumerate(keys):
            if len(k) != 32:
                raise ValueError(f"reuse-detection key #{i} must be 32 bytes")
        self._keys = list(keys)
        self._active_generation = active_generation

    @property
    def active_generation(self) -> int:
        return self._active_generation

    @property
    def active_key(self) -> bytes:
        return self._keys[0]

    def hash_active(self, address: str) -> bytes:
        """Hash with the active key. Used at session-create."""
        return _blake2b_keyed(address.encode("utf-8"), self.active_key)

    def matches_any(self, address: str, candidate_hashes: list[bytes]) -> bool:
        """Return True iff any of ``candidate_hashes`` matches the
        address under any of our currently-loaded keys.

        The caller passes the set of historical hashes (skipping
        the sentinel) and we recompute the address's hash
        under each known key.
        """
        candidate = address.encode("utf-8")
        for k in self._keys:
            h = _blake2b_keyed(candidate, k)
            for c in candidate_hashes:
                if hmac.compare_digest(h, c):
                    return True
        return False


def _blake2b_keyed(data: bytes, key: bytes) -> bytes:
    return hashlib.blake2b(data, key=key, digest_size=32).digest()


def is_sentinel(value: bytes) -> bool:
    """True iff the row's hash has been overwritten by gc on key purge."""
    return value == REUSE_DETECTION_SENTINEL


# ────────────────────────────────────────────────────────────────────
# Destination-reuse hard-block DB lookup.
# ────────────────────────────────────────────────────────────────────


async def fetch_reuse_hashes_for_destination(
    db: AsyncSession,
    *,
    candidate_address: str,
    keyset: ReuseDetectionKeySet,
) -> list[bytes]:
    """Return the historical reuse-hashes that match ``candidate_address``.

    The candidate is hashed under every loaded key generation; we
    look up each hash against ``anonymize_session.destination_address_blake2b_keyed``
    via the partial index that excludes the all-zeros
    sentinel and the soft-deleted rows.

    Returns the list of *matching* hashes (one per generation that
    matches). An empty list means "no historical reuse" — the caller
    accepts the create. A non-empty list is the hard-block path
    (normalized 422 ``destination_rejected``).
    """
    candidate_bytes = candidate_address.encode("utf-8")
    # Compute the candidate hash under every loaded key.
    candidate_hashes: list[bytes] = [
        _blake2b_keyed(candidate_bytes, k)
        for k in keyset._keys  # type: ignore[attr-defined]
    ]
    if not candidate_hashes:
        return []
    # The partial index already excludes deleted + sentinel rows.
    stmt = select(AnonymizeSession.destination_address_blake2b_keyed).where(
        AnonymizeSession.destination_address_blake2b_keyed.in_(candidate_hashes),
        AnonymizeSession.deleted_at.is_(None),
        AnonymizeSession.destination_address_blake2b_keyed != REUSE_DETECTION_SENTINEL,
    )
    result = await db.execute(stmt)
    matches = [row[0] for row in result.all()]
    return matches


async def is_destination_reused(
    db: AsyncSession,
    *,
    candidate_address: str,
    keyset: ReuseDetectionKeySet,
) -> bool:
    """Hard-block predicate: True iff any historical session matches."""
    matches = await fetch_reuse_hashes_for_destination(db, candidate_address=candidate_address, keyset=keyset)
    return bool(matches)


def load_reuse_detection_keyset() -> "ReuseDetectionKeySet | None":
    """Decode ``ANONYMIZE_REUSE_DETECTION_KEY_FERNET`` into a keyset.

    Mirrors :func:`quote_token.load_quote_token_keyset` — the setting
    holds one or more 44-character urlsafe-base64 entries that
    decode to 32-byte raw BLAKE2b keys. Returns ``None`` when the
    setting is unset/blank so the caller can decide whether to
    fail-loud at boot.
    """
    import base64

    from app.core.config import settings

    from .crypto import parse_fernet_bundle_config

    raw = str(settings.anonymize_reuse_detection_key_fernet or "").strip()
    if not raw:
        return None
    encoded = parse_fernet_bundle_config(raw)
    if not encoded:
        return None
    decoded: list[bytes] = []
    for entry in encoded:
        material = base64.urlsafe_b64decode(entry)
        if len(material) != 32:
            raise ValueError(f"each reuse-detection key must decode to 32 bytes; got {len(material)}")
        decoded.append(material)
    return ReuseDetectionKeySet(keys=decoded, active_generation=0)


__all__ = [
    "ReuseDetectionKeySet",
    "is_sentinel",
    "fetch_reuse_hashes_for_destination",
    "is_destination_reused",
    "load_reuse_detection_keyset",
]
