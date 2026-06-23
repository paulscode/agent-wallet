# SPDX-License-Identifier: MIT
"""Encryption helpers for anonymize sensitive columns.

Uses ``MultiFernet(FERNET_KEYS)``
on ``destination_address_enc`` plus a startup canary-decrypt that
refuses to start the anonymize service if any rotated-out key has
gone missing.

The existing project-wide ``app.core.encryption`` already implements
a 2-key rotation (``SECRET_KEY`` + ``SECRET_KEY_PREVIOUS``) with
per-field salt, which is functionally equivalent to a 2-element
MultiFernet. A "MultiFernet with arbitrary key list" is a
generalization; until the operator-runbook step that introduces
N-key rotation lands, we ride on the project-wide pair via thin
wrappers so the anonymize call sites can switch to a richer key set
later without re-encrypting any data.

Three responsibilities:

* :func:`encrypt_destination_address` / :func:`decrypt_destination_address`
  — round-trip the destination address. The ciphertext is bytes; the
  ORM column is ``BYTEA``.
* :func:`redact_destination_address` — overwrite a row's ciphertext
  with the ``<redacted>`` sentinel post-retention.
* :func:`run_canary_decrypt` — the startup gate. Stores a known
  plaintext on first run, then refuses to start subsequent runs if
  decryption fails (would imply the active key set lost a generation).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.encryption import decrypt_field, encrypt_field
from app.models.anonymize_session import AnonymizeSettings

# Sentinel ciphertext written by gc.py once the destination-retention
# window expires. Reads of this value MUST NOT attempt to decrypt —
# the plaintext is gone.
DESTINATION_REDACTED_SENTINEL: bytes = b"<redacted>"


# Singleton key used to anchor the canary value in ``anonymize_settings``.
_CANARY_KEY: str = "crypto_canary"
# Plaintext we write under the canary key. The exact bytes are not
# load-bearing — startup just needs to round-trip whatever was written.
_CANARY_PLAINTEXT: str = "anonymize-canary-v1"


class CryptoCanaryError(RuntimeError):
    """Raised when the startup canary-decrypt fails."""


def encrypt_destination_address(plaintext: str) -> bytes:
    """Encrypt ``plaintext`` for storage in ``destination_address_enc``."""
    if not isinstance(plaintext, str) or not plaintext:
        raise ValueError("destination address must be a non-empty string")
    # ``encrypt_field`` returns a urlsafe-base64 string token. We wrap
    # it as raw bytes for the BYTEA column so a future migration to a
    # binary-only Fernet bundle is a column-write change, not an API
    # change.
    return encrypt_field(plaintext).encode("ascii")


def decrypt_destination_address(ciphertext: bytes) -> str:
    """Decrypt ``ciphertext`` to the original address.

    Raises :class:`ValueError` if the ciphertext is the post-retention
    redacted sentinel (the caller should check
    :func:`is_redacted_destination` first when retention may have
    fired).
    """
    if ciphertext == DESTINATION_REDACTED_SENTINEL:
        raise ValueError("destination address has been retention-redacted")
    return decrypt_field(ciphertext.decode("ascii"))


def is_redacted_destination(ciphertext: bytes) -> bool:
    """True iff the ciphertext is the post-retention sentinel."""
    return ciphertext == DESTINATION_REDACTED_SENTINEL


def redact_destination_address() -> bytes:
    """Return the sentinel ciphertext gc.py writes on retention expiry."""
    return DESTINATION_REDACTED_SENTINEL


async def run_canary_decrypt(db: AsyncSession) -> None:
    """Startup gate: round-trip a canary plaintext through encrypt + decrypt.

    On first ever run, writes the canary row. On subsequent runs,
    reads + decrypts; failure raises :class:`CryptoCanaryError` and
    the lifespan refuses to start the anonymize service.

    The goal is to catch a key-rotation accident *before* it silently
    bricks every active session at first read.
    """
    result = await db.execute(select(AnonymizeSettings).where(AnonymizeSettings.key == _CANARY_KEY))
    row = result.scalar_one_or_none()

    if row is None:
        # First run: create the canary row.
        ciphertext = encrypt_destination_address(_CANARY_PLAINTEXT)
        # JSONB value: store ciphertext as a base64-decoded ASCII so
        # the JSONB column round-trips without a binary-encoding step.
        new_row = AnonymizeSettings(
            key=_CANARY_KEY,
            value={
                "ciphertext_b64": ciphertext.decode("ascii"),
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
            set_at=datetime.now(timezone.utc),
        )
        db.add(new_row)
        await db.commit()
        return

    # Subsequent run: decrypt + verify.
    try:
        ct = row.value.get("ciphertext_b64", "")
        if not ct:
            raise CryptoCanaryError("canary row is malformed (missing ciphertext)")
        plaintext = decrypt_destination_address(ct.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 — we want a clear error
        raise CryptoCanaryError(
            "anonymize crypto canary failed to decrypt — the active "
            "SECRET_KEY (and SECRET_KEY_PREVIOUS, if set) cannot read "
            "the previously-written canary row. Check that key rotation "
            "preserved the prior key. Refusing to start the anonymize "
            "service to avoid silently bricking existing sessions."
        ) from exc

    if plaintext != _CANARY_PLAINTEXT:
        raise CryptoCanaryError(f"anonymize crypto canary plaintext mismatch (got {plaintext!r})")


# --------------------------------------------------------------------
# N-key MultiFernet bundle.
# --------------------------------------------------------------------


from dataclasses import dataclass

from cryptography.fernet import Fernet, MultiFernet


@dataclass
class MultiFernetBundle:
    """Ordered N-key Fernet bundle.

    Encryption always uses the *active* (first) key. Decryption tries
    every key in order so rotation never breaks an in-flight row.
    Rotated-out keys past their retention horizon are purged
    externally; this wrapper only manages the
    encrypt/decrypt round-trip.

    Use this for any new at-rest column whose retention horizon is
    independent of ``SECRET_KEY``'s 2-key rotation cadence.
    """

    keys: tuple[bytes, ...]
    active_generation: int = 0

    def __post_init__(self) -> None:
        if not self.keys:
            raise ValueError("at least one Fernet key is required")
        for i, k in enumerate(self.keys):
            if len(k) != 44:
                raise ValueError(
                    f"Fernet key #{i} must be a 44-byte urlsafe-base64 string (produced by Fernet.generate_key())"
                )
        # MultiFernet's encrypt method uses keys[0] for new
        # ciphertext; decrypt walks the list. We bind once for reuse.
        self._mf = MultiFernet([Fernet(k) for k in self.keys])

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt under the active key."""
        return self._mf.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt with whichever key in the bundle still admits ``ciphertext``.

        Raises :class:`cryptography.fernet.InvalidToken` when no key
        admits the ciphertext (the caller routes the session to
        ``awaiting_reconciliation`` and surfaces a CRITICAL log line).
        """
        return self._mf.decrypt(ciphertext)

    def rotate(self, ciphertext: bytes) -> bytes:
        """Re-encrypt ``ciphertext`` under the active key.

        Used by the rotation task to bring rows generated under a
        retired key forward to the new active key.
        """
        return self._mf.rotate(ciphertext)


def parse_fernet_bundle_config(value: str) -> tuple[bytes, ...]:
    """Parse a comma-separated Fernet key bundle from config.

    Supports both a single key (legacy) and a comma-separated list
    (the N-key form). Keys are urlsafe-base64 strings as produced
    by ``cryptography.fernet.Fernet.generate_key()``.

    Returns an empty tuple when the input is empty/blank — the
    caller decides whether to refuse to start.
    """
    raw = (value or "").strip()
    if not raw:
        return ()
    out: list[bytes] = []
    for part in raw.split(","):
        s = part.strip()
        if not s:
            continue
        out.append(s.encode("ascii"))
    return tuple(out)


__all__ = [
    "DESTINATION_REDACTED_SENTINEL",
    "CryptoCanaryError",
    "MultiFernetBundle",
    "encrypt_destination_address",
    "decrypt_destination_address",
    "is_redacted_destination",
    "redact_destination_address",
    "run_canary_decrypt",
    "parse_fernet_bundle_config",
]
