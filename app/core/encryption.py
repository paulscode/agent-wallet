# SPDX-License-Identifier: MIT
"""
Fernet encryption for secrets stored in the database.

Encrypts sensitive data (preimage, claim keys) at rest.
Key is derived from SECRET_KEY via PBKDF2-HMAC-SHA256.

Each encrypted value uses a random 16-byte salt, stored alongside the
ciphertext.  This ensures different derived keys per field even when
the master SECRET_KEY is shared.

Key rotation: set SECRET_KEY_PREVIOUS to the old key when rotating.
decrypt_field() will attempt the current key first, then fall back.
"""

import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

logger = logging.getLogger(__name__)

_LEGACY_KDF_SALT = b"agent-wallet:field-encryption:v1"
_KDF_ITERATIONS = 600_000
_SALT_LENGTH = 16  # 128-bit random salt per field
# Prefix byte distinguishes new (per-field salt) format from legacy
_FORMAT_V2_PREFIX = b"\x02"

# Cached legacy Fernet for fast decryption of old data
_legacy_fernet: Fernet | None = None
_legacy_prev_fernet: Fernet | None = None


def _derive_fernet(secret: str, salt: bytes) -> Fernet:
    """Derive a Fernet instance from a secret and salt."""
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode("utf-8"),
        salt,
        iterations=_KDF_ITERATIONS,
        dklen=32,
    )
    return Fernet(base64.urlsafe_b64encode(derived))


def _get_legacy_fernet(secret: str | None = None) -> Fernet:
    """Return a cached Fernet using the legacy static salt."""
    global _legacy_fernet, _legacy_prev_fernet
    if secret is None or secret == settings.secret_key:
        if _legacy_fernet is None:
            _legacy_fernet = _derive_fernet(settings.secret_key, _LEGACY_KDF_SALT)
        return _legacy_fernet
    # Previous key path
    if _legacy_prev_fernet is None:
        _legacy_prev_fernet = _derive_fernet(secret, _LEGACY_KDF_SALT)
    return _legacy_prev_fernet


def encrypt_field(plaintext: str) -> str:
    """Encrypt a plaintext string for database storage.

    Format: base64( 0x02 || 16-byte-salt || fernet_token )
    The per-field random salt ensures unique derived keys.
    """
    salt = os.urandom(_SALT_LENGTH)
    f = _derive_fernet(settings.secret_key, salt)
    token = f.encrypt(plaintext.encode("utf-8"))
    combined = base64.urlsafe_b64encode(_FORMAT_V2_PREFIX + salt + token)
    return combined.decode("utf-8")


def decrypt_field(ciphertext: str, *, _allow_static_salt: bool | None = None) -> str:
    """Decrypt a ciphertext string back to plaintext.

    Reads the v2 (per-field salt) format. The older static-salt format is
    read only when ``ALLOW_STATIC_SALT_FIELD_DECRYPTION`` is enabled (or a
    caller passes ``_allow_static_salt=True``, which the field-format
    upgrade migration uses so it can always read forward). When
    SECRET_KEY_PREVIOUS is set, falls back to the previous key. Raises
    ValueError if decryption fails with all available keys, or if a
    static-salt value is encountered while that format is disabled.
    """
    raw = base64.urlsafe_b64decode(ciphertext.encode("utf-8"))

    if raw[:1] == _FORMAT_V2_PREFIX:
        return _decrypt_v2(raw)

    allow_static_salt = (
        settings.allow_static_salt_field_decryption if _allow_static_salt is None else _allow_static_salt
    )
    if not allow_static_salt:
        raise ValueError(
            "Refusing to decrypt a static-salt field: enable ALLOW_STATIC_SALT_FIELD_DECRYPTION to read pre-v2 values."
        )
    return _decrypt_legacy(ciphertext)


def _decrypt_v2(raw: bytes) -> str:
    """Decrypt v2 format: 0x02 || salt || fernet_token."""
    salt = raw[1 : 1 + _SALT_LENGTH]
    token = raw[1 + _SALT_LENGTH :]

    # Try current key
    try:
        f = _derive_fernet(settings.secret_key, salt)
        return f.decrypt(token).decode("utf-8")
    except InvalidToken:
        pass

    # Try previous key
    prev = settings.secret_key_previous
    if prev:
        try:
            f = _derive_fernet(prev, salt)
            return f.decrypt(token).decode("utf-8")
        except InvalidToken:
            pass

    raise ValueError("Cannot decrypt field (v2). SECRET_KEY may have changed.")


def _decrypt_legacy(ciphertext: str) -> str:
    """Decrypt legacy format (static salt, bare Fernet token)."""
    token = ciphertext.encode("utf-8")

    # Try current key with legacy salt
    try:
        return _get_legacy_fernet().decrypt(token).decode("utf-8")
    except InvalidToken:
        pass

    # Try previous key with legacy salt
    prev = settings.secret_key_previous
    if prev:
        try:
            return _get_legacy_fernet(prev).decrypt(token).decode("utf-8")
        except InvalidToken:
            pass

    raise ValueError("Cannot decrypt field (legacy). SECRET_KEY may have changed.")


def re_encrypt_field(ciphertext: str) -> str | None:
    """Decrypt with any available key and re-encrypt with current key + v2 format.

    Returns the new ciphertext, or None if already in v2 format with current key.
    """
    raw = base64.urlsafe_b64decode(ciphertext.encode("utf-8"))
    if raw[:1] == _FORMAT_V2_PREFIX:
        salt = raw[1 : 1 + _SALT_LENGTH]
        token = raw[1 + _SALT_LENGTH :]
        try:
            _derive_fernet(settings.secret_key, salt).decrypt(token)
            return None  # Already encrypted with current key in v2 format
        except InvalidToken:
            pass

    # Force static-salt reads so the format upgrade always moves forward,
    # independent of the runtime ALLOW_STATIC_SALT_FIELD_DECRYPTION gate.
    plaintext = decrypt_field(ciphertext, _allow_static_salt=True)
    return encrypt_field(plaintext)
