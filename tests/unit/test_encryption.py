# SPDX-License-Identifier: MIT
"""
Unit tests for app.core.encryption — Fernet field encryption.

Covers the v2 (per-field salt) round-trip, SECRET_KEY rotation fallback,
the static-salt legacy format and its access gate, the re-encryption
upgrade path, and malformed-input error handling.
"""

import base64

import pytest
from hypothesis import example, given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st

import app.core.encryption as enc
from app.core.config import settings
from app.core.encryption import decrypt_field, encrypt_field, re_encrypt_field

# Two distinct keys that both satisfy the ≥32-char strength floor, used to
# stand in for a "current" and a rotated-away "previous" SECRET_KEY.
_KEY_A = "key-a-" + "a" * 32
_KEY_B = "key-b-" + "b" * 32


def _make_legacy(plaintext: str, key: str) -> str:
    """Build a static-salt (pre-v2) ciphertext: a bare Fernet token."""
    f = enc._derive_fernet(key, enc._LEGACY_KDF_SALT)
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


@pytest.fixture
def fresh_legacy_cache(monkeypatch):
    """Reset the module-level legacy-Fernet caches so a key change in a
    test is honored rather than served from a stale cache."""
    monkeypatch.setattr(enc, "_legacy_fernet", None)
    monkeypatch.setattr(enc, "_legacy_prev_fernet", None)


class TestEncryption:
    """Fernet encryption/decryption tests."""

    def test_round_trip(self):
        """Encrypt then decrypt returns the original plaintext."""
        plaintext = "my-secret-preimage-hex"
        encrypted = encrypt_field(plaintext)
        decrypted = decrypt_field(encrypted)
        assert decrypted == plaintext

    def test_encrypted_is_not_plaintext(self):
        """Ciphertext should not equal or contain the plaintext."""
        plaintext = "0a1b2c3d4e5f"
        encrypted = encrypt_field(plaintext)
        assert encrypted != plaintext
        assert plaintext not in encrypted

    def test_different_plaintexts_differ(self):
        """Different plaintexts produce different ciphertexts."""
        enc1 = encrypt_field("secret1")
        enc2 = encrypt_field("secret2")
        assert enc1 != enc2

    def test_same_plaintext_different_tokens(self):
        """Same plaintext encrypted twice produces different Fernet tokens (due to IV)."""
        enc1 = encrypt_field("same-text")
        enc2 = encrypt_field("same-text")
        assert enc1 != enc2  # Fernet uses random IV
        # But both decrypt to the same value
        assert decrypt_field(enc1) == decrypt_field(enc2)

    def test_tampered_ciphertext_raises(self):
        """Tampered ciphertext should raise ValueError."""
        encrypted = encrypt_field("test")
        tampered = encrypted[:-5] + "XXXXX"
        with pytest.raises(ValueError, match="Cannot decrypt"):
            decrypt_field(tampered)

    def test_empty_string(self):
        """Empty string can be encrypted and decrypted."""
        encrypted = encrypt_field("")
        assert decrypt_field(encrypted) == ""

    def test_unicode(self):
        """Unicode strings can be encrypted and decrypted."""
        plaintext = "Hello 🌍! Ñoño €100"
        encrypted = encrypt_field(plaintext)
        assert decrypt_field(encrypted) == plaintext

    def test_long_string(self):
        """Long strings (hex keys) work correctly."""
        plaintext = "a" * 512
        encrypted = encrypt_field(plaintext)
        assert decrypt_field(encrypted) == plaintext

    def test_garbage_input_raises(self):
        """Completely invalid ciphertext raises ValueError."""
        with pytest.raises((ValueError, Exception)):
            decrypt_field("not-a-fernet-token")


class TestRoundTripProperty:
    """Property: decrypt(encrypt(x)) == x for arbitrary text.

    Bounded example count because each example runs two 600k-iteration
    PBKDF2 derivations; the @example pins keep the historically tricky
    inputs (empty, multibyte unicode) covered every run.
    """

    @hyp_settings(max_examples=20)
    @given(st.text())
    @example("")
    @example("Hello 🌍! Ñoño €100")
    @example("a" * 1024)
    def test_encrypt_decrypt_roundtrip(self, plaintext):
        assert decrypt_field(encrypt_field(plaintext)) == plaintext


class TestKeyRotation:
    """v2 decryption falls back to SECRET_KEY_PREVIOUS after rotation."""

    def test_decrypts_with_previous_key_after_rotation(self, monkeypatch):
        """A value sealed under the old key decrypts once that key is set
        as SECRET_KEY_PREVIOUS and a new SECRET_KEY is in place."""
        monkeypatch.setattr(settings, "secret_key", _KEY_A)
        monkeypatch.setattr(settings, "secret_key_previous", None)
        sealed = encrypt_field("rotated-secret")

        # Rotate: new current key, old key demoted to previous.
        monkeypatch.setattr(settings, "secret_key", _KEY_B)
        monkeypatch.setattr(settings, "secret_key_previous", _KEY_A)

        assert decrypt_field(sealed) == "rotated-secret"

    def test_current_key_preferred_over_previous(self, monkeypatch):
        """A value sealed under the current key decrypts without consulting
        the previous key."""
        monkeypatch.setattr(settings, "secret_key", _KEY_B)
        monkeypatch.setattr(settings, "secret_key_previous", _KEY_A)
        sealed = encrypt_field("fresh-secret")
        assert decrypt_field(sealed) == "fresh-secret"

    def test_raises_when_no_key_matches(self, monkeypatch):
        """With neither current nor a (set-but-wrong) previous key matching,
        v2 decryption raises rather than returning garbage."""
        monkeypatch.setattr(settings, "secret_key", _KEY_A)
        monkeypatch.setattr(settings, "secret_key_previous", None)
        sealed = encrypt_field("orphaned")

        # A previous key is configured but is also wrong — exercises the
        # previous-key attempt before the final raise.
        monkeypatch.setattr(settings, "secret_key", _KEY_B)
        monkeypatch.setattr(settings, "secret_key_previous", "wrong-" + "w" * 32)
        with pytest.raises(ValueError, match="v2"):
            decrypt_field(sealed)


class TestLegacyFormat:
    """Static-salt (pre-v2) values, the access gate, and key fallback."""

    def test_legacy_decrypts_with_current_key_when_param_allows(self, fresh_legacy_cache, monkeypatch):
        monkeypatch.setattr(settings, "secret_key", _KEY_A)
        monkeypatch.setattr(settings, "secret_key_previous", None)
        legacy = _make_legacy("old-format", _KEY_A)
        assert decrypt_field(legacy, _allow_static_salt=True) == "old-format"

    def test_legacy_decrypts_when_settings_gate_open(self, fresh_legacy_cache, monkeypatch):
        monkeypatch.setattr(settings, "secret_key", _KEY_A)
        monkeypatch.setattr(settings, "secret_key_previous", None)
        monkeypatch.setattr(settings, "allow_static_salt_field_decryption", True)
        legacy = _make_legacy("old-format", _KEY_A)
        assert decrypt_field(legacy) == "old-format"

    def test_legacy_refused_when_gate_closed(self, fresh_legacy_cache, monkeypatch):
        monkeypatch.setattr(settings, "secret_key", _KEY_A)
        monkeypatch.setattr(settings, "allow_static_salt_field_decryption", False)
        legacy = _make_legacy("old-format", _KEY_A)
        with pytest.raises(ValueError, match="Refusing to decrypt a static-salt field"):
            decrypt_field(legacy)

    def test_legacy_decrypts_with_previous_key(self, fresh_legacy_cache, monkeypatch):
        monkeypatch.setattr(settings, "secret_key", _KEY_B)
        monkeypatch.setattr(settings, "secret_key_previous", _KEY_A)
        legacy = _make_legacy("old-format", _KEY_A)
        assert decrypt_field(legacy, _allow_static_salt=True) == "old-format"

    def test_legacy_raises_when_no_key_matches(self, fresh_legacy_cache, monkeypatch):
        # Previous key configured but wrong — exercises the previous-key
        # attempt in the legacy path before the final raise.
        monkeypatch.setattr(settings, "secret_key", _KEY_B)
        monkeypatch.setattr(settings, "secret_key_previous", "wrong-" + "w" * 32)
        legacy = _make_legacy("old-format", _KEY_A)
        with pytest.raises(ValueError, match="legacy"):
            decrypt_field(legacy, _allow_static_salt=True)


class TestReEncrypt:
    """re_encrypt_field upgrades values to v2-under-current-key."""

    def test_already_v2_current_returns_none(self, monkeypatch):
        monkeypatch.setattr(settings, "secret_key", _KEY_A)
        monkeypatch.setattr(settings, "secret_key_previous", None)
        sealed = encrypt_field("already-current")
        assert re_encrypt_field(sealed) is None

    def test_legacy_upgraded_to_v2(self, fresh_legacy_cache, monkeypatch):
        monkeypatch.setattr(settings, "secret_key", _KEY_A)
        monkeypatch.setattr(settings, "secret_key_previous", None)
        # Gate is closed; re_encrypt_field must still read forward.
        monkeypatch.setattr(settings, "allow_static_salt_field_decryption", False)
        legacy = _make_legacy("upgrade-me", _KEY_A)

        upgraded = re_encrypt_field(legacy)
        assert upgraded is not None
        raw = base64.urlsafe_b64decode(upgraded.encode("utf-8"))
        assert raw[:1] == enc._FORMAT_V2_PREFIX
        assert decrypt_field(upgraded) == "upgrade-me"

    def test_v2_under_previous_key_reencrypted_to_current(self, monkeypatch):
        monkeypatch.setattr(settings, "secret_key", _KEY_A)
        monkeypatch.setattr(settings, "secret_key_previous", None)
        sealed_old = encrypt_field("migrate-me")

        monkeypatch.setattr(settings, "secret_key", _KEY_B)
        monkeypatch.setattr(settings, "secret_key_previous", _KEY_A)
        upgraded = re_encrypt_field(sealed_old)
        assert upgraded is not None

        # The upgraded value decrypts under the current key with no previous
        # key configured — i.e. it was genuinely re-sealed, not passed through.
        monkeypatch.setattr(settings, "secret_key_previous", None)
        assert decrypt_field(upgraded) == "migrate-me"


class TestErrorPaths:
    """Malformed inputs surface as ValueError, never silent corruption."""

    def test_malformed_base64_raises(self):
        with pytest.raises((ValueError, Exception)):
            decrypt_field("@@@not-base64@@@")

    def test_legacy_fernet_cache_returns_stable_instances(self, fresh_legacy_cache, monkeypatch):
        """The current- and previous-key legacy Fernets are cached and
        distinct from each other."""
        monkeypatch.setattr(settings, "secret_key", _KEY_A)
        first = enc._get_legacy_fernet()
        assert enc._get_legacy_fernet() is first  # cached
        prev = enc._get_legacy_fernet(_KEY_B)
        assert prev is not first
        assert enc._get_legacy_fernet(_KEY_B) is prev  # cached
