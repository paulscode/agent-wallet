# SPDX-License-Identifier: MIT
"""N-key MultiFernet bundle wrapper."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet, InvalidToken

from app.services.anonymize.crypto import (
    MultiFernetBundle,
    parse_fernet_bundle_config,
)


def _key() -> bytes:
    return Fernet.generate_key()


def test_bundle_requires_at_least_one_key() -> None:
    with pytest.raises(ValueError, match="at least one"):
        MultiFernetBundle(keys=())


def test_bundle_rejects_short_key() -> None:
    with pytest.raises(ValueError, match="44-byte"):
        MultiFernetBundle(keys=(b"too-short",))


def test_encrypt_decrypt_roundtrips_under_active_key() -> None:
    k = _key()
    bundle = MultiFernetBundle(keys=(k,))
    ct = bundle.encrypt(b"secret destination")
    assert bundle.decrypt(ct) == b"secret destination"


def test_decrypt_succeeds_after_rotation() -> None:
    """A row encrypted under the old key still decrypts after the
    rotation prepends a new active key."""
    old = _key()
    new = _key()
    pre = MultiFernetBundle(keys=(old,))
    ct = pre.encrypt(b"secret")
    # Operator rotates: new becomes active, old slides to index 1.
    post = MultiFernetBundle(keys=(new, old))
    assert post.decrypt(ct) == b"secret"


def test_decrypt_fails_when_no_key_admits_ciphertext() -> None:
    foreign = MultiFernetBundle(keys=(_key(),))
    ct_foreign = foreign.encrypt(b"x")
    other = MultiFernetBundle(keys=(_key(),))  # different key
    with pytest.raises(InvalidToken):
        other.decrypt(ct_foreign)


def test_rotate_brings_old_ciphertext_forward_to_active_key() -> None:
    old = _key()
    new = _key()
    pre = MultiFernetBundle(keys=(old,))
    ct = pre.encrypt(b"secret")
    post = MultiFernetBundle(keys=(new, old))
    rotated = post.rotate(ct)
    # Rotated ciphertext decrypts under both bundles…
    assert post.decrypt(rotated) == b"secret"
    # …but it no longer needs the old key (encrypts under the new one).
    new_only = MultiFernetBundle(keys=(new,))
    assert new_only.decrypt(rotated) == b"secret"


def test_parse_config_returns_empty_for_blank_input() -> None:
    assert parse_fernet_bundle_config("") == ()
    assert parse_fernet_bundle_config("   ") == ()
    assert parse_fernet_bundle_config(None) == ()  # type: ignore[arg-type]


def test_parse_config_supports_single_key() -> None:
    k = _key()
    out = parse_fernet_bundle_config(k.decode())
    assert out == (k,)


def test_parse_config_supports_comma_separated_list() -> None:
    a = _key()
    b = _key()
    c = _key()
    raw = f"{a.decode()}, {b.decode()}, {c.decode()}"
    out = parse_fernet_bundle_config(raw)
    assert out == (a, b, c)


def test_parse_config_rejects_via_bundle_construction() -> None:
    """Garbage in the config produces a usable bundle only when valid."""
    out = parse_fernet_bundle_config("invalid-key,another-bad-one")
    # The parser does NOT validate length — that's the bundle's job —
    # so the construction step is what surfaces the error.
    with pytest.raises(ValueError):
        MultiFernetBundle(keys=out)
