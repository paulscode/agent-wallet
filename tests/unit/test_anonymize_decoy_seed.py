# SPDX-License-Identifier: MIT
"""Anonymize-decoy seed (on-chain self-source)."""

from __future__ import annotations

from uuid import UUID

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.services.anonymize.decoy_seed import (
    DECOY_CANARY_SESSION_ACCOUNT,
    DecoyDerivationPath,
    DecoySeedError,
    assert_decoy_seed_configured,
    derive_session_account,
    is_decoy_seed_required,
    load_decoy_seed_bundle,
    make_canary_path,
    make_derivation_path,
)

_ACCOUNT_KEY = b"\xaa" * 32
_OTHER_KEY = b"\xbb" * 32
_SESSION_A = UUID("11111111-1111-1111-1111-111111111111")
_SESSION_B = UUID("22222222-2222-2222-2222-222222222222")


def test_session_account_is_deterministic() -> None:
    a = derive_session_account(_SESSION_A, account_key=_ACCOUNT_KEY)
    b = derive_session_account(_SESSION_A, account_key=_ACCOUNT_KEY)
    assert a == b


def test_session_account_changes_with_session_id() -> None:
    a = derive_session_account(_SESSION_A, account_key=_ACCOUNT_KEY)
    b = derive_session_account(_SESSION_B, account_key=_ACCOUNT_KEY)
    assert a != b


def test_session_account_changes_with_account_key() -> None:
    """Without the account key, an attacker cannot enumerate accounts."""
    a = derive_session_account(_SESSION_A, account_key=_ACCOUNT_KEY)
    b = derive_session_account(_SESSION_A, account_key=_OTHER_KEY)
    assert a != b


def test_session_account_below_canary_sentinel() -> None:
    """The derivation must never collide with the canary sentinel."""
    for i in range(100):
        sid = UUID(int=i + 0x42)
        out = derive_session_account(sid, account_key=_ACCOUNT_KEY)
        assert out != DECOY_CANARY_SESSION_ACCOUNT
        assert 0 <= out < (2**31)


def test_short_account_key_rejected() -> None:
    with pytest.raises(DecoySeedError, match="at least 16 bytes"):
        derive_session_account(_SESSION_A, account_key=b"short")


def test_make_derivation_path_assembles_bip86() -> None:
    p = make_derivation_path(
        session_id=_SESSION_A,
        derivation_index=7,
        account_key=_ACCOUNT_KEY,
    )
    assert isinstance(p, DecoyDerivationPath)
    assert p.derivation_index == 7
    # Path string has the BIP-86 prefix.
    s = p.to_bip86_path()
    assert s.startswith("m/86'/")
    assert "/7" in s


def test_make_derivation_path_rejects_negative_index() -> None:
    with pytest.raises(DecoySeedError, match="non-negative"):
        make_derivation_path(
            session_id=_SESSION_A,
            derivation_index=-1,
            account_key=_ACCOUNT_KEY,
        )


def test_make_canary_path_uses_sentinel_account() -> None:
    p = make_canary_path()
    assert p.session_account == DECOY_CANARY_SESSION_ACCOUNT
    assert p.derivation_index == 0


def test_is_decoy_seed_required_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_decoy_seed_required", True)
    assert is_decoy_seed_required() is True
    monkeypatch.setattr(settings, "anonymize_decoy_seed_required", False)
    assert is_decoy_seed_required() is False


def test_load_bundle_returns_none_when_unset(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_decoy_seed_fernet", "")
    assert load_decoy_seed_bundle() is None


def test_load_bundle_returns_multifernet_when_configured(monkeypatch) -> None:
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "anonymize_decoy_seed_fernet", key)
    bundle = load_decoy_seed_bundle()
    assert bundle is not None
    # Round-trip something.
    ct = bundle.encrypt(b"secret-seed")
    assert bundle.decrypt(ct) == b"secret-seed"


def test_assert_decoy_seed_configured_raises_when_required_but_missing(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_decoy_seed_required", True)
    monkeypatch.setattr(settings, "anonymize_decoy_seed_fernet", "")
    with pytest.raises(DecoySeedError, match="ANONYMIZE_DECOY_SEED_FERNET"):
        assert_decoy_seed_configured()


def test_assert_decoy_seed_configured_passes_when_required_and_set(monkeypatch) -> None:
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "anonymize_decoy_seed_required", True)
    monkeypatch.setattr(settings, "anonymize_decoy_seed_fernet", key)
    assert_decoy_seed_configured()


def test_assert_decoy_seed_configured_logs_when_regression_opted_in(
    monkeypatch,
    caplog,
) -> None:
    monkeypatch.setattr(settings, "anonymize_decoy_seed_required", False)
    monkeypatch.setattr(settings, "anonymize_decoy_seed_fernet", "")
    with caplog.at_level("CRITICAL"):
        assert_decoy_seed_configured()  # no raise
    assert any("residual #30" in r.message for r in caplog.records)


# ── Canary collision sentinel ───────────────────────────────────


def test_canary_session_account_is_reserved_sentinel() -> None:
    """The sentinel is exactly 2**31 - 1."""
    from app.services.anonymize.decoy_seed import (
        DECOY_CANARY_SESSION_ACCOUNT,
    )

    assert DECOY_CANARY_SESSION_ACCOUNT == (2**31) - 1


def test_derive_session_account_never_returns_canary_sentinel() -> None:
    """A regular session_id must never collide with the canary."""
    from uuid import UUID

    from app.services.anonymize.decoy_seed import (
        DECOY_CANARY_SESSION_ACCOUNT,
        derive_session_account,
    )

    # Try many session ids; none should land on the sentinel.
    seen_sentinel = False
    for i in range(1000):
        sid = UUID(int=i * 7919 + 1)
        acct = derive_session_account(sid, account_key=b"key" + (b"\x00" * 16))
        if acct == DECOY_CANARY_SESSION_ACCOUNT:
            seen_sentinel = True
            break
    assert not seen_sentinel


def test_detect_canary_collision_false_on_fresh_deploy() -> None:
    from app.services.anonymize.decoy_seed import detect_canary_collision

    assert (
        detect_canary_collision(
            observed_canary_address=None,
            freshly_derived_canary_address="bcrt1qfresh",
        )
        is False
    )


def test_detect_canary_collision_false_on_identical_seed() -> None:
    from app.services.anonymize.decoy_seed import detect_canary_collision

    assert (
        detect_canary_collision(
            observed_canary_address="bcrt1qsame",
            freshly_derived_canary_address="bcrt1qsame",
        )
        is False
    )


def test_detect_canary_collision_true_on_mismatched_seed() -> None:
    from app.services.anonymize.decoy_seed import detect_canary_collision

    assert (
        detect_canary_collision(
            observed_canary_address="bcrt1qold",
            freshly_derived_canary_address="bcrt1qnew",
        )
        is True
    )


def test_assert_no_canary_collision_passes_when_clean() -> None:
    from app.services.anonymize.decoy_seed import assert_no_canary_collision

    assert_no_canary_collision(
        observed_canary_address=None,
        freshly_derived_canary_address="bcrt1qx",
    )


def test_assert_no_canary_collision_raises_with_runbook_pointer() -> None:
    from app.services.anonymize.decoy_seed import (
        DecoyCanaryCollisionError,
        assert_no_canary_collision,
    )

    with pytest.raises(DecoyCanaryCollisionError, match="tools/anonymize_decoy_seed_reset.py"):
        assert_no_canary_collision(
            observed_canary_address="bcrt1qold",
            freshly_derived_canary_address="bcrt1qnew",
        )
