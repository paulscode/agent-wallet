# SPDX-License-Identifier: MIT
"""Dedicated ``anonymize_stepup_state`` table."""

from __future__ import annotations

from pathlib import Path

from app.services.anonymize.metadata import ANONYMIZE_RUNTIME_STATE_KEYS

REPO = Path(__file__).resolve().parents[2]
MIGRATION = REPO / "alembic" / "versions" / "021_anonymize_stepup_state.py"


def test_migration_021_exists() -> None:
    assert MIGRATION.is_file()


def test_migration_021_chains_to_020b() -> None:
    text = MIGRATION.read_text(encoding="utf-8")
    assert 'down_revision: Union[str, None] = "020b_anonymize_runtime_state_finalize"' in text


def test_migration_021_creates_purpose_built_table() -> None:
    text = MIGRATION.read_text(encoding="utf-8")
    # The table shape pinned by.
    assert "anonymize_stepup_state" in text
    assert '"cookie_id_hmac"' in text  # HMAC under dedicated Fernet bundle
    assert '"kind"' in text  # discriminator between nonce + lockout
    assert '"scope"' in text  # per-flow categorization
    assert '"nonce_enc"' in text  # Fernet-encrypted nonce payload
    assert '"expires_at"' in text  # TTL for purge pass
    assert '"failed_verifies"' in text  # per-lockout counter
    # CHECK constraint pins the discriminator vocabulary.
    assert "kind IN ('nonce', 'lockout')" in text


def test_migration_021_indexes_cover_query_paths() -> None:
    text = MIGRATION.read_text(encoding="utf-8")
    # Index that supports cookie+kind lookup.
    assert "ix_anonymize_stepup_cookie_kind" in text
    # Index that supports the recurring TTL purge.
    assert "ix_anonymize_stepup_expires_at" in text


def test_runtime_state_registry_excludes_stepup_keys() -> None:
    """Runtime_state narrows to long-lived stable keys only.

    Per-cookie stepup nonces and lockouts must NOT appear in the
    registry; they live exclusively in the new table.
    """
    for k in ANONYMIZE_RUNTIME_STATE_KEYS:
        assert not k.startswith("stepup_nonce"), f"runtime_state registry still carries stepup nonce key: {k}"
        assert not k.startswith("stepup_lockout"), f"runtime_state registry still carries stepup lockout key: {k}"
