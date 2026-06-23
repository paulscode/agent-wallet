# SPDX-License-Identifier: MIT
"""Regression tests for DASHBOARD_TOKEN persistence (M1, L3)."""

from __future__ import annotations

import os
import stat
from unittest.mock import patch

import pytest

from app.core.config import settings
from app.dashboard import auth


@pytest.fixture
def restore_token():
    original = settings.dashboard_token
    yield
    settings.dashboard_token = original


class TestAtomicEnvWrite:
    """``.env`` must never exist at default umask before chmod 0600."""

    def test_creates_new_env_with_mode_0600(self, tmp_path, restore_token):
        settings.dashboard_token = ""
        env = tmp_path / ".env"
        with (
            patch("app.dashboard.auth.os.path.exists") as exists,
            patch("app.dashboard.auth.os.getcwd", return_value=str(tmp_path)),
        ):
            # /.dockerenv → False, env file → False (force create branch)
            exists.side_effect = lambda p: False
            auth._get_token()
        assert env.exists()
        mode = stat.S_IMODE(env.stat().st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
        body = env.read_text()
        assert "DASHBOARD_TOKEN=" in body

    def test_appends_to_existing_env_and_tightens_mode(self, tmp_path, restore_token):
        settings.dashboard_token = ""
        env = tmp_path / ".env"
        env.write_text("OTHER_VAR=1\n")
        os.chmod(env, 0o644)  # simulate a permissive pre-existing file
        with (
            patch("app.dashboard.auth.os.path.exists") as exists,
            patch("app.dashboard.auth.os.getcwd", return_value=str(tmp_path)),
        ):
            exists.side_effect = lambda p: p != "/.dockerenv"
            auth._get_token()
        mode = stat.S_IMODE(env.stat().st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
        assert "DASHBOARD_TOKEN=" in env.read_text()

    def test_persistence_failure_aborts_startup(self, tmp_path, restore_token):
        settings.dashboard_token = ""
        with (
            patch("app.dashboard.auth.os.path.exists") as exists,
            patch("app.dashboard.auth.os.getcwd", return_value=str(tmp_path)),
            patch("app.dashboard.auth._append_env_line_0600", side_effect=OSError("read-only fs")),
        ):
            exists.side_effect = lambda p: p != "/.dockerenv"
            with pytest.raises(RuntimeError, match="DASHBOARD_TOKEN"):
                auth._get_token()


class TestTokenStrengthFloor:
    """operator-supplied tokens below the strength floor abort startup."""

    def test_short_token_rejected(self, restore_token):
        settings.dashboard_token = "short-token"
        with pytest.raises(RuntimeError, match="too short"):
            auth.ensure_token_ready()

    def test_low_distinct_character_token_rejected(self, restore_token):
        # Long enough to clear the length floor, but a single repeated
        # character carries almost no entropy.
        settings.dashboard_token = "x" * auth._MIN_DASHBOARD_TOKEN_LENGTH
        with pytest.raises(RuntimeError, match="distinct characters"):
            auth.ensure_token_ready()

    def test_minimum_length_accepted(self, restore_token):
        # Meets the length floor and carries enough distinct characters.
        token = ("abcdefgh" * ((auth._MIN_DASHBOARD_TOKEN_LENGTH // 8) + 1))[
            : auth._MIN_DASHBOARD_TOKEN_LENGTH
        ]
        settings.dashboard_token = token
        assert auth.ensure_token_ready() == token

    def test_per_request_calls_skip_strength_check(self, restore_token):
        """Per-request _get_token() must not re-enforce the floor (test
        fixtures use short tokens; only startup should refuse)."""
        settings.dashboard_token = "short-test-token"
        # Should not raise.
        assert auth._get_token() == "short-test-token"
