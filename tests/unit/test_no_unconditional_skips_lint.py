# SPDX-License-Identifier: MIT
"""Verify the unconditional-skip lint.

The flagged always-skip marker token is never written contiguously in
this file's source, so the lint does not flag itself when scanning the
unit suite — fixture strings are assembled at runtime from inert
components.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.guardrail

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "check_no_unconditional_skips.py"


def _unconditional_skip_fixture_body() -> str:
    """Build a module whose source carries an unconditional skip
    marker, without baking the flagged token into THIS file."""
    marker = "@pytest.mark." + "skip" + '(reason="wip")'
    return "import pytest\n\n\n" + marker + "\ndef test_planted():\n    assert True\n"


def _conditional_skip_fixture_body() -> str:
    """A skipif-gated test is conditional — the lint must allow it."""
    marker = "@pytest.mark." + "skip" + "if(True, reason='env')"
    return "import pytest\n\n\n" + marker + "\ndef test_gated():\n    assert True\n"


def test_lint_passes_on_current_tree() -> None:
    """Running the lint over the repo's current state exits 0."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        cwd=str(REPO),
    )
    assert result.returncode == 0, f"lint regressed; stderr={result.stderr.decode('utf-8', 'replace')}"


def test_lint_flags_unconditional_skip_in_unit_test() -> None:
    """A planted unconditional skip in a unit test fails the lint."""
    target = REPO / "tests" / "unit" / "test_planted_unconditional_skip_DELETE.py"
    target.write_text(_unconditional_skip_fixture_body(), encoding="utf-8")
    try:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            cwd=str(REPO),
        )
        assert result.returncode == 1
        assert b"test_planted_unconditional_skip_DELETE.py" in result.stderr
    finally:
        target.unlink(missing_ok=True)


def test_lint_allows_conditional_skipif() -> None:
    """A ``skipif``-gated test is conditional and must not be flagged."""
    target = REPO / "tests" / "unit" / "test_planted_conditional_skip_DELETE.py"
    target.write_text(_conditional_skip_fixture_body(), encoding="utf-8")
    try:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            cwd=str(REPO),
        )
        assert result.returncode == 0
    finally:
        target.unlink(missing_ok=True)
