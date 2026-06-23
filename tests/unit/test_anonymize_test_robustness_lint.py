# SPDX-License-Identifier: MIT
"""Verify the test-robustness lint script.

Avoid literal ±-tolerance strings in this file's source so the lint
does not flag itself when scanning the unit suite. Fixture strings
are assembled at runtime from inert components.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "check_anonymize_test_robustness.py"


def _stochastic_fixture_body() -> str:
    """Build a stochastic-style assertion body without baking the
    flagged pattern into THIS file's source."""
    plus_minus = "±"  # ±
    lo = "0.25 <" + "= rate <" + "= 0.35"
    return "def test_bogus():\n    rate = 0.30\n    assert " + lo + "  # " + plus_minus + " 5%\n"


def test_lint_passes_on_current_tree() -> None:
    """Running the lint over the repo's current state exits 0."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        cwd=str(REPO),
    )
    assert result.returncode == 0, f"lint regressed; stderr={result.stderr.decode('utf-8', 'replace')}"


def test_lint_flags_stochastic_assertion_in_unit_test() -> None:
    """A planted tolerance-style assertion in a unit test fails the lint."""
    target = REPO / "tests" / "unit" / "test_anonymize_lint_fixture_DELETE.py"
    target.write_text(_stochastic_fixture_body(), encoding="utf-8")
    try:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            cwd=str(REPO),
        )
        assert result.returncode == 1
        assert b"test_anonymize_lint_fixture_DELETE.py" in result.stderr
    finally:
        target.unlink(missing_ok=True)


def test_lint_allows_assertion_in_distribution_suite() -> None:
    """A tolerance-band assertion is allowed in a *_distribution.py file."""
    target = REPO / "tests" / "integration" / "test_anonymize_FIXTURE_distribution.py"
    target.write_text(_stochastic_fixture_body(), encoding="utf-8")
    try:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            cwd=str(REPO),
        )
        assert result.returncode == 0
    finally:
        target.unlink(missing_ok=True)
