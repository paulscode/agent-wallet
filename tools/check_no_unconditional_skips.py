# SPDX-License-Identifier: MIT
"""CI lint: reject unconditional skips in the unit test tier.

An unconditional ``@pytest.mark.skip`` (or ``pytestmark =
pytest.mark.skip``) silently removes a test from the suite — it shows
green and contributes nothing to coverage, so a test that was meant to
assert behavior can rot undetected. Conditional skips are fine and
expected: ``@pytest.mark.skipif(<cond>, ...)`` and runtime
``pytest.skip(...)`` guards (e.g. "binary not installed") gate a test
on the environment rather than disabling it outright.

This script scans the unit test tree and refuses any unconditional
``pytest.mark.skip`` decorator. ``skipif`` and runtime ``pytest.skip``
guards are allowed; the opt-in integration tiers under
``tests/integration/`` are out of scope (they carry harness
placeholders gated by env-conditional module marks).

Usage::

    python tools/check_no_unconditional_skips.py

Exits 0 on clean, 1 with a file:line list on violations.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Match ``pytest.mark.skip`` NOT followed by ``if`` — i.e. the
# unconditional always-skip marker, whether used as a decorator
# (``@pytest.mark.skip(...)``) or a module-level
# (``pytestmark = pytest.mark.skip(...)``). ``skipif`` is explicitly
# excluded by the negative lookahead.
_UNCONDITIONAL_SKIP = re.compile(r"pytest\.mark\.skip(?!if)")

REPO = Path(__file__).resolve().parents[1]
SCAN_ROOT = REPO / "tests" / "unit"

# Allow-listed filename suffix: this lint's own self-test writes a
# throwaway fixture file carrying a planted unconditional skip and
# asserts the lint flags it. Skip that sentinel so the self-test does
# not race the lint's own clean run.
_ALLOWED_SUFFIX = "_skiplint_fixture_DELETE.py"


def scan_file(path: Path) -> list[tuple[int, str]]:
    if path.name.endswith(_ALLOWED_SUFFIX):
        return []
    out: list[tuple[int, str]] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for idx, line in enumerate(text.splitlines(), start=1):
        # Ignore comments so a line discussing the rule is not flagged.
        code = line.split("#", 1)[0]
        if _UNCONDITIONAL_SKIP.search(code):
            out.append((idx, line.strip()))
    return out


def main(argv: list[str]) -> int:
    violations: list[tuple[Path, int, str]] = []
    for path in sorted(SCAN_ROOT.rglob("test_*.py")):
        for line_no, line in scan_file(path):
            violations.append((path, line_no, line))
    if violations:
        print("Unconditional skip found in the unit test tier:", file=sys.stderr)
        for path, line_no, line in violations:
            rel = path.relative_to(REPO)
            print(f"  {rel}:{line_no}: {line}", file=sys.stderr)
        print(
            "\nUse @pytest.mark.skipif(<condition>, reason=...) or a runtime "
            "pytest.skip() guard instead — an unconditional skip hides a "
            "non-running test from both the green check and coverage.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
