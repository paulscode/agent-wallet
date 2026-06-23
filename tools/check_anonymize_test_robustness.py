# SPDX-License-Identifier: MIT
"""CI lint: reject statistical-mean assertions
outside the nightly suite.

Per-PR runs cannot tolerate ±N% empirical-mean assertions: even at large
N they flake. Such assertions belong in the nightly slow
suite under ``tests/integration/`` with ``@pytest.mark.slow``. This
script scans the unit test tree and refuses any tolerance-style
assertion on a sampler's empirical rate, mean, or distribution.

Usage::

    python tools/check_anonymize_test_robustness.py

Exits 0 on clean, 1 with file:line list on violations.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Reject lines that combine "rate" / "mean" / "empirical" / "counter" with
# tolerance arithmetic (`±`, `tolerance`, `approx`) that gates a per-PR
# test. The patterns are deliberately narrow so a deterministic-equality
# test passes the lint.
STOCHASTIC_PATTERNS = [
    # Bare tolerance literals in float-rate assertions, e.g. `0.25 <= rate <= 0.35`.
    re.compile(r"(?:rate|mean|empirical)\s*[<>=]+\s*\d+\.\d+\s*[+\-]"),
    # Explicit ±/two-sigma comments.
    re.compile(r"±\s*\d|±\s*\d+σ|two[-\s]*sigma|2σ", re.IGNORECASE),
    # ``pytest.approx`` on a sampled rate/mean (NOT on a duration field).
    re.compile(r"(?:rate|mean|empirical)\s*==\s*pytest\.approx"),
]

# Allow-listed paths: nightly suite + this lint's own self-tests.
ALLOWED_DIRS = ("tests/integration/",)
ALLOWED_SUFFIX = "_distribution.py"

REPO = Path(__file__).resolve().parents[1]
SCAN_ROOT = REPO / "tests" / "unit"


def _is_allowed(path: Path) -> bool:
    rel = path.relative_to(REPO).as_posix()
    if any(rel.startswith(d) for d in ALLOWED_DIRS):
        return True
    if rel.endswith(ALLOWED_SUFFIX):
        return True
    return False


def scan_file(path: Path) -> list[tuple[int, str]]:
    if _is_allowed(path):
        return []
    out: list[tuple[int, str]] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for idx, line in enumerate(text.splitlines(), start=1):
        for pat in STOCHASTIC_PATTERNS:
            if pat.search(line):
                out.append((idx, line.strip()))
                break
    return out


def main(argv: list[str]) -> int:
    violations: list[tuple[Path, int, str]] = []
    targets = list(SCAN_ROOT.rglob("test_anonymize_*.py"))
    for path in targets:
        for line_no, line in scan_file(path):
            violations.append((path, line_no, line))
    if violations:
        print("Stochastic-mean assertion found in non-nightly suite:", file=sys.stderr)
        for path, line_no, line in violations:
            rel = path.relative_to(REPO)
            print(f"  {rel}:{line_no}: {line}", file=sys.stderr)
        print(
            "\nMove statistical-mean assertions to tests/integration/*_distribution.py (marked @pytest.mark.slow).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
