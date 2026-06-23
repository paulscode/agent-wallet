# SPDX-License-Identifier: MIT
"""Anonymize service forbids WebSocket / SSE.

A long-lived subscription is uniquely strong cross-circuit linker:
"same-exit-same-time-window" matches across legs even with different
exits if both connections overlap. Anonymize sessions use only short
HTTP polls on the constant cadence; each poll establishes,
transacts, and tears down within seconds.

This test walks the ``app/services/anonymize/`` package and asserts
no module imports a websocket or SSE library. It is intentionally
implemented as a static text scan, not via ``importlib`` / mocked
imports — those would need to actually load every module, which
defeats the goal of catching the import statement before runtime.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_FORBIDDEN_IMPORTS: tuple[str, ...] = (
    "websockets",
    "httpx_ws",
    "aiohttp.ws_client",
    "sseclient",
    "httpx_sse",
)


def _anonymize_module_files() -> list[Path]:
    root = Path(__file__).resolve().parents[2] / "app" / "services" / "anonymize"
    if not root.is_dir():
        pytest.fail(f"anonymize service directory not found at {root}")
    return [p for p in root.rglob("*.py") if "__pycache__" not in str(p)]


@pytest.mark.parametrize("forbidden", _FORBIDDEN_IMPORTS)
def test_no_websocket_or_sse_imports(forbidden: str) -> None:
    """No ``import`` line in the anonymize package may reference these."""
    # Match either ``import X`` or ``from X import …``.
    pat = re.compile(
        rf"^\s*(?:import\s+{re.escape(forbidden)}|"
        rf"from\s+{re.escape(forbidden)}(?:\.|$|\s))",
        re.MULTILINE,
    )
    offenders: list[str] = []
    for path in _anonymize_module_files():
        text = path.read_text(encoding="utf-8")
        if pat.search(text):
            offenders.append(str(path))
    assert not offenders, f"forbidden import {forbidden!r} found in: {offenders}"


def test_at_least_one_anonymize_module_exists() -> None:
    """Sanity-check that the static scan is actually scanning files."""
    files = _anonymize_module_files()
    assert len(files) > 1, files
