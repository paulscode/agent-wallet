# SPDX-License-Identifier: MIT
"""Guard against CSP-incompatible Alpine directives in the dashboard.

The dashboard is served with the ``@alpinejs/csp`` build, whose
expression parser does NOT support multi-statement directives — e.g.
``@click="a = b; c()"`` raises *"CSP Parser Error: Unexpected token"*
at runtime and the handler silently does nothing. Each such handler
must be a single expression (typically one method call) with the
multi-step logic moved into a component method.

This scans every Alpine event/init directive in the template and fails
if any contains a ``;`` (statement separator).
"""

from __future__ import annotations

import re
from pathlib import Path

_HTML = Path(__file__).resolve().parents[2] / "app" / "dashboard" / "templates" / "dashboard.html"

# Alpine event/init directives whose value is a JS expression the CSP
# parser must evaluate: ``@event``/``x-on:event`` (any modifiers) and
# ``x-init``. (``:class`` / ``x-text`` etc. are expressions too, but the
# ';' footgun is specific to event handlers / init.)
_DIRECTIVE_WITH_SEMICOLON = re.compile(r'(?:@[a-zA-Z][\w.:-]*|x-on:[\w.:-]+|x-init)="([^"]*;[^"]*)"')


def test_no_multistatement_alpine_directives() -> None:
    html = _HTML.read_text(encoding="utf-8")
    offenders = _DIRECTIVE_WITH_SEMICOLON.findall(html)
    assert not offenders, (
        "CSP-incompatible multi-statement Alpine directive(s) found — the "
        "@alpinejs/csp parser rejects ';'-separated expressions, so the "
        "handler silently no-ops. Move the logic into a component method "
        "and bind a single call:\n  - " + "\n  - ".join(offenders)
    )
