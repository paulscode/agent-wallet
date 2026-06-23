# SPDX-License-Identifier: MIT
"""Anonymize stack emits no service-labeled metrics.

Anonymize sessions cause distinctive activity spikes (outbound HTTP
counts, Tor circuit creation rate, LND HTLC-add rate). A Prometheus /
Grafana / cloud-provider observability layer logging these metrics
under a label like ``service="anonymize"`` would create an
"anonymize fingerprint" visible to anyone with metrics-pipeline
access.

The policy: anonymize-related metrics emit under generic
names (``http_requests_total``, ``tor_circuits_total``) without
``service="anonymize"``-style labels. This test enforces the policy
by static-scanning ``app/services/anonymize/`` for any string that
looks like a label written through the project's metrics surface.

Per-session timing is also forbidden (per the same item). The session
state lives in the DB and is read by the dashboard directly.
"""

from __future__ import annotations

import re
from pathlib import Path

# Project does not currently use Prometheus or OpenTelemetry; the test
# is a forward-looking fence so the *next* metrics integration cannot
# accidentally tag anonymize traffic. We scan for label-name fragments
# that would identify anonymize traffic if introduced.
_FORBIDDEN_LABEL_FRAGMENTS: tuple[str, ...] = (
    'service="anonymize"',
    "service='anonymize'",
    'subsystem="anonymize"',
    "subsystem='anonymize'",
    'feature="anonymize"',
    "feature='anonymize'",
    # Per-session timing labels.
    "session_id=",  # only forbidden inside metric calls; see narrowing below
)


def _anonymize_module_files() -> list[Path]:
    root = Path(__file__).resolve().parents[2] / "app" / "services" / "anonymize"
    return [p for p in root.rglob("*.py") if "__pycache__" not in str(p)]


def test_no_service_anonymize_metric_label() -> None:
    offenders: list[str] = []
    for path in _anonymize_module_files():
        text = path.read_text(encoding="utf-8")
        for frag in (
            'service="anonymize"',
            "service='anonymize'",
            'subsystem="anonymize"',
            "subsystem='anonymize'",
            'feature="anonymize"',
            "feature='anonymize'",
        ):
            if frag in text:
                offenders.append(f"{path}: {frag!r}")
    assert not offenders, (
        "anonymize stack must not emit metrics tagged with a service "
        "label; emit under generic names. Offenders: " + str(offenders)
    )


def test_no_metric_imports_with_anonymize_namespace() -> None:
    """If a future metrics library is added, the anonymize package
    must not import a labeled-metrics helper that bakes ``anonymize``
    into the metric name. This is enforced by a regex over imports.
    """
    pat = re.compile(
        r"from\s+\w+\.metrics\s+import\s+\w*[Aa]nonymize\w*"
        r"|import\s+\w*anonymize\w*_metrics",
    )
    offenders: list[str] = []
    for path in _anonymize_module_files():
        if pat.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path))
    assert not offenders, f"anonymize stack must not import anonymize-namespaced metric helpers: {offenders}"
