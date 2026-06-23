# SPDX-License-Identifier: MIT
"""Anonymize stack uses no third-party telemetry.

The wallet forbids:

* Third-party fee oracles (the wallet-wide ``mempool_fee_service`` is
  acceptable; an external graph / centrality service is not).
* Centrality look-ups against external graph services. Peer selection
  is restricted to LND's local ``describe_graph``.

This static-import lint catches a future regression that imports a
remote-graph or remote-fee SDK from inside the anonymize stack.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# Third-party services + SDKs that would constitute "telemetry" or
# "external graph look-up" for the anonymize stack. Any of these
# names appearing in an ``import`` line inside ``app/services/anonymize/``
# is a regression.
_FORBIDDEN_NAMES: tuple[str, ...] = (
    # Generic third-party SDKs.
    "datadog",
    "sentry_sdk",
    "newrelic",
    "honeycomb",
    "logfire",
    # Public chain analysis / graph services.
    "amboss",
    "lnrouter",
    "1ml",
    # External fee oracles other than the wallet's own mempool service.
    "mempool_space_api",
    "blockchair",
)


def _anonymize_files() -> list[Path]:
    root = Path(__file__).resolve().parents[2] / "app" / "services" / "anonymize"
    return [p for p in root.rglob("*.py") if "__pycache__" not in str(p)]


@pytest.mark.parametrize("forbidden", _FORBIDDEN_NAMES)
def test_no_third_party_telemetry_import(forbidden: str) -> None:
    pat = re.compile(
        rf"^\s*(?:import\s+{re.escape(forbidden)}|"
        rf"from\s+{re.escape(forbidden)}(?:\.|\s|$))",
        re.MULTILINE,
    )
    offenders: list[str] = []
    for path in _anonymize_files():
        if pat.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path))
    assert not offenders, f"forbidden third-party SDK {forbidden!r} found in: {offenders}"


def test_no_telemetry_helper_imports_from_app_services() -> None:
    """Block accidental import of a future ``app.services.metrics_thirdparty``
    or similar from inside the anonymize package.

    The wallet's own ``app.services.mempool_fee_service`` is the only
    acceptable fee-source for general wallet flows; the anonymize
    stack uses ``chain.py`` directly through its dedicated SOCKS
    listener instead.
    """
    pat = re.compile(
        r"from\s+app\.services\.\w*(third_party|external_graph|telemetry)\w*"
        r"|import\s+app\.services\.\w*(third_party|external_graph|telemetry)\w*"
    )
    offenders: list[str] = []
    for path in _anonymize_files():
        if pat.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path))
    assert not offenders, offenders
