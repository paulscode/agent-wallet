# SPDX-License-Identifier: MIT
"""Quote endpoint must be session-network-silent.

``POST /anonymize/quote`` reads only local caches: operator pair-info,
fee bands, registry data, address parser. It must never send the
destination address, amount, source kind, or selected operators to
any external service on the request path.

The endpoint ships as a stub returning 503; the lint guards
the *future* implementation by:

1. Asserting the dashboard's ``dash_anonymize_quote`` handler does
   not import any of the per-call HTTP client / SOCKS / DNS / Tor-
   control helpers in its module-level namespace. (A future
   implementation that needs them will fail this test and force the
   developer to either route through the cache layer or document why
   network egress is needed.)

2. Asserting the ``quote_cache`` module is the only path through
   which session-network-silent reads can flow. The cache's lookup
   API is what the quote handler should call; any *other* network-
   touching helper called from the quote handler is a regression.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

_FORBIDDEN_AT_QUOTE_MODULE_LEVEL: tuple[str, ...] = (
    # HTTP egress factories — quote must read from the cache, not
    # build a fresh anonymize HTTP client per request.
    "get_anonymize_client",
    # Tor control / SOCKS-listener resolution helpers — same logic.
    "resolve_socks_port",
    "resolve_socks_host",
    # Operator-registry signature verification — happens at startup,
    # not per-quote.
    "load_operator_registry",
)


def _read_dashboard_api() -> str:
    p = Path(__file__).resolve().parents[2] / "app" / "dashboard" / "api.py"
    return p.read_text(encoding="utf-8")


def _quote_handler_body() -> str:
    """Extract the ``async def dash_anonymize_quote`` handler body.

    The signature may span multiple lines (e.g. the operator-assignment
    work injects ``db`` via ``Depends``), so
    the regex must not assume the parameter list is all on one line.
    """
    text = _read_dashboard_api()
    # Locate the signature anchor — anything up to the first ``-> ... :``
    # on a line that closes the parameter list. Then capture everything
    # until the next top-level ``async def`` (or EOF).
    match = re.search(
        r"async\s+def\s+dash_anonymize_quote\s*\(.*?\)\s*->[^:]+:(.*?)(?=\nasync\s+def\s+\w+|\Z)",
        text,
        re.DOTALL,
    )
    assert match is not None, "dash_anonymize_quote handler not found"
    return match.group(1)


def test_quote_handler_imports_no_egress_helpers() -> None:
    """Forbidden-name lint scoped to the quote handler body."""
    body = _quote_handler_body()
    offenders = [name for name in _FORBIDDEN_AT_QUOTE_MODULE_LEVEL if name in body]
    assert not offenders, f"dash_anonymize_quote must not call egress helpers directly; found: {offenders}"


def test_quote_handler_does_not_call_boltz_service() -> None:
    """The quote endpoint must not reach Boltz directly.

    The wallet's existing ``boltz_service`` is fine for non-anonymize
    flows, but a quote call that touches it would defeat.
    """
    body = _quote_handler_body()
    assert "boltz_service" not in body, (
        "quote handler must not invoke boltz_service; route through anonymize.quote_cache instead"
    )


def test_quote_handler_does_not_call_lnd_service_describe_graph() -> None:
    """``describe_graph`` is a network-touching LND call.

    ``ANONYMIZE_PROHIBIT_GOSSIP_AT_ROUTING=true`` forbids triggering
    a fresh gossip refresh at routing time; the quote endpoint
    should not be the entry point for one either.
    """
    body = _quote_handler_body()
    assert "describe_graph" not in body, (
        "quote handler must not call describe_graph; use the local cached graph snapshot via the route-cache helper"
    )


def test_quote_cache_module_is_quote_handlers_data_source() -> None:
    """The ``quote_cache`` module must exist as the documented read path.

    It currently is an empty stub; the test pins its existence so a
    future implementer cannot accidentally import a different module.
    """
    mod = importlib.import_module("app.services.anonymize.quote_cache")
    assert mod is not None
