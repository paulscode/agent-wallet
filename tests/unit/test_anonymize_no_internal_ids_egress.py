# SPDX-License-Identifier: MIT
"""Internal-ID egress strip.

The anonymize HTTP wrapper must refuse to emit any of the forbidden
field names in the outbound request body, query string, or headers.
This is the ``EgressFingerprintError`` enforcement in
``app.services.anonymize.http``.

Two layers of enforcement:
1. **Runtime gate** — ``assert_outbound_request_ok()`` called by the
   anonymize HTTP wrapper before every request.
2. **Static lint** — a CI scan over the wallet's Boltz / LND request
   builders, refusing to admit any literal request body that names
   a forbidden field. The lint covers ``boltz_service``, the
   anonymize-stack hop body, and ``boltz_request``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services.anonymize.http import (
    EgressFingerprintError,
    assert_outbound_request_ok,
)
from app.services.anonymize.metadata import ANONYMIZE_FORBIDDEN_EGRESS_FIELDS

REPO = Path(__file__).resolve().parents[2]
_SCAN_FILES = [
    REPO / "app" / "services" / "boltz_service.py",
    REPO / "app" / "services" / "anonymize" / "boltz_request.py",
    REPO / "app" / "services" / "anonymize" / "boltz_egress.py",
    REPO / "app" / "services" / "anonymize" / "hops" / "reverse.py",
    REPO / "app" / "services" / "anonymize" / "hop_dispatcher.py",
]


def test_static_lint_no_forbidden_field_literals_in_egress_modules() -> None:
    """static lint: refuse to admit any module that names a
    forbidden field as a request-body dict key literal."""
    offenders: list[str] = []
    for path in _SCAN_FILES:
        text = path.read_text(encoding="utf-8", errors="replace")
        for field in ANONYMIZE_FORBIDDEN_EGRESS_FIELDS:
            # Look for ``"field":`` or ``'field':`` patterns that
            # indicate a dict-key literal.
            pat = re.compile(
                rf'["\']{re.escape(field)}["\']\s*:',
            )
            if pat.search(text):
                offenders.append(f"{path.relative_to(REPO)}: forbidden field '{field}' appears as a dict key")
    assert offenders == [], (
        f" violation: forbidden internal-ID field names found in egress request builders: {offenders}"
    )


def test_forbidden_fields_constant_includes_documented_names() -> None:
    """The list must include every documented internal-id name."""
    documented = {
        "session_id",
        "quote_token",
        "idempotency_key",
        "internal_swap_id",
        "internal_audit_id",
        "our_node_pubkey",
    }
    assert documented <= ANONYMIZE_FORBIDDEN_EGRESS_FIELDS


def test_assert_outbound_request_ok_passes_clean_payload() -> None:
    """Clean Boltz request shape passes the gate."""
    assert_outbound_request_ok(
        {"amount": 250_000, "preimageHash": "deadbeef"},
        {"Accept": "*/*"},
    )


def test_assert_outbound_request_ok_rejects_session_id() -> None:
    with pytest.raises(EgressFingerprintError, match="session_id"):
        assert_outbound_request_ok(
            {"amount": 250_000, "session_id": "abc"},
            None,
        )


def test_assert_outbound_request_ok_rejects_quote_token() -> None:
    with pytest.raises(EgressFingerprintError, match="quote_token"):
        assert_outbound_request_ok(
            {"quote_token": "tok"},
            None,
        )


def test_assert_outbound_request_ok_rejects_traceparent_header() -> None:
    """Trace headers from upstream middleware must not propagate."""
    with pytest.raises(EgressFingerprintError, match="[Tt]raceparent"):
        assert_outbound_request_ok(
            None,
            {"traceparent": "00-foo-bar-00"},
        )
