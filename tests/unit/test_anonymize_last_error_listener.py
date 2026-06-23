# SPDX-License-Identifier: MIT
"""Last_error redaction at write.

The SQLAlchemy ``set`` event listener runs the redactor on every
assignment to ``AnonymizeSession.last_error``, so a future call site
that writes the column directly cannot bypass the redactor.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.task_supervisor import (
    install_last_error_redaction_listener,
)


@pytest.fixture(scope="module", autouse=True)
def _install_listener_once() -> None:
    install_last_error_redaction_listener()


def _row() -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.FAILED.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=datetime.now(timezone.utc),
    )


def test_listener_redacts_bech32_address_on_write() -> None:
    sess = _row()
    sess.last_error = "claim tx for bcrt1qexampleexampleexampleexampleexampleexample failed"
    assert "bcrt1q" not in sess.last_error
    assert "<redacted>" in sess.last_error


def test_listener_redacts_hex_run_on_write() -> None:
    sess = _row()
    sess.last_error = "Boltz returned txid=" + ("aa" * 32) + " not found"
    assert ("aa" * 32) not in sess.last_error
    assert "<redacted>" in sess.last_error


def test_listener_passes_through_clean_text() -> None:
    sess = _row()
    sess.last_error = "Operator returned 503; retried 3 times"
    assert sess.last_error == "Operator returned 503; retried 3 times"


def test_listener_handles_none_assignment() -> None:
    sess = _row()
    sess.last_error = "something"
    sess.last_error = None
    assert sess.last_error is None


def test_listener_coerces_non_string_to_str() -> None:
    sess = _row()
    sess.last_error = RuntimeError("destination=bcrt1qexampleexampleexampleexampleexampleexample")  # type: ignore[assignment]
    # Coerced to str via repr; address is still redacted.
    assert "bcrt1q" not in sess.last_error
    assert "<redacted>" in sess.last_error


def test_listener_is_idempotent() -> None:
    """Running the redactor twice on already-redacted text leaves it stable."""
    sess = _row()
    sess.last_error = "<redacted> not found"
    assert sess.last_error == "<redacted> not found"


def test_listener_redacts_v3_onion() -> None:
    onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv2d.onion"
    sess = _row()
    sess.last_error = f"could not reach {onion}"
    assert ".onion" not in sess.last_error
