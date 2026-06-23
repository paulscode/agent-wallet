# SPDX-License-Identifier: MIT
"""/ item 23 + — hop idempotency HMAC.

The HMAC must be:

* Deterministic across runs given the same inputs.
* Domain-separated by ``hop_kind`` so two hops with identical
  ``(session_id, hop_index, attempt, payload)`` but different kinds
  produce different keys.
* Stable across Python versions (canonical-json payloads).
* Resistant to brute force without the per-row nonce.
"""

from __future__ import annotations

import uuid

import pytest

from app.services.anonymize.hop_idempotency import (
    canonicalize_payload,
    make_hop_idempotency_key,
    make_per_row_nonce,
)

_KEY = b"\x42" * 32
_NONCE = b"\x10" * 16
_SESSION = uuid.UUID("12345678-1234-5678-1234-567812345678").bytes


def test_per_row_nonce_is_128_bits_and_random() -> None:
    a = make_per_row_nonce()
    b = make_per_row_nonce()
    assert isinstance(a, bytes)
    assert len(a) == 16
    assert a != b


def test_canonicalize_payload_is_sort_stable() -> None:
    """Insertion order must not affect the canonical encoding."""
    a = canonicalize_payload({"b": 2, "a": 1})
    b = canonicalize_payload({"a": 1, "b": 2})
    assert a == b == b'{"a":1,"b":2}'


def test_canonicalize_payload_supports_bytes_and_none() -> None:
    assert canonicalize_payload(None) == b""
    assert canonicalize_payload(b"raw") == b"raw"


def test_canonicalize_payload_rejects_unknown_types() -> None:
    with pytest.raises(TypeError):
        canonicalize_payload(("not", "supported"))  # type: ignore[arg-type]


def test_hmac_is_deterministic() -> None:
    args = dict(
        key_bytes=_KEY,
        nonce=_NONCE,
        session_id=_SESSION,
        hop_index=0,
        hop_kind="reverse",
        attempt=0,
        payload={"amount": 250_000},
    )
    a = make_hop_idempotency_key(**args)
    b = make_hop_idempotency_key(**args)
    assert a == b
    assert len(a) == 64  # sha256 hex


def test_hmac_changes_when_hop_kind_changes() -> None:
    base = dict(
        key_bytes=_KEY,
        nonce=_NONCE,
        session_id=_SESSION,
        hop_index=0,
        attempt=0,
        payload=None,
    )
    a = make_hop_idempotency_key(hop_kind="reverse", **base)
    b = make_hop_idempotency_key(hop_kind="ln_self_pay", **base)
    assert a != b


def test_hmac_changes_when_nonce_changes() -> None:
    base = dict(
        key_bytes=_KEY,
        session_id=_SESSION,
        hop_index=0,
        hop_kind="reverse",
        attempt=0,
        payload=None,
    )
    a = make_hop_idempotency_key(nonce=b"\x11" * 16, **base)
    b = make_hop_idempotency_key(nonce=b"\x22" * 16, **base)
    assert a != b


def test_hmac_rejects_wrong_key_length() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        make_hop_idempotency_key(
            key_bytes=b"short",
            nonce=_NONCE,
            session_id=_SESSION,
            hop_index=0,
            hop_kind="reverse",
            attempt=0,
        )


def test_hmac_rejects_wrong_nonce_length() -> None:
    with pytest.raises(ValueError, match="must be 16 bytes"):
        make_hop_idempotency_key(
            key_bytes=_KEY,
            nonce=b"\x00" * 8,
            session_id=_SESSION,
            hop_index=0,
            hop_kind="reverse",
            attempt=0,
        )


def test_hmac_rejects_negative_indices() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        make_hop_idempotency_key(
            key_bytes=_KEY,
            nonce=_NONCE,
            session_id=_SESSION,
            hop_index=-1,
            hop_kind="reverse",
            attempt=0,
        )


# ── Dispatcher decision + end-to-end walk ───────────────────────


def test_dispatcher_no_events_issues_side_effect() -> None:
    from app.services.anonymize.hop_idempotency import dispatcher_decision

    assert (
        dispatcher_decision(
            started_event=None,
            completed_event=None,
        )
        == "issue_side_effect"
    )


def test_dispatcher_started_only_verifies_remote() -> None:
    """Timeouts are reconciliation triggers, not retries."""
    from app.services.anonymize.hop_idempotency import dispatcher_decision

    fake = object()
    assert (
        dispatcher_decision(
            started_event=fake,
            completed_event=None,
        )
        == "verify_remote_state"
    )


def test_dispatcher_both_events_idempotent_noop() -> None:
    from app.services.anonymize.hop_idempotency import dispatcher_decision

    a, b = object(), object()
    assert (
        dispatcher_decision(
            started_event=a,
            completed_event=b,
        )
        == "completed_idempotent_no_op"
    )


@pytest.mark.asyncio
async def test_dispatch_hop_attempt_walks_db(db_session) -> None:
    from datetime import datetime, timezone
    from uuid import uuid4

    from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
    from app.services.anonymize.hop_idempotency import (
        HopAttemptKey,
        dispatch_hop_attempt,
        record_hop_attempt_completed,
        record_hop_attempt_started,
    )

    sess = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.HOPPING.value,
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
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(sess)
    await db_session.flush()

    key = HopAttemptKey(
        session_id=sess.id,
        hop_index=0,
        hop_kind="reverse",
        attempt=1,
        idempotency_key="ik-1",
        nonce=b"\x00" * 16,
        key_generation=0,
    )

    # No events yet ⇒ issue_side_effect.
    out = await dispatch_hop_attempt(db_session, idempotency_key="ik-1")
    assert out == "issue_side_effect"

    # Started, not completed ⇒ verify_remote_state.
    await record_hop_attempt_started(db_session, key=key)
    await db_session.flush()
    out = await dispatch_hop_attempt(db_session, idempotency_key="ik-1")
    assert out == "verify_remote_state"

    # Both events ⇒ completed_idempotent_no_op.
    await record_hop_attempt_completed(db_session, key=key)
    await db_session.flush()
    out = await dispatch_hop_attempt(db_session, idempotency_key="ik-1")
    assert out == "completed_idempotent_no_op"
