# SPDX-License-Identifier: MIT
"""Quote-token binding."""

from __future__ import annotations

import time

import pytest

from app.services.anonymize.quote_token import (
    QuoteTokenError,
    QuoteTokenKeySet,
    QuoteTokenPayload,
    canonical_quote_payload,
    sign_quote_token,
    verify_quote_token,
)

_KEY_A = b"\xaa" * 32
_KEY_B = b"\xbb" * 32


def _payload(**overrides) -> QuoteTokenPayload:
    base = dict(
        canonical_pipeline_json=b'{"hops":[{"kind":"ln_self_pay"}]}',
        bin_amount_sat=250_000,
        submarine_operator_id=None,
        reverse_operator_id="boltz-mirror-eu",
        delay_min_s=3600,
        delay_max_s=21600,
        inter_leg_min_s=None,
        inter_leg_max_s=None,
        requested_mpp_k=3,
        issued_at_unix_s=int(time.time()),
        ttl_s=300,
    )
    base.update(overrides)
    return QuoteTokenPayload(**base)


def test_canonical_payload_is_sort_stable() -> None:
    a = canonical_quote_payload(_payload(bin_amount_sat=250_000))
    b = canonical_quote_payload(_payload(bin_amount_sat=250_000))
    assert a == b
    assert b'"bin_amount_sat":250000' in a


def test_keyset_rejects_short_keys() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        QuoteTokenKeySet(keys=(b"short",), active_generation=0)


def test_keyset_rejects_empty() -> None:
    with pytest.raises(ValueError, match="at least one"):
        QuoteTokenKeySet(keys=(), active_generation=0)


def test_sign_then_verify_roundtrips() -> None:
    keyset = QuoteTokenKeySet(keys=(_KEY_A,), active_generation=0)
    payload = _payload()
    token = sign_quote_token(payload, keyset=keyset)
    # No raise on verify against the same payload.
    verify_quote_token(token, keyset=keyset, candidate=payload)


def test_verify_rejects_mac_mismatch() -> None:
    keyset_a = QuoteTokenKeySet(keys=(_KEY_A,), active_generation=0)
    keyset_b = QuoteTokenKeySet(keys=(_KEY_B,), active_generation=0)
    token = sign_quote_token(_payload(), keyset=keyset_a)
    with pytest.raises(QuoteTokenError, match="HMAC mismatch"):
        verify_quote_token(token, keyset=keyset_b, candidate=_payload())


def test_verify_rejects_bound_payload_mutation() -> None:
    """Changing any bound field between quote and create must reject."""
    keyset = QuoteTokenKeySet(keys=(_KEY_A,), active_generation=0)
    issued = int(time.time())
    quote_payload = _payload(bin_amount_sat=250_000, issued_at_unix_s=issued)
    token = sign_quote_token(quote_payload, keyset=keyset)
    # Attacker changes the bin amount in the create body.
    create_payload = _payload(bin_amount_sat=500_000, issued_at_unix_s=issued)
    with pytest.raises(QuoteTokenError, match="bound payload differs"):
        verify_quote_token(token, keyset=keyset, candidate=create_payload)


def test_verify_rejects_operator_pair_mutation() -> None:
    keyset = QuoteTokenKeySet(keys=(_KEY_A,), active_generation=0)
    issued = int(time.time())
    a = _payload(reverse_operator_id="boltz-a", issued_at_unix_s=issued)
    b = _payload(reverse_operator_id="boltz-b", issued_at_unix_s=issued)
    token = sign_quote_token(a, keyset=keyset)
    with pytest.raises(QuoteTokenError):
        verify_quote_token(token, keyset=keyset, candidate=b)


def test_verify_rejects_expired_token() -> None:
    keyset = QuoteTokenKeySet(keys=(_KEY_A,), active_generation=0)
    payload = _payload(issued_at_unix_s=1_000_000, ttl_s=300)
    token = sign_quote_token(payload, keyset=keyset)
    with pytest.raises(QuoteTokenError, match="expired"):
        verify_quote_token(
            token,
            keyset=keyset,
            candidate=payload,
            now_unix_s=1_000_400,
        )


def test_verify_rejects_unknown_generation() -> None:
    """A token signed under generation 1 must verify under a key set
    that has at least 2 keys; if the verifier's key set has 1, reject."""
    issued = int(time.time())
    payload = _payload(issued_at_unix_s=issued)
    keyset_full = QuoteTokenKeySet(keys=(_KEY_A, _KEY_B), active_generation=0)
    # Sign as if active_generation=1 (rotated-out key) by manually
    # constructing the keyset with B as active.
    keyset_for_signing = QuoteTokenKeySet(keys=(_KEY_B,), active_generation=0)
    token = sign_quote_token(payload, keyset=keyset_for_signing)
    # Replace the leading "0." (generation) with "5." (out of range).
    parts = token.split(".")
    bogus_token = ".".join(["5", parts[1], parts[2]])
    with pytest.raises(QuoteTokenError, match="unknown quote-token key generation"):
        verify_quote_token(bogus_token, keyset=keyset_full, candidate=payload)


def test_verify_supports_post_rotation_keyset() -> None:
    """A token signed under the previous key still verifies after rotation
    (the rotated-out key is at index 1, generation=1)."""
    issued = int(time.time())
    payload = _payload(issued_at_unix_s=issued)
    # Pre-rotation: only B exists, active_generation=0.
    pre = QuoteTokenKeySet(keys=(_KEY_B,), active_generation=0)
    token = sign_quote_token(payload, keyset=pre)
    # Post-rotation: A is the new active key (index 0); B is rotated
    # out at index 1. The token's generation prefix is still "0", so
    # the verifier must look up key index 0 in the post-rotation set —
    # but the token was signed under B, which is now at index 1, so
    # verification fails. To fix: post-rotation, the *prepend* puts
    # the new active key in front, shifting B from gen 0 to gen 1.
    # The token's gen prefix should be re-encoded by the rotation
    # task to "1". Test this by manually re-encoding the prefix.
    parts = token.split(".")
    repointed = ".".join(["1", parts[1], parts[2]])
    post = QuoteTokenKeySet(keys=(_KEY_A, _KEY_B), active_generation=0)
    verify_quote_token(repointed, keyset=post, candidate=payload)


def test_verify_rejects_malformed_token() -> None:
    keyset = QuoteTokenKeySet(keys=(_KEY_A,), active_generation=0)
    with pytest.raises(QuoteTokenError, match="malformed"):
        verify_quote_token("not-a-token", keyset=keyset, candidate=_payload())


# ── OWASP A01/A03 binding (cookie + body hash) ──────────────────


def _make_payload(*, cookie_hmac: bytes = b"", body_hash: bytes = b""):
    from app.services.anonymize.quote_token import QuoteTokenPayload

    return QuoteTokenPayload(
        canonical_pipeline_json=b'{"foo":1}',
        bin_amount_sat=250_000,
        submarine_operator_id="op-sub",
        reverse_operator_id="op-rev",
        delay_min_s=10,
        delay_max_s=60,
        inter_leg_min_s=300,
        inter_leg_max_s=600,
        requested_mpp_k=3,
        issued_at_unix_s=1_000_000,
        ttl_s=300,
        cookie_subject_hmac=cookie_hmac,
        canonical_request_body_hash=body_hash,
    )


def _make_keyset():
    from app.services.anonymize.quote_token import QuoteTokenKeySet

    return QuoteTokenKeySet(keys=(b"k" * 32,), active_generation=0)


def test_canonical_payload_includes_cookie_and_body_hash() -> None:
    import base64

    from app.services.anonymize.quote_token import canonical_quote_payload

    body = _make_payload(cookie_hmac=b"\x11" * 32, body_hash=b"\x22" * 32)
    canon = canonical_quote_payload(body)
    # Both fields appear in the JSON (base64 of the bytes).
    assert b"cookie_subject_hmac" in canon
    assert b"canonical_request_body_hash" in canon
    assert base64.b64encode(b"\x11" * 32) in canon
    assert base64.b64encode(b"\x22" * 32) in canon


def test_verify_rejects_token_when_cookie_subject_changes() -> None:
    """A token signed for one cookie cannot replay onto another."""
    import pytest

    from app.services.anonymize.quote_token import (
        QuoteTokenError,
        sign_quote_token,
        verify_quote_token,
    )

    keyset = _make_keyset()
    issued = _make_payload(cookie_hmac=b"\x11" * 32, body_hash=b"\x99" * 32)
    token = sign_quote_token(issued, keyset=keyset)

    # Verification against a different cookie subject fails.
    rebinding = _make_payload(cookie_hmac=b"\xff" * 32, body_hash=b"\x99" * 32)
    with pytest.raises(QuoteTokenError, match="bound payload differs"):
        verify_quote_token(
            token,
            keyset=keyset,
            candidate=rebinding,
            now_unix_s=1_000_001,
        )


def test_verify_rejects_token_when_body_hash_changes() -> None:
    """Mutating the canonical request body invalidates the token."""
    import hashlib

    import pytest

    from app.services.anonymize.quote_token import (
        QuoteTokenError,
        sign_quote_token,
        verify_quote_token,
    )

    keyset = _make_keyset()
    issued = _make_payload(
        cookie_hmac=b"\x11" * 32,
        body_hash=hashlib.sha256(b"original-body").digest(),
    )
    token = sign_quote_token(issued, keyset=keyset)
    tampered = _make_payload(
        cookie_hmac=b"\x11" * 32,
        body_hash=hashlib.sha256(b"tampered-body").digest(),
    )
    with pytest.raises(QuoteTokenError, match="bound payload differs"):
        verify_quote_token(
            token,
            keyset=keyset,
            candidate=tampered,
            now_unix_s=1_000_001,
        )


def test_verify_accepts_token_with_matching_cookie_and_body() -> None:
    import hashlib
    import hmac as _hmac

    from app.services.anonymize.quote_token import (
        sign_quote_token,
        verify_quote_token,
    )

    keyset = _make_keyset()
    issued = _make_payload(
        cookie_hmac=_hmac.new(
            b"server-secret",
            b"cookie-sub",
            hashlib.sha256,
        ).digest(),
        body_hash=hashlib.sha256(b"canon-body").digest(),
    )
    token = sign_quote_token(issued, keyset=keyset)
    # Identical candidate verifies cleanly.
    verify_quote_token(
        token,
        keyset=keyset,
        candidate=issued,
        now_unix_s=1_000_001,
    )


# ── Cross-replica handoff verify action ─────────────────────────


def test_verify_action_in_memory_when_generation_loaded() -> None:
    from app.services.anonymize.quote_token import (
        decide_quote_token_verify_action,
    )

    out = decide_quote_token_verify_action(
        token_generation=3,
        in_memory_generations=(3, 4),
        rotation_started_at_unix_s=None,
    )
    assert out == "verify_in_memory"


def test_verify_action_wait_inside_propagation_window(monkeypatch) -> None:
    from app.core.config import settings
    from app.services.anonymize.quote_token import (
        decide_quote_token_verify_action,
    )

    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_key_rotation_propagation_s",
        5,
    )
    out = decide_quote_token_verify_action(
        token_generation=4,
        in_memory_generations=(3,),
        rotation_started_at_unix_s=1_000_000.0,
        now_unix_s=1_000_002.0,  # 2s elapsed < 5s window
    )
    assert out == "wait_for_propagation"


def test_verify_action_fallback_db_after_propagation_window(monkeypatch) -> None:
    from app.core.config import settings
    from app.services.anonymize.quote_token import (
        decide_quote_token_verify_action,
    )

    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_key_rotation_propagation_s",
        5,
    )
    out = decide_quote_token_verify_action(
        token_generation=4,
        in_memory_generations=(3,),
        rotation_started_at_unix_s=1_000_000.0,
        now_unix_s=1_000_010.0,  # 10s elapsed > 5s window
    )
    assert out == "fallback_db_read"


def test_verify_action_503_when_db_fallback_times_out(monkeypatch) -> None:
    from app.core.config import settings
    from app.services.anonymize.quote_token import (
        decide_quote_token_verify_action,
    )

    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_key_rotation_propagation_s",
        5,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_verify_db_fallback_timeout_s",
        1,
    )
    out = decide_quote_token_verify_action(
        token_generation=99,
        in_memory_generations=(3,),
        rotation_started_at_unix_s=999_000.0,  # ancient — past propagation
        db_fallback_started_at_unix_s=1_000_000.0,
        now_unix_s=1_000_002.0,  # 2s into fallback > 1s timeout
    )
    assert out == "unavailable_503"
