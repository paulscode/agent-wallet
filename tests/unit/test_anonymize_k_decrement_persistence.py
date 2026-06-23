# SPDX-License-Identifier: MIT
"""Persisted strict-K decrement counter."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.k_decrement import (
    get_frozen_fallback_mode,
    get_k_decrements_used,
    increment_k_decrements_used,
)


def _session(
    *,
    pipeline_json: dict | None = None,
    k_decrements_used: int = 0,
) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.LN_HOLDING.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json=pipeline_json or {},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        completed_at=datetime.now(timezone.utc),
        k_decrements_used=k_decrements_used,
    )


def test_get_returns_zero_for_fresh_session() -> None:
    sess = _session()
    assert get_k_decrements_used(sess) == 0


def test_get_handles_none() -> None:
    sess = _session()
    sess.k_decrements_used = None  # type: ignore[assignment]
    assert get_k_decrements_used(sess) == 0


def test_increment_bumps_counter_monotonically() -> None:
    sess = _session()
    assert increment_k_decrements_used(sess) == 1
    assert increment_k_decrements_used(sess) == 2
    assert sess.k_decrements_used == 2


def test_increment_handles_initial_none() -> None:
    sess = _session()
    sess.k_decrements_used = None  # type: ignore[assignment]
    assert increment_k_decrements_used(sess) == 1


def test_frozen_fallback_mode_reads_pipeline_json() -> None:
    sess = _session(pipeline_json={"reverse_payment_mpp_fallback_mode": "abort_below_min"})
    assert get_frozen_fallback_mode(sess) == "abort_below_min"


def test_frozen_fallback_mode_falls_back_to_config(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_reverse_mpp_fallback_mode",
        "legacy",
    )
    sess = _session(pipeline_json={})
    assert get_frozen_fallback_mode(sess) == "legacy"


def test_frozen_fallback_mode_rejects_invalid_pipeline_value(monkeypatch) -> None:
    """A garbage value in pipeline_json falls through to the config default."""
    monkeypatch.setattr(
        settings,
        "anonymize_reverse_mpp_fallback_mode",
        "strict",
    )
    sess = _session(pipeline_json={"reverse_payment_mpp_fallback_mode": "bogus"})
    assert get_frozen_fallback_mode(sess) == "strict"


def test_frozen_fallback_mode_unrecognized_config_returns_strict(monkeypatch) -> None:
    """A bad config value defaults to ``strict`` (the safe choice)."""
    monkeypatch.setattr(
        settings,
        "anonymize_reverse_mpp_fallback_mode",
        "bogus",
    )
    sess = _session(pipeline_json={})
    assert get_frozen_fallback_mode(sess) == "strict"
