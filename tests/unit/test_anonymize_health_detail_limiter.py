# SPDX-License-Identifier: MIT
"""Health-detail rate-limit + audit-log."""

from __future__ import annotations

import time

from app.services.anonymize.health_detail import (
    HealthDetailLimiter,
    build_full_detail_audit_payload,
    coarsen_full_detail_body,
)


def test_limiter_admits_under_budget() -> None:
    lim = HealthDetailLimiter(limit_per_hour=3)
    for _ in range(3):
        assert lim.admit(cookie_id="abc") is True
    assert lim.admit(cookie_id="abc") is False


def test_limiter_admits_separate_cookies_independently() -> None:
    lim = HealthDetailLimiter(limit_per_hour=2)
    assert lim.admit(cookie_id="alice") is True
    assert lim.admit(cookie_id="alice") is True
    assert lim.admit(cookie_id="alice") is False
    # Bob has his own bucket.
    assert lim.admit(cookie_id="bob") is True


def test_limiter_resets_after_window() -> None:
    lim = HealthDetailLimiter(limit_per_hour=2, window_seconds=10)
    now = time.time()
    assert lim.admit(cookie_id="a", now_unix_s=now) is True
    assert lim.admit(cookie_id="a", now_unix_s=now) is True
    assert lim.admit(cookie_id="a", now_unix_s=now) is False
    assert lim.admit(cookie_id="a", now_unix_s=now + 100) is True


def test_limiter_refuses_empty_cookie() -> None:
    lim = HealthDetailLimiter(limit_per_hour=10)
    assert lim.admit(cookie_id="") is False
    assert lim.can_admit(cookie_id="") is False


def test_can_admit_does_not_consume() -> None:
    lim = HealthDetailLimiter(limit_per_hour=2)
    for _ in range(5):
        assert lim.can_admit(cookie_id="x") is True
    # Bucket is still empty.
    assert lim.admit(cookie_id="x") is True


def test_audit_payload_has_short_cookie() -> None:
    payload = build_full_detail_audit_payload(
        cookie_id_short="abcdef0123456789",
        body_keys=["a", "z", "m"],
    )
    assert payload["cookie_short"] == "abcdef01"
    # body_keys are sorted so a regression that re-orders them is flagged.
    assert payload["body_keys"] == ["a", "m", "z"]
    assert isinstance(payload["ts_unix_s"], int)


def test_coarsen_clock_skew_to_50ms_buckets() -> None:
    out = coarsen_full_detail_body({"clock_skew_ms": 173})
    assert out["clock_skew_ms"] == 150


def test_coarsen_cache_age_to_60s_buckets() -> None:
    out = coarsen_full_detail_body({"cache_age_seconds": 487})
    assert out["cache_age_seconds"] == 480


def test_coarsen_registry_size_buckets() -> None:
    assert coarsen_full_detail_body({"registry_size": 0}) == {"registry_size": "0"}
    assert coarsen_full_detail_body({"registry_size": 1}) == {"registry_size": "1-2"}
    assert coarsen_full_detail_body({"registry_size": 4}) == {"registry_size": "3-5"}
    assert coarsen_full_detail_body({"registry_size": 50}) == {"registry_size": "6+"}


def test_coarsen_passes_through_unknown_keys() -> None:
    """Fields not in the coarsening allow-list pass through unchanged."""
    out = coarsen_full_detail_body({"tor_ok": True, "unknown_metric": 999})
    assert out["tor_ok"] is True
    assert out["unknown_metric"] == 999
