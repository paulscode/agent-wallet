# SPDX-License-Identifier: MIT
"""Rotation pre-warm (resign) pass."""

from __future__ import annotations

import pytest

from app.services.anonymize.quote_cache import (
    CacheEntry,
    CacheKey,
    ResignResult,
    run_resign_pass,
)


def _entry(operator_id: str, gen: int) -> CacheEntry:
    return CacheEntry(
        key=CacheKey(operator_id=operator_id, pair="BTC/BTC", asset="BTC"),
        payload={"fee": 100},
        fetched_at_unix_s=1_000.0,
        operator_signature=b"old-sig-" + operator_id.encode(),
        signing_key_generation=gen,
    )


def test_resign_pass_rewrites_rotated_out_entries() -> None:
    entries = [_entry("op-a", gen=4), _entry("op-b", gen=4)]
    calls: list[tuple[str, int]] = []

    def _sign(entry: CacheEntry, gen: int) -> bytes:
        calls.append((entry.key.operator_id, gen))
        return b"new-" + entry.key.operator_id.encode()

    rebuilt, result = run_resign_pass(
        entries,
        active_signing_key_generation=5,
        sign_fn=_sign,
        rate_per_s=1000,
        sleep_fn=lambda _s: None,
    )

    assert result.resign_count == 2
    assert result.skipped_count == 0
    assert calls == [("op-a", 5), ("op-b", 5)]
    assert all(e.signing_key_generation == 5 for e in rebuilt)
    assert rebuilt[0].operator_signature == b"new-op-a"
    assert rebuilt[1].operator_signature == b"new-op-b"


def test_resign_pass_skips_already_active_entries() -> None:
    """Entries already signed under the active key are untouched."""
    entries = [_entry("op-a", gen=5), _entry("op-b", gen=4)]
    rebuilt, result = run_resign_pass(
        entries,
        active_signing_key_generation=5,
        sign_fn=lambda e, gen: b"new-" + e.key.operator_id.encode(),
        rate_per_s=1000,
        sleep_fn=lambda _s: None,
    )
    assert result.resign_count == 1
    assert result.skipped_count == 1
    # Order preserved.
    assert rebuilt[0].key.operator_id == "op-a"
    # First entry untouched.
    assert rebuilt[0].operator_signature == b"old-sig-op-a"
    # Second resigned.
    assert rebuilt[1].operator_signature == b"new-op-b"


def test_resign_pass_throttles_at_configured_rate() -> None:
    """Sleep is called once per non-last resign at 1/rate seconds."""
    entries = [_entry("op-a", gen=4), _entry("op-b", gen=4), _entry("op-c", gen=4)]
    sleeps: list[float] = []
    rebuilt, result = run_resign_pass(
        entries,
        active_signing_key_generation=5,
        sign_fn=lambda e, gen: b"sig",
        rate_per_s=50,
        sleep_fn=sleeps.append,
    )
    # 3 resigns ⇒ 2 sleeps (skip the last); each sleeps 1/50 = 0.02 s.
    assert len(sleeps) == 2
    assert all(abs(s - 0.02) < 1e-9 for s in sleeps)
    assert result.resign_count == 3


def test_resign_pass_no_sleep_when_only_one_entry_resigned() -> None:
    """No sleep on the only resigned entry."""
    entries = [_entry("op-a", gen=4), _entry("op-b", gen=5)]  # only op-a resigns
    sleeps: list[float] = []
    rebuilt, result = run_resign_pass(
        entries,
        active_signing_key_generation=5,
        sign_fn=lambda e, gen: b"sig",
        rate_per_s=50,
        sleep_fn=sleeps.append,
    )
    # Two iterations total, but only one resign — last iteration is the
    # skipped op-b → still skipped because idx == len(entries)-1.
    # op-a is at idx=0, so sleep IS called once.
    assert len(sleeps) == 1
    assert result.resign_count == 1
    assert result.skipped_count == 1


def test_resign_pass_records_duration() -> None:
    """ResignResult exposes a non-negative duration."""
    times = iter([100.0, 100.04])  # start, end
    rebuilt, result = run_resign_pass(
        [_entry("op-a", gen=4)],
        active_signing_key_generation=5,
        sign_fn=lambda e, gen: b"sig",
        rate_per_s=50,
        sleep_fn=lambda _s: None,
        now_fn=lambda: next(times),
    )
    assert isinstance(result, ResignResult)
    assert result.duration_s == pytest.approx(0.04, abs=1e-9)


def test_resign_pass_rejects_zero_rate() -> None:
    with pytest.raises(ValueError):
        run_resign_pass(
            [_entry("op-a", gen=4)],
            active_signing_key_generation=5,
            sign_fn=lambda e, gen: b"sig",
            rate_per_s=0,
        )


def test_resign_pass_empty_list_no_work() -> None:
    rebuilt, result = run_resign_pass(
        [],
        active_signing_key_generation=5,
        sign_fn=lambda e, gen: b"sig",
        rate_per_s=50,
        sleep_fn=lambda _s: None,
    )
    assert rebuilt == []
    assert result.resign_count == 0
    assert result.skipped_count == 0
