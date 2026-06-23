# SPDX-License-Identifier: MIT
"""Unit tests for the per-API-key concurrency cap in app.core.concurrency.

Exercises the non-blocking acquire/release counter that bounds how many
in-flight requests a single API key may hold at once.
"""

from __future__ import annotations

import pytest

from app.core import concurrency


@pytest.fixture(autouse=True)
def _reset():
    concurrency._reset_for_tests()
    concurrency.configure_concurrent_cap(0)
    yield
    concurrency._reset_for_tests()
    concurrency.configure_concurrent_cap(0)


def test_cap_disabled_always_acquires():
    concurrency.configure_concurrent_cap(0)
    assert all(concurrency.try_acquire_for_key("k") for _ in range(100))


def test_acquire_blocks_past_cap_then_frees_on_release():
    concurrency.configure_concurrent_cap(2)
    assert concurrency.try_acquire_for_key("k") is True
    assert concurrency.try_acquire_for_key("k") is True
    # Third concurrent acquire for the same key is refused.
    assert concurrency.try_acquire_for_key("k") is False
    # Releasing one frees exactly one slot.
    concurrency.release_for_key("k")
    assert concurrency.try_acquire_for_key("k") is True
    assert concurrency.try_acquire_for_key("k") is False


def test_keys_are_isolated():
    concurrency.configure_concurrent_cap(1)
    assert concurrency.try_acquire_for_key("a") is True
    assert concurrency.try_acquire_for_key("a") is False
    # A different key has its own independent slot.
    assert concurrency.try_acquire_for_key("b") is True


def test_release_never_exceeds_cap():
    concurrency.configure_concurrent_cap(1)
    assert concurrency.try_acquire_for_key("k") is True
    # Unbalanced extra releases must not inflate the available slots.
    concurrency.release_for_key("k")
    concurrency.release_for_key("k")
    concurrency.release_for_key("k")
    assert concurrency.try_acquire_for_key("k") is True
    assert concurrency.try_acquire_for_key("k") is False


def test_release_unknown_key_is_noop():
    concurrency.configure_concurrent_cap(2)
    # Releasing a key that was never acquired must not raise or create slots.
    concurrency.release_for_key("never-seen")
    assert concurrency.try_acquire_for_key("never-seen") is True


def test_idle_keys_are_evicted_from_the_map():
    """balanced acquire/release must not leave a permanent map entry.

    The concurrency middleware keys this map on the raw (pre-auth) bearer token,
    so an unauthenticated attacker sending one unique token per request
    must not be able to grow the map without bound."""
    concurrency.configure_concurrent_cap(2)
    assert concurrency.tracked_key_count() == 0
    for i in range(1000):
        key = f"attacker-token-{i}"
        assert concurrency.try_acquire_for_key(key) is True
        concurrency.release_for_key(key)
    # Every request fully released → no residual entries.
    assert concurrency.tracked_key_count() == 0


def test_inflight_keys_are_tracked_until_released():
    concurrency.configure_concurrent_cap(2)
    concurrency.try_acquire_for_key("a")
    concurrency.try_acquire_for_key("b")
    assert concurrency.tracked_key_count() == 2
    concurrency.release_for_key("a")
    assert concurrency.tracked_key_count() == 1
    concurrency.release_for_key("b")
    assert concurrency.tracked_key_count() == 0


def test_map_size_backstop_refuses_new_keys_when_full(monkeypatch):
    """When the map is saturated with in-flight keys, NEW keys are
    refused (503) rather than growing the map unbounded."""
    monkeypatch.setattr(concurrency, "_MAX_TRACKED_KEYS", 5)
    concurrency.configure_concurrent_cap(2)
    # Fill the map with 5 distinct in-flight keys (never released).
    for i in range(5):
        assert concurrency.try_acquire_for_key(f"k{i}") is True
    assert concurrency.tracked_key_count() == 5
    # A 6th distinct key is refused by the backstop.
    assert concurrency.try_acquire_for_key("k-overflow") is False
    # An already-tracked key can still acquire its second slot.
    assert concurrency.try_acquire_for_key("k0") is True
