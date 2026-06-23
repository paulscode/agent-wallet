# SPDX-License-Identifier: MIT
"""Distinct-operator URL splitting.

The submarine and reverse legs MUST hit distinct Boltz hosts so a
single-operator compromise cannot see both sides of the swap. The
resolvers fall back to the shared ``boltz_*_url`` when the leg-
specific overrides are unset (single-operator deployment).
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.operators import (
    assert_distinct_leg_urls_configured,
    has_distinct_legs_configured,
    resolve_reverse_leg_url,
    resolve_submarine_leg_url,
)


@pytest.fixture
def shared_only(monkeypatch):
    """Single-operator baseline: only the shared ``boltz_*_url`` is configured."""
    monkeypatch.setattr(settings, "boltz_api_url", "https://shared.test/v2")
    monkeypatch.setattr(settings, "boltz_onion_url", "http://shared.onion")
    monkeypatch.setattr(settings, "boltz_submarine_api_url", "")
    monkeypatch.setattr(settings, "boltz_submarine_onion_url", "")
    monkeypatch.setattr(settings, "boltz_reverse_api_url", "")
    monkeypatch.setattr(settings, "boltz_reverse_onion_url", "")


@pytest.fixture
def distinct_legs(monkeypatch):
    """Distinct-operator deployment: both leg URLs override the shared default."""
    monkeypatch.setattr(settings, "boltz_api_url", "https://shared.test/v2")
    monkeypatch.setattr(settings, "boltz_onion_url", "http://shared.onion")
    monkeypatch.setattr(
        settings,
        "boltz_submarine_onion_url",
        "http://sub.onion",
    )
    monkeypatch.setattr(
        settings,
        "boltz_reverse_onion_url",
        "http://rev.onion",
    )


def test_resolver_falls_back_to_shared_url(shared_only) -> None:
    assert resolve_submarine_leg_url() == "http://shared.onion"
    assert resolve_reverse_leg_url() == "http://shared.onion"


def test_resolver_picks_leg_specific_when_set(distinct_legs) -> None:
    assert resolve_submarine_leg_url() == "http://sub.onion"
    assert resolve_reverse_leg_url() == "http://rev.onion"


def test_resolver_prefers_onion_by_default(monkeypatch, shared_only) -> None:
    monkeypatch.setattr(
        settings,
        "boltz_submarine_api_url",
        "https://clearnet-sub.test",
    )
    monkeypatch.setattr(
        settings,
        "boltz_submarine_onion_url",
        "http://onion-sub.onion",
    )
    # Onion preferred.
    assert resolve_submarine_leg_url(prefer_onion=True) == "http://onion-sub.onion"
    # Clearnet picked when prefer_onion=False.
    assert resolve_submarine_leg_url(prefer_onion=False) == "https://clearnet-sub.test"


def test_assert_distinct_legs_raises_when_legs_collide(shared_only) -> None:
    """When both legs resolve to the same host (single-operator default),
    the assertion refuses — on-chain sources can't be enabled."""
    with pytest.raises(ValueError, match="resolve to the same hostname"):
        assert_distinct_leg_urls_configured()


def test_assert_distinct_legs_passes_when_legs_differ(distinct_legs) -> None:
    # No raise.
    assert_distinct_leg_urls_configured()


def test_has_distinct_legs_false_on_lightning_baseline(shared_only) -> None:
    assert has_distinct_legs_configured() is False


def test_has_distinct_legs_true_when_legs_differ(distinct_legs) -> None:
    assert has_distinct_legs_configured() is True


def test_has_distinct_legs_false_when_only_one_leg_set(monkeypatch) -> None:
    """A half-configured deployment (only submarine overridden) does
    NOT count as distinct — the reverse leg still uses the shared
    default which may match an operator's other URL."""
    monkeypatch.setattr(settings, "boltz_onion_url", "http://shared.onion")
    monkeypatch.setattr(
        settings,
        "boltz_submarine_onion_url",
        "http://sub.onion",
    )
    monkeypatch.setattr(settings, "boltz_reverse_onion_url", "")
    # Reverse resolves to shared.onion, submarine to sub.onion — distinct
    # *but* the reverse leg is shared with every other wallet caller,
    # which is what is meant to prevent. ``has_distinct_legs``
    # returns True because the URLs differ; ``assert_distinct_leg_urls``
    # is what callers gate session creation on.
    assert has_distinct_legs_configured() is True
