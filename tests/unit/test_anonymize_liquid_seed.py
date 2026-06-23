# SPDX-License-Identifier: MIT
"""Liquid blinding seed loader + startup gate.

The Liquid hop derives blinding pubkeys from a *separate* seed so
deriving them from the LND wallet seed (a tempting code-reuse)
cannot leak via xpub escape. The Liquid round-trip startup gate refuses to
admit the hop unless ``ANONYMIZE_LIQUID_SEED_FERNET`` is set.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.services.anonymize.liquid_seed import (
    LiquidBlindingPath,
    LiquidSeedError,
    assert_liquid_seed_configured,
    liquid_enabled,
    load_liquid_seed_bundle,
    make_blinding_path,
)


def test_liquid_enabled_reads_setting(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    assert liquid_enabled() is True
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", False)
    assert liquid_enabled() is False


def test_load_returns_none_when_seed_unset(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", "")
    assert load_liquid_seed_bundle() is None


def test_load_returns_bundle_when_seed_set(monkeypatch) -> None:
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", key)
    bundle = load_liquid_seed_bundle()
    assert bundle is not None


def test_assert_configured_noop_when_hop_disabled(monkeypatch) -> None:
    """Hop disabled → seed not required → startup passes."""
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", False)
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", "")
    assert_liquid_seed_configured()


def test_assert_configured_refuses_when_hop_enabled_seed_unset(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", "")
    with pytest.raises(LiquidSeedError) as exc:
        assert_liquid_seed_configured()
    assert "ANONYMIZE_LIQUID_SEED_FERNET" in str(exc.value)


def test_assert_configured_passes_when_hop_enabled_seed_set(
    monkeypatch,
) -> None:
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", key)
    assert_liquid_seed_configured()


def test_blinding_path_uses_slip44_liquid_coin_type() -> None:
    path = make_blinding_path(derivation_index=0)
    assert path.coin_type == 1776  # SLIP-44 Liquid Bitcoin
    assert path.derivation_index == 0
    assert path.to_path() == "m/84'/1776'/0'/0/0"


def test_blinding_path_increments_index() -> None:
    p0 = make_blinding_path(derivation_index=0)
    p1 = make_blinding_path(derivation_index=1)
    assert p0.derivation_index == 0
    assert p1.derivation_index == 1
    assert p0.to_path() != p1.to_path()


def test_blinding_path_refuses_negative_index() -> None:
    with pytest.raises(LiquidSeedError):
        make_blinding_path(derivation_index=-1)


def test_blinding_path_is_immutable() -> None:
    """Per-session derivation paths must be value objects."""
    p = LiquidBlindingPath(derivation_index=0)
    with pytest.raises(Exception):
        p.derivation_index = 1  # type: ignore[misc]
