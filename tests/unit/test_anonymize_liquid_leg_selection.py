# SPDX-License-Identifier: MIT
"""Unit tests for :func:`select_liquid_leg_urls`.

Mirrors the LN↔on-chain leg-picking policy: canonical Boltz on the
LN→L-BTC (reverse-analog) leg, alt operator (Middleway → Eldamar
fallback) on the L-BTC→LN (submarine-analog) leg, with env-pin
overrides taking precedence over registry-driven resolution.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.operators import (
    OperatorEntry,
    select_liquid_leg_urls,
)


def _entry(
    op_id: str,
    *,
    volume: int = 0,
    audit_date: str = "2026-05-19",
    onion: str | None = None,
    chain_swap_pairs: tuple[str, ...] = (),
) -> OperatorEntry:
    return OperatorEntry(
        operator_id=op_id,
        onion=onion or f"http://{op_id}.onion/v2",
        public_key_hex="",
        attested_min_24h_volume_satoshis=volume,
        last_audit_date=audit_date,
        chain_swap_pairs=chain_swap_pairs,
    )


_BUNDLED = [
    _entry("boltz-canonical", volume=200_000_000),
    _entry("middleway", volume=2_000_000),
    _entry("eldamar", volume=1_000_000),
]


@pytest.fixture(autouse=True)
def _clear_env_overrides(monkeypatch):
    monkeypatch.setattr(settings, "boltz_chain_ln_to_lbtc_api_url", "")
    monkeypatch.setattr(settings, "boltz_chain_lbtc_to_ln_api_url", "")


def test_default_picks_canonical_for_ln_to_lbtc_middleway_for_lbtc_to_ln():
    """Reverse-analog leg → canonical; submarine-analog leg →
    middleway (highest-volume non-canonical operator with the same
    audit date)."""
    sel = select_liquid_leg_urls(registry=_BUNDLED)
    assert sel.ln_to_lbtc_operator_id == "boltz-canonical"
    assert sel.lbtc_to_ln_operator_id == "middleway"
    assert sel.legs_distinct is True


def test_lbtc_to_ln_falls_back_to_eldamar_when_middleway_absent():
    """Same policy as _compute_chain — drop middleway, eldamar wins
    on the non-canonical sort."""
    registry = [_BUNDLED[0], _BUNDLED[2]]  # canonical + eldamar only
    sel = select_liquid_leg_urls(registry=registry)
    assert sel.ln_to_lbtc_operator_id == "boltz-canonical"
    assert sel.lbtc_to_ln_operator_id == "eldamar"
    assert sel.legs_distinct is True


def test_lbtc_to_ln_falls_back_to_canonical_when_only_canonical_remains():
    """Single-operator deployment → both legs collapse to canonical.
    The selector returns this gracefully; the dispatcher logs a
    diversity-reduced warning."""
    registry = [_BUNDLED[0]]
    sel = select_liquid_leg_urls(registry=registry)
    assert sel.ln_to_lbtc_operator_id == "boltz-canonical"
    assert sel.lbtc_to_ln_operator_id == "boltz-canonical"
    assert sel.legs_distinct is False


def test_env_override_pins_ln_to_lbtc(monkeypatch):
    monkeypatch.setattr(
        settings,
        "boltz_chain_ln_to_lbtc_api_url",
        "https://pinned-a.invalid/v2",
    )
    sel = select_liquid_leg_urls(registry=_BUNDLED)
    assert sel.ln_to_lbtc_url == "https://pinned-a.invalid/v2"
    # Operator-id is None because the URL came from env, not registry.
    assert sel.ln_to_lbtc_operator_id is None
    # The other leg still uses registry policy.
    assert sel.lbtc_to_ln_operator_id == "middleway"


def test_env_override_pins_lbtc_to_ln(monkeypatch):
    monkeypatch.setattr(
        settings,
        "boltz_chain_lbtc_to_ln_api_url",
        "https://pinned-b.invalid/v2",
    )
    sel = select_liquid_leg_urls(registry=_BUNDLED)
    assert sel.lbtc_to_ln_url == "https://pinned-b.invalid/v2"
    assert sel.lbtc_to_ln_operator_id is None
    assert sel.ln_to_lbtc_operator_id == "boltz-canonical"


def test_both_env_overrides_pin_both_legs(monkeypatch):
    monkeypatch.setattr(
        settings,
        "boltz_chain_ln_to_lbtc_api_url",
        "https://pinned-a.invalid/v2",
    )
    monkeypatch.setattr(
        settings,
        "boltz_chain_lbtc_to_ln_api_url",
        "https://pinned-b.invalid/v2",
    )
    sel = select_liquid_leg_urls(registry=[])  # registry not consulted
    assert sel.ln_to_lbtc_url == "https://pinned-a.invalid/v2"
    assert sel.lbtc_to_ln_url == "https://pinned-b.invalid/v2"
    assert sel.legs_distinct is True


def test_empty_registry_and_no_env_raises():
    with pytest.raises(RuntimeError) as exc:
        select_liquid_leg_urls(registry=[])
    assert "no Liquid chain-swap operator URL" in str(exc.value)


def test_chain_swap_pairs_filter_excludes_non_liquid_operators():
    """An operator with chain_swap_pairs declared that doesn't
    contain BTC/LBTC is filtered out."""
    registry = [
        _entry("boltz-canonical", volume=200_000_000),
        _entry(
            "alt-no-liquid",
            volume=5_000_000,
            chain_swap_pairs=("BTC/LTC",),  # explicit non-Liquid
        ),
        _entry(
            "alt-with-liquid",
            volume=1_000_000,
            chain_swap_pairs=("BTC/LBTC",),
        ),
    ]
    sel = select_liquid_leg_urls(registry=registry)
    # alt-no-liquid is filtered out → alt-with-liquid is the only
    # non-canonical candidate on the submarine-analog leg.
    assert sel.lbtc_to_ln_operator_id == "alt-with-liquid"


def test_empty_chain_swap_pairs_treated_as_supported():
    """Backwards compat: legacy registry entries without the field
    are implicitly L-BTC-capable (registry-inclusion is trust)."""
    registry = [
        _entry("boltz-canonical", volume=200_000_000),
        _entry("middleway", volume=2_000_000),  # no chain_swap_pairs
    ]
    sel = select_liquid_leg_urls(registry=registry)
    assert sel.lbtc_to_ln_operator_id == "middleway"


def test_most_recent_audit_wins_when_volumes_tie():
    """If two non-canonical operators have the same volume, the
    newer audit-date wins."""
    registry = [
        _entry("boltz-canonical", volume=200_000_000),
        _entry("alt-old", volume=1_000_000, audit_date="2025-01-01"),
        _entry("alt-new", volume=1_000_000, audit_date="2026-05-19"),
    ]
    sel = select_liquid_leg_urls(registry=registry)
    assert sel.lbtc_to_ln_operator_id == "alt-new"
