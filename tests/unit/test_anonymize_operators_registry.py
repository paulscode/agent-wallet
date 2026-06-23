# SPDX-License-Identifier: MIT
"""Operator registry loader + per-session pair sampler.

Single-operator deployments typically run with an empty / missing
``operators.json`` and use the legacy single-operator flow. The test
covers:

* Empty / missing file → ``[]`` (no error).
* Malformed JSON / missing fields → ``RegistryLoadError``.
* Duplicate operator_id or public_key_hex → rejected.
* Non-onion ``onion`` field → rejected (v3 onion requirement).
* Sampler refuses pairs from < 2 eligible entries.
* Sampler honors ``excluded_ids`` (degraded operators).
* Sampler always picks a distinct (submarine, reverse) pair.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.anonymize.operators import (
    OperatorEntry,
    RegistryLoadError,
    load_operator_registry,
    sample_operator_pair,
)

_VALID_ENTRY_A = {
    "operator_id": "boltz-exchange-2026",
    "onion": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion",
    "public_key_hex": "02" + "a" * 64,
    "attested_min_24h_volume_satoshis": 50_000_000_000,
    "last_audit_date": "2026-05-01",
}
_VALID_ENTRY_B = {
    "operator_id": "boltz-mirror-eu",
    "onion": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbad.onion",
    "public_key_hex": "02" + "b" * 64,
    "attested_min_24h_volume_satoshis": 30_000_000_000,
    "last_audit_date": "2026-04-15",
}
_VALID_ENTRY_C = {
    "operator_id": "boltz-mirror-na",
    "onion": "ccccccccccccccccccccccccccccccccccccccccccccccccccccccad.onion",
    "public_key_hex": "02" + "c" * 64,
    "attested_min_24h_volume_satoshis": 20_000_000_000,
}


def _write_registry(tmp_path: Path, entries: list[dict]) -> Path:
    p = tmp_path / "operators.json"
    p.write_text(json.dumps(entries))
    return p


def test_missing_file_returns_empty(tmp_path: Path) -> None:
    out = load_operator_registry(tmp_path / "does_not_exist.json")
    assert out == []


def test_empty_file_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "operators.json"
    p.write_text("")
    assert load_operator_registry(p) == []


def test_loads_valid_entries(tmp_path: Path) -> None:
    p = _write_registry(tmp_path, [_VALID_ENTRY_A, _VALID_ENTRY_B])
    out = load_operator_registry(p)
    assert len(out) == 2
    assert out[0].operator_id == "boltz-exchange-2026"
    assert out[1].public_key_hex.startswith("02")


def test_invalid_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "operators.json"
    p.write_text("{not json")
    with pytest.raises(RegistryLoadError, match="not valid JSON"):
        load_operator_registry(p)


def test_non_array_raises(tmp_path: Path) -> None:
    p = tmp_path / "operators.json"
    p.write_text('{"operator_id": "x"}')
    with pytest.raises(RegistryLoadError, match="JSON array"):
        load_operator_registry(p)


def test_duplicate_operator_id_rejected(tmp_path: Path) -> None:
    dup = dict(_VALID_ENTRY_B, operator_id=_VALID_ENTRY_A["operator_id"])
    p = _write_registry(tmp_path, [_VALID_ENTRY_A, dup])
    with pytest.raises(RegistryLoadError, match="duplicate operator_id"):
        load_operator_registry(p)


def test_duplicate_public_key_rejected(tmp_path: Path) -> None:
    dup = dict(_VALID_ENTRY_B, public_key_hex=_VALID_ENTRY_A["public_key_hex"])
    p = _write_registry(tmp_path, [_VALID_ENTRY_A, dup])
    with pytest.raises(RegistryLoadError, match="duplicate public_key_hex"):
        load_operator_registry(p)


def test_non_onion_rejected(tmp_path: Path) -> None:
    bad = dict(_VALID_ENTRY_A, onion="api.boltz.exchange")
    p = _write_registry(tmp_path, [bad])
    with pytest.raises(RegistryLoadError, match="not a v3 .onion"):
        load_operator_registry(p)


def test_missing_required_field_rejected(tmp_path: Path) -> None:
    missing_pk = dict(_VALID_ENTRY_A)
    missing_pk.pop("public_key_hex")
    p = _write_registry(tmp_path, [missing_pk])
    with pytest.raises(RegistryLoadError, match="malformed entry"):
        load_operator_registry(p)


# ── sampler ──────────────────────────────────────────────────────────


def _make_entry(suffix: str) -> OperatorEntry:
    return OperatorEntry(
        operator_id=f"boltz-{suffix}",
        onion=f"{suffix}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion",
        public_key_hex="02" + suffix.ljust(64, "0"),
    )


def test_sampler_returns_none_when_under_two_entries() -> None:
    assert sample_operator_pair([]) is None
    assert sample_operator_pair([_make_entry("a")]) is None


def test_sampler_picks_distinct_pair() -> None:
    a, b, c = _make_entry("a"), _make_entry("b"), _make_entry("c")
    for _ in range(50):
        pair = sample_operator_pair([a, b, c])
        assert pair is not None
        sub, rev = pair
        assert sub.operator_id != rev.operator_id


def test_sampler_excludes_degraded() -> None:
    a, b, c = _make_entry("a"), _make_entry("b"), _make_entry("c")
    for _ in range(20):
        pair = sample_operator_pair([a, b, c], excluded_ids=frozenset({"boltz-c"}))
        assert pair is not None
        sub, rev = pair
        assert sub.operator_id != "boltz-c"
        assert rev.operator_id != "boltz-c"


def test_sampler_returns_none_when_excluded_collapses_to_one() -> None:
    a, b = _make_entry("a"), _make_entry("b")
    out = sample_operator_pair([a, b], excluded_ids=frozenset({"boltz-b"}))
    assert out is None  # only `a` remains, can't form a distinct pair
