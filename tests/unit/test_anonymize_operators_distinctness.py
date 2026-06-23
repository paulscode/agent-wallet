# SPDX-License-Identifier: MIT
"""Distinct-operator predicate."""

from __future__ import annotations

import pytest

from app.services.anonymize.operators import (
    OperatorEntry,
    assert_operators_distinct,
    assert_url_pair_distinct,
    canonicalize_operator_url,
)


def _e(suffix: str, *, pk: str | None = None, host: str | None = None) -> OperatorEntry:
    return OperatorEntry(
        operator_id=f"boltz-{suffix}",
        onion=host or f"{suffix}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion",
        public_key_hex=(pk or ("02" + suffix.ljust(64, "0"))),
    )


def test_canonicalize_strips_scheme_and_lowercases() -> None:
    assert canonicalize_operator_url("https://Foo.Onion/path") == "foo.onion"
    assert canonicalize_operator_url("foo.onion") == "foo.onion"
    assert canonicalize_operator_url("FOO.ONION:443/api") == "foo.onion"
    assert canonicalize_operator_url("") == ""


def test_distinct_operators_pass() -> None:
    a = _e("a")
    b = _e("b")
    assert_operators_distinct(a, b)  # no raise


def test_same_operator_id_rejected() -> None:
    a = _e("a")
    b = OperatorEntry(operator_id="boltz-a", onion=a.onion, public_key_hex="02" + "b" * 64)
    # Override id collision specifically.
    b = OperatorEntry(operator_id=a.operator_id, onion=_e("b").onion, public_key_hex="02" + "b" * 64)
    with pytest.raises(ValueError, match="operator_id"):
        assert_operators_distinct(a, b)


def test_same_public_key_rejected() -> None:
    a = _e("a")
    b = _e("b", pk=a.public_key_hex)
    with pytest.raises(ValueError, match="public_key_hex"):
        assert_operators_distinct(a, b)


def test_same_onion_host_rejected() -> None:
    """Two operator_ids pointing at the same onion are rejected."""
    a = _e("a")
    b = _e("b", host=a.onion)
    with pytest.raises(ValueError, match="onion host"):
        assert_operators_distinct(a, b)


def test_url_pair_distinct_passes() -> None:
    assert_url_pair_distinct(
        "http://aaa.onion/api/v2",
        "http://bbb.onion/api/v2",
    )


def test_url_pair_distinct_rejects_same_host() -> None:
    with pytest.raises(ValueError, match="share hostname"):
        assert_url_pair_distinct(
            "http://aaa.onion:80/api",
            "http://AAA.onion/v2",  # same host, different scheme/path
        )


def test_url_pair_distinct_skips_when_either_empty() -> None:
    """Single-operator deployments have empty BOLTZ_SUBMARINE_API_URL."""
    assert_url_pair_distinct("", "http://aaa.onion")
    assert_url_pair_distinct("http://aaa.onion", "")
