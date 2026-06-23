# SPDX-License-Identifier: MIT
"""Release-key fingerprint multi-entry support.

The settings accessor ``anonymize_registry_release_key_fingerprints_list``
is the canonical read path for the detached-signature
verification. It supports:

* The plural ``ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS`` config
  (comma-separated list).
* The legacy singular ``ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINT``
  config as an alias for backwards compatibility.
* Empty / unset configurations (returns ``[]``).
"""

from __future__ import annotations

from app.core.config import settings


def test_returns_empty_when_unset(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_registry_release_key_fingerprints", "")
    monkeypatch.setattr(settings, "anonymize_registry_release_key_fingerprint", "")
    assert settings.anonymize_registry_release_key_fingerprints_list == []


def test_returns_singular_alias(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_registry_release_key_fingerprints", "")
    monkeypatch.setattr(
        settings,
        "anonymize_registry_release_key_fingerprint",
        "ABCD1234",
    )
    assert settings.anonymize_registry_release_key_fingerprints_list == ["ABCD1234"]


def test_returns_plural_list(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "anonymize_registry_release_key_fingerprints",
        "AAAA,BBBB,CCCC",
    )
    monkeypatch.setattr(settings, "anonymize_registry_release_key_fingerprint", "")
    assert settings.anonymize_registry_release_key_fingerprints_list == [
        "AAAA",
        "BBBB",
        "CCCC",
    ]


def test_plural_overrides_singular_alias(monkeypatch) -> None:
    """When the plural list is set, the legacy singular alias is ignored."""
    monkeypatch.setattr(
        settings,
        "anonymize_registry_release_key_fingerprints",
        "AAAA,BBBB",
    )
    monkeypatch.setattr(
        settings,
        "anonymize_registry_release_key_fingerprint",
        "LEGACY",
    )
    out = settings.anonymize_registry_release_key_fingerprints_list
    assert out == ["AAAA", "BBBB"]
    assert "LEGACY" not in out


def test_supports_json_array_form(monkeypatch) -> None:
    """The ``_parse_str_list`` helper accepts JSON arrays for the plural value."""
    monkeypatch.setattr(
        settings,
        "anonymize_registry_release_key_fingerprints",
        '["AAAA","BBBB"]',
    )
    out = settings.anonymize_registry_release_key_fingerprints_list
    assert out == ["AAAA", "BBBB"]
