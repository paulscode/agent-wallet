# SPDX-License-Identifier: MIT
"""Dedicated chain-backend client factories."""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.chain import (
    ChainBackendError,
    ChainClientSpec,
    assert_listeners_distinct,
    get_anonymize_chain_client_spec,
    get_general_chain_client_spec,
    sample_first_connect_jitter_s,
)


def test_general_spec_has_general_listener_and_no_jitter(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "tcp://localhost:50001")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    spec = get_general_chain_client_spec()
    assert spec.purpose == "general"
    assert spec.socks_listener == "chain_backend_general"
    assert spec.first_connect_jitter_s == 0
    assert spec.backend_url == "tcp://localhost:50001"


def test_anonymize_spec_has_anonymize_listener_and_jitter(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "tcp://aaa.onion:50001")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    monkeypatch.setattr(settings, "anonymize_chain_client_first_connect_jitter_s", 30)
    spec = get_anonymize_chain_client_spec()
    assert spec.purpose == "anonymize"
    assert spec.socks_listener == "chain_backend_anonymize"
    assert spec.first_connect_jitter_s == 30


def test_assert_listeners_distinct_passes_for_different_listeners(monkeypatch) -> None:
    g = ChainClientSpec(
        purpose="general",
        socks_listener="chain_backend_general",
        backend_url="tcp://x",
        first_connect_jitter_s=0,
    )
    a = ChainClientSpec(
        purpose="anonymize",
        socks_listener="chain_backend_anonymize",
        backend_url="tcp://x",
        first_connect_jitter_s=30,
    )
    assert_listeners_distinct(g, a)  # no raise


def test_assert_listeners_distinct_rejects_collision() -> None:
    g = ChainClientSpec(
        purpose="general",
        socks_listener="chain_backend_shared",
        backend_url="tcp://x",
        first_connect_jitter_s=0,
    )
    a = ChainClientSpec(
        purpose="anonymize",
        socks_listener="chain_backend_shared",
        backend_url="tcp://x",
        first_connect_jitter_s=30,
    )
    with pytest.raises(ChainBackendError, match="distinct SOCKS"):
        assert_listeners_distinct(g, a)


def test_first_connect_jitter_within_band(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_chain_client_first_connect_jitter_s", 30)
    spec = get_anonymize_chain_client_spec()
    for _ in range(50):
        out = sample_first_connect_jitter_s(spec)
        assert 0.0 <= out <= 30.0


def test_first_connect_jitter_zero_for_general_spec(monkeypatch) -> None:
    spec = get_general_chain_client_spec()
    assert sample_first_connect_jitter_s(spec) == 0.0
