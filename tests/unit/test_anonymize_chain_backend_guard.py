# SPDX-License-Identifier: MIT
"""Private chain-backend guard.

Resolution + acceptance check + per-call query-shape validation.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.chain import (
    ChainBackendError,
    ChainBackendKind,
    _host_is_local,
    assert_chain_backend_acceptable_for_anonymize,
    assert_txid_query_allowed,
    is_destination_query_allowed,
    is_trusted_local_chain_backend,
    resolve_chain_backend_kind,
)

_ONION_ELECTRUM = "tcp://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxad.onion:50001"


def test_destination_query_always_forbidden() -> None:
    """Anonymize never queries the chain by destination."""
    assert is_destination_query_allowed() is False


def test_resolve_unset_when_no_backend(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    assert resolve_chain_backend_kind() == ChainBackendKind.UNSET


def test_resolve_private_electrum_clearnet(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "tcp://10.0.0.1:50001")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    assert resolve_chain_backend_kind() == ChainBackendKind.PRIVATE_ELECTRUM


def test_resolve_private_electrum_onion(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "lnd_electrum_url",
        "tcp://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxad.onion:50001",
    )
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    assert resolve_chain_backend_kind() == ChainBackendKind.PRIVATE_ELECTRUM_ONION


def test_resolve_public_http(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "https://mempool.space")
    assert resolve_chain_backend_kind() == ChainBackendKind.PUBLIC_HTTP


def test_acceptance_private_onion_passes_no_cap(monkeypatch) -> None:
    monkeypatch.setattr(
        settings,
        "lnd_electrum_url",
        "tcp://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxad.onion:50001",
    )
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    monkeypatch.setattr(settings, "anonymize_allow_public_chain_backend", False)
    status = assert_chain_backend_acceptable_for_anonymize()
    assert status.accepted is True
    assert status.caps_tier_at_weak is False


def test_acceptance_public_refuses_unless_opted_in(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "https://mempool.space")
    monkeypatch.setattr(settings, "anonymize_allow_public_chain_backend", False)
    status = assert_chain_backend_acceptable_for_anonymize()
    assert status.accepted is False
    assert status.caps_tier_at_weak is True
    assert "private chain backend" in (status.reason or "")


def test_acceptance_public_opt_in_caps_at_weak(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "https://mempool.space")
    monkeypatch.setattr(settings, "anonymize_allow_public_chain_backend", True)
    status = assert_chain_backend_acceptable_for_anonymize()
    assert status.accepted is True
    assert status.caps_tier_at_weak is True


def test_acceptance_unset_refuses_by_default(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    monkeypatch.setattr(settings, "anonymize_allow_public_chain_backend", False)
    status = assert_chain_backend_acceptable_for_anonymize()
    assert status.accepted is False


@pytest.mark.parametrize(
    "url",
    [
        "tcp://127.0.0.1:50001",
        "tcp://localhost:50001",
        "tcp://10.0.0.5:50001",
        "tcp://172.16.3.4:50001",
        "tcp://192.168.1.2:50001",
        "tcp://169.254.1.1:50001",  # link-local
        "tcp://electrs.embassy:50001",
        "tcp://fulcrum.startos:50001",
        "http://mempool-rdts.embassy:8999",
        "tcp://electrs:50001",  # bare docker service name
        "http://[::1]:50001",  # IPv6 loopback
    ],
)
def test_host_is_local_true(url: str) -> None:
    assert _host_is_local(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://mempool.space",
        "tcp://8.8.8.8:50001",
        "https://electrum.example.com:50002",
        _ONION_ELECTRUM,  # onion is private but not "local"
        "",
    ],
)
def test_host_is_local_false(url: str) -> None:
    assert _host_is_local(url) is False


def test_trusted_local_requires_opt_in(monkeypatch) -> None:
    """A local backend without the explicit flag is NOT trusted-local."""
    monkeypatch.setattr(settings, "lnd_electrum_url", "tcp://electrs.embassy:50001")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    monkeypatch.setattr(settings, "anonymize_trusted_local_chain_backend", False)
    assert is_trusted_local_chain_backend() is False


def test_trusted_local_true_for_local_endpoints(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "tcp://electrs.embassy:50001")
    monkeypatch.setattr(settings, "lnd_mempool_url", "http://mempool-rdts.embassy:8999")
    monkeypatch.setattr(settings, "anonymize_trusted_local_chain_backend", True)
    assert is_trusted_local_chain_backend() is True


def test_trusted_local_inert_on_public_host(monkeypatch) -> None:
    """The opt-in must be ignored when the backend is genuinely public."""
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "https://mempool.space")
    monkeypatch.setattr(settings, "anonymize_trusted_local_chain_backend", True)
    assert is_trusted_local_chain_backend() is False


def test_trusted_local_false_when_any_endpoint_public(monkeypatch) -> None:
    """A mix of local + public is not fully local — opt-in is inert."""
    monkeypatch.setattr(settings, "lnd_electrum_url", "tcp://electrs.embassy:50001")
    monkeypatch.setattr(settings, "lnd_mempool_url", "https://mempool.space")
    monkeypatch.setattr(settings, "anonymize_trusted_local_chain_backend", True)
    assert is_trusted_local_chain_backend() is False


def test_trusted_local_false_when_unset(monkeypatch) -> None:
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "")
    monkeypatch.setattr(settings, "anonymize_trusted_local_chain_backend", True)
    assert is_trusted_local_chain_backend() is False


def test_acceptance_trusted_local_mempool_no_cap(monkeypatch) -> None:
    """A co-resident Mempool HTTP backend (no electrum) is accepted with no cap
    when trusted-local is opted in — without ANONYMIZE_ALLOW_PUBLIC_CHAIN_BACKEND."""
    monkeypatch.setattr(settings, "lnd_electrum_url", "")
    monkeypatch.setattr(settings, "lnd_mempool_url", "http://mempool-rdts.embassy:8999")
    monkeypatch.setattr(settings, "anonymize_allow_public_chain_backend", False)
    monkeypatch.setattr(settings, "anonymize_trusted_local_chain_backend", True)
    status = assert_chain_backend_acceptable_for_anonymize()
    assert status.accepted is True
    assert status.caps_tier_at_weak is False


def test_assert_txid_query_allowed_normalizes_case() -> None:
    txid = "AABBCCDD" + "00" * 28
    out = assert_txid_query_allowed(txid)
    assert out == txid.lower()


def test_assert_txid_query_allowed_rejects_bad_lengths() -> None:
    with pytest.raises(ChainBackendError):
        assert_txid_query_allowed("aa" * 31)  # 62 hex chars
    with pytest.raises(ChainBackendError):
        assert_txid_query_allowed("aa" * 33)  # 66 hex chars


def test_assert_txid_query_allowed_rejects_non_hex() -> None:
    with pytest.raises(ChainBackendError):
        assert_txid_query_allowed("zz" * 32)


def test_assert_txid_query_allowed_rejects_non_string() -> None:
    with pytest.raises(ChainBackendError):
        assert_txid_query_allowed(b"aa" * 32)  # type: ignore[arg-type]
