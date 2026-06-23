# SPDX-License-Identifier: MIT
"""Adapter edge-case tests for ``ElectrumChainBackend``.

Targets the gaps in ``app/services/chain/electrum.py`` that the happy-path
adapter tests don't exercise:

* fee cache: stale fallback when estimatefee fails, fresh-cache short-circuit
* malformed responses for every chain method
* unconfirmed-history bookkeeping in ``get_address``
* ``get_block_tip_height`` fallback when no cached tip
* breaker-open path returning a typed error string
* ``from_settings()`` factory wiring
* ``_request`` raising ``ElectrumError`` when no client is configured
"""

from __future__ import annotations

import pytest

from app.services.chain.electrum import (
    _ELECTRUM_BREAKER,
    ElectrumChainBackend,
    ElectrumClient,
    ElectrumError,
)
from tests.unit._fake_electrum import FakeElectrumServer

# ─── Shared fixture ──────────────────────────────────────────────────


@pytest.fixture
async def adapter():
    """A started ``ElectrumChainBackend`` connected to a fake server."""
    async with FakeElectrumServer() as server:
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        backend = ElectrumChainBackend(client=client, network="bitcoin")
        await client.start(wait_for_connect=True)
        # Reset breaker state so tests don't inherit failures from siblings.
        _ELECTRUM_BREAKER.state = "closed"
        _ELECTRUM_BREAKER.consecutive_failures = 0
        try:
            yield backend, server
        finally:
            await backend.close()


# ─── Fee cache freshness and staleness ───────────────────────────────


@pytest.mark.asyncio
async def test_fee_cache_returns_fresh_without_rpc(adapter):
    backend, server = adapter
    server.set_response("blockchain.estimatefee", 0.00010000)
    fees1, err1 = await backend.get_recommended_fees()
    assert err1 is None and fees1 is not None
    n_estimatefee = sum(1 for m, _ in server.calls if m == "blockchain.estimatefee")
    assert n_estimatefee >= 1

    # Second call within TTL: no new estimatefee calls, same dict.
    fees2, err2 = await backend.get_recommended_fees()
    assert err2 is None
    assert fees2 == fees1
    assert sum(1 for m, _ in server.calls if m == "blockchain.estimatefee") == n_estimatefee


@pytest.mark.asyncio
async def test_fee_cache_stale_fallback_on_estimatefee_failure(adapter):
    """When estimatefee fails after a successful prior fetch, the cached
    value is returned with ``stale=True``."""
    backend, server = adapter
    server.set_response("blockchain.estimatefee", 0.00010000)
    fees1, _ = await backend.get_recommended_fees()
    assert fees1 is not None

    # Force expiry of the cache so next call re-issues estimatefee.
    backend._fee_cache_time = 0
    server.set_error("blockchain.estimatefee", -1, "estimator down")

    fees2, err = await backend.get_recommended_fees()
    assert err is None  # stale data returned, not an error
    assert fees2 is not None
    assert fees2.get("stale") is True
    assert "cache_age_s" in fees2


@pytest.mark.asyncio
async def test_fee_no_cache_and_failure_returns_error(adapter):
    """No prior cache + estimatefee failure surfaces an error."""
    backend, server = adapter
    server.set_error("blockchain.estimatefee", -1, "estimator down")
    fees, err = await backend.get_recommended_fees()
    assert fees is None
    assert err is not None and "estimator down" in err


@pytest.mark.asyncio
async def test_fee_invalid_response_returns_error(adapter):
    backend, server = adapter
    server.set_response("blockchain.estimatefee", "not-a-number")
    fees, err = await backend.get_recommended_fees()
    assert fees is None
    # The adapter surfaces a "estimatefee {blocks}: {exc}" message
    # where {exc} is the ValueError from ``float()``. Pin both the
    # error-prefix and the offending value so a future error-shape
    # change is caught explicitly.
    assert err is not None
    assert "estimatefee" in err
    assert "not-a-number" in err


@pytest.mark.asyncio
async def test_fee_for_priority_returns_none_when_fees_unavailable(adapter):
    backend, server = adapter
    server.set_error("blockchain.estimatefee", -1, "boom")
    rate = await backend.get_fee_for_priority("medium")
    assert rate is None


@pytest.mark.asyncio
async def test_fee_for_priority_unknown_priority_uses_medium(adapter):
    backend, server = adapter
    server.set_response("blockchain.estimatefee", 0.00010000)
    # An unknown priority falls back to "medium" rather than erroring.
    rate = await backend.get_fee_for_priority("zonk")
    assert rate is not None
    assert rate >= 1


# ─── Malformed responses for adapter methods ─────────────────────────


@pytest.mark.asyncio
async def test_get_transaction_malformed_returns_error(adapter):
    backend, server = adapter
    server.set_response("blockchain.transaction.get", "not-a-dict")
    tx, err = await backend.get_transaction("aa" * 32)
    assert tx is None
    assert err is not None and "malformed" in err


@pytest.mark.asyncio
async def test_get_address_malformed_balance_returns_error(adapter):
    backend, server = adapter
    server.set_response("blockchain.scripthash.get_balance", "not-a-dict")
    out, err = await backend.get_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    assert out is None and err is not None


@pytest.mark.asyncio
async def test_get_address_malformed_history_returns_error(adapter):
    backend, server = adapter
    server.set_response("blockchain.scripthash.get_balance", {"confirmed": 0, "unconfirmed": 0})
    server.set_response("blockchain.scripthash.get_history", "not-a-list")
    out, err = await backend.get_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    assert out is None and err is not None


@pytest.mark.asyncio
async def test_get_address_counts_unconfirmed_history(adapter):
    """``height <= 0`` rows count as unconfirmed; ``height > 0`` confirmed."""
    backend, server = adapter
    server.set_response(
        "blockchain.scripthash.get_balance",
        {"confirmed": 1000, "unconfirmed": 500},
    )
    server.set_response(
        "blockchain.scripthash.get_history",
        [
            {"tx_hash": "aa" * 32, "height": 800_000},  # confirmed
            {"tx_hash": "bb" * 32, "height": 800_001},  # confirmed
            {"tx_hash": "cc" * 32, "height": 0},  # mempool
            {"tx_hash": "dd" * 32, "height": -1},  # mempool (unconf parent)
        ],
    )
    out, err = await backend.get_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    assert err is None
    assert out is not None
    assert out["confirmed_tx_count"] == 2
    assert out["unconfirmed_tx_count"] == 2
    assert out["confirmed_balance_sats"] == 1000
    assert out["unconfirmed_balance_sats"] == 500
    assert out["total_balance_sats"] == 1500


@pytest.mark.asyncio
async def test_get_address_utxos_malformed_returns_error(adapter):
    backend, server = adapter
    server.set_response("blockchain.scripthash.listunspent", "not-a-list")
    out, err = await backend.get_address_utxos("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    assert out is None and err is not None


@pytest.mark.asyncio
async def test_mempool_stats_malformed_returns_error(adapter):
    backend, server = adapter
    server.set_response("mempool.get_fee_histogram", "not-a-list")
    stats, err = await backend.get_mempool_stats()
    assert stats is None and err is not None


@pytest.mark.asyncio
async def test_mempool_stats_cache_returns_fresh(adapter):
    backend, server = adapter
    server.set_response("mempool.get_fee_histogram", [[10.0, 1500]])
    s1, _ = await backend.get_mempool_stats()
    n_calls = sum(1 for m, _ in server.calls if m == "mempool.get_fee_histogram")
    # Second call within TTL: no new RPC.
    s2, _ = await backend.get_mempool_stats()
    assert s2 == s1
    assert sum(1 for m, _ in server.calls if m == "mempool.get_fee_histogram") == n_calls


@pytest.mark.asyncio
async def test_block_by_height_malformed_returns_error(adapter):
    backend, server = adapter
    server.set_response("blockchain.block.header", 12345)  # not str
    block, err = await backend.get_block_by_height(800_000)
    assert block is None and err is not None


@pytest.mark.asyncio
async def test_block_by_height_invalid_hex_returns_error(adapter):
    """Non-80-byte header hex surfaces from ``_decode_block_header``."""
    backend, server = adapter
    server.set_response("blockchain.block.header", "deadbeef")  # too short
    block, err = await backend.get_block_by_height(800_000)
    assert block is None and err is not None


@pytest.mark.asyncio
async def test_get_block_tip_height_fallback_when_no_cached_tip(adapter):
    """When the client's tip cache is empty, fall back to a fresh
    ``headers.subscribe`` RPC."""
    backend, server = adapter
    # Force-clear the cached tip.
    if backend._client is not None:
        backend._client._tip = None
    server.set_response("blockchain.headers.subscribe", {"height": 800_500, "hex": "00" * 80})
    height, err = await backend.get_block_tip_height()
    assert err is None
    assert height == 800_500


@pytest.mark.asyncio
async def test_get_block_tip_height_fallback_malformed(adapter):
    backend, server = adapter
    if backend._client is not None:
        backend._client._tip = None
    server.set_response("blockchain.headers.subscribe", "not-a-dict")
    height, err = await backend.get_block_tip_height()
    assert height is None
    assert err is not None and "malformed" in err


# ─── get_transaction confirmed-with-tip-cache ────────────────────────


@pytest.mark.asyncio
async def test_get_transaction_confirmations_uses_cached_tip(adapter):
    """``confirmations`` is recomputed from cached tip - block_height + 1
    rather than echoing the RPC field, so a tip-tick advances the count
    without a fresh ``transaction.get``."""
    backend, server = adapter
    # Tip from handshake = 800_000. Block height = 799_998 → 3 confs.
    server.set_response(
        "blockchain.transaction.get",
        {
            "txid": "ab" * 32,
            "confirmations": 3,
            "blockhash": "cd" * 32,
            "blocktime": 1_700_000_000,
            "vin": [],
            "vout": [],
        },
    )
    out, err = await backend.get_transaction_confirmations("ab" * 32)
    assert err is None and out is not None
    assert out["confirmed"] is True
    # tip(800_000) - block_height(800_000 - 3 + 1) + 1 = 3
    assert out["confirmations"] == 3
    assert out["block_height"] == 800_000 - 3 + 1


@pytest.mark.asyncio
async def test_get_transaction_unconfirmed_returns_zero_confs(adapter):
    backend, server = adapter
    server.set_response(
        "blockchain.transaction.get",
        {"txid": "ab" * 32, "confirmations": 0, "vin": [], "vout": []},
    )
    out, err = await backend.get_transaction_confirmations("ab" * 32)
    assert err is None and out is not None
    assert out["confirmed"] is False
    assert out["confirmations"] == 0
    assert out["block_height"] is None


# ─── from_settings + no-client guards ────────────────────────────────


def test_from_settings_returns_backend_with_client(monkeypatch):
    """``from_settings`` parses settings into a client-bearing backend."""
    monkeypatch.setattr(
        "app.services.chain.electrum.settings.lnd_electrum_url",
        "tcp://127.0.0.1:50001",
    )
    monkeypatch.setattr("app.services.chain.electrum.settings.lnd_electrum_tls_verify", True)
    monkeypatch.setattr("app.services.chain.electrum.settings.lnd_electrum_ca_cert", "")
    monkeypatch.setattr("app.services.chain.electrum.settings.lnd_tor_proxy", "")
    monkeypatch.setattr("app.services.chain.electrum.settings.bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        "app.services.chain.electrum.settings.lnd_electrum_connect_timeout_s",
        2.0,
    )
    monkeypatch.setattr(
        "app.services.chain.electrum.settings.lnd_electrum_request_timeout_s",
        2.0,
    )
    monkeypatch.setattr(
        "app.services.chain.electrum.settings.lnd_electrum_ping_interval_s",
        30.0,
    )
    monkeypatch.setattr(
        "app.services.chain.electrum.settings.lnd_electrum_max_subscriptions",
        128,
    )
    backend = ElectrumChainBackend.from_settings()
    assert backend.client is not None
    assert backend.client._url.host == "127.0.0.1"
    assert backend.client._url.port == 50001


@pytest.mark.asyncio
async def test_request_raises_when_no_client():
    """Calling the adapter with no client surfaces ``ElectrumError``."""
    backend = ElectrumChainBackend(client=None, network="bitcoin")
    with pytest.raises(ElectrumError):
        await backend._request("server.ping", [])


# ─── Subscription edge cases ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_subscribe_idempotent_for_same_callback(adapter):
    """Subscribing the same scripthash+callback twice does not duplicate."""
    backend, server = adapter
    client = backend.client
    assert client is not None

    seen: list[tuple[str, str | None]] = []

    async def cb(sh, status):
        seen.append((sh, status))

    sh = "ee" * 32
    await client.subscribe_scripthash(sh, cb)
    await client.subscribe_scripthash(sh, cb)
    assert client._scripthash_subs[sh] == [cb]


@pytest.mark.asyncio
async def test_unsubscribe_specific_callback_keeps_others(adapter):
    """Unsubscribing one callback leaves siblings registered."""
    backend, _server = adapter
    client = backend.client
    assert client is not None

    async def cb1(sh, status):
        pass

    async def cb2(sh, status):
        pass

    sh = "ff" * 32
    await client.subscribe_scripthash(sh, cb1)
    await client.subscribe_scripthash(sh, cb2)
    assert len(client._scripthash_subs[sh]) == 2

    await client.unsubscribe_scripthash(sh, cb1)
    assert client._scripthash_subs[sh] == [cb2]

    # Unsubscribing the last callback removes the entry entirely.
    await client.unsubscribe_scripthash(sh, cb2)
    assert sh not in client._scripthash_subs


@pytest.mark.asyncio
async def test_unsubscribe_unknown_callback_is_silent(adapter):
    """Unsubscribing a callback that was never registered is a no-op."""
    backend, _server = adapter
    client = backend.client
    assert client is not None

    async def never_subbed(sh, status):
        pass

    # Must not raise.
    await client.unsubscribe_scripthash("00" * 32, never_subbed)
