# SPDX-License-Identifier: MIT
"""Unit tests for ``ElectrumChainBackend`` response shape mapping.

Asserts the adapter produces the same ``(data, error)`` envelope and
the same field names the legacy ``MempoolFeeService`` exposes, so
call sites elsewhere in the codebase don't have to special-case the
backend.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from app.services.chain.electrum import ElectrumChainBackend, ElectrumClient
from tests.unit._fake_electrum import FakeElectrumServer


def _build_block_header(
    *,
    version: int = 1,
    prev_hash: str = "00" * 32,
    merkle_root: str = "11" * 32,
    timestamp: int = 1_700_000_000,
    bits: int = 0x1D00FFFF,
    nonce: int = 12345,
) -> str:
    """Encode an 80-byte Bitcoin block header to hex."""
    raw = (
        struct.pack("<I", version)
        + bytes.fromhex(prev_hash)[::-1]
        + bytes.fromhex(merkle_root)[::-1]
        + struct.pack("<I", timestamp)
        + struct.pack("<I", bits)
        + struct.pack("<I", nonce)
    )
    assert len(raw) == 80
    return raw.hex()


@pytest.fixture
async def started_backend():
    async with FakeElectrumServer() as server:
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        backend = ElectrumChainBackend(client=client, network="bitcoin")
        await backend.ensure_started(wait_for_connect=True)
        try:
            yield backend, server
        finally:
            await backend.close()


# ─── Fees ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_recommended_fees_shape(started_backend) -> None:
    backend, server = started_backend
    # Server returns BTC/kB; adapter converts to sat/vB.
    # 0.00010 BTC/kB == 10 sat/vB.
    server.set_response("blockchain.estimatefee", 0.00010)
    fees, err = await backend.get_recommended_fees()
    assert err is None
    assert set(fees.keys()) >= {
        "fastestFee",
        "halfHourFee",
        "hourFee",
        "economyFee",
        "minimumFee",
    }
    # All values present, ordering monotone non-increasing.
    keys = ["fastestFee", "halfHourFee", "hourFee", "economyFee", "minimumFee"]
    vals = [fees[k] for k in keys]
    assert all(v >= 1 for v in vals)
    for a, b in zip(vals, vals[1:]):
        assert a >= b


@pytest.mark.asyncio
async def test_recommended_fees_clamped_when_estimates_invert(
    started_backend,
) -> None:
    backend, server = started_backend
    # Sequence: faster targets return *lower* fees than slower targets
    # (electrumX can do this at low congestion). Adapter must clamp.
    seq = [0.00001, 0.00002, 0.00003, 0.00004, 0.00005]

    async def fee_handler(params: list) -> float:
        # Pop in call order: 1, 3, 6, 36, 144
        return seq.pop(0)

    server.set_handler("blockchain.estimatefee", fee_handler)
    fees, err = await backend.get_recommended_fees()
    assert err is None
    assert fees["fastestFee"] >= fees["halfHourFee"] >= fees["hourFee"] >= fees["economyFee"] >= fees["minimumFee"] >= 1


@pytest.mark.asyncio
async def test_get_fee_for_priority(started_backend) -> None:
    backend, server = started_backend
    server.set_response("blockchain.estimatefee", 0.00010)
    rate = await backend.get_fee_for_priority("medium")
    assert isinstance(rate, int) and rate >= 1
    rate2 = await backend.get_fee_for_priority("unknown-priority")
    assert isinstance(rate2, int)


@pytest.mark.asyncio
async def test_recommended_fees_returns_error_when_estimate_unavailable(
    started_backend,
) -> None:
    """Core returns ``-1`` for targets it can't estimate (common on a
    quiet mempool for the 3- / 6-block windows). The adapter must
    surface this as an error so :class:`MempoolFeeService` falls back
    to the Mempool HTTP backend — silently pinning the priority to 1
    sat/vB produced the visible Low=1 / Med=1 / High=5 dashboard bug.
    """
    backend, server = started_backend
    # First call (1-block target) succeeds; subsequent targets return -1.
    seq = [0.00005, -1, -1, -1, -1]

    async def fee_handler(params: list) -> float:
        return seq.pop(0)

    server.set_handler("blockchain.estimatefee", fee_handler)
    fees, err = await backend.get_recommended_fees()
    assert fees is None
    assert err is not None
    assert "estimatefee" in err


# ─── Transaction ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_transaction_confirmed(started_backend) -> None:
    backend, server = started_backend
    txid = "ab" * 32
    server.set_response(
        "blockchain.transaction.get",
        {
            "txid": txid,
            "confirmations": 3,
            "blockhash": "cd" * 32,
            "blocktime": 1_700_000_000,
            "fee": 0.00001000,  # 1000 sat
            "size": 200,
            "weight": 800,
            "version": 2,
            "locktime": 0,
            "vin": [{}, {}],
            "vout": [
                {
                    "value": 0.5,  # 50_000_000 sat
                    "scriptPubKey": {
                        "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                    },
                }
            ],
        },
    )
    tx, err = await backend.get_transaction(txid)
    assert err is None
    assert tx["txid"] == txid
    assert tx["confirmed"] is True
    assert tx["fee"] == 1000
    assert tx["block_height"] == 800_000 - 3 + 1  # tip 800000 - confs + 1
    assert tx["vout"][0]["value"] == 50_000_000
    assert tx["vout"][0]["scriptpubkey_address"] == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert tx["vin_count"] == 2
    assert tx["vout_count"] == 1


@pytest.mark.asyncio
async def test_get_transaction_unconfirmed(started_backend) -> None:
    backend, server = started_backend
    txid = "01" * 32
    server.set_response(
        "blockchain.transaction.get",
        {
            "txid": txid,
            "confirmations": 0,
            "fee": None,
            "vin": [],
            "vout": [],
        },
    )
    tx, err = await backend.get_transaction(txid)
    assert err is None
    assert tx["confirmed"] is False
    assert tx["block_height"] is None
    assert tx["block_hash"] is None


@pytest.mark.asyncio
async def test_get_transaction_confirmations(started_backend) -> None:
    backend, server = started_backend
    server.set_response(
        "blockchain.transaction.get",
        {
            "txid": "02" * 32,
            "confirmations": 6,
            "blockhash": "00" * 32,
            "blocktime": 1_700_000_000,
            "vin": [],
            "vout": [],
        },
    )
    out, err = await backend.get_transaction_confirmations("02" * 32)
    assert err is None
    assert out["confirmed"] is True
    assert out["confirmations"] == 6


@pytest.mark.asyncio
async def test_protocol_error_returned_as_string(started_backend) -> None:
    backend, server = started_backend
    server.set_error("blockchain.transaction.get", -32600, "no such tx")
    tx, err = await backend.get_transaction("ff" * 32)
    assert tx is None
    assert err is not None
    assert "no such tx" in err


# ─── Address ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_address_balance_and_history(started_backend) -> None:
    backend, server = started_backend
    addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    server.set_response(
        "blockchain.scripthash.get_balance",
        {"confirmed": 100_000, "unconfirmed": 5_000},
    )
    server.set_response(
        "blockchain.scripthash.get_history",
        [
            {"tx_hash": "aa" * 32, "height": 800_000},
            {"tx_hash": "bb" * 32, "height": 0},  # mempool
            {"tx_hash": "cc" * 32, "height": 799_999},
        ],
    )
    out, err = await backend.get_address(addr)
    assert err is None
    assert out["address"] == addr
    assert out["confirmed_balance_sats"] == 100_000
    assert out["unconfirmed_balance_sats"] == 5_000
    assert out["total_balance_sats"] == 105_000
    assert out["confirmed_tx_count"] == 2
    assert out["unconfirmed_tx_count"] == 1
    # These are explicitly None for the electrum backend.
    assert out["funded_txo_count"] is None
    assert out["spent_txo_count"] is None


@pytest.mark.asyncio
async def test_get_address_utxos(started_backend) -> None:
    backend, server = started_backend
    addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    server.set_response(
        "blockchain.scripthash.listunspent",
        [
            {
                "tx_hash": "11" * 32,
                "tx_pos": 0,
                "value": 50_000,
                "height": 800_000,
            },
            {
                "tx_hash": "22" * 32,
                "tx_pos": 1,
                "value": 10_000,
                "height": 0,
            },
        ],
    )
    utxos, err = await backend.get_address_utxos(addr)
    assert err is None
    assert len(utxos) == 2
    assert utxos[0]["txid"] == "11" * 32
    assert utxos[0]["value_sats"] == 50_000
    assert utxos[0]["confirmed"] is True
    assert utxos[1]["confirmed"] is False
    assert utxos[1]["block_height"] is None


@pytest.mark.asyncio
async def test_get_address_invalid(started_backend) -> None:
    backend, _server = started_backend
    out, err = await backend.get_address("not-an-address")
    assert out is None
    assert err is not None


# ─── Mempool stats ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_mempool_stats(started_backend) -> None:
    backend, server = started_backend
    server.set_response(
        "mempool.get_fee_histogram",
        [[100.0, 50_000], [50.0, 200_000], [10.0, 1_000_000]],
    )
    stats, err = await backend.get_mempool_stats()
    assert err is None
    assert stats["fee_histogram"] == [
        [100.0, 50_000],
        [50.0, 200_000],
        [10.0, 1_000_000],
    ]
    # These are documented as None on the electrum backend.
    assert stats["tx_count"] is None
    assert stats["total_vsize"] is None
    assert stats["total_fee_btc"] is None


# ─── Block tip / header ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_block_tip_height_uses_cache(started_backend) -> None:
    backend, server = started_backend
    height, err = await backend.get_block_tip_height()
    assert err is None
    assert height == 800_000
    # Pushed notification updates the cache without an extra RPC.
    await server.notify_headers(800_005)
    import asyncio as _a

    for _ in range(50):
        if backend.client and backend.client.cached_tip_height == 800_005:
            break
        await _a.sleep(0.01)
    height, err = await backend.get_block_tip_height()
    assert err is None
    assert height == 800_005


@pytest.mark.asyncio
async def test_get_block_by_height_decodes_header(started_backend) -> None:
    backend, server = started_backend
    prev_hash = "ab" * 32
    timestamp = 1_705_000_000
    header_hex = _build_block_header(prev_hash=prev_hash, timestamp=timestamp)
    server.set_response("blockchain.block.header", header_hex)
    block, err = await backend.get_block_by_height(801_234)
    assert err is None
    assert block["height"] == 801_234
    assert block["timestamp"] == timestamp
    assert block["previous_block_hash"] == prev_hash
    # Hash = sha256d(raw)[::-1].
    expected_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(header_hex)).digest()).digest()[::-1].hex()
    assert block["hash"] == expected_hash
    # Not derivable from a header alone.
    assert block["tx_count"] is None
    assert block["size"] is None
    assert block["weight"] is None
    assert block["difficulty"] is None
