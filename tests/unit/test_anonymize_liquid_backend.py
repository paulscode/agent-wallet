# SPDX-License-Identifier: MIT
"""Liquid backend abstraction.

Covers:

* :class:`MockLiquidBackend` conforms to the :class:`LiquidBackend`
  Protocol at the type-checker level (``isinstance`` against the
  runtime-checkable Protocol).
* All ``(result, error)`` contract paths return the shapes the
  caller expects — success populates ``result``, failure populates
  ``error``.
* The mock's operator-controllable failure injection works per-op.
* The mock broadcast records the submitted hex (for round-trip
  assertions in higher-layer tests).
"""

from __future__ import annotations

import pytest

from app.services.anonymize.liquid_backend import (
    ElectrumLiquidBackend,
    LiquidBackend,
    LiquidTxStatus,
    LiquidUtxo,
    MockLiquidBackend,
)


def _utxo(*, txid: str = "ab" * 32, vout: int = 0) -> LiquidUtxo:
    return LiquidUtxo(
        txid=txid,
        vout=vout,
        script_pubkey=b"\x00\x14" + b"\x11" * 20,
        value_commitment=b"\x09" + b"\xa0" * 32,
        asset_commitment=b"\x0a" + b"\xb0" * 32,
        nonce_commitment=b"\x02" + b"\xc0" * 32,
        rangeproof=b"\xff" * 64,
        surjectionproof=b"\xee" * 64,
        block_height=100,
    )


# ── Protocol conformance ────────────────────────────────────────────


def test_mock_backend_satisfies_protocol() -> None:
    """Runtime-checkable Protocol — the mock must qualify."""
    backend = MockLiquidBackend()
    assert isinstance(backend, LiquidBackend)


def test_electrum_backend_satisfies_protocol() -> None:
    """The live ``ElectrumLiquidBackend`` also conforms to the Protocol."""

    # Pass a stub object — the constructor doesn't probe the client.
    class _StubClient:
        async def close(self) -> None:
            pass

    backend = ElectrumLiquidBackend(_StubClient())
    assert isinstance(backend, LiquidBackend)


# ── Tip height ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_block_tip_height_default_returns_zero() -> None:
    backend = MockLiquidBackend()
    height, err = await backend.get_block_tip_height()
    assert err is None
    assert height == 0


@pytest.mark.asyncio
async def test_get_block_tip_height_reads_set_value() -> None:
    backend = MockLiquidBackend()
    backend.set_tip_height(3_881_110)
    height, err = await backend.get_block_tip_height()
    assert err is None
    assert height == 3_881_110


@pytest.mark.asyncio
async def test_get_block_tip_height_returns_error_when_failed() -> None:
    backend = MockLiquidBackend()
    backend.fail("get_block_tip_height", "rpc_timeout")
    height, err = await backend.get_block_tip_height()
    assert height is None
    assert err == "rpc_timeout"


# ── Fee estimate ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fee_estimate_default_returns_one_sat_per_vb() -> None:
    backend = MockLiquidBackend()
    rate, err = await backend.estimate_fee_sat_per_vb()
    assert err is None
    assert rate == 1.0


@pytest.mark.asyncio
async def test_fee_estimate_respects_preloaded_rate() -> None:
    backend = MockLiquidBackend()
    backend.set_fee_sat_per_vb(2.5)
    rate, err = await backend.estimate_fee_sat_per_vb(target_blocks=12)
    assert err is None
    assert rate == 2.5


@pytest.mark.asyncio
async def test_fee_estimate_rejects_non_positive_target() -> None:
    backend = MockLiquidBackend()
    rate, err = await backend.estimate_fee_sat_per_vb(target_blocks=0)
    assert rate is None
    assert "positive" in (err or "")


# ── UTXO listing ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_address_utxos_returns_empty_by_default() -> None:
    backend = MockLiquidBackend()
    script = b"\x00\x14" + b"\x11" * 20
    utxos, err = await backend.get_address_utxos(script_pubkey=script)
    assert err is None
    assert utxos == []


@pytest.mark.asyncio
async def test_get_address_utxos_returns_added() -> None:
    backend = MockLiquidBackend()
    script = b"\x00\x14" + b"\x22" * 20
    u1 = _utxo(txid="aa" * 32, vout=0)
    u2 = _utxo(txid="aa" * 32, vout=1)
    backend.add_utxo(script, u1)
    backend.add_utxo(script, u2)
    utxos, err = await backend.get_address_utxos(script_pubkey=script)
    assert err is None
    assert utxos == [u1, u2]


@pytest.mark.asyncio
async def test_get_address_utxos_keyed_by_script() -> None:
    """Adding a UTXO to one script must not surface under another."""
    backend = MockLiquidBackend()
    script_a = b"\x00\x14" + b"\x11" * 20
    script_b = b"\x00\x14" + b"\x22" * 20
    backend.add_utxo(script_a, _utxo())
    utxos_b, _ = await backend.get_address_utxos(script_pubkey=script_b)
    assert utxos_b == []


@pytest.mark.asyncio
async def test_get_address_utxos_error_path() -> None:
    backend = MockLiquidBackend()
    backend.fail("get_address_utxos", "backend_disconnected")
    utxos, err = await backend.get_address_utxos(script_pubkey=b"x" * 22)
    assert utxos is None
    assert err == "backend_disconnected"


# ── Transaction hex ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_transaction_hex_returns_added() -> None:
    backend = MockLiquidBackend()
    backend.add_transaction("ab" * 32, "020000000001...")
    hex_str, err = await backend.get_transaction_hex("ab" * 32)
    assert err is None
    assert hex_str == "020000000001..."


@pytest.mark.asyncio
async def test_get_transaction_hex_unknown_returns_error() -> None:
    backend = MockLiquidBackend()
    hex_str, err = await backend.get_transaction_hex("ab" * 32)
    assert hex_str is None
    assert "not found" in (err or "")


# ── Transaction status ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_transaction_status_returns_added() -> None:
    backend = MockLiquidBackend()
    backend.set_transaction_status(
        LiquidTxStatus(
            txid="ab" * 32,
            confirmed=True,
            confirmations=6,
            block_height=100,
        )
    )
    status, err = await backend.get_transaction_status("ab" * 32)
    assert err is None
    assert status is not None
    assert status.confirmed is True
    assert status.confirmations == 6
    assert status.block_height == 100


@pytest.mark.asyncio
async def test_get_transaction_status_unknown_returns_error() -> None:
    backend = MockLiquidBackend()
    status, err = await backend.get_transaction_status("ab" * 32)
    assert status is None
    assert "status unknown" in (err or "")


# ── Broadcast ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_broadcast_returns_txid_and_records() -> None:
    backend = MockLiquidBackend()
    tx_hex = "0200000000010142000000..."
    txid, err = await backend.broadcast_transaction(tx_hex)
    assert err is None
    assert isinstance(txid, str) and len(txid) == 64
    assert backend.broadcasted == [tx_hex]


@pytest.mark.asyncio
async def test_broadcast_is_deterministic_for_same_hex() -> None:
    """The mock synthesises txid from the hex so tests can assert on
    the returned value without prior knowledge."""
    backend = MockLiquidBackend()
    tx_hex = "020000000001abcd"
    txid_a, _ = await backend.broadcast_transaction(tx_hex)
    txid_b, _ = await backend.broadcast_transaction(tx_hex)
    assert txid_a == txid_b


@pytest.mark.asyncio
async def test_broadcast_rejects_empty_hex() -> None:
    backend = MockLiquidBackend()
    txid, err = await backend.broadcast_transaction("")
    assert txid is None
    assert "non-empty" in (err or "")


@pytest.mark.asyncio
async def test_broadcast_error_path() -> None:
    backend = MockLiquidBackend()
    backend.fail("broadcast_transaction", "mempool_min_fee_not_met")
    txid, err = await backend.broadcast_transaction("0200")
    assert txid is None
    assert err == "mempool_min_fee_not_met"


# ── Failure injection consumes once ─────────────────────────────────


@pytest.mark.asyncio
async def test_fail_consumes_once() -> None:
    """Each ``fail()`` injection applies to a single call; the next
    call succeeds. This lets tests script intermittent failures."""
    backend = MockLiquidBackend()
    backend.fail("get_block_tip_height", "transient")
    h1, e1 = await backend.get_block_tip_height()
    h2, e2 = await backend.get_block_tip_height()
    assert h1 is None and e1 == "transient"
    assert h2 == 0 and e2 is None


# ── close() ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_close_is_no_op_on_mock() -> None:
    backend = MockLiquidBackend()
    await backend.close()
