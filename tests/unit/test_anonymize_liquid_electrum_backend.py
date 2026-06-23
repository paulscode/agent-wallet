# SPDX-License-Identifier: MIT
"""Live ElectrumLiquidBackend wire.

Anchors against a real Liquid mainnet tx (fixture
``tests/vectors/liquid/blinded_tx_4outputs.hex`` — txid
``0c4c79f32f0bc6e927893a71b8a56911e4a5a507cd382f5e21b1a0abbfef393b``,
5 outputs: 4 CT-blinded + 1 explicit fee). Confirms that the
backend's tx-parsing path extracts the right CT commitment bytes
from a wire-format Liquid tx.

The Electrum protocol layer is mocked at the ``ElectrumClient.request``
boundary so each method's wire mapping is verified without needing
a live electrs-liquid server.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.services.anonymize.liquid_backend import (
    ElectrumLiquidBackend,
    LiquidBackend,
    LiquidUtxo,
    _parse_liquid_utxo,
    _script_pubkey_to_scripthash,
)

# Real Liquid mainnet tx fixture: 4 blinded outputs + 1 explicit fee.
_FIXTURE = Path(__file__).parent.parent / "vectors" / "liquid" / "blinded_tx_4outputs.hex"
_TX_HEX = _FIXTURE.read_text(encoding="utf-8").strip()
_TXID = "0c4c79f32f0bc6e927893a71b8a56911e4a5a507cd382f5e21b1a0abbfef393b"


class _MockClient:
    """Minimal ElectrumClient stand-in for tests.

    Operator-controllable: preload responses via ``set_response`` keyed
    by ``(method, tuple(params))``. The mock records every call into
    ``calls`` for downstream assertions.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, list]] = []
        self._responses: dict[tuple[str, tuple], object] = {}
        self._default_response: object = None
        self._error: Exception | None = None

    def set_response(self, method: str, params: tuple, response: object) -> None:
        self._responses[(method, tuple(params))] = response

    def set_default(self, response: object) -> None:
        self._default_response = response

    def fail(self, exc: Exception) -> None:
        self._error = exc

    async def request(self, method: str, params: list | None = None) -> object:
        p = tuple(params or [])
        self.calls.append((method, list(p)))
        if self._error is not None:
            raise self._error
        if (method, p) in self._responses:
            return self._responses[(method, p)]
        return self._default_response

    async def close(self) -> None:
        pass


# ── Protocol conformance ──────────────────────────────────────────


def test_satisfies_liquid_backend_protocol() -> None:
    backend = ElectrumLiquidBackend(_MockClient())
    assert isinstance(backend, LiquidBackend)


# ── scripthash helper ─────────────────────────────────────────────


def test_scripthash_helper_byte_reverses_sha256() -> None:
    """Electrum protocol scripthash = SHA-256 of scriptPubKey, byte-reversed."""
    import hashlib

    script = b"\x00\x14" + b"\x11" * 20
    expected = hashlib.sha256(script).digest()[::-1].hex()
    assert _script_pubkey_to_scripthash(script) == expected


# ── get_block_tip_height ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_block_tip_height_reads_height() -> None:
    client = _MockClient()
    client.set_response("blockchain.headers.subscribe", (), {"height": 3_881_402, "hex": "..."})
    backend = ElectrumLiquidBackend(client)
    h, err = await backend.get_block_tip_height()
    assert err is None
    assert h == 3_881_402


@pytest.mark.asyncio
async def test_get_block_tip_height_handles_malformed() -> None:
    client = _MockClient()
    client.set_response("blockchain.headers.subscribe", (), "not-a-dict")
    backend = ElectrumLiquidBackend(client)
    h, err = await backend.get_block_tip_height()
    assert h is None
    assert "unexpected" in (err or "")


@pytest.mark.asyncio
async def test_get_block_tip_height_propagates_rpc_error() -> None:
    client = _MockClient()
    client.fail(RuntimeError("disconnected"))
    backend = ElectrumLiquidBackend(client)
    h, err = await backend.get_block_tip_height()
    assert h is None
    assert "disconnected" in (err or "")


# ── estimate_fee_sat_per_vb ───────────────────────────────────────


@pytest.mark.asyncio
async def test_estimate_fee_converts_btc_per_kvb_to_sat_per_vb() -> None:
    """Electrum returns BTC/kvB as a float. The wallet converts to
    sat/vB by multiplying by 1e5. Pick an input where the conversion
    is exactly representable to keep the check deterministic."""
    client = _MockClient()
    # 0.001 BTC/kvB × 1e5 = 100.0 sat/vB — both exactly representable.
    client.set_response("blockchain.estimatefee", (6,), 0.001)
    backend = ElectrumLiquidBackend(client)
    rate, err = await backend.estimate_fee_sat_per_vb()
    assert err is None
    assert rate == 100.0


@pytest.mark.asyncio
async def test_estimate_fee_handles_unavailable_signal() -> None:
    """``-1`` means electrs couldn't estimate."""
    client = _MockClient()
    client.set_response("blockchain.estimatefee", (6,), -1)
    backend = ElectrumLiquidBackend(client)
    rate, err = await backend.estimate_fee_sat_per_vb()
    assert rate is None
    assert "no fee estimate" in (err or "")


@pytest.mark.asyncio
async def test_estimate_fee_passes_target_blocks() -> None:
    """The wire param is the configured target."""
    client = _MockClient()
    client.set_default(0.0001)
    backend = ElectrumLiquidBackend(client)
    await backend.estimate_fee_sat_per_vb(target_blocks=12)
    assert client.calls[-1] == ("blockchain.estimatefee", [12])


@pytest.mark.asyncio
async def test_estimate_fee_rejects_non_positive_target() -> None:
    backend = ElectrumLiquidBackend(_MockClient())
    rate, err = await backend.estimate_fee_sat_per_vb(target_blocks=0)
    assert rate is None
    assert "positive" in (err or "")


# ── get_transaction_hex ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_transaction_hex_passes_raw_flag() -> None:
    """The second param ``False`` requests the raw hex (not verbose)."""
    client = _MockClient()
    client.set_response("blockchain.transaction.get", ("ab" * 32, False), "0200")
    backend = ElectrumLiquidBackend(client)
    hex_str, err = await backend.get_transaction_hex("ab" * 32)
    assert err is None
    assert hex_str == "0200"


@pytest.mark.asyncio
async def test_get_transaction_hex_rejects_empty_txid() -> None:
    backend = ElectrumLiquidBackend(_MockClient())
    hex_str, err = await backend.get_transaction_hex("")
    assert hex_str is None
    assert "non-empty" in (err or "")


# ── get_transaction_status ────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_transaction_status_reads_confirmations() -> None:
    client = _MockClient()
    client.set_response(
        "blockchain.transaction.get",
        ("ab" * 32, True),
        {"confirmations": 6, "height": 100},
    )
    backend = ElectrumLiquidBackend(client)
    status, err = await backend.get_transaction_status("ab" * 32)
    assert err is None
    assert status is not None
    assert status.confirmed is True
    assert status.confirmations == 6
    assert status.block_height == 100


@pytest.mark.asyncio
async def test_get_transaction_status_treats_zero_confs_as_unconfirmed() -> None:
    client = _MockClient()
    client.set_response(
        "blockchain.transaction.get",
        ("ab" * 32, True),
        {"confirmations": 0},  # in mempool, no height yet
    )
    backend = ElectrumLiquidBackend(client)
    status, err = await backend.get_transaction_status("ab" * 32)
    assert err is None
    assert status.confirmed is False
    assert status.confirmations == 0
    assert status.block_height is None


# ── broadcast_transaction ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_broadcast_returns_txid() -> None:
    client = _MockClient()
    client.set_response(
        "blockchain.transaction.broadcast",
        ("0200",),
        "abcd" * 16,
    )
    backend = ElectrumLiquidBackend(client)
    txid, err = await backend.broadcast_transaction("0200")
    assert err is None
    assert txid == "abcd" * 16


@pytest.mark.asyncio
async def test_broadcast_rejects_empty_hex() -> None:
    backend = ElectrumLiquidBackend(_MockClient())
    txid, err = await backend.broadcast_transaction("")
    assert txid is None
    assert "non-empty" in (err or "")


@pytest.mark.asyncio
async def test_broadcast_handles_empty_response() -> None:
    client = _MockClient()
    client.set_default("")
    backend = ElectrumLiquidBackend(client)
    txid, err = await backend.broadcast_transaction("0200")
    assert txid is None
    assert "unexpected" in (err or "")


# ── _parse_liquid_utxo against a real Liquid tx ───────────────────


def test_parse_extracts_blinded_output_from_real_tx() -> None:
    """Output 0 of the fixture is CT-blinded; parser must surface the
    33-byte asset commitment + 33-byte value commitment + nonce +
    rangeproof + surjection proof."""
    utxo = _parse_liquid_utxo(
        tx_hex=_TX_HEX,
        txid=_TXID,
        vout=0,
        block_height=3_881_402,
    )
    assert utxo is not None
    assert isinstance(utxo, LiquidUtxo)
    assert utxo.txid == _TXID
    assert utxo.vout == 0
    assert len(utxo.script_pubkey) > 0
    # CT commitment shapes
    assert len(utxo.asset_commitment) == 33
    assert utxo.asset_commitment[0] in (0x0A, 0x0B)
    assert len(utxo.value_commitment) == 33
    assert utxo.value_commitment[0] in (0x08, 0x09)
    assert len(utxo.nonce_commitment) == 33
    assert len(utxo.rangeproof) > 100  # real proofs are kilobytes
    assert len(utxo.surjectionproof) > 30
    assert utxo.block_height == 3_881_402
    # No advisory cleartext for blinded outputs
    assert utxo.advisory_value_sat is None
    assert utxo.advisory_asset_id is None


def test_parse_extracts_all_four_blinded_outputs() -> None:
    """All four CT-blinded outputs (0..3) parse cleanly."""
    for vout in range(4):
        utxo = _parse_liquid_utxo(
            tx_hex=_TX_HEX,
            txid=_TXID,
            vout=vout,
            block_height=None,
        )
        assert utxo is not None, f"output {vout} failed to parse"
        assert utxo.vout == vout
        assert utxo.asset_commitment[0] in (0x0A, 0x0B)


def test_parse_filters_explicit_fee_output_by_default() -> None:
    """Output 4 is the explicit (unblinded) fee output. The receive
    path only handles CT-blinded credits, so the parser filters
    unblinded outputs by default."""
    utxo = _parse_liquid_utxo(
        tx_hex=_TX_HEX,
        txid=_TXID,
        vout=4,
        block_height=None,
    )
    assert utxo is None


def test_parse_surfaces_explicit_output_when_flag_set() -> None:
    """For testing / read-only operator queries, set
    ``accept_unblinded=True`` to surface fee outputs."""
    utxo = _parse_liquid_utxo(
        tx_hex=_TX_HEX,
        txid=_TXID,
        vout=4,
        block_height=None,
        accept_unblinded=True,
    )
    assert utxo is not None
    assert utxo.advisory_value_sat is not None
    assert utxo.advisory_value_sat > 0
    assert utxo.advisory_asset_id is not None
    assert len(utxo.advisory_asset_id) == 32


def test_parse_returns_none_for_out_of_range_vout() -> None:
    utxo = _parse_liquid_utxo(
        tx_hex=_TX_HEX,
        txid=_TXID,
        vout=99,
        block_height=None,
    )
    assert utxo is None


def test_parse_returns_none_for_malformed_hex() -> None:
    utxo = _parse_liquid_utxo(
        tx_hex="not-hex",
        txid=_TXID,
        vout=0,
        block_height=None,
    )
    assert utxo is None


def test_parse_returns_none_for_empty_hex() -> None:
    utxo = _parse_liquid_utxo(
        tx_hex="",
        txid=_TXID,
        vout=0,
        block_height=None,
    )
    assert utxo is None


# ── get_address_utxos end-to-end (full flow) ──────────────────────


@pytest.mark.asyncio
async def test_get_address_utxos_full_flow_with_blinded_tx() -> None:
    """End-to-end: scripthash → listunspent → fetch hex → parse.

    Loads the fixture tx into the mock client + responds to the
    ``listunspent`` call with a single hit pointing at output 0 of
    the fixture. Confirms the backend returns a parsed LiquidUtxo
    carrying the right CT commitments.
    """
    import wallycore as _wally

    # Extract the output 0 scriptPubKey from the fixture so we can
    # compute the scripthash the backend will query.
    FLAGS = _wally.WALLY_TX_FLAG_USE_ELEMENTS | _wally.WALLY_TX_FLAG_USE_WITNESS
    tx = _wally.tx_from_bytes(bytes.fromhex(_TX_HEX), FLAGS)
    script0 = bytes(_wally.tx_get_output_script(tx, 0))
    sh = _script_pubkey_to_scripthash(script0)

    client = _MockClient()
    client.set_response(
        "blockchain.scripthash.listunspent",
        (sh,),
        [{"tx_hash": _TXID, "tx_pos": 0, "height": 3_881_402, "value": 0}],
    )
    client.set_response(
        "blockchain.transaction.get",
        (_TXID, False),
        _TX_HEX,
    )

    backend = ElectrumLiquidBackend(client)
    utxos, err = await backend.get_address_utxos(script_pubkey=script0)
    assert err is None
    assert utxos is not None
    assert len(utxos) == 1
    u = utxos[0]
    assert u.txid == _TXID
    assert u.vout == 0
    assert u.script_pubkey == script0
    assert len(u.asset_commitment) == 33
    assert u.asset_commitment[0] in (0x0A, 0x0B)
    assert u.block_height == 3_881_402


@pytest.mark.asyncio
async def test_get_address_utxos_skips_unfetchable_entries() -> None:
    """If transaction.get fails for one entry, the backend skips it
    and continues. This defends against partial backend failures —
    a transient error on one UTXO shouldn't block the whole list."""

    class _PartialFailClient(_MockClient):
        async def request(self, method, params=None):
            self.calls.append((method, list(params or [])))
            if method == "blockchain.scripthash.listunspent":
                return [
                    {"tx_hash": "aa" * 32, "tx_pos": 0, "height": 100},
                    {"tx_hash": _TXID, "tx_pos": 0, "height": 200},
                ]
            if method == "blockchain.transaction.get":
                txid = params[0]
                if txid == "aa" * 32:
                    raise RuntimeError("not found")
                return _TX_HEX
            return None

    client = _PartialFailClient()
    backend = ElectrumLiquidBackend(client)
    utxos, err = await backend.get_address_utxos(script_pubkey=b"\x00\x14" + b"\x11" * 20)
    assert err is None
    # Only the second (parsable) entry surfaces
    assert utxos is not None
    assert len(utxos) == 1
    assert utxos[0].txid == _TXID


@pytest.mark.asyncio
async def test_get_address_utxos_returns_empty_when_listunspent_empty() -> None:
    client = _MockClient()
    client.set_default([])
    backend = ElectrumLiquidBackend(client)
    utxos, err = await backend.get_address_utxos(script_pubkey=b"\x00\x14" + b"\x11" * 20)
    assert err is None
    assert utxos == []


@pytest.mark.asyncio
async def test_get_address_utxos_rejects_empty_script() -> None:
    backend = ElectrumLiquidBackend(_MockClient())
    utxos, err = await backend.get_address_utxos(script_pubkey=b"")
    assert utxos is None
    assert "non-empty" in (err or "")


# ── close ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_close_calls_client_close() -> None:
    closed: list[bool] = []

    class _Client(_MockClient):
        async def close(self) -> None:
            closed.append(True)

    backend = ElectrumLiquidBackend(_Client())
    await backend.close()
    assert closed == [True]


@pytest.mark.asyncio
async def test_close_tolerates_client_without_close_method() -> None:
    class _Client:
        async def request(self, method, params=None):
            return None

    backend = ElectrumLiquidBackend(_Client())
    # Should not raise.
    await backend.close()
