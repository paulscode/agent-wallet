# SPDX-License-Identifier: MIT
"""Liquid chain-backend abstraction.

The Liquid hop needs an interface to:

* Observe credits to a watch-only confidential address (when Boltz
  publishes the LN→L-BTC lockup tx).
* Pull the raw blinded outputs (so we can locally unblind via
  :mod:`liquid_ct`).
* Broadcast our claim/spend transactions.
* Estimate fees at quote time.
* Read the current chain tip for confirmation counting.

This module is the boundary between the wallet and the operator-
deployed Liquid backend. **Default implementation: electrs-liquid via
the Electrum protocol** (see the docstring on
:class:`ElectrumLiquidBackend` for the wire mapping). The abstraction
intentionally mirrors the existing Bitcoin
:class:`app.services.chain.backend.ChainBackend` so reviewers don't
have to context-switch between two paradigms.

A future Elements-RPC backend would implement the same Protocol; the
hop body should not know which implementation is in play.

All operations follow the wallet's ``(result, error)`` async return
convention — errors do not raise into the per-session loop's
bounded-retry budget.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable

# ── Return-shape value objects ─────────────────────────────────────


@dataclass(frozen=True)
class LiquidUtxo:
    """One Liquid UTXO under a watched scriptPubKey.

    Unlike a Bitcoin UTXO, the ``value`` is not directly readable from
    the chain — it's hidden behind a Pedersen commitment. The wallet
    pulls the raw blinded fields here and unblinds locally via
    :mod:`liquid_ct` using the corresponding blinding privkey.

    All commitments are 33-byte compressed-form bytes (the on-wire
    encoding); range proofs vary in size and are passed through
    untouched.
    """

    txid: str
    vout: int
    script_pubkey: bytes
    value_commitment: bytes
    asset_commitment: bytes
    nonce_commitment: bytes
    rangeproof: bytes
    surjectionproof: bytes
    block_height: Optional[int]
    # The backend MAY surface a cleartext ``value_sat`` + ``asset_id``
    # when the operator's electrs has explicit blinding-key visibility
    # (e.g., backend-side `importblindingkey`), but the wallet does
    # NOT trust these — unblinding always happens locally to keep
    # blinding-key authority on the wallet host.
    advisory_value_sat: Optional[int] = None
    advisory_asset_id: Optional[bytes] = None


@dataclass(frozen=True)
class LiquidTxStatus:
    """Confirmation state of a broadcast/observed tx."""

    txid: str
    confirmed: bool
    confirmations: int
    block_height: Optional[int]


# ── Protocol ───────────────────────────────────────────────────────


@runtime_checkable
class LiquidBackend(Protocol):
    """The async interface the Liquid hop calls into.

    Implementations:
    * :class:`MockLiquidBackend` — for tests + early integration.
    * :class:`ElectrumLiquidBackend` — production wire to electrs-liquid
      over the dedicated ``liquid=9052`` Tor SOCKS listener.
    """

    name: str

    async def get_block_tip_height(self) -> tuple[Optional[int], Optional[str]]:
        """Current chain tip height or ``(None, error)``."""

    async def estimate_fee_sat_per_vb(
        self,
        target_blocks: int = 6,
    ) -> tuple[Optional[float], Optional[str]]:
        """Fee-rate estimate in sat/vB. ``target_blocks`` mirrors
        Electrum's ``estimatefee`` semantics."""

    async def get_address_utxos(
        self,
        *,
        script_pubkey: bytes,
    ) -> tuple[Optional[list[LiquidUtxo]], Optional[str]]:
        """List UTXOs for the address represented by ``script_pubkey``.

        Liquid is multi-asset; the backend MAY return non-L-BTC UTXOs.
        The caller filters by ``asset_id`` after unblinding locally.
        """

    async def get_transaction_hex(
        self,
        txid: str,
    ) -> tuple[Optional[str], Optional[str]]:
        """Fetch the full Elements-format raw transaction hex."""

    async def get_transaction_status(
        self,
        txid: str,
    ) -> tuple[Optional[LiquidTxStatus], Optional[str]]:
        """Confirmation state for ``txid``."""

    async def broadcast_transaction(
        self,
        tx_hex: str,
    ) -> tuple[Optional[str], Optional[str]]:
        """Broadcast a signed Elements-format hex tx; return its
        txid or an error string."""

    async def close(self) -> None:
        """Tear down connections held by this backend."""


# ── Mock implementation ────────────────────────────────────────────


class MockLiquidBackend:
    """In-memory backend for tests + early hop integration.

    Behaviour is deterministic and operator-controllable: the test
    body pre-loads the expected responses via the ``preload_*`` /
    ``add_utxo`` methods, then runs the hop body. Each query consumes
    a preloaded response (FIFO) or returns the configured default.
    """

    name: str = "mock-liquid"

    def __init__(self) -> None:
        self._tip_height: Optional[int] = 0
        self._fee_sat_per_vb: Optional[float] = 1.0
        # script_pubkey hex → list of UTXOs
        self._utxos_by_script: dict[str, list[LiquidUtxo]] = {}
        # txid → hex
        self._tx_hex: dict[str, str] = {}
        # txid → status
        self._tx_status: dict[str, LiquidTxStatus] = {}
        # Captured broadcasts (most recent first), for test assertions.
        self.broadcasted: list[str] = []
        # When set, the corresponding op returns this error string.
        self._error_for: dict[str, str] = {}

    # — operator-side controls used by test bodies —

    def set_tip_height(self, height: int) -> None:
        self._tip_height = int(height)

    def set_fee_sat_per_vb(self, rate: float) -> None:
        self._fee_sat_per_vb = float(rate)

    def add_utxo(self, script_pubkey: bytes, utxo: LiquidUtxo) -> None:
        self._utxos_by_script.setdefault(script_pubkey.hex(), []).append(utxo)

    def add_transaction(self, txid: str, hex_str: str) -> None:
        self._tx_hex[txid] = hex_str

    def set_transaction_status(self, status: LiquidTxStatus) -> None:
        self._tx_status[status.txid] = status

    def fail(self, op: str, err: str) -> None:
        """Make ``op`` (one of ``get_block_tip_height``, ``estimate_fee``,
        ``get_address_utxos``, ``get_transaction_hex``,
        ``get_transaction_status``, ``broadcast_transaction``) return
        ``(None, err)`` on the next call."""
        self._error_for[op] = err

    def _consume_error(self, op: str) -> Optional[str]:
        return self._error_for.pop(op, None)

    # — Protocol implementation —

    async def get_block_tip_height(self) -> tuple[Optional[int], Optional[str]]:
        err = self._consume_error("get_block_tip_height")
        if err is not None:
            return None, err
        return self._tip_height, None

    async def estimate_fee_sat_per_vb(
        self,
        target_blocks: int = 6,
    ) -> tuple[Optional[float], Optional[str]]:
        err = self._consume_error("estimate_fee")
        if err is not None:
            return None, err
        if target_blocks <= 0:
            return None, "target_blocks must be positive"
        return self._fee_sat_per_vb, None

    async def get_address_utxos(
        self,
        *,
        script_pubkey: bytes,
    ) -> tuple[Optional[list[LiquidUtxo]], Optional[str]]:
        err = self._consume_error("get_address_utxos")
        if err is not None:
            return None, err
        return list(self._utxos_by_script.get(script_pubkey.hex(), [])), None

    async def get_transaction_hex(
        self,
        txid: str,
    ) -> tuple[Optional[str], Optional[str]]:
        err = self._consume_error("get_transaction_hex")
        if err is not None:
            return None, err
        hex_str = self._tx_hex.get(txid)
        if hex_str is None:
            return None, f"tx not found: {txid}"
        return hex_str, None

    async def get_transaction_status(
        self,
        txid: str,
    ) -> tuple[Optional[LiquidTxStatus], Optional[str]]:
        err = self._consume_error("get_transaction_status")
        if err is not None:
            return None, err
        status = self._tx_status.get(txid)
        if status is None:
            return None, f"tx status unknown: {txid}"
        return status, None

    async def broadcast_transaction(
        self,
        tx_hex: str,
    ) -> tuple[Optional[str], Optional[str]]:
        err = self._consume_error("broadcast_transaction")
        if err is not None:
            return None, err
        if not tx_hex:
            return None, "tx_hex must be non-empty"
        # Synthesize a stable txid by hashing — fine for tests.
        import hashlib

        txid = hashlib.sha256(tx_hex.encode("utf-8")).hexdigest()
        self.broadcasted.append(tx_hex)
        return txid, None

    async def close(self) -> None:
        pass


# ── Placeholder for the production wire ────────────────────────────


def _script_pubkey_to_scripthash(script_pubkey: bytes) -> str:
    """Compute the Electrum-protocol scripthash for ``script_pubkey``.

    SHA-256 of the scriptPubKey, byte-reversed, hex-encoded — the
    same hash electrs / electrs-liquid index by. The script_pubkey
    is network-agnostic at the wire level so Bitcoin and Liquid
    share the helper.
    """
    import hashlib

    return hashlib.sha256(bytes(script_pubkey)).digest()[::-1].hex()


# Liquid CT commitment prefix bytes (Elements binary tx format).
# Sources: bitcoin/bips wallet test vectors + Elements project docs.
_BLINDED_VALUE_PREFIXES: frozenset[int] = frozenset({0x08, 0x09})
_BLINDED_ASSET_PREFIXES: frozenset[int] = frozenset({0x0A, 0x0B})
_EXPLICIT_VALUE_PREFIX: int = 0x01
_EXPLICIT_ASSET_PREFIX: int = 0x01


def _parse_liquid_utxo(
    *,
    tx_hex: str,
    txid: str,
    vout: int,
    block_height: Optional[int],
    accept_unblinded: bool = False,
) -> Optional[LiquidUtxo]:
    """Parse one output of an Elements-format tx into :class:`LiquidUtxo`.

    Returns ``None`` for unparseable input or for unblinded outputs
    (unless ``accept_unblinded=True``). The Liquid hop's credit
    observer only cares about CT-blinded credits — unblinded
    outputs are filtered out at this layer so the higher layers
    never see them.

    For unblinded outputs accepted via the flag, the cleartext value
    (in sats) is extracted into ``advisory_value_sat`` and the
    explicit asset id (in display byte order) into
    ``advisory_asset_id``.
    """
    import wallycore as _wally

    flags = _wally.WALLY_TX_FLAG_USE_ELEMENTS | _wally.WALLY_TX_FLAG_USE_WITNESS
    try:
        tx = _wally.tx_from_bytes(bytes.fromhex(tx_hex), flags)
        n = _wally.tx_get_num_outputs(tx)
        if vout < 0 or vout >= n:
            return None
        script = bytes(_wally.tx_get_output_script(tx, vout))
        asset = bytes(_wally.tx_get_output_asset(tx, vout))
        value = bytes(_wally.tx_get_output_value(tx, vout))
        nonce = bytes(_wally.tx_get_output_nonce(tx, vout))
        rangeproof = bytes(_wally.tx_get_output_rangeproof(tx, vout))
        surjproof = bytes(_wally.tx_get_output_surjectionproof(tx, vout))
    except (ValueError, RuntimeError, Exception):  # noqa: BLE001
        return None

    if not asset or not value:
        return None

    is_blinded = (
        len(asset) == 33
        and asset[0] in _BLINDED_ASSET_PREFIXES
        and len(value) == 33
        and value[0] in _BLINDED_VALUE_PREFIXES
    )
    is_explicit = (
        len(asset) == 33
        and asset[0] == _EXPLICIT_ASSET_PREFIX
        and len(value) == 9
        and value[0] == _EXPLICIT_VALUE_PREFIX
    )

    if not is_blinded and not is_explicit:
        return None

    if is_explicit and not accept_unblinded:
        return None

    if is_explicit:
        # Elements stores explicit asset id with bytes reversed from
        # display order; reverse to get the canonical display form.
        advisory_asset_id = bytes(asset[1:33][::-1])
        # 8-byte big-endian satoshi value
        advisory_value_sat = int.from_bytes(value[1:9], "big")
    else:
        advisory_asset_id = None
        advisory_value_sat = None

    return LiquidUtxo(
        txid=txid,
        vout=vout,
        script_pubkey=script,
        value_commitment=value,
        asset_commitment=asset,
        nonce_commitment=nonce,
        rangeproof=rangeproof,
        surjectionproof=surjproof,
        block_height=block_height,
        advisory_value_sat=advisory_value_sat,
        advisory_asset_id=advisory_asset_id,
    )


class ElectrumLiquidBackend:
    """electrs-liquid backend wire (production default).

    Composes against the existing
    :class:`app.services.chain.electrum.ElectrumClient` — electrs-liquid
    speaks the same Electrum JSON-RPC protocol as Bitcoin electrs,
    so the client's connection management + reconnect logic is
    reused. Liquid-specific concerns (CT-commitment extraction,
    Elements tx parsing via wallycore) live in this wrapper.

    Routing: the caller constructs the :class:`ElectrumClient` with
    the dedicated ``liquid`` SOCKS listener. This
    class does not configure routing itself — it expects an
    already-configured client.

    Per-method wire mapping:

    * ``get_block_tip_height`` → ``blockchain.headers.subscribe``
    * ``estimate_fee_sat_per_vb`` → ``blockchain.estimatefee``
      (returns BTC/kvB; we convert to sat/vB at the boundary)
    * ``get_address_utxos`` → ``blockchain.scripthash.listunspent``
      per scripthash + ``blockchain.transaction.get`` for each
      hit (raw hex, parsed via wallycore to extract CT commitments)
    * ``get_transaction_hex`` → ``blockchain.transaction.get``
      (raw=True)
    * ``get_transaction_status`` → ``blockchain.transaction.get``
      (verbose=True)
    * ``broadcast_transaction`` → ``blockchain.transaction.broadcast``
    """

    name: str = "electrum-liquid"

    def __init__(
        self,
        client: Any,
        *,
        accept_unblinded_outputs: bool = False,
    ) -> None:
        """Construct over a pre-configured :class:`ElectrumClient`.

        ``accept_unblinded_outputs`` defaults to False — the receive
        path doesn't handle unblinded outputs, so filtering them out
        at the backend level prevents them from leaking into the
        observer. Set to True for testing / read-only operator
        queries that want to see fee outputs.
        """
        self._client = client
        self._accept_unblinded = bool(accept_unblinded_outputs)

    async def get_block_tip_height(
        self,
    ) -> tuple[Optional[int], Optional[str]]:
        try:
            res = await self._client.request("blockchain.headers.subscribe")
        except Exception as exc:  # noqa: BLE001
            return None, f"electrum-liquid: {exc}"
        if not isinstance(res, dict) or "height" not in res:
            return None, f"unexpected headers.subscribe response: {res!r}"
        try:
            return int(res["height"]), None
        except (TypeError, ValueError):
            return None, f"non-integer height: {res!r}"

    async def estimate_fee_sat_per_vb(
        self,
        target_blocks: int = 6,
    ) -> tuple[Optional[float], Optional[str]]:
        if target_blocks <= 0:
            return None, "target_blocks must be positive"
        try:
            res = await self._client.request(
                "blockchain.estimatefee",
                [int(target_blocks)],
            )
        except Exception as exc:  # noqa: BLE001
            return None, f"electrum-liquid: {exc}"
        # Electrum returns BTC/kvB as a float. -1 means "no estimate".
        if not isinstance(res, (int, float)):
            return None, f"unexpected estimatefee response: {res!r}"
        if res < 0:
            return None, "no fee estimate available"
        # Convert BTC/kvB → sat/vB: × 10^8 / 10^3 = × 10^5
        return float(res) * 100_000.0, None

    async def get_address_utxos(
        self,
        *,
        script_pubkey: bytes,
    ) -> tuple[Optional[list[LiquidUtxo]], Optional[str]]:
        if not script_pubkey:
            return None, "script_pubkey must be non-empty"
        sh = _script_pubkey_to_scripthash(script_pubkey)
        try:
            unspent = await self._client.request(
                "blockchain.scripthash.listunspent",
                [sh],
            )
        except Exception as exc:  # noqa: BLE001
            return None, f"electrum-liquid: {exc}"
        if not isinstance(unspent, list):
            return None, f"unexpected listunspent response: {unspent!r}"

        utxos: list[LiquidUtxo] = []
        for entry in unspent:
            if not isinstance(entry, dict):
                continue
            tx_hash = entry.get("tx_hash")
            tx_pos = entry.get("tx_pos")
            height = entry.get("height")
            if not isinstance(tx_hash, str) or not isinstance(tx_pos, int):
                continue
            hex_str, err = await self.get_transaction_hex(tx_hash)
            if err is not None or hex_str is None:
                # Skip individual fetch failures; surface them only if
                # everything fails (the loop completes with no UTXOs).
                continue
            utxo = _parse_liquid_utxo(
                tx_hex=hex_str,
                txid=tx_hash,
                vout=tx_pos,
                block_height=int(height) if isinstance(height, int) else None,
                accept_unblinded=self._accept_unblinded,
            )
            if utxo is not None:
                utxos.append(utxo)
        return utxos, None

    async def get_transaction_hex(
        self,
        txid: str,
    ) -> tuple[Optional[str], Optional[str]]:
        if not txid:
            return None, "txid must be non-empty"
        try:
            res = await self._client.request(
                "blockchain.transaction.get",
                [txid, False],
            )
        except Exception as exc:  # noqa: BLE001
            return None, f"electrum-liquid: {exc}"
        if not isinstance(res, str):
            return None, f"unexpected transaction.get response: {res!r}"
        return res, None

    async def get_transaction_status(
        self,
        txid: str,
    ) -> tuple[Optional[LiquidTxStatus], Optional[str]]:
        if not txid:
            return None, "txid must be non-empty"
        try:
            res = await self._client.request(
                "blockchain.transaction.get",
                [txid, True],
            )
        except Exception as exc:  # noqa: BLE001
            return None, f"electrum-liquid: {exc}"
        if not isinstance(res, dict):
            return None, f"unexpected verbose response: {res!r}"
        confirms_raw = res.get("confirmations", 0)
        try:
            confirms = int(confirms_raw or 0)
        except (TypeError, ValueError):
            confirms = 0
        height_raw = res.get("height")
        block_height = int(height_raw) if isinstance(height_raw, int) and height_raw > 0 else None
        return LiquidTxStatus(
            txid=txid,
            confirmed=confirms > 0,
            confirmations=confirms,
            block_height=block_height,
        ), None

    async def broadcast_transaction(
        self,
        tx_hex: str,
    ) -> tuple[Optional[str], Optional[str]]:
        if not tx_hex:
            return None, "tx_hex must be non-empty"
        try:
            res = await self._client.request(
                "blockchain.transaction.broadcast",
                [tx_hex],
            )
        except Exception as exc:  # noqa: BLE001
            return None, f"electrum-liquid: {exc}"
        if not isinstance(res, str) or not res:
            return None, f"unexpected broadcast response: {res!r}"
        return res, None

    async def close(self) -> None:
        close = getattr(self._client, "close", None)
        if close is not None:
            await close()


__all__ = [
    "ElectrumLiquidBackend",
    "LiquidBackend",
    "LiquidTxStatus",
    "LiquidUtxo",
    "MockLiquidBackend",
]
