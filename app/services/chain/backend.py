# SPDX-License-Identifier: MIT
"""Chain-backend protocol definition.

Every backend (Mempool HTTP, Electrum, future Bitcoin Core RPC, …)
exposes the same surface so the public facade can swap them out
transparently.

Return shapes deliberately match the legacy ``MempoolFeeService``
contract.
"""

from __future__ import annotations

import math
from typing import Any, Optional, Protocol, runtime_checkable

# Defensive ceiling on any fee rate derived from an UNTRUSTED chain
# backend (Electrum / mempool server). Far above any realistic mainnet
# fee market (which has historically peaked well under this), but bounds
# a malicious or compromised server's ability to drain a small UTXO
# entirely as miner fee on an automated send.
MAX_SANE_FEERATE_SAT_PER_VB = 2000


def clamp_feerate_sat_per_vb(value: Any) -> Optional[int]:
    """Coerce an untrusted feerate to a sane int in ``[1, MAX]``.

    Returns ``None`` for non-numeric / non-finite / non-positive input so
    callers can treat a malformed server feerate as an error and fall
    back rather than caching or spending against it.
    """
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(f) or f <= 0:
        return None
    return max(1, min(int(f), MAX_SANE_FEERATE_SAT_PER_VB))


@runtime_checkable
class ChainBackend(Protocol):
    """Async API used by the wallet for every non-LND chain query."""

    name: str

    async def get_recommended_fees(
        self,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Return mempool.space-shaped recommended-fee dict, or ``(None, error)``."""

    async def get_fee_for_priority(self, priority: str = "medium") -> Optional[int]:
        """Return sat/vB for the named priority (``low`` / ``medium`` / ``high``)."""

    async def get_transaction(self, txid: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Look up a TX by id; mempool.space-shaped dict or ``(None, error)``."""

    async def get_transaction_confirmations(self, txid: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """``{"txid", "confirmed", "confirmations", "block_height", ...}``."""

    async def get_address(self, address: str) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Address summary (balance, tx counts) or ``(None, error)``."""

    async def get_address_utxos(self, address: str) -> tuple[Optional[list[dict[str, Any]]], Optional[str]]:
        """List of UTXOs for an address or ``(None, error)``."""

    async def get_mempool_stats(
        self,
    ) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Mempool congestion stats (tx_count, vsize, fee_histogram) or ``(None, error)``."""

    async def get_block_tip_height(self) -> tuple[Optional[int], Optional[str]]:
        """Current chain tip height or ``(None, error)``."""

    async def get_block_by_height(self, height: int) -> tuple[Optional[dict[str, Any]], Optional[str]]:
        """Block header at ``height`` or ``(None, error)``."""

    async def close(self) -> None:
        """Tear down any connections held by this backend."""
