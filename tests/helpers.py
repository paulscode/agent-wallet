# SPDX-License-Identifier: MIT
"""
Shared test builders.

Two kinds of factory live here:

* **Model builders** (`make_api_key`) construct ORM instances with sensible
  defaults so a test states only the fields it cares about. They do not
  persist — the caller adds to its session and keeps the returned object
  referenced (SQLAlchemy's identity map is weak; a dropped reference lets a
  re-query reload from SQLite, which drops timezone info on datetime columns).

* **Response builders** (`lnd_*`, `boltz_*`) return dicts whose shape matches
  the real ``lnd_service`` / ``boltz_service`` return contracts. Centralizing
  the shapes here means a contract change is fixed in one place instead of
  across the dozens of tests that hand-roll these dicts, and keeps mocks
  honest about what the production code actually returns.

The ``lnd_service`` / ``boltz_service`` methods return ``(data, error)``
tuples — success is ``(data, None)``, failure ``(None, "message")``. These
builders return the ``data`` half; wrap with :func:`ok` / :func:`err` for the
tuple.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from app.core.encryption import encrypt_field
from app.core.security import generate_api_key, hash_api_key
from app.models.api_key import SCOPE_ADMIN, SCOPE_MONITOR, APIKey
from app.models.boltz_swap import BoltzSwap, BoltzSwapDirection, SwapStatus

__all__ = [
    "ok",
    "err",
    "make_api_key",
    "make_boltz_swap",
    "lnd_get_info",
    "lnd_channel",
    "lnd_invoice",
    "lnd_wallet_balance",
    "boltz_reverse_pair_info",
    "boltz_submarine_pair_info",
]


# ─── (data, error) tuple helpers ──────────────────────────────────────
def ok(data: Any) -> tuple[Any, None]:
    """The success half of the lnd/boltz ``(data, error)`` convention."""
    return data, None


def err(message: str) -> tuple[None, str]:
    """The failure half of the lnd/boltz ``(data, error)`` convention."""
    return None, message


# ─── Model builders ───────────────────────────────────────────────────
def make_api_key(
    *,
    name: str = "test-key",
    scope: str | None = None,
    is_admin: bool = False,
    is_active: bool = True,
    expires_at: datetime | None = None,
    raw_key: str | None = None,
) -> tuple[APIKey, str]:
    """Build (but do not persist) an ``APIKey`` and return ``(key, raw_token)``.

    ``scope`` wins when given; otherwise ``is_admin`` selects admin vs monitor.
    The raw token is generated unless supplied, and ``key_hash`` is derived
    from it so the key authenticates under the current ``SECRET_KEY``.
    """
    token = raw_key if raw_key is not None else generate_api_key()
    resolved_scope = scope if scope is not None else (SCOPE_ADMIN if is_admin else SCOPE_MONITOR)
    key = APIKey(
        id=uuid4(),
        name=name,
        key_hash=hash_api_key(token),
        scope=resolved_scope,
        is_active=is_active,
        expires_at=expires_at,
    )
    return key, token


def make_boltz_swap(
    *,
    status: SwapStatus = SwapStatus.CREATED,
    direction: BoltzSwapDirection = BoltzSwapDirection.REVERSE,
    boltz_swap_id: str = "boltz-test-swap",
    api_key_id: Any = None,
    invoice_amount_sats: int = 100_000,
    onchain_amount_sats: int = 99_000,
    destination_address: str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
    claim_txid: str | None = None,
    timeout_block_height: int = 850_000,
) -> BoltzSwap:
    """Build (not persist) a reverse ``BoltzSwap`` mid-lifecycle.

    The encrypted crypto material round-trips under the test ``SECRET_KEY``
    so claim/refund code paths that ``decrypt_field`` it run for real; the
    decrypted values are placeholders (the node crypto subprocess is faked
    in tests, so their content is never used on-chain).
    """
    return BoltzSwap(
        id=uuid4(),
        boltz_swap_id=boltz_swap_id,
        direction=direction,
        api_key_id=api_key_id or uuid4(),
        invoice_amount_sats=invoice_amount_sats,
        onchain_amount_sats=onchain_amount_sats,
        destination_address=destination_address,
        fee_percentage="0.5",
        miner_fee_sats=800,
        preimage_hex=encrypt_field("00" * 32),
        preimage_hash_hex="ab" * 32,
        claim_private_key_hex=encrypt_field("11" * 32),
        claim_public_key_hex="02" + "cd" * 32,
        boltz_invoice="lnbcrt1...",
        boltz_lockup_address="bcrt1plockup",
        boltz_refund_public_key_hex="03" + "ef" * 32,
        boltz_swap_tree_json={"claimLeaf": {}, "refundLeaf": {}},
        timeout_block_height=timeout_block_height,
        claim_txid=claim_txid,
        status=status,
        boltz_status="swap.created",
        status_history=[],
    )


# ─── LND response builders (match app/services/lnd_service.py shapes) ──
def lnd_get_info(**overrides: Any) -> dict[str, Any]:
    """A ``get_info`` NodeInfo dict."""
    info = {
        "alias": "test-node",
        "identity_pubkey": "02" + "ab" * 32,
        "num_active_channels": 1,
        "num_inactive_channels": 0,
        "num_pending_channels": 0,
        "num_peers": 1,
        "block_height": 800_000,
        "synced_to_chain": True,
        "synced_to_graph": True,
        "version": "0.18.0-beta",
        "commit_hash": "deadbeef",
        "uris": [],
    }
    info.update(overrides)
    return info


def lnd_channel(**overrides: Any) -> dict[str, Any]:
    """One ``get_channels`` ChannelInfo dict."""
    chan = {
        "chan_id": "123456789",
        "remote_pubkey": "03" + "cd" * 32,
        "channel_point": "ab" * 32 + ":0",
        "capacity": 1_000_000,
        "local_balance": 600_000,
        "remote_balance": 400_000,
        "commit_fee": 183,
        "total_satoshis_sent": 0,
        "total_satoshis_received": 0,
        "num_updates": 1,
        "active": True,
        "private": False,
        "initiator": True,
        "peer_alias": "peer",
        "uptime": 3600,
        "lifetime": 3600,
        "local_chan_reserve_sat": 10_000,
        "remote_chan_reserve_sat": 10_000,
        "unsettled_balance": 0,
    }
    chan.update(overrides)
    return chan


def lnd_invoice(**overrides: Any) -> dict[str, Any]:
    """A ``create_invoice`` InvoiceResult dict."""
    inv = {
        "r_hash": "ab" * 32,
        "payment_request": "lnbcrt1...",
        "add_index": "1",
    }
    inv.update(overrides)
    return inv


def lnd_wallet_balance(**overrides: Any) -> dict[str, Any]:
    """A ``get_wallet_balance`` WalletBalance dict."""
    bal = {
        "total_balance": 1_000_000,
        "confirmed_balance": 1_000_000,
        "unconfirmed_balance": 0,
        "locked_balance": 0,
        "reserved_balance_anchor_chan": 0,
    }
    bal.update(overrides)
    return bal


# ─── Boltz response builders ──────────────────────────────────────────
def boltz_reverse_pair_info(**overrides: Any) -> dict[str, Any]:
    """A ``get_reverse_pair_info`` dict (LN → on-chain)."""
    info = {
        "fees_percentage": 0.5,
        "fees_miner_claim": 600,
        "fees_miner_lockup": 200,
        "min": 25_000,
        "max": 25_000_000,
    }
    info.update(overrides)
    return info


def boltz_submarine_pair_info(**overrides: Any) -> dict[str, Any]:
    """A ``get_submarine_pair_info`` dict (on-chain → LN)."""
    info = {
        "fees_percentage": 0.1,
        "fees_miner_lockup": 462,
        "min": 25_000,
        "max": 25_000_000,
        "hash": "pairhash",
    }
    info.update(overrides)
    return info
