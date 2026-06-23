# SPDX-License-Identifier: MIT
"""
TypedDict definitions for LND REST API responses.

Provides type safety and self-documenting structure for the most common
LND response shapes flowing through the service → API layers.
"""

from typing import Optional, TypedDict

try:
    from typing import NotRequired  # py3.11+
except ImportError:  # pragma: no cover
    from typing_extensions import NotRequired


class NodeInfo(TypedDict):
    alias: str
    identity_pubkey: str
    num_active_channels: int
    num_inactive_channels: int
    num_pending_channels: int
    num_peers: int
    block_height: int
    synced_to_chain: bool
    synced_to_graph: bool
    version: str
    commit_hash: str
    uris: list[str]


class WalletBalance(TypedDict):
    total_balance: int
    confirmed_balance: int
    unconfirmed_balance: int
    locked_balance: int
    reserved_balance_anchor_chan: int


class ChannelBalance(TypedDict):
    local_balance_sat: int
    remote_balance_sat: int
    pending_open_local_sat: int
    pending_open_remote_sat: int
    unsettled_local_sat: int
    unsettled_remote_sat: int


class PendingChannelsSummary(TypedDict):
    pending_open_channels: int
    pending_closing_channels: int
    pending_force_closing_channels: int
    waiting_close_channels: int
    total_limbo_balance: int


class WalletSummaryTotals(TypedDict):
    total_balance_sats: int
    onchain_sats: int
    lightning_local_sats: int
    lightning_remote_sats: int
    unconfirmed_sats: int
    num_active_channels: int
    num_pending_channels: int
    synced: bool


class WalletSummary(TypedDict):
    connected: bool
    node_info: Optional[NodeInfo]
    onchain: Optional[WalletBalance]
    lightning: Optional[ChannelBalance]
    pending_channels: Optional[PendingChannelsSummary]
    totals: WalletSummaryTotals


class ChannelInfo(TypedDict):
    chan_id: str
    remote_pubkey: str
    channel_point: str
    capacity: int
    local_balance: int
    remote_balance: int
    commit_fee: int
    total_satoshis_sent: int
    total_satoshis_received: int
    num_updates: int
    active: bool
    private: bool
    initiator: bool
    peer_alias: str
    uptime: int
    lifetime: int
    # Reserves and in-flight balance — needed for accurate
    # "max sendable / max receivable" math on rebalance UX.
    local_chan_reserve_sat: int
    remote_chan_reserve_sat: int
    unsettled_balance: int
    # Best-effort unix-seconds timestamp of the last successful HTLC
    # in either direction (forwarded, sent, or received). Absent when
    # we have no record of recent activity for the channel.
    last_used: NotRequired[int]


class RouteQuote(TypedDict):
    """Result of a ``QueryRoutes`` probe — a single best-route summary."""

    hops: int
    total_amt_sat: int
    total_fees_sat: int
    total_amt_msat: int
    total_fees_msat: int
    total_time_lock: int
    ppm: int  # fee in parts-per-million of amount


class RebalanceResult(TypedDict):
    """Result of a successful circular self-payment rebalance."""

    payment_hash: str
    payment_preimage: str
    amount_sats: int
    fee_sats: int
    fee_msat: int
    hops: int
    duration_ms: int


class PaymentInfo(TypedDict):
    payment_hash: str
    value_sat: int
    fee_sat: int
    status: str
    creation_date: int
    payment_request: str
    failure_reason: str


class InvoiceInfo(TypedDict):
    memo: str
    r_hash: str
    value: int
    settled: bool
    creation_date: int
    settle_date: int
    amt_paid_sat: int
    state: str
    is_keysend: bool
    payment_request: str


class OnchainTransaction(TypedDict):
    tx_hash: str
    amount: int
    num_confirmations: int
    block_height: int
    time_stamp: int
    total_fees: int
    label: str


class PaymentRoute(TypedDict):
    total_amt: int
    total_fees: int
    total_amt_msat: int
    total_fees_msat: int
    hops: int


class SendPaymentResult(TypedDict):
    payment_hash: str
    payment_preimage: str
    payment_route: Optional[PaymentRoute]


class NewAddressResult(TypedDict):
    address: str
    address_type: str


class SendCoinsResult(TypedDict):
    txid: str


class EstimateFeeResult(TypedDict):
    fee_sat: int
    feerate_sat_per_byte: int
    sat_per_vbyte: int


class InvoiceResult(TypedDict):
    r_hash: str
    payment_request: str
    add_index: str


class BlindedInvoiceResult(TypedDict):
    """LND ``AddInvoice`` response when ``is_blinded=true``.

    ``payment_request`` still encodes a BOLT 11 string, but it
    advertises 1+ blinded routes via the ``r``/route-hint field
    rather than the destination's plaintext pubkey. The blinded
    paths and their per-path metadata (CLTV deltas, fee budgets,
    introduction nodes) are surfaced separately as the raw response
    payload so the BOLT 12 layer can lift them into
    ``invoice_paths`` / ``invoice_blindedpay`` records.
    """

    r_hash: str
    payment_request: str
    add_index: str
    payment_addr: str  # 32-byte hex secret used for MPP
    blinded_paths: list[dict]  # raw LND blinded-path objects (opaque to caller)


class DecodedPayReq(TypedDict):
    destination: str
    payment_hash: str
    num_satoshis: int
    timestamp: int
    expiry: int
    description: str
    description_hash: str
    cltv_expiry: int
    num_msat: int
    features: dict


class PaymentLookup(TypedDict):
    status: str
    payment_hash: str
    fee_sat: int
    payment_preimage: str
    value_sat: int


class OpenChannelResult(TypedDict):
    funding_txid: str
    output_index: int


class SignAddrResult(TypedDict):
    """Result of signing a message with an on-chain address key.

    `signature` is the LND-returned base64 signature; `format` is the
    underlying Bitcoin signature scheme (BIP-322 simple for SegWit /
    Taproot, BIP-137 for legacy P2PKH and P2SH-P2WKH).
    """

    address: str
    address_type: str
    signature: str
    format: str


class VerifyAddrResult(TypedDict):
    valid: bool
    pubkey: Optional[str]


class SignNodeResult(TypedDict):
    """Result of signing a message with the node identity key (zbase32)."""

    signature: str
    node_pubkey: str


class VerifyNodeResult(TypedDict):
    valid: bool
    pubkey: Optional[str]


class Outpoint(TypedDict):
    """A reference to a single transaction output (txid + vout).

    The two fields mirror LND's ``OutPoint`` proto: ``txid_str`` is the
    big-endian hex used everywhere outside the wire format, and
    ``output_index`` is the 32-bit vout. We never speak ``txid_bytes``
    directly — every public surface in the wallet uses the hex form.
    """

    txid_str: str
    output_index: int


class Utxo(TypedDict):
    """A single spendable on-chain output reported by LND ``ListUnspent``.

    ``address_type`` is the LND-name (``WITNESS_PUBKEY_HASH``,
    ``NESTED_PUBKEY_HASH``, ``TAPROOT_PUBKEY``, ``UNKNOWN``); we keep it
    verbatim so the dashboard can render the matching badge without
    re-deriving it from the address prefix.
    """

    outpoint: Outpoint
    amount_sat: int
    address: str
    address_type: str
    pk_script: str
    confirmations: int
