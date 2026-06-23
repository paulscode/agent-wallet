# SPDX-License-Identifier: MIT
"""Dust-safe single-input single-output sends.

Background — economic dust threshold
====================================

The Bitcoin network's ``minrelay`` rule forbids outputs below ~330
sats (P2WPKH at 1 sat/vB). That's a HARD floor below which the tx
won't even relay. But the operationally relevant threshold is much
higher: an UTXO whose value is less than the cost to spend it in a
future tx is economically dust — the operator loses it permanently
until fees fall enough that consolidation pays for itself.

At 60 sat/vB, a 110-vbyte P2TR spend costs 6,600 sats. Any UTXO
under that value is economically dead until fees drop. At 100 sat/vB
the threshold is 11,000 sats.

The naive ``SendCoins(address, amount, fee)`` flow lets LND compute
change automatically. In a high-fee environment the change output
lands as economic dust at the wallet, and the sats are silently
lost. ``build_and_broadcast_no_change_send`` builds a tx with NO
change output — the entire selected UTXO is spent, with the
difference between UTXO value and network fee absorbed into the
single destination output.

Trade-off the caller signs off on
=================================

* The destination receives slightly MORE than the requested amount
  in low-fee environments (the would-be change becomes part of the
  output).
* The destination receives slightly LESS than the UTXO value in
  high-fee environments (the fee comes out of the output).
* Either way: no wallet-side change UTXO ever exists, dust risk
  eliminated, exact "amount sent to destination" is variable and
  must be surfaced to the caller for downstream audit / UX.

Originally designed for the Braiins Deposit flow (the
dust-prevention plan). The module is feature-agnostic — Anonymize
submarine funding's fallback path (the same plan) can
adopt it once Boltz over-funding semantics are characterised.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from app.services.lnd_service import LNDService

logger = logging.getLogger(__name__)


# 1-in 1-out P2TR (key-path) spends are ~110 vbytes. P2WPKH is ~140;
# we use the larger number as the conservative default so the
# resulting tx never underpays the network fee. Caller can override
# when the input + output script types are known.
_DEFAULT_ESTIMATED_VBYTES = 140

# Minimum vbytes for the floor-case (always at least this; LND's own
# floor protects us anyway, but we don't want to hand off a clearly-
# bogus value).
_MIN_VBYTES = 100


class InfeasibleSendError(RuntimeError):
    """Raised when the source UTXO is too small to cover the network
    fee at the requested feerate. The caller decides whether to
    retry later (fee drop), refund, or fail.

    Carries the input value + projected fee so the caller can log
    the exact reason without re-computing.
    """

    def __init__(self, *, utxo_value: int, projected_fee: int, sat_per_vbyte: int) -> None:
        super().__init__(
            f"utxo value {utxo_value} sats is below projected network "
            f"fee {projected_fee} sats at {sat_per_vbyte} sat/vB — "
            f"cannot build a dust-safe send."
        )
        self.utxo_value = utxo_value
        self.projected_fee = projected_fee
        self.sat_per_vbyte = sat_per_vbyte


@dataclass(frozen=True)
class NoChangeSendResult:
    """Outcome of a successful dust-safe send.

    ``arrived_at_destination`` is what the receiver actually got;
    ``estimated_fee`` is our local projection (the on-chain tx may
    pay slightly different fee depending on LND's final vbyte
    calculation, but we use the estimate for telemetry).
    """

    txid: str
    arrived_at_destination: int
    estimated_fee: int


async def build_and_broadcast_no_change_send(
    *,
    lnd: LNDService,
    source_txid: str,
    source_vout: int,
    source_value_sats: int,
    destination_address: str,
    sat_per_vbyte: int,
    estimated_vbytes: int = _DEFAULT_ESTIMATED_VBYTES,
    label: str = "",
    min_confs: int = 0,
) -> NoChangeSendResult:
    """Build a single-input single-output send tx that spends the
    entire ``source_txid:source_vout`` UTXO to ``destination_address``.

    Implementation strategy: ``LND.send_coins(send_all=True,
    outpoints=[...])``. LND restricts spending to the pinned
    outpoint, computes the network fee at ``sat_per_vbyte``, and
    emits a single output to the destination valued at
    ``source_value - fee``. No change output is created.

    Returns the resulting :class:`NoChangeSendResult` with the
    projected arrival amount. Raises :class:`InfeasibleSendError`
    when the source UTXO is too small to cover the projected fee
    at the requested rate.

    Caller's responsibility: feed back ``arrived_at_destination``
    to whatever downstream record-keeping needs the "actual sent"
    figure (e.g. the Braiins Deposit session's
    ``actual_sent_sats`` column).
    """
    if source_value_sats <= 0:
        raise ValueError(f"source_value_sats must be positive; got {source_value_sats}")
    if sat_per_vbyte <= 0:
        raise ValueError(f"sat_per_vbyte must be positive; got {sat_per_vbyte}")
    vbytes = max(_MIN_VBYTES, int(estimated_vbytes))
    projected_fee = vbytes * int(sat_per_vbyte)
    if source_value_sats <= projected_fee:
        raise InfeasibleSendError(
            utxo_value=source_value_sats,
            projected_fee=projected_fee,
            sat_per_vbyte=int(sat_per_vbyte),
        )

    # Use LND's send_all + pinned outpoint. LND's internal fee
    # calculation may produce slightly different vbytes than our
    # estimate (it knows the precise script size); the arrival
    # amount we record below is OUR projection, which is an
    # upper bound — the actual arrival may be ~10-50 sats higher
    # than our number, never lower. Downstream code that compares
    # arrival amounts must tolerate this slack.
    result, err = await lnd.send_coins(
        address=destination_address,
        amount_sats=None,
        sat_per_vbyte=int(sat_per_vbyte),
        label=label,
        outpoints=[
            {
                "txid_str": source_txid,
                "output_index": int(source_vout),
            }
        ],
        send_all=True,
        min_confs=int(min_confs),
    )
    if err or not result or not result.get("txid"):
        raise RuntimeError(f"dust-safe send failed: {err or 'no txid returned'}")
    return NoChangeSendResult(
        txid=str(result["txid"]),
        arrived_at_destination=source_value_sats - projected_fee,
        estimated_fee=projected_fee,
    )


def economic_dust_threshold_sats(
    sat_per_vbyte: int,
    *,
    spend_vbytes: int = 110,
) -> int:
    """Cost in sats to spend a single UTXO at ``sat_per_vbyte``.

    Default ``spend_vbytes=110`` matches a P2TR key-path spend.
    A UTXO worth less than this is economically dust — the operator
    cannot recover it without paying more than its value in fees.

    Use this when projecting at quote/wizard time: any change
    output projected below this threshold is "would-be dust" and
    must be absorbed via the no-change send pattern.
    """
    return max(0, int(spend_vbytes) * max(1, int(sat_per_vbyte)))


def project_no_change_send(
    *,
    source_value_sats: int,
    sat_per_vbyte: int,
    estimated_vbytes: int = _DEFAULT_ESTIMATED_VBYTES,
) -> Optional[NoChangeSendResult]:
    """Dry-run the dust-safe send: project the arrival amount + fee
    WITHOUT broadcasting anything. Returns ``None`` when infeasible
    (caller treats as "wait for lower fees").

    ``txid`` in the result is the empty string for dry-runs — the
    caller should never persist a dry-run result as if it were a
    broadcast tx.
    """
    if source_value_sats <= 0 or sat_per_vbyte <= 0:
        return None
    vbytes = max(_MIN_VBYTES, int(estimated_vbytes))
    projected_fee = vbytes * int(sat_per_vbyte)
    if source_value_sats <= projected_fee:
        return None
    return NoChangeSendResult(
        txid="",
        arrived_at_destination=source_value_sats - projected_fee,
        estimated_fee=projected_fee,
    )


__all__ = [
    "InfeasibleSendError",
    "NoChangeSendResult",
    "build_and_broadcast_no_change_send",
    "economic_dust_threshold_sats",
    "project_no_change_send",
]
