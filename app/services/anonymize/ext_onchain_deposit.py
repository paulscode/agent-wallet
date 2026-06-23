# SPDX-License-Identifier: MIT
"""Ext-onchain deposit address + amount lock + dwell timer.

For ``ext-onchain`` sources, the depositor sends BTC directly to a
wallet-controlled address; the wallet then routes the deposit UTXO
through the submarine swap. Two anti-correlation properties matter:

1. **Amount lock**: the deposit must exactly equal the bin
   amount the session was created under. A mismatched amount lets
   the operator pair the deposit tx with the eventual submarine
   funding via the unique value, undoing the binning's anonymity
   set. The wallet refuses non-matching deposits (or rounds to the
   nearest bin with depositor opt-in).
2. **Dwell time**: the wallet waits a documented minimum
   before consuming the deposit UTXO as the submarine source.
   Defaults to ``ANONYMIZE_EXT_DEPOSIT_MIN_DWELL_S`` (2 h); the
    skew-aware deadline applies on top so a clock blip
   doesn't release the UTXO prematurely.

The wallet's address-generation path uses BIP-86 P2TR derivation
to keep the deposit indistinguishable from a normal taproot
receive. The on-chain self-source path ships:

* :func:`issue_ext_onchain_deposit_address` — derive a fresh
  per-session address and bind it into ``pipeline_json``.
* :func:`is_deposit_amount_locked` — predicate the deposit observer
  uses to gate progress into ``FUNDING``.
* :func:`is_dwell_elapsed` — predicate the per-session loop uses
  to decide whether ``LN_HOLDING`` may transition.

Pure helpers — no DB I/O. Tests exercise the predicates directly;
the wiring into ``hops/submarine.py`` + the per-session loop lives
alongside the Cluster F coin-control flow.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from app.core.config import settings

# Depositor-facing tolerance. A deposit whose amount
# differs from the bin amount by more than this many sats is
# rejected. Default is zero (exact match) — production deployments
# may opt into a small tolerance for fee-bumped depositor wallets,
# but the default keeps the binning's anonymity set tight.
_DEFAULT_AMOUNT_TOLERANCE_SAT: int = 0


@dataclass(frozen=True)
class ExtOnchainDepositInstruction:
    """Depositor-facing instructions the wizard renders."""

    address: str  # wallet-controlled BIP-86 P2TR
    amount_sat: int  # bin amount the session was created under
    expiry_unix_s: float  # session create_at + retention window
    derivation_index: int  # for the wallet's address book


async def issue_ext_onchain_deposit_address(
    *,
    bin_amount_sat: int,
    expiry_unix_s: float,
    derivation_index: int,
    address: str,
) -> ExtOnchainDepositInstruction:
    """Bind a fresh wallet-controlled P2TR address to a session.

    The caller (create endpoint) computes the BIP-86 address +
    derivation index from the wallet's HD path; this helper is the
    binding shape the orchestrator persists into ``pipeline_json``.

    The shape is intentionally narrow — every field is the depositor-
    visible content. The wallet's derivation secret never lands here.
    """
    if bin_amount_sat <= 0:
        raise ValueError("bin_amount_sat must be positive")
    if not address:
        raise ValueError("address must be a non-empty string")
    return ExtOnchainDepositInstruction(
        address=address,
        amount_sat=int(bin_amount_sat),
        expiry_unix_s=float(expiry_unix_s),
        derivation_index=int(derivation_index),
    )


def is_deposit_amount_locked(
    *,
    deposited_sat: int,
    expected_bin_amount_sat: int,
    tolerance_sat: int | None = None,
) -> bool:
    """Refuse to admit a deposit whose value differs from
    the bin amount by more than the tolerance.

    Returns True iff the deposit is within tolerance; the orchestrator
    routes a False-result deposit through reconciliation with reason
    ``ext_onchain_amount_mismatch``.
    """
    if deposited_sat < 0 or expected_bin_amount_sat <= 0:
        return False
    tol = int(tolerance_sat) if tolerance_sat is not None else _DEFAULT_AMOUNT_TOLERANCE_SAT
    return abs(int(deposited_sat) - int(expected_bin_amount_sat)) <= tol


def is_dwell_elapsed(
    *,
    deposit_observed_at_unix_s: float,
    now_unix_s: float | None = None,
    min_dwell_s: int | None = None,
) -> bool:
    """Predicate the per-session loop consults before
    consuming the deposit UTXO as the submarine source.

    Returns True iff the deposit has aged at least
    ``ANONYMIZE_EXT_DEPOSIT_MIN_DWELL_S`` seconds.
    """
    now = now_unix_s if now_unix_s is not None else time.time()
    dwell = int(min_dwell_s) if min_dwell_s is not None else int(settings.anonymize_ext_deposit_min_dwell_s)
    elapsed = max(0.0, now - float(deposit_observed_at_unix_s))
    return elapsed >= float(dwell)


__all__ = [
    "ExtOnchainDepositInstruction",
    "issue_ext_onchain_deposit_address",
    "is_deposit_amount_locked",
    "is_dwell_elapsed",
]
