# SPDX-License-Identifier: MIT
"""Liquid credit observer.

When Boltz publishes the LN→L-BTC chain swap's Liquid lockup tx, the
wallet observes it via :class:`LiquidBackend` and validates locally
that the credit is for the expected (asset_id, amount). This module
encapsulates that loop so the hop-adapter layer stays thin.

The observer is **non-blocking**: it polls the backend once and
returns either an observation or ``None`` (still waiting). The hop
dispatcher calls it once per session-loop tick. If a credit matching
the validation contract is found, the observation is returned; if a
credit appears but fails validation (wrong asset, wrong amount), the
observer raises so the hop body routes the session through
reconciliation rather than silently consuming a bad output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .liquid_backend import LiquidBackend
from .liquid_receive import (
    LiquidReceiveError,
    UnblindedUtxo,
    unblind_liquid_utxo,
    validate_lbtc_credit,
)


class LiquidCreditObserverError(RuntimeError):
    """Raised when an observed credit fails validation.

    Distinct from :class:`LiquidReceiveError` (the underlying unblind
    failure) so the hop body can distinguish: backend transient error
    vs. cryptographically-bad credit vs. policy-violating credit.
    """


@dataclass(frozen=True)
class LiquidCreditObservation:
    """A successfully observed + validated L-BTC credit."""

    unblinded: UnblindedUtxo
    backend_error: None = None  # convenience: distinguishes from error path


async def observe_and_validate_credit(
    *,
    backend: LiquidBackend,
    lockup_script: bytes,
    blinding_privkey: bytes,
    expected_asset_id: bytes,
    expected_amount_sat: int,
    expected_max_amount_sat: Optional[int] = None,
) -> tuple[Optional[LiquidCreditObservation], Optional[str]]:
    """Poll the backend for a Liquid credit at ``lockup_script`` and
    validate it.

    Returns one of three outcomes:

    * ``(observation, None)`` — a matching credit is on-chain and
      validated. The hop body proceeds.
    * ``(None, None)`` — no credit yet. The hop body waits.
    * ``(None, error)`` — backend error (transient) OR validation
      failure (cryptographically-bad / policy-violating credit). The
      hop body routes through reconciliation.

    The observer scans every UTXO at ``lockup_script`` and returns
    the first one that unblinds correctly under
    ``blinding_privkey`` AND passes :func:`validate_lbtc_credit`. A
    UTXO that fails unblinding is silently skipped (it may belong to
    a different swap on the same address — extremely unlikely in
    practice but defensive). A UTXO that unblinds but fails the
    asset/amount validation surfaces as a hard error.
    """
    utxos, err = await backend.get_address_utxos(script_pubkey=lockup_script)
    if err is not None:
        return None, f"liquid backend error: {err}"
    if not utxos:
        return None, None

    last_validation_err: Optional[str] = None
    for utxo in utxos:
        try:
            unblinded = unblind_liquid_utxo(
                utxo=utxo,
                blinding_privkey=blinding_privkey,
            )
        except LiquidReceiveError:
            # Not for us — this UTXO uses a different blinding key.
            # Skip silently and try the next one.
            continue
        verr = validate_lbtc_credit(
            unblinded,
            expected_asset_id=expected_asset_id,
            expected_min_amount_sat=expected_amount_sat,
            expected_max_amount_sat=expected_max_amount_sat,
        )
        if verr is not None:
            # Unblinds correctly (so it's intended for us) but the
            # value/asset is wrong. Surface as a hard error.
            last_validation_err = verr
            continue
        return LiquidCreditObservation(unblinded=unblinded), None

    if last_validation_err is not None:
        return None, f"liquid credit validation failed: {last_validation_err}"
    return None, None


__all__ = [
    "LiquidCreditObservation",
    "LiquidCreditObserverError",
    "observe_and_validate_credit",
]
