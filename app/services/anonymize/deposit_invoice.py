# SPDX-License-Identifier: MIT
"""Blinded-path BOLT11 invoices for ext-lightning deposits.

The anonymize wizard's `ext-lightning` source kind requires the
depositor to pay an invoice whose hop list is *blinded* — i.e., LND
synthesises a fake last-hop scid so the depositor's wallet can't
read the recipient's node id off the invoice. Without this, a
depositor wallet observing a vanilla BOLT11 deposit invoice
trivially learns the recipient's pubkey, defeating.4's
deanonymization mitigation.

LND already implements blinded BOLT11 invoices via the
``AddInvoice`` REST surface with ``is_blinded=true``; we expose a
thin anonymize-stack wrapper that:

1. Pins the conservative defaults (``num_hops=1, max_num_paths=2``).
2. Forces a positive expiry (the orchestrator's ext-deposit dwell
   timer measures against the invoice's ``expiry`` so a missing one
   would silently wedge a session).
3. Bounds the maximum amount via ``settings.anonymize_max_sat``.

The wrapper is a pure adapter — it doesn't open a DB session; the
caller persists the resulting payment-request string into
``anonymize_session.pipeline_json.source.deposit_invoice``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.core.config import settings

if TYPE_CHECKING:
    from app.services.lnd_service import LNDService


class DepositInvoiceError(RuntimeError):
    """Raised when the LND-side blinded-invoice call refuses the request."""


@dataclass(frozen=True)
class DepositInvoiceResult:
    """Output of the deposit-invoice builder."""

    payment_request: str  # BOLT11 string the wizard hands to the depositor
    payment_hash_hex: str
    expiry_seconds: int
    blinded_paths_count: int


async def issue_ext_lightning_deposit_invoice(
    *,
    amount_msat: int,
    memo: str = "",
    expiry_seconds: int = 3600,
    num_hops: int = 1,
    max_num_paths: int = 2,
    lnd_client: LNDService | None = None,
) -> DepositInvoiceResult:
    """Request a blinded BOLT11 invoice for ext-lightning deposit.

    ``lnd_client`` is the LND service instance; defaults to the
    module-level singleton so the create endpoint can call this
    without passing it explicitly. Tests inject a Mock.

    Raises :class:`DepositInvoiceError` on:
    * Amount above the configured ``ANONYMIZE_MAX_SAT`` ceiling.
    * Non-positive expiry (the dwell timer needs a real window).
    * LND-side refusal (e.g., no inbound liquidity).
    """
    if amount_msat <= 0:
        raise DepositInvoiceError("amount_msat must be positive for a deposit invoice")
    max_sats = int(settings.anonymize_max_sat)
    if amount_msat > max_sats * 1000:
        raise DepositInvoiceError(f"amount_msat={amount_msat} exceeds ANONYMIZE_MAX_SAT={max_sats}")
    if expiry_seconds <= 0:
        raise DepositInvoiceError("expiry_seconds must be positive")

    if lnd_client is None:
        from app.services.lnd_service import lnd_service

        lnd_client = lnd_service

    result, err = await lnd_client.add_blinded_invoice(
        amount_msat=amount_msat,
        memo=memo,
        expiry=expiry_seconds,
        num_hops=num_hops,
        max_num_paths=max_num_paths,
    )
    if err or result is None:
        raise DepositInvoiceError(f"LND refused blinded-invoice request: {err or 'unknown error'}")
    # ``add_blinded_invoice`` returns a ``BlindedInvoiceResult`` TypedDict (a
    # plain dict): ``r_hash`` is the payment hash in hex, ``blinded_paths`` is
    # the raw per-path list. (Previously this read the fields as attributes,
    # which only worked against the test's MagicMock — real LND returns a dict.)
    return DepositInvoiceResult(
        payment_request=str(result["payment_request"]),
        payment_hash_hex=str(result["r_hash"]),
        expiry_seconds=int(expiry_seconds),
        blinded_paths_count=len(result["blinded_paths"]),
    )


__all__ = [
    "DepositInvoiceError",
    "DepositInvoiceResult",
    "issue_ext_lightning_deposit_invoice",
]
