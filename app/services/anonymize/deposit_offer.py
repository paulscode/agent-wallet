# SPDX-License-Identifier: MIT
"""BOLT 12 offer + BIP-353 handle for ext-lightning deposits.

The anonymize wizard's ``ext-lightning`` source kind admits two
deposit modes:

* **BOLT 11** — a single-use blinded payment-request. See
  :func:`deposit_invoice.issue_ext_lightning_deposit_invoice`.
* **BOLT 12** — a per-session offer (this module). The depositor's
  wallet sends an ``invoice_request`` to the offer's blinded paths;
  the wallet's existing BOLT 12 responder signs an invoice for the
  fixed session amount and LND settles it.

The BOLT 12 deposit path optionally also publishes a
``user@domain`` **BIP-353** handle whose DNS TXT record carries the
BOLT 12 offer string. The operator must own the parent domain and
publish the resulting zone-file fragment via their DNS provider —
the wallet emits the record contents but does not reach out to any
DNS host. When ``ANONYMIZE_BIP353_DEPOSIT_DOMAIN`` is unset, the
session carries only the BOLT 12 offer (no handle).

Both helpers are pure adapters — they don't open a long-lived DB
session for the caller. The session-create endpoint is responsible
for persisting the resulting strings into
``anonymize_session.pipeline_json.source``.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings


class DepositOfferError(RuntimeError):
    """Raised when the BOLT 12 offer-mint flow refuses the request."""


@dataclass(frozen=True)
class DepositOfferResult:
    """Output of the deposit-offer builder."""

    bolt12_offer: str  # ``lno1...`` string the depositor's wallet sees
    offer_id: str  # bolt12_offers.id (UUID string) for join lookups
    bip353_handle: str | None  # ``user@domain`` when a domain is configured
    bip353_txt_record: str | None  # RFC 1035 zone-file TXT fragment
    bip353_user_label: str | None  # randomised ``user`` part of the handle


# Length of the random per-session subdomain label. 12 hex chars =
# 48 bits of entropy, more than enough to prevent a probing attacker
# from guessing live session handles by enumeration.
_BIP353_USER_LABEL_BYTES = 6


async def issue_ext_lightning_deposit_offer(
    *,
    amount_msat: int,
    description: str,
    api_key_id: Any,
    db: AsyncSession,
    bip353_domain: str | None = None,
) -> DepositOfferResult:
    """Mint a per-session BOLT 12 offer (and optionally a BIP-353
    handle) for an ext-lightning deposit.

    The offer is **single-amount**: bound to the session's
    ``bin_amount_sat`` so an inbound invreq for a different amount
    is refused by the existing BOLT 12 responder's amount-policy
    check.

    Persistence: the offer is inserted into ``bolt12_offers`` with
    ``source=ISSUED`` so the existing dashboard tab sees it. The
    inserted row's ``id`` is returned for the anonymize session to
    bind onto.

    Raises :class:`DepositOfferError` on:

    * Amount above the configured ``ANONYMIZE_MAX_SAT`` ceiling.
    * BOLT 12 encode failure.
    * Bad BIP-353 domain (rejected when the configured domain
      doesn't parse as a series of LDH-ASCII labels).
    """
    if amount_msat <= 0:
        raise DepositOfferError("amount_msat must be positive for a deposit offer")
    max_sats = int(settings.anonymize_max_sat)
    if amount_msat > max_sats * 1000:
        raise DepositOfferError(f"amount_msat={amount_msat} exceeds ANONYMIZE_MAX_SAT={max_sats}")

    # Mint the BOLT 12 offer + persist the row. We re-use the
    # wallet's existing offer-issuance machinery so the inbound
    # responder routes incoming invreqs to it automatically.
    from app.api.bolt12 import _build_offer_paths_for_issuance
    from app.core.encryption import encrypt_field
    from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferSource
    from app.services.bolt12 import (
        Bolt12Error,
        CoincurveSigner,
        Offer,
    )
    from app.services.bolt12 import encode as encode_bolt12
    from app.services.bolt12.chain_hash import (
        MAINNET_CHAIN_HASH,
        chain_hash_for,
    )

    issuer_signer = CoincurveSigner.generate()
    issuer_id = issuer_signer.public_key

    our_chain = chain_hash_for(settings.bitcoin_network)
    offer_chains: tuple[bytes, ...] = () if our_chain == MAINNET_CHAIN_HASH else (our_chain,)

    # Embed offer_paths so a depositor whose wallet doesn't
    # gossip-discover the wallet's identity_pubkey can still reach
    # us. Same logic as the public ``/offers/issue`` endpoint.
    offer_paths = await _build_offer_paths_for_issuance()

    offer_obj = Offer(
        chains=offer_chains,
        description=description,
        amount=amount_msat,
        currency=None,
        issuer=None,
        quantity_max=None,
        absolute_expiry=None,
        issuer_id=issuer_id,
        paths=offer_paths,
        metadata=secrets.token_bytes(16),
    )
    try:
        bolt12_str = encode_bolt12(offer_obj.to_bolt12_string())
    except Bolt12Error as exc:
        raise DepositOfferError(f"BOLT 12 offer encode failed: {exc}") from exc

    row = Bolt12Offer(
        api_key_id=api_key_id,
        bolt12=bolt12_str,
        description=description,
        amount_msat=int(amount_msat),
        currency=None,
        issuer=None,
        issuer_id_hex=issuer_id.hex(),
        quantity_max=None,
        source=Bolt12OfferSource.ISSUED,
        encrypted_metadata=encrypt_field(issuer_signer.secret.hex()),
    )
    db.add(row)
    await db.flush()
    await db.refresh(row)

    # Optionally also generate a per-session BIP-353 handle. The
    # ``user`` portion is random per session so handles cannot be
    # enumerated; the ``domain`` is the operator-configured root.
    handle_str: str | None = None
    txt_record: str | None = None
    user_label: str | None = None
    if bip353_domain:
        user_label = secrets.token_hex(_BIP353_USER_LABEL_BYTES)
        handle_str, txt_record = _build_bip353_handle_and_record(
            user=user_label,
            domain=bip353_domain,
            offer=bolt12_str,
        )

    # Emit an audit-trail entry mirroring the
    # public ``/offers/issue`` endpoint. The redactor's
    # privacy-preserving subset is enforced by ``log_action``; we
    # pass only the offer-id + amount + a flag indicating whether
    # a BIP-353 handle was minted alongside, NOT the handle itself
    # (the handle is a DNS artifact whose privacy belongs to the
    # operator's publishing decision).
    try:
        from app.models.api_key import APIKey
        from app.services.audit_service import log_action

        actor = await db.get(APIKey, api_key_id)
        if actor is not None:
            await log_action(
                db,
                actor,
                "anonymize_deposit_offer_issue",
                "bolt12_offer",
                amount_sats=int(amount_msat) // 1000,
                details={
                    "offer_id": str(row.id),
                    "amount_msat": int(amount_msat),
                    "has_bip353_handle": handle_str is not None,
                },
                ip_address=None,
            )
    except Exception:  # noqa: BLE001 — audit must never block the mint
        # The audit module raising here would otherwise rollback the
        # offer insert; we intentionally swallow + log so the deposit
        # path remains available even if the audit chain is wedged.
        import logging as _logging

        from .metadata import ANONYMIZE_LOGGER_NAME

        _logging.getLogger(ANONYMIZE_LOGGER_NAME).exception(
            "anonymize: deposit-offer audit log failed; offer was minted",
        )

    return DepositOfferResult(
        bolt12_offer=bolt12_str,
        offer_id=str(row.id),
        bip353_handle=handle_str,
        bip353_txt_record=txt_record,
        bip353_user_label=user_label,
    )


def _build_bip353_handle_and_record(
    *,
    user: str,
    domain: str,
    offer: str,
) -> tuple[str, str]:
    """Build ``("user@domain", TXT record fragment)`` for a deposit handle.

    Raises :class:`DepositOfferError` on a malformed ``domain``.
    """
    from app.services.bolt12.bip353 import PaymentHandle, build_zone_record

    try:
        handle = PaymentHandle.parse(f"{user}@{domain}")
    except ValueError as exc:
        raise DepositOfferError(f"invalid BIP-353 domain {domain!r}: {exc}") from exc

    try:
        txt_record = build_zone_record(handle, offer=offer)
    except ValueError as exc:
        raise DepositOfferError(f"BIP-353 TXT record build failed: {exc}") from exc

    return f"{handle.user}@{handle.domain}", txt_record


__all__ = [
    "DepositOfferError",
    "DepositOfferResult",
    "issue_ext_lightning_deposit_offer",
]
