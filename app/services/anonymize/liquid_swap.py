# SPDX-License-Identifier: MIT
"""Boltz reverse + submarine swap HTTP clients for the Liquid hop.

**This module replaces ``liquid_chain_swap.py``** — that file targeted
``POST /v2/swap/chain`` (Boltz's on-chain ↔ on-chain product) which is
NOT what the wallet's Liquid hop needs.

The Liquid hop's two legs map to:

* **LN → L-BTC**: a **reverse swap** with ``to: L-BTC`` —
  ``POST /v2/swap/reverse`` with ``{from: BTC, to: L-BTC, invoiceAmount,
  preimageHash, claimPublicKey}``. Boltz returns a Liquid lockup
  address + an LN invoice the wallet pays + a blinding key for
  unblinding the eventual credit.
* **L-BTC → LN**: a **submarine swap** with ``from: L-BTC`` —
  ``POST /v2/swap/submarine`` with ``{from: L-BTC, to: BTC, invoice,
  refundPublicKey}``. The wallet supplies the LN invoice it wants
  paid; Boltz returns a Liquid address the wallet locks its L-BTC
  into. Boltz settles the LN invoice once the lockup confirms.

Both call sites route through the dedicated ``liquid`` SOCKS
listener so circuit-isolation defends against a Boltz-side
observer correlating these calls with the LN-on-Bitcoin reverse /
submarine traffic.

The response shapes are pinned against real Boltz regtest responses
captured against [BoltzExchange/regtest](https://github.com/BoltzExchange/regtest)
running locally — see ``tests/integration/anonymize/`` for the
regtest harness usage.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
from coincurve import PrivateKey

from app.core.http_limits import request_capped

from .boltz_request import (
    make_reverse_create_request,
    make_submarine_create_request,
)
from .http import (
    EgressFingerprintError,
    assert_outbound_request_ok,
    get_anonymize_client,
)
from .metadata import ANONYMIZE_LOGGER_NAME
from .tor import resolve_socks_host, resolve_socks_port

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


_CALL_SITE = "liquid"


# ── Value objects ──────────────────────────────────────────────────


@dataclass(frozen=True)
class SwapTreeLeaf:
    """One leaf of a Boltz swap tree (claim or refund).

    ``output`` is the leaf script as hex; ``version`` is the
    taproot leaf-version byte (typically 196 / 0xc4 for the
    Liquid-tweaked variant).
    """

    version: int
    output: str


@dataclass(frozen=True)
class SwapTree:
    """The taproot swap tree returned by Boltz."""

    claim_leaf: SwapTreeLeaf
    refund_leaf: SwapTreeLeaf


@dataclass(frozen=True)
class LiquidReverseSwap:
    """Result of ``POST /v2/swap/reverse`` with ``to: L-BTC``.

    The wallet pays ``invoice`` over LN; Boltz publishes a CT-blinded
    Liquid output at ``lockup_address`` that the wallet later claims
    cooperatively via MuSig2 (using ``blinding_key`` to unblind +
    ``refund_public_key`` as Boltz's MuSig2 contribution).
    """

    id: str
    swap_tree: SwapTree
    blinding_key_hex: str
    lockup_address: str
    refund_public_key_hex: str
    timeout_block_height: int
    invoice: str
    onchain_amount_sat: int
    raw: dict[str, Any]


@dataclass(frozen=True)
class LiquidSubmarineSwap:
    """Result of ``POST /v2/swap/submarine`` with ``from: L-BTC``.

    The wallet pays ``expected_amount_sat`` of L-BTC into
    ``address`` (a Liquid confidential address Boltz controls);
    Boltz settles the wallet-supplied LN invoice once the lockup
    confirms.
    """

    id: str
    swap_tree: SwapTree
    blinding_key_hex: str
    address: str
    claim_public_key_hex: str
    expected_amount_sat: int
    timeout_block_height: int
    accept_zero_conf: bool
    bip21: str
    raw: dict[str, Any]


# ── Helpers (preimage + keypair) ───────────────────────────────────


def generate_preimage_and_hash() -> tuple[str, str]:
    """Generate a 32-byte random preimage + its SHA-256 hash.

    Returns ``(preimage_hex, preimage_hash_hex)``.
    """
    preimage = secrets.token_bytes(32)
    return preimage.hex(), hashlib.sha256(preimage).hexdigest()


def generate_swap_keypair() -> tuple[str, str]:
    """Generate a fresh secp256k1 keypair for a Liquid swap.

    Returns ``(private_key_hex, public_key_hex_compressed)`` — 64 +
    66 hex chars respectively. Used for claim + refund keys.
    """
    sk = PrivateKey()
    return sk.secret.hex(), sk.public_key.format(compressed=True).hex()


# ── Helpers (response parsing) ─────────────────────────────────────


def _parse_swap_tree(raw: Any) -> SwapTree:
    if not isinstance(raw, dict):
        raise ValueError("swapTree must be a JSON object")
    claim_raw = raw.get("claimLeaf") or {}
    refund_raw = raw.get("refundLeaf") or {}
    return SwapTree(
        claim_leaf=SwapTreeLeaf(
            version=int(claim_raw.get("version", 0)),
            output=str(claim_raw.get("output", "")),
        ),
        refund_leaf=SwapTreeLeaf(
            version=int(refund_raw.get("version", 0)),
            output=str(refund_raw.get("output", "")),
        ),
    )


# ── Client ─────────────────────────────────────────────────────────


class LiquidSwapClient:
    """Anonymize-stack Liquid swap client.

    Composes two methods:

    * :meth:`create_reverse_swap_to_lbtc` — LN → L-BTC.
    * :meth:`create_submarine_swap_from_lbtc` — L-BTC → LN.
    * :meth:`get_swap_status` — ``GET /swap/{id}`` (reuses the
      generic Boltz status endpoint).

    Every method opens a fresh anonymize HTTP client (fresh Tor
    circuit); ``base_url`` selects which Boltz operator
    is hit (the wallet may target distinct operators).
    """

    def __init__(
        self,
        *,
        base_url: str,
        socks_host: str | None = None,
        socks_port: int | None = None,
        timeout_s: float = 30.0,
    ) -> None:
        if not base_url:
            raise ValueError("base_url must be set (no implicit default)")
        self._base_url = base_url.rstrip("/")
        self._socks_host = socks_host or resolve_socks_host()
        self._socks_port_override = socks_port
        self._timeout_s = timeout_s

    def _resolved_port(self) -> int:
        if self._socks_port_override is not None:
            return self._socks_port_override
        return resolve_socks_port(_CALL_SITE)

    async def create_reverse_swap_to_lbtc(
        self,
        *,
        invoice_amount_sat: int,
        preimage_hash_hex: str,
        claim_public_key_hex: str,
    ) -> tuple[LiquidReverseSwap | None, str | None]:
        """Issue ``POST /v2/swap/reverse`` with ``to: L-BTC``.

        Returns ``(swap, None)`` on success or ``(None, error)``.
        """
        if invoice_amount_sat <= 0:
            return None, "invoice_amount_sat must be positive"
        if len(preimage_hash_hex) != 64:
            return None, "preimage_hash_hex must be 64 chars"

        request_body = make_reverse_create_request(
            preimage_hash_hex=preimage_hash_hex,
            claim_public_key_hex=claim_public_key_hex,
            invoice_amount_sats=int(invoice_amount_sat),
            destination_address=None,
            from_chain="BTC",
            to_chain="L-BTC",
            pad=False,
        )

        try:
            assert_outbound_request_ok(request_body, None)
        except EgressFingerprintError as exc:
            return None, f"egress lint failed: {exc}"

        url = f"{self._base_url}/v2/swap/reverse"
        try:
            async with get_anonymize_client(
                call_site=_CALL_SITE,
                socks_host=self._socks_host,
                socks_port=self._resolved_port(),
                timeout_s=self._timeout_s,
            ) as client:
                response = await request_capped(client, "POST", url, json=request_body)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text
            try:
                body = exc.response.json().get("error", body)
            except Exception:  # noqa: BLE001
                pass
            return None, (f"Boltz reverse swap (to L-BTC) failed: {exc.response.status_code}: {body}")
        except Exception as exc:  # noqa: BLE001
            return None, f"Boltz reverse swap (to L-BTC) egress failed: {exc}"

        if not isinstance(data, dict) or "id" not in data:
            return None, "Boltz response missing 'id'"

        required = (
            "swapTree",
            "blindingKey",
            "lockupAddress",
            "refundPublicKey",
            "timeoutBlockHeight",
            "invoice",
            "onchainAmount",
        )
        for field in required:
            if field not in data:
                return None, f"Boltz response missing {field!r}"

        # Bind the returned hold-invoice to OUR preimage hash. A reverse
        # swap is only trustless if the invoice we are about to pay commits
        # to sha256(preimage) we generated. Otherwise a malicious operator
        # returns an invoice whose payment hash it already knows the
        # preimage for, settles the HTLC to take our LN funds, and never
        # has to reveal the preimage we need to claim the on-chain lockup.
        import hmac as _hmac

        from app.core.bolt11 import payment_hash_from_bolt11

        invoice_payment_hash = payment_hash_from_bolt11(str(data["invoice"]))
        if invoice_payment_hash is None or not _hmac.compare_digest(
            invoice_payment_hash, preimage_hash_hex.lower()
        ):
            return None, "Boltz reverse invoice payment_hash does not commit to our preimage hash"

        try:
            swap_tree = _parse_swap_tree(data["swapTree"])
        except ValueError as exc:
            return None, f"malformed swapTree: {exc}"

        # Fairness guard: refuse a grossly under-delivering on-chain amount.
        # Liquid swap fees are low; allow a generous 20% haircut margin so
        # this only trips on a malicious operator, not normal fees.
        try:
            onchain_amount = int(data["onchainAmount"])
        except (TypeError, ValueError, KeyError):
            return None, "Boltz reverse (L-BTC) response missing/invalid onchainAmount"
        if onchain_amount < int(invoice_amount_sat * 0.80):
            return None, (
                f"Boltz reverse (L-BTC) onchainAmount {onchain_amount} is below 80% of "
                f"invoice {invoice_amount_sat}; refusing"
            )

        return LiquidReverseSwap(
            id=str(data["id"]),
            swap_tree=swap_tree,
            blinding_key_hex=str(data["blindingKey"]),
            lockup_address=str(data["lockupAddress"]),
            refund_public_key_hex=str(data["refundPublicKey"]),
            timeout_block_height=int(data["timeoutBlockHeight"]),
            invoice=str(data["invoice"]),
            onchain_amount_sat=onchain_amount,
            raw=data,
        ), None

    async def create_submarine_swap_from_lbtc(
        self,
        *,
        invoice: str,
        refund_public_key_hex: str,
    ) -> tuple[LiquidSubmarineSwap | None, str | None]:
        """Issue ``POST /v2/swap/submarine`` with ``from: L-BTC``.

        The wallet supplies the LN ``invoice`` it wants paid; Boltz
        returns the Liquid lockup ``address`` the wallet must fund.
        """
        if not invoice:
            return None, "invoice must be non-empty"
        if not refund_public_key_hex:
            return None, "refund_public_key_hex must be non-empty"

        request_body = make_submarine_create_request(
            invoice=invoice,
            refund_public_key_hex=refund_public_key_hex,
            from_chain="L-BTC",
            to_chain="BTC",
            pad=False,
        )

        try:
            assert_outbound_request_ok(request_body, None)
        except EgressFingerprintError as exc:
            return None, f"egress lint failed: {exc}"

        url = f"{self._base_url}/v2/swap/submarine"
        try:
            async with get_anonymize_client(
                call_site=_CALL_SITE,
                socks_host=self._socks_host,
                socks_port=self._resolved_port(),
                timeout_s=self._timeout_s,
            ) as client:
                response = await request_capped(client, "POST", url, json=request_body)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text
            try:
                body = exc.response.json().get("error", body)
            except Exception:  # noqa: BLE001
                pass
            return None, (f"Boltz submarine swap (from L-BTC) failed: {exc.response.status_code}: {body}")
        except Exception as exc:  # noqa: BLE001
            return None, f"Boltz submarine swap (from L-BTC) egress failed: {exc}"

        if not isinstance(data, dict) or "id" not in data:
            return None, "Boltz response missing 'id'"

        required = (
            "swapTree",
            "blindingKey",
            "address",
            "claimPublicKey",
            "expectedAmount",
            "timeoutBlockHeight",
        )
        for field in required:
            if field not in data:
                return None, f"Boltz response missing {field!r}"

        try:
            swap_tree = _parse_swap_tree(data["swapTree"])
        except ValueError as exc:
            return None, f"malformed swapTree: {exc}"

        return LiquidSubmarineSwap(
            id=str(data["id"]),
            swap_tree=swap_tree,
            blinding_key_hex=str(data["blindingKey"]),
            address=str(data["address"]),
            claim_public_key_hex=str(data["claimPublicKey"]),
            expected_amount_sat=int(data["expectedAmount"]),
            timeout_block_height=int(data["timeoutBlockHeight"]),
            accept_zero_conf=bool(data.get("acceptZeroConf", False)),
            bip21=str(data.get("bip21", "")),
            raw=data,
        ), None

    async def get_swap_status(
        self,
        swap_id: str,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """``GET /swap/{id}`` — reuses Boltz's generic status endpoint."""
        if not swap_id:
            return None, "swap_id must be non-empty"
        url = f"{self._base_url}/swap/{quote(swap_id, safe='')}"
        try:
            async with get_anonymize_client(
                call_site=_CALL_SITE,
                socks_host=self._socks_host,
                socks_port=self._resolved_port(),
                timeout_s=self._timeout_s,
            ) as client:
                response = await request_capped(client, "GET", url)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as exc:
            return None, (f"Boltz status failed: {exc.response.status_code}: {exc.response.text[:200]}")
        except Exception as exc:  # noqa: BLE001
            return None, f"Boltz status egress failed: {exc}"
        if not isinstance(data, dict):
            return None, "Boltz status response was not a JSON object"
        return data, None


__all__ = [
    "LiquidReverseSwap",
    "LiquidSubmarineSwap",
    "LiquidSwapClient",
    "SwapTree",
    "SwapTreeLeaf",
    "generate_preimage_and_hash",
    "generate_swap_keypair",
]
