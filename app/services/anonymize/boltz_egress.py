# SPDX-License-Identifier: MIT
"""Anonymize-stack-direct
Boltz HTTP egress.

The reverse-hop dispatcher must not delegate to the wallet's general
``boltz_service`` for Boltz API calls: that client routes through
``LND_TOR_PROXY`` (a single shared SOCKS listener) and emits the
default httpx ClientHello + ``Content-Type: application/json`` header
set. Sharing that path with a wallet's organic Boltz traffic both:

* breaks **Tor stream isolation**: every anonymize
  call needs a fresh circuit via the per-call ``IsolateSOCKSAuth``
  SOCKS authentication pair.
* leaks a **stable client fingerprint**: the operator sees
  the same ClientHello + header set across legs.
* and skips the **circuit-rebuild bandwidth budget**: the
  anonymize wrapper enforces a per-listener token bucket on
  fresh-circuit issuance.

This module wraps the pinned-shape Boltz endpoints (POST /swap/reverse
and GET /swap/{id}) through :func:`app.services.anonymize.http.get_anonymize_client`
so every anonymize-stack Boltz call:

1. Picks the ``boltz_reverse`` SOCKS listener.
2. Issues a fresh SOCKS-auth pair → fresh Tor circuit.
3. Goes through the pinned-headers / pinned-ClientHello wrapper.
4. Posts a.4-padded request body produced by
   :func:`make_reverse_create_request` (the body carries ``_pad``).
5. Counts against the circuit-rebuild budget; a starved
   listener raises :class:`CircuitRebuildThrottledError` and routes
   the session through reconciliation.

The resulting :class:`BoltzSwap` row + downstream cooperative-claim
flow continue to live in the existing wallet machinery —
``create_reverse_swap_via_anonymize`` builds + persists the row using
the same encrypted columns as ``boltz_service.create_reverse_swap``
but performs the upstream HTTP through the anonymize wrapper.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import UUID

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.bolt11 import payment_hash_from_bolt11, principal_sats_from_bolt11
from app.core.config import settings
from app.core.encryption import encrypt_field
from app.core.http_limits import request_capped
from app.models.boltz_swap import BoltzSwap, SwapStatus

from .boltz_request import make_reverse_create_request
from .http import (
    EgressFingerprintError,
    assert_outbound_request_ok,
    get_anonymize_client,
)
from .metadata import ANONYMIZE_LOGGER_NAME
from .tor import resolve_socks_host, resolve_socks_port

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


_CALL_SITE = "boltz_reverse"


def _boltz_base_url() -> str:
    """Return the Boltz base URL the anonymize stack should hit.

    Always prefers the onion URL when configured — the anonymize
    wrapper routes through the dedicated ``boltz_reverse`` SOCKS
    listener regardless, but the onion service shortens the path
    and avoids the exit-relay step.
    """
    onion = (settings.boltz_onion_url or "").strip()
    if onion:
        return onion
    return settings.boltz_api_url


def _generate_preimage() -> tuple[str, str]:
    """Generate a 32-byte random preimage + its SHA-256 hash."""
    preimage = secrets.token_bytes(32)
    return preimage.hex(), hashlib.sha256(preimage).hexdigest()


def _scripts_dir() -> str:
    """Return the absolute path to the repo's ``scripts/`` directory.

    Node's ``require()`` resolves modules relative to the script's
    cwd, so we must point our ``node -e`` subprocesses at this dir —
    that's where ``scripts/package.json`` + ``scripts/node_modules``
    (carrying ``ecpair``, ``tiny-secp256k1``, etc.) live. Running the
    subprocess with the default ``/app`` cwd would otherwise fail
    with ``Cannot find module 'ecpair'``.
    """
    return str(Path(__file__).resolve().parents[3] / "scripts")


# Resolve ``node`` to an absolute path so the subprocess runs the system
# interpreter rather than whatever an earlier, writable ``PATH`` entry
# might shadow. Falls back to the bare name on a mis-provisioned host,
# which then surfaces as a clear subprocess error.
_NODE_BIN = shutil.which("node") or "node"
_NODE_BIN_DIR = str(Path(_NODE_BIN).parent) if os.path.sep in _NODE_BIN else "/usr/local/bin"


def _node_subprocess_env() -> dict[str, str]:
    """Minimal environment for the Node keypair subprocess.

    The child inherits only a pinned ``PATH`` (the resolved node
    directory plus the standard system bins), ``HOME``, and
    ``NODE_PATH``, so ``SECRET_KEY``, ``DATABASE_URL``, ``BOLTZ_*`` and
    the rest of the process environment never reach the JS process or
    anything it spawns.
    """
    return {
        "PATH": f"{_NODE_BIN_DIR}:/usr/local/bin:/usr/bin:/bin",
        "HOME": os.environ.get("HOME", "/tmp"),
        "NODE_PATH": str(Path(_scripts_dir()) / "node_modules"),
        "LC_ALL": "C",
    }


def _generate_keypair() -> tuple[str, str]:
    """Generate an ephemeral secp256k1 keypair via Node boltz-core.

    Private key is passed via stdin so it never appears in argv.
    The anonymize-stack uses the same keypair shape as
    ``boltz_service``; we duplicate the helper here so this module
    doesn't import the wallet's general Boltz path.
    """
    private_key = secrets.token_bytes(32)
    result = subprocess.run(
        [
            _NODE_BIN,
            "-e",
            """
            const { ECPairFactory } = require('ecpair');
            const ecc = require('tiny-secp256k1');
            const ECPair = ECPairFactory(ecc);
            let data = '';
            process.stdin.on('data', c => data += c);
            process.stdin.on('end', () => {
                const kp = ECPair.fromPrivateKey(Buffer.from(data.trim(), 'hex'));
                console.log(JSON.stringify({
                    privateKey: kp.privateKey.toString('hex'),
                    publicKey: kp.publicKey.toString('hex')
                }));
            });
            """,
        ],
        input=private_key.hex(),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        # Run from ``scripts/`` so Node resolves ``ecpair`` /
        # ``tiny-secp256k1`` from ``scripts/node_modules`` instead of
        # falling through to the api container's empty /app.
        cwd=_scripts_dir(),
        # Scrubbed env so the keypair child never sees SECRET_KEY,
        # DATABASE_URL, or the BOLTZ_* configuration.
        env=_node_subprocess_env(),
    )
    if result.returncode != 0:
        raise RuntimeError(f"keypair gen failed: {result.stderr[:200]}")
    parsed = json.loads(result.stdout.strip())
    return parsed["privateKey"], parsed["publicKey"]


# The submarine lockup-address verifier now lives in a shared module so
# the mainline / Braiins-deposit submarine path can call the same
# implementation (follow-up H1). Re-exported here for the existing call
# site + any importers of this symbol.
from app.services.boltz_lockup_verify import (  # noqa: E402
    verify_reverse_lockup_address as verify_reverse_lockup_address,
)
from app.services.boltz_lockup_verify import (
    verify_submarine_lockup_address as verify_submarine_lockup_address,
)


class AnonymizeBoltzClient:
    """Anonymize-stack-direct Boltz client.

    Every call opens a fresh anonymize HTTP client through
    :func:`get_anonymize_client`. Reusing a client across calls would
    re-use the same SOCKS auth pair (so the same Tor circuit), which
    is exactly what stream isolation forbids.

    The two methods mirror the wallet's ``boltz_service`` surface
    the reverse-hop dispatcher needs:

    * :meth:`create_reverse_swap` — POST /swap/reverse with the
       pinned body shape.
    * :meth:`get_swap_status` — GET /swap/{id}.

    Both run the forbidden-field lint via
    :func:`assert_outbound_request_ok` before egress.
    """

    def __init__(
        self,
        *,
        base_url: str | None = None,
        socks_host: str | None = None,
        socks_port: int | None = None,
        timeout_s: float = 30.0,
    ) -> None:
        self._base_url = base_url or _boltz_base_url()
        self._socks_host = socks_host or resolve_socks_host()
        # Late-bind the port so missing SOCKS-listener configuration
        # raises only when an egress is actually attempted (tests that
        # mock the client don't need a live listener mapping).
        self._socks_port_override = socks_port
        self._timeout_s = timeout_s

    def _resolved_port(self) -> int:
        if self._socks_port_override is not None:
            return self._socks_port_override
        return resolve_socks_port(_CALL_SITE)

    def _verify_response_signature(
        self,
        *,
        response: httpx.Response,
        response_body: bytes,
        operator_id: str | None,
    ) -> str | None:
        """Verify the operator's signature header against the
        registry entry's pinned ``public_key_hex``.

        Returns ``None`` on success (no error) or an error string when
        verification fails. A signed-registry deployment requires every
        Boltz API response to carry ``X-Operator-Signature: <hex>``.
        Single-operator deployments without a registry have
        ``operator_id is None`` — verification is skipped (the
        single-operator trust model applies).
        """
        if not operator_id:
            return None
        try:
            from .operators import (
                load_signed_operator_registry,
                verify_operator_api_response,
            )
        except ImportError:  # pragma: no cover — defensive
            return None
        try:
            registry = load_signed_operator_registry()
        except Exception as exc:  # noqa: BLE001
            # A non-null operator_id means
            # this session is bound to a specific registry operator whose
            # responses MUST be signature-verified. If the registry fails
            # to load (file swap, signature corruption, a rotated-out key,
            # transient FS error), we must NOT silently fall through to
            # the single-operator no-verify path — that would degrade the
            # whole deployment to unverified operator responses. Fail
            # closed with an error so the hop routes through
            # reconciliation as an operator_signature_mismatch.
            logger.error(
                "operator registry failed to load while verifying a response "
                "bound to operator %r (%s); refusing to skip verification",
                operator_id,
                type(exc).__name__,
            )
            return "operator registry unavailable for signature verification"
        op = next(
            (o for o in registry if o.operator_id == operator_id),
            None,
        )
        if op is None or not (op.public_key_hex or "").strip():
            # Operator missing from a *successfully-loaded* registry or it
            # has no signing key. Single-leg / single-operator deployments
            # (intentionally-empty registry) legitimately fall through.
            return None
        sig_hex = (response.headers.get("X-Operator-Signature") or "").strip()
        if not sig_hex:
            return "operator response missing X-Operator-Signature header"
        try:
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError:
            return "operator response signature is not valid hex"
        if not verify_operator_api_response(
            operator=op,
            response_body=response_body,
            signature_bytes=sig_bytes,
        ):
            return f"operator response signature did not verify for operator {operator_id!r}"
        return None

    async def create_reverse_swap(
        self,
        db: AsyncSession,
        *,
        api_key_id: UUID,
        invoice_amount_sats: int,
        destination_address: str,
        operator_id: str | None = None,
    ) -> tuple[BoltzSwap | None, str | None]:
        """Issue POST /swap/reverse through the anonymize HTTP wrapper.

        Returns ``(swap, None)`` on success or ``(None, error)`` on
        failure. The persisted :class:`BoltzSwap` row carries the
        encrypted preimage + claim private key so the downstream
        cooperative-claim subprocess can decrypt them.

        When ``operator_id`` is supplied and the loaded registry has
        a matching entry, the response's ``X-Operator-Signature``
        header is verified against the operator's pinned
        ``public_key_hex``.
        """
        try:
            preimage_hex, preimage_hash_hex = _generate_preimage()
            claim_private_key_hex, claim_public_key_hex = _generate_keypair()
        except (RuntimeError, OSError) as exc:
            return None, f"keypair generation failed: {exc}"

        request_body = make_reverse_create_request(
            preimage_hash_hex=preimage_hash_hex,
            claim_public_key_hex=claim_public_key_hex,
            invoice_amount_sats=invoice_amount_sats,
            destination_address=destination_address,
        )

        try:
            assert_outbound_request_ok(request_body, None)
        except EgressFingerprintError as exc:
            return None, f"egress lint failed: {exc}"

        port = self._resolved_port()
        url = f"{self._base_url}/swap/reverse"

        try:
            async with get_anonymize_client(
                call_site=_CALL_SITE,
                socks_host=self._socks_host,
                socks_port=port,
                timeout_s=self._timeout_s,
            ) as client:
                response = await request_capped(client, "POST", url, json=request_body)
                response.raise_for_status()
                response_body = response.content
                data = response.json()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text
            try:
                body = exc.response.json().get("error", body)
            except Exception:  # noqa: BLE001
                pass
            return None, (f"Boltz reverse-swap creation failed: {exc.response.status_code}: {body}")
        except Exception as exc:  # noqa: BLE001
            return None, f"Boltz reverse-swap egress failed: {exc}"

        # Verify the operator's response signature against
        # the registry's pinned public_key_hex.
        sig_err = self._verify_response_signature(
            response=response,
            response_body=response_body,
            operator_id=operator_id,
        )
        if sig_err is not None:
            return None, sig_err

        if not isinstance(data, dict) or "id" not in data:
            return None, "Boltz response missing 'id' field"

        # Bind the returned hold-invoice to OUR preimage hash before we
        # ever pay it. The response signature only proves the operator
        # authored the response — a malicious operator happily signs an
        # invoice whose payment hash it controls, settles the HTLC to take
        # our LN funds, and never reveals the preimage we need to claim the
        # on-chain lockup. This equality is the check that makes the reverse
        # swap trustless.
        invoice_str = data.get("invoice")
        invoice_payment_hash = payment_hash_from_bolt11(invoice_str) if isinstance(invoice_str, str) else None
        if invoice_payment_hash is None or not hmac.compare_digest(invoice_payment_hash, preimage_hash_hex.lower()):
            return None, "Boltz reverse invoice payment_hash does not commit to our preimage hash"

        # Bind the invoice *principal* to the amount we asked to send.
        # The operator constructs the hold invoice and chooses both its
        # payment hash (which we pin above) and its amount, so without
        # this check it could inflate the principal — LND would pay the
        # larger amount while the operator still only locks up
        # ``onchainAmount``, pocketing the difference once the preimage is
        # revealed. The on-chain fairness floor below keys off the
        # *requested* amount, not the invoice, so it does not catch this.
        invoice_principal = principal_sats_from_bolt11(invoice_str) if isinstance(invoice_str, str) else None
        if invoice_principal is None or invoice_principal != int(invoice_amount_sats):
            return None, (
                f"Boltz reverse invoice principal {invoice_principal} does not match "
                f"requested amount {int(invoice_amount_sats)}; refusing"
            )

        # Fairness floor: the on-chain amount the operator locks up must be
        # at least (invoice − the configured fee ceiling). The egress path
        # posts straight to /swap/reverse without a pair-info block, so the
        # floor is driven from ANONYMIZE_REVERSE_MAX_TOTAL_FEE_PCT rather
        # than operator-declared fees. Evaluated before the Lightning
        # hold-invoice is paid so an unfair swap is never funded — a swap
        # quoting a fair LN invoice while delivering far less on-chain
        # would otherwise let the operator keep the difference once the
        # preimage is revealed.
        try:
            onchain_amount = int(data.get("onchainAmount"))
        except (TypeError, ValueError):
            return None, "Boltz reverse response missing/invalid onchainAmount"
        fee_ceiling = int(invoice_amount_sats * float(settings.anonymize_reverse_max_total_fee_pct) / 100.0)
        fair_min = invoice_amount_sats - fee_ceiling
        if onchain_amount < fair_min:
            return None, (
                f"Boltz reverse onchainAmount {onchain_amount} below fair minimum "
                f"{fair_min} (invoice {invoice_amount_sats} − "
                f"{settings.anonymize_reverse_max_total_fee_pct}% ceiling); refusing"
            )

        # Verify the reverse lockup address commits to the swap tree + OUR claim
        # key BEFORE the hold invoice is paid. The payment-hash binding above
        # stops LN-settlement theft, but it does NOT stop a malicious operator
        # returning a lockup whose claim leaf it controls — that would leave us
        # unable to sweep the on-chain BTC after we've paid LN. Mirrors the
        # submarine leg below and cold-storage's reverse path.
        lockup_address = data.get("lockupAddress")
        swap_tree_json = data.get("swapTree")
        if not lockup_address or not swap_tree_json:
            return None, "Boltz reverse response missing lockupAddress/swapTree"
        ok, reason = verify_reverse_lockup_address(
            swap_tree_json=swap_tree_json,
            claim_public_key_hex=claim_public_key_hex,
            refund_public_key_hex=data.get("refundPublicKey"),
            lockup_address=str(lockup_address),
            network=settings.bitcoin_network,
        )
        if not ok:
            logger.error(
                "anonymize reverse swap %s: lockup address verification FAILED (%s); refusing to pay invoice",
                data.get("id"),
                reason,
            )
            return None, f"reverse lockup address verification failed: {reason}"

        swap = BoltzSwap(
            boltz_swap_id=data["id"],
            api_key_id=api_key_id,
            invoice_amount_sats=invoice_amount_sats,
            onchain_amount_sats=data.get("onchainAmount"),
            destination_address=destination_address,
            fee_percentage="0",
            miner_fee_sats=0,
            preimage_hex=encrypt_field(preimage_hex),
            preimage_hash_hex=preimage_hash_hex,
            claim_private_key_hex=encrypt_field(claim_private_key_hex),
            claim_public_key_hex=claim_public_key_hex,
            boltz_invoice=data.get("invoice"),
            boltz_lockup_address=data.get("lockupAddress"),
            boltz_refund_public_key_hex=data.get("refundPublicKey"),
            boltz_swap_tree_json=data.get("swapTree"),
            timeout_block_height=data.get("timeoutBlockHeight"),
            boltz_blinding_key=data.get("blindingKey"),
            status=SwapStatus.CREATED,
            boltz_status="swap.created",
            status_history=[
                {
                    "status": "created",
                    "boltz_status": "swap.created",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ],
        )
        db.add(swap)
        await db.commit()
        await db.refresh(swap)

        logger.info(
            "anonymize reverse swap created via anonymize-egress: id=%s amount=%d",
            swap.boltz_swap_id,
            invoice_amount_sats,
        )
        return swap, None

    async def create_submarine_swap(
        self,
        db: AsyncSession,
        *,
        api_key_id: UUID,
        invoice: str,
        pair_hash: str | None = None,
        anonymize_session_id: UUID | None = None,
        operator_id: str | None = None,
    ) -> tuple[BoltzSwap | None, str | None]:
        """— POST /swap/submarine through the anonymize wrapper.

        The wallet supplies the BOLT11 invoice the swap will pay out
        to; the server returns the on-chain lockup address the
        wallet funds. The persisted :class:`BoltzSwap` row carries
        the refund private key (Fernet-encrypted) so the wallet can
        broadcast the if the server fails to settle.

        Returns ``(swap, None)`` on success or ``(None, error)``.
        """
        # Wallet-controlled keypair for the refund path. The private
        # key never leaves this process; the server only sees the
        # public key.
        try:
            refund_private_key_hex, refund_public_key_hex = _generate_keypair()
        except (RuntimeError, OSError) as exc:
            return None, f"refund keypair generation failed: {exc}"

        from .boltz_request import make_submarine_create_request

        request_body = make_submarine_create_request(
            invoice=invoice,
            refund_public_key_hex=refund_public_key_hex,
            pair_hash=pair_hash,
        )

        try:
            assert_outbound_request_ok(request_body, None)
        except EgressFingerprintError as exc:
            return None, f"egress lint failed: {exc}"

        port = self._resolved_port()
        url = f"{self._base_url}/swap/submarine"

        try:
            async with get_anonymize_client(
                call_site=_CALL_SITE,
                socks_host=self._socks_host,
                socks_port=port,
                timeout_s=self._timeout_s,
            ) as client:
                response = await request_capped(client, "POST", url, json=request_body)
                response.raise_for_status()
                response_body = response.content
                data = response.json()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text
            try:
                body = exc.response.json().get("error", body)
            except Exception:  # noqa: BLE001
                pass
            return None, (f"Boltz submarine-swap creation failed: {exc.response.status_code}: {body}")
        except Exception as exc:  # noqa: BLE001
            return None, f"Boltz submarine-swap egress failed: {exc}"

        # Verify the operator's signature header.
        sig_err = self._verify_response_signature(
            response=response,
            response_body=response_body,
            operator_id=operator_id,
        )
        if sig_err is not None:
            return None, sig_err

        if not isinstance(data, dict) or "id" not in data:
            return None, "Boltz response missing 'id' field"

        # Verify the operator-supplied lockup address actually commits to
        # the swap tree + our refund key BEFORE we ever fund it. The
        # response signature only proves the operator authored the
        # response; it does NOT stop a malicious operator returning an
        # address it controls (no refundable script) to steal the funding.
        # Reconstruct the expected address and refuse on mismatch.
        lockup_address = data.get("address")
        swap_tree_json = data.get("swapTree")
        if not lockup_address or not swap_tree_json:
            return None, "Boltz submarine response missing address/swapTree"
        ok, reason = verify_submarine_lockup_address(
            swap_tree_json=swap_tree_json,
            refund_public_key_hex=refund_public_key_hex,
            lockup_address=str(lockup_address),
            network=settings.bitcoin_network,
        )
        if not ok:
            logger.error(
                "anonymize submarine swap %s: lockup address verification FAILED (%s); refusing to fund",
                data.get("id"),
                reason,
            )
            return None, f"submarine lockup address verification failed: {reason}"

        # Bound the funded amount. The wallet funds Boltz's returned
        # ``expectedAmount``; cap it to (invoice principal + fee ceiling +
        # slack) so a malicious operator can't inflate it and make us
        # silently over-fund. The egress path carries no pair-info block,
        # so the ceiling is driven from the configured max-total-fee pct
        # (the same knob the reverse fairness floor uses). Mirrors the
        # mainline submarine path's ``fair_lockup`` bound.
        invoice_principal = principal_sats_from_bolt11(invoice)
        expected_amount = int(data.get("expectedAmount", 0) or 0)
        if invoice_principal is not None and invoice_principal > 0:
            fee_ceiling = int(invoice_principal * float(settings.anonymize_reverse_max_total_fee_pct) / 100.0)
            slack = max(1000, int(invoice_principal * 0.01))
            fair_lockup = invoice_principal + fee_ceiling
            if expected_amount > fair_lockup + slack:
                return None, (
                    f"Boltz submarine expectedAmount {expected_amount} exceeds fair lockup "
                    f"{fair_lockup} (+{slack} slack); refusing"
                )

        # The wallet must persist a BoltzSwap row with the refund
        # material so the orchestrator's refund-tx path can later
        # spend the lockup. Note: submarine swaps reuse the BoltzSwap
        # schema; ``preimage_hex`` is unused (only reverse swaps mint
        # preimages — for submarine, the invoice carries the preimage
        # hash + the server reveals the preimage by paying).
        swap = BoltzSwap(
            boltz_swap_id=data["id"],
            api_key_id=api_key_id,
            invoice_amount_sats=0,  # set by upstream invoice; not on the wire
            onchain_amount_sats=data.get("expectedAmount"),
            destination_address=data.get("address") or "",
            fee_percentage="0",
            miner_fee_sats=0,
            preimage_hex=encrypt_field("00" * 32),  # unused for submarine
            preimage_hash_hex="00" * 32,
            claim_private_key_hex=encrypt_field(refund_private_key_hex),
            claim_public_key_hex=refund_public_key_hex,
            boltz_invoice=invoice,  # the wallet-supplied invoice
            boltz_lockup_address=data.get("address"),
            boltz_refund_public_key_hex=refund_public_key_hex,
            boltz_swap_tree_json=data.get("swapTree"),
            timeout_block_height=data.get("timeoutBlockHeight"),
            boltz_blinding_key=data.get("blindingKey"),
            status=SwapStatus.CREATED,
            boltz_status="swap.created",
            status_history=[
                {
                    "status": "created",
                    "boltz_status": "swap.created",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ],
        )
        db.add(swap)
        await db.commit()
        await db.refresh(swap)

        logger.info(
            "anonymize submarine swap created via anonymize-egress: id=%s lockup_address=%s",
            swap.boltz_swap_id,
            (swap.boltz_lockup_address or "")[:12],
        )
        return swap, None

    async def get_swap_status(
        self,
        boltz_swap_id: str,
        *,
        operator_id: str | None = None,
    ) -> tuple[str | None, dict[str, Any] | None, str | None]:
        """Issue GET /swap/{id} through the anonymize HTTP wrapper.

        Returns ``(status, data, None)`` on success or ``(None, None, error)``.

        When ``operator_id`` is supplied + a registry entry exists, the
        response's ``X-Operator-Signature`` header is verified
        against the operator's pinned ``public_key_hex``.
        """
        port = self._resolved_port()
        url = f"{self._base_url}/swap/{quote(boltz_swap_id, safe='')}"
        try:
            async with get_anonymize_client(
                call_site=_CALL_SITE,
                socks_host=self._socks_host,
                socks_port=port,
                timeout_s=self._timeout_s,
            ) as client:
                response = await request_capped(client, "GET", url)
                response.raise_for_status()
                response_body = response.content
                data = response.json()
        except httpx.HTTPStatusError as exc:
            return None, None, (f"Boltz status query failed: {exc.response.status_code}: {exc.response.text[:200]}")
        except Exception as exc:  # noqa: BLE001
            return None, None, f"Boltz status egress failed: {exc}"

        # Verify the operator's signature header.
        sig_err = self._verify_response_signature(
            response=response,
            response_body=response_body,
            operator_id=operator_id,
        )
        if sig_err is not None:
            return None, None, sig_err

        if not isinstance(data, dict):
            return None, None, "Boltz status response was not a JSON object"
        return data.get("status"), data, None


# --------------------------------------------------------------------
# Quote-cache refresh egress.
# --------------------------------------------------------------------


_CACHE_REFRESH_CALL_SITE = "quote_cache_refresh"


async def fetch_reverse_pair_info_for_cache(
    operator_id: str,
    *,
    base_url: str | None = None,
    socks_host: str | None = None,
    socks_port: int | None = None,
    timeout_s: float = 30.0,
) -> tuple[dict[str, Any] | None, str | None]:
    """Refresh the Boltz reverse-swap pair-info into the
    quote cache via the dedicated ``quote_cache_refresh`` SOCKS
    listener.

    A separate listener from ``boltz_reverse`` means a passive
    observer of the reverse-hop call site can't correlate cache
    refreshes (constant cadence) with session-bound reverse swaps
    (sparse, per-session). ``operator_id`` is informational for the
    caller; the egress itself does not put it on the wire.
    """
    resolved_host = socks_host or resolve_socks_host()
    resolved_port = socks_port if socks_port is not None else resolve_socks_port(_CACHE_REFRESH_CALL_SITE)
    resolved_base = (base_url or _boltz_base_url()).rstrip("/")
    url = f"{resolved_base}/swap/reverse"
    try:
        async with get_anonymize_client(
            call_site=_CACHE_REFRESH_CALL_SITE,
            socks_host=resolved_host,
            socks_port=resolved_port,
            timeout_s=timeout_s,
        ) as client:
            response = await request_capped(client, "GET", url)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPStatusError as exc:
        return None, (f"Boltz pair-info refresh failed: {exc.response.status_code}: {exc.response.text[:200]}")
    except Exception as exc:  # noqa: BLE001
        return None, f"Boltz pair-info refresh failed: {exc}"
    if not isinstance(data, dict):
        return None, "Boltz pair-info response was not a JSON object"
    return data, None


__all__ = [
    "AnonymizeBoltzClient",
    "fetch_reverse_pair_info_for_cache",
]
