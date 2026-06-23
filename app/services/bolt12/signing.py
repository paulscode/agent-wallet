# SPDX-License-Identifier: MIT
"""BIP-340 signing / verification for BOLT 12 messages.

BOLT 12 mandates BIP-340 (x-only Schnorr) signatures over
the Merkle root of every TLV that isn't itself in the signature
range (240..1000). This module provides:

* A small ``Bip340Signer`` Protocol so callers can plug in HSMs,
  remote signers, or unit-test fakes without depending on libsecp.
* :class:`CoincurveSigner` — the production implementation using
  the well-vetted ``coincurve`` libsecp256k1 binding.
* High-level helpers :func:`sign_invoice_request`,
  :func:`verify_invoice_request`, :func:`sign_invoice`, and
  :func:`verify_invoice` that operate on the typed dataclasses from
  :mod:`app.services.bolt12.fields`.

Key conventions (BOLT 12 §1.7):

* The signing key for an ``invoice_request`` is the transient
  ``invreq_payer_id`` (33-byte compressed point). BIP-340 is x-only,
  so the y-parity byte is ignored when verifying — this is part of
  the spec, not a hack.
* The signing key for an ``invoice`` is ``invoice_node_id`` (also
  a 33-byte compressed point), with the same x-only convention.
* The signed message is the 32-byte ``signature_message_hash``
  produced by :func:`Bolt12String.signature_digest`. We deliberately
  re-use the codec's tagged-hash code so test vectors are exercised
  end-to-end.

This module is intentionally **stateless and dependency-light**.
Anything that requires private-key custody should compose a signer
implementation rather than reaching into the dataclasses directly.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Protocol, runtime_checkable

from coincurve import PrivateKey
from coincurve.keys import PublicKeyXOnly

from app.services.bolt12.fields import Invoice, InvoiceRequest

# ── primitive helpers ─────────────────────────────────────────────


def _xonly_from_compressed(point33: bytes) -> bytes:
    """Strip the y-parity prefix from a 33-byte compressed pubkey.

    Raises ``ValueError`` on malformed input.
    """
    if len(point33) != 33 or point33[0] not in (0x02, 0x03):
        raise ValueError("expected 33-byte compressed pubkey (0x02/0x03 prefix)")
    return point33[1:]


def verify_bip340(*, pubkey33: bytes, message32: bytes, signature64: bytes) -> bool:
    """Verify a BIP-340 Schnorr signature over a 32-byte message.

    ``pubkey33`` is a 33-byte compressed point per BOLT 12 conventions
    — the y-parity byte is dropped before verification. Returns
    ``False`` on any kind of malformed input rather than raising,
    so callers can use the result as a boolean validity check.
    """
    if len(message32) != 32 or len(signature64) != 64:
        return False
    try:
        xonly = _xonly_from_compressed(pubkey33)
    except ValueError:
        return False
    try:
        # PublicKeyXOnly accepts the raw 32-byte x-coordinate.
        pk = PublicKeyXOnly(xonly)
    except Exception:  # noqa: BLE001 — coincurve raises a variety of native errors
        return False
    try:
        return bool(pk.verify(signature64, message32))
    except Exception:  # noqa: BLE001
        return False


# ── signer protocol + production impl ────────────────────────────


@runtime_checkable
class Bip340Signer(Protocol):
    """Callable that produces a 64-byte BIP-340 signature over a 32-byte digest.

    Implementations may be sync (HSM, in-memory) or async-wrapped by
    callers; this layer stays sync because every production signer
    we know of (libsecp, hardware) operates synchronously.
    """

    def sign(self, digest32: bytes) -> bytes: ...

    @property
    def public_key(self) -> bytes:
        """The signer's 33-byte compressed pubkey."""
        ...


class CoincurveSigner:
    """In-process BIP-340 signer backed by libsecp256k1 via ``coincurve``.

    Suitable for orchestrator-side payer keys (which BOLT 12 expects
    to be **transient** — generate a fresh one per invoice_request to
    keep payer identity unlinkable across receipts).
    """

    __slots__ = ("_priv",)

    def __init__(self, secret: bytes | None = None) -> None:
        if secret is None:
            self._priv = PrivateKey()
        else:
            if len(secret) != 32:
                raise ValueError("secret must be 32 bytes")
            self._priv = PrivateKey(secret)

    @classmethod
    def generate(cls) -> "CoincurveSigner":
        """Create a signer with a freshly-randomised private key."""
        return cls()

    @property
    def secret(self) -> bytes:
        """The raw 32-byte private scalar (handle with care)."""
        return self._priv.secret

    @property
    def public_key(self) -> bytes:
        """33-byte compressed public key (suitable for ``invreq_payer_id``)."""
        return self._priv.public_key.format(compressed=True)

    def sign(self, digest32: bytes) -> bytes:
        if len(digest32) != 32:
            raise ValueError("digest must be 32 bytes")
        return self._priv.sign_schnorr(digest32)


# ── high-level helpers operating on typed dataclasses ────────────


def sign_invoice_request(invreq: InvoiceRequest, signer: Bip340Signer) -> InvoiceRequest:
    """Return a copy of ``invreq`` with a freshly-computed BIP-340 signature.

    Asserts that ``invreq.payer_id`` (the BOLT 12 ``invreq_payer_id``)
    matches the signer's public key on the x-only coordinate — a
    mismatch would produce an invoice no recipient could verify, so
    we fail fast at sign time.
    """
    if invreq.payer_id is None:
        raise ValueError("invoice_request has no payer_id; cannot sign")
    if _xonly_from_compressed(invreq.payer_id) != _xonly_from_compressed(signer.public_key):
        raise ValueError("signer.public_key x-only does not match invreq.payer_id")

    digest = invreq.signature_digest()
    sig = signer.sign(digest)
    return replace(invreq, signature=sig)


def verify_invoice_request(invreq: InvoiceRequest) -> bool:
    """Return True iff ``invreq`` carries a valid BIP-340 signature.

    A missing ``payer_id`` or ``signature`` returns ``False`` rather
    than raising — this is the natural shape for "is this thing
    ready to use?" callers.
    """
    if invreq.payer_id is None or invreq.signature is None:
        return False
    return verify_bip340(
        pubkey33=invreq.payer_id,
        message32=invreq.signature_digest(),
        signature64=invreq.signature,
    )


def sign_invoice(invoice: Invoice, signer: Bip340Signer) -> Invoice:
    """Sign an :class:`Invoice` with the recipient's node key.

    The verifying key for an invoice is ``invoice_node_id`` per
    BOLT 12 §1.6 (or the offer's ``offer_issuer_id`` when no
    blinded paths are involved). The caller is responsible for
    setting ``node_id`` to a value whose x-only coord matches the
    signer.
    """
    if invoice.node_id is None:
        raise ValueError("invoice has no node_id; cannot sign")
    if _xonly_from_compressed(invoice.node_id) != _xonly_from_compressed(signer.public_key):
        raise ValueError("signer.public_key x-only does not match invoice.node_id")

    digest = invoice.signature_digest()
    sig = signer.sign(digest)
    return replace(invoice, signature=sig)


def verify_invoice(invoice: Invoice) -> bool:
    """Return True iff ``invoice`` carries a valid BIP-340 signature.

    Verification key is ``invoice.node_id``. Callers that need to
    verify against ``offer_issuer_id`` instead (e.g. for direct,
    non-blinded offers) should fall back to that point when
    ``node_id`` is absent — but that's an orchestration policy
    decision, not a codec concern.
    """
    if invoice.node_id is None or invoice.signature is None:
        return False
    return verify_bip340(
        pubkey33=invoice.node_id,
        message32=invoice.signature_digest(),
        signature64=invoice.signature,
    )


__all__ = [
    "Bip340Signer",
    "CoincurveSigner",
    "sign_invoice",
    "sign_invoice_request",
    "verify_bip340",
    "verify_invoice",
    "verify_invoice_request",
]
