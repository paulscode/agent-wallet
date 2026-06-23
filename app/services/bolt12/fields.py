# SPDX-License-Identifier: MIT
"""Field-level codec for BOLT 12 messages.

Built on top of the byte-level :mod:`codec` /
:mod:`tlv` primitives, this module gives orchestration code typed
:class:`Offer`, :class:`InvoiceRequest`, and :class:`Invoice`
dataclasses so callers don't have to reason about TLV numbers.

Scope (deliberately narrow):

* **Round-trip parsing** between :class:`Bolt12String` and the typed
  dataclasses. Any TLV the parser doesn't recognise is preserved
  verbatim in ``unknown_records`` so re-encoding is byte-identical.
* **Mirror semantics**: when building an ``invoice_request`` the
  caller passes the source :class:`Offer` and we copy every offer
  TLV (including unknowns) into the outbound stream — that's the
  spec contract that makes the merchant stateless.
* **Truncated integer codec** (tu64/tu32) per BOLT 12.

Out of scope (separate follow-ups):

* BIP-340 / Schnorr signing or verification. Callers that need to
  produce a *signed* ``invoice_request`` are expected to call
  :meth:`InvoiceRequest.signature_digest` and supply the 64-byte
  signature themselves; a pluggable signer will be added once a
  vetted libsecp256k1 binding lands as a dep.
* Parsing the ``BlindedPath``/``BlindedPayInfo`` substructures.
  Their contents are kept as opaque ``bytes`` so the orchestrator
  can hand them straight to the gateway/LND. A future module will
  break them down for fee selection and CLTV math.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Self

from .codec import Bolt12String
from .errors import Bolt12FormatError
from .tlv import TLVRecord, is_signature_type

# ── TLV numbers (BOLT 12 §1.4-§1.6) ────────────────────────────────

# Offer fields (in 1-79; even types are spec-defined).
OFFER_CHAINS = 2
OFFER_METADATA = 4
OFFER_CURRENCY = 6
OFFER_AMOUNT = 8
OFFER_DESCRIPTION = 10
OFFER_FEATURES = 12
OFFER_ABSOLUTE_EXPIRY = 14
OFFER_PATHS = 16
OFFER_ISSUER = 18
OFFER_QUANTITY_MAX = 20
OFFER_ISSUER_ID = 22

# Invoice-request fields (mirrors offer + 0 + 80-159).
INVREQ_METADATA = 0
INVREQ_CHAIN = 80
INVREQ_AMOUNT = 82
INVREQ_FEATURES = 84
INVREQ_QUANTITY = 86
INVREQ_PAYER_ID = 88
INVREQ_PAYER_NOTE = 89
INVREQ_PAYS_PATHS = 90
INVREQ_BIP353_NAME = 91

# Invoice fields (mirrors invreq + 160-239).
INVOICE_PATHS = 160
INVOICE_BLINDEDPAY = 162
INVOICE_CREATED_AT = 164
INVOICE_RELATIVE_EXPIRY = 166
INVOICE_PAYMENT_HASH = 168
INVOICE_AMOUNT = 170
INVOICE_FALLBACKS = 172
INVOICE_FEATURES = 174
INVOICE_NODE_ID = 176

# Signature record type (BOLT 12 reserves 240..1000 for sigs).
SIGNATURE = 240

# Inclusive ranges for spec-level partitioning (used by mirror logic).
OFFER_RANGE = range(0, 80)
INVREQ_RANGE = range(0, 160)
INVOICE_RANGE = range(0, 240)


# ── primitive codecs ──────────────────────────────────────────────


def encode_tu64(n: int) -> bytes:
    """Encode ``n`` as BOLT 1 ``tu64`` (big-endian, no leading zeros).

    Zero encodes as the empty string.
    """
    if n < 0:
        raise ValueError("tu64 must be non-negative")
    if n == 0:
        return b""
    nbytes = (n.bit_length() + 7) // 8
    return n.to_bytes(nbytes, "big")


def decode_tu64(data: bytes) -> int:
    """Decode a ``tu64`` field. Empty bytes → 0.

    A ``tu64`` occupies at most 8 bytes; per BOLT 1 leading zero bytes are
    forbidden in the wire form.
    """
    if len(data) > 8:
        raise Bolt12FormatError("tu64: value exceeds 8 bytes")
    if data and data[0] == 0:
        raise Bolt12FormatError("tu64: leading zero byte not allowed")
    return int.from_bytes(data, "big") if data else 0


# tu32 / tu64 share an encoding; only the upper bound differs.
def encode_tu32(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError("tu32 out of range")
    return encode_tu64(n)


def decode_tu32(data: bytes) -> int:
    if len(data) > 4:
        raise Bolt12FormatError("tu32: value exceeds 4 bytes")
    return decode_tu64(data)


def _check_point(name: str, value: bytes) -> None:
    if len(value) != 33:
        raise Bolt12FormatError(f"{name}: must be a 33-byte compressed pubkey")
    if value[0] not in (0x02, 0x03):
        raise Bolt12FormatError(f"{name}: invalid compressed-pubkey prefix")


def _check_chain_hash(name: str, value: bytes) -> None:
    if len(value) != 32:
        raise Bolt12FormatError(f"{name}: must be a 32-byte chain hash")


# ── Offer (lno) ───────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Offer:
    """Typed view of a BOLT 12 offer.

    All fields are optional in the spec; most callers care about
    ``amount``, ``description``, ``paths``, and ``issuer_id``.
    Unknown TLVs from the wire are kept in ``unknown_records`` so a
    parse-then-encode round trip is byte-identical.
    """

    chains: tuple[bytes, ...] = ()
    metadata: bytes | None = None
    currency: str | None = None
    amount: int | None = None
    description: str | None = None
    features: bytes | None = None
    absolute_expiry: int | None = None
    paths: bytes | None = None  # raw ``offer_paths`` value (concat of BlindedPaths)
    issuer: str | None = None
    quantity_max: int | None = None
    issuer_id: bytes | None = None
    unknown_records: tuple[TLVRecord, ...] = ()

    # ── parsing ──

    @classmethod
    def parse(cls, b12: Bolt12String) -> Self:
        if b12.hrp != "lno":
            raise Bolt12FormatError(f"Offer.parse: expected hrp 'lno', got {b12.hrp!r}")
        return cls._from_records(b12.records, allowed_range=OFFER_RANGE)

    @classmethod
    def _from_records(cls, records: list[TLVRecord], *, allowed_range: range) -> Self:
        kwargs: dict[str, object] = {}
        unknown: list[TLVRecord] = []
        for rec in records:
            t = rec.type
            v = rec.value
            if t == OFFER_CHAINS:
                if len(v) % 32 != 0:
                    raise Bolt12FormatError("offer_chains: length not a multiple of 32")
                kwargs["chains"] = tuple(v[i : i + 32] for i in range(0, len(v), 32))
            elif t == OFFER_METADATA:
                kwargs["metadata"] = v
            elif t == OFFER_CURRENCY:
                kwargs["currency"] = v.decode("ascii")
            elif t == OFFER_AMOUNT:
                kwargs["amount"] = decode_tu64(v)
            elif t == OFFER_DESCRIPTION:
                kwargs["description"] = v.decode("utf-8")
            elif t == OFFER_FEATURES:
                kwargs["features"] = v
            elif t == OFFER_ABSOLUTE_EXPIRY:
                kwargs["absolute_expiry"] = decode_tu64(v)
            elif t == OFFER_PATHS:
                kwargs["paths"] = v
            elif t == OFFER_ISSUER:
                kwargs["issuer"] = v.decode("utf-8")
            elif t == OFFER_QUANTITY_MAX:
                kwargs["quantity_max"] = decode_tu64(v)
            elif t == OFFER_ISSUER_ID:
                _check_point("offer_issuer_id", v)
                kwargs["issuer_id"] = v
            elif t in allowed_range or is_signature_type(t):
                # Out-of-band-but-allowed (forward-compat) or signature.
                # Signatures aren't valid in offers, but invoice/invreq
                # may surface them via this path; the parent class
                # filters before getting here.
                unknown.append(rec)
            else:
                raise Bolt12FormatError(f"unexpected TLV type {t} for {cls.__name__}")
        kwargs["unknown_records"] = tuple(unknown)
        return cls(**kwargs)  # type: ignore[arg-type]

    # ── building ──

    def to_records(self) -> list[TLVRecord]:
        """Serialize to a sorted, canonical TLV stream.

        Unknown records are interleaved by type so the resulting
        stream stays in ascending order without duplicates.
        """
        recs: list[TLVRecord] = []
        if self.chains:
            recs.append(TLVRecord(OFFER_CHAINS, b"".join(self.chains)))
        if self.metadata is not None:
            recs.append(TLVRecord(OFFER_METADATA, self.metadata))
        if self.currency is not None:
            recs.append(TLVRecord(OFFER_CURRENCY, self.currency.encode("ascii")))
        if self.amount is not None:
            recs.append(TLVRecord(OFFER_AMOUNT, encode_tu64(self.amount)))
        if self.description is not None:
            recs.append(TLVRecord(OFFER_DESCRIPTION, self.description.encode("utf-8")))
        if self.features is not None:
            recs.append(TLVRecord(OFFER_FEATURES, self.features))
        if self.absolute_expiry is not None:
            recs.append(TLVRecord(OFFER_ABSOLUTE_EXPIRY, encode_tu64(self.absolute_expiry)))
        if self.paths is not None:
            recs.append(TLVRecord(OFFER_PATHS, self.paths))
        if self.issuer is not None:
            recs.append(TLVRecord(OFFER_ISSUER, self.issuer.encode("utf-8")))
        if self.quantity_max is not None:
            recs.append(TLVRecord(OFFER_QUANTITY_MAX, encode_tu64(self.quantity_max)))
        if self.issuer_id is not None:
            _check_point("offer_issuer_id", self.issuer_id)
            recs.append(TLVRecord(OFFER_ISSUER_ID, self.issuer_id))
        recs.extend(self.unknown_records)
        return _sort_and_check(recs)

    def to_bolt12_string(self) -> Bolt12String:
        return Bolt12String(hrp="lno", records=self.to_records())


# ── InvoiceRequest (lnr) ──────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class InvoiceRequest:
    """Typed view of a BOLT 12 ``invoice_request``.

    The offer-mirror fields live in :attr:`offer`; invreq-only
    fields are top-level. The optional 64-byte BIP-340 signature is
    held separately so unsigned and signed instances are both
    representable. Use :meth:`with_signature` to attach one.
    """

    offer: Offer
    metadata: bytes | None = None
    chain: bytes | None = None
    amount: int | None = None
    features: bytes | None = None
    quantity: int | None = None
    payer_id: bytes | None = None
    payer_note: str | None = None
    paths: bytes | None = None
    bip353_name: bytes | None = None
    signature: bytes | None = None  # 64 raw bytes (BIP-340)
    unknown_records: tuple[TLVRecord, ...] = ()

    # ── parsing ──

    @classmethod
    def parse(cls, b12: Bolt12String) -> Self:
        if b12.hrp != "lnr":
            raise Bolt12FormatError(f"InvoiceRequest.parse: expected hrp 'lnr', got {b12.hrp!r}")

        offer_records: list[TLVRecord] = []
        invreq_only: list[TLVRecord] = []
        signature: bytes | None = None

        for rec in b12.records:
            if is_signature_type(rec.type):
                if rec.type == SIGNATURE:
                    if len(rec.value) != 64:
                        raise Bolt12FormatError("signature: must be 64 bytes")
                    signature = rec.value
                else:
                    # Other signature-range TLVs are reserved; preserve verbatim.
                    invreq_only.append(rec)
            elif rec.type in OFFER_RANGE and rec.type != INVREQ_METADATA:
                offer_records.append(rec)
            elif rec.type in INVREQ_RANGE:
                invreq_only.append(rec)
            else:
                raise Bolt12FormatError(f"unexpected TLV type {rec.type} for InvoiceRequest")

        offer = Offer._from_records(offer_records, allowed_range=OFFER_RANGE)

        kwargs: dict[str, object] = {"offer": offer, "signature": signature}
        unknown: list[TLVRecord] = []
        for rec in invreq_only:
            t = rec.type
            v = rec.value
            if t == INVREQ_METADATA:
                kwargs["metadata"] = v
            elif t == INVREQ_CHAIN:
                _check_chain_hash("invreq_chain", v)
                kwargs["chain"] = v
            elif t == INVREQ_AMOUNT:
                kwargs["amount"] = decode_tu64(v)
            elif t == INVREQ_FEATURES:
                kwargs["features"] = v
            elif t == INVREQ_QUANTITY:
                kwargs["quantity"] = decode_tu64(v)
            elif t == INVREQ_PAYER_ID:
                _check_point("invreq_payer_id", v)
                kwargs["payer_id"] = v
            elif t == INVREQ_PAYER_NOTE:
                kwargs["payer_note"] = v.decode("utf-8")
            elif t == INVREQ_PAYS_PATHS:
                kwargs["paths"] = v
            elif t == INVREQ_BIP353_NAME:
                kwargs["bip353_name"] = v
            else:
                unknown.append(rec)
        kwargs["unknown_records"] = tuple(unknown)
        return cls(**kwargs)  # type: ignore[arg-type]

    # ── mirror-from-offer constructor ──

    @classmethod
    def from_offer(
        cls,
        offer: Offer,
        *,
        metadata: bytes,
        payer_id: bytes,
        amount: int | None = None,
        quantity: int | None = None,
        payer_note: str | None = None,
        chain: bytes | None = None,
        features: bytes | None = None,
        paths: bytes | None = None,
    ) -> Self:
        """Construct an *unsigned* invreq mirroring ``offer``.

        BOLT 12 mandates that an invoice_request copy every offer
        TLV verbatim — that's how the merchant stays stateless. The
        caller supplies invreq-only fields plus a fresh
        ``invreq_metadata`` and the transient ``invreq_payer_id``.

        Sign by computing :meth:`signature_digest` and calling
        :meth:`with_signature`.
        """
        _check_point("invreq_payer_id", payer_id)
        if chain is not None:
            _check_chain_hash("invreq_chain", chain)
        return cls(
            offer=offer,
            metadata=metadata,
            chain=chain,
            amount=amount,
            features=features,
            quantity=quantity,
            payer_id=payer_id,
            payer_note=payer_note,
            paths=paths,
        )

    # ── building ──

    def to_records(self, *, include_signature: bool = True) -> list[TLVRecord]:
        recs: list[TLVRecord] = list(self.offer.to_records())
        if self.metadata is not None:
            recs.append(TLVRecord(INVREQ_METADATA, self.metadata))
        if self.chain is not None:
            recs.append(TLVRecord(INVREQ_CHAIN, self.chain))
        if self.amount is not None:
            recs.append(TLVRecord(INVREQ_AMOUNT, encode_tu64(self.amount)))
        if self.features is not None:
            recs.append(TLVRecord(INVREQ_FEATURES, self.features))
        if self.quantity is not None:
            recs.append(TLVRecord(INVREQ_QUANTITY, encode_tu64(self.quantity)))
        if self.payer_id is not None:
            recs.append(TLVRecord(INVREQ_PAYER_ID, self.payer_id))
        if self.payer_note is not None:
            recs.append(TLVRecord(INVREQ_PAYER_NOTE, self.payer_note.encode("utf-8")))
        if self.paths is not None:
            recs.append(TLVRecord(INVREQ_PAYS_PATHS, self.paths))
        if self.bip353_name is not None:
            recs.append(TLVRecord(INVREQ_BIP353_NAME, self.bip353_name))
        recs.extend(self.unknown_records)
        if include_signature and self.signature is not None:
            recs.append(TLVRecord(SIGNATURE, self.signature))
        return _sort_and_check(recs)

    def to_bolt12_string(self) -> Bolt12String:
        return Bolt12String(hrp="lnr", records=self.to_records())

    def signature_digest(self) -> bytes:
        """Return the 32-byte digest a payer must BIP-340 sign.

        The digest covers the Merkle root over every TLV in the
        invreq except those in the signature range (240–1000),
        tagged with ``"lightning" || "invoice_request" ||
        "signature"``.
        """
        unsigned = self.to_records(include_signature=False)
        return Bolt12String(hrp="lnr", records=unsigned).signature_digest()

    def with_signature(self, sig: bytes) -> Self:
        if len(sig) != 64:
            raise ValueError("signature must be 64 bytes (BIP-340)")
        return replace(self, signature=sig)


# ── Invoice (lni) ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Invoice:
    """Typed view of a BOLT 12 invoice (the receipt of an invreq).

    Mirrors the originating :class:`InvoiceRequest` and adds the
    invoice-only fields. Same signature handling as
    :class:`InvoiceRequest`.
    """

    invreq: InvoiceRequest
    paths: bytes | None = None
    blindedpay: bytes | None = None
    created_at: int | None = None
    relative_expiry: int | None = None
    payment_hash: bytes | None = None
    amount: int | None = None
    fallbacks: bytes | None = None
    features: bytes | None = None
    node_id: bytes | None = None
    signature: bytes | None = None
    unknown_records: tuple[TLVRecord, ...] = ()

    # ── parsing ──

    @classmethod
    def parse(cls, b12: Bolt12String) -> Self:
        if b12.hrp != "lni":
            raise Bolt12FormatError(f"Invoice.parse: expected hrp 'lni', got {b12.hrp!r}")

        # Split into the three layers, parse the lower two by
        # delegation.
        offer_records: list[TLVRecord] = []
        invreq_records: list[TLVRecord] = []
        invoice_only: list[TLVRecord] = []
        invoice_sig: bytes | None = None

        # Per spec the sole signature TLV (240) is the *invoice*
        # signature; the invreq's own signature is not carried
        # inside the invoice — only the (now-mirrored) request
        # fields are.
        for rec in b12.records:
            t = rec.type
            if is_signature_type(t):
                if t == SIGNATURE:
                    if len(rec.value) != 64:
                        raise Bolt12FormatError("signature: must be 64 bytes")
                    invoice_sig = rec.value
                else:
                    invoice_only.append(rec)
            elif t in OFFER_RANGE and t != INVREQ_METADATA:
                offer_records.append(rec)
            elif t in INVREQ_RANGE:
                invreq_records.append(rec)
            elif t in INVOICE_RANGE:
                invoice_only.append(rec)
            else:
                raise Bolt12FormatError(f"unexpected TLV type {t} for Invoice")

        offer = Offer._from_records(offer_records, allowed_range=OFFER_RANGE)
        # Re-use InvoiceRequest.parse for the invreq layer by
        # synthesizing an unsigned ``lnr`` wrapper.
        invreq_b12 = Bolt12String(hrp="lnr", records=offer.to_records() + invreq_records)
        invreq = InvoiceRequest.parse(invreq_b12)

        kwargs: dict[str, object] = {"invreq": invreq, "signature": invoice_sig}
        unknown: list[TLVRecord] = []
        for rec in invoice_only:
            t = rec.type
            v = rec.value
            if t == INVOICE_PATHS:
                kwargs["paths"] = v
            elif t == INVOICE_BLINDEDPAY:
                kwargs["blindedpay"] = v
            elif t == INVOICE_CREATED_AT:
                kwargs["created_at"] = decode_tu64(v)
            elif t == INVOICE_RELATIVE_EXPIRY:
                kwargs["relative_expiry"] = decode_tu32(v)
            elif t == INVOICE_PAYMENT_HASH:
                if len(v) != 32:
                    raise Bolt12FormatError("invoice_payment_hash: must be 32 bytes")
                kwargs["payment_hash"] = v
            elif t == INVOICE_AMOUNT:
                kwargs["amount"] = decode_tu64(v)
            elif t == INVOICE_FALLBACKS:
                kwargs["fallbacks"] = v
            elif t == INVOICE_FEATURES:
                kwargs["features"] = v
            elif t == INVOICE_NODE_ID:
                _check_point("invoice_node_id", v)
                kwargs["node_id"] = v
            else:
                unknown.append(rec)
        kwargs["unknown_records"] = tuple(unknown)
        return cls(**kwargs)  # type: ignore[arg-type]

    # ── building ──

    def to_records(self, *, include_signature: bool = True) -> list[TLVRecord]:
        # Lower layers minus their own signature (mirror semantics).
        recs: list[TLVRecord] = list(self.invreq.to_records(include_signature=False))
        if self.paths is not None:
            recs.append(TLVRecord(INVOICE_PATHS, self.paths))
        if self.blindedpay is not None:
            recs.append(TLVRecord(INVOICE_BLINDEDPAY, self.blindedpay))
        if self.created_at is not None:
            recs.append(TLVRecord(INVOICE_CREATED_AT, encode_tu64(self.created_at)))
        if self.relative_expiry is not None:
            recs.append(TLVRecord(INVOICE_RELATIVE_EXPIRY, encode_tu32(self.relative_expiry)))
        if self.payment_hash is not None:
            recs.append(TLVRecord(INVOICE_PAYMENT_HASH, self.payment_hash))
        if self.amount is not None:
            recs.append(TLVRecord(INVOICE_AMOUNT, encode_tu64(self.amount)))
        if self.fallbacks is not None:
            recs.append(TLVRecord(INVOICE_FALLBACKS, self.fallbacks))
        if self.features is not None:
            recs.append(TLVRecord(INVOICE_FEATURES, self.features))
        if self.node_id is not None:
            recs.append(TLVRecord(INVOICE_NODE_ID, self.node_id))
        recs.extend(self.unknown_records)
        if include_signature and self.signature is not None:
            recs.append(TLVRecord(SIGNATURE, self.signature))
        return _sort_and_check(recs)

    def to_bolt12_string(self) -> Bolt12String:
        return Bolt12String(hrp="lni", records=self.to_records())

    def signature_digest(self) -> bytes:
        unsigned = self.to_records(include_signature=False)
        return Bolt12String(hrp="lni", records=unsigned).signature_digest()

    def with_signature(self, sig: bytes) -> Self:
        if len(sig) != 64:
            raise ValueError("signature must be 64 bytes (BIP-340)")
        return replace(self, signature=sig)


# ── helpers ───────────────────────────────────────────────────────


def _sort_and_check(recs: list[TLVRecord]) -> list[TLVRecord]:
    """Sort records by type ascending; reject duplicate types.

    Used by every ``to_records`` to build a canonical, spec-valid
    TLV stream regardless of source ordering.
    """
    out = sorted(recs, key=lambda r: r.type)
    for i in range(1, len(out)):
        if out[i].type == out[i - 1].type:
            raise Bolt12FormatError(f"duplicate TLV type {out[i].type}")
    return out


__all__ = [
    "INVOICE_AMOUNT",
    "INVOICE_BLINDEDPAY",
    "INVOICE_CREATED_AT",
    "INVOICE_FALLBACKS",
    "INVOICE_FEATURES",
    "INVOICE_NODE_ID",
    "INVOICE_PATHS",
    "INVOICE_PAYMENT_HASH",
    "INVOICE_RELATIVE_EXPIRY",
    "INVREQ_AMOUNT",
    "INVREQ_BIP353_NAME",
    "INVREQ_CHAIN",
    "INVREQ_FEATURES",
    "INVREQ_METADATA",
    "INVREQ_PAYER_ID",
    "INVREQ_PAYER_NOTE",
    "INVREQ_PAYS_PATHS",
    "INVREQ_QUANTITY",
    "Invoice",
    "InvoiceRequest",
    "OFFER_ABSOLUTE_EXPIRY",
    "OFFER_AMOUNT",
    "OFFER_CHAINS",
    "OFFER_CURRENCY",
    "OFFER_DESCRIPTION",
    "OFFER_FEATURES",
    "OFFER_ISSUER",
    "OFFER_ISSUER_ID",
    "OFFER_METADATA",
    "OFFER_PATHS",
    "OFFER_QUANTITY_MAX",
    "Offer",
    "SIGNATURE",
    "decode_tu32",
    "decode_tu64",
    "encode_tu32",
    "encode_tu64",
]
