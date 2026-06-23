# SPDX-License-Identifier: MIT
"""BOLT 12 codec — pure-Python.

This package implements the low-level encoding primitives of BOLT 12
(BigSize integers, TLV records, bech32-without-checksum framing, Merkle
tree construction, signature-digest derivation).

The codec layer deliberately knows nothing about onion messages,
gateways, or LND. Higher-level orchestration lives in
`app.services.bolt12.orchestrator`.

Codec layer:
    * `bigsize` — BOLT 1 BigSize integers.
    * `bech32_nochk` — bech32 alphabet with `+` continuation and no
      checksum (BOLT 12 §Encoding).
    * `tlv` — TLV records, signature-record range (240..1000).
    * `merkle` — `LnLeaf` / `LnNonce` / `LnBranch` tagged hashing.
    * `codec` — top-level decode/encode of `lno`/`lnr`/`lni` strings.

Driven by upstream test vectors vendored at
`tests/vectors/bolt12/`.
"""

from .codec import Bolt12Codec, Bolt12String, decode, encode
from .errors import (
    Bolt12DecodeError,
    Bolt12Error,
    Bolt12FormatError,
    Bolt12TLVError,
)
from .fields import (
    Invoice,
    InvoiceRequest,
    Offer,
    decode_tu32,
    decode_tu64,
    encode_tu32,
    encode_tu64,
)
from .lnd_paths import encode_invoice_paths
from .merkle import merkle_root, signature_message_hash
from .orchestrator import (
    Bolt12Service,
    Bolt12ServiceError,
    Bolt12ServiceMetrics,
    InboundInvreqContext,
    InvoiceRequestTimeoutError,
    InvoiceResponder,
    InvreqBuildContext,
    InvreqBuilder,
    ReplyPathSpec,
    SendDestination,
    SendPlan,
    ServiceNotRunningError,
)
from .selective_disclosure import (
    ProofStep,
    RevealedRecord,
    SelectiveDisclosureProof,
    build_proof,
    verify_proof,
)
from .signing import (
    Bip340Signer,
    CoincurveSigner,
    sign_invoice,
    sign_invoice_request,
    verify_bip340,
    verify_invoice,
    verify_invoice_request,
)
from .tlv import TLVRecord, is_signature_type

__all__ = [
    "Bolt12Codec",
    "Bolt12DecodeError",
    "Bolt12Error",
    "Bolt12FormatError",
    "Bolt12Service",
    "Bolt12ServiceError",
    "Bolt12ServiceMetrics",
    "Bolt12String",
    "Bolt12TLVError",
    "Bip340Signer",
    "CoincurveSigner",
    "InboundInvreqContext",
    "InvoiceRequestTimeoutError",
    "InvoiceResponder",
    "InvreqBuildContext",
    "InvreqBuilder",
    "Invoice",
    "InvoiceRequest",
    "Offer",
    "ProofStep",
    "ReplyPathSpec",
    "RevealedRecord",
    "SelectiveDisclosureProof",
    "SendDestination",
    "SendPlan",
    "ServiceNotRunningError",
    "TLVRecord",
    "build_proof",
    "decode",
    "decode_tu32",
    "decode_tu64",
    "encode",
    "encode_invoice_paths",
    "encode_tu32",
    "encode_tu64",
    "is_signature_type",
    "merkle_root",
    "sign_invoice",
    "sign_invoice_request",
    "signature_message_hash",
    "verify_bip340",
    "verify_invoice",
    "verify_invoice_request",
    "verify_proof",
]
