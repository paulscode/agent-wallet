# SPDX-License-Identifier: MIT
"""Top-level decode / encode for BOLT 12 strings.

This layer is deliberately thin — it only round-trips between the
bech32-no-checksum string form and a list of `TLVRecord`s. Higher-level
field interpretation (e.g. "what's the offer amount?") lives in
`app.services.bolt12.fields`.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import bech32_nochk, tlv
from .errors import Bolt12FormatError
from .merkle import merkle_root, signature_message_hash
from .tlv import TLVRecord

# Mapping of HRP → BOLT 12 message name. Used for signature-tag
# derivation; "lni" (invoice) shares its message name with the
# inner stream.
_HRP_TO_MESSAGE = {
    "lno": "offer",
    "lnr": "invoice_request",
    "lni": "invoice",
}


@dataclass(frozen=True, slots=True)
class Bolt12String:
    """Decoded BOLT 12 wire form.

    `hrp` is one of `lno`, `lnr`, `lni`. `records` is the full TLV
    stream including any signature records; consumers that want only
    the payload-records can filter via `record.is_signature`.
    """

    hrp: str
    records: list[TLVRecord]

    @property
    def message_name(self) -> str:
        return _HRP_TO_MESSAGE[self.hrp]

    def merkle_root(self) -> bytes:
        return merkle_root(self.records)

    def signature_digest(self, field_name: str = "signature") -> bytes:
        return signature_message_hash(
            message_name=self.message_name,
            field_name=field_name,
            merkle_root_bytes=self.merkle_root(),
        )


class Bolt12Codec:
    """Stateless decoder / encoder for BOLT 12 strings.

    Exposed as a class for symmetry with other services in the
    project, but holds no state — every method is a pure function.
    """

    @staticmethod
    def decode(
        s: str,
        *,
        max_records: int | None = None,
        max_value_bytes: int | None = None,
    ) -> Bolt12String:
        """Decode a BOLT 12 string into its HRP + TLV records.

        ``max_records`` / ``max_value_bytes`` are the same defence-in-depth
        caps ``tlv.decode_stream`` accepts. Callers decoding **untrusted**
        bytes (anything sourced from the network) should pass both from
        ``settings.bolt12_max_tlv_records`` / ``bolt12_max_tlv_value_bytes``;
        the responder and the inbound-invoice path already do. The defaults
        stay uncapped only for trusted, locally-produced strings.
        """
        hrp, payload = bech32_nochk.decode(s)
        records = tlv.decode_stream(
            payload,
            max_records=max_records,
            max_value_bytes=max_value_bytes,
        )
        return Bolt12String(hrp=hrp, records=records)

    @staticmethod
    def encode(b12: Bolt12String) -> str:
        if b12.hrp not in _HRP_TO_MESSAGE:
            raise Bolt12FormatError(f"unknown HRP {b12.hrp!r}")
        return bech32_nochk.encode(b12.hrp, tlv.encode_stream(b12.records))


# Convenience module-level functions.
def decode(
    s: str,
    *,
    max_records: int | None = None,
    max_value_bytes: int | None = None,
) -> Bolt12String:
    return Bolt12Codec.decode(s, max_records=max_records, max_value_bytes=max_value_bytes)


def encode(b12: Bolt12String) -> str:
    return Bolt12Codec.encode(b12)
