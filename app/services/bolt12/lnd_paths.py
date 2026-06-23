# SPDX-License-Identifier: MIT
"""Encode LND ``blinded_paths`` REST output into BOLT 12 invoice TLVs.

When ``lnd_service.add_blinded_invoice`` returns, the ``blinded_paths``
list contains LND's :class:`BlindedPaymentPath` rendered as JSON.

This module is the single place that maps the LND REST shape onto
the BOLT 12 wire format for ``invoice_paths`` (TLV 160) and
``invoice_blindedpay`` (TLV 162). Both TLVs carry a *concatenation*
of subtype records — there is no inner length prefix between them
because each subtype is self-delimiting.

Subtype layout (BOLT 4 / BOLT 12 §"Format"):

* ``blinded_path`` (used inside ``invoice_paths``)::

      [point: first_node_id]            (33B)
      [point: first_path_key]           (33B)
      [byte:  num_hops]
      [num_hops * blinded_path_hop: hops]

* ``blinded_path_hop``::

      [point: blinded_node_id]          (33B)
      [u16:   enclen]
      [enclen * byte: encrypted_recipient_data]

* ``blinded_payinfo`` (used inside ``invoice_blindedpay``)::

      [u32: fee_base_msat]
      [u32: fee_proportional_millionths]
      [u16: cltv_expiry_delta]
      [u64: htlc_minimum_msat]
      [u64: htlc_maximum_msat]
      [u16: flen]
      [flen * byte: features]

Binary fields in LND REST come back base64-encoded; integer fields
come back as JSON numbers or strings (LND uses strings for ``u64``
to dodge JS-precision issues). We normalise both shapes here.

This module is **pure** — no I/O, no DB. It takes the LND dict and
returns ``(invoice_paths_bytes, invoice_blindedpay_bytes)`` ready to
drop into :class:`app.services.bolt12.fields.Invoice`.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

# ── helpers ──────────────────────────────────────────────────────


def _decode_b64_or_hex(value: object, *, field: str, expected_len: int | None = None) -> bytes:
    """Accept either base64 (LND REST default) or hex string for binary fields.

    LND's REST gateway returns binary as base64 strings. Some test
    fixtures (and hand-crafted callers) prefer hex — accept both so
    we don't lock callers into one encoding.

    When ``expected_len`` is given, try whichever decoding produces
    a buffer of the right length. (Hex strings of length ``2N``
    are also valid base64 producing ``N*1.5`` bytes — we have to
    pick the one that matches.)
    """
    if value is None:
        raise ValueError(f"{field}: missing required binary field")
    if isinstance(value, (bytes, bytearray)):
        out = bytes(value)
        if expected_len is not None and len(out) != expected_len:
            raise ValueError(f"{field}: expected {expected_len} bytes, got {len(out)}")
        return out
    if not isinstance(value, str):
        raise TypeError(f"{field}: expected str/bytes, got {type(value).__name__}")

    candidates: list[bytes] = []
    try:
        candidates.append(base64.b64decode(value, validate=True))
    except (binascii.Error, ValueError):
        pass
    try:
        candidates.append(bytes.fromhex(value))
    except ValueError:
        pass
    if not candidates:
        raise ValueError(f"{field}: not valid base64 or hex")
    if expected_len is None:
        # No length hint — prefer base64 (LND default) when both worked.
        return candidates[0]
    for cand in candidates:
        if len(cand) == expected_len:
            return cand
    # None matched expected length — report against the first candidate
    # so the error mentions a real decoded size.
    raise ValueError(f"{field}: expected {expected_len} bytes, got {len(candidates[0])}")


def _to_int(value: object, *, field: str, default: int | None = None) -> int:
    """LND returns u64 fields as JSON strings; coerce safely."""
    if value is None:
        if default is not None:
            return default
        raise ValueError(f"{field}: missing required integer")
    if isinstance(value, bool):  # bool is an int subclass; reject.
        raise TypeError(f"{field}: bool is not a valid integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError as exc:
            raise ValueError(f"{field}: not a valid integer: {value!r}") from exc
    raise TypeError(f"{field}: expected int or str, got {type(value).__name__}")


def _u16(n: int, *, field: str) -> bytes:
    if not 0 <= n <= 0xFFFF:
        raise ValueError(f"{field}: u16 out of range: {n}")
    return n.to_bytes(2, "big")


def _u32(n: int, *, field: str) -> bytes:
    if not 0 <= n <= 0xFFFFFFFF:
        raise ValueError(f"{field}: u32 out of range: {n}")
    return n.to_bytes(4, "big")


def _u64(n: int, *, field: str) -> bytes:
    if not 0 <= n <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"{field}: u64 out of range: {n}")
    return n.to_bytes(8, "big")


def _u8(n: int, *, field: str) -> bytes:
    if not 0 <= n <= 0xFF:
        raise ValueError(f"{field}: byte out of range: {n}")
    return n.to_bytes(1, "big")


# LND's gRPC ``FeatureBit`` enum, REST-serialized as name strings.
# Only the names we plausibly receive in a ``BlindedPaymentPath``
# need entries; unknown strings raise so we notice unfamiliar bits
# rather than silently dropping them.
_LND_FEATURE_BIT_NAMES: dict[str, int] = {
    "DATALOSS_PROTECT_REQ": 0,
    "DATALOSS_PROTECT_OPT": 1,
    "INITIAL_ROUING_SYNC": 3,  # LND uses this misspelling
    "UPFRONT_SHUTDOWN_SCRIPT_REQ": 4,
    "UPFRONT_SHUTDOWN_SCRIPT_OPT": 5,
    "GOSSIP_QUERIES_REQ": 6,
    "GOSSIP_QUERIES_OPT": 7,
    "TLV_ONION_REQ": 8,
    "TLV_ONION_OPT": 9,
    "EXT_GOSSIP_QUERIES_REQ": 10,
    "EXT_GOSSIP_QUERIES_OPT": 11,
    "STATIC_REMOTE_KEY_REQ": 12,
    "STATIC_REMOTE_KEY_OPT": 13,
    "PAYMENT_ADDR_REQ": 14,
    "PAYMENT_ADDR_OPT": 15,
    "MPP_REQ": 16,
    "MPP_OPT": 17,
    "WUMBO_CHANNELS_REQ": 18,
    "WUMBO_CHANNELS_OPT": 19,
    "ANCHORS_REQ": 20,
    "ANCHORS_OPT": 21,
    "ANCHORS_ZERO_FEE_HTLC_REQ": 22,
    "ANCHORS_ZERO_FEE_HTLC": 23,
    "ROUTE_BLINDING_REQUIRED": 24,
    "ROUTE_BLINDING_OPTIONAL": 25,
    "AMP_REQ": 30,
    "AMP_OPT": 31,
}


def _pack_feature_bits(bits: list[Any], *, field: str) -> bytes:
    """Convert LND's ``repeated FeatureBit`` list to a packed BOLT bitmap.

    LND emits this as a JSON array of either:
      * integer bit indices, or
      * enum-name strings (``MPP_OPT`` etc.).

    BOLT 12 ``blinded_payinfo.features`` is a big-endian packed
    bitmap where bit ``n`` (LSB of the rightmost byte being bit 0)
    is set iff feature ``n`` is present. Empty list → empty bytes.
    """
    if not bits:
        return b""
    indices: list[int] = []
    for i, item in enumerate(bits):
        if isinstance(item, bool):  # bool subclass of int — reject.
            raise TypeError(f"{field}[{i}]: bool is not a feature-bit")
        if isinstance(item, int):
            idx = item
        elif isinstance(item, str):
            try:
                idx = _LND_FEATURE_BIT_NAMES[item]
            except KeyError as exc:
                # Fall back to parsing a numeric string before giving up,
                # so a future LND that emits ints-as-strings still works.
                try:
                    idx = int(item)
                except ValueError:
                    raise ValueError(f"{field}[{i}]: unknown feature bit name {item!r}") from exc
        else:
            raise TypeError(f"{field}[{i}]: expected int or str, got {type(item).__name__}")
        if idx < 0 or idx > 0xFFFF:
            raise ValueError(f"{field}[{i}]: feature bit {idx} out of range")
        indices.append(idx)

    max_bit = max(indices)
    nbytes = (max_bit // 8) + 1
    buf = bytearray(nbytes)
    for idx in indices:
        # BOLT spec: features are big-endian — bit 0 is the LSB of
        # the *last* (rightmost) byte. So byte position from the end
        # is idx // 8, bit within byte is idx % 8.
        byte_from_end = idx // 8
        bit_in_byte = idx % 8
        buf[nbytes - 1 - byte_from_end] |= 1 << bit_in_byte
    return bytes(buf)


# ── single-path encoders ─────────────────────────────────────────


def _encode_blinded_path(bp: dict[str, Any]) -> bytes:
    """Encode a single BOLT 4 ``blinded_path`` subtype.

    Accepts LND field names (``introduction_node`` / ``blinding_point``
    / ``blinded_hops[].{blinded_node, encrypted_data}``).
    """
    first_node_id = _decode_b64_or_hex(bp.get("introduction_node"), field="introduction_node", expected_len=33)
    first_path_key = _decode_b64_or_hex(bp.get("blinding_point"), field="blinding_point", expected_len=33)
    hops = bp.get("blinded_hops") or []
    if not isinstance(hops, list):
        raise TypeError("blinded_hops: expected list")
    if not hops:
        # BOLT 12 §"requirements": MUST reject `num_hops` == 0.
        raise ValueError("blinded_hops: must contain at least one hop")
    if len(hops) > 0xFF:
        raise ValueError(f"blinded_hops: max 255 hops, got {len(hops)}")

    out = bytearray()
    out += first_node_id
    out += first_path_key
    out += _u8(len(hops), field="num_hops")
    for i, hop in enumerate(hops):
        if not isinstance(hop, dict):
            raise TypeError(f"blinded_hops[{i}]: expected object")
        blinded_node = _decode_b64_or_hex(
            hop.get("blinded_node"),
            field=f"blinded_hops[{i}].blinded_node",
            expected_len=33,
        )
        encrypted = _decode_b64_or_hex(
            hop.get("encrypted_data"),
            field=f"blinded_hops[{i}].encrypted_data",
        )
        if len(encrypted) > 0xFFFF:
            raise ValueError(f"blinded_hops[{i}].encrypted_data: too long ({len(encrypted)} > 65535)")
        out += blinded_node
        out += _u16(len(encrypted), field=f"blinded_hops[{i}].enclen")
        out += encrypted
    return bytes(out)


def _encode_blinded_payinfo(payinfo: dict[str, Any]) -> bytes:
    """Encode a single BOLT 12 ``blinded_payinfo`` subtype."""
    base_fee = _to_int(payinfo.get("base_fee_msat"), field="base_fee_msat", default=0)
    prop_fee = _to_int(
        payinfo.get("proportional_fee_rate"),
        field="proportional_fee_rate",
        default=0,
    )
    cltv = _to_int(payinfo.get("total_cltv_delta"), field="total_cltv_delta", default=0)
    htlc_min = _to_int(payinfo.get("htlc_min_msat"), field="htlc_min_msat", default=0)
    htlc_max = _to_int(payinfo.get("htlc_max_msat"), field="htlc_max_msat", default=0)
    feats_raw = payinfo.get("features")
    # LND's BlindedPaymentPath.features is `repeated FeatureBit` —
    # a JSON list of feature-bit indices (ints, or enum-name strings
    # depending on LND build). BOLT 12 `blinded_payinfo.features` is
    # a packed bitmap, so we convert by setting each named bit. An
    # empty list (the common case for plain payments) becomes the
    # empty bitmap. We continue to accept str/bytes for back-compat
    # with hand-crafted callers / tests that supply the raw bitmap.
    if feats_raw in (None, "", []):
        features = b""
    elif isinstance(feats_raw, list):
        features = _pack_feature_bits(feats_raw, field="features")
    else:
        features = _decode_b64_or_hex(feats_raw, field="features")
    if len(features) > 0xFFFF:
        raise ValueError(f"features: too long ({len(features)} > 65535)")

    out = bytearray()
    out += _u32(base_fee, field="base_fee_msat")
    out += _u32(prop_fee, field="proportional_fee_rate")
    out += _u16(cltv, field="total_cltv_delta")
    out += _u64(htlc_min, field="htlc_min_msat")
    out += _u64(htlc_max, field="htlc_max_msat")
    out += _u16(len(features), field="flen")
    out += features
    return bytes(out)


# ── public API ───────────────────────────────────────────────────


def encode_invoice_paths(
    lnd_blinded_paths: list[dict[str, Any]],
) -> tuple[bytes, bytes]:
    """Encode LND's ``blinded_paths`` array into BOLT 12 TLV values.

    ``lnd_blinded_paths`` is the value of ``data["blinded_paths"]``
    returned by ``lnd_service.add_blinded_invoice`` — a list of
    LND :class:`BlindedPaymentPath` JSON objects with shape::

        {
            "blinded_path": {
                "introduction_node": <base64 33B>,
                "blinding_point": <base64 33B>,
                "blinded_hops": [
                    {"blinded_node": <base64 33B>,
                     "encrypted_data": <base64 N>},
                    ...
                ],
            },
            "base_fee_msat": <u32>,
            "proportional_fee_rate": <u32>,
            "total_cltv_delta": <u16>,
            "htlc_min_msat": <u64-as-string>,
            "htlc_max_msat": <u64-as-string>,
            "features": <base64> | "",
        }

    Returns ``(invoice_paths_bytes, invoice_blindedpay_bytes)`` —
    each is the concatenation of the relevant subtype records,
    suitable for use as :attr:`Invoice.paths` /
    :attr:`Invoice.blindedpay`.

    Raises :class:`ValueError` / :class:`TypeError` on malformed
    input (including the spec-mandated empty-paths and zero-hops
    rejections).
    """
    if not isinstance(lnd_blinded_paths, list):
        raise TypeError("blinded_paths: expected list")
    if not lnd_blinded_paths:
        raise ValueError("blinded_paths: must contain at least one path")

    paths_out = bytearray()
    pay_out = bytearray()
    for i, entry in enumerate(lnd_blinded_paths):
        if not isinstance(entry, dict):
            raise TypeError(f"blinded_paths[{i}]: expected object")
        bp = entry.get("blinded_path")
        if not isinstance(bp, dict):
            raise TypeError(f"blinded_paths[{i}].blinded_path: expected object")
        try:
            paths_out += _encode_blinded_path(bp)
            pay_out += _encode_blinded_payinfo(entry)
        except (ValueError, TypeError) as exc:
            raise type(exc)(f"blinded_paths[{i}]: {exc}") from exc
    return bytes(paths_out), bytes(pay_out)


# ── Decoders (inverse of ``encode_invoice_paths``) ───────────────


def _read_u8(buf: memoryview, off: int, *, field: str) -> tuple[int, int]:
    if off + 1 > len(buf):
        raise ValueError(f"{field}: truncated u8 at offset {off}")
    return int(buf[off]), off + 1


def _read_u16(buf: memoryview, off: int, *, field: str) -> tuple[int, int]:
    if off + 2 > len(buf):
        raise ValueError(f"{field}: truncated u16 at offset {off}")
    return int.from_bytes(buf[off : off + 2], "big"), off + 2


def _read_u32(buf: memoryview, off: int, *, field: str) -> tuple[int, int]:
    if off + 4 > len(buf):
        raise ValueError(f"{field}: truncated u32 at offset {off}")
    return int.from_bytes(buf[off : off + 4], "big"), off + 4


def _read_u64(buf: memoryview, off: int, *, field: str) -> tuple[int, int]:
    if off + 8 > len(buf):
        raise ValueError(f"{field}: truncated u64 at offset {off}")
    return int.from_bytes(buf[off : off + 8], "big"), off + 8


def _read_bytes(
    buf: memoryview,
    off: int,
    n: int,
    *,
    field: str,
) -> tuple[bytes, int]:
    if off + n > len(buf):
        raise ValueError(f"{field}: truncated read of {n} bytes at offset {off}")
    return bytes(buf[off : off + n]), off + n


def _decode_blinded_path(
    buf: memoryview,
    off: int,
) -> tuple[dict[str, Any], int]:
    """Parse a single ``blinded_path`` subtype starting at ``off``.

    Returns ``(blinded_path_dict, next_offset)``. Field names match
    LND's REST :class:`BlindedPath` shape so callers can drop the
    dict straight into a ``BlindedPaymentPath`` request body.
    """
    first_node_id, off = _read_bytes(buf, off, 33, field="first_node_id")
    first_path_key, off = _read_bytes(buf, off, 33, field="first_path_key")
    num_hops, off = _read_u8(buf, off, field="num_hops")
    if num_hops == 0:
        raise ValueError("blinded_path: num_hops MUST be > 0")
    hops: list[dict[str, str]] = []
    for i in range(num_hops):
        blinded_node, off = _read_bytes(
            buf,
            off,
            33,
            field=f"blinded_hops[{i}].blinded_node",
        )
        enclen, off = _read_u16(buf, off, field=f"blinded_hops[{i}].enclen")
        encrypted, off = _read_bytes(
            buf,
            off,
            enclen,
            field=f"blinded_hops[{i}].encrypted_data",
        )
        hops.append(
            {
                "blinded_node": base64.b64encode(blinded_node).decode("ascii"),
                "encrypted_data": base64.b64encode(encrypted).decode("ascii"),
            }
        )
    return {
        "introduction_node": base64.b64encode(first_node_id).decode("ascii"),
        "blinding_point": base64.b64encode(first_path_key).decode("ascii"),
        "blinded_hops": hops,
    }, off


def _decode_blinded_payinfo(
    buf: memoryview,
    off: int,
) -> tuple[dict[str, Any], int]:
    """Parse a single ``blinded_payinfo`` subtype starting at ``off``.

    Returns the payinfo fields keyed for LND REST's
    :class:`BlindedPaymentPath` (i.e. flattened — these sit
    alongside ``blinded_path`` in the same parent dict).
    """
    base_fee, off = _read_u32(buf, off, field="base_fee_msat")
    prop_fee, off = _read_u32(buf, off, field="proportional_fee_rate")
    cltv, off = _read_u16(buf, off, field="total_cltv_delta")
    htlc_min, off = _read_u64(buf, off, field="htlc_min_msat")
    htlc_max, off = _read_u64(buf, off, field="htlc_max_msat")
    flen, off = _read_u16(buf, off, field="flen")
    features, off = _read_bytes(buf, off, flen, field="features")
    # LND uses strings for uint64s; the REST gateway accepts either.
    # Emit strings to match the existing encoder shape exactly.
    return {
        "base_fee_msat": str(base_fee),
        "proportional_fee_rate": prop_fee,
        "total_cltv_delta": cltv,
        "htlc_min_msat": str(htlc_min),
        "htlc_max_msat": str(htlc_max),
        # Empty features → omit the field so LND's JSON parser doesn't
        # have to handle ``""``. Non-empty → base64-encoded bytes.
        **({"features_raw_b64": base64.b64encode(features).decode("ascii")} if features else {}),
    }, off


def decode_invoice_paths(
    invoice_paths_bytes: bytes,
    invoice_blindedpay_bytes: bytes,
) -> list[dict[str, Any]]:
    """Inverse of :func:`encode_invoice_paths`.

    Given the raw ``invoice_paths`` TLV value (concat of
    ``blinded_path`` subtypes) and the parallel ``invoice_blindedpay``
    value (concat of ``blinded_payinfo`` subtypes), return a list of
    dicts shaped for LND's REST ``BlindedPaymentPath`` — ready to
    splice into the ``blinded_payment_paths`` array of a
    ``QueryRoutesRequest``.

    Per BOLT 12 the two blobs MUST have the same number of subtype
    entries: the n-th ``blinded_path`` is described by the n-th
    ``blinded_payinfo``. We enforce that here.

    Raises :class:`ValueError` on any malformed input (truncated
    subtype, length mismatch, zero-hop blinded path, trailing bytes).

    Note on the ``features_raw_b64`` key: LND's REST surface uses
    ``features`` as a repeated ``FeatureBit`` enum (not raw bytes).
    The BOLT 12 wire field is a raw feature-bit bitmask. We expose
    the raw base64 under a distinct key so callers can decide whether
    to translate (most production paths leave features empty per the
    LND blinded-invoice flow); callers who need the enum form must
    map the bits explicitly.
    """
    paths_buf = memoryview(invoice_paths_bytes)
    pay_buf = memoryview(invoice_blindedpay_bytes)

    paths: list[dict[str, Any]] = []
    p_off = 0
    while p_off < len(paths_buf):
        blinded_path, p_off = _decode_blinded_path(paths_buf, p_off)
        paths.append({"blinded_path": blinded_path})
    if p_off != len(paths_buf):  # pragma: no cover — _decode_blinded_path advances exactly
        raise ValueError(f"invoice_paths: trailing bytes after final subtype (consumed {p_off}, len {len(paths_buf)})")

    payinfos: list[dict[str, Any]] = []
    y_off = 0
    while y_off < len(pay_buf):
        payinfo, y_off = _decode_blinded_payinfo(pay_buf, y_off)
        payinfos.append(payinfo)
    if y_off != len(pay_buf):  # pragma: no cover
        raise ValueError(f"invoice_blindedpay: trailing bytes (consumed {y_off}, len {len(pay_buf)})")

    if len(paths) != len(payinfos):
        raise ValueError(
            f"invoice_paths / invoice_blindedpay subtype-count mismatch: paths={len(paths)} payinfos={len(payinfos)}"
        )

    for path, payinfo in zip(paths, payinfos):
        path.update(payinfo)
    return paths


__all__ = ["decode_invoice_paths", "encode_invoice_paths"]
