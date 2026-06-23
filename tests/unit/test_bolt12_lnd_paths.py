# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.lnd_paths.encode_invoice_paths``."""

from __future__ import annotations

import base64

import pytest

from app.services.bolt12.lnd_paths import encode_invoice_paths

# ── fixtures / helpers ───────────────────────────────────────────


def _hex33(seed: str) -> str:
    """33-byte hex string built by repeating ``seed`` (1-byte hex)."""
    return ("02" if seed == "02" else seed) + (seed * 32)[: 32 * 2]


_NODE_A = "02" + "33" * 32
_NODE_B = "03" + "44" * 32
_NODE_C = "02" + "55" * 32
_NODE_D = "03" + "66" * 32

_PAYINFO_DEFAULT = {
    "base_fee_msat": 1000,
    "proportional_fee_rate": 100,
    "total_cltv_delta": 144,
    "htlc_min_msat": "1",
    "htlc_max_msat": "100000000",
    "features": "",
}


def _path(intro: str, blind: str, hops: list[tuple[str, str]]) -> dict:
    return {
        "blinded_path": {
            "introduction_node": intro,
            "blinding_point": blind,
            "blinded_hops": [{"blinded_node": n, "encrypted_data": d} for n, d in hops],
        },
        **_PAYINFO_DEFAULT,
    }


# ── happy paths ──────────────────────────────────────────────────


def test_single_path_single_hop_lengths() -> None:
    enc = b"\xde" * 16
    paths = [_path(_NODE_A, _NODE_B, [(_NODE_C, enc)])]
    paths_b, pay_b = encode_invoice_paths(paths)

    # blinded_path: 33 + 33 + 1 + (33 + 2 + 16) = 118 bytes
    assert len(paths_b) == 33 + 33 + 1 + 33 + 2 + 16
    # blinded_payinfo: 4 + 4 + 2 + 8 + 8 + 2 + 0 = 28 bytes
    assert len(pay_b) == 4 + 4 + 2 + 8 + 8 + 2

    # Verify field positions in paths_b.
    assert paths_b[0:33] == bytes.fromhex(_NODE_A)
    assert paths_b[33:66] == bytes.fromhex(_NODE_B)
    assert paths_b[66] == 1  # num_hops
    assert paths_b[67:100] == bytes.fromhex(_NODE_C)
    assert int.from_bytes(paths_b[100:102], "big") == 16
    assert paths_b[102:118] == b"\xde" * 16

    # Verify field positions in pay_b.
    assert int.from_bytes(pay_b[0:4], "big") == 1000
    assert int.from_bytes(pay_b[4:8], "big") == 100
    assert int.from_bytes(pay_b[8:10], "big") == 144
    assert int.from_bytes(pay_b[10:18], "big") == 1
    assert int.from_bytes(pay_b[18:26], "big") == 100_000_000
    assert int.from_bytes(pay_b[26:28], "big") == 0


def test_multi_path_multi_hop_concatenates() -> None:
    paths = [
        _path(_NODE_A, _NODE_B, [(_NODE_C, b"\xab" * 8), (_NODE_D, b"\xcd" * 12)]),
        _path(_NODE_B, _NODE_A, [(_NODE_D, b"\xef" * 4)]),
    ]
    paths_b, pay_b = encode_invoice_paths(paths)

    # First path: 33+33+1 + 2*(33+2) + 8 + 12 = 157
    # Second path: 33+33+1 + 1*(33+2) + 4 = 106
    assert len(paths_b) == 157 + 106
    # Two payinfos at 28 bytes each.
    assert len(pay_b) == 56
    # The two payinfos are identical → second 28B == first 28B.
    assert pay_b[:28] == pay_b[28:]


def test_accepts_base64_inputs() -> None:
    intro = base64.b64encode(bytes.fromhex(_NODE_A)).decode()
    blind = base64.b64encode(bytes.fromhex(_NODE_B)).decode()
    bnode = base64.b64encode(bytes.fromhex(_NODE_C)).decode()
    enc = base64.b64encode(b"\xde" * 16).decode()
    paths = [_path(intro, blind, [(bnode, enc)])]
    paths_b, _ = encode_invoice_paths(paths)
    assert paths_b[0:33] == bytes.fromhex(_NODE_A)
    assert paths_b[33:66] == bytes.fromhex(_NODE_B)
    assert paths_b[67:100] == bytes.fromhex(_NODE_C)


def test_features_field_is_included_when_present() -> None:
    paths = [_path(_NODE_A, _NODE_B, [(_NODE_C, b"\xde" * 16)])]
    paths[0]["features"] = b"\xff" * 4  # 4-byte features blob
    _, pay_b = encode_invoice_paths(paths)
    # 26 bytes header + 2 bytes flen + 4 bytes features = 32 bytes
    assert len(pay_b) == 32
    assert int.from_bytes(pay_b[26:28], "big") == 4
    assert pay_b[28:32] == b"\xff\xff\xff\xff"


def test_payinfo_fields_default_to_zero_when_missing() -> None:
    paths = [
        {
            "blinded_path": {
                "introduction_node": _NODE_A,
                "blinding_point": _NODE_B,
                "blinded_hops": [{"blinded_node": _NODE_C, "encrypted_data": b"\xab" * 8}],
            },
            # No payinfo fields at all.
        }
    ]
    _, pay_b = encode_invoice_paths(paths)
    assert pay_b == b"\x00" * 28


# ── rejection paths ──────────────────────────────────────────────


def test_rejects_empty_paths_list() -> None:
    with pytest.raises(ValueError, match="at least one path"):
        encode_invoice_paths([])


def test_rejects_non_list_input() -> None:
    with pytest.raises(TypeError):
        encode_invoice_paths("not a list")  # type: ignore[arg-type]


def test_rejects_zero_hops() -> None:
    paths = [_path(_NODE_A, _NODE_B, [])]
    with pytest.raises(ValueError, match="at least one hop"):
        encode_invoice_paths(paths)


def test_rejects_wrong_length_pubkey() -> None:
    paths = [
        {
            "blinded_path": {
                "introduction_node": "02" * 16,  # only 16 bytes
                "blinding_point": _NODE_B,
                "blinded_hops": [{"blinded_node": _NODE_C, "encrypted_data": b"\xab"}],
            },
            **_PAYINFO_DEFAULT,
        }
    ]
    with pytest.raises(ValueError, match="introduction_node"):
        encode_invoice_paths(paths)


def test_rejects_missing_blinded_path() -> None:
    paths = [{**_PAYINFO_DEFAULT}]
    with pytest.raises(TypeError, match="blinded_path"):
        encode_invoice_paths(paths)


def test_rejects_invalid_binary_encoding() -> None:
    paths = [
        {
            "blinded_path": {
                "introduction_node": "@@notvalid@@",
                "blinding_point": _NODE_B,
                "blinded_hops": [{"blinded_node": _NODE_C, "encrypted_data": b"\xab"}],
            },
            **_PAYINFO_DEFAULT,
        }
    ]
    with pytest.raises(ValueError):
        encode_invoice_paths(paths)


def test_rejects_payinfo_overflow() -> None:
    paths = [_path(_NODE_A, _NODE_B, [(_NODE_C, b"\xab")])]
    paths[0]["base_fee_msat"] = 2**32  # u32 overflow
    with pytest.raises(ValueError, match="base_fee_msat"):
        encode_invoice_paths(paths)


# ── features: LND-style list[int|str] (regression for May-29 Ocean #5) ──


def test_features_empty_list_encodes_as_empty_bitmap() -> None:
    """LND returns ``features: []`` for blinded paths without extras."""
    paths = [_path(_NODE_A, _NODE_B, [(_NODE_C, b"\xab")])]
    paths[0]["features"] = []
    _, pay_b = encode_invoice_paths(paths)
    # 28-byte header (with flen=0, no features payload)
    assert len(pay_b) == 28
    assert int.from_bytes(pay_b[26:28], "big") == 0


def test_features_list_of_ints_packs_to_bitmap() -> None:
    """LND may emit ``features: [17]`` (MPP_OPT) as raw int indices."""
    paths = [_path(_NODE_A, _NODE_B, [(_NODE_C, b"\xab")])]
    paths[0]["features"] = [17]  # MPP_OPT
    _, pay_b = encode_invoice_paths(paths)
    # bit 17 → byte index 2 from end, bit 1 → 0x02 in byte at offset 0
    # nbytes = 3, bitmap = b"\x02\x00\x00"
    assert pay_b[26:28] == b"\x00\x03"
    assert pay_b[28:31] == b"\x02\x00\x00"


def test_features_list_of_enum_names_packs_to_bitmap() -> None:
    """LND-rest serializes enum values as string names."""
    paths = [_path(_NODE_A, _NODE_B, [(_NODE_C, b"\xab")])]
    paths[0]["features"] = ["MPP_OPT", "PAYMENT_ADDR_OPT"]  # bits 17, 15
    _, pay_b = encode_invoice_paths(paths)
    # max bit 17 → 3 bytes; bits 17 (0x02 at byte 0) and 15 (0x80 at byte 1)
    assert pay_b[26:28] == b"\x00\x03"
    assert pay_b[28:31] == b"\x02\x80\x00"


def test_features_unknown_enum_name_rejected() -> None:
    paths = [_path(_NODE_A, _NODE_B, [(_NODE_C, b"\xab")])]
    paths[0]["features"] = ["WHO_KNOWS_OPT"]
    with pytest.raises(ValueError, match="unknown feature bit name"):
        encode_invoice_paths(paths)


def test_features_numeric_string_falls_back_to_int() -> None:
    paths = [_path(_NODE_A, _NODE_B, [(_NODE_C, b"\xab")])]
    paths[0]["features"] = ["17"]
    _, pay_b = encode_invoice_paths(paths)
    assert pay_b[26:28] == b"\x00\x03"
    assert pay_b[28:31] == b"\x02\x00\x00"
