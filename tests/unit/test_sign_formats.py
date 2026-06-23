# SPDX-License-Identifier: MIT
"""Unit tests for app.core.sign_formats."""

from __future__ import annotations

import json

import pytest

from app.core.sign_formats import (
    parse_signed_message,
    render_address_signed,
    render_node_signed,
)

ADDR = "bc1qexampleaddressxxxxxxxxxxxxxxxxxx99"
MSG = "I control this address.\nLine two."
SIG = "AbC123+/=_-defghijklmnopqrstuvwxyz0123456789ABCDEF"


class TestRenderAddressSigned:
    def test_json(self):
        out = render_address_signed(
            address=ADDR,
            message=MSG,
            signature=SIG,
            sig_format="bip322-simple",
            fmt="json",
        )
        obj = json.loads(out)
        assert obj["address"] == ADDR
        assert obj["message"] == MSG
        assert obj["signature"] == SIG
        assert obj["format"] == "bip322-simple"

    def test_sparrow(self):
        out = render_address_signed(
            address=ADDR,
            message=MSG,
            signature=SIG,
            sig_format="bip322-simple",
            fmt="sparrow",
        )
        # Three logical sections separated by single newlines.
        assert out.startswith(ADDR + "\n")
        assert SIG in out

    def test_ascii(self):
        out = render_address_signed(
            address=ADDR,
            message=MSG,
            signature=SIG,
            sig_format="bip137",
            fmt="ascii",
        )
        assert "-----BEGIN BITCOIN SIGNED MESSAGE-----" in out
        assert "-----BEGIN BITCOIN SIGNATURE-----" in out
        assert "-----END BITCOIN SIGNATURE-----" in out
        assert ADDR in out
        assert SIG in out

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError):
            render_address_signed(
                address=ADDR,
                message=MSG,
                signature=SIG,
                sig_format="bip137",
                fmt="bogus",  # type: ignore[arg-type]
            )


class TestRenderNodeSigned:
    def test_json(self):
        out = render_node_signed(
            message=MSG,
            signature=SIG,
            node_pubkey="02" + "a" * 64,
            fmt="json",
        )
        obj = json.loads(out)
        assert obj["message"] == MSG
        assert obj["signature"] == SIG
        assert obj["node_pubkey"].startswith("02")

    def test_signature_only(self):
        out = render_node_signed(
            message=MSG,
            signature=SIG,
            node_pubkey="02" + "a" * 64,
            fmt="signature",
        )
        assert out.strip() == SIG


class TestParseSignedMessage:
    def test_json_address_roundtrip(self):
        rendered = render_address_signed(
            address=ADDR,
            message=MSG,
            signature=SIG,
            sig_format="bip322-simple",
            fmt="json",
        )
        p = parse_signed_message(rendered)
        assert p.identity == "address"
        assert p.address == ADDR
        assert p.message == MSG
        assert p.signature == SIG

    def test_json_node_roundtrip(self):
        rendered = render_node_signed(
            message=MSG,
            signature=SIG,
            node_pubkey="02" + "a" * 64,
            fmt="json",
        )
        p = parse_signed_message(rendered)
        assert p.identity == "node"
        assert p.address is None
        assert p.message == MSG

    def test_sparrow_roundtrip(self):
        rendered = render_address_signed(
            address=ADDR,
            message=MSG,
            signature=SIG,
            sig_format="bip322-simple",
            fmt="sparrow",
        )
        p = parse_signed_message(rendered)
        assert p.identity == "address"
        assert p.address == ADDR
        assert p.signature == SIG
        assert p.message == MSG

    def test_ascii_roundtrip(self):
        rendered = render_address_signed(
            address=ADDR,
            message=MSG,
            signature=SIG,
            sig_format="bip137",
            fmt="ascii",
        )
        p = parse_signed_message(rendered)
        assert p.identity == "address"
        assert p.address == ADDR
        assert p.signature == SIG
        assert p.message == MSG

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            parse_signed_message("")
        with pytest.raises(ValueError):
            parse_signed_message("    \n  \t ")

    def test_garbage_raises(self):
        with pytest.raises(ValueError):
            parse_signed_message("not a signed message at all")

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError):
            parse_signed_message("{not json")

    def test_json_missing_fields_raises(self):
        with pytest.raises(ValueError):
            parse_signed_message('{"address": "x"}')

    def test_json_node_pubkey_explicit(self):
        """A JSON blob with `node_pubkey` (no address) → identity='node'."""
        blob = json.dumps(
            {
                "node_pubkey": "02" + "a" * 64,
                "message": "hi",
                "signature": "zsig",
            }
        )
        p = parse_signed_message(blob)
        assert p.identity == "node"
        assert p.address is None

    def test_json_bare_message_signature_defaults_to_node(self):
        """{message, signature} with neither address nor node_pubkey → node."""
        p = parse_signed_message('{"message": "m", "signature": "s"}')
        assert p.identity == "node"

    def test_none_blob_raises(self):
        with pytest.raises(ValueError):
            parse_signed_message(None)  # type: ignore[arg-type]

    def test_unknown_node_format_raises(self):
        with pytest.raises(ValueError, match="unknown node export format"):
            render_node_signed(
                message=MSG,
                signature=SIG,
                node_pubkey="02" + "a" * 64,
                fmt="xml",  # type: ignore[arg-type]
            )

    def test_ascii_missing_signature_raises(self):
        """ASCII-armored block with header but empty signature body."""
        blob = (
            "-----BEGIN BITCOIN SIGNED MESSAGE-----\n"
            "msg\n"
            "-----BEGIN BITCOIN SIGNATURE-----\n"
            "Address: " + ADDR + "\n"
            "\n"
            "-----END BITCOIN SIGNATURE-----\n"
        )
        with pytest.raises(ValueError, match="missing a signature"):
            parse_signed_message(blob)

    def test_ascii_without_header_lines(self):
        """ASCII block where signature follows BEGIN SIGNATURE with no Address: header."""
        blob = (
            "-----BEGIN BITCOIN SIGNED MESSAGE-----\n"
            "hello\n"
            "-----BEGIN BITCOIN SIGNATURE-----\n" + SIG + "\n"
            "-----END BITCOIN SIGNATURE-----\n"
        )
        p = parse_signed_message(blob)
        assert p.identity == "node"  # no address → node
        assert p.signature == SIG
        assert p.message == "hello"
