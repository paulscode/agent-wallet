# SPDX-License-Identifier: MIT
"""Tests for :mod:`app.services.anonymize.dns` — BIP-353 resolver.

Covers:

* DNS owner-name construction (``alice@x`` → ``alice.user._bitcoin-payment.x``).
* DNS query wire-format encoding (header + question section).
* DNS response wire-format decoding (TXT records + ``AD`` flag).
* BIP-21 URI parser for the published TXT content.
* cache discipline (24h floor, 7-day ceiling).
* End-to-end resolver path with a mocked DoH client:
  - Happy path (AD set, single TXT, BIP-21 with ``lno=``).
  - DNSSEC refusal (AD=0 → ``Bip353DnssecError``).
  - Multiple TXT records (BIP-353 forbids → ``Bip353DnsError``).
  - DoH non-200 / wrong Content-Type.
  - Wrong QID mismatch.
  - Cache hit returns without egress.
* Input validation (missing ``@``, exotic chars, empty parts).
"""

from __future__ import annotations

import contextlib
from typing import AsyncIterator

import httpx
import pytest

from app.services.anonymize import dns as bip353
from app.services.anonymize.dns import (
    Bip353DnsError,
    Bip353DnssecError,
    Bip353DoHError,
    Bip353ParseError,
    Bip353SyntaxError,
    _build_dns_txt_query,
    _cache_ttl_for,
    _make_dns_name,
    _parse_bip21_uri,
    _parse_dns_txt_response,
    _split_user_at_domain,
    reset_cache_for_tests,
    resolve_bip353,
)

# ── Input validation ───────────────────────────────────────────────


def test_split_user_at_domain_happy_path() -> None:
    assert _split_user_at_domain("Alice@Example.Com") == ("alice", "example.com")
    assert _split_user_at_domain("a.b-c_d@x.y") == ("a.b-c_d", "x.y")


def test_split_rejects_missing_at() -> None:
    with pytest.raises(Bip353SyntaxError, match="missing '@'"):
        _split_user_at_domain("aliceexample.com")


def test_split_rejects_multiple_at() -> None:
    with pytest.raises(Bip353SyntaxError, match="multiple '@'"):
        _split_user_at_domain("a@b@c")


def test_split_rejects_empty_parts() -> None:
    with pytest.raises(Bip353SyntaxError, match="empty user"):
        _split_user_at_domain("@example.com")
    with pytest.raises(Bip353SyntaxError, match="empty domain"):
        _split_user_at_domain("alice@")
    with pytest.raises(Bip353SyntaxError, match="empty input"):
        _split_user_at_domain("")


def test_split_rejects_exotic_chars() -> None:
    """Defends against a typo that would otherwise generate a bogus DNS query."""
    with pytest.raises(Bip353SyntaxError, match="unsupported character"):
        _split_user_at_domain("alice+filter@example.com")
    with pytest.raises(Bip353SyntaxError, match="unsupported character"):
        _split_user_at_domain("alice@example.com/")


# ── DNS name construction ──────────────────────────────────────────


def test_make_dns_name_inserts_user_subdomain() -> None:
    """BIP-353 specifies ``<user>.user._bitcoin-payment.<domain>``."""
    assert _make_dns_name("alice", "example.com") == "alice.user._bitcoin-payment.example.com"


# ── DNS query encoding ─────────────────────────────────────────────


def test_dns_query_header_shape() -> None:
    q = _build_dns_txt_query("alice.user._bitcoin-payment.example.com", query_id=0xCAFE)
    assert int.from_bytes(q[0:2], "big") == 0xCAFE
    # RD=1 (recursion desired), no other flags.
    assert int.from_bytes(q[2:4], "big") == 0x0100
    # QDCOUNT=1, ANCOUNT=NSCOUNT=ARCOUNT=0.
    assert int.from_bytes(q[4:6], "big") == 1
    assert int.from_bytes(q[6:8], "big") == 0
    assert int.from_bytes(q[8:10], "big") == 0
    assert int.from_bytes(q[10:12], "big") == 0


def test_dns_query_encodes_labels() -> None:
    q = _build_dns_txt_query("a.b.c", query_id=1)
    # Question section after the 12-byte header. Each label is
    # length-prefixed and the root label terminator is a zero byte:
    # \x01 a \x01 b \x01 c \x00  → 7 bytes.
    name_part = q[12:19]
    assert name_part == b"\x01a\x01b\x01c\x00"
    # Followed by QTYPE (TXT=16) + QCLASS (IN=1).
    assert q[19:21] == b"\x00\x10"
    assert q[21:23] == b"\x00\x01"


def test_dns_query_rejects_oversized_label() -> None:
    with pytest.raises(Bip353SyntaxError, match="too long"):
        _build_dns_txt_query("a" * 64 + ".example.com", query_id=1)


# ── DNS response decoding ──────────────────────────────────────────


def _build_dns_txt_response(
    *,
    qid: int,
    txt: str | list[str],
    ttl: int = 3600,
    ad_flag: bool = True,
    rcode: int = 0,
    extra_qd_offset: bool = False,
    answer_count: int | None = None,
) -> bytes:
    """Build a minimal DNS response wire message for tests.

    ``txt`` is either a single string (one TXT record) or a list
    (multiple records, which BIP-353 forbids — used to test the
    refusal path).
    """
    if isinstance(txt, str):
        txts = [txt]
    else:
        txts = list(txt)
    flags = 0x8000  # QR
    flags |= 0x0100  # RD
    flags |= 0x0080  # RA
    if ad_flag:
        flags |= 0x0020
    flags |= rcode & 0x0F
    n_answers = answer_count if answer_count is not None else len(txts)
    hdr = bytearray()
    hdr += int(qid).to_bytes(2, "big")
    hdr += int(flags).to_bytes(2, "big")
    hdr += (1).to_bytes(2, "big")  # QDCOUNT
    hdr += int(n_answers).to_bytes(2, "big")
    hdr += (0).to_bytes(2, "big")  # NSCOUNT
    hdr += (0).to_bytes(2, "big")  # ARCOUNT
    # Question section: a.b.c IN TXT
    qname = b"\x01a\x01b\x01c\x00"
    qtype = b"\x00\x10"
    qclass = b"\x00\x01"
    body = bytearray(hdr) + qname + qtype + qclass
    # Answer section: TXT records sharing the same name (compressed
    # pointer back to offset 12).
    for t in txts:
        # Compressed pointer to QNAME at offset 12.
        body += b"\xc0\x0c"
        body += b"\x00\x10"  # TYPE=TXT
        body += b"\x00\x01"  # CLASS=IN
        body += int(ttl).to_bytes(4, "big")
        # RDATA: single length-prefixed string for simplicity.
        as_bytes = t.encode("ascii")
        rdata = bytes([len(as_bytes)]) + as_bytes
        body += int(len(rdata)).to_bytes(2, "big")
        body += rdata
    return bytes(body)


def test_response_parser_accepts_single_txt() -> None:
    raw = _build_dns_txt_response(qid=0xABCD, txt="bitcoin:bc1q?lno=lno1xyz", ttl=600)
    txts, ad = _parse_dns_txt_response(raw, expect_qid=0xABCD)
    assert len(txts) == 1
    assert txts[0] == ("bitcoin:bc1q?lno=lno1xyz", 600)
    assert ad is True


def test_response_parser_returns_ad_false_when_unset() -> None:
    raw = _build_dns_txt_response(qid=1, txt="bitcoin:bc1q?lno=x", ad_flag=False)
    _txts, ad = _parse_dns_txt_response(raw, expect_qid=1)
    assert ad is False


def test_response_parser_rejects_qid_mismatch() -> None:
    raw = _build_dns_txt_response(qid=0xAAAA, txt="x")
    with pytest.raises(Bip353DnsError, match="QID"):
        _parse_dns_txt_response(raw, expect_qid=0xBBBB)


def test_response_parser_rejects_nonzero_rcode() -> None:
    raw = _build_dns_txt_response(qid=1, txt="x", rcode=3)  # NXDOMAIN
    with pytest.raises(Bip353DnsError, match="RCODE=3"):
        _parse_dns_txt_response(raw, expect_qid=1)


def test_response_parser_rejects_zero_answers() -> None:
    raw = _build_dns_txt_response(qid=1, txt=[], answer_count=0)
    with pytest.raises(Bip353DnsError, match="no answer"):
        _parse_dns_txt_response(raw, expect_qid=1)


# ── BIP-21 URI parsing ─────────────────────────────────────────────


def test_parse_bip21_extracts_lno() -> None:
    r = _parse_bip21_uri("bitcoin:bc1qxyz?lno=lno1deadbeef")
    assert r.bolt12_offer == "lno1deadbeef"
    assert r.onchain_address == "bc1qxyz"


def test_parse_bip21_extracts_lightning() -> None:
    r = _parse_bip21_uri("bitcoin:bc1q?lightning=lnbc100u")
    assert r.bolt11_invoice == "lnbc100u"


def test_parse_bip21_supports_no_address_with_lno() -> None:
    """A BIP-353 record may omit the on-chain part and carry only ``lno=``."""
    r = _parse_bip21_uri("bitcoin:?lno=lno1abc")
    assert r.bolt12_offer == "lno1abc"
    assert r.onchain_address is None


def test_parse_bip21_case_insensitive_scheme() -> None:
    r = _parse_bip21_uri("BITCOIN:bc1q?LNO=lno1xyz&LIGHTNING=lnbc")
    assert r.bolt12_offer == "lno1xyz"
    assert r.bolt11_invoice == "lnbc"


def test_parse_bip21_rejects_non_bitcoin_scheme() -> None:
    with pytest.raises(Bip353ParseError, match="must start with"):
        _parse_bip21_uri("lightning:lnbc?")


def test_parse_bip21_rejects_no_payable_handle() -> None:
    """A URI with no on-chain + no lno + no lightning has no actionable target."""
    with pytest.raises(Bip353ParseError, match="no payable handle"):
        _parse_bip21_uri("bitcoin:?label=hello")


# ── Cache TTL discipline ──────────────────────────────────────────


def test_cache_ttl_floor_applies_for_short_record() -> None:
    """Default floor is 24h; even a record TTL of 300s caches for 24h."""
    assert _cache_ttl_for(300) == 86400


def test_cache_ttl_ceiling_caps_at_seven_days() -> None:
    assert _cache_ttl_for(9_999_999) == 7 * 86400


def test_cache_ttl_zero_record_falls_back_to_floor() -> None:
    """A zero/negative published TTL is treated as missing → floor."""
    assert _cache_ttl_for(0) == 86400
    assert _cache_ttl_for(-5) == 86400


# ── End-to-end resolver ────────────────────────────────────────────


@pytest.fixture(autouse=True)
async def _clear_cache():
    """Reset the resolver cache between tests so cache hits don't leak."""
    await reset_cache_for_tests()
    yield
    await reset_cache_for_tests()


def _install_fake_client(monkeypatch, handler) -> list[httpx.Request]:
    """Replace ``get_anonymize_client`` with one returning a MockTransport.

    The returned list captures every request the resolver fires so
    tests can assert egress shape (URL, content-type, body).
    """
    captured: list[httpx.Request] = []

    def _wrapped(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    @contextlib.asynccontextmanager
    async def _factory(
        *,
        call_site: str,
        socks_host: str,
        socks_port: int,
        timeout_s: float = 30.0,
    ) -> AsyncIterator[httpx.AsyncClient]:
        assert call_site == "bip353_dns"
        transport = httpx.MockTransport(_wrapped)
        async with httpx.AsyncClient(transport=transport) as c:
            yield c

    monkeypatch.setattr(bip353, "get_anonymize_client", _factory)
    return captured


def _doh_response(
    request: httpx.Request, *, txt: str = "bitcoin:bc1q?lno=lno1xyz", ad_flag: bool = True
) -> httpx.Response:
    """Build a 200 OK DoH response mirroring the request QID."""
    body = request.content
    qid = int.from_bytes(body[0:2], "big")
    raw = _build_dns_txt_response(qid=qid, txt=txt, ad_flag=ad_flag)
    return httpx.Response(
        200,
        content=raw,
        headers={"Content-Type": "application/dns-message"},
    )


@pytest.mark.asyncio
async def test_resolve_happy_path(monkeypatch) -> None:
    captured = _install_fake_client(
        monkeypatch,
        lambda req: _doh_response(req, txt="bitcoin:bc1q?lno=lno1abc"),
    )
    out = await resolve_bip353("alice@example.com")
    assert out.bolt12_offer == "lno1abc"
    assert out.dns_name == "alice.user._bitcoin-payment.example.com"
    assert out.user_at_domain == "alice@example.com"
    # One DoH request fired with the expected wire shape.
    assert len(captured) == 1
    req = captured[0]
    assert req.method == "POST"
    assert req.headers["Content-Type"] == "application/dns-message"
    assert req.headers["Accept"] == "application/dns-message"
    assert req.url.host == "dns.mullvad.net"


@pytest.mark.asyncio
async def test_resolve_caches_result(monkeypatch) -> None:
    """A second call for the same address must NOT egress."""
    captured = _install_fake_client(monkeypatch, _doh_response)
    out1 = await resolve_bip353("bob@example.com")
    out2 = await resolve_bip353("bob@example.com")
    assert out1 == out2
    assert len(captured) == 1, "cached lookup should not fire a second DoH request"


@pytest.mark.asyncio
async def test_resolve_refuses_ad_false(monkeypatch) -> None:
    """DNSSEC AD=0 must produce :class:`Bip353DnssecError`."""
    _install_fake_client(
        monkeypatch,
        lambda req: _doh_response(req, ad_flag=False),
    )
    with pytest.raises(Bip353DnssecError, match="did not set AD"):
        await resolve_bip353("alice@example.com")


@pytest.mark.asyncio
async def test_resolve_refuses_multiple_txt(monkeypatch) -> None:
    """BIP-353 forbids multiple TXT records for the same name."""

    def _multi(req: httpx.Request) -> httpx.Response:
        body = req.content
        qid = int.from_bytes(body[0:2], "big")
        raw = _build_dns_txt_response(
            qid=qid,
            txt=["bitcoin:bc1?lno=a", "bitcoin:bc1?lno=b"],
        )
        return httpx.Response(
            200,
            content=raw,
            headers={"Content-Type": "application/dns-message"},
        )

    _install_fake_client(monkeypatch, _multi)
    with pytest.raises(Bip353DnsError, match="exactly one TXT"):
        await resolve_bip353("alice@example.com")


@pytest.mark.asyncio
async def test_resolve_refuses_doh_non_200(monkeypatch) -> None:
    _install_fake_client(
        monkeypatch,
        lambda req: httpx.Response(503, content=b"down"),
    )
    with pytest.raises(Bip353DoHError, match="HTTP 503"):
        await resolve_bip353("alice@example.com")


@pytest.mark.asyncio
async def test_resolve_refuses_wrong_content_type(monkeypatch) -> None:
    """If the DoH provider returns HTML (e.g. an interstitial), refuse."""
    _install_fake_client(
        monkeypatch,
        lambda req: httpx.Response(
            200,
            content=b"<html>captive portal</html>",
            headers={"Content-Type": "text/html"},
        ),
    )
    with pytest.raises(Bip353DoHError, match="unexpected Content-Type"):
        await resolve_bip353("alice@example.com")


@pytest.mark.asyncio
async def test_resolve_propagates_syntax_error_without_egress(monkeypatch) -> None:
    """Bad input fails validation before any DoH egress."""
    captured = _install_fake_client(monkeypatch, _doh_response)
    with pytest.raises(Bip353SyntaxError):
        await resolve_bip353("not-an-address")
    assert captured == []


@pytest.mark.asyncio
async def test_resolve_refuses_empty_doh_endpoint(monkeypatch) -> None:
    """Operator with an empty DoH config must fail loudly."""
    _install_fake_client(monkeypatch, _doh_response)
    monkeypatch.setattr(
        bip353.settings,
        "anonymize_bip353_doh_endpoint",
        "",
    )
    with pytest.raises(Bip353DoHError, match="unset"):
        await resolve_bip353("alice@example.com")
