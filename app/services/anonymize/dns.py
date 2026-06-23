# SPDX-License-Identifier: MIT
"""BIP-353 DoH resolver.

Resolves Lightning-address-style strings (``alice@example.com``) into
BOLT 12 offers (and optionally BOLT 11 / on-chain fallbacks) via
DNS-over-HTTPS, routed through the dedicated ``bip353_dns`` SOCKS
listener over Tor.

Per BIP-353:

* The input ``user@domain`` is translated to a DNS name
  ``<user>.user._bitcoin-payment.<domain>``.
* A ``TXT`` query at that name returns a record whose content is a
  BIP-21 URI (``bitcoin:bc1q...?lno=lno1...&lightning=...``).
* The resolver MUST verify the response is DNSSEC-authenticated.

Threat-model constraints from:

* Lookups go over a **dedicated** SOCKS listener (``bip353_dns``),
  never shared with Boltz / Liquid / chain-backend traffic.
* The DoH provider must not log; default
  ``ANONYMIZE_BIP353_DOH_ENDPOINT=https://dns.mullvad.net/dns-query``
  is non-logging by stated policy. Other providers (Quad9) are
  operator-configurable.
* DNSSEC validation is delegated to the DoH provider — we verify
  the response's ``AD`` (Authenticated Data) flag is set. Self-
  validating the DNSSEC chain would require a Python validator +
  root-anchor management; the design accepts the trust in
  the DoH provider that the operator pinned in config.
* Results are cached aggressively (24h minimum, capped at the
  DNSSEC TTL ceiling) so a repeat-lookup-as-confirmation attack
  cannot trigger a fresh egress per session.
* Lookups happen at quote-time only, never during pipeline
  execution (caller-enforced).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Final, Optional

import httpx

from app.core.config import settings
from app.core.http_limits import ResponseTooLargeError, request_capped

from .http import get_anonymize_client
from .metadata import ANONYMIZE_LOGGER_NAME
from .tor import resolve_socks_host, resolve_socks_port

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


_CALL_SITE: Final[str] = "bip353_dns"


class Bip353Error(RuntimeError):
    """Base class for BIP-353 resolver failures."""


class Bip353SyntaxError(Bip353Error):
    """Raised when the input is not a syntactically valid Lightning-
    address-style string."""


class Bip353DoHError(Bip353Error):
    """Raised when the DoH request itself fails (network / non-200)."""


class Bip353DnsError(Bip353Error):
    """Raised when the DNS response carries an error code or no answer."""


class Bip353DnssecError(Bip353Error):
    """Raised when the DoH response did NOT set the ``AD`` flag,
    meaning the upstream resolver could not validate DNSSEC for the
    record. we refuse unauthenticated answers — accepting
    them would let an upstream forge any user→offer mapping."""


class Bip353ParseError(Bip353Error):
    """Raised when the TXT record content cannot be parsed as a
    BIP-21 URI with at least one supported payment field."""


# ── Value objects ──────────────────────────────────────────────────


@dataclass(frozen=True)
class Bip353Result:
    """The payment-handles extracted from a successful BIP-353 lookup.

    Per BIP-21 / BIP-353 the TXT record can carry several payment
    primitives; we surface them all and let the caller pick the
    preferred one (the anonymize stack picks ``bolt12_offer`` for
    Tor-friendly BOLT 12 outbound).
    """

    # The original input that produced this result. Useful for
    # logging — the resolver itself only uses the derived DNS name.
    user_at_domain: str
    # The DNS name actually queried.
    dns_name: str
    # Discovered payment handles (any may be ``None``).
    bolt12_offer: Optional[str] = None
    bolt11_invoice: Optional[str] = None
    onchain_address: Optional[str] = None
    # Raw TXT record content (the BIP-21 URI as published).
    raw_txt: str = ""


@dataclass(frozen=True)
class _CacheEntry:
    """Stored entry in the per-process resolver cache."""

    result: Bip353Result
    expires_at_unix_s: float


# ── DNS wire-format encoder (RFC 1035 + 8484) ─────────────────────


def _encode_dns_name(name: str) -> bytes:
    """Encode a DNS owner name as a length-prefixed label sequence."""
    out = bytearray()
    if name and name.endswith("."):
        name = name[:-1]
    for label in name.split("."):
        if not label:
            raise Bip353SyntaxError(f"empty DNS label in {name!r} (consecutive dots?)")
        b = label.encode("ascii", errors="strict")
        if len(b) > 63:
            raise Bip353SyntaxError(f"DNS label too long ({len(b)}>63): {label!r}")
        out.append(len(b))
        out += b
    out.append(0)  # root label terminator
    return bytes(out)


_DNS_TYPE_TXT: Final[int] = 16
_DNS_CLASS_IN: Final[int] = 1
_DNS_FLAG_QR: Final[int] = 0x8000  # response bit
_DNS_FLAG_RD: Final[int] = 0x0100  # recursion desired
_DNS_FLAG_RA: Final[int] = 0x0080  # recursion available
_DNS_FLAG_AD: Final[int] = 0x0020  # DNSSEC authenticated data
_DNS_RCODE_MASK: Final[int] = 0x000F


def _build_dns_txt_query(name: str, *, query_id: int) -> bytes:
    """Build the binary DNS query message body for a TXT lookup.

    The flags request recursion (``RD=1``); the upstream DoH
    resolver sets ``AD=1`` if it validates the answer. We do NOT
    set ``DO=1`` (EDNS DNSSEC-OK) because doing so would force the
    resolver to return RRSIG records we don't process; the upstream
    still validates regardless when ``DO=0`` and signals success
    via ``AD``.
    """
    header = bytearray()
    header += int(query_id & 0xFFFF).to_bytes(2, "big")
    header += int(_DNS_FLAG_RD).to_bytes(2, "big")
    header += (1).to_bytes(2, "big")  # QDCOUNT
    header += (0).to_bytes(2, "big")  # ANCOUNT
    header += (0).to_bytes(2, "big")  # NSCOUNT
    header += (0).to_bytes(2, "big")  # ARCOUNT
    qname = _encode_dns_name(name)
    qtype = int(_DNS_TYPE_TXT).to_bytes(2, "big")
    qclass = int(_DNS_CLASS_IN).to_bytes(2, "big")
    return bytes(header) + qname + qtype + qclass


# ── DNS wire-format decoder (limited — TXT answers only) ──────────


class _DnsParseError(Bip353DnsError):
    pass


def _read_name(buf: bytes, off: int) -> tuple[str, int]:
    """Read a (possibly-compressed) DNS name; return (name, new_offset).

    Supports compression pointers per RFC 1035.
    """
    labels: list[str] = []
    seen_pointer = False
    cursor = off
    final_off = off
    # Bound the loop to defend against malformed inputs that could
    # otherwise create a pointer cycle.
    for _ in range(256):
        if cursor >= len(buf):
            raise _DnsParseError("truncated DNS name")
        b = buf[cursor]
        if b == 0:
            cursor += 1
            if not seen_pointer:
                final_off = cursor
            return ".".join(labels), final_off
        if (b & 0xC0) == 0xC0:
            if cursor + 1 >= len(buf):
                raise _DnsParseError("truncated DNS pointer")
            if not seen_pointer:
                final_off = cursor + 2
            target = ((b & 0x3F) << 8) | buf[cursor + 1]
            cursor = target
            seen_pointer = True
            continue
        # Plain label.
        if (b & 0xC0) != 0:
            raise _DnsParseError(f"unsupported DNS label type {b:#x}")
        ln = b
        cursor += 1
        if cursor + ln > len(buf):
            raise _DnsParseError("truncated DNS label")
        labels.append(buf[cursor : cursor + ln].decode("ascii", errors="strict"))
        cursor += ln
    raise _DnsParseError("DNS name decoding exceeded label cap")


def _parse_dns_txt_response(
    buf: bytes,
    *,
    expect_qid: int,
) -> tuple[list[tuple[str, int]], bool]:
    """Parse a DNS response message; return ``(txt_records, ad_flag)``.

    Each TXT record yields ``(content_str, ttl_s)``. The ``ad_flag``
    is the upstream DoH provider's DNSSEC validation result —
    ``True`` means the chain validated, ``False`` means we refuse.

    Raises :class:`Bip353DnsError` on any wire-level malformation,
    truncated answer, non-zero RCODE, or missing/zero answers.
    """
    if len(buf) < 12:
        raise _DnsParseError("DNS response shorter than header")
    qid = int.from_bytes(buf[0:2], "big")
    if qid != expect_qid:
        raise _DnsParseError(f"DNS response QID {qid} != request QID {expect_qid}")
    flags = int.from_bytes(buf[2:4], "big")
    if not (flags & _DNS_FLAG_QR):
        raise _DnsParseError("DNS message is not a response (QR=0)")
    rcode = flags & _DNS_RCODE_MASK
    if rcode != 0:
        raise _DnsParseError(f"DNS RCODE={rcode}")
    ad_flag = bool(flags & _DNS_FLAG_AD)
    qdcount = int.from_bytes(buf[4:6], "big")
    ancount = int.from_bytes(buf[6:8], "big")

    off = 12
    for _ in range(qdcount):
        _qname, off = _read_name(buf, off)
        off += 4  # QTYPE (2) + QCLASS (2)

    if ancount == 0:
        raise _DnsParseError("DNS response has no answer records")

    txts: list[tuple[str, int]] = []
    for _ in range(ancount):
        _name, off = _read_name(buf, off)
        if off + 10 > len(buf):
            raise _DnsParseError("truncated RR header")
        rtype = int.from_bytes(buf[off : off + 2], "big")
        # rclass is at [off+2:off+4]; ignored — the spec admits IN only.
        ttl = int.from_bytes(buf[off + 4 : off + 8], "big")
        rdlen = int.from_bytes(buf[off + 8 : off + 10], "big")
        off += 10
        if off + rdlen > len(buf):
            raise _DnsParseError("truncated RDATA")
        rdata = buf[off : off + rdlen]
        off += rdlen
        if rtype != _DNS_TYPE_TXT:
            continue
        # TXT rdata is a concatenation of length-prefixed strings.
        parts: list[str] = []
        i = 0
        while i < len(rdata):
            ln = rdata[i]
            i += 1
            if i + ln > len(rdata):
                raise _DnsParseError("truncated TXT string")
            parts.append(rdata[i : i + ln].decode("ascii", errors="strict"))
            i += ln
        txts.append(("".join(parts), int(ttl)))
    return txts, ad_flag


# ── BIP-21 URI parser (just the fields BIP-353 cares about) ──────


def _parse_bip21_uri(uri: str) -> Bip353Result:
    """Parse a ``bitcoin:<address>?<query>`` URI into a result.

    BIP-353 publishes its payment handles via BIP-21:

    * ``bitcoin:<address>`` — optional on-chain fallback.
    * ``?lno=<bolt12-offer>`` — preferred for Tor BOLT 12 routing.
    * ``?lightning=<bolt11-invoice>`` — fallback.

    We accept the URI in either case and any-cased scheme prefix
    per RFC 3986 (BIP-21 inherits this).

    Returns a :class:`Bip353Result` with only the fields BIP-353
    surfaces. ``user_at_domain`` and ``dns_name`` are left blank;
    the caller fills them in.
    """
    s = uri.strip()
    if not s:
        raise Bip353ParseError("empty BIP-21 URI")
    if "?" in s:
        scheme_and_addr, _, query = s.partition("?")
    else:
        scheme_and_addr, query = s, ""
    if not scheme_and_addr.lower().startswith("bitcoin:"):
        raise Bip353ParseError(f"BIP-21 URI must start with 'bitcoin:' (got {scheme_and_addr!r})")
    addr = scheme_and_addr[len("bitcoin:") :]
    bolt12_offer: Optional[str] = None
    bolt11_invoice: Optional[str] = None
    for kv in query.split("&"):
        if not kv:
            continue
        if "=" not in kv:
            continue
        k, _, v = kv.partition("=")
        kl = k.lower()
        if kl == "lno" and v:
            bolt12_offer = v
        elif kl == "lightning" and v:
            bolt11_invoice = v
    if not (bolt12_offer or bolt11_invoice or addr):
        raise Bip353ParseError("BIP-21 URI carries no payable handle (no on-chain, no lno, no lightning)")
    return Bip353Result(
        user_at_domain="",
        dns_name="",
        bolt12_offer=bolt12_offer,
        bolt11_invoice=bolt11_invoice,
        onchain_address=addr or None,
        raw_txt=uri,
    )


# ── Input validation ──────────────────────────────────────────────


def _split_user_at_domain(addr: str) -> tuple[str, str]:
    """Validate + split a Lightning-address-style string.

    Per BIP-353 the local part follows DNS label syntax (a-z, 0-9,
    hyphen, dot for sub-labels) and the domain part is a standard
    DNS name. We accept the union of:

    * RFC 5321 local-part (without quoting) — alphanumerics, hyphen,
      underscore, dot.
    * RFC 1035 LDH domain names.

    The caller is responsible for cookie-subject or other
    application-layer auth; this function is shape-only.
    """
    s = (addr or "").strip().lower()
    if not s:
        raise Bip353SyntaxError("empty input")
    if "@" not in s:
        raise Bip353SyntaxError("missing '@' separator")
    user, _, domain = s.partition("@")
    if not user:
        raise Bip353SyntaxError("empty user part")
    if not domain:
        raise Bip353SyntaxError("empty domain part")
    if "@" in domain:
        raise Bip353SyntaxError("multiple '@' separators")
    # Local-part: allow LDH + dot + underscore. Refuse anything
    # exotic so a typo doesn't silently produce a bogus DNS query.
    for c in user:
        if c.isalnum() or c in "-_.":
            continue
        raise Bip353SyntaxError(f"unsupported character {c!r} in user part of {addr!r}")
    # Domain: LDH only.
    for c in domain:
        if c.isalnum() or c in "-.":
            continue
        raise Bip353SyntaxError(f"unsupported character {c!r} in domain part of {addr!r}")
    return user, domain


def _make_dns_name(user: str, domain: str) -> str:
    """Build the BIP-353 DNS owner name from a ``user@domain``."""
    return f"{user}.user._bitcoin-payment.{domain}"


# ── Cache ─────────────────────────────────────────────────────────


class _Bip353Cache:
    """Process-wide TTL cache for BIP-353 results.

    Keyed by the DNS name (lower-case, no trailing dot) since the
    only RR type we query is TXT. the TTL floor is
    ``ANONYMIZE_BIP353_CACHE_MIN_TTL_S`` (24h default) so a
    short-TTL DNSSEC answer cannot force per-session repeat egress;
    the ceiling defends against an upstream that advertises an
    unreasonable TTL.
    """

    # Hard cap so the cache can't grow without bound across the process
    # lifetime. On overflow the oldest-inserted entry is evicted (dicts
    # preserve insertion order); the entry simply re-resolves on next use.
    _MAX_ENTRIES = 4096

    def __init__(self) -> None:
        self._entries: dict[str, _CacheEntry] = {}
        self._lock = asyncio.Lock()

    def _now(self) -> float:
        return time.time()

    async def get(self, dns_name: str) -> Optional[Bip353Result]:
        async with self._lock:
            entry = self._entries.get(dns_name)
            if entry is None:
                return None
            if entry.expires_at_unix_s <= self._now():
                # Don't auto-remove; let the next put() overwrite.
                # Returning ``None`` here is enough.
                return None
            return entry.result

    async def put(
        self,
        dns_name: str,
        result: Bip353Result,
        *,
        ttl_s: int,
    ) -> None:
        async with self._lock:
            self._entries[dns_name] = _CacheEntry(
                result=result,
                expires_at_unix_s=self._now() + max(0, ttl_s),
            )
            while len(self._entries) > self._MAX_ENTRIES:
                oldest = next(iter(self._entries))
                del self._entries[oldest]

    async def clear(self) -> None:
        async with self._lock:
            self._entries.clear()

    async def size(self) -> int:
        async with self._lock:
            return len(self._entries)


_CACHE: Final[_Bip353Cache] = _Bip353Cache()


async def reset_cache_for_tests() -> None:
    """Test-only — drop every cached entry."""
    await _CACHE.clear()


# ── Resolver ──────────────────────────────────────────────────────


def _cache_ttl_for(record_ttl_s: int) -> int:
    """Apply the floor/ceiling to a DNSSEC-published TTL.

    Floor: ``ANONYMIZE_BIP353_CACHE_MIN_TTL_S`` (default 24h). Even
    a published TTL of 300s must be cached for 24h locally, so an
    adversary cannot use repeat-lookup-as-confirmation.

    Ceiling: the published TTL itself, capped at 7 days (a defense
    against an upstream that advertises a wildly inflated TTL).
    The wording is "capped at the DNSSEC TTL upper bound";
    a 7-day cap mirrors common DNS TTL practice.
    """
    floor = int(settings.anonymize_bip353_cache_min_ttl_s)
    seven_days = 7 * 86400
    return max(floor, min(int(record_ttl_s) if record_ttl_s > 0 else floor, seven_days))


async def resolve_bip353(
    user_at_domain: str,
    *,
    timeout_s: float = 15.0,
) -> Bip353Result:
    """Resolve a Lightning-address-style ``user@domain`` to a BOLT 12
    offer (and any companion BIP-21 fields) via DoH over Tor.

    Caches the result aggressively per :func:`_cache_ttl_for`. Cache
    hits return without any egress.

    Raises a subclass of :class:`Bip353Error` on every failure mode:

    * :class:`Bip353SyntaxError` — input is not a valid Lightning
      address.
    * :class:`Bip353DoHError` — HTTPS request to the DoH provider
      failed.
    * :class:`Bip353DnssecError` — the response was not DNSSEC-
      authenticated (``AD=0``). we refuse unauthenticated
      answers because an upstream that doesn't validate could
      forge any user→offer mapping.
    * :class:`Bip353DnsError` — the response is malformed, carries
      an RCODE, or has zero TXT answers.
    * :class:`Bip353ParseError` — the TXT content isn't a parseable
      BIP-21 URI with at least one payable handle.
    """
    user, domain = _split_user_at_domain(user_at_domain)
    dns_name = _make_dns_name(user, domain)

    cached = await _CACHE.get(dns_name)
    if cached is not None:
        return cached

    doh_url = (settings.anonymize_bip353_doh_endpoint or "").strip()
    if not doh_url:
        raise Bip353DoHError("ANONYMIZE_BIP353_DOH_ENDPOINT is unset")
    # Require an encrypted transport. The query carries the user→offer
    # mapping; an ``http://`` endpoint would expose it (and the DNS answer)
    # in cleartext over the Tor exit. A ``.onion`` host gets its
    # authentication + encryption from the Tor circuit itself.
    _scheme, _, _rest = doh_url.partition("://")
    _host = _rest.split("/", 1)[0].split("@", 1)[-1].split(":", 1)[0]
    if _scheme.lower() != "https" and not _host.endswith(".onion"):
        raise Bip353DoHError("ANONYMIZE_BIP353_DOH_ENDPOINT must use https:// (or a .onion host)")

    socks_host = resolve_socks_host()
    socks_port = resolve_socks_port(_CALL_SITE)

    query_id = int.from_bytes(secrets.token_bytes(2), "big")
    body = _build_dns_txt_query(dns_name, query_id=query_id)

    try:
        async with get_anonymize_client(
            call_site=_CALL_SITE,
            socks_host=socks_host,
            socks_port=socks_port,
            timeout_s=timeout_s,
        ) as client:
            response = await request_capped(
                client,
                "POST",
                doh_url,
                content=body,
                headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                },
            )
    except ResponseTooLargeError as exc:
        raise Bip353DoHError(f"DoH response too large: {exc}") from exc
    except httpx.HTTPError as exc:
        raise Bip353DoHError(f"DoH HTTPS request failed: {exc}") from exc

    if response.status_code != 200:
        # Don't include the response body in the error — the body
        # may be the DNS error wire-form, which is fine; just keep
        # the message short and consistent.
        raise Bip353DoHError(f"DoH provider returned HTTP {response.status_code}")
    ctype = (response.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if ctype != "application/dns-message":
        # Some DoH providers also accept GET ?dns=, but the response
        # MUST carry the DNS message media type per RFC 8484. Refuse
        # anything else — it's almost certainly an HTML error page.
        raise Bip353DoHError(f"DoH response had unexpected Content-Type {ctype!r}")
    raw = response.content
    txts, ad_flag = _parse_dns_txt_response(raw, expect_qid=query_id)
    if not ad_flag:
        raise Bip353DnssecError(
            f"DoH response for {dns_name!r} did not set AD; refusing "
            f"unauthenticated answer (upstream resolver did not "
            f"validate the DNSSEC chain)"
        )
    # BIP-353: there MUST be exactly one TXT record. Multiple
    # records are a misconfiguration on the publisher's side; we
    # refuse rather than guess which one to use.
    if len(txts) != 1:
        raise Bip353DnsError(f"BIP-353 expects exactly one TXT record; got {len(txts)}")
    txt_content, record_ttl = txts[0]

    result = _parse_bip21_uri(txt_content)
    result = Bip353Result(
        user_at_domain=user_at_domain.strip().lower(),
        dns_name=dns_name,
        bolt12_offer=result.bolt12_offer,
        bolt11_invoice=result.bolt11_invoice,
        onchain_address=result.onchain_address,
        raw_txt=result.raw_txt,
    )
    await _CACHE.put(dns_name, result, ttl_s=_cache_ttl_for(record_ttl))
    return result


__all__ = [
    "Bip353DnsError",
    "Bip353DnssecError",
    "Bip353DoHError",
    "Bip353Error",
    "Bip353ParseError",
    "Bip353Result",
    "Bip353SyntaxError",
    "_build_dns_txt_query",
    "_cache_ttl_for",
    "_make_dns_name",
    "_parse_bip21_uri",
    "_parse_dns_txt_response",
    "_split_user_at_domain",
    "reset_cache_for_tests",
    "resolve_bip353",
]
