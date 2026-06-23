# SPDX-License-Identifier: MIT
"""BIP-353 — Human-Readable Names for Bitcoin Payments.

Per BIP-353 a payment-handle name like ``alice@example.com`` resolves
to a TXT record at:

    alice.user._bitcoin-payment.example.com.

The TXT value is a single ``bitcoin:`` URI containing query
parameters such as ``lno=lno1...`` (BOLT 12 offer) and/or
``lightning=lnbc...`` (BOLT 11 invoice). DNSSEC validation is
*required* — an unsigned answer must be rejected.

This module is split into two halves:

* :func:`build_zone_record` — emit the RFC1035 zone-file fragment a
  domain operator would publish for a given offer + name.
* :func:`resolve_payment_handle` — perform a DNSSEC-validating TXT
  lookup and parse the resulting ``bitcoin:`` URI back into its
  components.

DNSSEC enforcement: ``dns.resolver.Resolver`` does not natively
validate RRSIGs, so we use the lower-level :func:`dns.message.make_query`
flow with ``want_dnssec=True`` and verify the response's ``ad``
(Authenticated Data) flag, which the resolver sets only when its
upstream did the cryptographic validation. Operators MUST point at a
validating resolver (e.g. unbound, knot-resolver) for this guarantee
to hold; pointing at an unvalidating resolver is a misconfiguration.

Hardened transport:

* All queries go over TCP. UDP DNS is forgeable on-path even with
  DNSSEC against resolvers we don't trust beyond their AD flag, and
  BIP-353 names rarely fit a 512-byte UDP datagram once RRSIGs are
  attached. TCP also moots the truncation-retry race.
* The resolver iterates **every** configured nameserver before
  giving up on transient timeouts/network errors.
* On first call we probe ``dnssec-failed.org``: a correctly
  validating resolver must return SERVFAIL (or at minimum AD=0).
  A resolver that answers NOERROR+AD=1 is a "rubber-stamp"
  validator and we refuse to use it. This catches misconfigured
  homelab resolvers + ISPs that intercept :53 traffic. Configurable
  via :attr:`Settings.bolt12_bip353_validate_resolver`.

Threat model: a network attacker who can MITM DNS *without* breaking
DNSSEC cannot spoof a payment handle. An attacker who controls the
resolver itself (i.e. the ad bit is forged) can — so the resolver
must be trusted.
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.nameserver
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

logger = logging.getLogger(__name__)

# RFC 5891 LDH ASCII subset; we additionally allow ``_`` because some
# practical deployments use it. The label MUST NOT begin with ``-``.
_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,62}[a-z0-9_])?$")


@dataclass(frozen=True, slots=True)
class PaymentHandle:
    """Components of a parsed ``user@domain`` BIP-353 handle."""

    user: str
    domain: str

    @classmethod
    def parse(cls, handle: str) -> "PaymentHandle":
        """Validate and split a ``user@domain`` payment-handle name.

        Both parts are lower-cased and must each match the LDH-ASCII
        label form (RFC 5891). Internationalised handles (UTF-8 user
        portion) are rejected — operators must IDNA-encode first.
        """
        h = handle.strip().lower()
        if h.startswith("₿"):
            # Some BIP-353 deployments prefix with `₿` for branding.
            h = h[len("₿") :]
        if "@" not in h:
            raise ValueError("payment handle must contain '@'")
        user, _, domain = h.partition("@")
        if not _LABEL_RE.match(user):
            raise ValueError(f"invalid user label: {user!r}")
        for part in domain.split("."):
            if not part or not _LABEL_RE.match(part):
                raise ValueError(f"invalid domain label: {part!r}")
        return cls(user=user, domain=domain)

    @property
    def fqdn(self) -> str:
        """The exact DNS name to query for this handle."""
        return f"{self.user}.user._bitcoin-payment.{self.domain}."


@dataclass(frozen=True, slots=True)
class ResolvedHandle:
    """Result of a successful BIP-353 resolution."""

    handle: PaymentHandle
    """The handle that was queried."""

    bitcoin_uri: str
    """The full ``bitcoin:?...`` URI extracted from the TXT record."""

    offer: str | None
    """``lno`` query-param if present (BOLT 12 offer)."""

    bolt11: str | None
    """``lightning`` query-param if present (BOLT 11 invoice)."""

    on_chain: str | None
    """The bare on-chain address (URI path) if present."""


def build_zone_record(
    handle: PaymentHandle,
    *,
    offer: str | None = None,
    bolt11: str | None = None,
    on_chain: str | None = None,
    ttl: int = 3600,
) -> str:
    """Build the RFC1035 zone-file fragment for a payment-handle.

    Output looks like::

        alice.user._bitcoin-payment.example.com. 3600 IN TXT "bitcoin:?lno=lno1..."

    The string is intentionally single-line for easy concat into a
    larger zone file. Long TXT values are *not* split across multiple
    chunks — callers are expected to feed this into a zone tool that
    handles ``"..."`` chunking on emit (most do).

    At least one of ``offer``, ``bolt11``, ``on_chain`` must be
    supplied; otherwise the URI would carry no payment information.
    """
    if not (offer or bolt11 or on_chain):
        raise ValueError("at least one of offer/bolt11/on_chain is required")

    params: list[str] = []
    if offer:
        params.append(f"lno={offer}")
    if bolt11:
        params.append(f"lightning={bolt11}")

    path = on_chain or ""
    query = "&".join(params)
    uri = "bitcoin:" + path + (f"?{query}" if query else "")

    # TXT values are wrapped in double-quotes per RFC1035 zone format;
    # we conservatively reject embedded quotes since BOLT 12 / BOLT 11
    # alphabets never contain them — easier than inventing an escape.
    if '"' in uri:
        raise ValueError("payment URI contains a double-quote, refusing to emit")
    return f'{handle.fqdn} {ttl} IN TXT "{uri}"'


def parse_payment_uri(uri: str) -> tuple[str | None, str | None, str | None]:
    """Decompose a ``bitcoin:`` URI into ``(on_chain, offer, bolt11)``.

    Returns ``(None, None, None)`` if the scheme is wrong; raises
    :class:`ValueError` only when the URI is structurally malformed.
    """
    if not uri.startswith("bitcoin:"):
        raise ValueError("payment URI must start with 'bitcoin:'")
    parsed = urlsplit(uri)
    on_chain = parsed.path or None
    qs = parse_qs(parsed.query, keep_blank_values=False)
    offer = qs.get("lno", [None])[0]
    bolt11 = qs.get("lightning", [None])[0]
    return on_chain, offer, bolt11


def resolve_payment_handle(
    handle: str,
    *,
    require_dnssec: bool = True,
    timeout: float = 5.0,
    resolver: dns.resolver.Resolver | None = None,
) -> ResolvedHandle:
    """Resolve a BIP-353 payment handle to a :class:`ResolvedHandle`.

    By default DNSSEC validation is required: the answer's ``ad``
    flag must be set, otherwise we raise. Pass
    ``require_dnssec=False`` only for development against an
    unvalidated resolver — *never* in production paths.

    Args:
        handle: ``user@domain`` form. ``₿`` prefix is also accepted.
        require_dnssec: enforce the ``ad`` flag on the response.
        timeout: per-query timeout in seconds.
        resolver: override the default resolver — useful for tests.

    Raises:
        ValueError: malformed handle / multiple TXT records / no
          valid bitcoin URI.
        dns.resolver.NXDOMAIN: name does not exist.
        dns.exception.Timeout: query timed out.
        Bolt12Bip353InsecureError: DNSSEC required but ``ad`` not set.
    """
    h = PaymentHandle.parse(handle)
    res = resolver or dns.resolver.Resolver()
    res.lifetime = timeout

    # Use raw query so we can read the response flags directly. The
    # higher-level `Resolver.resolve` swallows the AD flag.
    qname = dns.name.from_text(h.fqdn)
    request = dns.message.make_query(qname, dns.rdatatype.TXT, want_dnssec=require_dnssec)

    # Probe for a rubber-stamp validator ONCE per resolver instance
    # (cached on the module). Off in tests / when the operator
    # explicitly opts out.
    if require_dnssec:
        from app.core.config import settings as _settings

        if _settings.bolt12_bip353_validate_resolver:
            _ensure_resolver_validates_dnssec(res, timeout=timeout)

    response = _query_with_failover(request, res.nameservers, timeout)

    if response.rcode() != dns.rcode.NOERROR:
        raise dns.resolver.NXDOMAIN(
            qnames=[qname],
            responses={qname: response},
        )

    if require_dnssec and not (response.flags & dns.flags.AD):
        raise Bolt12Bip353InsecureError(
            f"BIP-353 resolution of {h.fqdn} returned AD=0; configure a DNSSEC-validating resolver"
        )

    txt_rrset = None
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.TXT and rrset.name == qname:
            txt_rrset = rrset
            break
    if txt_rrset is None:
        raise ValueError(f"no TXT record at {h.fqdn}")

    # BIP-353 specifies exactly one bitcoin: URI per name.
    if len(txt_rrset) != 1:
        raise ValueError(f"expected exactly one TXT record at {h.fqdn}, got {len(txt_rrset)}")
    rdata = next(iter(txt_rrset))
    # TXT records are sequences of byte strings; concatenate per
    # RFC 6763.
    raw = b"".join(rdata.strings).decode("ascii", errors="strict")
    if not raw.startswith("bitcoin:"):
        raise ValueError(f"TXT at {h.fqdn} does not contain a bitcoin: URI")

    on_chain, offer, bolt11 = parse_payment_uri(raw)
    if not (offer or bolt11 or on_chain):
        raise ValueError(f"bitcoin URI at {h.fqdn} has no payment information")

    return ResolvedHandle(
        handle=h,
        bitcoin_uri=raw,
        offer=offer,
        bolt11=bolt11,
        on_chain=on_chain,
    )


class Bolt12Bip353InsecureError(RuntimeError):
    """DNSSEC validation required but the response's ``AD`` flag is 0."""


# ── Hardened transport helpers ──────────────────────────────


# Per-process cache of the validation-probe outcome, keyed on the
# tuple of upstream nameservers. Cleared whenever ``Resolver``
# instances point at a different upstream. Guarded by a lock so
# concurrent first-callers don't all probe in parallel.
_validated_resolvers: set[tuple[str | dns.nameserver.Nameserver, ...]] = set()
_validation_lock = threading.Lock()


def _query_with_failover(
    request: dns.message.Message,
    nameservers: Sequence[str | dns.nameserver.Nameserver],
    timeout: float,
) -> dns.message.Message:
    """Send ``request`` to each nameserver in turn over TCP.

    UDP is intentionally not used: BIP-353 answers carry RRSIGs that
    routinely exceed the 512-byte UDP cap, and a hostile on-path
    actor can flip the TC bit to force a re-query. Iterating all
    upstreams matters for resolvers configured with multiple
    nameservers (``/etc/resolv.conf`` style) so a single down
    upstream doesn't break payments.
    """
    if not nameservers:
        raise RuntimeError("BIP-353 resolver has no upstream nameservers configured")
    last_exc: Exception | None = None
    for ns in nameservers:
        where = ns if isinstance(ns, str) else ns.answer_nameserver()
        try:
            return dns.query.tcp(request, where, timeout=timeout)
        except (dns.exception.Timeout, OSError, dns.query.UnexpectedSource) as exc:
            logger.warning("bip353: nameserver %s failed (%s); trying next", ns, exc)
            last_exc = exc
            continue
    assert last_exc is not None  # nameservers non-empty -> we tried at least one
    raise last_exc


def _ensure_resolver_validates_dnssec(res: dns.resolver.Resolver, *, timeout: float) -> None:
    """Detect rubber-stamp resolvers via ``dnssec-failed.org``.

    A correctly validating resolver MUST refuse to return data for
    ``dnssec-failed.org`` (returns SERVFAIL or at least AD=0).
    A resolver that answers NOERROR+AD=1 is forging the AD flag
    and we must not trust it for BIP-353 lookups — an attacker who
    breaks DNS for *any* zone could then forge payment handles.

    Probe is per-process and per-(nameserver-tuple); subsequent
    lookups against the same upstream skip it.
    """
    ns_key = tuple(res.nameservers)
    if ns_key in _validated_resolvers:
        return
    with _validation_lock:
        if ns_key in _validated_resolvers:
            return
        probe = dns.message.make_query(
            dns.name.from_text("dnssec-failed.org."),
            dns.rdatatype.A,
            want_dnssec=True,
        )
        try:
            response = _query_with_failover(probe, list(res.nameservers), timeout)
        except Exception as exc:  # noqa: BLE001
            # The probe is the only thing standing between us and a
            # rubber-stamp resolver: a resolver that forges AD=1 also
            # forges it for the real lookup, so an unrun probe gives no
            # safety. Refuse the lookup and leave ``ns_key`` unrecorded
            # so a later attempt re-probes once the probe domain is
            # reachable. Operators whose network blocks the probe domain
            # opt out via ``BOLT12_BIP353_VALIDATE_RESOLVER=false``,
            # accepting the rubber-stamp risk.
            logger.warning("bip353: resolver-validation probe failed (%s); refusing the lookup", exc)
            raise Bolt12Bip353InsecureError(
                "BIP-353 resolver-validation probe could not complete "
                f"({exc}). The probe is required to detect a resolver "
                "that forges the DNSSEC AD flag; without it the handle "
                "lookup is refused. Ensure the resolver can reach "
                "dnssec-failed.org, or set "
                "BOLT12_BIP353_VALIDATE_RESOLVER=false to disable this "
                "check."
            ) from exc
        rubber_stamp = (
            response.rcode() == dns.rcode.NOERROR and bool(response.flags & dns.flags.AD) and len(response.answer) > 0
        )
        if rubber_stamp:
            raise Bolt12Bip353InsecureError(
                "BIP-353 upstream resolver "
                f"{res.nameservers[0]} answered NOERROR+AD=1 for "
                "dnssec-failed.org \u2014 it is forging the AD flag and "
                "MUST NOT be trusted. Configure a validating "
                "resolver (unbound / knot-resolver) or set "
                "BOLT12_BIP353_VALIDATE_RESOLVER=false to disable "
                "this check."
            )
        _validated_resolvers.add(ns_key)


__all__ = [
    "Bolt12Bip353InsecureError",
    "PaymentHandle",
    "ResolvedHandle",
    "build_zone_record",
    "parse_payment_uri",
    "resolve_payment_handle",
]
