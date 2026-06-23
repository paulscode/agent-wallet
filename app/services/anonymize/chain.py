# SPDX-License-Identifier: MIT
"""Private chain-backend guard + dedicated anonymize chain client.

Privacy tiers above ``weak`` require a private chain backend
and refuse destination-address chain queries. A public backend
(``ANONYMIZE_ALLOW_PUBLIC_CHAIN_BACKEND``) must be explicitly opted in and
caps the session at ``weak``. A co-resident / private-network backend
(``ANONYMIZE_TRUSTED_LOCAL_CHAIN_BACKEND``, honored only when every chain
host is actually local) is exempt from the onion-only egress gate WITHOUT
the cap — a local backend has no third-party observer to leak to.

The anonymize stack owns a *separate* chain-backend
connection from the wallet-wide one (``mempool_fee_service``) so the
backend operator cannot correlate anonymize lookups with general
wallet activity that shares the host.

This module exposes:

* :class:`ChainBackendKind` — enum of supported backend kinds.
* :func:`resolve_chain_backend_kind` — read the live config and
  classify the configured backend as private, public, or unset.
* :func:`assert_chain_backend_acceptable_for_anonymize` — refuse
  to admit anonymize queries against a public backend unless the
  operator has explicitly opted in.
* :func:`is_destination_query_allowed` — always False; the anonymize
  stack must NOT query the chain by destination address.
* :func:`assert_txid_query_allowed` — guard the only allowed query
  shape (txid-only confirmation polls).

The concrete ``httpx.AsyncClient`` / ``electrum-client`` factories live
with the chain-subscription call sites; this module is the guard layer
that every such call site routes through.
"""

from __future__ import annotations

import enum
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.core.config import settings

# Hostname suffixes that are never public FQDNs: StartOS service
# hostnames (``*.embassy`` / ``*.startos``), mDNS (``*.local``), and the
# common private-LAN conventions. A co-resident backend reached at one of
# these names cannot leak queries off-host the way a clearnet explorer can.
_LOCAL_HOST_SUFFIXES = (".embassy", ".startos", ".local", ".internal", ".lan")


def _host_is_local(url: str) -> bool:
    """True iff ``url``'s host is loopback, private, or a non-public name.

    Covers loopback / RFC1918 / link-local / ULA IP literals, ``localhost``,
    the :data:`_LOCAL_HOST_SUFFIXES`, and single-label hostnames (e.g. a
    docker service name like ``electrs``), which cannot resolve on the
    public internet. An ``.onion`` host is private but NOT "local" — it is
    handled by the onion-only path, so it returns False here.
    """
    raw = (url or "").strip()
    if not raw:
        return False
    parsed = urlparse(raw if "://" in raw else "tcp://" + raw)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return ip.is_loopback or ip.is_private or ip.is_link_local
    if host == "localhost":
        return True
    if host.endswith(_LOCAL_HOST_SUFFIXES):
        return True
    # A dot-less single label is a container/LAN name, not a public FQDN.
    return "." not in host


def is_trusted_local_chain_backend() -> bool:
    """True iff the configured chain backend is a trusted local one.

    Requires the explicit ``ANONYMIZE_TRUSTED_LOCAL_CHAIN_BACKEND`` opt-in
    AND that every configured chain endpoint (electrum and/or mempool)
    resolves to a local host (:func:`_host_is_local`). The host check makes
    the opt-in inert on a genuinely public backend, so it cannot be used to
    silently relax a remote endpoint.

    When True, the backend is exempt from the onion-only egress gate and the
    scorer does NOT apply the public-chain-backend ``weak`` cap: a co-resident
    backend has no third-party observer, so it is strictly more private than a
    Tor-routed public one.
    """
    if not settings.anonymize_trusted_local_chain_backend:
        return False
    urls = [
        u
        for u in (
            (settings.lnd_electrum_url or "").strip(),
            (settings.lnd_mempool_url or "").strip(),
        )
        if u
    ]
    if not urls:
        return False
    return all(_host_is_local(u) for u in urls)


class ChainBackendKind(enum.Enum):
    """Classification of the configured chain backend.

    ``UNSET`` means no chain backend is configured at all (a fresh
    deployment); we treat it the same as ``PUBLIC_HTTP`` for the
    anonymize-side acceptance check (refuse unless opted in).
    """

    UNSET = "unset"
    PRIVATE_ELECTRUM = "private_electrum"
    PRIVATE_ELECTRUM_ONION = "private_electrum_onion"
    PUBLIC_HTTP = "public_http"


class ChainBackendError(RuntimeError):
    """Raised when the anonymize stack cannot use the configured backend."""


def resolve_chain_backend_kind() -> ChainBackendKind:
    """Read live config and classify the configured backend."""
    electrum = (settings.lnd_electrum_url or "").strip()
    if electrum:
        # Electrs / electrum is private when self-hosted; an
        # ``.onion`` URL is *de facto* private (the operator stood up
        # a hidden service for their own use).
        if ".onion" in electrum.lower():
            return ChainBackendKind.PRIVATE_ELECTRUM_ONION
        return ChainBackendKind.PRIVATE_ELECTRUM
    if settings.lnd_mempool_url:
        return ChainBackendKind.PUBLIC_HTTP
    return ChainBackendKind.UNSET


@dataclass(frozen=True)
class ChainBackendStatus:
    """Result of an anonymize-side chain-backend acceptance check."""

    kind: ChainBackendKind
    accepted: bool
    caps_tier_at_weak: bool
    reason: str | None  # human-readable when not accepted


def assert_chain_backend_acceptable_for_anonymize() -> ChainBackendStatus:
    """Gate anonymize chain queries against the active backend.

    Returns a :class:`ChainBackendStatus` describing the outcome:

    * Private electrs / electrum — accepted, no tier cap.
    * Public Mempool HTTP — accepted ONLY when
      ``ANONYMIZE_ALLOW_PUBLIC_CHAIN_BACKEND=true`` (and the resulting
      session caps at ``weak`` via the scorer hard-cap).
    * Unset — refused unless the operator opts in to the public
      fallback explicitly.

    Refusal returns ``accepted=False``; the orchestrator surfaces the
    error to the dashboard. We do NOT raise here so the health-card
    can render the boolean status without an exception path.
    """
    kind = resolve_chain_backend_kind()
    if kind in (
        ChainBackendKind.PRIVATE_ELECTRUM,
        ChainBackendKind.PRIVATE_ELECTRUM_ONION,
    ):
        return ChainBackendStatus(kind=kind, accepted=True, caps_tier_at_weak=False, reason=None)
    # A trusted local backend (e.g. a co-resident Mempool HTTP backend with
    # no electrum) is accepted with no cap — there is no third party to leak
    # to. Checked before the public opt-in so the two flags don't both apply.
    if is_trusted_local_chain_backend():
        return ChainBackendStatus(kind=kind, accepted=True, caps_tier_at_weak=False, reason=None)
    # Public / unset paths.
    if settings.anonymize_allow_public_chain_backend:
        return ChainBackendStatus(
            kind=kind,
            accepted=True,
            caps_tier_at_weak=True,
            reason=(
                "public chain backend opted-in via ANONYMIZE_ALLOW_PUBLIC_CHAIN_BACKEND — session tier capped at weak"
            ),
        )
    return ChainBackendStatus(
        kind=kind,
        accepted=False,
        caps_tier_at_weak=True,
        reason=(
            "anonymize requires a private chain backend; configure "
            "LND_ELECTRUM_URL (preferably .onion) or set "
            "ANONYMIZE_ALLOW_PUBLIC_CHAIN_BACKEND=true to accept "
            "the weak-tier cap"
        ),
    )


# ────────────────────────────────────────────────────────────────────
# Per-call query-shape guards.
# ────────────────────────────────────────────────────────────────────


# Bitcoin txid: 64 lowercase hex characters.
_TXID_RE = re.compile(r"^[0-9a-f]{64}$")


def is_destination_query_allowed() -> bool:
    """Always False forbids destination-address chain queries."""
    return False


def assert_txid_query_allowed(txid: str) -> str:
    """Validate a txid for an anonymize-side confirmation poll.

    Refuses anything that isn't a 64-char hex txid. Returns the
    canonical lowercase form.
    """
    if not isinstance(txid, str):
        raise ChainBackendError("txid must be a string")
    canonical = txid.strip().lower()
    if not _TXID_RE.match(canonical):
        raise ChainBackendError("not a valid 64-char hex txid")
    return canonical


# --------------------------------------------------------------------
# Dedicated chain-backend client
# factories with first-connect jitter.
# --------------------------------------------------------------------


@dataclass(frozen=True)
class ChainClientSpec:
    """Configuration for one chain-backend connection.

    The orchestrator constructs an actual ``httpx.AsyncClient`` /
    electrum-client from this spec; the spec itself is what the
    factories return so the connection-pool isolation property is
    preserved (each call site that requests a client gets a
    fresh spec, never a shared connection).
    """

    purpose: str  # "general" | "anonymize"
    socks_listener: str  # SOCKS-listener key in TOR_CONTROL_SOCKS_PORTS
    backend_url: str
    first_connect_jitter_s: int  # 0 for general; non-zero for anonymize


def _resolve_backend_url() -> str:
    """Return the configured chain-backend URL (electrum or mempool)."""
    return (settings.lnd_electrum_url or "").strip() or (settings.lnd_mempool_url or "").strip()


def get_general_chain_client_spec() -> ChainClientSpec:
    """Wallet-wide chain queries (mempool fee oracle, etc.)."""
    return ChainClientSpec(
        purpose="general",
        socks_listener="chain_backend_general",
        backend_url=_resolve_backend_url(),
        first_connect_jitter_s=0,
    )


def get_anonymize_chain_client_spec() -> ChainClientSpec:
    """Anonymize-only chain queries (reorg sub, claim broadcast).

    The first connection is jittered by
    ``Uniform(0, ANONYMIZE_CHAIN_CLIENT_FIRST_CONNECT_JITTER_S)`` so a
    passive observer cannot pair this client with the general one
    by simultaneous boot-time circuit establishment.
    """
    return ChainClientSpec(
        purpose="anonymize",
        socks_listener="chain_backend_anonymize",
        backend_url=_resolve_backend_url(),
        first_connect_jitter_s=int(settings.anonymize_chain_client_first_connect_jitter_s),
    )


def assert_listeners_distinct(
    general: ChainClientSpec,
    anonymize: ChainClientSpec,
) -> None:
    """Startup refuses same-listener configuration.

    The two clients MUST point at different SOCKS listeners so the
    chain-backend operator's view of anonymize activity is isolated
    from general wallet activity (residual #19).
    """
    if general.socks_listener == anonymize.socks_listener:
        raise ChainBackendError(
            "anonymize and general chain clients must use distinct SOCKS "
            f"listeners; both currently target {general.socks_listener!r}. "
            "Configure ANONYMIZE_TOR_SOCKS_PORTS so "
            "chain_backend_general and chain_backend_anonymize map to "
            "separate ports."
        )


def sample_first_connect_jitter_s(spec: ChainClientSpec) -> float:
    """Pure helper: sample the first-connect jitter.

    The orchestrator sleeps for this many seconds *before* the
    anonymize client opens its first connection. The general client
    has no jitter (its boot-time connection happens whenever the
    wallet's other startup paths need it).
    """
    if spec.first_connect_jitter_s <= 0:
        return 0.0
    import secrets

    return secrets.SystemRandom().uniform(0.0, float(spec.first_connect_jitter_s))


__all__ = [
    "ChainBackendKind",
    "ChainBackendError",
    "ChainBackendStatus",
    "ChainClientSpec",
    "resolve_chain_backend_kind",
    "is_trusted_local_chain_backend",
    "assert_chain_backend_acceptable_for_anonymize",
    "is_destination_query_allowed",
    "assert_txid_query_allowed",
    "get_general_chain_client_spec",
    "get_anonymize_chain_client_spec",
    "assert_listeners_distinct",
    "sample_first_connect_jitter_s",
]
