# SPDX-License-Identifier: MIT
"""
Application configuration — loaded from environment variables.

All LND credentials and secrets are loaded from env vars (never hardcoded).
The .env file is loaded by pydantic-settings and must never be committed.
"""

import base64
import json
import logging
import warnings
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings


def _parse_str_list(val: str) -> list[str]:
    """Parse a string into a list: accepts JSON arrays or comma-separated values."""
    val = val.strip()
    if not val:
        return []
    if val.startswith("["):
        return json.loads(val)  # type: ignore[no-any-return]
    return [s.strip() for s in val.split(",") if s.strip()]


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── Application ──
    secret_key: str  # Required — no default; generate with: python -c 'import secrets; print(secrets.token_hex(32))'
    secret_key_previous: str = (
        ""  # Previous SECRET_KEY for key rotation — set when rotating to allow decryption of old data
    )
    # At-rest field encryption uses a per-field random salt (the v2
    # format). When True, decryption also accepts the older static-salt
    # format at read time; leave False so the weaker derivation is never
    # reachable from runtime request paths. Re-encryption (used by the
    # field-format upgrade migration) reads static-salt rows regardless,
    # so a deployment that still holds them can always migrate forward.
    allow_static_salt_field_decryption: bool = False
    debug: bool = False
    # When True, long-lived background tasks short-circuit at startup so
    # unit tests don't have to mock every interval setting or fight
    # leaked asyncio tasks. Set via the TESTING env var in
    # tests/conftest.py. Production never sets this (defaults False).
    testing: bool = False
    log_level: str = "info"
    log_format: str = "text"  # "text" or "json"
    api_host: str = "127.0.0.1"  # Use 0.0.0.0 only inside Docker or behind a reverse proxy
    api_port: int = 8100
    enable_docs: bool = False  # Serve /docs, /redoc, /openapi.json — opt in with ENABLE_DOCS=true
    enable_hsts: bool = True  # Strict-Transport-Security — disable only if NOT behind TLS
    cookie_secure: bool = True  # Set Secure flag on auth cookies — set False ONLY for local plain-HTTP dev

    # ── Database ──
    database_url: str  # Required — no default; e.g. postgresql+asyncpg://user:pass@host:5432/dbname
    database_require_ssl: bool = False  # Require SSL for non-localhost database connections

    # ── Redis ──
    redis_url: str = "redis://redis:6379/0"

    # ── LND Node Connection ──
    lnd_rest_url: str = "https://localhost:8080"
    lnd_macaroon_hex: str = ""
    lnd_tls_verify: bool = True
    lnd_tls_cert: str = ""  # base64-encoded TLS cert
    lnd_tor_proxy: str = ""  # socks5://tor-proxy:9050

    # ── Mempool Explorer ──
    lnd_mempool_url: str = "https://mempool.space"
    mempool_tls_verify: bool = True  # Set to False for self-hosted instances with self-signed certs
    # Operator-supplied PEM (filesystem path, base64-encoded PEM, or raw PEM
    # text) to pin the mempool TLS trust root. Prefer this over
    # MEMPOOL_TLS_VERIFY=false for self-hosted instances with self-signed
    # certs — disabling verification with no pin allows on-path attackers to
    # tamper with fee/chain-tip/tx-status responses.
    mempool_ca_cert: str = ""
    mempool_allow_internal: bool = (
        False  # Set to True only when LND_MEMPOOL_URL is an explicit self-hosted internal address
    )
    # Public mempool URL used by the dashboard UI for transaction
    # links. Leave empty to derive from ``lnd_mempool_url`` when it's
    # clearnet-reachable, falling back to ``https://mempool.space``
    # for onion or unset configurations. Set explicitly when you want
    # UI links to point at a different host than the server-side
    # fee-fetching URL (e.g. onion server-side, clearnet UI).
    mempool_public_url: str = ""

    # ── Chain backend (electrs / mempool) ──
    # "auto"     — use Electrum if LND_ELECTRUM_URL is set, otherwise Mempool HTTP.
    #              When both are configured, Electrum is primary and Mempool HTTP is
    #              the fallback used when the Electrum breaker opens. Default.
    # "mempool"  — force the Mempool HTTP backend (ignoring LND_ELECTRUM_URL).
    # "electrum" — force the Electrum backend; require LND_ELECTRUM_URL; no HTTP
    #              fallback. Startup fails loud if the connection can't come up.
    chain_backend: Literal["auto", "mempool", "electrum"] = "auto"
    # Route clearnet chain-backend traffic (mempool HTTP / Electrum) through
    # the Tor SOCKS proxy. ``.onion`` and ``.local`` hosts always use the
    # proxy regardless of this setting.
    #   "true"  — always proxy, resolving the host remotely at the proxy so
    #             the queried addresses and the host IP are never exposed on
    #             a clearnet path. Requires LND_TOR_PROXY.
    #   "false" — connect to clearnet hosts directly.
    #   "auto"  — proxy clearnet hosts iff LND_REST_URL is a ``.onion`` host
    #             (i.e. the deployment is already Tor-only). Default.
    chain_backend_force_tor: Literal["auto", "true", "false"] = "auto"
    # Electrum/electrs endpoint. Examples:
    #   tcp://localhost:50001         — same-host plaintext (Start9 default port)
    #   ssl://electrs.local:50002     — LAN over TLS (self-signed OK with verify=False)
    #   tcp://abcd…xyz.onion:50001    — hidden-service plaintext (recommended for Start9 remote)
    #   ssl://abcd…xyz.onion:50002    — hidden-service over TLS (rare; .onion already authenticated)
    # Empty string disables the Electrum backend entirely.
    lnd_electrum_url: str = ""
    lnd_electrum_tls_verify: bool = True  # Set False for self-signed Start9 certs
    lnd_electrum_ca_cert: str = ""  # Optional PEM (path or base64-encoded contents)
    lnd_electrum_ping_interval_s: float = 30.0
    lnd_electrum_request_timeout_s: float = 8.0
    lnd_electrum_connect_timeout_s: float = 10.0
    lnd_electrum_max_subscriptions: int = 256

    # Background keepalive cadence for the LND REST endpoint. A
    # lightweight ``GET /v1/getinfo`` runs every N seconds to keep
    # at least one warm Tor circuit to LND's hidden service ready
    # for latency-sensitive callers (e.g. a BOLT-12 invreq responder
    # racing a payer's invoice-request timeout). Set to 0 to disable.
    lnd_keepalive_interval_s: float = 60.0

    # ── Safety Limits ──
    lnd_max_payment_sats: int = 10_000
    lnd_rate_limit_sats: int = 100_000
    lnd_rate_limit_window_seconds: int = 3600
    lnd_velocity_max_txns: int = 5
    lnd_velocity_window_seconds: int = 900
    rate_limit_fail_policy: str = "closed"  # "open" or "closed" — behaviour when Redis is unavailable
    # Global SlowAPI default limit applied per-client-IP across all
    # routes that don't declare their own ``@limiter.limit(...)``.
    # Authenticated dashboard sessions naturally fan out many small
    # polls (balances, sessions, channels, fees, etc.) so the upstream
    # 60/minute default is uncomfortably tight in practice. Bumped to
    # 240/minute; tighter per-endpoint caps still apply to sensitive
    # routes (login, sign, payments, CSRF-protected mutations) via
    # explicit decorators.
    slowapi_default_limit: str = "240/minute"
    api_key_max_ttl_days: int = 365  # Maximum API key lifetime in days (enforced server-side)
    # Per-API-key in-flight request cap. 0 disables the cap.
    max_concurrent_requests_per_key: int = 10
    # Shutdown drain window (seconds). New requests get 503 once
    # shutdown begins; in-flight requests have up to this long to
    # finish before the worker terminates.
    shutdown_drain_seconds: float = 30.0

    # HTTP-client recycle interval (seconds). Periodically tears
    # down upstream HTTP clients (LND, Boltz, mempool) so any leaked
    # sockets / stale TLS sessions / connection-pool wedges are
    # forcibly cleaned. Set to 0 to disable. Default: 30 minutes.
    http_client_recycle_seconds: float = 1800.0

    # Ceiling (bytes) on the body read from outbound calls to
    # operator-configured / signed-registry endpoints (Boltz, the DoH
    # resolver, the chain backend) via ``app.core.http_limits``. The body
    # is streamed and refused once it crosses this size so a misbehaving
    # upstream cannot drive memory exhaustion. The recipient-supplied LNURL
    # path keeps its own tighter ``lnurl_max_response_bytes`` cap. Set to 0
    # to disable. Default: 1 MB — far above any API/JSON response these
    # endpoints return.
    outbound_max_response_bytes: int = 1_000_000

    # ── Boltz Exchange ──
    boltz_api_url: str = "https://api.boltz.exchange/v2"
    boltz_onion_url: str = "http://boltzzzbnus4m7mta3cxmflnps4fp7dueu2tgurstbvrbt6xswzcocyd.onion/api/v2"
    # Distinct-operator splitting. When non-empty
    # these override the shared ``boltz_api_url`` / ``boltz_onion_url``
    # for the two anonymize-stack legs so a single-operator
    # compromise can't see both sides of the swap. Leaving them
    # empty falls back to the shared URL (single-operator
    # deployment).
    boltz_submarine_api_url: str = ""
    boltz_submarine_onion_url: str = ""
    boltz_reverse_api_url: str = ""
    boltz_reverse_onion_url: str = ""
    boltz_use_tor: bool = True
    boltz_fallback_clearnet: bool = False
    # Max MPP parts for the Boltz swap LN payment. >1 lets LND split the
    # invoice across several channels (multi-path payment), so a node
    # whose total outbound spans multiple small channels can still pay a
    # swap invoice no single channel could carry alone — the common
    # ``no_route`` cause on small-channel nodes. 1 disables splitting.
    boltz_payment_max_parts: int = 16

    # ── BOLT 12 Gateway ──
    # gRPC target of the bare-LDK onion-message gateway daemon.
    # Inside docker-compose this is ``bolt12-gateway:50061``; for
    # local development point to a host:port. Empty disables BOLT 12.
    bolt12_gateway_grpc: str = ""
    bolt12_gateway_timeout_seconds: float = 10.0
    # Shared bearer token for the gateway gRPC surface. When the
    # gateway has BOLT12_GATEWAY_TOKEN set, every wallet RPC must
    # carry the same value here or the gateway rejects with
    # UNAUTHENTICATED. When both ends are empty, the channel is
    # unauthenticated — only safe inside a private docker network.
    bolt12_gateway_token: str = ""
    # Optional mTLS material for the wallet → gateway channel. All
    # three paths must be set together (or all unset). When set, the
    # client uses ``grpc.aio.secure_channel`` with ssl credentials
    # built from the listed PEM files; the gateway must mount the
    # matching server cert + a CA that signs ``client_cert_path``.
    # Defaults to cleartext, matching the single-host compose deploy
    # where the channel sits on an ``internal: true`` network and a
    # shared bearer token is sufficient. See docs/bolt12.md →
    # "Optional: mTLS" for the operator-side procedure.
    bolt12_gateway_tls_ca_cert: str = ""
    bolt12_gateway_tls_client_cert: str = ""
    bolt12_gateway_tls_client_key: str = ""
    # Override the TLS server name the client expects to match
    # against the server cert's SubjectAltName. Useful when dialing
    # by IP or via a tunnel that masks the docker service hostname.
    # Empty = derive from the target hostname.
    bolt12_gateway_tls_server_name: str = ""
    # Master kill-switch. Even if ``bolt12_gateway_grpc`` is set, the
    # runtime will not connect unless this is true. Defaults to ``True``
    # so the dashboard's BOLT 12 tab is functional out of the box;
    # the runtime stays dormant until ``bolt12_gateway_grpc`` is also
    # populated, so flipping this on alone does not expose the wallet
    # to onion-message traffic. Set ``BOLT12_ENABLED=false`` to hard-
    # disable BOLT 12 even when the gateway address is configured.
    bolt12_enabled: bool = True
    # Allow inbound ``invoice_request`` messages that do **not** reference
    # one of our published offers. With this off (default), the responder
    # only mints invoices for invreqs whose ``offer_issuer_id`` matches a
    # wallet-issued offer — the safe BIP-353 / paste-an-offer flow. With
    # it on, any onion-message peer can ask the wallet to mint a BOLT 12
    # invoice for an arbitrary amount; the wallet attributes the inbound
    # payment to the dashboard sentinel key. Most operators don't need
    # this; enable only if you know you want to receive direct (offer-
    # less) BOLT 12 payments such as merchant-issued refunds.
    bolt12_accept_offerless_invreqs: bool = False
    # Per-payer rate limit for inbound BOLT 12 invreqs. Keyed on
    # ``invreq_payer_id`` (or, when missing, the gateway's
    # ``recv_id``). Set to 0 to disable. Window is in seconds.
    bolt12_inbound_rate_limit_count: int = 30
    bolt12_inbound_rate_limit_window_seconds: int = 60
    # Global cap on inbound invreq rate across all payers (sliding
    # window over the same ``bolt12_inbound_rate_limit_window_seconds``).
    # Defends against per-payer-id rotation bypass — CLN's default
    # ``fetchinvoice`` generates a fresh ``payer_id`` per call, so
    # the per-peer cap above is effectively per-invreq under any
    # spec-compliant payer. The global cap is sized far above the
    # legitimate aggregate traffic a typical wallet sees (on the order
    # of one invreq per payout). Bounded [0, 10000]. 0 disables it.
    bolt12_inbound_rate_limit_global_count: int = Field(default=300, ge=0, le=10_000)
    # Per-offer cap on inbound invreqs (sliding window). Keyed on the
    # offer's ``issuer_id`` rather than the attacker-chosen ``payer_id``,
    # so a single offer cannot be milked for unbounded invoice mints by a
    # peer that rotates its ``payer_id`` every request. Onion-message
    # senders are anonymous (no authenticated peer identity), so this and
    # the global cap — not the courtesy per-payer bucket — are the
    # effective bounds against a deliberate attacker. Bounded [0, 10000].
    # 0 disables it.
    bolt12_inbound_rate_limit_per_offer_count: int = Field(default=60, ge=0, le=10_000)
    # Concurrent inbound-mint cap. The rate limit bounds rate; this
    # bounds CONCURRENCY so a burst that fits inside the rate-limit
    # window can't fan out into unbounded simultaneous LND mint
    # calls. Each new concurrent mint costs one outstanding LND
    # ``add_blinded_invoice`` call (~100 ms on a healthy LND).
    # Acquire-timeout drops the invreq with an audit row past this
    # window. Bounded [1, 256] for the cap and [1, 60] for the
    # timeout.
    bolt12_inbound_max_concurrent_mints: int = Field(default=16, ge=1, le=256)
    bolt12_inbound_mint_acquire_timeout_s: float = Field(default=5.0, ge=1.0, le=60.0)
    # Hard cap (msat) on individual inbound BOLT 12 invoices the
    # responder will mint. The wallet still relies on per-channel
    # capacity; this is a defence against abusive offer-less peers
    # tying up large amounts of inbound liquidity. Set to 0 to
    # disable.
    bolt12_inbound_max_amount_msat: int = 100_000_000  # 100k sats default
    # Hard cap on the number of in-flight outbound ``request_invoice``
    # calls the orchestrator will hold simultaneously. Each slot
    # carries a Future + the captured invreq builder closure; without
    # a cap, a slow-recipient flood (or a compromised admin key) can
    # pin tens of MB per ~minute of timeout. The default keeps
    # legitimate retry-burst headroom while bounding worst-case heap.
    bolt12_max_pending_requests: int = 64
    # Defence-in-depth caps on TLV decoding for inbound onion-message
    # payloads (the responder + outbound reply path). REST entry
    # points already cap raw bytes via Pydantic; these protect the
    # parser itself against giant-record / record-flood DoS payloads
    # crafted by hostile onion-message peers.
    bolt12_max_payload_bytes: int = 65_536  # ~2x the BOLT 4 onion limit
    bolt12_max_tlv_records: int = 512
    bolt12_max_tlv_value_bytes: int = 8192
    # Defensive ceiling on the encoded BOLT 12 invoice the responder
    # returns to the gateway. The onion-message reply envelope has
    # its own hard limit (~32 KB after onion overhead); minting an
    # invoice larger than that gets silently dropped or fragmented
    # by the gateway. Bound the per-mint output here so a future
    # misconfiguration (8 blinded paths + long description) gets
    # caught as an audit row rather than a silent dead-letter at
    # the payer.
    bolt12_max_outbound_invoice_bytes: int = Field(default=32_768, ge=4096, le=65_536)

    # When True, BIP-353 resolution probes ``dnssec-failed.org``
    # once per resolver bootstrap and refuses to trust the upstream
    # if it answers NOERROR+AD=1 (a "rubber-stamp" validator that
    # would let an attacker forge AD on legitimate names too). Cost
    # is one extra DNS round-trip per process; default-on because
    # mis-pointed resolvers silently break the BIP-353 trust model.
    bolt12_bip353_validate_resolver: bool = True

    # Inbound capacity below this threshold (in sats) triggers a
    # ``low_inbound_liquidity`` warning on the dashboard receive
    # panel. Mining-pool payouts vary widely (small ASIC users see
    # frequent <1k-sat payouts; larger fleets see much larger ones),
    # so the right threshold is highly operator-specific. The
    # conservative default warns only when capacity is nearly empty;
    # operators with lumpier payouts can raise it. Set to 0 to
    # disable the warning entirely.
    bolt12_receive_inbound_warn_sats: int = 1_000

    # Minimum number of *real* (non-dummy) hops in the blinded paths
    # the responder advertises on minted BOLT 12 invoices. ``1`` makes
    # the introduction node our direct LN peer — fine when that peer
    # is itself a well-connected routing hub, but a routability dead
    # end for users whose only peer is a small-graph LSP endpoint
    # (a leaf node with few public channels) where payers must traverse
    # the public graph to reach it. ``2`` shifts the introduction
    # node one hop further upstream (a peer-of-peer), so payers can
    # aim at well-known hubs the leaf is attached to. We fall back to
    # 1 hop automatically if LND cannot build any path at the
    # requested length, so this is safe to default high.
    bolt12_blinded_path_min_real_hops: int = Field(default=2, ge=1, le=8)
    # Maximum number of blinded paths LND embeds in a minted invoice.
    # 2 is the sweet spot: one primary + one fallback introduction
    # node. Going higher bait-traps sender-side MPP splitters (notably
    # CLN's ``pay``): on small payments, CLN sees "many paths
    # advertised => MPP-friendly" and fragments into shards even when
    # a single HTLC would route fine. With higher ``max_paths`` on a
    # small payment, CLN can split off a tiny second shard that fails
    # at the ``htlc_minimum_msat`` of a public hop, sinking the whole
    # payment. Also, on small-graph
    # topologies LND often only finds 1-2 unique introduction nodes
    # anyway; requesting more just pads with duplicates that confuse
    # splitters further. LND caps this at 8.
    bolt12_blinded_path_max_paths: int = Field(default=2, ge=1, le=8)
    # Comma-separated (or JSON array) hex pubkeys to omit from blinded
    # paths LND builds for minted invoices. Defaults to Boltz
    # (026165850492521f4ac8abd9bd8088123446d126f648ca35e60f88177dc149ceb2),
    # which advertises itself as a routing node in gossip but reserves
    # outbound for its swap engine and consistently returns
    # ``temporary_channel_failure`` on third-party forwarding attempts.
    # Extend the list with any other swap-only / non-routing nodes
    # operators discover; LND will refuse to use them as the
    # introduction node or any intermediate hop.
    bolt12_blinded_path_omit_nodes: str = "026165850492521f4ac8abd9bd8088123446d126f648ca35e60f88177dc149ceb2"

    # Auto-peer with well-known payers' LN nodes at offer-issuance
    # time AND keep an always-on connection to a small set of
    # universally-gossiped OM-capable bootstrap peers (currently
    # ACINQ + LNBIG). When the offer description matches a payer's
    # documented format (e.g. a recognised payout-memo prefix) the
    # gateway dials that payer's node before constructing
    # ``offer_paths``. Bootstrap peers guarantee at least one
    # publicly-gossiped introduction node is available so any
    # counterparty can route a reply
    # back without having to discover an address for our gateway.
    # Set to ``false`` to disable both auto-peer behaviors; the
    # payer + bootstrap registries live in
    # :mod:`app.services.bolt12.well_known_payers`.
    bolt12_auto_peer_well_known_payers: bool = True

    # Periodic push of LND-known peer addresses to the gateway's
    # in-memory cache. The cache is the load-bearing source for the
    # gateway's ``Event::ConnectionNeeded`` handler — without it, an
    # outbound onion message reply destined for a peer we're not
    # already connected to (the common case for a payer's
    # reply-path introduction node) gets buffered and silently
    # dropped after LDK's teardown timer.
    # Interval (seconds) controls the push cadence; ``0`` disables
    # the task entirely (handler will still warn on miss).
    bolt12_gateway_node_address_refresh_interval_s: int = Field(default=3600, ge=0, le=86_400)
    # Hard ceiling on the number of nodes the push includes. The LND
    # graph can have ~50 k entries; we sort by channel count and
    # take the top N so the most-likely reply-path intermediates
    # land on the gateway first. ~5 000 entries × ~100 B each =
    # ~500 KB per push, comfortably under any gRPC payload limit.
    bolt12_gateway_node_address_max_nodes: int = Field(default=5000, ge=100, le=50_000)

    # Real-time LND settlement subscriber. When True, a background
    # task streams ``GET /v2/invoices/subscribe`` from LND and flips
    # matching ``Bolt12Invoice`` rows OPEN → PAID immediately. When
    # False, the slower reconcile cron (60 s cadence) is the only
    # path; settlement state stays stale for up to a minute.
    bolt12_settlement_subscriber_enabled: bool = True

    # Retention (days) for terminal Bolt12InvoiceRequest /
    # Bolt12Invoice rows. After this age and when the row's status
    # is terminal (and the linked offer is not active), the daily
    # cleanup task deletes it. Audit-log rows are preserved
    # independently. Bounded [7, 3650]. Defaults to 90 days
    # (one quarter — covers accounting + plausible incident-
    # investigation windows).
    bolt12_request_retention_days: int = Field(default=90, ge=7, le=3650)
    bolt12_invoice_retention_days: int = Field(default=90, ge=7, le=3650)

    # Periodic htlc_max-vs-balance drift check. The blinded path
    # ``max_htlc_msat`` LND advertises to payers derives from the
    # gossiped channel ``max_htlc`` policy, which is typically set
    # once at channel open (~99% of capacity) and never updated
    # against the live remote_balance. When the ratio
    # ``advertised / receivable`` rises above this threshold,
    # payers may pick the over-advertised path and fail mid-route
    # — the channel advertises an htlc_max larger than what it can
    # actually receive, so the HTLC clears the advertised bound but
    # exceeds the live receivable balance.
    # Defaults to 1.5x — generous enough to allow normal balance
    # fluctuation but tight enough to surface a real over-claim.
    # Set to a very high value (e.g. 100.0) to disable the alert
    # without removing the audit-row trail. Bounded [1.0, 100.0].
    bolt12_htlc_max_drift_ratio_alert: float = Field(default=1.5, ge=1.0, le=100.0)

    # Telemetry #1: stream LND HTLC events so we can distinguish
    # "HTLC reached our node and we rejected it" from "HTLC died
    # upstream / never reached us". Without this, a failed inbound
    # payout looks identical to silent mint-with-no-attempt from
    # our logs alone. Off-by-default ONLY for split deployments
    # where the wallet can't subscribe to LND's router stream.
    bolt12_htlc_event_subscriber_enabled: bool = True

    # Telemetry #2: capture a snapshot of every active channel's
    # (capacity, local_balance, remote_balance, gossiped_max_htlc
    # both directions) inside ``Bolt12Invoice.channel_state_snapshot``
    # at mint time. Lets us reconstruct the channel-state context
    # of a failed payout AFTER the fact, without having to ask
    # "what was the balance at 10:15 UTC three days ago?". Small
    # JSON blob (~500 B per row).
    #
    # Off by default: the blob is a point-in-time topology + live-balance
    # map of the node, persisted per invoice. Any read of that table (a
    # backup leak, support tooling, a future invoice-detail view) would
    # expose it. Enable only as a debugging aid on a deployment actively
    # diagnosing payout failures, ideally with short retention.
    bolt12_channel_snapshot_at_mint_enabled: bool = False

    # Telemetry #3: settlement-watchdog window. An inbound BOLT 12
    # invoice that hasn't transitioned OPEN → PAID within this
    # many minutes after mint gets a one-shot
    # ``bolt12_invoice_settle_timeout`` audit row, so operators
    # can proactively notice "we minted but the payer never paid"
    # WITHOUT waiting for the payer's next failure report. The audit
    # row carries the original mint payment_hash + payer_note so
    # cross-referencing against an external failure timestamp is
    # trivial. Set to 0 to disable. Bounded [0, 1440] (24 h cap
    # — beyond that the invoice has typically expired anyway).
    bolt12_invoice_settle_watchdog_minutes: int = Field(default=5, ge=0, le=1440)

    # ── htlc_max clamp ──
    # Safety buffer (in parts-per-million) subtracted from the live
    # ``remote_balance`` when computing the clamped ``htlc_max_msat``
    # for each blinded path. ``10_000`` = 1% headroom against
    # rebalances mid-payment. Bounded [0, 100_000] (10% max).
    bolt12_htlc_max_safety_buffer_ppm: int = Field(default=10_000, ge=0, le=100_000)
    # Granularity (in msat) the clamped ``htlc_max_msat`` is rounded DOWN to
    # before it is advertised in an invoice's blinded-path payinfo. The clamp
    # derives from the live channel ``remote_balance``; advertising it raw
    # would disclose the wallet's receivable balance to any payer that reads
    # the invoice back. Rounding down to a coarse bucket keeps the advertised
    # ceiling a safe upper bound for routing while disclosing only the bucket
    # floor. ``1_000_000`` msat = 1000 sat granularity. Set to 0 to advertise
    # the unbucketed clamp. Bounded [0, 100_000_000] (1 BTC max bucket).
    bolt12_htlc_max_bucket_msat: int = Field(default=1_000_000, ge=0, le=100_000_000)

    # Drop paths whose clamped ``htlc_max`` is below
    # the requested amount. Without this, LND can advertise paths
    # we know cannot carry the payment, leaving the payer's
    # pathfinder to discover the problem mid-route.
    bolt12_drop_undersized_paths: bool = True

    # Refresh each path's encoded fees / htlc-bounds
    # from the intro's current gossip BEFORE the BOLT 12 invoice
    # is serialised and signed. Closes the LND ``add_blinded_invoice``
    # → stale per-channel-policy cache gap: a stale cache can encode a
    # fee budget below an intermediate hop's current real fee, so the
    # forwarded HTLC arrives short and the payment is CANCELED at our
    # LND. Default ON: the only
    # downside is one extra ``/v1/graph/edge`` Tor round-trip per
    # path per mint, which is negligible at typical mint cadence.
    # Flip off only if it itself starts to misfire.
    bolt12_blinded_path_refresh_policy_from_gossip: bool = True

    # PAYINFO safety margin. Even when the gossip refresh leaves the
    # encoded fees matching gossip exactly, an intermediate hop can
    # deduct more than it advertises — e.g. a CLN
    # ``fee_proportional_millionths`` set above what was last
    # announced, or an internal liquidity-management plugin — so the
    # forwarded HTLC arrives short of the invoice amount.
    # The ppm margin pads our encoded ``proportional_fee_rate``
    # above gossip so the payer's HTLC over-pays slightly,
    # absorbing the gap. Default 1,000 ppm gives roughly 2× headroom
    # over the small undisclosed margins seen in practice. Operators
    # on lower-fee peers can drop this; operators seeing similar
    # shortfalls can raise it. Disable entirely with 0.
    bolt12_blinded_path_payinfo_safety_margin_ppm: int = Field(default=1_000, ge=0, le=100_000)

    # Base-msat companion to the ppm margin. On large HTLCs a
    # proportional (ppm) margin absorbs an intermediate hop's
    # undisclosed fee, but on tiny HTLCs the undisclosed extra is
    # dominated by what looks like a fixed min-fee floor, which a
    # proportional margin can't cover (e.g. 1000 ppm × 35 sat is
    # only 35 msat of headroom). A flat 1,000-msat base margin
    # gives every payment ≥1 sat of absolute headroom regardless
    # of size; payer cost is 0.001 sat per payment, negligible.
    # Raise further only if a small-HTLC failure shows a larger
    # flat gap.
    bolt12_blinded_path_payinfo_safety_margin_base_msat: int = Field(default=1_000, ge=0, le=100_000)

    # Liveness probe each candidate path before
    # advertising it (intro reachable + relevant channel active).
    # OFF by default — the probe adds ~1 LND round-trip per path
    # per mint. Operators dealing with chronic intermediate-hop
    # failures can flip this on to reduce mint-of-unroutable-paths.
    bolt12_probe_paths_before_mint: bool = False

    # Prefer paths through different introduction
    # nodes. When multiple paths share an intro, only the best
    # (lowest fee) is kept. Reduces all-paths-share-one-intro
    # single-point-of-failure topologies.
    bolt12_path_diversity_enforce: bool = True

    # Half-open circuit breaker per intro_pubkey.
    # Tracks failure/success per intro across recent mints and
    # deprioritises (does not exclude) intros that have failed
    # recently. State is in-memory only; resets on wallet restart.
    bolt12_path_breaker_enabled: bool = True
    bolt12_path_breaker_failures_to_open: int = Field(default=2, ge=1, le=10)
    bolt12_path_breaker_initial_cooldown_s: int = Field(default=600, ge=30, le=86_400)
    bolt12_path_breaker_cooldown_cap_s: int = Field(default=86_400, ge=300, le=604_800)

    # Pigeonhole pairing for the htlc_max
    # clamp. When the responder gets N paths from LND and the
    # wallet has exactly N active channels, the clamp pairs
    # them ``(sorted by aggregate fee asc) ↔ (sorted by
    # remote_balance asc)``. The heuristic: cheaper paths
    # correspond to simpler intermediate routes, which LND
    # tends to construct through smaller terminal channels.
    # Lets the clamp identify the terminal channel for
    # multi-hop paths (the common case) where the previous
    # strategies couldn't. Falls back to the conservative
    # max-channel cap when counts don't match.
    bolt12_path_pigeonhole_pairing_enabled: bool = True

    # BOLT 12 subscribers hold long-lived h2 streams
    # to LND over Tor. Onion-only LNDs see those streams die with
    # ``httpx.ProxyError: TTL expired`` / ``ReadError`` / ``Remote
    # ProtocolError`` when Tor circuits churn. On those specific
    # transport-class errors, fire NEWNYM (throttled by
    # ``tor_newnym_min_interval_s``) and reconnect on a short
    # fixed backoff instead of escalating to the exponential
    # ceiling. Defaults on; set false to keep the legacy
    # exponential-backoff-only behaviour.
    bolt12_subscriber_newnym_on_transport_error: bool = True
    # Fixed backoff (seconds) used after a transport-class error
    # — short by design, so we reconnect on the freshly built
    # NEWNYM circuit. Default 2 s.
    bolt12_subscriber_transport_error_backoff_s: float = 2.0

    # lnd_keepalive watches num_inactive_channels
    # transitions and fires NEWNYM when peers disconnect from us
    # in bursts. Symptom: an onion-only LND's HS descriptor goes
    # stale → peers can't reach us → channels go INACTIVE briefly
    # → forwards into our blinded paths fail. Threshold of 2
    # transitions within 300 s = "this is more than a normal
    # peer-side flap" without being so loose that any cluster
    # disconnect spams NEWNYM. Set the burst threshold to 0 to
    # disable entirely.
    lnd_inbound_burst_newnym_threshold: int = 2
    lnd_inbound_burst_window_s: int = 300

    # Polling-mode subscribers. When true, both
    # BOLT 12 subscribers stop holding long-lived h2 streams to
    # LND and instead run a tight reconcile loop. Trades push
    # latency (ms → poll-interval seconds) for stream resilience
    # on Tor-unstable deployments. Default off — operators on
    # stable transports keep the lower-latency push path.
    # When this is False, the subscribers auto-
    # detect onion-only LND deployments and flip themselves to
    # polling. Explicit True or False always wins over the auto-
    # default — see ``onion_only_detect.py``.
    bolt12_subscriber_polling_mode_enabled: bool = False
    bolt12_subscriber_polling_interval_s: int = 5
    # S2 auto-detect kill switch. When the polling-mode setting
    # above is at its default ``False``, we auto-flip to polling
    # for onion-only LND deployments. Operators who explicitly
    # want polling OFF (e.g. on a Tor-stable onion-only box) can
    # set this to ``False`` to disable the auto-detect; the
    # polling-mode setting then wins verbatim.
    bolt12_subscriber_polling_mode_auto_detect: bool = True

    # Subscriber heartbeat interval. Periodic
    # ``bolt12_subscriber_heartbeat`` audit row so the absence of
    # events is itself diagnostic. Set to 0 to disable heartbeat.
    bolt12_subscriber_heartbeat_interval_s: int = 300  # 5 min

    # Pre-emptive subscriber stream warmup probe.
    # GETINFO probe before each long stream open so dead pool
    # connections surface here instead of mid-stream.
    bolt12_subscriber_warmup_probe_enabled: bool = True

    # Periodic HSFETCH of our LND onion to track
    # descriptor freshness. Interval seconds; 0 disables.
    lnd_hs_descriptor_probe_interval_s: int = 600  # 10 min

    # Channel uptime tracker poll interval.
    # Tighter than keepalive (60s) so we catch sub-minute flaps.
    # 0 disables.
    lnd_channel_uptime_track_interval_s: int = 30

    # Channel flap detector poll interval. Feeds
    # the same burst window as B's keepalive trigger AND the
    # inbound supervisor's ``channel_flap`` signal source.
    # Kept tight (a few seconds) so brief peer→us Tor-circuit blips
    # still register as flaps.
    # 0 disables.
    lnd_channel_flap_detect_interval_s: int = 5

    # Inbound-symptom HS supervisor with SIGHUP
    # escalation. Fires SIGHUP Tor when subscribers can't keep a
    # stream alive long enough — the strongest wallet-level
    # action available for "peers can't reach our HS" symptoms.
    bolt12_inbound_supervisor_enabled: bool = True
    bolt12_inbound_supervisor_tick_interval_s: int = 30
    bolt12_inbound_supervisor_window_s: int = 300  # 5 min
    bolt12_inbound_supervisor_failure_threshold: int = 10
    bolt12_inbound_supervisor_healthy_lifetime_s: float = 30.0
    bolt12_inbound_supervisor_sighup_throttle_s: int = 3600  # 1 hr
    # Channel-flap signal threshold for SIGHUP.
    # Channel ``active→inactive`` transitions are rarer than
    # subscriber transport errors so a lower threshold catches
    # the same "Tor degrading" pattern. In polling-mode
    # deployments (auto-enabled for onion-only LNDs) the
    # subscriber stream doesn't exist, so channel flaps become
    # the supervisor's primary signal source.
    bolt12_inbound_supervisor_flap_threshold: int = 3
    # HSFETCH-failure signal threshold for
    # SIGHUP. A SUSTAINED HSFETCH-failure pattern is the canonical
    # "HS descriptor going stale" signal — peers can no longer
    # find us via the DHT. The HS-descriptor probe records ONE
    # signal here per probe past the threshold (see
    # ``lnd_hs_descriptor_failure_supervisor_threshold``); the
    # supervisor's own threshold here is how many signals it
    # needs in its window before firing.
    bolt12_inbound_supervisor_hs_fetch_failure_threshold: int = 1

    # Consecutive HSFETCH failures before
    # the probe starts feeding signals into the inbound
    # supervisor. Set to 0 to disable.
    lnd_hs_descriptor_failure_supervisor_threshold: int = 3

    # Option B-adaptive: when the primary-depth
    # mint produces paths whose intros are ALL marked open by
    # the breaker, retry at the alternative depth (1 ↔ 2) and
    # use whichever has at least one healthy intro. The unused
    # LND invoice is cancelled via ``cancel_invoice`` so it
    # doesn't stay as a stranded r_hash. Adds one LND round-
    # trip when triggered (rare for healthy operation; only
    # fires after the breaker has opened the entire primary
    # depth's intro set). Disable if the operator wants the
    # responder to never make a second LND mint per invreq.
    bolt12_adaptive_depth_fallback_enabled: bool = True

    # ── Network ──
    bitcoin_network: str = "bitcoin"  # bitcoin, testnet, signet, regtest

    # ── Reverse Proxy ──
    trusted_proxies: str = ""  # comma-separated or JSON array, e.g. "172.16.0.0/12"

    # ── Dashboard ──
    dashboard_token: str = ""  # Auto-generated if empty
    enable_dashboard: bool = True
    dashboard_session_hours: int = Field(default=4, ge=1, le=24)  # Session duration in hours (1–24)
    dashboard_idle_timeout_minutes: int = Field(default=30, ge=5, le=60)  # Idle timeout (clamped to session duration)
    dashboard_max_payment_sats: int = -1  # Max sats per dashboard payment (-1 = no limit)
    # Lightning Address shown in the dashboard's "Tip the developer"
    # dialog. Defaults to the upstream maintainer's address; FORKS
    # SHOULD set their own (or leave it empty to hide the tip option).
    dashboard_tip_lightning_address: str = "paypaul@paulscode.com"

    # ── CORS ──
    cors_origins: str = ""  # comma-separated or JSON array, e.g. "http://localhost:3000,https://example.com"

    # ── Alerting ──
    alert_webhook_url: str = ""  # Optional webhook URL for security alerts (Slack, Discord, etc.)
    alert_webhook_events: str = "login_failed,tor_fallback,lnd_disconnect,rate_limit_bypass,rate_limit_degraded,auth_brute_force,csrf_violation,audit_chain_broken,audit_anchor"  # comma-separated event types
    # Optional shared secret for webhook payload authentication. When set,
    # every alert carries an ``X-Agent-Wallet-Signature: sha256=<hex>``
    # header computed over the canonicalised JSON body. Receivers should
    # reject unsigned or mis-signed deliveries to defeat URL-leak spoofing.
    # Documented in SECURITY.md.
    alert_webhook_shared_secret: str = ""

    # ── Audit Log ──
    audit_log_retention_days: int = 90  # Days to retain audit log entries (0 = keep forever)

    # ── Sign / Verify Message ──
    # Both sign API endpoints default to enabled. They live under
    # admin-authenticated routes (``/v1/wallet/sign/...``) and are
    # rate-limited per API key, so leaving them on by default is the
    # ergonomic default for operators who already trust their admin
    # bearer tokens. Flip to ``false`` to 404 the routes entirely
    # if the deployment never needs programmatic message signing.
    enable_sign_address_api: bool = True  # Mount POST /v1/wallet/sign/address (admin)
    enable_sign_node_api: bool = True  # Mount POST /v1/wallet/sign/node (admin)
    sign_message_max_chars: int = Field(default=4096, ge=1, le=65536)
    sign_audit_record_message: bool = False  # If false, audit log stores SHA-256(msg) only
    sign_address_autocomplete: str = "txn_history"  # "txn_history" | "wallet_addresses" | "off"
    sign_rate_limit_per_hour: int = Field(default=30, ge=0)  # Per-API-key sign cap (0 = disabled)
    sign_rate_limit_dashboard_per_hour: int = Field(default=60, ge=0)  # Per-dashboard-session cap

    # ── LNURL / Lightning Address resolution ──
    # Tri-state Tor preference for outbound LNURL HTTP fetches:
    #   "auto"  → use Tor iff LND_REST_URL is .onion (default)
    #   "true"  → always route LNURL via lnd_tor_proxy
    #   "false" → never force Tor for clearnet (.onion recipients still go via Tor)
    lnurl_force_tor: Literal["auto", "true", "false"] = "auto"
    # Allow plain HTTP for clearnet recipients. Default false; .onion
    # hosts ignore this because Tor terminates the encryption layer.
    lnurl_allow_http: bool = False
    # SSRF defence: block RFC1918 / loopback / link-local / ULA hosts.
    # Set true only on regtest harnesses.
    lnurl_allow_private_hosts: bool = False
    # Hard cap on response body bytes from any LNURL endpoint (resolve + callback).
    lnurl_max_response_bytes: int = 100_000
    lnurl_resolve_timeout_seconds: float = 15.0
    # Server-side opaque-handle TTL (seconds) for /lnurl/resolve → /lnurl/invoice.
    lnurl_handle_ttl_seconds: int = 300
    # Idempotency cache for /lnurl/invoice: dedupes accidental double-clicks
    # on Continue. Keyed on (handle, amount_sats, comment). Set to 0 to disable.
    lnurl_invoice_cache_ttl_seconds: int = 30

    # ── Braiins Deposit ────────────────────────────────────────────
    # The feature ships enabled but never triggers any swap or
    # payment activity until the user opens the wizard and clicks
    # "Start", so the master kill-switch is here only as an
    # operator-side opt-out of the UI button.
    braiins_deposit_enabled: bool = True
    # How many confirmations the fresh UTXO from Boltz must reach
    # before we send to the destination. 1 is reasonable on mainnet
    # (Boltz cooperative claim is a vanilla taproot key-spend); raise
    # to 2-3 for paranoid operators or noisy chains.
    braiins_deposit_confirmations_before_send: int = 1
    # Confirmation threshold for the BROADCAST -> COMPLETED transition
    # of the final send-to-Braiins tx.
    braiins_deposit_confirmations_for_completion: int = 1
    # Blocks after the send tx is broadcast before we surface a
    # non-fatal "tx hasn't confirmed yet" warning. 144 ≈ 1 day.
    braiins_deposit_broadcast_stuck_blocks: int = 144
    # Safety buffer added to the Boltz invoice amount above the round
    # deposit + estimated send fee, to absorb fee drift between quote
    # and send time.
    braiins_deposit_safety_buffer_sats: int = 1000
    # Re-quote tolerance — percentage drift between the quote shown
    # to the user and the server-side re-quote at session create
    # time before we require explicit re-confirmation.
    braiins_deposit_quote_staleness_pct: int = 10
    # Continuous LND-unavailability window before a session detail
    # surfaces a warning. Sessions never auto-FAIL on LND outages —
    # the funds are recoverable as soon as LND comes back.
    braiins_deposit_lnd_transient_max_age_s: int = 3600
    # Dwell-time in CREATED before a non-fatal "started but not yet
    # advanced" warning is surfaced. Most CREATED rows
    # advance to SWAPPING within seconds.
    braiins_deposit_created_ttl_s: int = 300
    # Default on-chain fee priority for the final send-to-Braiins tx
    # . Operators may override per-session via the wizard's
    # Advanced disclosure.
    braiins_deposit_send_fee_priority: str = "medium"
    # Dust prevention.
    # When True (default), the send-to-Braiins tx is built with NO
    # change output — the entire fresh UTXO is spent to Braiins minus
    # the network fee. Eliminates dust UTXOs at the wallet at the
    # cost of slightly variable arrival amount (the bin amount is the
    # FLOOR, not exact). When False, the legacy send path is used
    # (LND coin-selection produces change). Feature flag for fast
    # rollback; remove after one stable release.
    braiins_deposit_dust_prevention_enabled: bool = True
    # Layer 4 — when the dust-prevention check fails at send time,
    # the session enters AWAITING_FEE_REDUCTION and a periodic
    # re-checker promotes back to FUNDED once fees fall below the
    # feasibility line. This cadence is how often (seconds) the
    # advance loop reconsiders a parked session.
    braiins_deposit_fee_reduction_recheck_s: int = 300
    # ── External sources ──
    # Independent kill switch for the External Source radios in the
    # wizard. When false, ``ext_lightning`` and ``ext_onchain`` source
    # kinds are rejected at the API layer; self-sourced
    # flows are unaffected.
    braiins_deposit_ext_enabled: bool = True
    # Boltz reverse-swap invoice expiry surfaced to the user on the
    # await_funds screen for ext-LN sessions. The actual
    # invoice expiry is set by Boltz; this knob is also used as the
    # frontend countdown's display ceiling.
    braiins_deposit_ext_ln_invoice_ttl_s: int = 3600
    # Confirmations required on a deposit to ``ext_intake_address``
    # before we count it (ext-OC only). Matches the spirit of
    # ``braiins_deposit_confirmations_before_send``.
    braiins_deposit_ext_oc_confirmations: int = 1
    # Soft TTL on AWAITING_ONCHAIN_FUNDS — after this we surface a
    # non-fatal warning, but never auto-cancel. The user's funds may
    # still arrive after this window and we will pick them up.
    braiins_deposit_ext_oc_funds_ttl_s: int = 86400
    # Fee priority for ext-OC refund sends (.c).
    braiins_deposit_ext_oc_refund_fee_priority: str = "medium"
    # Tier 2 inbound routability probe (on-chain deposits). Before
    # locking funds, ask LND whether a route exists from Boltz's LN
    # node → our node for the submarine receive amount. ADVISORY by
    # default: a "no route" result only records a warning (the local
    # graph view can't model Boltz's fees/htlc-limits/live-liquidity/
    # MPP, so it's non-authoritative). Set
    # ``braiins_deposit_routability_probe_enforce=True`` to hard-refuse
    # on a confident "no route" result.
    braiins_deposit_routability_probe_enabled: bool = True
    braiins_deposit_routability_probe_enforce: bool = False
    # Dashboard request-resilience: the session-detail endpoint
    # drives a best-effort ``advance()`` on every poll as a "works
    # without Celery" fallback, but the Celery beat ticker also advances
    # sessions. Skip the detail-read advance when this session was
    # advanced via a detail read within this many seconds, so a tight
    # poll can't issue redundant get_channels / confirmation calls over
    # Tor. 0 disables the throttle (advance on every read).
    braiins_deposit_detail_advance_min_interval_s: int = 3
    # Observability: log a warning when a slow dashboard-side
    # backend call (e.g. the detail-read advance, which fans out to LND
    # get_channels + mempool confirmation lookups over Tor) exceeds this
    # many seconds, so slow-backend episodes surface in ops rather than
    # only as user reports.
    dashboard_slow_call_warn_s: float = 5.0
    # Channel-open alternative for on-chain deposits (swap-bypass). When
    # enabled, on-chain sources can fund the deposit by OPENING a channel
    # to a preset peer instead of a submarine swap — bypassing the inbound
    # routing the submarine leg needs. Enabled by default: this only makes
    # the per-deposit "Open a channel instead" toggle AVAILABLE — the user
    # still opts in per deposit, and a deposit only proceeds with a
    # reachable peer + an eligible amount. Peer config is pre-populated
    # from the onboarding presets; set this False to hide the option
    # entirely.
    braiins_deposit_channel_open_enabled: bool = True
    # Primary preset peer — the large-amount default. Chosen when the channel
    # capacity is ≥ ``..._peer_min_sats`` (that min IS the primary-vs-small
    # discriminator). Values mirror the onboarding wizard's preset nodes.
    # These are the upstream project's recommended public LN peers; forks /
    # operators can repoint them (here and in the dashboard onboarding presets)
    # to any node they prefer.
    braiins_deposit_channel_peer_pubkey: str = "0322d0e43b3d92d30ed187f4e101a9a9605c3ee5fc9721e6dac3ce3d7732fbb13e"
    braiins_deposit_channel_peer_host: str = "164.92.106.32:9735"
    braiins_deposit_channel_peer_min_sats: int = 1_000_000
    braiins_deposit_channel_peer_max_sats: int = 0  # 0 = no cap
    # Secondary small-channels preset — the otherwise default (capacity below
    # the primary node's min, down to this node's own min).
    braiins_deposit_channel_peer_small_pubkey: str = (
        "02a98c86ef366ce226aad6e7706959456e1701058915c3cbf527b37da143bb1441"
    )
    braiins_deposit_channel_peer_small_host: str = "146.190.169.210:9735"
    braiins_deposit_channel_peer_small_min_sats: int = 150_000
    braiins_deposit_channel_peer_small_max_sats: int = 0
    # Confs before the freshly-opened channel is considered usable.
    braiins_deposit_channel_activation_confs: int = 3
    # Soft TTL on OPENING_CHANNEL before we surface a "stuck" warning
    # (never auto-FAIL / never auto-move funds).
    braiins_deposit_channel_open_timeout_s: int = 7200
    # Fee priority for the channel funding tx.
    braiins_deposit_channel_fee_priority: str = "medium"
    # Extra capacity headroom (fraction) above the bare reserve+safety
    # sizing, to absorb Boltz/miner fee drift between open and reverse-swap.
    braiins_deposit_channel_capacity_headroom_pct: float = 0.01

    # ── Anonymize ──────────────────────────────────────────────────
    # Opt-in (OFF by default). This subsystem handles wallet seeds and
    # keys for coinjoin-style mixing, so a fresh install does not enable
    # it unprompted — set ``ANONYMIZE_ENABLED=true`` to turn it on. The
    # remaining defaults below are chosen so that, once enabled, the
    # feature runs in a privacy-strict configuration; operators tune via
    # environment variables (case-insensitive, ``ANONYMIZE_*``).
    anonymize_enabled: bool = False
    anonymize_min_sat: int = 50_000
    anonymize_max_sat: int = 10_000_000
    # Ceiling on the combined percentage + miner fee the wallet tolerates
    # on the egress reverse-swap leg. The on-chain amount the operator
    # locks up must be at least ``invoice − this%``; a response below the
    # floor is refused before the Lightning hold-invoice is paid. The same
    # ceiling backstops the claim-output value band in the reverse hop.
    anonymize_reverse_max_total_fee_pct: float = 5.0
    # On-chain sources fund the mix through a submarine swap, whose
    # operator enforces a minimum well above the global floor. Sessions
    # below this are rejected at quote time (fail fast) rather than
    # wedging at swap-create. Set to the configured submarine operator's
    # ``minimal`` limit.
    anonymize_onchain_source_min_sat: int = 100_000
    anonymize_require_tor: bool = True
    anonymize_cooperative_claim_only: bool = True
    anonymize_default_delay_min_s: int = 3600
    anonymize_default_delay_max_s: int = 21600
    # LN self-pay source hop. The self-payment reshuffles channel
    # balances before the reverse-swap exit. ``mode`` selects the
    # routing posture: ``pinned`` sends through one weighted-random
    # channel; ``split`` fans out via MPP with the operator blocklist
    # excluded from first hops; ``auto`` splits when at least
    # ``split_min_channels`` active channels exist, else pins.
    anonymize_self_pay_mode: str = "auto"
    anonymize_self_pay_split_min_channels: int = 3
    anonymize_self_pay_fee_limit_sats: int = 5000
    anonymize_priv_channel_default_capacity_sat: int = 1_000_000
    anonymize_liquid_enabled: bool = False
    # Operator-managed peer blocklist (e.g. exchange-owned hubs).
    # Comma-separated 33-byte hex pubkeys.
    anonymize_peer_blocklist: str = ""

    # distinct-operator splitting for on-chain pipelines.
    # (``boltz_submarine_api_url`` / ``boltz_reverse_api_url`` are
    # declared above in the BOLT 12 Gateway / anonymize-stack section.)

    # amount binning. JSON list-of-int or comma-separated.
    anonymize_amount_bins_sat: str = "50000,100000,250000,500000,1000000,2000000,5000000"
    # reverse-leg MPP K range.
    anonymize_reverse_mpp_chunks: int = 3  # legacy; coerced to range
    anonymize_reverse_mpp_chunks_range_min: int = 2
    anonymize_reverse_mpp_chunks_range_max: int = 4
    anonymize_auto_blocklist_top_n_peers: int = 3
    anonymize_onchain_min_interleg_delay_s: int = 6 * 3600
    anonymize_onchain_max_interleg_delay_s: int = 48 * 3600
    anonymize_claim_broadcast_jitter_s: int = 3600
    anonymize_utc_quiet_window: str = ""  # "" or "HH:HH" pair
    anonymize_ext_deposit_min_dwell_s: int = 2 * 3600
    anonymize_ext_deposit_max_dwell_s: int = 24 * 3600
    anonymize_allow_plain_bolt11_deposit: bool = False
    anonymize_broadcast_via: Literal["boltz", "self"] = "boltz"
    anonymize_audit_bucket_s: int = 3600
    anonymize_audit_bucket_emit_jitter_s: int = 900
    anonymize_exact_audit_logs: bool = False
    anonymize_destination_retention_days: int = 7

    # SOCKS listener layout — JSON object or
    # ``label=port,label=port`` comma list. Empty => disabled.
    anonymize_tor_socks_ports: str = (
        "boltz_submarine=9050,boltz_reverse=9051,liquid=9052,"
        "chain_backend=9053,bip353_dns=9054,quote_cache_refresh=9055,"
        "chain_backend_general=9056,chain_backend_anonymize=9057"
    )
    anonymize_require_exit_diversity: Literal["asn", "country", "off"] = "asn"
    anonymize_quote_cache_refresh_s: int = 600
    anonymize_quote_cache_max_age_s: int = 1800
    anonymize_allow_public_chain_backend: bool = False
    # Treat a co-resident / private-network chain backend (loopback,
    # RFC1918, link-local, or a non-public hostname such as
    # ``electrs.embassy`` / ``fulcrum.startos``) as trusted: exempt it
    # from the onion-only egress gate WITHOUT the ``weak`` tier cap that
    # ``anonymize_allow_public_chain_backend`` carries. The opt-in only
    # takes effect when every configured chain host is actually local —
    # it is ignored on a genuinely public backend, so it cannot be set
    # by accident to relax a remote endpoint. Unlike the public opt-in,
    # a local backend has no third-party observer to leak queries to, so
    # there is no privacy basis for capping the tier.
    anonymize_trusted_local_chain_backend: bool = False
    anonymize_allow_external_explorer_links: bool = False
    anonymize_boltz_poll_interval_s: int = 30
    anonymize_inter_leg_http_dwell_min_s: int = 60
    anonymize_inter_leg_http_dwell_max_s: int = 600
    anonymize_bip353_doh_endpoint: str = "https://dns.mullvad.net/dns-query"
    anonymize_bip353_cache_min_ttl_s: int = 86400
    # BIP-353 / BOLT 12 inbound deposit acceptance. When
    # ``anonymize_ext_lightning_deposit_method`` is ``"bolt12"`` the
    # ext-lightning source-kind mints a per-session BOLT 12 offer
    # instead of the legacy BOLT 11 invoice. When
    # ``anonymize_bip353_deposit_domain`` is set, the session also
    # carries a per-session ``<session-handle>@<domain>`` and a
    # zone-file TXT-record fragment so an operator can publish the
    # handle out-of-band. The domain MUST be one the operator
    # controls and intends to serve TXT lookups for.
    anonymize_ext_lightning_deposit_method: Literal["bolt11", "bolt12"] = "bolt11"
    anonymize_bip353_deposit_domain: str = ""
    # create-time clock-skew tolerance. The probe takes
    # ``anonymize_clock_skew_samples_per_tick`` samples per tick and
    # statistically aggregates them (trimmed-median + truncation-bias
    # correction) to recover sub-second precision from second-
    # resolution HTTP ``Date`` headers. The standard error of the
    # aggregate at N=12 is ~85 ms, but the half-RTT midpoint compen-
    # sation that the probe applies assumes a symmetric round-trip —
    # an assumption Tor circuits routinely violate by hundreds of
    # milliseconds (the outbound and inbound paths through Tor are
    # not necessarily the same length). The 1000 ms default leaves
    # room for that asymmetry; tightening it on a clearnet probe is
    # fine, but doing so on Tor will refuse on correctly-synced
    # clocks. The looser runtime tolerance (5000 ms) is below.
    anonymize_max_clock_skew_ms: int = 1000
    anonymize_boltz_operator_registry_path: str = "app/services/anonymize/operators.json"
    # Signed clock-skew probe-source registry. Loaded as the
    # fallback when ``anonymize_clock_skew_probe_sources`` is blank.
    # Signed by the same maintainer key as ``operators.json``; the
    # signed-load path reuses
    # ``anonymize_registry_release_key_fingerprints`` for the allow-list.
    anonymize_clock_skew_sources_path: str = "app/services/anonymize/clock_skew_sources.json"
    anonymize_clock_skew_sources_sig_path: str = "app/services/anonymize/clock_skew_sources.sig"
    # Statistical-aggregation probe knobs. Each probe tick
    # collects N samples spread across the sample window, then takes
    # a trimmed median to recover sub-second precision from the
    # second-resolution HTTP ``Date`` header.
    anonymize_clock_skew_samples_per_tick: int = 12
    anonymize_clock_skew_sample_window_s: float = 20.0
    anonymize_clock_skew_min_samples_for_decision: int = 6
    anonymize_clock_skew_trim_fraction: float = 0.15
    anonymize_prohibit_gossip_at_routing: bool = True
    anonymize_coop_sig_timeout_s: int = 120
    anonymize_coop_sig_max_attempts: int = 3
    # On-chain inbound pre-flight (mirrors the Braiins on-chain deposit
    # inbound gate). An on-chain-sourced session's mandated first hop is
    # a submarine swap, which requires THIS node to RECEIVE the bin
    # amount over Lightning from the swap provider (Boltz pays our
    # invoice = inbound routing into us). If our inbound capacity can't
    # plausibly cover it, the session is structurally un-completable: it
    # would lock funds on-chain, then refund ~30 min later, burning fees
    # and reconciliation budget. When enabled, the create path refuses
    # such a session up front (byte-pinned ``creation_unavailable``).
    # This is a purely LOCAL check (reads our own channels) — no
    # third-party egress, so it does not touch the egress-isolation
    # invariant. (The Braiins Tier-2 routability probe is deliberately
    # NOT ported: it fetches Boltz node pubkeys over the shared,
    # non-isolated Boltz transport, which would breach that invariant.)
    anonymize_inbound_preflight_enabled: bool = True

    # Robustness / recovery.
    anonymize_claim_min_confirmations: int = 2
    anonymize_claim_broadcast_safety_margin_s: int = 600
    anonymize_claim_reorg_giveup_blocks: int = 12
    anonymize_retry_backoff_s: int = 60
    anonymize_health_probe_interval_s: int = 600
    anonymize_health_flip_threshold: int = 2
    anonymize_priv_channel_close_delay_min_s: int = 2 * 3600
    anonymize_priv_channel_close_delay_max_s: int = 24 * 3600
    anonymize_claim_js_timeout_s: int = 30
    anonymize_claim_js_max_output_bytes: int = 64 * 1024
    anonymize_operator_sig_mismatch_grace_s: int = 3600
    anonymize_allow_unverified_operators: bool = False
    anonymize_pipeline_schema_version_current: int = 10
    anonymize_pipeline_schema_version_min_supported: int = 10
    anonymize_hard_delete_after_days: int = 365

    # Second-pass review.
    anonymize_min_registry_size_for_strong: int = 3
    anonymize_enforce_onion_only_egress: bool = True
    anonymize_exact_bin_tolerance_sat: int = 50
    anonymize_preconsolidation_min_dwell_s: int = 6 * 3600
    anonymize_auto_peer_top_k: int = 10
    anonymize_auto_peer_cooldown_s: int = 24 * 3600
    # Randomized throwaway-channel cooperative-close delay
    # window (2–24 h default). force-close is NEVER automated.
    anonymize_throwaway_channel_close_delay_min_s: int = 2 * 3600
    anonymize_throwaway_channel_close_delay_max_s: int = 24 * 3600
    # Extra CLTV blocks added to the HTLC's expiry on
    # retry when the previous attempt got stuck. Bounds retry-induced
    # CLTV margin growth at the operator's chosen ceiling.
    anonymize_stuck_htlc_cltv_margin_bump_blocks: int = 6
    # Tier-keyed concurrency caps. Form: ``weak=3,moderate=2,strong=1``.
    anonymize_tier_concurrency_cap: str = "weak=3,moderate=2,strong=1"
    # Max sessions one identity may create per rolling hour (the
    # admission-gate sliding window). Raise it when testing.
    anonymize_create_window_max_per_hour: int = 10
    anonymize_quote_cache_refresh_min_s: int = 450
    anonymize_quote_cache_refresh_max_s: int = 750
    # keyed-BLAKE2b reuse-detection key. Hex-encoded bytes.
    # Required when ``anonymize_enabled`` is true.
    anonymize_reuse_detection_key_fernet: str = ""
    anonymize_reuse_override_phrase: str = "I accept this destination address has been used"
    anonymize_feerate_jitter_lo: float = 0.85
    anonymize_feerate_jitter_hi: float = 1.15

    # Third-pass review.
    anonymize_preconsolidation_overpad_min_sat: int = 0
    anonymize_preconsolidation_overpad_max_sat: int = 25_000
    anonymize_boltz_broadcast_grace_s: int = 60
    # Per-cookie/user/IP cap on session-create calls. The
    # 100/hour default is calibrated for a single-user Agent Wallet:
    # still defeats a compromised-cookie spam attack (1.6/min sustained
    # ceiling) but won't punish legitimate retry-during-debugging or
    # an operator-initiated test loop. Multi-operator deployments can
    # lower this to 10 (the prior default) for tighter posture.
    anonymize_reuse_check_rate_limit_per_hour: int = 100
    anonymize_reuse_override_rate_limit_per_day: int = 1
    anonymize_reuse_detection_key_rotation_days: int = 30
    anonymize_reuse_detection_key_retention_days: int = 90
    anonymize_retain_redacted_history_rows: bool = False
    anonymize_audit_min_bucket_count: int = 5

    # Robustness hardenings.
    anonymize_awaiting_reconciliation_cap: int = 10
    anonymize_reconcile_probe_min_s: int = 300
    anonymize_reconcile_probe_max_s: int = 1800
    anonymize_reconcile_giveup_s: int = 7 * 86400

    # External-source reconciliation auto-retry probe + wedge detector
    # . only the Class A retry
    # budget is configurable — Class B is a code-level constant in
    # reconciliation_classify.MAX_RETRIES_SEMI.
    anonymize_reconciliation_probe_interval_s: int = 300
    anonymize_reconciliation_probe_jitter_frac: float = 0.20
    anonymize_reconciliation_probe_batch_size: int = 20
    anonymize_reconciliation_probe_boot_delay_s: int = 60
    anonymize_reconciliation_max_retries_transient: int = 12
    anonymize_reconciliation_backoff_base_s: int = 30
    anonymize_reconciliation_backoff_max_s: int = 3600
    anonymize_reconciliation_countdown_threshold_s: int = 600
    anonymize_reconciliation_runtime_wall_clock_budget_s: int = 14400
    anonymize_clock_recheck_interval_s: int = 1800
    anonymize_max_runtime_clock_skew_ms: int = 5000
    # Comma-separated source URLs the clock-skew probe
    # consults. Empty = probe stays no-op. Operators MUST configure
    # at least two onion HTTPS endpoints (more is better — the probe
    # takes the median so one misbehaving operator can't poison the
    # measurement). Sample: ``https://operator-a.onion/,https://operator-b.onion/``.
    anonymize_clock_skew_probe_sources: str = ""
    anonymize_max_hops: int = 6
    anonymize_max_pipeline_json_bytes: int = 8192
    anonymize_preconsolidation_overpad_resample_limit: int = 16
    anonymize_self_broadcast_verify_timeout_s: int = 300
    anonymize_quote_response_floor_ms: int = 250
    # Uniform jitter (ms) added on top of the quote response floor so the
    # floor is not a flat, deterministic release line that itself leaks the
    # true processing time whenever it is exceeded. Set to 0 to disable.
    anonymize_quote_response_floor_jitter_ms: int = 40
    anonymize_reuse_detection_key_rotation_min_interval_s: int = 3600
    anonymize_audit_per_bucket_suppression_markers: bool = False
    anonymize_chain_client_first_connect_jitter_s: int = 30

    # Fourth-pass review.
    anonymize_redact_chain_anchors_on_retention: bool = True
    anonymize_boltz_swap_redact_on_anonymize_retention: bool = True
    anonymize_claim_feerate_tolerance_lo: float = 0.6
    anonymize_claim_feerate_tolerance_hi: float = 1.5
    anonymize_claim_feerate_outlier_grace_s: int = 600
    anonymize_operator_degrade_outlier_threshold: int = 3
    anonymize_registry_sig_path: str = "app/services/anonymize/operators.sig"
    anonymize_registry_release_key_fingerprint: str = ""
    anonymize_registry_require_threshold_sig: bool = False
    # k-of-n threshold-signed registry. ``threshold_k``
    # is the minimum number of distinct release-key fingerprints whose
    # signatures must verify. ``threshold_sig_paths`` is a comma-
    # separated list of additional ``.sig`` files (one per maintainer
    # key); the main ``operators.sig`` is always loaded alongside.
    anonymize_registry_threshold_k: int = 0
    anonymize_registry_threshold_sig_paths: str = ""
    anonymize_operator_min_volume_multiple: int = 100
    # Chain composition for on-chain anonymize sessions (empty
    # = default-computation rule).
    anonymize_submarine_operator_primary: str = ""
    anonymize_submarine_operator_secondary: str = ""
    anonymize_reverse_operator: str = ""
    # Per-probe network budget for the operator-reachability
    # health-check. Tor first-circuit-to-onion latency can be 3-5 s; 6 s
    # covers typical cold-start without false-positive flapping.
    anonymize_operator_probe_timeout_s: float = 6.0
    # In-memory probe-result cache TTL. Short enough that
    # the cache doesn't outlive a typical wizard interaction (1-3 min);
    # long enough that filling out the form doesn't re-probe per field.
    anonymize_operator_probe_cache_ttl_s: float = 60.0
    anonymize_circuit_rebuild_tokens_per_hour: int = 6
    anonymize_circuit_rebuild_burst: int = 3
    anonymize_circuit_rebuild_aggregate_tokens_per_hour: int = 18
    anonymize_operator_degrade_autoclear_s: int = 7 * 24 * 3600
    anonymize_registry_release_key_fingerprints: str = ""
    anonymize_claim_feerate_probe_retry_delay_s: int = 5
    anonymize_feerate_probe_failure_health_threshold: float = 0.05
    anonymize_reuse_check_allow_coarse_identity: bool = False
    anonymize_quote_cache_reverify_jitter_s: int = 60

    # Fifth-pass review.
    anonymize_create_response_floor_ms: int = 350
    anonymize_consolidation_decoy_min_sat: int = 20_000
    anonymize_consolidation_decoy_max_sat: int = 80_000
    anonymize_preconsolidation_merge_with_pending_payment: bool = False
    anonymize_hop_idempotency_key_fernet: str = ""
    anonymize_hop_idempotency_key_rotation_days: int = 7
    anonymize_hop_idempotency_key_retention_days: int = 14
    anonymize_create_response_floor_jitter_ms: int = 50
    anonymize_allow_degenerate_mpp_k_range: bool = False
    anonymize_decoy_value_history_days: int = 30
    anonymize_consolidation_to_submarine_delay_min_s: int = 300
    anonymize_consolidation_to_submarine_delay_max_s: int = 7200
    anonymize_refuse_decoy_override_spends: bool = False
    anonymize_preconsolidation_merge_require_queue: bool = False
    anonymize_hop_idempotency_key_fernet_restore_keys: str = ""
    anonymize_allow_hop_idempotency_key_generation_drift: bool = False
    anonymize_allow_hop_idempotency_key_horizon_shrink: bool = False

    # Sixth-pass review.
    anonymize_refund_utxo_hardening_enabled: bool = True
    anonymize_refuse_refund_override_spends: bool = False
    anonymize_decoy_seed_fernet: str = ""
    anonymize_decoy_seed_required: bool = True
    anonymize_reverse_mpp_k_min_executed: int = 2
    anonymize_reverse_mpp_fallback_mode: Literal["strict", "abort_below_min", "legacy"] = "strict"
    anonymize_refund_count_reveal_requires_stepup: bool = True
    anonymize_stepup_nonce_ttl_s: int = 60
    anonymize_refund_locked_event_hard_horizon_days: int = 0  # 0 = auto
    anonymize_redactor_hex_threshold: int = 100
    anonymize_redactor_hex_whitespace_tolerance_bytes: int = 4
    anonymize_subprocess_capture_max_bytes: int = 65536
    anonymize_boltz_claim_js_sri_dev_bypass: bool = False
    anonymize_decoy_seed_account_key: str = ""
    anonymize_k_floor_metric_window_days: int = 7

    # Seventh-pass review.
    anonymize_quote_token_hmac_key_fernet: str = ""
    anonymize_quote_token_hmac_key_rotation_days: int = 1
    anonymize_quote_token_hmac_key_retention_days: int = 8
    anonymize_quote_token_ttl_s: int = 300  # ANONYMIZE_QUOTE_TTL_S
    anonymize_quote_cache_signing_key_fernet: str = ""
    anonymize_first_egress_bootstrap_jitter_s: int = 60
    anonymize_tor_bootstrap_timeout_s: int = 120
    anonymize_reverse_mpp_decoy_decrement_rate: float = 0.15
    anonymize_quote_cache_soft_stale_refresh_timeout_s: int = 5
    anonymize_stepup_nonce_bytes: int = 32
    anonymize_stepup_nonce_verify_rate_limit_per_min: int = 10
    anonymize_stepup_nonce_verify_lockout_s: int = 300

    # Eighth-pass review.
    anonymize_gc_catchup_interval_s: int = 3600
    anonymize_gc_tick_interval_s: int = 300
    anonymize_quote_token_verify_db_fallback_timeout_s: int = 1
    anonymize_quote_token_key_rotation_propagation_s: int = 5
    anonymize_tor_control_reconnect_attempts: int = 5
    anonymize_tor_control_reconnect_backoff_s: int = 1
    # Control-port address for Tor
    # bootstrap probes, NEWNYM watchdog, SETEVENTS stream
    # , and per-listener / diversity / HSFETCH probes.
    # Default points at the bundled ``tor-proxy`` sibling container's
    # ControlPort (9100, per tor-proxy/torrc). Operators running
    # their own Tor on the host re-point at it via
    # ``ANONYMIZE_TOR_CONTROL_HOST`` / ``_PORT`` env vars; setting
    # the host to empty disables the probe.
    #
    # Historical note: the pre default was ``127.0.0.1:9051``
    # for the host-Tor era. That value is now wrong for the
    # containerized deployment shape — from inside the api
    # container, ``127.0.0.1`` is the api's own loopback (nothing
    # listening), and 9051 is a SOCKS port even if it could be
    # reached. The new defaults match the bundled service.
    anonymize_tor_control_host: str = "tor-proxy"
    anonymize_tor_control_port: int = 9100
    # Optional control-port password for ``HashedControlPassword``
    # auth. Empty selects ``AUTHENTICATE`` with no args (cookie
    # auth via the running torrc).
    #
    # Kept for backward compatibility with operators who
    # configured this name historically. New deployments should set
    # the unified ``TOR_CONTROL_PASSWORD`` instead; the resolver below
    # picks whichever is non-empty.
    anonymize_tor_control_password: str = ""

    # Unified ControlPort password. Set by the operator
    # in ``.env`` (or auto-generated at api-container first boot by
    # the lifespan and written to ``.env.local``). Both the api
    # process (for probes + watchdog NEWNYM) and the tor-proxy
    # container (for HashedControlPassword derivation in the
    # entrypoint shim) read from this single source.
    tor_control_password: str = ""

    # Minimum seconds between NEWNYM signals fired by the
    # watchdog. Tor enforces 10s as a hard floor; we use a longer
    # cadence so we don't thrash circuits during a flapping outage.
    tor_newnym_min_interval_s: int = 60

    # Watchdog tick cadence. Also drives the "watchdog
    # unhealthy" threshold (3x this value without a recorded tick).
    tor_watchdog_interval_s: int = 30

    # Two-tier breaker thresholds. The Tor breaker opens
    # after this many consecutive Tor-attributable failures.
    tor_breaker_failure_threshold: int = 5

    # DataDirectory growth threshold. The watchdog emits an
    # audit warning when the mounted /var/lib/tor volume exceeds
    # this size. Tor steady-state is ~10-30 MB; >100 MB is an
    # operator-attention signal (likely descriptor-cache anomaly
    # or accumulated state from a long-running incident).
    tor_data_dir_warn_mb: int = 100

    # Path the watchdog statvfs()s for the growth check. The
    # api container mounts the tor_data volume at this path read-only.
    # Set to empty to disable the check (operators running their own
    # Tor outside the compose stack).
    tor_data_dir_mount_path: str = "/var/lib/tor"

    # Startup exit-relay diversity smoke test. When True,
    # lifespan startup blocks on the smoke test; a circuit-collision
    # failure aborts the process before traffic is accepted (the
    # "fail loud" behaviour). When False (default
    # for now), the smoke test runs as a background task and a
    # collision is logged but doesn't refuse to serve. Operators
    # who want the strict variant flip this on.
    tor_diversity_smoke_blocking: bool = False

    # Preventive Tor age rotation. A Celery beat task issues
    # SIGNAL HUP on this cadence so guard-state degradation can't
    # accumulate indefinitely. Set to 0 to disable the rotation
    # task entirely (operators with their own rotation policy).
    # 7 days is the upstream-recommended floor; tighten via env
    # only when the operator's threat model justifies the churn.
    tor_rotation_interval_days: int = 7

    # LND-side HS descriptor freshness check cadence
    # (seconds). The Celery beat task ``check_lnd_hs_descriptor_freshness``
    # fires HSFETCH against LND's onion every N seconds; two
    # consecutive failures cross the alarm threshold. Default
    # 21600 = 6 hours. Tighten only for diagnostic windows.
    tor_hs_descriptor_check_interval_s: int = 6 * 3600

    # ── LND Tor supervisor (recovery for stale HS descriptors) ──
    #
    # The supervisor watches _LND_BREAKER + corroborating signals
    # and runs a staggered HSFETCH → NEWNYM → SIGHUP → healthcheck
    # ladder when LND's hidden service goes unreachable via our
    # Tor proxy. See docs/anonymize_troubleshooting.md "Liquid backend
    # not ready yet". Motivated by stale-descriptor incidents where
    # LND's hidden service becomes unreachable via the Tor proxy.
    #
    # Master kill switch. ``false`` reverts to today's audit-only
    # behaviour (the watchdog still fires NEWNYM on the unified Tor
    # breaker if the breaker-reset wiring fix lets it open — but the
    # corroborating onion-probe + HSFETCH-led escalation in this
    # supervisor stays off).
    lnd_tor_recovery_enabled: bool = True

    # How long _LND_BREAKER must be open before C1 evaluates true.
    # Rules out a single bad batch. Must be ≤ the natural
    # half-open interval of _LND_BREAKER (30s) plus a few keepalive
    # ticks — otherwise we'd never observe "sustained" failure.
    lnd_tor_recovery_detect_window_s: int = 60

    # Step 1 (HSFETCH) maximum wall time. Tor HSDir lookups can
    # take ~30-60 s; we wait up to this long for an HS_DESC event.
    lnd_tor_recovery_hsfetch_timeout_s: int = 60

    # After step 2 (NEWNYM), wait this long for the breaker to
    # close before escalating to step 3.
    lnd_tor_recovery_newnym_wait_s: int = 90

    # After step 3 (SIGHUP), wait this long before yielding to
    # the Docker healthcheck (step 4).
    lnd_tor_recovery_sighup_wait_s: int = 120

    # Rolling 24 h cycle cap. 4+ cycles in 24 h disables the
    # supervisor for the rest of the window — chronic LND-side
    # issues should not look like a healthy auto-recovery loop.
    lnd_tor_recovery_max_cycles_per_day: int = 4

    # C3 corroborating probe target. Empty → auto-resolve from
    # LND_MEMPOOL_URL / LND_ELECTRUM_URL (first .onion wins).
    # The supervisor probes up to 2 endpoints per detection — see
    # plan Q2 (option c).
    lnd_tor_recovery_other_onion_probe_url: str = ""

    # Per-probe timeout for the C3 onion reachability check.
    lnd_tor_recovery_other_onion_timeout_s: int = 10

    # Backoff durations between cycles. Cycle 1 → 2
    # uses _15m; 2 → 3 uses _45m; 3 → 4 uses _2h; 4+ → disabled.
    lnd_tor_recovery_cooldown_15m_s: int = 900
    lnd_tor_recovery_cooldown_45m_s: int = 2700
    lnd_tor_recovery_cooldown_2h_s: int = 7200

    # Tor split mode: separate Tor processes for LND vs
    # Anonymize. When False (default), one tor-proxy container
    # serves both. When True, the operator brings up two: tor-lnd
    # and tor-anonymize (via docker-compose.tor-split.yml). Code
    # paths branch on this flag to spawn ONE vs TWO watchdog /
    # event-stream tasks and to route Tor-attributable failures
    # into per-pool breakers.
    tor_split_mode: bool = False

    # Host the anonymize-side SOCKS listeners are reachable
    # at. Single mode: ``tor-proxy``. Split mode: ``tor-anonymize``.
    # Probes (per-listener, diversity smoke) build their URLs from
    # this setting instead of hard-coding ``tor-proxy`` so flipping
    # ``tor_split_mode`` requires changing exactly one env knob.
    anonymize_tor_socks_host: str = "tor-proxy"

    # Clearnet endpoint used by the three Tor SOCKS5 health probes
    # (one-shot reach check at startup, diversity smoke at startup,
    # per-listener round-robin every 30 s). NOT used for any actual
    # chain data — it's purely a "did the SOCKS5 round-trip
    # succeed?" probe target. Default is Cloudflare's DNS resolver
    # ``cdn-cgi/trace`` endpoint: small text response, anycast-
    # backed, no Bitcoin-project association. Operators who prefer
    # a Bitcoin-themed target can point it at any cheap public
    # endpoint that returns 2xx to GET (e.g.
    # ``https://bitcoinexplorer.org/api/blocks/tip/height``).
    tor_probe_url: str = "https://1.1.1.1/cdn-cgi/trace"

    # LND-side Tor control port host. Empty in single mode
    # (the watchdog uses the anonymize control host for both
    # purposes). In split mode set to ``tor-lnd`` so the LND-pool
    # watchdog can probe and SIGNAL its own Tor instance.
    lnd_tor_control_host: str = ""
    lnd_tor_control_port: int = 9100
    anonymize_tor_bootstrap_recheck_interval_s: int = 300
    allow_boltz_swap_sequence_regression: bool = False
    anonymize_reverse_mpp_decoy_decrement_headroom: int = 2
    allow_offline_runtime_state_migration: bool = False
    anonymize_quote_cache_resign_rate_per_s: int = 50
    anonymize_stepup_cookie_hmac_key_fernet: str = ""
    anonymize_test_deterministic_rng_seed: int = 1

    # Multi-output sessions.
    # Cap on the number of outputs a single session may produce. Above
    # this, the quote builder refuses — operators who want larger
    # fan-out compose multiple sessions instead.
    anonymize_multi_output_max_count: int = 5
    # Ceiling on the *aggregate* value a single multi-output session may
    # move, summed across all of its outputs. Defaults to the per-session
    # ``ANONYMIZE_MAX_SAT`` so the count cap cannot be used to multiply the
    # single-output value ceiling; operators who want a different aggregate
    # bound set this explicitly.
    anonymize_multi_output_max_total_sat: int = 10_000_000
    # Per-output egress-time spread, in seconds. The plan-builder
    # samples one offset per output from this band; outputs are
    # ordered by ``scheduled_at_unix_s`` at egress time so a chain
    # observer sees a spread, not a simultaneous burst.
    anonymize_multi_output_schedule_min_s: int = 3600
    anonymize_multi_output_schedule_max_s: int = 21600

    # Liquid hop.
    # The Liquid hop is opt-in (`anonymize_liquid_enabled`); even when
    # enabled, the seed MUST be configured or startup refuses.
    anonymize_liquid_seed_fernet: str = ""
    # SLIP-77 seed derivation version (0 or 1). 0 seeds SLIP-77 from the
    # Fernet first-key bytes verbatim; 1 runs them through a
    # domain-separated HKDF so the Liquid spend authority is independent
    # of the at-rest encryption key. The default is 0 so an existing
    # deployment keeps deriving the same Liquid addresses; move to 1 only
    # while no Liquid funds are in flight (a Liquid dwell output exists
    # only inside an active session), since the two versions produce
    # different on-chain keys.
    anonymize_liquid_seed_derivation_version: int = 0
    anonymize_liquid_min_dwell_s: int = 3 * 3600
    anonymize_liquid_max_dwell_s: int = 24 * 3600
    # Liquid leg's per-operator quote dwell.
    anonymize_liquid_quote_dwell_min_s: int = 60
    anonymize_liquid_quote_dwell_max_s: int = 600
    # Boltz chain-swap API endpoints (LN↔L-BTC↔LN). Empty disables
    # the corresponding side of the round-trip.
    boltz_chain_ln_to_lbtc_api_url: str = ""
    boltz_chain_lbtc_to_ln_api_url: str = ""
    # L-BTC asset id allow-list. Mainnet + testnet have
    # well-known constants (see ``liquid_ct.LBTC_ASSET_ID_*``);
    # regtest is operator-config-dependent (the regtest L-BTC asset
    # id is determined by the elementsd network parameters). When
    # set, this value overrides any built-in default — operators
    # who want to pin a non-default asset id can do so explicitly.
    # 64-char lowercase hex (no ``0x`` prefix); empty falls back to
    # the built-in default per ``BITCOIN_NETWORK``.
    anonymize_liquid_btc_asset_id: str = ""

    # Electrs-liquid endpoint the wallet's
    # ``ElectrumLiquidBackend`` connects to. Internal-network Docker
    # deployments use the overlay's ``electrs-liquid:50001``;
    # external-host deployments expose the indexer via Tor and the
    # operator supplies the onion URL here. Format:
    # ``tcp://host:port`` or ``ssl://host:port``.
    anonymize_liquid_electrum_url: str = ""
    # Runtime gate guarding the Liquid hop's end-to-end path. The
    # claim ceremony (cooperative MuSig2 + Liquid tx assembly) needs
    # a Node subprocess extension that the operator must validate
    # against a real Boltz regtest harness before flipping this to
    # ``true``. Default false so unverified deployments cannot start
    # a stuck session.
    anonymize_liquid_integration_verified: bool = False

    # Liquid fee oracle. Cached + clamped so per-quote reads
    # never trigger egress to the backend (defeats per-session
    # timing-correlation). The recurring oracle-refresh task polls the
    # backend on ``anonymize_liquid_fee_rate_cache_ttl_s`` cadence and
    # writes the cache; quote-time reads are synchronous + cache-only.
    # Floor/ceiling clamp the reported rate so a misbehaving backend
    # cannot produce a "fee-zero" or "fee-drain" quote.
    anonymize_liquid_fee_rate_floor_sat_per_vb: float = 0.1
    anonymize_liquid_fee_rate_ceiling_sat_per_vb: float = 1000.0
    anonymize_liquid_fee_rate_cache_ttl_s: int = 300
    anonymize_liquid_fee_rate_default_target_blocks: int = 6

    # Liquid residual swap-out dust threshold. Residual L-BTC
    # outputs at wallet-controlled addresses below this size cannot
    # be economically recovered via an L-BTC->LN submarine swap —
    # the operator fee + Liquid network fee exceeds the residual
    # itself. The recovery banner still surfaces sub-threshold
    # outputs (for operator awareness + audit) but disables the
    # swap-out button on them; an explicit "acknowledge as dust"
    # admin action stamps the row so it stops contributing to the
    # banner total. Conservative default; refine if telemetry shows
    # operator fees moving meaningfully.
    liquid_residual_dust_threshold_sat: int = 5000
    # How often the residual-balance scan task polls
    # electrs-liquid for unspent wallet-controlled outputs. The
    # scan only runs at all when at least one Liquid hop has been
    # attempted in the wallet's history (avoids unnecessary egress
    # on LN-only deployments).
    liquid_residual_scan_interval_s: int = 15 * 60

    @property
    def anonymize_amount_bins_list(self) -> list[int]:
        """Parse ``anonymize_amount_bins_sat`` into a sorted ascending list."""
        raw = self.anonymize_amount_bins_sat.strip()
        if not raw:
            return []
        if raw.startswith("["):
            return sorted(int(v) for v in json.loads(raw))
        return sorted(int(v) for v in raw.split(",") if v.strip())

    @property
    def anonymize_tier_cap_dict(self) -> dict[str, int]:
        """Parse ``anonymize_tier_concurrency_cap`` into a dict."""
        out: dict[str, int] = {}
        raw = self.anonymize_tier_concurrency_cap.strip()
        if not raw:
            return out
        if raw.startswith("{"):
            return {str(k): int(v) for k, v in json.loads(raw).items()}
        for part in raw.split(","):
            if "=" not in part:
                continue
            k, _, v = part.partition("=")
            out[k.strip()] = int(v.strip())
        return out

    @property
    def anonymize_tor_socks_ports_dict(self) -> dict[str, int]:
        """Parse ``anonymize_tor_socks_ports`` into a dict."""
        out: dict[str, int] = {}
        raw = self.anonymize_tor_socks_ports.strip()
        if not raw:
            return out
        if raw.startswith("{"):
            return {str(k): int(v) for k, v in json.loads(raw).items()}
        for part in raw.split(","):
            if "=" not in part:
                continue
            k, _, v = part.partition("=")
            out[k.strip()] = int(v.strip())
        return out

    @property
    def resolved_tor_control_password(self) -> str:
        """Single resolver for the Tor control-port password.

        Prefers the unified ``TOR_CONTROL_PASSWORD`` knob. Falls
        back to the legacy ``ANONYMIZE_TOR_CONTROL_PASSWORD`` so
        operators who configured it historically don't have to
        migrate immediately. Returns the empty string when neither
        is set (no auth attempted; control-port stack stays dormant
        unless the entrypoint shim has left the port unauthenticated).
        """
        if self.tor_control_password:
            return self.tor_control_password
        return self.anonymize_tor_control_password

    @property
    def anonymize_peer_blocklist_list(self) -> list[str]:
        return _parse_str_list(self.anonymize_peer_blocklist)

    @property
    def anonymize_registry_release_key_fingerprints_list(self) -> list[str]:
        # multi-fingerprint allow-list with legacy alias support.
        out = _parse_str_list(self.anonymize_registry_release_key_fingerprints)
        if not out and self.anonymize_registry_release_key_fingerprint.strip():
            out = [self.anonymize_registry_release_key_fingerprint.strip()]
        return out

    @property
    def anonymize_registry_threshold_sig_paths_list(self) -> list[str]:
        return _parse_str_list(self.anonymize_registry_threshold_sig_paths)

    @property
    def cors_origins_list(self) -> list[str]:
        return _parse_str_list(self.cors_origins)

    @property
    def trusted_proxies_list(self) -> list[str]:
        return _parse_str_list(self.trusted_proxies)

    @property
    def bolt12_blinded_path_omit_pubkeys(self) -> list[bytes]:
        """Decoded omit-pubkey list for blinded-path construction.

        Skips entries that aren't 33-byte compressed pubkeys after hex
        decode — a malformed env var should not block invoice minting.
        """
        out: list[bytes] = []
        for entry in _parse_str_list(self.bolt12_blinded_path_omit_nodes):
            try:
                pk = bytes.fromhex(entry)
            except ValueError:
                continue
            if len(pk) == 33:
                out.append(pk)
        return out

    @model_validator(mode="after")
    def _warn_placeholder_passwords(self) -> "Settings":
        """Warn at startup if placeholder passwords from .env.example are in use."""
        _log = logging.getLogger(__name__)
        _placeholders = ("change-me", "__replace_me__")
        for field in ("database_url", "redis_url", "secret_key"):
            value = getattr(self, field, "")
            hit = next((p for p in _placeholders if p in value.lower()), None)
            if hit:
                msg = (
                    f"{field.upper()} contains a placeholder password ('{hit}'). "
                    f"Update it before deploying to production."
                )
                _log.warning(msg)
                warnings.warn(msg, stacklevel=1)
        return self

    @model_validator(mode="after")
    def _validate_secret_key_strength(self) -> "Settings":
        """Enforce a minimum SECRET_KEY strength at config load.

        SECRET_KEY keys API-key hashing, field encryption, and the audit
        hash chain, so a weak or placeholder value undermines all three.
        Validating here (rather than only at API startup) means every
        process that loads settings — Celery workers, management scripts,
        migrations — fails closed identically instead of operating under a
        weak secret. ``SECRET_KEY_PREVIOUS``, when set for rotation, must
        meet the same bar.
        """
        _insecure = {"", "change-me-to-a-random-64-char-string"}
        if self.secret_key in _insecure or len(self.secret_key) < 32:
            raise ValueError(
                "SECRET_KEY is missing or too weak (must be >= 32 chars and not a "
                "placeholder). Generate one with: "
                "python -c 'import secrets; print(secrets.token_hex(32))'"
            )
        if self.secret_key_previous and len(self.secret_key_previous) < 32:
            raise ValueError("SECRET_KEY_PREVIOUS is set but too weak (must be >= 32 chars).")
        return self

    @model_validator(mode="after")
    def _validate_anonymize_seed_material(self) -> "Settings":
        """Validate decoy / Liquid seed material at config load.

        When the features that consume this material are enabled, a
        missing or malformed value is rejected here so every process
        fails closed at startup rather than at the first session that
        derives an address. Mirrors the strength the call sites enforce:
        the decoy account key folds into a BIP-32 derivation and needs at
        least 16 bytes; the decoy and Liquid seeds are Fernet bundles
        whose every comma-separated key must be a 44-char urlsafe-base64
        string decoding to 32 bytes.
        """

        def _fernet_key_ok(key: str) -> bool:
            try:
                return len(base64.urlsafe_b64decode(key.encode("ascii"))) == 32
            except Exception:
                return False

        def _bundle_ok(value: str) -> bool:
            keys = [k.strip() for k in value.split(",") if k.strip()]
            return bool(keys) and all(_fernet_key_ok(k) for k in keys)

        if self.anonymize_enabled and self.anonymize_decoy_seed_required:
            account_key = (self.anonymize_decoy_seed_account_key or "").strip()
            if len(account_key.encode("utf-8")) < 16:
                raise ValueError(
                    "ANONYMIZE_DECOY_SEED_ACCOUNT_KEY must be at least 16 bytes "
                    "when the decoy seed is enabled (ANONYMIZE_DECOY_SEED_REQUIRED=true)."
                )
            if not _bundle_ok((self.anonymize_decoy_seed_fernet or "").strip()):
                raise ValueError(
                    "ANONYMIZE_DECOY_SEED_FERNET must be a comma-separated list of "
                    "44-char urlsafe-base64 Fernet keys when the decoy seed is enabled."
                )

        if self.anonymize_liquid_enabled and not _bundle_ok((self.anonymize_liquid_seed_fernet or "").strip()):
            raise ValueError(
                "ANONYMIZE_LIQUID_SEED_FERNET must be a comma-separated list of "
                "44-char urlsafe-base64 Fernet keys when the Liquid hop is enabled "
                "(ANONYMIZE_LIQUID_ENABLED=true)."
            )
        if self.anonymize_liquid_seed_derivation_version not in (0, 1):
            raise ValueError(
                "ANONYMIZE_LIQUID_SEED_DERIVATION_VERSION must be 0 or 1; got "
                f"{self.anonymize_liquid_seed_derivation_version}."
            )
        return self

    @model_validator(mode="after")
    def _validate_rate_limit_fail_policy(self) -> "Settings":
        """Refuse to
        boot the API with ``RATE_LIMIT_FAIL_POLICY=open`` in
        production. With ``open`` semantics a Redis outage silently
        disables every Redis-backed dashboard protection
        (revocation, idle timeout, IP binding, rate limit) — an
        unacceptable failure mode for a production wallet. Operators
        who want this for local development must explicitly set
        ``DEBUG=true``.
        """
        if (self.rate_limit_fail_policy or "").strip().lower() == "open" and not self.debug:
            raise ValueError(
                "RATE_LIMIT_FAIL_POLICY=open is not permitted in "
                "production (DEBUG=false). It silently disables "
                "session revocation, idle-timeout, IP binding, and "
                "rate limits when Redis is unavailable. Set "
                "RATE_LIMIT_FAIL_POLICY=closed (default) or set "
                "DEBUG=true to opt into the dev-only behaviour."
            )
        return self

    @model_validator(mode="after")
    def _validate_database_ssl(self) -> "Settings":
        """Refuse to boot when DATABASE_URL targets a public host without SSL.

        A database reached over a globally-routable address carries the audit
        log, API-key HMACs, and encrypted-field ciphertext across the network;
        on that link ``DATABASE_REQUIRE_SSL`` must be on (it drives a fully
        cert- and hostname-verified ``ssl.create_default_context()`` in
        ``database.py``). Internal targets are exempt: a SQLite file, a
        loopback / private / non-routable IP, a single-label docker/k8s
        service name, or a ``*.local`` / ``*.internal`` hostname. ``DEBUG=true``
        opts out entirely for local experimentation.
        """
        url = (self.database_url or "").strip()
        if not url or url.startswith("sqlite") or self.database_require_ssl or self.debug:
            return self

        from urllib.parse import urlparse

        host = (urlparse(url).hostname or "").lower()
        if not host or host == "localhost":
            return self

        try:
            import ipaddress

            ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(host)
        except ValueError:
            ip = None

        if ip is not None:
            # IP literal: a non-routable address (loopback / RFC1918 / CGNAT /
            # link-local / reserved) stays on an internal link.
            if not ip.is_global:
                return self
        else:
            # Hostname: a single-label service name (docker/k8s) or an explicit
            # internal suffix is an internal target; a multi-label FQDN is
            # treated as potentially public.
            if "." not in host or host.endswith((".local", ".internal")):
                return self

        raise ValueError(
            "DATABASE_URL targets a public host but DATABASE_REQUIRE_SSL is "
            "false. The audit log, API-key hashes, and encrypted-field "
            "ciphertext would cross the network in cleartext. Set "
            "DATABASE_REQUIRE_SSL=true, or DEBUG=true for local development."
        )

    @model_validator(mode="after")
    def _validate_cors_origins(self) -> "Settings":
        """Refuse the wildcard CORS origin.

        ``main.py`` builds the CORS middleware with
        ``allow_credentials=True`` whenever any origin is configured.
        Starlette, given ``allow_origins=["*"]`` together with
        ``allow_credentials=True``, *reflects* the caller's Origin and
        emits ``Access-Control-Allow-Credentials: true`` — i.e. any
        website can make credentialed cross-origin reads against the
        dashboard/API. A wallet must never combine the two. Operators
        list explicit origins instead.
        """
        if "*" in self.cors_origins_list:
            raise ValueError(
                "CORS_ORIGINS='*' (wildcard) is not permitted: combined "
                "with credentialed requests it lets any website read "
                "dashboard/API responses. List explicit origins, e.g. "
                "CORS_ORIGINS=https://wallet.example.com"
            )
        return self

    @model_validator(mode="after")
    def _validate_chain_backend(self) -> "Settings":
        """Validate chain backend selection + Electrum URL.

        Rules:
        * ``chain_backend="electrum"`` requires ``lnd_electrum_url``.
        * ``chain_backend="mempool"`` with ``lnd_electrum_url`` set is a likely
          misconfiguration — warn but allow.
        * If ``lnd_electrum_url`` is set, validate scheme (``tcp://`` / ``ssl://``)
          and port. ``.onion`` hosts require ``lnd_tor_proxy`` to be set.
        """
        _log = logging.getLogger(__name__)
        url = (self.lnd_electrum_url or "").strip()

        if self.chain_backend == "electrum" and not url:
            raise ValueError("CHAIN_BACKEND='electrum' requires LND_ELECTRUM_URL to be set")

        if self.chain_backend == "mempool" and url:
            _log.warning(
                "CHAIN_BACKEND='mempool' but LND_ELECTRUM_URL is set (%s) — Electrum URL will be ignored.",
                url,
            )

        if url:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            if parsed.scheme not in ("tcp", "ssl"):
                raise ValueError(f"LND_ELECTRUM_URL must use tcp:// or ssl:// (got '{parsed.scheme}://')")
            if not parsed.hostname:
                raise ValueError("LND_ELECTRUM_URL is missing a hostname")
            # Default port: 50001 for tcp, 50002 for ssl. Validation only.
            port = parsed.port
            if port is not None and not (1 <= port <= 65535):
                raise ValueError(f"LND_ELECTRUM_URL port must be 1..65535 (got {port})")
            host = parsed.hostname.lower()
            if host.endswith(".onion") and not (self.lnd_tor_proxy or "").strip():
                raise ValueError("LND_ELECTRUM_URL is a .onion hostname but LND_TOR_PROXY is not configured")
        return self

    @model_validator(mode="after")
    def _validate_chain_backend_force_tor(self) -> "Settings":
        if self.chain_backend_force_tor == "true" and not (self.lnd_tor_proxy or "").strip():
            raise ValueError("CHAIN_BACKEND_FORCE_TOR='true' requires LND_TOR_PROXY to be configured")
        return self

    def chain_backend_force_tor_enabled(self) -> bool:
        """Whether clearnet chain-backend traffic should route via Tor.

        ``.onion``/``.local`` hosts proxy unconditionally elsewhere; this
        governs only clearnet hosts. ``auto`` enables it when LND itself is
        reached over a ``.onion`` address (a Tor-only deployment).
        """
        mode = self.chain_backend_force_tor
        if mode == "true":
            return True
        if mode == "false":
            return False
        from urllib.parse import urlparse

        try:
            host = (urlparse(self.lnd_rest_url).hostname or "").lower()
        except Exception:
            return False
        return host.endswith(".onion")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }


settings = Settings()  # type: ignore[call-arg]

# Shared API version prefix — used by all routers
API_V1_PREFIX = "/v1"
