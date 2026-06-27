# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-06-27

### Added

#### Small-channel peer discovery
- Public guide [`docs/small-channel-peers.md`](docs/small-channel-peers.md):
  a vetted list of 15 Lightning routing peers confirmed (by empirical
  channel open) to accept ~150,000 sat opens. For each peer: pubkey,
  socket, channel count, capacity, fee structure (median + min/max
  base/ppm), outbound-enable ratio, `min_htlc` / `time_lock_delta` /
  `max_htlc`, geographic location, and a plain-English summary of
  trade-offs. Intended for new operators / small wallets needing
  inbound liquidity without committing to 1M-sat-plus channels.
  Indexed in `docs/README.md`.
- Companion CLI tooling at [`scripts/peer_probe/`](scripts/peer_probe/):
  `recon.py` ranks the LN graph by small-channel-friendliness from a
  local LND's `DescribeGraph` view; `probe.py` walks the resulting
  candidates one at a time, opening a real ~150 k sat channel, and
  records each outcome to a persistent JSON checkpoint so the
  operator can stop / resume across many rounds without losing
  state. Both honour an operator-supplied SKIP set and the new
  routing-health filter (see *Changed* below).

#### Dashboard
- **Reverse-swap lockup transaction surfaced in the UI.** `BoltzSwap.lockup_txid`
  is now persisted the first time we observe a `transaction.mempool` /
  `transaction.confirmed` event from Boltz, and both the Open Inbound
  and Cold Storage panels render a Mempool link plus live confirmation
  count for the lockup TX (alongside the existing claim-TX panel).
  Previously the lockup txid was referenced only during ephemeral
  verification and the user had no visibility into the on-chain step
  while waiting for it to confirm.
- **"Reconnect peer" action on stuck channels.** When a channel is
  inactive because we're still waiting for the peer to send
  `channel_ready` after enough confirmations (standard LND foot-gun
  after a long open), the dashboard channel card now offers a one-tap
  "Reconnect peer" button that disconnects + reconnects the peer via
  the new
  `POST /dashboard/api/channels/{chan_id}/reconnect-peer` endpoint.
  Picks the best clearnet address from the peer's gossiped
  `node_announcement` with clearnet-IPv4 → clearnet-IPv6 → Tor
  fallback. No funds movement; safe to run against an
  already-healthy channel.
- **Three-state channel-status indicator.** Channel cards now
  distinguish **active** (green), **waiting for `channel_ready`**
  (yellow, with the "Reconnect peer" affordance), and **peer offline**
  (grey). Backed by a new `LNDService.list_peer_pubkeys()` helper
  whose result is joined with the active-channels list so the
  dashboard can tell apart the two "inactive but not the same thing"
  states that both surface as `active=False` on LND's channel record.
- **One-tap "use suggested amount" retry on cold-storage rejection.**
  When `POST /dashboard/api/cold-storage/initiate` is rejected for
  `insufficient_balance`, the response now includes
  `available_sats` and `suggested_amount_sats` (the largest
  amount whose `A * (1 + routing_fee_buffer_pct)` fits in
  `available`). The dashboard renders an inline retry button that
  drops the suggested value into the amount field, so users no
  longer need to redo the math by hand.

### Changed

#### BOLT 12
- **Blinded-path `PAYINFO` safety-margin base bumped 1,000 → 1,500 msat**
  (`BOLT12_BLINDED_PATH_PAYINFO_SAFETY_MARGIN_BASE_MSAT`). A multi-hop
  intro audit row on 2026-06-26 showed a ~367 msat extra undisclosed
  deduction, which fit within the prior 1,000 msat floor only with
  zero headroom. Raising the default to 1,500 preserves the same
  flat-headroom property with margin. Per-payment cost: 0.0015 sat
  (negligible). `start.sh` and `.env.example` updated to match.

#### Boltz claim subprocess + DB pool
- **Boltz claim/refund Node.js subprocess calls are now non-blocking.**
  Replaced four blocking `subprocess.run(timeout=…)` sites in
  `BoltzSwapService` — `cooperative_claim`, `unilateral_claim`,
  `cooperative_refund_submarine`, `unilateral_refund_submarine` —
  with `asyncio.create_subprocess_exec` + `proc.communicate`. The
  previous synchronous call froze the entire event loop for up to
  120 s per call, which under sustained load left the async
  SQLAlchemy pool unable to recycle connections (see *Fixed*). The
  10-second keypair-gen subprocess at swap creation is unchanged —
  its blocking window is short and the call doesn't hold a DB
  session.
- **Boltz-recovery classifier soft-pedals fresh failures.** During
  the first 20 minutes after a failed cooperative-claim attempt
  (`CLAIM_RETRY_GRACE_SECONDS = 20 * 60`), the classifier now
  returns a new INFO-severity `claim_retry_in_progress` hint with
  copy "Retrying claim shortly" rather than the WARNING-severity
  `claim_retry_available` "Claim attempt failed; retry available."
  The auto-retry pipeline (Boltz status poll, periodic
  `recover_boltz_swaps`, or external block notification) almost
  always lands the next attempt within this window; previously
  users saw a scary banner during the normal recovery cycle. The
  same retry action stays available throughout — only the copy and
  severity are downgraded.

#### Peer-probe recon filter
- **`recon.py` now excludes non-routing nodes.** New
  `--max-disabled-outbound-ratio` flag (default 0.50) drops nodes
  whose own outbound policy is disabled on more than 50% of their
  channels — catches the "accepts opens but won't actually route"
  pattern (e.g. 1ML.com node ALPHA, 82% disabled outbound, confirmed
  non-routing after a 150 k sat open + three reverse-swap attempts
  hitting `FAILURE_REASON_NO_ROUTE`). Combined with a small
  hardcoded `SKIP_PUBKEYS` set covering known self-rejecting
  nodes (Megalithic main + small-channels), custodial wallets
  (Wallet of Satoshi), and now 1ML.com node ALPHA.

#### Documentation
- README brought current with the code: alembic head bumped
  043 → 047 in the Project Structure listing; test-suite size
  corrected from "~1,400 tests" to "~3,900 tests across 376
  files"; Boltz retry-backoff tiers corrected from
  "10 s → 30 s → 120 s → 300 s" to the actual
  "15 s for the first 10 retries → 60 s for the next 20 → 300 s
  thereafter"; the API Reference admin table no longer lists four
  REST endpoints (`POST /v1/admin/api-keys` and its
  PATCH/DELETE/purge siblings) that have always been
  dashboard-only — API-key mutations stay session-authed and
  CSRF-gated at `/dashboard/api/api-keys[...]`. The Quickstart
  bootstrap-script callout now points subsequent-key creation at
  the dashboard's **⚙ Settings → API Keys** panel.

### Fixed

- **PostgreSQL connection-pool exhaustion under reverse-swap load.**
  The four blocking `subprocess.run(timeout=120)` calls in
  `BoltzSwapService` (see *Changed*) were freezing the event loop
  for up to 120 s per claim, holding open any DB session that
  happened to be checked out by the same coroutine. Under load
  this leaked 30 PostgreSQL connections into `idle in transaction`
  state, exhausting the SQLAlchemy pool (`pool_size=10 +
  max_overflow=20`) and causing the BOLT 12 settlement-subscriber
  poll, `/ready` health probe, and dashboard polls to fail with
  `QueuePool limit of size 10 overflow 20 reached`. Surfaced in
  StartOS as `Node Connectivity: Timed out. Retrying soon…`.
- **Reverse-swap "Max" button no longer fails the server-side check.**
  The dashboard previously auto-filled the Max amount without
  subtracting the 3% Boltz routing-fee buffer, so a fresh Max
  value would be rejected by `/cold-storage/initiate` at confirm
  time. A new `_withBoltzBuffer()` helper now applies the buffer
  client-side using the same constant the server enforces, so the
  numbers stay in sync.
- **Peer-probe state no longer poisoned by our-side failures.**
  `probe.py` now detects "our LND ran out of on-chain"
  (`reserved wallet balance invalidated`, `insufficient funds`)
  and **aborts the run without recording the attempted peer** —
  previously a wallet-OOM mid-batch falsely recorded every
  subsequent peer in the batch as `open_failed`. Transient
  transport errors (`connection refused`, `i/o timeout`, SOCKS
  read timeouts, etc.) are similarly skipped without recording so
  intermittently-flaky candidates stay in the pending queue for
  the next round.
- **Channel status no longer conflates two distinct
  "inactive" states.** LND returns `active=False` for both
  "channel exists on-chain but peer hasn't sent `channel_ready`
  yet" and "channel was active but the peer is now disconnected."
  The dashboard now distinguishes them (see the three-state
  indicator under *Added*), so the operator sees the correct
  remedy (wait / reconnect peer) instead of the same generic
  "inactive" state for both.

### Security

- **PostgreSQL `idle_in_transaction_session_timeout=300000`** (5 min)
  added to the asyncpg `connect_args` as a safety net. Any future
  session that gets abandoned mid-transaction — e.g. by coroutine
  cancellation while a long external await is in progress — will be
  reaped by PostgreSQL rather than sitting in the pool forever.
  Defence-in-depth against the specific bug fixed above and against
  any future similar regression.

## [0.1.0] - 2026-06-23

### Added

#### Dashboard
- Interactive single-page dashboard (Alpine.js + Tailwind CSS + Jinja2)
- Token-based login with session cookie authentication
- Balance overview cards: Total (BTC/sats toggle), On-chain (confirmed + pending), Outbound Lightning, Inbound Lightning
- Live mempool fee estimates bar (Low / Medium / High sat/vB) with error handling
- Collapsible Node Info panel (alias, sync status, channels, peers, block height)
- Five tabbed data views: Channels, Payments, Invoices, On-chain Transactions, Activity (Audit Log)
- Channel list with capacity visualization, remote alias, active/inactive status, and pending channels. Each card shows its last-activity time beside the local balance and offers two per-channel actions: **Rebalance** and **Open Inbound**
- Open Inbound dialog (per channel): frees up room to receive on a chosen channel by moving some of its balance out, with two destinations — **To my wallet** (a channel-pinned Boltz reverse swap into the user's own on-chain wallet, with a one-tap **Generate** button that mints a fresh native-SegWit address, a review step, and guided one-tap recovery if a swap gets stuck) or **Pay a Lightning bill** (pay a BOLT11 / LNURL / Lightning address out through that channel, with an optional max-fee control). Live fee preview with expandable details, an amount **Max** clamped to the channel's spendable balance, a swap progress tracker with the on-chain claim txid (copy + mempool link), and mid-swap refresh resume
- Close Channels dialog: a multi-select picker (search / sort / show-offline) for closing one or more channels at once. Online peers are closed cooperatively (funds back in minutes); offline peers are auto-detected and closed with a clearly-warned force close (funds time-locked until they mature). A review step groups cooperative vs force closes, a destructive confirm gates the action, and per-channel results offer a one-tap "force close instead" when a cooperative close can't reach the peer. Closing channels render in the channel list with plain-language status — cooperative closes show the closing tx + confirmations, force closes show a release countdown — and the On-chain card surfaces funds being released from a force-closed channel
- Fund Wallet dialog: address type selector (Taproot / Native SegWit / Nested SegWit), QR code, click-to-copy
- Send Payment dialog: multi-step flow with invoice paste, input type detection (BOLT11 / LNURL / Lightning Address), decode & review with expiry check, success/failure result with fee and hop details. Advanced routing controls mirror the Rebalance dialog: a `% / sats` fee-limit toggle with a live `≈ N sats max` hint, a configurable send timeout, an optional outgoing-channel pin via a collapsible "Source channel" accordion (search + sort + show-all), and an explicit "Estimate fee" button that probes the route and shows hops + fee + ppm before committing. The LNURL amount input has a Max button clamped to both the recipient's `maxSendable` and (when a source channel is pinned) the source's outbound headroom
- Receive Invoice dialog: amount (or open-amount), memo, expiry selector (10 min / 1 hour / 24 hours), QR code display, click-to-copy
- Open Channel dialog: peer pubkey + host, funding amount, fee rate, push amount, private channel toggle
- Cold Storage dialog with two modes:
  - On-chain: address validation with type detection, fee priority selector with live rates, amount with Send Max, review step with irreversibility warning
  - Lightning (Boltz): non-custodial reverse submarine swaps, fee breakdown, min/max from Boltz pair info, swap progress tracker
- QR code generation for addresses and invoices
- Copy-to-clipboard with visual feedback throughout
- Dark navy theme with neon accent color palette

#### API Key Management & Audit Log
- Settings dropdown in the dashboard header (replaces the bare Logout
  button) with entries for **API Keys**, **Audit Log**, and Logout.
  CSP-safe Alpine component; closes on `Esc` or outside-click.
- Three-tier permission model for API keys — every key carries a
  `scope`: **monitor** (read all state and receive funds — generate
  addresses, create invoices — but never move funds out), **spend**
  (monitor plus pay invoices / keysend / withdraw to cold storage —
  the tier for autonomous agents), or **admin** (full control,
  including channel management and message signing). A `spend` key
  can move funds without the god-mode that opening/closing channels,
  signing, and key management require; a `monitor` key powers a
  receive-only agent (point-of-sale, invoicing, donations) that is
  provably unable to spend. `is_admin` / `can_spend` are derived
  views of the scope; fund-moving endpoints are gated by a dedicated
  `get_spend_key` dependency that accepts `spend` or `admin`.
- API Keys modal: full inventory view with scope pills
  (`monitor` / `spend` / `admin`) and status pills (`active`,
  `expiring` ≤14d, `disabled`, `expired`, `revoked`), filter +
  search, and per-row lifecycle actions — rename (inline), rotate
  (mints replacement at the same scope, soft-deletes the old key
  only after the operator confirms they captured the new plaintext),
  pause/resume, change scope (a three-way selector with an explicit
  confirm modal that requires an extra acknowledgement when
  escalating to admin), revoke (soft delete), and purge (hard
  delete; gated by `AUDIT_LOG_RETENTION_DAYS`).
- Newly minted plaintext keys are shown exactly once with a copy
  button, an unmissable warning, and a "I've saved it" confirmation
  that wipes the secret from component state. The clipboard is
  auto-cleared 60 seconds after copy with a visible countdown
  (best-effort; only blanks when the clipboard still holds the key,
  with a fall-back wipe when `navigator.clipboard.readText()` is
  denied).
- Bootstrap-only callout: when the inventory contains a single
  active admin key, an info banner nudges the operator to mint
  scoped per-agent keys and keep the bootstrap key as a break-glass
  credential.
- Self-protection: the dashboard refuses to revoke / disable /
  demote the only remaining active admin key (UI guards plus a
  service-layer check that runs on every mutation).
- Audit Log modal: cursor-paginated viewer with filters (action
  dropdown, key-name substring, time range presets `1h / 24h / 7d
  / 30d / all`), expandable rows that pretty-print the `details`
  JSON via `textContent` (never `innerHTML`), red left border on
  failed entries, and a **Verify chain** button that walks the
  hash chain and reports the first tampered row.
- API-key *mutation* (create / update / delete / purge) is
  operator-only: it lives exclusively on the dashboard's
  session-authed surface (`/dashboard/api/api-keys`) and is
  deliberately **absent** from the API-key-authed REST router, so no
  API key — of any scope, including admin — can mint, promote, or
  revoke another key. The admin REST surface
  (`/api/v1/admin/api-keys`) keeps only the read-only inventory
  listing.
- `app/services/api_key_service.py` is the single source of
  truth for create / list / update / soft-delete / purge plus the
  audit-log emission that goes with each mutation, so validation,
  self-protection, retention-window gating, and audit emission stay
  byte-identical regardless of caller.
- All dashboard mutations are CSRF-protected, attributed to the
  `DASHBOARD_KEY_ID` sentinel in the audit log with the originating
  IP, and surfaced in `Audit Log → Verify chain` for tamper
  evidence.

#### Sign / Verify Message
- Dashboard "Sign / Verify Message" modal in the On-chain tab with a
  three-step sign flow (form → review → result), a Verify tab with
  paste-and-autofill, and multi-format export (JSON, Sparrow / Bitcoin
  Core 3-line, ASCII armor) for address signatures plus signature-only
  or JSON export for Lightning node-identity signatures.
- Opt-in API endpoints for signing arbitrary messages with the
  base-layer wallet keys (BIP-322 simple for SegWit/Taproot, BIP-137
  for legacy P2PKH/P2SH-P2WPKH) and with the Lightning node identity
  key (zbase32). Verification endpoints are always mounted; sign
  endpoints are gated behind `ENABLE_SIGN_ADDRESS_API` and
  `ENABLE_SIGN_NODE_API` (both default `false`, so disabled routes
  return `404` to probes).
- Per-API-key sliding-window rate limit on sign ops
  (`SIGN_RATE_LIMIT_PER_HOUR`, default 30) backed by Redis and failing
  closed on Redis errors.
- Configurable max message length (`SIGN_MESSAGE_MAX_CHARS`, default
  4096) and audit-record-plaintext toggle (`SIGN_AUDIT_RECORD_MESSAGE`,
  default `false` — only SHA-256 + length recorded).
- Configurable dashboard address autocomplete
  (`SIGN_ADDRESS_AUTOCOMPLETE`: `txn_history` | `wallet_addresses` |
  `off`).

#### BOLT 12
- Pure-Python BOLT 12 codec for offers, invoice requests, and
  invoices: bech32-no-checksum encoding/decoding with `+`-continuation
  support, BigSize-prefixed TLV streams with strict canonical-encoding
  enforcement, and field-level helpers for every spec-defined record.
- Schnorr/BIP-340 signing and verification over the BOLT 12 merkle
  tag-hash tree, including the offer issuer key path and per-invreq
  payer key path, plus a selective-disclosure proof builder
  (`build_proof`) that reveals chosen TLVs while hiding the rest
  behind merkle siblings — signature-range TLVs (types 240..1000) are
  always stripped before proof emission.
- BOLT 12 REST router (`/v1/bolt12/*`, 17 endpoints): decode, import
  offer, list/get/deactivate offers, mint signed offers, set/clear
  default-receive offer, list invoices for an offer, fetch a stored
  invoice, build a disclosure proof, send `invoice_request` and
  persist the signed reply (pay-offer flow), receive-side controls,
  service status, and BIP-353 resolve / zone-record endpoints.
- Inbound `invoice_request` responder that decodes the request,
  resolves the matching offer (issuer-key reuse semantics: lookup by
  decoded offer bytes scoped to the receiving API key), enforces the
  amount/quantity/chain/expiry rules, mints a Schnorr-signed
  `invoice` via LND, persists it under
  `(api_key_id, payment_hash_hex)`, and replies through the supplied
  blinded reply path.
- Idempotent inbound handling: replays of an `invoice_request` with
  the same `invreq_metadata` re-emit the previously minted invoice
  rather than minting a fresh one. Backed by a partial unique index
  on `(api_key_id, invreq_metadata_hex)` for inbound rows
  (Alembic migration `013_bolt12_invreq_metadata_dedup`) and a
  composite unique index on `(api_key_id, payment_hash_hex)`
  (migration `014_bolt12_payment_hash_unique`).
- BIP-353 payment-handle resolver (`user@domain` → `bitcoin:` URI):
  TCP-only DNS via `dns.query.tcp` (no UDP fallback), per-resolver
  DNSSEC-validation probe against `dnssec-failed.org` cached behind a
  thread lock, multi-nameserver failover, strict LDH-ASCII label
  validation, and an RFC1035 zone-record builder for publishing
  handles. Insecure-resolver and DNS-failure errors surface as
  sanitised `502`s; full exceptions land in structured logs only.
- Out-of-process BOLT 12 onion-message gateway (`bolt12-gateway`,
  Rust + LDK) with a gRPC API (`proto/bolt12_gateway.proto`) consumed
  by the orchestrator. The orchestrator caps in-flight requests
  (`BOLT12_MAX_PENDING_REQUESTS`, default 64), drops oversized
  inbound payloads (`BOLT12_MAX_PAYLOAD_BYTES`, default 64 KiB),
  enforces TLV count and value-size caps on every inbound message,
  and tracks per-flow metrics (sent / unmatched / oversized /
  capacity-exceeded / send-failure / responder-rejected /
  responder-error counters).
- Gateway honours LDK's `Event::ConnectionNeeded` in
  `bolt12-gateway/src/runner.rs`: when an outbound onion-message
  reply (typically the invoice reply on a BOLT 12 fetchinvoice
  round-trip) is buffered waiting for a peer we're not yet
  connected to, the onion-event pump dials that peer through
  `sticky_peers::dial_peer` so LDK can flush the buffered message.
  Addresses are resolved in priority order from: the event's
  `addresses` field, a wallet-pushed in-memory address cache, and
  the LDK `NetworkGraph`'s latest signed `node_announcement` (the
  third is empty under the current `IgnoringMessageHandler` config
  but retained for future configurations that consume gossip).
  Each dial is fire-and-forget on a dedicated tokio task so a slow
  TCP handshake never blocks the pump, and the fan-out is bounded
  by a `Semaphore` capped at 32 concurrent dials so a payer that
  varies their reply-path introduction node across many peers
  cannot force unbounded outbound connections. Without this
  handler, an Ocean payout whose reply-path introduction node we
  didn't already peer with timed out at 60 s (2026-06-03 incident).
- Wallet-side address cache for the gateway's `ConnectionNeeded`
  recovery (2026-06-04 incident). The gateway's LDK NetworkGraph
  stays empty under `IgnoringMessageHandler` so the previous
  gossip-only fallback never had addresses to surface. New gRPC
  streaming RPC `SetKnownNodeAddresses` lets the wallet push LND's
  `DescribeGraph` view (top-N by channel count, 5 000 default) to
  the gateway's in-memory cache; the `ConnectionNeeded` handler
  consults the cache before warning. Freshness:
  * **1 h periodic refresh** (`BOLT12_GATEWAY_NODE_ADDRESS_REFRESH_INTERVAL_S`).
    Failure / disconnect backs off to a 60 s retry cadence so the
    cache hydrates within a minute of an api↔gateway reconnect
    instead of the full hour.
  * **24 h per-entry TTL** in `AddressCache::lookup_at` so a peer
    that stops gossiping ages out even if the wallet push side
    falls behind.
  * **10 min negative-cache window** on all-candidate dial
    failures, so a dead pubkey doesn't burn a Tor circuit per
    payment retry.
  * **REPLACE semantics** on push, staged-then-swap on the
    service side so a mid-stream validation error never half-
    clears the existing cache.
  Address list per pubkey preserves `.onion`-first ordering so
  the gateway's SOCKS5-tunnelled dial tries the most-likely-to-
  work address before clearnet fallback.
- Cross-tenant isolation throughout: every BOLT 12 row carries
  `api_key_id` and every query, dedup index, and audit event is
  scoped to the calling key so issuer-key collisions across tenants
  cannot leak invoices or offers.
- Audit hygiene: every state-changing BOLT 12 endpoint emits an
  audit event with redacted detail (no full bolt12 strings, no
  payment hashes in cleartext beyond their own `payment_hash_hex`
  column).
- Configuration knobs: `BOLT12_ENABLE`, `BOLT12_GATEWAY_URL`,
  `BOLT12_REQUEST_TIMEOUT_SECONDS`, `BOLT12_MAX_PENDING_REQUESTS`,
  `BOLT12_MAX_PAYLOAD_BYTES`, `BOLT12_MAX_TLV_COUNT`,
  `BOLT12_MAX_TLV_VALUE_BYTES`, `BOLT12_BIP353_VALIDATE_RESOLVER`,
  and the receive-side toggles for offerless / open-amount
  acceptance.

#### Anonymize (privacy-preserving UTXO + Lightning mixing)
- Full anonymize feature shipped behind `ANONYMIZE_ENABLED=true`. A
  threat-model-driven design with three privacy/capability tiers (see
  [docs/anonymize.md](docs/anonymize.md)):
  - **Lightning sources (moderate tier)**: Lightning-source mixing via Boltz reverse swaps. Per-call
    Tor stream isolation across dedicated SOCKS listeners, amount binning,
    cooperative MuSig2 claim, randomized broadcast jitter, blinded BOLT 11
    ext-lightning deposit invoices, MPP fragmentation with bounded K-fallback,
    destination-reuse hard-block, frozen pipeline policy with schema
    versioning. Tier ceiling: `moderate` (Lightning sources).
  - **On-chain sources + private channels**: `submarine` hop unlocks
    `onchain-self` and `ext-onchain` sources via Boltz submarine swaps; `priv_channel`
    hop opens a throwaway private channel + cooperative close; multi-operator
    pair sampling with response-signature verification; exact-bin coin selection
    + over-padded consolidation; decoy outputs with separate BIP-86 seed;
    refund-UTXO lockdown.
  - **Liquid round-trip (strongest tier)**: Liquid round-trip hop interposes a
    Confidential-Transactions-blinded L-BTC dwell between the two LN legs;
    in-process decoy spending gated by step-up re-auth (BIP-32 chain walk +
    BIP-86 taproot tweak + BIP-340 Schnorr + BIP-341 sighash, pinned against
    published test vectors); BIP-353 destination resolution via DoH-over-Tor;
    BOLT 12 exit hop for BIP-353 handles publishing only `lno=`; per-session
    BOLT 12 offer minting for ext-lightning deposits with optional BIP-353
    handle generation; multi-output sessions split a single source into N
    outputs with independent per-output timing; threshold-signed operator
    registry opt-in.
 admission policy: single-operator on-chain sessions are admitted at
  the `moderate` tier cap (was: hard-refused) with an in-wizard advisory banner.
  Configuring `BOLTZ_SUBMARINE_ONION_URL` and `BOLTZ_REVERSE_ONION_URL` to
  distinct onions suppresses the banner + lifts the cap.
- v1 ships with a curated, signed operator registry at
  `app/services/anonymize/operators.json` covering canonical Boltz + two
  community Boltz-protocol operators (Middle Way + Eldamar, verified live
  2026-05-13). Detached GPG signature at `operators.sig.asc` verifies against
  the in-repo `maintainer.asc` public key + the pinned fingerprint in
  `ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS`. Both armored OpenPGP (RSA /
  EdDSA) and raw ed25519 detached signatures are supported; the verifier
  auto-detects format. See [docs/anonymize_operator_diversity.md](docs/anonymize_operator_diversity.md)
  for the maintainer signing ceremony and operator-evaluation runbook.
- `start.sh` install wizard offers two pre-vetted alt-operator picks (Middle
  Way for healthy liquidity, Eldamar for contactability) so users can opt
  into distinct-leg routing at install time; auto-generates all required
  Fernet at-rest encryption keys (`ANONYMIZE_REUSE_DETECTION_KEY_FERNET`,
  `ANONYMIZE_HOP_IDEMPOTENCY_KEY_FERNET`, `ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET`,
  `ANONYMIZE_QUOTE_CACHE_SIGNING_KEY_FERNET`, `ANONYMIZE_STEPUP_COOKIE_HMAC_KEY_FERNET`,
  `ANONYMIZE_DECOY_SEED_FERNET`, optional `ANONYMIZE_LIQUID_SEED_FERNET`)
  and warns about backup-envelope discipline (separate from the LND seed).
- Dashboard wizard: 3-step quote/review/confirm flow with single-operator
  advisory banner on step 1, deposit-method radio (BOLT 11 / BOLT 12) on
  step 2 for ext-lightning sources, tier-tier cap reason surfaced verbatim
  on step 3, new step 4 renders the deposit primitive (BOLT 11 invoice /
  BOLT 12 offer / BIP-353 handle / on-chain address) with QR + click-to-copy.
- 25 new env knobs covering tier-concurrency caps, retention horizons,
  destination-reuse rate limits, MPP K range, inter-leg delay window, Liquid
  fee-oracle floor/ceiling, BIP-353 DoH endpoint + cache TTL, ext-lightning
  deposit method default, optional `ANONYMIZE_BIP353_DEPOSIT_DOMAIN` for
  per-session deposit handles, operator-registry signing fingerprints, and
  the hard-refusal flags for decoy / refund override spends.
- 1946 anonymize-specific unit tests covering scorer cap stacking, pipeline
  validator, hop bodies (reverse / submarine / priv_channel / liquid /
  bolt12_pay), operator registry signature verification (both GPG and raw
  ed25519), per-session pair sampling, BIP-353 DNS resolver, BOLT 12
  outbound settlement, multi-output orchestration, GC retention passes,
  Tor circuit-rebuild bandwidth limiting, decoy-spend BIP-86/BIP-341
  signing primitives, install-artifact pins (operator onions, fingerprints,
  Fernet generators). Two regtest integration suites exercise the Liquid
  swap-chain end-to-end against a `MockLiquidBackend` and a real Liquid
  mainnet tx fixture.
- Operator runbook in [docs/anonymize.md](docs/anonymize.md) covers Tor
  listener layout, Liquid overlay deployment (`docker-compose.liquid.yml`
  with `elementsd` + `electrs-liquid`), backup-envelope discipline for the
  three separate at-rest seeds, stuck-state triage, threshold-signed
  registry rotation, step-up nonce lockout policy.

#### LNURL-pay & Lightning Address (LUD-01 / LUD-06 / LUD-12 / LUD-16 / LUD-17)
- Dashboard-only send flow for `user@domain.tld` Lightning Addresses
  and bech32 `lnurl1...` strings (also accepts the `lightning:`
  scheme prefix per LUD-17). Two-stage UX: a recipient card
  (image, domain, description, min/max sendable) is shown after
  resolution; the user picks an amount + optional comment; the
  server fetches the BOLT11 from the recipient and feeds it into
  the existing pay confirm panel.
- Server-side LNURL bech32 decoder
  (`app/core/bech32_lnurl.py`) — vendored, no new dependencies,
  capped at 2 KB to prevent DoS via overlong inputs.
- New `LnurlService`
  (`app/services/lnurl_service.py`) handling resolve + invoice
  request with strict validation: SHA-256 metadata binding,
  exact-msat amount match, expiry refusal under 60 s, response-
  body size cap, no HTTP redirects. Cross-host callbacks are
  permitted (LUD-06 only recommends same-origin) so the common
  `.well-known/lnurlp/<name>` redirect pattern that points at a
  third-party callback (Alby, LNbits, Phoenix, etc.) works; the
  callback URL is independently SSRF-validated and Tor-routed
  per its own host.
- SSRF prevention: outbound requests refuse RFC1918, loopback,
  link-local and ULA hosts (toggle: `LNURL_ALLOW_PRIVATE_HOSTS`,
  default false). Plain `http://` rejected for clearnet hosts
  (toggle: `LNURL_ALLOW_HTTP`, default false). `.onion` hosts
  bypass the DNS check and may use HTTP.
- Tor egress: `LNURL_FORCE_TOR` is tri-state (`auto` / `true` /
  `false`, default `auto`). In auto mode the LNURL HTTP client
  routes through `LND_TOR_PROXY` iff `LND_REST_URL` is a `.onion`
  address.
- Two new dashboard routes: `POST /dashboard/api/lnurl/resolve`
  and `POST /dashboard/api/lnurl/invoice`. Both enforce session
  auth + CSRF; the invoice route enforces
  `DASHBOARD_MAX_PAYMENT_SATS` early (before contacting the
  recipient) so a cap-busting amount never burns an invoice.
- Idempotency cache (30 s, configurable via
  `LNURL_INVOICE_CACHE_TTL_SECONDS`, success-only) on
  `(handle, amount_sats, comment)` so an accidental double-click
  on Continue does not mint two invoices.
- Audit log entries for `lnurl_resolve` and
  `lnurl_request_invoice` (comment truncated to 200 chars); no
  raw recipient metadata is stored.
- success_action sanitisation: text capped at 144 chars; URLs
  rendered as non-clickable monospace + copy button (never as
  anchors); AES variants shown as a placeholder. Inline images
  allowed only for `image/png` / `image/jpeg`.
- Configuration knobs: `LNURL_FORCE_TOR`, `LNURL_ALLOW_HTTP`,
  `LNURL_ALLOW_PRIVATE_HOSTS`, `LNURL_MAX_RESPONSE_BYTES`,
  `LNURL_RESOLVE_TIMEOUT_SECONDS`, `LNURL_HANDLE_TTL_SECONDS`,
  `LNURL_INVOICE_CACHE_TTL_SECONDS`. Interactive setup wizard
  (`start.sh`) prompts for the three operationally-relevant toggles
  in its Advanced section.
- User-facing documentation: `docs/lnurl.md`.

#### API
- LND REST API integration (balances, channels, payments, invoices)
- Lightning payment support with configurable safety limits
- `POST /dashboard/api/pay` accepts an optional `outgoing_chan_id`;
  when set, the payment is routed through the streaming
  `/v2/router/send` endpoint (`send_payment_v2`) so the pin is
  honoured. Routing failures (no path / fee-limit too tight)
  surface as a `400` with an actionable message rather than a
  generic upstream error, matching the `/dashboard/api/rebalance`
  pattern
- `POST /dashboard/api/pay/quote`: read-only route probe via
  `QueryRoutes` for BOLT 11 invoices. Refuses open-amount invoices
  (LND limitation), maps "no route" to a `200` + `no_route: true`
  flag for friendly UX, and forwards an optional `outgoing_chan_id`
- On-chain operations (address generation, send, fee estimation)
- Channel management (connect peer, open channel with safety limits)
- Cold storage sweeps via Boltz Exchange reverse submarine swaps
- Boltz swap lifecycle management with Celery background tasks
- Mempool Explorer integration (fees, transactions, addresses, blocks)
- Optional **electrs / Electrum-server backend** as a privacy-preserving
  alternative to mempool.space. Operators point `LND_ELECTRUM_URL` at
  their own electrs instance (Start9-style `tcp://<onion>:50001`,
  `ssl://host:50002`, or LAN `tcp://host:50001`) and the wallet routes
  every fee estimate, transaction lookup, address balance/UTXO query,
  and Boltz timeout poll over a single persistent TCP/SSL connection
  instead of per-call HTTPS to a third party. `CHAIN_BACKEND=auto`
  (default) keeps mempool.space as a transparent fallback when electrs
  is unreachable; `CHAIN_BACKEND=electrum` enforces strict no-fallback
  mode for operators who refuse any third-party traffic. Tor `.onion`
  endpoints route through the existing `LND_TOR_PROXY`. Includes
  pushed chain-tip caching (zero-RPC `current_block_height`),
  scripthash subscriptions, a circuit breaker exposed on
  `/v1/status/services` as `electrum`, and full address-decoder
  support (P2WPKH, P2WSH, P2TR, P2SH, P2PKH on all networks).
- Electrs-driven optional layer (silently degrades when electrs is
  absent or its breaker is open):
  - Independent verification of Boltz lockup transactions against the
    expected lockup address (defence-in-depth, observation-only —
    never blocks claim).
  - Live confirmation count and block height for cold-storage swap
    claim transactions surfaced in API and dashboard responses.
  - Tip-aware Boltz timeout urgency (`current_block_height`,
    `blocks_until_timeout` fields) on swap detail.
  - Push-driven receive notifications: scripthash subscriptions on
    every issued receive address trigger a debounced UTXO reconcile
    on incoming funds (the 5-minute poll remains as a safety net).
  - Live confirmation polling for consolidate and send-onchain
    broadcasts via a dashboard-auth `/dashboard/api/tx/{txid}/confirmations`
    endpoint.
- Admin API key management (create, list, update, soft-delete, hard-purge, audit-log view + verify)
- `/health` liveness and `/ready` readiness endpoints (the latter checks database connectivity)

#### Security
- API key authentication: HMAC-SHA-256 keyed with `SECRET_KEY`, admin/regular roles, optional expiry, soft-delete with retention-gated hard purge
- Zero-downtime `SECRET_KEY` rotation via `SECRET_KEY_PREVIOUS`: bearer tokens verify under the previous digest and are transparently re-hashed on next use, with the prior digest parked in `key_hash_prev` for one cycle
- Field encryption at rest (Fernet) with PBKDF2-HMAC-SHA256 (600,000 iterations) and a per-field 16-byte random salt; legacy fixed-salt ciphertext remains readable for backward compatibility
- Keyed-HMAC-chained audit log (HMAC over previous hash + canonical row payload, keyed from `SECRET_KEY`) with `pg_advisory_xact_lock` to serialize appends, `GET /v1/admin/audit-log/verify` to detect tampering or reordering, and `POST /v1/admin/audit-log/reanchor` (plus a dashboard button) to re-baseline the chain after a database restore or `SECRET_KEY` rotation. The daily retention task (`AUDIT_LOG_RETENTION_DAYS`) verifies the chain first, prunes expired rows and records a truncation anchor, and refuses (raising a security alert) rather than rewriting a chain that does not verify
- Redis-backed Lua-atomic rate limiters (per-payment cap, aggregate spend, velocity, per-API-key sign quota) with `RATE_LIMIT_FAIL_POLICY=closed` as the default so payments cannot bypass spend caps during a Redis outage
- Dashboard hardening: HMAC-signed session cookies with server-side revocation in Redis, CSRF double-submit tokens, optional IP binding (requires `TRUSTED_PROXIES`), 30-minute idle timeout, per-request CSP nonce on every template, and a startup warning if the dashboard is exposed behind a proxy without `TRUSTED_PROXIES`
- SSRF defenses: outbound `LND_MEMPOOL_URL`, alert webhooks, and LND peer-host inputs are checked against private/loopback ranges; `MEMPOOL_ALLOW_INTERNAL=false` by default refuses startup against private mempool targets, and webhook DNS is re-resolved at request time to defeat rebind attacks
- Request body size limit short-circuited before handlers run so oversize uploads cannot exhaust the event loop
- Security headers middleware (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Cache-Control, optional HSTS) and CORS middleware
- Bitcoin address validation against the configured `BITCOIN_NETWORK` to prevent mainnet/testnet mistakes
- Startup warnings for remote PostgreSQL/Redis hosts without TLS (`DATABASE_REQUIRE_SSL`, `rediss://`)
- Container hardening: `read_only` filesystems, `cap_drop=ALL`, `no-new-privileges`, non-root `appuser` in API and worker containers

#### Tor Robustness (Group A — self-heal wedged circuits)
- **Tor control port exposed** (`127.0.0.1:9100` in the `tor-proxy`
  container) with `HashedControlPassword` auth derived at container
  start from `$TOR_CONTROL_PASSWORD`. Empty value leaves the port
  unauthenticated; the entrypoint shim warns in that case. The same
  password is consumed by the api container for control-protocol
  AUTHENTICATE.
- **Circuit-validating healthcheck** replaces the port-bind probe:
  one SOCKS5 round-trip via 9050 to mempool.space verifies actual
  circuit health. `start_period: 180s` gives Tor time to bootstrap
  on first deploy. Failing the healthcheck 3 × 60 s triggers
  `restart: unless-stopped` — autonomous recovery from wedged
  circuits without operator action..
- **Two-tier circuit breaker** — separate `tor` breaker alongside the
  existing `lnd` breaker. Tor-attributable errors (ProxyError,
  SOCKS handshake failure, TTL expired, etc.) bump the Tor breaker;
  semantic LND errors bump only the LND breaker. Available at
  `/v1/status/services` for diagnosis..
- **NEWNYM watchdog** with escalation tiers:
  - Tier 1 — today's transient-error patches (per-call recovery).
  - Tier 2 — `SIGNAL NEWNYM` after Tor breaker open ≥ 60s. Gated on
    a comprehensive in-flight check (LN HTLCs, Boltz swaps, Braiins
    Deposit sessions, Anonymize sessions, step-up MFA, BOLT12
    invoice requests). Fail-closed on uncertainty.
  - Tier 3 — `SIGNAL HUP` (torrc reload) after NEWNYM didn't recover.
  - Tier 4 — Docker healthcheck-driven container restart.
  - Tier 5 — operator runbook (alarm emitted).
- **Watchdog observability**: in-process state (last tick, last
  NEWNYM, last SIGHUP), hourly heartbeat in the audit log, and
  self-supervision (up to 3 restarts in 5 minutes before staying
  stopped)..
- **`probe_entry_guards()` / `probe_network_liveness()`** — control-
  port diagnostics that surface Tor's own assessment of guard
  reachability + network status..
- **Resource limits on `tor-proxy`** (`256M` memory, `0.5` CPU) —
  defensive baseline against a misbehaving Tor exhausting host
  memory..
- New unified `TOR_CONTROL_PASSWORD` env knob with backward-compat
  resolver: code paths fall back to the legacy
  `ANONYMIZE_TOR_CONTROL_PASSWORD` so existing deployments don't
  break.
- New env knobs: `TOR_NEWNYM_MIN_INTERVAL_S` (default 60),
  `TOR_WATCHDOG_INTERVAL_S` (default 30),
  `TOR_BREAKER_FAILURE_THRESHOLD` (default 5).

#### Tor Robustness (Group B — safety nets + observability)
- Persistent `tor_data` Docker volume mounted at `/var/lib/tor`
  . Tor's consensus cache + entry-guard selections now
  survive container restarts; first-boot bootstrap (~60 s) no
  longer repeats on every redeploy.
- Guard tuning (`NumEntryGuards 3`, `GuardLifetime 6 weeks`,
  `LearnCircuitBuildTimeout 1`, `MaxCircuitDirtiness 600`) to
  recover from the "all current guards excluded by path
  restriction" failure mode.
- `LongLivedPorts` extended to cover 8080 (LND REST) and 9735
  (LN p2p) so HOLD-invoice payments aren't torn down mid-stream
  .
- `SafeLogging 1` scrubs onion addresses + peer fingerprints from
  notice-level Tor logs — operators can paste container logs into
  bug reports without leaking which hidden services we contact
  .
- Tor health surfaces:
  - `GET /v1/status/tor` (admin auth): JSON snapshot for tooling
    .
  - `GET /v1/status/tor/metrics` (admin auth): Prometheus text
    format with `tor_*` and `lnd_breaker_*` gauges. Probes are
    cached for 15 s to keep scrape load off the control port.
  - Dashboard Tor Health modal — settings menu → Tor Health.
    Indicator dot in the menu reflects the Tor breaker state.
- Push-event subscription on the control port: `SETEVENTS WARN ERR
  CIRC HS_DESC GUARD NETWORK_LIVENESS` with bounded reconnect
  backoff. Captures incidents the 30 s watchdog tick would
  miss between polls.
- DataDirectory growth detection: the watchdog `statvfs()`s the
  Tor volume (mounted read-only into `api`) and emits an audit
  warning when usage crosses `TOR_DATA_DIR_WARN_MB` (default 100,
  ).
- Healthcheck consolidated: removed the weaker compose-level
  `nc -z` override so the Dockerfile's circuit-validating
  healthcheck (`curl --socks5-hostname`) is what Docker actually
  runs.
- New env knobs: `TOR_DATA_DIR_WARN_MB` (default 100),
  `TOR_DATA_DIR_MOUNT_PATH` (default `/var/lib/tor`).

#### Tor Robustness (Group C — per-listener depth + log-driven recovery)
- Per-listener SOCKS5 health probe. The watchdog round-robins
  one listener per tick — 8 listeners × 30 s = ~4 min full cycle.
  Results surface in:
  - The dashboard Tor Health modal (per-listener status table).
  - `GET /v1/status/tor` JSON (under ``listeners``).
  - Prometheus: ``tor_listener_ok{name,port}`` and
    ``tor_listener_last_probe_age_seconds{name,port}``.
- Tor log-pattern matching inside the control-port event stream
  . The dispatcher sniffs WARN/ERR payloads for known
  recovery-relevant signatures (``All current guards excluded by
  path restriction``, ``Tried for N seconds to get a connection``)
  and bumps dedicated counters: ``guard_excluded_total`` /
  ``circuit_stuck_total``. Picks up the failure modes that don't
  have a typed CIRC/HS_DESC/GUARD event.
- HS descriptor pre-warming at lifespan startup. The api
  process issues lightweight HEAD requests against every known
  ``.onion`` endpoint (LND REST, Boltz onions, signed operator
  registry) so the first real call doesn't pay the 5-15 s
  HSDir-lookup latency. Bounded by a 10 s whole-batch budget;
  partial results are fine.
- `SIGNAL HUP` reload helper surfaced on the dashboard.
  - `POST /v1/admin/tor/reload` (admin auth).
  - `POST /dashboard/api/tor-reload` (cookie + CSRF).
  - "Reload torrc" button in the Tor Health modal with confirm
    + outcome text.
- Startup exit-relay diversity smoke test. Opens one
  concurrent probe per listener, compares ``circuit-status`` before
  and after, asserts each probe got a distinct circuit. Skipped on
  cold Tor (not failed); soft-fail on probe timeouts; HARD-fail
  (raises) only on observed circuit collision — broken listener
  isolation is a security regression and refusing to serve is the
  correct response. Default is non-blocking (background task);
  ``TOR_DIVERSITY_SMOKE_BLOCKING=true`` makes lifespan wait so
  the failure aborts startup.

#### Tor Robustness (Group D — structural improvements)
- Preventive Tor age rotation via SIGHUP. A new Celery beat
  task ``rotate_tor_age`` fires on ``TOR_ROTATION_INTERVAL_DAYS``
  cadence (default 7) so accumulated guard-state degradation can't
  silently wedge the wallet. In-flight gated: defers when ANY of
  the six in-flight surfaces (LN HTLCs, Boltz swaps, Braiins
  deposits, anonymize sessions, step-up, BOLT 12) is live. Audit-
  logged on both the fire and the deferral.
- ``IsolateSOCKSAuth`` added to every torrc SocksPort. The
  anonymize stack already issued per-call (user, pass) pairs in
  ``anonymize/http.py``; without this directive Tor ignored them
  and the per-session isolation contract collapsed silently.
- Layered torrc for operator overrides. The Dockerfile now
  ships ``/etc/tor/torrc.d/00-default.conf`` (wallet defaults) and
  ``/etc/tor/torrc.d/99-operator.conf`` (empty stub). Operators
  mount their own override file via compose. Tor's
  ``--defaults-torrc`` flag merges them at start; the operator
  file's directives replace matching ones from the defaults. Bad
  syntax in the override → Tor refuses to start, healthcheck
  fails, operator sees the cause in ``docker compose logs``.
- Split-mode Tor: separate ``tor-lnd`` + ``tor-anonymize`` Tor
  processes. Opt-in via a new compose override
  ``docker-compose.tor-split.yml`` — existing deploys keep running
  the single ``tor-proxy`` unchanged. Wedge on one pool's guard
  set no longer affects the other.
  - New role-specific torrcs ``tor-proxy/torrc.lnd`` and
    ``tor-proxy/torrc.anonymize`` selected via ``$TOR_ROLE`` in
    the entrypoint shim.
  - Independent named volumes (``tor_lnd_data``,
    ``tor_anonymize_data``) so consensus cache + guard list stay
    isolated per pool.
  - New ``_TOR_LND_BREAKER`` (registered as ``tor-lnd`` in the
    service-health registry). LND-attributable Tor failures route
    into it when split mode is on; the existing ``_TOR_BREAKER``
    continues to track anonymize-pool failures.
  - Watchdog + event-stream gained a ``pool`` parameter; lifespan
    starts one task per pool in split mode and one task total in
    single mode. Both NEWNYM and SIGHUP signal the correct
    control port for the pool that observed the wedge.
  - Prewarm in split mode fires per-URL through the right proxy
    (LND REST → tor-lnd; everything else → tor-anonymize) so
    descriptor-cache warming applies to the right Tor process.
  - Dashboard Tor Health modal shows both Tor breakers when split
    mode is on; the indicator dot reflects the WORSE of the two
    so either-pool wedges surface in the header.
  - New Prometheus metrics: ``tor_lnd_breaker_state``,
    ``tor_split_mode_enabled``. JSON ``/v1/status/tor`` and
    ``/dashboard/api/tor-status`` gain ``tor_lnd_breaker_*`` and
    ``tor_split_mode_enabled`` fields (zero/false in single mode).
  - New env knobs:
    - ``TOR_SPLIT_MODE`` (default ``false``).
    - ``ANONYMIZE_TOR_SOCKS_HOST`` (default ``tor-proxy``;
      ``tor-anonymize`` in split mode).
    - ``LND_TOR_CONTROL_HOST`` (default empty; ``tor-lnd`` in
      split mode).
    - ``LND_TOR_CONTROL_PORT`` (default ``9100``).
    - ``TOR_ROTATION_INTERVAL_DAYS`` (default ``7``; set ``0`` to
      disable the rotation task).

#### Tor Robustness (Group E — operational polish)
- Operator-supplied Tor explicitly supported. Updated
  `.env.example` documents pointing `LND_TOR_PROXY` at a host
  Tor (`host.docker.internal:9050` / `172.17.0.1:9050`) and
  disabling the bundled service. New startup check
  ([app/services/tor_proxy_reach_check.py](app/services/tor_proxy_reach_check.py))
  issues one SOCKS5 round-trip via the configured proxy at
  lifespan startup; an unreachable proxy logs a clear ERROR
  pointing at the runbook so misconfigured setups surface on
  first boot instead of 30 minutes later in an onion call.
  Non-fatal — clearnet endpoints continue to work.
- DNS-leak / Tor-routing verification at startup. New
  [app/services/tor_dns_leak_check.py](app/services/tor_dns_leak_check.py)
  queries `check.torproject.org/api/ip` through the configured
  SOCKS proxy and checks the JSON `IsTor` field. A confirmed
  leak (`IsTor=false`) is a loud ERROR but does not refuse to
  start — operator decides whether to fix or proceed (dual-
  stack networks can produce ambiguous results). Network
  failures are informational only.
- LND-side HS descriptor freshness check. New
  [app/services/lnd_hs_descriptor_check.py](app/services/lnd_hs_descriptor_check.py)
  issues `HSFETCH` against LND's onion via the wallet's Tor
  control port; reads the resulting `HS_DESC RECEIVED` /
  `FAILED` async event. Runs every 6 h via Celery beat
  (`check_lnd_hs_descriptor_freshness` task). The first
  consecutive failure is silent (HSDir flap is normal); after
  the second the task emits a `lnd_hs_descriptor_stale` audit
  row and surfaces a red "LND HS descriptor" section in the
  Tor Health modal. Read-only diagnostic — only LND can
  republish.
- Operator runbook shipped at
  [docs/operator_tor_runbook.md](docs/operator_tor_runbook.md).
  Nine sections: "Tor unhealthy yellow", "Tor unhealthy red",
  "recurring wedges", "LND HS descriptor stale",
  "info.log keyword catalog", "operator torrc overrides",
  "split-mode migration", "operator-supplied Tor", and a
  "verifying a fix" smoke-test recipe. The startup-check error
  messages reference this doc by section
  anchor, so the runbook has paths for operators landing
  there from their docker logs.

#### Braiins Deposit — dust UTXO prevention
- New send-tx shape: the wallet now broadcasts a single-input
  single-output transaction from the fresh Boltz claim UTXO
  directly to the Braiins destination, absorbing the network fee
  into the output instead of creating a wallet-side change UTXO.
  Eliminates the field-observed dust risk at elevated fees (a
  change UTXO whose value is below the cost-to-spend at current
  fees is operationally lost).
- Shared utility module at
  [app/services/dust_safe_send.py](app/services/dust_safe_send.py)
  with `build_and_broadcast_no_change_send`,
  `project_no_change_send`, `economic_dust_threshold_sats`,
  and `InfeasibleSendError`. Module is feature-agnostic so the
  documented future extension to the Anonymize
  submarine-funding fallback can adopt it without dependency
  inversion.
- DB migration `032_braiins_deposit_dust_prevention.py` adds
  `actual_sent_sats` and `send_infeasible_reason` columns to
  `braiins_deposit_sessions` plus the new `awaiting_fee_reduction`
  enum value. All additive; existing rows are unaffected.
- Dashboard wizard surfaces the arrival range explicitly: the
  "Braiins receives" line shows `X – Y sats` (not a single
  number) when the dust-safe send produces variability, with
  inline copy explaining why. At extreme fees the bin is
  disabled in the preset grid with a tooltip.
- Adaptive bin floor: presets that aren't viable at current
  fees grey out on the wizard's amount-preset grid; the smallest
  viable bin gets a `rec` tag. Per-bin viability is computed
  from per-bin quotes fetched on wizard open.
- Stuck-at-send recovery: when fees spike between Boltz claim
  and broadcast (worst-case scenario), the session enters the
  new `AWAITING_FEE_REDUCTION` state with reason recorded. A
  periodic re-checker promotes back to `FUNDED` when fees fall
  enough that the no-change send arrives at >= bin amount. No
  manual intervention required.
- Session detail surfaces an "absorbed" delta when
  `actual_sent_sats != deposit_amount_sats` (e.g.
  `1,000,000 sat (+847 absorbed)` for a low-fee send that
  routed the buffer into the deposit).
- Cross-feature regression tests pin that **cold storage** and
  the **Anonymize final hop** retain their direct-claim pattern
  (Boltz claims directly to the destination; no wallet-side send
  exists). The dust-safe-send adoption is intentionally limited
  to the path that has the dust risk.
- New env knob `BRAIINS_DEPOSIT_DUST_PREVENTION_ENABLED`
  (default `true`). Set to `false` and restart api + worker to
  fall back to the legacy `send_coins(amount, fee)` path with
  LND-managed change. Feature-flag canary; remove after one
  stable release.
- New env knob `BRAIINS_DEPOSIT_FEE_REDUCTION_RECHECK_S`
  (default `300`). Cadence at which a parked session re-checks
  feasibility against current fees.
- Operator override on parked sessions: the deposit-list row's
  "Broadcast anyway" button hits
  `POST /braiins-deposit/sessions/{id}/retry-send?accept_underpay=true`
  to bypass the dust-prevention floor when the operator decides
  waiting for fees to drop isn't worth the delay. One-way; the
  arrival ends up below the bin amount as hashpower credit at
  Braiins.

#### Infrastructure
- Interactive `start.sh` setup wizard with config generation and launch management
- Docker Compose deployment with PostgreSQL 16, Redis 7, Tor SOCKS5 proxy, Celery worker
- Multi-stage Docker build with non-root container user
- Bundled Tor proxy with auto-detection of `.onion` LND URLs
- Tor SOCKS5 proxy support for LND, Boltz, and Mempool APIs with clearnet fallback
- Alembic database migrations (run automatically before API start in Docker)
- Multi-network support (mainnet, testnet, signet, regtest)
- Structured JSON logging option (`LOG_FORMAT=json`)
- `ENABLE_DOCS` setting to control OpenAPI/Swagger independently of DEBUG
- Persistent HTTP client for Mempool Explorer service
- Comprehensive test suite (unit + integration)
- GitHub Actions CI pipeline (lint, type check, test, dependency audit)
- `py.typed` marker for PEP 561 compliance
- LICENSE (MIT), CODE_OF_CONDUCT.md, CONTRIBUTING.md, SECURITY.md, CHANGELOG.md
