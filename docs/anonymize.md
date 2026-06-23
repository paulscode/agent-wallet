# Anonymize — forward-anonymity sessions

> **Lawful use only.** This privacy feature is provided for lawful
> financial-privacy purposes. Mixing and coinjoin-style techniques may be
> regulated or restricted in some jurisdictions, and you are solely responsible
> for ensuring your use complies with all applicable laws. See the
> [DISCLAIMER](../DISCLAIMER.md).

The **Anonymize** feature produces a base-layer UTXO at a
user-supplied destination address with materially improved forward
anonymity relative to the chosen input. Sources may be the on-chain
wallet, Lightning channels, or an external deposit; all on-chain
sources are mandatorily normalised to the Lightning side via a
Boltz submarine swap before any mixing hop runs.

The multi-hop pipeline composes from: Lightning self-routing,
Boltz reverse swaps, an optional private-channel ephemeral hop
(`priv_channel`), and an optional Liquid round-trip (`liquid`).
Score tiers are `weak` / `moderate` / `strong`; the strongest is
reachable only with the Liquid hop enabled.

This guide focuses on **what operators need to do** to deploy and
run the feature. Per-reason recovery steps for sessions stuck in
`awaiting_reconciliation` are split out into a dedicated
[troubleshooting guide](anonymize_troubleshooting.md). The
operator-diversity threat model and registry rationale live in
[`anonymize_operator_diversity.md`](anonymize_operator_diversity.md).

## Contents

- [How a session flows](#how-a-session-flows)
- [Score tiers](#score-tiers)
- [Quick start](#quick-start)
- [Staged adoption](#staged-adoption)
- [Operator registry](#operator-registry)
- [Strong-tier (Liquid) deployment](#strong-tier-liquid-deployment)
- [BIP-353 destinations](#bip-353-destinations)
- [BOLT 12 deposit acceptance](#bolt-12-deposit-acceptance)
- [Step-up re-auth for overrides](#step-up-re-auth-for-overrides)
- [Operator runbook](#operator-runbook)
- [Security posture](#security-posture)

---

## How a session flows

At a high level, every anonymize session normalises its input onto
Lightning, runs one or more mixing hops, then exits to the
destination:

```
  source ──► (submarine swap, if on-chain) ──► LN
                                                │
                                                ▼
                                  ┌──── priv_channel hop ────┐
                                  │                          │
                                  └────► (optional Liquid ◄──┘
                                          round-trip)
                                                │
                                                ▼
                                       Boltz reverse swap
                                                │
                                                ▼
                                  destination address (on-chain)
                                              or
                                       BOLT 12 / BIP-353 exit
```

Each hop runs as an idempotent step machine under a per-session
control loop. Sessions are persisted, survive restarts, and emit
an append-only audit-log row per state transition.

The dashboard exposes three source kinds:

- **`onchain-self`** — UTXO already in the wallet's on-chain account.
- **`lightning-self`** — outbound balance on a channel the wallet owns.
- **`ext-lightning`** — external Lightning deposit via a one-shot
  BOLT 11 invoice or per-session BOLT 12 offer (with optional
  BIP-353 handle).

## Score tiers

The wizard advertises an **advisory tier** at quote time, computed
from the pipeline that will run:

| Tier | Required composition |
|---|---|
| `weak` | Single-hop reverse swap, no decoys, no Liquid. |
| `moderate` | LN routing or `priv_channel` hop with distinct operators on the reverse leg. |
| `strong` | `priv_channel` + Liquid round-trip (LN source) **or** distinct submarine + reverse operators + Liquid round-trip (on-chain source). |

If the operator registry doesn't have enough diverse operators
available at quote time, the wallet caps the advertised tier and
surfaces the cap to the user before they commit.

### Chain backend and the tier cap

Tiers above `weak` require a **private** chain backend. A self-hosted
Electrum/Electrs (`LND_ELECTRUM_URL`, including an `.onion`) qualifies and
carries no cap. A **public** backend (e.g. a remote Mempool HTTP endpoint
that can observe every address/tx the wallet looks up) must be opted into
with `ANONYMIZE_ALLOW_PUBLIC_CHAIN_BACKEND=true` and caps the session at
`weak` — that operator can correlate your chain queries.

A **co-resident / private-network** backend (loopback, RFC1918, or a
non-public hostname such as `electrs.embassy` / `fulcrum.startos`) is a
different case: the query never leaves the host, so there is no third-party
observer to leak to. Set `ANONYMIZE_TRUSTED_LOCAL_CHAIN_BACKEND=true` to
exempt such a backend from the onion-only egress gate **without** the tier
cap. The opt-in is honored only when *every* configured chain host is
actually local — it is ignored on a genuinely public backend, so it cannot
be used to relax a remote endpoint by mistake. The privacy-critical Boltz
swap legs are unaffected and still must be `.onion`.

---

## Quick start

Minimum production configuration for the default tier
(LN-source, `priv_channel` hop, no Liquid):

```ini
ANONYMIZE_ENABLED=true
ANONYMIZE_REQUIRE_TOR=true

# Fernet bundle for at-rest destination address + claim_tx_hex.
FERNET_KEYS=<key1>,<key2>

# Separate seed for decoy outputs.
ANONYMIZE_DECOY_SEED_FERNET=<bundle>
ANONYMIZE_DECOY_SEED_ACCOUNT_KEY=<32+ random bytes, base64>

# Step-up re-auth nonces for refund / decoy spend overrides.
ANONYMIZE_STEPUP_COOKIE_HMAC_KEY_FERNET=<bundle>

# Pin the project release-key fingerprint(s) for the operator registry.
ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS=<fp1>,<fp2>
```

## Staged adoption

Each major capability is opt-in via its own knob so operators can
stage adoption without re-rolling their base configuration:

| Knob | Default | Enables |
|---|---|---|
| `ANONYMIZE_ENABLED` | `false` | The whole feature. |
| `ANONYMIZE_LIQUID_ENABLED` | `false` | Liquid round-trip hop (required for `strong`). |
| `ANONYMIZE_REGISTRY_REQUIRE_THRESHOLD_SIG` | `false` | k-of-n operator-registry signatures. |
| `ANONYMIZE_REFUSE_DECOY_OVERRIDE_SPENDS` | `false` | Hard-refuse decoy override spends (recommended once a deployment has matured). |
| `ANONYMIZE_REFUSE_REFUND_OVERRIDE_SPENDS` | `false` | Hard-refuse refund override spends. |

---

## Operator registry

`app/services/anonymize/operators.json` is the curated list of
Boltz operators the per-session pair sampler draws from. Every
multi-operator deployment must ship a verified registry; the
loader **refuses to start** when the registry is non-empty and the
detached signature does not verify against any pinned fingerprint
in `ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS` (comma-separated;
rotation is supported by pinning the old + new fingerprints
simultaneously).

For the threat-model rationale behind why operator diversity
matters, how the default chain is composed, and how to vet a
third-party operator, see
[`anonymize_operator_diversity.md`](anonymize_operator_diversity.md).

### Threshold-signed registry (recommended for mature deployments)

Operators are encouraged to flip
`ANONYMIZE_REGISTRY_REQUIRE_THRESHOLD_SIG=true` and require **k
distinct maintainer fingerprints** to have a verifying signature
before the registry loads. This defends against a single
compromised maintainer credential.

```ini
ANONYMIZE_REGISTRY_REQUIRE_THRESHOLD_SIG=true
ANONYMIZE_REGISTRY_THRESHOLD_K=2
ANONYMIZE_REGISTRY_THRESHOLD_SIG_PATHS=app/services/anonymize/operators.sig.maint-1,app/services/anonymize/operators.sig.maint-2
ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS=<fp-primary>,<fp-maint-1>,<fp-maint-2>
```

A single maintainer who submits two signatures under the same key
only counts **once** — that's what makes k-of-n meaningful. The
loader refuses configurations where `k` exceeds the number of
pinned fingerprints. Flipping the flag back to `false` reverts to
single-signature mode without re-rolling signatures.

A `RegistrySignatureError` at startup with the message
`threshold-signed registry requires k=K distinct verifying
fingerprints, found N` means the deployed signatures do not yet
meet the threshold.

---

## Strong-tier (Liquid) deployment

The strongest reachable score tier (`strong`) requires:

- **LN-source pipeline** — `priv_channel` + Liquid round-trip, OR
- **on-chain-source pipeline** — distinct submarine + reverse
  operators + Liquid round-trip.

Operators who want this tier ship a Liquid backend
(`elementsd` + `electrs-liquid`, via the
[`docker-compose.liquid.yml`](../docker-compose.liquid.yml)
overlay) and flip `ANONYMIZE_LIQUID_ENABLED=true`. When this is
enabled in `start.sh config`, the wizard:

1. Auto-generates `ANONYMIZE_LIQUID_SEED_FERNET` (the SLIP-77
   master blinding key) — back this up in a SEPARATE envelope
   from the LND seed.
2. Auto-generates `ELEMENTSD_RPC_PASSWORD`.
3. Sets `ENABLE_LIQUID=true` so subsequent `./start.sh up`
   invocations automatically include `-f docker-compose.liquid.yml`
   in the compose command — `elementsd` comes up alongside the
   other services. If `ENABLE_LIQUID_INDEXER=true` is also set,
   the embedded `electrs-liquid` container comes up too (default
   off — see [Sizing the host](#sizing-the-host) below for why).
   First boot syncs the Liquid chain (~75 GB elementsd disk +
   ~75 GB electrs disk if self-hosting the indexer; ~1 h block
   fetch + ~30–60 min post-IBD RocksDB compaction).

```ini
ANONYMIZE_LIQUID_ENABLED=true                          # master switch
ENABLE_LIQUID=true                                     # compose overlay
ANONYMIZE_LIQUID_SEED_FERNET=<bundle>                  # separate seed
ANONYMIZE_LIQUID_ELECTRUM_URL=tcp://electrs-liquid:50001
ELEMENTSD_RPC_PASSWORD=<auto-generated by start.sh>

# Optional. Empty → both LN↔L-BTC legs are resolved from the signed
# operator registry (operators.json) using the same diversity
# policy as the LN↔on-chain chain selector — canonical Boltz on
# the LN→L-BTC leg (large L-BTC dwell anonymity set); the next
# most-recently-audited non-canonical operator (Middleway →
# Eldamar fallback) on the L-BTC→LN leg. Set either variable to a
# full URL to pin that leg to a specific operator (regtest /
# externally-managed Boltz).
BOLTZ_CHAIN_LN_TO_LBTC_API_URL=
BOLTZ_CHAIN_LBTC_TO_LN_API_URL=

# Regtest only — supply the network-specific L-BTC asset id.
# ANONYMIZE_LIQUID_BTC_ASSET_ID=<64-char hex>

# Kill-switch (default true). Set to false to refuse Liquid swap-
# create at runtime independent of ANONYMIZE_LIQUID_ENABLED. The
# in-repo regtest E2E harness at
# tests/integration/anonymize/test_liquid_e2e_regtest.py is the
# gate that backs the default-on stance.
ANONYMIZE_LIQUID_INTEGRATION_VERIFIED=true
```

If the wizard's "Enable Liquid hop?" prompt is left
**off**, the wallet hides every Liquid-related UI control (the
"Route through Liquid" checkbox in the new-session wizard is
gated on `/anonymize/policy`'s `liquid_available` flag). The
overlay is not launched and no Liquid disk/RAM is consumed.

#### Externally-managed Liquid backend

Two configurations are supported, in order of decreasing
self-hosting:

1. **Embedded `elementsd`, external `electrs-liquid`.** Keep
   `ENABLE_LIQUID=true` (so `start.sh` launches the overlay with
   `elementsd`) but leave `ENABLE_LIQUID_INDEXER=false` (the
   default). Point `ANONYMIZE_LIQUID_ELECTRUM_URL` at an
   external Liquid Electrum endpoint — Blockstream operates
   public ones, or run `electrs-liquid` yourself on a beefier
   host. This is the recommended setup for hosts with < 48 GiB
   of RAM (see [Sizing the host](#sizing-the-host)).
2. **Both external.** If `elementsd` and `electrs-liquid` both
   run outside the overlay (e.g. on a separate host), keep
   `ANONYMIZE_LIQUID_ENABLED=true` and set `ENABLE_LIQUID=false`.
   The wallet still uses the Liquid hop; `start.sh` won't try to
   launch its own overlay. Point `ANONYMIZE_LIQUID_ELECTRUM_URL`
   at your external indexer.

#### Sizing the host

The local Liquid backend adds ~12 GiB RAM, dominated by
`elementsd`. The `electrs-liquid` image is built with the
slim-headers patch
([`liquid-overlay/patches/0001-slim-headers.patch`](../liquid-overlay/patches/0001-slim-headers.patch)),
which keeps only per-block header metadata in RAM and reads full
headers from RocksDB on demand, so the indexer's footprint is
~2 GiB. `elementsd` (Elements Core) still holds the full
~3.9 M-block index in memory — Liquid's dynafed headers are
1–4 KiB each, far larger than Bitcoin's fixed 80 bytes — a
~9.6 GiB resident floor that is now the heavier half of the stack.

| Stack component | Build peak | Steady-state | Notes |
|---|---|---|---|
| `elementsd` | ~10 GiB | **~9.6 GiB** | Full block index in RAM; the dominant Liquid cost. Compose cap 12 G. |
| `electrs-liquid` | **~3.7 GiB** | **~2.4 GiB** | slim-headers patch (build peak is the post-index compaction; restart ~1.2 GiB). Compose cap 6 G. Grows slowly as the chain extends. |
| Agent-wallet (api + worker + postgres + redis + tor + bolt12) | ~0.4 GiB | ~0.4 GiB | Negligible |
| `bitcoind` + Bitcoin `electrs` + LND (typical) | — | ~3–8 GiB | Bitcoin headers are 80 B fixed — none of the Liquid floor |
| OS + filesystem cache | — | 2–10 GiB | More FS cache materially speeds RocksDB reads |

Tier recommendations for a host running the agent-wallet stack
alongside a self-hosted Bitcoin node, Bitcoin `electrs`, and
LND:

| Host RAM | What it gets you |
|---|---|
| **24 GiB** | Comfortable with `ENABLE_LIQUID_INDEXER=false` (external Liquid Electrum endpoint): only `elementsd` runs locally (~10 GiB). |
| **32 GiB** ⭐ | Recommended for self-hosting the full Liquid stack. The ~12 GiB Liquid backend fits alongside the base node stack with headroom for filesystem cache. |
| **48 GiB+** | Generous headroom for filesystem cache and years of Liquid chain growth, no tuning required. |

The compose cap on `electrs-liquid` is 6 GiB and on `elementsd`
is 12 GiB, both documented in
[`docker-compose.liquid.yml`](../docker-compose.liquid.yml) with
the full rationale.

### Per-call-site Tor isolation

The Liquid hop runs on its own dedicated Tor SOCKS listener,
distinct from the Bitcoin chain backend, Boltz, BIP-353 DNS, and
LND traffic. This keeps the hop's circuit identity uncorrelated
with the operator's other egress.

### Liquid seed isolation

`ANONYMIZE_LIQUID_SEED_FERNET` is a **separate** seed from the
primary LND wallet and from the decoy-output seed. Mixing them up
during recovery is the primary operational risk for strong-tier
deployments — see the [backup envelope discipline](#backup-envelope-discipline)
runbook section.

### Liquid dwell windows

The hop draws a random dwell between
`ANONYMIZE_LIQUID_MIN_DWELL_S` (default 3 h) and
`ANONYMIZE_LIQUID_MAX_DWELL_S` (default 24 h) before initiating
the L-BTC → LN return swap. Operators who want a faster turnover
floor should be aware that shortening the window narrows the
anonymity set the hop can join.

---

## BIP-353 destinations

The wizard's destination field accepts both raw Bitcoin addresses
and BIP-353-style handles (``user@domain``). The handle is
resolved at quote time via DoH-over-Tor through a dedicated
``bip353_dns`` listener that is never shared with Boltz, Liquid,
or chain-backend traffic.

| Setting | Default | Role |
|---|---|---|
| `ANONYMIZE_BIP353_DOH_ENDPOINT` | `https://dns.mullvad.net/dns-query` | Tor-routable DoH provider. Must be a non-logging provider; Mullvad and Quad9 are the supported defaults. |
| `ANONYMIZE_BIP353_CACHE_MIN_TTL_S` | `86400` (24 h) | Floor for per-handle cache TTL. Even when the DNSSEC record advertises shorter, the wallet caches for at least this long so repeat-lookup-as-confirmation cannot trigger fresh DNS egress per session. The published TTL caps cache lifetime at 7 days. |

The resolver refuses DoH answers that don't carry the DNSSEC ``AD``
(Authenticated Data) flag — an upstream that doesn't validate
could forge any ``user@domain`` → offer mapping. All
resolver-internal errors (NXDOMAIN, DNSSEC fail, multiple TXT
records, malformed BIP-21 URI) surface as the same generic
``destination_rejected`` shape so a probing payer cannot
distinguish sub-failures.

### Resolution outcomes

The published TXT record content is a BIP-21 URI:
``bitcoin:<address>?lno=<offer>&lightning=<bolt11>``. The
anonymize stack chooses an exit primitive based on what's present:

| Published handle | Outcome |
|---|---|
| `bitcoin:bc1q...` (with or without `lno=` / `lightning=`) | The on-chain handle is validated through the standard address gate and feeds the reverse-swap exit. |
| `bitcoin:?lno=lno1...` (BOLT 12 offer only, no on-chain fallback) | The session terminates via the ``bolt12_pay`` exit hop, paying the offer through the wallet's BOLT 12 outbound subsystem. **LN-source pipelines only.** |
| `bitcoin:?lightning=lnbc...` (BOLT 11 only) | **Refused** — a BOLT 11 invoice's sub-hour expiry cannot survive a meaningful mixing dwell. |

The SPA renders the resolved address-or-offer as a confirmation
step before the user commits to the quote.

### Choosing a DoH provider

Mullvad's `dns.mullvad.net/dns-query` is the default for
consistency with the wallet's Tor-only egress policy. Any
override must:

- Respond with `application/dns-message` (RFC 8484 wire format);
  the resolver refuses HTML / JSON responses.
- Perform upstream DNSSEC validation and set ``AD=1`` on
  validated answers.
- Be reachable over Tor.

Examples that meet all three: Mullvad
(`https://dns.mullvad.net/dns-query`), Quad9
(`https://dns.quad9.net/dns-query`).

---

## BOLT 12 deposit acceptance

The wizard's ``ext-lightning`` source kind admits two deposit modes:

* **BOLT 11** (default) — the wallet mints a single-use blinded
  payment-request when the session is created. The depositor's
  wallet pays the invoice once.
* **BOLT 12** — the wallet mints a **per-session BOLT 12 offer**.
  The depositor's wallet sends an ``invoice_request`` to the
  offer's blinded paths; the wallet signs an invoice for the fixed
  session amount and LND settles it. Optionally also publishes a
  **BIP-353 handle** the depositor can paste into a wallet that
  supports ``user@domain`` resolution.

| Setting | Default | Role |
|---|---|---|
| `ANONYMIZE_EXT_LIGHTNING_DEPOSIT_METHOD` | `bolt11` | Operator-wide default. Per-quote override via the ``deposit_method`` field on ``POST /anonymize/quote``. |
| `ANONYMIZE_BIP353_DEPOSIT_DOMAIN` | (unset) | Parent domain for per-session BIP-353 handles (``<random-subdomain>@<domain>``). Leaving this unset suppresses handle generation; the BOLT 12 offer is still issued. |

### Publishing the BIP-353 handle

The wallet emits an RFC 1035 zone-file fragment in the
session-create response but does **not** push it to any DNS host
— operators are responsible for the publishing path. A wallet
that auto-pushed records to a third-party DNS API would leak the
wallet's liveness to that provider on every session. Sample:

```
xa3kz7p9w2qf.user._bitcoin-payment.wallet.example.com. 3600 IN TXT "bitcoin:?lno=lno1..."
```

Until the record is served, depositors can still pay the BOLT 12
offer directly.

### Threat-model notes

- BOLT 11 + BOLT 12 deposit modes are mutually exclusive on a
  given session. Accepting both at once would let an attacker
  race payments across two listeners.
- The BIP-353 ``user`` portion is 48 bits of random entropy per
  session so live handles cannot be enumerated. Operators that
  publish a wildcard or short handle defeat this property.
- BOLT 12 deposit sessions require both the BOLT 12 inbound
  responder and the recurring reconciliation sweep to be running
  (both ship in the default Celery task config). Deployments with
  `BOLT12_DISABLED=true` should prefer the BOLT 11 deposit
  method.

---

## Step-up re-auth for overrides

The dashboard's spend-override flow (used to spend a refund UTXO
or a decoy output on a session that has otherwise concluded) is
gated on a **fresh server-issued step-up nonce** — single-use and
bound to the caller's session and the specific override scope — that
the client echoes back to confirm the action. It is a deliberate
confirmation step on top of the session's existing authentication and
CSRF protection, not an independent second factor.

- `POST /anonymize/stepup/issue` — issues a nonce scoped to either
  `anonymize_decoy_spend_override` or `anonymize_refund_spend_override`.
- `POST /anonymize/sessions/{id}/spend-override` — verifies the
  nonce (single-use, TTL-bounded) and records an audit event.

`ANONYMIZE_STEPUP_NONCE_TTL_S` (default 60 s) bounds replay; rate
limits and lockouts defend against brute-forcing or replay of
stale nonces. After
`ANONYMIZE_STEPUP_NONCE_VERIFY_RATE_LIMIT_PER_MIN` failed
verifications under one cookie, the cookie is locked out of the
override path for `ANONYMIZE_STEPUP_NONCE_VERIFY_LOCKOUT_S`. The
lockout is per-cookie-HMAC (not per-IP), so a hostile client
can't lock out a legitimate operator on the same network.

Mature deployments are encouraged to flip
`ANONYMIZE_REFUSE_{DECOY,REFUND}_OVERRIDE_SPENDS=true` so the
override path is **hard-refused** even with a valid nonce — the
operator must consolidate decoy/refund UTXOs through a separate
non-anonymize payment instead.

---

## Operator runbook

### Backup envelope discipline

Up to three independent secrets must be backed up in
**separately-labelled envelopes**:

1. **Primary LND wallet seed** — the existing wallet's BIP-39 seed.
2. **`ANONYMIZE_DECOY_SEED_FERNET`** — the decoy-output seed.
3. **`ANONYMIZE_LIQUID_SEED_FERNET`** — the Liquid blinding seed
   (strong-tier deployments only).

Mix-ups between the three are the primary operational risk for
strong-tier deployments. Each envelope should call out its
purpose + its associated config knob name, and the recovery
procedure should walk an operator through restoring **only one**
seed without contaminating the others.

### Liquid initial-sync expectations

A fresh self-hosted Liquid backend (`ENABLE_LIQUID_INDEXER=true`)
goes through three phases on first boot:

1. **`elementsd` block download** — Liquid mainnet is ~75 GB on
   disk and ~3.9 M blocks (mid-2026). Over Tor on residential
   bandwidth, plan for many hours to overnight. The healthcheck
   `start_period` (30 minutes) covers steady-state restarts but
   is intentionally NOT sized for cold-IBD; the api container
   retry-loops against the policy endpoint until the indexer is
   reachable.
2. **`electrs-liquid` header download + block fetch** — once
   `elementsd` is at chain tip, electrs fetches every header
   then every block via RPC. Expect ~2 hours. With the
   slim-headers patch, electrs memory peaks ~3.7 GiB (the
   post-index RocksDB compaction) and settles to ~2.4 GiB
   serving — headers are streamed into a slim in-RAM index
   rather than buffered in full.
3. **Post-IBD RocksDB compaction** — three databases compacted
   serially (`txstore`, then `history`, then `cache`). The
   first alone took ~22 minutes on our reference deployment;
   plan for ~30–60 minutes total. The Electrum port stays
   closed throughout, so the wallet's "Liquid backend not ready
   yet" banner persists until compaction finishes.

Until all three complete, the wallet's session-create surface
returns `anonymize_quote_unavailable` because the fee-oracle's
first refresh hasn't populated the cache.

If you hit OOM kills, `missing txo` panics, or the IBD never
seems to start, see the
[Liquid sync troubleshooting section](anonymize_troubleshooting.md#trouble-liquid-backend-not-ready).

### Fee oracle gone stale

`ANONYMIZE_LIQUID_FEE_RATE_CACHE_TTL_S` (default 300 s) bounds the
oracle's freshness. If the indexer is unreachable for longer than
the TTL, quote-time reads return a `"stale"` marker and the SPA
surfaces a `quote_unavailable` response. Recovery: restart
`electrs-liquid`, watch its logs for "Index is ready", then the
oracle's next recurring refresh will repopulate the cache.

### Liquid hop disabled — does my wallet still work?

Yes. `ANONYMIZE_LIQUID_ENABLED=false` (the default) leaves every
Liquid-related setting ignored. The LN-only and on-chain
submarine paths continue to work without any Liquid
infrastructure. Operators staging adoption can keep the Liquid
backend running but disabled, validate connectivity via the
dashboard's health card, and flip the enable switch on a
separately-scheduled change window.

### Sessions stuck in `awaiting_reconciliation`

When a session lands in `awaiting_reconciliation`, the wallet's
auto-retry loop decides whether to retry, escalate, or wait for
operator action based on the **reason code** persisted on the
row. See the dedicated
[troubleshooting guide](anonymize_troubleshooting.md) for the
per-reason decision tree.

---

## Security posture

Key points operators must understand:

- The wallet delivers **forward anonymity**, not full
  unlinkability between the chosen input and the produced output.
- The pipeline does **not** defeat a global passive adversary
  watching all of LN + chain + Boltz + Liquid simultaneously.
- Coinjoin / payjoin are **out of scope**: there is no
  production-grade two-party coinjoin protocol that fits a
  single-sig, LND-only daemon. The wallet leans on LN + swaps +
  Liquid instead.
- Operator-attested 24 h volumes published in the registry are
  not cryptographically verified — community audit is the
  mitigation.

For the operator-diversity threat model and the rationale behind
the default operator chain, see
[`anonymize_operator_diversity.md`](anonymize_operator_diversity.md).

---

## Pointers

- Operator diversity & registry vetting: [`anonymize_operator_diversity.md`](anonymize_operator_diversity.md)
- Troubleshooting `awaiting_reconciliation`: [`anonymize_troubleshooting.md`](anonymize_troubleshooting.md)
- Boltz integration (cold-storage sweeps): [`boltz.md`](boltz.md)
- BOLT 12 subsystem: [`bolt12.md`](bolt12.md)
- Liquid deployment overlay: [`docker-compose.liquid.yml`](../docker-compose.liquid.yml) + [`liquid-overlay/`](../liquid-overlay/)
- API-key model: [`api-keys.md`](api-keys.md)
- Chain backend (Bitcoin side): [`electrs.md`](electrs.md)
- Tor operator runbook: [`operator_tor_runbook.md`](operator_tor_runbook.md)
