<p align="center">
  <img src="docs/assets/agent-wallet-logo.png" alt="Agent Wallet logo" width="220" height="220">
</p>

<h1 align="center">Agent Wallet</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/rust-1.85%2B-orange" alt="Rust 1.85+">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT">
  <img src="https://img.shields.io/badge/version-0.1.0-orange" alt="Version">
</p>

A Bitcoin and Lightning wallet service that wraps an LND node with a secure REST
API and a web dashboard. Built for two audiences:

- **AI agents** — a fully-typed OpenAPI surface, API-key auth, configurable spend
  caps, velocity limits, and a complete audit trail.
- **Human operators** — a session-authenticated dashboard for balances, channels,
  payments, on-chain sends/receives, cold-storage sweeps, and BOLT 12 offer
  management.

The wallet covers on-chain payments, Lightning (BOLT 11) payments and invoices,
LNURL-pay and Lightning Address sends, Lightning-to-on-chain cold-storage sweeps
via Boltz Exchange, BOLT 12 offers and invoice requests via an embedded Rust
gateway, message signing (BIP-322 / BIP-137 / zbase32), and mempool-explorer
integration for fee estimation and transaction tracking.

> **For AI agents:** the API exposes a full OpenAPI 3.x schema at
> `GET /openapi.json` (when `ENABLE_DOCS=true`). Import it into your tool
> framework, or fetch it at runtime. Interactive docs are at `/docs`
> (Swagger UI) and `/redoc`.

---

## ⚠️ Disclaimer

Agent Wallet is experimental, self-custodial software for Bitcoin and Lightning.
It is provided **as is, with no warranty — use it at your own risk**, and bugs
or misconfiguration can result in the **permanent loss of funds**. Nothing here
is financial, legal, or tax advice. **You are solely responsible for compliance
with all laws applicable to you** — including AML/KYC, sanctions, tax, and
money-transmission rules. The optional **"Anonymize"** privacy feature is for
lawful financial-privacy purposes only; mixing/coinjoin may be regulated or
restricted in some jurisdictions, and ensuring your use is legal is your
responsibility. See [DISCLAIMER.md](DISCLAIMER.md) for the full terms.

**Cryptography / export note:** this distribution contains and uses encryption
(e.g. TLS, Fernet field encryption, HMAC) and is published as publicly available
open-source software.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Authentication](#authentication)
- [API Reference](#api-reference)
- [Safety Limits](#safety-limits)
- [Usage Examples](#usage-examples)
- [AI Agent Integration](#ai-agent-integration)
- [Boltz Swap Lifecycle](#boltz-swap-lifecycle)
- [BOLT 12](#bolt-12)
- [Testing](#testing)
- [Security](#security)
- [Project Structure](#project-structure)
- [Documentation](#documentation)
- [License](#license)

---

## Features

- **LND node interface** — balance, info, channels, invoices, payments, on-chain
  transactions, fee estimation
- **Lightning payments (BOLT 11)** — create / decode / pay invoices with
  configurable safety limits
- **LNURL-pay & Lightning Address** — dashboard-only send flow for
  `user@domain.tld` and bech32 `lnurl1...` strings (LUD-01 / 06 / 12 / 16 /
  17). SSRF-hardened, Tor-aware, with response-size caps and idempotent
  invoice fetch. See [docs/lnurl.md](docs/lnurl.md)
- **On-chain operations** — generate addresses (P2TR / P2WPKH / NP2WKH), send
  Bitcoin, fee estimation
- **Cold-storage sweeps** — Lightning → on-chain via Boltz Exchange reverse
  submarine swaps (Taproot / Musig2). Automatic retry (200 attempts, tiered
  backoff), startup recovery of pending swaps, cooperative claims for lower fees
- **BOLT 12 offers** — issue, list, decode, and pay BOLT 12 offers via an
  embedded Rust onion-message gateway. BIP-353 human-readable resolution.
  Offerless invoice-request acceptance (opt-in)
- **Anonymize** — privacy-preserving UTXO + Lightning mixing via Boltz
  submarine + reverse swaps with per-call Tor stream isolation, amount
  binning, randomized inter-leg delay, MPP fragmentation, optional
  private-channel hop, optional Liquid Confidential-Transactions
  round-trip, multi-output sessions, decoy outputs with separate
  BIP-86 seed, BIP-353 / BOLT 12 destination resolution and per-session
  deposit-offer minting. Ships with a curated, GPG-signed operator
  registry (canonical Boltz + community alts) and an install wizard
  that auto-generates Fernet at-rest keys + offers pre-vetted operator
  picks. See [docs/anonymize.md](docs/anonymize.md) and
  [docs/anonymize_operator_diversity.md](docs/anonymize_operator_diversity.md)
  for the operator runbook, score-tier definitions, and registry vetting checklist.
- **Braiins Deposit** — guided round-amount deposit flow for Braiins
  Hashpower (and any service with a similar anti-fraud heuristic).
  Converts a slice of your balance to a fresh Taproot UTXO via a
  Boltz reverse swap, then sends a clean single-input round-amount
  transaction (50k / 100k / 250k / 500k / 1M / 2M / 3M / 4M / 5M sats)
  to the destination — bypassing manual review. Deposit from any
  wallet — Lightning or on-chain, internal or external — by paying a
  one-time invoice or sending to a fresh address; no upfront transfer
  into this wallet required.
  See [docs/braiins_deposit.md](docs/braiins_deposit.md)
- **Sign / verify message** — prove control of an on-chain address
  (BIP-322 simple / BIP-137 legacy) or the LN node identity (zbase32)
- **Mempool explorer** — fee estimation, transaction tracking, address
  lookups, congestion stats, block-height queries. Defaults to a public
  mempool.space instance; operators can opt in to their own
  [electrs](https://github.com/romanz/electrs) server (Start9-style
  `tcp://<onion>:50001` works out of the box) so every chain query stays
  on their own infrastructure. See [docs/electrs.md](docs/electrs.md)
- **Web dashboard** — HTMX + Alpine.js (CSP-locked, nonce-gated) for
  human-friendly access to all of the above. The Send Payment dialog
  exposes the same advanced controls as Rebalance: %/sats fee toggle,
  optional outgoing-channel pin, and a route-estimate probe
- **API-key authentication** — HMAC-SHA-256 hashed keys, admin/regular
  roles, expiration, rotation via `SECRET_KEY_PREVIOUS`. Full lifecycle
  (create, rename, scope toggle, rotate, revoke, purge) is also available
  point-and-click from the dashboard — see [docs/api-keys.md](docs/api-keys.md)
- **Field encryption** — sensitive data (preimages, private keys) encrypted
  at rest via Fernet, key derived with PBKDF2-HMAC-SHA256 (600k iterations,
  per-field 16-byte salt)
- **Audit logging** — every write logged with actor, action, and metadata;
  rows form a keyed-HMAC hash chain verifiable via
  `GET /v1/admin/audit-log/verify`
- **Tor support** — SOCKS5 proxy for `.onion` LND nodes (Start9, Umbrel,
  etc.) and the Boltz API
- **Multi-network** — Bitcoin mainnet, testnet, signet, regtest

---

## Architecture

```
   ┌──────────────┐  API key   ┌──────────────────────┐
   │  AI agents   │───────────▶│                      │
   └──────────────┘            │   FastAPI app        │   REST  ┌──────┐
   ┌──────────────┐  session   │   + middleware       │────────▶│ LND  │
   │  Operators   │───────────▶│   + dashboard        │         │ node │
   └──────────────┘            │   + Celery worker    │         └──────┘
                               └──┬──────┬──────┬─────┘
                                  │      │      │
                          ┌───────┘      │      └──────────┐
                          ▼              ▼                 ▼
                     ┌─────────┐    ┌─────────┐    ┌────────────────┐
                     │Postgres │    │  Redis  │    │ Mempool / electrs
                     │  (DB)   │    │ (broker │    │  (chain backend)
                     │         │    │ + cache)│    └────────────────┘
                     └─────────┘    └─────────┘
                                                   ┌────────────────┐
                                                   │ Boltz Exchange │
                                                   │   (swaps)      │
                                                   └────────────────┘
                               ┌──────────────────────┐
                               │ bolt12-gateway       │  onion msgs
                               │ (Rust, LDK + gRPC)   │◀───────────▶ Lightning peers
                               └──────────────────────┘
```

### Design philosophy

The wallet exposes two distinct interfaces — a **REST API** for programs and a
**web dashboard** for humans — each designed around its audience:

**API → AI agents.** Agents authenticate exclusively with API keys, never
touching the LND macaroon directly. This deliberate layer of credential
isolation means a compromised agent key is revoked with a single API call;
without it, a compromised macaroon would require regenerating credentials on
the LND node itself, potentially rebuilding channels or restoring from backup.
The API also enforces per-payment caps, aggregate spend limits, velocity
circuit breakers, and full audit logging — guardrails appropriate for an
autonomous program that must be constrained by policy.

**Dashboard → human operators.** The dashboard provides the same visibility
into wallet state plus richer flows for cold-storage sweeps and BOLT 12 offer
management, but is session-authenticated and not bound by agent-oriented spend
caps. A human reviewing channel health or initiating a sweep needs a clear UI
and direct control, not programmatic guardrails.

**bolt12-gateway.** BOLT 12 operates over Lightning onion messages, which LND
does not currently expose to external RPC clients. The wallet ships a small
Rust sidecar (`bolt12-gateway/`, built on LDK) that connects to peers as a
Lightning node and bridges onion-message traffic to the wallet over gRPC. The
rest of the BOLT 12 logic — offer storage, invoice-request matching, BIP-353
resolution, payment — lives in the Python service. The gateway runs only when
`BOLT12_GATEWAY_GRPC` is configured.

---

## Quickstart

### Prerequisites

- Docker + Docker Compose (recommended path), or
- Python 3.11+, Node.js 20+, PostgreSQL 15+, Redis 7+ for a local install
- A reachable LND node (v0.17+) — REST endpoint, admin macaroon
- (Optional) Rust 1.85+ if you plan to run BOLT 12 features outside Docker

### The fastest path: `./start.sh`

The repository ships an interactive launcher that handles first-run setup,
config review, Tor proxy, and starting the stack:

```bash
git clone <repo> agent-wallet && cd agent-wallet
./start.sh
```

The script will:

1. Create `.venv/` and install Python dependencies if missing.
2. Walk you through `.env` interactively if it isn't there yet — generating a
   strong `SECRET_KEY`, prompting for LND credentials, network, etc.
3. Offer a launch menu: **Docker Compose** (recommended) or **uvicorn-only**
   (you supply Postgres + Redis).
4. Print the API, dashboard, and (if enabled) `/docs` URLs.

On subsequent runs it presents a menu: start, reconfigure, stop, or exit.

### Manual Docker setup

If you'd rather skip the wizard:

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"   # paste into SECRET_KEY
# Edit .env — fill in at minimum:
#   SECRET_KEY, LND_REST_URL, LND_MACAROON_HEX, BITCOIN_NETWORK
#   POSTGRES_PASSWORD, REDIS_PASSWORD

docker compose up -d --build
# Database migrations are applied by the dedicated `migrate` compose service
# (`alembic upgrade head`), which runs once and must complete before the `api`
# and `celery-worker` services start (they `depends_on` it).
```

> **Note on `DATABASE_URL` under Docker Compose:** the `migrate`, `api`, and
> `celery-worker` services set `DATABASE_URL` inline in `docker-compose.yml`
> (pointing at the `postgres` service / `agent_btc_wallet` database), so editing
> the `DATABASE_URL` line in your `.env` has **no effect** on the Compose stack.
> That `.env` value is used for bare-metal / uvicorn-only runs.

Get your LND admin macaroon as hex (run on the LND host):

```bash
xxd -ps -u -c 1000 ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon
```

Create your first admin API key. The wallet ships no bootstrap CLI,
so the first key is inserted directly into the database — every
subsequent key can be minted via `POST /v1/admin/api-keys`:

```bash
docker compose exec api python3 - <<'PY'
import asyncio
from app.core.database import get_db_context
from app.core.security import generate_api_key, hash_api_key
from app.models.api_key import APIKey

async def main() -> None:
    raw = generate_api_key()
    async with get_db_context() as db:
        db.add(APIKey(name="bootstrap", key_hash=hash_api_key(raw), is_admin=True))
        await db.commit()
    print("bootstrap admin key (store securely, shown ONCE):")
    print(raw)

asyncio.run(main())
PY
```

### Manual local install (Linux / macOS)

```bash
sudo apt install python3-venv nodejs npm postgresql redis-server   # Debian/Ubuntu
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
(cd scripts && npm install)         # Boltz Musig2 claim deps

cp .env.example .env && $EDITOR .env
# Create the database named in .env.example's DATABASE_URL
# (postgresql+asyncpg://agent_btc_wallet:...@.../agent_btc_wallet_db):
createdb agent_btc_wallet_db
alembic upgrade head    # bare-metal runs apply migrations manually

uvicorn app.main:app --host 0.0.0.0 --port 8100 --reload
# In a second terminal (same venv):
celery -A app.tasks.boltz_tasks.celery_app worker --loglevel=info
```

BOLT 12 in a local install requires building and running the Rust gateway
separately:

```bash
cargo build --release -p bolt12-gateway
cp bolt12-gateway/config.example.toml bolt12-gateway/config.toml   # edit
BOLT12_GATEWAY_CONFIG=$PWD/bolt12-gateway/config.toml \
    target/release/bolt12-gateway
# Then set BOLT12_GATEWAY_GRPC=127.0.0.1:50061 in the wallet's .env
```

---

## Configuration

All configuration is via environment variables. See `.env.example` for the full,
annotated list. The most commonly tuned ones are below; defaults match
`app/core/config.py`.

#### Core

| Variable | Description | Default |
|---|---|---|
| `SECRET_KEY` | HMAC key for API-key hashing and KDF input for Fernet field encryption | **required** |
| `SECRET_KEY_PREVIOUS` | Previous `SECRET_KEY` during rotation — decrypts legacy ciphertext and one-shot re-hashes API keys on next use | `""` |
| `DATABASE_URL` | PostgreSQL async connection string | **required** |
| `DATABASE_REQUIRE_SSL` | Require SSL/TLS for non-localhost database connections | `false` |
| `REDIS_URL` | Redis broker for Celery + rate limiters | `redis://redis:6379/0` |
| `BITCOIN_NETWORK` | `bitcoin`, `testnet`, `signet`, `regtest` | `bitcoin` |
| `API_HOST` | Host address to bind the API server | `127.0.0.1` |
| `API_PORT` | Port for the API server | `8100` |
| `ENABLE_DOCS` | Expose `/docs`, `/redoc`, `/openapi.json` (opt-in) | `false` |
| `ENABLE_DASHBOARD` | Enable the web dashboard at `/dashboard/` | `true` |
| `ENABLE_HSTS` | Send Strict-Transport-Security header (disable only if **not** behind TLS) | `true` |
| `LOG_LEVEL` / `LOG_FORMAT` | `debug`/`info`/…, and `text`/`json` | `info` / `text` |

> **`ENABLE_DOCS` default:** the application default is `false` (interactive
> docs and `/openapi.json` are opt-in). The shipped `.env.example` sets
> `ENABLE_DOCS=true` for convenience during local setup — set it back to
> `false` (or remove the line) for production unless you intend to expose the
> docs endpoints.

#### LND

| Variable | Description | Default |
|---|---|---|
| `LND_REST_URL` | LND REST API URL | `https://localhost:8080` |
| `LND_MACAROON_HEX` | Hex-encoded LND admin macaroon | `""` |
| `LND_TLS_VERIFY` | Verify LND TLS cert | `true` |
| `LND_TLS_CERT` | Base64-encoded LND TLS cert | `""` |
| `LND_TOR_PROXY` | SOCKS5 proxy for `.onion` LND nodes | `""` |
| `LND_MEMPOOL_URL` | Mempool Explorer instance | `https://mempool.space` |
| `MEMPOOL_ALLOW_INTERNAL` | Bypass SSRF guard refusing private/loopback `LND_MEMPOOL_URL`. Set `true` only for self-hosted internal instances | `false` |

#### Chain backend (optional electrs)

By default the wallet uses the Mempool Explorer HTTP backend for fee
estimates, transaction lookups, address balances, and mempool stats.
Operators running their own [electrs](https://github.com/romanz/electrs)
(e.g. on a Start9 server) can opt in to using it as the primary chain
backend — improving privacy and removing a third-party dependency. See
[docs/electrs.md](docs/electrs.md) for the full guide.

| Variable | Description | Default |
|---|---|---|
| `CHAIN_BACKEND` | `auto` \| `mempool` \| `electrum`. `auto` uses Electrum when `LND_ELECTRUM_URL` is set, with Mempool HTTP as fallback. `electrum` is strict (no fallback). `mempool` ignores Electrum entirely | `auto` |
| `LND_ELECTRUM_URL` | Electrum server URL: `tcp://host:50001` or `ssl://host:50002`. `.onion` hosts route via `LND_TOR_PROXY` | `""` |
| `LND_ELECTRUM_TLS_VERIFY` | Verify TLS cert for `ssl://` URLs (set `false` for self-signed Start9 certs) | `true` |
| `LND_ELECTRUM_CA_CERT` | Optional CA cert (file path or base64-encoded PEM) for `ssl://` URLs | `""` |
| `LND_ELECTRUM_PING_INTERVAL_S` | `server.ping` keepalive interval | `30.0` |
| `LND_ELECTRUM_REQUEST_TIMEOUT_S` | Per-request timeout | `8.0` |
| `LND_ELECTRUM_CONNECT_TIMEOUT_S` | TCP/SSL/SOCKS5 connect timeout | `10.0` |
| `LND_ELECTRUM_MAX_SUBSCRIPTIONS` | Cap on active scripthash subscriptions | `256` |

#### Spend safety

| Variable | Description | Default |
|---|---|---|
| `LND_MAX_PAYMENT_SATS` | Max sats per outgoing payment (`-1` = unlimited) | `10000` |
| `LND_RATE_LIMIT_SATS` | Cumulative spend cap per window | `100000` |
| `LND_RATE_LIMIT_WINDOW_SECONDS` | Window for aggregate spend cap | `3600` |
| `LND_VELOCITY_MAX_TXNS` | Max send txns per velocity window | `5` |
| `LND_VELOCITY_WINDOW_SECONDS` | Window for velocity cap | `900` |
| `RATE_LIMIT_FAIL_POLICY` | Redis-outage behavior — `closed` (block) or `open` (allow) | `closed` |
| `DASHBOARD_MAX_PAYMENT_SATS` | Optional per-payment cap for dashboard ops (`-1` = no limit) | `-1` |
| `API_KEY_MAX_TTL_DAYS` | Maximum lifetime (in days) accepted for `expires_in_days` when minting an API key. Server-side ceiling for both REST and dashboard create flows | `365` |

#### Boltz (cold-storage swaps)

| Variable | Description | Default |
|---|---|---|
| `BOLTZ_API_URL` | Boltz Exchange API URL | `https://api.boltz.exchange/v2` |
| `BOLTZ_USE_TOR` | Route Boltz API via Tor | `true` |
| `BOLTZ_FALLBACK_CLEARNET` | Fall back to clearnet if Tor fails | `false` |

#### BOLT 12

| Variable | Description | Default |
|---|---|---|
| `BOLT12_ENABLED` | Master kill-switch for the BOLT 12 runtime (also requires `BOLT12_GATEWAY_GRPC`) | `true` |
| `BOLT12_GATEWAY_GRPC` | `host:port` of the Rust onion-message gateway (`bolt12-gateway:50061` inside Docker; empty = disabled) | `""` |
| `BOLT12_GATEWAY_TIMEOUT_SECONDS` | Per-RPC timeout to the gateway | `10.0` |
| `BOLT12_GATEWAY_TOKEN` | Shared secret enforced on every wallet ↔ gateway RPC | `""` |
| `BOLT12_ACCEPT_OFFERLESS_INVREQS` | Accept inbound invreqs without a stored offer (advanced) | `false` |
| `BOLT12_INBOUND_RATE_LIMIT_COUNT` / `_WINDOW_SECONDS` | Per-peer onion-message rate limit | `30` / `60` |
| `BOLT12_INBOUND_MAX_AMOUNT_MSAT` | Max amount of inbound invreqs we'll quote for | `100000000` (0.001 BTC) |
| `BOLT12_BIP353_VALIDATE_RESOLVER` | Require DNSSEC-validating resolver for BIP-353 lookups | `true` |

#### LNURL-pay / Lightning Address (dashboard-only)

| Variable | Description | Default |
|---|---|---|
| `LNURL_FORCE_TOR` | Tri-state Tor preference for outbound LNURL fetches: `auto` (mirror LND's posture), `true` (always), `false` (never force) | `auto` |
| `LNURL_ALLOW_HTTP` | Accept plain `http://` for clearnet recipients (`.onion` always allowed) | `false` |
| `LNURL_ALLOW_PRIVATE_HOSTS` | Allow RFC1918 / loopback / link-local recipients (regtest only) | `false` |
| `LNURL_MAX_RESPONSE_BYTES` | Hard cap on recipient response body | `100000` |
| `LNURL_RESOLVE_TIMEOUT_SECONDS` | Per-request timeout for resolve + invoice callbacks | `15.0` |
| `LNURL_HANDLE_TTL_SECONDS` | Server-side opaque-handle TTL bridging resolve→invoice | `300` |
| `LNURL_INVOICE_CACHE_TTL_SECONDS` | Idempotency cache for double-clicked Continue (0 disables) | `30` |

#### Sign / verify message

| Variable | Description | Default |
|---|---|---|
| `ENABLE_SIGN_ADDRESS_API` | Mount `POST /v1/wallet/sign/address` | `true` |
| `ENABLE_SIGN_NODE_API` | Mount `POST /v1/wallet/sign/node` | `true` |
| `SIGN_MESSAGE_MAX_CHARS` | Hard cap on input message length | `4096` |
| `SIGN_AUDIT_RECORD_MESSAGE` | Audit log records full plaintext (otherwise SHA-256 only) | `false` |
| `SIGN_RATE_LIMIT_PER_HOUR` | Per-API-key sliding-window cap on sign ops | `30` |
| `SIGN_RATE_LIMIT_DASHBOARD_PER_HOUR` | Same cap for dashboard sign ops | `60` |

#### Dashboard / ops / observability

| Variable | Description | Default |
|---|---|---|
| `DASHBOARD_TOKEN` | Token for dashboard login (auto-generated if empty) | `""` |
| `DASHBOARD_SESSION_HOURS` | Max session lifetime | `4` |
| `DASHBOARD_IDLE_TIMEOUT_MINUTES` | Idle session timeout | `30` |
| `TRUSTED_PROXIES` | CIDRs allowed to set `X-Forwarded-For`. Required when the dashboard is behind a proxy, or session IP-binding silently no-ops | `""` |
| `CORS_ORIGINS` | Allowed CORS origins (JSON list) | `[]` |
| `AUDIT_LOG_RETENTION_DAYS` | Days to retain audit log entries (`0` = keep forever). Daily Celery task verifies the chain, prunes aged rows, and records a truncation anchor; it skips (and alerts) if the chain does not verify | `90` |
| `ALERT_WEBHOOK_URL` / `ALERT_WEBHOOK_EVENTS` | Outbound security webhook (DNS-rebind hardened) | `""` |

> **Production TLS:** Within Docker Compose, PostgreSQL and Redis connections are internal to the network and unencrypted. For production deployments where the database or Redis is on a separate host, use TLS:
> - **PostgreSQL:** set `DATABASE_REQUIRE_SSL=true` (or append `?ssl=require` to `DATABASE_URL`)
> - **Redis:** use the `rediss://` scheme (e.g., `rediss://:password@host:6379/0`)
>
> The application will log a warning at startup if it detects a remote database or Redis host without TLS.

> **Reverse proxies:** if `ENABLE_DASHBOARD=true` and the API is bound to a non-loopback `API_HOST` (e.g., behind nginx, Caddy, or Cloudflare), set `TRUSTED_PROXIES` to the proxy's CIDR (e.g., `172.16.0.0/12`). Without it, `request.client.host` is the proxy itself — identical for every user — and the dashboard's session IP-binding control degrades to a silent no-op. The application logs a warning at startup when this misconfiguration is detected.

---

## Authentication

All endpoints (except `GET /health` and `GET /ready`) require an API key:

```
Authorization: Bearer lwk_<48 hex chars>
```

| Auth Level | Required For |
|---|---|
| **Any valid key** | Read-only wallet data, fee estimates, mempool lookups, swap status |
| **Admin key only** | Payments, channel operations, cold storage initiation, API key management |

| Error Code | Meaning |
|---|---|
| `401` | Missing, invalid, disabled, or expired API key |
| `403` | Non-admin key used on an admin-only endpoint |

---

## API Reference

### Wallet (Read-Only — any key)

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/wallet/config` | Network config: `{lnd_configured, mempool_url, max_payment_sats, network}` |
| `GET` | `/v1/wallet/summary` | Combined on-chain + lightning balances and node info |
| `GET` | `/v1/wallet/info` | LND node info (alias, pubkey, sync status, block height) |
| `GET` | `/v1/wallet/balance` | `{onchain: {total, confirmed, unconfirmed, ...}, lightning: {...}}` |
| `GET` | `/v1/wallet/fees` | Mempool fee estimates with low/medium/high priorities |
| `GET` | `/v1/wallet/channels` | Active lightning channels |
| `GET` | `/v1/wallet/channels/pending` | Pending channels (opening, closing, force-closing) |
| `GET` | `/v1/wallet/payments?limit=20` | Outgoing payment history (max 100) |
| `GET` | `/v1/wallet/invoices?limit=20` | Incoming invoice history (max 100) |
| `GET` | `/v1/wallet/transactions?limit=20` | On-chain transaction history (max 100) |

### Payments (Write — admin key)

| Method | Path | Body | Description |
|---|---|---|---|
| `POST` | `/v1/payments/address` | `{address_type: "p2tr"\|"p2wkh"\|"np2wkh"}` | Generate new Bitcoin address |
| `POST` | `/v1/payments/invoice` | `{amount_sats: int, memo?: str, expiry?: int}` | Create Lightning invoice |
| `POST` | `/v1/payments/decode` | `{payment_request: str}` | Decode a BOLT11 invoice (any key) |
| `POST` | `/v1/payments/pay` | `{payment_request: str, fee_limit_sats?: int, timeout_seconds?: int}` | Pay Lightning invoice (enforces safety limit) |
| `POST` | `/v1/payments/send-onchain` | `{address: str, amount_sats: int, sat_per_vbyte?: int, fee_priority?: str}` | Send on-chain Bitcoin |
| `POST` | `/v1/payments/estimate-fee` | `{address: str, amount_sats: int, target_conf?: int}` | Estimate on-chain fee (any key) |
| `GET` | `/v1/payments/lookup/{payment_hash}` | — | Look up outgoing payment (any key) |
| `GET` | `/v1/payments/invoice/{r_hash}` | — | Look up incoming invoice (any key) |

**Request body details:**

| Model | Field | Type | Default | Constraints |
|---|---|---|---|---|
| `NewAddressRequest` | `address_type` | `str` | `"p2tr"` | `p2wkh`, `np2wkh`, `p2tr` |
| `CreateInvoiceRequest` | `amount_sats` | `int` | *required* | `≥ 0` (0 = any-amount invoice) |
| | `memo` | `str` | `""` | max 256 chars |
| | `expiry` | `int` | `3600` | 60–86400 seconds |
| `PayInvoiceRequest` | `payment_request` | `str` | *required* | BOLT11 string |
| | `fee_limit_sats` | `int?` | `null` | `≥ 0` |
| | `timeout_seconds` | `int` | `60` | 5–300 |
| `SendOnchainRequest` | `address` | `str` | *required* | Bitcoin address |
| | `amount_sats` | `int` | *required* | `> 0` |
| | `sat_per_vbyte` | `int?` | `null` | `≥ 1` (overrides fee_priority) |
| | `fee_priority` | `str?` | `null` | `low`, `medium`, `high` |
| | `label` | `str` | `""` | max 256 chars |
| `EstimateFeeRequest` | `address` | `str` | *required* | |
| | `amount_sats` | `int` | *required* | `> 0` |
| | `target_conf` | `int` | `6` | 1–144 blocks |

### Channels (Write — admin key)

| Method | Path | Body | Description |
|---|---|---|---|
| `POST` | `/v1/channels/connect-peer` | `{pubkey: str, host: str}` | Connect to a Lightning peer |
| `POST` | `/v1/channels/open` | `{node_pubkey: str, local_funding_amount: int, ...}` | Open a channel |
| `GET` | `/v1/channels/pending/detail` | — | Detailed pending channel info |

| Model | Field | Type | Default | Constraints |
|---|---|---|---|---|
| `ConnectPeerRequest` | `pubkey` | `str` | *required* | exactly 66 hex chars |
| | `host` | `str` | *required* | `ip:port` |
| `OpenChannelRequest` | `node_pubkey` | `str` | *required* | 66 hex chars |
| | `local_funding_amount` | `int` | *required* | `> 0` sats |
| | `sat_per_vbyte` | `int?` | `null` | `≥ 1` |
| | `push_sat` | `int` | `0` | `≥ 0` |
| | `private` | `bool` | `false` | |

### Cold Storage — Boltz Swaps

Lightning-to-on-chain swaps via Boltz Exchange reverse submarine swaps.

| Method | Path | Auth | Body | Description |
|---|---|---|---|---|
| `GET` | `/v1/cold-storage/fees` | any | — | Current Boltz swap fees and limits |
| `POST` | `/v1/cold-storage/initiate` | admin | `InitiateSwapRequest` | Start a Lightning→on-chain swap |
| `GET` | `/v1/cold-storage/swaps?limit=20` | any | — | List swaps for your API key (max 50) |
| `GET` | `/v1/cold-storage/swaps/{swap_id}` | any | — | Get swap status (UUID path param) |
| `POST` | `/v1/cold-storage/swaps/{swap_id}/cancel` | admin | — | Cancel a pending swap |

| Model | Field | Type | Default | Constraints |
|---|---|---|---|---|
| `InitiateSwapRequest` | `amount_sats` | `int` | *required* | 25,000–25,000,000 sats |
| | `destination_address` | `str` | *required* | 26–256 chars, validated per network |
| | `routing_fee_limit_percent` | `float` | `3.0` | 0.1–10.0% |

**Address validation** — the `destination_address` is validated against the configured `BITCOIN_NETWORK`:
- **mainnet** (`bitcoin`): Must start with `bc1`, `1`, or `3`
- **testnet/signet**: Must start with `tb1`, `m`, `n`, or `2`
- **regtest**: Must start with `bcrt1`, `m`, `n`, or `2`

**Swap response shape:**
```json
{
  "id": "uuid",
  "boltz_swap_id": "string",
  "status": "created|paying_invoice|invoice_paid|claiming|claimed|completed|failed|cancelled|refunded",
  "boltz_status": "string",
  "invoice_amount_sats": 500000,
  "onchain_amount_sats": 498500,
  "destination_address": "bc1q...",
  "fee_percentage": 0.25,
  "miner_fee_sats": 1500,
  "boltz_invoice": "lnbc...",
  "claim_txid": "hex|null",
  "error_message": "string|null",
  "status_history": [{"status": "created", "timestamp": "ISO8601"}, ...],
  "created_at": "ISO8601",
  "updated_at": "ISO8601",
  "completed_at": "ISO8601|null"
}
```

### Mempool Explorer (Read-Only — any key)

Query the configured Mempool Explorer instance for on-chain data.

| Method | Path | Description |
|---|---|---|
| `GET` | `/v1/mempool/tx/{txid}` | Transaction lookup — fee, size, outputs, confirmation status |
| `GET` | `/v1/mempool/tx/{txid}/confirmations` | Confirmation count (tip height − block height + 1) |
| `GET` | `/v1/mempool/address/{address}` | Address balance (confirmed + unconfirmed) and tx counts |
| `GET` | `/v1/mempool/address/{address}/utxos` | Unspent outputs: `{address, utxo_count, utxos: [...]}` |
| `GET` | `/v1/mempool/stats` | Mempool congestion: tx count, vsize, total fees, fee histogram (cached 30s) |
| `GET` | `/v1/mempool/block/tip/height` | Current blockchain tip height: `{height: int}` |
| `GET` | `/v1/mempool/block/{height}` | Block header info: hash, timestamp, tx count, size, weight |

**Validation:** `txid` must be 64 hex characters. `address` must be 26–90 alphanumeric characters. `height` must be ≥ 0.

**Transaction response shape:**
```json
{
  "txid": "hex64",
  "confirmed": true,
  "block_height": 800000,
  "block_hash": "hex64",
  "block_time": 1700000000,
  "fee": 1500,
  "size": 250,
  "weight": 680,
  "vin_count": 1,
  "vout_count": 2,
  "vout": [{"scriptpubkey_address": "bc1q...", "value": 50000}, ...]
}
```

**Address response shape:**
```json
{
  "address": "bc1q...",
  "confirmed_balance_sats": 800000,
  "unconfirmed_balance_sats": 50000,
  "total_balance_sats": 850000,
  "confirmed_tx_count": 5,
  "unconfirmed_tx_count": 1,
  "funded_txo_count": 3,
  "spent_txo_count": 1
}
```

### Admin (admin key)

| Method | Path | Body | Description |
|---|---|---|---|
| `POST` | `/v1/admin/api-keys` | `{name, is_admin?, expires_in_days?}` | Create API key — **plaintext key returned only once** |
| `GET` | `/v1/admin/api-keys` | — | List all API keys (hashed, no plaintext) |
| `PATCH` | `/v1/admin/api-keys/{key_id}` | `{name?, is_active?, is_admin?}` | Update API key |
| `DELETE` | `/v1/admin/api-keys/{key_id}` | — | Revoke an API key (cannot delete own key) |
| `GET` | `/v1/admin/audit-log?limit=50&action=...` | — | View audit log (max 200) |
| `GET` | `/v1/admin/audit-log/verify?limit=...` | — | Walk the audit-log hash chain and report any tampered entries: `{checked, ok, first_bad_id, first_bad_reason}` |
| `POST` | `/v1/admin/audit-log/reanchor` | — | Re-anchor the keyed hash chain under the current `SECRET_KEY` after a database restore or key rotation. Deliberate, admin-only; records its own audit entry: `{reanchored, was_consistent, first_bad_id}` |
| `POST` | `/v1/admin/api-keys/{key_id}/purge` | — | Hard-delete a soft-deleted API key. Refuses to run until `AUDIT_LOG_RETENTION_DAYS` has elapsed since `deleted_at` |
| `GET` | `/v1/admin/health` | — | Health check: `{status, lnd_connected, lnd_info}` |

| Model | Field | Type | Default | Constraints |
|---|---|---|---|---|
| `CreateAPIKeyRequest` | `name` | `str` | *required* | 1–128 chars |
| | `is_admin` | `bool` | `false` | |
| | `expires_in_days` | `int?` | `null` | 1–`API_KEY_MAX_TTL_DAYS` (default 365); values above are clamped server-side |

### System (no auth)

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness probe: `{status: "ok"}` |
| `GET` | `/ready` | Readiness probe: `{status: "ok", database: "connected"}`; returns `503` if the database is unreachable |

### Sign / Verify Message

Prove control of an on-chain address or the Lightning node identity by signing
an arbitrary text message. Sign endpoints are mounted by default and can be
disabled per-flag; verify endpoints are always available. With both flags off
the sign routes return `404` to probes.

Feature flags (env / `app.core.config.Settings`) — see the
[Sign / verify message](#sign--verify-message) configuration table above.

| Method | Path | Auth | Body | Description |
|---|---|---|---|---|
| `POST` | `/v1/wallet/sign/address` | admin | `{address, message}` | Sign with an on-chain address private key. Format: BIP-322 simple for SegWit/Taproot, BIP-137 for legacy. |
| `POST` | `/v1/wallet/verify/address` | any | `{address, message, signature}` | Verify an address signature. |
| `POST` | `/v1/wallet/sign/node` | admin | `{message}` | Sign with the Lightning node identity key (zbase32). |
| `POST` | `/v1/wallet/verify/node` | any | `{message, signature}` | Verify a node-identity signature. |

Sign-with-address response:

```json
{
  "address": "bc1q…",
  "address_type": "p2wkh",
  "signature": "…",
  "format": "BIP-322"
}
```

### BOLT 12

BOLT 12 endpoints are mounted under `/v1/bolt12/*`. They are always present, but
endpoints that require live onion-message I/O return `503` when
`BOLT12_ENABLED=false` or `BOLT12_GATEWAY_GRPC` is unset. Read the
[BOLT 12 section](#bolt-12) below for an overview, and [docs/bolt12.md](docs/bolt12.md)
for protocol-level notes.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/bolt12/status` | any | Runtime + gateway health, network, peer count |
| `GET` | `/v1/bolt12/metrics` | any | Prometheus metrics for BOLT 12 ops |
| `POST` | `/v1/bolt12/decode` | any | Decode a BOLT 12 offer / invreq / invoice string |
| `POST` | `/v1/bolt12/offers` | admin | Persist (import) a third-party offer |
| `POST` | `/v1/bolt12/offers/issue` | admin | Issue a new offer signed by this wallet |
| `GET` | `/v1/bolt12/offers` | any | List stored offers |
| `GET` | `/v1/bolt12/offers/{id}` | any | Get one offer + linked invreqs/invoices |
| `DELETE` | `/v1/bolt12/offers/{id}` | admin | Disable / soft-delete an offer |
| `POST` | `/v1/bolt12/offers/{id}/set-default` | admin | Mark an offer as the dashboard “receive” default |
| `GET` | `/v1/bolt12/offers/{id}/invoice-requests` | any | List invreqs received for an offer |
| `GET` | `/v1/bolt12/offers/{id}/invoices` | any | List invoices issued for an offer |
| `POST` | `/v1/bolt12/invoices/{id}/proof` | admin | Re-emit settlement proof |
| `GET` | `/v1/bolt12/receive` | any | Default-receive offer for the dashboard |
| `POST` | `/v1/bolt12/receive/configure` | admin | Configure / regenerate the default-receive offer |
| `POST` | `/v1/bolt12/bip353/resolve` | any | Resolve `name@domain` → BOLT 12 offer (BIP-353) |
| `POST` | `/v1/bolt12/bip353/zone-record` | admin | Generate a DNS TXT record for an offer |
| `POST` | `/v1/bolt12/pay` | admin | Pay an offer or BIP-353 handle (fetch invoice + pay) |

---

## Error Codes

| Code | Meaning |
|---|---|
| `400` | Validation error, safety limit exceeded, invalid UUID, cannot cancel swap, self-delete |
| `401` | Missing, invalid, disabled, or expired API key |
| `403` | Non-admin key used on an admin-only endpoint |
| `404` | Resource not found (payment, invoice, swap, API key, transaction, address, block) |
| `502` | LND or Boltz returned an error |
| `503` | LND or Mempool Explorer unreachable |

---

## Safety Limits

The API enforces configurable guards to prevent accidental large payments:

| Guard | Config Variable | Default | Behavior |
|---|---|---|---|
| Per-payment max | `LND_MAX_PAYMENT_SATS` | 10,000 | Rejects payments exceeding this amount |
| Aggregate spend | `LND_RATE_LIMIT_SATS` | 100,000 | Cumulative cap in rolling window |
| Rate window | `LND_RATE_LIMIT_WINDOW_SECONDS` | 3,600 | Window for aggregate limit (1 hour) |
| Velocity | `LND_VELOCITY_MAX_TXNS` | 5 | Max send transactions per window |
| Velocity window | `LND_VELOCITY_WINDOW_SECONDS` | 900 | Window for velocity limit (15 min) |
| Redis outage policy | `RATE_LIMIT_FAIL_POLICY` | `closed` | `closed` blocks payments for safety; `open` allows them |
| Dashboard per-payment cap | `DASHBOARD_MAX_PAYMENT_SATS` | `-1` (unlimited) | Optional cap on dashboard send/open operations |

Set any limit to `0` to disable it. Set `LND_MAX_PAYMENT_SATS=-1` for unlimited.

---

## Usage Examples

```bash
# Set your API key and base URL
export API_KEY="lwk_your_key_here"
BASE="http://localhost:8100"
AUTH="Authorization: Bearer $API_KEY"

# ── Read wallet state ──
curl -s -H "$AUTH" "$BASE/v1/wallet/summary" | jq
curl -s -H "$AUTH" "$BASE/v1/wallet/balance" | jq
curl -s -H "$AUTH" "$BASE/v1/wallet/fees" | jq

# ── Generate a Taproot address ──
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"address_type": "p2tr"}' \
  "$BASE/v1/payments/address" | jq

# ── Create a Lightning invoice ──
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"amount_sats": 50000, "memo": "Test invoice"}' \
  "$BASE/v1/payments/invoice" | jq

# ── Pay a Lightning invoice ──
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"payment_request": "lnbc500u1p..."}' \
  "$BASE/v1/payments/pay" | jq

# ── Send on-chain with medium fee priority ──
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"address": "bc1q...", "amount_sats": 100000, "fee_priority": "medium"}' \
  "$BASE/v1/payments/send-onchain" | jq

# ── Sweep to cold storage via Boltz ──
curl -s -X POST -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"amount_sats": 500000, "destination_address": "bc1q...", "routing_fee_limit_percent": 3.0}' \
  "$BASE/v1/cold-storage/initiate" | jq

# ── Track a swap ──
curl -s -H "$AUTH" "$BASE/v1/cold-storage/swaps/SWAP_UUID" | jq

# ── Check transaction confirmations ──
curl -s -H "$AUTH" "$BASE/v1/mempool/tx/TXID_HEX/confirmations" | jq

# ── Look up a cold storage address balance ──
curl -s -H "$AUTH" "$BASE/v1/mempool/address/bc1q.../utxos" | jq

# ── Check mempool congestion before sending ──
curl -s -H "$AUTH" "$BASE/v1/mempool/stats" | jq

# ── Get current block height (for Boltz timeout monitoring) ──
curl -s -H "$AUTH" "$BASE/v1/mempool/block/tip/height" | jq
```

---

## AI Agent Integration

### Getting the API Schema

The API auto-generates an OpenAPI 3.x schema with full type information, descriptions, and examples:

These endpoints are only available when `ENABLE_DOCS=true`.

| URL | Format |
|---|---|
| `GET /openapi.json` | Machine-readable JSON schema (no auth required) |
| `GET /docs` | Swagger UI (interactive, browser) |
| `GET /redoc` | ReDoc (readable reference, browser) |

### For Agent Frameworks

```python
# LangChain / CrewAI / any OpenAPI-compatible agent
import httpx

schema = httpx.get("http://localhost:8100/openapi.json").json()
# Pass `schema` to your agent's tool registry
```

### Static Schema Export

Generate a static `openapi.json` file to bundle with agent prompts:

```bash
cd agent-wallet && source .venv/bin/activate
python3 -c "
import json
from app.main import app
with open('openapi.json', 'w') as f:
    json.dump(app.openapi(), f, indent=2)
print('Schema exported to openapi.json')
"
```

### What an Agent Needs

1. **Base URL** — e.g., `http://agent-wallet:8100`
2. **API key** — a `lwk_...` token, passed as `Authorization: Bearer lwk_...`
3. **Schema** — fetched from `/openapi.json` or bundled statically
4. **Network awareness** — know which `BITCOIN_NETWORK` is configured (returned by `GET /v1/wallet/config`)

Every endpoint description in the schema explains what the endpoint does and when to use it, serving as natural-language tool descriptions for the LLM.

---

## Boltz Swap Lifecycle

```
CREATED → PAYING_INVOICE → INVOICE_PAID → CLAIMING → CLAIMED → COMPLETED
    ↓
 CANCELLED                     FAILED ←── (any step can fail)
```

- **Automatic Retry**: Failed swaps retry up to 200 times with tiered backoff (10s → 30s → 120s → 300s)
- **Startup Recovery**: Pending swaps automatically recovered when the API starts
- **Cooperative Claims**: Musig2 Taproot claims via boltz-core (Node.js) for lower fees
- **Status History**: Every state transition recorded with timestamps
- **Timeout Monitoring**: Compare `swap.timeout_block_height` against `GET /v1/mempool/block/tip/height`

---

## BOLT 12

BOLT 12 (offers, invoice requests, invoices) is delivered over Lightning
**onion messages**, which LND does not currently surface to external RPC
clients. Agent Wallet ships a small Rust sidecar built on
[LDK](https://lightningdevkit.org/) (`bolt12-gateway/`) that:

- connects to the Lightning network as its own peer (using a key separate from
  your LND identity),
- accepts inbound `invoice_request` onion messages and forwards them to the
  wallet over gRPC,
- relays outbound `invoice` and payment-flow messages from the wallet to the
  destination node.

The gateway is started automatically by `docker-compose.yml` on port `50061`.
For manual installs, see the build/run commands in [Quickstart](#quickstart).

### What you get

- **Issue offers** — reusable BOLT 12 "static invoices" signed by the wallet.
  Settable amount or amount-less (donation-style).
- **Pay offers** — fetch a fresh invoice for any third-party offer, then pay it
  through your LND node.
- **BIP-353 handles** — resolve `alice@example.com` to an offer via DNSSEC and
  emit zone records for offers you control.
- **Default-receive offer** — the dashboard auto-creates a permanent offer for
  the “receive” button, with an SVG QR code.
- **Offerless invreqs** (advanced; opt-in via `BOLT12_ACCEPT_OFFERLESS_INVREQS`)
  — quote any peer that asks, without needing a stored offer first.

Protocol-level details and threat model live in [docs/bolt12.md](docs/bolt12.md).

---

## Web Dashboard

When `ENABLE_DASHBOARD=true` (the default), the wallet serves a
session-authenticated UI at `/dashboard/`:

- **Login** with the dashboard token (set `DASHBOARD_TOKEN`, or check the
  startup logs for the auto-generated value).
- Tabs for **Channels**, **Payments** (BOLT 11 send), **Invoices** (BOLT 11
  receive), **On-chain**, **BOLT 12**, and **Activity** (recent
  audit-log summary).
- A **⚙ Settings** menu in the header opens **API Keys** (full
  lifecycle management — create, rename, rotate, scope toggle, revoke,
  purge — with one-shot plaintext display, 60s clipboard auto-clear,
  and bootstrap-key safeguards) and the **Audit Log** viewer (filter by
  action / key name / time range, expand rows for `details` JSON,
  **Verify chain** button that recomputes the keyed hash chain
  server-side, plus a **Re-anchor** action shown when the chain needs
  re-baselining after a restore or `SECRET_KEY` rotation). See
  [docs/api-keys.md](docs/api-keys.md) for the
  operator guide.
- The **Send Payment** dialog auto-detects the input type — BOLT 11 invoice,
  bech32 `lnurl1...` string, or Lightning Address (`user@domain.tld`) — and
  routes through the LNURL resolver for the latter two before handing off to
  the standard pay confirm panel.
- The On-chain tab includes quick-access **Send** and **Receive** buttons next
  to the Sign / Verify message panel.
- **Cold storage** sweep flow with live Boltz fee preview and swap-status
  polling. When the optional electrs backend is configured, the swap
  detail panel also shows live claim-TX confirmation count and a
  tip-aware "blocks until timeout" indicator.
- **Sign / verify** message panels (BIP-322 / BIP-137 / zbase32).
- **Live broadcast tracking** for consolidate and send-onchain flows
  when an electrs backend is configured: the success view polls
  confirmation count automatically until the TX reaches 6 confirmations.

The dashboard is hardened with HMAC-signed session cookies, server-side session
revocation in Redis, CSRF double-submit tokens, optional IP binding, a
30-minute idle timeout, and a per-request CSP nonce.

---

## Testing

```bash
source .venv/bin/activate

# Run all tests (~1400 tests, ~100s)
python -m pytest tests/ -v

# Unit tests only
python -m pytest tests/unit/ -v

# Integration tests only
python -m pytest tests/integration/ -v

# With coverage
python -m pytest tests/ --cov=app --cov-report=term-missing
```

Tests use SQLite in-memory databases — no PostgreSQL, Redis, or LND required.

---

## Security

- **API Keys**: `lwk_` prefix + 24 random bytes (48 hex chars). Stored as HMAC-SHA-256 digests keyed with `SECRET_KEY` — raw keys cannot be recovered after creation. Rotation is supported via `SECRET_KEY_PREVIOUS`: keys verify under the old digest and are transparently re-hashed under the new key on next use.
- **Field Encryption**: Preimages and private keys encrypted at rest via Fernet. Key is derived from `SECRET_KEY` using PBKDF2-HMAC-SHA256 with 600,000 iterations and a **per-field 16-byte random salt** (legacy fixed-salt ciphertext is still readable for backward compatibility).
- **Payment Safety**: Configurable per-payment max, aggregate spend limit, and velocity circuit breaker. Redis-backed Lua-atomic counters; outage policy is fail-closed by default.
- **Audit Trail**: All write operations logged with API key ID, action, resource, amount, and metadata. Each row carries a **keyed HMAC** (derived from `SECRET_KEY`) chained to its predecessor; tampering or reordering is detected by `/v1/admin/audit-log/verify`. Because the chain is keyed, only a holder of `SECRET_KEY` can produce valid hashes — a database-write attacker without the key cannot silently rewrite history (an attacker holding `SECRET_KEY` itself still can; the chain is not an external anchor). Retention pruning verifies the chain before deleting and refuses (raising a security alert) if it does not verify — it never rewrites surviving rows. After a database restore or a `SECRET_KEY` rotation the chain will no longer verify until you re-anchor it via `POST /v1/admin/audit-log/reanchor` (also a dashboard button); the re-anchor is itself recorded in the log.
- **Dashboard**: HMAC-signed session cookies with server-side revocation in Redis, CSRF double-submit, IP binding (when `TRUSTED_PROXIES` is configured), 30-minute idle timeout, and per-request CSP nonce.
- **Network Validation**: Bitcoin addresses validated against the configured network to prevent mainnet/testnet mistakes.
- **SSRF Hardening**: Outbound webhook and `LND_MEMPOOL_URL` targets are checked against private/loopback ranges at request time; peer-host inputs to LND are validated similarly.
- **Tor Support**: Optional SOCKS5 proxy for .onion LND nodes and Boltz API.
- **Container Hardening**: `read_only`, `cap_drop=ALL`, `no-new-privileges`, non-root `appuser` in the API and worker containers.

---

## Project Structure

```
agent-wallet/
├── app/                              # Python FastAPI service
│   ├── api/                          # FastAPI route handlers
│   │   ├── admin.py                  # API key CRUD, audit log + verify, health
│   │   ├── bolt12.py                 # /v1/bolt12/* (offers, invreqs, BIP-353, pay)
│   │   ├── channels.py               # Connect peer, open channel
│   │   ├── cold_storage.py           # Boltz swap endpoints + address validation
│   │   ├── mempool.py                # Tx lookup, address, blocks, congestion stats
│   │   ├── payments.py               # Invoice, pay, send, address generation
│   │   ├── sign.py                   # Sign / verify message (BIP-322, BIP-137, zbase32)
│   │   └── wallet.py                 # Read-only wallet state
│   ├── core/
│   │   ├── config.py                 # Pydantic settings from env vars
│   │   ├── database.py               # Async SQLAlchemy (per-event-loop isolation)
│   │   ├── encryption.py             # Fernet field encryption (per-field salt)
│   │   ├── rate_limit.py             # Redis Lua-atomic rate limiters, fail-closed
│   │   └── security.py               # API key generation, HMAC hashing, FastAPI deps
│   ├── dashboard/                    # Web dashboard (HTMX + Alpine, CSP-locked)
│   │   ├── api.py                    # Dashboard endpoints (session+CSRF gated)
│   │   ├── auth.py                   # Session cookie sign/verify, IP binding, idle timeout
│   │   ├── routes.py                 # Page renderers
│   │   ├── static/                   # JS, CSS, icons
│   │   └── templates/                # Jinja templates with per-request CSP nonces
│   ├── models/
│   │   ├── api_key.py                # APIKey (soft-delete + previous-hash for rotation)
│   │   ├── audit_log.py              # AuditLog with keyed-HMAC hash chain
│   │   ├── bolt12_offer.py           # BOLT 12 offer storage
│   │   ├── bolt12_invoice.py         # BOLT 12 invoice + invreq storage
│   │   └── boltz_swap.py             # BoltzSwap model, SwapStatus enum
│   ├── services/
│   │   ├── alert_service.py          # Webhook alerts (DNS-rebind hardened)
│   │   ├── audit_service.py          # Action logging + chain verify + retention prune
│   │   ├── boltz_service.py          # Boltz Exchange reverse swaps
│   │   ├── lnd_service.py            # LND REST API client
│   │   ├── lnurl_service.py          # LNURL-pay / Lightning Address resolver
│   │   ├── mempool_fee_service.py    # Public chain-state facade (delegates to a backend)
│   │   ├── chain/                    # Pluggable chain backends
│   │   │   ├── backend.py            # ChainBackend Protocol + shared types
│   │   │   ├── mempool_http.py       # Mempool Explorer HTTP backend (default)
│   │   │   ├── electrum.py           # Electrum/electrs backend + circuit breaker
│   │   │   └── electrum_protocol.py  # Wire framing + scripthash address decoder
│   │   ├── utxo_service.py           # ListUnspent reconcile + auto:receive labels
│   │   ├── utxo_subscriptions.py     # Push-driven receive notifications (electrs only)
│   │   ├── bolt12/                   # BOLT 12 runtime: offer issuance, invreq matching, BIP-353
│   │   └── bolt12_gateway/           # gRPC client + protobuf bindings for the Rust gateway
│   ├── tasks/                        # Celery: swap processing, recovery, audit retention
│   └── main.py                       # FastAPI app, lifespan, router mounting
├── bolt12-gateway/                   # Rust onion-message sidecar (LDK + tonic gRPC)
│   ├── src/                          # Server code
│   ├── tests/                        # Integration tests against the gRPC surface
│   └── config.example.toml           # Sample gateway config
├── proto/
│   └── bolt12_gateway.proto          # gRPC schema shared by Python + Rust
├── alembic/                          # Database migrations (current head: 043)
├── scripts/                          # Node.js Boltz claim, regtest smoke tests, helpers
├── tor-proxy/                        # Tor SOCKS5 proxy (`tor-proxy` compose service)
├── tests/
│   ├── unit/                         # Unit tests — services, models, auth, validation
│   └── integration/                  # Full request→response endpoint tests
├── docs/                             # User-facing feature guides — see docs/README.md for the full index
├── CHANGELOG.md
├── .env.example                      # Annotated config template
├── docker-compose.yml                # postgres, redis, tor-proxy, migrate, api, celery, bolt12-gateway
├── docker-compose.liquid.yml         # Optional Liquid overlay (strong-tier Anonymize)
├── docker-compose.tor-split.yml      # Optional split-Tor overlay
├── Dockerfile                        # Python 3.12 + Node.js 20 (wallet image)
├── Dockerfile.gateway                # Rust 1.85 (BOLT 12 gateway image)
├── start.sh                          # Interactive setup + launcher
├── Cargo.toml                        # Rust workspace
└── pyproject.toml                    # Python deps + tool config
```

---

## Documentation

The full set of feature and operator guides lives under
[`docs/`](docs/README.md). Some of the most useful, easily-missed ones:

- [docs/secret_key_backup.md](docs/secret_key_backup.md) — backing up and protecting `SECRET_KEY` and at-rest encryption material
- [docs/operator_tor_runbook.md](docs/operator_tor_runbook.md) — running and monitoring the bundled Tor SOCKS5 proxy
- [docs/boltz.md](docs/boltz.md) — Boltz Exchange swap integration
- [docs/boltz_recovery.md](docs/boltz_recovery.md) — recovering stuck or pending Boltz swaps
- [docs/anonymize_troubleshooting.md](docs/anonymize_troubleshooting.md) — recovering Anonymize sessions stuck in `awaiting_reconciliation`

---

## License

[MIT](LICENSE)

Third-party components bundled in this repository are listed, with their
licenses, in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

Use of this software is subject to the [DISCLAIMER](DISCLAIMER.md).
