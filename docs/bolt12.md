# BOLT 12 — operator guide

This document is the user-facing reference for the wallet's BOLT 12
("offers") subsystem. For the spec itself see
[bolt12.org](https://bolt12.org) and
[BOLT-12](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md).

> **Status:** the BOLT 12 subsystem is production-ready on regtest
> and testnet — receive-side and outbound HTLC settlement (paying a
> remote BOLT 12 offer) are both wired end-to-end. Run with eyes
> open before flipping `BOLT12_ENABLED=true` on mainnet.

---

## What works today

| Capability | Status | Notes |
| --- | --- | --- |
| Issue an offer (`POST /v1/bolt12/offers/issue`) | ✅ | Bech32 (`lno…`) string returned, signed with a fresh per-offer key, advertises a blinded reply path through the gateway. |
| BIP-353 lookup (Lightning addresses → offer fetch) | ✅ | `POST /v1/bolt12/pay/offer` resolves `name@host` via DNSSEC and proceeds. |
| Pay-offer-to-fetch-invoice | ✅ | Wallet sends an `invoice_request` over an onion message and waits for the peer's signed `invoice` reply. |
| Pay-offer outbound HTLC settlement | ✅ | Once the invoice arrives, the wallet decodes `invoice_paths` + `invoice_blindedpay` into LND `BlindedPaymentPath` JSON, calls `QueryRoutes` over the blinded paths, and forwards the HTLC via `SendToRouteV2`. Terminal status surfaces in `Bolt12Invoice.status` (`PAID` / `FAILED`) and the API response's `settlement.status`. |
| Receive-side responder (offer-bound `invreq`) | ✅ | Inbound `invoice_request`s referencing one of our offers are answered with a freshly minted LND blinded invoice. |
| Optional offer-less responder | ✅ (off by default) | Mints invoices for invreqs that *don't* reference an offer. Anyone with onion-message access can trigger this — see threat model. |
| Audit log + dashboard activity | ✅ | All inbound mints, drops, rate-limits, and amount-cap rejections land in the audit chain and surface in `/dashboard/activity`. |
| Settlement reconciliation | ✅ | Background worker projects LND HTLC state onto `bolt12_invoices.status`: inbound (`OPEN → PAID / EXPIRED`) and outbound (`OPEN → PAID / FAILED` via `lookup_payment`, as a catch-up safety net for the synchronous pay-offer path). |
| Prometheus exposition | ✅ | `GET /v1/bolt12/metrics` returns text-format counters + gauges. |

## Reachability — `offer_paths`

Every issued offer (single-shot, dashboard-minted, or the
auto-minted default receive offer) carries a blinded `offer_paths`
(TLV 16) whose introduction node is one of the BOLT 12 gateway's
onion-message-capable peers. The payer reads the offer, sees the
blinded path, connects to the (gossiped) introduction node, and
sends its `invoice_request` to us over an onion message. The
per-offer `issuer_id` identifies which of our offers a given
inbound `invreq` belongs to — it's a *destination tag*, not a
routing address; the ephemeral key is never advertised in gossip.

**Degraded path.** If the gateway has no onion-message-capable
peers at offer-issuance time (gateway down, no peers connected
yet, regtest with the gateway in isolation), the offer is still
minted but **without** `offer_paths`, and a WARNING is logged
identifying the operator-side remediation. Direct-routing offers
are only useful in unit/regtest harnesses where the issuer_id is
mapped manually — they cannot work over real networks.

> **If your payer (OCEAN, BTCPayServer, a CLN sender) reports**
> *"could not route or connect directly to <pubkey>"* or *"no
> address known for peer"*, the offer was minted while the gateway
> had no onion-message peers. Bring the gateway up, confirm at
> least one peer advertises onion-message support
> (`GET /v1/bolt12/status`), then re-mint the offer with
> `POST /v1/bolt12/receive/configure` (or
> `POST /v1/bolt12/offers/issue` for a one-shot offer).

## Limitations

- **No merchant-issued refunds.** The receive-side does not yet
  process `invoice_request` messages with `invreq_payer_id` matching
  a pinned refund context.
- **Single-tenant offers.** Offers are issued under the dashboard
  sentinel API key only. There is no per-tenant ownership boundary
  on the receive side; an inbound payment for offer X is attributed
  to the dashboard key, not to the API key that originally created
  X.
- **Network gating is enforced.** Offers issued on regtest carry an
  explicit `chains=(regtest,)` field; the responder rejects
  cross-chain invreqs (audit action `bolt12_invreq_dropped`,
  reason=`chain_mismatch`). Mainnet implicitly carries empty
  `chains` per the BOLT 12 spec.

---

## Architecture

```
                     ┌──────────────────────────────────────────────┐
                     │                Wallet (FastAPI)              │
                     │                                              │
   API calls ───────▶│  /v1/bolt12/* ── Bolt12Service ──┐           │
   /metrics  ◀───────│                                  │           │
                     │      ┌──── responder (recv) ─────┘           │
                     │      │           │                           │
                     │      ▼           ▼                           │
                     │   AuditLog   Bolt12Invoice (DB)              │
                     │      │           │                           │
                     │      └────▶ reconciler ─────▶ LND ──────────┐│
                     │                            (REST + macaroon)││
                     │                                              ││
                     │  Bolt12GatewayClient (gRPC + bearer token)   ││
                     └──────────────────┬───────────────────────────┘│
                                        │ 127.0.0.1:50061            │
                                        ▼                            │
                     ┌──────────────────────────────────────────────┐│
                     │            bolt12-gateway (Rust + LDK)       ││
                     │                                              ││
                     │  • OnionMessenger / PeerManager              ││
                     │  • BlindedMessagePath builder                ││
                     │  • peers connect via SOCKS5 → tor-proxy      ││
                     └──────────────────┬───────────────────────────┘│
                                        │                            │
                              onion-msg │  HTLC settlement           │
                                        ▼            ▼               ▼
                                  Lightning peers      LND (BOLT-11)
```

Key points:

1. **Settlement is owned by LND.** When we mint a BOLT 12 invoice we
   call `add_blinded_invoice` on LND so LND owns the preimage and
   auto-settles the inbound HTLC. The Rust gateway never touches the
   on-chain channel — it only routes onion messages.
2. **The gateway is process-isolated.** It runs as a separate
   container and exposes a private gRPC API on
   `127.0.0.1:50061`. The wallet authenticates with a shared
   bearer token (`BOLT12_GATEWAY_TOKEN`).

   > **Deployment note (multi-tenant hosts).** The default gRPC
   > channel is plaintext bearer-token over loopback — appropriate
   > for single-host Docker Compose where the loopback interface is
   > a trust boundary. If you co-locate the gateway with workloads
   > from a different trust domain (e.g., a shared Kubernetes
   > namespace, a multi-tenant VM), terminate the gRPC channel with
   > **mTLS** or bind the gateway to a **Unix domain socket** owned
   > by the wallet user instead of `127.0.0.1:50061`. Without that,
   > any process that can open a TCP socket on the host can mint
   > BOLT-12 invoice requests using the wallet's bearer token if it
   > is also leaked.
3. **The reconciler is the source of truth for invoice state.** The
   responder writes `bolt12_invoices` rows in `OPEN`; the reconciler
   joins them against LND's `LookupInvoice` and flips them to
   `PAID` / `EXPIRED`.

---

## Control knobs

All knobs are environment variables read into `app/core/config.py`.

### Wallet side

| Variable | Default | Effect |
| --- | --- | --- |
| `BOLT12_ENABLED` | `false` | Master kill switch. Even if the gateway target is set, BOLT 12 stays inert until this is `true`. |
| `BOLT12_GATEWAY_GRPC` | `""` | gRPC target (`host:port`) of the bolt12-gateway daemon. Empty disables BOLT 12. |
| `BOLT12_GATEWAY_TIMEOUT_SECONDS` | `10` | Per-RPC deadline. |
| `BOLT12_GATEWAY_TOKEN` | `""` | Shared bearer token. Must match the gateway's `auth_token`. Empty on both ends = unauthenticated channel (only safe inside a private docker network). |
| `BOLT12_ACCEPT_OFFERLESS_INVREQS` | `false` | Allow inbound `invoice_request` messages that do **not** reference one of our offers. See the threat model below before enabling. |
| `BOLT12_INBOUND_RATE_LIMIT_COUNT` | `30` | Per-payer sliding-window rate limit. Set to `0` to disable. |
| `BOLT12_INBOUND_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window. |
| `BOLT12_INBOUND_MAX_AMOUNT_MSAT` | `100_000_000` | Hard cap on the amount any single inbound invreq may request (default 100 000 sats). Set to `0` to disable the cap. |
| `BITCOIN_NETWORK` | `mainnet` | Which chain hash the wallet stamps onto offers/invreqs. |
| `RATE_LIMIT_FAIL_POLICY` | `closed` | When Redis is unavailable, `closed` rejects requests, `open` admits them. Production should keep `closed`. |

### Gateway side (`bolt12-gateway/config.toml`)

| Field / env | Default | Effect |
| --- | --- | --- |
| `network` / `BOLT12_GATEWAY_NETWORK` | `regtest` | **Must match** `BITCOIN_NETWORK`. The wallet refuses to start the BOLT 12 runtime on mismatch. |
| `auth_token` / `BOLT12_GATEWAY_TOKEN` | unset | Shared bearer token. Must match the wallet's setting. |
| `grpc_listen` / `BOLT12_GATEWAY_GRPC_LISTEN` | `127.0.0.1:50061` | gRPC bind address. |
| `socks5_proxy` / `BOLT12_GATEWAY_SOCKS5_PROXY` | unset | Route peer traffic through this SOCKS5 proxy (typically `tor-proxy:9050`). |
| `bootstrap_peers` | `[]` | Onion-message-capable seed peers. |

---

## Threat model

The receive-side surface is reachable by **any onion-message peer**
that the gateway is connected to. There is no peer authentication
beyond what BOLT 12 itself provides (the `invoice_request` is signed
by the payer's `invreq_payer_id`, but that key is unauthenticated to
us). The wallet defends with three layers:

1. **Chain-hash gate.** Cross-chain invreqs are rejected before any
   minting work.
2. **Per-payer rate limit.** Sliding-window cap on invreqs per
   `payer_id`. Default 30/min. Falls open if Redis is down only
   when `RATE_LIMIT_FAIL_POLICY=open`.
3. **Hard amount cap.** Any inbound invreq whose `invreq_amount`
   exceeds `BOLT12_INBOUND_MAX_AMOUNT_MSAT` is dropped before
   `add_blinded_invoice`.

All drops emit audit-log entries (`bolt12_invreq_dropped`,
`bolt12_invreq_rate_limited`, `bolt12_invreq_amount_cap`). Successful
mints emit `bolt12_invoice_minted`.

**Risks that are NOT mitigated in code** and need operator
diligence:

- **Liquidity exhaustion.** A flood of small valid invreqs (under
  the amount cap, under the rate limit) can pin inbound liquidity
  in unredeemed invoices until they expire. The reconciler will
  flip them to `EXPIRED` after the LND timer fires; until then the
  liquidity is reserved.
- **Privacy leaks via timing.** Onion-message replies carry no
  metadata, but reply latency can correlate the responder with a
  specific peer. If you care, run the gateway behind Tor.
- **Gateway compromise.** A compromised gateway can intercept and
  alter onion messages. The bearer-token auth limits *who can talk
  to the gateway*, not *what the gateway does with the messages*.
  Run it as an unprivileged user in a hardened container.

### Issuer-key reuse semantics

Each offer carries a fresh `issuer_id` keypair, generated when the
offer is minted and encrypted at rest under the wallet's master
key. The keypair is **scoped to the offer** — it is never shared
across offers, never reused after the offer is disabled, and never
rotated for an active offer.

Practical consequences:

- **Disabling an offer is permanent for that key.** Once an offer
  is moved out of `ACTIVE` (deleted, expired, or replaced as the
  default-receive offer), its issuer key will never sign another
  invoice. There is no "reactivate" path; mint a new offer instead.
- **Recurring payers must be re-onboarded if you rotate.** A
  payer registered against `lno1...A` cannot transparently follow
  you to `lno1...B`. Only rotate the receive offer when you are
  prepared to hand the new string to every recurring payer (e.g.
  the Ocean pool dashboard). The default-receive flow is built to
  discourage churn for this reason.
- **No cross-offer linkability via the key.** Because each offer
  has its own `issuer_id`, an on-path observer cannot correlate
  two of your offers by inspecting the published bech32 strings
  alone. Correlation by `node_id` (in the signed invoice) is a
  separate concern — see the privacy notes above.
- **Key compromise is contained to one offer.** A leak of one
  encrypted-issuer-key blob (e.g. via a partial DB exfiltration)
  lets the attacker mint invoices that look like they came from
  *that one offer* only. Disable the offer; the key cannot be
  used to impersonate any other offer.

If you want a single long-lived "brand" identity for an issuer (as
opposed to one per offer), that is **not currently supported** —
it would require a separate identity-key abstraction with its own
rotation policy. File an issue if you need it.

---

## Mainnet operator checklist

1. **Set `BITCOIN_NETWORK=mainnet`** on the wallet *and*
   `BOLT12_GATEWAY_NETWORK=mainnet` on the gateway. The wallet
   refuses to start the BOLT 12 runtime if these disagree.
2. **Generate a shared token:** `openssl rand -hex 32` (or just run
   `./start.sh config`, which auto-generates one). Set it as
   `BOLT12_GATEWAY_TOKEN` on both ends.
3. **Pick an amount cap appropriate for your liquidity.** Default
   is 100 000 sats per inbound invreq.
4. **Decide on offer-less mode.** Default off. Only enable
   `BOLT12_ACCEPT_OFFERLESS_INVREQS=true` if you specifically
   intend to receive direct (no-published-offer) BOLT 12 payments
   such as merchant-issued refunds.
5. **Run `alembic upgrade head`** before flipping `BOLT12_ENABLED`.
   Migration `002_dashboard_sentinel_key` in particular is a
   prerequisite for offer-less mode — the responder writes inbound
   rows under the dashboard sentinel API key.
6. **Wire the metrics scrape.** Point Prometheus at
   `https://your-host/v1/bolt12/metrics`. Alert on
   `bolt12_consecutive_probe_failures > 3` and on a rising rate of
   `bolt12_gateway_send_failure_total`.
7. **Verify the gateway network at startup.** The wallet logs
   `BOLT 12 runtime started (target=…)` on success. A network
   mismatch logs `network mismatch (wallet=…, gateway=…)` and the
   runtime stays down.
8. **Review the audit log.** After the first few receive flows
   confirm the audit chain captured each `bolt12_invoice_minted`
   row with the expected `payment_hash`.
9. **Have an L2 monitoring alert for `bolt12_invoices` rows stuck
   in `OPEN` past their expiry**, in case the reconciler stalls.

> **Outbound payments** land the HTLC synchronously through LND's
> blinded-path router. The reconciler is the safety net: a session
> that loses sync between the synchronous settlement step and the
> row update gets resolved on the next pass.

### Bearer token rotation

The wallet → gateway gRPC channel is authenticated solely by the
shared `BOLT12_GATEWAY_TOKEN` (the docker network bind address is
not the security boundary — see [docker-compose.yml](../docker-compose.yml)).
Rotate the token to limit the half-life of any leak:

- **When:** on every operator credential change, after any
  incident that may have exposed `.env` or container memory, and
  annually as routine hygiene.
- **How:** `./scripts/rotate_bolt12_token.sh` generates a fresh
  token, updates `.env`, and bounces `bolt12-gateway`, `api`, and
  `celery-worker` together so the wallet and gateway pick up the
  new value in lock-step. Pass `--yes` for non-interactive use.
- **Outage envelope:** the script does a single `docker compose
  up -d` for the three services. Expect a brief BOLT 12 outage
  (<5 s on a warm host). In-flight `invoice_request` flows that
  hit the seam land as transient errors and are retried by the
  orchestrator's normal reconcile loop. No fund-loss path.

### Optional: mTLS on the wallet → gateway channel

The default deployment runs the gRPC surface in cleartext on a
dedicated, `internal: true` docker network (`bolt12-internal`)
with bearer-token auth. That is appropriate for single-host
deployments where the docker bridge is trusted.

For split-host deploys, hostile-tenant hosts, or operators who
want belt-and-braces, you can enable **mTLS** with cryptographic
peer identity on top of the bearer token.

**When to turn this on:**

- The wallet and gateway run on different hosts (the gRPC traffic
  crosses a network you don't fully control).
- The docker host is shared with workloads outside your trust
  boundary.
- Compliance or policy requires TLS for service-to-service
  traffic.

**Threat model with mTLS on:** an attacker on the docker bridge
(or wire) cannot dial the gateway without a client cert signed by
the configured CA, *and* must also know the bearer token. Cert
revocation is independent from token rotation — rotating the
client cert kicks the wallet without invalidating the token, and
vice versa.

#### Setup

1. **Generate cert material.** From the repo root:

   ```bash
   ./scripts/gen_bolt12_certs.sh ./bolt12-gateway/certs
   ```

   This writes a 10-year self-signed CA and 3-year leaf certs
   (server + client) into the named directory. The CA is the
   trust anchor for both sides; the server cert has
   `SAN=DNS:bolt12-gateway` so the in-compose service name
   resolves; the client cert authenticates the wallet to the
   gateway.

2. **Set the env vars in `.env`.** Add all six paths together —
   half-configured TLS is rejected loudly on both sides:

   ```ini
   BOLT12_CERTS_DIR=./bolt12-gateway/certs

   # Gateway side
   BOLT12_GATEWAY_TLS_CA_CERT=/etc/bolt12-gateway/certs/ca.pem
   BOLT12_GATEWAY_TLS_SERVER_CERT=/etc/bolt12-gateway/certs/server.pem
   BOLT12_GATEWAY_TLS_SERVER_KEY=/etc/bolt12-gateway/certs/server.key

   # Wallet side (api + celery-worker, both read from .env)
   BOLT12_GATEWAY_TLS_CLIENT_CERT=/etc/bolt12-gateway/certs/client.pem
   BOLT12_GATEWAY_TLS_CLIENT_KEY=/etc/bolt12-gateway/certs/client.key
   ```

   The CA env var is shared (same file, same path) between the
   gateway (where it's the trust root for client certs) and the
   wallet (where it's the trust root for the server cert).

3. **Bounce all three services together** (lock-step, like a
   token rotation):

   ```bash
   docker compose up -d bolt12-gateway api celery-worker
   ```

   Watch the logs — the gateway should print
   `BOLT 12 gateway: mTLS ENABLED` on startup, and the wallet's
   first `connect` log line should show
   `opened bolt12-gateway TLS channel`.

#### Env var reference

| Var | Scope | Required when | Notes |
|---|---|---|---|
| `BOLT12_CERTS_DIR` | host | mTLS on | Host directory bind-mounted into all three services at `/etc/bolt12-gateway/certs`. |
| `BOLT12_GATEWAY_TLS_CA_CERT` | both | mTLS on | Trust anchor PEM. Same file on both ends. |
| `BOLT12_GATEWAY_TLS_SERVER_CERT` | gateway | mTLS on | Server leaf cert PEM. SAN must match the wallet's dial target. |
| `BOLT12_GATEWAY_TLS_SERVER_KEY` | gateway | mTLS on | Server private key PEM. 0600 on disk. |
| `BOLT12_GATEWAY_TLS_CLIENT_CERT` | wallet | mTLS on | Wallet leaf cert PEM, signed by the CA. |
| `BOLT12_GATEWAY_TLS_CLIENT_KEY` | wallet | mTLS on | Wallet private key PEM. 0600 on disk. |
| `BOLT12_GATEWAY_TLS_SERVER_NAME` | wallet | optional | Override the TLS SNI / expected SAN. Default = derive from dial hostname. Set to `bolt12-gateway` when dialing the service name. |

#### Cert rotation

- **Leaf certs** (server + client) expire in 3 years. Rotate by
  re-running the gen script with `--force`:

  ```bash
  ./scripts/gen_bolt12_certs.sh ./bolt12-gateway/certs --force
  docker compose up -d bolt12-gateway api celery-worker
  ```

  The CA stays the same; both ends still trust each other after
  the bounce. Brief outage envelope (<5 s on a warm host).

- **CA rotation** is a bigger ceremony — it invalidates *every*
  leaf cert. Schedule for the ~10-year mark or after a key-
  compromise event. Procedure:
  1. Run the gen script in a fresh directory to mint a new CA +
     fresh leaves.
  2. Update `BOLT12_CERTS_DIR` to point at the new directory.
  3. Bounce all three services together.

#### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Wallet logs `BOLT 12 gateway TLS misconfigured: ... is partial` | Only some of the wallet-side TLS env vars are set | Set all of `BOLT12_GATEWAY_TLS_CA_CERT`, `_CLIENT_CERT`, `_CLIENT_KEY`, or unset all three. |
| Gateway refuses to start with `TLS configuration is partial` | Same, gateway side | Set all of `BOLT12_GATEWAY_TLS_CA_CERT`, `_SERVER_CERT`, `_SERVER_KEY`, or unset all three. |
| Handshake fails with `Hostname mismatch` or SAN error | Dial target hostname not in server cert's SAN | Set `BOLT12_GATEWAY_TLS_SERVER_NAME=bolt12-gateway` on the wallet side, or regenerate the server cert with the actual hostname/IP in the SAN. |
| `UNAVAILABLE` after rotating certs | One side bounced before the other; clients still presenting an old cert that the new CA doesn't sign | Always bounce all three services in the same `docker compose up -d` invocation. |
| Cert expired (`certificate has expired`) | Leaf certs past their 3-year window | Re-run `gen_bolt12_certs.sh ... --force` and bounce. |

---

## Endpoints reference (quick)

- `GET /v1/bolt12/receive` — return (and on first call, mint) the
  caller's *default receive offer*. Use this to give a recurring
  payer (Ocean, a marketplace, your own services) **one** stable
  offer string. Bundles inbound-liquidity + gateway runtime
  context for the dashboard.
- `POST /v1/bolt12/receive/configure` — mint a new default receive
  offer with a payer-specified description (e.g. Ocean's required
  `"OCEAN Payouts for bc1…address"` format). The previous default
  is demoted but kept in offer history.
- `POST /v1/bolt12/offers/{id}/set-default` — promote an existing
  issued offer to be the new default receive offer.
- `POST /v1/bolt12/offers/issue` — issue a new offer (one-shot
  variant: lets you pin amount, expiry, quantity).
- `POST /v1/bolt12/decode` — decode any offer string (read-only).
- `POST /v1/bolt12/offers` — import a remote offer for tracking.
- `POST /v1/bolt12/pay/offer` — fetch a payable invoice for a remote
  offer or BIP-353 address **and** route the HTLC via the blinded
  paths. Returns the terminal status (`paid` / `failed`) under
  `settlement.status` in the response body.
- `GET /v1/bolt12/invoices` — paginated list of inbound BOLT 12
  invoices, including their reconciled status.
- `GET /v1/bolt12/status` — runtime health snapshot (JSON).
- `GET /v1/bolt12/metrics` — Prometheus text-format metrics.

All endpoints require an API key with the appropriate scope.

---

## Recipe: receiving Ocean mining-pool payouts

Ocean.xyz pays miners over Lightning. Ocean accepts a raw BOLT 12
offer string (`lno1…`) plus a signed message proving you control
the Bitcoin address you registered as your Ocean username. Ocean
mandates a specific format for the offer:

* **Amount:** "any" (no amount pinned on the offer).
* **Description:** must read exactly
  `OCEAN Payouts for <your-bitcoin-address>`.

This wallet's dashboard generates an offer that meets both
requirements with one form.

1. **Confirm BOLT 12 is online.** On the dashboard's Offers tab,
   the *"Your receive offer"* panel at the top should show a green
   "Online" gateway status. If it shows "Offline" or "Disabled",
   review the [Configuration](#configuration) section and your
   `bolt12-gateway` logs before continuing.
2. **Confirm you have inbound liquidity.** The same panel shows
   the wallet's current inbound capacity. Ocean payouts are
   typically 5 000–500 000 sats; if the panel warns about low
   inbound liquidity, open a channel with sufficient remote
   balance (or rebalance an existing one) before sharing the
   offer.
3. **Set the description for Ocean.** Click the **Configure**
   button on the receive panel. Choose the *"Ocean mining
   payouts"* preset, paste the same Bitcoin address you
   registered with Ocean (it's your Ocean username), and click
   *Mint new offer*. The description preview will read exactly
   `OCEAN Payouts for bc1…your_address`, matching Ocean's
   requirement.
4. **Copy the offer string.** Click the **Copy** button on the
   panel. The same offer can be paid an unlimited number of
   times — register it with Ocean once and leave it. The
   description shown on the panel doubles as a label, so you
   can recognise this as the Ocean offer when you come back
   later.
5. **Sign the ownership message.** Open the dashboard's
   **Sign / Verify Message** dialog (gear-style menu →
   *Sign message*). Choose the same Bitcoin address you used
   above, paste Ocean's challenge text into the message field,
   and copy the resulting signature.
6. **Paste both into Ocean's payout configuration.** Use the
   offer string as your Lightning destination and the signature
   as ownership proof.
7. **Verify the round-trip.** Trigger a small test payout from
   Ocean (or wait for the first natural payout). On the
   dashboard's **Activity** tab you will see a
   `bolt12_invoice_minted` row when Ocean's invoice request
   arrives, followed by an LND invoice settling on the
   **Invoices** tab.

> **Operator note.** While the wallet or the
> `bolt12-gateway` daemon is offline, Ocean's invoice requests
> have nowhere to land and the payout will fail/retry per Ocean's
> policy. Treat the gateway like any other always-on receive
> infrastructure.

> **Why "Configure" mints a new offer.** BOLT 12 offers are
> immutable — the description is part of the signed bech32 string
> — so the only way to change the description is to mint a fresh
> offer. The previous default is kept in the *My offers* table
> below the panel and can be re-promoted via the star icon if
> needed.

---

## Testing

- Unit + integration tests: `pytest -q -k bolt12`
- Spec-vector codec tests: `tests/vectors/bolt12/*.json` (drawn
  from the BOLT 12 spec repo) are exercised by
  `tests/unit/test_bolt12_codec.py`.
- A regtest end-to-end smoke harness scaffold lives at
  `scripts/regtest_offerless_invreq_smoke.py`. It is **not** wired
  into CI because synthesizing a payer-side offer-less invreq with
  a real onion-message reply path requires an out-of-process LDK
  peer; the script documents the manual operator setup.

---

## Where things live

| Concern | Path |
| --- | --- |
| HTTP API + dashboard wiring | `app/api/bolt12.py` |
| Receive-side responder | `app/services/bolt12/responder.py` |
| Outbound flow + orchestrator | `app/services/bolt12/orchestrator.py` |
| Pure-Python codec (TLV / bech32) | `app/services/bolt12/` |
| LND blinded-invoice helper | `app/services/lnd_service.py` (`add_blinded_invoice`) |
| Gateway gRPC client | `app/services/bolt12_gateway/client.py` |
| Rust gateway daemon | `bolt12-gateway/` |
| DB models | `app/models/bolt12_*.py` |
| Migrations | `alembic/versions/00{8,9,10,11}_bolt12_*.py` |
| Settlement reconciler | `app/services/bolt12/reconcile.py` |
| Runtime singleton + lifespan | `app/services/bolt12/runtime.py` |
