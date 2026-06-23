# Cold-storage sweeps via Boltz

The wallet can move Lightning funds back to on-chain Bitcoin without
custody intermediaries by using **Boltz Exchange reverse submarine
swaps**. The flow:

1. The wallet generates a fresh preimage and claim keypair.
2. Boltz returns a hold invoice plus a Taproot lockup script.
3. The wallet pays the invoice over Lightning.
4. Boltz publishes a lockup transaction to the address.
5. The wallet co-signs a cooperative Musig2 claim (or, if Boltz is
   uncooperative, falls back to the script-path spend) sweeping the
   funds to your destination address.

Boltz never custodies funds — they're either locked in HTLCs you
control the preimage for, or in a Taproot output you can claim
unilaterally after the timeout.

> **Status:** production-ready on mainnet, testnet and regtest.
> Lightning → on-chain (`reverse`) is implemented; on-chain →
> Lightning (`submarine`) is not.

---

## Where to use it

### Dashboard

**Wallet → Cold storage**. Enter an amount and a destination
address; the dashboard shows the fee breakdown (Boltz percentage
fee + miner fees for both lockup and claim) and the min/max range
returned live by the Boltz pair-info endpoint. Submitting initiates
the swap; the activity log and the **Swaps** table track progress
through the lifecycle states below.

The dashboard uses a single **sentinel API key** for every
operator-initiated swap (see [api-keys.md](api-keys.md)). All swaps
are visible to any authenticated dashboard user — there is no
per-user filtering on the dashboard surface.

### REST API

Under `/api/v1/cold-storage` (see [`app/api/cold_storage.py`](../app/api/cold_storage.py)):

| Method | Path                              | Scope     | Purpose |
| ------ | --------------------------------- | --------- | ------- |
| `GET`  | `/cold-storage/fees`              | read      | Live Boltz pair info: percentage fee, lockup + claim miner fees, min/max amounts, Tor status |
| `POST` | `/cold-storage/initiate`          | **admin** | Start a swap. Body: `amount_sats`, `destination_address`, `routing_fee_limit_percent` |
| `GET`  | `/cold-storage/swaps`             | read      | List recent swaps owned by the calling key |
| `GET`  | `/cold-storage/swaps/{id}`        | read      | Single swap, augmented with `claim_confirmations`, `current_block_height`, `blocks_until_timeout` when the chain backend is reachable |
| `POST` | `/cold-storage/swaps/{id}/cancel` | **admin** | Cancel a swap that has not yet paid the Boltz invoice |

REST swaps are owned by the calling API key — `GET /swaps` and
`/swaps/{id}` only return swaps initiated by that key.

---

## Lifecycle

`SwapStatus` (see [`app/models/boltz_swap.py`](../app/models/boltz_swap.py))
transitions through these states. Every transition is appended to
`status_history` on the swap row for forensics:

| State            | Meaning |
| ---------------- | ------- |
| `created`        | Boltz accepted the swap; hold invoice + lockup details persisted. |
| `paying_invoice` | Celery worker has called LND `SendPaymentV2` on the hold invoice. |
| `invoice_paid`   | Lightning HTLC settled into Boltz; Boltz now owes us the lockup TX. |
| `claiming`       | Lockup TX seen on-chain; cooperative Musig2 claim in flight. |
| `claimed`        | Claim TX broadcast. |
| `completed`      | Claim TX has ≥1 confirmation. Funds are in your destination address. |
| `failed`         | Unrecoverable error — see `error_message` and the audit chain. |
| `cancelled`      | Operator cancelled before invoice payment, or Boltz timed out before lockup. |
| `refunded`       | Hold invoice refund settled (Boltz never paid the lockup). |

Funds are never lost in any of these terminal states: a Lightning
HTLC that doesn't settle is automatically refunded by LND, and a
lockup TX that we fail to claim cooperatively is swept via the
script-path spend after `timeout_block_height`.

### Background processing

Swap progression runs in the **Celery worker** (`app.tasks.boltz_tasks`),
not in the request handler — `POST /initiate` returns as soon as
the swap row is persisted. The worker:

* Polls Boltz status on a tiered backoff (15 s for the first 10
  attempts, 60 s for the next 20, 300 s thereafter) and caps at
  200 retries (~16 hours).
* Schedules a `recover_boltz_swaps` task every 5 minutes to pick
  up any swap left mid-flight by a worker crash, plus a
  synchronous recovery pass on app startup.
* Stamps `claim_txid`, `boltz_status`, and `status_history` as it
  goes. The dashboard polls these fields for live progress.

This means **the worker container must be running** for swaps to
make progress. With `docker-compose up`, the `celery` service
covers it; on bare-metal deployments run
`celery -A app.tasks.boltz_tasks.celery_app worker` alongside the
API process.

---

## Configuration

| Variable                  | Description                                                                                                  | Default |
| ------------------------- | ------------------------------------------------------------------------------------------------------------ | ------- |
| `BOLTZ_API_URL`           | Clearnet Boltz v2 base URL.                                                                                  | `https://api.boltz.exchange/v2` |
| `BOLTZ_ONION_URL`         | Tor v3 hidden-service URL for the Boltz API.                                                                 | The official `boltzzzbnus4m7m…onion` v2 endpoint |
| `BOLTZ_USE_TOR`           | Route Boltz API calls through `LND_TOR_PROXY`. Strongly recommended — Boltz traffic reveals swap intent.     | `true` |
| `BOLTZ_FALLBACK_CLEARNET` | If Tor is unreachable, retry against `BOLTZ_API_URL`. Less private but more reliable.                        | `false` |
| `LND_TOR_PROXY`           | SOCKS5 proxy used when `BOLTZ_USE_TOR=true`. Shared with LND and Mempool egress.                             | `""` |
| `LND_MAX_PAYMENT_SATS`    | Per-payment safety limit. Swaps above this size are rejected before Boltz is contacted.                      | enforced |
| `BITCOIN_NETWORK`         | `bitcoin` \| `testnet` \| `signet` \| `regtest`. Determines address validation; on regtest a self-hosted Boltz instance is required. | `bitcoin` |

Hard-coded swap bounds (see `app/services/boltz_service.py`):
**25 000 sats** minimum, **25 000 000 sats** maximum. The
dashboard and REST schema both enforce these client-side; the
Boltz pair-info endpoint may further tighten them based on Boltz's
liquidity at any given moment.

### Tor egress

Boltz operates a Tor hidden service so swap requests don't
correlate your clearnet IP with the on-chain destination address.
`BOLTZ_USE_TOR=true` (the default) routes every Boltz API call
through `LND_TOR_PROXY`. With `BOLTZ_FALLBACK_CLEARNET=false`
(also the default), Tor failures cause the swap to error out
rather than silently leaking; flip it to `true` only if your
operational reliability budget outweighs the privacy hit.

The `tor-proxy` container shipped in `docker-compose.yml` is a
ready-made SOCKS5 endpoint — no extra setup required if you use
the bundled compose file.

---

## Cooperative claim — Node.js dependency

The cooperative Musig2 claim path uses the upstream `boltz-core`
JavaScript reference implementation rather than re-deriving the
Taproot logic in Python. This is invoked as a sandboxed Node.js
subprocess from `app/services/boltz_service.py` via
[`scripts/boltz_claim.js`](../scripts/boltz_claim.js):

```bash
cd scripts
npm install   # one-time, pulls boltz-core@3.1.x
```

The subprocess runs with a **scrubbed environment** — only `PATH`,
`HOME`, and `NODE_PATH` are exposed, never `SECRET_KEY` or
`DATABASE_URL`. If the cooperative claim fails for any reason
(Boltz uncooperative, Node missing, network flake), the swap
falls back to the timeout-locked script-path spend without
operator intervention.

Node.js 20+ is required. See
[`CONTRIBUTING.md`](../CONTRIBUTING.md) for a full development
setup.

---

## Security posture

| Concern | Mitigation |
| ------- | ---------- |
| **Boltz acts maliciously** | Funds are locked in a Taproot output the wallet can claim unilaterally after `timeout_block_height` — Boltz can't run off with them. The cooperative path is an optimization, not a trust assumption. |
| **Lockup TX paid the wrong address** | Before claiming, the wallet verifies via the chain backend that a vout in the lockup TX actually pays the address Boltz committed to during swap creation (`_tx_pays_address`). |
| **Sensitive material on disk** | `preimage_hex` and `claim_private_key_hex` are encrypted at rest with Fernet (key derived from `SECRET_KEY`). Loss of `SECRET_KEY` means in-flight swaps cannot be claimed cooperatively, but the script path still works. |
| **Worker crash mid-swap** | A `recover_boltz_swaps` Celery beat task plus a synchronous startup pass requeue any swap in a non-terminal state. Status history records every transition for after-the-fact reconciliation. |
| **Address poisoning** | All destination addresses are validated against `BITCOIN_NETWORK` before any Boltz call (`app/core/validation.py`). Cross-network addresses (mainnet on testnet, etc.) are rejected. |
| **Spend caps** | Both `LND_MAX_PAYMENT_SATS` and the cumulative/velocity rate limits in `app/core/rate_limit.py` are enforced before reserving the Lightning payment. The reservation is rolled back if Boltz refuses the swap. |
| **Egress correlation** | `BOLTZ_USE_TOR=true` routes all Boltz API traffic via the same Tor SOCKS5 proxy LND uses — Boltz never sees the wallet's clearnet IP. |
| **Upstream error leakage** | Boltz error bodies are passed through `sanitize_upstream_error` before reaching the API or dashboard, stripping potentially sensitive headers/tracebacks. |
| **Circuit breaker** | A breaker around Boltz HTTP (`failure_threshold=8`, `open_duration_s=60`) absorbs flapping Tor circuits and prevents the worker from hammering a degraded endpoint. |

---

## Recovering a swap

If the worker dies between *invoice paid* and *claim broadcast*,
the swap can always be resumed:

1. **Periodic recovery** picks it up automatically within 5
   minutes (`recover_boltz_swaps` Celery beat task).
2. **Startup recovery** runs synchronously on app startup with a
   60 s budget — enough for the common case after `docker-compose
   restart`.
3. **Manual** — `GET /api/v1/cold-storage/swaps/{id}` will show
   the current state including `boltz_status`, `error_message`,
   and `blocks_until_timeout`. If `blocks_until_timeout` goes
   negative the script-path spend is your safety net; it requires
   no Boltz cooperation and uses only the encrypted material on
   the swap row.

The **audit chain** records every swap action — initiate, cancel,
status transition — under `category=cold_storage` /
`resource=swap`, hashed into the tamper-evident chain alongside
all other actions. See [`app/services/audit_service.py`](../app/services/audit_service.py).
