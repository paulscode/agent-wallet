# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Agent Wallet, **please do not open a public issue**.

This project handles Bitcoin and Lightning Network operations. Security vulnerabilities could lead to loss of funds.

### How to Report

1. **GitHub Security Advisories (preferred):** Use [GitHub Security Advisories](https://github.com/paulscode/agent-wallet/security/advisories/new) to privately report the vulnerability.
2. **Forum (fallback):** Send a private message to the maintainer via the forum at `paulscode.com`.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix timeline:** Critical vulnerabilities within 14 days; others within 30 days
- **Credit:** We will credit reporters in the release notes (unless you prefer anonymity)

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |
| < latest | No       |

## Security Best Practices for Operators

- **Never** commit `.env` files or expose `SECRET_KEY`
- Use a unique, high-entropy `SECRET_KEY` (64+ hex chars)
- Use a high-entropy `DASHBOARD_TOKEN` (the auto-generated
  `secrets.token_urlsafe(32)` value, or longer). It is a shared secret
  compared in constant time, so its entropy is its primary defense. The
  per-IP login lockout slows a single-source attacker but **alerts rather
  than blocks** on the cross-IP threshold (so a spoofed source cannot lock
  the operator out) — meaning a distributed, IP-rotating attacker is not
  hard-blocked. Do **not** use a short or human-memorable passphrase. The
  application refuses to boot on a token below the length or
  distinct-character floor
- Restrict API key permissions: use non-admin keys for read-only agents
- Set `LND_MAX_PAYMENT_SATS` to the minimum value your use case requires
- Enable Tor (`BOLTZ_USE_TOR=true`) for Boltz API traffic
- Run behind a reverse proxy (nginx, Caddy) with TLS in production, and enable
  `ENABLE_HSTS=true` once HTTPS is in place
- When the dashboard is exposed behind a reverse proxy, set `TRUSTED_PROXIES`
  to the proxy CIDR so dashboard session IP-binding stays effective. Without
  it, every request appears to come from the proxy and IP-binding silently
  becomes a no-op (the application logs a warning at startup when this
  misconfiguration is detected)
- Leave `RATE_LIMIT_FAIL_POLICY=closed` (the default) so payments cannot bypass
  spend caps during a Redis outage; only set it to `open` if you accept that
  trade-off explicitly
- Leave `MEMPOOL_ALLOW_INTERNAL=false` unless you genuinely run a self-hosted
  Mempool instance on a private address — the SSRF guard refuses startup
  otherwise
- When pointing `LND_MEMPOOL_URL` at a self-hosted instance with a self-signed
  certificate, **pin the cert via `MEMPOOL_CA_CERT`** (filesystem path,
  base64-encoded PEM, or raw PEM text) instead of setting
  `MEMPOOL_TLS_VERIFY=false`. Disabling verification with no pin leaves
  fee / chain-tip / transaction-status responses tamperable by on-path
  attackers; the application emits a startup warning when this combination
  is detected. The same pattern is available for LND (`LND_TLS_CERT`) and
  Electrum (`LND_ELECTRUM_CA_CERT`).
- Monitor the audit log (`GET /v1/admin/audit-log`) and periodically run
  `GET /v1/admin/audit-log/verify` to confirm the keyed hash chain is intact.
  The chain is an HMAC keyed from `SECRET_KEY`, so it detects **modification**
  of any row by anyone who can write the database but does **not** hold
  `SECRET_KEY` (an attacker holding `SECRET_KEY` can still forge it — the chain
  is not an external anchor). The verify endpoint also tries
  `SECRET_KEY_PREVIOUS`, so a chain stays verifiable across a key rotation
  without a re-anchor. After a database restore or a full `SECRET_KEY` rotation
  (current **and** previous keys retired) the chain will no longer verify and
  retention pruning pauses until you re-anchor it
  (`POST /v1/admin/audit-log/reanchor`, or the dashboard **Re-anchor**
  button); the re-anchor is recorded in the log
- **Front-truncation caveat & external anchoring.** The keyed chain detects
  modification but, on its own, *cannot* detect a DB-write attacker **deleting
  the oldest rows** — from inside the database that is indistinguishable from
  legitimate retention pruning (the surviving head still verifies). To close
  this, set `ALERT_WEBHOOK_URL` **and** `ALERT_WEBHOOK_SHARED_SECRET`: on every
  retention cycle (and as a heartbeat even when retention is disabled) the
  server emits a **signed** `audit_anchor` event carrying the current row
  `count`, `head_hash`, `oldest_created_at`, `newest_created_at`, and — critically
  — `deleted`, the number of rows that cycle's prune removed, computed
  in-process. Because the payload is HMAC-signed with
  `ALERT_WEBHOOK_SHARED_SECRET`, an attacker who can write the database but does
  not hold that secret cannot forge or inflate any of these fields. An off-box
  receiver that **retains** the signed anchor stream must verify the
  `X-Agent-Wallet-Signature` on every delivery (reject unsigned/forged ones, or
  the guarantee does not hold) and then apply two checks:

  1. **`oldest_created_at` boundary (the precise front-truncation signal).**
     The oldest retained row can only advance to the retention cutoff. With
     retention `N` days, `oldest_created_at` must stay `≈ now − N` and never
     jump *past* it. With retention **disabled** (keep-forever) nothing is ever
     legitimately deleted, so `oldest_created_at` must **never move forward at
     all** — any advance, even by a single row, proves the oldest rows were
     deleted out of band. This catches front-truncation precisely, including
     slow single-row drip.
  2. **`count + Σdeleted` monotonicity (bulk-deletion backstop).** Track the
     running total of the signed `deleted` values; `count + Σdeleted`
     ("rows that ever existed") must be non-decreasing across the anchor
     stream, since every legitimate add increments it and every legitimate
     prune leaves it unchanged. A decrease means rows vanished without being
     reported as pruned.

  Note the residual: check 2 alone cannot see a deletion *smaller* than the
  organic row growth in the same interval (the receiver has no independent
  count of legitimate additions) — which is exactly why check 1, anchored on
  the immovable `oldest_created_at`, is the load-bearing signal for the
  oldest-rows threat. `GET /v1/admin/audit-log/verify` also returns the current
  `anchor` snapshot for manual spot-checks. Without an external receiver that
  retains and signature-checks these anchors, front-truncation remains
  undetectable — the database alone cannot anchor its own history.
- Rotate API keys periodically and disable unused keys; soft-deleted keys
  cannot be hard-purged until `AUDIT_LOG_RETENTION_DAYS` has elapsed so the
  audit trail is preserved
- Configure webhook destinations (`ALERT_WEBHOOK_URL`) over HTTPS only;
  the alert service blocks private/loopback targets, pins the resolved
  IP for the actual delivery (so a DNS-rebind attacker cannot redirect
  the POST to an internal service after validation), and keeps the
  original hostname for SNI / certificate validation.
- When operating webhook receivers, set `ALERT_WEBHOOK_SHARED_SECRET`
  and verify the `X-Agent-Wallet-Signature` header on every delivery
  to defeat URL-leak spoofing. The header is
  `sha256=<hex>` where `<hex>` is
  `HMAC-SHA256(secret, json.dumps(payload, sort_keys=True, separators=(",", ":")))`.
  Reject deliveries whose payload `timestamp` is more than ±5 minutes
  from your own clock.
- The **BOLT 12 gateway** gRPC listener (`BOLT12_GATEWAY_GRPC_LISTEN`)
  defaults to loopback (`127.0.0.1:50061`), and its bearer-token / mTLS auth is
  **opt-in** (off by default). Inside Docker Compose the listener is bound to
  the isolated `bolt12-internal` network and is never published on the host. Do
  **not** bind `BOLT12_GATEWAY_GRPC_LISTEN` to a non-loopback address (e.g.
  `0.0.0.0`) without also enabling authentication via `BOLT12_GATEWAY_TOKEN`
  and/or mTLS (`BOLT12_GATEWAY_TLS_*`); the bind address alone is not the
  security boundary. See [docs/bolt12.md](docs/bolt12.md) for the full gateway
  runbook and cert generation.
- `DASHBOARD_TOKEN` should be set explicitly in production and never
  left to auto-generation; the auto-generator persists to `.env` with
  mode `0600` but the file is still on disk and may be exposed by
  bind mounts, backups, or image layers. Operator-supplied tokens
  must be at least 24 characters; the application refuses to start
  with a shorter token.

## Rotating `SECRET_KEY`

`SECRET_KEY` is used as the HMAC key for the API-key digest stored in
`api_keys.key_hash`. Rotating it without downtime:

1. Generate a fresh value and put the **current** value into
   `SECRET_KEY_PREVIOUS`, then set `SECRET_KEY` to the new value and
   restart the service.
2. Live API calls keep working: on a digest mismatch the auth path
   re-hashes the bearer token under `SECRET_KEY_PREVIOUS` and, on a
   match, rewrites the row's digest under the new `SECRET_KEY`. The
   prior digest is parked in `key_hash_prev` for one rotation cycle.
3. Once every active key has been used at least once under the new
   secret (check `last_used_at` on `api_keys`), unset
   `SECRET_KEY_PREVIOUS` and restart. Any row that never got rewritten
   will stop authenticating — issue a replacement key for those.
4. Encrypted-field rotation (Fernet payloads in the database) still
   relies on the existing re-encryption migration; treat it as a
   separate runbook.

## Encrypting Database and Redis Connections

When running PostgreSQL or Redis on a remote host (outside Docker Compose or
on a separate machine), **enable TLS** to protect credentials and data in
transit.

### PostgreSQL (SSL)

Use `ssl=require` (or `ssl=verify-full` with a CA cert) in your connection
string:

```
DATABASE_URL=postgresql+asyncpg://user:pass@db-host:5432/agent_btc_wallet?ssl=require
```

asyncpg respects these query-string parameters natively.

### Redis (TLS)

Use the `rediss://` scheme (note the double `s`) for TLS-enabled Redis:

```
REDIS_URL=rediss://:password@redis-host:6380/0
```

redis-py and Celery handle `rediss://` URIs natively — no code changes are
needed.

> **Note:** Within Docker Compose, PostgreSQL and Redis traffic stays on an
> isolated bridge network and TLS is not required. These settings are only
> necessary for remote or shared-network deployments.

## Known Trade-offs

### Sign endpoint authorization vs. rate-limit ordering

The sign endpoints (`POST /v1/wallet/sign/address`, `POST /v1/wallet/sign/node`)
require an admin API key and enforce a per-key sliding-hour rate limit. The
admin check runs **before** the rate-limit check. A non-admin caller is
rejected with `403` without consuming the per-key sign quota. This means a
sufficiently fast attacker could distinguish admin from non-admin keys via
response timing if Redis is materially slower than the database. The leak is
considered acceptable: an attacker with valid credentials is already past
the boundary that matters.

### Boltz Tor → clearnet fallback

`BOLTZ_FALLBACK_CLEARNET=true` allows the application to retry Boltz API
requests over clearnet when Tor is unreachable. This is gated behind an
opt-in flag and emits a `tor_fallback` security alert on every fallback so
operators can detect prolonged Tor outages or attempts to force clearnet
exposure of swap traffic.
