# Chain backend (electrs / Electrum)

The wallet's on-chain queries — fee estimation, transaction lookups,
address balances and UTXOs, mempool stats, block tips — are served by
a *chain backend*. Two implementations are supported:

| Backend | Module | Used when |
|---|---|---|
| Mempool Explorer (HTTP) | `app/services/chain/mempool_http.py` | Default. Public mempool.space or self-hosted Mempool instance |
| Electrum protocol (TCP / SSL / Tor) | `app/services/chain/electrum.py` | Opt-in. Self-hosted [electrs](https://github.com/romanz/electrs) — typical Start9, Umbrel, RaspiBlitz setups |

Selection is controlled by the `CHAIN_BACKEND` setting:

| Mode | Behavior |
|---|---|
| `auto` *(default)* | Use Electrum when `LND_ELECTRUM_URL` is set, with Mempool HTTP as a fallback if Electrum is unavailable. Identical to legacy behavior when no Electrum URL is configured |
| `electrum` | Strict Electrum-only. Requires `LND_ELECTRUM_URL`. Errors are surfaced — no HTTP fallback. Use this on privacy-sensitive deployments where leaking address queries to a public API is unacceptable |
| `mempool` | Force Mempool HTTP. Ignores `LND_ELECTRUM_URL` even if set (with a warning at startup) |

## Configuration

| Variable | Description | Default |
|---|---|---|
| `CHAIN_BACKEND` | `auto` \| `mempool` \| `electrum` | `auto` |
| `LND_ELECTRUM_URL` | Electrum server URL (`tcp://host:50001` or `ssl://host:50002`) | `""` |
| `LND_ELECTRUM_TLS_VERIFY` | Verify TLS cert for `ssl://` connections | `true` |
| `LND_ELECTRUM_CA_CERT` | CA cert for `ssl://` — file path or base64-encoded PEM | `""` |
| `LND_ELECTRUM_PING_INTERVAL_S` | `server.ping` keepalive interval | `30.0` |
| `LND_ELECTRUM_REQUEST_TIMEOUT_S` | Per-request timeout | `8.0` |
| `LND_ELECTRUM_CONNECT_TIMEOUT_S` | Connect timeout (incl. SOCKS5 negotiation) | `10.0` |
| `LND_ELECTRUM_MAX_SUBSCRIPTIONS` | Cap on active scripthash subscriptions | `256` |
| `LND_TOR_PROXY` | SOCKS5 proxy used for `.onion` Electrum URLs | `""` |

### URL formats

* `tcp://host:50001` — plaintext TCP. Default Electrum protocol port
  is `50001` for clearnet, but you must specify it explicitly.
* `ssl://host:50002` — TLS-wrapped. Electrum SSL port is `50002`.
* `tcp://abc...xyz.onion:50001` — Tor v3 hidden service. Requires
  `LND_TOR_PROXY` (e.g. `socks5://tor-proxy:9050`).

The validator in `Settings._validate_chain_backend` rejects unsupported
schemes (e.g. `http://`, `https://`) and refuses `.onion` URLs when
no Tor proxy is configured.

## Connection examples

### Start9 (self-signed TLS)

Start9 ships electrs behind a self-signed certificate per service. The
TLS hostname embedded in the cert is the Tor `.onion` address rather
than your local hostname, so verification typically fails when
connecting on the LAN.

```env
CHAIN_BACKEND=electrum
LND_ELECTRUM_URL=ssl://startos.local:50002
LND_ELECTRUM_TLS_VERIFY=false
```

If you have downloaded the Start9 root CA bundle, prefer:

```env
CHAIN_BACKEND=electrum
LND_ELECTRUM_URL=ssl://startos.local:50002
LND_ELECTRUM_TLS_VERIFY=true
LND_ELECTRUM_CA_CERT=/etc/agent-wallet/start9-ca.pem
```

`LND_ELECTRUM_CA_CERT` may be either a filesystem path or the
base64-encoded PEM contents (handy for Docker secrets / env-only
deploys).

### Tor / .onion

```env
CHAIN_BACKEND=electrum
LND_ELECTRUM_URL=tcp://abcdefghijklmnop...xyz.onion:50001
LND_TOR_PROXY=socks5://tor-proxy:9050
```

The client opens the TCP connection through SOCKS5 and speaks the
plaintext Electrum protocol over the Tor circuit. SSL is unnecessary
since Tor already provides authentication and end-to-end encryption.

### Local clearnet electrs

```env
CHAIN_BACKEND=electrum
LND_ELECTRUM_URL=tcp://127.0.0.1:50001
```

## Behavior

* **Connection management** — the client maintains a single supervised
  TCP/SSL connection with automatic reconnect-with-backoff. On
  reconnect, all active scripthash subscriptions are replayed.
* **Handshake** — every new connection performs `server.version` (the
  server is sent `["agent-wallet/<version>", "1.4"]`) and
  `blockchain.headers.subscribe` to seed the cached tip height.
* **Keepalives** — `server.ping` is sent every
  `LND_ELECTRUM_PING_INTERVAL_S` seconds; failure to receive a reply
  triggers a reconnect.
* **Strict vs. fallback** — in `electrum` mode the facade returns the
  Electrum error string verbatim; in `auto` mode it silently retries
  via Mempool HTTP and only surfaces an error if both backends fail.
* **No address leakage in `electrum` mode** — verified by integration
  tests that assert zero `httpx.AsyncClient` requests when the
  Electrum backend is healthy.
* **Health surface** — `/v1/status/services` reports an `electrum`
  entry (with `enabled`, `connected`, `tip_height`,
  `subscriptions_active`) when the backend is configured.

## Privacy notes

* The Mempool HTTP backend leaks every queried txid/address to the
  configured `LND_MEMPOOL_URL` host. For a public instance
  (mempool.space) this is a third-party correlation risk.
* The Electrum backend leaks the same data to the configured electrs
  server — but you typically run that server yourself, on the same
  trust domain as the wallet itself. Combined with `LND_TOR_PROXY` and
  a `.onion` URL, the connection is also hidden from network-level
  observers.
* `CHAIN_BACKEND=electrum` (strict) is recommended for any deployment
  where leaking address-to-IP correlation to a third party is
  unacceptable.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `CHAIN_BACKEND='electrum' requires LND_ELECTRUM_URL` at startup | Strict mode without a URL — set `LND_ELECTRUM_URL` or switch to `auto`/`mempool` |
| `LND_ELECTRUM_URL must use tcp:// or ssl://` | An `http://`/`https://` URL was supplied — Electrum is not HTTP |
| `LND_ELECTRUM_URL is a .onion hostname but LND_TOR_PROXY is not configured` | Set `LND_TOR_PROXY=socks5://...` |
| `failed to connect within Ns` (logged) | Server unreachable; check firewall, SSL/TCP port mismatch, or Tor proxy |
| TLS verification errors against Start9 | Set `LND_ELECTRUM_TLS_VERIFY=false`, or supply `LND_ELECTRUM_CA_CERT` |
| Wallet works but `/v1/status/services` shows `electrum.connected=false` | Reconnect loop is running; inspect logs for the underlying error |
