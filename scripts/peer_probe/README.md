# peer_probe — find a working small-channel partner

A two-step tool for empirically discovering an LN node that:

1. is well-connected to the network's main routing hubs (so Ocean's CLN
   has a routable path to it), and
2. **actually accepts** a small (~150k sat) inbound channel open from us.

The "actually accepts" half is the part no LN explorer can answer — see
[the deep-research note](../../internal_docs/peer_probe_design.md) (TODO)
on why `min_chan_size` isn't gossiped. So we probe empirically: try, log
the outcome, move on.

## Files

| File | Purpose |
|---|---|
| `recon.py` | Pulls LND gossip graph, scores every node by `top_hub_connections × 100 + chan_count + capacity_btc`, writes `/data/probe/candidates.json` (top 150 by default). |
| `probe.py` | Walks `candidates.json`, attempts connect + sync channel open. Stops on first success. Persists `probe_state.json` so re-runs skip already-attempted candidates. |

Both scripts are pure-stdlib Python — no extra packages needed. They
auto-discover LND credentials by reading `/proc/<api-pid>/environ` of the
running `uvicorn app.main` process inside the container.

## Deployment (StartOS)

Copy both files into the package's persistent volume so they survive
container restarts:

```bash
# from your dev box
scp scripts/peer_probe/recon.py scripts/peer_probe/probe.py \
    start9@worthy-maverick.local:/tmp/

# place inside the agent-wallet container
ssh start9@worthy-maverick.local '
  sudo podman cp /tmp/recon.py agent-wallet.embassy:/data/probe/recon.py &&
  sudo podman cp /tmp/probe.py agent-wallet.embassy:/data/probe/probe.py
'
```

`/data/probe/` is part of the package's `main` volume (mounted from
`/embassy-data/package-data/volumes/agent-wallet/data/`), so the scripts
and their state survive across `start-cli package restart`.

## Usage

### Step 1 — generate the candidate list (run once)

```bash
ssh start9@worthy-maverick.local \
  'sudo podman exec --privileged agent-wallet.embassy python /data/probe/recon.py'
```

Takes ~1–2 minutes — most of that is the LND graph fetch. Output goes to
stderr (progress lines + top-10 preview) and writes
`/data/probe/candidates.json`.

Tweakables:
- `--top-n 200` — keep more candidates (default 150).
- `--min-chan-count 50` — raise the floor for "well-connected" (default 30).
- `--hub-count 30` — use top-30 instead of top-20 nodes as routing hubs.
- `--include-tor-only` — keep `.onion`-only nodes (default skips them).

### Step 2 — preview without opening anything

```bash
ssh start9@worthy-maverick.local \
  'sudo podman exec --privileged agent-wallet.embassy python /data/probe/probe.py --dry-run'
```

Shows the first 20 pending candidates in rank order with their addresses.

### Step 3 — probe one or N at a time

Single open attempt (stops on first success either way):
```bash
ssh start9@worthy-maverick.local \
  'sudo podman exec --privileged agent-wallet.embassy python /data/probe/probe.py --limit 1'
```

Try up to 5 in one session before stopping (slower-and-watch mode):
```bash
ssh start9@worthy-maverick.local \
  'sudo podman exec --privileged agent-wallet.embassy python /data/probe/probe.py --limit 5'
```

Try ALL pending until either a success or the list is exhausted:
```bash
ssh start9@worthy-maverick.local \
  'sudo podman exec --privileged agent-wallet.embassy python /data/probe/probe.py'
```

### Step 4 — when an open succeeds

The script prints `*** opened a channel ***`, stores funding_txid in
`probe_state.json` under `last_success`, and exits 0. You then:

1. Note the alias / pubkey / funding_txid.
2. Close the channel via the dashboard or `lncli closechannel <txid>:<vout>`.
3. Re-run `probe.py` to continue; the successful peer is recorded in
   state so the script moves on to the next candidate automatically.

### Inspecting state

```bash
ssh start9@worthy-maverick.local \
  'sudo podman exec --privileged agent-wallet.embassy cat /data/probe/probe_state.json' \
  | python3 -m json.tool | less
```

State file shape:
```jsonc
{
  "attempts": {
    "<pubkey>": {
      "alias": "...",
      "address": "...",
      "outcome": "open_succeeded" | "open_failed" | "connect_failed",
      "funding_txid": "...",      // only on success
      "http_code": 500,           // only on open_failed
      "detail": "<error snippet>" // only on failure paths
    },
    ...
  },
  "last_success": { ... }
}
```

### Reset (rare)

```bash
sudo podman exec --privileged agent-wallet.embassy python /data/probe/probe.py --reset --dry-run
```

Wipes `probe_state.json`. Use sparingly — most operators want
`--limit 1` to walk slowly through the ranked list, not start over.

## What the scripts deliberately do NOT do

- **They don't filter by `min_chan_size`** — that field isn't gossiped.
  The probe IS the test.
- **They don't auto-close failed channels.** A failure means the open was
  rejected before any UTXO was committed. The script just disconnects.
- **They don't push sats at open time.** Channel opens with `push_sat=0`.
  That's intentional — you get to keep the 150k sat after closing the
  test channel.
- **They don't try the same peer twice** unless `--reset` is used. A
  rejection is sticky for the duration of this candidates.json.

## Tuning notes

- `score = hub_conn × 100 + chan_count + capacity_btc` — heavily weighted
  on direct connections to the network's top-20 routing hubs. The
  intuition: Ocean's CLN almost certainly has those hubs in gossip, so a
  candidate one hop away from them is easy to route to.
- The default 150k channel size matches the StartOS Bitaxe-miner persona.
  Bump `--chan-sat` if you want to test mid-size openings (e.g., 500k).
- Default on-chain feerate is 1 sat/vB (cheap; the open tx will sit in
  the mempool a while). Raise with `--sat-per-vbyte` if you want it
  confirmed faster.
