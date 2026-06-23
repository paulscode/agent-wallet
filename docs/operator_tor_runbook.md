# Operator Tor Runbook

This runbook tells you what to do when the wallet's Tor stack misbehaves. Each playbook below is referenced by a section number you can quote when filing an issue.

The wallet has four layers of recovery already built in:

| Tier | Mechanism | Triggers | Mean recovery |
|---|---|---|---|
| 1 | In-flight retries (per-call patches) | Transient connection blip | <30 s |
| 2 | NEWNYM via the watchdog | Tor breaker open ≥ 60 s | 30-90 s |
| 3 | SIGNAL HUP via the watchdog | Tor breaker open ≥ 3 min after NEWNYM | ~90 s |
| 4 | Docker healthcheck → container restart | Healthcheck fails 3 × 60 s | 2-3 min |
| 5 | This runbook | Tier 1-4 didn't recover, or repeats more than once a week | Human-driven |

If you reach tier 5, work the playbooks below in order.

## §1 — "Tor unhealthy" / yellow in the dashboard

What the wallet thinks is happening: the Tor breaker has tripped
but the watchdog hasn't escalated past tier 2 yet.

1. Open the dashboard's settings menu → **Tor Health**.
2. Look at the **Bootstrap** + **Circuit breakers** sections.
   - Bootstrap < 100 % → Tor is mid-bootstrap; wait 60 s and refresh.
   - Tor breaker `half_open` → the watchdog is mid-recovery; wait
     another 30 s. The breaker should close on its own.
3. Scroll to the **SOCKS listeners** table.
   - One listener row red while others are green → that specific
     anonymize call site is wedged. The round-robin probe
     will continue testing it; if it stays red across two cycles
     (~8 min), proceed to §2 below.
4. Watch the **Watchdog → Last NEWNYM** field. If it advances in
   the next minute, recovery is in progress; come back in 5 min
   and confirm the breaker closed.

If everything still says yellow after 5 minutes, treat as red and
move to §2.

## §2 — "Tor unhealthy" / red AND watchdog already fired NEWNYM ≥ 2x

Steps, in order:

1. **Confirm no in-flight payments.** On the LND host:
   ```bash
   lncli listpayments --include_incomplete \
     | jq '.payments[] | select(.status=="IN_FLIGHT")'
   ```
   Expect zero rows. If there's anything live, **wait for it to
   complete or fail naturally before doing anything destructive** —
   the wallet's recovery actions are in-flight-gated for a reason.

2. **Manual SIGHUP.** Settings → Tor Health → "Reload torrc"
   button. This is the same SIGNAL HUP the watchdog would issue
   at tier 3 but operator-initiated. Watch the dashboard for the
   breaker to close in the next 60-90 s.

3. **If SIGHUP didn't help, restart the Tor container.** Choose
   one based on which mode you're running:
   - Single mode (default): `docker restart agent-wallet-tor-proxy-1`
   - Split mode: figure out which pool is wedged from the Tor
     Health modal (it labels them "Tor (LND)" vs "Tor
     (anonymize)") and restart only that one:
     `docker restart agent-wallet-tor-lnd-1` or
     `docker restart agent-wallet-tor-anonymize-1`.
   - Cold restart takes ~60-120 s. The api auto-reconnects.

4. **Check the SOCKS5 round-trip works.** From the host:
   ```bash
   # single mode
   curl -s --socks5-hostname 127.0.0.1:9050 \
        https://mempool.space/api/blocks/tip/height
   # split mode (LND pool)
   docker compose exec tor-lnd \
       curl -s --socks5-hostname 127.0.0.1:9050 \
       https://mempool.space/api/blocks/tip/height
   ```
   A clean reply → Tor is back. No reply or `proxy connection
   failed` → escalate to §3.

## §3 — Recurring wedges (multiple times per week)

If you're hitting §1 or §2 more than once a week, the root cause
is operational, not a one-off. In order of likelihood:

1. **Guard-set saturation.** Tor's entry guards rotate on a
   6-week cadence by default. If the guards picked for
   you keep meeting path restrictions, tightening the rotation
   helps. Edit `.env`:
   ```
   TOR_ROTATION_INTERVAL_DAYS=1
   ```
   This makes the Celery beat task fire SIGHUP every 24 h
   instead of weekly, forcing fresher circuits before a wedge
   accumulates.

2. **LongLivedPorts mismatch.** If you've upstreamed LND from the
   default REST port 8080 to something else, the torrc's
   `LongLivedPorts` list doesn't cover it and Tor's CBT
   learner tears down LN streams aggressively. Add your port via
   the operator override file (see §6 below).

3. **Single-Tor-pool collision.** If LND traffic and anonymize
   traffic both saturate the shared `tor-proxy` and you see
   wedges that affect both surfaces simultaneously, the right
   answer is to split the Tor processes. See §7 below.

4. **Upstream Tor network event.** If multiple Tor users on your
   ISP report similar issues at the same time, ride it out —
   our watchdog isn't going to outrun a real network problem.

## §4 — LND-side HS descriptor stale

The dashboard's **LND HS descriptor** panel went red. This is
NOT a wallet-side bug — LND itself has stopped republishing its
hidden-service descriptor. The wallet can't fix this; only LND
can.

1. **Check LND is up.** From the LND host:
   ```bash
   lncli getinfo | jq .synced_to_chain,.synced_to_graph
   ```
   Both `true` → LND is healthy enough; the descriptor issue is
   LND-Tor-specific. False → fix LND first.

2. **Restart LND-side Tor.** This is whichever Tor instance LND
   itself uses for hidden service publishing — that's separate
   from the wallet's Tor. On Start9 / Embassy this is the system
   Tor; on other setups it's whatever you pointed LND at via
   `tor.socks` + `tor.control` in `lnd.conf`.

3. **Verify the descriptor republishes.** From inside the
   wallet's api container:
   ```bash
   docker compose exec api python -c \
       "from app.services.lnd_hs_descriptor_check import check_lnd_hs_descriptor_freshness; \
        import asyncio; print(asyncio.run(check_lnd_hs_descriptor_freshness()))"
   ```
   Expect `{"status": "fresh", ...}` within ~60 s after the LND-
   side restart.

If the wallet's check still reports stale after 30 min: the
descriptor's signing key may be corrupt. Engage LND vendor
support / consult the LND docs on `hiddenservice.private_key`.

## §5 — Tor info.log keyword catalog

When you bump `Log info file /var/log/tor/info.log` via the
operator override (see §6), or when you're reading
`docker compose logs tor-proxy`, these are the phrases that mean
something:

| Phrase | What it means | What to do |
|---|---|---|
| `All current guards excluded by path restriction` | A guard can't satisfy a Tor path requirement; this is the 2026-05-21 incident's smoking gun. | Wait. The `NumEntryGuards 3` lets the next guard try; the watchdog's tier-2 NEWNYM forces a re-pick. The dashboard's `tor_guard_excluded_total` counter tracks how often this happens. |
| `Tried for N seconds to get a connection to ...` | Circuit build wedged on a specific hop. | The `LearnCircuitBuildTimeout 1` + `MaxCircuitDirtiness 600` recycle the circuit; watchdog NEWNYM accelerates if it doesn't recover. |
| `HS_DESC FAILED` | A hidden-service descriptor fetch failed. | Usually transient. If the address matches your LND onion AND it's sustained, see §4 above. |
| `Bootstrapped 100%` | Tor is fully online. | No action — you want to see this on startup. |
| `Heartbeat: Tor's uptime is ...` | Tor's own status ping (~hourly). | Tracks the rotation cadence — confirms Tor itself is alive. |

## §6 — Operator torrc overrides

The wallet's defaults ship at
`/etc/tor/torrc.d/00-default.conf` inside the container.
Operator overrides go at `/etc/tor/torrc.d/99-operator.conf` and
**replace** matching directives from the defaults at startup.

Example (mounted via `docker-compose.override.yml`):

```yaml
services:
  tor-proxy:
    volumes:
      - ./my-tor.conf:/etc/tor/torrc.d/99-operator.conf:ro
```

`my-tor.conf` might contain:

```
# Tighter rotation than the wallet default
NumEntryGuards 1
GuardLifetime 24 hours

# Exclude jurisdiction
ExcludeExitNodes {ru},{cn},{ir}
StrictNodes 1

# Bridges
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
Bridge obfs4 ...

# Higher circuit-pending cap if you've maxed
# IsolateSOCKSAuth concurrency
MaxClientCircuitsPending 64
```

Notes:
- `SocksPort` directives **replace**, not append. If you want to
  override one, copy ALL eight from the default file and edit
  the one you care about.
- Bad syntax means Tor refuses to start. The healthcheck fails;
  `docker compose logs tor-proxy` shows the exact line.
- After editing, you don't need to restart the whole container —
  the dashboard's "Reload torrc" button issues SIGHUP
  which re-reads both files.

## §7 — Split-mode Tor

When repeated wedges affect both LND and anonymize surfaces at
the same time, the single shared Tor process is the root cause.
Splitting into `tor-lnd` (just LND) and `tor-anonymize` (just
the 8 anonymize listeners) gives each surface an independent
guard set; a wedge on one no longer touches the other.

Migration (one-time, opt-in):

```bash
# 1. Drain in-flight payments (no NEWNYM/SIGHUP mid-cutover)
lncli listpayments --include_incomplete \
  | jq '.payments[] | select(.status=="IN_FLIGHT")'
# Expect zero rows. Wait if not.

# 2. Stop the existing tor-proxy + dependents
docker compose stop tor-proxy api celery-worker

# 3. Bring up the split stack
docker compose \
  -f docker-compose.yml \
  -f docker-compose.tor-split.yml \
  up -d

# 4. Watch both Tor containers reach healthy (~120 s cold-start)
docker compose logs -f tor-lnd tor-anonymize

# 5. Verify in the dashboard Tor Health modal:
#    - "Tor (LND)" breaker: closed
#    - "Tor (anonymize)" breaker: closed
#    - both watchdogs alive
#    - bootstrap=100% on both
```

To roll back, drop the `-f docker-compose.tor-split.yml` flag
and `docker compose up -d` — `tor-lnd` / `tor-anonymize` stop;
`tor-proxy` comes back; the named volumes stay (Tor uses them
again when the operator re-runs the split command).

## §8 — Operator-supplied Tor

If you already run your own Tor instance (Whonix, Tails,
hardened host) and don't want the bundled `tor-proxy`:

1. Edit `.env`:
   ```
   LND_TOR_PROXY=socks5://host.docker.internal:9050   # macOS/Windows
   # or
   LND_TOR_PROXY=socks5://172.17.0.1:9050             # Linux
   ```
2. Disable the bundled service:
   ```bash
   docker compose stop tor-proxy
   docker compose rm -f tor-proxy
   ```
3. Restart the api so the proxy-reach check confirms the
   handover worked:
   ```bash
   docker compose restart api
   docker compose logs api | grep "tor proxy reach"
   ```
   Expect a single `tor proxy reach check: socks5://... OK` line.

Caveats:
- Without the bundled tor-proxy, the watchdog can't issue
  NEWNYM / SIGHUP — those features go quiet. Recovery becomes
  manual: you signal your own Tor.
- The per-listener probe and event stream need
  the wallet's container to reach a control port. If your host
  Tor exposes its control port reachably and you populate
  `ANONYMIZE_TOR_CONTROL_HOST` / `_PORT` accordingly, the
  diagnostics keep working. If not, the dashboard panel
  degrades gracefully (no event stream, no per-listener probes;
  the breaker + bootstrap state are still accurate).

## §9 — Verifying a fix

After working through any playbook, run this canonical smoke
test before declaring it fixed:

1. Anonymize happy-path. Dashboard → Anonymize tab → start one
   small session (use a regtest amount if you're on regtest).
   The session should reach `COMPLETED` within ~10 minutes
   without operator intervention.

2. Braiins Deposit happy-path. Dashboard → New Deposit → small
   amount → confirm the deposit reaches `COMPLETED`.

3. Dashboard Tor Health modal: all breakers closed, watchdog
   alive, event stream connected, no per-listener row red.

If all three are clean, the wallet's Tor stack is healthy. If
not, restart at the playbook step that matches the symptom.
