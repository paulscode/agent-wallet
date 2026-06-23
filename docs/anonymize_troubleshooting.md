<a id="troubleshooting"></a>
# Anonymize — troubleshooting `awaiting_reconciliation`

See [`anonymize.md`](anonymize.md) for the feature overview. This page is a per-reason-code reference for sessions that land in the `awaiting_reconciliation` state.

When a session lands in `awaiting_reconciliation`, the wallet's
auto-retry loop decides whether to retry, escalate, or
wait for operator action based on the **reason code** persisted on
the row. The dashboard shows a plain-English label; this section
maps each underlying reason to:

1. **What it means** — in concrete terms.
2. **What happened to your funds** — the operator's #1 question.
3. **What the wallet does automatically** — auto-retry behaviour.
4. **What you can do** — the buttons available on the row.
5. **When to escalate** — signs the operator should intervene.

Per-reason classes:

- **Class A — transient.** The wallet auto-retries on a backoff
  schedule up to
  `ANONYMIZE_RECONCILIATION_MAX_RETRIES_TRANSIENT` (default 12).
  Most users never see these resolve — the row blips into
  `awaiting_reconciliation` and back out before they notice.
- **Class B — semi-terminal.** Bounded auto-retry (3 attempts),
  then escalate to `failed`. Class B reasons all have funds-state
  implications, so the budget is pinned at a code-level constant
  (`reconciliation_classify.MAX_RETRIES_SEMI`).
- **Class C — terminal.** No automated retry. The wallet refreshes
  the "last seen" timestamp on each tick but operator action is
  required.

### Operator decision tree

When a session sits in `awaiting_reconciliation` longer than the
auto-retry window suggests:

1. Open the row's **Details** disclosure on the dashboard. Note
   the raw reason code and the pre-reconciliation status.
2. Cross-reference the per-reason block below.
3. Click **Try again** if the underlying condition has cleared
   (e.g., LN liquidity restored, Tor circuit recovered).
4. Click **Refund** if funds are recoverable but the session can't
   safely resume. Requires a step-up nonce confirmation.
5. Click **Cancel** when no funds moved and you want to abandon.
6. Inspect the per-session audit log (`anonymize_session_event`
   rows) for the full sequence of `reconciliation_attempt_*` /
   `reconciliation_escalated` events.

The buttons each row surfaces depend on the reason — see the
per-reason blocks below.

<a id="trouble-mpp-k-floor-exhausted"></a>

### Lightning routing failed (`mpp_k_floor_exhausted`)

**What it means.** The reverse-leg's Lightning payment couldn't
find a route to Boltz at any of the configured MPP K values. By
default the wallet tries K=4, K=3, K=2 in sequence (the
randomized-K plus the K-fallback). All three failed with
`FAILURE_REASON_NO_ROUTE`.

**Funds.** **Zero sats moved.** `NO_ROUTE` means LND never
committed an HTLC. Refunding isn't needed and isn't offered.

**Wallet does.** Class B — auto-retries up to 3 times on backoff.
On exhaustion, escalates to `failed`.

**You can.**
- **Try again** if you've added outbound LN liquidity or expect
  the routing landscape has changed. Common after opening a new
  channel or rebalancing.
- **Cancel** if you want to abandon the session without retrying.
  Marks it `cancelled` (the no-funds-moved set permits this).

**Escalate when.** Repeated `mpp_k_floor_exhausted` across many
sessions points to a structural liquidity issue:
- Your largest channel can't carry the bin amount single-shot AND
  your MPP-K range can't split small enough.
- Boltz operator's LN node has limited inbound for your direction.
- A peer on every viable route is congested or offline.

The fix is **outbound liquidity** (open channels, rebalance) or
**smaller bins** (add lower values to `ANONYMIZE_AMOUNT_BINS_SAT`
in `.env`).

<a id="trouble-circuit-rebuild-throttled"></a>

### Network throttled — retrying (`circuit_rebuild_throttled`)

**What it means.** The token-bucket cap on Tor circuit
rebuilds blocked another attempt. The wallet enforces an aggregate
per-listener + per-hour cap so a malicious entry guard can't
fingerprint outage-driven burst patterns.

**Funds.** **Zero sats moved.** The throttle fires before any
HTLC could be committed.

**Wallet does.** Class A — auto-retries every probe tick (default
5 min) until the bucket refills. Backoff is exponential up to the
configured maximum, then steady. Typical recovery: within ~60 min
of an outage event.

**You can.**
- Watch for the "Session resumed" toast — usually no action needed.
- **Cancel** if you don't want to wait. Safe (no funds at risk).

**Escalate when.** Repeated throttling across many sessions points
to one of:
- Tor entry-guard congestion (try restarting the wallet's Tor
  container after a few minutes of downtime).
- Boltz operator (or a hardcoded onion endpoint) is genuinely
  unreachable — see [Boltz reverse swap stuck](#boltz-reverse-swap-stuck-in-transactionmempool).
- The budget is set too tight for the deployment's
  workload; bump `ANONYMIZE_CIRCUIT_REBUILD_TOKENS_PER_HOUR`.

<a id="trouble-bounded-retry-exhausted"></a>

### Hit a snag (`bounded_retry_exhausted`)

**What it means.** The per-session loop's tick handler raised an
exception too many times in a row ( bounded-retry counter).
The wallet routes the session to reconciliation rather than
hammering a wedged dependency.

**Funds.** **Zero sats moved at the bounded-retry threshold.** The
counter only increments on exceptions raised before the per-session
loop reached a fund-moving step, so by construction the row is
pre-payment when this reason lands.

**Wallet does.** Class A — auto-retries until the underlying
exception clears (typically a transient dependency: DB, LND REST,
Tor circuit).

**You can.**
- **Try again** to force a fresh attempt now.
- **Cancel** to abandon (safe — pre-payment).

**Escalate when.** The same session repeatedly lands here despite
retries. Inspect the wallet's container logs around the session
id for the underlying exception. Likely culprits:
- LND REST connectivity (`tor-proxy:9050` config drift; see
  [Step-up nonce lockout](#step-up-nonce-lockout) for the COOKIE_NAME
  bug class).
- DB lock contention (look for advisory-lock timeouts in `app.db`).
- An assertion in the orchestrator's tick body — this is a bug;
  open an issue with the redacted `last_error` from the Details
  panel.

<a id="trouble-wall-clock-budget-exceeded"></a>

### Session went stale (`wall_clock_budget_exceeded`)

**What it means.** The wedge detector noticed a non-terminal
row whose `updated_at` is older than
`ANONYMIZE_RECONCILIATION_RUNTIME_WALL_CLOCK_BUDGET_S` (default 4 h).
This catches sessions that wedged in an active status without ever
self-reporting a failure (e.g., a hop body that returned from a
tick without making forward progress).

**Funds.** **Depends on the pre-reconciliation status.** Open the
Details panel and check the **Was:** line:
- `sending to your address` (`exiting`) — funds may be in flight on
  Lightning. Refund is available.
- `mixing` (`hopping`) — Boltz reverse swap may already have your
  LN payment. Refund is available.
- `received funding` (`funding`) / earlier — no funds moved.

**Wallet does.** Class A — auto-retries the resume path on
backoff. Typically resolves within minutes once the underlying
condition clears.

**You can.**
- Wait for auto-retry (countdown shown on the row).
- **Refund** if the pre-status indicates funds at risk and you
  don't want to wait.
- **Cancel** if pre-status indicates pre-payment.

**Escalate when.** Sessions repeatedly time out at this stage —
the underlying bug is a hop body that returns from a tick without
making forward progress. Inspect the audit log for the
`reconciliation_wall_clock_flipped` event and the event sequence
preceding it.

<a id="trouble-pipeline-schema-below-min-supported"></a>

### Session schema too old (`pipeline_schema_below_min_supported`)

**What it means.** The session row was created under an older
wallet version whose `pipeline_json` shape the running code no
longer executes. The schema-version gate refuses to drive
forward.

**Funds.** **Depends on pre-status.** Same heuristic as for
[wall_clock_budget_exceeded](#trouble-wall-clock-budget-exceeded).

**Wallet does.** Class C — no automated retry. The row stays
parked indefinitely.

**You can.**
- **Mark done** if pre-status is pre-payment (no funds at risk).
  Marks `failed` with a stub audit note.
- **Refund** if pre-status indicates funds in flight.

**Escalate when.** A wallet upgrade has bumped
`ANONYMIZE_MIN_SUPPORTED_PIPELINE_SCHEMA_VERSION` past in-flight
session schemas. The right action is usually to refund every
affected session, then start fresh ones under the new schema.

<a id="trouble-external-state-unknown"></a>

### Can't reach operator (`external_state_unknown`)

**What it means.** The wallet couldn't query Boltz (or the chain
backend) for the session's external state. Common causes: Boltz
onion endpoint is down, Tor circuit churn, deep mempool/index lag
on the chain backend.

**Funds.** **Funds may be in flight.** Depending on
pre-reconciliation status, Boltz may already be holding LN funds
or have published the on-chain claim. Until the external state can
be queried, the wallet doesn't know.

**Wallet does.** Class A — auto-retries via the polling
cadence + circuit-rebuild path. The probe tick spaces these out
with backoff so guard correlation doesn't get fingerprinted.

**You can.**
- Wait — most outages recover within minutes.
- **Get help** (this section) if it persists past the auto-retry
  budget.

**Escalate when.** Class A budget exhausts. The wallet escalates
to `failed` automatically. At that point the operator must:
1. Verify Boltz reachability via the dashboard's health card.
2. Check the operator-registry signature matches what the
   wallet expects.
3. If the swap state is recoverable (the swap row is still in
   Boltz's database), the swap proceeds independently of the
   wallet's session and the operator should manually reconcile by
   reading the Boltz response.

<a id="trouble-economy-feerate-unavailable"></a>

### Can't read on-chain fees (`economy_feerate_unavailable`)

**What it means.** The feerate sanity gate couldn't get
a fresh `economy` feerate from the chain backend after two
attempts. The wallet refuses to claim against an outlier fee.

**Funds.** **Funds in flight.** The reverse swap's LN side may
already be paid. The claim is paused until a fresh feerate read
succeeds OR the operator forces a refund.

**Wallet does.** Class A — auto-retries the feerate probe.

**You can.**
- Wait — usually resolves within one probe tick (5 min default).
- **Refund** if you don't want to wait and the swap's
  `timeout_block_height` is approaching.

**Escalate when.** The wallet's chain backend (electrs / mempool
HTTP) is persistently failing. See [Fee oracle gone stale](#fee-oracle-gone-stale)
for related recovery.

<a id="trouble-stuck-htlc-alarm"></a>

### Lightning payment stuck (`stuck_htlc_alarm`)

**What it means.** The stuck-HTLC alarm fired — your
reverse-leg LN payment has been in-flight at LND for longer than
the documented threshold without settling or failing.

**Funds.** **In flight on Lightning.** LND holds the HTLC; Boltz
hasn't received the preimage yet.

**Wallet does.** Class B — bounded auto-retry by re-polling LN
payment state. If LND settles or fails, the session resumes. If
the HTLC stays stuck past the class budget, the wallet escalates.

**You can.**
- Wait — most stuck HTLCs settle or fail within the channel's
  CLTV expiry window.
- **Refund** if you don't want to wait. Note: a refund cannot
  cancel an in-flight HTLC; it only initiates the on-chain refund
  path on the Boltz side. Lightning fees already paid are not
  recoverable.

**Escalate when.** Repeated stuck-HTLC alarms across sessions
point to a routing peer that's accepting HTLCs but not forwarding
them — consider adding that peer to
`ANONYMIZE_AUTO_BLOCKLIST_TOP_N_PEERS`.

<a id="trouble-claim-feerate-outlier"></a>

### Operator changed fees (`claim_feerate_outlier`)

**What it means.** Boltz returned a claim feerate outside the
configured tolerance band (`ANONYMIZE_CLAIM_FEERATE_TOLERANCE_LO/HI`)
relative to the wallet's live economy estimate. The wallet refuses
to claim at the operator's quoted feerate.

**Funds.** **Funds in flight at the operator.** Boltz has your
LN payment; the on-chain claim is pending. The
`ANONYMIZE_CLAIM_FEERATE_OUTLIER_GRACE_S` grace window allows the
wallet to re-request a fresh quote before escalating to refund.

**Wallet does.** Class B — bounded auto-retry by re-requesting a
fresh swap quote. On grace exhaustion, escalates to `refunding`.

**You can.**
- Wait — most operator outages recover within the grace window.
- **Refund** to take the on-chain refund path immediately. The
  step-up nonce confirms you accept that LN fees already paid are
  not recoverable.

**Escalate when.** Repeated outlier feerates from one operator
mark them `degraded_operator`. Consider removing them
from your operator pair set until their pricing recovers.

<a id="trouble-operator-signature-mismatch"></a>

### Operator security check failed (`operator_signature_mismatch`)

**What it means.** A response from a Boltz operator failed the
 signature check against the registry's pinned public key.
**This is a security-critical event** — either the operator has
rotated keys without coordinating a registry update OR the
response was tampered with in transit.

**Funds.** **Funds in flight.** Boltz has your LN payment; the
wallet is refusing to act on the operator's claim response.

**Wallet does.** Class C — **no automated retry**. The wallet
refuses to silently retry because that would mask an active
attack.

**You can.**
- **Refund** — recommended. The on-chain refund path uses the
  swap's `refund_private_key` (locally held), not the operator's
  signature, so it's safe even if the operator key is compromised.
- **Get help** if you suspect the registry needs updating.

**Escalate when.** Always. Open the audit log, capture the
`reconciliation_attempt_started` event detail, and:
1. Check the project's release manifest for a recent operator-key
   rotation announcement.
2. If no announcement: this is a potential incident. Halt new
   anonymize sessions, contact the project, and audit recent
   sessions against the Boltz operator's published swap database.

<a id="trouble-claim-tx-validation-failed"></a>

### Couldn't sign claim (`claim_tx_validation_failed`)

**What it means.** The cooperative-claim Musig2 ceremony produced
a transaction that failed the wallet's local validation gate
. The wallet refuses to broadcast it.

**Funds.** **Funds in flight.** Boltz has your LN payment; the
on-chain claim hasn't broadcast.

**Wallet does.** Class C — **no automated retry**. Re-running
the same Musig2 ceremony with the same inputs would produce the
same outcome.

**You can.**
- **Refund** — recommended. The on-chain refund path bypasses the
  Musig2 ceremony entirely.

**Escalate when.** Always. The validation failure points to either
a Boltz-side ceremony bug OR a wallet-side gate mis-configuration.
Capture the redacted `last_error` from the Details panel and the
session's audit log before clicking Refund.

<a id="trouble-clock-skew-exceeds-deadline-margin"></a>

### Clock too far off (`clock_skew_exceeds_deadline_margin`)

**What it means.** The clock-skew gate refuses to drive
the session forward because the host's clock has drifted past the
safe deadline margin. Allowing the session to continue would risk
broadcasting a claim transaction after the swap's
`timeout_block_height`, which would let Boltz refund itself.

**Funds.** **Funds in flight.** Boltz has your LN payment.

**Wallet does.** Class C — **no automated retry**. The wallet
won't resume until the operator confirms the clock is correct.

**You can.**
- Verify the host's chrony / NTP status; restart `chronyd` if
  needed.
- After the clock catches up, click **Try again** to force a
  fresh attempt.
- **Refund** if the clock issue can't be resolved before the swap
  timeout.

**Escalate when.** The host's clock has been corrected but the
session won't resume — the wallet may need a process restart for
the clock-skew probe to re-measure.

<a id="trouble-inbound-insufficient-at-lockup"></a>

### Can't receive over Lightning (`inbound_insufficient_at_lockup`)

**What it means.** This is an on-chain-sourced session. To convert
on-chain funds to Lightning it uses a submarine swap, which requires
the node to **receive** the bin amount over Lightning from the swap
provider (inbound routing into us). Immediately before broadcasting
the on-chain lockup, the wallet re-checked inbound capacity (mirroring
the Braiins on-chain deposit gate) and found it can no longer cover the
amount — inbound that was sufficient at session creation has since
dropped (most often on `ext-onchain`, which dwells waiting for the
deposit). It aborted **before** the lockup.

**Funds.** **Safe — nothing moved.** The re-check fires before the
on-chain funding broadcast, so no coins left the wallet.

**Wallet does.** Class A. The row is routed to reconciliation, but
because there is no `AWAITING_RECONCILIATION → FUNDING` resume edge
(an on-chain funding step can't be auto-resumed), the recovery probe
escalates the row to **failed** rather than retrying — the same
behaviour `bounded_retry_exhausted` exhibits when it fires from
`FUNDING`.

**You can.**
- **Cancel** immediately (no funds moved), then start a new session
  once inbound is available — e.g. after a pending channel confirms
  or a rebalance lands.
- Or use a **Lightning source** (`lightning-self` / `ext-lightning`),
  which needs no inbound.

**Escalate when.** You believe the node has ample inbound — verify the
channels are active and not depleted on the receive side, then retry.

<a id="trouble-unknown"></a>

### Unknown reason

**What it means.** The reason code on the row isn't in the
classifier's known set. By default the wallet treats unknown
reasons as Class C (terminal) so a new bug-driven reason can't
silently retry into a tight loop.

**Funds.** **Status unknown.** Open the Details panel for the
raw reason string, the pre-reconciliation status, and the redacted
`last_error`. The combination usually tells you whether funds
moved.

**Wallet does.** Class C — refresh the "last seen" timestamp on
each probe tick but no automated retry.

**You can.**
- **Try again** if you understand the reason from the audit log
  and believe it's transient.
- **Refund** if pre-status indicates funds in flight.
- **Stop trying** (the `Mark done` button on the row) to mark
  `failed` once you've decided.

**Escalate when.** Always — this means either a wallet upgrade
introduced a reason without updating the classifier, OR the row's
reason column was set by a code path that bypassed the helper.
Either way, open an issue with the reason string + the audit log.

---

## Deployment troubleshooting

The entries above cover per-session reconciliation reasons. This
section covers infrastructure-level issues that prevent sessions
from being created in the first place.

<a id="trouble-liquid-backend-not-ready"></a>

### "Liquid backend not ready yet" banner on the Anonymize tab

**What it means.** The wallet polls `/anonymize/policy`'s
`liquid_indexer_reachable` field; this banner stays up while
that field is false. The Anonymize tab continues to work for
LN-only and on-chain paths — only strong-tier (Liquid-routed)
session create is blocked.

**Normal cases** (no operator action required):

- **First boot, IBD in progress.** The first sync goes through
  three phases — elementsd block download (hours), electrs
  block fetch (~1 h), post-IBD RocksDB compaction (~30–60 min).
  See [Liquid initial-sync expectations](anonymize.md#liquid-initial-sync-expectations)
  for the breakdown. The banner clears automatically when the
  Electrum port opens.
- **Brief flap during electrs restart.** Every `electrs-liquid`
  boot reloads the (slim) Liquid header index from RocksDB before
  opening port 50001 — a few seconds, ~1.2 GiB peak with the
  slim-headers patch. The banner flickers during that window.

**Failure modes** (operator action required):

- **electrs-liquid OOM-kills.** With the slim-headers patch the
  indexer peaks at ~3.7 GiB during the initial index build and
  ~2.4 GiB serving, so OOM under the shipped 6 GiB compose cap
  should not happen.
  If you see one (`dmesg -T | grep "Killed process.*electrs"`),
  the most likely cause is the patch not having applied — confirm
  the build log shows `Applying /build/patches/0001-slim-headers.patch`.
  Without the patch the unpatched upstream needs 10–16 GiB on
  Liquid mainnet (it holds the whole-chain header set in RAM), so
  the 6 GiB cap will crash-loop.
- **`missing txo {txid}:{vout}` panic in `schema.rs`.**
  The default `blkfiles_fetcher` returns blocks in elementsd's
  blk-file order (not chain order), violating the single-pass
  `add()+index()` invariant in recent Blockstream/electrs.
  The compose file ships `--jsonrpc-import` to force the
  chain-ordered RPC fetcher; if you removed it, restore it.
- **electrs running but Electrum port closed.** Most likely
  still compacting post-IBD — `docker logs agent-wallet-electrs-liquid-1 | tail -5`
  shows lines like `starting full compaction on RocksDB { path: ".../txstore" }`.
  Wait for `finished full compaction` on all three of
  `txstore`, `history`, `cache`, then the port opens.
- **elementsd OOM-kills.** `dmesg -T | grep "Killed process.*elementsd"`.
  Elements Core holds the full Liquid block index in memory — a
  ~9.6 GiB resident floor at the tip — so the compose cap is
  12 GiB. A tighter cap sits on the floor and thrashes (or
  OOM-kills) during catch-up. This floor is the dominant memory
  cost of the local Liquid stack; reducing it would require
  patching Elements Core itself.
- **Used to work, now broken after bumping `ELECTRS_GIT_REF`.**
  The build applies a local patch at
  [`liquid-overlay/patches/0001-slim-headers.patch`](../liquid-overlay/patches/0001-slim-headers.patch);
  if upstream changed the touched files, `git apply --check`
  fails and the build aborts loudly. Regenerate the patch
  against the new pin and commit it.

**Quick diagnostic** (run all in one shot):

```sh
docker stats --no-stream agent-wallet-electrs-liquid-1 agent-wallet-elementsd-1
docker logs agent-wallet-electrs-liquid-1 --tail 20
dmesg -T 2>&1 | grep -E "Killed process.*(electrs|elementsd)" | tail -3
# Probe the Electrum port directly:
echo '{"id":1,"method":"server.version","params":["probe","1.4"]}' \
  | docker exec -i agent-wallet-electrs-liquid-1 sh -c 'nc -w 3 127.0.0.1 50001'
```

**Don't want to run electrs-liquid at all?** Set
`ENABLE_LIQUID_INDEXER=false` and point
`ANONYMIZE_LIQUID_ELECTRUM_URL` at an external Liquid Electrum
endpoint (Blockstream operates public ones, or run electrs on
a beefier separate host). See
[Externally-managed Liquid backend](anonymize.md#externally-managed-liquid-backend).

<a id="trouble-dashboard-timeout-stale-onion"></a>

### "Request timed out — the node may be unreachable" (dashboard)

**What it means.** The wallet's keepalive can't reach LND. The
dashboard shows this banner; the LND breaker has fast-failed.
Despite the message naming "LND and Tor", the root cause in the
2026-06-01 incident — and the most common pattern when LND
itself is healthy — was a **stale Tor hidden-service descriptor**
in the wallet's `tor-proxy` cache. Tor found the descriptor in
the DHT, but all three "introduction points" it listed were no
longer reachable, so circuit-build timed out.

**Self-recovery (default behaviour).** The LND Tor supervisor
detects this signature within ~60 s and walks a staggered
recovery ladder:

| Step | Action | Typical effect |
|---|---|---|
| 1 | `HSFETCH` against the LND onion | Forces a fresh descriptor lookup from HSDirs. Surgical fix. Often resolves the incident here within 30 s. |
| 2 | `SIGNAL NEWNYM` | Drops dirty circuits process-wide. Anonymize circuits rebuild too; the exit-diversity cache invalidates. |
| 3 | `SIGNAL HUP` | Reloads `torrc`, drops all guards. ~30 s extra latency on first egress after. |
| 4 | Yield to Docker healthcheck | Container restart after 3 × 60 s of failed healthchecks. |
| 5 | Exhausted — hard alarm | Operator runbook (this section). |

To watch the supervisor work in real time:

```sh
docker logs agent-wallet-api-1 -f | grep -E "tor_lnd_recovery|lnd tor supervisor"
```

A cycle that clears at step 1 looks like:
```
INFO  lnd tor supervisor: cycle armed (id=lnd-tor-1717280123-a3f2)
AUDIT action=tor_lnd_recovery_armed correlation_id=lnd-tor-1717280123-a3f2
AUDIT action=tor_lnd_recovery_step_1_outcome outcome=success
AUDIT action=tor_lnd_recovery_cleared cleared_at_step=hsfetch
INFO  lnd tor supervisor: cleared at step hsfetch
```

**Failure modes** (operator action required):

- **Supervisor `tor_lnd_recovery_exhausted`.** All four recovery
  steps fired and the LND breaker still didn't close. The issue
  is almost certainly on the LND host side — the wallet has done
  everything it can locally. Check: is LND's Tor controller
  publishing fresh descriptors? Is the LND host's network
  connectivity OK? On a Start9, restart the Tor service. RTL
  working on the same LND host **does not** rule this out — RTL
  uses LND's local socket, not the hidden service.
- **Supervisor `tor_lnd_recovery_disabled_cycle_cap`.** 4+
  cycles in the last 24 h. The supervisor is intentionally
  off-line for the rest of the window so a chronic root cause
  doesn't look like a healthy auto-recovery loop. Investigate
  why we keep needing recovery — check LND host stability +
  recent Tor relay churn.
- **Supervisor not ticking.**
  `docker exec agent-wallet-api-1 curl -s http://127.0.0.1:8100/v1/admin/tor/metrics -H "X-API-Key: …" | jq '.lnd_tor_supervisor.alive'`
  returns false. Restart the api container to bring the
  supervisor task back. If it crashed repeatedly (3 restarts in
  5 min), `tor_lnd_recovery_supervision_exhausted` audit will
  appear — open an issue.

**Manual override.** If you want to short-circuit the
ladder, `docker compose restart tor-proxy` clears all cached
descriptors in ~30 s. Useful when you don't want to wait the
~60 s detection window.

**Disabling auto-recovery.** Set
`LND_TOR_RECOVERY_ENABLED=false`. The supervisor stays loaded
but its tick is a no-op. The legacy single-watchdog wiring (which lets the
existing `tor_watchdog` Tier 2 fire NEWNYM at ~60 s) still
works.
