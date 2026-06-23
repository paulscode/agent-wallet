# Boltz swap recovery

The wallet uses Boltz swaps to move sats between Lightning and
on-chain Bitcoin (Cold Storage, Braiins Deposit), and — when the
Liquid round-trip is enabled — through Liquid as part of the
Anonymize hop. Most swaps complete in a few minutes without any
operator interaction. This page describes what happens when one
doesn't, and how to get unstuck.

> **Funds-safety bottom line.** A "stuck" swap is almost never a
> funds-loss event. Reverse swaps (Lightning → on-chain) use a hold
> invoice — your Lightning sats are not debited until the on-chain
> claim broadcasts a preimage. If the on-chain leg fails, Boltz
> refunds itself on chain and your Lightning HTLC is cancelled.
> Submarine swaps (on-chain → Lightning) can always be refunded
> back to the wallet after the swap's `timeout_block_height`. The
> recovery surface described here exists to surface those refund
> and retry paths to you when the wallet's automatic loop has
> exhausted its options.

---

## 1. The recovery banner

When the dashboard detects that a swap has stalled, it surfaces a
coloured banner under the swap row (Cold Storage tab, Anonymize
tab, or Braiins Deposit reconciliation tab depending on where the
swap lives). The banner has four parts:

| Part            | What it means                                                                    |
|-----------------|----------------------------------------------------------------------------------|
| **State**       | One-word description of why the swap is stuck. See §2 for the full list.         |
| **User message**| Plain-language explanation suitable for a non-technical reader.                  |
| **Stuck since** | How long the swap has been in this state, in human terms (e.g. "23 minutes").    |
| **Action button**| A single recommended next step. The button is greyed out if no action is safe yet. |

The banner is *advisory*. The wallet's automatic reconciliation
loop continues to run in the background, so you can usually leave
a stuck swap alone for a few minutes and watch it clear on its own.
Click the action button only if the banner has been showing for
longer than the time horizon the message suggests.

---

## 2. Recovery states

The recovery classifier emits one of these states for every active
swap. The values match the `recovery.state` field in the swap's
API response.

### `clean`

The swap is progressing normally. No banner is shown.

### `in_progress`

The swap is in an intermediate state (paying invoice, awaiting
lockup, claiming) but has been there for less than the
stuck-threshold for that state. No banner; the dashboard shows
normal "in progress" copy.

### `stuck_in_paying_invoice`

The wallet has been trying to pay the Boltz hold invoice for more
than 10 minutes without a definitive success or failure. Usually
caused by a transient routing problem.

- **What you do:** Wait. The wallet retries automatically. If the
  banner persists for more than 30 minutes, contact support.
- **Funds:** Safe — the HTLC is not settled until the on-chain
  preimage is revealed.

### `transient_payment_error`

The `send_payment_sync` call returned a non-definitive error
(network blip, LND timeout). The wallet stays in `paying_invoice`
and the next reconciliation tick will retry.

- **What you do:** Wait. This typically clears within one reconciliation
  cycle.
- **Funds:** Safe.

### `awaiting_lockup_confirmation`

Boltz (reverse) or the wallet (submarine) has broadcast the lockup
transaction and it is sitting in the mempool. With normal fee
markets this clears in a block or two. If the mempool is
congested, the banner may also flag `fee_bump_recommended` (see
§3 below).

- **What you do:** Wait — or, if the banner shows
  `fee_bump_recommended`, click **Bump fee** and pick a higher
  sat/vB target.
- **Funds:** Safe.

### `awaiting_claim` / `claim_retry_available`

The lockup has confirmed but the wallet has not yet broadcast the
claim. The automatic loop retries periodically; if it has been
stuck for more than 30 minutes the banner offers
**Retry cooperative claim**.

- **What you do:** Click **Retry cooperative claim**. If that
  also fails repeatedly, see §4.
- **Funds:** Safe.

### `timeout_warning` / `timeout_imminent` / `timeout_passed`

The on-chain timeout block is approaching or has passed.

- **What you do:**
  - `timeout_warning` (>24h to timeout): no action needed yet.
  - `timeout_imminent` (<24h to timeout): begin investigating; if
    the swap is still in an intermediate state at this point, the
    automatic loop is likely struggling.
  - `timeout_passed`: the cooperative paths no longer work. The
    banner offers **Unilateral refund** (submarine) or
    **Unilateral claim** (reverse). See §4.
- **Funds:** Safe — the refund and claim scripts target your own
  wallet address.

### `awaiting_confirmations`

The claim or refund transaction has been broadcast and the wallet
is waiting for it to confirm. The dashboard shows confirmation
count; the recovery surface only flags this as actionable if
`fee_bump_recommended` is also set (§3).

- **What you do:** Wait — or **Bump fee** if the banner suggests it.
- **Funds:** Safe.

### `refunded`

Boltz reclaimed the on-chain lockup via the timeout-script path.
For reverse swaps this means the on-chain leg never completed and
your Lightning HTLC will be cancelled — your Lightning sats remain
liquid in your channel balance. For submarine swaps this is the
expected terminal state of the unilateral refund flow.

- **What you do:** Nothing. The banner is purely informational.
- **Funds:** Safe.

### `failed` / `cancelled` / `completed`

Terminal states. No banner is shown (other than the standard swap
row status).

---

## 3. Fee-bumping a stuck mempool transaction

When the wallet's own broadcast (submarine lockup or reverse claim)
has been sitting in the mempool for more than 4 hours without
confirming, the recovery banner adds a `fee_bump_recommended` flag
and shows a **Bump fee** button. Clicking it:

- For a **submarine** lockup, builds an RBF replacement of the
  unconfirmed lockup transaction at the new sat/vB target.
- For a **reverse** claim, builds a CPFP child spending the claim
  output at the new sat/vB target. (The claim itself is already
  in the mempool and not directly replaceable — CPFP is the only
  option for accelerating it.)

Both paths route through LND's wallet fee-bumping RPC, so the
wallet picks the right mechanism automatically. You only choose
the sat/vB target.

**There is no automatic fee-bumping.** Every bump requires you to
press the button. The wallet records each bump in the audit log
with the target rate, the original txid, and the replacement txid.

---

## 4. The recovery actions

The banner's action button maps to one of these recovery actions.
Each is exposed via an admin-authenticated API endpoint and
recorded in the audit log.

| Action ID                | What it does                                                                                                    |
|--------------------------|-----------------------------------------------------------------------------------------------------------------|
| `retry_payment`          | Re-queue the Boltz invoice payment for a swap stuck in `paying_invoice`.                                        |
| `cooperative_claim`      | Re-run the cooperative (Musig2) claim against Boltz for a reverse swap whose lockup has confirmed.              |
| `cooperative_refund`     | Ask Boltz to cooperatively refund a submarine lockup that hasn't been picked up.                                |
| `unilateral_refund`      | Script-path spend of the submarine lockup back to the wallet after `timeout_block_height` has passed.           |
| `unilateral_claim`       | Script-path spend of the reverse lockup to the wallet's claim address (revealing the preimage on-chain).        |
| `bump_fee`               | RBF or CPFP fee-bump of a stuck wallet broadcast — see §3.                                                      |

All buttons require the dashboard's admin gesture (same as
initiating a new swap) before they fire. They are intentionally
not auto-triggered: each one is irreversible on-chain or
fee-bearing.

---

## 5. Anonymize sessions and the Liquid hop

When the Anonymize feature is configured with `ENABLE_LIQUID=true`,
each session creates **two** Boltz swaps against **two distinct
operators**:

1. **LN → L-BTC (reverse chain swap)** — the operator wallet
   receives a Lightning payment and locks L-BTC at a wallet-derived
   blinded address.
2. **L-BTC → LN (submarine chain swap)** — after the dwell delay,
   the wallet spends the L-BTC lockup to the second operator's
   Liquid address and receives Lightning back.

The recovery surface for each leg mirrors the BTC-side surface,
with a few Liquid-specific additions.

### 5.1 Operator visibility

The session row records which operator was used for each leg
(`liquid_reverse_operator_id` and `liquid_submarine_operator_id`).
When a Liquid leg gets stuck, the recovery banner includes the
operator id so a support investigation can target the right
operator's status page.

### 5.2 Liquid recovery actions

The Liquid-side endpoints are keyed on `(session_id, leg)`:

| Endpoint                                                                                  | Purpose                                                |
|-------------------------------------------------------------------------------------------|--------------------------------------------------------|
| `POST /v1/anonymize/sessions/{id}/liquid-recovery/submarine/cooperative-refund`           | Cooperative L-BTC submarine refund                     |
| `POST /v1/anonymize/sessions/{id}/liquid-recovery/submarine/unilateral-refund`            | Script-path L-BTC submarine refund after timeout       |
| `POST /v1/anonymize/sessions/{id}/liquid-recovery/reverse/unilateral-claim`               | Script-path L-BTC reverse claim after preimage reveal  |

These mirror the BTC-side cooperative-refund / unilateral-refund /
unilateral-claim flows. The endpoints validate that you're calling
the right action for the right leg (e.g. `unilateral-claim` on the
submarine leg returns `incompatible_leg`).

### 5.3 electrs-liquid outage

The Liquid hop depends on a reachable electrs-liquid instance for
mempool and UTxO reads. If electrs-liquid is down, sessions in the
`awaiting_liquid_dwell` state cannot observe their lockup's
confirmation depth and will stall indefinitely.

The dashboard surfaces this two ways:

- A top-of-page banner on the Anonymize tab when
  `/anonymize/policy` reports `liquid_indexer_reachable: false`.
- Per-session recovery banners with copy that calls out the
  indexer as the most-likely cause.

If you operate the electrs-liquid container yourself (the default
Liquid overlay does), the fix is usually `docker compose restart
electrs-liquid` followed by a few minutes of catch-up sync time.
Sessions resume automatically once the indexer is reachable again.

### 5.4 Residual L-BTC recovery

A unilateral L-BTC claim (§5.2 above) deposits the recovered
L-BTC at a wallet-derived blinded address. The wallet does *not*
expose a general-purpose Liquid send/receive surface; instead,
residual outputs are surfaced via a one-click swap-back-to-Lightning
flow:

1. A background job scans wallet-derived Liquid addresses for
   unspent outputs and persists them in `liquid_residual_outputs`.
2. When the table has un-recovered, non-dust rows, a banner appears
   under the Anonymize tab showing the total residual balance and a
   **Swap residual L-BTC to Lightning** button.
3. Clicking the button runs one L-BTC → LN submarine swap per
   residual output, using the same operator selection policy as
   the regular Liquid hop's submarine leg. Each successful swap
   stamps `recovered_at` on the row.

**Dust threshold.** Outputs below 5,000 sat are flagged as dust —
the operator fee plus Liquid network fee would exceed the residual.
Dust rows show in the banner with the swap-out button disabled and
an **Acknowledge as dust** action that stamps the row's
`dust_acknowledged_at` so it stops contributing to the banner total.
The acknowledgement is reversible if fee dynamics change.

If residual rows persist for more than 30 days without resolving,
something is wrong with either the scan or the swap-out path —
contact support.

---

## 6. When the banner says "contact support"

A handful of states fall outside the automated recovery paths. The
banner explicitly says **Contact support** for these:

- `recovery_count` has hit the 200-retry shelf without making
  progress.
- A swap is stuck past `timeout_passed` and the unilateral refund /
  claim has also failed (e.g. operator outage AND a Bitcoin
  reorg).
- `SECRET_KEY` or `ANONYMIZE_LIQUID_SEED_FERNET` has been lost and
  the wallet cannot decrypt the row's secrets (see the
  [encryption-key backup](./secret_key_backup.md) page for the
  recovery path).
- A residual L-BTC output has been visible for more than 30 days
  without successfully recovering.

In all of these cases, the swap rows and their on-chain history
remain intact in the database. A support technician can use the
audit log, the operator's swap-id, and the wallet's archived
status history to determine the right manual intervention.

---

## 7. Related reading

- [Encryption-key backup](./secret_key_backup.md) — `SECRET_KEY` and
  `ANONYMIZE_LIQUID_SEED_FERNET` handling.
- [Boltz integration overview](./boltz.md) — how the wallet talks to
  Boltz under the hood.
- [Anonymize troubleshooting](./anonymize_troubleshooting.md) —
  Anonymize-specific stuck-state diagnostics that don't map neatly
  to the Boltz recovery banner.
