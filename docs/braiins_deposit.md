# Braiins Deposit

The **Braiins Deposit** wizard sends a clean, round-amount Bitcoin
deposit to a [Braiins Hashpower](https://braiins.com/hashpower)
address without triggering manual review.

---

## When to use it

Braiins Hashpower's anti-fraud system flags deposits whose recent
transaction history looks "complex" (mixers, custodial Lightning
apps like Strike, exchange withdrawals) for a human review before
crediting your account. Reviews almost always pass — but they
introduce a delay of hours to a day.

The Braiins Deposit wizard sidesteps the review by:

1. Converting some of your Lightning balance into a brand-new
   Bitcoin transaction in your wallet (via Boltz Exchange — the
   same service Cold Storage uses).
2. Sending a round-number amount (50,000 / 100,000 / 250,000 /
   500,000 / 1,000,000 / 2,000,000 / 3,000,000 / 4,000,000 /
   5,000,000 sats) on-chain to your Braiins address.

The result is a single-input single-output transaction whose only
parent is a vanilla Taproot spend from Boltz — the shape the
anti-fraud algorithm clears automatically.

The technique is general: any service that flags unusual deposits
for manual review will treat the Braiins Deposit output the same
way. Braiins Hashpower is just the most common target in the Agent
Wallet community.

---

## What you'll need

* Bitcoin in your wallet, on one of two "sides":
  * **Lightning balance** (fastest, cheapest) — the deposit amount
    plus ~3.5 % headroom for fees is a safe rule of thumb.
  * **On-chain balance** (slower, costs a bit more) — the deposit
    amount plus ~4.5 % headroom. The wizard will route through
    Lightning automatically via an extra swap step.
  The wizard auto-selects whichever side has enough; you can override
  the choice with a single click. Chips you cannot afford are greyed
  out.
* The current deposit address from your Braiins Hashpower account.
  (Copy it from the *Add funds* page on Braiins; we never store it.)

Launch the wizard from the dedicated **Braiins Deposit** tab in the
dashboard nav (placed after Anonymize). The tab opens to a header
card with a **+ New deposit** button, and the panel below it lists
your recent deposit sessions with live status — so you can observe
in-flight deposits without re-opening the wizard. A small pulse-dot
appears beside the tab label whenever at least one session is still
working through the pipeline, so progress remains visible even when
you're on a different tab.

---

## Walk-through

### Step 1 — Pick a source, amount, and address

**Source.** The wizard offers four options under two headers:

* **Agent Wallet — Lightning** uses this wallet's Lightning balance.
* **Agent Wallet — On-chain** uses this wallet's on-chain balance.
* **External Source — Lightning** lets you pay an invoice from any
  other Lightning wallet (your phone, desktop, custodial service).
  The wizard generates a one-time Lightning invoice on Step 3.
* **External Source — On-chain** lets you send to a fresh Bitcoin
  address from any other on-chain wallet (hardware wallet, exchange
  withdrawal, paper backup, etc.).

Each radio carries a small ⓘ icon that opens a plain-language
explanation of what that source does.

The wizard auto-picks Agent Wallet Lightning when your channel
balance covers the deposit; otherwise it picks Agent Wallet on-chain;
otherwise it picks External Lightning (it never auto-picks External
on-chain — that's the slowest path and you should opt in deliberately).
Click any other radio to override.

**Amount.** Nine preset chips. Greyed-out chips need more balance
than you have on the currently-selected source. Selecting a chip
triggers a quote.

**Address.** Paste your Braiins deposit address. The wizard
rejects legacy "1…" addresses; Braiins issues bech32 ("bc1…")
or P2SH ("3…") addresses, both of which work.

### Step 2 — Review fees

A fee breakdown appears once you've selected an amount:

* **Braiins receives** — exactly the round amount you picked.
* **Total fees** — the sum of the conversion fee, Bitcoin network
  fees, Lightning routing headroom, and on-chain send fee.
* **Lightning balance debited** — what comes out of your Lightning
  channels.

Expand *Fee details* to see each component.

### Step 3 — Working...

After you click **Start deposit**, the wizard switches to a
progress view.

**Lightning source (3 stages):**

1. **Building your Bitcoin transaction** — we pay a Boltz invoice
   from your Lightning balance, then receive the matching Bitcoin
   transaction at a fresh Taproot address in your wallet.
2. **Sending to Braiins** — we send the round amount on-chain from
   that fresh transaction to your Braiins address.
3. **Confirming on the Bitcoin chain** — we wait for the first
   confirmation.

**On-chain source (4 stages):**

1. **Converting on-chain to Lightning** — we send a slice of your
   on-chain balance to Boltz, who pays us back over Lightning.
   This adds about ~10 minutes to the total time.
2. **Building your Bitcoin transaction** — same as the LN-source
   step 1.
3. **Sending to Braiins** — same as above.
4. **Confirming on the Bitcoin chain** — same as above.

Each transaction is shown with **📋 Copy** and **🔗 Open** buttons —
the Open link goes to your configured mempool explorer (defaults to
[mempool.space](https://mempool.space)). You can close the wizard
at any point; everything continues in the background.

### Step 4 — Done

A green checkmark and the final transaction ID. The full transaction
history for the deposit (the prepared Bitcoin transaction + the send
to Braiins) is available under the *All transactions in this deposit*
toggle.

---

## Funding from an external wallet

When you pick an **External Source** on Step 1, the wizard inserts an
extra step between the form and the progress view that shows you what
to pay (Lightning) or where to send to (on-chain). Once your payment /
deposit is detected, the wizard auto-advances and runs the rest of
the flow exactly like a self-sourced deposit.

### External Lightning

The wizard generates a one-time Lightning invoice and surfaces it as:

* a QR code with the `lightning:` URI prefix — most modern Lightning
  wallets recognise the prefix and pre-fill the amount when you scan
  it,
* the exact amount to pay (the largest text on the screen),
* a countdown showing how long the invoice has before it expires
  (typically ~1 hour),
* the raw `lnbc…` invoice text with a click-to-copy affordance.

Pay it from your other wallet — your phone, a desktop wallet, or any
custodial service that supports Lightning withdrawals. Once the
payment lands the wizard flips to *"✓ Payment received! Building
your Bitcoin transaction…"* for a couple seconds, then advances to
the progress view. The wallet handles the rest in the background.

If the countdown hits zero before you pay, the QR is replaced with
a *"This invoice expired"* message and a **Generate new invoice**
button mints a fresh one. Your other wallet will still be able to
pay the new invoice — nothing is lost.

You don't need a Lightning channel on this wallet to use external
Lightning sourcing. The payment is routed via Boltz Exchange, who
handles the Lightning → on-chain conversion as part of the same
swap.

### External on-chain

The wizard generates a fresh Bitcoin address (a Taproot `bc1p…`
address) and surfaces it as:

* a QR code with a BIP-21 URI (`bitcoin:bc1p…?amount=0.0…`) — every
  modern on-chain wallet honours the URI's amount parameter, so you
  don't have to re-type the number,
* the exact amount to send (the largest text on the screen),
* the raw address with a click-to-copy affordance.

Send it from your other wallet — a hardware wallet, an exchange
withdrawal, a paper backup, or any other on-chain Bitcoin wallet.

If your deposit confirms but you sent **less than** the required
amount, the wizard switches to a partial-deposit banner that tells
you exactly how much more to send to the **same address**. Multiple
deposits to the same address are aggregated automatically.

Once the cumulative amount reaches the required total and confirms
(~10–30 minutes), the wizard flips to the progress view and runs the
rest of the flow (an internal submarine swap to Lightning, then the
standard fresh-transaction build, then the send to Braiins).

If a later step fails after we've received your deposit, the failure
screen prompts you for a refund address — paste any address from
your other wallet and click **Send refund →** to send the deposit
back. The refund spends the exact deposit outpoints, so the refund
transaction provably matches what you sent in.

---

## Glossary

| Term | Plain explanation |
|---|---|
| **sats** | Short for *satoshis*, the smallest unit of bitcoin. 100,000,000 sats = 1 BTC. 100,000 sats ≈ a small everyday amount. |
| **Lightning balance** | The portion of your bitcoin held in Lightning payment channels. Lightning lets you send and receive instantly with very low fees, but its balance has to be opened in a "channel" first. |
| **Bitcoin chain / on-chain** | The main Bitcoin ledger — slower than Lightning (~10 minutes per confirmation) and has a per-transaction fee, but anyone can see and verify the transaction with a block explorer. |
| **Bitcoin transaction prepared** | Boltz Exchange has produced a Bitcoin transaction that pays the sats you converted into your wallet. The transaction has been broadcast and is waiting to be confirmed by miners. |
| **Boltz Exchange** | The service we use to convert sats between Lightning and the Bitcoin chain. Your wallet already uses it for the *Cold Storage* and *Add Receive Capacity* features. No account or login — every transaction is independent. |
| **Confirmation** | A Bitcoin block added on top of the block that includes your transaction. More confirmations = harder to reverse. Most services credit your deposit after 1–3 confirmations (~10–30 minutes). |
| **Transaction ID** | A 64-character unique fingerprint for a Bitcoin transaction. Paste it into any block explorer (such as mempool.space) to see its current status and details. |
| **Mempool** | The waiting room for Bitcoin transactions. After broadcast a transaction sits in the network's "mempool" for a few minutes to ~an hour until a miner includes it in a block. |
| **Manual review** | Some services (including Braiins Hashpower) automatically flag deposits whose recent history looks unusual for a human to check before crediting. Reviews almost always pass but they introduce a delay. The Braiins Deposit flow produces a transaction shape the algorithm clears automatically. |

---

## FAQ

### Which source should I pick — Lightning or on-chain?

If your Lightning balance covers the deposit + ~3.5 % fees,
**Lightning** is the cheaper and faster option (one swap, ~10
minutes end-to-end). Use **on-chain** when you don't have enough
on Lightning — the wizard adds a leading submarine swap to move
your on-chain sats into Lightning first, then continues as
normal. The total time is ~20 minutes and the fees are about 0.5
percentage-points higher.

### Can I cancel an on-chain-source deposit after it starts?

Only before we broadcast the on-chain funding transaction. Once
your sats are en route to Boltz's lockup address, cancel is not
available — you have to wait for the swap to either complete
(LN balance bumps, then the flow continues normally) or for
Boltz to refund automatically after the timeout block. The
wizard will show **Refunded** in either case and your on-chain
sats are recovered.

### Is this the same as the Anonymize feature?

No. Anonymize is designed to make a transaction's destination hard
to link to its source for a chain analyst. Braiins Deposit doesn't
hide anything — Braiins knows exactly who you are and the address
on your Braiins account is public to them. The only goal here is
to produce a transaction shape that Braiins' anti-fraud algorithm
clears automatically.

### Why does it cost more than a direct send?

A direct send is one Bitcoin transaction; Braiins Deposit involves a
Lightning payment plus a Boltz cooperative claim plus the final
on-chain send. The conversion fee (~0.5% on the invoice amount) and
the extra on-chain footprint add up to a few thousand sats. The
trade-off is that the deposit clears Braiins immediately instead of
sitting in manual review for hours.

### What if I'm only depositing once a month — should I bother?

If a same-day deposit is important to you, yes. If it doesn't matter
when your funds become available, the regular Send-on-chain flow
costs less and works just as well — Braiins just takes longer to
credit you.

### What if the on-chain transaction doesn't confirm?

The wizard keeps polling. If the send transaction has been stuck for
more than a day (144 blocks) we surface a warning on the session
detail, but we never auto-fail the session — the bitcoin in the
transaction is still yours. You can wait for the next mempool dip,
or use the **Retry send** button (when the session is in a failed
state) to re-attempt with the current fee estimate.

### What if Boltz is unreachable?

Boltz is routed through Tor by default. Network blips are absorbed
automatically — the session stays in *Working...* and tries again
on the next tick. If Boltz stays unreachable for a long time the
session detail shows a warning but the session is recoverable as
soon as Boltz comes back.

### Can I open the wizard from another device?

Each session is server-side, so yes — open the dashboard from any
authenticated device and an in-flight session reopens to its
progress view automatically. Each dashboard supports one in-flight
session at a time; starting a new one while another is running
reopens the existing session's progress view.

### What if my configured mempool explorer is down?

The 📋 Copy button always works — paste the transaction ID into any
public block explorer (mempool.space, blockstream.info, etc.) to
look it up.

### What if I lose Lightning balance partway through?

The Lightning payment is the first step. If it fails before reaching
Boltz, no funds move and the session ends in *failed* — your
balance is unchanged. If Boltz settles but later steps fail, your
sats are in your wallet as a fresh Bitcoin transaction; use **Retry
send** to send them to Braiins, or use the standard *Send Bitcoin*
flow to send them anywhere else.

---

### Why does the amount I'm asked to send differ from the deposit
amount?

The "amount to send" surfaced on the await-funds screen is the
**intake amount** — what you pay from your other wallet. The
**deposit amount** is what arrives at Braiins. The difference is
the sum of:

* the Boltz conversion fee (~0.5% of the invoice),
* Lightning routing fees (~3% headroom — the actual paid fee is
  usually much less, but enough has to be reserved upfront for the
  payment to succeed),
* on-chain miner fees for the final send to Braiins, and
* (External on-chain only) the submarine-swap fee for the
  on-chain → Lightning conversion.

The wizard's Step-2 Fee details panel breaks each component down so
you can see exactly where the difference goes.

### Can I send less and add more later? (External on-chain)

Yes. The wizard treats multiple deposits to the same address as
additive: each confirmed deposit bumps the *received* total, and as
soon as the cumulative amount reaches the required total, the
session proceeds. Send a small test deposit first if you want — it
won't be lost; just send the remainder afterwards.

This only applies to **External on-chain**. Lightning invoices are
exact-amount (a wallet that tries to pay less than the invoice
amount is rejected), so external Lightning sessions don't need the
top-up flow.

### What if my external wallet doesn't support BOLT 11?

Use the **External on-chain** option instead. Every modern Bitcoin
wallet supports sending to an address via BIP-21. The flow is a
little slower (you wait ~10–30 minutes for the deposit to confirm
before the swap-and-send starts) but the result is identical.

### What if my invoice expires before I pay?

Click **Generate new invoice** on the await-funds screen. The wizard
disposes the old invoice on Boltz's side and mints a fresh one
against current fees. The old invoice can no longer be paid; the new
one is what you scan or paste into your wallet.

The button stays disabled until the countdown is below 5 minutes (or
already at zero) — this prevents accidentally regenerating the
invoice while you're in the middle of paying it from your other
wallet.

### What does "External Lightning" actually do under the hood?

We initiate a Boltz reverse swap with your fresh Bitcoin address as
the on-chain destination and the deposit's intake amount as the
invoice. We do **not** pay the invoice from our wallet — instead we
surface Boltz's invoice directly to you. When you pay it from your
other wallet, Boltz settles the Lightning side and broadcasts the
on-chain payout to our address. From that point the flow is identical
to a Lightning-source deposit: we wait for the claim to confirm, then
send the round amount to Braiins.

This means **the wallet never custodies your Lightning funds** for
external Lightning sessions — your payment goes straight to Boltz.
Refunds, when needed, are handled by Boltz returning the Lightning
HTLC to your wallet automatically.

---

## Configuration knobs

The wizard ships enabled. The full set of operator-tuneable knobs
is in `app/core/config.py` (search for `braiins_deposit_*`). The
most commonly changed:

| Var | Default | Description |
|---|---|---|
| `BRAIINS_DEPOSIT_ENABLED` | `true` | Hides the Braiins Deposit tab and 404s the API when set to `false`. |
| `BRAIINS_DEPOSIT_CONFIRMATIONS_BEFORE_SEND` | `1` | Confirmations required on the fresh transaction before we send to Braiins. Raise to 2–3 for paranoid setups. |
| `BRAIINS_DEPOSIT_SEND_FEE_PRIORITY` | `"medium"` | Default fee priority for the send to Braiins — `low`, `medium`, or `high`. |
| `BRAIINS_DEPOSIT_SAFETY_BUFFER_SATS` | `1000` | Extra headroom on the Boltz invoice amount to absorb fee drift. |
| `BRAIINS_DEPOSIT_EXT_ENABLED` | `true` | Hides the External Source radios when set to `false`. Self-sourced flows are unaffected. |
| `BRAIINS_DEPOSIT_EXT_LN_INVOICE_TTL_S` | `3600` | Display ceiling for the ext-LN invoice countdown (1 hour). |
| `BRAIINS_DEPOSIT_EXT_OC_CONFIRMATIONS` | `1` | Confirmations required on a deposit to the ext intake address before it counts. |
| `BRAIINS_DEPOSIT_EXT_OC_FUNDS_TTL_S` | `86400` | Soft TTL on ext-OC waiting state (24 h). After this we surface a non-fatal "no activity" warning but never auto-cancel. |
| `BRAIINS_DEPOSIT_EXT_OC_REFUND_FEE_PRIORITY` | `"medium"` | Fee priority for ext-OC refund sends. |
