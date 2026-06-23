# Backing up the wallet's encryption keys

Agent Wallet keeps a small handful of operator-managed secrets that
are catastrophic to lose. This page walks through *which* keys
matter, *why* they matter, and *how* to back them up so you can
recover from disk loss, container reset, or accidental wipe.

> **TL;DR:** Two keys — `SECRET_KEY` and (only if you enabled the
> Liquid round-trip) `ANONYMIZE_LIQUID_SEED_FERNET` — must be backed
> up to offline storage the first time you start the wallet. Both
> are written to a small, self-describing `*-backup-<timestamp>.txt`
> file next to your `.env` whenever `start.sh` generates them. Move
> those files to a USB stick, password manager, or paper backup,
> then delete the on-disk copy.

---

## 1. `SECRET_KEY` — the master encryption key

### What it protects

`SECRET_KEY` is the master input to PBKDF2-HMAC-SHA256, which derives
the Fernet key used to encrypt at-rest secrets in the wallet's
database:

- Boltz swap claim and refund private keys
- Boltz swap preimages (the hashlock secret for reverse swaps)
- Per-session Liquid blinding seeds (encrypted again with the
  Liquid master, see §2)
- Operator API keys and a handful of integration tokens

If `SECRET_KEY` is lost while a Boltz swap is in flight:

- **Reverse swaps (Lightning → on-chain).** The wallet cannot
  cooperatively claim the lockup, cannot script-path claim it after
  timeout, and cannot decrypt the preimage. Boltz will eventually
  refund the on-chain lockup, and your Lightning HTLC will be
  cancelled — so you don't lose Lightning funds, but in-flight
  swaps will all fail.
- **Submarine swaps (on-chain → Lightning).** The wallet cannot
  cooperatively refund a stuck swap, and cannot run the unilateral
  refund script after timeout. Funds are *eventually* recoverable
  with significant operator intervention (the lockup-tx hex and
  swap tree are stored unencrypted), but the practical outcome is
  the same: the wallet's automated recovery paths break.
- **Operator API keys.** Operator-signed Anonymize sessions need
  the per-operator credential to talk to the right Boltz instance.
  Losing the key forces a fresh registration round-trip per
  operator.

### How `start.sh` writes the backup

The first time the wallet starts without a `SECRET_KEY` in `.env`
the launcher generates one and writes a **narrow** backup file:

```
secret-key-backup-<timestamp>.txt   (mode 0600)
```

It sits next to `.env`. Its contents are deliberately minimal — only
the key material, with a self-describing header:

```
# Agent Wallet — SECRET_KEY backup
# Generated: 2026-05-25T18:04:12Z
# PURPOSE: required to decrypt Boltz swap private keys / preimages
# at rest in the database. Without this value, in-flight swaps
# cannot be cooperatively claimed or refunded.
#
# STORE THIS OFFLINE (USB, paper, password manager).
# This file does NOT contain LND macaroons, API tokens, or other
# operational secrets — those live in .env and have their own
# lifecycle.

SECRET_KEY=<value>
SECRET_KEY_PREVIOUS=<value-if-rotating>
```

`start.sh` then prompts you to acknowledge the backup:

```
⚠ A SECRET_KEY backup was written to
  secret-key-backup-<timestamp>.txt (mode 0600).
  Move it to offline storage now (USB / paper / password
  manager). Press ENTER once you have backed up the file…
```

Press ENTER **only after** you have actually copied the file
somewhere durable. Then delete the on-disk copy.

### Why not just back up `.env`?

`.env` contains far more than `SECRET_KEY`: the LND admin macaroon,
dashboard tokens, Boltz-gateway tokens, Tor hidden-service private
keys (when self-managed), webhook URLs, and any third-party API
credentials you've added. Backing up `.env` to a USB stick or cloud
drive is a much larger blast radius than backing up just the
encryption key.

The narrow backup file is intentionally tiny — it fits on a printout
or a single password-manager entry — so it's practical to store
offline.

### Restoring

If you need to redeploy the wallet against the same database (e.g.
disk loss, migrating containers, recovering from a botched upgrade):

1. Install the wallet on the new host as normal.
2. Edit `.env` and paste the backed-up `SECRET_KEY=…` line *before*
   the first `start.sh` run.
3. Start the wallet. It will pick up the existing `SECRET_KEY`,
   skip generation, and successfully decrypt all existing rows.

If the database is empty (fresh install with no in-flight swaps),
restoring is unnecessary — let `start.sh` generate a new key.

### Rotation

The wallet supports zero-downtime rotation via `SECRET_KEY_PREVIOUS`:

1. Generate a new key offline: `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
2. Edit `.env`:
   - Set `SECRET_KEY_PREVIOUS=<the old SECRET_KEY value>`.
   - Set `SECRET_KEY=<the new value>`.
3. Restart the wallet. New writes are encrypted with the new key;
   reads transparently fall back to `SECRET_KEY_PREVIOUS` for any
   row still encrypted under the old key.
4. After a few weeks (long enough that any in-flight swap that
   started before rotation has fully terminated), remove
   `SECRET_KEY_PREVIOUS` from `.env`. The next process restart
   will then refuse to decrypt any row still under the old key —
   if that happens, restore `SECRET_KEY_PREVIOUS` and investigate
   before proceeding.

Back up the new `SECRET_KEY` immediately, exactly as you did the
original. The narrow backup file approach applies to rotation too.

### Re-anchor the audit hash chain after rotation

The audit log's tamper-evident hash chain is keyed from `SECRET_KEY`
(and, unlike field encryption, does **not** fall back to
`SECRET_KEY_PREVIOUS`). So immediately after a rotation
`GET /v1/admin/audit-log/verify` will report the chain as broken, and
the daily retention prune will pause rather than delete over a chain it
cannot verify. This is expected — not evidence of tampering.

To resume normal operation, re-anchor the chain once under the new key:
`POST /v1/admin/audit-log/reanchor` (admin key), or click **Re-anchor**
in the dashboard's Audit Log viewer. The re-anchor recomputes every row
under the current key and records its own `audit_chain_reanchor` entry
(actor + the pre-re-anchor verdict), so the recovery is itself part of
the tamper-evident record. The same step applies after a partial
database restore that leaves the chain inconsistent.

### What happens if the key is lost mid-swap

The in-flight swap surfaces a *Failed* / *Recovery needed* banner
on the dashboard (see "Boltz recovery" page). The recovery actions
that depend on at-rest secrets — cooperative claim, cooperative
refund, unilateral refund — all return clear errors stating the
encrypted material cannot be decrypted. You will need to wait for
the swap to time out naturally and then manually reconcile the
on-chain state with the operator. Plan to lose any in-flight swap
fees in this scenario.

---

## 2. `ANONYMIZE_LIQUID_SEED_FERNET` — the Liquid blinding master

> Only relevant if you answered `yes` to "Enable Liquid round-trip?"
> in the start wizard (or set `ENABLE_LIQUID=true` in `.env`).
> LN-only deployments can skip this section.

### What it protects

`ANONYMIZE_LIQUID_SEED_FERNET` is a second, separate master Fernet
key that encrypts the per-Anonymize-session Liquid blinding seed.
The per-session seed, in turn, derives (via SLIP-77) the blinding
keypair that lets the wallet unblind its Liquid lockup outputs and
construct claim or refund transactions on the Liquid network.

The key chain is:

```
ANONYMIZE_LIQUID_SEED_FERNET   (env, operator-managed)
   ↓ decrypts
session.liquid_blinding_seed_enc  (per-row, DB)
   ↓ SLIP-77 derives
per-session blinding privkey      (in memory only)
   ↓ unblinds
L-BTC lockup outputs              (on-chain)
```

If the master is lost:

- The wallet cannot decrypt any session's blinding seed → cannot
  derive the per-session blinding key → cannot unblind L-BTC
  outputs → cannot construct claim or cooperative refund.
- Funds remain safe in the long run — Boltz refunds the L-BTC
  lockup at the swap's `timeout_block_height` automatically — but
  **every in-flight Liquid session blocks until Boltz's timeout
  fires**. Liquid blocks are 60 seconds, so the wait is typically
  minutes to a few hours depending on the operator's
  `timeout_block_delta`. No funds are at risk; only liveness is.

### How `start.sh` writes the backup

When the start wizard generates a fresh `ANONYMIZE_LIQUID_SEED_FERNET`
(i.e. you opted into Liquid and no existing value was present), it
writes:

```
liquid-seed-backup-<timestamp>.txt   (mode 0600)
```

with the same self-describing header pattern as the `SECRET_KEY`
backup, containing only the Liquid master:

```
# Agent Wallet — ANONYMIZE_LIQUID_SEED_FERNET backup
# Generated: 2026-05-25T18:04:12Z
# PURPOSE: required to decrypt per-session Liquid blinding seeds.
# Without this value, in-flight Liquid hops cannot be claimed or
# cooperatively refunded; Boltz will refund the lockup at the
# Liquid timeout block height (typically minutes to a few hours).
#
# STORE THIS OFFLINE — same handling as SECRET_KEY.

ANONYMIZE_LIQUID_SEED_FERNET=<value>
```

The wizard prompts for acknowledgement the same way it does for
`SECRET_KEY`. Back up both files together — losing one but keeping
the other still breaks half your recovery surface.

### Restoring + rotating

Restoration is identical to `SECRET_KEY`: paste the backed-up value
into `.env` before the first start, then proceed.

Rotation is **not** supported via a parallel `_PREVIOUS` slot today.
The Liquid blinding chain is per-session and short-lived — any given
session terminates within the operator's `timeout_block_delta`
window — so the operational guidance is:

1. Wait until no Anonymize sessions are in the `awaiting_liquid_dwell`
   or `hopping` states.
2. Generate a fresh `ANONYMIZE_LIQUID_SEED_FERNET`.
3. Replace the value in `.env`.
4. Restart the wallet.

New sessions encrypt under the new master. Already-completed sessions
do not need to be decrypted again.

---

## 3. Backup checklist

When you finish the start wizard, you should have:

- [ ] `secret-key-backup-<timestamp>.txt` — copied to durable offline
      storage, then deleted from the wallet host.
- [ ] `liquid-seed-backup-<timestamp>.txt` (Liquid users only) —
      same handling.
- [ ] (Optional) A full backup of the wallet database itself
      (`agent_wallet.db` or your configured database file). The
      encryption keys above are only useful in combination with the
      encrypted rows; the database is the rows.

The two backup files together are tiny (a few hundred bytes). Treat
them like you would your Lightning channel seed: store at least two
copies in physically separate locations, and verify periodically
that you can still read them.
