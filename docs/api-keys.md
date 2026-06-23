# Managing API keys

API keys are minted, rotated, and revoked from the dashboard. Sign
in, click the **⚙ Settings** menu in the top-right corner, and pick
**API Keys**.

The same operations are also available headlessly via
`/api/v1/admin/api-keys` for scripted workflows; the dashboard is a
thin proxy over those endpoints (see [`app/api/admin.py`](../app/api/admin.py)
and [`app/services/api_key_service.py`](../app/services/api_key_service.py)).

---

## Inventory at a glance

The modal lists every key — active, disabled, expired, and revoked —
with a status pill:

| Pill        | Meaning                                                          |
| ----------- | ---------------------------------------------------------------- |
| `active`    | usable; not expired and not soft-deleted                         |
| `expiring`  | active, but ≤14 days from `expires_at` — rotate soon             |
| `disabled`  | `is_active = false`; can be re-enabled in place                  |
| `expired`   | past `expires_at`; treated as inactive by the auth middleware    |
| `revoked`   | soft-deleted; key no longer authenticates                        |

Use the filter dropdown and the search box at the top of the modal
to narrow by status or name.

---

## Creating a key

1. Click **+ New Key**.
2. Pick a name (1–128 chars), a scope (**Read-only** or **Admin**),
   and a TTL in days (clamped to `api_key_max_ttl_days`).
3. Click **Create**.
4. The plaintext key is shown **exactly once** with a copy button.
   Store it in your secret manager before clicking **I've saved it**.

> The key is held only in the browser tab's component state until
> you confirm capture. It is never written to `localStorage`. If you
> use the copy button, the dashboard schedules a clipboard wipe 60
> seconds later (with a visible countdown) — the same pattern
> password managers use.

---

## Rotating a key

**Rotate** mints a replacement with the same scope and a fresh TTL,
then waits for you to confirm capture before disabling the original.
The old key keeps working through the entire flow, so an agent can
swap keys without downtime.

1. Click the rotate icon on the key's row.
2. Capture the new plaintext (same one-time view as creation).
3. Click **I've saved it & disable old** to revoke the predecessor.
   Cancelling instead revokes the freshly-minted replacement so you
   are not left with two live admin keys by mistake.

If you close the tab between steps the old key is still active and
the replacement appears in the inventory tagged `(rotated)` — finish
the swap manually.

---

## Disable / re-enable, revoke, purge

- **Disable** (pause icon) flips `is_active = false`. The key still
  exists and can be turned back on in place.
- **Toggle scope** (shield icon) promotes a read-only key to admin or
  demotes an admin key to read-only. Promotion requires an explicit
  confirmation. The dashboard refuses to demote the only remaining
  active admin key.
- **Revoke** (trash icon) is a soft delete. The row moves to the
  `revoked` status and the key stops authenticating immediately. The
  audit-log row remains intact so the chain is preserved.
- **Purge** is only offered on revoked rows once
  `audit_log_retention_days` has elapsed since the soft delete. Until
  then the button is disabled with a tooltip showing the eligibility
  date. Purging removes the row entirely and is irreversible.

---

## Bootstrap key warning

If the inventory contains exactly one active admin key, the modal
shows a callout asking you to mint a scoped key per agent and rotate
the bootstrap key out. The **Revoke** and **Disable** controls on the
last active admin are greyed out — you cannot lock yourself out.

---

## Audit log

The same settings menu has an **Audit Log** entry. It surfaces every
key mutation (and every other auditable action) with the originating
IP, supports filtering by action / key name / time range, and exposes
a **Verify chain** button that recomputes the hash chain server-side
and reports the first broken row if any tampering is detected.

Dashboard-initiated key mutations are attributed to the
`__dashboard__` sentinel actor in the audit log — distinct from real
API keys so an operator can tell at a glance whether a change came
from the UI or from a scripted admin call.
