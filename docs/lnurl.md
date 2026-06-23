# LNURL-pay & Lightning Address support

The dashboard's **Send Lightning** dialog accepts three input formats:

1. A pasted `lnbc...` BOLT11 invoice (existing path).
2. A **Lightning Address** of the form `user@wallet.example` (LUD-16).
3. A bech32 **LNURL-pay** string (LUD-01 / LUD-06 / LUD-12).

Lightning Addresses and LNURLs both resolve to an LNURL-pay endpoint;
the dashboard shows a recipient card (image + domain + description +
amount range), lets the operator pick an amount (and optional comment
when the recipient supports LUD-12), then asks the recipient for a
BOLT11 invoice and feeds that into the existing pay flow.

## Why server-side resolution?

The LNURL HTTP fetches happen **on the dashboard server**, not in the
browser. Two reasons:

1. **Tor egress.** A node operator running LND over Tor wants the
   recipient to never see the dashboard's clearnet IP. The server
   reuses the same Tor proxy that LND uses (see `LNURL_FORCE_TOR`
   below).
2. **Description-hash binding.** LUD-06 binds the recipient's BOLT11
   to `sha256(metadata)`. We have to keep the original `metadata`
   string around between resolve and pay so we can verify the binding;
   the safest place is the server.

Both endpoints (`/dashboard/api/lnurl/resolve` and `/dashboard/api/lnurl/invoice`)
require an authenticated dashboard session and CSRF token; they share
the same protections as `/pay`.

## Security posture

| Concern | Mitigation |
| --- | --- |
| **SSRF** | Outbound requests refuse private/loopback/link-local/multicast hosts. Toggle: `LNURL_ALLOW_PRIVATE_HOSTS=true` (regtest only). |
| **HTTP downgrade** | Plain `http://` rejected for clearnet. `.onion` may use `http://` (Tor encrypts). Toggle: `LNURL_ALLOW_HTTP=true` (testing only). |
| **Redirect-based SSRF** | `follow_redirects=False`. Recipients must serve their LNURL-pay endpoint at the URL they advertised. |
| **Memory exhaustion** | Response body cap `LNURL_MAX_RESPONSE_BYTES=100000`; metadata cap 32 KB. |
| **Description-hash forgery** | Server recomputes `sha256(metadata)` and rejects the recipient's BOLT11 if it doesn't match. |
| **Amount tampering** | Recipient's BOLT11 must encode exactly the requested amount in millisats. |
| **Stale invoice** | We refuse a BOLT11 with less than 60 seconds left until expiry. |
| **Phishing via success_action** | `successAction.url` is rendered as **non-clickable monospace text** with a copy button — never as an anchor. AES variants are not decrypted. |
| **Image-data XSS** | Inline images allowed only for `image/png` and `image/jpeg`; SVG is dropped. |
| **Comment forwarding** | Length is hard-clamped to `min(commentAllowed, 280)` chars. Comments are logged to audit (truncated to 200 chars). |

## Egress / Tor settings

`LNURL_FORCE_TOR` is tri-state:

| Value | Behaviour |
| --- | --- |
| `auto` (default) | Use the Tor SOCKS proxy (`LND_TOR_PROXY`) iff `LND_REST_URL` is a `.onion` address. The reasoning: an operator who runs LND over Tor almost certainly wants the same egress posture for LNURL fetches. |
| `true` | Always route LNURL HTTP through the Tor proxy. Required for full sender-IP privacy on a clearnet LND deployment. |
| `false` | Never force Tor for clearnet hosts. `.onion` recipients still go through the Tor proxy. |

If a `.onion` recipient is requested but `LND_TOR_PROXY` is empty, the
request is refused before any network call.

## Resolve / pay flow

```
[ user pastes user@host or LNURL.. ]
                │
                ▼
  POST /dashboard/api/lnurl/resolve   ── audit: lnurl_resolve
                │
                │ recipient card (image, description, range, comment box)
                ▼
  POST /dashboard/api/lnurl/invoice   ── audit: lnurl_request_invoice
                │  ↑ 30 s idempotency cache on (handle, amount, comment)
                │
                ▼
   existing /dashboard/api/decode  → review screen → /pay
                                                 ── audit: pay_invoice
```

The opaque 32-character handle returned by `/lnurl/resolve` ties the
follow-up `/lnurl/invoice` call back to the cached LNURL params. The
handle TTL is `LNURL_HANDLE_TTL_SECONDS` (default 300 s). After the
TTL expires the handle is forgotten and the user must re-resolve.

The 30 s invoice cache prevents an accidental double-click on the
**Continue** button from causing the recipient to issue (and us to
attempt to pay) two distinct invoices. It is keyed on
`(handle, amount_sats, comment)` and only caches successful responses,
so a transient recipient error can be retried immediately.

## Audit log

Every LNURL operation produces a row in the audit log:

| `action` | Details |
| --- | --- |
| `lnurl_resolve` | `source_kind`, `callback_host` (no metadata, no LN address local-part) |
| `lnurl_request_invoice` | `handle`, `payment_hash`, `amount_sats`, comment (truncated to 200 chars), `cache_hit` |
| `pay_invoice` | unchanged — same end-to-end audit row as for any BOLT11 payment |

Together this gives an operator a full trail per LNURL payment
without duplicating data and without storing the (untrusted)
recipient metadata blob.

## Not implemented in v1

- **LUD-18 payerData** (sending KYC name/email to the recipient).
- **AES success_action decryption** — the encrypted-receipt placeholder is shown.
- **Static internal QR for LNURL-withdraw** — withdraw URLs are rejected with a clear "withdraw not supported" error.
- **Caching of resolved LNURL params** across requests — every resolve hits the wire.
