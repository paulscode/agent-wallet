# Operator diversity for on-chain anonymize sessions

> **TL;DR.** The wallet's bundled `operators.json` ships three operators: canonical Boltz, Middleway, and Eldamar. The default chain puts canonical Boltz on the **reverse** leg (where the destination address is visible) and Middleway → Eldamar on the **submarine** leg with a pre-funding fallback chain. If both alts are unreachable at quote time, the wizard surfaces a consent modal offering single-operator-Boltz at the cost of capping the tier at `moderate`. This document explains the threat-model rationale and how to vet a third-party operator if you want to expand the chain.

## Default operator assignment

The most-vetted operator (canonical Boltz) sits on the reverse leg because **the reverse leg is where the destination address is exposed** — the secret the user is trying to keep private. The submarine leg sees only the funding UTXO, which the threat model assumes is already identity-linked.

The default chain (when none of `ANONYMIZE_SUBMARINE_OPERATOR_PRIMARY`, `_SECONDARY`, or `ANONYMIZE_REVERSE_OPERATOR` are set):

| Slot | Operator | Notes |
|---|---|---|
| Submarine primary | `middleway` | Picked first; tried via Tor probe at quote time |
| Submarine secondary | `eldamar` | Tried when primary is unreachable, capacity-skipped, or degraded |
| Reverse | `boltz-canonical` | Always; capacity is high enough to also serve as the single-operator-fallback target |

If both alts are unreachable at quote time, the wizard surfaces a modal asking the user whether to proceed with single-operator-Boltz (capped at moderate tier) or try again later. The user's consent is **explicit and per-session** — never persisted, never implicitly granted.

## Why two operators matter

An on-chain anonymize session has two halves:

1. **Submarine swap.** Your on-chain BTC funds a lockup address controlled by Boltz operator A; operator A pays you Lightning sats.
2. **Reverse swap.** You pay Lightning sats to operator B; operator B sends BTC to your destination address.

If operator A and operator B are the same entity, their logs contain both halves of the mix:

- The input UTXO that funded the submarine lockup (visible because the funding tx spent your UTXO into their address).
- The destination address (visible because the reverse-swap request carries `claimAddress`).
- Approximate timing, the (binned) amount, and a network-level fingerprint of the requests.

Two genuinely independent operators each only see one half. Neither alone can correlate your input UTXO with your destination address without colluding with the other.

This is **distinct-operator splitting**, and it's the dominant non-Lightning correlation defense the wallet relies on for `strong`-tier on-chain sessions.

## What's still mitigated when you only have one operator

The wallet's other defenses don't go away. With a single operator configured, the following are still active on every on-chain session:

| Defense | Effect |
|---|---|
| Tor stream isolation | Submarine and reverse legs run on different SOCKS listeners with fresh circuits. The operator can't link the two requests by Tor circuit identity. |
| Pinned-JA4 HTTP client | Both legs share an identical, fingerprint-pinned TLS handshake. The TLS layer doesn't differentiate the two calls. |
| Per-call internal-ID strip | Neither leg's request body carries session IDs, quote tokens, or other wallet-internal identifiers. |
| Amount binning | Both legs use a bin amount, not your exact request, so amount-based matching has many candidates. |
| Inter-leg delay 6–48 h | The two legs are separated by a randomized multi-hour gap, weakening timing correlation. |
| Priv-channel hop | Lightning-side traffic routes through a fresh throwaway private channel, hiding your primary Lightning node identity from the operator. |
| MPP fragmentation | Lightning payments split across paths weaken any "this LN node paid me" signal. |
| Liquid round-trip hop | Interposes a Confidential-Transactions-blinded L-BTC dwell between the two legs (when `ANONYMIZE_LIQUID_ENABLED=true`). |
| Multi-output sessions | Lets you split a single source into N outputs with independent timing; breaks the 1:1 input:output relationship. |

So a single-operator session with all of the above enabled is meaningfully better than no mixing — an attacker has to actively correlate amounts, timings, and destination addresses against the operator's own volume to break the link. The operator has the data to do this; the wallet's job is to make the work hard and the link probabilistic.

## What the wallet can't defend against in software

Two things genuinely require operator diversity:

1. **A logging-then-correlating operator.** If Boltz (or any single operator) chooses to log both halves and run a correlation pipeline on its own data, no in-wallet mitigation breaks the link. The wallet can raise the noise floor but can't make the data unavailable.
2. **A subpoenaed or compromised operator.** Logs the operator currently keeps for legitimate operational reasons (anti-abuse, support tickets, fee accounting) become correlation evidence if a future legal compulsion or breach exposes them.

For both of these, **two independent operators** is the only defense — neither alone has the full picture.

## How the wallet surfaces this trade-off

- **Wizard banner.** When you select an on-chain source (`onchain-self` or `ext-onchain`) and the deployment is single-operator, the wizard shows an advisory banner with a "Learn more" link pointing here.
- **Tier cap.** The scorer caps single-operator on-chain sessions at `moderate` via the existing stacked caps (`no distinct operators`, `no Liquid round-trip`, `<3 registered operators`). The review step shows the cap reason verbatim.
- **No silent downgrade.** Configuring `BOLTZ_SUBMARINE_ONION_URL` and `BOLTZ_REVERSE_ONION_URL` to two distinct onions lifts the cap and removes the banner. The wizard re-renders the tier badge without anyone needing to re-deploy.

## How to find a second operator

Independent Boltz-protocol operators exist; the ecosystem is small but real. As of this writing, the [SwapMarket project](https://github.com/SwapMarket/swapmarket.github.io) maintains a curated list of Boltz-compatible providers in [`src/configs/mainnet.ts`](https://github.com/SwapMarket/swapmarket.github.io/blob/main/src/configs/mainnet.ts). The canonical Boltz operator is the most-trusted entry; community operators vary in maturity.

### Diligence checklist for a second operator

Before pointing `BOLTZ_REVERSE_ONION_URL` (or `BOLTZ_SUBMARINE_ONION_URL`) at a non-canonical operator, verify:

1. **Onion authenticity.** Cross-reference the onion address against the operator's own published documentation (their GitHub README, social media, or operator-controlled domain). Don't rely on a single third-party source.
2. **Lightning capacity.** The operator's Lightning node needs outbound liquidity in the bin-amount range you'll be swapping. Look up their node pubkey on [amboss.space](https://amboss.space), [1ml.com](https://1ml.com), or [lightningnetwork.plus](https://lightningnetwork.plus) and check capacity + channel count.
3. **Operational contactability.** If a swap stalls, you (or your users) need to reach the operator. Verify their contact channel (email, Matrix, Nostr, or web form) has been responsive in the last 30 days. A dead contact link is a leading indicator of a hobby project that may go silent.
4. **Backend version.** Hit `/v2/version` (or the operator's equivalent) and confirm they're running a recent `boltz-backend` release. Aging deployments are more likely to hit bugs the canonical Boltz operator has already fixed.
5. **Uptime history.** A status page or third-party uptime monitor is ideal. Failing that, ask the operator directly for their last-30-day uptime numbers.
6. **Self-attested 24h volume.** This isn't load-bearing today (the wallet's `attested_min_24h_volume_satoshis` field requires a curated registry to use), but an operator who can name a number suggests they're paying attention.

### Run your own second operator

The most defensible second operator is one you control. The Boltz backend is open source ([github.com/BoltzExchange/boltz-backend](https://github.com/BoltzExchange/boltz-backend)) and ships as Docker images. Running your own:

- Pin a small LND node with a couple of channels (~500k-1M sat outbound liquidity to start).
- Deploy `boltz-backend` against that LND node.
- Expose its API on a fresh onion service.
- Point `BOLTZ_REVERSE_ONION_URL` (or submarine) at that onion.

The user-facing trade-off is that the bin amounts your wizard accepts are capped by your second operator's liquidity. Your own operator is a known-good second operator with full transparency on logging posture (you decide what gets kept).

## Operator registry signing

When you ship a curated multi-operator registry, the wallet's signed-load path verifies a maintainer-signed detached signature over `operators.json` before admitting the entries. The wallet supports two signature formats:

| Format | Sig file | Tool | Pubkey location |
|---|---|---|---|
| **OpenPGP** (RSA or EdDSA) | `operators.sig.asc` | `gpg --armor --detach-sign --local-user <id>` | Bundled in-repo at `app/services/anonymize/maintainer.asc` |
| **Raw ed25519** | `operators.sig` | `signify`, `age`, `openssl pkeyutl`, etc. | Pinned by fingerprint in `ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS` |

The dispatcher auto-detects format based on the signature file contents — an armored `.sig.asc` routes to system `gpg` (which the wallet invokes in an isolated keyring built from `maintainer.asc`); a raw 64-byte `.sig` routes to in-process ed25519 verification. Both formats can be pinned simultaneously in `ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS` (comma-separated) during a rotation overlap.

The wallet imports the bundled `maintainer.asc` into an **isolated GPG keyring** at every verify-time call, so verification does NOT depend on whatever's in the deployment host's `~/.gnupg`. A host with a corrupted or attacker-poisoned default keyring cannot influence the wallet's decision.

### Re-signing or replacing the maintainer key

For a single-machine signing flow, the included helper script automates everything:

```sh
./scripts/sign_operator_registry.sh --sign <your-gpg-key-id>
# → bootstraps operators.json from .example, computes canonical bytes,
#   runs gpg --armor --detach-sign, places operators.sig.asc, verifies.
```

Forks that want to replace the bundled maintainer key:

1. Replace `app/services/anonymize/maintainer.asc` with the fork's own GPG pubkey (`gpg --armor --export <id> > maintainer.asc`).
2. Update `ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS` in `.env.example` + `start.sh` to match the new key.
3. Re-sign `operators.json` with the new key using the script above.

Rotation works the same way: add the new fingerprint alongside the old one in `ANONYMIZE_REGISTRY_RELEASE_KEY_FINGERPRINTS` (both validate during the overlap window), re-sign, ship, then drop the old fingerprint in a follow-up release.

## Reference

- [`anonymize.md`](anonymize.md) — feature overview, score tiers, runbook.
- [SwapMarket repository](https://github.com/SwapMarket/swapmarket.github.io) — community-curated list of Boltz-compatible providers.
- [Boltz API documentation](https://api.docs.boltz.exchange/) — authoritative Boltz endpoint reference.
