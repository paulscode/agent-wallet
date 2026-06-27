# Lightning peers that accept small (~150k sat) channels

This is a vetted list of **15 lightning routing peers** confirmed to accept channel opens
at ~150,000 sats — well below the 1M-sat-plus floor that most
established routing nodes require. Useful if you're spinning up a small
LND node, opening your first inbound channel, or building out
diversity without locking up large amounts of on-chain BTC.

Every peer below was **empirically tested**: I connected to them, sent
a real 150,000 sat funding transaction, and observed the channel accept.
The data on fees, channel counts, and outbound enable rates is read
straight from public gossip. Channel handles you, the reader, can open
with these peers right now (subject to the usual gossip-staleness
caveats — see [Caveats](#caveats) below).

> **Snapshot date.** All numbers below are current as of **2026-06-27**.
> Lightning is a living network; peers add/drop channels, rotate ports,
> retune fees, and occasionally go offline. Reverify before opening if
> the dates here are more than a couple of weeks old.

## Why this list exists

The Lightning Network's biggest routing operators — LNBiG, River
Financial, ACINQ, lnmarkets.com, OKX, IBEX, etc. — typically reject
channel opens below 400,000 - 1,000,000 sats. That's a real barrier for:

- **New operators** standing up their first node who don't want to
  immediately lock up the equivalent of $500+ in a single inbound
  channel.
- **Small/mobile wallets** opening direct inbound channels for receive
  liquidity.
- **Existing operators** building out peer diversity (geographic, AS,
  software) with a smaller-than-headline-capacity budget.

The 15 peers documented here all accepted a 150k sat open. Most are
mid-sized routing nodes that **actively maintain channels with popular
large hubs**, so a channel with one of them gives you incoming-routing
access into the broader network without requiring you to open directly
with the big operators.

## How to read this list

Entries are ordered **cheapest-typical-receive-fee first**. Every peer
on this list passed two empirical checks — they accepted a small open,
and gossip shows they peer with multiple top-tier routing hubs — so the
remaining axis you're choosing on is fee. The plain-English summary in
each entry captures the trade-offs.

Labels used:

| Fee tier (median `fee_rate_milli_msat` on the peer's outgoing edges) | Label |
|---:|---|
| < 50 ppm | **Very low fees** |
| 50 – 500 ppm | **Low fees** |
| 500 – 2,000 ppm | **Moderate fees** |
| > 2,000 ppm | **High fees** |

| Top-20-hub connections | Label |
|---:|---|
| ≥ 30 | **Highly connected** |
| 20 – 29 | **Well connected** |
| 10 – 19 | **Adequately connected** |
| < 10 | **Limited connectivity** |

**Outbound enabled ratio**: the share of the peer's own gossiped
channels on which they currently have outbound forwarding enabled.
A healthy router sits at 95%+. Anything below ~80% is a yellow flag —
they may accept your open but not actively route HTLCs through the
channel. Every peer here is at ≥36% (and most are ≥87%); I explicitly
call out the lower-end ones.

## Quick reference

| # | Alias | Median fee | Channels | Capacity | Location |
|---:|---|---|---:|---:|---|
| 1 | [`Babylon-4a`](#1-babylon-4a) ⭐ | 0 base + 20 ppm | 284 | 17.98 BTC | Linode US |
| 2 | [`krut42`](#2-krut42) ⭐ | 0 base + 0 ppm | 33 | 2.37 BTC | Selectel Russia |
| 3 | [`New Horizons`](#3-new-horizons) ⭐ | 0 base + 15 ppm | 136 | 6.62 BTC | Hetzner Germany |
| 4 | [`connect-to-this-node-please`](#4-connect-to-this-node-please) | 0 base + 65 ppm | 90 | 22.76 BTC | AWS Oregon |
| 5 | [`ORANGEIRON`](#5-orangeiron) | 0 base + 138 ppm | 60 | 5.19 BTC | Vultr |
| 6 | [`BavarianBitcoinBank`](#6-bavarianbitcoinbank) | 0 base + 159 ppm | 112 | 1.91 BTC | IONOS Germany |
| 7 | [`Porcino 🍄‍🟫`](#7-porcino-) | 0 base + 200 ppm | 93 | 14.31 BTC | Netcup Germany |
| 8 | [`hashposition.com 🔵`](#8-hashpositioncom-) | 0 base + 252 ppm | 64 | 2.90 BTC | DigitalOcean |
| 9 | [Operator-pair: hex aliases](#9-large-routing-operator-pair-hex-aliased) | 0 base + 500 ppm | 214 + 191 | 90.77 + 97.15 BTC | AWS Oregon |
| 10 | [`absolute.money`](#10-absolutemoney) | 0 base + 777 ppm | 129 | 15.25 BTC | (unknown clearnet IP) |
| 11 | [`HydraNode`](#11-hydranode) | 329 base + 208 ppm | 89 | 6.94 BTC | RU-CENTER Russia |
| 12 | [`CoinGate`](#12-coingate-marginal-routing-health) ⚠️ | 1 sat + 1 ppm | 1,321 | 16.62 BTC | AWS Frankfurt |
| 13 | [`DedanKimathi`](#13-dedankimathi) | 1 sat + 100 ppm | 48 | 14.90 BTC | AWS Cape Town |
| 14 | [`points-nexus`](#14-points-nexus) | 1 sat + 1,300 ppm | 52 | 31.80 BTC | AWS Oregon |
| 15 | [`Chessa ✨`](#15-chessa-) | 1.5 sat + 326 ppm | 31 | 5.19 BTC | AWS Oregon |

⭐ marks my three recommended defaults — well-rounded across fees,
connectivity, and routing health. ⚠️ marks `CoinGate`, which has a
remarkable headline fee but a marginal outbound-enabled rate; see its
entry for full context.

---

## The peers

### 1. `Babylon-4a`

| | |
|---|---|
| **Pubkey** | `0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3` |
| **Socket** | `45.33.71.93:9739` (Linode US — note non-standard port `9739`, not `9735`) |
| **Channels (gossip)** | 284 |
| **Capacity (gossip)** | 17.98 BTC |
| **Top-20-hub connections** | 24 |
| **Typical `fee_base_msat`** | **0** (median across 264 active edges) |
| **Typical `fee_rate_milli_msat`** | **20 ppm** (median; min=0, max=9,000) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | 100 |
| **Typical `max_htlc_msat`** | ~42 M msat per HTLC (median); wide variance |
| **About this peer** | The cheapest peer in the list when you factor in routing-depth and connectivity together — 284 gossiped channels and almost 18 BTC of capacity backing them. A solid default for receive liquidity at a small-channel price point. |

### 2. `krut42`

| | |
|---|---|
| **Pubkey** | `02961ed16db648f99ff5aa121a263420911d6b6011794f2a99b79397b5e8b2eed4` |
| **Socket** | `193.124.56.148:9735` (Selectel, Russia) |
| **Channels (gossip)** | 33 |
| **Capacity (gossip)** | 2.37 BTC |
| **Top-20-hub connections** | 16 |
| **Outbound enabled** | 33 / 33 (100%) — every edge active |
| **Typical `fee_base_msat`** | **0** (median; min=0, max=1,000) |
| **Typical `fee_rate_milli_msat`** | **0 ppm** (median; min=0, max=475) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | 80 |
| **Typical `max_htlc_msat`** | ~5.9 M sat per HTLC (median); up to ~12.9 M sat |
| **About this peer** | Cheapest median fees of any peer here — half their outbound channels are completely free to route through. Smaller than Babylon (33 vs 284 channels) so onward path diversity is more limited, but 100% of edges are enabled (rare) and the operator is in Russia, giving useful geographic diversity if your other peers are US-hosted. |

### 3. `New Horizons`

| | |
|---|---|
| **Pubkey** | `03e86afe389d298f8f53a2f09fcc4d50cdd34e2fbd8f32cbd55583c596413705c2` |
| **Socket** | `5.75.184.195:43313` (Hetzner Germany — non-standard port) |
| **Channels (gossip)** | 136 |
| **Capacity (gossip)** | 6.62 BTC |
| **Top-20-hub connections** | 14 |
| **Outbound enabled** | 133 / 136 (98%) — near-perfect routing posture |
| **Typical `fee_base_msat`** | **0** (median, min=max=0 — **zero base on every edge**) |
| **Typical `fee_rate_milli_msat`** | **15 ppm** (median; min=1, max=4,444) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | **40** (median; min=40, max=80 — *shorter* than the LND default, route-friendly) |
| **Typical `max_htlc_msat`** | ~4.95 M sat per HTLC (median); up to ~16.6 M sat |
| **About this peer** | Second-cheapest median fee in the list and substantially better-connected than the lowest (krut42). The combination of zero base + 15 ppm + 98% enabled + a 40-block `time_lock_delta` is the most route-friendly profile of any peer here — well-suited for both small payments and longer multi-hop routes. Strong recommendation alongside Babylon-4a; pick either depending on whether you prefer larger raw capacity (Babylon) or lower fees + better edge utilization (this one). |

### 4. `connect-to-this-node-please`

| | |
|---|---|
| **Pubkey** | `026c2595bddf44ca1eadb65ad26942b325616690d104442f8560a7faaf67c4c323` |
| **Socket** | `54.244.234.100:20078` (AWS us-west-2, Oregon — non-standard port) |
| **Channels (gossip)** | 90 |
| **Capacity (gossip)** | 22.76 BTC |
| **Top-20-hub connections** | 33 — the highest of any peer in this list |
| **Typical `fee_base_msat`** | **0** (median across 86 active edges) |
| **Typical `fee_rate_milli_msat`** | **65 ppm** (median; min=0, max=9,999) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | 100 |
| **Typical `max_htlc_msat`** | ~99 M msat per HTLC (median) |
| **About this peer** | The strongest *connectivity* signal of any peer here — 33 direct channels to top-tier routing hubs. Best pick if you're worried about routes being available from unusual paying nodes (an exchange in a different region, an LSP, etc.) — an extra-safe choice that costs ~3× more in routing fees than Babylon-4a. |

### 5. `ORANGEIRON`

| | |
|---|---|
| **Pubkey** | `03a465772d45616bf6c8450a69191db8f3cf8cca19ff92138735fd5f1d436fe4dc` |
| **Socket** | `45.77.75.86:9735` (Vultr) |
| **Channels (gossip)** | 60 |
| **Capacity (gossip)** | 5.19 BTC |
| **Top-20-hub connections** | 13 |
| **Outbound enabled** | 58 / 59 sampled (97%) |
| **Typical `fee_base_msat`** | **0** (median, min=max=0 — zero base on every edge) |
| **Typical `fee_rate_milli_msat`** | **138 ppm** (median; min=0, max=8,693) |
| **Typical `min_htlc_msat`** | 1 msat (the lowest in the list — true micro-payment ready) |
| **Typical `time_lock_delta`** | **34** (uniformly — **the shortest in the list**) |
| **Typical `max_htlc_msat`** | ~1.2 M sat per HTLC (median); up to ~25 M sat |
| **About this peer** | Strong all-rounder. The uniform 34-block `time_lock_delta` is the most CLTV-budget-friendly of any peer here — it leaves the maximum possible budget for downstream hops on long routes. The 1-msat `min_htlc` makes it usable for genuine micro-payments (Lightning's smallest possible HTLC). Smaller per-HTLC cap than most (~1.2 M sat median) — fine for typical receive sizes, but you'd want to split a single 10 M sat payment across multiple HTLCs. |

### 6. `BavarianBitcoinBank`

| | |
|---|---|
| **Pubkey** | `037886fe3551ab7a38f33598e96471c697da8ac6fb9d8b7b4d23708877ee831ef5` |
| **Socket** | `212.227.64.36:9735` (1&1 / IONOS, Germany) |
| **Channels (gossip)** | 112 |
| **Capacity (gossip)** | 1.91 BTC |
| **Top-20-hub connections** | 12 |
| **Outbound enabled** | 109 / 112 (97%) — near-perfect routing posture |
| **Typical `fee_base_msat`** | **0** (median, min=max=0 — zero base on every edge) |
| **Typical `fee_rate_milli_msat`** | **159 ppm** (median; min=0, max=1,973) |
| **Typical `min_htlc_msat`** | 1 msat (micro-payment ready, matches ORANGEIRON) |
| **Typical `time_lock_delta`** | 80 (uniformly — LND default) |
| **Typical `max_htlc_msat`** | ~359 k sat per HTLC (median); up to ~9.9 M sat |
| **About this peer** | Solid mid-low-tier peer with pure-percentage pricing and 97% enabled outbound. Modest 1.91 BTC capacity is the smallest of the cheap-tier peers, so its routing depth is more limited than Babylon-4a or Porcino — but for typical receive sizes that's not a constraint. Branded operator (Bavarian Bitcoin Bank). Complements New Horizons's Hetzner-Germany via a different German provider (IONOS). |

### 7. `Porcino 🍄‍🟫`

| | |
|---|---|
| **Pubkey** | `02f9cdc8df3f142dcef499ce66464e2697f6e80e0db4b1d49c86f3e272931191c1` |
| **Socket** | `152.53.106.28:19735` (Netcup, Germany — non-standard port) |
| **Channels (gossip)** | 93 |
| **Capacity (gossip)** | 14.31 BTC |
| **Top-20-hub connections** | 15 |
| **Outbound enabled** | 91 / 93 (98%) — almost every edge active |
| **Typical `fee_base_msat`** | **0** (median, min=max=0 — zero base on every edge) |
| **Typical `fee_rate_milli_msat`** | **200 ppm** (median; min=0, max=2,500) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | 144 (uniformly — higher than the LND default of 80) |
| **Typical `max_htlc_msat`** | ~4.9 M sat per HTLC (median); up to ~48.5 M sat |
| **About this peer** | One of two peers in the list with **zero base fee on every single edge** (the other is ORANGEIRON); fees are pure-percentage. The 144-block `time_lock_delta` is roughly 2× the LND default, which subtracts ~64 blocks from your usable HTLC budget — for very long routes that touch multiple high-delta hops, this could nudge a payment over LND's 1,008-block CLTV ceiling. Solid mid-tier choice with strong capacity (14.31 BTC). |

### 8. `hashposition.com 🔵`

| | |
|---|---|
| **Pubkey** | `02ad6fb8d693dc1e4569bcedefadf5f72a931ae027dc0f0c544b34c1c6f3b9a02b` |
| **Socket** | `161.35.9.253:9735` (DigitalOcean) |
| **Channels (gossip)** | 64 |
| **Capacity (gossip)** | 2.90 BTC |
| **Top-20-hub connections** | 13 |
| **Outbound enabled** | 55 / 63 sampled (87%) — moderate, 8 edges disabled |
| **Typical `fee_base_msat`** | **0** (median, min=max=0 — zero base on every edge) |
| **Typical `fee_rate_milli_msat`** | **252 ppm** (median; min=0, max=2,000) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | 80 (uniformly — LND default) |
| **Typical `max_htlc_msat`** | ~990 k sat per HTLC (median); up to ~49.5 M sat |
| **About this peer** | Pure-percentage pricing at 252 ppm median. Routing health is moderate (12.7% of edges disabled — the lower end of acceptable). Smaller per-HTLC cap than most (~990 k sat median); plenty for typical receive sizes but might force splitting on a single mid-six-figure payment. Branded operator. |

### 9. Large routing operator-pair (hex-aliased)

A pair of clearly-sibling nodes operated by the same entity — same
uniform 0 + 500 ppm policy, same 80-block CLTV delta, same 1-sat
`min_htlc`, same AWS us-west-2 region, ports 10015/10016 adjacent, both
operators left their aliases as raw pubkey-prefix hex. Opening to BOTH
gives only marginal additional routing diversity since they likely
share upstream paths. **For most users, pick either one** (whichever
responds first).

| | Node A | Node B |
|---|---|---|
| **Pubkey** | `02a98e8c590a1b5602049d6b21d8f4c8861970aa310762f42eae1b2be88372e924` | `039174f846626c6053ba80f5443d0db33da384f1dde135bf7080ba1eec465019c3` |
| **Socket** | `54.201.244.204:10016` | `34.219.38.168:10015` |
| **Channels** | 214 | 191 |
| **Capacity** | 90.77 BTC | 97.15 BTC |
| **Top-20-hub connections** | 15 | 15 |

Common policy (identical fingerprint across both nodes):

| | |
|---|---|
| **Typical `fee_base_msat`** | **0** (uniformly) |
| **Typical `fee_rate_milli_msat`** | **500 ppm** (uniformly — tight, identical policy on every channel) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | 80 |
| **Typical `max_htlc_msat`** | ~5.94 M sat (Node A) / ~10 M sat (Node B) per HTLC (median) |
| **About this operator** | Big-capacity routing operator (~190 BTC across the pair) with a uniform 500-ppm fee. ~25× more expensive per sat received than Babylon-4a, but the size + uniform policy suggest a serious, professionally-managed operation. Reasonable choice when you want a large stable node and don't mind paying for it; if you want to maximize diversity within this operator's footprint, opening with one is enough — the second adds little. |

### 10. `absolute.money`

| | |
|---|---|
| **Pubkey** | `036635ba9a28a8ba133bb630ddf67f84b56d20073c8f2b5fca92dfa571507cd973` |
| **Socket** | `5.11.92.140:9735` |
| **Channels (gossip)** | 129 |
| **Capacity (gossip)** | 15.25 BTC |
| **Top-20-hub connections** | 19 |
| **Typical `fee_base_msat`** | **0** (median across 124 active edges) |
| **Typical `fee_rate_milli_msat`** | **777 ppm** (median; min=1, max=5,000) |
| **Typical `min_htlc_msat`** | 1 msat (accepts truly tiny payments) |
| **Typical `time_lock_delta`** | **34** (across the board — unusually short; most operators use 40-144) |
| **Typical `max_htlc_msat`** | ~7.6 M msat per HTLC (median) |
| **About this peer** | Functional but pricier — at 777 ppm, you'll pay roughly 39× more in routing fees than through Babylon-4a. A reasonable backup if the cheaper peers above are unreachable from your wallet's gossip view. The 1-msat `min_htlc` and short CLTV (34 blocks) make it well-suited for micro-payment use cases. |

### 11. `HydraNode`

| | |
|---|---|
| **Pubkey** | `02ceb27f3d4e32b83f37dff8bad8cc802dc0f380ca0193e90514ae25bc32c7542e` |
| **Socket** | `194.145.208.114:9735` (RU-CENTER, Russia) |
| **Channels (gossip)** | 89 |
| **Capacity (gossip)** | 6.94 BTC |
| **Top-20-hub connections** | 15 |
| **Outbound enabled** | 70 / 89 (79%) — non-trivial fraction of edges disabled |
| **Typical `fee_base_msat`** | **329** msat (median; min=1, max=1,578) |
| **Typical `fee_rate_milli_msat`** | **208 ppm** (median; min=0, max=2,392) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | **40** (median — shorter than the LND default of 80, route-friendly) |
| **Typical `max_htlc_msat`** | ~4.95 M sat per HTLC (median); up to ~73.7 M sat |
| **About this peer** | Hybrid pricing — meaningful 329 msat base **plus** 208 ppm proportional. For typical sub-10k sat payments the base dominates, giving an effective ~0.33 sats per payment regardless of size. Routing health (79% enabled) is weaker than most of the peers above; consider it a yellow flag rather than a deal-breaker. The short `time_lock_delta` (40) is a small bonus on long routes. |

### 12. `CoinGate` ⚠️ Marginal routing health

| | |
|---|---|
| **Pubkey** | `0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3` |
| **Socket** | `3.124.63.44:9735` (AWS eu-central-1, Frankfurt) |
| **Channels (gossip)** | 1,321 (largest in this list — a major commercial payment processor) |
| **Capacity (gossip)** | 16.62 BTC |
| **Outbound enabled** | **472 / 1,319 sampled (36%)** — ⚠️ **64% of edges are disabled outbound** |
| **Typical `fee_base_msat`** | **1,000** msat (uniformly — min=median=max=1,000) |
| **Typical `fee_rate_milli_msat`** | **1 ppm** (uniformly — the lowest rate in the entire list) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | 80 (median; min=40, max=144) |
| **Typical `max_htlc_msat`** | ~544 k sat per HTLC (median); up to ~16.8 M sat |
| **About this peer** | **The most attractive fee structure in the list on paper** — 1 sat base + 1 ppm is essentially a flat 1-sat fee that doesn't scale up with payment size at all. **But the 64% disabled-outbound rate is a real concern** for inbound liquidity: it means CoinGate may not actively forward HTLCs back to you over the channel you opened, even though the channel exists and the fee policy is published. Their 472 enabled outbound channels are a real routing surface (more than most peers here have channels total), so it's not non-routing — but it's a noticeably weaker enable rate than the rest of the list. Treat as a fallback choice; if you open here and find that payments to you start landing as `NO_ROUTE` failures, close and pick from earlier in this list. |

### 13. `DedanKimathi`

| | |
|---|---|
| **Pubkey** | `0397391be2af48d7d61aa488d209d4767e2fcc5d0bec0f783abb4a1a2002c40186` |
| **Socket** | `13.245.66.35:9735` (AWS af-south-1, Cape Town — sole African peer here) |
| **Channels (gossip)** | 48 |
| **Capacity (gossip)** | 14.90 BTC |
| **Top-20-hub connections** | 14 |
| **Outbound enabled** | 48 / 48 (100%) — every edge active |
| **Typical `fee_base_msat`** | **1,000** msat (uniformly — min=median=max=1,000) |
| **Typical `fee_rate_milli_msat`** | **100 ppm** (median; min=25, max=750) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | 80 (uniformly — LND default) |
| **Typical `max_htlc_msat`** | ~9.6 M sat per HTLC (median); up to ~49.5 M sat |
| **About this peer** | Hybrid pricing — 1 sat base + 100 ppm — so the effective cost is ~1 sat per payment for typical receive sizes and stays close to that even at 1 M sat (the 100 ppm is mild). 100% enabled outbound and a high per-HTLC cap make it route-reliable. Geographic standout — sole African peer in the list, valuable diversity if any of your paying nodes happen to be in af-south-1 or want a short-RTT southern-hemisphere hop. |

### 14. `points-nexus`

| | |
|---|---|
| **Pubkey** | `0379dbd35a22abe30d87f89664bad7aea31e4ba15a2e69ec4946113cfb9843c445` |
| **Socket** | `54.214.32.132:20147` (AWS us-west-2, Oregon — non-standard port) |
| **Channels (gossip)** | 52 |
| **Capacity (gossip)** | 31.80 BTC |
| **Top-20-hub connections** | 15 |
| **Outbound enabled** | 52 / 52 (100%) — every edge active |
| **Typical `fee_base_msat`** | **1,000** msat (uniformly — min=median=max=1,000) |
| **Typical `fee_rate_milli_msat`** | **1,300 ppm** (median; min=1, max=1,300 — near-uniform) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | 144 (median; min=80, max=144) |
| **Typical `max_htlc_msat`** | ~49.5 M sat per HTLC (median); up to ~297 M sat |
| **About this peer** | Combines a 1 sat base **and** a 1,300 ppm rate — expensive both ways. For typical sub-10k sat payouts you'd pay ~1 sat per payment (base-dominated). For larger payments the 1,300 ppm rate dominates — at 1 M sat this peer becomes pricier than Chessa. On the plus side: 100% enabled outbound and the largest per-HTLC cap of any peer in the list (~50 M sat median). |

### 15. `Chessa ✨`

| | |
|---|---|
| **Pubkey** | `03f4553a2e6092fb7c03e7c4041451d9946e7326f6bf2c852278dacbaff798a4b3` |
| **Socket** | `54.71.27.149:20367` (AWS us-west-2, non-standard port) |
| **Channels (gossip)** | 31 |
| **Capacity (gossip)** | 5.19 BTC |
| **Top-20-hub connections** | 16 |
| **Outbound enabled** | 27 / 31 (87%) — healthy router |
| **Typical `fee_base_msat`** | **1,500** msat (median; min=0, max=2,000) |
| **Typical `fee_rate_milli_msat`** | **326 ppm** (median; min=0, max=5,000) |
| **Typical `min_htlc_msat`** | 1,000 msat (1 sat) |
| **Typical `time_lock_delta`** | 100 |
| **Typical `max_htlc_msat`** | ~9.9 M sat per HTLC (median — high cap) |
| **About this peer** | Different fee model than most peers above — a high base fee dominates the cost for small payments, so the effective rate is roughly **1.5 sats per payment** regardless of size up to ~100 k sat. The 87% enabled-outbound ratio means they actively route, and the high per-HTLC cap (median ~10 M sat) makes them well-suited for *larger* payments where the flat base becomes negligible. |

---

## Caveats

**Gossip lag.** Once you open a channel with one of these peers, your
own LND won't see their *outbound-to-you* policy in gossip
until they advertise it (usually within 24–72 hours of the channel
confirming). Until then, payers can route to you on a default policy
which may differ from the typical numbers above. Reverify after
gossip catches up.

**Snapshot staleness.** Every number on this page reflects the public
gossip view at the snapshot date. Channel counts, fees, and outbound
enable rates change. The longer it's been since the snapshot date, the
more you should reverify (use a public node explorer like Amboss,
LightningNetwork+, or your own node's `describegraph`).

**Outbound enable rate ≠ guaranteed routing.** A peer with 100%
enabled outbound is well-behaved by gossip convention, but nothing
about LN's protocol prevents them from selectively rejecting HTLCs at
forward time. The empirical rate of enable in their gossiped policies
is the best signal available without actually sending payments through.

**No endorsement.** These peers were selected on empirical
small-channel-acceptance and on connectivity / fee criteria — not on
operator identity, jurisdiction, or anything reputational. If a
particular operator's hosting, AS, or jurisdiction matters for your
threat model, do your own research before opening.

**Reverify before opening.** A 30-second sanity check with `lncli
getnodeinfo --include_channels <pubkey>` or the equivalent on your
node software will tell you whether the peer is still online and
whether their advertised channel count / capacity is in the same
ballpark as what's tabulated above. If anything looks drastically
different, treat this list as suggestive only and look for newer data.
