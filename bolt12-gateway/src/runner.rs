// SPDX-License-Identifier: MIT
//! Background-task runner for the LDK stack.
//!
//! Two cooperating loops keep the gateway alive:
//!
//! 1. `peer_event_pump`: polls `PeerManager::process_events()` whenever
//!    the `PeerManager` signals work via its update future, plus a 1s
//!    safety tick so we don't sit on stuck events forever.
//! 2. `onion_event_pump`: drains
//!    `OnionMessenger::process_pending_events_async`. The pump
//!    handles `Event::ConnectionNeeded` — LDK fires this when an
//!    outbound onion message (typically our invoice reply on a BOLT
//!    12 fetchinvoice round-trip) is buffered waiting for a peer
//!    we're not yet connected to. The handler looks the peer up in
//!    the `NetworkGraph` and fires a dial through
//!    `sticky_peers::dial_peer` so the buffered message can flush.
//!    Without this, the dropped event caused every Ocean payout
//!    whose `reply_path` introduction node we didn't already peer
//!    with to time out at 60 s (root cause of the 2026-06-03
//!    incident). Each dial is fire-and-forget on a dedicated tokio
//!    task — the pump itself must NOT await the dial (would block
//!    every subsequent event for a 15 s TCP timeout) — and the
//!    fan-out is bounded by a `Semaphore` to cap the worst case at
//!    `CONNECTION_NEEDED_DIAL_CONCURRENCY` concurrent outbound
//!    connections regardless of payer behaviour.
//! 3. `timer_tick`: fires `peer_manager.timer_tick_occurred()` and
//!    `onion_messenger.timer_tick_occurred()` every 30s — required by
//!    LDK to detect dead connections and roll its session keys.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use lightning::events::Event;
use lightning::ln::msgs::{OnionMessageHandler, SocketAddress};
use lightning::routing::gossip::NodeId;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::ldk_glue::GatewayState;
use crate::sticky_peers::{dial_peer, DialError, DialLocks, DialOutcome};

/// Cap on the number of `Event::ConnectionNeeded`-triggered dials
/// running concurrently across the whole onion-event pump. Sized to
/// comfortably absorb a burst from one Ocean-style payer (30
/// invreqs/min by default via
/// `bolt12_inbound_rate_limit_count`) while still bounding the
/// worst case if a single payer or aggregated traffic attempts a
/// fan-out across many distinct reply-path introduction nodes.
/// Each in-flight dial uses one outbound TCP connection (via SOCKS5
/// when configured) plus the per-pubkey `DialLock`; with the cap
/// the worst-case is 32 concurrent TCP/Tor circuits regardless of
/// payer behaviour.
const CONNECTION_NEEDED_DIAL_CONCURRENCY: usize = 32;

/// Configuration the `onion_event_pump` needs in order to honour
/// `Event::ConnectionNeeded`. Mirrors the values
/// `sticky_peers::spawn` already uses for its reconnect loop so the
/// two dial paths behave identically.
#[derive(Clone)]
pub struct DialConfig {
    pub tcp_connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub socks5_proxy: Option<Arc<str>>,
}

impl Default for DialConfig {
    fn default() -> Self {
        Self {
            tcp_connect_timeout: Duration::from_secs(15),
            handshake_timeout: Duration::from_secs(5),
            socks5_proxy: None,
        }
    }
}

/// Handles to the spawned background tasks. Dropping them lets the
/// tasks run forever; cancelling each via `abort()` shuts the gateway
/// down. Held by `main.rs` for the gateway's lifetime.
#[allow(dead_code)]
pub struct BackgroundTasks {
    pub peer_pump: JoinHandle<()>,
    pub onion_pump: JoinHandle<()>,
    pub timer_tick: JoinHandle<()>,
}

/// Spawn the three background pumps. Returns immediately.
pub fn spawn(state: &Arc<GatewayState>, dial: DialConfig) -> BackgroundTasks {
    let pm = state.peer_manager();
    let om = state.onion_messenger();

    let pm_for_pump = Arc::clone(&pm);
    let peer_pump = tokio::spawn(async move {
        loop {
            pm_for_pump.process_events();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    let om_for_pump = Arc::clone(&om);
    let state_for_pump = Arc::clone(state);
    // Bounded concurrency for ConnectionNeeded-triggered dials. The
    // permit lives for the duration of one dial attempt; releasing
    // it on drop unblocks the next queued spawn.
    let dial_semaphore = Arc::new(Semaphore::new(CONNECTION_NEEDED_DIAL_CONCURRENCY));
    let onion_pump = tokio::spawn(async move {
        loop {
            let state_for_handler = Arc::clone(&state_for_pump);
            let dial_for_handler = dial.clone();
            let sem_for_handler = Arc::clone(&dial_semaphore);
            om_for_pump
                .process_pending_events_async(move |event| {
                    let state = Arc::clone(&state_for_handler);
                    let dial = dial_for_handler.clone();
                    let sem = Arc::clone(&sem_for_handler);
                    Box::pin(async move {
                        if let Event::ConnectionNeeded { node_id, addresses } = event {
                            // Fire-and-forget. ``process_pending_events_async``
                            // polls handler futures with
                            // ``MultiResultFuturePoller`` and won't return
                            // until ALL of them resolve, so awaiting a
                            // 15 s TCP timeout here would block every
                            // subsequent event (including the
                            // ``PeerConnected`` for the very peer this
                            // dial is trying to land). Spawn into a
                            // bounded-concurrency task instead; LDK
                            // auto-flushes the buffered onion message
                            // when the peer connects, so we don't need
                            // to thread completion back to the pump.
                            tokio::spawn(async move {
                                // ``acquire_owned`` is cheap on the
                                // semaphore; the await yields if we're
                                // already at the cap. ``close()``
                                // never runs in practice (the
                                // semaphore lives for the gateway
                                // lifetime) — the expect message
                                // documents the invariant.
                                let _permit = sem
                                    .acquire_owned()
                                    .await
                                    .expect("dial semaphore not closed");
                                handle_connection_needed(state, dial, node_id, addresses).await;
                            });
                        }
                        Ok(())
                    })
                })
                .await;
            // Wake either when the messenger signals new work or every
            // second as a safety net.
            let fut = om_for_pump.get_update_future();
            let _ = tokio::time::timeout(Duration::from_secs(1), fut).await;
        }
    });

    let timer_tick = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            pm.timer_tick_occurred();
            om.timer_tick_occurred();
        }
    });

    BackgroundTasks {
        peer_pump,
        onion_pump,
        timer_tick,
    }
}

/// Honour a single `Event::ConnectionNeeded`.
///
/// Resolves dial-able addresses for the requested peer from three
/// sources, in priority order:
///
///   1. `Event::ConnectionNeeded.addresses` — the LDK-shipped hint.
///      Always wins when non-empty; LDK provided it intentionally.
///   2. **Wallet-pushed address cache** (the load-bearing source for
///      the 2026-06-04 Ocean wedge — LDK's `NetworkGraph` stays empty
///      under our `IgnoringMessageHandler` so this cache is the only
///      way the gateway learns addresses for non-peer nodes). The
///      cache enforces a 24 h TTL on each entry and a 10 min
///      negative-cache window on all-candidate dial failures.
///   3. `NetworkGraph` `node_announcement` — vestigial fallback for
///      future configurations where gossip is consumed (e.g. a
///      `RoutingMessageHandler` swap-in).
///
/// Tries each candidate via `sticky_peers::dial_peer` and stops at
/// the first success. On all-candidate failure, records the failure
/// against the address cache so the next `Event::ConnectionNeeded`
/// for this pubkey within `FAILURE_TTL` short-circuits without
/// burning more Tor circuits.
///
/// Fire-and-forget by design: the LDK `OnionMessenger` re-flushes any
/// buffered messages as soon as the peer connects, so we don't need
/// to thread a completion signal back. If we can't connect at all,
/// LDK will drop the buffered message on its own teardown timer.
async fn handle_connection_needed(
    state: Arc<GatewayState>,
    dial: DialConfig,
    node_id: PublicKey,
    addresses_hint: Vec<SocketAddress>,
) {
    // Already connected? Fast-fail before spawning a dial — saves the
    // dial-lock acquire on a no-op.
    let peer_manager = state.peer_manager();
    if peer_manager.peer_by_node_id(&node_id).is_some() {
        debug!(
            target: "bolt12_gateway::runner",
            node = %node_id,
            "ConnectionNeeded: already connected, no-op"
        );
        return;
    }

    let address_cache = state.address_cache();
    let now = std::time::Instant::now();

    // Read each priority source. Gossip read is cheap (single
    // HashMap lookup) and the current `IgnoringMessageHandler`
    // config keeps it empty, but reading it unconditionally
    // future-proofs the call site for a swap-in that consumes
    // gossip.
    let cache_lookup = address_cache.lookup_reason_at(&node_id, now);
    let gossip_addresses: Vec<SocketAddress> = {
        let graph = state.network_graph();
        let read_only = graph.read_only();
        let target = NodeId::from_pubkey(&node_id);
        read_only
            .nodes()
            .get(&target)
            .and_then(|node| node.announcement_info.as_ref())
            .map(|ann| ann.addresses().to_vec())
            .unwrap_or_default()
    };

    let candidates = match resolve_candidates(&addresses_hint, &cache_lookup, &gossip_addresses) {
        ResolveOutcome::Dial(c) => c,
        ResolveOutcome::CacheExpired { age_s } => {
            warn!(
                target: "bolt12_gateway::runner",
                node = %node_id,
                cache_entry_age_s = age_s,
                "ConnectionNeeded: cache entry expired (push side lagging?); \
                 skipping dial"
            );
            return;
        }
        ResolveOutcome::NegativelyCached { since_failure_s } => {
            // Silence at debug! because retry storms during a
            // payment-failure backoff would otherwise produce noisy
            // WARN spam.
            debug!(
                target: "bolt12_gateway::runner",
                node = %node_id,
                since_failure_s,
                "ConnectionNeeded: peer recently failed every candidate; \
                 suppressing redial until negative-cache window expires"
            );
            return;
        }
        ResolveOutcome::NoAddresses => {
            warn!(
                target: "bolt12_gateway::runner",
                node = %node_id,
                cache_entries = address_cache.len(),
                "ConnectionNeeded: no dial-able addresses found in event hint, \
                 wallet-pushed cache, or NetworkGraph; buffered onion message \
                 will be dropped on LDK's teardown timer"
            );
            return;
        }
    };

    info!(
        target: "bolt12_gateway::runner",
        node = %node_id,
        candidate_count = candidates.len(),
        "ConnectionNeeded: dialing peer to flush buffered onion message"
    );

    let locks = state.dial_locks();
    let outcome = try_addresses(&peer_manager, &locks, &dial, &node_id, &candidates).await;

    match outcome {
        Ok(DialOutcome::Connected) => info!(
            target: "bolt12_gateway::runner",
            node = %node_id,
            "ConnectionNeeded: dial succeeded; LDK will flush buffered message"
        ),
        Ok(DialOutcome::AlreadyConnected) => debug!(
            target: "bolt12_gateway::runner",
            node = %node_id,
            "ConnectionNeeded: peer connected concurrently, no dial needed"
        ),
        Err(last_err) => {
            // Negative-cache the failure so retries don't burn a Tor
            // circuit per attempt. ``record_failure_at`` is a no-op
            // when the entry isn't in the cache (e.g. we dialed from
            // the event hint), which is the desired behaviour — a
            // future push is authoritative.
            address_cache.record_failure_at(&node_id, now);
            warn!(
                target: "bolt12_gateway::runner",
                node = %node_id,
                error = %last_err,
                "ConnectionNeeded: all candidate addresses failed; buffered \
                 onion message lost (negative-cache window armed)"
            );
        }
    }
}

/// Try each candidate address in turn. Returns the first success or
/// the last failure when none succeed.
async fn try_addresses(
    peer_manager: &Arc<crate::ldk_glue::GatewayPeerManager>,
    dial_locks: &DialLocks,
    dial: &DialConfig,
    node_id: &PublicKey,
    candidates: &[String],
) -> Result<DialOutcome, DialError> {
    let mut last: Option<DialError> = None;
    for address in candidates {
        match dial_peer(
            peer_manager,
            dial_locks,
            *node_id,
            address,
            dial.tcp_connect_timeout,
            dial.handshake_timeout,
            dial.socks5_proxy.as_deref(),
        )
        .await
        {
            Ok(outcome) => return Ok(outcome),
            Err(err) => {
                debug!(
                    target: "bolt12_gateway::runner",
                    node = %node_id,
                    address = %address,
                    error = %err,
                    "ConnectionNeeded: dial attempt failed; trying next candidate"
                );
                last = Some(err);
            }
        }
    }
    Err(last.unwrap_or(DialError::ConnectFailed {
        address: "<no candidates>".to_string(),
    }))
}

/// Decision returned by [`resolve_candidates`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResolveOutcome {
    /// Use these candidate dial-strings in order.
    Dial(Vec<String>),
    /// No addresses anywhere — log a warn and drop.
    NoAddresses,
    /// Cache entry exists but is too old; the wallet's push side has
    /// fallen behind. Logged at warn so an operator notices.
    CacheExpired { age_s: u64 },
    /// Cache entry was recently force-failed; suppress the redial
    /// until the negative-cache window expires.
    NegativelyCached { since_failure_s: u64 },
}

/// Pure helper: choose the dial-candidate list from the four address
/// sources, honoring the priority order documented on
/// [`handle_connection_needed`].
///
/// Split out for testability — the caller does the `AddressCache`
/// lookup + `NetworkGraph` read first, then hands the materialised
/// inputs here so the priority decision can be unit-tested without
/// constructing a full [`GatewayState`].
pub(crate) fn resolve_candidates(
    event_addresses: &[SocketAddress],
    cache_lookup: &crate::address_cache::LookupReason,
    gossip_addresses: &[SocketAddress],
) -> ResolveOutcome {
    use crate::address_cache::LookupReason;

    // Priority 1: event hint always wins when non-empty.
    if !event_addresses.is_empty() {
        return ResolveOutcome::Dial(
            event_addresses
                .iter()
                .map(SocketAddress::to_string)
                .collect(),
        );
    }

    match cache_lookup {
        LookupReason::Hit(addrs) => ResolveOutcome::Dial(addrs.clone()),
        LookupReason::Expired { age } => ResolveOutcome::CacheExpired {
            age_s: age.as_secs(),
        },
        LookupReason::NegativelyCached { since_failure } => ResolveOutcome::NegativelyCached {
            since_failure_s: since_failure.as_secs(),
        },
        LookupReason::Missing => {
            // Priority 3: NetworkGraph gossip fallback. Empty under
            // the current `IgnoringMessageHandler` config but kept
            // for future configurations that DO consume gossip.
            let from_gossip: Vec<String> = gossip_addresses
                .iter()
                .map(SocketAddress::to_string)
                .collect();
            if from_gossip.is_empty() {
                ResolveOutcome::NoAddresses
            } else {
                ResolveOutcome::Dial(from_gossip)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address_cache::LookupReason;
    use std::time::Duration;

    fn tcp_v4(octets: [u8; 4], port: u16) -> SocketAddress {
        SocketAddress::TcpIpV4 { addr: octets, port }
    }

    #[test]
    fn event_hint_wins_over_cache_and_gossip() {
        // The `Event::ConnectionNeeded.addresses` field is
        // authoritative: when LDK shipped sockets we use them
        // verbatim and ignore every other source. Pins priority so
        // a future refactor that "helpfully" merges sources doesn't
        // regress.
        let hint = vec![tcp_v4([10, 0, 0, 1], 9735)];
        let cache = LookupReason::Hit(vec!["from-cache:9735".into()]);
        let gossip = vec![tcp_v4([10, 0, 0, 2], 9735)];
        assert_eq!(
            resolve_candidates(&hint, &cache, &gossip),
            ResolveOutcome::Dial(vec!["10.0.0.1:9735".to_string()]),
        );
    }

    #[test]
    fn cache_hit_used_when_event_empty() {
        // `ConnectionNeeded { addresses: [] }` is the common case
        // for a payer-built reply path. The wallet-pushed cache is
        // the load-bearing fallback for the 2026-06-04 wedge.
        let hint: Vec<SocketAddress> = Vec::new();
        let cache = LookupReason::Hit(vec!["primary.onion:9735".into(), "fallback:9735".into()]);
        assert_eq!(
            resolve_candidates(&hint, &cache, &[]),
            ResolveOutcome::Dial(vec![
                "primary.onion:9735".to_string(),
                "fallback:9735".to_string(),
            ]),
        );
    }

    #[test]
    fn cache_expired_short_circuits_with_age() {
        // Past TTL → return the age so the caller can warn with the
        // exact lag (operator-actionable signal that the push side
        // is stalled).
        let outcome = resolve_candidates(
            &[],
            &LookupReason::Expired {
                age: Duration::from_secs(90_000),
            },
            &[],
        );
        assert_eq!(outcome, ResolveOutcome::CacheExpired { age_s: 90_000 });
    }

    #[test]
    fn cache_negatively_cached_short_circuits() {
        // Recent all-candidate failure → suppress. Pin so a future
        // change that "tries anyway" can't reintroduce per-payment
        // retry storms on a dead peer.
        let outcome = resolve_candidates(
            &[],
            &LookupReason::NegativelyCached {
                since_failure: Duration::from_secs(120),
            },
            &[],
        );
        assert_eq!(
            outcome,
            ResolveOutcome::NegativelyCached {
                since_failure_s: 120
            },
        );
    }

    #[test]
    fn falls_back_to_gossip_when_event_and_cache_both_miss() {
        // Future-proofs the runner for a config that DOES consume
        // gossip. Under the current `IgnoringMessageHandler` this
        // branch never fires in practice but remains tested.
        let gossip = vec![tcp_v4([1, 2, 3, 4], 9735), tcp_v4([5, 6, 7, 8], 9736)];
        assert_eq!(
            resolve_candidates(&[], &LookupReason::Missing, &gossip),
            ResolveOutcome::Dial(vec!["1.2.3.4:9735".to_string(), "5.6.7.8:9736".to_string(),]),
        );
    }

    #[test]
    fn no_addresses_when_every_source_empty() {
        // Pinned explicitly so a future change that "defaults" to
        // some hardcoded probe address gets caught.
        assert_eq!(
            resolve_candidates(&[], &LookupReason::Missing, &[]),
            ResolveOutcome::NoAddresses,
        );
    }

    #[test]
    fn preserves_event_address_order() {
        // `try_addresses` walks the list and stops at the first
        // success; preserve sender ordering verbatim (a payer who
        // listed v4 before v6 almost certainly knows which their
        // path can reach).
        let hint = vec![
            tcp_v4([1, 1, 1, 1], 9735),
            tcp_v4([2, 2, 2, 2], 9735),
            tcp_v4([3, 3, 3, 3], 9735),
        ];
        let outcome = resolve_candidates(&hint, &LookupReason::Missing, &[]);
        assert_eq!(
            outcome,
            ResolveOutcome::Dial(vec![
                "1.1.1.1:9735".to_string(),
                "2.2.2.2:9735".to_string(),
                "3.3.3.3:9735".to_string(),
            ]),
        );
    }
}
