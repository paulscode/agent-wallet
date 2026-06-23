// SPDX-License-Identifier: MIT
//! In-memory cache of known peer addresses pushed by the wallet.
//!
//! The gateway's LDK [`NetworkGraph`] is intentionally empty (the peer
//! manager uses `IgnoringMessageHandler` for routing messages so we
//! never accumulate gossip), which means `Event::ConnectionNeeded`
//! with an empty `addresses` field would otherwise be unactionable.
//!
//! The wallet's LND DOES sync gossip and knows the public addresses
//! of most public Lightning nodes. The wallet pushes that view here
//! via the gRPC `SetKnownNodeAddresses` streaming RPC; the runner's
//! [`crate::runner::handle_connection_needed`] consults this cache
//! before warning + dropping the buffered onion message.
//!
//! Freshness mechanisms (2026-06-04 design discussion):
//!
//! * **TTL eviction.** Each entry carries the wall-clock at which it
//!   was last pushed. A lookup older than [`AddressCache::ENTRY_TTL`]
//!   returns no addresses, so a peer that stops gossiping ages out
//!   even if the wallet's push side falls behind.
//! * **Negative caching.** When the runner has tried every address
//!   for a peer and they all failed, it records the failure here.
//!   Subsequent lookups within [`AddressCache::FAILURE_TTL`] return
//!   no addresses so we don't hammer a dead pubkey on every retry.
//! * **REPLACE semantics on push.** Each successful push overwrites
//!   the whole cache. The wallet is authoritative; the gateway has
//!   no merging logic that could drift between push cycles.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use secp256k1::PublicKey;

use crate::lock_recover::lock_recover;

/// One entry in [`AddressCache`].
#[derive(Clone, Debug)]
pub struct AddressCacheEntry {
    /// Dial-strings in preferred order. [`crate::runner::try_addresses`]
    /// walks in order and stops at the first success.
    pub addresses: Vec<String>,
    /// LND-side `node_announcement.timestamp` (unix seconds). Held
    /// for diagnostic output; the gateway never compares it against
    /// wall-clock — the wallet is authoritative on freshness via the
    /// push cadence + replace semantics.
    pub node_announcement_timestamp: u32,
    /// When this entry was inserted on the gateway side. Used by
    /// [`AddressCache::lookup_at`] for TTL eviction.
    pub inserted_at: Instant,
    /// When all candidate addresses last failed for this peer.
    /// Populated by [`AddressCache::record_failure_at`] and consulted
    /// by [`AddressCache::lookup_at`]; suppresses redial attempts for
    /// [`AddressCache::FAILURE_TTL`].
    pub last_dial_failure_at: Option<Instant>,
}

/// Thread-safe address cache.
///
/// Uses a `Mutex` (not `RwLock`) for consistency with the rest of
/// the gateway's shared-state pattern (`sticky_peers::DialLocks`,
/// `GatewayOnionMessenger::outbound`, …) — the lock contention here
/// is negligible (`ConnectionNeeded` events fire at most a few per
/// minute and the pusher's REPLACE is a single brief write), and
/// routing through the codebase's `lock_recover` helper means a
/// panic inside a critical section can't permanently disable the
/// cache for the rest of the process lifetime.
pub struct AddressCache {
    entries: Mutex<HashMap<[u8; 33], AddressCacheEntry>>,
}

impl Default for AddressCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressCache {
    /// Maximum age of a cache entry before lookup treats it as
    /// missing. Tuned to LND's `node_announcement` republish cadence
    /// (well-known nodes re-broadcast roughly daily) plus a margin
    /// so a one-cycle push miss on the wallet side doesn't immediately
    /// evict.
    pub const ENTRY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

    /// Negative-cache TTL. After all candidate addresses fail for a
    /// peer, ignore re-lookups for this long so we don't burn a Tor
    /// circuit on every retry. Aligned with the typical Ocean
    /// payout retry cadence (~minutes apart) so one bad address
    /// burst doesn't pin a recovery window.
    pub const FAILURE_TTL: Duration = Duration::from_secs(10 * 60);

    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// REPLACE the entire cache with the supplied entries.
    ///
    /// Callers MUST push the full desired set on every call; entries
    /// absent from `incoming` are dropped immediately. Returns the
    /// number of entries the cache holds afterwards.
    pub fn replace<I>(&self, incoming: I, now: Instant) -> usize
    where
        I: IntoIterator<Item = (PublicKey, Vec<String>, u32)>,
    {
        let mut map = lock_recover(&self.entries);
        map.clear();
        for (pubkey, addresses, ts) in incoming {
            // Skip entries with no addresses — they'd be no-ops on
            // lookup and waste a HashMap slot. Distinguished from
            // "no entry at all" so the operator-facing replace
            // counter stays accurate.
            if addresses.is_empty() {
                continue;
            }
            map.insert(
                pubkey.serialize(),
                AddressCacheEntry {
                    addresses,
                    node_announcement_timestamp: ts,
                    inserted_at: now,
                    last_dial_failure_at: None,
                },
            );
        }
        map.len()
    }

    /// Look up dial-able addresses for `pubkey` at instant `now`.
    ///
    /// Returns an empty `Vec` when:
    ///   * the entry is absent,
    ///   * the entry was inserted more than [`ENTRY_TTL`] ago, OR
    ///   * the last all-candidate dial failure was within
    ///     [`FAILURE_TTL`] of `now`.
    ///
    /// The split between "no entry" and "negatively cached" is
    /// surfaced to the caller via [`Self::lookup_reason_at`] when
    /// they need to log it distinctly.
    pub fn lookup_at(&self, pubkey: &PublicKey, now: Instant) -> Vec<String> {
        let map = lock_recover(&self.entries);
        let Some(entry) = map.get(&pubkey.serialize()) else {
            return Vec::new();
        };
        if now.saturating_duration_since(entry.inserted_at) > Self::ENTRY_TTL {
            return Vec::new();
        }
        if let Some(failed_at) = entry.last_dial_failure_at {
            if now.saturating_duration_since(failed_at) < Self::FAILURE_TTL {
                return Vec::new();
            }
        }
        entry.addresses.clone()
    }

    /// Diagnostic-friendly lookup. Returns
    /// [`LookupReason::Hit(addresses)`] on success and a distinct
    /// reason variant for each miss path so logging can attribute
    /// the cause precisely.
    pub fn lookup_reason_at(&self, pubkey: &PublicKey, now: Instant) -> LookupReason {
        let map = lock_recover(&self.entries);
        let Some(entry) = map.get(&pubkey.serialize()) else {
            return LookupReason::Missing;
        };
        if now.saturating_duration_since(entry.inserted_at) > Self::ENTRY_TTL {
            return LookupReason::Expired {
                age: now.saturating_duration_since(entry.inserted_at),
            };
        }
        if let Some(failed_at) = entry.last_dial_failure_at {
            let since_failure = now.saturating_duration_since(failed_at);
            if since_failure < Self::FAILURE_TTL {
                return LookupReason::NegativelyCached { since_failure };
            }
        }
        LookupReason::Hit(entry.addresses.clone())
    }

    /// Record that every candidate address for `pubkey` failed at
    /// `now`. The negative-cache window starts immediately; the next
    /// `FAILURE_TTL` worth of lookups will return empty for this
    /// peer.
    pub fn record_failure_at(&self, pubkey: &PublicKey, now: Instant) {
        let mut map = lock_recover(&self.entries);
        if let Some(entry) = map.get_mut(&pubkey.serialize()) {
            entry.last_dial_failure_at = Some(now);
        }
        // If there's no entry, we don't insert one — the caller had
        // candidates from somewhere (event hint, NetworkGraph) and a
        // future push will supply addresses if they're worth caching.
    }

    /// Total number of entries in the cache. Used in operator-
    /// facing counters / status responses.
    pub fn len(&self) -> usize {
        lock_recover(&self.entries).len()
    }

    /// Whether the cache holds zero entries.
    pub fn is_empty(&self) -> bool {
        lock_recover(&self.entries).is_empty()
    }
}

/// Diagnostic detail returned by [`AddressCache::lookup_reason_at`].
/// Lets the runner emit a precise log line ("expired", "negatively
/// cached", "no entry") rather than a single opaque "miss".
#[derive(Clone, Debug)]
pub enum LookupReason {
    /// Cache had a fresh entry; the addresses are included verbatim.
    Hit(Vec<String>),
    /// No entry for this pubkey.
    Missing,
    /// Entry exists but its `inserted_at` is older than [`AddressCache::ENTRY_TTL`].
    Expired { age: Duration },
    /// Entry exists and is within TTL, but a prior all-candidate
    /// dial failed less than [`AddressCache::FAILURE_TTL`] ago.
    NegativelyCached { since_failure: Duration },
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn pubkey(seed: u8) -> PublicKey {
        let sk = SecretKey::from_slice(&[seed.max(1); 32]).expect("valid secret");
        PublicKey::from_secret_key(&Secp256k1::new(), &sk)
    }

    #[test]
    fn fresh_replace_then_lookup_returns_addresses() {
        let cache = AddressCache::new();
        let pk = pubkey(1);
        let now = Instant::now();
        let inserted = cache.replace(
            vec![(pk, vec!["1.2.3.4:9735".into(), "x.onion:9735".into()], 100)],
            now,
        );
        assert_eq!(inserted, 1);
        assert_eq!(
            cache.lookup_at(&pk, now),
            vec!["1.2.3.4:9735".to_string(), "x.onion:9735".to_string()],
        );
    }

    #[test]
    fn replace_drops_old_entries() {
        // Pin REPLACE semantics: keys absent from the new push must
        // disappear, not merge with the previous cache. A regression
        // here would cause stale addresses to live forever once
        // they'd ever been pushed.
        let cache = AddressCache::new();
        let now = Instant::now();
        cache.replace(
            vec![
                (pubkey(1), vec!["a:9735".into()], 100),
                (pubkey(2), vec!["b:9735".into()], 100),
            ],
            now,
        );
        cache.replace(vec![(pubkey(1), vec!["a:9735".into()], 101)], now);
        assert_eq!(cache.lookup_at(&pubkey(1), now), vec!["a:9735".to_string()]);
        assert!(cache.lookup_at(&pubkey(2), now).is_empty());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn empty_address_lists_are_skipped() {
        // A NodeAddresses entry with zero addresses is a no-op on
        // lookup, so skip it on insert to keep the cache compact.
        let cache = AddressCache::new();
        let inserted = cache.replace(
            vec![
                (pubkey(1), vec![], 100),
                (pubkey(2), vec!["a:9735".into()], 100),
            ],
            Instant::now(),
        );
        assert_eq!(inserted, 1);
    }

    #[test]
    fn entry_past_ttl_returns_empty() {
        let cache = AddressCache::new();
        let pk = pubkey(1);
        let inserted_at = Instant::now();
        cache.replace(vec![(pk, vec!["a:9735".into()], 100)], inserted_at);
        let still_fresh = inserted_at
            + AddressCache::ENTRY_TTL
                .checked_sub(Duration::from_secs(1))
                .expect("TTL > 1s");
        assert!(!cache.lookup_at(&pk, still_fresh).is_empty());
        let stale = inserted_at + AddressCache::ENTRY_TTL + Duration::from_secs(1);
        assert!(cache.lookup_at(&pk, stale).is_empty());
    }

    #[test]
    fn lookup_reason_distinguishes_miss_kinds() {
        // Each miss path must surface a distinct reason so the
        // gateway's log line can tell an operator which mechanism
        // dropped the lookup. The reasons drive separate
        // troubleshooting paths.
        let cache = AddressCache::new();
        let pk = pubkey(1);
        let inserted_at = Instant::now();
        // Missing
        match cache.lookup_reason_at(&pk, inserted_at) {
            LookupReason::Missing => {}
            other => panic!("expected Missing, got {other:?}"),
        }
        // Hit
        cache.replace(vec![(pk, vec!["a:9735".into()], 100)], inserted_at);
        match cache.lookup_reason_at(&pk, inserted_at) {
            LookupReason::Hit(addrs) => assert_eq!(addrs, vec!["a:9735".to_string()]),
            other => panic!("expected Hit, got {other:?}"),
        }
        // Expired
        let stale = inserted_at + AddressCache::ENTRY_TTL + Duration::from_secs(1);
        match cache.lookup_reason_at(&pk, stale) {
            LookupReason::Expired { .. } => {}
            other => panic!("expected Expired, got {other:?}"),
        }
        // Negatively cached
        let failed_at = inserted_at + Duration::from_secs(60);
        cache.record_failure_at(&pk, failed_at);
        let just_after = failed_at + Duration::from_secs(30);
        match cache.lookup_reason_at(&pk, just_after) {
            LookupReason::NegativelyCached { .. } => {}
            other => panic!("expected NegativelyCached, got {other:?}"),
        }
    }

    #[test]
    fn negative_cache_expires_after_failure_ttl() {
        let cache = AddressCache::new();
        let pk = pubkey(1);
        let inserted_at = Instant::now();
        cache.replace(vec![(pk, vec!["a:9735".into()], 100)], inserted_at);
        let failed_at = inserted_at + Duration::from_secs(60);
        cache.record_failure_at(&pk, failed_at);
        // Still suppressed within the window.
        assert!(cache
            .lookup_at(
                &pk,
                failed_at
                    + AddressCache::FAILURE_TTL
                        .checked_sub(Duration::from_secs(1))
                        .expect("TTL > 1s"),
            )
            .is_empty());
        // After the window the addresses come back. Pinned so a
        // future change that "remembers forever" is caught — the
        // operator must always get a fresh chance to dial after a
        // backoff window.
        assert!(!cache
            .lookup_at(
                &pk,
                failed_at + AddressCache::FAILURE_TTL + Duration::from_secs(1)
            )
            .is_empty());
    }

    #[test]
    fn record_failure_on_missing_entry_is_noop() {
        // No insert. If the runner records a failure for a pubkey we
        // never cached (it dialed from the event hint or NetworkGraph
        // fallback), don't synthesise an entry: a later push is
        // authoritative.
        let cache = AddressCache::new();
        cache.record_failure_at(&pubkey(1), Instant::now());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn lookup_preserves_address_order() {
        // try_addresses walks the list in order; the sender's
        // preference (e.g. .onion first when SOCKS5 is configured)
        // must survive replace + lookup.
        let cache = AddressCache::new();
        let pk = pubkey(1);
        let now = Instant::now();
        cache.replace(
            vec![(
                pk,
                vec![
                    "onion-first.onion:9735".into(),
                    "1.2.3.4:9735".into(),
                    "fallback.onion:9735".into(),
                ],
                100,
            )],
            now,
        );
        assert_eq!(
            cache.lookup_at(&pk, now),
            vec![
                "onion-first.onion:9735".to_string(),
                "1.2.3.4:9735".to_string(),
                "fallback.onion:9735".to_string(),
            ],
        );
    }
}
