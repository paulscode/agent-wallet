// SPDX-License-Identifier: MIT
//! Sticky-peer set + auto-redial loop.
//!
//! The Python wallet maintains a set of "important" peers (today: the
//! well-known payers list — OCEAN's CLN node, etc.) that should stay
//! connected as long as the gateway is up. Two failure modes existed
//! before this module:
//!
//! 1. **Race on dial.** When two callers (e.g. Python's startup
//!    re-peer + Python's periodic re-peer) hit `ConnectPeer` for the
//!    same pubkey simultaneously, both could pass the
//!    `peer_by_node_id().is_some()` check and both spawn TCP
//!    connections. LDK's `PeerManager` would clean up the loser but
//!    log noise + wasted Tor work in the meantime. Solved here by a
//!    per-pubkey async mutex ([`DialLocks`]) that serialises
//!    `ConnectPeer` calls per-pubkey while still letting different
//!    pubkeys dial in parallel.
//!
//! 2. **Silent disconnect with no recovery.** A flap (network blip,
//!    peer restart, TCP RST) drops the LDK `PeerManager` entry. Nothing
//!    redials. Solved here by an explicit sticky set + dedicated
//!    background loop that watches `peer_by_node_id` for the sticky
//!    pubkeys and redials with exponential backoff when one drops.
//!
//! Coordination with Python:
//! * Python pushes the desired sticky set via the `SetStickyPeers`
//!   RPC. REPLACE semantics — the wallet's periodic task re-pushes
//!   on every tick so a gateway-restart-induced cache loss heals on
//!   the next push.
//! * Both Python's `ConnectPeer` calls AND the sticky-peer loop
//!   funnel through the same [`DialLocks`] guard, so the per-pubkey
//!   serialisation invariant holds across both paths.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use secp256k1::PublicKey;
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;

use crate::lock_recover::lock_recover;

/// Per-pubkey async mutex registry. Acquiring a guard for a given
/// pubkey serialises dial-related work for that pubkey while letting
/// independent pubkeys proceed in parallel.
///
/// Cheap to clone — the inner state is held in an `Arc`. Hand the
/// clone to background tasks; the locks are global to the gateway.
///
/// Memory profile: the inner `HashMap` grows monotonically — an
/// entry is inserted the first time we lock a given pubkey and is
/// never removed. In the wallet's current shape this is bounded by
/// the well-known-payers registry (today: 1) plus the occasional
/// one-off `ConnectPeer` dial, so the steady-state footprint is a
/// few hundred bytes. A future caller that dials many distinct
/// pubkeys would need to add a GC pass.
/// Map from serialised pubkey to its per-pubkey async dial mutex.
type DialLockMap = HashMap<[u8; 33], Arc<TokioMutex<()>>>;

#[derive(Clone, Default)]
pub struct DialLocks {
    inner: Arc<std::sync::Mutex<DialLockMap>>,
}

impl DialLocks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire (or create) the per-pubkey async mutex for `pubkey`
    /// and return its lock guard. Multiple callers for the SAME
    /// pubkey serialise; different pubkeys proceed in parallel.
    pub async fn lock(&self, pubkey: &PublicKey) -> tokio::sync::OwnedMutexGuard<()> {
        let key = pubkey.serialize();
        let mutex = {
            // sync mutex held only for the HashMap insert — never
            // crosses an await.
            let mut map = lock_recover(&self.inner);
            map.entry(key)
                .or_insert_with(|| Arc::new(TokioMutex::new(())))
                .clone()
        };
        mutex.lock_owned().await
    }

    /// Drop entries
    /// whose lock has no outstanding holders (`strong_count == 1`,
    /// meaning the only reference is the map itself) and which are
    /// NOT in `keep`. Returns the number of entries evicted.
    ///
    /// Call periodically (every few minutes) and pass the current
    /// sticky-peer pubkeys as `keep` so the persistent locks survive.
    pub fn gc(&self, keep: &[PublicKey]) -> usize {
        let keep_set: std::collections::HashSet<[u8; 33]> =
            keep.iter().map(secp256k1::PublicKey::serialize).collect();
        let mut map = lock_recover(&self.inner);
        let before = map.len();
        map.retain(|k, v| keep_set.contains(k) || Arc::strong_count(v) > 1);
        before - map.len()
    }

    /// Current entry count — exposed for metrics and tests.
    #[must_use]
    pub fn len(&self) -> usize {
        lock_recover(&self.inner).len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One entry in the sticky set. Mirrors `proto::StickyPeer`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StickyPeerEntry {
    pub node_id: PublicKey,
    pub address: String,
}

/// In-memory sticky-peer registry. Replaced atomically by
/// [`Self::replace`]; read by the background reconnect loop. Cheap
/// to clone — the inner state is held in an `Arc`.
#[derive(Clone, Default)]
pub struct StickyRegistry {
    inner: Arc<std::sync::Mutex<Vec<StickyPeerEntry>>>,
}

impl StickyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the entire set. REPLACE semantics — entries absent
    /// from `peers` are dropped on the next reconnect loop tick.
    pub fn replace(&self, peers: Vec<StickyPeerEntry>) {
        let mut g = lock_recover(&self.inner);
        *g = peers;
    }

    /// Snapshot the current set for the reconnect loop.
    pub fn snapshot(&self) -> Vec<StickyPeerEntry> {
        let g = lock_recover(&self.inner);
        g.clone()
    }

    pub fn len(&self) -> usize {
        let g = lock_recover(&self.inner);
        g.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Reconnect-loop tuning. Exposed so tests can shorten the cadence
/// without touching production defaults.
#[derive(Clone, Copy, Debug)]
pub struct ReconnectConfig {
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub poll_interval: Duration,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
            // How often the loop wakes to check sticky-peer health.
            // The loop also sleeps inside `dial_one` after a failed
            // dial (the per-pubkey backoff), so this interval is the
            // "happy-path" tick: every 5 s scan the sticky set and
            // dial anything missing.
            poll_interval: Duration::from_secs(5),
        }
    }
}

/// Hand-off shared with the running sticky-peer loop. Holding it
/// lets the loop run forever; calling `abort()` shuts it down.
pub struct StickyTaskHandle {
    pub task: JoinHandle<()>,
}

impl StickyTaskHandle {
    pub fn abort(&self) {
        self.task.abort();
    }
}

/// Outcome of a single dial attempt. Surfaces just enough state for
/// the `ConnectPeer` RPC to translate into its proto response.
#[derive(Debug)]
pub enum DialOutcome {
    /// Peer was already connected at lock-acquire time. No socket
    /// activity took place.
    AlreadyConnected,
    /// We dialled and the LDK init handshake completed.
    Connected,
}

/// Errors `dial_peer` can return. Distinguished so the RPC layer
/// can map them to the right gRPC `Status` code.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    #[error("bad address {address}: {source}")]
    BadAddress {
        address: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("tcp connect to {address} timed out")]
    ConnectTimeout { address: String },
    #[error("tcp connect to {address} failed")]
    ConnectFailed { address: String },
    #[error("handshake with {address} did not complete within {timeout_secs}s")]
    HandshakeTimeout { address: String, timeout_secs: u64 },
}

/// Shared dial implementation. Both the `ConnectPeer` RPC and the
/// sticky-peer reconnect loop go through this function so the
/// per-pubkey serialisation invariant holds across both paths.
///
/// Steps:
/// 1. Acquire the per-pubkey async mutex.
/// 2. After the lock, re-check `peer_by_node_id` — a racing dial may
///    have just finished while we were waiting.
/// 3. Open a TCP stream to the peer. If ``socks5_proxy`` is set,
///    tunnel through it (using `SOCKS5h`, so hostnames — including
///    ``.onion`` — are resolved at the proxy, never locally).
///    Otherwise resolve and dial directly.
/// 4. Hand the stream to ``lightning_net_tokio::setup_outbound``.
/// 5. Spawn the LDK connection future (it returns when the peer
///    disconnects).
/// 6. Wait briefly for the BOLT 1 init handshake to land.
pub async fn dial_peer(
    peer_manager: &Arc<crate::ldk_glue::GatewayPeerManager>,
    dial_locks: &DialLocks,
    pubkey: PublicKey,
    address: &str,
    tcp_connect_timeout: Duration,
    handshake_timeout: Duration,
    socks5_proxy: Option<&str>,
) -> Result<DialOutcome, DialError> {
    let _guard = dial_locks.lock(&pubkey).await;

    // After acquiring the lock, re-check. A serialised concurrent
    // caller may have just landed the connection.
    if peer_manager.peer_by_node_id(&pubkey).is_some() {
        return Ok(DialOutcome::AlreadyConnected);
    }

    // Build the TCP stream. Two paths: SOCKS5 tunnel (preferred
    // when configured — works for both ``.onion`` and clearnet,
    // and is the only path that works inside the ``bolt12-internal``
    // docker network which denies direct egress) or plain TCP.
    let std_stream: std::net::TcpStream = if let Some(proxy) = socks5_proxy {
        // ``Socks5Stream::connect(proxy, target)`` does SOCKS5h —
        // remote DNS resolution. Pass the original address string
        // (no local resolve) so ``host.onion:9735`` round-trips to
        // the Tor SOCKS port intact.
        let tunnelled = tokio::time::timeout(
            tcp_connect_timeout,
            tokio_socks::tcp::Socks5Stream::connect(proxy, address),
        )
        .await
        .map_err(|_| DialError::ConnectTimeout {
            address: address.to_string(),
        })?
        .map_err(|_e| DialError::ConnectFailed {
            address: address.to_string(),
        })?;
        // ``into_inner`` peels off the SOCKS5 layer once the
        // handshake with the proxy completes; what remains is the
        // raw tokio TcpStream carrying the peer-side bytes.
        let tokio_tcp = tunnelled.into_inner();
        tokio_tcp.into_std().map_err(|_| DialError::ConnectFailed {
            address: address.to_string(),
        })?
    } else {
        let addr = parse_socket_addr(address)
            .await
            .map_err(|e| DialError::BadAddress {
                address: address.to_string(),
                source: e,
            })?;
        let tokio_tcp =
            tokio::time::timeout(tcp_connect_timeout, tokio::net::TcpStream::connect(addr))
                .await
                .map_err(|_| DialError::ConnectTimeout {
                    address: address.to_string(),
                })?
                .map_err(|_| DialError::ConnectFailed {
                    address: address.to_string(),
                })?;
        tokio_tcp.into_std().map_err(|_| DialError::ConnectFailed {
            address: address.to_string(),
        })?
    };

    // Hand the stream to LDK. ``setup_outbound`` re-registers it
    // with tokio's reactor internally; the returned future drives
    // the connection until disconnect.
    let connection =
        lightning_net_tokio::setup_outbound(Arc::clone(peer_manager), pubkey, std_stream);

    // Drive the connection in the background; the future returns
    // when the peer disconnects.
    tokio::spawn(connection);

    // Wait for handshake completion so the caller sees a peer with
    // its init features populated. Poll cadence matches the existing
    // 100 ms tick.
    let deadline = tokio::time::Instant::now() + handshake_timeout;
    while tokio::time::Instant::now() < deadline {
        if peer_manager.peer_by_node_id(&pubkey).is_some() {
            return Ok(DialOutcome::Connected);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(DialError::HandshakeTimeout {
        address: address.to_string(),
        timeout_secs: handshake_timeout.as_secs(),
    })
}

fn parse_socket_addr_inline(address: &str) -> Option<std::net::SocketAddr> {
    use std::str::FromStr;
    std::net::SocketAddr::from_str(address).ok()
}

/// Resolve `address`
/// without blocking the tonic worker. If `address` is already an
/// `ip:port` literal we skip DNS entirely; otherwise we hand the
/// hostname to tokio's async resolver.
async fn parse_socket_addr(address: &str) -> anyhow::Result<std::net::SocketAddr> {
    if let Some(addr) = parse_socket_addr_inline(address) {
        return Ok(addr);
    }
    let resolved = tokio::net::lookup_host(address)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no address resolved for {address}"))?;
    Ok(resolved)
}

/// Spawn the sticky-peer reconnect loop. Returns immediately; the
/// task runs until aborted.
///
/// Each tick:
/// 1. Snapshot the sticky registry.
/// 2. For each entry, check `peer_manager.peer_by_node_id`. If
///    present, do nothing.
/// 3. Otherwise, attempt a dial through `dial_peer` (which acquires
///    the same per-pubkey lock the `ConnectPeer` RPC uses).
/// 4. On failure, advance that pubkey's per-pubkey backoff so the
///    next retry waits longer. Successful dial resets the backoff.
///
/// The loop is cooperative with the `ConnectPeer` RPC: a Python
/// caller's manual reconnect attempt and the loop's automatic one
/// serialise through `DialLocks`. The first to acquire the lock
/// performs the dial; the other sees `AlreadyConnected` immediately
/// after the lock and returns.
pub fn spawn(
    peer_manager: Arc<crate::ldk_glue::GatewayPeerManager>,
    dial_locks: DialLocks,
    sticky_registry: StickyRegistry,
    config: ReconnectConfig,
    tcp_connect_timeout: Duration,
    handshake_timeout: Duration,
    socks5_proxy: Option<Arc<str>>,
) -> StickyTaskHandle {
    let task = tokio::spawn(async move {
        // Per-pubkey current backoff. Resets to `initial_backoff` on
        // successful dial; doubled (capped) on each failure.
        let mut backoff: HashMap<[u8; 33], Duration> = HashMap::new();
        // Per-pubkey monotonic wall-clock at which we may next try.
        let mut next_attempt: HashMap<[u8; 33], tokio::time::Instant> = HashMap::new();

        loop {
            let snapshot = sticky_registry.snapshot();
            let now = tokio::time::Instant::now();

            for entry in snapshot {
                let key = entry.node_id.serialize();
                if peer_manager.peer_by_node_id(&entry.node_id).is_some() {
                    // Peer is up — reset its backoff so a future
                    // disconnect retries quickly.
                    backoff.remove(&key);
                    next_attempt.remove(&key);
                    continue;
                }
                if let Some(deadline) = next_attempt.get(&key) {
                    if now < *deadline {
                        continue;
                    }
                }

                let outcome = dial_peer(
                    &peer_manager,
                    &dial_locks,
                    entry.node_id,
                    &entry.address,
                    tcp_connect_timeout,
                    handshake_timeout,
                    socks5_proxy.as_deref(),
                )
                .await;

                match outcome {
                    Ok(_) => {
                        backoff.remove(&key);
                        next_attempt.remove(&key);
                        tracing::info!(
                            target: "bolt12_gateway::sticky_peers",
                            node_id = %hex::encode(key),
                            address = %entry.address,
                            "sticky peer reconnected",
                        );
                    }
                    Err(e) => {
                        let cur = backoff.get(&key).copied().unwrap_or(config.initial_backoff);
                        let next = std::cmp::min(cur * 2, config.max_backoff);
                        backoff.insert(key, next);
                        next_attempt.insert(key, now + cur);
                        tracing::warn!(
                            target: "bolt12_gateway::sticky_peers",
                            node_id = %hex::encode(key),
                            address = %entry.address,
                            error = %e,
                            next_retry_in_secs = cur.as_secs(),
                            "sticky peer dial failed",
                        );
                    }
                }
            }

            // Garbage-collect backoff entries for pubkeys that are no
            // longer in the sticky set (Python removed them via a
            // SetStickyPeers replace).
            let current: std::collections::HashSet<[u8; 33]> = sticky_registry
                .snapshot()
                .iter()
                .map(|e| e.node_id.serialize())
                .collect();
            backoff.retain(|k, _| current.contains(k));
            next_attempt.retain(|k, _| current.contains(k));

            tokio::time::sleep(config.poll_interval).await;
        }
    });
    StickyTaskHandle { task }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey};

    fn fake_pubkey(seed: u8) -> PublicKey {
        let sk = SecretKey::from_slice(&[seed.max(1); 32]).expect("valid secret");
        PublicKey::from_secret_key(&Secp256k1::new(), &sk)
    }

    #[tokio::test]
    async fn dial_locks_serialise_same_pubkey() {
        let locks = DialLocks::new();
        let pk = fake_pubkey(1);

        let g1 = locks.lock(&pk).await;
        // Second acquire MUST block until g1 drops.
        let locks2 = locks.clone();
        let pk2 = pk;
        let handle = tokio::spawn(async move {
            let _g2 = locks2.lock(&pk2).await;
            tokio::time::Instant::now()
        });

        // Give the spawned task a beat to actually attempt the lock.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let release_time = tokio::time::Instant::now();
        drop(g1);

        let g2_acquired_at = handle.await.expect("task ok");
        assert!(
            g2_acquired_at >= release_time,
            "second acquire must observe release",
        );
    }

    #[tokio::test]
    async fn dial_locks_parallel_for_different_pubkeys() {
        let locks = DialLocks::new();
        let pk_a = fake_pubkey(1);
        let pk_b = fake_pubkey(2);

        let g_a = locks.lock(&pk_a).await;
        // Holding A must NOT block B.
        let g_b = tokio::time::timeout(Duration::from_millis(50), locks.lock(&pk_b))
            .await
            .expect("different pubkeys must not serialise");
        drop(g_a);
        drop(g_b);
    }

    #[test]
    fn sticky_registry_replace_semantics() {
        let reg = StickyRegistry::new();
        assert_eq!(reg.len(), 0);

        let pk_a = fake_pubkey(1);
        let pk_b = fake_pubkey(2);
        reg.replace(vec![
            StickyPeerEntry {
                node_id: pk_a,
                address: "1.1.1.1:9735".to_string(),
            },
            StickyPeerEntry {
                node_id: pk_b,
                address: "2.2.2.2:9735".to_string(),
            },
        ]);
        assert_eq!(reg.len(), 2);

        // REPLACE: pushing a smaller set drops the missing entry.
        reg.replace(vec![StickyPeerEntry {
            node_id: pk_a,
            address: "1.1.1.1:9735".to_string(),
        }]);
        assert_eq!(reg.len(), 1);
        let snapshot = reg.snapshot();
        assert_eq!(snapshot[0].node_id, pk_a);

        // Empty set clears.
        reg.replace(vec![]);
        assert_eq!(reg.len(), 0);
    }
}
