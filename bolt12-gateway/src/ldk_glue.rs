// SPDX-License-Identifier: MIT
//! LDK glue layer.
//!
//! Owns the long-lived `OnionMessenger` + `PeerManager` stack that
//! gives the gateway a real Lightning identity and onion-message
//! transport. The Python orchestrator drives this over gRPC and
//! never speaks LDK directly.
//!
//! Concretely this module owns:
//! * a 32-byte seed persisted on disk (`<data_dir>/seed`, mode 0600);
//! * a [`KeysManager`] derived from that seed (`get_node_id` is the
//!   gateway's stable Lightning node-id);
//! * an in-memory [`NetworkGraph`] populated only with peers we
//!   actively connect to — this is enough for [`DefaultMessageRouter`]
//!   to route onion messages but we do not consume gossip;
//! * a custom [`OffersMessageHandler`] (`GatewayOffersHandler`) that
//!   captures inbound parsed BOLT-12 messages and serialises them
//!   back to wire bytes for delivery over the gRPC `StreamInbound`,
//!   and exposes a queue that the gateway uses to push outbound
//!   messages produced by `SendOnionMessage`;
//! * an [`OnionMessenger`] driving the BOLT-12 message-handling state
//!   machine on top of all of the above;
//! * a [`PeerManager`] (onion-message-only — we do not own channels)
//!   wired to `lightning-net-tokio` for socket I/O.

use std::collections::{HashMap, VecDeque};
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::lock_recover::lock_recover;

use anyhow::Context as _;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1};

use lightning::blinded_path::message::{
    BlindedMessagePath, MessageContext, MessageForwardNode, OffersContext,
};
use lightning::blinded_path::EmptyNodeIdLookUp;
use lightning::ln::peer_handler::{
    ErroringMessageHandler, IgnoringMessageHandler, MessageHandler, PeerManager,
};
use lightning::offers::invoice::Bolt12Invoice;
use lightning::offers::invoice_error::InvoiceError;
use lightning::offers::invoice_request::InvoiceRequest;
use lightning::offers::nonce::Nonce;
use lightning::offers::static_invoice::StaticInvoice;
use lightning::onion_message::messenger::{
    DefaultMessageRouter, Destination, MessageSendInstructions, OnionMessenger, Responder,
    ResponseInstruction,
};
use lightning::onion_message::offers::{OffersMessage, OffersMessageHandler};
use lightning::routing::gossip::NetworkGraph;
use lightning::sign::{KeysManager, NodeSigner, Recipient};
use lightning::util::logger::{Level, Logger, Record};
use lightning::util::ser::{BigSize, Readable, Writeable};
use lightning_net_tokio::SocketDescriptor;

/// Length of the on-disk seed file in bytes.
pub const SEED_LEN: usize = 32;

// BOLT 4 onion-message inner-TLV types we recognise on outbound
// (also the values OffersMessage::tlv_type returns).
const INVOICE_REQUEST_TLV_TYPE: u64 = 64;
const INVOICE_TLV_TYPE: u64 = 66;
const INVOICE_ERROR_TLV_TYPE: u64 = 68;
const STATIC_INVOICE_TLV_TYPE: u64 = 70;

// ─── Logger ──────────────────────────────────────────────────────────

/// Logger that forwards LDK records into the `tracing` ecosystem.
#[derive(Default)]
pub struct GatewayLogger;

impl Logger for GatewayLogger {
    fn log(&self, record: Record) {
        match record.level {
            Level::Gossip | Level::Trace => {
                tracing::trace!(target: "bolt12_gateway::ldk", "{}", record.args);
            }
            Level::Debug => {
                tracing::debug!(target: "bolt12_gateway::ldk", "{}", record.args);
            }
            Level::Info => {
                tracing::info!(target: "bolt12_gateway::ldk", "{}", record.args);
            }
            Level::Warn => {
                tracing::warn!(target: "bolt12_gateway::ldk", "{}", record.args);
            }
            Level::Error => {
                tracing::error!(target: "bolt12_gateway::ldk", "{}", record.args);
            }
        }
    }
}

// ─── Inbound / outbound queues ───────────────────────────────────────

/// One inbound onion message decoded by LDK and serialised back to
/// wire bytes for the gRPC consumer.
#[derive(Debug, Clone)]
pub struct InboundOnion {
    pub payload_tlv_type: u64,
    pub payload: Vec<u8>,
    pub reply_path: Option<Vec<u8>>,
    pub received_at_ms: i64,
    pub inbound_context: Vec<u8>,
}

struct OutboundOnion {
    contents: OffersMessage,
    instructions: MessageSendInstructions,
}

/// Hard cap on the number of outstanding blinded-path contexts. Each
/// `CreateBlindedPath` registers one entry that is only removed when a
/// reply arrives along that exact path; paths that never receive a reply
/// (timed-out `fetchinvoice` round-trips, offers that are never paid)
/// would otherwise leak entries forever. Bounding the insertion-order
/// queue transitively bounds the map, so an actor that drives
/// `CreateBlindedPath` cannot grow gateway memory without limit.
const MAX_PENDING_CONTEXTS: usize = 16_384;

/// Bounded side-table of outstanding blinded-path contexts. `map` holds
/// the live entries; `order` records insertion order so the oldest can be
/// evicted once the cap is exceeded (consumed keys linger in `order`
/// until evicted, which is fine — `order` itself is the bound).
#[derive(Default)]
struct PendingContexts {
    map: HashMap<[u8; Nonce::LENGTH], Vec<u8>>,
    order: VecDeque<[u8; Nonce::LENGTH]>,
}

/// Offers handler implementation owned by the gateway.
pub struct GatewayOffersHandler {
    inbound: tokio::sync::broadcast::Sender<InboundOnion>,
    outbound: Mutex<VecDeque<OutboundOnion>>,
    /// Side-table mapping the 16-byte LDK [`Nonce`] embedded in
    /// `OffersContext::InvoiceRequest` to the opaque context bytes
    /// the Python orchestrator supplied when calling
    /// `CreateBlindedPath`. We can only carry ≤16 raw bytes through
    /// LDK's typed `OffersContext` enum, so the gateway maintains
    /// this in-memory map and surfaces the bytes via
    /// `InboundOnion.inbound_context` when a message arrives along
    /// the path. Entries are consumed on first lookup and bounded by
    /// `MAX_PENDING_CONTEXTS`.
    pending_contexts: Mutex<PendingContexts>,
}

impl GatewayOffersHandler {
    fn new() -> Self {
        let (inbound, _rx) = tokio::sync::broadcast::channel(256);
        Self {
            inbound,
            outbound: Mutex::new(VecDeque::new()),
            pending_contexts: Mutex::new(PendingContexts::default()),
        }
    }

    /// Register opaque context bytes under a fresh nonce drawn from
    /// `entropy_source` and return the nonce. The caller embeds the
    /// nonce inside an `OffersContext::InvoiceRequest` of a freshly
    /// minted [`BlindedMessagePath`].
    pub fn register_context<ES>(&self, context_bytes: Vec<u8>, entropy_source: &ES) -> Nonce
    where
        ES: lightning::sign::EntropySource,
    {
        let nonce = Nonce::from_entropy_source(entropy_source);
        let key = *<&[u8; Nonce::LENGTH]>::try_from(nonce.as_slice()).expect("nonce length");
        let mut pc = lock_recover(&self.pending_contexts);
        // Empty contexts still occupy a slot so that an empty inbound
        // payload remains distinguishable from "no path matched".
        pc.map.insert(key, context_bytes);
        pc.order.push_back(key);
        // Evict the oldest entries once the insertion-order queue exceeds
        // the cap; this transitively bounds `map`. A popped key that was
        // already consumed simply removes nothing.
        while pc.order.len() > MAX_PENDING_CONTEXTS {
            if let Some(old) = pc.order.pop_front() {
                pc.map.remove(&old);
            } else {
                break;
            }
        }
        nonce
    }

    /// Pop and return the context previously registered under
    /// `nonce`, or `None` if no entry exists.
    fn consume_context(&self, nonce: &Nonce) -> Option<Vec<u8>> {
        let key = <&[u8; Nonce::LENGTH]>::try_from(nonce.as_slice()).ok()?;
        lock_recover(&self.pending_contexts).map.remove(key)
    }

    /// Test/metrics helper.
    #[must_use]
    pub fn pending_contexts_len(&self) -> usize {
        lock_recover(&self.pending_contexts).map.len()
    }

    /// Subscribe to the inbound stream.
    pub fn subscribe_inbound(&self) -> tokio::sync::broadcast::Receiver<InboundOnion> {
        self.inbound.subscribe()
    }

    /// Queue an outbound BOLT-12 message for the next event-pump
    /// cycle. Returns the TLV type of the queued message.
    pub fn enqueue_outbound(
        &self,
        contents: OffersMessage,
        instructions: MessageSendInstructions,
    ) -> u64 {
        let tlv = match &contents {
            OffersMessage::InvoiceRequest(_) => INVOICE_REQUEST_TLV_TYPE,
            OffersMessage::Invoice(_) => INVOICE_TLV_TYPE,
            OffersMessage::InvoiceError(_) => INVOICE_ERROR_TLV_TYPE,
            OffersMessage::StaticInvoice(_) => STATIC_INVOICE_TLV_TYPE,
        };
        lock_recover(&self.outbound).push_back(OutboundOnion {
            contents,
            instructions,
        });
        tlv
    }

    /// Number of currently buffered outbound messages — exposed for
    /// tests and metrics.
    #[must_use]
    pub fn pending_outbound_len(&self) -> usize {
        lock_recover(&self.outbound).len()
    }
}

impl OffersMessageHandler for GatewayOffersHandler {
    fn handle_message(
        &self,
        message: OffersMessage,
        context: Option<OffersContext>,
        responder: Option<Responder>,
    ) -> Option<(OffersMessage, ResponseInstruction)> {
        let tlv_type = match &message {
            OffersMessage::InvoiceRequest(_) => INVOICE_REQUEST_TLV_TYPE,
            OffersMessage::Invoice(_) => INVOICE_TLV_TYPE,
            OffersMessage::InvoiceError(_) => INVOICE_ERROR_TLV_TYPE,
            OffersMessage::StaticInvoice(_) => STATIC_INVOICE_TLV_TYPE,
        };
        let mut payload = Vec::new();
        if let Err(err) = message.write(&mut payload) {
            tracing::warn!(
                target: "bolt12_gateway::ldk",
                ?err,
                tlv_type,
                "failed to serialise inbound offers message; dropping",
            );
            return None;
        }

        let reply_path = responder.as_ref().and_then(extract_reply_path_bytes);

        // Reply-path introduction-node diagnostic (DEBUG). The
        // payer-built reply path's introduction node is the LDK-
        // visible peer the gateway will dial via the
        // ConnectionNeeded handler. Logging the leading bytes of
        // the encoded reply_path (which begin with the intro
        // pubkey after the outer length prefix) lets an operator
        // correlate "Ocean's reply path went via X" with the
        // wallet's audit row — without flipping the gateway to
        // TRACE level (which emits ~50× more noise).
        if let Some(rp_bytes) = reply_path.as_ref() {
            if rp_bytes.len() >= 33 {
                tracing::debug!(
                    target: "bolt12_gateway::ldk",
                    tlv_type,
                    reply_path_intro_prefix = %hex::encode(&rp_bytes[..33]),
                    "inbound invreq: reply-path introduction extracted",
                );
            }
        }

        // Diagnostic for the silent-drop class of bugs (e.g. an LDK
        // upgrade that changes the `Responder` wire layout): we want
        // an INFO-level breadcrumb whenever a Some(responder) yields
        // a None reply_path on the way out to the Python orchestrator.
        // The orchestrator drops invreqs without a reply_path, and
        // without this log the only symptom is the peer timing out.
        if responder.is_some() && reply_path.is_none() {
            tracing::warn!(
                target: "bolt12_gateway::ldk",
                tlv_type,
                "Inbound onion message carried a Responder but reply_path \
                 extraction returned None — Python orchestrator will drop \
                 the invreq. See raw_hex diagnostic above.",
            );
        }

        let received_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0);

        // If the message arrived along a blinded path we issued via
        // `CreateBlindedPath`, recover the orchestrator-supplied
        // context bytes. Other context variants are surfaced as
        // empty (per proto contract).
        let inbound_context = match context {
            Some(OffersContext::InvoiceRequest { nonce }) => {
                self.consume_context(&nonce).unwrap_or_default()
            }
            _ => Vec::new(),
        };

        let inbound = InboundOnion {
            payload_tlv_type: tlv_type,
            payload,
            reply_path,
            received_at_ms,
            inbound_context,
        };
        // broadcast::send only fails when no live subscribers — fine
        // during gateway-without-Python bring-up.
        let _ = self.inbound.send(inbound);

        // Python orchestrator emits responses asynchronously via
        // SendOnionMessage. Never reply synchronously here.
        None
    }

    fn release_pending_messages(&self) -> Vec<(OffersMessage, MessageSendInstructions)> {
        let mut q = lock_recover(&self.outbound);
        let drained: Vec<OutboundOnion> = q.drain(..).collect();
        drop(q);
        drained
            .into_iter()
            .map(|o| (o.contents, o.instructions))
            .collect()
    }
}

// ─── LDK type aliases ────────────────────────────────────────────────

type Logr = Arc<GatewayLogger>;
type GraphArc = Arc<NetworkGraph<Logr>>;
type Router = Arc<DefaultMessageRouter<GraphArc, Logr, Arc<KeysManager>>>;
type Lookup = Arc<EmptyNodeIdLookUp>;
type Ignoring = Arc<IgnoringMessageHandler>;
type Erroring = Arc<ErroringMessageHandler>;
type Offers = Arc<GatewayOffersHandler>;

pub type GatewayOnionMessenger = OnionMessenger<
    Arc<KeysManager>,
    Arc<KeysManager>,
    Logr,
    Lookup,
    Router,
    Offers,
    Ignoring,
    Ignoring,
    Ignoring,
>;

pub type GatewayPeerManager = PeerManager<
    SocketDescriptor,
    Erroring,
    Ignoring,
    Arc<GatewayOnionMessenger>,
    Logr,
    Ignoring,
    Arc<KeysManager>,
    Ignoring,
>;

// ─── State ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct IdentitySnapshot {
    pub node_id: PublicKey,
    pub network: bitcoin::Network,
}

pub struct GatewayState {
    keys_manager: Arc<KeysManager>,
    node_id: PublicKey,
    network: bitcoin::Network,
    logger: Logr,
    network_graph: GraphArc,
    offers_handler: Offers,
    onion_messenger: Arc<GatewayOnionMessenger>,
    peer_manager: Arc<GatewayPeerManager>,
    // Per-pubkey async locks serialising ConnectPeer + the sticky-
    // peer reconnect loop so two callers can't race a duplicate dial
    // through LDK's PeerManager. See `sticky_peers.rs` module docs.
    dial_locks: crate::sticky_peers::DialLocks,
    // Sticky-peer registry — the set of peers the gateway's
    // reconnect loop tries to keep up. Replaced atomically by the
    // SetStickyPeers RPC. Empty by default; a pre-Python-startup
    // gateway has no sticky peers, which matches the existing
    // behaviour.
    sticky_registry: crate::sticky_peers::StickyRegistry,
    // Wallet-pushed cache of known peer addresses. Consulted by
    // ``runner::handle_connection_needed`` when LDK fires
    // ``Event::ConnectionNeeded`` for a peer we have no addresses
    // for via the event hint or NetworkGraph. The cache is empty
    // until Python pushes via ``SetKnownNodeAddresses``; entries
    // age out on lookup via the cache's own TTL semantics.
    address_cache: Arc<crate::address_cache::AddressCache>,
}

impl GatewayState {
    pub fn load_or_create(data_dir: &Path, network: bitcoin::Network) -> anyhow::Result<Self> {
        let seed = load_or_create_seed(data_dir)?;
        Self::from_seed(seed, network)
    }

    fn from_seed(seed: [u8; SEED_LEN], network: bitcoin::Network) -> anyhow::Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before UNIX epoch")?;

        let keys_manager = Arc::new(KeysManager::new(
            &seed,
            now.as_secs(),
            now.subsec_nanos(),
            // BOLT-12 gateway never opens channels.
            false,
        ));

        let node_id = keys_manager
            .get_node_id(Recipient::Node)
            .map_err(|()| anyhow::anyhow!("KeysManager refused to derive node id"))?;

        let logger: Logr = Arc::new(GatewayLogger);

        let network_graph: GraphArc = Arc::new(NetworkGraph::new(network, Arc::clone(&logger)));

        let message_router: Router = Arc::new(DefaultMessageRouter::new(
            Arc::clone(&network_graph),
            Arc::clone(&keys_manager),
        ));

        let offers_handler: Offers = Arc::new(GatewayOffersHandler::new());

        let node_id_lookup: Lookup = Arc::new(EmptyNodeIdLookUp {});

        let ignoring: Ignoring = Arc::new(IgnoringMessageHandler {});

        let onion_messenger: Arc<GatewayOnionMessenger> = Arc::new(OnionMessenger::new(
            Arc::clone(&keys_manager),
            Arc::clone(&keys_manager),
            Arc::clone(&logger),
            Arc::clone(&node_id_lookup),
            Arc::clone(&message_router),
            Arc::clone(&offers_handler),
            Arc::clone(&ignoring),
            Arc::clone(&ignoring),
            Arc::clone(&ignoring),
        ));

        let mut ephemeral = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ephemeral);

        let current_time = u32::try_from(now.as_secs() & u64::from(u32::MAX)).unwrap_or(0);

        let chan_handler: Erroring = Arc::new(ErroringMessageHandler::new());

        let peer_manager: Arc<GatewayPeerManager> = Arc::new(PeerManager::new(
            MessageHandler {
                chan_handler: Arc::clone(&chan_handler),
                route_handler: Arc::clone(&ignoring),
                onion_message_handler: Arc::clone(&onion_messenger),
                custom_message_handler: Arc::clone(&ignoring),
                send_only_message_handler: Arc::clone(&ignoring),
            },
            current_time,
            &ephemeral,
            Arc::clone(&logger),
            Arc::clone(&keys_manager),
        ));

        Ok(Self {
            keys_manager,
            node_id,
            network,
            logger,
            network_graph,
            offers_handler,
            onion_messenger,
            peer_manager,
            dial_locks: crate::sticky_peers::DialLocks::new(),
            sticky_registry: crate::sticky_peers::StickyRegistry::new(),
            address_cache: Arc::new(crate::address_cache::AddressCache::new()),
        })
    }

    pub fn identity_snapshot(&self) -> IdentitySnapshot {
        IdentitySnapshot {
            node_id: self.node_id,
            network: self.network,
        }
    }

    pub fn node_id(&self) -> PublicKey {
        self.node_id
    }

    pub fn peer_manager(&self) -> Arc<GatewayPeerManager> {
        Arc::clone(&self.peer_manager)
    }

    pub fn dial_locks(&self) -> crate::sticky_peers::DialLocks {
        self.dial_locks.clone()
    }

    pub fn sticky_registry(&self) -> crate::sticky_peers::StickyRegistry {
        self.sticky_registry.clone()
    }

    pub fn address_cache(&self) -> Arc<crate::address_cache::AddressCache> {
        Arc::clone(&self.address_cache)
    }

    pub fn onion_messenger(&self) -> Arc<GatewayOnionMessenger> {
        Arc::clone(&self.onion_messenger)
    }

    pub fn offers_handler(&self) -> Offers {
        Arc::clone(&self.offers_handler)
    }

    pub fn keys_manager(&self) -> Arc<KeysManager> {
        Arc::clone(&self.keys_manager)
    }

    pub fn network_graph(&self) -> GraphArc {
        Arc::clone(&self.network_graph)
    }

    pub fn logger(&self) -> Logr {
        Arc::clone(&self.logger)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn load_or_create_seed(data_dir: &Path) -> anyhow::Result<[u8; SEED_LEN]> {
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("create data dir {}", data_dir.display()))?;

    let seed_path = data_dir.join("seed");
    if seed_path.exists() {
        let raw = std::fs::read(&seed_path)
            .with_context(|| format!("read seed {}", seed_path.display()))?;
        anyhow::ensure!(
            raw.len() == SEED_LEN,
            "seed file {} has wrong length: expected {SEED_LEN}, got {}",
            seed_path.display(),
            raw.len()
        );
        let mut buf = [0u8; SEED_LEN];
        buf.copy_from_slice(&raw);
        Ok(buf)
    } else {
        let mut buf = [0u8; SEED_LEN];
        rand::thread_rng().fill_bytes(&mut buf);
        write_seed(&seed_path, &buf)
            .with_context(|| format!("write seed {}", seed_path.display()))?;
        Ok(buf)
    }
}

#[cfg(unix)]
fn write_seed(path: &Path, seed: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(seed)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_seed(path: &Path, seed: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, seed)
}

/// Extract the wire-format `BlindedMessagePath` bytes out of a
/// [`Responder`].
///
/// LDK's [`Responder`] keeps the reply-path private; its `Writeable`
/// impl is a length-prefixed TLV stream `{ 0: BlindedMessagePath }`.
///
/// Wire layout produced by LDK's `impl_writeable_tlv_based!` macro:
///
/// ```text
///   <BigSize: total_length>
///       <BigSize: type=0> <BigSize: length> <reply_path bytes>
///       [...optional future TLVs ignored here...]
/// ```
///
/// The outer length must be peeled before reading TLV records; otherwise
/// the first `BigSize` read produces the *stream length* (≠ 0) and we
/// silently miss the `reply_path` field, returning `None` for every real
/// inbound invreq. This bug was latent through regtest because the
/// Python integration tests inject `reply_path: bytes` directly into the
/// orchestrator's `InboundInvreqContext` and never round-trip through
/// this extractor.
fn extract_reply_path_bytes(responder: &Responder) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    if responder.write(&mut buf).is_err() {
        tracing::warn!(
            target: "bolt12_gateway::ldk",
            "Responder::write failed; dropping reply_path",
        );
        return None;
    }
    match parse_length_prefixed_tlv_type_zero(&buf) {
        Ok(bytes) => Some(bytes),
        Err(reason) => {
            tracing::warn!(
                target: "bolt12_gateway::ldk",
                reason,
                raw_hex = %hex::encode(&buf),
                "Responder TLV parse failed; dropping reply_path",
            );
            None
        }
    }
}

/// Parse the TLV value at type 0 from an LDK length-prefixed TLV
/// stream (the wire format produced by `impl_writeable_tlv_based!`).
///
/// Returns the raw value bytes at type 0, or a static error string
/// describing why the buffer couldn't be parsed. Factored out of
/// [`extract_reply_path_bytes`] so the byte-parsing logic is unit
/// testable without needing to construct an LDK `Responder` (whose
/// constructor is `pub(super)` to this crate).
fn parse_length_prefixed_tlv_type_zero(buf: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut cursor = std::io::Cursor::new(buf);

    // Peel the outer varint length prefix.
    let total_len = BigSize::read(&mut cursor)
        .map_err(|_| "outer length missing")?
        .0;
    let total_len = usize::try_from(total_len).map_err(|_| "outer length overflows usize")?;
    let start = usize::try_from(cursor.position()).unwrap_or(usize::MAX);
    let end = start
        .checked_add(total_len)
        .ok_or("outer length + offset overflows")?;
    if end > buf.len() {
        return Err("inner stream truncated");
    }

    // Iterate (type, length, value) records inside the framed body.
    while usize::try_from(cursor.position()).unwrap_or(usize::MAX) < end {
        let tlv_type = BigSize::read(&mut cursor)
            .map_err(|_| "tlv type missing")?
            .0;
        let len = BigSize::read(&mut cursor)
            .map_err(|_| "tlv length missing")?
            .0;
        let len = usize::try_from(len).map_err(|_| "tlv length overflows usize")?;
        // Bound the allocation to the bytes actually remaining in the
        // framed body before reserving — a record claiming a length far
        // larger than the frame must fail cheaply, not attempt a huge
        // allocation up front.
        let pos = usize::try_from(cursor.position()).unwrap_or(usize::MAX);
        if len > end.saturating_sub(pos) {
            return Err("tlv value truncated");
        }
        let mut value = vec![0u8; len];
        cursor
            .read_exact(&mut value)
            .map_err(|_| "tlv value truncated")?;
        if tlv_type == 0 {
            return Ok(value);
        }
    }

    Err("no tlv type 0 present")
}

/// Build [`MessageSendInstructions`] from a [`Destination`] and
/// optional reply-path bytes.
pub fn build_send_instructions(
    destination: Destination,
    reply_path_bytes: Option<&[u8]>,
) -> anyhow::Result<MessageSendInstructions> {
    if let Some(bytes) = reply_path_bytes {
        let mut cursor = std::io::Cursor::new(bytes);
        let path = BlindedMessagePath::read(&mut cursor)
            .map_err(|e| anyhow::anyhow!("decode reply_path: {e:?}"))?;
        Ok(MessageSendInstructions::WithSpecifiedReplyPath {
            destination,
            reply_path: path,
        })
    } else {
        Ok(MessageSendInstructions::WithoutReplyPath { destination })
    }
}

/// Parse opaque payload bytes into an [`OffersMessage`] based on the
/// caller-supplied inner-TLV type.
pub fn decode_offers_message(tlv_type: u64, payload: Vec<u8>) -> anyhow::Result<OffersMessage> {
    match tlv_type {
        INVOICE_REQUEST_TLV_TYPE => InvoiceRequest::try_from(payload)
            .map(OffersMessage::InvoiceRequest)
            .map_err(|e| anyhow::anyhow!("invoice_request decode: {e:?}")),
        INVOICE_TLV_TYPE => Bolt12Invoice::try_from(payload)
            .map(OffersMessage::Invoice)
            .map_err(|e| anyhow::anyhow!("invoice decode: {e:?}")),
        STATIC_INVOICE_TLV_TYPE => StaticInvoice::try_from(payload)
            .map(OffersMessage::StaticInvoice)
            .map_err(|e| anyhow::anyhow!("static_invoice decode: {e:?}")),
        INVOICE_ERROR_TLV_TYPE => {
            let mut cursor = std::io::Cursor::new(payload.as_slice());
            InvoiceError::read(&mut cursor)
                .map(OffersMessage::InvoiceError)
                .map_err(|e| anyhow::anyhow!("invoice_error decode: {e:?}"))
        }
        other => Err(anyhow::anyhow!(
            "unsupported BOLT-12 inner TLV type {other}; expected 64/66/68/70",
        )),
    }
}

/// Decode a serialised [`BlindedMessagePath`] from the gRPC wire
/// representation.
pub fn decode_blinded_message_path(bytes: &[u8]) -> anyhow::Result<BlindedMessagePath> {
    let mut cursor = std::io::Cursor::new(bytes);
    BlindedMessagePath::read(&mut cursor).map_err(|e| anyhow::anyhow!("decode blinded_path: {e:?}"))
}

/// Build a [`Destination::BlindedPath`] from wire bytes.
pub fn blinded_destination_from_bytes(bytes: &[u8]) -> anyhow::Result<Destination> {
    Ok(Destination::BlindedPath(decode_blinded_message_path(
        bytes,
    )?))
}

/// Maximum number of dummy hops we will pad a path with. Mirrors
/// the proto's `0..=7` range.
pub const MAX_DUMMY_HOPS: usize = 7;

/// Build a [`BlindedMessagePath`] terminating at this gateway, using
/// the first introduction-node candidate we are currently peered
/// with as the unblinded entry hop. Returns the serialised on-wire
/// representation ready to drop into a BOLT 12 TLV.
///
/// The orchestrator-supplied `context_bytes` are stashed in the
/// gateway's in-memory side-table keyed on a fresh
/// [`OffersContext::InvoiceRequest`] nonce. When a message later
/// arrives along the path, those bytes are surfaced via
/// [`InboundOnion::inbound_context`].
pub fn create_blinded_message_path(
    state: &GatewayState,
    introduction_candidates: &[PublicKey],
    dummy_hops: usize,
    context_bytes: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        !introduction_candidates.is_empty(),
        "at least one introduction-node candidate is required",
    );
    anyhow::ensure!(
        dummy_hops <= MAX_DUMMY_HOPS,
        "dummy_hops {dummy_hops} exceeds maximum {MAX_DUMMY_HOPS}",
    );

    let pm = state.peer_manager();
    let intro = introduction_candidates
        .iter()
        .find(|pk| pm.peer_by_node_id(pk).is_some())
        .copied()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "none of the {} introduction-node candidates are currently \
                 peered with this gateway",
                introduction_candidates.len(),
            )
        })?;

    let keys_manager = state.keys_manager();
    let nonce = state
        .offers_handler()
        .register_context(context_bytes, &*keys_manager);
    let context = MessageContext::Offers(OffersContext::InvoiceRequest { nonce });

    let receive_key = keys_manager.get_receive_auth_key();
    let secp_ctx = Secp256k1::new();

    let intermediate = [MessageForwardNode {
        node_id: intro,
        short_channel_id: None,
    }];

    let path = BlindedMessagePath::new_with_dummy_hops(
        &intermediate,
        state.node_id(),
        dummy_hops,
        receive_key,
        context,
        keys_manager,
        &secp_ctx,
    );

    let mut buf = Vec::new();
    path.write(&mut buf)
        .map_err(|e| anyhow::anyhow!("serialise blinded_path: {e:?}"))?;
    Ok(buf)
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn creates_seed_when_missing() {
        let dir = TempDir::new().unwrap();
        let data = dir.path().join("state");
        assert!(!data.exists());

        let state =
            GatewayState::load_or_create(&data, bitcoin::Network::Regtest).expect("load_or_create");

        let seed_path = data.join("seed");
        let raw = std::fs::read(&seed_path).expect("seed exists");
        assert_eq!(raw.len(), SEED_LEN, "seed must be exactly {SEED_LEN} bytes");

        let serialized = state.identity_snapshot().node_id.serialize();
        assert_eq!(serialized.len(), 33);
    }

    #[cfg(unix)]
    #[test]
    fn seed_file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let data = dir.path().join("state");
        GatewayState::load_or_create(&data, bitcoin::Network::Regtest).expect("load_or_create");

        let meta = std::fs::metadata(data.join("seed")).expect("stat seed");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected mode 0600, got {mode:o}");
    }

    #[test]
    fn reusing_seed_yields_same_node_id() {
        let dir = TempDir::new().unwrap();
        let data = dir.path().join("state");

        let first =
            GatewayState::load_or_create(&data, bitcoin::Network::Regtest).expect("first load");
        let id1 = first.identity_snapshot().node_id;
        drop(first);

        let second =
            GatewayState::load_or_create(&data, bitcoin::Network::Regtest).expect("second load");
        let id2 = second.identity_snapshot().node_id;

        assert_eq!(
            id1.serialize(),
            id2.serialize(),
            "node_id must be stable across restarts"
        );
    }

    #[test]
    fn fresh_dirs_yield_distinct_node_ids() {
        let a = TempDir::new().unwrap();
        let b = TempDir::new().unwrap();
        let s1 = GatewayState::load_or_create(a.path(), bitcoin::Network::Regtest).expect("a");
        let s2 = GatewayState::load_or_create(b.path(), bitcoin::Network::Regtest).expect("b");

        assert_ne!(
            s1.identity_snapshot().node_id.serialize(),
            s2.identity_snapshot().node_id.serialize(),
            "independent seeds must produce different node ids"
        );
    }

    #[test]
    fn wrong_length_seed_errors() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(dir.path().join("seed"), b"too short").unwrap();

        let Err(err) = GatewayState::load_or_create(dir.path(), bitcoin::Network::Regtest) else {
            panic!("expected error for wrong-length seed");
        };
        let msg = format!("{err:#}");
        assert!(
            msg.contains("wrong length") || msg.contains("expected"),
            "got: {msg}"
        );
    }

    #[test]
    fn creates_nested_data_dir() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        assert!(!nested.exists());

        GatewayState::load_or_create(&nested, bitcoin::Network::Regtest).expect("load_or_create");
        assert!(nested.is_dir());
        assert!(nested.join("seed").is_file());
    }

    #[test]
    fn peer_manager_starts_with_no_peers() {
        let dir = TempDir::new().unwrap();
        let state =
            GatewayState::load_or_create(dir.path(), bitcoin::Network::Regtest).expect("load");
        assert_eq!(state.peer_manager().list_peers().len(), 0);
    }

    #[test]
    fn decode_offers_message_rejects_unknown_tlv_type() {
        let err = decode_offers_message(99, vec![0u8; 32]).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported"));
    }

    /// Build an LDK length-prefixed TLV stream `{ tlv_type: value }`,
    /// matching the byte layout produced by `impl_writeable_tlv_based!`.
    fn build_length_prefixed_tlv(tlv_type: u64, value: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        BigSize(tlv_type).write(&mut inner).unwrap();
        BigSize(value.len() as u64).write(&mut inner).unwrap();
        inner.extend_from_slice(value);

        let mut outer = Vec::new();
        BigSize(inner.len() as u64).write(&mut outer).unwrap();
        outer.extend_from_slice(&inner);
        outer
    }

    #[test]
    fn parse_length_prefixed_tlv_type_zero_returns_payload() {
        // Mirrors the Responder layout: single TLV `{ 0: reply_path }`.
        let reply_path = vec![0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05];
        let buf = build_length_prefixed_tlv(0, &reply_path);
        let parsed = parse_length_prefixed_tlv_type_zero(&buf).expect("parses");
        assert_eq!(parsed, reply_path);
    }

    #[test]
    fn parse_length_prefixed_tlv_type_zero_skips_higher_types() {
        // If a future LDK release adds TLVs before type 0 in the
        // stream, we should still find type 0 (TLV streams are
        // ordered by type, so type 0 always sorts first — but defend
        // against re-ordering anyway).
        let mut inner = Vec::new();
        BigSize(0u64).write(&mut inner).unwrap();
        BigSize(4u64).write(&mut inner).unwrap();
        inner.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        BigSize(5u64).write(&mut inner).unwrap();
        BigSize(2u64).write(&mut inner).unwrap();
        inner.extend_from_slice(&[0x99, 0x88]);

        let mut outer = Vec::new();
        BigSize(inner.len() as u64).write(&mut outer).unwrap();
        outer.extend_from_slice(&inner);

        let parsed = parse_length_prefixed_tlv_type_zero(&outer).expect("parses");
        assert_eq!(parsed, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn parse_length_prefixed_tlv_type_zero_errors_on_missing_type_zero() {
        // Stream with only a type-5 record — no type 0.
        let mut inner = Vec::new();
        BigSize(5u64).write(&mut inner).unwrap();
        BigSize(2u64).write(&mut inner).unwrap();
        inner.extend_from_slice(&[0x99, 0x88]);

        let mut outer = Vec::new();
        BigSize(inner.len() as u64).write(&mut outer).unwrap();
        outer.extend_from_slice(&inner);

        let err = parse_length_prefixed_tlv_type_zero(&outer).unwrap_err();
        assert_eq!(err, "no tlv type 0 present");
    }

    #[test]
    fn parse_length_prefixed_tlv_type_zero_errors_on_truncated_inner() {
        // Outer length claims 100 bytes but only 4 are present.
        let mut buf = Vec::new();
        BigSize(100u64).write(&mut buf).unwrap();
        buf.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
        let err = parse_length_prefixed_tlv_type_zero(&buf).unwrap_err();
        assert_eq!(err, "inner stream truncated");
    }

    #[test]
    fn parse_length_prefixed_tlv_type_zero_errors_on_empty_buffer() {
        let err = parse_length_prefixed_tlv_type_zero(&[]).unwrap_err();
        assert_eq!(err, "outer length missing");
    }

    #[test]
    fn parse_length_prefixed_tlv_type_zero_handles_zero_length_inner() {
        // Outer length 0 → no inner TLVs → "no tlv type 0".
        let buf = vec![0u8]; // BigSize(0) is a single zero byte
        let err = parse_length_prefixed_tlv_type_zero(&buf).unwrap_err();
        assert_eq!(err, "no tlv type 0 present");
    }
}
