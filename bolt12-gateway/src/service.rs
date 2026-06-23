// SPDX-License-Identifier: MIT
//! gRPC service implementation.
//!
//! All four RPCs are wired against the LDK stack assembled
//! in `ldk_glue.rs`. The Python orchestrator is the only consumer.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_stream::try_stream;
use futures::Stream;
use rand::RngCore;
use secp256k1::PublicKey;
use tonic::{Request, Response, Status};

use crate::ldk_glue::{
    blinded_destination_from_bytes, build_send_instructions, create_blinded_message_path,
    decode_offers_message, GatewayState, MAX_DUMMY_HOPS,
};
use crate::proto::{
    bolt12_gateway_server::Bolt12Gateway, send_onion_message_request::Destination as ProtoDest,
    BlindedMessagePathBytes, ConnectPeerRequest, ConnectPeerResponse, CreateBlindedPathRequest,
    CreateBlindedPathResponse, GetIdentityRequest, GetIdentityResponse, InboundOnionMessage,
    NodeAddresses, PeerInfo, SendOnionMessageRequest, SendOnionMessageResponse,
    SetKnownNodeAddressesResponse, SetStickyPeersRequest, SetStickyPeersResponse,
    StreamInboundRequest,
};
use crate::sticky_peers::{dial_peer, DialError, DialOutcome, StickyPeerEntry};
use lightning::onion_message::messenger::Destination;

/// TCP connect timeout used by `ConnectPeer` and the sticky-peer
/// reconnect loop. The legacy hard-coded value was 15 s; keep that
/// here so callers see no behavioural change.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Handshake-wait budget — caller side of the BOLT 1 init exchange.
/// Legacy was 50 iterations × 100 ms = 5 s; keep parity.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Cadence of inbound-stream liveness heartbeats. Real onion messages
/// are sporadic — minutes or hours can pass between them — so the
/// stream emits an explicit heartbeat this often during idle. Kept
/// well inside the consumer's 90 s inbound-idle watchdog so a single
/// dropped heartbeat doesn't trip a spurious reconnect.
const INBOUND_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Concrete gRPC service.
pub struct GatewayService {
    state: Arc<GatewayState>,
    /// Shared SOCKS5 proxy used for outbound peer dials. Mirrors
    /// ``GatewayConfig::socks5_proxy``. When ``None`` the dialer
    /// uses plain TCP — only safe for a single-host install where
    /// the gateway has direct internet egress. In every compose
    /// deployment this is ``Some("tor-proxy:9050")`` so peer
    /// traffic is routed through Tor regardless of whether the
    /// address is ``.onion`` or clearnet.
    socks5_proxy: Option<Arc<str>>,
}

impl GatewayService {
    pub fn new(state: Arc<GatewayState>) -> Self {
        Self {
            state,
            socks5_proxy: None,
        }
    }

    /// Attach a SOCKS5 proxy that will be used for every outbound
    /// peer dial (both the ``ConnectPeer`` RPC and the sticky-peer
    /// reconnect loop go through it).
    #[must_use]
    pub fn with_socks5_proxy(mut self, proxy: Option<String>) -> Self {
        self.socks5_proxy = proxy.map(Into::into);
        self
    }

    /// Cloneable handle on the proxy used by the sticky-peer task
    /// spawned alongside this service.
    pub fn socks5_proxy(&self) -> Option<Arc<str>> {
        self.socks5_proxy.clone()
    }
}

type InboundStream =
    Pin<Box<dyn Stream<Item = Result<InboundOnionMessage, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl Bolt12Gateway for GatewayService {
    async fn get_identity(
        &self,
        _request: Request<GetIdentityRequest>,
    ) -> Result<Response<GetIdentityResponse>, Status> {
        let snapshot = self.state.identity_snapshot();
        let pm = self.state.peer_manager();
        let peers: Vec<PeerInfo> = pm
            .list_peers()
            .into_iter()
            .map(|p| PeerInfo {
                node_id: p.counterparty_node_id.serialize().to_vec(),
                address: p
                    .socket_address
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                inbound: p.is_inbound_connection,
                advertises_onion_messages: p.init_features.supports_onion_messages(),
            })
            .collect();

        let connected_peers = u32::try_from(peers.len()).unwrap_or(u32::MAX);

        let network = match snapshot.network {
            bitcoin::Network::Bitcoin => "mainnet".to_string(),
            bitcoin::Network::Testnet => "testnet".to_string(),
            bitcoin::Network::Signet => "signet".to_string(),
            bitcoin::Network::Regtest => "regtest".to_string(),
            bitcoin::Network::Testnet4 => "testnet4".to_string(),
            // bitcoin::Network is #[non_exhaustive]; fall back to the
            // Display impl for any future variant added upstream.
            #[allow(unreachable_patterns)]
            other => other.to_string().to_lowercase(),
        };

        Ok(Response::new(GetIdentityResponse {
            node_id: snapshot.node_id.serialize().to_vec(),
            connected_peers,
            peers,
            version: env!("CARGO_PKG_VERSION").to_string(),
            network,
        }))
    }

    async fn send_onion_message(
        &self,
        request: Request<SendOnionMessageRequest>,
    ) -> Result<Response<SendOnionMessageResponse>, Status> {
        // Cap
        // payload size at the gRPC layer max so a single oversize RPC
        // cannot force a >65 KiB allocation cycle even if the tonic
        // decoder ceiling is later raised.
        const MAX_ONION_PAYLOAD: usize = 65_535;

        let req = request.into_inner();
        if req.payload.len() > MAX_ONION_PAYLOAD {
            return Err(Status::invalid_argument(format!(
                "payload exceeds {MAX_ONION_PAYLOAD}-byte limit ({} bytes)",
                req.payload.len()
            )));
        }

        let destination = match req.destination {
            Some(ProtoDest::DirectNodeId(bytes)) => {
                let pk = PublicKey::from_slice(&bytes).map_err(|e| {
                    Status::invalid_argument(format!("destination.direct_node_id: {e}"))
                })?;
                Destination::Node(pk)
            }
            Some(ProtoDest::BlindedPath(BlindedMessagePathBytes { serialized })) => {
                blinded_destination_from_bytes(&serialized).map_err(|e| {
                    Status::invalid_argument(format!("destination.blinded_path: {e:#}"))
                })?
            }
            None => {
                return Err(Status::invalid_argument(
                    "destination must be set (direct_node_id or blinded_path)",
                ));
            }
        };

        let reply_path_bytes: Option<Vec<u8>> = req.reply_path.map(|p| p.serialized);
        let instructions = build_send_instructions(destination, reply_path_bytes.as_deref())
            .map_err(|e| Status::invalid_argument(format!("reply_path: {e:#}")))?;

        let offers = decode_offers_message(req.payload_tlv_type, req.payload)
            .map_err(|e| Status::invalid_argument(format!("payload: {e:#}")))?;

        let _tlv = self
            .state
            .offers_handler()
            .enqueue_outbound(offers, instructions);

        let mut id_bytes = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        Ok(Response::new(SendOnionMessageResponse {
            send_id: hex::encode(id_bytes),
        }))
    }

    type StreamInboundStream = InboundStream;

    async fn stream_inbound(
        &self,
        _request: Request<StreamInboundRequest>,
    ) -> Result<Response<Self::StreamInboundStream>, Status> {
        let mut rx = self.state.offers_handler().subscribe_inbound();

        let stream = try_stream! {
            let mut counter: u64 = 0;
            // Heartbeat ticker. The first tick of a tokio interval fires
            // immediately; consume it up front so the first heartbeat
            // lands one full interval in rather than the instant the
            // stream opens.
            let mut heartbeat = tokio::time::interval(INBOUND_HEARTBEAT_INTERVAL);
            // Under sustained real traffic the biased select below never
            // polls the tick future, so its deadlines pass un-observed.
            // `Delay` (vs the default `Burst`) means the next idle poll
            // emits a single heartbeat and reschedules — no catch-up
            // burst of stale heartbeats once traffic goes quiet.
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            heartbeat.tick().await;
            loop {
                // Bias toward real messages: when both a message and a
                // heartbeat tick are ready, deliver the message first so
                // heartbeats never delay or displace real traffic.
                let recv = tokio::select! {
                    biased;
                    recv = rx.recv() => recv,
                    _ = heartbeat.tick() => {
                        yield InboundOnionMessage {
                            recv_id: String::new(),
                            payload_tlv_type: 0,
                            payload: Vec::new(),
                            reply_path: None,
                            received_at_ms: 0,
                            inbound_context: Vec::new(),
                            heartbeat: true,
                        };
                        continue;
                    }
                };
                match recv {
                    Ok(msg) => {
                        counter = counter.wrapping_add(1);
                        let recv_id = format!("{counter:016x}");
                        yield InboundOnionMessage {
                            recv_id,
                            payload_tlv_type: msg.payload_tlv_type,
                            payload: msg.payload,
                            reply_path: msg.reply_path.map(|s| BlindedMessagePathBytes { serialized: s }),
                            received_at_ms: msg.received_at_ms,
                            inbound_context: msg.inbound_context,
                            heartbeat: false,
                        };
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            target: "bolt12_gateway::service",
                            skipped,
                            "inbound stream consumer lagged",
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream) as InboundStream))
    }

    async fn create_blinded_path(
        &self,
        request: Request<CreateBlindedPathRequest>,
    ) -> Result<Response<CreateBlindedPathResponse>, Status> {
        let req = request.into_inner();

        if req.introduction_node_candidates.is_empty() {
            return Err(Status::invalid_argument(
                "introduction_node_candidates must contain at least one entry",
            ));
        }
        if req.context.len() > 256 {
            return Err(Status::invalid_argument("context must be ≤ 256 bytes"));
        }

        let mut candidates = Vec::with_capacity(req.introduction_node_candidates.len());
        for (idx, raw) in req.introduction_node_candidates.iter().enumerate() {
            let pk = PublicKey::from_slice(raw).map_err(|e| {
                Status::invalid_argument(format!("introduction_node_candidates[{idx}]: {e}",))
            })?;
            candidates.push(pk);
        }

        // Proto comment: "Defaults to 2 if zero". We treat 0 as the
        // signal to apply the default; >MAX_DUMMY_HOPS is rejected.
        // The conversion is fallible only on platforms where usize
        // is narrower than u32 (e.g. 16-bit embedded). Reject
        // explicitly rather than silently saturating to usize::MAX.
        let dummy_hops = if req.dummy_hops == 0 {
            2usize
        } else {
            usize::try_from(req.dummy_hops)
                .map_err(|_| Status::invalid_argument("dummy_hops out of range for usize"))?
        };
        if dummy_hops > MAX_DUMMY_HOPS {
            return Err(Status::invalid_argument(format!(
                "dummy_hops must be in [0, {MAX_DUMMY_HOPS}]",
            )));
        }

        let serialized =
            create_blinded_message_path(&self.state, &candidates, dummy_hops, req.context)
                .map_err(|e| {
                    let msg = format!("{e:#}");
                    if msg.contains("currently peered") {
                        Status::failed_precondition(msg)
                    } else {
                        Status::invalid_argument(msg)
                    }
                })?;

        Ok(Response::new(CreateBlindedPathResponse {
            path: Some(BlindedMessagePathBytes { serialized }),
        }))
    }

    async fn connect_peer(
        &self,
        request: Request<ConnectPeerRequest>,
    ) -> Result<Response<ConnectPeerResponse>, Status> {
        let req = request.into_inner();

        let pubkey = PublicKey::from_slice(&req.node_id)
            .map_err(|e| Status::invalid_argument(format!("node_id: {e}")))?;

        // Dial through the shared helper so this RPC and the sticky-
        // peer reconnect loop serialise on the per-pubkey lock. Two
        // concurrent ConnectPeer calls for the same pubkey will both
        // reach `dial_peer`; the second waits on the lock and returns
        // `AlreadyConnected` after the first lands.
        let outcome = dial_peer(
            &self.state.peer_manager(),
            &self.state.dial_locks(),
            pubkey,
            &req.address,
            TCP_CONNECT_TIMEOUT,
            HANDSHAKE_TIMEOUT,
            self.socks5_proxy.as_deref(),
        )
        .await
        .map_err(|e| match e {
            DialError::BadAddress { source, .. } => {
                Status::invalid_argument(format!("address: {source}"))
            }
            DialError::ConnectTimeout { address } => {
                Status::deadline_exceeded(format!("tcp connect to {address} timed out"))
            }
            DialError::ConnectFailed { address } => {
                Status::unavailable(format!("tcp connect to {address} failed"))
            }
            DialError::HandshakeTimeout {
                address,
                timeout_secs,
            } => Status::deadline_exceeded(format!(
                "handshake with {address} did not complete within {timeout_secs}s",
            )),
        })?;

        let already_connected = matches!(outcome, DialOutcome::AlreadyConnected);
        Ok(Response::new(ConnectPeerResponse { already_connected }))
    }

    async fn set_sticky_peers(
        &self,
        request: Request<SetStickyPeersRequest>,
    ) -> Result<Response<SetStickyPeersResponse>, Status> {
        let req = request.into_inner();
        // REPLACE semantics — callers push the whole desired set on
        // every call. Validate all entries before swapping so a
        // malformed pubkey doesn't half-update the registry.
        let mut entries: Vec<StickyPeerEntry> = Vec::with_capacity(req.peers.len());
        for (idx, p) in req.peers.iter().enumerate() {
            let pubkey = PublicKey::from_slice(&p.node_id)
                .map_err(|e| Status::invalid_argument(format!("peers[{idx}].node_id: {e}")))?;
            if p.address.is_empty() {
                return Err(Status::invalid_argument(format!(
                    "peers[{idx}].address must not be empty",
                )));
            }
            entries.push(StickyPeerEntry {
                node_id: pubkey,
                address: p.address.clone(),
            });
        }

        let registry = self.state.sticky_registry();
        registry.replace(entries);
        let sticky_count = u32::try_from(registry.len()).unwrap_or(u32::MAX);
        Ok(Response::new(SetStickyPeersResponse { sticky_count }))
    }

    async fn set_known_node_addresses(
        &self,
        request: Request<tonic::Streaming<NodeAddresses>>,
    ) -> Result<Response<SetKnownNodeAddressesResponse>, Status> {
        // Drain the stream into a staged Vec before swapping the
        // cache so a mid-stream error doesn't half-clear it. The
        // wallet's payload is small enough (top-N nodes × ~100 B
        // each, where N is typically 5 000) to buffer comfortably.
        let mut stream = request.into_inner();
        let mut raw: Vec<NodeAddresses> = Vec::new();
        while let Some(msg) = stream.message().await? {
            raw.push(msg);
        }
        let accepted = self.apply_known_node_addresses(raw)?;
        Ok(Response::new(SetKnownNodeAddressesResponse {
            accepted_count: u32::try_from(accepted).unwrap_or(u32::MAX),
        }))
    }
}

impl GatewayService {
    /// Validate a drained `SetKnownNodeAddresses` payload and swap
    /// the address cache. Split off the RPC method so unit tests can
    /// exercise the validation rules without standing up a tonic
    /// streaming transport.
    // `Status` is tonic's standard RPC error and is propagated via `?`
    // into the streaming RPC method, which must also return `Status`.
    // Boxing here would force unboxing at the call site for no benefit.
    #[allow(clippy::result_large_err)]
    pub(crate) fn apply_known_node_addresses(
        &self,
        raw: Vec<NodeAddresses>,
    ) -> Result<usize, Status> {
        let mut entries: Vec<(PublicKey, Vec<String>, u32)> = Vec::with_capacity(raw.len());
        for (idx, msg) in raw.into_iter().enumerate() {
            let pubkey = PublicKey::from_slice(&msg.node_id)
                .map_err(|e| Status::invalid_argument(format!("entries[{idx}].node_id: {e}")))?;
            // Empty address list is legal on the wire (callers may
            // ship a placeholder); the cache drops empties so they
            // become no-ops on lookup. Each non-empty entry MUST
            // contain only non-blank addresses, though — a blank
            // address would waste a candidate slot at dial time.
            for (a_idx, addr) in msg.addresses.iter().enumerate() {
                if addr.trim().is_empty() {
                    return Err(Status::invalid_argument(format!(
                        "entries[{idx}].addresses[{a_idx}] must not be empty",
                    )));
                }
            }
            entries.push((pubkey, msg.addresses, msg.node_announcement_timestamp));
        }
        let cache = self.state.address_cache();
        let now = std::time::Instant::now();
        Ok(cache.replace(entries, now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        ConnectPeerRequest, CreateBlindedPathRequest, GetIdentityRequest, SendOnionMessageRequest,
        StreamInboundRequest,
    };
    use tempfile::TempDir;
    use tonic::Code;

    fn fresh_service() -> (TempDir, GatewayService) {
        let dir = TempDir::new().expect("tempdir");
        let state = Arc::new(
            GatewayState::load_or_create(dir.path(), bitcoin::Network::Regtest).expect("init"),
        );
        (dir, GatewayService::new(state))
    }

    #[tokio::test]
    async fn get_identity_returns_well_formed_response() {
        let (_dir, svc) = fresh_service();

        let resp = svc
            .get_identity(Request::new(GetIdentityRequest {}))
            .await
            .expect("get_identity ok")
            .into_inner();

        assert_eq!(resp.node_id.len(), 33, "compressed secp256k1 pubkey");
        assert!(
            resp.node_id[0] == 0x02 || resp.node_id[0] == 0x03,
            "first byte must be 0x02 or 0x03, got 0x{:02x}",
            resp.node_id[0]
        );
        assert_eq!(resp.connected_peers, 0, "no peers yet");
        assert!(resp.peers.is_empty());
        assert_eq!(resp.version, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn get_identity_is_stable_across_calls() {
        let (_dir, svc) = fresh_service();

        let a = svc
            .get_identity(Request::new(GetIdentityRequest {}))
            .await
            .unwrap()
            .into_inner();
        let b = svc
            .get_identity(Request::new(GetIdentityRequest {}))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(a.node_id, b.node_id);
    }

    #[tokio::test]
    async fn send_onion_message_rejects_missing_destination() {
        let (_dir, svc) = fresh_service();

        let status = svc
            .send_onion_message(Request::new(SendOnionMessageRequest::default()))
            .await
            .expect_err("must reject");

        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("destination"));
    }

    #[tokio::test]
    async fn send_onion_message_rejects_unknown_tlv_type() {
        let (_dir, svc) = fresh_service();
        let req = SendOnionMessageRequest {
            destination: Some(ProtoDest::DirectNodeId(vec![0x02; 33])),
            reply_path: None,
            payload: vec![0u8; 8],
            payload_tlv_type: 99,
        };
        let status = svc
            .send_onion_message(Request::new(req))
            .await
            .expect_err("must reject");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("payload"));
    }

    #[tokio::test]
    async fn create_blinded_path_rejects_empty_candidates() {
        let (_dir, svc) = fresh_service();

        let status = svc
            .create_blinded_path(Request::new(CreateBlindedPathRequest::default()))
            .await
            .expect_err("must reject");

        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("introduction_node_candidates"));
    }

    #[tokio::test]
    async fn create_blinded_path_rejects_oversized_context() {
        let (_dir, svc) = fresh_service();

        let status = svc
            .create_blinded_path(Request::new(CreateBlindedPathRequest {
                introduction_node_candidates: vec![vec![0x02u8; 33]],
                dummy_hops: 0,
                context: vec![0u8; 257],
            }))
            .await
            .expect_err("must reject");

        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("context"));
    }

    #[tokio::test]
    async fn create_blinded_path_fails_when_no_peer() {
        let (_dir, svc) = fresh_service();

        // Well-formed but unconnected pubkey.
        let candidate = vec![0x02u8; 33];

        let status = svc
            .create_blinded_path(Request::new(CreateBlindedPathRequest {
                introduction_node_candidates: vec![candidate],
                dummy_hops: 1,
                context: b"correlate-me".to_vec(),
            }))
            .await
            .expect_err("must reject");

        assert_eq!(status.code(), Code::FailedPrecondition);
        assert!(status.message().contains("peered"));
    }

    #[tokio::test]
    async fn connect_peer_rejects_bad_pubkey() {
        let (_dir, svc) = fresh_service();
        let status = svc
            .connect_peer(Request::new(ConnectPeerRequest {
                node_id: vec![0u8; 10],
                address: "127.0.0.1:9735".to_string(),
            }))
            .await
            .expect_err("must reject");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn stream_inbound_yields_pushed_messages() {
        use futures::StreamExt;
        use lightning::offers::invoice_error::InvoiceError;
        use lightning::onion_message::offers::{OffersMessage, OffersMessageHandler};

        let (_dir, svc) = fresh_service();
        let resp = svc
            .stream_inbound(Request::new(StreamInboundRequest {}))
            .await
            .expect("stream ok");
        let mut stream = resp.into_inner();

        let invoice_err = InvoiceError::from_string("test".to_string());

        // Drive a synthetic inbound by calling the handler directly.
        let handler = svc.state.offers_handler();
        // Subscribers must exist before send for broadcast::send to
        // deliver — `stream_inbound` already subscribed above.
        // Give the stream a beat to install its receiver task.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let _ = handler.handle_message(OffersMessage::InvoiceError(invoice_err), None, None);

        let next = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .expect("stream produced a message")
            .expect("stream did not end")
            .expect("message ok");

        assert_eq!(next.payload_tlv_type, 68, "invoice_error TLV type");
    }

    #[tokio::test(start_paused = true)]
    async fn stream_inbound_emits_heartbeats_while_idle() {
        use futures::StreamExt;

        let (_dir, svc) = fresh_service();
        let resp = svc
            .stream_inbound(Request::new(StreamInboundRequest {}))
            .await
            .expect("stream ok");
        let mut stream = resp.into_inner();

        // No real inbound traffic ever arrives. The only thing that can
        // wake the stream is the heartbeat ticker; with the clock paused
        // the runtime auto-advances to the ticker's deadline, so the
        // first (and every) item must be a payload-less heartbeat.
        let msg = stream
            .next()
            .await
            .expect("stream did not end")
            .expect("message ok");

        assert!(msg.heartbeat, "idle stream must emit a heartbeat");
        assert_eq!(msg.payload_tlv_type, 0);
        assert!(msg.payload.is_empty());
        assert!(msg.recv_id.is_empty());
        assert!(msg.reply_path.is_none());
        assert!(msg.inbound_context.is_empty());
    }

    // ── SetKnownNodeAddresses ─────────────────────────────────────

    fn fake_pubkey(seed: u8) -> PublicKey {
        let sk = secp256k1::SecretKey::from_slice(&[seed.max(1); 32]).expect("valid secret");
        PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk)
    }

    #[test]
    fn apply_known_node_addresses_populates_cache() {
        // Happy path: a single entry lands in the cache and the
        // cache lookup returns the same addresses verbatim. Pins
        // the staged-then-swap contract end-to-end.
        let (_dir, svc) = fresh_service();
        let pk = fake_pubkey(1);
        let accepted = svc
            .apply_known_node_addresses(vec![crate::proto::NodeAddresses {
                node_id: pk.serialize().to_vec(),
                addresses: vec!["1.2.3.4:9735".into(), "x.onion:9735".into()],
                node_announcement_timestamp: 100,
            }])
            .expect("ok");
        assert_eq!(accepted, 1);

        let cache = svc.state.address_cache();
        let got = cache.lookup_at(&pk, std::time::Instant::now());
        assert_eq!(
            got,
            vec!["1.2.3.4:9735".to_string(), "x.onion:9735".to_string()]
        );
    }

    #[test]
    fn apply_known_node_addresses_rejects_bad_pubkey() {
        // 32-byte (not 33) node_id is the most likely Python-side
        // mistake. The handler must surface InvalidArgument with
        // the failing entry index so the operator can locate the
        // bad row. Pins so a refactor to ``unwrap_or_default()``-
        // style silent skipping can't mask malformed pushes.
        let (_dir, svc) = fresh_service();
        let err = svc
            .apply_known_node_addresses(vec![crate::proto::NodeAddresses {
                node_id: vec![0u8; 32], // wrong length
                addresses: vec!["1.2.3.4:9735".into()],
                node_announcement_timestamp: 100,
            }])
            .expect_err("must reject");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            err.message().contains("entries[0].node_id"),
            "error message must locate failing entry: {}",
            err.message(),
        );
    }

    #[test]
    fn apply_known_node_addresses_rejects_blank_address() {
        // A blank ("" or whitespace-only) address would dial nowhere
        // and waste a candidate slot. Validate before swapping the
        // cache.
        let (_dir, svc) = fresh_service();
        let pk = fake_pubkey(1);
        let err = svc
            .apply_known_node_addresses(vec![crate::proto::NodeAddresses {
                node_id: pk.serialize().to_vec(),
                addresses: vec!["1.2.3.4:9735".into(), "   ".into()],
                node_announcement_timestamp: 100,
            }])
            .expect_err("must reject");
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("addresses[1]"));
    }

    #[test]
    fn apply_known_node_addresses_validation_does_not_clear_existing() {
        // Critical: a failed validation must NOT clear the previous
        // cache. The staged-then-swap pattern is the load-bearing
        // contract; a regression to "validate-and-insert-in-place"
        // would mean one bad row from Python drops the whole
        // cache on the floor.
        let (_dir, svc) = fresh_service();
        let pk_good = fake_pubkey(1);
        svc.apply_known_node_addresses(vec![crate::proto::NodeAddresses {
            node_id: pk_good.serialize().to_vec(),
            addresses: vec!["good:9735".into()],
            node_announcement_timestamp: 100,
        }])
        .expect("first push ok");
        assert_eq!(svc.state.address_cache().len(), 1);

        // Second push contains a bad entry. The cache must be
        // unchanged.
        let err = svc
            .apply_known_node_addresses(vec![crate::proto::NodeAddresses {
                node_id: vec![0u8; 32],
                addresses: vec!["bad:9735".into()],
                node_announcement_timestamp: 200,
            }])
            .expect_err("validation must reject");
        assert_eq!(err.code(), Code::InvalidArgument);
        let cache = svc.state.address_cache();
        assert_eq!(
            cache.len(),
            1,
            "cache must be untouched on validation failure"
        );
        assert_eq!(
            cache.lookup_at(&pk_good, std::time::Instant::now()),
            vec!["good:9735".to_string()],
        );
    }

    #[test]
    fn apply_known_node_addresses_replace_drops_old_keys() {
        // REPLACE semantics: two-phase push, the second must clear
        // entries absent from the new set. This is the load-bearing
        // contract documented in the proto comment — drift here
        // causes stale addresses to outlive their LND-graph
        // lifetime.
        let (_dir, svc) = fresh_service();
        let pk_a = fake_pubkey(1);
        let pk_b = fake_pubkey(2);
        svc.apply_known_node_addresses(vec![
            crate::proto::NodeAddresses {
                node_id: pk_a.serialize().to_vec(),
                addresses: vec!["a:9735".into()],
                node_announcement_timestamp: 100,
            },
            crate::proto::NodeAddresses {
                node_id: pk_b.serialize().to_vec(),
                addresses: vec!["b:9735".into()],
                node_announcement_timestamp: 100,
            },
        ])
        .expect("first push ok");
        assert_eq!(svc.state.address_cache().len(), 2);

        // Second push only contains pk_a — pk_b must disappear.
        svc.apply_known_node_addresses(vec![crate::proto::NodeAddresses {
            node_id: pk_a.serialize().to_vec(),
            addresses: vec!["a-new:9735".into()],
            node_announcement_timestamp: 101,
        }])
        .expect("second push ok");
        let cache = svc.state.address_cache();
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.lookup_at(&pk_a, std::time::Instant::now()),
            vec!["a-new:9735".to_string()],
        );
        assert!(cache.lookup_at(&pk_b, std::time::Instant::now()).is_empty());
    }
}
