// SPDX-License-Identifier: MIT
//! End-to-end transport tests: real `tonic::transport::Server` over
//! a 127.0.0.1 socket, real `tonic::transport::Channel` client.
//!
//! `GetIdentity` / `SendOnionMessage` / `StreamInbound` /
//! `ConnectPeer` / `CreateBlindedPath` are wired against the real
//! LDK stack. Tests here exercise argument validation over the
//! wire — full LDK behavior is covered by the regtest harness.

use std::sync::Arc;

use bolt12_gateway::ldk_glue::GatewayState;
use bolt12_gateway::proto::bolt12_gateway_client::Bolt12GatewayClient;
use bolt12_gateway::proto::bolt12_gateway_server::Bolt12GatewayServer;
use bolt12_gateway::proto::{
    ConnectPeerRequest, CreateBlindedPathRequest, GetIdentityRequest, SendOnionMessageRequest,
    StreamInboundRequest,
};
use bolt12_gateway::service::GatewayService;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tonic::transport::{Endpoint, Server};
use tonic::Code;

/// Spin up a gateway gRPC server on an ephemeral port and return a
/// connected client + a shutdown trigger.
async fn spawn_test_server() -> (
    Bolt12GatewayClient<tonic::transport::Channel>,
    TempDir,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let dir = TempDir::new().expect("tempdir");
    let state = Arc::new(
        GatewayState::load_or_create(dir.path(), bitcoin::Network::Regtest).expect("init state"),
    );
    let svc = GatewayService::new(state);

    // Bind to 127.0.0.1:0 and learn the assigned port.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        Server::builder()
            .add_service(Bolt12GatewayServer::new(svc).max_decoding_message_size(64 * 1024))
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("server");
    });

    // Connect.
    let endpoint = Endpoint::from_shared(format!("http://{addr}"))
        .expect("endpoint")
        .connect_timeout(std::time::Duration::from_secs(2));
    let client = Bolt12GatewayClient::connect(endpoint)
        .await
        .expect("client connect");

    (client, dir, shutdown_tx, server_task)
}

#[tokio::test]
async fn get_identity_round_trips_over_tcp() {
    let (mut client, _dir, shutdown, task) = spawn_test_server().await;

    let resp = client
        .get_identity(GetIdentityRequest {})
        .await
        .expect("get_identity ok")
        .into_inner();

    assert_eq!(resp.node_id.len(), 33);
    assert!(resp.node_id[0] == 0x02 || resp.node_id[0] == 0x03);
    assert!(!resp.version.is_empty());
    assert_eq!(resp.connected_peers, 0);

    let _ = shutdown.send(());
    let _ = task.await;
}

#[tokio::test]
async fn send_onion_message_rejects_missing_destination_over_tcp() {
    let (mut client, _dir, shutdown, task) = spawn_test_server().await;

    let err = client
        .send_onion_message(SendOnionMessageRequest::default())
        .await
        .expect_err("must reject");

    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("destination"));

    let _ = shutdown.send(());
    let _ = task.await;
}

#[tokio::test]
async fn create_blinded_path_rejects_empty_candidates_over_tcp() {
    let (mut client, _dir, shutdown, task) = spawn_test_server().await;

    let err = client
        .create_blinded_path(CreateBlindedPathRequest::default())
        .await
        .expect_err("must reject");

    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("introduction_node_candidates"));

    let _ = shutdown.send(());
    let _ = task.await;
}

#[tokio::test]
async fn connect_peer_rejects_bad_node_id_over_tcp() {
    let (mut client, _dir, shutdown, task) = spawn_test_server().await;

    let err = client
        .connect_peer(ConnectPeerRequest::default())
        .await
        .expect_err("must reject");

    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("node_id"));

    let _ = shutdown.send(());
    let _ = task.await;
}

#[tokio::test]
async fn stream_inbound_opens_over_tcp() {
    use futures::StreamExt;

    let (mut client, _dir, shutdown, task) = spawn_test_server().await;

    // The stream itself opens successfully; with no inbound traffic
    // it just blocks. Verify by racing a short timeout.
    let resp = client
        .stream_inbound(StreamInboundRequest {})
        .await
        .expect("stream open")
        .into_inner();
    let mut stream = resp;
    let outcome = tokio::time::timeout(std::time::Duration::from_millis(150), stream.next()).await;
    assert!(outcome.is_err(), "no messages expected; should time out");

    // Drop the streaming RPC before shutting the server down so
    // graceful shutdown isn't blocked by the in-flight stream.
    drop(stream);
    let _ = shutdown.send(());
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn create_blinded_path_rejects_dummy_hops_above_max() {
    // A too-large `dummy_hops`
    // must surface as `InvalidArgument` rather than panicking or
    // silently saturating. Even at `u32::MAX` (which fits usize on
    // every supported 64-bit target) the `MAX_DUMMY_HOPS` guard
    // must fire with a structured error message.
    let (mut client, _dir, shutdown, task) = spawn_test_server().await;

    // Use the secp256k1 generator point G as a well-known valid
    // compressed pubkey so the candidate-validation guard passes
    // and the dummy_hops guard is reached.
    let g_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let g_compressed: Vec<u8> = (0..g_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&g_hex[i..i + 2], 16).unwrap())
        .collect();
    let req = CreateBlindedPathRequest {
        introduction_node_candidates: vec![g_compressed],
        dummy_hops: u32::MAX,
        ..Default::default()
    };
    let err = client
        .create_blinded_path(req)
        .await
        .expect_err("must reject huge dummy_hops");

    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(
        err.message().contains("dummy_hops"),
        "expected dummy_hops in error message, got: {}",
        err.message()
    );

    let _ = shutdown.send(());
    let _ = task.await;
}

#[tokio::test]
async fn identity_is_stable_after_restart() {
    async fn capture_node_id(data_dir: &std::path::Path) -> Vec<u8> {
        let state = Arc::new(
            GatewayState::load_or_create(data_dir, bitcoin::Network::Regtest).expect("init"),
        );
        let svc = GatewayService::new(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(Bolt12GatewayServer::new(svc))
                .serve_with_incoming_shutdown(incoming, async move {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });

        let endpoint = Endpoint::from_shared(format!("http://{addr}")).unwrap();
        let mut client = Bolt12GatewayClient::connect(endpoint).await.unwrap();
        let id = client
            .get_identity(GetIdentityRequest {})
            .await
            .unwrap()
            .into_inner()
            .node_id;
        let _ = tx.send(());
        let _ = task.await;
        id
    }

    // Same data_dir → same node_id, even if the gateway process
    // (= tonic server) is recycled.
    let dir = TempDir::new().expect("tempdir");

    let a = capture_node_id(dir.path()).await;
    let b = capture_node_id(dir.path()).await;
    assert_eq!(a, b);
}

/// The gateway must
/// refuse onion payloads above the documented BOLT-spec ceiling so a
/// single oversized RPC cannot force a >65 KiB allocation cycle.
#[tokio::test]
async fn send_onion_message_rejects_oversized_payload() {
    let (mut client, _dir, shutdown, task) = spawn_test_server().await;

    // 64 KiB + 1 byte — one over the documented limit.
    let payload = vec![0u8; 65_535 + 1];
    let g_hex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let g_compressed: Vec<u8> = (0..g_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&g_hex[i..i + 2], 16).unwrap())
        .collect();
    let req = SendOnionMessageRequest {
        payload_tlv_type: 64, // invoice request
        payload,
        destination: Some(
            bolt12_gateway::proto::send_onion_message_request::Destination::DirectNodeId(
                g_compressed,
            ),
        ),
        ..Default::default()
    };
    let err = client
        .send_onion_message(req)
        .await
        .expect_err("must reject oversized payload");
    // The tonic decoder's `max_decoding_message_size` may fire first
    // (Code::OutOfRange) for payloads that exceed the per-message
    // wire limit; the service-level guard fires with
    // Code::InvalidArgument for sizes between the two. Either error
    // proves the gateway is no longer willing to allocate an
    // unbounded buffer for the caller.
    assert!(
        matches!(err.code(), Code::InvalidArgument | Code::OutOfRange),
        "expected InvalidArgument or OutOfRange, got: {:?} / {}",
        err.code(),
        err.message()
    );

    let _ = shutdown.send(());
    let _ = task.await;
}

/// The shipped `config.example.toml` must bind to loopback so a
/// fresh operator deploy is not exposed on `0.0.0.0`.
#[test]
fn default_grpc_listen_is_loopback() {
    let raw = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config.example.toml"),
    )
    .expect("read config.example.toml");
    // Either the field is commented out (=> Rust default applies, which
    // we assert in default_grpc_listen) or it must start with 127.0.0.1.
    let listen_line = raw
        .lines()
        .find(|line| line.trim_start().starts_with("grpc_listen"));
    if let Some(line) = listen_line {
        assert!(
            line.contains("127.0.0.1") || line.trim_start().starts_with('#'),
            "config.example.toml binds non-loopback: {line:?}"
        );
    }
}

/// The in-code default for `grpc_listen` must be loopback.
#[test]
fn rust_default_grpc_listen_is_loopback() {
    // Reach in via TOML round-trip so we exercise the same code path
    // operators trigger when they leave `grpc_listen` unset.
    let cfg: bolt12_gateway::config::GatewayConfig =
        toml::from_str("data_dir = \"/tmp/test\"\n").expect("parse minimal config");
    assert_eq!(cfg.grpc_listen.ip().to_string(), "127.0.0.1");
}

/// `DialLocks` GC
/// evicts unused entries, preserving sticky-registry pubkeys.
#[test]
fn dial_locks_gc_evicts_unused_entries() {
    use bolt12_gateway::sticky_peers::DialLocks;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let locks = DialLocks::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Seed N distinct pubkeys via the same code path ConnectPeer would
    // take. The guards are dropped at the end of each iteration, so
    // strong_count drops back to 1 (= map only).
    let mut pubkeys = Vec::new();
    for i in 1u32..=64 {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&i.to_be_bytes());
        let sk = SecretKey::from_slice(&seed).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        pubkeys.push(pk);
        runtime.block_on(async {
            let _g = locks.lock(&pk).await;
        });
    }
    assert_eq!(locks.len(), 64);

    // Keep the first one; everything else is GC-eligible.
    let evicted = locks.gc(&pubkeys[..1]);
    assert_eq!(evicted, 63);
    assert_eq!(locks.len(), 1);
}

/// corollary: an entry currently held by an outstanding guard
/// must not be evicted even when it's not in the keep-set.
#[test]
fn dial_locks_gc_preserves_held_entries() {
    use bolt12_gateway::sticky_peers::DialLocks;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let locks = DialLocks::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let sk = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);

    let _guard = runtime.block_on(async { locks.lock(&pk).await });
    let evicted = locks.gc(&[]);
    assert_eq!(evicted, 0, "must not evict a held entry");
    assert_eq!(locks.len(), 1);
}
