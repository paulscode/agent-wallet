// SPDX-License-Identifier: MIT
//! BOLT 12 onion-message gateway daemon entry point.
//!
//! Architectural rationale (Option E — external onion-message gateway
//! paired with managed LND for settlement).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Status};
use tracing::{info, warn, Level};
use tracing_subscriber::EnvFilter;

use bolt12_gateway::config::GatewayConfig;
use bolt12_gateway::ldk_glue::GatewayState;
use bolt12_gateway::proto::bolt12_gateway_server::Bolt12GatewayServer;
use bolt12_gateway::service::GatewayService;

// Linear daemon bootstrap: load config, spawn background pumps, build
// the TLS/auth server stack and serve. Splitting it would only scatter
// a one-shot startup sequence across helpers with no reuse value.
#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Bound tonic-level decoding so a single malicious peer cannot
    // push the gateway into a 4MB+ allocation cycle.
    const MAX_DECODING_MESSAGE_SIZE: usize = 64 * 1024; // 64 KiB

    init_tracing();

    let config_path: PathBuf = std::env::var_os("BOLT12_GATEWAY_CONFIG").map_or_else(
        || PathBuf::from("/etc/bolt12-gateway/config.toml"),
        PathBuf::from,
    );

    let config = GatewayConfig::load(&config_path)
        .with_context(|| format!("load gateway config {}", config_path.display()))?;

    let network = config
        .parsed_network()
        .context("parse gateway bitcoin network")?;

    let state = Arc::new(
        GatewayState::load_or_create(&config.data_dir, network)
            .context("initialize gateway identity")?,
    );

    let identity = state.identity_snapshot();
    info!(
        node_id = %hex::encode(identity.node_id.serialize()),
        network = %identity.network,
        bind = %config.grpc_listen,
        "BOLT 12 gateway starting"
    );

    // Spawn the sticky-peer reconnect loop. It watches the registry
    // populated by Python's SetStickyPeers RPC and redials anything
    // missing. Uses the same per-pubkey mutex as ConnectPeer, so
    // Python-driven dials + Rust-driven redials can never race a
    // duplicate connection through LDK.
    //
    // The SOCKS5 proxy (when configured) is honoured for every dial
    // — both this reconnect loop and the ConnectPeer RPC. Inside
    // the ``bolt12-internal`` docker network this is the ONLY way
    // to reach a peer: ``internal: true`` denies direct egress, so
    // peer traffic must funnel through ``tor-proxy``. Onion peers
    // get the proxy by definition; clearnet peers (e.g. Ocean's
    // 16.63.81.71) also route through Tor for IP-privacy.
    let socks5_proxy: Option<std::sync::Arc<str>> = config.socks5_proxy.as_deref().map(Into::into);
    let tcp_connect_timeout = std::time::Duration::from_secs(15);
    let handshake_timeout = std::time::Duration::from_secs(5);

    // Spawn LDK background pumps. The onion pump now handles
    // ``Event::ConnectionNeeded`` and may dial peers on demand
    // (when an outbound onion reply, e.g. a BOLT 12 fetchinvoice
    // response, targets a peer we're not yet connected to). Reuses
    // the same dial config as the sticky-peer loop so the two dial
    // paths behave identically. Held until the gRPC server exits.
    let _bg = bolt12_gateway::runner::spawn(
        &state,
        bolt12_gateway::runner::DialConfig {
            tcp_connect_timeout,
            handshake_timeout,
            socks5_proxy: socks5_proxy.clone(),
        },
    );

    let _sticky = bolt12_gateway::sticky_peers::spawn(
        state.peer_manager(),
        state.dial_locks(),
        state.sticky_registry(),
        bolt12_gateway::sticky_peers::ReconnectConfig::default(),
        tcp_connect_timeout,
        handshake_timeout,
        socks5_proxy.clone(),
    );

    let svc = GatewayService::new(state.clone()).with_socks5_proxy(config.socks5_proxy.clone());
    if socks5_proxy.is_some() {
        info!(
            proxy = %config.socks5_proxy.as_deref().unwrap_or(""),
            "BOLT 12 gateway: peer dials will be routed through SOCKS5 proxy"
        );
    } else {
        info!("BOLT 12 gateway: SOCKS5 proxy not configured — peer dials use direct TCP");
    }

    // In
    // production, refuse to boot without a configured auth_token of
    // adequate length. The opt-out env var is reserved for regtest
    // CI and integration tests that spin up a private socket.
    let environment =
        std::env::var("BOLT12_GATEWAY_ENVIRONMENT").unwrap_or_else(|_| "production".to_string());
    let is_production = environment.eq_ignore_ascii_case("production");
    let token_ok = config.auth_token.as_deref().is_some_and(|t| t.len() >= 32);
    if is_production && !token_ok {
        anyhow::bail!(
            "BOLT 12 gateway: auth_token is required (≥32 bytes) when \
             BOLT12_GATEWAY_ENVIRONMENT=production. Set BOLT12_GATEWAY_TOKEN \
             or the `auth_token` field in {}.",
            config_path.display()
        );
    }

    // Regardless of environment, refuse to expose the privileged RPC
    // surface (pay / sign / connect-peer) on a NON-loopback address
    // without authentication. The dev/test no-token convenience is only
    // safe on loopback (or an `internal: true` docker network reached via
    // loopback). A non-loopback bind without a token AND without mTLS is
    // an open privileged endpoint — never allow it.
    if !token_ok && !config.grpc_listen.ip().is_loopback() && !config.tls.is_complete() {
        anyhow::bail!(
            "BOLT 12 gateway: refusing to bind a non-loopback address ({}) without \
             authentication. Set BOLT12_GATEWAY_TOKEN (≥32 bytes) or enable mTLS.",
            config.grpc_listen
        );
    }

    // Bound tonic-level idle behaviour so a single malicious peer
    // cannot hold an idle stream forever.
    let mut server = Server::builder()
        .timeout(std::time::Duration::from_secs(30))
        .http2_keepalive_interval(Some(std::time::Duration::from_secs(15)))
        .http2_keepalive_timeout(Some(std::time::Duration::from_secs(20)));

    // Opt-in mTLS. When all three paths are set we terminate TLS on
    // this listener and require every client to present a cert
    // signed by ``ca_cert_path``. Handshake failures are rejected
    // before any application data — they never reach the bearer-
    // token interceptor. Combining TLS with the token gives us
    // cryptographic peer identity + a revocable auth credential,
    // which is the right shape for split-host or hostile-tenant
    // deploys. Cleartext + bearer-token alone remains the default
    // for single-host installs where the channel sits on an
    // ``internal: true`` docker network.
    if config.tls.is_complete() {
        let ca_path = config.tls.ca_cert_path.as_ref().expect("checked above");
        let cert_path = config.tls.server_cert_path.as_ref().expect("checked above");
        let key_path = config.tls.server_key_path.as_ref().expect("checked above");
        let ca_pem = std::fs::read(ca_path)
            .with_context(|| format!("read TLS CA cert {}", ca_path.display()))?;
        let cert_pem = std::fs::read(cert_path)
            .with_context(|| format!("read TLS server cert {}", cert_path.display()))?;
        let key_pem = std::fs::read(key_path)
            .with_context(|| format!("read TLS server key {}", key_path.display()))?;
        let identity = Identity::from_pem(&cert_pem, &key_pem);
        let client_ca = tonic::transport::Certificate::from_pem(&ca_pem);
        let tls = ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(client_ca);
        server = server
            .tls_config(tls)
            .context("install TLS config on gRPC listener")?;
        info!(
            ca_cert = %ca_path.display(),
            server_cert = %cert_path.display(),
            "BOLT 12 gateway: mTLS ENABLED — clients must present a cert signed by the configured CA"
        );
    }
    let server = match config.auth_token.clone() {
        Some(tok) if !tok.is_empty() => {
            use bitcoin::hashes::{sha256, Hash};
            use subtle::ConstantTimeEq;
            let expected = format!("Bearer {tok}");
            // Compare SHA-256 digests of the provided and expected bearer
            // strings rather than the raw bytes. The per-byte compare is
            // already constant-time for equal-length inputs, but hashing
            // first makes both operands a fixed 32 bytes, so the compare
            // no longer leaks the expected token's *length* via an
            // early-out on a length mismatch. The interceptor closure is
            // invoked for every incoming request, including the streaming
            // inbound feed.
            let expected_digest = sha256::Hash::hash(expected.as_bytes()).to_byte_array();
            let interceptor = move |req: Request<()>| -> Result<Request<()>, Status> {
                let provided = req
                    .metadata()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let provided_digest = sha256::Hash::hash(provided.as_bytes()).to_byte_array();
                let ok: bool = provided_digest[..].ct_eq(&expected_digest[..]).into();
                if ok {
                    Ok(req)
                } else {
                    Err(Status::unauthenticated("invalid or missing bearer token"))
                }
            };
            info!("BOLT 12 gateway: bearer-token authentication ENABLED");
            let mut s = server;
            let inner =
                Bolt12GatewayServer::new(svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE);
            s.add_service(tonic::service::interceptor::InterceptedService::new(
                inner,
                interceptor,
            ))
        }
        _ => {
            warn!(
                "BOLT 12 gateway: BOLT12_GATEWAY_TOKEN not set — gRPC \
                 surface is UNAUTHENTICATED. Only safe on a private \
                 docker network or for regtest CI; set the token for \
                 any production deploy."
            );
            let mut s = server;
            s.add_service(
                Bolt12GatewayServer::new(svc).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE),
            )
        }
    };

    server
        .serve(config.grpc_listen)
        .await
        .context("gRPC server fatal error")?;

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,bolt12_gateway=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_max_level(Level::TRACE)
        .json()
        .init();
}
