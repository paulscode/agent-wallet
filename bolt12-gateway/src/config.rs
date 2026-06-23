// SPDX-License-Identifier: MIT
//! Configuration loaded from environment + TOML on disk.
//!
//! This defines the configuration surface; production wiring (e.g.
//! on-disk seed file, peer whitelist) lands in subsequent work.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

/// Top-level gateway configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// Address the gRPC server binds to. Defaults to localhost so the
    /// gateway is not exposed outside the docker network unless the
    /// operator opts in.
    #[serde(default = "default_grpc_listen")]
    pub grpc_listen: SocketAddr,

    /// Directory holding the gateway's persistent state (seed, peer
    /// store, blinded-path context cache).
    pub data_dir: PathBuf,

    /// Optional path to a unix socket / TCP host:port for an outbound
    /// SOCKS5 proxy (used when peering with `.onion` nodes via the
    /// shared `tor-proxy` service).
    #[serde(default)]
    pub socks5_proxy: Option<String>,

    /// Initial peer set the gateway should attempt to connect to on
    /// startup. Each entry is `<33-byte-hex-pubkey>@<host:port>`.
    /// Public onion-message-capable nodes (Olympus, ACINQ,
    /// Megalithic, Boltz) are typical seeds.
    #[serde(default)]
    #[allow(dead_code)] // Wired in PeerManager bootstrap.
    pub bootstrap_peers: Vec<String>,

    /// Bitcoin network the gateway operates on. Must match the
    /// wallet's `BITCOIN_NETWORK` setting — the wallet refuses to
    /// start if the two disagree.
    ///
    /// Accepted values: `"mainnet"` / `"bitcoin"`, `"testnet"`,
    /// `"signet"`, `"regtest"`. Defaults to `"regtest"` to keep
    /// development boxes from accidentally talking to mainnet peers.
    #[serde(default = "default_network")]
    pub network: String,

    /// Optional shared bearer token. When set, every gRPC request
    /// must carry `authorization: Bearer <token>`; mismatches are
    /// rejected with `UNAUTHENTICATED`. When unset, the gateway
    /// runs unauthenticated — only safe on a private docker
    /// network. Override at runtime with `BOLT12_GATEWAY_TOKEN`.
    #[serde(default)]
    pub auth_token: Option<String>,

    /// Optional mTLS configuration. When all three paths are set
    /// the gateway terminates TLS on the gRPC listener and requires
    /// every client to present a certificate signed by the
    /// configured CA. When any path is missing the listener runs in
    /// cleartext (the default for in-network single-host deploys
    /// where bearer-token + docker network isolation are sufficient).
    /// Override per-deployment via the `BOLT12_GATEWAY_TLS_*` env
    /// vars.
    #[serde(default)]
    pub tls: TlsConfig,
}

/// On-disk paths to the materials terminating TLS on the gRPC
/// listener. All three fields are required to enable TLS; if any is
/// missing the gateway runs in cleartext (cleartext is appropriate
/// when the channel sits on an `internal: true` docker network
/// behind a shared bearer token).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TlsConfig {
    /// Path to the CA certificate (PEM) that signed both the
    /// server certificate and every accepted client certificate.
    /// When mTLS is enabled, clients without a cert chained to this
    /// CA are rejected at TLS handshake (before any application
    /// data — never reaches the bearer-token interceptor).
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
    /// Path to the gateway's server certificate (PEM). The
    /// certificate's SAN MUST cover the hostname the wallet uses to
    /// dial the gateway (default `bolt12-gateway` inside docker
    /// compose). The bundled `scripts/gen_bolt12_certs.sh` helper
    /// emits a cert with the right SAN by default.
    #[serde(default)]
    pub server_cert_path: Option<PathBuf>,
    /// Path to the gateway's server private key (PEM).
    #[serde(default)]
    pub server_key_path: Option<PathBuf>,
}

impl TlsConfig {
    /// All three paths present → mTLS enabled. The "any but not all"
    /// case is a misconfiguration and is rejected by `validate()`.
    pub fn is_complete(&self) -> bool {
        self.ca_cert_path.is_some()
            && self.server_cert_path.is_some()
            && self.server_key_path.is_some()
    }

    /// Returns true when at least one but not all TLS paths are set
    /// — a configuration error rather than a deliberate opt-out.
    pub fn is_partial(&self) -> bool {
        let any = self.ca_cert_path.is_some()
            || self.server_cert_path.is_some()
            || self.server_key_path.is_some();
        any && !self.is_complete()
    }
}

fn default_network() -> String {
    "regtest".to_string()
}

fn default_grpc_listen() -> SocketAddr {
    "127.0.0.1:50061"
        .parse()
        .expect("hard-coded default is valid")
}

impl GatewayConfig {
    /// Load from a TOML file, with environment overrides for the
    /// fields most operators tweak per-deployment.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read config {}: {}", path.display(), e))?;
        let mut cfg: Self = toml::from_str(&raw)?;

        if let Ok(addr) = std::env::var("BOLT12_GATEWAY_GRPC_LISTEN") {
            cfg.grpc_listen = addr
                .parse()
                .map_err(|e| anyhow::anyhow!("BOLT12_GATEWAY_GRPC_LISTEN: {e}"))?;
        }
        if let Ok(proxy) = std::env::var("BOLT12_GATEWAY_SOCKS5_PROXY") {
            cfg.socks5_proxy = Some(proxy);
        }
        if let Ok(net) = std::env::var("BOLT12_GATEWAY_NETWORK") {
            cfg.network = net;
        }
        if let Ok(tok) = std::env::var("BOLT12_GATEWAY_TOKEN") {
            // Empty string treated as unset so an operator can
            // explicitly override a TOML-set token back to "no auth"
            // by exporting `BOLT12_GATEWAY_TOKEN=`.
            cfg.auth_token = if tok.is_empty() { None } else { Some(tok) };
        }
        // mTLS env overrides. Empty string clears the field so an
        // operator can disable a TOML-configured TLS by exporting
        // ``BOLT12_GATEWAY_TLS_CA_CERT=`` (for example when running a
        // shared image in a cleartext-only dev environment).
        if let Ok(p) = std::env::var("BOLT12_GATEWAY_TLS_CA_CERT") {
            cfg.tls.ca_cert_path = if p.is_empty() { None } else { Some(p.into()) };
        }
        if let Ok(p) = std::env::var("BOLT12_GATEWAY_TLS_SERVER_CERT") {
            cfg.tls.server_cert_path = if p.is_empty() { None } else { Some(p.into()) };
        }
        if let Ok(p) = std::env::var("BOLT12_GATEWAY_TLS_SERVER_KEY") {
            cfg.tls.server_key_path = if p.is_empty() { None } else { Some(p.into()) };
        }
        if cfg.tls.is_partial() {
            anyhow::bail!(
                "BOLT 12 gateway: TLS configuration is partial. \
                 To enable mTLS set ALL of ca_cert_path / \
                 server_cert_path / server_key_path (or the \
                 BOLT12_GATEWAY_TLS_CA_CERT / _SERVER_CERT / \
                 _SERVER_KEY env vars). To disable, clear all \
                 three. Half-configured TLS would silently fall \
                 back to cleartext on a refusable connection."
            );
        }
        Ok(cfg)
    }

    /// Parse `network` into a `bitcoin::Network`. Accepts `mainnet`
    /// as an alias for `bitcoin` because that's the wallet-side label
    /// and the more common operator vocabulary.
    pub fn parsed_network(&self) -> anyhow::Result<bitcoin::Network> {
        match self.network.to_ascii_lowercase().as_str() {
            "mainnet" | "bitcoin" => Ok(bitcoin::Network::Bitcoin),
            "testnet" | "testnet3" => Ok(bitcoin::Network::Testnet),
            "signet" => Ok(bitcoin::Network::Signet),
            "regtest" => Ok(bitcoin::Network::Regtest),
            other => Err(anyhow::anyhow!(
                "unknown bitcoin network {other:?} (expected mainnet/testnet/signet/regtest)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serialize all tests that mutate process-wide env vars. Cargo
    /// runs unit tests on threads, so without this the env-override
    /// tests race against one another.
    fn env_lock() -> &'static Mutex<()> {
        static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// RAII guard that clears the named env vars on drop, regardless
    /// of whether the test passed or panicked.
    struct EnvGuard {
        vars: Vec<&'static str>,
    }

    impl EnvGuard {
        fn new(vars: &[&'static str]) -> Self {
            for v in vars {
                std::env::remove_var(v);
            }
            Self {
                vars: vars.to_vec(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for v in &self.vars {
                std::env::remove_var(v);
            }
        }
    }

    fn write_config(dir: &TempDir, body: &str) -> PathBuf {
        let path = dir.path().join("config.toml");
        let mut f = std::fs::File::create(&path).expect("create config");
        f.write_all(body.as_bytes()).expect("write config");
        path
    }

    #[test]
    fn default_grpc_listen_is_loopback() {
        let addr = default_grpc_listen();
        assert_eq!(addr.to_string(), "127.0.0.1:50061");
    }

    #[test]
    fn loads_minimal_config_with_defaults() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&["BOLT12_GATEWAY_GRPC_LISTEN", "BOLT12_GATEWAY_SOCKS5_PROXY"]);

        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, r#"data_dir = "/var/lib/bolt12-gateway""#);

        let cfg = GatewayConfig::load(&path).expect("load");
        assert_eq!(cfg.data_dir, PathBuf::from("/var/lib/bolt12-gateway"));
        assert_eq!(cfg.grpc_listen, default_grpc_listen());
        assert!(cfg.socks5_proxy.is_none());
        assert!(cfg.bootstrap_peers.is_empty());
    }

    #[test]
    fn loads_full_config() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&["BOLT12_GATEWAY_GRPC_LISTEN", "BOLT12_GATEWAY_SOCKS5_PROXY"]);

        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
            grpc_listen = "0.0.0.0:50062"
            data_dir = "/data"
            socks5_proxy = "tor:9050"
            bootstrap_peers = ["abc@host:9735", "def@other:9735"]
            "#,
        );

        let cfg = GatewayConfig::load(&path).expect("load");
        assert_eq!(cfg.grpc_listen.to_string(), "0.0.0.0:50062");
        assert_eq!(cfg.data_dir, PathBuf::from("/data"));
        assert_eq!(cfg.socks5_proxy.as_deref(), Some("tor:9050"));
        assert_eq!(cfg.bootstrap_peers.len(), 2);
        assert_eq!(cfg.bootstrap_peers[0], "abc@host:9735");
    }

    #[test]
    fn missing_required_field_errors() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&["BOLT12_GATEWAY_GRPC_LISTEN", "BOLT12_GATEWAY_SOCKS5_PROXY"]);

        let dir = TempDir::new().unwrap();
        // No `data_dir` — required.
        let path = write_config(&dir, r#"grpc_listen = "127.0.0.1:50061""#);

        let err = GatewayConfig::load(&path).expect_err("must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("data_dir") || msg.to_lowercase().contains("missing"),
            "expected missing-field error, got: {msg}"
        );
    }

    #[test]
    fn nonexistent_file_errors() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&["BOLT12_GATEWAY_GRPC_LISTEN", "BOLT12_GATEWAY_SOCKS5_PROXY"]);

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does_not_exist.toml");

        let err = GatewayConfig::load(&path).expect_err("must fail");
        assert!(format!("{err:#}").contains("read config"));
    }

    #[test]
    fn malformed_toml_errors() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&["BOLT12_GATEWAY_GRPC_LISTEN", "BOLT12_GATEWAY_SOCKS5_PROXY"]);

        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "this is = not = valid toml");

        GatewayConfig::load(&path).expect_err("must fail");
    }

    #[test]
    fn env_overrides_grpc_listen() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&["BOLT12_GATEWAY_GRPC_LISTEN", "BOLT12_GATEWAY_SOCKS5_PROXY"]);

        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
            grpc_listen = "127.0.0.1:50061"
            data_dir = "/data"
            "#,
        );

        std::env::set_var("BOLT12_GATEWAY_GRPC_LISTEN", "10.0.0.5:9999");
        let cfg = GatewayConfig::load(&path).expect("load");
        assert_eq!(cfg.grpc_listen.to_string(), "10.0.0.5:9999");
    }

    #[test]
    fn env_overrides_socks5_proxy_even_when_unset_in_toml() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&["BOLT12_GATEWAY_GRPC_LISTEN", "BOLT12_GATEWAY_SOCKS5_PROXY"]);

        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, r#"data_dir = "/data""#);

        std::env::set_var("BOLT12_GATEWAY_SOCKS5_PROXY", "tor:9150");
        let cfg = GatewayConfig::load(&path).expect("load");
        assert_eq!(cfg.socks5_proxy.as_deref(), Some("tor:9150"));
    }

    #[test]
    fn env_invalid_grpc_listen_errors() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&["BOLT12_GATEWAY_GRPC_LISTEN", "BOLT12_GATEWAY_SOCKS5_PROXY"]);

        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, r#"data_dir = "/data""#);

        std::env::set_var("BOLT12_GATEWAY_GRPC_LISTEN", "not-an-addr");
        let err = GatewayConfig::load(&path).expect_err("must fail");
        assert!(format!("{err:#}").contains("BOLT12_GATEWAY_GRPC_LISTEN"));
    }

    /// Default TOML body → mTLS off (all three paths None). The
    /// gateway starts in cleartext; this is the in-network single-
    /// host deploy mode.
    #[test]
    fn tls_is_off_by_default() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&[
            "BOLT12_GATEWAY_TLS_CA_CERT",
            "BOLT12_GATEWAY_TLS_SERVER_CERT",
            "BOLT12_GATEWAY_TLS_SERVER_KEY",
        ]);

        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, r#"data_dir = "/data""#);
        let cfg = GatewayConfig::load(&path).expect("load");
        assert!(!cfg.tls.is_complete());
        assert!(!cfg.tls.is_partial());
    }

    /// All three paths set in TOML → mTLS enabled. The mere
    /// presence of all three flips the runtime into TLS-terminating
    /// mode; the file contents are validated when the gateway
    /// actually starts.
    #[test]
    fn tls_full_toml_config_is_complete() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&[
            "BOLT12_GATEWAY_TLS_CA_CERT",
            "BOLT12_GATEWAY_TLS_SERVER_CERT",
            "BOLT12_GATEWAY_TLS_SERVER_KEY",
        ]);

        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
            data_dir = "/data"
            [tls]
            ca_cert_path     = "/certs/ca.pem"
            server_cert_path = "/certs/server.pem"
            server_key_path  = "/certs/server.key"
            "#,
        );
        let cfg = GatewayConfig::load(&path).expect("load");
        assert!(cfg.tls.is_complete());
        assert!(!cfg.tls.is_partial());
        assert_eq!(
            cfg.tls.ca_cert_path.as_deref(),
            Some(std::path::Path::new("/certs/ca.pem"))
        );
    }

    /// Half-configured TLS is a fail-loud error, not a silent
    /// fallback to cleartext. This is the most dangerous shape — an
    /// operator who set two of three paths almost certainly intends
    /// TLS; refusing the boot is the right call.
    #[test]
    fn tls_partial_config_errors() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&[
            "BOLT12_GATEWAY_TLS_CA_CERT",
            "BOLT12_GATEWAY_TLS_SERVER_CERT",
            "BOLT12_GATEWAY_TLS_SERVER_KEY",
        ]);

        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            r#"
            data_dir = "/data"
            [tls]
            ca_cert_path = "/certs/ca.pem"
            "#,
        );
        let err = GatewayConfig::load(&path).expect_err("must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("TLS configuration is partial"),
            "expected partial-TLS error, got: {msg}"
        );
    }

    /// Env-var TLS paths override the TOML. Empty-string env var
    /// clears the field — same opt-out shape as
    /// ``BOLT12_GATEWAY_TOKEN=``.
    #[test]
    fn tls_env_overrides_toml() {
        let _g = env_lock().lock().unwrap();
        let _e = EnvGuard::new(&[
            "BOLT12_GATEWAY_TLS_CA_CERT",
            "BOLT12_GATEWAY_TLS_SERVER_CERT",
            "BOLT12_GATEWAY_TLS_SERVER_KEY",
        ]);

        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, r#"data_dir = "/data""#);
        std::env::set_var("BOLT12_GATEWAY_TLS_CA_CERT", "/env/ca.pem");
        std::env::set_var("BOLT12_GATEWAY_TLS_SERVER_CERT", "/env/srv.pem");
        std::env::set_var("BOLT12_GATEWAY_TLS_SERVER_KEY", "/env/srv.key");
        let cfg = GatewayConfig::load(&path).expect("load");
        assert!(cfg.tls.is_complete());
        assert_eq!(
            cfg.tls.ca_cert_path.as_deref(),
            Some(std::path::Path::new("/env/ca.pem"))
        );
    }
}
