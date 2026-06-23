// SPDX-License-Identifier: MIT
//! BOLT 12 onion-message gateway library surface.
//!
//! The crate ships as both a binary (`src/main.rs`) and a library so
//! integration tests under `tests/` can drive the gRPC server in
//! process. The public surface is intentionally small — Python is
//! the only consumer, and it talks gRPC, not Rust — but it is
//! re-exported here so test harnesses don't have to grovel around
//! `OUT_DIR`.

pub mod address_cache;
pub mod config;
pub mod ldk_glue;
pub mod lock_recover;
pub mod proto;
pub mod runner;
pub mod service;
pub mod sticky_peers;
