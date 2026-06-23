// SPDX-License-Identifier: MIT
//! Build script: compile the BOLT 12 gateway gRPC contract.
//!
//! Drives `tonic_build` over `proto/bolt12_gateway.proto`. Generated
//! code lands in `OUT_DIR` and is re-exported from `src/proto.rs`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../proto";
    let proto_file = "bolt12_gateway.proto";

    println!("cargo:rerun-if-changed={proto_root}/{proto_file}");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[format!("{proto_root}/{proto_file}")],
            &[proto_root.to_string()],
        )?;

    Ok(())
}
