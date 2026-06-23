#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────
# gen_bolt12_certs.sh — generate CA + server + client material for
# the optional mTLS hardening on the wallet ↔ bolt12-gateway gRPC
# channel.
#
# The default deployment runs the gateway in cleartext on an
# ``internal: true`` docker network behind a shared bearer token.
# That is sufficient for single-host installs. Operators who run
# split-host deploys, multi-tenant hosts, or who simply want a
# defence-in-depth layer can enable mTLS by:
#
#   1. Running this script once to populate the cert directory.
#   2. Setting the BOLT12_GATEWAY_TLS_* env vars on the gateway and
#      the BOLT12_GATEWAY_TLS_* env vars on the wallet (see
#      docs/bolt12.md → "Optional: mTLS").
#
# WHAT THIS GENERATES
# ───────────────────
# * ``ca.pem``        — self-signed CA root, 10-year lifetime.
# * ``ca.key``        — CA private key (PROTECT — used to sign new
#                       client certs during rotation).
# * ``server.pem``    — server cert, SAN=DNS:bolt12-gateway (the
#                       compose service name) + DNS:localhost,
#                       3-year lifetime.
# * ``server.key``    — server private key.
# * ``client.pem``    — client cert (one per wallet — defaults to a
#                       single "wallet" identity, sufficient for the
#                       single-host compose deployment), 3-year
#                       lifetime.
# * ``client.key``    — client private key.
#
# All keys are emitted as 0600 PEM files; the cert chain trust
# anchors at ``ca.pem``.
#
# WHY NOT MTLS BY DEFAULT
# ───────────────────────
# Cert lifecycle is a non-trivial operational burden: rotation,
# revocation, monitoring expiry. For the bearer-token + private-
# network default deployment, that overhead is not justified. mTLS
# is the right call when the threat model includes a hostile party
# on the docker bridge or a split-host wire.
#
# USAGE
# ─────
#     ./scripts/gen_bolt12_certs.sh ./certs/bolt12
#         → writes the six files into the named directory.
#         Refuses to overwrite an existing directory.
#
#     ./scripts/gen_bolt12_certs.sh ./certs/bolt12 --force
#         → overwrites (use during rotation).
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

OUT_DIR="${1:-}"
FORCE="${2:-}"

if [[ -z "$OUT_DIR" ]]; then
    echo "usage: $0 <output-dir> [--force]" >&2
    exit 2
fi

if [[ -e "$OUT_DIR" && "$FORCE" != "--force" ]]; then
    if [[ -n "$(ls -A "$OUT_DIR" 2>/dev/null || true)" ]]; then
        echo "error: $OUT_DIR is non-empty. Pass --force to overwrite (rotation)." >&2
        exit 1
    fi
fi

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# ─── CA ───────────────────────────────────────────────────────────
# 10-year root because rotating the CA invalidates every client and
# server cert; keep it long-lived and rotate the leaf certs instead.
openssl genrsa -out ca.key 4096 >/dev/null 2>&1
chmod 0600 ca.key
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
    -out ca.pem \
    -subj "/CN=bolt12-gateway-ca" \
    >/dev/null 2>&1
chmod 0644 ca.pem

# ─── Server cert (gateway) ────────────────────────────────────────
# SAN MUST cover the hostname the wallet uses to dial the gateway.
# Inside docker compose that's the service name ``bolt12-gateway``.
# Add ``localhost`` for host-mode testing.
openssl genrsa -out server.key 4096 >/dev/null 2>&1
chmod 0600 server.key
cat > server.cnf <<'EOF'
[req]
distinguished_name = req_dn
prompt = no
[req_dn]
CN = bolt12-gateway
[v3_req]
subjectAltName = DNS:bolt12-gateway,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
openssl req -new -key server.key -out server.csr -config server.cnf >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out server.pem -days 1095 -sha256 \
    -extfile server.cnf -extensions v3_req \
    >/dev/null 2>&1
chmod 0644 server.pem
rm -f server.csr server.cnf ca.srl

# ─── Client cert (wallet) ─────────────────────────────────────────
# A single client identity is enough for the default deployment
# where api + celery-worker share the same image and the same
# mounted cert directory. Multi-wallet deployments can re-run this
# script with a different output directory and use the resulting
# pair as a per-wallet client identity.
openssl genrsa -out client.key 4096 >/dev/null 2>&1
chmod 0600 client.key
cat > client.cnf <<'EOF'
[req]
distinguished_name = req_dn
prompt = no
[req_dn]
CN = agent-wallet
[v3_req]
extendedKeyUsage = clientAuth
EOF
openssl req -new -key client.key -out client.csr -config client.cnf >/dev/null 2>&1
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out client.pem -days 1095 -sha256 \
    -extfile client.cnf -extensions v3_req \
    >/dev/null 2>&1
chmod 0644 client.pem
rm -f client.csr client.cnf ca.srl

echo
echo "✓ Generated mTLS material in $(pwd):"
ls -la ca.pem ca.key server.pem server.key client.pem client.key
echo
echo "Next steps:"
echo "  1. Mount this directory into both bolt12-gateway and api/celery-worker."
echo "     The bundled docker-compose.yml provides a ``bolt12_certs:`` named"
echo "     volume reference; populate it via:"
echo "         docker compose cp ./$OUT_DIR/. bolt12-gateway:/etc/bolt12-gateway/certs/"
echo "  2. Set the following in .env to enable TLS:"
echo "         BOLT12_GATEWAY_TLS_CA_CERT=/etc/bolt12-gateway/certs/ca.pem"
echo "         BOLT12_GATEWAY_TLS_SERVER_CERT=/etc/bolt12-gateway/certs/server.pem"
echo "         BOLT12_GATEWAY_TLS_SERVER_KEY=/etc/bolt12-gateway/certs/server.key"
echo "         BOLT12_GATEWAY_TLS_CLIENT_CA=/etc/bolt12-gateway/certs/ca.pem"
echo "         BOLT12_GATEWAY_TLS_CLIENT_CERT=/etc/bolt12-gateway/certs/client.pem"
echo "         BOLT12_GATEWAY_TLS_CLIENT_KEY=/etc/bolt12-gateway/certs/client.key"
echo "         BOLT12_GATEWAY_TLS_SERVER_NAME=bolt12-gateway"
echo "  3. Recreate the three services together:"
echo "         docker compose up -d bolt12-gateway api celery-worker"
echo
echo "Leaf certs expire in 3 years; rotate with:"
echo "     ./scripts/gen_bolt12_certs.sh $OUT_DIR --force"
echo "(the CA stays the same; only server/client leaves rotate.)"
