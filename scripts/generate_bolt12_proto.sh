#!/usr/bin/env bash
# Regenerate Python gRPC stubs from proto/bolt12_gateway.proto.
#
# Output: app/services/bolt12_gateway/_proto/{bolt12_gateway_pb2.py,
#                                              bolt12_gateway_pb2.pyi,
#                                              bolt12_gateway_pb2_grpc.py}
#
# Requires: grpcio-tools (installed via the [dev] extra).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="app/services/bolt12_gateway/_proto"

# Prefer the project venv if present so grpcio-tools is reliably found.
PYTHON="${PYTHON:-python}"
if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    PYTHON="$REPO_ROOT/.venv/bin/python"
fi

"$PYTHON" -m grpc_tools.protoc \
    -I proto \
    --python_out="$OUT_DIR" \
    --grpc_python_out="$OUT_DIR" \
    --pyi_out="$OUT_DIR" \
    proto/bolt12_gateway.proto

# protoc emits a top-level `import bolt12_gateway_pb2 as ...` which
# breaks when the stubs are imported as a sub-package. Rewrite to a
# relative import.
sed -i \
    's/^import bolt12_gateway_pb2 as bolt12__gateway__pb2$/from . import bolt12_gateway_pb2 as bolt12__gateway__pb2/' \
    "$OUT_DIR/bolt12_gateway_pb2_grpc.py"

echo "Regenerated stubs in $OUT_DIR"
