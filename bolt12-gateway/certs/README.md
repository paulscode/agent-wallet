# Placeholder so the default ``BOLT12_CERTS_DIR=./bolt12-gateway/certs``
# bind-mount path exists when mTLS is disabled (the default). When
# you opt in to mTLS, populate this directory with
# ``./scripts/gen_bolt12_certs.sh ./bolt12-gateway/certs`` (or point
# ``BOLT12_CERTS_DIR`` at a different host path).
#
# Contents are ignored by git via ``.gitignore``.
