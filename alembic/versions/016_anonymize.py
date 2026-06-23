# SPDX-License-Identifier: MIT
"""Add anonymize_session and supporting tables.

Revision ID: 016_anonymize
Revises: 015_utxo_labels
Create Date: 2026-05-10 00:00:00.000000

Establishes the schema backing the dashboard "Anonymize" feature.
Six new tables land in this migration:

* ``anonymize_session`` — primary state row per anonymize session.
  Captures source kind, frozen pipeline_json, encrypted destination,
  swap-leg foreign keys, retention bookkeeping, and the
  ``gc_passes_completed`` bitfield gating the ten retention passes.
* ``anonymize_session_event`` — append-only per-session event log
  (state changes, hop attempts, warnings, idempotency keys).
* ``anonymize_settings`` — singleton key/value table for durable
  knobs that must survive backup-restore (notably
  ``feature_enabled_at_day``).
* ``anonymize_bin_set_history`` — historical record of bin-set
  changes for the pre-existing-exact-bin-UTXO refusal rule.
* ``anonymize_operator_health`` — persisted operator outlier counter
  and ``degraded`` flag.
* ``anonymize_runtime_state`` — persisted small JSON state blobs
  (circuit-rebuild leaky bucket, decoy histograms, redactor
  allow-list, refund-label backfill high-water-mark). The ``value``
  column is encrypted by migration ``020a/020b``;
  this migration writes it as cleartext JSONB ``BYTEA`` placeholder
  per the two-step migration plan.

Sentinel-UUID handling for ``submarine_swap_id`` / ``reverse_swap_id``
is: the FK is rewritten as ``NOT VALID`` and a
CHECK constraint admits either a real ``boltz_swaps.id`` or the
all-zeros sentinel ``'00000000-0000-0000-0000-000000000000'``. A pre-
INSERT trigger ``trg_anonymize_session_reject_sentinel_uuid`` rejects
sentinel writes from non-gc paths (gated by the session-local GUC
``anonymize.gc_writer = 'on'`` set only by ``gc.py``).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "016_anonymize"
down_revision: Union[str, None] = "015_utxo_labels"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Sentinel UUID used by gc.py pass 8 (`swap_anchor_severance`) when
# severing the foreign-key reference from `anonymize_session` to a
# fully-redacted `boltz_swaps` row. CHECK constraints below accept
# this value alongside real boltz_swaps.id values.
_SENTINEL_UUID = "00000000-0000-0000-0000-000000000000"


def upgrade() -> None:
    # ── anonymize_session ──────────────────────────────────────────
    op.create_table(
        "anonymize_session",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        # State machine status — stored as TEXT (not native ENUM) so
        # forward-compat additions (new substates) do not require an
        # ALTER TYPE migration. CHECK-constrained at the application
        # layer via the AnonymizeStatus enum mirror.
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("source_kind", sa.Text(), nullable=False),
        sa.Column("requested_amount_sat", sa.BigInteger(), nullable=False),
        # binned amount; replaced with bin_index by gc on retention.
        sa.Column("bin_amount_sat", sa.BigInteger(), nullable=False),
        # frozen pipeline policy. JSONB so we can validate /
        # query the schema_version at execute time.
        sa.Column("pipeline_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        # HMAC over the canonicalized quote payload. Provided
        # by quote_token issuance; persisted so create can verify
        # the body did not change between quote and create.
        sa.Column("quote_hmac", sa.LargeBinary(), nullable=False),
        # destination. MultiFernet ciphertext bytes; decrypted
        # only at execute-time by the orchestrator.
        sa.Column("destination_address_enc", sa.LargeBinary(), nullable=False),
        # destination script type — non-secret. Overwritten
        # with literal "redacted" by gc on retention.
        sa.Column("destination_script_type", sa.Text(), nullable=False),
        # retention bookkeeping; bucket-quantized by gc pass 7.
        sa.Column(
            "destination_address_redacted_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        # chain anchors — nulled by gc on retention.
        sa.Column("output_txid", sa.Text(), nullable=True),
        sa.Column("output_vout", sa.Integer(), nullable=True),
        # reorg-aware completion timestamp. Bucket-quantized by
        # gc pass 7 on retention.
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        # cooperative-claim tx hex. Persisted before broadcast
        # jitter starts so a crash mid-jitter is recoverable.
        # Redacted by gc on the destination-retention schedule;
        # the scriptPubKey inside contains the destination address.
        sa.Column("claim_tx_hex", sa.Text(), nullable=True),
        sa.Column("claim_broadcast_at_ts", sa.DateTime(timezone=True), nullable=True),
        # broadcast deadline (local-only; never sent to Boltz).
        sa.Column("broadcast_deadline_unix_s", sa.BigInteger(), nullable=True),
        # self-broadcast crash-consistency marker.
        sa.Column(
            "self_broadcast_attempted_at_ts",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        # prior status when entering awaiting_reconciliation.
        sa.Column("pre_reconciliation_status", sa.Text(), nullable=True),
        # awaiting_reconciliation human-readable cause.
        sa.Column("awaiting_reconciliation_reason", sa.Text(), nullable=True),
        sa.Column(
            "last_reconciliation_attempt_ts",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        # frozen schema version, MAJOR*10+MINOR encoding; ≥10
        # so gc's `// 10` quantization on retention never collapses
        # to zero.
        sa.Column(
            "pipeline_schema_version",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "reconciliation_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        # executed-pipeline score (vs. quote-time score in pipeline_json).
        sa.Column(
            "final_score_report_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("delay_until_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("inter_leg_delay_until_ts", sa.DateTime(timezone=True), nullable=True),
        # last_error — writes route through a regex redactor;
        # gc nulls on retention.
        sa.Column("last_error", sa.Text(), nullable=True),
        # Per-hop intermediate state (nullable). FK is left in place
        # but the DB-level constraint is created NOT VALID below so
        # the gc-pass-8 sentinel UUID is admissible. A CHECK
        # constraint enforces "real id OR sentinel".
        sa.Column(
            "submarine_swap_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("submarine_operator_id", sa.Text(), nullable=True),
        sa.Column(
            "reverse_swap_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("reverse_operator_id", sa.Text(), nullable=True),
        sa.Column("priv_channel_point", sa.Text(), nullable=True),
        sa.Column("deposit_invoice_id", sa.Text(), nullable=True),
        sa.Column("deposit_address", sa.Text(), nullable=True),
        # destination-reuse detection (BLAKE2b keyed; survives
        # redaction). Sentinel `b'\x00' * 32` marks rows whose
        # generating reuse-key has been purged.
        sa.Column("destination_address_blake2b_keyed", sa.LargeBinary(), nullable=False),
        # reuse-key generation index.
        sa.Column("destination_reuse_key_generation", sa.Integer(), nullable=False),
        # funding-shape indicator (true if onchain-self funding
        # tx will produce change). Null for LN sources. Nulled by gc
        # pass 7 on retention.
        sa.Column("funding_has_change", sa.Boolean(), nullable=True),
        # over-pad consolidation use indicator. Null for LN
        # sources, false for direct exact-bin selection, true when
        # over-pad consolidation was used.
        sa.Column("used_preconsolidation", sa.Boolean(), nullable=True),
        # actual MPP K used by the reverse-leg outbound
        # payment. Sampled (requested) K is frozen into pipeline_json;
        # this column records the K actually used after fallback.
        sa.Column("reverse_payment_chunks_k", sa.Integer(), nullable=True),
        # strict-mode K-fallback decrement counter (added
        # ahead of migration 019 so the column exists in 016 too;
        # 019 only adds the default).
        sa.Column(
            "k_decrements_used",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        # retention-pass bitfield. ALL_PASSES_MASK = 0b1111111111.
        sa.Column(
            "gc_passes_completed",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        # bin-set history reference. The Lightning self-source tier
        # writes sentinel 0; the on-chain self-source migration seeds
        # anonymize_bin_set_history.id=1 and rewrites bin_set_id=0 rows to 1.
        sa.Column(
            "bin_set_id",
            sa.BigInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        # CHECK: pipeline_schema_version ≥ 10
        sa.CheckConstraint(
            "pipeline_schema_version >= 10",
            name="ck_anonymize_session_pipeline_schema_version_ge_10",
        ),
        # CHECK: submarine_swap_id is NULL or sentinel or a real boltz_swaps.id
        # The "or a real boltz_swaps.id" branch is enforced by the
        # NOT VALID FK we add below; the CHECK only ensures it's a UUID
        # value (which it is by column type).
    )
    op.create_index(
        "ix_anonymize_session_status",
        "anonymize_session",
        ["status"],
    )
    op.create_index(
        "ix_anonymize_session_created_at",
        "anonymize_session",
        [sa.text("created_at DESC")],
    )
    # reuse-detection lookup index. Partial:
    # excludes deleted rows AND excludes the all-zeros sentinel
    # (purged rows) so they neither hot-spot the index nor
    # produce false-positive reuse hits.
    op.execute(
        """
        CREATE INDEX ix_anonymize_session_destination_keyed
            ON anonymize_session(destination_address_blake2b_keyed)
            WHERE deleted_at IS NULL
              AND destination_address_blake2b_keyed
                  != E'\\x' || repeat('00', 32)::bytea
        """
    )
    # partial indexes that skip the swap-anchor sentinel UUID.
    op.execute(
        f"""
        CREATE INDEX ix_anonymize_session_submarine_swap
            ON anonymize_session(submarine_swap_id)
            WHERE submarine_swap_id IS NOT NULL
              AND submarine_swap_id != '{_SENTINEL_UUID}'::uuid
        """
    )
    op.execute(
        f"""
        CREATE INDEX ix_anonymize_session_reverse_swap
            ON anonymize_session(reverse_swap_id)
            WHERE reverse_swap_id IS NOT NULL
              AND reverse_swap_id != '{_SENTINEL_UUID}'::uuid
        """
    )

    # NOT VALID foreign keys for the swap-id columns: real values
    # reference boltz_swaps; the sentinel is admitted by the CHECK.
    # We do not validate the constraint because the sentinel violates
    # it by design (no boltz_swaps row exists for the all-zeros UUID).
    # Application-level integrity checks (startup pass)
    # cover the substitute-FK behavior.
    op.execute(
        """
        ALTER TABLE anonymize_session
            ADD CONSTRAINT fk_anonymize_session_submarine_swap
            FOREIGN KEY (submarine_swap_id)
            REFERENCES boltz_swaps(id)
            NOT VALID
        """
    )
    op.execute(
        """
        ALTER TABLE anonymize_session
            ADD CONSTRAINT fk_anonymize_session_reverse_swap
            FOREIGN KEY (reverse_swap_id)
            REFERENCES boltz_swaps(id)
            NOT VALID
        """
    )

    # pre-INSERT trigger: rejects sentinel-UUID writes
    # unless gc.py has set the session-local GUC anonymize.gc_writer.
    op.execute(
        f"""
        CREATE OR REPLACE FUNCTION trg_anonymize_session_reject_sentinel_uuid()
        RETURNS trigger AS $$
        BEGIN
            IF (NEW.submarine_swap_id = '{_SENTINEL_UUID}'::uuid
                OR NEW.reverse_swap_id = '{_SENTINEL_UUID}'::uuid)
               AND COALESCE(current_setting('anonymize.gc_writer', true), '') != 'on'
            THEN
                RAISE EXCEPTION
                    'sentinel UUID may only be written by gc.py (set anonymize.gc_writer=on)';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_anonymize_session_reject_sentinel_uuid_ins
            BEFORE INSERT OR UPDATE ON anonymize_session
            FOR EACH ROW EXECUTE FUNCTION
            trg_anonymize_session_reject_sentinel_uuid()
        """
    )

    # ── anonymize_session_event ────────────────────────────────────
    op.create_table(
        "anonymize_session_event",
        sa.Column(
            "id",
            sa.BigInteger(),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("anonymize_session.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        # See the AnonymizeSession model for the full enum of valid kinds.
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column(
            "detail_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        # gc.py truncation marker.
        sa.Column("truncated_at", sa.DateTime(timezone=True), nullable=True),
        # idempotency key.
        sa.Column("hop_idempotency_key", sa.Text(), nullable=True),
        # reuse-key-style generation index.
        sa.Column("hop_idempotency_key_generation", sa.Integer(), nullable=True),
        # per-row 128-bit nonce, Fernet-encrypted at rest.
        sa.Column("hop_idempotency_nonce_enc", sa.LargeBinary(), nullable=True),
    )
    op.create_index(
        "ix_anonymize_event_session_ts",
        "anonymize_session_event",
        ["session_id", "ts"],
    )
    op.execute(
        """
        CREATE INDEX ix_anonymize_event_idempotency
            ON anonymize_session_event(hop_idempotency_key)
            WHERE hop_idempotency_key IS NOT NULL
        """
    )
    op.execute(
        """
        CREATE INDEX ix_anonymize_event_hop_key_generation
            ON anonymize_session_event(hop_idempotency_key_generation)
            WHERE hop_idempotency_key_generation IS NOT NULL
        """
    )

    # ── anonymize_settings ─────────────────────────────────────────
    # singleton key/value table for durable knobs.
    op.create_table(
        "anonymize_settings",
        sa.Column("key", sa.Text(), primary_key=True),
        sa.Column(
            "value",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "set_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # ── anonymize_bin_set_history ──────────────────────────────────
    # The Lightning self-source tier inserts no rows; the on-chain
    # self-source migration seeds id=1 from the frozen bin set.
    op.create_table(
        "anonymize_bin_set_history",
        sa.Column(
            "id",
            sa.BigInteger(),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column(
            "activated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "bin_set_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("schema_version", sa.Integer(), nullable=False),
    )
    op.create_index(
        "ix_anonymize_bin_set_activated_at",
        "anonymize_bin_set_history",
        ["activated_at"],
    )

    # ── anonymize_operator_health ──────────────────────────────────
    # persisted operator outlier counter and degraded flag.
    op.create_table(
        "anonymize_operator_health",
        sa.Column("operator_id", sa.Text(), primary_key=True),
        sa.Column(
            "outlier_count_24h",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("last_outlier_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "degraded",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("degraded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("degraded_reason", sa.Text(), nullable=True),
    )

    # ── anonymize_runtime_state ────────────────────────────────────
    # persisted small JSON blobs. Migration 020a/b
    # encrypts the value column with MultiFernet(FERNET_KEYS); this
    # initial migration writes BYTEA so the type is forward-compatible.
    op.create_table(
        "anonymize_runtime_state",
        sa.Column("key", sa.Text(), primary_key=True),
        # Stored as cleartext JSONB-bytes pre-020; encrypted by 020a/b.
        sa.Column("value", sa.LargeBinary(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    # Drop in reverse order (FKs first).
    op.drop_table("anonymize_runtime_state")
    op.drop_table("anonymize_operator_health")
    op.drop_index(
        "ix_anonymize_bin_set_activated_at",
        table_name="anonymize_bin_set_history",
    )
    op.drop_table("anonymize_bin_set_history")
    op.drop_table("anonymize_settings")
    op.execute("DROP INDEX IF EXISTS ix_anonymize_event_hop_key_generation")
    op.execute("DROP INDEX IF EXISTS ix_anonymize_event_idempotency")
    op.drop_index(
        "ix_anonymize_event_session_ts",
        table_name="anonymize_session_event",
    )
    op.drop_table("anonymize_session_event")
    op.execute("DROP TRIGGER IF EXISTS trg_anonymize_session_reject_sentinel_uuid_ins ON anonymize_session")
    op.execute("DROP FUNCTION IF EXISTS trg_anonymize_session_reject_sentinel_uuid()")
    op.execute("ALTER TABLE anonymize_session DROP CONSTRAINT IF EXISTS fk_anonymize_session_reverse_swap")
    op.execute("ALTER TABLE anonymize_session DROP CONSTRAINT IF EXISTS fk_anonymize_session_submarine_swap")
    op.execute("DROP INDEX IF EXISTS ix_anonymize_session_reverse_swap")
    op.execute("DROP INDEX IF EXISTS ix_anonymize_session_submarine_swap")
    op.execute("DROP INDEX IF EXISTS ix_anonymize_session_destination_keyed")
    op.drop_index(
        "ix_anonymize_session_created_at",
        table_name="anonymize_session",
    )
    op.drop_index(
        "ix_anonymize_session_status",
        table_name="anonymize_session",
    )
    op.drop_table("anonymize_session")
