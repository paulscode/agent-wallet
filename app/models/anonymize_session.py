# SPDX-License-Identifier: MIT
"""Anonymize session ORM models.

The migration that creates these tables is ``016_anonymize.py``
(with follow-on ``017``, ``019``, ``020a/b``, ``021``).

Sensitive fields are stored encrypted at rest:

* ``destination_address_enc`` — ``MultiFernet(FERNET_KEYS)``
  /. Decrypted only at execute-time by the orchestrator.
* ``destination_address_blake2b_keyed`` — keyed-BLAKE2b hash for
  destination-reuse detection. Survives redaction;
  purged-key rows carry the all-zeros sentinel ``b"\\x00" * 32``.
* ``hop_idempotency_nonce_enc`` — per-row 128-bit nonce, Fernet-
  encrypted.

These are SQLAlchemy mapped classes; the encryption helpers live in
``app.services.anonymize.crypto`` (created alongside the service
skeleton).
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AnonymizeStatus(str, enum.Enum):
    """Anonymize session lifecycle status — mirror of state machine."""

    CREATED = "created"
    SOURCING = "sourcing"
    FUNDING = "funding"
    LN_HOLDING = "ln_holding"
    DELAYING = "delaying"
    HOPPING = "hopping"
    EXITING = "exiting"
    CONFIRMING = "confirming"
    COMPLETED = "completed"
    COMPLETED_WITH_REORG_UNCERTAINTY = "completed_with_reorg_uncertainty"
    AWAITING_RECONCILIATION = "awaiting_reconciliation"
    AWAITING_CHANNEL_CLOSE = "awaiting_channel_close"
    AWAITING_LIQUID_DWELL = "awaiting_liquid_dwell"
    CANCELLED = "cancelled"
    REFUNDING = "refunding"
    FAILED = "failed"


# Set of statuses the gc retention pass treats as terminal.
ANONYMIZE_TERMINAL_STATUSES = frozenset(
    {
        AnonymizeStatus.COMPLETED.value,
        AnonymizeStatus.COMPLETED_WITH_REORG_UNCERTAINTY.value,
        AnonymizeStatus.CANCELLED.value,
        AnonymizeStatus.FAILED.value,
    }
)


class AnonymizeSourceKind(str, enum.Enum):
    """Source kinds: self-sourced and externally-funded Lightning and on-chain."""

    LIGHTNING_SELF = "lightning-self"
    EXT_LIGHTNING = "ext-lightning"
    ONCHAIN_SELF = "onchain-self"
    EXT_ONCHAIN = "ext-onchain"


class AnonymizeSession(Base):
    """Per-session state row."""

    __tablename__ = "anonymize_session"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        onupdate=_utc_now,
    )

    # State machine status, stored as TEXT so adding new substates
    # does not require an ALTER TYPE migration.
    status: Mapped[str] = mapped_column(Text, nullable=False)
    source_kind: Mapped[str] = mapped_column(Text, nullable=False)

    requested_amount_sat: Mapped[int] = mapped_column(BigInteger, nullable=False)
    bin_amount_sat: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # frozen pipeline policy.
    pipeline_json: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # quote-token HMAC, persisted so create can verify the body
    # was unchanged between quote and create.
    quote_hmac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # destination ciphertext.
    destination_address_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # script type — non-secret; literal "redacted" post-retention.
    destination_script_type: Mapped[str] = mapped_column(Text, nullable=False)
    destination_address_redacted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # chain anchors — nulled by gc on retention.
    output_txid: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    output_vout: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # cooperative-claim tx hex, persisted before broadcast jitter.
    claim_tx_hex: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    claim_broadcast_at_ts: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    broadcast_deadline_unix_s: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    self_broadcast_attempted_at_ts: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Chain-confirmation tracking for CONFIRMING → COMPLETED.
    # ``claim_txid`` is the derived index for chain-poll lookups;
    # ``claim_tx_hex`` remains the rebroadcast source-of-truth.
    claim_txid: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    claim_tx_confirmations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    claim_tx_reorg_observed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    pre_reconciliation_status: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    awaiting_reconciliation_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_reconciliation_attempt_ts: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # frozen schema version, MAJOR*10+MINOR encoding.
    pipeline_schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    reconciliation_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # executed-pipeline score.
    final_score_report_json: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    delay_until_ts: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    inter_leg_delay_until_ts: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Per-hop intermediate state. The FK to boltz_swaps is NOT VALID
    # at the DB level (see migration 016) so the gc-pass-8 sentinel
    # UUID can be written without FK violation.
    submarine_swap_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    submarine_operator_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reverse_swap_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    reverse_operator_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Per-leg operator attribution for the Liquid round-trip hop.
    # Unlike the non-Liquid path, Liquid swaps don't get BoltzSwap
    # rows — state lives in ``pipeline_json`` + an in-process cache.
    # These columns let recovery code answer "which operator handled
    # leg N of this Liquid session" without re-deriving it from the
    # process-cached ``LiquidLegSelection``. NULL on sessions that
    # don't use the Liquid hop. No distinct-CHECK: single-operator
    # Liquid deployments legitimately collapse both legs.
    liquid_reverse_operator_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    liquid_submarine_operator_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    priv_channel_point: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    deposit_invoice_id: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    deposit_address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Per-session Liquid blinding-derivation index (Fernet-
    # encrypted at-rest so a DB-snapshot adversary cannot enumerate
    # Liquid hops by walking the index). Liquid hop only; NULL on
    # sessions that don't use the Liquid hop.
    liquid_blinding_seed_enc: Mapped[Optional[bytes]] = mapped_column(
        LargeBinary,
        nullable=True,
    )

    # reuse-detection hash + key generation index.
    destination_address_blake2b_keyed: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    destination_reuse_key_generation: Mapped[int] = mapped_column(Integer, nullable=False)

    funding_has_change: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    used_preconsolidation: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    reverse_payment_chunks_k: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    k_decrements_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # retention-pass bitfield.
    gc_passes_completed: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bin_set_id: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint(
            "pipeline_schema_version >= 10",
            name="ck_anonymize_session_pipeline_schema_version_ge_10",
        ),
        # Refuse rows that pair the two legs with the same
        # operator id. Migration 025 adds the matching DB CHECK.
        CheckConstraint(
            "submarine_operator_id IS NULL "
            "OR reverse_operator_id IS NULL "
            "OR submarine_operator_id <> reverse_operator_id",
            name="ck_anonymize_session_distinct_operator_ids",
        ),
        Index("ix_anonymize_session_status", "status"),
    )


class AnonymizeSessionEvent(Base):
    """Per-session event log row.

    Rows are append-only at the application layer. for the
    full enum of valid ``kind`` values. The retention pass either
    deletes (default) or kind-collapses these rows on retention
    expiry.
    """

    __tablename__ = "anonymize_session_event"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("anonymize_session.id", ondelete="CASCADE"),
        nullable=False,
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    detail_json: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    truncated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    hop_idempotency_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hop_idempotency_key_generation: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    hop_idempotency_nonce_enc: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    __table_args__ = (Index("ix_anonymize_event_session_ts", "session_id", "ts"),)


class AnonymizeSettings(Base):
    """Singleton key/value table.

    The most important key is ``feature_enabled_at_day`` (/
    ) — UTC-day-quantized timestamp recording when this
    wallet first ran an anonymize session. The pre-INSERT trigger
    ``trg_anonymize_settings_quantize_set_at`` (migration 017)
    auto-truncates ``set_at`` to UTC-day for keys in the quantize
    allow-list.
    """

    __tablename__ = "anonymize_settings"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False)
    set_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)


class AnonymizeBinSetHistory(Base):
    """Bin-set history.

    For Lightning-only deployments this stays empty; the on-chain
    decoy migration seeds id=1 from the frozen bin set.
    """

    __tablename__ = "anonymize_bin_set_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    bin_set_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)


class AnonymizeOperatorHealth(Base):
    """Persisted per-operator outlier counter and degraded flag."""

    __tablename__ = "anonymize_operator_health"

    operator_id: Mapped[str] = mapped_column(Text, primary_key=True)
    outlier_count_24h: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_outlier_ts: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    degraded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    degraded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    degraded_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class AnonymizeRuntimeState(Base):
    """Persisted small JSON state blobs.

    The ``value`` column holds JSONB cleartext bytes pre-020, and
    ``MultiFernet(FERNET_KEYS)`` ciphertext post-020. The
    application reads / writes via ``app.services.anonymize.runtime_state``
    so the encryption transition is invisible to call sites.

    The cleartext ``key`` is itself a small leak surface (residual
    #33); the registry constant ``ANONYMIZE_RUNTIME_STATE_KEYS``
    fixes the allowed key set.
    """

    __tablename__ = "anonymize_runtime_state"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)


class AnonymizeStepupState(Base):
    """Step-up re-auth nonce / lockout rows.

    ``cookie_id_hmac`` is HMAC-blinded under
    ``ANONYMIZE_STEPUP_COOKIE_HMAC_KEY_FERNET`` so a DB-snapshot
    adversary cannot map rows to specific operator cookies.
    """

    __tablename__ = "anonymize_stepup_state"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    cookie_id_hmac: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce_enc: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    scope: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    failed_verifies: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (CheckConstraint("kind IN ('nonce', 'lockout')", name="ck_anonymize_stepup_kind"),)


class AnonymizeDecoyOutput(Base):
    """On-chain decoy-output table.

    The migration ``018_anonymize_decoy_seed.py`` creates the
    table with a partial-unique index ``WHERE session_id IS NOT NULL``
    so post-retention sentinel-FK rows do not contend with fresh
    decoy issuance. The retention pass (gc pass 10) nulls
    ``address`` / ``value_sat`` / ``session_account`` /
    ``derivation_index`` once the parent session is past retention,
    and replaces ``session_id`` with the all-zeros sentinel
    UUID. Spent decoy ``outpoint`` is also nulled; unspent decoys
    preserve ``outpoint`` (residual #34) so the wallet still tracks
    the UTXO.

    Lightning-only deployments never write to this table; the on-chain
    decoy migrations create + populate it. The ORM lives here so the gc
    helpers can reference it without a circular import.
    """

    __tablename__ = "anonymize_decoy_output"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("anonymize_session.id", ondelete="CASCADE"),
        nullable=True,  # set to sentinel UUID by retention pass
    )
    session_account: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    derivation_index: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    value_sat: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    outpoint: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    seed_orphaned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    spent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AnonymizeSessionOutput(Base):
    """Multi-output session row.

    A multi-output session produces N base-layer outputs at N user-
    supplied destination addresses, each with its own bin amount and
    randomized schedule offset so an observer cannot trivially link
    them by simultaneous arrival. Single-output sessions continue to
    use the singular ``anonymize_session.destination_address_enc`` +
    ``bin_amount_sat`` columns; multi-output sessions write one row
    per output here and the singular columns hold the index-0 output
    for backwards compatibility.

    ``destination_address_enc`` follows the Fernet-wrap +
     retention rules. ``destination_address_blake2b_keyed`` is
    the reuse-detection sentinel for each output (keyed under
    the same reuse-key generation as the parent session row).

    ``scheduled_at_unix_s`` is the per-output egress timestamp; the
    orchestrator orders the multi-output egress by this value so a
    chain observer correlating "all outputs of session X arriving at
    t" sees a spread, not a simultaneous burst.
    """

    __tablename__ = "anonymize_session_output"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("anonymize_session.id", ondelete="CASCADE"),
        nullable=False,
    )
    # 0-based position within the session's output set; UNIQUE per session.
    output_index: Mapped[int] = mapped_column(Integer, nullable=False)
    destination_address_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    destination_script_type: Mapped[str] = mapped_column(Text, nullable=False)
    bin_amount_sat: Mapped[int] = mapped_column(BigInteger, nullable=False)
    scheduled_at_unix_s: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    output_txid: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    output_vout: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_address_blake2b_keyed: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    destination_reuse_key_generation: Mapped[int] = mapped_column(Integer, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    destination_address_redacted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "session_id",
            "output_index",
            name="uq_anonymize_session_output_session_index",
        ),
        CheckConstraint(
            "output_index >= 0",
            name="ck_anonymize_session_output_index_nonneg",
        ),
        CheckConstraint(
            "bin_amount_sat > 0",
            name="ck_anonymize_session_output_bin_amount_positive",
        ),
    )


class AnonymizeQuoteTokenKeyGeneration(Base):
    """Cross-replica HMAC-key generation index.

    Holds one row per quote-token HMAC key generation the deployment
    has ever issued. Replicas whose in-memory keyset is older than a
    just-rotated generation use this table as the synchronous
    DB-fallback the verify path consults
    (``decide_quote_token_verify_action``); rotated-out generations
    persist until the retention horizon.

    ``key_fingerprint_hex`` is SHA-256 of the raw 32-byte HMAC key
    material (NOT the key itself — the key lives in the operator's
    Fernet bundle).
    """

    __tablename__ = "anonymize_quote_token_key_generations"

    generation: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=False,
    )
    key_fingerprint_hex: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )
    retired_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class LiquidResidualOutput(Base):
    """Unspent L-BTC at a wallet-controlled address awaiting recovery.

    Populated by the periodic ``scan_residual_liquid_balances``
    task: it queries electrs-liquid for outputs at addresses
    derived from the wallet's master Liquid blinding seed (via
    SLIP-77) that are not associated with a still-active anonymize
    session, and upserts each finding here. Recovery is via a
    one-shot L-BTC->LN submarine swap (one swap per row for v1).

    The row exists for the lifetime of the residual: even after
    ``recovered_at`` is set, the row stays in-place so the operator
    audit page can render the full history. The recovery banner
    excludes rows with a non-NULL ``recovered_at`` OR
    ``dust_acknowledged_at`` so swept and acknowledged-dust rows
    stop nagging.

    ``session_id`` is FK to ``anonymize_session.id`` with
    ON DELETE SET NULL: retention purges the session row long
    before the residual audit needs to retain it.
    """

    __tablename__ = "liquid_residual_outputs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    session_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("anonymize_session.id", ondelete="SET NULL"),
        nullable=True,
    )
    txid: Mapped[str] = mapped_column(Text, nullable=False)
    vout: Mapped[int] = mapped_column(Integer, nullable=False)
    asset_id: Mapped[str] = mapped_column(Text, nullable=False)
    value_sat: Mapped[int] = mapped_column(BigInteger, nullable=False)
    address: Mapped[str] = mapped_column(Text, nullable=False)
    derivation_path: Mapped[str] = mapped_column(Text, nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )
    recovered_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    # Boltz swap id of the L-BTC->LN submarine swap used to sweep
    # this output. NULL until ``recovered_at`` is set.
    recovered_swap_id: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    dust_acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint(
            "txid",
            "vout",
            name="uq_liquid_residual_outpoint",
        ),
        CheckConstraint(
            "value_sat > 0",
            name="ck_liquid_residual_value_positive",
        ),
        CheckConstraint(
            "vout >= 0",
            name="ck_liquid_residual_vout_nonneg",
        ),
        # A residual UTXO is swept by exactly one swap. The partial
        # unique index turns any second stamp of ``recovered_swap_id``
        # into a loud failure rather than a silent double-spend, even if
        # a future caller bypasses the row-level serialization in
        # ``initiate_residual_recovery``.
        Index(
            "uq_liquid_residual_recovered_swap_id",
            "recovered_swap_id",
            unique=True,
            postgresql_where=text("recovered_swap_id IS NOT NULL"),
        ),
    )


__all__ = [
    "AnonymizeStatus",
    "AnonymizeSourceKind",
    "ANONYMIZE_TERMINAL_STATUSES",
    "AnonymizeSession",
    "AnonymizeSessionEvent",
    "AnonymizeSettings",
    "AnonymizeBinSetHistory",
    "AnonymizeOperatorHealth",
    "AnonymizeRuntimeState",
    "AnonymizeStepupState",
    "AnonymizeDecoyOutput",
    "AnonymizeQuoteTokenKeyGeneration",
    "AnonymizeSessionOutput",
    "LiquidResidualOutput",
]
