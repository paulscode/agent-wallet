# SPDX-License-Identifier: MIT
"""Module-level constants used by the anonymize stack and its tests.

These are the surfaces the hardening checklist + robustness
sections refer to repeatedly. Keeping them in a single file makes:

* CI lint tests cheaper (`tools/check_anonymize_column_disposition.py`,
  `test_anonymize_no_internal_ids_egress.py`, etc.) — they import the
  registry from here rather than re-deriving it.
* Cross-section invariants easier to enforce (e.g. reuse
  sentinel internal-consistency runtime-state key registry).
"""

from __future__ import annotations

import logging as _logging

# dedicated logger name. WARNING is the default level so
# routine INFO chatter doesn't expose request cadence post-mortem.
# The operator can override via standard logging.config; we set the
# default here at module-import time so the level is in effect from
# the first session-create.
ANONYMIZE_LOGGER_NAME = "app.services.anonymize"
_logging.getLogger(ANONYMIZE_LOGGER_NAME).setLevel(_logging.WARNING)


# / checklist item 60 / 118: the
# ``destination_address_blake2b_keyed`` purge sentinel is the literal
# 32 zero bytes. Earlier drafts of specified a BLAKE2b-keyed
# sentinel under an undefined key — that draft is retracted in favor of
# the all-zeros literal used everywhere else in the pipeline.
REUSE_DETECTION_SENTINEL: bytes = b"\x00" * 32


# Registry of allowed keys in ``anonymize_runtime_state``.
# Writes whose key is not in this registry are flagged by the
# ``test_anonymize_runtime_state_key_registry.py`` lint. The tuple is
# deliberately conservative; new keys must be added explicitly via PR.
ANONYMIZE_RUNTIME_STATE_KEYS: frozenset[str] = frozenset(
    {
        # circuit-rebuild leaky bucket — one per
        # listener class plus the aggregate.
        "circuit_rebuild_bucket:listener=boltz_submarine",
        "circuit_rebuild_bucket:listener=boltz_reverse",
        "circuit_rebuild_bucket:listener=liquid",
        "circuit_rebuild_bucket:listener=chain_backend",
        "circuit_rebuild_bucket:listener=bip353_dns",
        "circuit_rebuild_bucket:listener=quote_cache_refresh",
        "circuit_rebuild_bucket:listener=chain_backend_general",
        "circuit_rebuild_bucket:listener=chain_backend_anonymize",
        "circuit_rebuild_bucket:aggregate",
        # decoy-output value sampler histogram.
        "decoy_value_histogram",
        # redactor allow-list (long-hex strings the redactor
        # should pass through unchanged: xpub, release-key fingerprint,
        # FERNET canary digest).
        "redactor_allowlist:xpub",
        "redactor_allowlist:release_key_fingerprint",
        "redactor_allowlist:fernet_canary",
        # refund-label backfill high-water-mark
        # (replaces the per-row ``boltz_swap.refund_label_backfilled_at_ts``
        # marker the prior plan specified).
        "refund_label_backfill_high_water_mark",
        # reuse-detection key rotation last-completed timestamp.
        "reuse_detection_key_rotation_last_at",
        # quote-token HMAC key rotation last-completed timestamp.
        "quote_token_hmac_key_rotation_last_at",
        # quote-cache signing key rotation last-completed timestamp.
        "quote_cache_signing_key_rotation_last_at",
        # hop-idempotency-key rotation last-completed timestamp.
        "hop_idempotency_key_rotation_last_at",
        # last-successful gc.py pass timestamp (health surface).
        "last_successful_gc_at",
        # Reconciliation-probe last-run timestamp. Updated by
        # ``tick_runners.make_reconciliation_probe_run_fn`` so the
        # health surface can flag a stalled probe.
        "last_successful_reconciliation_probe_at",
        # Audit-chain emission high-water mark.
        # Records the bucket start (unix_s) of the most-recently
        # emitted ``anonymize.bucket_summary`` row. The emitter picks
        # up from this mark + bucket_seconds on each tick.
        "audit_chain_last_emitted_bucket_start_unix_s",
        # Most-recent clock-skew measurement (NTP probe
        # output). The self-broadcast tick reads this to decide
        # whether the skew-window gate allows firing.
        "clock_skew_state",
    }
)


# Keys whose ``set_at`` should be UTC-day-truncated
# by trigger ``trg_anonymize_settings_quantize_set_at``. Mirrored into
# the ``anonymize_settings_quantize_allowlist`` table by migration 017
# (the trigger reads the GUC fallback list when the session-local GUC
# is unset;).
ANONYMIZE_SETTINGS_QUANTIZE_KEYS: frozenset[str] = frozenset(
    {
        "feature_enabled_at_day",
    }
)


# forbidden internal-ID names that the anonymize HTTP client
# wrapper must never propagate to upstream operators. CI lint asserts
# (mocking httpx) that no outbound request body / query string / header
# from ``app/services/anonymize/**`` contains any of these names.
ANONYMIZE_FORBIDDEN_EGRESS_FIELDS: frozenset[str] = frozenset(
    {
        "session_id",
        "quote_token",
        "idempotency_key",
        "internal_swap_id",
        "internal_audit_id",
        "our_node_pubkey",
        "X-Request-Id",
        "X-Trace-Id",
        "Traceparent",
        "x-request-id",
        "x-trace-id",
        "traceparent",
    }
)


# fixed minimal HTTP-header set for every anonymize-egress
# call. The wrapper produces a constant ClientHello and a fixed
# request shape so a Boltz operator cannot fingerprint our wallet
# across legs even when stream-isolated.
ANONYMIZE_PINNED_HTTP_HEADERS: dict[str, str] = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip",
    "Connection": "close",
}


__all__ = [
    "ANONYMIZE_LOGGER_NAME",
    "REUSE_DETECTION_SENTINEL",
    "ANONYMIZE_RUNTIME_STATE_KEYS",
    "ANONYMIZE_SETTINGS_QUANTIZE_KEYS",
    "ANONYMIZE_FORBIDDEN_EGRESS_FIELDS",
    "ANONYMIZE_PINNED_HTTP_HEADERS",
]
