# SPDX-License-Identifier: MIT
"""Anonymize service package.

The package layout follows:

* ``service`` — :class:`AnonymizeService` orchestrator + state machine.
* ``pipelines`` — pipeline / hop dataclasses + the normalization
  invariant validator.
* ``hops/`` — per-hop logic (``ln_self_pay``, ``reverse``, plus the
  on-chain submarine/private-channel and Liquid round-trip hops).
* ``policy`` — :class:`AnonymityScorer`, fee estimator, jitter helpers.
* ``coin_control`` — source-side UTXO selector and labelling rules.
* ``http`` — pinned-JA4 / header-normalized httpx client factory.
* ``tor`` — per-call-site SOCKS listener selector + control-port
  client + exit-relay diversity check.
* ``operators`` — multi-operator registry loader + signature
  verification + per-session ordered-pair sampler.
* ``quote_cache`` — background pair-info / fee cache; the ``quote``
  endpoint reads only from this cache.
* ``chain`` — private chain-backend guard with separate clients for
  general-wallet vs anonymize chain queries.
* ``dns`` — BIP-353 DoH resolver used by the Liquid round-trip path.
* ``clock`` — NTP skew probe + dashboard health-card data.
* ``gc`` — destination redaction + event GC + retention bitfield
  driver.
* ``metadata`` — constants used by tests (forbidden egress fields,
  pinned headers, expected JA4 hash).
* ``txpolicy`` — Bitcoin-Core-shaped envelope policy +
  feerate jitter.
* ``reuse_detection`` — keyed-BLAKE2b destination-reuse hashing.
* ``broadcast`` — broadcast-via-Boltz primary path + self-broadcast
  fallback through ``chain``.

The package covers the LN-source path; the on-chain self-source path
adds the submarine hop, ``priv_channel`` hop, ``coin_control``
over-pad consolidation, and the operator-registry signature
verification surface; the external user-funded and Liquid round-trip
paths add Liquid round-tripping.
"""

from __future__ import annotations

# Public re-exports kept narrow so call sites don't grow accidental
# coupling to internal helpers.
from .metadata import (
    ANONYMIZE_LOGGER_NAME,
    ANONYMIZE_RUNTIME_STATE_KEYS,
    ANONYMIZE_SETTINGS_QUANTIZE_KEYS,
    REUSE_DETECTION_SENTINEL,
)

__all__ = [
    "ANONYMIZE_LOGGER_NAME",
    "ANONYMIZE_RUNTIME_STATE_KEYS",
    "ANONYMIZE_SETTINGS_QUANTIZE_KEYS",
    "REUSE_DETECTION_SENTINEL",
]
