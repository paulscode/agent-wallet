# SPDX-License-Identifier: MIT
"""Per-hop logic for the anonymize pipeline.

The LN-source path uses ``ln_self_pay`` and ``reverse``; the on-chain
self-source path adds ``submarine`` and ``priv_channel``; the Liquid
round-trip path adds ``liquid``.

Each hop module exposes a ``Hop`` class with ``prepare()``,
``execute()``, ``poll()``, ``cancel()``, ``refund()`` async methods
.
"""
