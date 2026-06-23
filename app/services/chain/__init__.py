# SPDX-License-Identifier: MIT
"""Chain-state backend abstraction.

Two implementations live here:

* :class:`MempoolHttpBackend` — wraps the public Mempool Explorer
  REST API (``https://mempool.space`` by default, or any self-hosted
  Mempool instance via ``LND_MEMPOOL_URL``).
* :class:`ElectrumChainBackend` — speaks the Electrum protocol over
  TCP/SSL/.onion+SOCKS5, intended for operators running ``electrs``
  on their own node (typical Start9 setup).

The wallet's existing public symbol — ``mempool_fee_service`` from
:mod:`app.services.mempool_fee_service` — is a thin facade that picks
a backend at startup and forwards calls. Call sites elsewhere in the
codebase do not need to change.
"""

from app.services.chain.backend import ChainBackend
from app.services.chain.mempool_http import MempoolHttpBackend

__all__ = ["ChainBackend", "MempoolHttpBackend"]
