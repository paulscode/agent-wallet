# SPDX-License-Identifier: MIT
"""Exception types raised by the BOLT 12 gateway client."""

from __future__ import annotations


class GatewayError(Exception):
    """Base class for all gateway client errors."""


class GatewayUnavailableError(GatewayError):
    """The gateway daemon is not reachable (channel down, refused, etc.)."""


class GatewayUnimplementedError(GatewayError):
    """The gateway returned ``UNIMPLEMENTED`` for this RPC."""


class GatewayRpcError(GatewayError):
    """The gateway returned a non-OK status that isn't otherwise classified."""

    def __init__(self, code: str, details: str) -> None:
        super().__init__(f"{code}: {details}")
        self.code = code
        self.details = details
