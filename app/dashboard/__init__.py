# SPDX-License-Identifier: MIT
"""
Dashboard package — web UI for monitoring and managing the wallet.

Provides a browser-based dashboard at /dashboard/ with:
- Token-based authentication (separate from API keys)
- Real-time wallet/channel/payment monitoring
- Manual LND node operations
- Audit log viewer
Security boundary: The dashboard is the node owner's direct management
interface and intentionally does NOT enforce API-layer payment safety
limits (LND_MAX_PAYMENT_SATS, spend/velocity rate limits). Those limits
are guardrails for AI agent callers, which have a higher risk of
compromise or erroneous operation. The dashboard uses session-based
authentication with its own security controls (login rate limiting,
configurable session timeout, HttpOnly/SameSite cookies)."""

from uuid import UUID

# Sentinel UUID for dashboard-initiated operations (e.g. Boltz swaps)
DASHBOARD_KEY_ID = UUID("00000000-0000-0000-0000-da5b0a4d0000")
