# SPDX-License-Identifier: MIT
"""Plan-token signing for the channel-mix planner.

The planner endpoint returns a :class:`Plan` plus a short opaque token
the executor endpoint will require. The token serves two purposes:

1. **Tamper resistance** — a caller can't forge a plan whose
   ``per_channel`` peers / capacities differ from what the planner
   actually produced. The token is an HMAC-SHA256 over the
   canonical-JSON-encoded plan body, keyed from ``SECRET_KEY`` with a
   domain-separated subkey so it can't collide with the audit-chain
   MAC or the API-key digest.

2. **Stale-plan rejection** — the executor recomputes the plan from
   the same inputs at execute time and compares the resulting body to
   the decoded one. If the inputs now produce a different plan (catalog
   refreshed, fee oracle moved, a peer disappeared), the executor
   rejects the token with ``plan_stale`` and returns the fresh plan so
   the dashboard can re-render.

Tokens are stateless — no row in the DB. The executor needs only the
original inputs the user provided plus the SECRET_KEY-derived subkey.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import asdict, is_dataclass
from typing import Any, Mapping

from app.core.config import settings
from app.services.channel_mix_planner import Plan

# Domain-separated subkey so this MAC can't collide with the audit
# chain, the API-key digest, or session-cookie signatures even when
# SECRET_KEY is shared across them.
_PLAN_TOKEN_CONTEXT = b"agent-wallet/channel-mix-plan-token/v1"


def _to_canonical_json(plan: Plan) -> bytes:
    """Serialize a :class:`Plan` to canonical JSON (sorted keys, no
    whitespace) so the digest is reproducible across implementations.

    Frozen-dataclasses become plain dicts via ``asdict``; nested
    dataclasses recurse. Tuples become lists in JSON which is fine
    because the digest only cares about ordered equality.
    """

    def _coerce(value: Any) -> Any:
        if is_dataclass(value) and not isinstance(value, type):
            return _coerce(asdict(value))
        if isinstance(value, Mapping):
            return {k: _coerce(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_coerce(v) for v in value]
        return value

    return json.dumps(
        _coerce(plan),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _subkey(secret: str | None = None) -> bytes:
    """Domain-separated MAC key derived from ``settings.secret_key``."""
    secret = secret or settings.secret_key
    return hmac.new(secret.encode("utf-8"), _PLAN_TOKEN_CONTEXT, hashlib.sha256).digest()


def sign_plan(plan: Plan, *, secret: str | None = None) -> str:
    """Produce a base64-URL-safe HMAC-SHA256 token for ``plan``.

    The token is opaque to callers; only :func:`verify_plan_token` knows
    how to validate it. Length: 43 chars (256-bit digest, base64-url
    without padding).
    """
    digest = hmac.new(_subkey(secret), _to_canonical_json(plan), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_plan_token(plan: Plan, token: str, *, secret: str | None = None) -> bool:
    """Constant-time comparison between ``token`` and the freshly-computed
    HMAC over ``plan``. Returns ``False`` for malformed tokens too —
    callers shouldn't have to distinguish "invalid base64" from "valid
    base64 but wrong digest" (both indicate the token shouldn't be
    accepted).
    """
    if not isinstance(token, str) or not token:
        return False
    try:
        expected = sign_plan(plan, secret=secret)
    except Exception:  # noqa: BLE001 — defensive; sign_plan is pure
        return False
    return hmac.compare_digest(expected, token)


def plan_token_digest(token: str) -> str:
    """SHA-256 hex digest of ``token`` — the executor's idempotency key.

    The execute endpoint stores this on the :class:`~app.models.channel_mix_run.ChannelMixRun`
    row with a ``UNIQUE`` constraint, so a double-submitted execute call
    (e.g. the dashboard retrying after a transient network hiccup) hits
    the constraint and is mapped to the existing run instead of opening
    every channel twice. The digest is stored — not the raw token — so
    a leaked database snapshot doesn't expose tokens an attacker could
    replay.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


__all__ = ["plan_token_digest", "sign_plan", "verify_plan_token"]
