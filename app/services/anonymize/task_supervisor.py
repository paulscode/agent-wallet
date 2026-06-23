# SPDX-License-Identifier: MIT
"""Per-session task isolation wrapper.

Each per-session orchestrator task is wrapped in a top-level handler
that catches :class:`BaseException`, redacts the error, logs it, and
moves the session to ``awaiting_reconciliation``. A poisoned
``pipeline_json`` or a programming bug in one session must NOT
cascade into other in-flight sessions.

When a session moves to ``awaiting_reconciliation`` because
of an unhandled exception, the ``last_error`` setter routes through
the regex redactor (replaces address-like / onion / swap-hash
substrings with ``<redacted>``). The raw stack trace stays in the
anonymize-specific logger at WARNING for debugging; the column is
the redacted form.

This module ships:
* :func:`redact_for_last_error` — the regex redactor.
* :func:`run_session_task_isolated` — the async wrapper a single
  per-session orchestrator task runs under.
"""

from __future__ import annotations

import logging
import re
import traceback
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final, TypeVar
from uuid import UUID

from .metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)

T = TypeVar("T")


# Patterns the redactor strips from any string before it
# reaches ``last_error`` or any user-visible surface.
_REDACTOR_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # bech32 / bech32m bitcoin addresses (mainnet, testnet, regtest).
    re.compile(r"\b(?:bc1|tb1|bcrt1|lnbc|lntb|lnbcrt)[a-zA-HJ-NP-Z0-9]{20,90}\b"),
    # legacy Base58 P2PKH / P2SH-style addresses (mainnet 1.../3...,
    # test/regtest m/n.../2...). Tighter length bounds reduce false
    # positives on ordinary text.
    re.compile(r"\b[13mn2][a-km-zA-HJ-NP-Z1-9]{24,33}\b"),
    # v3 onion hosts.
    re.compile(r"\b[a-z2-7]{56}\.onion\b"),
    # 64-char hex (txids, payment hashes, swap hashes, preimages).
    re.compile(r"\b[0-9a-fA-F]{64}\b"),
    # 66-char hex (compressed secp256k1 pubkeys).
    re.compile(r"\b0[23][0-9a-fA-F]{64}\b"),
)


def redact_for_last_error(text: str) -> str:
    """Strip address-like, onion, and hex-id substrings from ``text``.

    Conservative / over-redacts. The raw trace remains in the
    anonymize logger at WARNING level — this redacted string is what
    we persist on the session row.
    """
    if not text:
        return text
    out = text
    for pat in _REDACTOR_PATTERNS:
        out = pat.sub("<redacted>", out)
    return out


def install_last_error_redaction_listener() -> None:
    """Wire the redactor into ``last_error`` writes.

    Registers a SQLAlchemy ``set`` attribute event on
    ``AnonymizeSession.last_error`` that runs every assigned value
    through :func:`redact_for_last_error` before the column is
    persisted. This makes the redactor impossible to bypass at the
    application layer — even a future call site that writes the
    column directly will see its input redacted.

    Idempotent: safe to call more than once (the underlying SQLAlchemy
    event registry de-dupes by listener identity).
    """
    from sqlalchemy import event

    from app.models.anonymize_session import AnonymizeSession

    @event.listens_for(AnonymizeSession.last_error, "set", retval=True, propagate=True)
    def _redact_on_set(
        target: object,
        value: object,
        oldvalue: object,
        initiator: object,
    ) -> str | None:  # noqa: ARG001
        if value is None:
            return None
        if not isinstance(value, str):
            value = str(value)
        return redact_for_last_error(value)


@dataclass(frozen=True)
class TaskFailure:
    """Result of an isolated session task that crashed.

    The orchestrator's per-session callback uses this to update the
    DB row: status → ``awaiting_reconciliation``, ``last_error``
    set to the redacted message, ``awaiting_reconciliation_reason``
    set to the exception class name.
    """

    session_id: UUID
    exception_class: str
    redacted_message: str


async def run_session_task_isolated(
    session_id: UUID,
    coro_factory: Callable[[], Awaitable[T]],
) -> T | TaskFailure:
    """Run ``coro_factory()`` under a top-level isolation handler.

    Returns the awaited value on success; on any
    :class:`BaseException` (except :class:`asyncio.CancelledError`
    which is re-raised so cooperative shutdown still works), returns
    a :class:`TaskFailure` carrying the redacted message.

    The per-session orchestrator is expected to:
    1. Build the coroutine via the factory.
    2. ``await run_session_task_isolated(...)``.
    3. Inspect the return value: if :class:`TaskFailure`, write the
       three fields to the session row and emit a
       ``state_change`` event with kind ``awaiting_reconciliation``.
    """
    import asyncio

    try:
        return await coro_factory()
    except asyncio.CancelledError:
        # Cooperative shutdown — propagate so the supervisor can
        # finish gracefully.
        raise
    except BaseException as exc:  # noqa: BLE001 — that's the point
        # Format the full traceback for the WARNING-level logger
        # (raw, behind the anonymize-specific logger), then redact a
        # short message for the column.
        raw = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        logger.warning(
            "anonymize session task %s raised %s; routing to awaiting_reconciliation",
            session_id,
            type(exc).__name__,
        )
        # Log the raw trace at DEBUG so an operator with verbose
        # logging can recover it; never emit at INFO+.
        logger.debug("traceback for %s:\n%s", session_id, raw)
        return TaskFailure(
            session_id=session_id,
            exception_class=type(exc).__name__,
            redacted_message=redact_for_last_error(str(exc)),
        )


__all__ = [
    "TaskFailure",
    "redact_for_last_error",
    "install_last_error_redaction_listener",
    "run_session_task_isolated",
]
