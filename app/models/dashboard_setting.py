# SPDX-License-Identifier: MIT
"""Small key/value store for server-persisted dashboard preferences.

Some dashboard state must survive page reloads and browser changes but
should reset when the app is reinstalled (its data volume is wiped) — the
browser's ``localStorage`` is the wrong home for it because it survives an
Agent Wallet / LND reinstall and differs per browser/device.

The first user is the onboarding "skip" flag: the value stored under
``onboarding_dismissed_pubkey`` is the LND node identity for which the
welcome wizard was dismissed, so onboarding reappears for a fresh node
(different pubkey) or a fresh install (empty table) while a deliberate
skip still sticks for the current node.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Setting key: the node pubkey the onboarding wizard was dismissed for.
ONBOARDING_DISMISSED_PUBKEY_KEY = "onboarding_dismissed_pubkey"

# Setting key: the id of the most recent failed channel-mix run the user
# dismissed from the dashboard "last build stopped" banner, so it doesn't
# reappear after they've acknowledged it.
LAST_FAILED_MIX_RUN_DISMISSED_KEY = "last_failed_mix_run_dismissed_id"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DashboardSetting(Base):
    """One server-persisted dashboard key/value pair."""

    __tablename__ = "dashboard_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        onupdate=_utc_now,
    )


__all__ = [
    "DashboardSetting",
    "ONBOARDING_DISMISSED_PUBKEY_KEY",
    "LAST_FAILED_MIX_RUN_DISMISSED_KEY",
]
