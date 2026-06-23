# SPDX-License-Identifier: MIT
"""`_assert_tor_or_blocked()` helper.

Refuses hop egress when ``ANONYMIZE_REQUIRE_TOR=false``. This test
asserts the helper's behavior directly; the "every hop calls this"
lint enforces that hop modules invoke it.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.startup import (
    AnonymizeStartupError,
    assert_tor_or_blocked,
)


def test_assert_tor_or_blocked_passes_when_tor_required(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_require_tor", True)
    assert_tor_or_blocked(call_site="boltz_submarine")  # no raise


def test_assert_tor_or_blocked_raises_when_tor_disabled(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_require_tor", False)
    with pytest.raises(AnonymizeStartupError, match="ANONYMIZE_REQUIRE_TOR=false"):
        assert_tor_or_blocked(call_site="boltz_reverse")


def test_call_site_appears_in_error_message(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_require_tor", False)
    with pytest.raises(AnonymizeStartupError, match=r"call_site='liquid'"):
        assert_tor_or_blocked(call_site="liquid")
