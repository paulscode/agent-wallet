# SPDX-License-Identifier: MIT
"""On-chain summary card headline = confirmed + pending total.

When a wallet's only UTXO is mid-spend, LND reports
``confirmed_balance == 0`` with the change as ``unconfirmed_balance``.
The card must headline the real total (confirmed + pending) rather than
"0 sats", with a small note clarifying the pending portion. Crucially,
the *spendable* figure (``confirmedBalance``, used by send / cold-
storage / Braiins gates) must stay confirmed-only — display only.

Regex-against-source guards (the SPA isn't headless-testable here).
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_JS = _REPO / "app" / "dashboard" / "static" / "dashboard.js"
_HTML = _REPO / "app" / "dashboard" / "templates" / "dashboard.html"


def test_onchain_total_getter_sums_confirmed_and_pending() -> None:
    js = _JS.read_text(encoding="utf-8")
    m = re.search(
        r"get onchainTotalBalance\(\)\s*\{(?P<b>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "onchainTotalBalance getter missing"
    body = m.group("b")
    assert "confirmedBalance" in body and "unconfirmedBalance" in body, (
        "total must sum confirmed + unconfirmed balances"
    )


def test_onchain_card_headlines_total_with_pending_note() -> None:
    html = _HTML.read_text(encoding="utf-8")
    # Scope to the On-chain summary card (between its marker and the
    # next card). The confirmed-only ``confirmedBalance`` headline is
    # still legitimately used by the send / cold-storage "sendable
    # balance" displays elsewhere, so we only assert within the card.
    start = html.index("<!-- On-chain -->")
    end = html.index("<!-- Lightning Outbound -->", start)
    card = html[start:end]
    assert "formatSats(onchainTotalBalance) + ' sats'" in card, (
        "On-chain card headline must show the confirmed+pending total"
    )
    assert "formatSats(confirmedBalance) + ' sats'" not in card, "On-chain card headline must not be confirmed-only"
    assert "pending confirmation" in card, "the card must clarify the pending portion"


def test_spendable_balance_stays_confirmed_only() -> None:
    js = _JS.read_text(encoding="utf-8")
    m = re.search(
        r"get confirmedBalance\(\)\s*\{(?P<b>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "confirmedBalance getter missing"
    assert "unconfirmed" not in m.group("b"), (
        "confirmedBalance must remain confirmed-only — send / cold-storage / Braiins spendability gates depend on it"
    )
