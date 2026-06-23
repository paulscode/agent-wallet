# SPDX-License-Identifier: MIT
"""Copy-amount-to-clipboard affordances on the "send exactly N sats to
this address" deposit screens.

Both the Braiins ext-onchain deposit and the Anonymize ext-onchain
deposit show an exact sat amount the user must send from another
wallet. Each gets a copy button that copies the RAW integer sats (no
thousands separators) so it pastes cleanly into the other wallet's
amount field. Regex-against-source guards (the SPA isn't headless-
testable here) so a silent refactor that drops a button is caught.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_JS = _REPO / "app" / "dashboard" / "static" / "dashboard.js"
_HTML = _REPO / "app" / "dashboard" / "templates" / "dashboard.html"


def _js() -> str:
    return _JS.read_text(encoding="utf-8")


def _html() -> str:
    return _HTML.read_text(encoding="utf-8")


# ── Braiins ext-onchain amount copy ──────────────────────────────────


def test_braiins_copy_amount_helper_copies_raw_sats() -> None:
    js = _js()
    m = re.search(
        r"async\s+braiinsDepositCopyAmount\(\)\s*\{(?P<b>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "braiinsDepositCopyAmount() helper missing"
    body = m.group("b")
    # Raw integer (String(...)), not the comma-formatted value.
    assert "String(sats)" in body, (
        "amount copy must use the raw integer sats (String(sats)), not the formatSats() value with separators"
    )
    assert "formatSats" not in body, "amount copy must NOT copy the formatted (comma'd) string"
    # Confirmation is the global toast (copyText) — no inline label.
    assert "copyText" in body, (
        "amount copy must go through copyText() so the global 'Copied!' toast confirms the action"
    )


def test_braiins_amount_line_has_icon_and_tooltip_no_label() -> None:
    html = _html()
    assert "braiinsDepositCopyAmount()" in html, "the ext-onchain amount line must wire a copy affordance"
    # Icon + tooltip, and NO persistent 'Click to copy' label.
    assert 'title="Copy amount in sats"' in html, "amount copy must expose a 'Copy amount in sats' tooltip"
    assert "Click to copy (sats only)" not in html, (
        "the persistent amount copy label should be removed (icon + tooltip + toast is sufficient)"
    )


def test_braiins_address_has_copy_icon_and_tooltip_no_label() -> None:
    html = _html()
    assert "braiinsDepositCopyAddress()" in html
    assert 'title="Copy address"' in html, "address copy must expose a 'Copy address' tooltip"
    # The braiins address no longer relies on a persistent 'Click to
    # copy' label (toast confirms); a copy icon is the visual cue.
    assert "braiinsDepositExtCopied === 'address'" not in html, (
        "braiins address inline 'Click to copy'/'Copied!' label should "
        "be removed in favour of an icon + tooltip + toast"
    )


# ── Anonymize ext-onchain amount copy ────────────────────────────────


def test_anonymize_copy_deposit_handles_onchain_amount_raw() -> None:
    js = _js()
    m = re.search(
        r"async\s+anonymizeCopyDeposit\(kind\)\s*\{(?P<b>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "anonymizeCopyDeposit(kind) helper missing"
    body = m.group("b")
    assert "onchain_amount" in body and "String(d.amount_sat)" in body, (
        "anonymizeCopyDeposit must handle the 'onchain_amount' kind by "
        "copying the raw integer sats (String(d.amount_sat))"
    )


def test_anonymize_amount_has_copy_button_that_stops_propagation() -> None:
    html = _html()
    # The button must use .stop so it doesn't also fire the parent
    # div's address-copy handler.
    assert re.search(
        r"x-on:click\.stop=\"anonymizeCopyDeposit\('onchain_amount'\)\"",
        html,
    ), (
        "anonymize amount copy button must call "
        "anonymizeCopyDeposit('onchain_amount') with .stop (the parent "
        "div copies the address)"
    )
    assert "anonymizeDepositCopied === 'onchain_amount'" in html, (
        "anonymize amount copy must surface a 'Copied!' confirmation"
    )


def test_anonymize_address_has_icon_and_transient_feedback_no_label() -> None:
    """The anonymize ext-onchain address card now shows a copy icon +
    'Copy address' tooltip and a TRANSIENT 'Copied!' (anonymize has no
    global toast) — but no persistent 'Click to copy' prompt."""
    html = _html()
    # Transient confirmation only (x-show), not a persistent prompt.
    assert re.search(
        r"x-show=\"anonymizeDepositCopied === 'onchain'\">Copied!</p>",
        html,
    ), "anonymize address must show a transient 'Copied!' (x-show)"
    assert "anonymizeDepositCopied === 'onchain' ? 'Copied!' : 'Click to copy'" not in html, (
        "the persistent 'Click to copy' anonymize address label should "
        "be removed in favour of an icon + tooltip + transient 'Copied!'"
    )
