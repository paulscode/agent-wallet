# SPDX-License-Identifier: MIT
"""CI lint: MPP and ``outgoing_chan_id`` are mutually exclusive.

LND refuses to honour ``outgoing_chan_id`` when ``max_parts > 1`` (MPP
chunks may need to take different first-hop channels). The anonymize
stack uses both: the reverse-leg outbound payment chunks via MPP
 and the LN-self-pay hop pins a specific channel.
Any single ``send_payment_v2`` call site that mixes the two breaks
silently — LND drops the pinning and the payment routes off-trail.

This lint walks every Python file under ``app/services/anonymize/``
and refuses to admit a call where both kwargs appear in the same
local block of source.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ANON_DIR = REPO / "app" / "services" / "anonymize"


def _send_payment_blocks(text: str) -> list[str]:
    """Return every ``send_payment_v2(...)`` call body as a string.

    Crude but sufficient: matches from ``send_payment_v2(`` to the
    next ``)`` that closes the same depth. Multi-line call sites
    work via the non-greedy match.
    """
    blocks: list[str] = []
    # Walk char by char to find matched-paren spans.
    i = 0
    needle = "send_payment_v2("
    while True:
        idx = text.find(needle, i)
        if idx == -1:
            break
        start = idx + len(needle)
        depth = 1
        j = start
        while j < len(text) and depth > 0:
            ch = text[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            j += 1
        blocks.append(text[start : j - 1])
        i = j
    return blocks


def test_no_send_payment_v2_mixes_mpp_and_outgoing_chan_id() -> None:
    """Any anonymize-stack ``send_payment_v2`` call that names both
    ``max_parts`` and ``outgoing_chan_id`` is a violation."""
    offenders: list[str] = []
    for py in ANON_DIR.rglob("*.py"):
        text = py.read_text(encoding="utf-8", errors="replace")
        for block in _send_payment_blocks(text):
            mentions_mpp = bool(re.search(r"\bmax_parts\b", block))
            mentions_chan = bool(re.search(r"\boutgoing_chan_id\b", block))
            if mentions_mpp and mentions_chan:
                offenders.append(str(py.relative_to(REPO)))
    assert offenders == [], (
        f" violation — ``send_payment_v2`` cannot mix ``max_parts`` and ``outgoing_chan_id``: {offenders}"
    )
