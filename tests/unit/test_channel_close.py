# SPDX-License-Identifier: MIT
"""Behaviour tests for the "Close Channels" dialog and closing-channel
rendering logic.

The getters/helpers live in ``app/dashboard/static/dashboard.js`` (the
``close*`` family plus the ``pending*`` rendering helpers). As with
``test_inbound_liquidity.py`` / ``test_channel_inbound.py``, we mirror
each pure piece in Python so the behaviour is exercised in CI and any
future JS change that drifts from this intent is caught.

If you change one of these helpers in dashboard.js, update the matching
mirror below and re-run this file. The mirrors are literal translations
of the JS — keep them that way.
"""

from __future__ import annotations

import pytest


# ── Mirrored helpers ─────────────────────────────────────────────────
def channel_alias(ch: dict) -> str:
    if not ch:
        return ""
    alias = (ch.get("peer_alias") or ch.get("remote_alias") or "").strip()
    if alias:
        return alias
    pk = ch.get("remote_pubkey") or ""
    return (pk[:16] + "…") if pk else ""


def close_candidates(channels, search: str, sort_by: str, show_inactive: bool, closing_ids=()):
    s = (search or "").strip().lower()
    out = []
    for c in channels:
        if c.get("chan_id") in closing_ids:  # already mid-close this session
            continue
        if not show_inactive and not c.get("active"):
            continue
        if s:
            alias = (c.get("peer_alias") or "").lower()
            pk = (c.get("remote_pubkey") or "").lower()
            if not (s in alias or pk.startswith(s)):
                continue
        out.append(c)
    if sort_by == "alias":
        out = sorted(out, key=lambda c: channel_alias(c))
    elif sort_by == "capacity":
        out = sorted(out, key=lambda c: -(c.get("capacity") or 0))
    else:  # 'local_desc'
        out = sorted(out, key=lambda c: -(c.get("local_balance") or 0))
    return out


def close_will_force(ch: dict) -> bool:
    return not (ch and ch.get("active"))


def close_retry_is_forceable(result: dict, channels) -> bool:
    if not result or result.get("ok"):
        return False
    ch = next((c for c in channels if c.get("chan_id") == result.get("chan_id")), None)
    return bool(ch and not ch.get("active"))


def close_selected_total(selected_ids, channels) -> int:
    return sum((c.get("local_balance") or 0) for c in channels if c.get("chan_id") in selected_ids)


def close_toggle(selected: list, chan_id: str) -> list:
    sel = list(selected)
    if chan_id in sel:
        sel.remove(chan_id)
    else:
        sel.append(chan_id)
    return sel


def pending_status_label(pc: dict) -> str:
    return {
        "pending_open": "Opening",
        "waiting_close": "Closing — broadcasting",
        "pending_close": "Closing",
        "force_closing": "Force-closing",
    }.get(pc.get("type"), "Pending")


def pending_dot_class(pc: dict) -> str:
    t = pc.get("type")
    if t == "force_closing":
        return "bg-amber-400 animate-pulse-neon"
    if t == "pending_close":
        return "bg-neon-cyan animate-pulse-neon"
    return "bg-neon-yellow animate-pulse-neon"


def pending_txid(pc: dict) -> str:
    cp = (pc.get("channel_point") or "")
    i = cp.find(":")
    return cp[:i] if i > 0 else cp


def pending_display_txid(pc: dict) -> str:
    # For a closing channel, surface only the closing tx — never fall back
    # to the funding (open) tx, which would mislead. For a pending-open
    # channel, the funding tx is the relevant one.
    if not pc:
        return ""
    if pc.get("type") == "pending_open":
        return pending_txid(pc)
    return pc.get("closing_txid") or ""


def pending_tx_label(pc: dict) -> str:
    return "Funding tx:" if pc.get("type") == "pending_open" else "Closing tx:"


def closing_maturity_label(blocks: int) -> str:
    blocks = blocks or 0
    if blocks <= 0:
        return "Funds maturing — releasing shortly"
    mins = blocks * 10
    if mins < 60:
        when = f"~{mins} min"
    elif mins < 1440:
        when = f"~{round(mins / 60)}h"
    else:
        days = round(mins / 1440)
        when = f"~{days} day" + ("" if days == 1 else "s")
    return f"Funds release in ~{blocks} block" + ("" if blocks == 1 else "s") + f" ({when})"


def limbo_line_visible(total_limbo: int) -> bool:
    return (total_limbo or 0) > 0


def is_channel_closing(close_chan_ids, chan_id) -> bool:
    return chan_id in close_chan_ids


# ── Fixtures ─────────────────────────────────────────────────────────
def _ch(chan_id, *, alias="", pubkey="", active=True, capacity=0, local=0, remote=0):
    return {
        "chan_id": chan_id,
        "channel_point": chan_id + ":0",
        "peer_alias": alias,
        "remote_pubkey": pubkey,
        "active": active,
        "capacity": capacity,
        "local_balance": local,
        "remote_balance": remote,
    }


CHANS = [
    _ch("c1", alias="ACINQ", active=True, capacity=2_000_000, local=1_200_000, remote=800_000),
    _ch("c2", alias="Bitrefill", active=False, capacity=500_000, local=150_000, remote=350_000),
    _ch("c3", alias="zebra", active=True, capacity=1_000_000, local=10_000, remote=990_000),
]


class TestCloseCandidates:
    def test_includes_inactive_when_toggled_on(self):
        out = close_candidates(CHANS, "", "local_desc", show_inactive=True)
        assert {c["chan_id"] for c in out} == {"c1", "c2", "c3"}

    def test_excludes_inactive_when_toggled_off(self):
        out = close_candidates(CHANS, "", "local_desc", show_inactive=False)
        assert {c["chan_id"] for c in out} == {"c1", "c3"}

    def test_search_by_alias(self):
        out = close_candidates(CHANS, "aci", "local_desc", show_inactive=True)
        assert [c["chan_id"] for c in out] == ["c1"]

    def test_sort_local_desc(self):
        out = close_candidates(CHANS, "", "local_desc", show_inactive=True)
        assert [c["chan_id"] for c in out] == ["c1", "c2", "c3"]

    def test_sort_capacity(self):
        out = close_candidates(CHANS, "", "capacity", show_inactive=True)
        assert [c["chan_id"] for c in out] == ["c1", "c3", "c2"]

    def test_sort_alias(self):
        out = close_candidates(CHANS, "", "alias", show_inactive=True)
        assert [c["chan_id"] for c in out] == ["c1", "c2", "c3"]  # ACINQ, Bitrefill, zebra


class TestForceDetection:
    def test_active_is_cooperative(self):
        assert close_will_force(_ch("c", active=True)) is False

    def test_inactive_requires_force(self):
        assert close_will_force(_ch("c", active=False)) is True


class TestForceRetryGating:
    """Decision Q1: force is never offered for an online-peer channel —
    only a failed close on an offline (inactive) channel may be retried
    as a force close."""

    def test_offline_failed_close_is_forceable(self):
        chans = [_ch("c2", active=False)]
        assert close_retry_is_forceable({"chan_id": "c2", "ok": False}, chans) is True

    def test_active_failed_close_is_not_forceable(self):
        # e.g. a coop close that failed on in-flight HTLCs — wait it out,
        # don't force-close a healthy channel.
        chans = [_ch("c1", active=True)]
        assert close_retry_is_forceable({"chan_id": "c1", "ok": False}, chans) is False

    def test_succeeded_close_is_not_forceable(self):
        chans = [_ch("c2", active=False)]
        assert close_retry_is_forceable({"chan_id": "c2", "ok": True}, chans) is False

    def test_missing_channel_is_not_forceable(self):
        assert close_retry_is_forceable({"chan_id": "gone", "ok": False}, []) is False


class TestPickerExcludesClosing:
    def test_just_closed_channel_hidden_from_picker(self):
        out = close_candidates(CHANS, "", "local_desc", show_inactive=True, closing_ids={"c1"})
        assert "c1" not in {c["chan_id"] for c in out}
        assert {c["chan_id"] for c in out} == {"c2", "c3"}


class TestSelection:
    def test_toggle_adds_then_removes(self):
        sel = close_toggle([], "c1")
        assert sel == ["c1"]
        sel = close_toggle(sel, "c1")
        assert sel == []

    def test_selected_total_sums_local(self):
        assert close_selected_total(["c1", "c2"], CHANS) == 1_350_000

    def test_selected_total_ignores_unselected(self):
        assert close_selected_total(["c3"], CHANS) == 10_000

    def test_is_channel_closing_membership(self):
        assert is_channel_closing(["c2"], "c2") is True
        assert is_channel_closing(["c2"], "c1") is False


class TestPendingPresentation:
    @pytest.mark.parametrize(
        "type_,label",
        [
            ("pending_open", "Opening"),
            ("waiting_close", "Closing — broadcasting"),
            ("pending_close", "Closing"),
            ("force_closing", "Force-closing"),
            ("weird", "Pending"),
        ],
    )
    def test_status_label(self, type_, label):
        assert pending_status_label({"type": type_}) == label

    def test_dot_class_by_type(self):
        assert "amber" in pending_dot_class({"type": "force_closing"})
        assert "neon-cyan" in pending_dot_class({"type": "pending_close"})
        assert "neon-yellow" in pending_dot_class({"type": "waiting_close"})
        assert "neon-yellow" in pending_dot_class({"type": "pending_open"})

    def test_display_txid_uses_closing_txid_for_closing(self):
        pc = {"type": "pending_close", "channel_point": "funding:0", "closing_txid": "closetx"}
        assert pending_display_txid(pc) == "closetx"
        wc = {"type": "waiting_close", "channel_point": "funding:0", "closing_txid": "wctx"}
        assert pending_display_txid(wc) == "wctx"

    def test_display_txid_closing_without_txid_is_empty(self):
        # A closing channel that hasn't published its closing tx yet must
        # NOT fall back to the funding (open) tx — show nothing.
        pc = {"type": "waiting_close", "channel_point": "fundingtxid:1"}
        assert pending_display_txid(pc) == ""

    def test_display_txid_uses_funding_for_pending_open(self):
        pc = {"type": "pending_open", "channel_point": "fundingtxid:1"}
        assert pending_display_txid(pc) == "fundingtxid"

    def test_tx_label_context(self):
        assert pending_tx_label({"type": "pending_open"}) == "Funding tx:"
        assert pending_tx_label({"type": "pending_close"}) == "Closing tx:"
        assert pending_tx_label({"type": "force_closing"}) == "Closing tx:"


class TestMaturityLabel:
    def test_zero_blocks_is_maturing(self):
        assert "maturing" in closing_maturity_label(0).lower()

    def test_minutes_scale(self):
        # 3 blocks → ~30 min
        assert closing_maturity_label(3) == "Funds release in ~3 blocks (~30 min)"

    def test_hours_scale(self):
        # 18 blocks → 180 min → ~3h
        assert closing_maturity_label(18) == "Funds release in ~18 blocks (~3h)"

    def test_one_day(self):
        # 144 blocks → 1440 min → ~1 day (singular)
        assert closing_maturity_label(144) == "Funds release in ~144 blocks (~1 day)"

    def test_multiple_days(self):
        # 288 blocks → ~2 days
        assert closing_maturity_label(288) == "Funds release in ~288 blocks (~2 days)"

    def test_singular_block(self):
        assert closing_maturity_label(1) == "Funds release in ~1 block (~10 min)"


class TestLimboLine:
    def test_visible_only_when_positive(self):
        assert limbo_line_visible(0) is False
        assert limbo_line_visible(None) is False
        assert limbo_line_visible(150_000) is True
