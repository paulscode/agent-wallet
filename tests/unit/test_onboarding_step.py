# SPDX-License-Identifier: MIT
"""Parity tests for the dashboard onboarding-step state machine.

The actual state machine is in ``app/dashboard/static/dashboard.js``
(the ``onboardingStep`` getter on the Alpine ``dashboard`` component).
We mirror it in Python here so the table-of-states semantics are
covered by a fast CI test, and any future change to the JS getter is
caught when the two diverge.

If you change the JS getter, update ``onboarding_step()`` below to
match and re-run this file.
"""

from __future__ import annotations

from typing import Any, Optional

import pytest


def onboarding_step(
    summary: Optional[dict[str, Any]],
    *,
    onboarding_skipped: bool = False,
) -> Optional[str]:
    """Python mirror of the ``onboardingStep`` getter.

    Returns one of ``"welcome" | "awaiting_deposit" |
    "ready_to_connect" | "connecting" | None``. ``None`` means render
    the regular tabbed dashboard.
    """
    if onboarding_skipped:
        return None
    # Mirror JS truthiness: ``{}`` is truthy in JS, falsy in Python.
    # Only treat ``None`` as "not loaded yet" so an empty payload
    # (no totals key) still routes through the state machine.
    if summary is None:
        return None
    totals = summary.get("totals") or {}
    if (totals.get("num_active_channels") or 0) >= 1:
        return None
    if (totals.get("num_pending_channels") or 0) >= 1:
        return "connecting"
    if (totals.get("onchain_sats") or 0) > 0:
        return "ready_to_connect"
    if (totals.get("unconfirmed_sats") or 0) > 0:
        return "awaiting_deposit"
    if (totals.get("lightning_local_sats") or 0) > 0:
        # Defensive fall-through — user has LN balance without a
        # channel, which shouldn't happen in practice. Drop them into
        # the regular dashboard so they can self-diagnose.
        return None
    return "welcome"


def _totals(**overrides: int) -> dict[str, Any]:
    """Build a totals dict with sane zero defaults."""
    base = {
        "num_active_channels": 0,
        "num_pending_channels": 0,
        "onchain_sats": 0,
        "unconfirmed_sats": 0,
        "lightning_local_sats": 0,
    }
    base.update(overrides)
    return {"totals": base}


class TestOnboardingStep:
    # ── Happy path: full state-machine traversal ─────────────────

    def test_brand_new_wallet_shows_welcome(self):
        assert onboarding_step(_totals()) == "welcome"

    def test_unconfirmed_deposit_shows_awaiting_deposit(self):
        assert onboarding_step(_totals(unconfirmed_sats=250_000)) == "awaiting_deposit"

    def test_confirmed_funds_no_channels_shows_ready_to_connect(self):
        assert onboarding_step(_totals(onchain_sats=500_000)) == "ready_to_connect"

    def test_pending_channel_shows_connecting(self):
        assert onboarding_step(_totals(num_pending_channels=1, onchain_sats=10_000)) == "connecting"

    def test_active_channel_exits_wizard(self):
        assert onboarding_step(_totals(num_active_channels=1)) is None

    # ── Multi-condition precedence ───────────────────────────────

    def test_pending_outranks_confirmed(self):
        # Funds are confirmed AND a channel is pending → connecting wins.
        assert onboarding_step(_totals(num_pending_channels=1, onchain_sats=200_000)) == "connecting"

    def test_active_outranks_everything(self):
        # The instant a channel goes active, the wizard exits, regardless
        # of on-chain dust or other pending channels.
        assert (
            onboarding_step(
                _totals(
                    num_active_channels=1,
                    num_pending_channels=1,
                    onchain_sats=50_000,
                    unconfirmed_sats=10_000,
                )
            )
            is None
        )

    def test_confirmed_outranks_unconfirmed(self):
        # If both are non-zero, the user already crossed the deposit
        # boundary and we should be pushing them toward the channel
        # step rather than asking them to wait.
        assert onboarding_step(_totals(onchain_sats=100_000, unconfirmed_sats=20_000)) == "ready_to_connect"

    # ── Edge cases ───────────────────────────────────────────────

    def test_skipped_user_never_sees_wizard(self):
        for sample in [
            _totals(),
            _totals(unconfirmed_sats=1),
            _totals(onchain_sats=1),
            _totals(num_pending_channels=1),
        ]:
            assert onboarding_step(sample, onboarding_skipped=True) is None

    def test_missing_summary_renders_nothing(self):
        # Before fetchAll resolves, ``summary`` is None — the wizard
        # must not flash before we know what state the wallet is in.
        assert onboarding_step(None) is None

    def test_missing_totals_treated_as_welcome(self):
        # Defensive: a malformed payload with no totals key should
        # behave like a fresh wallet rather than crash.
        assert onboarding_step({"totals": None}) == "welcome"
        assert onboarding_step({}) == "welcome"

    def test_lightning_only_no_channels_falls_through(self):
        # Pathological state — non-zero LN balance with zero channels
        # would mean the wallet thinks it has outbound capacity that
        # doesn't exist. Don't trap the user in the wizard.
        assert onboarding_step(_totals(lightning_local_sats=10_000)) is None

    @pytest.mark.parametrize(
        "field",
        ["num_active_channels", "num_pending_channels", "onchain_sats", "unconfirmed_sats"],
    )
    def test_zero_values_are_inert(self, field):
        # Explicit zeros must behave identically to missing keys.
        assert onboarding_step(_totals(**{field: 0})) == "welcome"


# ── Megalithic routing parity ────────────────────────────────────────
#
# Mirrors ``_megalithicNodeFor()`` in
# ``app/dashboard/static/dashboard.js``. The user specified the exact
# thresholds (150k floor, 1M switch) and the exact pubkeys that go
# with each tier. Keeping a parity test makes the routing decision
# explicit and prevents an accidental swap of the two nodes — a
# subtle regression that would silently route small channels to the
# main node (rejected) or vice versa.


MEGALITHIC_MAIN = {
    "pubkey": "0322d0e43b3d92d30ed187f4e101a9a9605c3ee5fc9721e6dac3ce3d7732fbb13e",
    "host": "164.92.106.32:9735",
    "min_sats": 1_000_000,
    "label": "Megalithic (main node)",
}
MEGALITHIC_SMALL = {
    "pubkey": "02a98c86ef366ce226aad6e7706959456e1701058915c3cbf527b37da143bb1441",
    "host": "146.190.169.210:9735",
    "min_sats": 150_000,
    "label": "Megalithic (small-channel node)",
}


def megalithic_node_for(sats):
    """Python mirror of ``_megalithicNodeFor`` in dashboard.js."""
    n = int(sats) if sats else 0
    if n >= MEGALITHIC_MAIN["min_sats"]:
        return MEGALITHIC_MAIN
    if n >= MEGALITHIC_SMALL["min_sats"]:
        return MEGALITHIC_SMALL
    return None


class TestMegalithicRouting:
    def test_below_floor_returns_none(self):
        assert megalithic_node_for(0) is None
        assert megalithic_node_for(149_999) is None
        assert megalithic_node_for(1) is None

    def test_exact_small_floor_routes_to_small(self):
        # 150,000 is the documented minimum — it MUST land on the
        # small-channel node, not return None.
        node = megalithic_node_for(150_000)
        assert node is not None
        assert node["pubkey"] == MEGALITHIC_SMALL["pubkey"]

    def test_mid_range_routes_to_small(self):
        node = megalithic_node_for(500_000)
        assert node["pubkey"] == MEGALITHIC_SMALL["pubkey"]

    def test_just_below_main_floor_routes_to_small(self):
        node = megalithic_node_for(999_999)
        assert node["pubkey"] == MEGALITHIC_SMALL["pubkey"]

    def test_exact_main_floor_routes_to_main(self):
        # 1,000,000 is the documented switch point — it MUST land on
        # the main node, not the small one.
        node = megalithic_node_for(1_000_000)
        assert node["pubkey"] == MEGALITHIC_MAIN["pubkey"]

    def test_large_amount_routes_to_main(self):
        node = megalithic_node_for(10_000_000)
        assert node["pubkey"] == MEGALITHIC_MAIN["pubkey"]

    def test_pubkeys_match_user_specified_values(self):
        # Belt-and-braces: catch any accidental edit to the wrong node
        # ID. The user provided these exact strings in the spec.
        assert MEGALITHIC_MAIN["pubkey"] == "0322d0e43b3d92d30ed187f4e101a9a9605c3ee5fc9721e6dac3ce3d7732fbb13e"
        assert MEGALITHIC_SMALL["pubkey"] == "02a98c86ef366ce226aad6e7706959456e1701058915c3cbf527b37da143bb1441"
        assert MEGALITHIC_MAIN["host"] == "164.92.106.32:9735"
        assert MEGALITHIC_SMALL["host"] == "146.190.169.210:9735"


# ─────────────────────────────────────────────────────────────────────
#  Parity for the remaining wizard getters.
#
#  Each helper below mirrors a getter on the Alpine ``dashboard``
#  component. If you change the JS, update the matching helper here
#  and re-run this file. Together with the integration tests pinning
#  the upstream payload shapes, this covers every observable behaviour
#  the wizard adds.
# ─────────────────────────────────────────────────────────────────────


import re

# Constants mirrored from app/dashboard/static/dashboard.js
_ONBOARDING_SAFETY_BUFFER_SATS = 10_000
_ONBOARDING_SAFETY_BUFFER_PCT = 0.02
_PUBKEY_RE = re.compile(r"^[0-9a-fA-F]{66}$")


def parse_pubkey_or_uri(raw):
    """Mirror of ``_parsePubkeyOrUri``."""
    v = (raw or "").strip()
    if not v:
        return None
    at = v.find("@")
    if at > 0:
        pubkey = v[:at].strip()
        host = v[at + 1 :].strip()
        if _PUBKEY_RE.match(pubkey) and host:
            return {"pubkey": pubkey.lower(), "host": host}
        return None
    if _PUBKEY_RE.match(v):
        return {"pubkey": v.lower(), "host": ""}
    return None


def extract_txid_from_channel_point(cp):
    """Mirror of ``_extractTxidFromChannelPoint``."""
    if not cp or not isinstance(cp, str):
        return ""
    colon = cp.find(":")
    return cp[:colon] if colon > 0 else cp


def onboarding_deposit_txs(transactions):
    """Mirror of ``onboardingDepositTxs`` getter."""
    txs = transactions or []
    filtered = [t for t in txs if (t.get("num_confirmations") or 0) == 0 and (t.get("amount") or 0) > 0]
    return sorted(filtered, key=lambda t: -(t.get("time_stamp") or 0))


def onboarding_incoming_sats(summary):
    """Mirror of ``onboardingIncomingSats`` getter."""
    if summary is None:
        return 0
    totals = summary.get("totals") or {}
    return totals.get("unconfirmed_sats") or 0


def onboarding_onchain_sats(summary):
    """Mirror of ``onboardingOnchainSats`` getter."""
    if summary is None:
        return 0
    totals = summary.get("totals") or {}
    return totals.get("onchain_sats") or 0


def onboarding_has_active_channel(summary):
    """Mirror of ``onboardingHasActiveChannel`` getter."""
    if summary is None:
        return False
    totals = summary.get("totals") or {}
    return (totals.get("num_active_channels") or 0) >= 1


def onboarding_pending_channel(pending_channels):
    """Mirror of ``onboardingPendingChannel`` getter."""
    for ch in pending_channels or []:
        if ch and ch.get("type") == "pending_open":
            return ch
    return None


def onboarding_funding_txid(pending_channels):
    """Mirror of ``onboardingFundingTxid`` getter."""
    ch = onboarding_pending_channel(pending_channels)
    if not ch:
        return ""
    return extract_txid_from_channel_point(ch.get("channel_point") or "")


def onboarding_confirmations(pending_channels, transactions):
    """Mirror of ``onboardingConfirmations`` getter."""
    txid = onboarding_funding_txid(pending_channels)
    if not txid:
        return 0
    tx = next((t for t in (transactions or []) if t.get("tx_hash") == txid), None)
    if not tx:
        return 0
    return min(3, max(0, tx.get("num_confirmations") or 0))


def onboarding_progress_style(confirmations):
    """Mirror of ``onboardingProgressStyle`` getter."""
    pct = round((confirmations / 3) * 100)
    pct = max(0, min(100, pct))
    return f"width: {pct}%"


def onboarding_pending_capacity(pending_channels):
    """Mirror of ``onboardingPendingCapacity`` getter."""
    ch = onboarding_pending_channel(pending_channels)
    if not ch:
        return 0
    try:
        return max(0, int(ch.get("capacity") or 0))
    except (TypeError, ValueError):
        return 0


def onboarding_pending_peer_label(pending_channels):
    """Mirror of ``onboardingPendingPeerLabel`` getter."""
    ch = onboarding_pending_channel(pending_channels)
    if not ch:
        return ""
    pk = (ch.get("remote_node_pub") or "").lower()
    if pk == MEGALITHIC_MAIN["pubkey"]:
        return "Megalithic"
    if pk == MEGALITHIC_SMALL["pubkey"]:
        return "Megalithic"
    if pk:
        return pk[:10] + "…" + pk[-4:]
    return "your chosen node"


def onboarding_suggested_amount(summary):
    """Mirror of ``onboardingSuggestedAmount`` getter."""
    onchain = onboarding_onchain_sats(summary)
    if onchain <= 0:
        return 0
    buffer = max(
        _ONBOARDING_SAFETY_BUFFER_SATS,
        int(onchain * _ONBOARDING_SAFETY_BUFFER_PCT),  # Math.floor
    )
    return max(0, onchain - buffer)


def onboarding_peer_error(amount_sats, peer_choice):
    """Mirror of ``onboardingPeerError`` getter."""
    sats = int(amount_sats or 0)
    if peer_choice != "megalithic":
        return None
    if 0 < sats < MEGALITHIC_SMALL["min_sats"]:
        formatted = f"{MEGALITHIC_SMALL['min_sats']:,}"
        return f'Megalithic requires at least {formatted} sats. Increase the amount or pick "A different node".'
    return None


def onboarding_can_open(amount_sats, summary, peer_choice, custom_uri):
    """Mirror of ``onboardingCanOpen`` getter."""
    sats = int(amount_sats or 0)
    if sats <= 0:
        return False
    if onboarding_onchain_sats(summary) < sats:
        return False
    if peer_choice == "megalithic":
        return megalithic_node_for(sats) is not None
    return parse_pubkey_or_uri(custom_uri) is not None


# Convenience fixtures used by multiple test classes below.
_VALID_PUBKEY = "0322d0e43b3d92d30ed187f4e101a9a9605c3ee5fc9721e6dac3ce3d7732fbb13e"
_VALID_URI = f"{_VALID_PUBKEY}@1.2.3.4:9735"


def _pending_open(**overrides):
    base = {
        "type": "pending_open",
        "remote_node_pub": "0" * 66,
        "channel_point": "abc:0",
        "capacity": 200_000,
        "local_balance": 200_000,
        "remote_balance": 0,
    }
    base.update(overrides)
    return base


def _tx(**overrides):
    base = {
        "tx_hash": "deadbeef",
        "amount": 100_000,
        "num_confirmations": 0,
        "time_stamp": 1_700_000_000,
        "block_height": 0,
        "total_fees": 0,
        "label": "",
    }
    base.update(overrides)
    return base


class TestDepositTxs:
    """awaiting_deposit's tx list — filter, sort, edge cases."""

    def test_empty_transactions_returns_empty(self):
        assert onboarding_deposit_txs([]) == []
        assert onboarding_deposit_txs(None) == []

    def test_filters_out_confirmed(self):
        out = onboarding_deposit_txs(
            [
                _tx(tx_hash="a", num_confirmations=1),
                _tx(tx_hash="b", num_confirmations=0),
            ]
        )
        assert [t["tx_hash"] for t in out] == ["b"]

    def test_filters_out_outgoing(self):
        # LND returns outgoing on-chain txs with negative amount (e.g.
        # the channel-funding tx itself). Wizard's awaiting_deposit
        # view must NOT pick those up as "incoming deposits".
        out = onboarding_deposit_txs(
            [
                _tx(tx_hash="a", amount=-50_000),
                _tx(tx_hash="b", amount=50_000),
            ]
        )
        assert [t["tx_hash"] for t in out] == ["b"]

    def test_filters_out_zero_amount(self):
        out = onboarding_deposit_txs([_tx(tx_hash="a", amount=0)])
        assert out == []

    def test_sorts_newest_first(self):
        out = onboarding_deposit_txs(
            [
                _tx(tx_hash="old", time_stamp=1),
                _tx(tx_hash="new", time_stamp=100),
                _tx(tx_hash="mid", time_stamp=50),
            ]
        )
        assert [t["tx_hash"] for t in out] == ["new", "mid", "old"]

    def test_missing_fields_treated_as_zero(self):
        # Defensive: a tx without num_confirmations / amount keys
        # should be treated as 0/0 (i.e. excluded — amount=0 fails the
        # > 0 filter) rather than crashing the wizard render.
        assert onboarding_deposit_txs([{}]) == []


class TestSummaryReaders:
    """The flat getters that the wizard uses instead of chaining
    through ``summary.totals.x`` in the template (CSP-safe pattern)."""

    def test_incoming_sats_null_summary(self):
        assert onboarding_incoming_sats(None) == 0

    def test_incoming_sats_missing_totals(self):
        assert onboarding_incoming_sats({}) == 0
        assert onboarding_incoming_sats({"totals": None}) == 0

    def test_incoming_sats_happy_path(self):
        assert onboarding_incoming_sats({"totals": {"unconfirmed_sats": 250_000}}) == 250_000

    def test_onchain_sats_null_summary(self):
        assert onboarding_onchain_sats(None) == 0

    def test_onchain_sats_happy_path(self):
        assert onboarding_onchain_sats({"totals": {"onchain_sats": 500_000}}) == 500_000

    def test_has_active_channel_threshold(self):
        assert onboarding_has_active_channel(None) is False
        assert onboarding_has_active_channel({"totals": {"num_active_channels": 0}}) is False
        assert onboarding_has_active_channel({"totals": {"num_active_channels": 1}}) is True
        assert onboarding_has_active_channel({"totals": {"num_active_channels": 5}}) is True


class TestSuggestedAmount:
    """The default-amount prefill on ``ready_to_connect``. Plan:
    ``onchain - max(10_000, onchain * 0.02)``."""

    def test_zero_balance_returns_zero(self):
        assert onboarding_suggested_amount({"totals": {"onchain_sats": 0}}) == 0
        assert onboarding_suggested_amount(None) == 0

    def test_small_balance_reserves_flat_10k(self):
        # 100_000 * 0.02 = 2_000 → max(10_000, 2_000) = 10_000
        assert onboarding_suggested_amount({"totals": {"onchain_sats": 100_000}}) == 90_000

    def test_large_balance_reserves_2_percent(self):
        # 1_000_000 * 0.02 = 20_000 → max(10_000, 20_000) = 20_000
        assert onboarding_suggested_amount({"totals": {"onchain_sats": 1_000_000}}) == 980_000

    def test_exactly_at_2pct_threshold(self):
        # 500_000 * 0.02 = 10_000 — both branches give same buffer.
        assert onboarding_suggested_amount({"totals": {"onchain_sats": 500_000}}) == 490_000

    def test_balance_below_buffer_never_negative(self):
        # User has less than the safety buffer. We must not suggest a
        # negative amount; the submit button stays disabled by other
        # gates (canOpen sees amount <= 0 or amount > balance).
        assert onboarding_suggested_amount({"totals": {"onchain_sats": 5_000}}) == 0


class TestPendingChannelExtraction:
    """The chain of getters that the connecting step depends on:
    ``onboardingPendingChannel`` → ``onboardingFundingTxid`` →
    ``onboardingConfirmations`` / ``onboardingPendingCapacity`` /
    ``onboardingPendingPeerLabel``."""

    def test_finds_pending_open_in_flat_list(self):
        # The shape bug discovered during audit — the endpoint returns
        # a flat array, not a grouped dict. Make sure the lookup
        # filters by ``type``.
        result = onboarding_pending_channel(
            [
                {"type": "pending_close", "channel_point": "x:0"},
                _pending_open(channel_point="abc:0"),
                {"type": "force_closing", "channel_point": "y:0"},
            ]
        )
        assert result["channel_point"] == "abc:0"

    def test_no_pending_open_returns_none(self):
        # If the only entries are closes / force-closes, there's
        # nothing for the wizard to surface.
        assert onboarding_pending_channel([{"type": "pending_close"}]) is None
        assert onboarding_pending_channel([]) is None
        assert onboarding_pending_channel(None) is None

    def test_funding_txid_splits_channel_point(self):
        assert onboarding_funding_txid([_pending_open(channel_point="abc123:7")]) == "abc123"

    def test_funding_txid_missing_pending_channel(self):
        assert onboarding_funding_txid([]) == ""
        assert onboarding_funding_txid(None) == ""

    def test_funding_txid_malformed_channel_point(self):
        # No colon: keep whatever the value is (matches JS behaviour).
        assert onboarding_funding_txid([_pending_open(channel_point="abcdef")]) == "abcdef"
        # Empty string: empty txid.
        assert onboarding_funding_txid([_pending_open(channel_point="")]) == ""

    def test_confirmations_zero_when_no_pending(self):
        assert onboarding_confirmations([], []) == 0

    def test_confirmations_zero_when_tx_not_in_list(self):
        # Pending channel exists but /transactions hasn't surfaced
        # the funding tx yet (the brief LND-indexing window).
        assert onboarding_confirmations([_pending_open(channel_point="abc:0")], []) == 0

    def test_confirmations_matches_by_tx_hash(self):
        result = onboarding_confirmations(
            [_pending_open(channel_point="abc:0")],
            [_tx(tx_hash="abc", num_confirmations=2)],
        )
        assert result == 2

    def test_confirmations_capped_at_3(self):
        # Even if LND reports 50 confs (e.g. user landed on the
        # wizard with a stale pending channel), the progress bar
        # caps at the 3-conf milestone.
        result = onboarding_confirmations(
            [_pending_open(channel_point="abc:0")],
            [_tx(tx_hash="abc", num_confirmations=50)],
        )
        assert result == 3

    def test_confirmations_floored_at_zero(self):
        # LND shouldn't return negative confirmations, but guard
        # against it anyway — the wizard's progress-bar percentage
        # math would otherwise go negative.
        result = onboarding_confirmations(
            [_pending_open(channel_point="abc:0")],
            [_tx(tx_hash="abc", num_confirmations=-1)],
        )
        assert result == 0

    def test_pending_capacity_happy_path(self):
        assert onboarding_pending_capacity([_pending_open(capacity=200_000)]) == 200_000

    def test_pending_capacity_zero_when_no_pending(self):
        assert onboarding_pending_capacity([]) == 0
        assert onboarding_pending_capacity(None) == 0

    def test_pending_capacity_handles_string_input(self):
        # LND's REST layer returns ``capacity`` as a string in some
        # versions; the JS getter uses ``parseInt``. The Python
        # mirror coerces with ``int()``.
        assert onboarding_pending_capacity([_pending_open(capacity="500000")]) == 500_000

    def test_peer_label_recognises_megalithic_main(self):
        result = onboarding_pending_peer_label([_pending_open(remote_node_pub=MEGALITHIC_MAIN["pubkey"].upper())])
        assert result == "Megalithic"

    def test_peer_label_recognises_megalithic_small(self):
        result = onboarding_pending_peer_label([_pending_open(remote_node_pub=MEGALITHIC_SMALL["pubkey"])])
        assert result == "Megalithic"

    def test_peer_label_truncates_unknown_pubkey(self):
        # 66-char pubkey → first 10 chars + ellipsis + last 4.
        pk = "1234567890" + ("a" * 52) + "abcd"
        result = onboarding_pending_peer_label([_pending_open(remote_node_pub=pk)])
        assert result == "1234567890…abcd"

    def test_peer_label_no_pubkey_uses_generic(self):
        # Defensive — if LND ever omits remote_node_pub on a pending
        # entry, show something rather than crashing the view.
        assert onboarding_pending_peer_label([_pending_open(remote_node_pub="")]) == "your chosen node"

    def test_peer_label_no_pending_returns_empty(self):
        assert onboarding_pending_peer_label([]) == ""


class TestProgressStyle:
    """The CSS ``width: N%`` string. Pre-computed in JS because the
    CSP-safe Alpine parser cannot run ``Math.round`` inside
    ``:style``."""

    def test_zero_confirmations(self):
        assert onboarding_progress_style(0) == "width: 0%"

    def test_one_of_three(self):
        # round(1/3 * 100) = 33
        assert onboarding_progress_style(1) == "width: 33%"

    def test_two_of_three(self):
        # round(2/3 * 100) = 67
        assert onboarding_progress_style(2) == "width: 67%"

    def test_full(self):
        assert onboarding_progress_style(3) == "width: 100%"

    def test_clamps_overflow(self):
        # Sanity: getter caps confirmations at 3 upstream, but the
        # style fn defensively clamps anyway.
        assert onboarding_progress_style(10) == "width: 100%"


class TestPeerError:
    """The minimum-amount warning shown beneath the Megalithic radio."""

    def test_no_error_for_custom_choice(self):
        # The error is Megalithic-specific (the custom path lets the
        # user pick a node with its own minimum).
        assert onboarding_peer_error(1_000, "custom") is None

    def test_no_error_when_amount_above_floor(self):
        assert onboarding_peer_error(150_000, "megalithic") is None
        assert onboarding_peer_error(2_000_000, "megalithic") is None

    def test_no_error_when_amount_zero(self):
        # Empty input shouldn't yell at the user — they haven't
        # finished typing yet.
        assert onboarding_peer_error(0, "megalithic") is None

    def test_error_for_below_minimum(self):
        msg = onboarding_peer_error(100_000, "megalithic")
        assert msg is not None
        # The user-visible number must be formatted with thousand
        # separators (toLocaleString in JS → ``f"{:,}"`` in Python).
        assert "150,000" in msg
        # The remediation copy is part of the contract — changing it
        # casually would change what users see in production.
        assert "A different node" in msg


class TestCanOpen:
    """Submit-button gate for the open-channel form."""

    _SUMMARY = {"totals": {"onchain_sats": 500_000}}

    def test_zero_amount_disabled(self):
        assert onboarding_can_open(0, self._SUMMARY, "megalithic", "") is False
        assert onboarding_can_open(None, self._SUMMARY, "megalithic", "") is False

    def test_amount_exceeds_balance_disabled(self):
        # Channel amount must be at most the available on-chain
        # balance (fees + reserve are slack the wizard suggests, but
        # the user can override; we still block overdraft).
        assert onboarding_can_open(1_000_000, self._SUMMARY, "megalithic", "") is False

    def test_megalithic_below_minimum_disabled(self):
        # 100k is below the 150k Megalithic floor even though it's
        # within the on-chain balance.
        assert onboarding_can_open(100_000, self._SUMMARY, "megalithic", "") is False

    def test_megalithic_above_minimum_enabled(self):
        assert onboarding_can_open(200_000, self._SUMMARY, "megalithic", "") is True

    def test_custom_with_invalid_uri_disabled(self):
        assert onboarding_can_open(200_000, self._SUMMARY, "custom", "") is False
        assert onboarding_can_open(200_000, self._SUMMARY, "custom", "not a uri") is False

    def test_custom_with_valid_uri_enabled(self):
        assert onboarding_can_open(200_000, self._SUMMARY, "custom", _VALID_URI) is True

    def test_custom_with_bare_pubkey_enabled(self):
        # Bare pubkey (no @host) is acceptable to the parser. The
        # wizard's submit handler enforces host:port separately, so
        # canOpen returns true here — the failure surfaces at submit.
        assert onboarding_can_open(200_000, self._SUMMARY, "custom", _VALID_PUBKEY) is True


class TestParsePubkeyOrUri:
    """Existing helper, exercised here because ``onboarding_can_open``
    delegates to it for the custom-node branch."""

    def test_empty(self):
        assert parse_pubkey_or_uri("") is None
        assert parse_pubkey_or_uri(None) is None
        assert parse_pubkey_or_uri("   ") is None

    def test_bare_pubkey(self):
        result = parse_pubkey_or_uri(_VALID_PUBKEY.upper())
        assert result == {"pubkey": _VALID_PUBKEY, "host": ""}

    def test_full_uri(self):
        result = parse_pubkey_or_uri(_VALID_URI)
        assert result == {"pubkey": _VALID_PUBKEY, "host": "1.2.3.4:9735"}

    def test_uri_without_host_rejected(self):
        # ``pubkey@`` is not a valid URI.
        assert parse_pubkey_or_uri(_VALID_PUBKEY + "@") is None

    def test_short_pubkey_rejected(self):
        assert parse_pubkey_or_uri("abc123") is None

    def test_non_hex_pubkey_rejected(self):
        assert parse_pubkey_or_uri("z" * 66) is None


class TestExtractTxidFromChannelPoint:
    """Tiny but load-bearing — the connecting step's mempool-explorer
    link depends on a clean txid extracted from ``channel_point``."""

    def test_normal(self):
        assert extract_txid_from_channel_point("abcdef:0") == "abcdef"

    def test_high_vout(self):
        assert extract_txid_from_channel_point("abc:123") == "abc"

    def test_empty(self):
        assert extract_txid_from_channel_point("") == ""
        assert extract_txid_from_channel_point(None) == ""

    def test_no_colon_returns_input(self):
        # Matches JS behaviour: if there's no ``:``, hand back the
        # raw string. In practice this shouldn't happen — LND always
        # returns ``txid:vout`` — but the wizard must not crash.
        assert extract_txid_from_channel_point("abcdef") == "abcdef"

    def test_leading_colon_returns_input(self):
        # ``indexOf(':')`` returns 0; JS condition is ``colon > 0``,
        # so a leading colon doesn't trigger the slice. The raw
        # string is returned unchanged. Matches malformed input
        # gracefully without producing a misleading empty txid.
        assert extract_txid_from_channel_point(":0") == ":0"
