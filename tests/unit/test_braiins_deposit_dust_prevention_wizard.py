# SPDX-License-Identifier: MIT
"""+ dust-prevention wizard / dashboard shape tests.

Static analysis of the dashboard template + JS to pin the
dust-prevention contracts:

* The wizard CTA disables when ``quote.arrival_feasible``
  is false. Operator can't blindly broadcast a session whose
  send tx would arrive below the bin amount.

* The arrival range displays in the Step-2 fee preview
  with a min/max bracket and a "depends on fees" explanation.

* The preset grid's selectable state binds to the
  per-bin viability getter (``braiinsDepositBinViableAtCurrentFees``),
  not just affordability. A regression that re-coupled the
  buttons to ``braiinsDepositCanAfford`` alone would silently
  let users pick infeasible bins.

* The dashboard list-row primary-action helpers handle
  the new ``awaiting_fee_reduction`` status with an explicit
  "Broadcast anyway" override label.

These tests live as static analysis (not Alpine-rendered DOM
checks) because the SPA isn't headless-testable in this repo.
The contracts they pin are visible enough to a code reader that
a future change touching them must update the tests deliberately.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_TEMPLATE = _REPO / "app" / "dashboard" / "templates" / "dashboard.html"
_JS = _REPO / "app" / "dashboard" / "static" / "dashboard.js"


# ── wizard CTA disables when infeasible ───────────────────────


def test_wizard_can_start_getter_gates_on_arrival_feasible() -> None:
    """The ``braiinsDepositCanStart`` getter must check
    ``quote.arrival_feasible !== false`` BEFORE the balance gate.
    Pinned because the balance check has historically been the
    last gate; sliding the new feasibility check in correctly
    requires it to come BEFORE the balance branches return true."""
    js = _JS.read_text(encoding="utf-8")
    # Grab the getter body.
    start = js.find("get braiinsDepositCanStart()")
    assert start != -1, "braiinsDepositCanStart getter missing"
    body_start = js.find("{", start)
    body_end = js.find("\n        },", body_start)
    body = js[body_start:body_end]
    assert "arrival_feasible" in body, (
        "braiinsDepositCanStart must consult quote.arrival_feasible "
        "so the CTA disables when the dust-prevention projection "
        "refuses the bin at current fees."
    )
    # The feasibility check must precede the balance gates (the
    # ext-source branches return true before the balance check, so an
    # AFTER-balance feasibility check would never fire for ext
    # sources). The simplest invariant: ``arrival_feasible`` is
    # referenced before the ``ext_lightning``/``ext_onchain`` early
    # return.
    feasibility_pos = body.find("arrival_feasible")
    ext_return_pos = body.find("ext_lightning")
    assert feasibility_pos != -1 and ext_return_pos != -1
    assert feasibility_pos < ext_return_pos, (
        "arrival_feasible check must come BEFORE the ext-source early-return so the gate applies to every source kind."
    )


def test_wizard_start_hint_explains_infeasibility() -> None:
    """The hint shown beneath a disabled CTA must explain WHY when
    feasibility is the reason. Operators need to know whether to
    pick a larger bin or wait — not just see a disabled button."""
    js = _JS.read_text(encoding="utf-8")
    start = js.find("get braiinsDepositStartHint()")
    assert start != -1, "braiinsDepositStartHint getter missing"
    body_start = js.find("{", start)
    body_end = js.find("\n        },", body_start)
    body = js[body_start:body_end]
    assert "arrival_feasible" in body, (
        "braiinsDepositStartHint must surface the feasibility reason text when the CTA is disabled due to fees."
    )
    # Hint copy mentions "Network fees" (verbatim) so the operator
    # knows the cause without context-switching to the wizard panel.
    assert "Network fees" in body or "network fees" in body


# ── wizard fee-preview range disclosure ──────────────────────


def test_wizard_fee_preview_shows_arrival_range() -> None:
    """The Step-2 fee-preview block renders the arrival as a range
    via ``braiinsDepositArrivalDisplay`` (not the bin amount). The
    range explanation appears beneath when min < max."""
    tpl = _TEMPLATE.read_text(encoding="utf-8")
    # Range display getter is referenced in the template.
    assert "braiinsDepositArrivalDisplay" in tpl, (
        "fee preview must render arrival via braiinsDepositArrivalDisplay so the min–max range shows."
    )
    # The "depends on Bitcoin network fees" copy gates on
    # ``braiinsDepositArrivalHasRange``.
    assert "braiinsDepositArrivalHasRange" in tpl, (
        "range explainer must gate on braiinsDepositArrivalHasRange "
        "so the copy doesn't appear when there's no real range."
    )


def test_wizard_renders_infeasibility_banner() -> None:
    """The infeasibility banner block is present and binds to
    ``braiinsDepositArrivalInfeasible``. Pinned via the getter name
    (not the underlying ``arrival_feasible === false`` expression)
    because the Alpine CSP build's evaluator doesn't short-circuit
    through dotted property access on null — the template binding
    must use a getter so the null-quote case doesn't throw."""
    tpl = _TEMPLATE.read_text(encoding="utf-8")
    assert "braiinsDepositArrivalInfeasible" in tpl, (
        "wizard missing the dust-prevention infeasibility banner "
        "that fires when ``braiinsDepositArrivalInfeasible`` is "
        "true. Template must use the getter, not a "
        "``quote && quote.arrival_feasible`` dotted chain — "
        "Alpine's CSP build rejects the latter."
    )
    js = _JS.read_text(encoding="utf-8")
    assert "get braiinsDepositArrivalInfeasible()" in js, "braiinsDepositArrivalInfeasible getter missing from JS."


# ── adaptive bin floor in the preset grid ─────────────────────


def test_preset_grid_binds_to_per_bin_viability() -> None:
    """The amount-preset grid must consult the per-bin viability
    getter, not just affordability. Pinned because a regression
    that returned to plain ``:disabled='!canAfford(amt)'`` would
    let users pick a bin whose send tx can't broadcast at current
    fees."""
    tpl = _TEMPLATE.read_text(encoding="utf-8")
    assert "braiinsDepositBinViableAtCurrentFees(amt)" in tpl, (
        "preset grid missing the dust-prevention viability gate "
        "; ``:disabled`` must include "
        "``!braiinsDepositBinViableAtCurrentFees(amt)``."
    )
    assert "braiinsDepositBinRecommended(amt)" in tpl, (
        "smallest currently-viable bin should be tagged "
        "``rec``; the ``braiinsDepositBinRecommended`` getter "
        "is missing from the preset markup."
    )


def test_bin_viability_helper_returns_true_when_cache_empty() -> None:
    """``braiinsDepositBinViableAtCurrentFees`` must default to
    "viable" when the per-bin quote cache hasn't loaded yet —
    otherwise the entire preset grid greys out on wizard open
    before the cache populates."""
    js = _JS.read_text(encoding="utf-8")
    start = js.find("braiinsDepositBinViableAtCurrentFees(amt)")
    assert start != -1
    body_start = js.find("{", start)
    body_end = js.find("\n        },", body_start)
    body = js[body_start:body_end]
    assert "return true" in body, (
        "viability check must return true when the per-bin cache "
        "hasn't populated; the wizard would otherwise grey out "
        "every preset before quotes land."
    )


# ── awaiting-fee-reduction list-row action ────────────────────


def test_primary_action_handles_awaiting_fee_reduction() -> None:
    """The list-row primary action handler must:
      * Accept ``awaiting_fee_reduction`` as an actionable status.
      * Surface the explicit "Broadcast anyway" label so the
        operator knows the override is one-way.
      * Hit the retry-send endpoint with ``accept_underpay=true``
        so the service-side override path runs.

    Pinned because the override is the operator's only way out
    of a parked session that's stuck for hours waiting for fees
    to drop."""
    js = _JS.read_text(encoding="utf-8")
    # awaiting_fee_reduction case in braiinsDepositHasPrimaryAction
    assert "case 'awaiting_fee_reduction':" in js, (
        "braiinsDepositHasPrimaryAction must include "
        "``awaiting_fee_reduction`` so the override action surfaces "
        "on parked rows."
    )
    # The label is "Broadcast anyway" (not "Resume" — different
    # semantic; this is a one-way override the user opts into).
    assert "'Broadcast anyway'" in js, (
        "parked-session primary action must use the ``Broadcast anyway`` label to make the one-way override explicit."
    )
    # The invocation hits the retry-send endpoint with the
    # ``accept_underpay=true`` query param.
    assert "accept_underpay=true" in js, (
        "primary-action handler must call /retry-send with "
        "accept_underpay=true so the service routes through the "
        "operator-override path."
    )


def test_awaiting_fee_reduction_status_has_badge_class() -> None:
    """The badge / caption helpers must cover the new status so
    operators see a coherent row in the deposit list (status chip
    + caption text + colour). Without explicit cases, the helpers
    fall through to ``default`` and the row blends in with
    in-progress states."""
    js = _JS.read_text(encoding="utf-8")
    # Badge class includes the new status.
    assert "case 'awaiting_fee_reduction':" in js
    # The chip class uses amber to differentiate from slate
    # in-progress states.
    badge_block_start = js.find("braiinsDepositStatusBadgeClass(")
    assert badge_block_start != -1
    badge_block_end = js.find(
        "braiinsDepositStatusLabel(",
        badge_block_start,
    )
    badge_block = js[badge_block_start:badge_block_end]
    assert "amber" in badge_block, (
        "awaiting_fee_reduction badge should use amber to stand out from in-progress (slate) states."
    )
