# SPDX-License-Identifier: MIT
"""Cross-feature regression tests for the dust-prevention work.

The shared ``dust_safe_send`` module is intended for the Braiins
Deposit flow and — as a deferred extension — the
Anonymize submarine-funding fallback. Two adjacent surfaces must
explicitly NOT adopt it because they already avoid the dust risk
by claiming directly to the user's destination:

  * Cold storage  — Boltz reverse swap claims to the operator-
                    supplied destination address. No second send,
                    no change UTXO, no dust risk.
  * Anonymize final hop — same pattern: Boltz reverse claim goes
                    directly to the user's payout address.

A regression here would mean a future change accidentally inserted
a wallet-side send-tx step into either flow, reintroducing the
dust risk in a path that was deliberately left alone. These tests
pin the "direct claim" pattern via static analysis of the relevant
source files so a future PR adding ``dust_safe_send`` to either
must update + justify these tests.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def test_cold_storage_uses_direct_boltz_claim_not_send_tx() -> None:
    """Cold storage relies on Boltz claiming the reverse
    swap directly to the destination address. There is NO
    subsequent ``send_coins`` / ``send_outputs`` / dust-safe-send
    call in this path because the Boltz claim IS the send.

    If a future change adds an explicit wallet-side send step to
    cold storage (e.g. to add fee bumps or change consolidation),
    this test must be updated to either:
      * incorporate the dust-safe-send pattern (preferred), or
      * justify the new send and explicitly accept the dust risk.
    """
    cold = (_REPO / "app" / "api" / "cold_storage.py").read_text(
        encoding="utf-8",
    )
    # No send_coins or send_outputs calls — Boltz settles directly.
    assert "send_coins" not in cold, (
        "cold storage must not call send_coins; if a real change requires it, adopt dust_safe_send to avoid dust risk."
    )
    assert "send_outputs" not in cold
    assert "dust_safe_send" not in cold, (
        "cold storage must NOT import dust_safe_send: the Boltz "
        "claim-to-destination pattern already avoids the dust "
        "risk dust_safe_send mitigates. Adding the import here "
        "without a paired send step is dead code; with one is a "
        "change in posture that should be deliberately reviewed."
    )


def test_anonymize_final_hop_uses_direct_boltz_claim_not_send_tx() -> None:
    """The anonymize final hop (boltz_egress) issues a Boltz
    reverse swap claiming directly to the user's destination
    address. Like cold storage, no wallet-side send tx exists.

    Pins that ``boltz_egress`` doesn't introduce a redundant send
    that would create a change UTXO at the wallet (which would
    also undermine the anonymity set, separate from the dust
    issue). If a future privacy improvement requires a multi-hop
    final delivery, it must adopt the dust-safe pattern AND
    re-evaluate the anonymity properties.
    """
    egress = (_REPO / "app" / "services" / "anonymize" / "boltz_egress.py").read_text(encoding="utf-8")
    # The destination address is passed THROUGH to Boltz; no
    # wallet-side send tx exists.
    assert "destination_address" in egress, (
        "boltz_egress must continue to pass destination_address to "
        "Boltz so the reverse claim lands directly at the user's "
        "payout address (no intermediate wallet UTXO)."
    )
    # No send_coins or dust_safe_send — the claim IS the send.
    assert "lnd_service.send_coins" not in egress
    assert "dust_safe_send" not in egress


def test_anonymize_funding_keeps_exact_bin_selector_as_primary_path() -> None:
    """future-work flag — the Anonymize submarine-funding
    fallback path (when no exact-bin UTXO exists) is the natural
    next adopter of ``dust_safe_send``. This test pins the EXISTING
    primary path (exact-bin selector → single-input/single-output
    fund tx) so a future dust-prevention extension doesn't quietly
    remove it.

    Adopting dust_safe_send for the fallback (no exact-bin UTXO)
    is fine; replacing the exact-bin selector with dust_safe_send
    would be a regression because the selector ALSO preserves
    bin-anonymity-set properties that dust_safe_send doesn't speak
    to. The two coexist.
    """
    cc = (_REPO / "app" / "services" / "anonymize" / "coin_control.py").read_text(encoding="utf-8")
    assert "select_exact_bin_funding" in cc, (
        "Anonymize exact-bin coin selector must remain — it's the "
        "primary path for the submarine funding tx. extension "
        "is the FALLBACK only."
    )
    # Hop dispatcher invokes the selector.
    hd = (_REPO / "app" / "services" / "anonymize" / "hop_dispatcher.py").read_text(encoding="utf-8")
    assert "select_exact_bin_funding" in hd


def test_dust_safe_send_module_exports_documented_surface() -> None:
    """Pin the public surface of ``dust_safe_send`` since it's
    intended to be imported by multiple features (Braiins now,
    Anonymize later). A regression that renames the
    helpers or drops an export silently breaks callers in
    features the test author may not have considered."""
    from app.services import dust_safe_send

    # Public surface that callers use.
    assert hasattr(dust_safe_send, "InfeasibleSendError")
    assert hasattr(dust_safe_send, "NoChangeSendResult")
    assert hasattr(dust_safe_send, "build_and_broadcast_no_change_send")
    assert hasattr(dust_safe_send, "economic_dust_threshold_sats")
    assert hasattr(dust_safe_send, "project_no_change_send")
    # __all__ exposes the same set.
    expected_all = {
        "InfeasibleSendError",
        "NoChangeSendResult",
        "build_and_broadcast_no_change_send",
        "economic_dust_threshold_sats",
        "project_no_change_send",
    }
    assert set(dust_safe_send.__all__) == expected_all
