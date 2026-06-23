# SPDX-License-Identifier: MIT
"""User-facing disclosure copy for the anonymize wizard.

 (other text-only checklist items), the
wizard surfaces fixed, audited warning text rather than free-form
strings generated at request time. Centralizing the copy here:

* Lets the dashboard SPA fetch a stable JSON object via the
  ``/anonymize/policy`` endpoint instead of building strings in JS.
* Lets unit tests assert the exact wording (this module pins
  specific phrases like "permanently imported into the chain
  analyst's pairing problem" — a regression that softens the
  language is caught by a string-match test).
* Keeps the depositor-instruction text, source-UTXO warning, and
  destination warning in one place so a future change touches one
  file.

The ``onchain-self`` / ``ext-onchain`` warnings are present even
though those source kinds are rejected at quote time; the copy is in
place for the on-chain self-source path.
"""

from __future__ import annotations

from typing import Final

# Source-UTXO doxing warning shown when
# ``onchain-self`` is selected. The wording is from the wizard's
# step-1 mock-up.
SOURCE_UTXO_DOXING_WARNING: Final[str] = (
    "Any prior public attribution of this UTXO is permanently imported "
    "into the chain analyst's pairing problem and CANNOT be removed by "
    "this pipeline. Use a UTXO whose history is not publicly associated "
    "with your identity, or do not use an on-chain source."
)


# Same warning, framed for the depositor of an
# ``ext-onchain`` deposit. The text travels with the
# deposit-instruction payload the user delivers to the depositor
# out-of-band.
EXT_ONCHAIN_DEPOSITOR_WARNING: Final[str] = (
    "Any prior public attribution of the UTXO you spend to fund this "
    "deposit is permanently imported into the chain analyst's pairing "
    "problem. Use a UTXO whose history is not publicly associated with "
    "the depositor's identity. The recipient's anonymize pipeline "
    "cannot remove this linkage."
)


# Destination-address warning shown in wizard step 1.
DESTINATION_ADDRESS_WARNING: Final[str] = (
    "This is where the anonymized output will land. Do not paste an "
    "address you have already publicly associated with your identity. "
    "Raw address only: no bitcoin: URI, label, message, or address-book "
    "alias."
)


# On-chain inter-leg delay disclosure shown in wizard step 3.
ONCHAIN_INTER_LEG_DELAY_NOTICE: Final[str] = (
    "On-chain sources require a mandatory inter-leg delay of 6–48 hours "
    "between the submarine swap and the reverse swap. You may extend "
    "but not shorten this window."
)


# Chain-backend / explorer disclosure shown in wizard step 4.
EXTERNAL_EXPLORER_DISCLOSURE: Final[str] = (
    "External block-explorer links can reveal the output txid and your "
    "browser IP / referrer to that explorer. The anonymize view never "
    "opens third-party explorers by default; copy the txid out-of-band "
    "if you need it before the retention window expires."
)


# Audit-log disclosure shown in wizard step 4.
AUDIT_LOG_DISCLOSURE: Final[str] = (
    "Sensitive state transitions are not synchronously written to the "
    "tamper-evident audit chain. The chain receives delayed coarse "
    "summaries with k-anonymity suppression below the configured "
    "threshold; per-session timing is not exported."
)


# Destination retention disclosure shown in wizard step 4.
DESTINATION_RETENTION_DISCLOSURE: Final[str] = (
    "After the retention window, this dashboard no longer holds your "
    "destination address or the output txid. Copy the txid out-of-band "
    "if you need a permanent receipt."
)


def disclosures_for_source_kind(source_kind: str) -> list[str]:
    """Return the disclosure list shown in wizard step 4 for ``source_kind``.

    The wizard renders this verbatim; the dashboard SPA
    receives the list via ``/anonymize/policy`` so the UI does not
    embed copy.
    """
    out = [
        DESTINATION_ADDRESS_WARNING,
        DESTINATION_RETENTION_DISCLOSURE,
        AUDIT_LOG_DISCLOSURE,
        EXTERNAL_EXPLORER_DISCLOSURE,
    ]
    if source_kind == "onchain-self":
        out.insert(0, SOURCE_UTXO_DOXING_WARNING)
        out.append(ONCHAIN_INTER_LEG_DELAY_NOTICE)
    elif source_kind == "ext-onchain":
        out.insert(0, EXT_ONCHAIN_DEPOSITOR_WARNING)
        out.append(ONCHAIN_INTER_LEG_DELAY_NOTICE)
    return out


__all__ = [
    "SOURCE_UTXO_DOXING_WARNING",
    "EXT_ONCHAIN_DEPOSITOR_WARNING",
    "DESTINATION_ADDRESS_WARNING",
    "ONCHAIN_INTER_LEG_DELAY_NOTICE",
    "EXTERNAL_EXPLORER_DISCLOSURE",
    "AUDIT_LOG_DISCLOSURE",
    "DESTINATION_RETENTION_DISCLOSURE",
    "disclosures_for_source_kind",
]
