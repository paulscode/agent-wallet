# SPDX-License-Identifier: MIT
"""/ items 6 + 32 — destination address policy.

* URI / label / wrapper inputs are rejected before any logging.
* P2TR + native P2WPKH classify correctly and are eligible for strong tier.
* P2WSH and P2SH-P2WPKH classify correctly and are NOT eligible for
  strong tier (cap to ``moderate``).
* Legacy P2PKH and arbitrary P2SH (mainnet) are rejected.
* Wrong-network addresses are rejected by the underlying validator.
"""

from __future__ import annotations

import pytest

from app.services.anonymize.address import (
    ACCEPTED_WITH_MODERATE_CAP,
    ELIGIBLE_FOR_STRONG,
    DestinationRejectedError,
    parse_and_validate_destination,
    script_type_eligible_for_strong,
)

# Conftest sets BITCOIN_NETWORK=regtest. Use regtest addresses where
# we need real, checksum-valid samples; for invalid samples we don't
# care about checksums.


# Test-only fixtures with valid checksums under the regtest network.
# Generated programmatically; do NOT use as receive addresses.
_REGTEST_P2WPKH = "bcrt1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpvxat9t"
_REGTEST_P2WSH = "bcrt1qqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqezzy8c"
_REGTEST_P2TR = "bcrt1pqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsk8mhfx"
# Regtest P2SH (2... base58check) with valid checksum.
_REGTEST_P2SH = "2MshmP1dBRx9TELRpoFu6oLqwLK6JASifGy"


def test_eligibility_table() -> None:
    assert ELIGIBLE_FOR_STRONG == {"p2tr", "p2wpkh"}
    assert ACCEPTED_WITH_MODERATE_CAP == {"p2wsh", "p2sh-p2wpkh"}
    assert script_type_eligible_for_strong("p2tr")
    assert script_type_eligible_for_strong("p2wpkh")
    assert not script_type_eligible_for_strong("p2wsh")
    assert not script_type_eligible_for_strong("p2sh-p2wpkh")


def test_p2wpkh_regtest_validates() -> None:
    addr, kind = parse_and_validate_destination(_REGTEST_P2WPKH)
    assert addr == _REGTEST_P2WPKH
    assert kind == "p2wpkh"


def test_p2tr_regtest_validates() -> None:
    addr, kind = parse_and_validate_destination(_REGTEST_P2TR)
    assert addr == _REGTEST_P2TR
    assert kind == "p2tr"


def test_p2wsh_regtest_validates_with_moderate_cap() -> None:
    addr, kind = parse_and_validate_destination(_REGTEST_P2WSH)
    assert addr == _REGTEST_P2WSH
    assert kind == "p2wsh"
    assert not script_type_eligible_for_strong(kind)


def test_p2sh_regtest_classified_as_wrapped_segwit() -> None:
    """Regtest P2SH addresses are accepted as p2sh-p2wpkh (moderate cap).

    Note: Bitcoin chain analysis cannot distinguish wrapped-SegWit
    (P2SH-P2WPKH) from arbitrary P2SH at the address layer — only the
    spending witness reveals it. The classifier accepts this ambiguity and
    treats every Base58 P2SH as ``p2sh-p2wpkh``-class (still capped at
    `moderate`); arbitrary multisig P2SH would also fall here, which
    is fine because the cap protects either way.
    """
    addr, kind = parse_and_validate_destination(_REGTEST_P2SH)
    assert addr == _REGTEST_P2SH
    assert kind == "p2sh-p2wpkh"


@pytest.mark.parametrize(
    "wrapped",
    [
        # bitcoin: URIs
        f"bitcoin:{_REGTEST_P2WPKH}",
        f"BITCOIN:{_REGTEST_P2WPKH}",
        f"bitcoin:{_REGTEST_P2WPKH}?amount=0.001",
        f"bitcoin:{_REGTEST_P2WPKH}?label=Alice",
        f"bitcoin:{_REGTEST_P2WPKH}?message=tip",
        # BIP-21 query string without scheme.
        f"{_REGTEST_P2WPKH}?label=foo",
        # LNURL / lightning prefixes.
        "lnurl1dp68gurn8ghj7mrws4qhqctnv7sqctnv5cz7vej",
        f"lightning:{_REGTEST_P2WPKH}",
        # BIP-70 payment URLs.
        f"https://example.com/pay/{_REGTEST_P2WPKH}",
        # Whitespace-wrapped pastes.
        f" {_REGTEST_P2WPKH} ",
        f"\n{_REGTEST_P2WPKH}\n",
    ],
)
def test_wrapped_inputs_are_rejected(wrapped: str) -> None:
    """Any URI / label / wrapper indicator rejects the input."""
    # Whitespace-only wrappers should be stripped before checking, so
    # those particular cases need a different assertion: stripping
    # leaves the bare address, which validates. The test above includes
    # cases that survive .strip() — those must reject.
    raw = wrapped
    is_pure_whitespace_wrap = raw.strip() == _REGTEST_P2WPKH
    if is_pure_whitespace_wrap:
        # .strip() handles these; result is the bare address.
        addr, kind = parse_and_validate_destination(raw)
        assert addr == _REGTEST_P2WPKH
        return
    with pytest.raises(DestinationRejectedError):
        parse_and_validate_destination(raw)


def test_empty_input_rejected() -> None:
    with pytest.raises(DestinationRejectedError, match="empty"):
        parse_and_validate_destination("")
    with pytest.raises(DestinationRejectedError, match="empty"):
        parse_and_validate_destination("   ")


def test_too_long_input_rejected() -> None:
    with pytest.raises(DestinationRejectedError, match="too long"):
        parse_and_validate_destination("a" * 200)


def test_non_string_input_rejected() -> None:
    with pytest.raises(DestinationRejectedError, match="must be a string"):
        parse_and_validate_destination(b"bcrt1q...")  # type: ignore[arg-type]


def test_legacy_p2pkh_rejected_via_wrong_network() -> None:
    """Mainnet P2PKH `1...` is rejected on the regtest test runner.

    Conftest sets ``BITCOIN_NETWORK=regtest``, so a mainnet legacy
    address is wrong-network and rejects through the underlying
    validator — which we treat as the script-policy rejection too.
    A separate unit test with patched settings confirms the explicit
    legacy-rejection branch.
    """
    with pytest.raises(DestinationRejectedError):
        parse_and_validate_destination("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")


def test_legacy_p2pkh_rejected_explicitly_on_mainnet(monkeypatch) -> None:
    """Even when network='bitcoin' makes the address valid, P2PKH is rejected."""
    from app.core.config import settings as live_settings

    monkeypatch.setattr(live_settings, "bitcoin_network", "bitcoin")
    # Genesis Satoshi address — valid checksum, mainnet P2PKH.
    with pytest.raises(DestinationRejectedError, match="script type"):
        parse_and_validate_destination("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")


def test_invalid_address_alphabet_rejected() -> None:
    """Strings outside the bech32/base58 alphabet are rejected."""
    with pytest.raises(DestinationRejectedError):
        parse_and_validate_destination("bcrt1!@#$")
