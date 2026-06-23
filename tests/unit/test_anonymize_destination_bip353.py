# SPDX-License-Identifier: MIT
"""Tests for the BIP-353 destination-resolution surface.

Covers:

* :func:`is_bip353_handle` — shape predicate (true positive,
  raw-address negative, ``@`` count edge cases).
* :func:`resolve_anonymize_destination` — full async path with the
  DoH resolver patched:
  - Raw on-chain address → passes through unchanged.
  - BIP-353 handle with on-chain fallback → returns the fallback
    address + script_type + carries the resolved metadata.
  - BIP-353 handle with only ``lno=`` / ``lightning=`` → refused
    (the BOLT 12 exit pipeline is the next step; today these
    fall through to ``DestinationRejectedError``).
  - DoH / DNSSEC errors → uniform ``DestinationRejectedError`` message
    (— error paths must not leak which sub-failure occurred).
"""

from __future__ import annotations

import pytest

from app.services.anonymize import dns as bip353
from app.services.anonymize.address import (
    DestinationRejectedError,
    ResolvedDestination,
    is_bip353_handle,
    resolve_anonymize_destination,
)

_REGTEST_P2TR = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
_REGTEST_P2WKH = "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"


# ── is_bip353_handle predicate ─────────────────────────────────────


def test_predicate_accepts_well_formed_handles() -> None:
    assert is_bip353_handle("alice@example.com")
    assert is_bip353_handle("alice@x")
    assert is_bip353_handle("a@b.c")


def test_predicate_rejects_raw_addresses() -> None:
    assert not is_bip353_handle(_REGTEST_P2TR)
    assert not is_bip353_handle(_REGTEST_P2WKH)
    assert not is_bip353_handle("3LMVUcyL59pT...")


def test_predicate_rejects_zero_or_multiple_at() -> None:
    assert not is_bip353_handle("alice")
    assert not is_bip353_handle("alice@@example.com")
    assert not is_bip353_handle("alice@example@com")


def test_predicate_rejects_empty_user_or_domain() -> None:
    assert not is_bip353_handle("@example.com")
    assert not is_bip353_handle("alice@")
    assert not is_bip353_handle("@")
    assert not is_bip353_handle("")


def test_predicate_non_string_input() -> None:
    assert not is_bip353_handle(None)  # type: ignore[arg-type]
    assert not is_bip353_handle(b"alice@example.com")  # type: ignore[arg-type]


# ── resolve_anonymize_destination ─────────────────────────────────


@pytest.fixture(autouse=True)
async def _clear_resolver_cache():
    await bip353.reset_cache_for_tests()
    yield
    await bip353.reset_cache_for_tests()


@pytest.mark.asyncio
async def test_resolve_passes_through_raw_address() -> None:
    """The fast path: a raw P2TR address never touches the resolver."""
    out = await resolve_anonymize_destination(_REGTEST_P2TR)
    assert isinstance(out, ResolvedDestination)
    assert out.address == _REGTEST_P2TR
    assert out.script_type == "p2tr"
    assert out.bip353_handle is None
    assert out.bolt12_offer is None


@pytest.mark.asyncio
async def test_resolve_bip353_with_onchain_fallback(monkeypatch) -> None:
    """A BIP-353 handle whose record carries ``bitcoin:bc1...`` resolves
    to that address and is then validated through the existing
    address gate."""

    async def _fake_resolve(handle: str, **_kwargs):
        # Simulate a publisher that includes an on-chain fallback +
        # a BOLT 12 offer (the BOLT 12 part is recorded but unactioned).
        return bip353.Bip353Result(
            user_at_domain=handle,
            dns_name="alice.user._bitcoin-payment.example.com",
            bolt12_offer="lno1xyz",
            bolt11_invoice=None,
            onchain_address=_REGTEST_P2TR,
            raw_txt=f"bitcoin:{_REGTEST_P2TR}?lno=lno1xyz",
        )

    # The address module does ``from .dns import resolve_bip353`` inside
    # the function body, so patching the ``dns`` module's name is enough.
    monkeypatch.setattr(bip353, "resolve_bip353", _fake_resolve)

    out = await resolve_anonymize_destination("alice@example.com")
    assert out.address == _REGTEST_P2TR
    assert out.script_type == "p2tr"
    assert out.bip353_handle == "alice@example.com"
    assert out.bolt12_offer == "lno1xyz"  # surfaced for audit
    assert out.bolt11_invoice is None


@pytest.mark.asyncio
async def test_resolve_bip353_lightning_only_returns_bolt12_exit(monkeypatch) -> None:
    """A BIP-353 handle that publishes ONLY a BOLT 12 offer (no
    on-chain fallback) resolves to a ``bolt12_pay`` exit. The
    pipeline's terminal hop pays the offer directly via LND."""

    async def _fake_resolve(handle: str, **_kwargs):
        return bip353.Bip353Result(
            user_at_domain=handle,
            dns_name="alice.user._bitcoin-payment.example.com",
            bolt12_offer="lno1onlyme",
            bolt11_invoice=None,
            onchain_address=None,
            raw_txt="bitcoin:?lno=lno1onlyme",
        )

    monkeypatch.setattr(bip353, "resolve_bip353", _fake_resolve)

    out = await resolve_anonymize_destination("alice@example.com")
    assert out.exit_kind == "bolt12_pay"
    assert out.address == ""
    assert out.script_type is None
    assert out.bolt12_offer == "lno1onlyme"
    assert out.bip353_handle == "alice@example.com"


@pytest.mark.asyncio
async def test_resolve_bip353_bolt11_only_still_refused(monkeypatch) -> None:
    """A BIP-353 record with only ``lightning=`` (no on-chain, no
    BOLT 12) is refused — a BOLT 11 invoice's sub-hour expiry
    cannot survive a meaningful mixing dwell."""

    async def _fake_resolve(handle: str, **_kwargs):
        return bip353.Bip353Result(
            user_at_domain=handle,
            dns_name="alice.user._bitcoin-payment.example.com",
            bolt12_offer=None,
            bolt11_invoice="lnbc100u",
            onchain_address=None,
            raw_txt="bitcoin:?lightning=lnbc100u",
        )

    monkeypatch.setattr(bip353, "resolve_bip353", _fake_resolve)

    with pytest.raises(DestinationRejectedError, match="rejected"):
        await resolve_anonymize_destination("alice@example.com")


@pytest.mark.asyncio
async def test_resolve_bip353_failure_is_uniform_rejection(monkeypatch) -> None:
    """Resolver-internal errors (NXDOMAIN, DNSSEC fail, malformed
    TXT) MUST surface as the generic ``DestinationRejectedError`` shape
    so a probing payer can't distinguish the sub-failure."""

    async def _fake_resolve(handle: str, **_kwargs):
        raise bip353.Bip353DnssecError("AD=0")

    monkeypatch.setattr(bip353, "resolve_bip353", _fake_resolve)

    with pytest.raises(DestinationRejectedError, match="rejected"):
        await resolve_anonymize_destination("alice@example.com")


@pytest.mark.asyncio
async def test_resolve_bip353_onchain_handle_revalidated(monkeypatch) -> None:
    """The publisher-supplied on-chain handle is sent through the
    normal address validator — a malformed / wrong-network handle
    is refused even though DNSSEC validated the TXT record."""

    async def _fake_resolve(handle: str, **_kwargs):
        return bip353.Bip353Result(
            user_at_domain=handle,
            dns_name="alice.user._bitcoin-payment.example.com",
            bolt12_offer=None,
            bolt11_invoice=None,
            # Legacy P2PKH — rejected by ``parse_and_validate_destination``.
            onchain_address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            raw_txt="bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        )

    monkeypatch.setattr(bip353, "resolve_bip353", _fake_resolve)

    with pytest.raises(DestinationRejectedError, match="rejected"):
        await resolve_anonymize_destination("alice@example.com")


@pytest.mark.asyncio
async def test_resolve_empty_raises_uniform_rejection() -> None:
    """An empty string is refused before any DoH egress."""
    with pytest.raises(DestinationRejectedError, match="empty"):
        await resolve_anonymize_destination("")


@pytest.mark.asyncio
async def test_resolve_non_string_raises_uniform_rejection() -> None:
    with pytest.raises(DestinationRejectedError, match="must be a string"):
        await resolve_anonymize_destination(123)  # type: ignore[arg-type]
