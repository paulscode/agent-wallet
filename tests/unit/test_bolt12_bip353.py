# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.bip353``."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from app.services.bolt12.bip353 import (
    Bolt12Bip353InsecureError,
    PaymentHandle,
    build_zone_record,
    parse_payment_uri,
    resolve_payment_handle,
)


def test_parse_handle_valid() -> None:
    h = PaymentHandle.parse("alice@example.com")
    assert h.user == "alice"
    assert h.domain == "example.com"
    assert h.fqdn == "alice.user._bitcoin-payment.example.com."


def test_parse_handle_strips_b_prefix() -> None:
    h = PaymentHandle.parse("₿bob@example.org")
    assert h.user == "bob"
    assert h.domain == "example.org"


def test_parse_handle_uppercase_normalised() -> None:
    h = PaymentHandle.parse("Alice@Example.COM")
    assert h.user == "alice"
    assert h.domain == "example.com"


@pytest.mark.parametrize(
    "bad",
    [
        "no-at-sign",
        "@example.com",
        "user@",
        "us er@example.com",
        "user@-bad.example.com",
        "user@example..com",
        "us!er@example.com",
    ],
)
def test_parse_handle_invalid(bad: str) -> None:
    with pytest.raises(ValueError):
        PaymentHandle.parse(bad)


def test_build_zone_record_offer_only() -> None:
    h = PaymentHandle.parse("alice@example.com")
    rec = build_zone_record(h, offer="lno1abc")
    assert rec == ('alice.user._bitcoin-payment.example.com. 3600 IN TXT "bitcoin:?lno=lno1abc"')


def test_build_zone_record_combined() -> None:
    h = PaymentHandle.parse("alice@example.com")
    rec = build_zone_record(h, offer="lno1abc", bolt11="lnbc1xyz", on_chain="bc1qxyz")
    assert "bc1qxyz?lno=lno1abc&lightning=lnbc1xyz" in rec


def test_build_zone_record_requires_payload() -> None:
    h = PaymentHandle.parse("alice@example.com")
    with pytest.raises(ValueError):
        build_zone_record(h)


def test_build_zone_record_rejects_double_quote() -> None:
    h = PaymentHandle.parse("alice@example.com")
    with pytest.raises(ValueError):
        build_zone_record(h, offer='lno1abc"injected')


def test_parse_payment_uri_offer_and_invoice() -> None:
    on_chain, offer, bolt11 = parse_payment_uri("bitcoin:?lno=lno1xyz&lightning=lnbc1abc")
    assert on_chain is None
    assert offer == "lno1xyz"
    assert bolt11 == "lnbc1abc"


def test_parse_payment_uri_address_only() -> None:
    on_chain, offer, bolt11 = parse_payment_uri("bitcoin:bc1qabc")
    assert on_chain == "bc1qabc"
    assert offer is None
    assert bolt11 is None


def test_parse_payment_uri_wrong_scheme() -> None:
    with pytest.raises(ValueError):
        parse_payment_uri("https://example.com/")


def _make_response(
    qname: dns.name.Name,
    txt_value: str | None,
    *,
    ad: bool = True,
    rcode: int = dns.rcode.NOERROR,
) -> dns.message.Message:
    msg = dns.message.make_response(dns.message.make_query(qname, dns.rdatatype.TXT))
    msg.flags |= dns.flags.QR
    if ad:
        msg.flags |= dns.flags.AD
    msg.set_rcode(rcode)
    if txt_value is not None:
        rrset = dns.rrset.from_text(qname.to_text(), 60, "IN", "TXT", f'"{txt_value}"')
        msg.answer.append(rrset)
    return msg


def test_resolve_payment_handle_offer(monkeypatch: pytest.MonkeyPatch) -> None:
    qname = dns.name.from_text("alice.user._bitcoin-payment.example.com.")
    response = _make_response(qname, "bitcoin:?lno=lno1abc")
    resolver = MagicMock()
    resolver.nameservers = ["127.0.0.1"]
    resolver.lifetime = 5.0
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_bip353_validate_resolver",
        False,
        raising=False,
    )

    with patch(
        "app.services.bolt12.bip353.dns.query.tcp",
        return_value=response,
    ):
        result = resolve_payment_handle(
            "alice@example.com",
            resolver=resolver,
        )

    assert result.offer == "lno1abc"
    assert result.bolt11 is None
    assert result.bitcoin_uri == "bitcoin:?lno=lno1abc"
    assert result.handle.user == "alice"


def test_resolve_payment_handle_rejects_unsigned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    qname = dns.name.from_text("alice.user._bitcoin-payment.example.com.")
    response = _make_response(qname, "bitcoin:?lno=lno1abc", ad=False)
    resolver = MagicMock()
    resolver.nameservers = ["127.0.0.1"]
    resolver.lifetime = 5.0

    monkeypatch.setattr(
        "app.core.config.settings.bolt12_bip353_validate_resolver",
        False,
        raising=False,
    )
    with (
        patch("app.services.bolt12.bip353.dns.query.tcp", return_value=response),
        pytest.raises(Bolt12Bip353InsecureError),
    ):
        resolve_payment_handle("alice@example.com", resolver=resolver)


def test_resolve_payment_handle_dev_mode_skips_dnssec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    qname = dns.name.from_text("alice.user._bitcoin-payment.example.com.")
    response = _make_response(qname, "bitcoin:?lno=lno1abc", ad=False)
    resolver = MagicMock()
    resolver.nameservers = ["127.0.0.1"]
    resolver.lifetime = 5.0

    with patch("app.services.bolt12.bip353.dns.query.tcp", return_value=response):
        result = resolve_payment_handle(
            "alice@example.com",
            resolver=resolver,
            require_dnssec=False,
        )

    assert result.offer == "lno1abc"


def test_resolve_payment_handle_no_nameservers() -> None:
    resolver = MagicMock()
    resolver.nameservers = []
    resolver.lifetime = 5.0

    with pytest.raises(RuntimeError, match="no upstream nameservers"):
        resolve_payment_handle("alice@example.com", resolver=resolver)


def test_resolve_payment_handle_nx_response() -> None:
    qname = dns.name.from_text("nope.user._bitcoin-payment.example.com.")
    response = _make_response(qname, None, rcode=dns.rcode.NXDOMAIN)
    resolver = MagicMock()
    resolver.nameservers = ["127.0.0.1"]
    resolver.lifetime = 5.0

    with (
        patch("app.services.bolt12.bip353.dns.query.tcp", return_value=response),
        pytest.raises(Exception),  # NXDOMAIN
    ):
        resolve_payment_handle("nope@example.com", resolver=resolver)


# ── Hardened transport (TCP-only + nameserver failover +
#       rubber-stamp resolver detection) ─────────────────────────


def test_resolve_payment_handle_fails_over_to_next_nameserver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the first nameserver errors, the resolver tries the next one."""
    qname = dns.name.from_text("alice.user._bitcoin-payment.example.com.")
    response = _make_response(qname, "bitcoin:?lno=lno1abc")
    resolver = MagicMock()
    resolver.nameservers = ["10.0.0.1", "10.0.0.2"]
    resolver.lifetime = 5.0
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_bip353_validate_resolver",
        False,
        raising=False,
    )

    calls: list[str] = []

    def fake_tcp(_request, where, timeout):  # noqa: ANN001
        calls.append(where)
        if where == "10.0.0.1":
            raise OSError(111, "Connection refused")
        return response

    with patch("app.services.bolt12.bip353.dns.query.tcp", side_effect=fake_tcp):
        result = resolve_payment_handle("alice@example.com", resolver=resolver)

    # Both nameservers were attempted in order.
    assert calls == ["10.0.0.1", "10.0.0.2"]
    assert result.offer == "lno1abc"


def test_resolve_payment_handle_rejects_rubber_stamp_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resolver that returns AD=1 for ``dnssec-failed.org`` is
    forging the AD flag and must be rejected."""
    # Wipe the per-process probe cache so this test starts fresh.
    import app.services.bolt12.bip353 as _bip353

    monkeypatch.setattr(_bip353, "_validated_resolvers", set())

    bad_probe = _make_response(
        dns.name.from_text("dnssec-failed.org."),
        "192.0.2.1",  # any A-ish data; we only check rcode + AD
        ad=True,
    )
    # Force the answer rrset to be A-typed for realism.
    bad_probe.answer = [dns.rrset.from_text("dnssec-failed.org.", 60, "IN", "A", "192.0.2.1")]

    resolver = MagicMock()
    resolver.nameservers = ["10.0.0.99"]
    resolver.lifetime = 5.0
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_bip353_validate_resolver",
        True,
        raising=False,
    )

    with (
        patch("app.services.bolt12.bip353.dns.query.tcp", return_value=bad_probe),
        pytest.raises(Bolt12Bip353InsecureError, match="rubber|forging|AD"),
    ):
        resolve_payment_handle("alice@example.com", resolver=resolver)


def test_resolve_payment_handle_accepts_validating_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resolver that returns SERVFAIL for ``dnssec-failed.org``
    passes the probe and the real lookup proceeds."""
    import app.services.bolt12.bip353 as _bip353

    monkeypatch.setattr(_bip353, "_validated_resolvers", set())

    qname = dns.name.from_text("alice.user._bitcoin-payment.example.com.")
    real_response = _make_response(qname, "bitcoin:?lno=lno1abc")

    probe_servfail = dns.message.make_response(
        dns.message.make_query(
            dns.name.from_text("dnssec-failed.org."),
            dns.rdatatype.A,
            want_dnssec=True,
        )
    )
    probe_servfail.set_rcode(dns.rcode.SERVFAIL)

    resolver = MagicMock()
    resolver.nameservers = ["10.0.0.7"]
    resolver.lifetime = 5.0
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_bip353_validate_resolver",
        True,
        raising=False,
    )

    responses = iter([probe_servfail, real_response])

    def fake_tcp(_req, _where, timeout):  # noqa: ANN001
        return next(responses)

    with patch("app.services.bolt12.bip353.dns.query.tcp", side_effect=fake_tcp):
        result = resolve_payment_handle("alice@example.com", resolver=resolver)

    assert result.offer == "lno1abc"


def test_resolver_validation_probe_failure_refuses_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resolver-validation probe that cannot complete refuses the
    handle lookup and leaves the resolver unrecorded, so a subsequent
    attempt re-probes rather than trusting an unverified resolver."""
    import app.services.bolt12.bip353 as _bip353

    monkeypatch.setattr(_bip353, "_validated_resolvers", set())

    resolver = MagicMock()
    resolver.nameservers = ["10.0.0.9"]
    resolver.lifetime = 5.0
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_bip353_validate_resolver",
        True,
        raising=False,
    )

    def fake_tcp(_req, _where, timeout):  # noqa: ANN001
        raise dns.exception.Timeout

    with patch("app.services.bolt12.bip353.dns.query.tcp", side_effect=fake_tcp):
        with pytest.raises(Bolt12Bip353InsecureError, match="probe could not complete"):
            resolve_payment_handle("alice@example.com", resolver=resolver)

    # The resolver tuple must NOT have been cached as validated.
    assert tuple(resolver.nameservers) not in _bip353._validated_resolvers
