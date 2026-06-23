# SPDX-License-Identifier: MIT
"""Unit tests for ``app.services.lnurl_service``.

Exercises:
- The lnurl_service ``resolve_recipient`` path with a mocked LNURL-pay
  endpoint over httpx MockTransport (no real network).
- ``request_invoice`` with a fabricated BOLT11 invoice produced
  in-test (no LND required), covering description-hash binding,
  amount enforcement, expiry rejection.
- The handle store + invoice idempotency cache.
- The BOLT11 minimal decoder.
- success_action sanitisation.

A small BOLT11 fabricator lives at the bottom of the file: it produces
bech32-checksummed invoices with arbitrary description_hash, amount and
expiry — the signature region is filled with zeros (our decoder skips
signature verification because LND verifies for real on pay).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from typing import Any, Optional

import httpx
import pytest
import pytest_asyncio

from app.core.config import settings
from app.services import lnurl_service as svc_mod
from app.services.lnurl_service import (
    LnurlService,
    _Bolt11Error,
    _decode_bolt11_minimal,
    _LnurlHandleStore,
    _LnurlInvoiceCache,
    _sanitise_success_action,
)

# ── BOLT11 fabricator ───────────────────────────────────────────────

_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bytes_to_u5(data: bytes) -> list[int]:
    out: list[int] = []
    acc = 0
    bits = 0
    for v in data:
        acc = (acc << 8) | v
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 31)
    if bits:
        out.append((acc << (5 - bits)) & 31)
    return out


def _int_to_u5(value: int, length: int) -> list[int]:
    """Encode ``value`` as ``length`` 5-bit big-endian groups."""
    out: list[int] = []
    for i in reversed(range(length)):
        out.append((value >> (5 * i)) & 31)
    return out


def _tagged_field(tag: int, payload: list[int]) -> list[int]:
    length = len(payload)
    return [tag, (length >> 5) & 31, length & 31] + payload


def _bech32_encode(hrp: str, data: list[int]) -> str:
    """Construct a bech32 string with constant=1 (LUD-01 / BOLT11)."""
    values = _hrp_expand(hrp) + data + [0] * 6
    polymod = _bech32_polymod(values) ^ 1
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32[d] for d in data + checksum)


def fabricate_bolt11(
    *,
    amount_msat: int,
    description_hash: bytes,
    payment_hash: Optional[bytes] = None,
    expiry_seconds: int = 3600,
    timestamp: Optional[int] = None,
    network: str = "bcrt",
) -> str:
    """Produce a bech32-checksummed BOLT11 carrying the requested fields.

    The signature region is filled with zero bytes — our minimal
    decoder doesn't verify it. Real recipients always sign properly;
    LND will verify on pay.
    """
    assert len(description_hash) == 32
    payment_hash = payment_hash or hashlib.sha256(b"test-payment-hash").digest()
    timestamp = timestamp if timestamp is not None else int(time.time())
    # Amount in HRP. We always emit picobtc (p) for exact integer math.
    # 1 picobtc = 0.1 msat → amount_msat * 10 picobtc.
    amount_pico = amount_msat * 10
    hrp = f"ln{network}{amount_pico}p"
    # Body: timestamp(7) + p(payment_hash) + h(desc_hash) + x(expiry).
    data: list[int] = []
    data += _int_to_u5(timestamp, 7)
    data += _tagged_field(1, _bytes_to_u5(payment_hash)[:52])
    data += _tagged_field(23, _bytes_to_u5(description_hash)[:52])
    # Expiry: LSB-up to needed groups. Use 2 groups (covers up to 1023s)
    # but for arbitrary values fall back to enough groups for 32 bits.
    exp_groups: list[int] = []
    v = expiry_seconds
    while v > 0:
        exp_groups.insert(0, v & 31)
        v >>= 5
    if not exp_groups:
        exp_groups = [0]
    data += _tagged_field(6, exp_groups)
    # Signature: 65 bytes = 104 5-bit groups (520 bits / 5).
    data += [0] * 104
    return _bech32_encode(hrp, data)


# ── Tests: BOLT11 decoder ───────────────────────────────────────────


class TestBolt11Decoder:
    def test_decodes_amount_and_desc_hash(self) -> None:
        desc = b"test metadata content"
        desc_hash = hashlib.sha256(desc).digest()
        invoice = fabricate_bolt11(amount_msat=10_000_000, description_hash=desc_hash, expiry_seconds=600)
        decoded = _decode_bolt11_minimal(invoice)
        assert decoded.amount_msat == 10_000_000
        assert decoded.description_hash == desc_hash
        assert decoded.expiry_seconds == 600

    def test_bad_checksum_rejected(self) -> None:
        desc_hash = hashlib.sha256(b"x").digest()
        invoice = fabricate_bolt11(amount_msat=1_000, description_hash=desc_hash)
        # Corrupt one char.
        bad = invoice[:-2] + ("p" if invoice[-2] != "p" else "q") + invoice[-1]
        with pytest.raises(_Bolt11Error):
            _decode_bolt11_minimal(bad)

    def test_wrong_network_prefix_rejected(self) -> None:
        # The test environment runs on regtest (``bcrt``); a mainnet
        # (``bc``) invoice must be refused by the decoder.
        desc_hash = hashlib.sha256(b"x").digest()
        invoice = fabricate_bolt11(amount_msat=1_000, description_hash=desc_hash, network="bc")
        with pytest.raises(_Bolt11Error):
            _decode_bolt11_minimal(invoice)

    def test_amount_with_too_many_digits_rejected(self) -> None:
        from app.services.lnurl_service import _parse_bolt11_amount

        with pytest.raises(_Bolt11Error):
            _parse_bolt11_amount("lnbcrt" + "9" * 15 + "p")


# ── Tests: handle store + invoice cache ─────────────────────────────


class TestHandleStore:
    @pytest.mark.asyncio
    async def test_put_and_get_round_trip(self) -> None:
        store = _LnurlHandleStore()
        params = {"callback": "https://example.com/cb", "metadata_raw": "[]"}
        h = await store.put(params)  # type: ignore[arg-type]
        assert len(h) == 32
        out = await store.get(h)
        assert out == params
        assert await store.get("0" * 32) is None

    @pytest.mark.asyncio
    async def test_ttl_expiry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "lnurl_handle_ttl_seconds", 0)
        store = _LnurlHandleStore()
        h = await store.put({"callback": "x"})  # type: ignore[arg-type]
        # TTL=0 means already-expired on next access.
        await asyncio.sleep(0.01)
        assert await store.get(h) is None


class TestInvoiceCache:
    @pytest.mark.asyncio
    async def test_hit_returns_same_payload(self) -> None:
        cache = _LnurlInvoiceCache()
        result: Any = {
            "payment_request": "lnbc...",
            "payment_hash": "deadbeef",
            "amount_sats": 1000,
            "description": "x",
            "expiry_seconds": 3600,
            "success_action": None,
            "cache_hit": False,
        }
        key = ("h" * 32, 1000, "")
        await cache.put(key, result)
        out = await cache.get(key)
        assert out == result

    @pytest.mark.asyncio
    async def test_disabled_when_ttl_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "lnurl_invoice_cache_ttl_seconds", 0)
        cache = _LnurlInvoiceCache()
        await cache.put(("h" * 32, 1, ""), {})  # type: ignore[arg-type]
        assert await cache.get(("h" * 32, 1, "")) is None


# ── Tests: success_action sanitisation ──────────────────────────────


class TestSuccessAction:
    def test_message_truncated(self) -> None:
        out = _sanitise_success_action({"tag": "message", "message": "x" * 500})
        assert out is not None and out["tag"] == "message"
        assert len(out["message"] or "") == 144

    def test_url_only_http_https(self) -> None:
        good = _sanitise_success_action({"tag": "url", "url": "https://x.com/r", "description": "thanks"})
        assert good is not None and good["tag"] == "url"
        bad = _sanitise_success_action({"tag": "url", "url": "javascript:alert(1)", "description": "x"})
        assert bad is None

    def test_aes_returns_placeholder(self) -> None:
        out = _sanitise_success_action({"tag": "aes", "ciphertext": "x"})
        assert out == {"tag": "aes"}

    def test_unknown_tag_dropped(self) -> None:
        assert _sanitise_success_action({"tag": "weird"}) is None
        assert _sanitise_success_action(None) is None
        assert _sanitise_success_action("string") is None


# ── Tests: resolve + request_invoice end-to-end (mocked) ────────────


_TEST_HOST = "lnurl.test"
_TEST_BASE = f"https://{_TEST_HOST}"


def _build_metadata() -> tuple[str, str]:
    """Return (raw_json, plain_text)."""
    text = "Pay to alice"
    raw = json.dumps([["text/plain", text]])
    return raw, text


def _make_resolve_response(metadata_raw: str, **overrides: Any) -> dict[str, Any]:
    body = {
        "tag": "payRequest",
        "callback": f"{_TEST_BASE}/lnurlp/callback",
        "minSendable": 1_000,
        "maxSendable": 100_000_000,
        "metadata": metadata_raw,
        "commentAllowed": 100,
    }
    body.update(overrides)
    return body


class _MockHTTP:
    """Helper that builds a httpx.MockTransport-backed AsyncClient and
    exposes a tiny scripting API for the recipient endpoints."""

    def __init__(self) -> None:
        self.resolve_response: Optional[httpx.Response] = None
        self.callback_response: Optional[httpx.Response] = None
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if "/.well-known/lnurlp/" in request.url.path or request.url.path.endswith("/lnurlp"):
            assert self.resolve_response is not None, "no resolve response queued"
            return self.resolve_response
        if "/callback" in request.url.path:
            assert self.callback_response is not None, "no callback response queued"
            return self.callback_response
        return httpx.Response(404)


def _patch_service_with_mock(service: LnurlService, mock: _MockHTTP, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the service's _get_client to return an AsyncClient backed
    by ``mock``. Bypasses Tor / SSRF logic so we can test the protocol
    layer independently."""
    transport = httpx.MockTransport(mock)
    client = httpx.AsyncClient(transport=transport, follow_redirects=False)

    async def _stub_get_client(*, target_is_onion: bool) -> tuple[httpx.AsyncClient, bool]:  # noqa: ARG001
        return client, False

    monkeypatch.setattr(service, "_get_client", _stub_get_client)
    # Also relax SSRF host check so "lnurl.test" doesn't get refused.
    monkeypatch.setattr(svc_mod, "_host_is_private", lambda host: False)
    # The protocol layer is tested independently of connection pinning,
    # which needs real DNS; pass the request through unchanged here. The
    # pinning behaviour itself is covered in test_net_guard.py.
    monkeypatch.setattr(svc_mod, "pin_request_args", lambda url: (url, {}, {}))
    monkeypatch.setattr(settings, "lnurl_allow_http", True)


@pytest_asyncio.fixture
async def service() -> LnurlService:
    return LnurlService()


@pytest.mark.asyncio
async def test_resolve_lightning_address_success(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, text = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)

    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert err is None
    assert result is not None
    assert result["source_kind"] == "lightning_address"
    assert result["callback_host"] == _TEST_HOST
    assert result["min_sendable_sats"] == 1
    assert result["max_sendable_sats"] == 100_000
    assert result["metadata_text"] == text
    assert result["comment_allowed"] == 100
    assert len(result["handle"]) == 32


@pytest.mark.asyncio
async def test_resolve_accepts_callback_on_other_host(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cross-host callbacks are permitted (LUD-06 only recommends same-origin).

    The widespread `.well-known/lnurlp/<name>` redirect pattern hosts a
    static file on a personal domain that points at a third-party callback
    (Alby, LNbits, etc.). The callback URL is independently SSRF-validated.
    """
    raw, _ = _build_metadata()
    body = _make_resolve_response(raw, callback="https://relay.example.test/cb")
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=body)
    _patch_service_with_mock(service, mock, monkeypatch)

    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert err is None and result is not None
    assert result["callback_host"] == "relay.example.test"


@pytest.mark.asyncio
async def test_resolve_rejects_non_pay_request(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json={"tag": "withdrawRequest", "callback": f"{_TEST_BASE}/cb"})
    _patch_service_with_mock(service, mock, monkeypatch)
    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is None and err is not None
    assert "payRequest" in err


@pytest.mark.asyncio
async def test_resolve_propagates_recipient_error(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json={"status": "ERROR", "reason": "user not found"})
    _patch_service_with_mock(service, mock, monkeypatch)
    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is None
    assert err is not None and "user not found" in err


@pytest.mark.asyncio
async def test_request_invoice_validates_amount_and_desc_hash(
    service: LnurlService, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)

    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None and err is None
    handle = result["handle"]

    # Mint a matching BOLT11.
    desc_hash = hashlib.sha256(raw.encode()).digest()
    invoice = fabricate_bolt11(amount_msat=10_000, description_hash=desc_hash, expiry_seconds=3600)
    mock.callback_response = httpx.Response(200, json={"pr": invoice})

    inv, err = await service.request_invoice(handle, amount_sats=10, comment="")
    assert err is None
    assert inv is not None
    assert inv["amount_sats"] == 10
    assert inv["payment_request"] == invoice
    assert inv["cache_hit"] is False


@pytest.mark.asyncio
async def test_request_invoice_rejects_wrong_amount(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)

    result, _err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    handle = result["handle"]

    # Recipient returns invoice for 5 sats when we asked for 10.
    desc_hash = hashlib.sha256(raw.encode()).digest()
    bad_invoice = fabricate_bolt11(amount_msat=5_000, description_hash=desc_hash, expiry_seconds=3600)
    mock.callback_response = httpx.Response(200, json={"pr": bad_invoice})

    inv, err = await service.request_invoice(handle, amount_sats=10, comment="")
    assert inv is None
    assert err is not None and "amount" in err


@pytest.mark.asyncio
async def test_request_invoice_rejects_wrong_desc_hash(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)

    result, _err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    handle = result["handle"]

    bogus_hash = hashlib.sha256(b"different metadata").digest()
    bad_invoice = fabricate_bolt11(amount_msat=10_000, description_hash=bogus_hash, expiry_seconds=3600)
    mock.callback_response = httpx.Response(200, json={"pr": bad_invoice})

    inv, err = await service.request_invoice(handle, amount_sats=10, comment="")
    assert inv is None
    assert err is not None and "description_hash" in err


@pytest.mark.asyncio
async def test_request_invoice_rejects_near_expiry(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    handle = result["handle"]

    desc_hash = hashlib.sha256(raw.encode()).digest()
    # Invoice expires 30s from now → less than the 60s minimum.
    invoice = fabricate_bolt11(amount_msat=10_000, description_hash=desc_hash, expiry_seconds=30)
    mock.callback_response = httpx.Response(200, json={"pr": invoice})

    inv, err = await service.request_invoice(handle, amount_sats=10, comment="")
    assert inv is None
    assert err is not None and "expires" in err


@pytest.mark.asyncio
async def test_request_invoice_cache_hit(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    handle = result["handle"]

    desc_hash = hashlib.sha256(raw.encode()).digest()
    invoice = fabricate_bolt11(amount_msat=10_000, description_hash=desc_hash, expiry_seconds=3600)
    mock.callback_response = httpx.Response(200, json={"pr": invoice})

    first, err1 = await service.request_invoice(handle, amount_sats=10, comment="")
    assert err1 is None and first is not None
    assert first["cache_hit"] is False

    # Swap the callback response to garbage; if the cache works we
    # should never see it.
    mock.callback_response = httpx.Response(200, json={"status": "ERROR", "reason": "x"})
    second, err2 = await service.request_invoice(handle, amount_sats=10, comment="")
    assert err2 is None and second is not None
    assert second["cache_hit"] is True
    assert second["payment_request"] == first["payment_request"]


@pytest.mark.asyncio
async def test_resolve_invalid_input(service: LnurlService) -> None:
    result, err = await service.resolve_recipient("not-an-address")
    assert result is None and err is not None


@pytest.mark.asyncio
async def test_request_invoice_unknown_handle(service: LnurlService) -> None:
    result, err = await service.request_invoice("0" * 32, amount_sats=10, comment="")
    assert result is None and err is not None


@pytest.mark.asyncio
async def test_request_invoice_amount_below_min(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    # Min is 1000 msat = 1 sat from default fixture.
    mock.resolve_response = httpx.Response(
        200,
        json=_make_resolve_response(raw, minSendable=10_000, maxSendable=1_000_000),
    )
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    inv, err = await service.request_invoice(result["handle"], amount_sats=5, comment="")
    assert inv is None and err is not None and "outside" in err


# ── SSRF host-block ─────────────────────────────────────────────────


class TestSSRF:
    def test_validate_url_blocks_private_host(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.lnurl_service import _validate_target_url

        monkeypatch.setattr(settings, "lnurl_allow_private_hosts", False)
        # Literal RFC1918 address — caught without DNS.
        _, err = _validate_target_url("https://192.168.1.5/", context="resolve")
        assert err is not None and "private" in err

    def test_validate_url_blocks_http_clearnet(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.lnurl_service import _validate_target_url

        monkeypatch.setattr(settings, "lnurl_allow_http", False)
        monkeypatch.setattr(svc_mod, "_host_is_private", lambda host: False)
        _, err = _validate_target_url("http://example.com/", context="resolve")
        assert err is not None and "http" in err.lower()

    def test_validate_url_allows_onion_http(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.lnurl_service import _validate_target_url

        monkeypatch.setattr(settings, "lnurl_allow_http", False)
        url, err = _validate_target_url("http://abcdefghijklmnop.onion/lnurlp/x", context="resolve")
        assert err is None


# ── Tor decision (LNURL_FORCE_TOR) ──────────────────────────────────


class TestTorDecision:
    def test_force_true_always_uses_tor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.lnurl_service import _should_use_tor

        monkeypatch.setattr(settings, "lnurl_force_tor", "true")
        monkeypatch.setattr(settings, "lnd_rest_url", "https://example.com:8080")
        assert _should_use_tor() is True

    def test_force_false_never_uses_tor(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.lnurl_service import _should_use_tor

        monkeypatch.setattr(settings, "lnurl_force_tor", "false")
        monkeypatch.setattr(settings, "lnd_rest_url", "https://abcd1234.onion:8080")
        assert _should_use_tor() is False

    def test_auto_uses_tor_when_lnd_is_onion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.lnurl_service import _should_use_tor

        monkeypatch.setattr(settings, "lnurl_force_tor", "auto")
        monkeypatch.setattr(settings, "lnd_rest_url", "https://abcdefghijklmnop.onion:8080")
        assert _should_use_tor() is True

    def test_auto_no_tor_when_lnd_is_clearnet(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.lnurl_service import _should_use_tor

        monkeypatch.setattr(settings, "lnurl_force_tor", "auto")
        monkeypatch.setattr(settings, "lnd_rest_url", "https://example.com:8080")
        assert _should_use_tor() is False

    @pytest.mark.asyncio
    async def test_tor_routed_request_resolves_at_proxy_not_locally(
        self, service: LnurlService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the client routes over Tor, the destination is resolved at
        the SOCKS proxy: no local IP pin is applied and the hostname is
        preserved in the request URL."""
        transport = httpx.MockTransport(lambda req: httpx.Response(200, json={"ok": True}))
        client = httpx.AsyncClient(transport=transport, follow_redirects=False)

        async def _stub_get_client(*, target_is_onion: bool) -> tuple[httpx.AsyncClient, bool]:  # noqa: ARG001
            return client, True  # routing over Tor

        monkeypatch.setattr(service, "_get_client", _stub_get_client)

        pin_calls: list[str] = []

        def _record_pin(url: str) -> tuple[str, dict, dict]:
            pin_calls.append(url)
            return url, {}, {}

        monkeypatch.setattr(svc_mod, "pin_request_args", _record_pin)
        try:
            body, err = await service._http_get_json(
                "https://pay.example.com/.well-known/lnurlp/alice", target_is_onion=False
            )
        finally:
            await client.aclose()
        assert err is None
        assert body == {"ok": True}
        assert pin_calls == []  # no local DNS resolution / pinning over Tor

    @pytest.mark.asyncio
    async def test_direct_request_pins_resolved_ip(
        self, service: LnurlService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A direct (non-Tor) clearnet request still pins to a validated IP."""
        transport = httpx.MockTransport(lambda req: httpx.Response(200, json={"ok": True}))
        client = httpx.AsyncClient(transport=transport, follow_redirects=False)

        async def _stub_get_client(*, target_is_onion: bool) -> tuple[httpx.AsyncClient, bool]:  # noqa: ARG001
            return client, False  # direct connection

        monkeypatch.setattr(service, "_get_client", _stub_get_client)

        pin_calls: list[str] = []

        def _record_pin(url: str) -> tuple[str, dict, dict]:
            pin_calls.append(url)
            return url, {}, {}

        monkeypatch.setattr(svc_mod, "pin_request_args", _record_pin)
        try:
            _body, err = await service._http_get_json(
                "https://pay.example.com/.well-known/lnurlp/alice", target_is_onion=False
            )
        finally:
            await client.aclose()
        assert err is None
        assert len(pin_calls) == 1


# ── lightning: scheme prefix (LUD-17) ──────────────────────────────


@pytest.mark.asyncio
async def test_resolve_strips_lightning_prefix_for_address(
    service: LnurlService, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, err = await service.resolve_recipient(f"lightning:alice@{_TEST_HOST}")
    assert err is None and result is not None
    assert result["source_input"] == f"alice@{_TEST_HOST}"


@pytest.mark.asyncio
async def test_resolve_strips_lightning_prefix_uppercase(
    service: LnurlService, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, err = await service.resolve_recipient(f"LIGHTNING:ALICE@{_TEST_HOST}")
    assert err is None and result is not None


# ── Metadata parsing ───────────────────────────────────────────────


class TestMetadataParsing:
    def test_long_desc_extracted(self) -> None:
        raw = json.dumps(
            [
                ["text/plain", "short"],
                ["text/long-desc", "the long form description"],
            ]
        )
        text, long_text, image = svc_mod._parse_metadata(raw)
        assert text == "short"
        assert long_text == "the long form description"
        assert image is None

    def test_image_png_accepted(self) -> None:
        # tiny base64 blob, valid charset.
        b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAA="
        raw = json.dumps([["text/plain", "x"], ["image/png;base64", b64]])
        _, _, image = svc_mod._parse_metadata(raw)
        assert image is not None and image.startswith("data:image/png;base64,")

    def test_image_jpeg_accepted(self) -> None:
        b64 = "/9j/4AAQSkZJRgABAQEAYABgAAD"
        raw = json.dumps([["text/plain", "x"], ["image/jpeg;base64", b64]])
        _, _, image = svc_mod._parse_metadata(raw)
        assert image is not None and image.startswith("data:image/jpeg;base64,")

    def test_image_svg_silently_dropped(self) -> None:
        raw = json.dumps([["text/plain", "x"], ["image/svg+xml;base64", "PHN2Zy8+"]])
        _, _, image = svc_mod._parse_metadata(raw)
        assert image is None

    def test_image_oversized_dropped(self) -> None:
        b64 = "A" * 200_000
        raw = json.dumps([["text/plain", "x"], ["image/png;base64", b64]])
        _, _, image = svc_mod._parse_metadata(raw)
        assert image is None

    def test_image_invalid_base64_charset_dropped(self) -> None:
        raw = json.dumps([["text/plain", "x"], ["image/png;base64", "*** not base64 ***"]])
        _, _, image = svc_mod._parse_metadata(raw)
        assert image is None

    def test_malformed_json_returns_none(self) -> None:
        text, long_text, image = svc_mod._parse_metadata("not json at all")
        assert text is None and long_text is None and image is None

    def test_non_list_root_returns_none(self) -> None:
        text, _, _ = svc_mod._parse_metadata(json.dumps({"text/plain": "hi"}))
        assert text is None

    def test_first_text_plain_wins(self) -> None:
        raw = json.dumps([["text/plain", "first"], ["text/plain", "second"]])
        text, _, _ = svc_mod._parse_metadata(raw)
        assert text == "first"

    def test_text_truncated_at_512(self) -> None:
        raw = json.dumps([["text/plain", "a" * 1000]])
        text, _, _ = svc_mod._parse_metadata(raw)
        assert text is not None and len(text) == 512


@pytest.mark.asyncio
async def test_resolve_rejects_missing_text_plain(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    bad_meta = json.dumps([["image/png;base64", "iVBORw0KGgo="]])
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(bad_meta))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is None and err is not None and "text/plain" in err


@pytest.mark.asyncio
async def test_resolve_rejects_oversized_metadata(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    huge_meta = json.dumps([["text/plain", "x" * 40_000]])
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(huge_meta))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is None and err is not None and "metadata" in err


@pytest.mark.asyncio
async def test_resolve_rejects_invalid_min_max(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _build_metadata()
    body = _make_resolve_response(raw, minSendable=1000, maxSendable=500)
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=body)
    _patch_service_with_mock(service, mock, monkeypatch)
    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is None and err is not None and "min/maxSendable" in err


# ── HTTP error cases ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_http_non_200_returns_error(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(404, text="not found")
    _patch_service_with_mock(service, mock, monkeypatch)
    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is None and err is not None and "404" in err


@pytest.mark.asyncio
async def test_http_non_json_response_rejected(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, content=b"<html>not json</html>")
    _patch_service_with_mock(service, mock, monkeypatch)
    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is None and err is not None and "JSON" in err


@pytest.mark.asyncio
async def test_http_response_over_byte_cap(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "lnurl_max_response_bytes", 100)
    raw, _ = _build_metadata()
    huge_body = _make_resolve_response(raw)
    huge_body["metadata"] = json.dumps([["text/plain", "x" * 5000]])
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=huge_body)
    _patch_service_with_mock(service, mock, monkeypatch)
    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is None and err is not None and "byte cap" in err


@pytest.mark.asyncio
async def test_http_redirect_refused(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    """``follow_redirects=False`` so a 30x is treated as a non-200."""
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(302, headers={"Location": "https://evil.example/"})
    _patch_service_with_mock(service, mock, monkeypatch)
    result, err = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is None and err is not None and "302" in err


# ── Comment behaviour ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_comment_not_forwarded_when_recipient_disallows(
    service: LnurlService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even with empty comment, the URL must not include ``comment=``."""
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw, commentAllowed=0))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    assert result["comment_allowed"] == 0
    desc_hash = hashlib.sha256(raw.encode()).digest()
    invoice = fabricate_bolt11(amount_msat=10_000, description_hash=desc_hash, expiry_seconds=3600)
    mock.callback_response = httpx.Response(200, json={"pr": invoice})
    inv, err = await service.request_invoice(result["handle"], amount_sats=10, comment="")
    assert err is None and inv is not None
    callback_call = next(c for c in mock.calls if "/callback" in c.url.path)
    assert "comment" not in str(callback_call.url)


@pytest.mark.asyncio
async def test_comment_rejected_when_recipient_disallows(
    service: LnurlService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-empty comment against ``commentAllowed=0`` is refused."""
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw, commentAllowed=0))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    inv, err = await service.request_invoice(result["handle"], amount_sats=10, comment="hi")
    assert inv is None and err is not None and "comment" in err


@pytest.mark.asyncio
async def test_comment_forwarded_when_allowed(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw, commentAllowed=144))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    desc_hash = hashlib.sha256(raw.encode()).digest()
    invoice = fabricate_bolt11(amount_msat=10_000, description_hash=desc_hash, expiry_seconds=3600)
    mock.callback_response = httpx.Response(200, json={"pr": invoice})
    _, err = await service.request_invoice(result["handle"], amount_sats=10, comment="thanks")
    assert err is None
    callback_call = next(c for c in mock.calls if "/callback" in c.url.path)
    assert "comment=thanks" in str(callback_call.url)


@pytest.mark.asyncio
async def test_callback_query_params_not_duplicated(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    """A callback URL that already carries amount/comment must not end up
    with duplicate, conflicting params; ours are authoritative and the
    recipient's other params are preserved."""
    from urllib.parse import parse_qs, urlparse

    raw, _ = _build_metadata()
    mock = _MockHTTP()
    # Recipient pre-populated amount + comment, plus an unrelated param.
    cb = f"{_TEST_BASE}/lnurlp/callback?token=abc&amount=999&comment=stale"
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw, callback=cb, commentAllowed=144))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    desc_hash = hashlib.sha256(raw.encode()).digest()
    invoice = fabricate_bolt11(amount_msat=10_000, description_hash=desc_hash, expiry_seconds=3600)
    mock.callback_response = httpx.Response(200, json={"pr": invoice})
    _, err = await service.request_invoice(result["handle"], amount_sats=10, comment="thanks")
    assert err is None
    callback_call = next(c for c in mock.calls if "/callback" in c.url.path)
    qs = parse_qs(urlparse(str(callback_call.url)).query)
    assert qs["amount"] == ["10000"]  # ours wins, exactly once
    assert qs["comment"] == ["thanks"]  # ours wins, exactly once
    assert qs["token"] == ["abc"]  # unrelated param preserved


@pytest.mark.asyncio
async def test_comment_too_long_rejected(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw, commentAllowed=10))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    inv, err = await service.request_invoice(result["handle"], amount_sats=10, comment="x" * 50)
    assert inv is None and err is not None and "comment" in err


@pytest.mark.asyncio
async def test_comment_clamped_to_280_hard_cap(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    """Recipient claims commentAllowed=2000; service must clamp at 280."""
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw, commentAllowed=2000))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    # Sanitised comment_allowed surfaced to client must be <=280.
    assert result["comment_allowed"] <= 280
    inv, err = await service.request_invoice(result["handle"], amount_sats=10, comment="x" * 281)
    assert inv is None and err is not None


# ── Onion / Tor edge cases ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_onion_target_without_tor_proxy_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "lnd_tor_proxy", "")
    monkeypatch.setattr(settings, "lnurl_force_tor", "false")
    s = LnurlService()
    # Force the lazy client init for an onion target.
    with pytest.raises(RuntimeError, match="onion"):
        await s._get_client(target_is_onion=True)


# ── Handle store: LRU eviction ─────────────────────────────────────


@pytest.mark.asyncio
async def test_handle_store_lru_eviction() -> None:
    store = _LnurlHandleStore()
    store._MAX_ENTRIES = 4  # type: ignore[misc]
    handles = []
    for i in range(6):
        params: Any = {"callback": f"https://x.test/{i}", "metadata_raw": "[]"}
        handles.append(await store.put(params))
    # First two should have been evicted.
    assert await store.get(handles[0]) is None
    assert await store.get(handles[1]) is None
    # Last four should still be live.
    for h in handles[2:]:
        assert await store.get(h) is not None


# ── BOLT11 decoder: extra coverage ─────────────────────────────────


class TestBolt11DecoderExtras:
    def test_payment_hash_extracted(self) -> None:
        ph = hashlib.sha256(b"some-payment").digest()
        desc_hash = hashlib.sha256(b"meta").digest()
        invoice = fabricate_bolt11(
            amount_msat=1_000,
            description_hash=desc_hash,
            payment_hash=ph,
            expiry_seconds=600,
        )
        decoded = _decode_bolt11_minimal(invoice)
        assert decoded.payment_hash_hex == ph.hex()

    def test_milli_multiplier(self) -> None:
        # 1m BTC = 0.001 BTC = 100_000 sat = 100_000_000 msat
        # Build by hand: 1m
        from app.services.lnurl_service import _parse_bolt11_amount

        assert _parse_bolt11_amount("lnbcrt1m") == 100_000_000

    def test_micro_multiplier(self) -> None:
        from app.services.lnurl_service import _parse_bolt11_amount

        # 1u BTC = 100 sat = 100_000 msat
        assert _parse_bolt11_amount("lnbcrt1u") == 100_000

    def test_nano_multiplier(self) -> None:
        from app.services.lnurl_service import _parse_bolt11_amount

        # 1n BTC = 0.1 sat = 100 msat
        assert _parse_bolt11_amount("lnbcrt1n") == 100

    def test_amountless_hrp_returns_none(self) -> None:
        from app.services.lnurl_service import _parse_bolt11_amount

        assert _parse_bolt11_amount("lnbcrt") is None

    def test_picobtc_must_be_multiple_of_ten(self) -> None:
        from app.services.lnurl_service import _parse_bolt11_amount

        with pytest.raises(_Bolt11Error):
            _parse_bolt11_amount("lnbcrt5p")

    def test_invalid_hrp_no_ln_prefix(self) -> None:
        from app.services.lnurl_service import _parse_bolt11_amount

        with pytest.raises(_Bolt11Error):
            _parse_bolt11_amount("xxbcrt100p")


# ── SSRF: extra coverage ───────────────────────────────────────────


class TestSSRFExtras:
    def test_validate_url_blocks_ipv6_loopback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.lnurl_service import _validate_target_url

        monkeypatch.setattr(settings, "lnurl_allow_private_hosts", False)
        _, err = _validate_target_url("https://[::1]/", context="resolve")
        assert err is not None and "private" in err

    def test_validate_url_blocks_localhost_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.lnurl_service import _validate_target_url

        monkeypatch.setattr(settings, "lnurl_allow_private_hosts", False)
        _, err = _validate_target_url("https://localhost/", context="resolve")
        assert err is not None and "private" in err

    def test_validate_url_allows_private_when_toggled_on(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services.lnurl_service import _validate_target_url

        monkeypatch.setattr(settings, "lnurl_allow_private_hosts", True)
        _, err = _validate_target_url("https://192.168.1.5/", context="resolve")
        assert err is None

    def test_validate_url_rejects_non_http_scheme(self) -> None:
        from app.services.lnurl_service import _validate_target_url

        _, err = _validate_target_url("ftp://example.com/x", context="resolve")
        assert err is not None and "http/https" in err

    def test_validate_url_rejects_missing_host(self) -> None:
        from app.services.lnurl_service import _validate_target_url

        _, err = _validate_target_url("https:///path", context="resolve")
        assert err is not None and "host" in err


# ── Lightning Address format validation ────────────────────────────


class TestLightningAddressFormat:
    @pytest.mark.asyncio
    async def test_rejects_uppercase_only_in_local_part(self, service: LnurlService) -> None:
        # After lowercasing, "ALICE@host" → "alice@host" passes — so
        # this is a no-op rejection-wise. Verify the path doesn't crash.
        # Truly invalid: empty local part.
        result, err = await service.resolve_recipient(f"@{_TEST_HOST}")
        assert result is None and err is not None

    @pytest.mark.asyncio
    async def test_rejects_no_tld(self, service: LnurlService) -> None:
        result, err = await service.resolve_recipient("alice@localhost")
        assert result is None and err is not None and "format" in err

    @pytest.mark.asyncio
    async def test_rejects_local_part_with_at_sign(self, service: LnurlService) -> None:
        result, err = await service.resolve_recipient("a@b@c.test")
        assert result is None and err is not None


# ── Callback / invoice extra error paths ──────────────────────────


@pytest.mark.asyncio
async def test_callback_recipient_returns_error_status(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    mock.callback_response = httpx.Response(200, json={"status": "ERROR", "reason": "out of liquidity"})
    inv, err = await service.request_invoice(result["handle"], amount_sats=10, comment="")
    assert inv is None and err is not None and "out of liquidity" in err


@pytest.mark.asyncio
async def test_callback_missing_pr_field(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    mock.callback_response = httpx.Response(200, json={"routes": []})
    inv, err = await service.request_invoice(result["handle"], amount_sats=10, comment="")
    assert inv is None and err is not None and "pr" in err


@pytest.mark.asyncio
async def test_callback_pr_decode_failure(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    mock.callback_response = httpx.Response(200, json={"pr": "lnbcrt-not-bech32"})
    inv, err = await service.request_invoice(result["handle"], amount_sats=10, comment="")
    assert inv is None and err is not None and "bolt11" in err.lower()


# ── BOLT11 amountless invoice rejected at request_invoice ─────────


@pytest.mark.asyncio
async def test_callback_amountless_bolt11_rejected(service: LnurlService, monkeypatch: pytest.MonkeyPatch) -> None:
    """A BOLT11 with no amount (amountless invoice) must be refused."""
    raw, _ = _build_metadata()
    mock = _MockHTTP()
    mock.resolve_response = httpx.Response(200, json=_make_resolve_response(raw))
    _patch_service_with_mock(service, mock, monkeypatch)
    result, _ = await service.resolve_recipient(f"alice@{_TEST_HOST}")
    assert result is not None
    # Construct an amountless BOLT11 by hand: HRP "lnbcrt" with no amount.
    desc_hash = hashlib.sha256(raw.encode()).digest()
    payment_hash = hashlib.sha256(b"ph").digest()
    # Reuse fabricator's data layout but skip the HRP amount.
    timestamp = int(time.time())
    data: list[int] = []
    data += _int_to_u5(timestamp, 7)
    data += _tagged_field(1, _bytes_to_u5(payment_hash)[:52])
    data += _tagged_field(23, _bytes_to_u5(desc_hash)[:52])
    data += _tagged_field(6, [0, 16, 16])  # 3600s expiry-ish
    data += [0] * 104
    invoice = _bech32_encode("lnbcrt", data)
    mock.callback_response = httpx.Response(200, json={"pr": invoice})
    inv, err = await service.request_invoice(result["handle"], amount_sats=10, comment="")
    assert inv is None and err is not None
    assert "amount" in err.lower()


# ── Singleton / aclose ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_lnurl_service_singleton() -> None:
    from app.services.lnurl_service import get_lnurl_service

    a = get_lnurl_service()
    b = get_lnurl_service()
    assert a is b


@pytest.mark.asyncio
async def test_aclose_resets_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "lnurl_force_tor", "false")
    s = LnurlService()
    client = await s._get_client(target_is_onion=False)
    assert client is not None
    await s.aclose()
    assert s._client is None


# ── Bech32 LNURL extras ───────────────────────────────────────────


def test_decode_lnurl_with_non_str_input() -> None:
    from app.core.bech32_lnurl import decode_lnurl

    assert decode_lnurl(None) is None  # type: ignore[arg-type]
    assert decode_lnurl(123) is None  # type: ignore[arg-type]


def test_decode_lnurl_no_separator() -> None:
    from app.core.bech32_lnurl import decode_lnurl

    assert decode_lnurl("lnurlqqqqqq") is None


def test_decode_lnurl_empty_data_part() -> None:
    from app.core.bech32_lnurl import decode_lnurl

    # Just HRP + separator + minimum-length checksum that won't validate.
    assert decode_lnurl("lnurl1") is None
