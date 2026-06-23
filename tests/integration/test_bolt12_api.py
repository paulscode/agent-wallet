# SPDX-License-Identifier: MIT
"""Integration tests for the BOLT 12 REST router.

Exercises the live FastAPI app via the standard ``client`` /
``authed_client`` fixtures from ``tests/conftest.py``. We build real
encoded offer strings via the field-level codec so the decode path
runs end-to-end (no fixture mocking).
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.bolt12 import Bolt12Codec, Offer

# Valid 33-byte secp256k1 point (low-x compressed pubkey from BOLT 1
# test vectors). Used so :class:`Offer.parse` accepts the issuer id.
_ISSUER_ID = bytes.fromhex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619")


def _make_offer_string(
    *,
    description: str = "coffee",
    amount: int | None = 1500,
    issuer: str | None = "alice",
) -> str:
    o = Offer(
        amount=amount,
        description=description,
        issuer=issuer,
        issuer_id=_ISSUER_ID,
    )
    return Bolt12Codec.encode(o.to_bolt12_string())


# ── /v1/bolt12/decode ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_decode_offer_happy_path(authed_client) -> None:
    client, _raw, _key_id = authed_client
    s = _make_offer_string()
    resp = await client.post("/v1/bolt12/decode", json={"offer": s})
    assert resp.status_code == 200
    body = resp.json()
    assert body["offer"] == s
    assert body["amount_msat"] == 1500
    assert body["description"] == "coffee"
    assert body["issuer"] == "alice"
    assert body["issuer_id_hex"] == _ISSUER_ID.hex()


@pytest.mark.asyncio
async def test_decode_offer_rejects_garbage(authed_client) -> None:
    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/decode", json={"offer": "not a real offer"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_decode_offer_requires_auth(client) -> None:
    s = _make_offer_string()
    resp = await client.post("/v1/bolt12/decode", json={"offer": s})
    assert resp.status_code in (401, 403)


# ── /v1/bolt12/offers (POST/GET) ─────────────────────────────────


@pytest.mark.asyncio
async def test_import_offer_creates_row(authed_client) -> None:
    client, _raw, _key_id = authed_client
    s = _make_offer_string(description="beer", amount=2500)

    resp = await client.post("/v1/bolt12/offers", json={"offer": s})
    assert resp.status_code == 201
    body = resp.json()
    assert body["bolt12"] == s
    assert body["description"] == "beer"
    assert body["amount_msat"] == 2500
    assert body["status"] == "active"
    offer_id = body["id"]

    # Idempotent re-import returns the same row at 200 (not 201).
    resp2 = await client.post("/v1/bolt12/offers", json={"offer": s})
    assert resp2.status_code == 200
    assert resp2.json()["id"] == offer_id


@pytest.mark.asyncio
async def test_import_offer_rejects_garbage(authed_client) -> None:
    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/offers", json={"offer": "lno1notreal"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_list_offers_returns_imported(authed_client) -> None:
    client, _raw, _key_id = authed_client
    s1 = _make_offer_string(description="a")
    s2 = _make_offer_string(description="b", amount=99)
    await client.post("/v1/bolt12/offers", json={"offer": s1})
    await client.post("/v1/bolt12/offers", json={"offer": s2})

    resp = await client.get("/v1/bolt12/offers")
    assert resp.status_code == 200
    descs = [o["description"] for o in resp.json()["offers"]]
    assert {"a", "b"} <= set(descs)


@pytest.mark.asyncio
async def test_list_offers_filters_by_status(authed_client) -> None:
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/bolt12/offers", params={"status": "active"})
    assert resp.status_code == 200
    resp = await client.get("/v1/bolt12/offers", params={"status": "bogus"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_get_offer_404(authed_client) -> None:
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/bolt12/offers/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_disable_offer_marks_disabled(authed_client) -> None:
    client, _raw, _key_id = authed_client
    s = _make_offer_string(description="kill-me")
    created = await client.post("/v1/bolt12/offers", json={"offer": s})
    offer_id = created.json()["id"]

    resp = await client.delete(f"/v1/bolt12/offers/{offer_id}")
    assert resp.status_code == 204

    fetched = await client.get(f"/v1/bolt12/offers/{offer_id}")
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "disabled"


@pytest.mark.asyncio
async def test_offer_invoice_listings_empty_for_new_offer(authed_client) -> None:
    client, _raw, _key_id = authed_client
    s = _make_offer_string(description="empty-children")
    created = await client.post("/v1/bolt12/offers", json={"offer": s})
    offer_id = created.json()["id"]

    invreqs = await client.get(f"/v1/bolt12/offers/{offer_id}/invoice-requests")
    assert invreqs.status_code == 200
    assert invreqs.json() == {"invoice_requests": []}

    invoices = await client.get(f"/v1/bolt12/offers/{offer_id}/invoices")
    assert invoices.status_code == 200
    assert invoices.json() == {"invoices": []}


@pytest.mark.asyncio
async def test_import_offer_requires_admin(client, db_session) -> None:
    """A non-admin key may decode but not import offers."""
    from uuid import uuid4

    from app.core.security import generate_api_key, hash_api_key
    from app.models.api_key import APIKey

    raw = generate_api_key()
    api_key = APIKey(
        id=uuid4(),
        name="readonly",
        key_hash=hash_api_key(raw),
        is_admin=False,
        is_active=True,
    )
    db_session.add(api_key)
    await db_session.commit()

    client.headers["Authorization"] = f"Bearer {raw}"

    s = _make_offer_string()
    # Decode endpoint allowed for any authenticated key.
    decode_resp = await client.post("/v1/bolt12/decode", json={"offer": s})
    assert decode_resp.status_code == 200

    # Import endpoint requires admin.
    import_resp = await client.post("/v1/bolt12/offers", json={"offer": s})
    assert import_resp.status_code == 403


# ── /v1/bolt12/status ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_status_reports_disabled_by_default(authed_client) -> None:
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/bolt12/status")
    assert resp.status_code == 200
    body = resp.json()
    # In tests, settings.bolt12_enabled defaults to False.
    assert body["enabled"] is False
    assert body["running"] is False
    assert "target" in body
    assert "last_error" in body


@pytest.mark.asyncio
async def test_status_requires_auth(client) -> None:
    resp = await client.get("/v1/bolt12/status")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_diagnostics_path_snapshot_requires_auth(client) -> None:
    resp = await client.get("/v1/bolt12/diagnostics/path-snapshot")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_diagnostics_path_snapshot_returns_drift_table(authed_client, monkeypatch) -> None:
    """The endpoint mints a probe invoice + returns per-channel
    drift state + per-path policy. With an LND that surfaces a
    3.0x over-claim the response's worst-offender row reflects
    that exactly."""
    from unittest.mock import AsyncMock

    from app.services.lnd_service import lnd_service

    # Stub LND surface: one channel with a 3.0x htlc_max drift.
    monkeypatch.setattr(
        lnd_service,
        "get_channels",
        AsyncMock(
            return_value=(
                [
                    {
                        "chan_id": "abc123",
                        "remote_pubkey": "02_peer",
                        "peer_alias": "Megalithic",
                        "capacity": 60_000,
                        "local_balance": 40_000,
                        "remote_balance": 20_000,
                        "active": True,
                    },
                ],
                None,
            )
        ),
    )
    monkeypatch.setattr(
        lnd_service,
        "get_info",
        AsyncMock(return_value=({"identity_pubkey": "03_ours"}, None)),
    )
    monkeypatch.setattr(
        lnd_service,
        "get_channel_edge",
        AsyncMock(
            return_value=(
                {
                    "node1_pub": "02_peer",
                    "node2_pub": "03_ours",
                    "node1_policy": {"max_htlc_msat": "60000000"},
                    "node2_policy": {"max_htlc_msat": "0"},
                },
                None,
            )
        ),
    )
    # Probe mint returns no paths to keep the test simple.
    monkeypatch.setattr(
        lnd_service,
        "add_blinded_invoice",
        AsyncMock(
            return_value=(
                {"r_hash": "ab" * 32, "blinded_paths": []},
                None,
            )
        ),
    )
    monkeypatch.setattr(
        lnd_service,
        "cancel_invoice",
        AsyncMock(return_value=(True, None)),
    )

    client, _raw, _key_id = authed_client
    resp = await client.get(
        "/v1/bolt12/diagnostics/path-snapshot?amount_msat=3345000",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["amount_msat"] == 3_345_000
    assert body["our_pubkey"] == "03_ours"
    assert body["drift_alert_ratio"] == 1.5
    assert len(body["channels"]) == 1
    row = body["channels"][0]
    assert row["chan_id"] == "abc123"
    assert row["gossiped_inbound_max_htlc_sat"] == 60_000
    assert row["remote_balance_sat"] == 20_000
    assert row["ratio_advertised_to_receivable"] == pytest.approx(3.0, rel=1e-3)


@pytest.mark.asyncio
async def test_diagnostics_path_snapshot_rejects_bad_amount(
    authed_client,
) -> None:
    client, _raw, _key_id = authed_client
    resp = await client.get(
        "/v1/bolt12/diagnostics/path-snapshot?amount_msat=0",
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_metrics_exposes_prometheus_text(authed_client) -> None:
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/bolt12/metrics")
    assert resp.status_code == 200
    body = resp.text
    # Always-present gauges + at least one counter.
    assert "bolt12_runtime_up" in body
    assert "# TYPE bolt12_runtime_up gauge" in body
    assert "bolt12_outbound_invreq_sent_total" in body
    assert "# TYPE bolt12_outbound_invreq_sent_total counter" in body


@pytest.mark.asyncio
async def test_metrics_requires_auth(client) -> None:
    resp = await client.get("/v1/bolt12/metrics")
    assert resp.status_code in (401, 403)


# ── /v1/bolt12/offers/issue ──────────────────────────────────────


@pytest.mark.asyncio
async def test_issue_offer_creates_signed_bech32(authed_client) -> None:
    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/offers/issue",
        json={"description": "hot coffee", "amount_msat": 1500, "issuer": "alice"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["bolt12"].startswith("lno1")
    assert body["description"] == "hot coffee"
    assert body["amount_msat"] == 1500
    assert body["issuer"] == "alice"
    # Wallet-side per-offer issuer key: 33-byte compressed pubkey hex.
    assert isinstance(body["issuer_id_hex"], str)
    assert len(body["issuer_id_hex"]) == 66
    issuer_id = bytes.fromhex(body["issuer_id_hex"])
    assert len(issuer_id) == 33 and issuer_id[0] in (0x02, 0x03)
    assert body["status"] == "active"

    # Round-trip: the encoded string decodes to the same fields.
    decode = await client.post("/v1/bolt12/decode", json={"offer": body["bolt12"]})
    assert decode.status_code == 200
    decoded = decode.json()
    assert decoded["description"] == "hot coffee"
    assert decoded["amount_msat"] == 1500
    assert decoded["issuer_id_hex"] == body["issuer_id_hex"]


@pytest.mark.asyncio
async def test_issue_offer_embeds_offer_paths_when_gateway_present(
    authed_client,
    monkeypatch,
) -> None:
    """Regression: issued offers MUST carry ``offer_paths`` (TLV 16)
    when the gateway has an onion-message-capable peer.

    Without ``offer_paths`` the per-offer ``issuer_id`` is the only
    routing handle; that key is a fresh ephemeral pubkey, never
    gossiped, so payers (CLN, LND, OCEAN's invreq path) fail to
    locate any network address and report 'no address known for
    peer'. This is the exact symptom OCEAN's payout errors showed.
    """
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api

    # Build a fake gateway with one OM-capable peer + a stub blinded-
    # path builder that returns a recognisable byte pattern. The
    # peer's ``address`` must be a non-onion clearnet socket so it
    # passes the introduction-node routability filter — Tor-only and
    # empty addresses are excluded by ``_build_offer_paths_for_issuance``.
    fake_peer = MagicMock()
    fake_peer.node_id = b"\x02" + b"\xaa" * 32
    fake_peer.advertises_onion_messages = True
    fake_peer.address = "1.2.3.4:9735"
    fake_ident = MagicMock()
    fake_ident.peers = (fake_peer,)
    fake_path_bytes = b"\xde\xad\xbe\xef" * 16  # opaque marker (64B)
    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(return_value=fake_ident)
    fake_service._gateway.create_blinded_path = AsyncMock(
        return_value=fake_path_bytes,
    )
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/offers/issue",
        json={"description": "ocean", "amount_msat": 1500},
    )
    assert resp.status_code == 201
    body = resp.json()

    # Decode the offer; the OFFER_PATHS TLV (type 16) must be present
    # and carry our stub bytes verbatim.
    from app.services.bolt12 import decode as decode_bolt12_str

    decoded = decode_bolt12_str(body["bolt12"])
    records = list(decoded.records)
    path_records = [r for r in records if r.type == 16]
    assert len(path_records) == 1, "offer must carry exactly one OFFER_PATHS TLV"
    assert path_records[0].value == fake_path_bytes

    # The blinded-path builder must have been invoked with the
    # gateway's OM-capable peer as the introduction candidate.
    fake_service._gateway.create_blinded_path.assert_awaited_once()
    call_kwargs = fake_service._gateway.create_blinded_path.await_args.kwargs
    assert call_kwargs["introduction_node_candidates"] == (b"\x02" + b"\xaa" * 32,)


@pytest.mark.asyncio
async def test_issue_offer_degrades_when_gateway_has_no_om_peers(
    authed_client,
    monkeypatch,
) -> None:
    """When the gateway exposes zero onion-message-capable peers we
    can't build a blinded path. The issue path still mints the offer
    (so tests + regtest deployments work) but logs a clear warning
    and OMITS the OFFER_PATHS TLV — operators inspecting the offer
    can tell from its absence that the offer is direct-only."""
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api
    from app.services.bolt12 import decode as decode_bolt12_str

    fake_ident = MagicMock()
    fake_ident.peers = ()  # no peers at all → no candidates
    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(return_value=fake_ident)
    fake_service._gateway.create_blinded_path = AsyncMock(
        return_value=b"\x00",  # must NOT be called
    )
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/offers/issue",
        json={"description": "degraded"},
    )
    assert resp.status_code == 201
    decoded = decode_bolt12_str(resp.json()["bolt12"])
    assert all(r.type != 16 for r in decoded.records)
    fake_service._gateway.create_blinded_path.assert_not_awaited()


@pytest.mark.asyncio
async def test_issue_offer_each_call_unique(authed_client) -> None:
    """Two issue calls with identical inputs produce different bolt12 strings
    AND different issuer keys (per-offer unlinkability)."""
    client, _raw, _key_id = authed_client
    body = {"description": "same", "amount_msat": 100}
    r1 = await client.post("/v1/bolt12/offers/issue", json=body)
    r2 = await client.post("/v1/bolt12/offers/issue", json=body)
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["bolt12"] != r2.json()["bolt12"]
    assert r1.json()["id"] != r2.json()["id"]
    assert r1.json()["issuer_id_hex"] != r2.json()["issuer_id_hex"]


@pytest.mark.asyncio
async def test_issue_offer_persists_encrypted_signing_seed(authed_client, db_session) -> None:
    """The issuer signing seed is Fernet-encrypted at rest and round-trips
    to the same pubkey as ``issuer_id_hex``."""
    from sqlalchemy import select

    from app.core.encryption import decrypt_field
    from app.models.bolt12_offer import Bolt12Offer
    from app.services.bolt12 import CoincurveSigner

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/offers/issue",
        json={"description": "keys", "amount_msat": 1},
    )
    assert resp.status_code == 201
    issuer_id_hex = resp.json()["issuer_id_hex"]

    row = (
        await db_session.execute(select(Bolt12Offer).where(Bolt12Offer.bolt12 == resp.json()["bolt12"]))
    ).scalar_one()
    assert row.encrypted_metadata is not None
    seed_hex = decrypt_field(row.encrypted_metadata)
    signer = CoincurveSigner(bytes.fromhex(seed_hex))
    assert signer.public_key.hex() == issuer_id_hex


@pytest.mark.asyncio
async def test_issue_offer_requires_admin(client, db_session) -> None:
    from uuid import uuid4

    from app.core.security import generate_api_key, hash_api_key
    from app.models.api_key import APIKey

    raw = generate_api_key()
    db_session.add(
        APIKey(
            id=uuid4(),
            name="readonly",
            key_hash=hash_api_key(raw),
            is_admin=False,
            is_active=True,
        )
    )
    await db_session.commit()
    client.headers["Authorization"] = f"Bearer {raw}"
    resp = await client.post(
        "/v1/bolt12/offers/issue",
        json={"description": "x"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_issue_offer_validates_inputs(authed_client) -> None:
    client, _raw, _key_id = authed_client
    # Empty description.
    r = await client.post("/v1/bolt12/offers/issue", json={"description": ""})
    assert r.status_code == 422
    # Negative amount.
    r = await client.post(
        "/v1/bolt12/offers/issue",
        json={"description": "x", "amount_msat": -1},
    )
    assert r.status_code == 422
    # Non-alpha currency.
    r = await client.post(
        "/v1/bolt12/offers/issue",
        json={"description": "x", "currency": "US1"},
    )
    assert r.status_code == 422


# ── /v1/bolt12/pay ───────────────────────────────────────────────


@pytest.fixture
def _pay_test_setup(monkeypatch):
    """Wire a fake orchestrator that mints a valid invoice in-process.

    Returns a dict with the recipient signer + offer string for the
    test to drive POST /v1/bolt12/pay against.
    """
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api
    from app.services.bolt12 import (
        CoincurveSigner,
        Invoice,
        InvoiceRequest,
        sign_invoice,
    )
    from app.services.bolt12.codec import Bolt12String
    from app.services.bolt12.tlv import (
        decode_stream as tlv_decode_stream,
    )
    from app.services.bolt12.tlv import (
        encode_stream as tlv_encode_stream,
    )

    # Recipient identity: same key signs the offer (issuer) and the
    # eventual invoice (node_id).
    recipient = CoincurveSigner.generate()

    offer = Offer(
        amount=1500,
        description="coffee",
        issuer="alice",
        issuer_id=recipient.public_key,
    )
    offer_str = Bolt12Codec.encode(offer.to_bolt12_string())

    # Fake gateway identity with one onion-message-capable peer.
    fake_peer = MagicMock()
    fake_peer.node_id = bytes(33)  # placeholder
    fake_peer.advertises_onion_messages = True
    fake_ident = MagicMock()
    fake_ident.peers = (fake_peer,)

    # The fake orchestrator: when `request_invoice` is called, it
    # invokes the builder (so the test path exercises invreq
    # construction + signing), parses the resulting bytes back, and
    # synthesises a signed invoice mirroring the request.
    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(return_value=fake_ident)

    async def _fake_request_invoice(
        *,
        offer,  # noqa: ARG001 — orchestrator passes it; we ignore
        build_invreq,
        destination,
        amount_msat=None,  # noqa: ARG001
        payer_note=None,  # noqa: ARG001
        quantity=None,  # noqa: ARG001
        timeout_seconds=None,  # noqa: ARG001
    ):
        # 1. Run the destination resolver (validates path candidates).
        plan = destination(offer)
        # 2. Drive the builder with a stub reply path.
        from app.services.bolt12.orchestrator import InvreqBuildContext

        invreq_bytes = await build_invreq(
            InvreqBuildContext(
                offer=offer,
                amount_msat=plan.destination.direct_node_id and 1500,
                payer_note=None,
                quantity=None,
                reply_path=b"\x00" * 64,  # opaque placeholder
            )
        )
        # 3. Parse the invreq bytes back, mint + sign an invoice.
        parsed_invreq = InvoiceRequest.parse(Bolt12String(hrp="lnr", records=tlv_decode_stream(invreq_bytes)))
        # Embed synthetic blinded paths so the J2 settlement path can
        # decode them. Real recipients populate ``invoice_paths`` +
        # ``invoice_blindedpay`` via their own LND ``AddInvoice(is_blinded:true)``;
        # we forge minimal valid blobs (one path, one hop) for the
        # test fixture to round-trip through ``decode_invoice_paths``.
        from app.services.bolt12.lnd_paths import encode_invoice_paths

        paths_b, pay_b = encode_invoice_paths(
            [
                {
                    "blinded_path": {
                        "introduction_node": __import__("base64").b64encode(b"\x02" + b"\x11" * 32).decode(),
                        "blinding_point": __import__("base64").b64encode(b"\x03" + b"\x22" * 32).decode(),
                        "blinded_hops": [
                            {
                                "blinded_node": __import__("base64").b64encode(b"\x02" + b"\x33" * 32).decode(),
                                "encrypted_data": __import__("base64").b64encode(b"\x44\x55").decode(),
                            }
                        ],
                    },
                    "base_fee_msat": 1000,
                    "proportional_fee_rate": 100,
                    "total_cltv_delta": 144,
                    "htlc_min_msat": "1",
                    "htlc_max_msat": "1000000000",
                    "features": "",
                }
            ]
        )
        invoice = Invoice(
            invreq=parsed_invreq,
            payment_hash=b"\xab" * 32,
            amount=parsed_invreq.amount,
            node_id=recipient.public_key,
            created_at=1700000000,
            relative_expiry=3600,
            paths=paths_b,
            blindedpay=pay_b,
        )
        signed = sign_invoice(invoice, recipient)
        return tlv_encode_stream(signed.to_records())

    fake_service.request_invoice = _fake_request_invoice

    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )

    # Mock the LND J2 settlement path. Real LND would route over the
    # blinded paths; for the test we synthesise a SUCCEEDED HTLC so
    # the happy-path lands ``status=paid``.
    fake_route = {"hops": [], "total_amt_msat": "1500000"}

    async def _fake_query_routes(
        *,
        amount_msat,
        blinded_payment_paths,
        **_kwargs,
    ):
        # Sanity: the decoder gave us one BlindedPaymentPath.
        assert isinstance(blinded_payment_paths, list)
        assert len(blinded_payment_paths) == 1
        return {"routes": [fake_route], "success_prob": 1.0}, None

    async def _fake_send_to_route(*, payment_hash_hex, route, **_kwargs):
        assert payment_hash_hex == "ab" * 32
        assert route == fake_route
        return {
            "status": "SUCCEEDED",
            "preimage": "cc" * 32,
            "route": route,
        }, None

    from app.services import lnd_service as lnd_mod

    monkeypatch.setattr(
        lnd_mod.lnd_service,
        "query_routes_with_blinded_paths",
        _fake_query_routes,
    )
    monkeypatch.setattr(
        lnd_mod.lnd_service,
        "send_to_route_v2",
        _fake_send_to_route,
    )

    return {
        "offer_str": offer_str,
        "recipient_pubkey_hex": recipient.public_key.hex(),
    }


@pytest.mark.asyncio
async def test_pay_offer_happy_path(authed_client, _pay_test_setup) -> None:
    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/pay",
        json={"offer": _pay_test_setup["offer_str"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["amount_msat"] == 1500
    assert body["payment_hash_hex"] == "ab" * 32
    assert body["node_id_hex"] == _pay_test_setup["recipient_pubkey_hex"]
    # J2 happy path: settlement succeeded → invoice marked paid.
    assert body["status"] == "paid"
    assert body["settlement"]["status"] == "paid"
    assert body["settlement"]["error"] is None
    assert body["invoice_id"] != body["invoice_request_id"]


@pytest.mark.asyncio
async def test_pay_offer_503_when_runtime_disabled(authed_client) -> None:
    """Default test settings have BOLT 12 disabled; pay must 503."""
    client, _raw, _key_id = authed_client
    # Need an offer string that decodes; reuse helper.
    s = _make_offer_string()
    resp = await client.post("/v1/bolt12/pay", json={"offer": s})
    assert resp.status_code == 503
    assert "disabled" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_pay_offer_400_below_offer_amount(authed_client, _pay_test_setup) -> None:
    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/pay",
        json={"offer": _pay_test_setup["offer_str"], "amount_msat": 500},
    )
    assert resp.status_code == 400
    assert "below offer minimum" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_pay_offer_400_for_unreachable_offer(authed_client, monkeypatch) -> None:
    """Offer with neither issuer_id nor paths is rejected before any RPC."""
    from app.api import bolt12 as bolt12_api

    # Stub get_bolt12_service so the codec-level check fires first.
    monkeypatch.setattr(
        bolt12_api, "get_bolt12_service", lambda: (_ for _ in ()).throw(AssertionError("must not be called"))
    )

    bare = Offer(amount=1000, description="bare")
    s = Bolt12Codec.encode(bare.to_bolt12_string())
    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/pay", json={"offer": s})
    assert resp.status_code == 400
    assert "unreachable" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_pay_offer_requires_admin(client, db_session) -> None:
    from uuid import uuid4

    from app.core.security import generate_api_key, hash_api_key
    from app.models.api_key import APIKey

    raw = generate_api_key()
    db_session.add(
        APIKey(
            id=uuid4(),
            name="readonly",
            key_hash=hash_api_key(raw),
            is_admin=False,
            is_active=True,
        )
    )
    await db_session.commit()
    client.headers["Authorization"] = f"Bearer {raw}"
    resp = await client.post(
        "/v1/bolt12/pay",
        json={"offer": _make_offer_string()},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_pay_offer_503_when_gateway_has_no_om_peers(authed_client, monkeypatch) -> None:
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api

    # Empty peer list.
    fake_ident = MagicMock()
    fake_ident.peers = ()
    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(return_value=fake_ident)
    monkeypatch.setattr(bolt12_api, "get_bolt12_service", lambda: fake_service)

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/pay",
        json={"offer": _make_offer_string()},
    )
    assert resp.status_code == 503
    assert "peers" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_pay_offer_504_on_orchestrator_timeout(authed_client, monkeypatch) -> None:
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api
    from app.services.bolt12 import InvoiceRequestTimeoutError

    fake_peer = MagicMock()
    fake_peer.node_id = bytes(33)
    fake_peer.advertises_onion_messages = True
    fake_ident = MagicMock()
    fake_ident.peers = (fake_peer,)
    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(return_value=fake_ident)
    fake_service.request_invoice = AsyncMock(side_effect=InvoiceRequestTimeoutError("no invoice reply within 30.0s"))
    monkeypatch.setattr(bolt12_api, "get_bolt12_service", lambda: fake_service)

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/pay",
        json={"offer": _make_offer_string()},
    )
    assert resp.status_code == 504
    assert "no invoice reply" in resp.json()["detail"].lower()


# ── J2 settlement failure modes ──────────────────────────────────


@pytest.mark.asyncio
async def test_pay_offer_settlement_fails_without_blinded_paths(authed_client, monkeypatch) -> None:
    """An invoice that comes back without invoice_paths /
    invoice_blindedpay cannot be routed via QueryRoutes; the
    settlement step must mark the row FAILED + surface a structured
    error."""
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api
    from app.services.bolt12 import (
        CoincurveSigner,
        Invoice,
        InvoiceRequest,
        sign_invoice,
    )
    from app.services.bolt12.codec import Bolt12String
    from app.services.bolt12.tlv import (
        decode_stream as tlv_decode_stream,
    )
    from app.services.bolt12.tlv import (
        encode_stream as tlv_encode_stream,
    )

    recipient = CoincurveSigner.generate()
    offer = Offer(
        amount=1500,
        description="no-paths",
        issuer_id=recipient.public_key,
    )
    offer_str = Bolt12Codec.encode(offer.to_bolt12_string())

    fake_peer = MagicMock()
    fake_peer.node_id = bytes(33)
    fake_peer.advertises_onion_messages = True
    fake_ident = MagicMock()
    fake_ident.peers = (fake_peer,)
    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(return_value=fake_ident)

    async def _fake_request_invoice(*, offer, build_invreq, destination, **_):
        plan = destination(offer)
        from app.services.bolt12.orchestrator import InvreqBuildContext

        invreq_bytes = await build_invreq(
            InvreqBuildContext(
                offer=offer,
                amount_msat=plan.destination.direct_node_id and 1500,
                payer_note=None,
                quantity=None,
                reply_path=b"\x00" * 64,
            )
        )
        parsed_invreq = InvoiceRequest.parse(Bolt12String(hrp="lnr", records=tlv_decode_stream(invreq_bytes)))
        # Build an invoice WITHOUT paths/blindedpay — J2 must reject.
        inv = Invoice(
            invreq=parsed_invreq,
            payment_hash=b"\xab" * 32,
            amount=parsed_invreq.amount,
            node_id=recipient.public_key,
            created_at=1700000000,
            relative_expiry=3600,
        )
        signed = sign_invoice(inv, recipient)
        return tlv_encode_stream(signed.to_records())

    fake_service.request_invoice = _fake_request_invoice
    monkeypatch.setattr(bolt12_api, "get_bolt12_service", lambda: fake_service)

    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/pay", json={"offer": offer_str})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "failed"
    assert body["settlement"]["status"] == "failed"
    assert "missing blinded paths" in body["settlement"]["error"]


@pytest.mark.asyncio
async def test_pay_offer_settlement_fails_when_route_not_found(
    authed_client,
    _pay_test_setup,
    monkeypatch,
) -> None:
    """QueryRoutes returning an empty routes list must mark FAILED."""
    from app.services import lnd_service as lnd_mod

    async def _no_routes(*, amount_msat, blinded_payment_paths, **_):
        return {"routes": [], "success_prob": 0.0}, None

    monkeypatch.setattr(
        lnd_mod.lnd_service,
        "query_routes_with_blinded_paths",
        _no_routes,
    )

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/pay",
        json={"offer": _pay_test_setup["offer_str"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "failed"
    assert "no routes" in body["settlement"]["error"].lower()


@pytest.mark.asyncio
async def test_pay_offer_settlement_fails_when_htlc_fails(
    authed_client,
    _pay_test_setup,
    monkeypatch,
) -> None:
    """SendToRouteV2 returning a FAILED HTLC must mark the row FAILED
    with the LND failure code threaded into ``error_message``."""
    from app.services import lnd_service as lnd_mod

    async def _failed_htlc(*, payment_hash_hex, route, **_):
        return {
            "status": "FAILED",
            "failure": {"code": "INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS"},
        }, None

    monkeypatch.setattr(
        lnd_mod.lnd_service,
        "send_to_route_v2",
        _failed_htlc,
    )

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/pay",
        json={"offer": _pay_test_setup["offer_str"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "failed"
    assert "INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS" in body["settlement"]["error"]


# ── /v1/bolt12/receive + /offers/{id}/set-default ────────────────


@pytest.mark.asyncio
async def test_receive_creates_default_offer_on_first_call(authed_client) -> None:
    """First GET mints a fresh default offer; subsequent GETs return the same one."""
    client, _raw, _key_id = authed_client

    r1 = await client.get("/v1/bolt12/receive")
    assert r1.status_code == 200
    body1 = r1.json()
    assert body1["offer"]["bolt12"].startswith("lno1")
    assert body1["offer"]["is_default_receive"] is True
    assert body1["offer"]["status"] == "active"
    assert body1["offer"]["amount_msat"] is None
    assert body1["offer"]["source"] == "issued"
    # Side-channel context fields exist (may be best-effort null on
    # unit-test environments without LND).
    assert "inbound_liquidity" in body1
    assert "runtime" in body1
    assert isinstance(body1["warnings"], list)

    r2 = await client.get("/v1/bolt12/receive")
    assert r2.status_code == 200
    assert r2.json()["offer"]["id"] == body1["offer"]["id"]
    assert r2.json()["offer"]["bolt12"] == body1["offer"]["bolt12"]


@pytest.mark.asyncio
async def test_default_receive_offer_embeds_offer_paths(
    authed_client,
    monkeypatch,
) -> None:
    """Regression: the auto-minted default receive offer (used for
    OCEAN payouts) MUST carry ``offer_paths``. The original OCEAN
    failure was a default offer minted without paths → CLN reported
    'no address known for peer' on the per-offer issuer_id."""
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api
    from app.services.bolt12 import decode as decode_bolt12_str

    fake_peer = MagicMock()
    fake_peer.node_id = b"\x02" + b"\xbb" * 32
    fake_peer.advertises_onion_messages = True
    # Clearnet socket — required by the routability filter introduced
    # alongside the OCEAN unreachability fix.
    fake_peer.address = "5.6.7.8:9735"
    fake_ident = MagicMock()
    fake_ident.peers = (fake_peer,)
    fake_path_bytes = b"\xca\xfe\xba\xbe" * 16
    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(return_value=fake_ident)
    fake_service._gateway.create_blinded_path = AsyncMock(
        return_value=fake_path_bytes,
    )
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )

    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/bolt12/receive")
    assert resp.status_code == 200
    offer_str = resp.json()["offer"]["bolt12"]
    decoded = decode_bolt12_str(offer_str)
    paths = [r for r in decoded.records if r.type == 16]
    assert len(paths) == 1
    assert paths[0].value == fake_path_bytes


class _StubGateway:
    """Hand-rolled fake to capture ``connect_peer`` invocations.

    AsyncMock would suffice but we want to record positional vs
    keyword args explicitly and let individual tests configure the
    ``connect_peer`` return value or side-effect.

    A successful ``connect_peer`` call adds the dialed node to the
    set returned by subsequent ``get_identity`` calls so the BOLT 1
    init-handshake wait in ``_connect_well_known_payer`` short-
    circuits immediately. Set ``simulate_no_om_after_connect=True``
    in a test to model the failure mode where the dial completes but
    the peer never advertises onion messages.
    """

    def __init__(self) -> None:
        from unittest.mock import MagicMock

        # Seed with one OM-capable peer so unconfigured tests still
        # get a valid introduction-node candidate when they don't
        # exercise ``connect_peer`` themselves.
        seed = MagicMock()
        seed.node_id = b"\x02" + b"\xbb" * 32
        seed.advertises_onion_messages = True
        seed.address = "1.2.3.4:9735"
        # Mutable list so ``connect_peer`` can append fresh peers.
        self._peers: list[Any] = [seed]
        # Tests set ``connect_peer_calls`` to inspect what was dialed.
        self.connect_peer_calls: list[dict[str, bytes | str]] = []
        self.connect_peer_should_raise: Exception | None = None
        self.connect_peer_already_connected = False
        # When True, ``connect_peer`` records the call but does NOT
        # add an OM-capable peer to ``get_identity``. Mirrors the
        # production failure mode where the BOLT 1 init handshake
        # never lands (peer is unreachable, doesn't advertise OM,
        # etc.) — the wait helper will time out in that case.
        self.simulate_no_om_after_connect: bool = False
        # Records each ``set_sticky_peers`` call. Each entry is the
        # tuple of (node_id, address) pairs that was pushed.
        self.set_sticky_peers_calls: list[tuple[tuple[bytes, str], ...]] = []

        async def _get_identity():
            ident = MagicMock()
            # Snapshot so a peer appended mid-poll doesn't break the
            # caller's iteration.
            ident.peers = tuple(self._peers)
            return ident

        self.get_identity = _get_identity

        async def _create_blinded_path(*args, **kwargs):
            return b"\xca\xfe\xba\xbe" * 16

        self.create_blinded_path = _create_blinded_path

        async def _connect_peer(*, node_id: bytes, address: str):
            self.connect_peer_calls.append(
                {"node_id": node_id, "address": address},
            )
            if self.connect_peer_should_raise is not None:
                raise self.connect_peer_should_raise
            if not self.simulate_no_om_after_connect:
                # Model a healthy handshake: the dialed peer now
                # appears in ``get_identity`` advertising OM.
                new_peer = MagicMock()
                new_peer.node_id = node_id
                new_peer.address = address
                new_peer.advertises_onion_messages = True
                # De-dup on node_id so re-dials don't grow the list.
                self._peers = [p for p in self._peers if p.node_id != node_id] + [new_peer]
            from unittest.mock import MagicMock as _MM

            r = _MM()
            r.already_connected = self.connect_peer_already_connected
            return r

        self.connect_peer = _connect_peer

        async def _set_sticky_peers(peers):
            entry = tuple((p.node_id, p.address) for p in peers)
            self.set_sticky_peers_calls.append(entry)
            from unittest.mock import MagicMock as _MM

            r = _MM()
            r.sticky_count = len(entry)
            return r

        self.set_sticky_peers = _set_sticky_peers


@pytest.mark.asyncio
async def test_configure_receive_with_ocean_description_auto_peers(
    authed_client,
    monkeypatch,
) -> None:
    """OCEAN-prefixed description should trigger a ``connect_peer``
    dial to OCEAN's documented LN node before the offer paths are
    built. Regression for the OCEAN-payouts unreachability issue."""
    from app.api import bolt12 as bolt12_api
    from app.services.bolt12.well_known_payers import WELL_KNOWN_PAYERS

    stub_gateway = _StubGateway()
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    # Force mainnet so the OCEAN mainnet_only entry matches.
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_auto_peer_well_known_payers",
        True,
    )

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/receive/configure",
        json={"description": "OCEAN Payouts for bc1qtestaddress"},
    )
    assert resp.status_code == 200

    # Exactly one connect_peer call to OCEAN's node.
    assert len(stub_gateway.connect_peer_calls) == 1
    call = stub_gateway.connect_peer_calls[0]
    ocean_entry = next(p for p in WELL_KNOWN_PAYERS if p.label == "OCEAN")
    assert call["node_id"] == bytes.fromhex(ocean_entry.node_id_hex)
    assert call["address"] == ocean_entry.address


@pytest.mark.asyncio
async def test_configure_receive_triggers_sticky_peer_refresh(
    authed_client,
    db_engine,
    monkeypatch,
) -> None:
    """After a successful OCEAN configure, the sticky-peer reconciler
    must be triggered out-of-band so the on-disconnect handler in the
    Rust gateway is watching the new peer *immediately* — not after
    the next periodic reconciler tick (which is up to 30 s away).

    Without this, an OCEAN reconnect lost in the post-configure
    window would have no auto-redial, since the Rust loop only acts
    on peers in the sticky set.
    """
    from contextlib import asynccontextmanager
    from unittest.mock import AsyncMock, MagicMock

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.api import bolt12 as bolt12_api
    from app.services.bolt12 import runtime as bolt12_runtime
    from app.services.bolt12 import sticky_peer_reconciler as sticky_recon

    stub_gateway = _StubGateway()
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_auto_peer_well_known_payers",
        True,
    )
    # ``refresh_sticky_set`` guards on these — the helper no-ops
    # when BOLT 12 isn't configured (matching the production guard
    # in ``start_reconciler``).
    monkeypatch.setattr(bolt12_api.settings, "bolt12_enabled", True)
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_gateway_grpc",
        "localhost:9999",
    )

    # The reconciler reads the DB via ``get_db_context()`` — its own
    # engine-creation path doesn't accept the test fixture's
    # sqlite-StaticPool config. Route it through the same in-memory
    # engine the test FastAPI app uses.
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    @asynccontextmanager
    async def _test_db_ctx():
        async with session_factory() as session:
            yield session

    monkeypatch.setattr(sticky_recon, "get_db_context", _test_db_ctx)

    # Patch the runtime client (used by ``refresh_sticky_set`` via
    # the reconciler) to a separate MagicMock so we can assert that
    # ``set_sticky_peers`` was called with the OCEAN entry.
    fake_client = MagicMock()
    fake_client.set_sticky_peers = AsyncMock(
        return_value=MagicMock(sticky_count=1),
    )
    monkeypatch.setattr(bolt12_runtime._runtime, "client", fake_client)

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/receive/configure",
        json={"description": "OCEAN Payouts for bc1qtestaddress"},
    )
    assert resp.status_code == 200

    fake_client.set_sticky_peers.assert_awaited_once()
    pushed = fake_client.set_sticky_peers.await_args.args[0]
    # Pushed set = bootstrap OM peers (always present on mainnet) +
    # OCEAN (the well-known payer matched by the configure
    # description). Verify the OCEAN entry is present with the
    # expected address — the bootstrap entries are covered
    # separately by ``test_bolt12_well_known_payers``.
    from app.services.bolt12.well_known_payers import (
        BOOTSTRAP_OM_PEERS,
        WELL_KNOWN_PAYERS,
    )

    ocean_entry = next(p for p in WELL_KNOWN_PAYERS if p.label == "OCEAN")
    expected_count = 1 + sum(
        1
        for b in BOOTSTRAP_OM_PEERS
        if b.mainnet_only or True  # mainnet
    )
    assert len(pushed) == expected_count, (
        f"OCEAN configure must push OCEAN + {expected_count - 1} bootstrap peer(s); got {len(pushed)}"
    )
    ocean_pushed = [p for p in pushed if p.node_id == bytes.fromhex(ocean_entry.node_id_hex)]
    assert len(ocean_pushed) == 1, "OCEAN entry must be in the pushed set"
    assert ocean_pushed[0].address == ocean_entry.address


@pytest.mark.asyncio
async def test_configure_receive_non_ocean_description_skips_auto_peer(
    authed_client,
    monkeypatch,
) -> None:
    """A generic description (no well-known prefix) must NOT dial any
    external peer — the auto-peer is opt-in via the documented payer
    formats and should never fire for arbitrary user input."""
    from app.api import bolt12 as bolt12_api

    stub_gateway = _StubGateway()
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_auto_peer_well_known_payers",
        True,
    )

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/receive/configure",
        json={"description": "Payouts for alice@example.com"},
    )
    assert resp.status_code == 200
    assert stub_gateway.connect_peer_calls == []


@pytest.mark.asyncio
async def test_configure_receive_auto_peer_disabled_skips_dial(
    authed_client,
    monkeypatch,
) -> None:
    """Setting ``bolt12_auto_peer_well_known_payers=False`` must
    suppress the dial even when the description matches OCEAN's
    prefix. Operators who want full control over their peer set
    rely on this kill switch."""
    from app.api import bolt12 as bolt12_api

    stub_gateway = _StubGateway()
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_auto_peer_well_known_payers",
        False,
    )

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/receive/configure",
        json={"description": "OCEAN Payouts for bc1qtestaddress"},
    )
    assert resp.status_code == 200
    assert stub_gateway.connect_peer_calls == []


def _mock_bolt12_runtime_running(monkeypatch) -> None:
    """Patch the BOLT 12 runtime state to ``running=True`` so the
    receive-panel warning block (which is gated on ``running``)
    actually fires. The OM-peer warning lives behind that gate, so
    tests that want to assert against it have to opt in."""
    from unittest.mock import MagicMock

    import app.services.bolt12.runtime as bolt12_runtime

    fake_state = MagicMock()
    fake_state.enabled = True
    fake_state.running = True
    fake_state.consecutive_probe_failures = 0
    fake_state.last_probe_at = None
    fake_state.last_error = None
    fake_state.permanently_disabled = False
    monkeypatch.setattr(
        bolt12_runtime,
        "get_bolt12_runtime_state",
        lambda: fake_state,
    )


@pytest.mark.asyncio
async def test_configure_receive_waits_for_init_handshake(
    authed_client,
    monkeypatch,
) -> None:
    """After ``connect_peer`` returns, the BOLT 1 init handshake (which
    populates the peer's ``advertises_onion_messages`` flag) lands
    asynchronously. ``_connect_well_known_payer`` MUST wait for the
    handshake to surface in subsequent ``get_identity`` calls before
    returning — otherwise the receive panel warnings + offer-path
    builder both observe a stale "no OM peer" state and the user sees
    the same no-peer warning they expected the configure to clear.

    The stub gateway models a healthy handshake: after a successful
    ``connect_peer``, the dialed peer appears in ``get_identity``
    advertising OM. Pin that the warning code is NOT in the response.
    """
    from app.api import bolt12 as bolt12_api

    stub_gateway = _StubGateway()
    # Empty seed so the only OM-capable peer is the one auto-peer
    # adds — otherwise the seeded peer would mask the bug we're
    # regression-testing.
    stub_gateway._peers = []
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_auto_peer_well_known_payers",
        True,
    )
    # Suppress the payer-node intro exclusion for THIS test: we're
    # specifically asserting the BOLT 1 init handshake wait, which
    # is orthogonal to whether OCEAN is allowed as the intro. With
    # the exclusion in place the receive panel would (correctly)
    # surface the no-OM-peer warning because the only OM peer in
    # this stub is OCEAN itself.
    monkeypatch.setattr(
        bolt12_api,
        "well_known_payer_node_ids",
        lambda *, network: frozenset(),
    )
    _mock_bolt12_runtime_running(monkeypatch)

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/receive/configure",
        json={"description": "OCEAN Payouts for bc1qtestaddress"},
    )
    assert resp.status_code == 200
    body = resp.json()
    codes = [w["code"] for w in body.get("warnings", [])]
    assert "no_publicly_routable_om_peer" not in codes, (
        "after a successful OCEAN auto-peer + BOLT 1 init handshake, "
        "the receive panel must not surface the no-OM-peer warning"
    )
    # Sanity: the dial was attempted, and the post-dial wait succeeded.
    assert len(stub_gateway.connect_peer_calls) == 1


@pytest.mark.asyncio
async def test_configure_receive_handshake_timeout_keeps_warning(
    authed_client,
    monkeypatch,
) -> None:
    """When the BOLT 1 init handshake never lands (peer is reachable
    via TCP but doesn't complete the feature exchange), the wait helper
    must return False after its timeout and the request must STILL
    complete (the offer is issued without ``offer_paths`` and the
    receive panel surfaces the no-OM-peer warning honestly — better
    than the pre-fix silent failure).

    A bounded test-only timeout keeps the test fast; the production
    default is 5 s.
    """
    from app.api import bolt12 as bolt12_api

    stub_gateway = _StubGateway()
    # Model the failure: connect_peer succeeds, but no OM-capable peer
    # ever appears for the dialed node_id.
    stub_gateway.simulate_no_om_after_connect = True
    stub_gateway._peers = []
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_auto_peer_well_known_payers",
        True,
    )
    _mock_bolt12_runtime_running(monkeypatch)
    # Cap the wait to a sub-second budget so the test stays fast.
    monkeypatch.setattr(
        bolt12_api,
        "_AUTO_PEER_HANDSHAKE_WAIT_S",
        0.3,
    )
    monkeypatch.setattr(
        bolt12_api,
        "_AUTO_PEER_POLL_INTERVAL_S",
        0.05,
    )

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/receive/configure",
        json={"description": "OCEAN Payouts for bc1qtestaddress"},
    )
    # The endpoint still returns 200 — the wait timeout is non-fatal.
    assert resp.status_code == 200
    body = resp.json()
    # Without an OM-capable peer the warning must be present so the
    # dashboard renders the "Connect a public node" CTA.
    codes = [w["code"] for w in body.get("warnings", [])]
    assert "no_publicly_routable_om_peer" in codes, (
        "with no OM-capable peer the receive panel must surface the "
        "no_publicly_routable_om_peer warning so the dashboard can "
        "render the Connect CTA"
    )


@pytest.mark.asyncio
async def test_auto_peer_endpoint_waits_for_init_handshake(
    authed_client,
    monkeypatch,
) -> None:
    """The /receive/auto-peer endpoint (driven by the dashboard's
    Connect button) must also wait for the BOLT 1 init handshake
    before returning. Without the wait, the dashboard's follow-up
    ``fetchBolt12Receive`` call lands before the peer's OM flag is
    set, re-rendering the same no-OM warning the user just clicked
    Connect to clear."""
    from app.api import bolt12 as bolt12_api

    stub_gateway = _StubGateway()
    # Empty seed so the only OM-capable peer is the one we dial.
    stub_gateway._peers = []
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")
    # See ``test_configure_receive_waits_for_init_handshake`` for
    # the rationale — neutralise the payer-node intro exclusion so
    # the dialed peer (OCEAN) counts as a valid intro for this
    # handshake-timing test.
    monkeypatch.setattr(
        bolt12_api,
        "well_known_payer_node_ids",
        lambda *, network: frozenset(),
    )
    # See ``test_configure_receive_waits_for_init_handshake`` for
    # the rationale — neutralise the payer-node intro exclusion so
    # the dialed peer (OCEAN) counts as a valid intro for this
    # handshake-timing test.
    monkeypatch.setattr(
        bolt12_api,
        "well_known_payer_node_ids",
        lambda *, network: frozenset(),
    )
    _mock_bolt12_runtime_running(monkeypatch)

    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/receive/auto-peer")
    assert resp.status_code == 200
    body = resp.json()
    assert body["connected"] is True
    # A follow-up GET /receive must reflect the freshly-dialed peer as
    # OM-capable (warning gone). This is the cross-endpoint invariant
    # the dashboard relies on.
    get_resp = await client.get("/v1/bolt12/receive")
    assert get_resp.status_code == 200
    codes = [w["code"] for w in get_resp.json().get("warnings", [])]
    assert "no_publicly_routable_om_peer" not in codes, (
        "after /receive/auto-peer succeeds, /receive must not surface "
        "the no-OM-peer warning — the post-dial wait should have let "
        "the BOLT 1 init handshake complete first"
    )


@pytest.mark.asyncio
async def test_configure_receive_auto_peer_failure_does_not_block_issuance(
    authed_client,
    monkeypatch,
) -> None:
    """A failed dial (network error, OCEAN node unreachable) must NOT
    fail offer creation. The auto-peer is a best-effort optimisation;
    the offer can still route via other peers."""
    from app.api import bolt12 as bolt12_api

    stub_gateway = _StubGateway()
    stub_gateway.connect_peer_should_raise = ConnectionError(
        "simulated dial failure",
    )
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_auto_peer_well_known_payers",
        True,
    )

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/receive/configure",
        json={"description": "OCEAN Payouts for bc1qtestaddress"},
    )
    assert resp.status_code == 200
    # The dial was attempted exactly once.
    assert len(stub_gateway.connect_peer_calls) == 1


@pytest.mark.asyncio
async def test_offer_paths_skip_tor_only_peers(
    authed_client,
    monkeypatch,
) -> None:
    """Peers whose recorded ``socket_address`` is ``.onion`` or empty
    must be excluded from the introduction-node candidate set, even
    when they advertise onion-message support. Otherwise public-
    network payers (CLN, LDK) abort with "no address known for peer"
    before the round-trip starts."""
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api

    # Mix: one Tor-only OM-capable peer, one empty-address OM-capable
    # peer, and one clearnet OM-capable peer. The clearnet peer is
    # the only one that should make it into the candidate set passed
    # to ``create_blinded_path``.
    tor_peer = MagicMock()
    tor_peer.node_id = b"\x02" + b"\xaa" * 32
    tor_peer.advertises_onion_messages = True
    tor_peer.address = "voibgcjsapdylerigku4gdpmu6sdb5x32b4p3bddtzr52endivdacoad.onion:9735"

    empty_peer = MagicMock()
    empty_peer.node_id = b"\x02" + b"\xbb" * 32
    empty_peer.advertises_onion_messages = True
    empty_peer.address = ""

    public_peer = MagicMock()
    public_peer.node_id = b"\x02" + b"\xcc" * 32
    public_peer.advertises_onion_messages = True
    public_peer.address = "1.2.3.4:9735"

    fake_ident = MagicMock()
    fake_ident.peers = (tor_peer, empty_peer, public_peer)
    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(return_value=fake_ident)
    fake_service._gateway.create_blinded_path = AsyncMock(
        return_value=b"\xab" * 32,
    )
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )

    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/bolt12/receive")
    assert resp.status_code == 200

    # Exactly one create_blinded_path call, with only the clearnet
    # peer in the candidates.
    fake_service._gateway.create_blinded_path.assert_called_once()
    call = fake_service._gateway.create_blinded_path.call_args
    candidates = call.kwargs["introduction_node_candidates"]
    assert candidates == (public_peer.node_id,)


@pytest.mark.asyncio
async def test_offer_paths_none_when_only_tor_peers(
    authed_client,
    monkeypatch,
) -> None:
    """When every onion-message-capable peer is Tor-only, the path
    builder returns ``None`` so the offer is issued without
    ``offer_paths`` (and the dashboard surfaces the warning). The
    blinded-path RPC must NOT be called with an empty candidate
    set."""
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api

    tor_peer = MagicMock()
    tor_peer.node_id = b"\x02" + b"\xdd" * 32
    tor_peer.advertises_onion_messages = True
    tor_peer.address = "abc.onion:9735"

    fake_ident = MagicMock()
    fake_ident.peers = (tor_peer,)
    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(return_value=fake_ident)
    fake_service._gateway.create_blinded_path = AsyncMock(
        return_value=b"\xff" * 32,
    )
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )

    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/bolt12/receive")
    assert resp.status_code == 200
    # The path builder bailed before calling create_blinded_path.
    fake_service._gateway.create_blinded_path.assert_not_called()


@pytest.mark.asyncio
async def test_receive_panel_emits_no_routable_om_peer_warning(
    authed_client,
    monkeypatch,
) -> None:
    """The receive panel must include a ``no_publicly_routable_om_peer``
    warning when the gateway is running but has no OM-capable peer
    with a clearnet address. The dashboard renders the warning with
    a "Connect to a public node" CTA."""
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api

    tor_peer = MagicMock()
    tor_peer.node_id = b"\x02" + b"\xdd" * 32
    tor_peer.advertises_onion_messages = True
    tor_peer.address = "abc.onion:9735"

    fake_ident = MagicMock()
    fake_ident.peers = (tor_peer,)
    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(return_value=fake_ident)
    fake_service._gateway.create_blinded_path = AsyncMock(
        return_value=b"\xff" * 32,
    )
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )

    # The runtime probe needs to report ``running: True`` for the
    # check to run.
    fake_state = MagicMock()
    fake_state.enabled = True
    fake_state.running = True
    fake_state.consecutive_probe_failures = 0
    fake_state.last_probe_at = None
    fake_state.last_error = None
    fake_state.permanently_disabled = False
    import app.services.bolt12.runtime as bolt12_runtime

    monkeypatch.setattr(
        bolt12_runtime,
        "get_bolt12_runtime_state",
        lambda: fake_state,
    )

    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/bolt12/receive")
    assert resp.status_code == 200
    body = resp.json()
    codes = [w["code"] for w in body["warnings"]]
    assert "no_publicly_routable_om_peer" in codes


@pytest.mark.asyncio
async def test_receive_panel_no_routable_warning_when_runtime_offline(
    authed_client,
    monkeypatch,
) -> None:
    """When the gateway runtime isn't running the routability check
    is skipped — ``gateway_offline`` already covers the user-facing
    story and we don't want to double-warn."""
    from unittest.mock import MagicMock

    from fastapi import HTTPException as _HE

    import app.services.bolt12.runtime as bolt12_runtime
    from app.api import bolt12 as bolt12_api

    # Force ``get_bolt12_service`` to raise 503 so the routability
    # probe takes the "runtime not reachable" branch.
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: (_ for _ in ()).throw(_HE(status_code=503, detail="off")),
    )

    fake_state = MagicMock()
    fake_state.enabled = True
    fake_state.running = False
    fake_state.consecutive_probe_failures = 0
    fake_state.last_probe_at = None
    fake_state.last_error = None
    fake_state.permanently_disabled = False
    monkeypatch.setattr(
        bolt12_runtime,
        "get_bolt12_runtime_state",
        lambda: fake_state,
    )

    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/bolt12/receive")
    assert resp.status_code == 200
    codes = [w["code"] for w in resp.json()["warnings"]]
    assert "no_publicly_routable_om_peer" not in codes


@pytest.mark.asyncio
async def test_auto_peer_endpoint_connects_first_payer(
    authed_client,
    monkeypatch,
) -> None:
    """``POST /v1/bolt12/receive/auto-peer`` should dial the first
    registry entry and return ``connected: true`` when the dial
    succeeds."""
    from app.api import bolt12 as bolt12_api
    from app.services.bolt12.well_known_payers import WELL_KNOWN_PAYERS

    stub_gateway = _StubGateway()
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")

    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/receive/auto-peer")
    assert resp.status_code == 200
    body = resp.json()
    assert body["connected"] is True
    assert body["peer"]["label"] == "OCEAN"
    ocean = next(p for p in WELL_KNOWN_PAYERS if p.label == "OCEAN")
    assert body["peer"]["node_id_hex"] == ocean.node_id_hex
    assert body["peer"]["already_connected"] is False
    # Exactly one attempt was recorded.
    assert len(body["attempts"]) == 1


@pytest.mark.asyncio
async def test_auto_peer_endpoint_reports_failure_when_all_dials_fail(
    authed_client,
    monkeypatch,
) -> None:
    """When every registry entry's dial errors, the endpoint must
    return ``connected: false`` with the per-attempt errors so the
    dashboard can render a friendly retry message instead of crashing
    on a missing field."""
    from app.api import bolt12 as bolt12_api

    stub_gateway = _StubGateway()
    stub_gateway.connect_peer_should_raise = ConnectionError(
        "simulated dial failure",
    )
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")

    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/receive/auto-peer")
    assert resp.status_code == 200
    body = resp.json()
    assert body["connected"] is False
    assert body["peer"] is None
    assert len(body["attempts"]) >= 1
    # The per-attempt failure detail is preserved (so logs / audits
    # can see what went wrong).
    assert "simulated dial failure" in body["attempts"][0]["error"]


@pytest.mark.asyncio
async def test_auto_peer_endpoint_returns_503_when_gateway_offline(
    authed_client,
    monkeypatch,
) -> None:
    """The endpoint depends on the gateway runtime to do the dial.
    When the runtime isn't up, return 503 so the dashboard surfaces
    a clear "gateway offline" message rather than reporting a stale
    "no peer connected"."""
    from fastapi import HTTPException as _HE

    from app.api import bolt12 as bolt12_api

    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: (_ for _ in ()).throw(_HE(status_code=503, detail="runtime offline")),
    )

    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/receive/auto-peer")
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_auto_peer_endpoint_skips_mainnet_payers_on_regtest(
    authed_client,
    monkeypatch,
) -> None:
    """Mainnet-only registry entries must not be dialled when the
    wallet is configured for testnet/signet/regtest. Today that means
    a regtest deployment hitting the endpoint returns
    ``connected: false`` with an empty attempts list (since OCEAN is
    the only seed entry and it's mainnet-only)."""
    from app.api import bolt12 as bolt12_api

    stub_gateway = _StubGateway()
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "regtest")

    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/receive/auto-peer")
    assert resp.status_code == 200
    body = resp.json()
    assert body["connected"] is False
    assert body["peer"] is None
    # OCEAN is mainnet-only — skipped → zero attempts recorded.
    assert body["attempts"] == []


@pytest.mark.asyncio
async def test_configure_receive_auto_peer_skipped_on_regtest(
    authed_client,
    monkeypatch,
) -> None:
    """OCEAN's pubkey is mainnet-only — a regtest wallet must not try
    to dial it even when the description prefix matches. Otherwise
    every regtest dev hits a spurious dial to a mainnet IP."""
    from app.api import bolt12 as bolt12_api

    stub_gateway = _StubGateway()
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "regtest")
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_auto_peer_well_known_payers",
        True,
    )

    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/receive/configure",
        json={"description": "OCEAN Payouts for bcrt1qtestaddress"},
    )
    assert resp.status_code == 200
    assert stub_gateway.connect_peer_calls == []


@pytest.mark.asyncio
async def test_receive_requires_admin(client, db_session) -> None:
    from uuid import uuid4

    from app.core.security import generate_api_key, hash_api_key
    from app.models.api_key import APIKey

    raw = generate_api_key()
    db_session.add(
        APIKey(
            id=uuid4(),
            name="readonly",
            key_hash=hash_api_key(raw),
            is_admin=False,
            is_active=True,
        )
    )
    await db_session.commit()
    client.headers["Authorization"] = f"Bearer {raw}"
    resp = await client.get("/v1/bolt12/receive")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_set_default_receive_promotes_existing_offer(authed_client) -> None:
    """Promoting a different issued offer demotes the previous default."""
    client, _raw, _key_id = authed_client

    # Auto-mint the first default.
    first = (await client.get("/v1/bolt12/receive")).json()["offer"]
    # Mint a second one-shot offer via the legacy issue route.
    second = (
        await client.post(
            "/v1/bolt12/offers/issue",
            json={"description": "another", "amount_msat": 100},
        )
    ).json()
    assert second["is_default_receive"] is False

    # Promote the second to default.
    promote = await client.post(f"/v1/bolt12/offers/{second['id']}/set-default")
    assert promote.status_code == 200
    assert promote.json()["is_default_receive"] is True
    assert promote.json()["id"] == second["id"]

    # /receive now returns the second offer; the first is no longer default.
    rcv = (await client.get("/v1/bolt12/receive")).json()["offer"]
    assert rcv["id"] == second["id"]
    assert rcv["is_default_receive"] is True

    # Confirm the previous default got demoted (only one row may
    # have the flag for a given API key).
    listing = await client.get("/v1/bolt12/offers?source=issued")
    rows = {o["id"]: o for o in listing.json()["offers"]}
    assert rows[first["id"]]["is_default_receive"] is False
    assert rows[second["id"]]["is_default_receive"] is True


@pytest.mark.asyncio
async def test_set_default_rejects_imported_offers(authed_client) -> None:
    """Only ``source=ISSUED`` offers may be promoted to default."""
    client, _raw, _key_id = authed_client
    s = _make_offer_string(description="imported", amount=100)
    imported = (await client.post("/v1/bolt12/offers", json={"offer": s})).json()
    resp = await client.post(f"/v1/bolt12/offers/{imported['id']}/set-default")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_set_default_unknown_offer_returns_404(authed_client) -> None:
    from uuid import uuid4

    client, _raw, _key_id = authed_client
    resp = await client.post(f"/v1/bolt12/offers/{uuid4()}/set-default")
    assert resp.status_code == 404


# ── /v1/bolt12/receive/configure ─────────────────────────────────


@pytest.mark.asyncio
async def test_configure_receive_replaces_description(authed_client) -> None:
    """Configuring mints a new offer with the requested description and
    demotes the previous default."""
    client, _raw, _key_id = authed_client

    # Bootstrap the auto-minted default.
    first = (await client.get("/v1/bolt12/receive")).json()["offer"]
    assert "configure" in (first["description"] or "").lower()

    # Configure for Ocean.
    addr = "bc1qexampleexampleexampleexampleexampl"
    desc = f"OCEAN Payouts for {addr}"
    resp = await client.post(
        "/v1/bolt12/receive/configure",
        json={"description": desc},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["offer"]["is_default_receive"] is True
    assert body["offer"]["description"] == desc
    assert body["offer"]["id"] != first["id"]
    # The bech32 string must change because the description is part
    # of the signed offer payload.
    assert body["offer"]["bolt12"] != first["bolt12"]

    # /receive now returns the new offer.
    rcv = (await client.get("/v1/bolt12/receive")).json()["offer"]
    assert rcv["id"] == body["offer"]["id"]
    assert rcv["description"] == desc

    # The previous default is demoted but still present.
    listing = (await client.get("/v1/bolt12/offers?source=issued")).json()["offers"]
    by_id = {o["id"]: o for o in listing}
    assert by_id[first["id"]]["is_default_receive"] is False
    assert by_id[body["offer"]["id"]]["is_default_receive"] is True


@pytest.mark.asyncio
async def test_configure_receive_validates_description(authed_client) -> None:
    client, _raw, _key_id = authed_client
    # Missing field.
    r = await client.post("/v1/bolt12/receive/configure", json={})
    assert r.status_code == 422
    # Empty after strip.
    r = await client.post("/v1/bolt12/receive/configure", json={"description": "   "})
    assert r.status_code == 422
    # Too long.
    r = await client.post("/v1/bolt12/receive/configure", json={"description": "x" * 641})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_configure_receive_requires_admin(client, db_session) -> None:
    from uuid import uuid4

    from app.core.security import generate_api_key, hash_api_key
    from app.models.api_key import APIKey

    raw = generate_api_key()
    db_session.add(
        APIKey(
            id=uuid4(),
            name="readonly",
            key_hash=hash_api_key(raw),
            is_admin=False,
            is_active=True,
        )
    )
    await db_session.commit()
    client.headers["Authorization"] = f"Bearer {raw}"
    resp = await client.post("/v1/bolt12/receive/configure", json={"description": "x"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_disable_default_clears_default_flag(authed_client) -> None:
    """Disabling the default receive offer must clear ``is_default_receive``
    so that ``GET /v1/bolt12/receive`` mints a fresh offer instead of
    reviving the disabled one."""
    client, _raw, _key_id = authed_client

    first = (await client.get("/v1/bolt12/receive")).json()["offer"]
    assert first["is_default_receive"] is True

    r = await client.delete(f"/v1/bolt12/offers/{first['id']}")
    assert r.status_code == 204

    # Next /receive call must mint a *new* default, not revive the
    # disabled one.
    second = (await client.get("/v1/bolt12/receive")).json()["offer"]
    assert second["is_default_receive"] is True
    assert second["id"] != first["id"]

    # And the disabled offer is still listed but no longer flagged.
    listing = (await client.get("/v1/bolt12/offers?source=issued")).json()["offers"]
    by_id = {o["id"]: o for o in listing}
    assert by_id[first["id"]]["is_default_receive"] is False
    assert by_id[first["id"]]["status"] == "disabled"


# ── Cross-tenant isolation ──────────────────────────────────


async def _make_second_admin(db_session) -> tuple[str, str]:
    """Create a second admin API key bound to a different tenant.

    Returns ``(raw_key, key_id)``.
    """
    from uuid import uuid4

    from app.core.security import generate_api_key, hash_api_key
    from app.models.api_key import APIKey

    raw = generate_api_key()
    api_key = APIKey(
        id=uuid4(),
        name="other-admin",
        key_hash=hash_api_key(raw),
        is_admin=True,
        is_active=True,
    )
    db_session.add(api_key)
    await db_session.commit()
    return raw, str(api_key.id)


@pytest.mark.asyncio
async def test_get_offer_returns_404_for_other_tenants_offer(authed_client, db_session) -> None:
    """Cross-tenant offer lookup returns 404 (not 403) so an attacker
    cannot enumerate offer ids belonging to other tenants."""
    client, _raw, _ = authed_client

    # Tenant A imports an offer.
    s = _make_offer_string(description="tenant-a-secret")
    created = (await client.post("/v1/bolt12/offers", json={"offer": s})).json()
    offer_id = created["id"]

    # Tenant B authenticates and tries to read tenant A's offer.
    other_raw, _other_id = await _make_second_admin(db_session)
    client.headers["Authorization"] = f"Bearer {other_raw}"

    resp = await client.get(f"/v1/bolt12/offers/{offer_id}")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Offer not found"


@pytest.mark.asyncio
async def test_list_offers_scopes_to_caller_api_key(authed_client, db_session) -> None:
    """Listing must only reveal offers owned by the caller."""
    client, _raw, _ = authed_client

    sa = _make_offer_string(description="alpha-only", amount=11)
    sb = _make_offer_string(description="alpha-too", amount=22)
    await client.post("/v1/bolt12/offers", json={"offer": sa})
    await client.post("/v1/bolt12/offers", json={"offer": sb})

    other_raw, _ = await _make_second_admin(db_session)
    # Tenant B has no offers of its own; listing must be empty.
    client.headers["Authorization"] = f"Bearer {other_raw}"
    resp = await client.get("/v1/bolt12/offers")
    assert resp.status_code == 200
    assert resp.json() == {"offers": []}


@pytest.mark.asyncio
async def test_disable_offer_404_for_other_tenants_offer(authed_client, db_session) -> None:
    """A cross-tenant DELETE must not be able to disable / demote
    another tenant's offer."""
    client, _raw, _ = authed_client

    s = _make_offer_string(description="hands-off")
    created = (await client.post("/v1/bolt12/offers", json={"offer": s})).json()
    offer_id = created["id"]

    other_raw, _ = await _make_second_admin(db_session)
    client.headers["Authorization"] = f"Bearer {other_raw}"

    resp = await client.delete(f"/v1/bolt12/offers/{offer_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_offer_invoice_requests_404_for_other_tenant(authed_client, db_session) -> None:
    client, _raw, _ = authed_client
    s = _make_offer_string(description="no-peek")
    offer_id = (await client.post("/v1/bolt12/offers", json={"offer": s})).json()["id"]

    other_raw, _ = await _make_second_admin(db_session)
    client.headers["Authorization"] = f"Bearer {other_raw}"

    resp = await client.get(f"/v1/bolt12/offers/{offer_id}/invoice-requests")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_offer_invoices_404_for_other_tenant(authed_client, db_session) -> None:
    client, _raw, _ = authed_client
    s = _make_offer_string(description="no-peek-2")
    offer_id = (await client.post("/v1/bolt12/offers", json={"offer": s})).json()["id"]

    other_raw, _ = await _make_second_admin(db_session)
    client.headers["Authorization"] = f"Bearer {other_raw}"

    resp = await client.get(f"/v1/bolt12/offers/{offer_id}/invoices")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_unauthorized_access_writes_audit_row(authed_client, db_session) -> None:
    """Cross-tenant access attempts emit an ``unauthorized_offer_access``
    audit-log row tied to the attacking key, so incident responders can
    grep the audit chain after a suspected breach."""
    from sqlalchemy import select

    from app.models.audit_log import AuditLog

    client, _raw, _ = authed_client
    s = _make_offer_string(description="audited")
    offer_id = (await client.post("/v1/bolt12/offers", json={"offer": s})).json()["id"]

    other_raw, other_id = await _make_second_admin(db_session)
    client.headers["Authorization"] = f"Bearer {other_raw}"

    resp = await client.get(f"/v1/bolt12/offers/{offer_id}")
    assert resp.status_code == 404

    # Audit row exists for tenant B's attempt.
    rows = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "unauthorized_offer_access")))
        .scalars()
        .all()
    )
    assert any(str(r.api_key_id) == other_id for r in rows)


@pytest.mark.asyncio
async def test_set_default_receive_404_for_other_tenant(authed_client, db_session) -> None:
    """Cross-tenant set-default uses 404, not 403, to avoid leaking
    the existence of the offer to a different tenant."""
    client, _raw, _ = authed_client
    issued = await client.post(
        "/v1/bolt12/offers/issue",
        json={"description": "mine", "amount_msat": 1000},
    )
    offer_id = issued.json()["id"]

    other_raw, _ = await _make_second_admin(db_session)
    client.headers["Authorization"] = f"Bearer {other_raw}"

    resp = await client.post(f"/v1/bolt12/offers/{offer_id}/set-default")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_disable_default_offer_triggers_sticky_refresh(
    authed_client,
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    """Disabling a default-receive offer must trigger an out-of-band
    sticky-peer push so the gateway stops watching a now-irrelevant
    payer right away — otherwise the on-disconnect loop would keep
    redialling a peer the wallet no longer cares about for up to 30 s
    (until the next periodic reconciler tick).

    Non-default offer disables don't need the refresh — they were
    never in the desired set.
    """
    from contextlib import asynccontextmanager
    from unittest.mock import AsyncMock, MagicMock

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.api import bolt12 as bolt12_api
    from app.services.bolt12 import runtime as bolt12_runtime
    from app.services.bolt12 import sticky_peer_reconciler as sticky_recon

    stub_gateway = _StubGateway()
    fake_service = type("S", (), {"_gateway": stub_gateway})()
    monkeypatch.setattr(
        bolt12_api,
        "get_bolt12_service",
        lambda: fake_service,
    )
    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_auto_peer_well_known_payers",
        True,
    )
    monkeypatch.setattr(bolt12_api.settings, "bolt12_enabled", True)
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_gateway_grpc",
        "localhost:9999",
    )

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    @asynccontextmanager
    async def _test_db_ctx():
        async with session_factory() as session:
            yield session

    monkeypatch.setattr(sticky_recon, "get_db_context", _test_db_ctx)

    fake_client = MagicMock()
    fake_client.set_sticky_peers = AsyncMock(
        return_value=MagicMock(sticky_count=0),
    )
    monkeypatch.setattr(bolt12_runtime._runtime, "client", fake_client)

    client, _raw, _key_id = authed_client

    # Step 1: mint an OCEAN default-receive offer. This triggers a
    # refresh push that includes OCEAN.
    resp = await client.post(
        "/v1/bolt12/receive/configure",
        json={"description": "OCEAN Payouts for bc1qtestaddress"},
    )
    assert resp.status_code == 200
    default_offer = resp.json()["offer"]

    # Sanity: configure-receive pushed OCEAN + bootstrap peers as sticky.
    assert fake_client.set_sticky_peers.await_count >= 1
    last_push = fake_client.set_sticky_peers.await_args_list[-1].args[0]
    from app.services.bolt12.well_known_payers import (
        BOOTSTRAP_OM_PEERS,
        WELL_KNOWN_PAYERS,
    )

    ocean_pk = bytes.fromhex(next(p for p in WELL_KNOWN_PAYERS if p.label == "OCEAN").node_id_hex)
    expected_count = 1 + sum(1 for b in BOOTSTRAP_OM_PEERS if b.mainnet_only)
    assert len(last_push) == expected_count, (
        f"OCEAN configure must push OCEAN + bootstrap peers (expected {expected_count}, got {len(last_push)})"
    )
    assert any(p.node_id == ocean_pk for p in last_push), "OCEAN must be in the post-configure sticky set"

    # Reset the mock so we can isolate the disable push.
    fake_client.set_sticky_peers.reset_mock()

    # Step 2: disable the offer. This should trigger a refresh push
    # that REMOVES OCEAN from the sticky set but KEEPS the always-on
    # bootstrap peers (they're independent of the offer lifecycle).
    resp = await client.delete(f"/v1/bolt12/offers/{default_offer['id']}")
    assert resp.status_code == 204

    fake_client.set_sticky_peers.assert_awaited_once()
    pushed = fake_client.set_sticky_peers.await_args.args[0]
    bootstrap_count = sum(1 for b in BOOTSTRAP_OM_PEERS if b.mainnet_only)
    assert len(pushed) == bootstrap_count, (
        f"disabling the only OCEAN default-receive offer must shrink "
        f"the sticky set to bootstrap-only ({bootstrap_count}); got "
        f"{len(pushed)}"
    )
    assert not any(p.node_id == ocean_pk for p in pushed), "OCEAN must no longer be in the sticky set after disable"


@pytest.mark.asyncio
async def test_disable_non_default_offer_does_not_trigger_sticky_refresh(
    authed_client,
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    """Disabling a NON-default offer must NOT push the sticky set —
    non-default offers don't contribute to the desired set, so the
    refresh would be wasted work."""
    from contextlib import asynccontextmanager
    from unittest.mock import AsyncMock, MagicMock
    from uuid import uuid4

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.api import bolt12 as bolt12_api
    from app.models.bolt12_offer import (
        Bolt12Offer,
        Bolt12OfferSource,
        Bolt12OfferStatus,
    )
    from app.services.bolt12 import runtime as bolt12_runtime
    from app.services.bolt12 import sticky_peer_reconciler as sticky_recon

    monkeypatch.setattr(bolt12_api.settings, "bitcoin_network", "bitcoin")
    monkeypatch.setattr(bolt12_api.settings, "bolt12_enabled", True)
    monkeypatch.setattr(
        bolt12_api.settings,
        "bolt12_gateway_grpc",
        "localhost:9999",
    )

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    @asynccontextmanager
    async def _test_db_ctx():
        async with session_factory() as session:
            yield session

    monkeypatch.setattr(sticky_recon, "get_db_context", _test_db_ctx)

    fake_client = MagicMock()
    fake_client.set_sticky_peers = AsyncMock(
        return_value=MagicMock(sticky_count=0),
    )
    monkeypatch.setattr(bolt12_runtime._runtime, "client", fake_client)

    client, _raw, key_id = authed_client

    # Insert a non-default issued offer directly.
    from uuid import UUID as _UUID

    api_key_id = _UUID(key_id)
    issuer_id_hex = "02" + "ab" * 32
    offer_row = Bolt12Offer(
        api_key_id=api_key_id,
        bolt12="lno1nondefault" + uuid4().hex,
        description="Not a well-known payer",
        amount_msat=None,
        currency=None,
        issuer=None,
        issuer_id_hex=issuer_id_hex,
        quantity_max=None,
        source=Bolt12OfferSource.ISSUED,
        is_default_receive=False,
        status=Bolt12OfferStatus.ACTIVE,
    )
    db_session.add(offer_row)
    await db_session.commit()
    await db_session.refresh(offer_row)

    resp = await client.delete(f"/v1/bolt12/offers/{offer_row.id}")
    assert resp.status_code == 204

    # No sticky push happened — non-default offers don't affect the
    # desired set.
    fake_client.set_sticky_peers.assert_not_awaited()


@pytest.mark.asyncio
async def test_disable_offer_audit_records_was_default_receive(authed_client, db_session) -> None:
    """``disable_offer`` audit details record whether the offer was
    the default receive offer at the time of disable."""
    from sqlalchemy import select

    from app.models.audit_log import AuditLog

    client, _raw, _ = authed_client

    # Mint default receive then disable it.
    default_offer = (await client.get("/v1/bolt12/receive")).json()["offer"]
    resp = await client.delete(f"/v1/bolt12/offers/{default_offer['id']}")
    assert resp.status_code == 204

    rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "disable_offer"))).scalars().all()
    target = [r for r in rows if r.details and r.details.get("offer_id") == default_offer["id"]]
    assert target, "disable_offer audit row missing"
    assert target[-1].details.get("was_default_receive") is True


# ── Selective-disclosure proof: signature TLV filter (H6.4) ──────


@pytest.mark.asyncio
async def test_proof_filters_signature_types_in_reveal_set(authed_client, db_session) -> None:
    """``build_invoice_proof`` MUST silently strip TLV types in the
    BOLT 12 signature range (240..1000) from the caller's
    ``reveal_types``, even if the lower codec layer would have
    accepted them. Defence-in-depth against future refactors."""
    import secrets
    from uuid import uuid4

    from app.core.encryption import encrypt_field
    from app.models.bolt12_invoice import (
        Bolt12Direction,
        Bolt12Invoice,
        Bolt12InvoiceRequest,
        Bolt12InvoiceRequestStatus,
        Bolt12InvoiceStatus,
    )
    from app.models.bolt12_offer import (
        Bolt12Offer,
        Bolt12OfferSource,
    )
    from app.services.bolt12 import (
        CoincurveSigner,
        Invoice,
        InvoiceRequest,
        sign_invoice,
        sign_invoice_request,
    )
    from app.services.bolt12 import (
        Offer as Bolt12Offer_,
    )
    from app.services.bolt12 import (
        encode as encode_bolt12,
    )

    client, _raw, key_id = authed_client

    # Build a complete offer + invreq + signed invoice end-to-end so
    # the proof endpoint has real bytes to operate on.
    issuer = CoincurveSigner.generate()
    payer = CoincurveSigner.generate()
    offer = Bolt12Offer_(
        amount=1500,
        description="proof-test",
        issuer_id=issuer.public_key,
        metadata=secrets.token_bytes(16),
    )
    unsigned_req = InvoiceRequest.from_offer(
        offer,
        metadata=secrets.token_bytes(16),
        payer_id=payer.public_key,
        amount=1500,
    )
    signed_req = sign_invoice_request(unsigned_req, payer)
    invoice = Invoice(
        invreq=signed_req,
        node_id=issuer.public_key,
        payment_hash=secrets.token_bytes(32),
        amount=1500,
        created_at=1_700_000_000,
        relative_expiry=3600,
    )
    signed_invoice = sign_invoice(invoice, issuer)

    offer_row = Bolt12Offer(
        id=uuid4(),
        api_key_id=key_id,
        bolt12=encode_bolt12(offer.to_bolt12_string()),
        description="proof-test",
        amount_msat=1500,
        issuer_id_hex=issuer.public_key.hex(),
        source=Bolt12OfferSource.ISSUED,
    )
    invreq_row = Bolt12InvoiceRequest(
        id=uuid4(),
        api_key_id=key_id,
        offer_id=offer_row.id,
        direction=Bolt12Direction.OUTBOUND,
        offer_bolt12=offer_row.bolt12,
        amount_msat=1500,
        payer_id_hex=payer.public_key.hex(),
        encrypted_payer_secret=encrypt_field(payer.secret.hex()),
        invreq_bolt12=encode_bolt12(signed_req.to_bolt12_string()),
        status=Bolt12InvoiceRequestStatus.INVOICE_RECEIVED,
    )
    invoice_row = Bolt12Invoice(
        id=uuid4(),
        api_key_id=key_id,
        invoice_request_id=invreq_row.id,
        direction=Bolt12Direction.OUTBOUND,
        invoice_bolt12=encode_bolt12(signed_invoice.to_bolt12_string()),
        amount_msat=1500,
        payment_hash_hex=signed_invoice.payment_hash.hex(),
        node_id_hex=issuer.public_key.hex(),
        status=Bolt12InvoiceStatus.OPEN,
    )
    db_session.add_all([offer_row, invreq_row, invoice_row])
    await db_session.commit()

    # Caller asks to reveal both legitimate fields and a signature
    # TLV. The endpoint must drop the signature type from the
    # reveal set; build_proof itself MAY also drop it, so we assert
    # by checking the proof's revealed_types contains only the
    # legitimate, non-signature types.
    resp = await client.post(
        f"/v1/bolt12/invoices/{invoice_row.id}/proof",
        json={"reveal_types": [160, 170, 240, 500, 1000]},
    )
    assert resp.status_code == 200
    import json as _json

    proof = _json.loads(resp.json()["proof"])
    revealed = {int(r["type"]) for r in proof["revealed"]}
    # No signature-range type may appear in the revealed set.
    assert all(not (240 <= t <= 1000) for t in revealed)


# ── Default-receive concurrency ─────────────────────────────


@pytest.mark.asyncio
async def test_repeated_get_receive_returns_same_default(authed_client) -> None:
    """Repeated ``GET /v1/bolt12/receive`` calls must return the same
    minted default receive offer \u2014 the auto-mint path is idempotent
    on the partial unique index ``uq_bolt12_offers_default_receive_per_key``.
    The IntegrityError-retry recovery in
    ``_get_or_create_default_receive`` handles concurrent races by
    rolling back the losing INSERT and returning the winning row."""
    client, _raw, _ = authed_client
    ids: set[str] = set()
    for _ in range(5):
        r = await client.get("/v1/bolt12/receive")
        assert r.status_code == 200
        ids.add(r.json()["offer"]["id"])
    assert len(ids) == 1, f"expected one offer, got {ids}"


@pytest.mark.asyncio
async def test_configure_receive_atomic_with_demote(authed_client, db_session) -> None:
    """``/receive/configure`` must demote the previous default and
    mint the new one in a single transaction. Verify post-state
    invariant: exactly one row has ``is_default_receive=True``."""
    from sqlalchemy import func, select

    from app.models.bolt12_offer import Bolt12Offer

    client, _raw, _ = authed_client

    # Seed a default via auto-mint.
    first = (await client.get("/v1/bolt12/receive")).json()["offer"]

    resp = await client.post(
        "/v1/bolt12/receive/configure",
        json={"description": "OCEAN Payouts for bc1qexample"},
    )
    assert resp.status_code == 200
    new_offer = resp.json()["offer"]
    assert new_offer["id"] != first["id"]

    # Exactly one default-receive row for this tenant.
    # Use the response's api_key indirectly via the offer rows we
    # have; simpler to count default-receive rows for this offer's
    # api_key_id.
    api_key_id = (
        await db_session.execute(select(Bolt12Offer.api_key_id).where(Bolt12Offer.id == new_offer["id"]))
    ).scalar_one()
    n = (
        await db_session.execute(
            select(func.count())
            .select_from(Bolt12Offer)
            .where(
                Bolt12Offer.api_key_id == api_key_id,
                Bolt12Offer.is_default_receive.is_(True),
            )
        )
    ).scalar_one()
    assert n == 1


# ── /v1/bolt12/bip353/resolve and /zone-record ───────────────────


@pytest.mark.asyncio
async def test_bip353_resolve_happy_path(authed_client, monkeypatch) -> None:
    """A successful resolution returns the decomposed payment URI."""
    from app.services.bolt12 import bip353 as _bip353

    client, _raw, _key_id = authed_client

    def _fake_resolve(handle: str, *, require_dnssec: bool = True):
        ph = _bip353.PaymentHandle.parse(handle)
        return _bip353.ResolvedHandle(
            handle=ph,
            bitcoin_uri="bitcoin:?lno=lno1example",
            offer="lno1example",
            bolt11=None,
            on_chain=None,
        )

    monkeypatch.setattr(_bip353, "resolve_payment_handle", _fake_resolve)

    resp = await client.post(
        "/v1/bolt12/bip353/resolve",
        json={"handle": "alice@example.com", "require_dnssec": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["handle"] == "alice@example.com"
    assert body["fqdn"] == "alice.user._bitcoin-payment.example.com."
    assert body["bitcoin_uri"] == "bitcoin:?lno=lno1example"
    assert body["offer"] == "lno1example"
    assert body["bolt11"] is None
    assert body["on_chain"] is None


@pytest.mark.asyncio
async def test_bip353_resolve_rejects_invalid_handle(authed_client) -> None:
    """A malformed handle short-circuits at validation with 400."""
    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/bip353/resolve",
        json={"handle": "no-at-sign-here"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_bip353_resolve_returns_502_on_insecure(authed_client, monkeypatch) -> None:
    """``Bolt12Bip353InsecureError`` surfaces as 502 with its message."""
    from app.services.bolt12 import bip353 as _bip353

    client, _raw, _key_id = authed_client

    def _raise_insecure(handle: str, *, require_dnssec: bool = True):
        raise _bip353.Bolt12Bip353InsecureError("resolver not validating DNSSEC")

    monkeypatch.setattr(_bip353, "resolve_payment_handle", _raise_insecure)

    resp = await client.post(
        "/v1/bolt12/bip353/resolve",
        json={"handle": "alice@example.com"},
    )
    assert resp.status_code == 502
    assert "DNSSEC" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_bip353_resolve_sanitises_dns_failure(authed_client, monkeypatch) -> None:
    """Generic DNS failures return a sanitised 502 (no leaky details)."""
    from app.services.bolt12 import bip353 as _bip353

    client, _raw, _key_id = authed_client

    def _raise_dns(handle: str, *, require_dnssec: bool = True):
        raise RuntimeError("internal: socket timed out connecting to 1.2.3.4:53")

    monkeypatch.setattr(_bip353, "resolve_payment_handle", _raise_dns)

    resp = await client.post(
        "/v1/bolt12/bip353/resolve",
        json={"handle": "alice@example.com"},
    )
    assert resp.status_code == 502
    detail = resp.json()["detail"]
    assert detail == "BIP-353 lookup failed"
    # Defence in depth: confirm internal text never leaked.
    assert "1.2.3.4" not in detail
    assert "socket" not in detail


@pytest.mark.asyncio
async def test_bip353_resolve_requires_auth(client) -> None:
    """The resolve endpoint requires an API key like the rest of the router."""
    resp = await client.post(
        "/v1/bolt12/bip353/resolve",
        json={"handle": "alice@example.com"},
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_bip353_zone_record_emits_rfc1035_fragment(authed_client) -> None:
    """Admin caller gets a zone-file fragment back."""
    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/bip353/zone-record",
        json={
            "handle": "alice@example.com",
            "offer": "lno1example",
            "ttl": 600,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["handle"] == "alice@example.com"
    assert body["fqdn"] == "alice.user._bitcoin-payment.example.com."
    record = body["zone_record"]
    assert record.startswith("alice.user._bitcoin-payment.example.com. 600 IN TXT ")
    assert "lno=lno1example" in record
    # The TXT value must be wrapped in double quotes (RFC1035).
    assert record.endswith('"')
    assert record.count('"') == 2


@pytest.mark.asyncio
async def test_bip353_zone_record_400_when_no_payment_info(authed_client) -> None:
    """A handle with no offer/bolt11/on_chain is a 400."""
    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/bip353/zone-record",
        json={"handle": "alice@example.com"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_bip353_zone_record_400_on_invalid_handle(authed_client) -> None:
    """An invalid handle is rejected at parse time with 400."""
    client, _raw, _key_id = authed_client
    resp = await client.post(
        "/v1/bolt12/bip353/zone-record",
        json={"handle": "not-a-handle", "offer": "lno1example"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_bip353_zone_record_requires_admin(client, db_session) -> None:
    """A non-admin key may not publish zone records."""
    from uuid import uuid4

    from app.core.security import generate_api_key, hash_api_key
    from app.models.api_key import APIKey

    raw = generate_api_key()
    api_key = APIKey(
        id=uuid4(),
        name="readonly-bip353",
        key_hash=hash_api_key(raw),
        is_admin=False,
        is_active=True,
    )
    db_session.add(api_key)
    await db_session.commit()

    client.headers["Authorization"] = f"Bearer {raw}"

    resp = await client.post(
        "/v1/bolt12/bip353/zone-record",
        json={"handle": "alice@example.com", "offer": "lno1example"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_bip353_zone_record_requires_auth(client) -> None:
    resp = await client.post(
        "/v1/bolt12/bip353/zone-record",
        json={"handle": "alice@example.com", "offer": "lno1example"},
    )
    assert resp.status_code in (401, 403)


# ── Additional error-contract coverage ───────────────────────────────


@pytest.mark.asyncio
async def test_list_offers_rejects_unknown_source_filter(authed_client) -> None:
    """The ``source`` filter is parsed against the ``Bolt12OfferSource``
    enum; an unrecognised value is a caller error mapped to 400 (not a
    500 from the bare ``ValueError``)."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/bolt12/offers", params={"source": "bogus"})
    assert resp.status_code == 400
    assert "Unknown source" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_list_offers_rejects_out_of_range_limit(authed_client) -> None:
    """``limit`` is bounded 1..500 at the query layer; an oversized
    value fails request validation with 422."""
    client, _raw, _key_id = authed_client
    resp = await client.get("/v1/bolt12/offers", params={"limit": 10_000})
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "limit" for err in resp.json()["detail"])


@pytest.mark.asyncio
async def test_decode_offer_rejects_empty_offer(authed_client) -> None:
    """``DecodeOfferRequest.offer`` has ``min_length=1``; an empty
    string fails Pydantic validation with 422 before the codec runs."""
    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/decode", json={"offer": ""})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_build_invoice_proof_unknown_invoice_is_404(authed_client) -> None:
    """A proof request for an invoice id that resolves no row returns
    404 'invoice not found' — the same response a cross-tenant id
    would produce (no existence leak)."""
    from uuid import uuid4

    client, _raw, _key_id = authed_client
    resp = await client.post(
        f"/v1/bolt12/invoices/{uuid4()}/proof",
        json={"reveal_types": [160]},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "invoice not found"


@pytest.mark.asyncio
async def test_set_default_receive_offer_requires_admin(client, db_session) -> None:
    """Promoting an offer to the default-receive slot is an admin-only
    write; a non-admin key is rejected with 403."""
    from uuid import uuid4

    from app.core.security import generate_api_key, hash_api_key
    from app.models.api_key import APIKey

    raw = generate_api_key()
    db_session.add(
        APIKey(
            id=uuid4(),
            name="readonly",
            key_hash=hash_api_key(raw),
            is_admin=False,
            is_active=True,
        )
    )
    await db_session.commit()
    client.headers["Authorization"] = f"Bearer {raw}"

    resp = await client.post(f"/v1/bolt12/offers/{uuid4()}/set-default")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_disable_offer_requires_admin(client, db_session) -> None:
    """Soft-disabling an offer mutates wallet state and is admin-only;
    a non-admin key is rejected with 403."""
    from uuid import uuid4

    from app.core.security import generate_api_key, hash_api_key
    from app.models.api_key import APIKey

    raw = generate_api_key()
    db_session.add(
        APIKey(
            id=uuid4(),
            name="readonly",
            key_hash=hash_api_key(raw),
            is_admin=False,
            is_active=True,
        )
    )
    await db_session.commit()
    client.headers["Authorization"] = f"Bearer {raw}"

    resp = await client.delete(f"/v1/bolt12/offers/{uuid4()}")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_diagnostics_path_snapshot_requires_admin(client, db_session) -> None:
    """The path-snapshot diagnostic is admin-only (it mints a probe
    invoice against LND); a non-admin key gets 403, not the data."""
    from uuid import uuid4

    from app.core.security import generate_api_key, hash_api_key
    from app.models.api_key import APIKey

    raw = generate_api_key()
    db_session.add(
        APIKey(
            id=uuid4(),
            name="readonly",
            key_hash=hash_api_key(raw),
            is_admin=False,
            is_active=True,
        )
    )
    await db_session.commit()
    client.headers["Authorization"] = f"Bearer {raw}"

    resp = await client.get("/v1/bolt12/diagnostics/path-snapshot")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_receive_offer_requires_auth(client) -> None:
    """The receive-offer panel mints/returns a wallet-bound offer and
    must reject anonymous callers."""
    resp = await client.get("/v1/bolt12/receive")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_pay_offer_rejects_empty_offer_body(authed_client) -> None:
    """``PayOfferRequest.offer`` is ``min_length=1``; an empty offer
    fails request validation with 422 before any runtime lookup."""
    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/pay", json={"offer": ""})
    assert resp.status_code == 422


# ── Pay endpoint: invoice-validation failure branches ────────────────


def _wire_pay_service_returning_invoice(monkeypatch, make_invoice):
    """Wire a fake BOLT 12 service whose ``request_invoice`` drives the
    real invreq builder, then hands the resulting parsed invreq to
    ``make_invoice(parsed_invreq, recipient)`` and returns the encoded
    invoice bytes. Lets each test perturb exactly one invoice field to
    exercise a specific post-receive validation branch in the pay
    endpoint. Returns the recipient signer + offer string.
    """
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api
    from app.services.bolt12 import CoincurveSigner, InvoiceRequest
    from app.services.bolt12.codec import Bolt12String
    from app.services.bolt12.orchestrator import InvreqBuildContext
    from app.services.bolt12.tlv import decode_stream as tlv_decode_stream
    from app.services.bolt12.tlv import encode_stream as tlv_encode_stream

    recipient = CoincurveSigner.generate()
    offer = Offer(amount=1500, description="validate", issuer_id=recipient.public_key)
    offer_str = Bolt12Codec.encode(offer.to_bolt12_string())

    fake_peer = MagicMock()
    fake_peer.node_id = bytes(33)
    fake_peer.advertises_onion_messages = True
    fake_ident = MagicMock()
    fake_ident.peers = (fake_peer,)
    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(return_value=fake_ident)

    async def _request_invoice(*, offer, build_invreq, destination, **_):  # noqa: A002
        plan = destination(offer)
        invreq_bytes = await build_invreq(
            InvreqBuildContext(
                offer=offer,
                amount_msat=plan.destination.direct_node_id and 1500,
                payer_note=None,
                quantity=None,
                reply_path=b"\x00" * 64,
            )
        )
        parsed = InvoiceRequest.parse(Bolt12String(hrp="lnr", records=tlv_decode_stream(invreq_bytes)))
        signed_records = make_invoice(parsed, recipient)
        return tlv_encode_stream(signed_records)

    fake_service.request_invoice = _request_invoice
    monkeypatch.setattr(bolt12_api, "get_bolt12_service", lambda: fake_service)
    return offer_str


@pytest.mark.asyncio
async def test_pay_offer_502_when_invoice_amount_mismatches(authed_client, monkeypatch) -> None:
    """A recipient that mirrors our invreq but bills a different amount
    is rejected with 502 — the wallet refuses to over-pay (BOLT 12
    'invoice amount must equal invreq amount')."""
    from app.services.bolt12 import Invoice, sign_invoice

    def _make(parsed, recipient):
        inv = Invoice(
            invreq=parsed,
            payment_hash=b"\xab" * 32,
            amount=9999,  # != invreq's 1500
            node_id=recipient.public_key,
            created_at=1700000000,
            relative_expiry=3600,
        )
        return sign_invoice(inv, recipient).to_records()

    offer_str = _wire_pay_service_returning_invoice(monkeypatch, _make)
    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/pay", json={"offer": offer_str})
    assert resp.status_code == 502
    assert "does not match invreq" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_pay_offer_502_when_invoice_missing_payment_hash(authed_client, monkeypatch) -> None:
    """An invoice with no payment_hash cannot be paid; the endpoint
    rejects it with 502 + an explicit detail."""
    from app.services.bolt12 import Invoice, sign_invoice

    def _make(parsed, recipient):
        inv = Invoice(
            invreq=parsed,
            payment_hash=None,
            amount=parsed.amount,
            node_id=recipient.public_key,
            created_at=1700000000,
            relative_expiry=3600,
        )
        return sign_invoice(inv, recipient).to_records()

    offer_str = _wire_pay_service_returning_invoice(monkeypatch, _make)
    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/pay", json={"offer": offer_str})
    assert resp.status_code == 502
    assert resp.json()["detail"] == "Invoice missing payment_hash"


@pytest.mark.asyncio
async def test_pay_offer_502_when_invoice_node_id_mismatches_issuer(authed_client, monkeypatch) -> None:
    """For a direct offer (issuer_id, no paths) the invoice MUST be
    signed by — and carry — the offer's issuer_id. An invoice signed
    by a different key surfaces as a 502 binding failure."""
    from app.services.bolt12 import CoincurveSigner, Invoice, sign_invoice

    impostor = CoincurveSigner.generate()

    def _make(parsed, _recipient):
        inv = Invoice(
            invreq=parsed,
            payment_hash=b"\xab" * 32,
            amount=parsed.amount,
            node_id=impostor.public_key,  # not the offer issuer
            created_at=1700000000,
            relative_expiry=3600,
        )
        return sign_invoice(inv, impostor).to_records()

    offer_str = _wire_pay_service_returning_invoice(monkeypatch, _make)
    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/pay", json={"offer": offer_str})
    assert resp.status_code == 502
    assert resp.json()["detail"]


@pytest.mark.asyncio
async def test_pay_offer_502_when_recipient_returns_malformed_invoice(authed_client, monkeypatch) -> None:
    """A recipient that returns bytes that don't decode as a BOLT 12
    invoice is rejected with 502 and a generic (non-leaking) detail."""
    offer_str = _wire_pay_service_returning_invoice(
        monkeypatch,
        # Return raw garbage records the invoice parser will reject.
        lambda _parsed, _recipient: [],
    )
    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/pay", json={"offer": offer_str})
    assert resp.status_code == 502
    assert resp.json()["detail"]


@pytest.mark.asyncio
async def test_pay_offer_502_when_gateway_identity_fails(authed_client, monkeypatch) -> None:
    """If the gateway's ``get_identity`` raises while building the
    reply path the pay endpoint maps the upstream fault to 502."""
    from unittest.mock import AsyncMock, MagicMock

    from app.api import bolt12 as bolt12_api

    fake_service = MagicMock()
    fake_service._gateway.get_identity = AsyncMock(side_effect=RuntimeError("gateway crashed"))
    monkeypatch.setattr(bolt12_api, "get_bolt12_service", lambda: fake_service)

    client, _raw, _key_id = authed_client
    resp = await client.post("/v1/bolt12/pay", json={"offer": _make_offer_string()})
    assert resp.status_code == 502
    assert resp.json()["detail"]
