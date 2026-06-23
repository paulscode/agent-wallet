# SPDX-License-Identifier: MIT
"""integration — hop_dispatcher production adapter bindings.

The default-adapter factories must construct cleanly and route
through the correct LND / Boltz / anonymize-chain primitives. These
tests don't exercise live LND; they instantiate the dep bundles +
check that the dispatcher routes by source-kind.
"""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import pytest

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.hop_dispatcher import (
    build_default_priv_channel_hop_deps,
    build_default_reverse_hop_deps,
    build_default_submarine_hop_deps,
    default_hop_step_fn,
)
from app.services.anonymize.hops.priv_channel import PrivChannelHopDeps
from app.services.anonymize.hops.reverse import ReverseHopDeps
from app.services.anonymize.hops.submarine import SubmarineHopDeps


def _session(*, status: str, source_kind: str) -> AnonymizeSession:
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind=source_kind,
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
    )


def test_build_default_reverse_hop_deps_constructs() -> None:
    deps = build_default_reverse_hop_deps()
    assert isinstance(deps, ReverseHopDeps)
    assert deps.boltz_create_reverse_swap is not None


def test_reverse_hop_client_uses_reverse_leg_url(monkeypatch) -> None:
    """The production reverse-hop client MUST be constructed
    against ``resolve_reverse_leg_url()`` (which prefers the leg-specific
    ``BOLTZ_REVERSE_ONION_URL`` env var). Without this, a deployment
    that configures distinct submarine + reverse onions for
    operator-splitting would pass the admission gate but route both
    legs to ``BOLTZ_ONION_URL``, silently defeating the protection."""
    from unittest.mock import patch

    from app.core.config import settings
    from app.services.anonymize.hop_dispatcher import (
        build_default_reverse_hop_deps,
    )

    monkeypatch.setattr(
        settings,
        "boltz_onion_url",
        "http://shared-default.onion/api/v2",
    )
    monkeypatch.setattr(
        settings,
        "boltz_reverse_onion_url",
        "http://reverse-leg-pinned.onion/v2",
    )

    captured: dict[str, str | None] = {}

    from unittest.mock import MagicMock

    from app.services.anonymize import boltz_egress as _be

    real_init = _be.AnonymizeBoltzClient.__init__

    def _spy_init(self, *, base_url=None, **kwargs):
        captured["base_url"] = base_url
        return real_init(self, base_url=base_url, **kwargs)

    # The client is constructed per-session inside the adapter
    # (not at module-init), so the assertion must invoke the adapter
    # to trigger the construction. A session with no bound
    # reverse_operator_id falls back to the env-pin URL.
    import asyncio

    async def _spy_create_reverse(self, *, db, api_key_id, **kwargs):
        return (MagicMock(boltz_swap_id="x", invoice=""), None)

    with (
        patch.object(
            _be.AnonymizeBoltzClient,
            "__init__",
            _spy_init,
        ),
        patch.object(
            _be.AnonymizeBoltzClient,
            "create_reverse_swap",
            _spy_create_reverse,
        ),
    ):
        deps = build_default_reverse_hop_deps()
        sess = MagicMock()
        sess.reverse_operator_id = None
        sess.pipeline_json = {}
        asyncio.run(
            deps.boltz_create_reverse_swap(
                db=None,
                request_body={"invoiceAmount": 1, "claimAddress": "bc1q…"},
                session=sess,
            )
        )

    assert captured["base_url"] == "http://reverse-leg-pinned.onion/v2"


def test_submarine_hop_client_uses_submarine_leg_url(monkeypatch) -> None:
    """Symmetric assertion for the submarine leg."""
    from unittest.mock import patch

    from app.core.config import settings
    from app.services.anonymize.hop_dispatcher import (
        build_default_submarine_hop_deps,
    )

    monkeypatch.setattr(
        settings,
        "boltz_onion_url",
        "http://shared-default.onion/api/v2",
    )
    monkeypatch.setattr(
        settings,
        "boltz_submarine_onion_url",
        "http://submarine-leg-pinned.onion/v2",
    )

    captured: dict[str, str | None] = {}

    import asyncio
    from unittest.mock import MagicMock

    from app.services.anonymize import boltz_egress as _be

    real_init = _be.AnonymizeBoltzClient.__init__

    def _spy_init(self, *, base_url=None, **kwargs):
        captured["base_url"] = base_url
        return real_init(self, base_url=base_url, **kwargs)

    async def _spy_create_submarine(self, *, db, api_key_id, **kwargs):
        return (MagicMock(boltz_swap_id="x"), None)

    with (
        patch.object(
            _be.AnonymizeBoltzClient,
            "__init__",
            _spy_init,
        ),
        patch.object(
            _be.AnonymizeBoltzClient,
            "create_submarine_swap",
            _spy_create_submarine,
        ),
    ):
        deps = build_default_submarine_hop_deps()
        sess = MagicMock()
        sess.submarine_operator_id = None
        sess.pipeline_json = {}
        sess.id = uuid4_mock()
        asyncio.run(
            deps.boltz_create_submarine_swap(
                db=None,
                invoice="lnbcrt1u",
                session=sess,
            )
        )

    assert captured["base_url"] == "http://submarine-leg-pinned.onion/v2"


@pytest.mark.asyncio
async def test_reverse_adapter_forwards_operator_id_from_pipeline_json(
    monkeypatch,
) -> None:
    """The reverse-hop's ``_create_reverse_swap`` adapter MUST
    extract ``reverse_operator_id`` from the session's pipeline_json
    and pass it into ``AnonymizeBoltzClient.create_reverse_swap`` so the
    client can verify the operator's response signature against the
    pinned ``public_key_hex``. A regression that dropped the
    ``operator_id=`` kwarg would silently disable verification
    for distinct-operator deployments — the wallet would accept any
    swap response without checking the operator actually signed it."""
    from unittest.mock import MagicMock, patch

    from app.services.anonymize import boltz_egress as _be
    from app.services.anonymize.hop_dispatcher import (
        build_default_reverse_hop_deps,
    )

    captured: dict = {}

    async def _spy_create_reverse(self, *, db, api_key_id, **kwargs):
        captured.update(kwargs)
        return (MagicMock(boltz_swap_id="swap-xyz", invoice="lnbc..."), None)

    with patch.object(
        _be.AnonymizeBoltzClient,
        "create_reverse_swap",
        _spy_create_reverse,
    ):
        deps = build_default_reverse_hop_deps()
        sess = MagicMock()
        # The adapter prefers the AnonymizeSession.reverse_operator_id
        # column over pipeline_json (the column is the authoritative source
        # since the chain selector lands there at session-create). Set it
        # explicitly to None on the MagicMock so the test exercises the
        # pipeline_json fallback path.
        sess.reverse_operator_id = None
        sess.pipeline_json = {"reverse_operator_id": "boltz-mirror-eu"}
        await deps.boltz_create_reverse_swap(
            db=None,
            request_body={
                "invoiceAmount": 250_000,
                "claimAddress": "bc1q…",
            },
            session=sess,
        )

    assert captured.get("operator_id") == "boltz-mirror-eu", (
        "reverse adapter dropped operator_id from pipeline_json —  response-signature verification would be disabled"
    )


@pytest.mark.asyncio
async def test_submarine_adapter_forwards_operator_id_from_pipeline_json(
    monkeypatch,
) -> None:
    """Symmetric assertion for the submarine leg."""
    from unittest.mock import MagicMock, patch

    from app.services.anonymize import boltz_egress as _be
    from app.services.anonymize.hop_dispatcher import (
        build_default_submarine_hop_deps,
    )

    captured: dict = {}

    async def _spy_create_submarine(self, *, db, api_key_id, **kwargs):
        captured.update(kwargs)
        return (MagicMock(boltz_swap_id="sub-xyz"), None)

    with patch.object(
        _be.AnonymizeBoltzClient,
        "create_submarine_swap",
        _spy_create_submarine,
    ):
        deps = build_default_submarine_hop_deps()
        sess = MagicMock()
        sess.id = uuid4_mock()  # any UUID-like
        # Column takes precedence; set to None so the pipeline_json
        # fallback path is exercised.
        sess.submarine_operator_id = None
        sess.pipeline_json = {"submarine_operator_id": "boltz-canonical"}
        await deps.boltz_create_submarine_swap(
            db=None,
            invoice="lnbcrt250u",
            session=sess,
        )

    assert captured.get("operator_id") == "boltz-canonical", (
        "submarine adapter dropped operator_id from pipeline_json —  response-signature verification would be disabled"
    )


@pytest.mark.asyncio
async def test_reverse_adapter_passes_none_when_operator_id_unset(
    monkeypatch,
) -> None:
    """When the registry is empty (single-operator deployment),
    ``pipeline_json`` has no ``reverse_operator_id`` — the adapter MUST
    pass ``operator_id=None`` rather than raising KeyError. The client
    then routes through the skip-when-no-registry path."""
    from unittest.mock import MagicMock, patch

    from app.services.anonymize import boltz_egress as _be
    from app.services.anonymize.hop_dispatcher import (
        build_default_reverse_hop_deps,
    )

    captured: dict = {}

    async def _spy_create_reverse(self, *, db, api_key_id, **kwargs):
        captured.update(kwargs)
        return (MagicMock(boltz_swap_id="swap-noop", invoice=""), None)

    with patch.object(
        _be.AnonymizeBoltzClient,
        "create_reverse_swap",
        _spy_create_reverse,
    ):
        deps = build_default_reverse_hop_deps()
        sess = MagicMock()
        sess.reverse_operator_id = None  # column unset
        sess.pipeline_json = {}  # and no fallback in pipeline_json
        await deps.boltz_create_reverse_swap(
            db=None,
            request_body={
                "invoiceAmount": 250_000,
                "claimAddress": "bc1q…",
            },
            session=sess,
        )

    assert "operator_id" in captured
    assert captured["operator_id"] is None


def uuid4_mock():
    """Helper: a deterministic UUID-like for the submarine session."""
    from uuid import UUID

    return UUID(int=0)


def test_hop_clients_fall_back_to_shared_url_when_leg_unset(
    monkeypatch,
) -> None:
    """When the leg-specific env vars are blank, the resolver falls
    back to the shared ``BOLTZ_ONION_URL`` (single-operator deployment
    posture). Both legs route to the same URL — which is the v1
    default + the case that triggers the operator-diversity advisory
    banner on the wizard."""
    from unittest.mock import patch

    from app.core.config import settings
    from app.services.anonymize.hop_dispatcher import (
        build_default_reverse_hop_deps,
        build_default_submarine_hop_deps,
    )

    monkeypatch.setattr(
        settings,
        "boltz_onion_url",
        "http://shared-fallback.onion/api/v2",
    )
    monkeypatch.setattr(settings, "boltz_submarine_onion_url", "")
    monkeypatch.setattr(settings, "boltz_reverse_onion_url", "")

    import asyncio
    from unittest.mock import MagicMock

    from app.services.anonymize import boltz_egress as _be

    captured_urls: list[str | None] = []
    real_init = _be.AnonymizeBoltzClient.__init__

    def _spy_init(self, *, base_url=None, **kwargs):
        captured_urls.append(base_url)
        return real_init(self, base_url=base_url, **kwargs)

    async def _spy_create_reverse(self, *, db, api_key_id, **kwargs):
        return (MagicMock(boltz_swap_id="x", invoice=""), None)

    async def _spy_create_submarine(self, *, db, api_key_id, **kwargs):
        return (MagicMock(boltz_swap_id="y"), None)

    # Clients are constructed per-session inside the adapter,
    # so invoke the adapter to trigger the construction.
    with (
        patch.object(
            _be.AnonymizeBoltzClient,
            "__init__",
            _spy_init,
        ),
        patch.object(
            _be.AnonymizeBoltzClient,
            "create_reverse_swap",
            _spy_create_reverse,
        ),
        patch.object(
            _be.AnonymizeBoltzClient,
            "create_submarine_swap",
            _spy_create_submarine,
        ),
    ):
        rev_deps = build_default_reverse_hop_deps()
        sub_deps = build_default_submarine_hop_deps()
        sess = MagicMock()
        sess.reverse_operator_id = None
        sess.submarine_operator_id = None
        sess.pipeline_json = {}
        sess.id = uuid4_mock()
        asyncio.run(
            rev_deps.boltz_create_reverse_swap(
                db=None,
                request_body={"invoiceAmount": 1, "claimAddress": "bc1q…"},
                session=sess,
            )
        )
        asyncio.run(
            sub_deps.boltz_create_submarine_swap(
                db=None,
                invoice="lnbcrt1u",
                session=sess,
            )
        )

    # Both clients constructed against the shared fallback URL when
    # neither leg-pin nor registry operator is set.
    assert captured_urls == [
        "http://shared-fallback.onion/api/v2",
        "http://shared-fallback.onion/api/v2",
    ]


def test_build_default_submarine_hop_deps_constructs() -> None:
    deps = build_default_submarine_hop_deps()
    assert isinstance(deps, SubmarineHopDeps)
    assert deps.boltz_create_submarine_swap is not None
    assert deps.lnd_add_invoice is not None
    assert deps.build_and_broadcast_funding_tx is not None
    assert deps.run_refund_subprocess is not None


def test_build_default_priv_channel_hop_deps_constructs() -> None:
    deps = build_default_priv_channel_hop_deps()
    assert isinstance(deps, PrivChannelHopDeps)
    assert deps.lnd_open_private_channel is not None
    assert deps.lnd_close_channel_cooperative is not None


@pytest.mark.asyncio
async def test_dispatcher_routes_onchain_self_sourcing_to_submarine(
    db_session,
    monkeypatch,
) -> None:
    """On-chain SOURCING / FUNDING / LN_HOLDING dispatches to the
    submarine hop body. Other statuses fall through to reverse."""
    from app.services.anonymize import hop_dispatcher as hd_mod
    from app.services.anonymize.hops.submarine import SubmarineHopOutcome

    sentinel = "submarine-dispatched"

    async def _stub(db, session, deps):
        return SubmarineHopOutcome(kind="noop", detail=sentinel)

    monkeypatch.setattr(hd_mod, "execute_submarine_hop_step", _stub)

    sess = _session(
        status=AnonymizeStatus.SOURCING.value,
        source_kind="onchain-self",
    )
    db_session.add(sess)
    await db_session.flush()
    out = await default_hop_step_fn()(db_session, sess)
    assert getattr(out, "detail", "") == sentinel


@pytest.mark.asyncio
async def test_dispatcher_routes_ln_source_to_reverse(
    db_session,
    monkeypatch,
) -> None:
    """LN sources always route to the reverse hop body."""
    from app.services.anonymize import hop_dispatcher as hd_mod
    from app.services.anonymize.hops.reverse import HopStepOutcome

    sentinel = "reverse-dispatched"

    async def _stub(db, session, deps):
        return HopStepOutcome(kind="noop", detail=sentinel)

    monkeypatch.setattr(hd_mod, "execute_reverse_hop_step", _stub)

    sess = _session(
        status=AnonymizeStatus.EXITING.value,
        source_kind="ext-lightning",
    )
    db_session.add(sess)
    await db_session.flush()
    out = await default_hop_step_fn()(db_session, sess)
    assert getattr(out, "detail", "") == sentinel


def test_build_default_bolt12_pay_hop_deps_constructs() -> None:
    """The production deps-builder returns a fully-formed
    :class:`Bolt12PayHopDeps` without touching the network — a
    construction-time failure (bad import / missing symbol) would
    crash the very first session whose pipeline_json carries
    ``exit.kind == "bolt12_pay"``."""
    from app.services.anonymize.hop_dispatcher import (
        build_default_bolt12_pay_hop_deps,
    )
    from app.services.anonymize.hops.bolt12_pay import Bolt12PayHopDeps

    deps = build_default_bolt12_pay_hop_deps()
    assert isinstance(deps, Bolt12PayHopDeps)
    assert deps.pay_bolt12_offer is not None


@pytest.mark.asyncio
async def test_bolt12_pay_adapter_translates_paid_response(
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    """The adapter wraps :func:`_perform_pay_offer` and MUST translate
    a ``status="PAID"`` response into the hop body's expected shape
    (``status="paid"`` + payment_hash_hex). A regression in this
    translation would silently leave BOLT 12-exit sessions stuck in
    EXITING even after a successful payment."""
    from unittest.mock import AsyncMock

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.api import bolt12 as bolt12_api
    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.api_key import APIKey
    from app.services.anonymize.hop_dispatcher import (
        build_default_bolt12_pay_hop_deps,
    )

    # Seed the DASHBOARD_KEY_ID row + override the global session
    # maker so the adapter's ``get_session_maker()`` resolves to a
    # session backed by the test engine.
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    db_session.add(
        APIKey(
            id=DASHBOARD_KEY_ID,
            name="dashboard",
            key_hash="d" * 64,
            is_admin=True,
            is_active=True,
        )
    )
    await db_session.commit()

    # Stub ``_perform_pay_offer`` to return a settled-PAID response.
    fake = AsyncMock(
        return_value={
            "status": "PAID",
            "payment_hash_hex": "ab" * 32,
            "invoice_id": "00000000-0000-0000-0000-000000000000",
        }
    )
    monkeypatch.setattr(bolt12_api, "_perform_pay_offer", fake)

    deps = build_default_bolt12_pay_hop_deps()
    result, error = await deps.pay_bolt12_offer(
        offer="lno1test",
        amount_msat=250_000_000,
        session=None,
    )
    assert error is None
    assert result == {
        "status": "paid",
        "payment_hash_hex": "ab" * 32,
        "preimage_hex": None,
        "error": None,
    }
    fake.assert_awaited_once()


@pytest.mark.asyncio
async def test_bolt12_pay_adapter_translates_failed_response(
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    """A ``status="FAILED"`` response translates to ``"failed"``."""
    from unittest.mock import AsyncMock

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.api import bolt12 as bolt12_api
    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.api_key import APIKey
    from app.services.anonymize.hop_dispatcher import (
        build_default_bolt12_pay_hop_deps,
    )

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    db_session.add(
        APIKey(
            id=DASHBOARD_KEY_ID,
            name="dashboard",
            key_hash="d" * 64,
            is_admin=True,
            is_active=True,
        )
    )
    await db_session.commit()

    fake = AsyncMock(
        return_value={
            "status": "FAILED",
            "payment_hash_hex": "cd" * 32,
        }
    )
    monkeypatch.setattr(bolt12_api, "_perform_pay_offer", fake)

    deps = build_default_bolt12_pay_hop_deps()
    result, error = await deps.pay_bolt12_offer(
        offer="lno1test",
        amount_msat=100_000_000,
        session=None,
    )
    assert error is None
    assert result["status"] == "failed"


@pytest.mark.asyncio
async def test_bolt12_pay_adapter_translates_open_to_in_flight(
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    """Any non-paid / non-failed status (e.g., ``OPEN``) folds to
    ``"in_flight"`` so the hop body idles + lets the BOLT 12
    reconciliation sweep close it out."""
    from unittest.mock import AsyncMock

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.api import bolt12 as bolt12_api
    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.api_key import APIKey
    from app.services.anonymize.hop_dispatcher import (
        build_default_bolt12_pay_hop_deps,
    )

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    db_session.add(
        APIKey(
            id=DASHBOARD_KEY_ID,
            name="dashboard",
            key_hash="d" * 64,
            is_admin=True,
            is_active=True,
        )
    )
    await db_session.commit()

    fake = AsyncMock(
        return_value={
            "status": "OPEN",  # invoice issued but not yet settled
            "payment_hash_hex": "ef" * 32,
        }
    )
    monkeypatch.setattr(bolt12_api, "_perform_pay_offer", fake)

    deps = build_default_bolt12_pay_hop_deps()
    result, error = await deps.pay_bolt12_offer(
        offer="lno1test",
        amount_msat=100_000_000,
        session=None,
    )
    assert error is None
    assert result["status"] == "in_flight"


@pytest.mark.asyncio
async def test_bolt12_pay_adapter_handles_missing_dashboard_key(
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    """When the DASHBOARD_KEY_ID row is absent, the adapter returns
    ``(None, "...missing...")`` instead of triggering a cryptic FK
    constraint violation deep in ``_perform_pay_offer``."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services.anonymize.hop_dispatcher import (
        build_default_bolt12_pay_hop_deps,
    )

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    # No DASHBOARD_KEY_ID seeded — adapter MUST detect this and
    # surface a clean error string.

    deps = build_default_bolt12_pay_hop_deps()
    result, error = await deps.pay_bolt12_offer(
        offer="lno1test",
        amount_msat=100_000_000,
        session=None,
    )
    assert result is None
    assert error is not None
    assert "dashboard api key" in error.lower()


@pytest.mark.asyncio
async def test_bolt12_pay_adapter_translates_helper_exception(
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    """An exception raised by ``_perform_pay_offer`` (gateway error,
    malformed invoice, signature mismatch) translates to a clean
    ``(None, error)`` tuple instead of crashing the per-session
    loop."""

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.api import bolt12 as bolt12_api
    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.api_key import APIKey
    from app.services.anonymize.hop_dispatcher import (
        build_default_bolt12_pay_hop_deps,
    )

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    db_session.add(
        APIKey(
            id=DASHBOARD_KEY_ID,
            name="dashboard",
            key_hash="d" * 64,
            is_admin=True,
            is_active=True,
        )
    )
    await db_session.commit()

    async def _raise(*_args, **_kwargs):
        raise RuntimeError("gateway unreachable")

    monkeypatch.setattr(bolt12_api, "_perform_pay_offer", _raise)

    deps = build_default_bolt12_pay_hop_deps()
    result, error = await deps.pay_bolt12_offer(
        offer="lno1test",
        amount_msat=100_000_000,
        session=None,
    )
    assert result is None
    assert error is not None
    assert "gateway unreachable" in error


@pytest.mark.asyncio
async def test_dispatcher_routes_bolt12_exit_to_bolt12_pay_hop(
    db_session,
    monkeypatch,
) -> None:
    """A session whose pipeline exit is ``bolt12_pay`` routes
    to the new hop body, bypassing the reverse-swap path."""
    from app.services.anonymize import hop_dispatcher as hd_mod
    from app.services.anonymize.hops.bolt12_pay import HopStepOutcome

    sentinel = "bolt12-pay-dispatched"

    async def _stub(db, session, deps):
        return HopStepOutcome(kind="noop", detail=sentinel)

    monkeypatch.setattr(hd_mod, "execute_bolt12_pay_hop_step", _stub)

    sess = _session(
        status=AnonymizeStatus.EXITING.value,
        source_kind="ext-lightning",
    )
    sess.pipeline_json = {
        "exit": {
            "kind": "bolt12_pay",
            "destination_address": "",
            "bolt12_offer": "lno1deadbeef",
            "bip353_handle": "alice@example.com",
        },
    }
    db_session.add(sess)
    await db_session.flush()
    out = await default_hop_step_fn()(db_session, sess)
    assert getattr(out, "detail", "") == sentinel


@pytest.mark.asyncio
async def test_dispatcher_routes_reverse_exit_to_reverse_hop(
    db_session,
    monkeypatch,
) -> None:
    """A raw reverse-exit pipeline routes to the reverse hop body
    even when the session row carries a ``bolt12_pay_outcome`` block
    from a stale state — the routing key is ``pipeline.exit.kind``."""
    from app.services.anonymize import hop_dispatcher as hd_mod
    from app.services.anonymize.hops.reverse import HopStepOutcome

    sentinel = "reverse-routed-not-bolt12"

    async def _stub(db, session, deps):
        return HopStepOutcome(kind="noop", detail=sentinel)

    monkeypatch.setattr(hd_mod, "execute_reverse_hop_step", _stub)

    sess = _session(
        status=AnonymizeStatus.EXITING.value,
        source_kind="ext-lightning",
    )
    sess.pipeline_json = {
        "exit": {"kind": "reverse", "destination_address": "bcrt1qtest"},
    }
    db_session.add(sess)
    await db_session.flush()
    out = await default_hop_step_fn()(db_session, sess)
    assert getattr(out, "detail", "") == sentinel


@pytest.mark.asyncio
async def test_submarine_funding_adapter_jitters_feerate(
    monkeypatch,
    db_session,
) -> None:
    """The funding-tx adapter pulls a live economy estimate
    and passes a jittered ``sat_per_vbyte`` to LND's ``send_coins``."""
    from app.core.config import settings
    from app.services.anonymize import chain_egress
    from app.services.anonymize import hop_dispatcher as hd_mod

    monkeypatch.setattr(settings, "anonymize_feerate_jitter_lo", 0.9)
    monkeypatch.setattr(settings, "anonymize_feerate_jitter_hi", 1.1)

    async def _stub_economy(**_):
        return 20.0, None

    captured: dict = {}

    class _StubLnd:
        async def send_coins(self, **kwargs):
            captured.update(kwargs)
            return {"txid": "ab" * 32}, None

    monkeypatch.setattr(
        chain_egress,
        "get_anonymize_economy_feerate",
        _stub_economy,
    )

    import app.services.lnd_service as lnd_mod

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = hd_mod.build_default_submarine_hop_deps()
    out, err = await deps.build_and_broadcast_funding_tx(
        lockup_address="bcrt1qlockup",
        amount_sat=250_000,
        session=_session(
            status=AnonymizeStatus.FUNDING.value,
            source_kind="onchain-self",
        ),
    )
    assert err is None
    # sat_per_vbyte is non-None + within the jitter band [18, 22].
    assert captured.get("sat_per_vbyte") is not None
    assert 18 <= int(captured["sat_per_vbyte"]) <= 22


@pytest.mark.asyncio
async def test_priv_channel_open_adapter_jitters_feerate(
    monkeypatch,
) -> None:
    """Channel-open feerate is jittered the same way."""
    from app.core.config import settings
    from app.services.anonymize import chain_egress
    from app.services.anonymize import hop_dispatcher as hd_mod

    monkeypatch.setattr(settings, "anonymize_feerate_jitter_lo", 0.9)
    monkeypatch.setattr(settings, "anonymize_feerate_jitter_hi", 1.1)

    async def _stub_economy(**_):
        return 30.0, None

    captured: dict = {}

    class _StubLnd:
        async def open_channel(self, **kwargs):
            captured.update(kwargs)
            return {"funding_txid": "ab" * 32, "output_index": 0}, None

    monkeypatch.setattr(
        chain_egress,
        "get_anonymize_economy_feerate",
        _stub_economy,
    )

    import app.services.lnd_service as lnd_mod

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = hd_mod.build_default_priv_channel_hop_deps()
    cp, err = await deps.lnd_open_private_channel(
        peer_pubkey="02" + "aa" * 32,
        local_funding_amount_sat=1_000_000,
    )
    assert err is None
    assert captured.get("sat_per_vbyte") is not None
    assert 27 <= int(captured["sat_per_vbyte"]) <= 33


@pytest.mark.asyncio
async def test_submarine_funding_pins_exact_bin_utxo_when_match_exists(
    monkeypatch,
    db_session,
) -> None:
    """When an exact-bin UTXO is in the wallet, the funding
    adapter pins it as the input via ``send_coins(outpoints=...)``
    so the funding tx is single-input + no-change."""
    from app.core.config import settings as _settings
    from app.services.anonymize import chain_egress
    from app.services.anonymize import hop_dispatcher as hd_mod

    # No jitter to keep test deterministic.
    monkeypatch.setattr(_settings, "anonymize_feerate_jitter_lo", 1.0)
    monkeypatch.setattr(_settings, "anonymize_feerate_jitter_hi", 1.0)
    # Wide exact-bin tolerance so the test UTXO passes.
    monkeypatch.setattr(_settings, "anonymize_exact_bin_tolerance_sat", 10_000)

    async def _stub_economy(**_):
        return 5.0, None

    captured: dict = {}

    class _StubLnd:
        async def list_unspent(self, **_):
            # One UTXO that's within tolerance of bin + max_fee
            # (250_000 + 400 = 250_400; this UTXO is 250_500).
            return [
                {
                    "outpoint": {"txid_str": "ab" * 32, "output_index": 1},
                    "amount_sat": 250_500,
                    "confirmations": 6,
                    "address": "bcrt1pX",
                    "address_type": "TAPROOT_PUBKEY",
                }
            ], None

        async def send_coins(self, **kwargs):
            captured.update(kwargs)
            return {"txid": "cd" * 32}, None

        async def send_outputs(self, **_):
            return None, "should not be called"

        async def new_address(self, **_):
            return None, "should not be called"

    monkeypatch.setattr(
        chain_egress,
        "get_anonymize_economy_feerate",
        _stub_economy,
    )
    import app.services.lnd_service as lnd_mod

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    sess_row = _session(
        status=AnonymizeStatus.FUNDING.value,
        source_kind="onchain-self",
    )
    db_session.add(sess_row)
    await db_session.commit()

    deps = hd_mod.build_default_submarine_hop_deps()
    out, err = await deps.build_and_broadcast_funding_tx(
        lockup_address="bcrt1qlockup",
        amount_sat=250_000,
        session=sess_row,
    )
    assert err is None
    # The matching UTXO was pinned as the input.
    pinned = captured.get("outpoints") or []
    assert len(pinned) == 1
    assert pinned[0]["txid_str"] == "ab" * 32
    assert pinned[0]["output_index"] == 1


@pytest.mark.asyncio
async def test_submarine_funding_refuses_utxo_matching_bin_post_feature_day(
    monkeypatch,
    db_session,
) -> None:
    """A UTXO whose value matches a published bin within
    tolerance + confirmed on/after ``feature_enabled_at_day`` is
    refused as a source. With NO other UTXOs available, the adapter
    falls through to the consolidation path (or LND default)."""
    from datetime import date as _date

    from app.core.config import settings as _settings
    from app.services.anonymize import chain_egress, settings_store
    from app.services.anonymize import hop_dispatcher as hd_mod

    monkeypatch.setattr(_settings, "anonymize_feerate_jitter_lo", 1.0)
    monkeypatch.setattr(_settings, "anonymize_feerate_jitter_hi", 1.0)
    monkeypatch.setattr(
        _settings,
        "anonymize_amount_bins_sat",
        "250000",
    )
    monkeypatch.setattr(
        _settings,
        "anonymize_exact_bin_tolerance_sat",
        100,
    )

    # Force feature_enabled_at_day to a long-past date so the UTXO
    # (1 confirmation = roughly now) counts as post-feature.
    async def _stub_feature_day(_db):
        return _date(2020, 1, 1)

    monkeypatch.setattr(
        settings_store,
        "get_feature_enabled_at_day",
        _stub_feature_day,
    )

    async def _stub_economy(**_):
        return 5.0, None

    captured: dict = {}

    class _StubLnd:
        async def list_unspent(self, **_):
            # UTXO whose value === bin amount (refused by).
            return [
                {
                    "outpoint": {"txid_str": "ee" * 32, "output_index": 0},
                    "amount_sat": 250_000,
                    "confirmations": 6,
                    "address": "bcrt1pE",
                    "address_type": "TAPROOT_PUBKEY",
                }
            ], None

        async def new_address(self, **_):
            return {"address": "bcrt1p" + "d" * 56}, None

        async def send_outputs(self, **kwargs):
            captured["used_consolidation"] = True
            captured["outputs"] = kwargs.get("outputs")
            return {"txid": "cc" * 32}, None

        async def send_coins(self, **kwargs):
            captured["used_send_coins"] = True
            captured["outpoints"] = kwargs.get("outpoints")
            return {"txid": "cc" * 32}, None

    monkeypatch.setattr(
        chain_egress,
        "get_anonymize_economy_feerate",
        _stub_economy,
    )
    import app.services.lnd_service as lnd_mod

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    monkeypatch.setattr(
        _settings,
        "anonymize_decoy_seed_account_key",
        "y" * 32,
    )

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.core import database as _db

    factory = async_sessionmaker(db_session.bind, expire_on_commit=False)
    monkeypatch.setattr(_db, "get_session_maker", lambda: factory)

    sess_row = _session(
        status=AnonymizeStatus.FUNDING.value,
        source_kind="onchain-self",
    )
    db_session.add(sess_row)
    await db_session.commit()

    deps = hd_mod.build_default_submarine_hop_deps()
    out, err = await deps.build_and_broadcast_funding_tx(
        lockup_address="bcrt1qlockup",
        amount_sat=250_000,
        session=sess_row,
    )
    assert err is None
    # The.1-refused UTXO was NOT pinned: no outpoints supplied
    # to send_coins; instead the consolidation fallback fired.
    assert captured.get("used_consolidation") is True


@pytest.mark.asyncio
async def test_submarine_funding_routes_through_consolidation_when_no_exact_bin(
    monkeypatch,
    db_session,
) -> None:
    """When ``select_exact_bin_funding`` can't find a
    single-UTXO match (no exact-bin in the wallet), the funding
    adapter emits a 2-output tx (lockup + decoy) via
    ``lnd_service.send_outputs`` AND persists the decoy row +
    derivation index."""
    from app.core.config import settings as _settings
    from app.models.anonymize_session import AnonymizeDecoyOutput
    from app.services.anonymize import chain_egress
    from app.services.anonymize import hop_dispatcher as hd_mod

    monkeypatch.setattr(
        _settings,
        "anonymize_decoy_seed_account_key",
        "y" * 32,
    )
    monkeypatch.setattr(
        _settings,
        "anonymize_consolidation_decoy_min_sat",
        100_000,
    )
    monkeypatch.setattr(
        _settings,
        "anonymize_consolidation_decoy_max_sat",
        500_000,
    )
    monkeypatch.setattr(
        _settings,
        "anonymize_preconsolidation_overpad_min_sat",
        10_000,
    )
    monkeypatch.setattr(
        _settings,
        "anonymize_preconsolidation_overpad_max_sat",
        20_000,
    )

    async def _stub_economy(**_):
        return 5.0, None

    captured: dict = {}

    class _StubLnd:
        async def list_unspent(self, **_):
            # No UTXO matches bin_amount + max_fee → consolidation
            # path triggers.
            return [], None

        async def new_address(self, **_):
            return {"address": "bcrt1p" + "f" * 56}, None

        async def send_outputs(self, **kwargs):
            captured.update(kwargs)
            return {"txid": "ab" * 32}, None

        async def send_coins(self, **_):
            return {"txid": "should-not-be-called"}, None

    monkeypatch.setattr(
        chain_egress,
        "get_anonymize_economy_feerate",
        _stub_economy,
    )
    import app.services.lnd_service as lnd_mod

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    # Pre-add a session row so record_decoy_output's FK is honored.
    sess_row = _session(
        status=AnonymizeStatus.FUNDING.value,
        source_kind="onchain-self",
    )
    db_session.add(sess_row)
    await db_session.commit()

    # Patch the session_maker so record_decoy_output writes against
    # the same db_session.
    from sqlalchemy.ext.asyncio import async_sessionmaker

    # Stub the get_session_maker call in record_decoy_output to use
    # the test db_engine.
    from app.core import database as _db

    factory = async_sessionmaker(
        db_session.bind,
        expire_on_commit=False,
    )
    monkeypatch.setattr(_db, "get_session_maker", lambda: factory)

    deps = hd_mod.build_default_submarine_hop_deps()
    out, err = await deps.build_and_broadcast_funding_tx(
        lockup_address="bcrt1qlockup",
        amount_sat=250_000,
        session=sess_row,
    )
    assert err is None
    assert captured  # send_outputs was called
    outputs = captured.get("outputs") or []
    addresses = [o["address"] for o in outputs]
    assert "bcrt1qlockup" in addresses
    assert any(a.startswith("bcrt1p") for a in addresses)  # decoy

    # Decoy row was written.
    from sqlalchemy import select as _select

    rows = (
        (await db_session.execute(_select(AnonymizeDecoyOutput).where(AnonymizeDecoyOutput.session_id == sess_row.id)))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].address.startswith("bcrt1p")
    assert 100_000 <= rows[0].value_sat <= 500_000


@pytest.mark.asyncio
async def test_submarine_funding_adapter_falls_back_when_no_economy_estimate(
    monkeypatch,
    db_session,
) -> None:
    """When the economy probe fails, the adapter still funds the
    lockup (passing ``sat_per_vbyte=None`` so LND picks its default)."""
    from app.services.anonymize import chain_egress
    from app.services.anonymize import hop_dispatcher as hd_mod

    async def _stub_no_economy(**_):
        return None, "chain backend unreachable"

    captured: dict = {}

    class _StubLnd:
        async def send_coins(self, **kwargs):
            captured.update(kwargs)
            return {"txid": "cd" * 32}, None

    monkeypatch.setattr(
        chain_egress,
        "get_anonymize_economy_feerate",
        _stub_no_economy,
    )

    import app.services.lnd_service as lnd_mod

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = hd_mod.build_default_submarine_hop_deps()
    out, err = await deps.build_and_broadcast_funding_tx(
        lockup_address="bcrt1qlockup",
        amount_sat=250_000,
        session=_session(
            status=AnonymizeStatus.FUNDING.value,
            source_kind="onchain-self",
        ),
    )
    assert err is None
    assert captured.get("sat_per_vbyte") is None


@pytest.mark.asyncio
async def test_dispatcher_routes_onchain_exiting_to_reverse(
    db_session,
    monkeypatch,
) -> None:
    """An on-chain source past LN_HOLDING (i.e., the submarine settled)
    routes the EXITING + CONFIRMING ticks to the reverse hop body."""
    from app.services.anonymize import hop_dispatcher as hd_mod
    from app.services.anonymize.hops.reverse import HopStepOutcome

    sentinel = "reverse-dispatched-for-onchain-exit"

    async def _stub(db, session, deps):
        return HopStepOutcome(kind="noop", detail=sentinel)

    monkeypatch.setattr(hd_mod, "execute_reverse_hop_step", _stub)

    sess = _session(
        status=AnonymizeStatus.EXITING.value,
        source_kind="onchain-self",
    )
    db_session.add(sess)
    await db_session.flush()
    out = await default_hop_step_fn()(db_session, sess)
    assert getattr(out, "detail", "") == sentinel


def test_build_default_ln_self_pay_hop_deps_constructs() -> None:
    """The production deps-builder returns a fully-formed
    :class:`LnSelfPayHopDeps` without touching the network — a
    construction-time failure (bad import / missing symbol) would
    surface here rather than at the first FUNDING tick."""
    from app.services.anonymize.hop_dispatcher import build_default_ln_self_pay_hop_deps
    from app.services.anonymize.hops.ln_self_pay import LnSelfPayHopDeps

    deps = build_default_ln_self_pay_hop_deps()
    assert isinstance(deps, LnSelfPayHopDeps)
    assert deps.lnd_send_self_payment is not None
    assert deps.resolve_self_pay_route is not None


@pytest.mark.asyncio
async def test_dispatcher_routes_ln_self_funding_to_self_pay(
    db_session,
    monkeypatch,
) -> None:
    """An LN-self source at FUNDING / LN_HOLDING dispatches to the
    self-pay hop body."""
    from app.services.anonymize import hop_dispatcher as hd_mod
    from app.services.anonymize.hops.ln_self_pay import LnSelfPayHopOutcome

    sentinel = "ln-self-pay-dispatched"

    async def _stub(db, session, deps):
        return LnSelfPayHopOutcome(kind="noop", detail=sentinel)

    monkeypatch.setattr(hd_mod, "execute_ln_self_pay_hop_step", _stub)

    for status in (AnonymizeStatus.FUNDING.value, AnonymizeStatus.LN_HOLDING.value):
        sess = _session(status=status, source_kind="lightning-self")
        db_session.add(sess)
        await db_session.flush()
        out = await default_hop_step_fn()(db_session, sess)
        assert getattr(out, "detail", "") == sentinel


@pytest.mark.asyncio
async def test_dispatcher_routes_ln_self_exiting_to_reverse(
    db_session,
    monkeypatch,
) -> None:
    """Past the source states, an LN-self session's EXITING tick routes
    to the reverse hop body for the exit — NOT the self-pay body."""
    from app.services.anonymize import hop_dispatcher as hd_mod
    from app.services.anonymize.hops.reverse import HopStepOutcome

    sentinel = "reverse-dispatched-for-ln-self-exit"

    async def _stub(db, session, deps):
        return HopStepOutcome(kind="noop", detail=sentinel)

    async def _self_pay_stub(db, session, deps):  # must NOT be called
        raise AssertionError("self-pay body must not run at EXITING")

    monkeypatch.setattr(hd_mod, "execute_reverse_hop_step", _stub)
    monkeypatch.setattr(hd_mod, "execute_ln_self_pay_hop_step", _self_pay_stub)

    sess = _session(status=AnonymizeStatus.EXITING.value, source_kind="lightning-self")
    db_session.add(sess)
    await db_session.flush()
    out = await default_hop_step_fn()(db_session, sess)
    assert getattr(out, "detail", "") == sentinel


# ── reverse-hop adapter primitives (status / payment / claim / broadcast) ──


@pytest.mark.asyncio
async def test_reverse_send_payment_forwards_lnd_error(monkeypatch) -> None:
    """The reverse-leg payment adapter relays LND's ``(None, error)``
    tuple unchanged so the hop body can route a failed self-payment to
    its bounded-retry path instead of crashing."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_reverse_hop_deps

    class _StubLnd:
        async def send_payment_v2(self, **_kwargs):
            return None, "no_route"

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_reverse_hop_deps()
    result, err = await deps.lnd_send_payment(payment_request="lnbcrt1u", max_parts=4)
    assert result is None
    assert err == "no_route"


@pytest.mark.asyncio
async def test_reverse_chain_broadcast_forwards_error(monkeypatch) -> None:
    """A broadcast rejection from the dedicated anonymize chain client
    surfaces as ``(None, error)`` — the claim hex is never silently
    treated as broadcast."""
    from app.services.anonymize import chain_egress
    from app.services.anonymize.hop_dispatcher import build_default_reverse_hop_deps

    async def _stub_broadcast(_tx_hex):
        return None, "txn-mempool-conflict"

    monkeypatch.setattr(chain_egress, "anonymize_broadcast_tx", _stub_broadcast)

    deps = build_default_reverse_hop_deps()
    txid, err = await deps.chain_broadcast_tx("0200dead")
    assert txid is None
    assert err == "txn-mempool-conflict"


@pytest.mark.asyncio
async def test_reverse_chain_broadcast_returns_txid_on_success(monkeypatch) -> None:
    from app.services.anonymize import chain_egress
    from app.services.anonymize.hop_dispatcher import build_default_reverse_hop_deps

    async def _stub_broadcast(_tx_hex):
        return "broadcast_txid", None

    monkeypatch.setattr(chain_egress, "anonymize_broadcast_tx", _stub_broadcast)

    deps = build_default_reverse_hop_deps()
    txid, err = await deps.chain_broadcast_tx("0200beef")
    assert err is None
    assert txid == "broadcast_txid"


@pytest.mark.asyncio
async def test_reverse_run_claim_subprocess_returns_txid_on_success(
    monkeypatch,
    db_session,
    db_engine,
) -> None:
    """When the swap row exists and ``cooperative_claim`` succeeds, the
    reverse-leg adapter returns the claim txid the hop body persists."""
    from uuid import uuid4 as _uuid4

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models.boltz_swap import BoltzSwap, SwapStatus
    from app.services.anonymize.hop_dispatcher import build_default_reverse_hop_deps

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    swap = BoltzSwap(
        id=_uuid4(),
        api_key_id=_uuid4(),
        boltz_swap_id="rev-claim-ok",
        status=SwapStatus.INVOICE_PAID,
        invoice_amount_sats=250_000,
        destination_address="bcrt1qdest",
        status_history=[],
    )
    db_session.add(swap)
    await db_session.commit()

    import app.services.boltz_service as boltz_mod

    async def _fake_coop_claim(*, swap, lockup_tx_hex):
        return "claim_txid_zzz", None

    monkeypatch.setattr(boltz_mod.boltz_service, "cooperative_claim", _fake_coop_claim)

    deps = build_default_reverse_hop_deps()
    txid, err = await deps.run_claim_subprocess(swap_id="rev-claim-ok", lockup_tx={"hex": "0200lock"})
    assert err is None
    assert txid == "claim_txid_zzz"


@pytest.mark.asyncio
async def test_reverse_run_claim_subprocess_forwards_claim_error(
    monkeypatch,
    db_session,
    db_engine,
) -> None:
    """A cooperative-claim failure propagates as ``(None, error)`` so the
    hop body can fall through to its retry / unilateral path."""
    from uuid import uuid4 as _uuid4

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.models.boltz_swap import BoltzSwap, SwapStatus
    from app.services.anonymize.hop_dispatcher import build_default_reverse_hop_deps

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    swap = BoltzSwap(
        id=_uuid4(),
        api_key_id=_uuid4(),
        boltz_swap_id="rev-claim-fail",
        status=SwapStatus.INVOICE_PAID,
        invoice_amount_sats=250_000,
        destination_address="bcrt1qdest",
        status_history=[],
    )
    db_session.add(swap)
    await db_session.commit()

    import app.services.boltz_service as boltz_mod

    async def _fake_coop_claim(*, swap, lockup_tx_hex):
        return None, "boltz cosign refused"

    monkeypatch.setattr(boltz_mod.boltz_service, "cooperative_claim", _fake_coop_claim)

    deps = build_default_reverse_hop_deps()
    txid, err = await deps.run_claim_subprocess(swap_id="rev-claim-fail", lockup_tx="0200lock")
    assert txid is None
    assert err == "boltz cosign refused"


@pytest.mark.asyncio
async def test_reverse_run_claim_subprocess_errors_when_swap_row_missing(
    monkeypatch,
    db_engine,
) -> None:
    """The reverse-leg claim adapter looks the swap up by its Boltz id;
    a missing row yields a specific error rather than dereferencing
    ``None`` against ``cooperative_claim``."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services.anonymize.hop_dispatcher import build_default_reverse_hop_deps

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    deps = build_default_reverse_hop_deps()
    txid, err = await deps.run_claim_subprocess(swap_id="no-such-swap", lockup_tx="0200")
    assert txid is None
    assert "swap row missing" in err
    assert "no-such-swap" in err


@pytest.mark.asyncio
async def test_reverse_get_swap_status_forwards_client_tuple(monkeypatch) -> None:
    """The reverse-leg status adapter must construct a per-call client
    and return the client's ``(status, data, error)`` triple unchanged so
    polling reflects the live Boltz state."""
    from app.services.anonymize import boltz_egress as _be
    from app.services.anonymize.hop_dispatcher import build_default_reverse_hop_deps

    async def _spy_status(self, boltz_swap_id, *, operator_id=None):
        return "swap.created", {"id": boltz_swap_id}, None

    with patch.object(_be.AnonymizeBoltzClient, "get_swap_status", _spy_status):
        deps = build_default_reverse_hop_deps()
        status, data, err = await deps.boltz_get_swap_status("rev-1", operator_id=None)
    assert err is None
    assert status == "swap.created"
    assert data == {"id": "rev-1"}


@pytest.mark.asyncio
async def test_submarine_get_swap_status_forwards_client_error(monkeypatch) -> None:
    """Symmetric assertion for the submarine leg's status adapter on an
    error triple."""
    from app.services.anonymize import boltz_egress as _be
    from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps

    async def _spy_status(self, boltz_swap_id, *, operator_id=None):
        return None, None, "operator unreachable"

    with patch.object(_be.AnonymizeBoltzClient, "get_swap_status", _spy_status):
        deps = build_default_submarine_hop_deps()
        status, data, err = await deps.boltz_get_swap_status("sub-1", operator_id=None)
    assert status is None
    assert err == "operator unreachable"


# ── submarine-hop adapter primitives ──────────────────────────────────


@pytest.mark.asyncio
async def test_submarine_add_invoice_translates_lnd_error(monkeypatch) -> None:
    """The submarine leg's invoice adapter must surface LND's error and
    return no result so the hop body doesn't try to fund against a
    missing payment_request."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps

    class _StubLnd:
        async def create_invoice(self, **_kwargs):
            return None, "lnd_unreachable"

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_submarine_hop_deps()
    result, err = await deps.lnd_add_invoice(amount_sat=250_000, memo="x")
    assert result is None
    assert err == "lnd_unreachable"


@pytest.mark.asyncio
async def test_submarine_add_invoice_translates_raised_exception(monkeypatch) -> None:
    """A raised exception from ``create_invoice`` is caught and returned
    as a clean ``(None, str)`` tuple rather than propagating out of the
    per-session loop."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps

    class _StubLnd:
        async def create_invoice(self, **_kwargs):
            raise RuntimeError("grpc deadline exceeded")

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_submarine_hop_deps()
    result, err = await deps.lnd_add_invoice(amount_sat=250_000, memo=None)
    assert result is None
    assert "grpc deadline exceeded" in err


@pytest.mark.asyncio
async def test_submarine_run_refund_subprocess_errors_when_swap_row_missing(
    monkeypatch,
    db_engine,
) -> None:
    """The submarine refund adapter resolves the swap row by Boltz id;
    a missing row fails closed with a specific error and never derives a
    change address or spawns the refund script."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    deps = build_default_submarine_hop_deps()
    hex_value, err = await deps.run_refund_subprocess(
        swap_id="ghost-submarine",
        session=_session(
            status=AnonymizeStatus.FUNDING.value,
            source_kind="onchain-self",
        ),
    )
    assert hex_value is None
    assert "submarine swap row missing" in err
    assert "ghost-submarine" in err


@pytest.mark.asyncio
async def test_submarine_run_refund_subprocess_errors_when_change_address_unavailable(
    monkeypatch,
    db_session,
    db_engine,
) -> None:
    """The refund output needs a wallet-controlled p2tr address; when LND
    can't derive one the adapter fails closed before spawning the refund
    script (otherwise the locked funds would be sent nowhere)."""
    from uuid import uuid4 as _uuid4

    from sqlalchemy.ext.asyncio import async_sessionmaker

    import app.services.lnd_service as lnd_mod
    from app.core.encryption import encrypt_field
    from app.models.boltz_swap import BoltzSwap, SwapStatus
    from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    swap = BoltzSwap(
        id=_uuid4(),
        api_key_id=_uuid4(),
        boltz_swap_id="refund-no-addr",
        status=SwapStatus.CREATED,
        invoice_amount_sats=250_000,
        destination_address="bcrt1qdest",
        status_history=[],
        claim_private_key_hex=encrypt_field("ab" * 32),
        claim_public_key_hex="02" + "cd" * 32,
        boltz_swap_tree_json={"claimLeaf": {}},
        timeout_block_height=800_000,
    )
    db_session.add(swap)
    await db_session.commit()

    class _StubLnd:
        async def new_address(self, **_kwargs):
            return None, "wallet locked"

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_submarine_hop_deps()
    hex_value, err = await deps.run_refund_subprocess(
        swap_id="refund-no-addr",
        session=_session(
            status=AnonymizeStatus.FUNDING.value,
            source_kind="onchain-self",
        ),
    )
    assert hex_value is None
    assert "could not derive change address" in err


def _seed_submarine_swap_for_refund(db_session, db_engine, monkeypatch, *, boltz_swap_id: str):
    """Persist a refundable submarine swap row + bind the session maker
    to the test engine. Returns nothing; the caller drives the adapter."""
    from uuid import uuid4 as _uuid4

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.core.encryption import encrypt_field
    from app.models.boltz_swap import BoltzSwap, SwapStatus

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr("app.core.database.get_session_maker", lambda: factory)

    swap = BoltzSwap(
        id=_uuid4(),
        api_key_id=_uuid4(),
        boltz_swap_id=boltz_swap_id,
        status=SwapStatus.CREATED,
        invoice_amount_sats=250_000,
        destination_address="bcrt1qdest",
        status_history=[],
        claim_private_key_hex=encrypt_field("ab" * 32),
        claim_public_key_hex="02" + "cd" * 32,
        boltz_swap_tree_json={"claimLeaf": {}},
        timeout_block_height=800_000,
    )
    db_session.add(swap)
    return swap


class _FakeClaimTxHex:
    def __init__(self, value):
        self.value = value


class _FakeSubprocessResult:
    def __init__(self, *, returncode, hex_value):
        self.returncode = returncode
        self.claim_tx_hex = _FakeClaimTxHex(hex_value)


def _refund_lnd_with_address(monkeypatch):
    import app.services.lnd_service as lnd_mod

    class _StubLnd:
        async def new_address(self, **_kwargs):
            return {"address": "bcrt1p" + "f" * 58}, None

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())


@pytest.mark.asyncio
async def test_submarine_run_refund_subprocess_returns_fd_hex_on_success(
    monkeypatch,
    db_session,
    db_engine,
) -> None:
    """A clean refund run returns the out-of-band tx hex the script
    wrote, which the hop body then broadcasts to reclaim the lockup."""
    from app.services.anonymize import subprocess as sub_mod
    from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps

    _seed_submarine_swap_for_refund(db_session, db_engine, monkeypatch, boltz_swap_id="refund-ok")
    await db_session.commit()
    _refund_lnd_with_address(monkeypatch)

    async def _fake_run(**_kwargs):
        return _FakeSubprocessResult(returncode=0, hex_value="0200refundhex")

    monkeypatch.setattr(sub_mod, "run_boltz_claim_js", _fake_run)

    deps = build_default_submarine_hop_deps()
    hex_value, err = await deps.run_refund_subprocess(
        swap_id="refund-ok",
        session=_session(status=AnonymizeStatus.FUNDING.value, source_kind="onchain-self"),
    )
    assert err is None
    assert hex_value == "0200refundhex"


@pytest.mark.asyncio
async def test_submarine_run_refund_subprocess_errors_on_empty_fd_hex(
    monkeypatch,
    db_session,
    db_engine,
) -> None:
    """A run that produces no fd hex is a failure — the refund tx must be
    captured out-of-band or the funds can't be reclaimed."""
    from app.services.anonymize import subprocess as sub_mod
    from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps

    _seed_submarine_swap_for_refund(db_session, db_engine, monkeypatch, boltz_swap_id="refund-nohex")
    await db_session.commit()
    _refund_lnd_with_address(monkeypatch)

    async def _fake_run(**_kwargs):
        return _FakeSubprocessResult(returncode=0, hex_value=None)

    monkeypatch.setattr(sub_mod, "run_boltz_claim_js", _fake_run)

    deps = build_default_submarine_hop_deps()
    hex_value, err = await deps.run_refund_subprocess(
        swap_id="refund-nohex",
        session=_session(status=AnonymizeStatus.FUNDING.value, source_kind="onchain-self"),
    )
    assert hex_value is None
    assert "no fd-3 hex" in err


@pytest.mark.asyncio
async def test_submarine_run_refund_subprocess_translates_timeout(
    monkeypatch,
    db_session,
    db_engine,
) -> None:
    from app.services.anonymize import subprocess as sub_mod
    from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps

    _seed_submarine_swap_for_refund(db_session, db_engine, monkeypatch, boltz_swap_id="refund-timeout")
    await db_session.commit()
    _refund_lnd_with_address(monkeypatch)

    async def _fake_run(**_kwargs):
        raise sub_mod.SubprocessTimeoutError("budget exceeded")

    monkeypatch.setattr(sub_mod, "run_boltz_claim_js", _fake_run)

    deps = build_default_submarine_hop_deps()
    hex_value, err = await deps.run_refund_subprocess(
        swap_id="refund-timeout",
        session=_session(status=AnonymizeStatus.FUNDING.value, source_kind="onchain-self"),
    )
    assert hex_value is None
    assert "timeout" in err


@pytest.mark.asyncio
async def test_submarine_chain_broadcast_forwards_error(monkeypatch) -> None:
    """The submarine leg's broadcast adapter relays a chain-client
    rejection rather than treating the refund tx as broadcast."""
    from app.services.anonymize import chain_egress
    from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps

    async def _stub_broadcast(_tx_hex):
        return None, "min relay fee not met"

    monkeypatch.setattr(chain_egress, "anonymize_broadcast_tx", _stub_broadcast)

    deps = build_default_submarine_hop_deps()
    txid, err = await deps.chain_broadcast_tx("0200refund")
    assert txid is None
    assert err == "min relay fee not met"


@pytest.mark.asyncio
async def test_submarine_check_inbound_sufficient_relays_refusal(monkeypatch) -> None:
    """The inbound-capacity preflight relays the refusal string from
    ``inbound_preflight`` so the hop body can decline a funding it can't
    receive back over LN."""
    from app.services.anonymize import inbound_preflight as ip_mod
    from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps

    async def _stub_preflight(*, receive_sats):
        return "insufficient inbound liquidity", None

    monkeypatch.setattr(ip_mod, "inbound_preflight", _stub_preflight)

    deps = build_default_submarine_hop_deps()
    refusal = await deps.check_inbound_sufficient(250_000)
    assert refusal == "insufficient inbound liquidity"


@pytest.mark.asyncio
async def test_submarine_check_inbound_sufficient_returns_none_when_ok(monkeypatch) -> None:
    from app.services.anonymize import inbound_preflight as ip_mod
    from app.services.anonymize.hop_dispatcher import build_default_submarine_hop_deps

    async def _stub_preflight(*, receive_sats):
        return None, None

    monkeypatch.setattr(ip_mod, "inbound_preflight", _stub_preflight)

    deps = build_default_submarine_hop_deps()
    refusal = await deps.check_inbound_sufficient(250_000)
    assert refusal is None


# ── priv_channel adapter primitives ───────────────────────────────────


@pytest.mark.asyncio
async def test_priv_channel_select_auto_peer_errors_on_describe_graph_failure(monkeypatch) -> None:
    """When LND's ``describe_graph`` fails, the auto-peer selector returns
    a specific error rather than picking from a half-built graph."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_priv_channel_hop_deps

    class _StubLnd:
        async def describe_graph(self, **_kwargs):
            return None, "graph rpc failed"

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_priv_channel_hop_deps()
    peer, err = await deps.select_auto_peer(
        session=_session(
            status=AnonymizeStatus.SOURCING.value,
            source_kind="ext-lightning",
        ),
    )
    assert peer is None
    assert "graph rpc failed" in err


@pytest.mark.asyncio
async def test_priv_channel_select_auto_peer_errors_when_no_eligible_candidate(monkeypatch) -> None:
    """An empty candidate set (no node passes the blocklist / capacity
    filters) yields a ``no eligible auto-peer`` error so the hop body can
    surface the unmet precondition."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_priv_channel_hop_deps

    class _StubLnd:
        async def describe_graph(self, **_kwargs):
            # An empty graph yields no candidates, so the selection
            # helper has nothing eligible to pick.
            return {"nodes": [], "edges": []}, None

        async def get_info(self):
            return {"identity_pubkey": "02" + "11" * 32}, None

        async def get_channels(self):
            return [], None

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_priv_channel_hop_deps()
    peer, err = await deps.select_auto_peer(
        session=_session(
            status=AnonymizeStatus.SOURCING.value,
            source_kind="ext-lightning",
        ),
    )
    assert peer is None
    assert "no eligible auto-peer" in err


@pytest.mark.asyncio
async def test_priv_channel_select_auto_peer_returns_chosen_pubkey(monkeypatch) -> None:
    """A surviving candidate is returned verbatim — the adapter doesn't
    mutate the selection helper's choice."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize import peer_selection as ps_mod
    from app.services.anonymize.hop_dispatcher import build_default_priv_channel_hop_deps

    chosen_pubkey = "03" + "ab" * 32

    class _StubLnd:
        async def describe_graph(self, **_kwargs):
            return {"nodes": [{"pub_key": chosen_pubkey}], "edges": []}, None

        async def get_info(self):
            return {"identity_pubkey": "02" + "11" * 32}, None

        async def get_channels(self):
            return [], None

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())
    # The adapter imports these from ``.peer_selection`` at call time,
    # so patch the source module the import resolves against.
    monkeypatch.setattr(ps_mod, "candidates_from_lnd_graph", lambda **_: ["cand"])
    monkeypatch.setattr(ps_mod, "select_auto_peer", lambda *a, **k: chosen_pubkey)

    deps = build_default_priv_channel_hop_deps()
    peer, err = await deps.select_auto_peer(
        session=_session(
            status=AnonymizeStatus.SOURCING.value,
            source_kind="ext-lightning",
        ),
    )
    assert err is None
    assert peer == chosen_pubkey


@pytest.mark.asyncio
async def test_priv_channel_close_rejects_malformed_channel_point(monkeypatch) -> None:
    """A channel_point that isn't ``txid:vout`` is rejected before any
    LND call, since LND needs the two parts split."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_priv_channel_hop_deps

    called = {"close": False}

    class _StubLnd:
        async def close_channel(self, **_kwargs):
            called["close"] = True
            return {"closing_txid": "ab" * 32}, None

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_priv_channel_hop_deps()
    result, err = await deps.lnd_close_channel_cooperative(channel_point="not-a-channel-point")
    assert result is None
    assert "malformed channel_point" in err
    assert called["close"] is False


@pytest.mark.asyncio
async def test_priv_channel_close_forwards_lnd_error(monkeypatch) -> None:
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_priv_channel_hop_deps

    class _StubLnd:
        async def close_channel(self, **_kwargs):
            return None, "peer offline"

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_priv_channel_hop_deps()
    result, err = await deps.lnd_close_channel_cooperative(channel_point=f"{'ab' * 32}:0")
    assert result is None
    assert err == "peer offline"


@pytest.mark.asyncio
async def test_priv_channel_is_active_reports_false_for_unknown_point(monkeypatch) -> None:
    """When no open channel matches the channel_point, the adapter
    reports ``(False, None)`` — the hop body keeps waiting rather than
    treating a missing channel as an error."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_priv_channel_hop_deps

    class _StubLnd:
        async def get_channels(self):
            return [{"channel_point": f"{'cd' * 32}:1", "active": True}], None

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_priv_channel_hop_deps()
    active, err = await deps.lnd_channel_is_active(channel_point=f"{'ab' * 32}:0")
    assert err is None
    assert active is False


@pytest.mark.asyncio
async def test_priv_channel_is_active_reports_true_for_matching_point(monkeypatch) -> None:
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_priv_channel_hop_deps

    cp = f"{'ab' * 32}:0"

    class _StubLnd:
        async def get_channels(self):
            return [{"channel_point": cp, "active": True}], None

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_priv_channel_hop_deps()
    active, err = await deps.lnd_channel_is_active(channel_point=cp)
    assert err is None
    assert active is True


@pytest.mark.asyncio
async def test_priv_channel_push_is_not_yet_wired(monkeypatch) -> None:
    """The push-through-channel adapter is an explicit fail-closed stub;
    pin that it surfaces an error rather than silently succeeding."""
    from app.services.anonymize.hop_dispatcher import build_default_priv_channel_hop_deps

    deps = build_default_priv_channel_hop_deps()
    result, err = await deps.lnd_send_payment_through_channel(
        channel_point=f"{'ab' * 32}:0",
        amount_sat=250_000,
        session=_session(
            status=AnonymizeStatus.HOPPING.value,
            source_kind="ext-lightning",
        ),
    )
    assert result is None
    assert "not yet completed" in err


# ── ln-self-pay adapter primitives ────────────────────────────────────


@pytest.mark.asyncio
async def test_ln_self_pay_add_invoice_translates_lnd_error(monkeypatch) -> None:
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_ln_self_pay_hop_deps

    class _StubLnd:
        async def create_invoice(self, **_kwargs):
            return None, "invoice_mint_failed"

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_ln_self_pay_hop_deps()
    result, err = await deps.lnd_add_invoice(amount_sat=250_000, memo="self-pay")
    assert result is None
    assert err == "invoice_mint_failed"


@pytest.mark.asyncio
async def test_ln_self_pay_pins_outgoing_channel_when_provided(monkeypatch) -> None:
    """With an ``outgoing_chan_id`` set, the self-pay adapter pins that
    channel and never passes ``max_parts`` (LND drops a pin when
    splitting), so the source-channel selection is honoured."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_ln_self_pay_hop_deps

    captured: dict = {}

    class _StubLnd:
        async def send_payment_v2(self, **kwargs):
            captured.update(kwargs)
            return {"status": "SUCCEEDED"}, None

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_ln_self_pay_hop_deps()
    result, err = await deps.lnd_send_self_payment(
        payment_request="lnbcrt1u",
        outgoing_chan_id="123x456x0",
        max_parts=8,  # must be ignored on the pinned path
    )
    assert err is None
    assert result == {"status": "SUCCEEDED"}
    assert captured.get("outgoing_chan_id") == "123x456x0"
    assert "max_parts" not in captured


@pytest.mark.asyncio
async def test_ln_self_pay_splits_when_no_channel_pinned(monkeypatch) -> None:
    """With no pinned channel, the adapter routes through the MPP-split
    call site, forwarding ``max_parts`` and never a channel pin."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_ln_self_pay_hop_deps

    captured: dict = {}

    class _StubLnd:
        async def send_payment_v2(self, **kwargs):
            captured.update(kwargs)
            return {"status": "SUCCEEDED"}, None

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_ln_self_pay_hop_deps()
    result, err = await deps.lnd_send_self_payment(
        payment_request="lnbcrt1u",
        max_parts=6,
    )
    assert err is None
    assert captured.get("max_parts") == 6
    assert "outgoing_chan_id" not in captured


@pytest.mark.asyncio
async def test_ln_self_pay_lookup_invoice_translates_exception(monkeypatch) -> None:
    """A raised exception from ``lookup_invoice`` is caught and returned
    as ``(None, str)`` so the settlement poll can't crash the loop."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_ln_self_pay_hop_deps

    class _StubLnd:
        async def lookup_invoice(self, _ph):
            raise RuntimeError("lookup boom")

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_ln_self_pay_hop_deps()
    result, err = await deps.lnd_lookup_invoice("ab" * 32)
    assert result is None
    assert "lookup boom" in err


@pytest.mark.asyncio
async def test_ln_self_pay_resolve_route_forwards_get_channels_error(monkeypatch) -> None:
    """When LND can't enumerate channels, the route resolver surfaces
    the error instead of computing a route against ``None``."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import build_default_ln_self_pay_hop_deps

    class _StubLnd:
        async def get_channels(self):
            return None, "lnd channels rpc failed"

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    deps = build_default_ln_self_pay_hop_deps()
    route, err = await deps.resolve_self_pay_route(
        session=_session(
            status=AnonymizeStatus.FUNDING.value,
            source_kind="lightning-self",
        ),
    )
    assert route is None
    assert "lnd channels rpc failed" in err


@pytest.mark.asyncio
async def test_ln_self_pay_resolve_route_threads_channels_into_resolver(monkeypatch) -> None:
    """On the happy path the resolver snapshots channels + our pubkey and
    hands them to ``resolve_self_pay_route``; the resolver's result is
    returned verbatim."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize import self_pay_routing as spr_mod
    from app.services.anonymize.hop_dispatcher import build_default_ln_self_pay_hop_deps

    class _StubLnd:
        async def get_channels(self):
            return [{"chan_id": "1", "remote_pubkey": "02" + "cd" * 32}], None

        async def get_info(self):
            return {"identity_pubkey": "02" + "11" * 32}, None

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())

    captured: dict = {}
    sentinel_route = {"mode": "pinned", "chan_id": "1"}

    def _spy_resolve(**kwargs):
        captured.update(kwargs)
        return sentinel_route, None

    monkeypatch.setattr(spr_mod, "resolve_self_pay_route", _spy_resolve)

    deps = build_default_ln_self_pay_hop_deps()
    route, err = await deps.resolve_self_pay_route(
        session=_session(
            status=AnonymizeStatus.FUNDING.value,
            source_kind="lightning-self",
        ),
    )
    assert err is None
    assert route == sentinel_route
    # The snapshot was threaded through with our pubkey + the bin amount.
    assert captured["our_pubkey"] == "02" + "11" * 32
    assert captured["bin_amount_sat"] == 250_000
    assert len(captured["channels"]) == 1


# ── liquid hop deps factory ───────────────────────────────────────────


def test_build_default_liquid_hop_deps_returns_none_when_disabled(monkeypatch) -> None:
    """The default-off posture: with ``ANONYMIZE_LIQUID_ENABLED=false``
    the factory returns ``None`` so the dispatcher skips the Liquid path
    entirely."""
    from app.core.config import settings
    from app.services.anonymize.hop_dispatcher import (
        build_default_liquid_hop_deps,
        reset_default_liquid_hop_deps_cache,
    )

    monkeypatch.setattr(settings, "anonymize_liquid_enabled", False)
    reset_default_liquid_hop_deps_cache()
    try:
        assert build_default_liquid_hop_deps() is None
    finally:
        reset_default_liquid_hop_deps_cache()


def test_build_default_liquid_hop_deps_raises_without_electrum_url(monkeypatch) -> None:
    """Enabled but unconfigured: a blank ``ANONYMIZE_LIQUID_ELECTRUM_URL``
    is a hard misconfiguration the factory surfaces rather than building
    a half-wired hop."""
    from app.core.config import settings
    from app.services.anonymize.hop_dispatcher import (
        build_default_liquid_hop_deps,
        reset_default_liquid_hop_deps_cache,
    )

    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "anonymize_liquid_electrum_url", "")
    reset_default_liquid_hop_deps_cache()
    try:
        with pytest.raises(RuntimeError, match="ANONYMIZE_LIQUID_ELECTRUM_URL"):
            build_default_liquid_hop_deps()
    finally:
        reset_default_liquid_hop_deps_cache()


def test_build_default_liquid_hop_deps_raises_without_seed(monkeypatch) -> None:
    """An electrum URL but no ``ANONYMIZE_LIQUID_SEED_FERNET`` (so no
    master blinding key) is refused — the hop can't unblind L-BTC
    outputs without it."""
    from app.core.config import settings
    from app.services.anonymize.hop_dispatcher import (
        build_default_liquid_hop_deps,
        reset_default_liquid_hop_deps_cache,
    )

    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "anonymize_liquid_electrum_url", "tcp://liquid-electrs.test:50001")
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", "")
    reset_default_liquid_hop_deps_cache()
    try:
        with pytest.raises(RuntimeError, match="ANONYMIZE_LIQUID_SEED_FERNET"):
            build_default_liquid_hop_deps()
    finally:
        reset_default_liquid_hop_deps_cache()


def _enable_liquid_fully(monkeypatch) -> None:
    """Configure the minimum settings for a fully-wired Liquid build:
    enabled flag, electrum URL, a valid 32-byte urlsafe-base64 seed, an
    explicit regtest L-BTC asset id, and env-pinned per-leg URLs so the
    operator registry isn't consulted."""
    import base64

    from app.core.config import settings

    seed_b64 = base64.urlsafe_b64encode(b"\x11" * 32).decode("ascii")
    monkeypatch.setattr(settings, "anonymize_liquid_enabled", True)
    monkeypatch.setattr(settings, "bitcoin_network", "regtest")
    monkeypatch.setattr(settings, "anonymize_liquid_electrum_url", "tcp://liquid-electrs.test:50001")
    monkeypatch.setattr(settings, "anonymize_liquid_seed_fernet", seed_b64)
    monkeypatch.setattr(settings, "anonymize_liquid_btc_asset_id", "ad" * 32)
    monkeypatch.setattr(settings, "boltz_chain_ln_to_lbtc_api_url", "http://ln2lbtc.test/v2")
    monkeypatch.setattr(settings, "boltz_chain_lbtc_to_ln_api_url", "http://lbtc2ln.test/v2")


def test_build_default_liquid_hop_deps_constructs_when_enabled(monkeypatch) -> None:
    """With a complete config + env-pinned distinct leg URLs, the factory
    wires a full :class:`LiquidHopDeps` and caches it (a second call
    returns the same instance without rebuilding the Electrum client)."""
    from app.services.anonymize.hop_dispatcher import (
        build_default_liquid_hop_deps,
        reset_default_liquid_hop_deps_cache,
    )
    from app.services.anonymize.hops.liquid import LiquidHopDeps

    _enable_liquid_fully(monkeypatch)
    reset_default_liquid_hop_deps_cache()
    try:
        deps = build_default_liquid_hop_deps()
        assert isinstance(deps, LiquidHopDeps)
        # Cached: a second call returns the identical instance.
        assert build_default_liquid_hop_deps() is deps
    finally:
        reset_default_liquid_hop_deps_cache()


def test_build_default_liquid_hop_deps_collapses_legs_when_same_url(monkeypatch) -> None:
    """When both env-pinned leg URLs are identical, the factory shares a
    single swap client across legs (``legs_distinct`` is false) — the hop
    still works but inter-leg unlinkability is reduced."""
    from app.core.config import settings
    from app.services.anonymize.hop_dispatcher import (
        build_default_liquid_hop_deps,
        reset_default_liquid_hop_deps_cache,
    )
    from app.services.anonymize.hops.liquid import LiquidHopDeps

    _enable_liquid_fully(monkeypatch)
    monkeypatch.setattr(settings, "boltz_chain_ln_to_lbtc_api_url", "http://shared-liquid.test/v2")
    monkeypatch.setattr(settings, "boltz_chain_lbtc_to_ln_api_url", "http://shared-liquid.test/v2")
    reset_default_liquid_hop_deps_cache()
    try:
        deps = build_default_liquid_hop_deps()
        assert isinstance(deps, LiquidHopDeps)
    finally:
        reset_default_liquid_hop_deps_cache()


@pytest.mark.asyncio
async def test_liquid_lnd_send_payment_adapter_translates_exception(monkeypatch) -> None:
    """The Liquid hop's LN-payment shim catches an LND exception and
    returns ``(None, error)`` so a failed LN leg doesn't raise into the
    per-session loop."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import (
        build_default_liquid_hop_deps,
        reset_default_liquid_hop_deps_cache,
    )

    _enable_liquid_fully(monkeypatch)
    reset_default_liquid_hop_deps_cache()

    class _StubLnd:
        async def send_payment_v2(self, **_kwargs):
            raise RuntimeError("ln payment boom")

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())
    try:
        deps = build_default_liquid_hop_deps()
        result, err = await deps.lnd_send_payment(payment_request="lnbcrt1u", amount_sat=250_000)
        assert result is None
        assert "ln payment boom" in err
    finally:
        reset_default_liquid_hop_deps_cache()


@pytest.mark.asyncio
async def test_liquid_observe_invoice_settled_errors_without_swap_state(monkeypatch) -> None:
    """The settlement observer keys off the per-swap state the create
    adapter stashes; an unknown swap_id reports a specific not-found
    error rather than looking up an empty payment hash."""
    from app.services.anonymize.hop_dispatcher import (
        build_default_liquid_hop_deps,
        reset_default_liquid_hop_deps_cache,
    )

    _enable_liquid_fully(monkeypatch)
    reset_default_liquid_hop_deps_cache()
    try:
        deps = build_default_liquid_hop_deps()
        settled, err = await deps.lnd_observe_invoice_settled(swap_id="unknown-swap", session_id=uuid4())
        assert settled is False
        assert "no per-swap state" in err
    finally:
        reset_default_liquid_hop_deps_cache()


@pytest.mark.asyncio
async def test_liquid_observe_invoice_settled_reports_lnd_settlement(monkeypatch) -> None:
    """With per-swap state recording the payment hash, the observer
    reflects LND's ``settled`` flag for the wallet-minted invoice."""
    import app.services.lnd_service as lnd_mod
    from app.services.anonymize.hop_dispatcher import (
        build_default_liquid_hop_deps,
        reset_default_liquid_hop_deps_cache,
    )

    _enable_liquid_fully(monkeypatch)
    reset_default_liquid_hop_deps_cache()

    class _StubLnd:
        async def lookup_invoice(self, _ph):
            return {"settled": True}, None

    monkeypatch.setattr(lnd_mod, "lnd_service", _StubLnd())
    try:
        deps = build_default_liquid_hop_deps()
        # Seed the per-swap state the create adapter would normally write.
        deps.swap_state["swap-xyz"] = {"payment_hash_hex": "ab" * 32}
        settled, err = await deps.lnd_observe_invoice_settled(swap_id="swap-xyz", session_id=uuid4())
        assert err is None
        assert settled is True
    finally:
        reset_default_liquid_hop_deps_cache()


@pytest.mark.asyncio
async def test_dispatcher_routes_awaiting_liquid_dwell_to_liquid_hop(
    db_session,
    monkeypatch,
) -> None:
    """The ``awaiting_liquid_dwell`` status is unambiguous — it only
    exists for the Liquid hop, so the dispatcher always routes it to the
    Liquid hop body when Liquid deps are present."""
    from app.services.anonymize import hop_dispatcher as hd_mod

    _enable_liquid_fully(monkeypatch)
    hd_mod.reset_default_liquid_hop_deps_cache()

    sentinel = "liquid-dwell-dispatched"

    async def _stub(db, session, deps):
        return _LiquidOutcome(sentinel)

    monkeypatch.setattr(hd_mod, "execute_liquid_hop_step", _stub)
    try:
        sess = _session(
            status="awaiting_liquid_dwell",
            source_kind="lightning-self",
        )
        db_session.add(sess)
        await db_session.flush()
        out = await hd_mod.default_hop_step_fn()(db_session, sess)
        assert getattr(out, "detail", "") == sentinel
    finally:
        hd_mod.reset_default_liquid_hop_deps_cache()


class _LiquidOutcome:
    def __init__(self, detail: str) -> None:
        self.detail = detail


# ── dispatcher routing: priv_channel-exit + remaining source kinds ─────


@pytest.mark.asyncio
async def test_dispatcher_routes_ext_onchain_sourcing_to_submarine(
    db_session,
    monkeypatch,
) -> None:
    """An ``ext-onchain`` source (deposit from outside the wallet) routes
    its SOURCING / FUNDING / LN_HOLDING ticks through the submarine hop
    body, same as ``onchain-self``."""
    from app.services.anonymize import hop_dispatcher as hd_mod
    from app.services.anonymize.hops.submarine import SubmarineHopOutcome

    sentinel = "ext-onchain-submarine"

    async def _stub(db, session, deps):
        return SubmarineHopOutcome(kind="noop", detail=sentinel)

    monkeypatch.setattr(hd_mod, "execute_submarine_hop_step", _stub)

    sess = _session(
        status=AnonymizeStatus.FUNDING.value,
        source_kind="ext-onchain",
    )
    db_session.add(sess)
    await db_session.flush()
    out = await default_hop_step_fn()(db_session, sess)
    assert getattr(out, "detail", "") == sentinel
