# SPDX-License-Identifier: MIT
"""
Contract tests for the shared test builders in tests/helpers.py.

Many test modules depend on these factories, so a drift between a builder
and the real model/contract it stands in for would silently weaken every
consumer. These tests pin the builders' behavior.
"""

from datetime import datetime, timezone

from app.core.security import hash_api_key
from app.models.api_key import SCOPE_ADMIN, SCOPE_MONITOR, SCOPE_SPEND
from tests import helpers


class TestTupleHelpers:
    def test_ok_and_err_shape(self):
        assert helpers.ok({"x": 1}) == ({"x": 1}, None)
        assert helpers.err("boom") == (None, "boom")


class TestMakeApiKey:
    def test_default_is_active_monitor(self):
        key, raw = helpers.make_api_key()
        assert key.scope == SCOPE_MONITOR
        assert key.is_admin is False and key.can_spend is False
        assert key.is_active is True

    def test_is_admin_maps_to_admin_scope(self):
        key, _ = helpers.make_api_key(is_admin=True)
        assert key.scope == SCOPE_ADMIN
        assert key.is_admin is True and key.can_spend is True

    def test_explicit_scope_wins(self):
        key, _ = helpers.make_api_key(scope=SCOPE_SPEND)
        assert key.scope == SCOPE_SPEND
        assert key.can_spend is True and key.is_admin is False

    def test_key_hash_matches_raw_token(self):
        key, raw = helpers.make_api_key()
        assert key.key_hash == hash_api_key(raw)

    def test_supplied_raw_key_is_used(self):
        key, raw = helpers.make_api_key(raw_key="lwk_fixed")
        assert raw == "lwk_fixed"
        assert key.key_hash == hash_api_key("lwk_fixed")

    def test_passthrough_fields(self):
        when = datetime(2030, 1, 1, tzinfo=timezone.utc)
        key, _ = helpers.make_api_key(name="agent-7", is_active=False, expires_at=when)
        assert key.name == "agent-7"
        assert key.is_active is False
        assert key.expires_at == when


class TestResponseBuilders:
    def test_lnd_get_info_keys_and_override(self):
        info = helpers.lnd_get_info(alias="custom")
        assert info["alias"] == "custom"
        assert {"identity_pubkey", "block_height", "synced_to_chain"} <= info.keys()

    def test_lnd_channel_balances_override(self):
        chan = helpers.lnd_channel(local_balance=1, remote_balance=2)
        assert chan["local_balance"] == 1 and chan["remote_balance"] == 2
        assert {"chan_id", "capacity", "active"} <= chan.keys()

    def test_lnd_invoice_and_wallet_balance(self):
        assert {"r_hash", "payment_request", "add_index"} <= helpers.lnd_invoice().keys()
        assert helpers.lnd_wallet_balance(total_balance=5)["total_balance"] == 5

    def test_boltz_pair_info_builders(self):
        rev = helpers.boltz_reverse_pair_info(min=1)
        assert rev["min"] == 1 and {"fees_percentage", "max"} <= rev.keys()
        sub = helpers.boltz_submarine_pair_info()
        assert {"fees_percentage", "fees_miner_lockup", "hash"} <= sub.keys()

    def test_make_boltz_swap_crypto_round_trips(self):
        from app.core.encryption import decrypt_field
        from app.models.boltz_swap import SwapStatus

        swap = helpers.make_boltz_swap(status=SwapStatus.INVOICE_PAID)
        assert swap.status == SwapStatus.INVOICE_PAID
        # The encrypted material decrypts under the test SECRET_KEY so
        # claim/refund code paths can run.
        assert decrypt_field(swap.preimage_hex) == "00" * 32
        assert decrypt_field(swap.claim_private_key_hex) == "11" * 32


class TestFakeLndService:
    async def test_default_results_follow_data_error_contract(self):
        from tests._fake_lnd import FakeLndService

        lnd = FakeLndService(fresh_address="bcrt1pfresh")
        addr, err = await lnd.new_address()
        assert err is None and addr["address"] == "bcrt1pfresh"
        info, err = await lnd.get_info()
        assert err is None and "identity_pubkey" in info
        utxos, err = await lnd.list_unspent(min_confs=0)
        assert err is None and utxos == []
        assert lnd.called("new_address") and lnd.called("list_unspent")

    async def test_overrides_and_errors(self):
        from tests._fake_lnd import FakeLndService

        lnd = FakeLndService()
        lnd.set_result("send_coins", {"txid": "ab"})
        data, err = await lnd.send_coins(address="x", amount_sats=1)
        assert err is None and data == {"txid": "ab"}

        lnd.set_error("new_address", "locked")
        data, err = await lnd.new_address()
        assert data is None and err == "locked"
