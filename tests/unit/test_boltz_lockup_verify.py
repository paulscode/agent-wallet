# SPDX-License-Identifier: MIT
"""
Unit tests for app.services.boltz_lockup_verify.

These verifiers gate funding/paying a Boltz swap: they must fail *closed*
on every subprocess, exit-code, or parse error so a malicious operator
that returns a lockup address it controls can never trick the wallet into
funding it. The Node verifier itself is exercised elsewhere; here we pin
the Python wrapper's payload shape and its fail-closed handling by faking
the ``node`` subprocess.
"""

import json
import subprocess
from types import SimpleNamespace

import pytest

import app.services.boltz_lockup_verify as blv


class _Result:
    """Stand-in for subprocess.CompletedProcess."""

    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def _fake_run_factory(captured, *, result=None, raises=None):
    def _fake_run(cmd, input=None, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = json.loads(input) if input else None
        captured["cwd"] = kwargs.get("cwd")
        if raises is not None:
            raise raises
        return result if result is not None else _Result(0, json.dumps({"ok": True, "reason": "ok"}))

    return _fake_run


# Minimal valid kwargs for each verifier, so a single fake subprocess can
# drive all three through the shared error/parse logic.
def _call_submarine():
    return blv.verify_submarine_lockup_address(
        swap_tree_json={"claimLeaf": {}, "refundLeaf": {}},
        refund_public_key_hex="aa" * 32,
        lockup_address="bc1ptest",
        network="regtest",
    )


def _call_reverse():
    return blv.verify_reverse_lockup_address(
        swap_tree_json={"claimLeaf": {}, "refundLeaf": {}},
        claim_public_key_hex="aa" * 32,
        refund_public_key_hex="bb" * 32,
        lockup_address="bc1ptest",
        network="regtest",
    )


def _call_liquid():
    return blv.verify_liquid_lockup_address(
        swap_tree={"claimLeaf": {}, "refundLeaf": {}},
        lockup_address="el1ptest",
        network="liquidregtest",
        swap_type="submarine",
        verify_leaf="refund",
        refund_public_key_hex="aa" * 32,
        asset_id_hex="cc" * 32,
    )


_ALL = [
    pytest.param(_call_submarine, id="submarine"),
    pytest.param(_call_reverse, id="reverse"),
    pytest.param(_call_liquid, id="liquid"),
]


class TestFailClosed:
    """Every failure mode yields (False, reason) — never (True, …)."""

    @pytest.mark.parametrize("call", _ALL)
    def test_nonzero_exit(self, call, monkeypatch):
        captured = {}
        monkeypatch.setattr(blv.subprocess, "run", _fake_run_factory(captured, result=_Result(1, "")))
        ok, reason = call()
        assert ok is False and reason == "verifier_nonzero_exit"

    @pytest.mark.parametrize("call", _ALL)
    def test_bad_json_output(self, call, monkeypatch):
        captured = {}
        monkeypatch.setattr(blv.subprocess, "run", _fake_run_factory(captured, result=_Result(0, "not json{")))
        ok, reason = call()
        assert ok is False and reason == "verifier_bad_output"

    @pytest.mark.parametrize("call", _ALL)
    def test_timeout(self, call, monkeypatch):
        captured = {}
        exc = subprocess.TimeoutExpired(cmd="node", timeout=20)
        monkeypatch.setattr(blv.subprocess, "run", _fake_run_factory(captured, raises=exc))
        ok, reason = call()
        assert ok is False and reason == "verifier_timeout"

    @pytest.mark.parametrize("call", _ALL)
    def test_generic_subprocess_error(self, call, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            blv.subprocess, "run", _fake_run_factory(captured, raises=FileNotFoundError("node missing"))
        )
        ok, reason = call()
        assert ok is False and reason.startswith("verifier_error:")

    @pytest.mark.parametrize("call", _ALL)
    def test_script_missing(self, call, monkeypatch, tmp_path):
        # Point scripts_dir at an empty directory so the .js is absent.
        monkeypatch.setattr(blv, "scripts_dir", lambda: str(tmp_path))
        ok, reason = call()
        assert ok is False and reason == "verifier_script_missing"

    @pytest.mark.parametrize("call", _ALL)
    def test_verifier_reports_failure(self, call, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            blv.subprocess,
            "run",
            _fake_run_factory(captured, result=_Result(0, json.dumps({"ok": False, "reason": "leaf_mismatch"}))),
        )
        ok, reason = call()
        assert ok is False and reason == "leaf_mismatch"


class TestSuccess:
    @pytest.mark.parametrize("call", _ALL)
    def test_verifier_reports_ok(self, call, monkeypatch):
        captured = {}
        monkeypatch.setattr(blv.subprocess, "run", _fake_run_factory(captured))
        ok, reason = call()
        assert ok is True and reason == "ok"

    @pytest.mark.parametrize("call", _ALL)
    def test_runs_node_from_scripts_dir(self, call, monkeypatch):
        captured = {}
        monkeypatch.setattr(blv.subprocess, "run", _fake_run_factory(captured))
        call()
        assert captured["cmd"][0] == "node"
        assert captured["cwd"] == blv.scripts_dir()


class TestPayloadShape:
    def test_submarine_payload(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(blv.subprocess, "run", _fake_run_factory(captured))
        _call_submarine()
        p = captured["input"]
        assert p["refundPublicKey"] == "aa" * 32
        assert p["lockupAddress"] == "bc1ptest"
        assert "claimPublicKey" not in p  # submarine path holds only the refund key

    def test_reverse_payload_pins_claim_leaf(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(blv.subprocess, "run", _fake_run_factory(captured))
        _call_reverse()
        p = captured["input"]
        assert p["verifyLeaf"] == "claim"
        assert p["claimPublicKey"] == "aa" * 32
        assert p["refundPublicKey"] == "bb" * 32

    def test_liquid_payload_includes_asset_and_leaf(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(blv.subprocess, "run", _fake_run_factory(captured))
        _call_liquid()
        p = captured["input"]
        assert p["assetId"] == "cc" * 32
        assert p["swapType"] == "submarine"
        assert p["verifyLeaf"] == "refund"
        assert p["refundPublicKey"] == "aa" * 32

    def test_liquid_reverse_maps_swap_type_and_claim_leaf(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(blv.subprocess, "run", _fake_run_factory(captured))
        blv.verify_liquid_lockup_address(
            swap_tree={"claimLeaf": {}, "refundLeaf": {}},
            lockup_address="el1ptest",
            network="liquidregtest",
            swap_type="reverse",
            verify_leaf="claim",
            claim_public_key_hex="dd" * 32,
        )
        p = captured["input"]
        assert p["swapType"] == "reverse"
        assert p["verifyLeaf"] == "claim"
        assert p["claimPublicKey"] == "dd" * 32
        assert "assetId" not in p  # omitted when not supplied


class TestSerializeSwapTree:
    def test_dict_passthrough(self):
        tree = {"claimLeaf": {"version": 1, "output": "ab"}}
        assert blv._serialize_swap_tree(tree) is tree

    def test_dataclass_like_serialized(self):
        leaf = lambda v, o: SimpleNamespace(version=v, output=o)  # noqa: E731
        tree = SimpleNamespace(claim_leaf=leaf(192, "aa"), refund_leaf=leaf(192, "bb"))
        out = blv._serialize_swap_tree(tree)
        assert out == {
            "claimLeaf": {"version": 192, "output": "aa"},
            "refundLeaf": {"version": 192, "output": "bb"},
        }

    def test_missing_leaves_passthrough(self):
        tree = SimpleNamespace(something_else=1)
        assert blv._serialize_swap_tree(tree) is tree


def test_scripts_dir_points_at_repo_scripts():
    import os

    d = blv.scripts_dir()
    assert d.endswith("scripts")
    assert os.path.isdir(d)
