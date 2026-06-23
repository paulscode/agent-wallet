# SPDX-License-Identifier: MIT
"""Cryptographic round-trip for the Liquid lockup-address verifier.

The verifier (``scripts/boltz_verify_lockup_address_liquid.js``) guards
both Liquid swap legs against an operator returning a lockup it solely
controls. This test builds a genuine Boltz swap tree + lockup address
with ``boltz-core``'s own Liquid primitives, then asserts the verifier
accepts the matching address and rejects a foreign key / wrong address —
so the verifier's derivation is pinned to the same library Boltz uses.

Skipped when Node or the Liquid JS toolchain is unavailable (the same
toolchain the lock/claim subprocesses require at runtime).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts"

# Node program that constructs a known-good vector with boltz-core and
# pipes candidate inputs through the verifier under test, emitting the
# four verdicts as JSON.
_DRIVER = r"""
'use strict';
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');
const liquidjs = require('liquidjs-lib');
const { Musig, swapTree, reverseSwapTree, SwapTreeSerializer } = require('boltz-core');
const liquid = require('boltz-core/dist/lib/liquid');
const ECPair = ECPairFactory(ecc);
function progFor(zkp, tree, claim, refund, swapType){
  // Boltz's Musig key order is [its-key, our-key] and is NOT sorted: submarine
  // = [claim, refund]; reverse = [refund, claim] (matches boltz_claim_liquid.js,
  // which claims real reverse Liquid lockups). Derive the genuine address per
  // direction rather than hardcoding one order.
  const keySet = swapType === 'reverse'
    ? [refund.publicKey, claim.publicKey]
    : [claim.publicKey, refund.publicKey];
  const m = new Musig(zkp, claim, crypto.randomBytes(32), keySet);
  const t = liquid.TaprootUtils.tweakMusig(m, tree.tree);
  return Buffer.concat([Buffer.from([0x51,0x20]), t.length===33?t.slice(1):t]);
}
function confAddr(p, b, net){
  return liquidjs.address.toConfidential(liquidjs.address.fromOutputScript(p, net), b.publicKey);
}
function verify(e){
  return JSON.parse(execFileSync('node', ['boltz_verify_lockup_address_liquid.js'], { input: JSON.stringify(e) }).toString());
}
(async () => {
  const zi = require('@vulpemventures/secp256k1-zkp');
  const zkp = await (zi.default || zi)();
  liquid.init(zkp);
  const net = liquidjs.networks.regtest;
  const claim = ECPair.makeRandom(), refund = ECPair.makeRandom(), blind = ECPair.makeRandom(), foreign = ECPair.makeRandom();
  const ph = crypto.createHash('sha256').update(crypto.randomBytes(32)).digest();

  const sub = swapTree(true, ph, claim.publicKey, refund.publicKey, 1000);
  const subA = confAddr(progFor(zkp, sub, claim, refund, 'submarine'), blind, net);
  const subS = SwapTreeSerializer.serializeSwapTree(sub);
  const rev = reverseSwapTree(true, ph, claim.publicKey, refund.publicKey, 1000);
  const revA = confAddr(progFor(zkp, rev, claim, refund, 'reverse'), blind, net);
  const revS = SwapTreeSerializer.serializeSwapTree(rev);

  const out = {
    sub_good: verify({swapTree: subS, refundPublicKey: refund.publicKey.toString('hex'), claimPublicKey: claim.publicKey.toString('hex'), lockupAddress: subA, network: 'regtest', verifyLeaf: 'refund', swapType: 'submarine'}),
    sub_foreign_refund: verify({swapTree: subS, refundPublicKey: foreign.publicKey.toString('hex'), claimPublicKey: claim.publicKey.toString('hex'), lockupAddress: subA, network: 'regtest', verifyLeaf: 'refund', swapType: 'submarine'}),
    rev_good: verify({swapTree: revS, refundPublicKey: refund.publicKey.toString('hex'), claimPublicKey: claim.publicKey.toString('hex'), lockupAddress: revA, network: 'regtest', verifyLeaf: 'claim', swapType: 'reverse'}),
    rev_foreign_claim: verify({swapTree: revS, refundPublicKey: refund.publicKey.toString('hex'), claimPublicKey: foreign.publicKey.toString('hex'), lockupAddress: revA, network: 'regtest', verifyLeaf: 'claim', swapType: 'reverse'}),
  };
  process.stdout.write(JSON.stringify(out));
})().catch(e => { process.stderr.write(String(e)); process.exit(1); });
"""


def _node_toolchain_available() -> bool:
    if shutil.which("node") is None:
        return False
    probe = "try{require('boltz-core');require('liquidjs-lib');require('@vulpemventures/secp256k1-zkp');process.exit(0)}catch(e){process.exit(1)}"
    try:
        r = subprocess.run(["node", "-e", probe], cwd=str(_SCRIPTS_DIR), capture_output=True, timeout=30)
    except Exception:
        return False
    return r.returncode == 0


@pytest.mark.skipif(
    not _node_toolchain_available(),
    reason="Node + Liquid JS toolchain (boltz-core/liquidjs-lib/secp256k1-zkp) not available",
)
def test_liquid_lockup_verifier_roundtrip_against_boltz_core() -> None:
    result = subprocess.run(
        ["node", "-e", _DRIVER],
        cwd=str(_SCRIPTS_DIR),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)

    # The genuine lockup address verifies on both legs.
    assert out["sub_good"]["ok"] is True
    assert out["rev_good"]["ok"] is True
    # A foreign key in the verified leaf is rejected — the core theft guard.
    assert out["sub_foreign_refund"]["ok"] is False
    assert out["sub_foreign_refund"]["reason"] == "refund_leaf_mismatch"
    assert out["rev_foreign_claim"]["ok"] is False
    assert out["rev_foreign_claim"]["reason"] == "claim_leaf_mismatch"
