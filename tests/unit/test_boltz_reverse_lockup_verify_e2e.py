# SPDX-License-Identifier: MIT
"""End-to-end check of the BTC reverse-swap lockup verifier.

The unit tests in ``test_boltz_lockup_verify.py`` mock the ``node`` subprocess,
so they cannot catch a wrong claim-pubkey extractor: the submarine claim leaf
puts the pubkey at script index 3, the reverse claim leaf at index 6, so using
the submarine extractor on a reverse tree throws ``claim_extract_failed``. This
test builds a real reverse swap tree with boltz-core and runs the actual
``node`` verifier against it, asserting it extracts + verifies cleanly.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
_VERIFIER = _SCRIPTS / "boltz_verify_lockup_address.js"
_BOLTZ_CORE = _SCRIPTS / "node_modules" / "boltz-core"

# Build a real reverse swap tree, derive its lockup address the same way the
# verifier does, then invoke the verifier with verifyLeaf='claim' and print its
# JSON result. Run via ``node -e`` from scripts/ so requires + the verifier
# resolve against scripts/node_modules.
_BUILDER_JS = r"""
const ecc = require('tiny-secp256k1');
const { ECPairFactory } = require('ecpair');
const { initEccLib, networks, payments } = require('bitcoinjs-lib');
const crypto = require('crypto');
const { Musig, TaprootUtils, SwapTreeSerializer, reverseSwapTree } = require('boltz-core');
const { execFileSync } = require('child_process');
initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const xonly = (b) => (b.length === 33 ? b.slice(1) : b);
(async () => {
  const z = require('@vulpemventures/secp256k1-zkp');
  const secp = await (z.default || z)();
  const claimKey = ECPair.makeRandom();
  const refundKey = ECPair.makeRandom();
  const preimageHash = crypto.createHash('sha256').update(crypto.randomBytes(32)).digest();
  const tree = reverseSwapTree(false, preimageHash, claimKey.publicKey, refundKey.publicKey, 800000);
  const claim33 = Buffer.from(claimKey.publicKey);
  const refund33 = Buffer.from(refundKey.publicKey);
  // Canonical reverse-swap key order (matches boltz_claim.js, which claims real
  // reverse lockups): [refund, claim] — Boltz's key first, ours second.
  const musig = new Musig(secp, ECPair.fromPublicKey(refund33), crypto.randomBytes(32), [refund33, claim33]);
  const tweaked = TaprootUtils.tweakMusig(musig, tree.tree);
  const lockupAddress = payments.p2tr({ pubkey: xonly(Buffer.from(tweaked)), network: networks.bitcoin }).address;
  const payload = JSON.stringify({
    swapTree: SwapTreeSerializer.serializeSwapTree(tree),
    refundPublicKey: refund33.toString('hex'),
    claimPublicKey: claim33.toString('hex'),
    lockupAddress, network: 'bitcoin', verifyLeaf: 'claim',
  });
  process.stdout.write(execFileSync('node', ['boltz_verify_lockup_address.js'], { input: payload, cwd: process.cwd() }).toString());
})().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""


@pytest.mark.skipif(
    not (shutil.which("node") and _VERIFIER.is_file() and _BOLTZ_CORE.is_dir()),
    reason="node / boltz-core not available in this environment",
)
def test_reverse_lockup_verifier_accepts_real_reverse_tree() -> None:
    proc = subprocess.run(
        ["node", "-e", _BUILDER_JS],
        cwd=str(_SCRIPTS),
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    # The crux: a reverse tree must extract cleanly (NOT claim_extract_failed)
    # and reconstruct the matching lockup address.
    assert result.get("ok") is True, result
    assert result.get("derivedAddress")
