// SPDX-License-Identifier: MIT
//
// Verify that a Boltz **Liquid** submarine-swap lockup address genuinely
// commits to the swap tree + our refund key BEFORE the wallet funds it.
//
// This is the Liquid (L-BTC) counterpart of
// ``boltz_verify_lockup_address.js``. The threat model is identical: a
// malicious/compromised operator could return a ``lockupAddress`` it
// controls that is NOT a real swap output, and the wallet would lock
// L-BTC with no refundable script and lose it. The helper reconstructs
// the expected taproot output from the (operator-supplied) swap tree +
// the two public keys and refuses unless:
//
//   1. the swap tree's refund leaf commits to OUR refund public key (so
//      we can unilaterally refund after the timeout), AND
//   2. the witness program derived from musig(claimKey, refundKey)
//      tweaked by the swap tree equals the witness program of the
//      operator-supplied lockupAddress.
//
// Liquid lockup addresses are *confidential* (``lq1``/``tlq1``/``el1``):
// the blinding public key is not derivable from the swap tree, so the
// comparison is on the unconfidential scriptPubKey (the witness
// program), obtained via ``liquidjs-lib``'s ``address.toOutputScript``
// which strips the blinding prefix.
//
// Input  (stdin JSON): { swapTree, refundPublicKey, claimPublicKey?,
//                        lockupAddress, network, assetId? }
// Output (stdout JSON): { ok: bool, derivedScriptHex?, reason? }
// Exit code is always 0 on a well-formed run; `ok` carries the verdict.
'use strict';

// Refuse grandchild spawns (defence-in-depth, matches sibling scripts).
(function lockChildProcess() {
  const cp = require('child_process');
  const refuse = (method) => function refusedSpawn() {
    process.stderr.write(JSON.stringify({ event: 'forbidden_grandchild_spawn', method }) + '\n');
    process.exit(2);
  };
  for (const m of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
    cp[m] = refuse(m);
  }
})();

const crypto = require('crypto');
const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');
const liquidjs = require('liquidjs-lib');
const {
  Musig,
  SwapTreeSerializer,
  extractRefundPublicKeyFromSwapTree,
  extractClaimPublicKeyFromSwapTree,
  extractRefundPublicKeyFromReverseSwapTree,
  extractClaimPublicKeyFromReverseSwapTree,
} = require('boltz-core');
const liquid = require('boltz-core/dist/lib/liquid');

const ECPair = ECPairFactory(ecc);

function xonly(buf) {
  return buf.length === 33 ? buf.slice(1) : buf;
}

function pickNetwork(name) {
  const nets = liquidjs.networks;
  if (name === 'testnet' || name === 'signet') return nets.testnet;
  if (name === 'regtest') return nets.regtest;
  return nets.liquid;
}

function emit(obj) {
  process.stdout.write(JSON.stringify(obj));
}

(async () => {
  let input;
  try {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    input = JSON.parse(Buffer.concat(chunks).toString());
  } catch (e) {
    emit({ ok: false, reason: 'bad_input' });
    return;
  }

  const { swapTree, refundPublicKey, claimPublicKey, lockupAddress, network, assetId } = input;
  // ``verifyLeaf`` selects which leaf must commit to OUR key:
  //   * "refund" (default) — the L-BTC→LN submarine funding leg, where
  //     we fund the lockup and must be able to refund it.
  //   * "claim" — the LN→L-BTC reverse leg, where we claim the lockup
  //     after paying and must be the one able to claim it.
  const verifyLeaf = input.verifyLeaf === 'claim' ? 'claim' : 'refund';
  // Submarine and reverse swap trees lay out their leaves differently,
  // so the right extractor family must be used for each.
  const swapType = input.swapType === 'reverse' ? 'reverse' : 'submarine';
  const extractRefund =
    swapType === 'reverse' ? extractRefundPublicKeyFromReverseSwapTree : extractRefundPublicKeyFromSwapTree;
  const extractClaim =
    swapType === 'reverse' ? extractClaimPublicKeyFromReverseSwapTree : extractClaimPublicKeyFromSwapTree;
  if (!swapTree || !lockupAddress) {
    emit({ ok: false, reason: 'missing_fields' });
    return;
  }
  if (verifyLeaf === 'refund' && !refundPublicKey) {
    emit({ ok: false, reason: 'missing_fields' });
    return;
  }
  if (verifyLeaf === 'claim' && !claimPublicKey) {
    emit({ ok: false, reason: 'missing_fields' });
    return;
  }

  let net = pickNetwork(network);
  if (assetId) net = { ...net, assetHash: assetId };

  const zkpInit = require('@vulpemventures/secp256k1-zkp');
  const zkp = await (zkpInit.default || zkpInit)();
  liquid.init(zkp);

  let tree;
  try {
    tree = SwapTreeSerializer.deserializeSwapTree(swapTree);
  } catch (e) {
    emit({ ok: false, reason: 'bad_tree_or_key' });
    return;
  }

  // (1) The chosen leaf MUST commit to OUR key so we retain control of
  // the lockup (refund it on the funding leg, claim it on the reverse
  // leg).
  try {
    if (verifyLeaf === 'refund') {
      const ours = xonly(Buffer.from(refundPublicKey, 'hex'));
      const inTree = extractRefund(tree);
      if (Buffer.compare(inTree, ours) !== 0) {
        emit({ ok: false, reason: 'refund_leaf_mismatch' });
        return;
      }
    } else {
      const ours = xonly(Buffer.from(claimPublicKey, 'hex'));
      const inTree = extractClaim(tree);
      if (Buffer.compare(inTree, ours) !== 0) {
        emit({ ok: false, reason: 'claim_leaf_mismatch' });
        return;
      }
    }
  } catch (e) {
    emit({ ok: false, reason: 'leaf_extract_failed' });
    return;
  }

  // (2) Reconstruct the witness program. Musig key aggregation does NOT sort
  // (secp256k1-zkp pubkeyAgg preserves order), and Boltz orders [its-key,
  // our-key]: submarine = [claim(Boltz), refund(ours)] = [claim, refund];
  // reverse = [refund(Boltz), claim(ours)] = [refund, claim] (matches
  // boltz_claim_liquid.js). The order is applied per swapType below. Either key
  // may arrive compressed or be recovered x-only from the tree (x-only loses
  // y-parity → try both candidates).
  function candidates(hexKey, extractFn) {
    const out = [];
    if (hexKey) {
      const b = Buffer.from(hexKey, 'hex');
      if (b.length === 33) out.push(b);
      else if (b.length === 32) {
        out.push(Buffer.concat([Buffer.from([0x02]), b]));
        out.push(Buffer.concat([Buffer.from([0x03]), b]));
      }
    }
    if (out.length === 0) {
      const x = extractFn(tree);
      out.push(Buffer.concat([Buffer.from([0x02]), x]));
      out.push(Buffer.concat([Buffer.from([0x03]), x]));
    }
    return out;
  }

  let claimCandidates;
  let refundCandidates;
  try {
    claimCandidates = candidates(claimPublicKey, extractClaim);
    refundCandidates = candidates(refundPublicKey, extractRefund);
  } catch (e) {
    emit({ ok: false, reason: 'key_extract_failed' });
    return;
  }

  let expectedScript;
  try {
    expectedScript = liquidjs.address.toOutputScript(lockupAddress, net);
  } catch (e) {
    emit({ ok: false, reason: 'bad_lockup_address' });
    return;
  }

  for (const claim of claimCandidates) {
    for (const refund of refundCandidates) {
      try {
        // The local key passed to Musig does not affect the aggregate
        // key; use the (public-only) refund key so no secret is needed.
        const localKey = ECPair.fromPublicKey(refund);
        const keySet = swapType === 'reverse' ? [refund, claim] : [claim, refund];
        const musig = new Musig(zkp, localKey, crypto.randomBytes(32), keySet);
        const tweaked = liquid.TaprootUtils.tweakMusig(musig, tree.tree);
        // P2TR witness program: OP_1 (0x51) push-32 (0x20) <x-only key>.
        const program = Buffer.concat([Buffer.from([0x51, 0x20]), xonly(tweaked)]);
        if (Buffer.compare(program, expectedScript) === 0) {
          emit({ ok: true, derivedScriptHex: program.toString('hex') });
          return;
        }
      } catch (e) {
        // try next parity combination
      }
    }
  }

  emit({ ok: false, reason: 'address_mismatch' });
})();
