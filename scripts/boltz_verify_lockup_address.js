// SPDX-License-Identifier: MIT
//
// Verify that a Boltz submarine-swap lockup address genuinely commits to
// the swap tree + our refund key BEFORE the wallet funds it.
//
// Threat model: the operator is semi-trusted. A
// malicious/compromised Boltz could return a `lockupAddress` it controls
// that is NOT a real swap output — the wallet would send on-chain funds
// with no refundable script and lose them. This helper reconstructs the
// expected P2TR lockup address from the (operator-supplied) swap tree +
// the two public keys and refuses unless:
//
//   1. the swap tree leaf WE spend through commits to OUR public key —
//      the refund leaf for a submarine swap (verifyLeaf="refund", our
//      refund key, so we can refund after the timeout) or the claim leaf
//      for a reverse swap (verifyLeaf="claim", our claim key, so we can
//      claim with our preimage), AND
//   2. the address derived from musig(claimKey, refundKey) tweaked by the
//      swap tree equals the operator-supplied lockupAddress.
//
// Input  (stdin JSON): { swapTree, refundPublicKey, claimPublicKey?,
//                        lockupAddress, network, verifyLeaf? }
//   verifyLeaf defaults to "refund" (submarine). Pass "claim" for the
//   reverse direction, with claimPublicKey set to our claim key.
// Output (stdout JSON): { ok: bool, derivedAddress?, reason? }
// Exit code is always 0 on a well-formed run; `ok` carries the verdict.

const ecc = require('tiny-secp256k1');
const { ECPairFactory } = require('ecpair');
const bitcoinjs = require('bitcoinjs-lib');
const { initEccLib, payments, networks } = bitcoinjs;
const crypto = require('crypto');
const {
  Musig,
  TaprootUtils,
  SwapTreeSerializer,
  extractRefundPublicKeyFromSwapTree,
  extractClaimPublicKeyFromSwapTree,
  extractClaimPublicKeyFromReverseSwapTree,
} = require('boltz-core');

initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

function pickNetwork(name) {
  if (name === 'testnet' || name === 'signet') return networks.testnet;
  if (name === 'regtest') return networks.regtest;
  return networks.bitcoin;
}

function xonly(buf) {
  return buf.length === 33 ? buf.slice(1) : buf;
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

  const {
    swapTree,
    refundPublicKey,
    claimPublicKey,
    lockupAddress,
    network,
    verifyLeaf = 'refund',
  } = input;
  if (!swapTree || !refundPublicKey || !lockupAddress) {
    emit({ ok: false, reason: 'missing_fields' });
    return;
  }
  if (verifyLeaf !== 'refund' && verifyLeaf !== 'claim') {
    emit({ ok: false, reason: 'bad_verify_leaf' });
    return;
  }
  if (verifyLeaf === 'claim' && !claimPublicKey) {
    emit({ ok: false, reason: 'missing_claim_key' });
    return;
  }

  const net = pickNetwork(network);

  const zkpInit = require('@vulpemventures/secp256k1-zkp');
  const secp = await (zkpInit.default || zkpInit)();

  let tree;
  let refundBuf;
  try {
    tree = SwapTreeSerializer.deserializeSwapTree(swapTree);
    refundBuf = Buffer.from(refundPublicKey, 'hex');
  } catch (e) {
    emit({ ok: false, reason: 'bad_tree_or_key' });
    return;
  }

  // (1) The leaf WE spend through MUST commit to our key: the refund leaf
  // for a submarine swap (so we can refund after the timeout), or the
  // claim leaf for a reverse swap (so we can claim with our preimage).
  if (verifyLeaf === 'claim') {
    try {
      // ``verifyLeaf='claim'`` is the reverse-swap path. The reverse claim
      // leaf carries our claim pubkey at a different script offset than the
      // submarine claim leaf (reverse: index 6 — preimage-hash check first;
      // submarine: index 3), so it needs the reverse-specific extractor.
      // Using the submarine extractor here reads the wrong element and throws
      // (claim_extract_failed).
      const treeClaimXonly = extractClaimPublicKeyFromReverseSwapTree(tree);
      if (Buffer.compare(treeClaimXonly, xonly(Buffer.from(claimPublicKey, 'hex'))) !== 0) {
        emit({ ok: false, reason: 'claim_leaf_mismatch' });
        return;
      }
    } catch (e) {
      emit({ ok: false, reason: 'claim_extract_failed' });
      return;
    }
  } else {
    try {
      const treeRefundXonly = extractRefundPublicKeyFromSwapTree(tree);
      if (Buffer.compare(treeRefundXonly, xonly(refundBuf)) !== 0) {
        emit({ ok: false, reason: 'refund_leaf_mismatch' });
        return;
      }
    } catch (e) {
      emit({ ok: false, reason: 'refund_extract_failed' });
      return;
    }
  }

  // (2) Reconstruct the address. The musig key set order Boltz uses is
  // [claimKey, refundKey]. The claim key may be supplied (compressed) or
  // recovered x-only from the tree — x-only loses y-parity, so try both.
  const claimCandidates = [];
  if (claimPublicKey) {
    const cb = Buffer.from(claimPublicKey, 'hex');
    if (cb.length === 33) claimCandidates.push(cb);
    else if (cb.length === 32) {
      claimCandidates.push(Buffer.concat([Buffer.from([0x02]), cb]));
      claimCandidates.push(Buffer.concat([Buffer.from([0x03]), cb]));
    }
  }
  if (claimCandidates.length === 0) {
    try {
      const cx = extractClaimPublicKeyFromSwapTree(tree);
      claimCandidates.push(Buffer.concat([Buffer.from([0x02]), cx]));
      claimCandidates.push(Buffer.concat([Buffer.from([0x03]), cx]));
    } catch (e) {
      emit({ ok: false, reason: 'claim_extract_failed' });
      return;
    }
  }

  // The local key passed to Musig does not affect the aggregate address;
  // use the (public-only) refund key so no secret is needed here.
  const refund33 = refundBuf.length === 33 ? refundBuf : Buffer.concat([Buffer.from([0x02]), refundBuf]);
  const localKey = ECPair.fromPublicKey(refund33);

  // Musig key order is significant — secp256k1-zkp's pubkeyAgg does NOT sort —
  // and it is direction-dependent: Boltz always orders [its key, our key].
  // Submarine: Boltz holds claim → [claim, refund] (matches submarine_refund.js).
  // Reverse: Boltz holds refund → [refund, claim] (matches boltz_claim.js, which
  // claims real reverse lockups with [refundPubKey, ourClaimKey]). Using the
  // wrong order yields a different aggregate and an address_mismatch.
  const orderKeySet = (claim) =>
    verifyLeaf === 'claim' ? [refund33, claim] : [claim, refund33];
  for (const claim of claimCandidates) {
    try {
      const musig = new Musig(secp, localKey, crypto.randomBytes(32), orderKeySet(claim));
      const tweaked = TaprootUtils.tweakMusig(musig, tree.tree);
      const p2tr = payments.p2tr({ pubkey: xonly(tweaked), network: net });
      if (p2tr.address === lockupAddress) {
        emit({ ok: true, derivedAddress: p2tr.address });
        return;
      }
    } catch (e) {
      // try next parity
    }
  }

  emit({ ok: false, reason: 'address_mismatch' });
})().catch((e) => {
  emit({ ok: false, reason: 'exception:' + (e && e.message ? e.message : String(e)) });
});
