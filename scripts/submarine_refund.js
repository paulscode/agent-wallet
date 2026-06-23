// SPDX-License-Identifier: MIT
/**
 * Boltz Submarine Refund Script
 *
 * Constructs and broadcasts a refund transaction for a Boltz
 * submarine swap that ended without settlement (Boltz reported
 * ``invoice.failedToPay``, ``swap.expired``, etc.).
 *
 * Two modes are supported:
 *
 *  * mode="cooperative"  — uses Musig2 (BIP-327) key-path spend.
 *    Boltz cooperates by returning a partial signature against the
 *    same aggregated key the lockup output is locked to. Works
 *    immediately after a failure; no need to wait for
 *    ``timeoutBlockHeight``. Requires Boltz's claim public key.
 *
 *  * mode="unilateral"   — uses the refund leaf script-path. Only
 *    valid past ``timeoutBlockHeight``. Used as a backstop if
 *    Boltz refuses cooperation (e.g. server outage).
 *
 * Input: JSON on stdin. Output: JSON event on stdout; refund-tx
 * hex on fd 3 when the parent opened it.
 *
 * Uses boltz-core (reference impl) for swap-tree parsing, Musig2
 * via @vulpemventures/secp256k1-zkp, and bitcoinjs-lib for tx
 * assembly. Mirrors ``scripts/boltz_claim.js`` for parity.
 *
 * @see https://docs.boltz.exchange/v/api/lifecycle#submarine-swaps
 */
'use strict';

// Refuse grandchild spawns. The parent expects this process to be a
// leaf in the process tree; any spawn from a transitively-loaded dep
// is a sandbox-escape signal.
(function lockChildProcess() {
  const cp = require('child_process');
  const refuse = (method) => function refusedSpawn() {
    process.stderr.write(
      JSON.stringify({ event: 'forbidden_grandchild_spawn', method }) + '\n'
    );
    process.exit(2);
  };
  cp.spawn = refuse('spawn');
  cp.spawnSync = refuse('spawnSync');
  cp.exec = refuse('exec');
  cp.execSync = refuse('execSync');
  cp.execFile = refuse('execFile');
  cp.execFileSync = refuse('execFileSync');
  cp.fork = refuse('fork');
})();

const crypto = require('crypto');
const fs = require('fs');
const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');
const {
  constructRefundTransaction,
  detectSwap,
  targetFee,
  Networks,
  Musig,
  TaprootUtils,
  OutputType,
} = require('boltz-core');
const { Transaction, address, initEccLib } = require('bitcoinjs-lib');
const http = require('http');
const https = require('https');

let SocksProxyAgent;
try {
  SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent;
} catch {
  // optional
}

initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

let proxyAgent = null;

async function httpRequest(url, method, body = null) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    const lib = isHttps ? https : http;
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method,
      headers: { 'Content-Type': 'application/json' },
      timeout: 60000,
    };
    if (proxyAgent) options.agent = proxyAgent;
    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`HTTP request timed out: ${method} ${url}`));
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

function parseSwapTree(swapTreeJson) {
  const tree = {
    claimLeaf: {
      version: swapTreeJson.claimLeaf.version,
      output: Buffer.from(swapTreeJson.claimLeaf.output, 'hex'),
    },
    refundLeaf: {
      version: swapTreeJson.refundLeaf.version,
      output: Buffer.from(swapTreeJson.refundLeaf.output, 'hex'),
    },
  };
  tree.tree = [tree.claimLeaf, tree.refundLeaf];
  return tree;
}

function pickBtcNetwork(name) {
  if (name === 'testnet' || name === 'signet') return Networks.bitcoinTestnet;
  if (name === 'regtest') return Networks.bitcoinRegtest;
  return Networks.bitcoinMainnet;
}

/**
 * Surface the final refund-tx hex out-of-band to the parent.
 *
 * Preferred transport is ``BOLTZ_TX_OUT_FILE`` (a temp-file path the
 * anonymize wrapper exports) — same protocol as the Liquid scripts and
 * robust against Node 20's fd-3 placeholder. Falls back to writing fd 3
 * for any legacy caller that opened it.
 */
function maybeWriteFd3(hex) {
  const outFile = process.env.BOLTZ_TX_OUT_FILE;
  if (outFile) {
    try {
      fs.writeFileSync(outFile, hex);
      return;
    } catch (err) {
      process.stderr.write(
        JSON.stringify({
          event: 'tx_out_file_write_failed',
          error: err && err.message ? err.message : String(err),
        }) + '\n'
      );
      // fall through to the fd-3 attempt
    }
  }
  let fd3Open = false;
  try {
    fs.fstatSync(3);
    fd3Open = true;
  } catch {
    // fd 3 not opened by parent
  }
  if (fd3Open) {
    try {
      fs.writeSync(3, hex);
    } catch (err) {
      // The refund tx has already been broadcast by this point;
      // fd3 is just an optional out-of-band channel for the parent
      // to capture the raw tx hex. Log + continue rather than
      // erroring out — otherwise the caller treats a successful
      // refund as a failure and may attempt a redundant retry.
      process.stderr.write(
        JSON.stringify({
          event: 'fd3_write_failed',
          error: err && err.message ? err.message : String(err),
        }) + '\n'
      );
    }
  }
}

async function main() {
  const inputChunks = [];
  for await (const chunk of process.stdin) inputChunks.push(chunk);
  const input = JSON.parse(Buffer.concat(inputChunks).toString());

  const {
    mode = 'cooperative',
    boltzUrl,
    swapId,
    refundPrivateKey,
    refundPublicKey,
    claimPublicKey, // Boltz's side of the Musig2 key set
    swapTree: swapTreeJson,
    lockupTxHex,
    refundAddress,
    timeoutBlockHeight,
    currentBlockHeight,
    socksProxy,
    network,
    feeRate, // sat/vB; defaults to 2
  } = input;

  const refundFeeRate = Number.isFinite(feeRate) && feeRate > 0
    ? Number(feeRate)
    : 2;

  if (!refundAddress) {
    process.stderr.write(
      JSON.stringify({ event: 'refund_missing_destination', swapId }) + '\n'
    );
    process.exit(5);
  }
  if (!refundPrivateKey || !swapTreeJson || !lockupTxHex) {
    process.stderr.write(
      JSON.stringify({ event: 'refund_missing_input', swapId }) + '\n'
    );
    process.exit(7);
  }

  if (socksProxy) {
    if (!SocksProxyAgent) {
      process.stderr.write(
        JSON.stringify({
          event: 'refund_missing_socks_agent',
          error: 'socks-proxy-agent not installed',
        }) + '\n'
      );
      process.exit(8);
    }
    const normalizedProxy = socksProxy.replace(/^socks5:\/\//, 'socks5h://');
    proxyAgent = new SocksProxyAgent(normalizedProxy);
    process.stderr.write(`[refund] Routing through Tor proxy: ${normalizedProxy}\n`);
  }

  const zkpInit = require('@vulpemventures/secp256k1-zkp');
  const secp = await (zkpInit.default || zkpInit)();

  const keys = ECPair.fromPrivateKey(Buffer.from(refundPrivateKey, 'hex'));
  const tree = parseSwapTree(swapTreeJson);
  const lockupTx = Transaction.fromHex(lockupTxHex);
  const btcNetwork = pickBtcNetwork(network);
  const destinationScript = address.toOutputScript(refundAddress, btcNetwork);

  if (mode === 'cooperative') {
    if (!claimPublicKey) {
      process.stderr.write(
        JSON.stringify({
          event: 'refund_missing_claim_pubkey',
          swapId,
          note: (
            'cooperative refund requires Boltz claim public key; '
            + 'use mode=unilateral past timeoutBlockHeight'
          ),
        }) + '\n'
      );
      process.exit(9);
    }
    // Build the candidate list of Boltz claim pubkey encodings to
    // try. A 33-byte compressed pubkey (``02`` / ``03``) is canonical
    // and tried first. A 32-byte x-only encoding (recovered from the
    // claim leaf script when the create response wasn't persisted)
    // doesn't carry y-parity, so we try both parities and pick the
    // one whose Musig2 aggregate matches the lockup output.
    const rawClaimBuf = Buffer.from(claimPublicKey, 'hex');
    let claimPubKeyCandidates;
    if (rawClaimBuf.length === 33) {
      claimPubKeyCandidates = [rawClaimBuf];
    } else if (rawClaimBuf.length === 32) {
      claimPubKeyCandidates = [
        Buffer.concat([Buffer.from([0x02]), rawClaimBuf]),
        Buffer.concat([Buffer.from([0x03]), rawClaimBuf]),
      ];
    } else {
      throw new Error(
        `Boltz claim public key must be 32 or 33 bytes, got ${rawClaimBuf.length}`
      );
    }

    let musig = null;
    let tweakedKey = null;
    let swapOutput = null;
    let claimPubKey = null;
    for (const candidate of claimPubKeyCandidates) {
      // Musig2 key set order matches the lockup output: Boltz's claim
      // pubkey first, our refund pubkey second. Mirrors what was used
      // by Boltz when generating the swap's aggregate key.
      const trialMusig = new Musig(secp, keys, crypto.randomBytes(32), [
        candidate,
        keys.publicKey,
      ]);
      const trialTweaked = TaprootUtils.tweakMusig(trialMusig, tree.tree);
      const trialOutput = detectSwap(trialTweaked, lockupTx);
      if (trialOutput) {
        musig = trialMusig;
        tweakedKey = trialTweaked;
        swapOutput = trialOutput;
        claimPubKey = candidate;
        break;
      }
    }
    if (!swapOutput) {
      throw new Error(
        `Could not find swap output in lockup tx ${lockupTx.getId()}`
          + ` (tried ${claimPubKeyCandidates.length} claim-pubkey`
          + ' parity variant(s))'
      );
    }

    // Cooperative refund tx: key-path spend, no witness script,
    // cooperative=true tells boltz-core to skip the script-leaf path.
    // ``targetFee(feeRate, …)`` produces a feeRate sat/vB refund tx;
    // the network sees it as a normal taproot spend.
    const refundTx = targetFee(refundFeeRate, (fee) =>
      constructRefundTransaction(
        [
          {
            ...swapOutput,
            txHash: lockupTx.getHash(),
            keys,
            cooperative: true,
            type: OutputType.Taproot,
            swapTree: tree,
          },
        ],
        destinationScript,
        // ``timeoutBlockHeight`` is irrelevant for key-path
        // cooperative spends (no script-leaf CHECKLOCKTIMEVERIFY)
        // but boltz-core's API still takes it; passing 0 keeps the
        // locktime out of the way.
        0,
        fee,
        true // isRbf
      )
    );

    // Fingerprint hygiene — match the boltz_claim.js envelope.
    refundTx.version = 2;
    for (const inp of refundTx.ins) inp.sequence = 0xfffffffd;

    const sigHash = refundTx.hashForWitnessV1(
      0,
      [swapOutput.script],
      [swapOutput.value],
      Transaction.SIGHASH_DEFAULT
    );

    const ourPubNonce = Buffer.from(musig.getPublicNonce()).toString('hex');

    const refundResponse = await httpRequest(
      `${boltzUrl}/swap/submarine/${swapId}/refund`,
      'POST',
      {
        pubNonce: ourPubNonce,
        transaction: refundTx.toHex(),
        index: 0,
      }
    );
    if (refundResponse.status !== 200) {
      throw new Error(
        `Boltz refund partial-sig request failed (${refundResponse.status}): `
          + JSON.stringify(refundResponse.data)
      );
    }
    const {
      pubNonce: boltzPubNonce,
      partialSignature: boltzPartialSig,
    } = refundResponse.data;
    if (!boltzPubNonce || !boltzPartialSig) {
      throw new Error(
        'Boltz refund response missing pubNonce/partialSignature: '
          + JSON.stringify(refundResponse.data)
      );
    }

    musig.aggregateNonces([
      [claimPubKey, Musig.parsePubNonce(boltzPubNonce)],
    ]);
    musig.initializeSession(sigHash);
    musig.signPartial();
    musig.addPartial(claimPubKey, Buffer.from(boltzPartialSig, 'hex'));
    const finalSig = musig.aggregatePartials();

    refundTx.ins[0].witness = [finalSig];

    const finalTxHex = refundTx.toHex();
    const broadcast = await httpRequest(
      `${boltzUrl}/chain/BTC/transaction`,
      'POST',
      { hex: finalTxHex }
    );
    if (broadcast.status !== 200 && broadcast.status !== 201) {
      throw new Error(
        `Refund broadcast failed (${broadcast.status}): `
          + JSON.stringify(broadcast.data)
      );
    }
    const txid =
      (broadcast.data && (broadcast.data.id || broadcast.data.txid)) ||
      refundTx.getId();

    maybeWriteFd3(finalTxHex);
    console.log(JSON.stringify({
      event: 'submarine_refund_broadcast',
      mode: 'cooperative',
      swapId,
      txid,
    }));
    return;
  }

  if (mode === 'unilateral') {
    // Script-path refund. Requires currentBlockHeight >=
    // timeoutBlockHeight or the network will reject for non-final.
    if (
      typeof timeoutBlockHeight === 'number'
      && typeof currentBlockHeight === 'number'
      && currentBlockHeight < timeoutBlockHeight
    ) {
      process.stderr.write(
        JSON.stringify({
          event: 'refund_not_yet_eligible',
          swapId,
          currentBlockHeight,
          timeoutBlockHeight,
        }) + '\n'
      );
      process.exit(4);
    }

    // For unilateral refund we don't need claimPublicKey or Musig2 —
    // the refund leaf script can be satisfied with our signature
    // alone (CHECKSIG against the refund key + CSV via the locktime).
    // We still need the aggregated output script to detectSwap, so
    // we tweak with a temporary Musig session just to compute the
    // tweaked output key. Cooperative=false routes through the
    // script leaf.
    if (!input.claimPublicKey) {
      // We can still discover the swap output by trial-detecting
      // against the tweaked key if we have the claim pubkey;
      // without it we'd need extra metadata. For now require it
      // even for unilateral refunds.
      process.stderr.write(
        JSON.stringify({
          event: 'refund_missing_claim_pubkey',
          swapId,
        }) + '\n'
      );
      process.exit(9);
    }
    const claimPubKey = Buffer.from(input.claimPublicKey, 'hex');
    const musig = new Musig(secp, keys, crypto.randomBytes(32), [
      claimPubKey,
      keys.publicKey,
    ]);
    const tweakedKey = TaprootUtils.tweakMusig(musig, tree.tree);
    const swapOutput = detectSwap(tweakedKey, lockupTx);
    if (!swapOutput) {
      throw new Error(
        `Could not find swap output in lockup tx ${lockupTx.getId()}`
      );
    }

    const refundTx = targetFee(refundFeeRate, (fee) =>
      constructRefundTransaction(
        [
          {
            ...swapOutput,
            txHash: lockupTx.getHash(),
            keys,
            cooperative: false,
            type: OutputType.Taproot,
            swapTree: tree,
          },
        ],
        destinationScript,
        timeoutBlockHeight,
        fee,
        true
      )
    );
    refundTx.version = 2;
    // BIP-68 sequences are managed by constructRefundTransaction
    // when cooperative=false. Don't override them.

    const finalTxHex = refundTx.toHex();
    const broadcast = await httpRequest(
      `${boltzUrl}/chain/BTC/transaction`,
      'POST',
      { hex: finalTxHex }
    );
    if (broadcast.status !== 200 && broadcast.status !== 201) {
      throw new Error(
        `Unilateral refund broadcast failed (${broadcast.status}): `
          + JSON.stringify(broadcast.data)
      );
    }
    const txid =
      (broadcast.data && (broadcast.data.id || broadcast.data.txid)) ||
      refundTx.getId();
    maybeWriteFd3(finalTxHex);
    console.log(JSON.stringify({
      event: 'submarine_refund_broadcast',
      mode: 'unilateral',
      swapId,
      txid,
    }));
    return;
  }

  process.stderr.write(
    JSON.stringify({ event: 'refund_unknown_mode', mode, swapId }) + '\n'
  );
  process.exit(10);
}

main().catch((err) => {
  process.stderr.write(
    JSON.stringify({ event: 'submarine_refund_error', error: err.message, stack: err.stack }) + '\n'
  );
  process.exit(1);
});
