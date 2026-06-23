// SPDX-License-Identifier: MIT
/**
 * Boltz Cooperative Taproot Claim Script
 *
 * Constructs and broadcasts a cooperative claim transaction for a Boltz
 * reverse submarine swap using Musig2 (BIP-327) key-path spending.
 *
 * Input: JSON on stdin with swap details
 * Output: JSON on stdout with { txid, txHex }
 *
 * Uses boltz-core@3.1.x (reference implementation) for:
 * - Taproot tree construction & swap output detection
 * - Musig2 nonce exchange + partial signatures via @vulpemventures/secp256k1-zkp
 * - Transaction construction + witness building via bitcoinjs-lib
 *
 * @see https://docs.boltz.exchange/v/api/lifecycle#reverse-submarine-swaps
 */
'use strict';

// Refuse grandchild spawns.
// The parent expects this process to be a leaf in the process tree.
// Any spawn/fork from within boltz_claim.js (e.g., a transitively-loaded
// dep that shells out) is a sandbox-escape signal — emit a structured
// event so the parent can flag it and crash the run.
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
const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');
const {
  constructClaimTransaction,
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

// Optional SOCKS proxy support for Tor routing
let SocksProxyAgent;
try {
  SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent;
} catch {
  // socks-proxy-agent not installed — proxy will not be available
}

// Initialize ECC library for bitcoinjs-lib
initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

// Shared proxy agent instance (initialized in main() if socksProxy is provided)
let proxyAgent = null;

/**
 * Make an HTTP(S) request, optionally routed through a SOCKS5 proxy (Tor).
 */
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

    if (proxyAgent) {
      options.agent = proxyAgent;
    }

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

/**
 * Parse swap tree from Boltz API response into boltz-core format.
 */
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

/**
 * Main claim flow. Dispatches on ``input.mode``:
 *
 * * ``"cooperative"`` (default) — Musig2 key-path spend negotiated
 *   with Boltz. Fastest, cheapest witness, but requires the
 *   counterparty to co-sign.
 * * ``"unilateral"`` — script-path spend using the swap's claim
 *   leaf (preimage + claim key). No counterparty interaction;
 *   used as the post-timeout escape hatch when Boltz refuses or
 *   is unreachable.
 *
 * Both modes broadcast via Boltz's ``/chain/BTC/transaction`` and
 * emit the same ``claim_broadcast_complete`` event on stdout.
 */
async function main() {
  const inputChunks = [];
  for await (const chunk of process.stdin) {
    inputChunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(inputChunks).toString());

  const {
    boltzUrl,
    swapId,
    preimage,
    claimPrivateKey,
    refundPublicKey,
    swapTree: swapTreeJson,
    lockupTxHex,
    destinationAddress,
    socksProxy,
    network,
    mode = 'cooperative',
    // When true, the broadcast claim-tx hex is included on the stdout
    // event so the (non-anonymize) caller can cross-check the output
    // script against the intended destination. The hex is public chain
    // data once broadcast; the anonymize wrapper leaves this off and
    // reads the hex out-of-band on fd 3 instead, keeping stdout clean.
    emitTxHexStdout = false,
  } = input;

  // ── Step 0: Initialize SOCKS proxy for Tor routing ──
  if (socksProxy) {
    if (!SocksProxyAgent) {
      throw new Error(
        'SOCKS proxy requested but socks-proxy-agent is not installed. ' +
        'Run: npm install socks-proxy-agent'
      );
    }
    // socks-proxy-agent treats `socks5://` as "client-side DNS lookup",
    // which breaks `.onion` hostnames (the system resolver can't resolve
    // them). `socks5h://` defers DNS to the proxy, which is required for
    // hidden-service URLs and is what the Python httpx side already does.
    const normalizedProxy = socksProxy.replace(/^socks5:\/\//, 'socks5h://');
    proxyAgent = new SocksProxyAgent(normalizedProxy);
    process.stderr.write(`[claim] Routing through Tor proxy: ${normalizedProxy}\n`);
  }

  // ── Step 1: Initialize secp256k1-zkp ──
  const zkpInit = require('@vulpemventures/secp256k1-zkp');
  const secp = await (zkpInit.default || zkpInit)();

  // ── Step 2: Derive keys and parse inputs ──
  const keys = ECPair.fromPrivateKey(Buffer.from(claimPrivateKey, 'hex'));
  const preimageBuffer = Buffer.from(preimage, 'hex');
  const refundPubKey = Buffer.from(refundPublicKey, 'hex');
  const tree = parseSwapTree(swapTreeJson);
  const lockupTx = Transaction.fromHex(lockupTxHex);

  // ── Step 3: Create Musig2 session and tweak for Taproot ──
  const musig = new Musig(secp, keys, crypto.randomBytes(32), [
    refundPubKey,
    keys.publicKey,
  ]);

  const tweakedKey = TaprootUtils.tweakMusig(musig, tree.tree);

  // ── Step 4: Find the swap output using the tweaked key ──
  const swapOutput = detectSwap(tweakedKey, lockupTx);
  if (!swapOutput) {
    throw new Error(
      `Could not find swap output in lockup transaction ${lockupTx.getId()}`
    );
  }

  // ── Step 5: Build claim transaction ──
  // Determine network for address parsing
  let btcNetwork = Networks.bitcoinMainnet;
  if (network === 'testnet' || network === 'signet') {
    btcNetwork = Networks.bitcoinTestnet;
  } else if (network === 'regtest') {
    btcNetwork = Networks.bitcoinRegtest;
  }

  const destinationScript = address.toOutputScript(
    destinationAddress,
    btcNetwork
  );

  // Mode dispatch: cooperative (Musig2 key-path) is the default;
  // unilateral falls through to the script-path branch below.
  if (mode === 'unilateral') {
    // ── Unilateral script-path claim ──
    // Spend the lockup via the claim leaf using preimage + claim
    // key. ``cooperative: false`` instructs ``constructClaimTransaction``
    // to build the script-path witness (control block + leaf script
    // + signature + preimage) rather than the empty key-path witness
    // it leaves room for under cooperative mode.
    const claimTx = targetFee(2, (fee) =>
      constructClaimTransaction(
        [
          {
            ...swapOutput,
            txHash: lockupTx.getHash(),
            keys,
            preimage: preimageBuffer,
            cooperative: false,
            type: OutputType.Taproot,
            swapTree: tree,
            internalKey: tweakedKey,
          },
        ],
        destinationScript,
        fee,
        true // isRbf
      )
    );

    claimTx.version = 2;
    for (const inp of claimTx.ins) {
      inp.sequence = 0xfffffffd;
    }

    const finalTxHex = claimTx.toHex();

    const broadcastResponse = await httpRequest(
      `${boltzUrl}/chain/BTC/transaction`,
      'POST',
      { hex: finalTxHex }
    );

    if (broadcastResponse.status !== 200 && broadcastResponse.status !== 201) {
      throw new Error(
        `Broadcast failed (${broadcastResponse.status}): ` +
          JSON.stringify(broadcastResponse.data)
      );
    }

    const txid =
      broadcastResponse.data.id ||
      broadcastResponse.data.txid ||
      claimTx.getId();

    // Mirror the cooperative path's fd-3 protocol so the
    // anonymize wrapper can capture the raw hex out-of-band.
    const fs = require('fs');
    let fd3Open = false;
    try {
      fs.fstatSync(3);
      fd3Open = true;
    } catch {
      // fd 3 not opened — caller doesn't want the out-of-band hex.
    }
    if (fd3Open) {
      try {
        fs.writeSync(3, finalTxHex);
      } catch (err) {
        process.stderr.write(
          JSON.stringify({
            event: 'fd3_write_failed',
            error: err && err.message ? err.message : String(err),
          }) + '\n'
        );
        process.exit(3);
      }
    }

    console.log(JSON.stringify({
      event: 'claim_broadcast_complete',
      txid,
      mode: 'unilateral',
      ...(emitTxHexStdout ? { txHex: finalTxHex } : {}),
    }));
    return;
  }

  // ── Cooperative Musig2 key-path claim (default) ──
  const claimTx = targetFee(2, (fee) =>
    constructClaimTransaction(
      [
        {
          ...swapOutput,
          txHash: lockupTx.getHash(),
          keys,
          preimage: preimageBuffer,
          cooperative: true,
          type: OutputType.Taproot,
          swapTree: tree,
        },
      ],
      destinationScript,
      fee,
      true // isRbf
    )
  );

  // Bitcoin-Core-shaped envelope policy:
  // nVersion=2 + nSequence=0xfffffffd (BIP-125 RBF-opt-in) so the
  // claim TX doesn't fingerprint us against organic mainnet
  // traffic. ``constructClaimTransaction(isRbf=true)`` already sets
  // nSequence to 0xfffffffd; we explicitly enforce nVersion=2 here
  // so the Python-side assertion can hard-refuse otherwise.
  claimTx.version = 2;
  for (const inp of claimTx.ins) {
    inp.sequence = 0xfffffffd;
  }

  // ── Step 6: Compute sighash for Taproot key-path spend ──
  const sigHash = claimTx.hashForWitnessV1(
    0,
    [swapOutput.script],
    [swapOutput.value],
    Transaction.SIGHASH_DEFAULT
  );

  // ── Step 7: Get our public nonce and request Boltz's ──
  const ourPubNonce = Buffer.from(musig.getPublicNonce()).toString('hex');

  const claimResponse = await httpRequest(
    `${boltzUrl}/swap/reverse/${swapId}/claim`,
    'POST',
    {
      preimage,
      pubNonce: ourPubNonce,
      transaction: claimTx.toHex(),
      index: 0,
    }
  );

  if (claimResponse.status !== 200) {
    throw new Error(
      `Boltz claim request failed (${claimResponse.status}): ` +
        JSON.stringify(claimResponse.data)
    );
  }

  const { pubNonce: boltzPubNonce, partialSignature: boltzPartialSig } =
    claimResponse.data;

  // ── Step 8: Musig2 signing ceremony ──
  musig.aggregateNonces([
    [refundPubKey, Musig.parsePubNonce(boltzPubNonce)],
  ]);

  musig.initializeSession(sigHash);
  musig.signPartial();
  musig.addPartial(refundPubKey, Buffer.from(boltzPartialSig, 'hex'));

  const finalSig = musig.aggregatePartials();

  // ── Step 9: Set the real witness and broadcast ──
  claimTx.ins[0].witness = [finalSig];

  const finalTxHex = claimTx.toHex();

  const broadcastResponse = await httpRequest(
    `${boltzUrl}/chain/BTC/transaction`,
    'POST',
    { hex: finalTxHex }
  );

  if (broadcastResponse.status !== 200 && broadcastResponse.status !== 201) {
    throw new Error(
      `Broadcast failed (${broadcastResponse.status}): ` +
        JSON.stringify(broadcastResponse.data)
    );
  }

  const txid =
    broadcastResponse.data.id ||
    broadcastResponse.data.txid ||
    claimTx.getId();

  // Write the claim-tx hex to fd 3 (out-of-band).
  // The parent opens fd 3 as a dedicated pipe and reads it via read_fd_3().
  // stdout carries only the structured event line without the hex so a
  // logger / exception capture can never observe the raw hex.
  //
  // The general ``boltz_service.py`` path does not open fd 3; only the
  // anonymize wrapper does. Probe with fstatSync first so we skip the
  // write entirely when fd 3 is not opened by the parent (rather than
  // exiting fatally after a successful broadcast).
  const fs = require('fs');
  let fd3Open = false;
  try {
    fs.fstatSync(3);
    fd3Open = true;
  } catch {
    // fd 3 not opened — caller doesn't want the out-of-band hex.
  }
  if (fd3Open) {
    try {
      fs.writeSync(3, finalTxHex);
    } catch (err) {
      process.stderr.write(
        JSON.stringify({
          event: 'fd3_write_failed',
          error: err && err.message ? err.message : String(err),
        }) + '\n'
      );
      process.exit(3);
    }
  }

  console.log(JSON.stringify({
    event: 'claim_broadcast_complete',
    txid,
    ...(emitTxHexStdout ? { txHex: finalTxHex } : {}),
  }));
}

main().catch((err) => {
  process.stderr.write(
    JSON.stringify({ error: err.message, stack: err.stack }) + '\n'
  );
  process.exit(1);
});
