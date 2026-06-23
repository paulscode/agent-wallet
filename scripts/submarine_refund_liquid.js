// SPDX-License-Identifier: MIT
/**
 * Boltz Liquid Submarine Refund Script
 *
 * Constructs and broadcasts a refund transaction for a Boltz
 * **L-BTC submarine swap** (the L-BTC→LN leg of the Anonymize
 * Liquid round-trip hop) that ended without settlement.
 *
 * Parallel to ``scripts/submarine_refund.js`` but using
 * ``liquidjs-lib`` + ``boltz-core/dist/lib/liquid`` for the
 * Confidential-Transaction-aware TX assembly. Two modes:
 *
 *  * ``mode="cooperative"`` — Musig2 (BIP-327) key-path refund
 *    against Boltz's claim public key. Works immediately; no
 *    timeout wait. Requires Boltz cooperation.
 *
 *  * ``mode="unilateral"`` — refund-leaf script-path spend. Only
 *    valid past ``timeoutBlockHeight``. Backstop when Boltz is
 *    unreachable or refuses to co-sign.
 *
 * Input: JSON on stdin matching the BTC script's shape plus:
 *   - ``blindingKey`` (hex, 32 bytes — per-session SLIP-77 blinding
 *     privkey for the lockup output we created)
 *   - ``assetId`` (hex, 32 bytes — optional regtest override of
 *     the L-BTC asset id)
 *   - ``network`` ∈ {``mainnet``, ``testnet``, ``regtest``}
 *
 * Output: ``{event:"liquid_submarine_refund_broadcast", txid, mode}``
 * on stdout; final raw tx hex on fd 3 / ``BOLTZ_TX_OUT_FILE``.
 */
'use strict';

// Refuse grandchild spawns — sandbox-escape signal.
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
const http = require('http');
const https = require('https');

const { ECPairFactory } = require('ecpair');
const ecc = require('tiny-secp256k1');
const { initEccLib } = require('bitcoinjs-lib');

const liquidjs = require('liquidjs-lib');
const {
  address: liquidAddress,
  Transaction: LiquidTransaction,
  networks: liquidNetworks,
} = liquidjs;

const { Musig, targetFee, OutputType, detectSwap } = require('boltz-core');
const liquidBoltz = require('boltz-core/dist/lib/liquid');
const {
  constructRefundTransaction: constructLiquidRefund,
  Networks: LiquidNetworks,
  TaprootUtils: LiquidTaprootUtils,
  init: initLiquidBoltz,
} = liquidBoltz;

let SocksProxyAgent;
try {
  SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent;
} catch {
  // optional — Tor routing only required when boltzUrl is a .onion
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

function resolveLiquidNetwork(name) {
  switch (name) {
    case 'mainnet':
    case 'liquid':
      return { liquid: liquidNetworks.liquid, boltz: LiquidNetworks.liquidMainnet };
    case 'testnet':
      return { liquid: liquidNetworks.testnet, boltz: LiquidNetworks.liquidTestnet };
    case 'regtest':
      return { liquid: liquidNetworks.regtest, boltz: LiquidNetworks.liquidRegtest };
    default:
      throw new Error(`unsupported liquid network: ${name}`);
  }
}

/**
 * Mirror the cooperative-claim fd-3 protocol: when the parent passes
 * ``BOLTZ_TX_OUT_FILE`` (the anonymize wrapper does), write the final
 * hex there; otherwise leave it on stdout-event only. Failure to
 * write the side-channel hex must NOT fail the script — the refund
 * has already broadcast at this point.
 */
function maybeWriteSideChannel(finalTxHex) {
  const outFile = process.env.BOLTZ_TX_OUT_FILE;
  if (!outFile) return;
  try {
    fs.writeFileSync(outFile, finalTxHex);
  } catch (err) {
    process.stderr.write(
      JSON.stringify({
        event: 'fd3_write_failed',
        error: err && err.message ? err.message : String(err),
      }) + '\n'
    );
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
    claimPublicKey,           // Boltz's side of the Musig2 key set
    swapTree: swapTreeJson,
    lockupTxHex,
    refundAddress,
    blindingKey,              // per-session SLIP-77 blinding privkey
    assetId,
    timeoutBlockHeight,
    currentBlockHeight,
    socksProxy,
    network,
    feeRate,                  // sat/vB; defaults to 2
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
  if (!refundPrivateKey || !swapTreeJson || !lockupTxHex || !blindingKey) {
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
    process.stderr.write(
      `[liquid-refund] Routing through Tor proxy: ${normalizedProxy}\n`
    );
  }

  // Liquid's CT primitives need secp256k1-zkp even on the
  // cooperative path (blinded refund-output construction).
  const zkpInit = require('@vulpemventures/secp256k1-zkp');
  const zkp = await (zkpInit.default || zkpInit)();
  initLiquidBoltz(zkp);

  const keys = ECPair.fromPrivateKey(Buffer.from(refundPrivateKey, 'hex'));
  const tree = parseSwapTree(swapTreeJson);
  const lockupTx = LiquidTransaction.fromHex(lockupTxHex);
  const blindingPrivKey = Buffer.from(blindingKey, 'hex');
  if (blindingPrivKey.length !== 32) {
    throw new Error(
      `blindingKey must be 32 bytes, got ${blindingPrivKey.length}`
    );
  }

  const networks = resolveLiquidNetwork(network);
  let liquidNet = networks.liquid;
  if (assetId) {
    // Regtest harnesses customize the L-BTC asset id; the network
    // object's assetHash must match for the blinded-output
    // bookkeeping. Clone so the shared singleton isn't mutated.
    liquidNet = { ...liquidNet, assetHash: assetId };
  }

  const destinationScript = liquidAddress.toOutputScript(
    refundAddress, liquidNet,
  );
  let destinationBlindingPub;
  try {
    destinationBlindingPub = liquidAddress.fromConfidential(
      refundAddress, liquidNet,
    ).blindingKey;
  } catch {
    // Unconfidential refund address — leave undefined. Real
    // deployments should always refund to a CT address; we don't
    // enforce here so regtest harnesses can opt out.
    destinationBlindingPub = undefined;
  }

  // ── Cooperative MuSig2 key-path refund ────────────────────────
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

    // Same y-parity recovery trick as the BTC script: a 32-byte
    // x-only encoding doesn't carry parity, so try both.
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
    let swapOutput = null;
    let claimPubKey = null;
    for (const candidate of claimPubKeyCandidates) {
      const trialMusig = new Musig(zkp, keys, crypto.randomBytes(32), [
        candidate,
        keys.publicKey,
      ]);
      const trialTweaked = LiquidTaprootUtils.tweakMusig(
        trialMusig, tree.tree,
      );
      const trialOutput = detectSwap(trialTweaked, lockupTx);
      if (trialOutput) {
        musig = trialMusig;
        swapOutput = trialOutput;
        claimPubKey = candidate;
        break;
      }
    }
    if (!swapOutput) {
      throw new Error(
        `Could not find swap output in lockup tx ${lockupTx.getId()}`
          + ` (tried ${claimPubKeyCandidates.length} claim-pubkey parity variant(s))`
      );
    }

    const refundTx = targetFee(refundFeeRate, (fee) =>
      constructLiquidRefund(
        [
          {
            ...swapOutput,
            txHash: lockupTx.getHash(),
            keys,
            cooperative: true,
            type: OutputType.Taproot,
            swapTree: tree,
            blindingPrivateKey: blindingPrivKey,
          },
        ],
        destinationScript,
        // Cooperative key-path: locktime is irrelevant. The
        // boltz-core API still takes it; passing 0 is the standard.
        0,
        fee,
        true,            // isRbf
        liquidNet,
        destinationBlindingPub,
      )
    );

    // Fingerprint hygiene parity with the BTC script.
    refundTx.version = 2;
    for (const inp of refundTx.ins) inp.sequence = 0xfffffffd;

    // Liquid taproot sighash includes the asset commitment — the
    // hashForWitnessV1 helper threads the network through for the
    // asset-id-aware preimage.
    const sigHash = LiquidTaprootUtils.hashForWitnessV1(
      liquidNet,
      [swapOutput],
      refundTx,
      0,
      undefined,                       // leafHash — undefined = key path
      LiquidTransaction.SIGHASH_DEFAULT,
    );

    const ourPubNonce = Buffer.from(musig.getPublicNonce()).toString('hex');
    const refundResponse = await httpRequest(
      `${boltzUrl}/v2/swap/submarine/${swapId}/refund`,
      'POST',
      {
        pubNonce: ourPubNonce,
        transaction: refundTx.toHex(),
        index: 0,
      },
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
      `${boltzUrl}/v2/chain/L-BTC/transaction`,
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

    maybeWriteSideChannel(finalTxHex);
    console.log(JSON.stringify({
      event: 'liquid_submarine_refund_broadcast',
      mode: 'cooperative',
      swapId,
      txid,
    }));
    return;
  }

  // ── Unilateral script-path refund ────────────────────────────
  if (mode === 'unilateral') {
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
    if (!claimPublicKey) {
      // Still required to discover the swap output via tweaked-key
      // detection. The refund leaf itself doesn't need it, but
      // detectSwap does.
      process.stderr.write(
        JSON.stringify({ event: 'refund_missing_claim_pubkey', swapId }) + '\n'
      );
      process.exit(9);
    }
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

    let swapOutput = null;
    for (const candidate of claimPubKeyCandidates) {
      const trialMusig = new Musig(zkp, keys, crypto.randomBytes(32), [
        candidate,
        keys.publicKey,
      ]);
      const trialTweaked = LiquidTaprootUtils.tweakMusig(
        trialMusig, tree.tree,
      );
      const trialOutput = detectSwap(trialTweaked, lockupTx);
      if (trialOutput) {
        swapOutput = trialOutput;
        break;
      }
    }
    if (!swapOutput) {
      throw new Error(
        `Could not find swap output in lockup tx ${lockupTx.getId()}`
      );
    }

    const refundTx = targetFee(refundFeeRate, (fee) =>
      constructLiquidRefund(
        [
          {
            ...swapOutput,
            txHash: lockupTx.getHash(),
            keys,
            cooperative: false,
            type: OutputType.Taproot,
            swapTree: tree,
            blindingPrivateKey: blindingPrivKey,
          },
        ],
        destinationScript,
        timeoutBlockHeight,
        fee,
        true,            // isRbf
        liquidNet,
        destinationBlindingPub,
      )
    );
    refundTx.version = 2;
    // BIP-68 sequences for the refund-leaf CHECKLOCKTIMEVERIFY are
    // managed by constructLiquidRefund when cooperative=false.

    const finalTxHex = refundTx.toHex();
    const broadcast = await httpRequest(
      `${boltzUrl}/v2/chain/L-BTC/transaction`,
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

    maybeWriteSideChannel(finalTxHex);
    console.log(JSON.stringify({
      event: 'liquid_submarine_refund_broadcast',
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
    JSON.stringify({
      event: 'liquid_submarine_refund_error',
      error: err.message,
      stack: err.stack,
    }) + '\n'
  );
  process.exit(1);
});
