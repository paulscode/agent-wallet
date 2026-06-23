// SPDX-License-Identifier: MIT
/**
 * Boltz Cooperative Liquid Taproot Claim Script
 *
 * Builds and broadcasts a cooperative claim transaction for a Boltz
 * reverse swap whose lockup is on **Liquid (L-BTC)**. The MuSig2
 * (BIP-327) ceremony is identical to the BTC variant in
 * ``boltz_claim.js``; the on-chain assembly differs in three ways:
 *
 *   1. The lockup TX is parsed by ``liquidjs-lib``'s ``Transaction``,
 *      whose outputs carry ``value: Buffer``, ``asset: Buffer``, and
 *      ``nonce: Buffer`` (CT-blinded) instead of an integer ``value``.
 *   2. The output is unblinded with the Boltz-revealed
 *      ``blindingPrivateKey`` so the claim TX can re-blind funds to a
 *      wallet-controlled CT destination address.
 *   3. The sighash is taken via ``boltz-core/dist/lib/liquid``'s
 *      ``TaprootUtils.hashForWitnessV1`` (Liquid-specific hash
 *      preimage that includes the asset commitment).
 *
 * Input: JSON on stdin matching the BTC script's shape plus:
 *   - ``blindingKey`` (hex, 32 bytes — Boltz-revealed for the lockup)
 *   - ``assetId`` (hex, 32 bytes — optional, overrides the network's
 *     baked-in ``assetHash`` for regtest deployments that customize
 *     the L-BTC asset id)
 *   - ``network`` ∈ {``mainnet``, ``testnet``, ``regtest``}
 *   - ``mode`` ∈ {``cooperative`` (default), ``unilateral``} —
 *     ``unilateral`` performs a script-path spend using the swap's
 *     claim leaf (preimage + claim key) without contacting Boltz
 *     for a MuSig2 partial signature. Used as the post-preimage-
 *     reveal escape hatch when Boltz is unreachable or refuses to
 *     co-sign on the LN→L-BTC reverse leg of the Anonymize Liquid
 *     hop.
 *
 * Output: ``{event: "liquid_claim_broadcast_complete", txid}`` on
 * stdout; final raw tx hex on fd 3.
 *
 * @see https://docs.boltz.exchange/api/lifecycle#reverse-submarine-swaps
 */
'use strict';

// Refuse grandchild spawns.
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

const { Musig, targetFee, OutputType } = require('boltz-core');
const liquidBoltz = require('boltz-core/dist/lib/liquid');
const {
  constructClaimTransaction: constructLiquidClaim,
  Networks: LiquidNetworks,
  TaprootUtils: LiquidTaprootUtils,
  init: initLiquidBoltz,
} = liquidBoltz;
const { detectSwap } = require('boltz-core');

// Optional SOCKS proxy (Tor)
let SocksProxyAgent;
try {
  SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent;
} catch {
  // socks-proxy-agent not installed — proxy will not be available
}

// Initialize ECC for bitcoinjs (used by ecpair + the BTC-side primitives
// re-exported from boltz-core). Liquid's secp-zkp init happens in main().
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
    blindingKey,
    assetId,
    socksProxy,
    network,
    mode = 'cooperative',
  } = input;

  // ── Step 0: SOCKS proxy for Tor routing ──
  if (socksProxy) {
    if (!SocksProxyAgent) {
      throw new Error(
        'SOCKS proxy requested but socks-proxy-agent is not installed.'
      );
    }
    // socks-proxy-agent treats `socks5://` as "client-side DNS lookup",
    // which breaks `.onion` hostnames. `socks5h://` defers DNS to the
    // proxy, which is what the Python httpx side already does.
    const normalizedProxy = socksProxy.replace(/^socks5:\/\//, 'socks5h://');
    proxyAgent = new SocksProxyAgent(normalizedProxy);
    process.stderr.write(`[liquid-claim] Routing through Tor proxy: ${normalizedProxy}\n`);
  }

  // ── Step 1: Init secp256k1-zkp + boltz-core/liquid ──
  // The Liquid namespace needs zkp for Confidential operations even on
  // the cooperative claim path (e.g. blinded output construction in
  // constructClaimTransaction when a blindingKey is supplied).
  const zkpInit = require('@vulpemventures/secp256k1-zkp');
  const zkp = await (zkpInit.default || zkpInit)();
  initLiquidBoltz(zkp);

  // ── Step 2: Derive keys + parse inputs ──
  const keys = ECPair.fromPrivateKey(Buffer.from(claimPrivateKey, 'hex'));
  const preimageBuffer = Buffer.from(preimage, 'hex');
  const refundPubKey = Buffer.from(refundPublicKey, 'hex');
  const blindingPrivKey = Buffer.from(blindingKey, 'hex');
  if (blindingPrivKey.length !== 32) {
    throw new Error(`blindingKey must be 32 bytes, got ${blindingPrivKey.length}`);
  }
  const tree = parseSwapTree(swapTreeJson);
  const lockupTx = LiquidTransaction.fromHex(lockupTxHex);

  // ── Step 3: MuSig2 session + tweak for Taproot ──
  const musig = new Musig(zkp, keys, crypto.randomBytes(32), [
    refundPubKey,
    keys.publicKey,
  ]);
  // ``tweakMusig`` in the liquid namespace folds the script tree into
  // the aggregated key, returning the x-only tweaked pubkey used as the
  // taproot output key.
  const tweakedKey = LiquidTaprootUtils.tweakMusig(musig, tree.tree);

  // ── Step 4: Find the swap output ──
  // ``detectSwap`` is generic over { outs: TxOutput | LiquidTxOutput }
  // so the BTC export accepts a liquidjs Transaction and returns a
  // LiquidTxOutput (value/asset/nonce as Buffers).
  const swapOutput = detectSwap(tweakedKey, lockupTx);
  if (!swapOutput) {
    throw new Error(
      `Could not find swap output in lockup transaction ${lockupTx.getId()}`
    );
  }

  // ── Step 5: Resolve network + optional regtest asset override ──
  const networks = resolveLiquidNetwork(network);
  let liquidNet = networks.liquid;
  if (assetId) {
    // Regtest harnesses (BoltzExchange/regtest) customize the L-BTC
    // asset id; the network object's ``assetHash`` must match for
    // constructClaimTransaction's blinded-output bookkeeping. Clone the
    // network so we don't mutate the shared singleton.
    liquidNet = { ...liquidNet, assetHash: assetId };
  }

  // ── Step 6: Resolve destination script (CT-aware) ──
  // ``liquidAddress.toOutputScript`` strips the blinding-pubkey prefix
  // from a CT address before returning the underlying scriptPubKey.
  const destinationScript = liquidAddress.toOutputScript(
    destinationAddress, liquidNet,
  );
  // If the caller passed a CT destination, lift its blinding pubkey so
  // constructLiquidClaim re-blinds the output back to the wallet.
  let destinationBlindingPub;
  try {
    destinationBlindingPub = liquidAddress.fromConfidential(
      destinationAddress, liquidNet,
    ).blindingKey;
  } catch (e) {
    // Unconfidential destination — leave undefined; boltz-core treats
    // a missing blinding key as "publish as an unblinded output". The
    // wallet's CT receive path should always supply a confidential
    // address; we don't enforce here.
    destinationBlindingPub = undefined;
  }

  // ── Unilateral script-path claim (mode='unilateral') ──
  // Spend the lockup via the claim leaf using preimage + claim key.
  // ``cooperative: false`` instructs ``constructLiquidClaim`` to
  // build the script-path witness (control block + leaf script +
  // signature + preimage) rather than the empty key-path witness
  // that cooperative mode leaves room for. No Boltz interaction —
  // works even when the operator is unreachable or refuses to
  // co-sign. Caller must have already revealed the preimage on the
  // LN side (i.e. Boltz has settled the hold invoice) so the
  // preimage in ``input`` is the wallet's own copy.
  if (mode === 'unilateral') {
    const claimTx = targetFee(2, (fee) =>
      constructLiquidClaim(
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
            blindingPrivateKey: blindingPrivKey,
          },
        ],
        destinationScript,
        fee,
        true,             // isRbf
        liquidNet,
        destinationBlindingPub,
      )
    );

    claimTx.version = 2;
    for (const inp of claimTx.ins) {
      inp.sequence = 0xfffffffd;
    }

    const finalTxHex = claimTx.toHex();

    const broadcastResponse = await httpRequest(
      `${boltzUrl}/v2/chain/L-BTC/transaction`,
      'POST',
      { hex: finalTxHex }
    );
    if (
      broadcastResponse.status !== 200 &&
      broadcastResponse.status !== 201
    ) {
      throw new Error(
        `Broadcast failed (${broadcastResponse.status}): ` +
          JSON.stringify(broadcastResponse.data)
      );
    }
    const txid =
      broadcastResponse.data.id ||
      broadcastResponse.data.txid ||
      claimTx.getId();

    // Same fd-3 / BOLTZ_TX_OUT_FILE protocol as the cooperative
    // path so the anonymize wrapper captures the raw hex.
    const outFile = process.env.BOLTZ_TX_OUT_FILE;
    if (outFile) {
      try {
        fs.writeFileSync(outFile, finalTxHex);
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
      event: 'liquid_claim_broadcast_complete',
      txid,
      mode: 'unilateral',
    }));
    return;
  }

  // ── Step 7: Build the cooperative claim TX ──
  // ``constructLiquidClaim`` expects ``LiquidClaimDetails`` which is
  // the LiquidTxOutput plus { txHash, vout, type, cooperative, keys,
  // preimage, swapTree, blindingPrivateKey }.
  const claimDetails = {
    ...swapOutput,
    txHash: lockupTx.getHash(),
    keys,
    preimage: preimageBuffer,
    cooperative: true,
    type: OutputType.Taproot,
    swapTree: tree,
    blindingPrivateKey: blindingPrivKey,
  };
  const claimTx = targetFee(2, (fee) =>
    constructLiquidClaim(
      [claimDetails],
      destinationScript,
      fee,
      true,             // isRbf
      liquidNet,
      destinationBlindingPub,
    )
  );

  // Enforce nVersion=2 + BIP-125 RBF sequence so
  // the claim TX doesn't fingerprint us against organic mainnet traffic.
  // ``constructLiquidClaim(isRbf=true)`` already sets nSequence; we
  // explicitly enforce nVersion=2 for the Python-side assertion.
  claimTx.version = 2;
  for (const inp of claimTx.ins) {
    inp.sequence = 0xfffffffd;
  }

  // ── Step 8: Compute sighash for Taproot key-path spend ──
  // The Liquid hashForWitnessV1 takes the network + an array of
  // prevout TxOutputs (one per input). Here we have a single input
  // pointing at the lockup output.
  const sigHash = LiquidTaprootUtils.hashForWitnessV1(
    liquidNet,
    [swapOutput],
    claimTx,
    0,
    undefined,                        // leafHash — undefined for key-path
    LiquidTransaction.SIGHASH_DEFAULT,
  );

  // ── Step 9: Exchange MuSig2 nonces with Boltz ──
  const ourPubNonce = Buffer.from(musig.getPublicNonce()).toString('hex');

  const claimResponse = await httpRequest(
    `${boltzUrl}/v2/swap/reverse/${swapId}/claim`,
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

  // ── Step 10: MuSig2 signing ceremony ──
  musig.aggregateNonces([
    [refundPubKey, Musig.parsePubNonce(boltzPubNonce)],
  ]);
  musig.initializeSession(sigHash);
  musig.signPartial();
  musig.addPartial(refundPubKey, Buffer.from(boltzPartialSig, 'hex'));
  const finalSig = musig.aggregatePartials();

  // ── Step 11: Witness + broadcast ──
  claimTx.ins[0].witness = [finalSig];
  const finalTxHex = claimTx.toHex();

  const broadcastResponse = await httpRequest(
    `${boltzUrl}/v2/chain/L-BTC/transaction`,
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

  // Claim-tx hex on fd 3 (out-of-band).
  // The parent passes a temp-file path via ``BOLTZ_TX_OUT_FILE``;
  // we write the final hex there and the parent reads + unlinks
  // it. This bypasses Node 20's startup-time fd-3+ placeholder
  // injection that mangles inherited pipes on low fds.
  //
  // The general ``boltz_service.py`` path does not set this env var;
  // only the anonymize wrapper does. When unset, skip the write — the
  // txid is still returned via stdout.
  const outFile = process.env.BOLTZ_TX_OUT_FILE;
  if (outFile) {
    try {
      fs.writeFileSync(outFile, finalTxHex);
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

  console.log(JSON.stringify({ event: 'liquid_claim_broadcast_complete', txid }));
}

main().catch((err) => {
  process.stderr.write(
    JSON.stringify({ error: err.message, stack: err.stack }) + '\n'
  );
  process.exit(1);
});
