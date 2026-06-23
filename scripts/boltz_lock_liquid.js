// SPDX-License-Identifier: MIT
/**
 * Boltz Liquid Lock Script
 *
 * Builds + signs + broadcasts the wallet's L-BTC spend that funds
 * Boltz's submarine-swap lockup. The leg-1 cooperative claim
 * produced a CT-blinded UTXO at the wallet's per-session p2wpkh
 * address; this script spends that UTXO to the address Boltz
 * returned in :class:`LiquidSubmarineSwap.address`.
 *
 * Transaction shape:
 *   - 1 input  (witness v0 p2wpkh, single-sig)
 *   - 1 destination output (CT-blinded, Boltz lockup, asset = L-BTC)
 *   - 1 change output     (CT-blinded, wallet, asset = L-BTC) [optional]
 *   - 1 fee output        (unblinded, asset = L-BTC; Liquid's explicit-fee convention)
 *
 * MuSig2 is NOT used here — the wallet owns the entire input via
 * its single-sig spending key. The Liquid signing path is the
 * standard PSET-V2 + p2wpkh sighash + ECDSA signature.
 *
 * Input: JSON on stdin (matches ``LiquidLockRequest`` in
 * ``app/services/anonymize/liquid_lock_subprocess.py``).
 * Output: stdout JSON event ``liquid_lock_broadcast_complete`` +
 * raw final tx hex on fd 3 (out-of-band).
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

const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');

const ecc = require('tiny-secp256k1');
const { ECPairFactory } = require('ecpair');
const { initEccLib } = require('bitcoinjs-lib');

const liquidjs = require('liquidjs-lib');
const {
  Pset, Creator, CreatorInput, CreatorOutput,
  Updater, Signer, Finalizer, Extractor,
  Blinder, ZKPGenerator, ZKPValidator,
  Transaction: LiquidTransaction,
  address: liquidAddress,
  payments: liquidPayments,
  networks: liquidNetworks,
} = liquidjs;

let SocksProxyAgent;
try {
  SocksProxyAgent = require('socks-proxy-agent').SocksProxyAgent;
} catch {
  // socks-proxy-agent not installed — no proxy
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

function resolveLiquidNetwork(name) {
  switch (name) {
    case 'mainnet':
    case 'liquid':
      return liquidNetworks.liquid;
    case 'testnet':
      return liquidNetworks.testnet;
    case 'regtest':
      return liquidNetworks.regtest;
    default:
      throw new Error(`unsupported liquid network: ${name}`);
  }
}

/**
 * Build, sign and broadcast the Liquid lock transaction.
 *
 * Steps:
 *   1. Parse inputs.
 *   2. Initialise secp256k1-zkp + create the spending keypair.
 *   3. Construct a one-input PSET with destination + change + fee
 *      outputs; let the fee be a rough first estimate that gets
 *      replaced in step 6 once we know the actual vsize.
 *   4. Attach the witness-UTXO + sighash type to the input.
 *   5. Blind the outputs (ZKPGenerator does the heavy lifting).
 *   6. Sign + finalise + extract.
 *   7. Broadcast via Boltz operator endpoint.
 *   8. Write fd-3 hex + emit stdout event.
 */
async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const input = JSON.parse(Buffer.concat(chunks).toString());

  const {
    utxoTxid, utxoVout, utxoValueSat,
    utxoAssetIdHex, utxoAssetBlindingFactorHex, utxoValueBlindingFactorHex,
    utxoPrevoutTxHex, utxoScriptPubKeyHex,
    spendingPrivateKey,
    destinationAddress, destinationAmountSat,
    feeSatPerVbyte,
    changeAddress,
    network, assetId,
    boltzUrl, socksProxy,
  } = input;

  if (socksProxy) {
    if (!SocksProxyAgent) {
      throw new Error('socks-proxy-agent not installed but socksProxy supplied');
    }
    // socks-proxy-agent treats `socks5://` as "client-side DNS lookup",
    // which breaks `.onion` hostnames. `socks5h://` defers DNS to the
    // proxy, which is what the Python httpx side already does.
    const normalizedProxy = socksProxy.replace(/^socks5:\/\//, 'socks5h://');
    proxyAgent = new SocksProxyAgent(normalizedProxy);
    process.stderr.write(`[liquid-lock] Routing through Tor proxy: ${normalizedProxy}\n`);
  }

  const zkpInit = require('@vulpemventures/secp256k1-zkp');
  const zkp = await (zkpInit.default || zkpInit)();

  // ── Network + asset overrides ──
  let liquidNet = resolveLiquidNetwork(network);
  if (assetId) {
    liquidNet = { ...liquidNet, assetHash: assetId };
  }
  // The ``assetId`` input + the network's ``assetHash`` are in
  // big-endian / "display" form (the form Boltz returns + the form
  // Liquid block explorers show). ``CreatorOutput(assetHash, ...)``
  // takes the BE hex string; ``AssetHash.fromHex`` reverses to LE
  // internally for the on-wire encoding. For the ZKP ownedInput's
  // ``asset`` field we have to reverse manually — see below.

  // ── Spending keypair ──
  const keys = ECPair.fromPrivateKey(Buffer.from(spendingPrivateKey, 'hex'));
  const inputScript = Buffer.from(utxoScriptPubKeyHex, 'hex');
  const p2wpkhPayment = liquidPayments.p2wpkh({ pubkey: keys.publicKey, network: liquidNet });
  if (!p2wpkhPayment.output || !p2wpkhPayment.output.equals(inputScript)) {
    throw new Error('spendingPrivateKey does not match utxoScriptPubKeyHex');
  }

  // ── Resolve destination + change scripts and blinding pubkeys ──
  function decodeOutputDestination(addr) {
    const out = { script: liquidAddress.toOutputScript(addr, liquidNet) };
    try {
      out.blindingPublicKey = liquidAddress.fromConfidential(addr, liquidNet).blindingKey;
    } catch (e) {
      // unconfidential — leave undefined; the output will be
      // unblinded if the caller passed an unconfidential address.
    }
    return out;
  }
  const destOut = decodeOutputDestination(destinationAddress);
  const changeOut = changeAddress
    ? decodeOutputDestination(changeAddress)
    : null;

  // ── Build PSET ──
  // The fee will be re-set after we compute vsize on a draft. Use a
  // conservative first pass.
  function buildPset(feeSat) {
    // BIP-125 RBF-opt-in sequence (0xfffffffd) on every input. We
    // MUST set this on the PSET input — not post-extraction — because
    // the sighash commits to ``input.sequence``. Setting it after
    // extraction would make the signed sighash diverge from what
    // chain validation recomputes, producing a NULLFAIL CHECKSIG
    // failure on broadcast.
    const RBF_SEQUENCE = 0xfffffffd;
    const inputs = [
      new CreatorInput(utxoTxid, Number(utxoVout), RBF_SEQUENCE),
    ];
    const outputs = [];
    // index 0: destination (blinded if confidential)
    outputs.push(new CreatorOutput(
      assetId, Number(destinationAmountSat),
      destOut.script,
      destOut.blindingPublicKey || undefined,
      destOut.blindingPublicKey ? 0 : undefined,
    ));
    // index 1: change (blinded)
    const changeAmount = Number(utxoValueSat) - Number(destinationAmountSat) - Number(feeSat);
    let changeIncluded = false;
    if (changeOut && changeAmount > 0) {
      outputs.push(new CreatorOutput(
        assetId, changeAmount,
        changeOut.script,
        changeOut.blindingPublicKey || undefined,
        changeOut.blindingPublicKey ? 0 : undefined,
      ));
      changeIncluded = true;
    } else if (changeAmount < 0) {
      throw new Error(
        `UTXO value ${utxoValueSat} too small for destination ${destinationAmountSat} + fee ${feeSat}`
      );
    }
    // Final output: explicit fee (unblinded, empty script).
    outputs.push(new CreatorOutput(assetId, Number(feeSat)));
    const pset = Creator.newPset({ inputs, outputs });
    return { pset, changeIncluded };
  }

  // The prevout TxOutput we attach as witness-utxo (the input's
  // blinded commitments live here).
  const prevoutTx = LiquidTransaction.fromHex(utxoPrevoutTxHex);
  const witnessUtxo = prevoutTx.outs[Number(utxoVout)];
  if (!witnessUtxo) {
    throw new Error(`UTXO vout ${utxoVout} not found in prevout tx`);
  }

  function attachInput(pset) {
    const updater = new Updater(pset);
    updater.addInWitnessUtxo(0, witnessUtxo);
    updater.addInSighashType(0, LiquidTransaction.SIGHASH_ALL);
    return updater;
  }

  // Build the owned-input descriptor so the ZKPGenerator can balance
  // the per-asset CT sum across inputs + outputs.
  const ownedInput = {
    index: 0,
    value: String(Number(utxoValueSat)),
    asset: Buffer.from(utxoAssetIdHex, 'hex').reverse(),
    valueBlindingFactor: Buffer.from(utxoValueBlindingFactorHex, 'hex'),
    assetBlindingFactor: Buffer.from(utxoAssetBlindingFactorHex, 'hex'),
  };

  async function buildSignedTx(feeSat) {
    const { pset } = buildPset(feeSat);
    attachInput(pset);

    // Blinding ceremony.
    const zkpValidator = new ZKPValidator(zkp);
    const zkpGenerator = new ZKPGenerator(
      zkp, ZKPGenerator.WithOwnedInputs([ownedInput]),
    );
    const keysGenerator = Pset.ECCKeysGenerator(zkp.ecc);
    const outputBlindingArgs = zkpGenerator.blindOutputs(pset, keysGenerator);
    const blinder = new Blinder(pset, [ownedInput], zkpValidator, zkpGenerator);
    blinder.blindLast({ outputBlindingArgs });

    // Sign input 0 with the spending privkey.
    // p2wpkh (witness v0) uses SIGHASH_ALL — SIGHASH_DEFAULT is a
    // taproot-only sighash that p2wpkh inputs cannot use.
    const sighashType = LiquidTransaction.SIGHASH_ALL;
    const preimage = pset.getInputPreimage(0, sighashType);
    const partialSig = {
      pubkey: keys.publicKey,
      signature: liquidjs.script.signature.encode(
        keys.sign(preimage), sighashType,
      ),
    };
    new Signer(pset).addSignature(
      0, { partialSig }, Pset.ECDSASigValidator(zkp.ecc),
    );
    new Finalizer(pset).finalize();
    const tx = Extractor.extract(pset);
    return tx;
  }

  // First pass: assume 250-vbyte tx for fee estimation.
  let feeSat = Math.max(1, Math.ceil(Number(feeSatPerVbyte) * 250));
  let tx = await buildSignedTx(feeSat);
  // Second pass with the actual vsize.
  const actualVsize = tx.virtualSize();
  feeSat = Math.max(1, Math.ceil(Number(feeSatPerVbyte) * actualVsize));
  tx = await buildSignedTx(feeSat);

  // Enforce nVersion=2. The BIP-125 RBF sequence is set on
  // the PSET inputs pre-signing (see ``buildPset``); the version is
  // also set by Creator.newPset to 2 already, but we re-assert for
  // defense in depth.
  tx.version = 2;

  const finalTxHex = tx.toHex();
  try {
    // The parent passes a temp-file path via ``BOLTZ_TX_OUT_FILE``;
    // we write the final hex there and the parent reads + unlinks
    // it. Avoids Node 20's fd-3+ placeholder behaviour.
    const outFile = process.env.BOLTZ_TX_OUT_FILE;
    if (!outFile) {
      throw new Error('BOLTZ_TX_OUT_FILE env var not set');
    }
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

  // Broadcast via Boltz operator's chain endpoint.
  const broadcastResponse = await httpRequest(
    `${boltzUrl}/v2/chain/L-BTC/transaction`,
    'POST',
    { hex: finalTxHex },
  );
  if (broadcastResponse.status !== 200 && broadcastResponse.status !== 201) {
    throw new Error(
      `Broadcast failed (${broadcastResponse.status}): ` +
        JSON.stringify(broadcastResponse.data),
    );
  }
  const txid =
    broadcastResponse.data.id ||
    broadcastResponse.data.txid ||
    tx.getId();

  console.log(JSON.stringify({
    event: 'liquid_lock_broadcast_complete',
    txid,
  }));
}

main().catch((err) => {
  process.stderr.write(
    JSON.stringify({ error: err.message, stack: err.stack }) + '\n'
  );
  process.exit(1);
});
