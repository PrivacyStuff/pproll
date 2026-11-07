// Move the payer's 0.01 notes into successive payroll periods.
// The older ring1 escrow note is left in the wallet.
// The period PDA uses a zero nullifier, which claim can derive again, and one viewing key
// saved at ~/.config/zolana/pproll-pda.json. That file is the spend key for the locked notes.

import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { AccountRole, address, getBase58Decoder } from "../../pescrow/sdk/node_modules/@solana/kit/dist/index.node.mjs";
import {
  LocalKeys,
  ShieldedAddress,
  ShieldedKeypair,
  SigningKey,
  Wallet,
  createSprClient,
  syncWallet,
} from "../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/index.js";
import { SignedTeePolicy } from "../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/client/index.js";
import { encodeTransactInstructionData } from "../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/interface/index.js";
import { randomBlinding } from "../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/keypair/index.js";
import {
  ProgramOwner,
  bindProgramTransaction,
  toProgramWalletUtxo,
  transactCpiAccounts,
} from "../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/program/index.js";
import {
  AddressLookupTableProgram,
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { ViewingKey } from "../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/keypair/index.js";
import init, { FundProver, fundTransaction } from "../target/zk/pproll/wasm/node.mjs";
import { CLOCK, PERIOD_LEN, connection, loadKeypair, loadStream } from "./chain.mjs";

const PROGRAM_ID = "5e6tZK4jSgHWUDW64PqRQwJBgN9VpgFEpcYiw5N9Lux6";
const STREAM_ID = "9EReUpZdvHUMx7pjh5GjQghuBFrRbZeSwgWHU4MtwFZW";
const RING1_TREE = "777pvSGe5LaBd9nCczvE2FXEauiwtfGJ5XRpjKyniGor";
const POOL_ID = "ring1GaLCuJnkUMVkX2JeZLTTX17wKsV4fZmPVzXANW";
const ESCROW_NOTE = "xUiK4RZz4JerbRzZjHVaBgaQM46A45eYhZ2uBMggNzY";
const LOCK_SEED = "payroll-lock";
const SOLANA_OWNER_TAG = 0x53;
const TREE_ID = 0;
const NOTE_LAMPORTS = 10_000_000n;
const FUNDS = 10;
const COMPUTE_UNIT_LIMIT = 1_400_000;
const PROOF_A = 32;
const PROOF_B = 64;
const PROOF_C = 32;
const VIEWING_PATH = join(homedir(), ".config/zolana/pproll-pda.json");

function scrub(value) {
  return String(value).replace(/api-key=[^&\s"]+/g, "api-key=REDACTED");
}

function heliusApiKey() {
  const text = readFileSync(join(homedir(), ".config/solana/cli/config.yml"), "utf8");
  const match = text.match(/api-key=([0-9a-f-]+)/i);
  if (match?.[1] === undefined) throw new Error("Helius key is not in the Solana CLI config");
  return match[1];
}

function devnetRpcUrl(apiKey) {
  const url = new URL("https://devnet.helius-rpc.com/");
  url.searchParams.set("api-key", apiKey);
  return url.toString();
}

function u64(bytes, offset) {
  let value = 0n;
  for (let i = 0; i < 8; i += 1) value += BigInt(bytes[offset + i] ?? 0) << BigInt(8 * i);
  return value;
}

function viewingKey() {
  try {
    const saved = JSON.parse(readFileSync(VIEWING_PATH, "utf8"));
    const secret = saved.viewing_secret_hex;
    if (typeof secret !== "string" || secret.length !== 64) throw new Error("payroll viewing key file is unreadable");
    return ViewingKey.fromBytes(Buffer.from(secret, "hex"));
  } catch (error) {
    if (error instanceof Error && error.message === "payroll viewing key file is unreadable") throw error;
    const created = ViewingKey.generate();
    writeFileSync(VIEWING_PATH, `${JSON.stringify({ viewing_secret_hex: Buffer.from(created.secretBytes()).toString("hex") })}\n`, { mode: 0o600 });
    chmodSync(VIEWING_PATH, 0o600);
    return created;
  }
}

function metaToKey(meta) {
  return {
    pubkey: new PublicKey(meta.address),
    isSigner: meta.role === AccountRole.READONLY_SIGNER || meta.role === AccountRole.WRITABLE_SIGNER,
    isWritable: meta.role === AccountRole.WRITABLE || meta.role === AccountRole.WRITABLE_SIGNER,
  };
}

const employer = loadKeypair(join(homedir(), ".config/solana/aob.json"));
let lookupAddress = null;
const listed = new Set();

async function sendSigned(tx) {
  const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash("confirmed");
  tx.recentBlockhash = blockhash;
  tx.feePayer = employer.publicKey;
  tx.sign(employer);
  const signature = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: false });
  const confirmed = await conn.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
  if (confirmed.value.err) throw new Error(`lookup ${signature} failed: ${JSON.stringify(confirmed.value.err)}`);
}

async function activateLookup(addresses) {
  const missing = addresses.filter((key) => !listed.has(key.toBase58()));
  if (lookupAddress === null) {
    // The RPC slot can be ahead of the bank that lands the transaction.
    // Walk backward until the slot is one the lookup-table program accepts.
    const tip = await conn.getSlot("confirmed");
    let created = false;
    for (let behind = 1; behind <= 64 && !created; behind += 1) {
      const [createIx, table] = AddressLookupTableProgram.createLookupTable({
        authority: employer.publicKey,
        payer: employer.publicKey,
        recentSlot: tip - behind,
      });
      const extendIx = AddressLookupTableProgram.extendLookupTable({
        payer: employer.publicKey,
        authority: employer.publicKey,
        lookupTable: table,
        addresses: missing,
      });
      try {
        await sendSigned(new Transaction().add(createIx, extendIx));
        lookupAddress = table;
        created = true;
      } catch (error) {
        const message = String(error?.message ?? error);
        if (!message.includes("not a recent slot")) throw error;
      }
    }
    if (!created) throw new Error("lookup table slot was not recent");
  } else if (missing.length > 0) {
    const extendIx = AddressLookupTableProgram.extendLookupTable({
      payer: employer.publicKey,
      authority: employer.publicKey,
      lookupTable: lookupAddress,
      addresses: missing,
    });
    const tx = new Transaction().add(extendIx);
    const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash("confirmed");
    tx.recentBlockhash = blockhash;
    tx.feePayer = employer.publicKey;
    tx.sign(employer);
    const signature = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: false });
    const confirmed = await conn.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
    if (confirmed.value.err) throw new Error(`lookup extend ${signature} failed: ${JSON.stringify(confirmed.value.err)}`);
  }
  for (const key of missing) listed.add(key.toBase58());
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const info = await conn.getAddressLookupTable(lookupAddress);
    const have = new Set((info.value?.state.addresses ?? []).map((key) => key.toBase58()));
    const slot = await conn.getSlot("confirmed");
    if (addresses.every((key) => have.has(key.toBase58())) && slot > info.value.state.lastExtendedSlot) {
      return info.value;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("address lookup table did not activate");
}
const programKey = new PublicKey(PROGRAM_ID);
const streamKey = new PublicKey(STREAM_ID);
const conn = connection();

const seedFile = JSON.parse(readFileSync(join(homedir(), ".config/zolana/party-a.json"), "utf8"));
const seed = Uint8Array.from(Buffer.from(seedFile.funding_secret_hex, "hex"));
const shielded = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed));
seed.fill(0);
const viewing = viewingKey();
const client = await createSprClient({
  solanaRpcUrl: devnetRpcUrl(heliusApiKey()),
  proverTee: SignedTeePolicy.forNetwork("devnet"),
});
const keys = LocalKeys.fromKeypair(shielded, client.proofService);
const wallet = new Wallet({ identity: shielded.shieldedAddress() });
await syncWallet({ client, wallet, keys });
const decoder = getBase58Decoder();
const notes = wallet
  .utxos()
  .filter((utxo) => utxo.outputContext.tree === RING1_TREE && !utxo.spent && utxo.utxo.amount === NOTE_LAMPORTS)
  .filter((utxo) => decoder.decode(utxo.outputContext.hash) !== ESCROW_NOTE)
  .sort((left, right) => (left.outputContext.leafIndex < right.outputContext.leafIndex ? -1 : 1))
  .slice(0, FUNDS);
if (notes.length === 0 || notes.length > FUNDS) throw new Error(`expected 1 to ${FUNDS} salary notes, found ${notes.length}`);

await init({ threads: 1 });
const provingKey = readFileSync(join(import.meta.dirname, "../target/zk/pproll/fund.pk"));
const keyHashHex = readFileSync(join(import.meta.dirname, "../target/zk/pproll/fund.pk.sha256"), "utf8").slice(0, 64);
const prover = FundProver.fromKey(provingKey, Buffer.from(keyHashHex, "hex"));
const buildFund = bindProgramTransaction(fundTransaction, { assets: wallet.registry });

try {
  for (const note of notes) {
    console.error(`proving index ${notes.indexOf(note)}`);
    const decoded = await loadStream(conn, streamKey);
    if (!decoded.employer.equals(employer.publicKey)) throw new Error("AoB is not the employer on this stream");
    if (decoded.termsFrozen !== 1) throw new Error("the stream terms are not frozen");
    const index = decoded.nextFund;
    const indexBytes = Buffer.alloc(4);
    indexBytes.writeUInt32LE(index);
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from(LOCK_SEED), streamKey.toBuffer(), indexBytes],
      programKey,
    );
    const nullifier = ProgramOwner.nullifierKey();
    const nullifierPk = Uint8Array.from(nullifier.publicKey());
    nullifier.destroy();
    const pdaAddress = ShieldedAddress.forPda({
      pda: address(pda.toBase58()),
      nullifierPublicKey: nullifierPk,
      viewingPublicKey: viewing.publicKey(),
    });
    const programNote = toProgramWalletUtxo(note, {
      nullifierPublicKey: shielded.nullifierPublicKey(),
      treeId: TREE_ID,
      assets: wallet.registry,
    });
    const built = await buildFund(
      {
        private: {
          txContext: { blindingSeed: randomBlinding(), outputTreeId: TREE_ID },
          note: [programNote],
          pda: { tag: SOLANA_OWNER_TAG, key: pda.toBuffer(), nullifierPk },
        },
        public: {
          stream0: u64(streamKey.toBuffer(), 0),
          stream1: u64(streamKey.toBuffer(), 8),
          stream2: u64(streamKey.toBuffer(), 16),
          stream3: u64(streamKey.toBuffer(), 24),
          index: BigInt(index),
          employer0: u64(employer.publicKey.toBuffer(), 0),
          employer1: u64(employer.publicKey.toBuffer(), 8),
          employer2: u64(employer.publicKey.toBuffer(), 16),
          employer3: u64(employer.publicKey.toBuffer(), 24),
        },
      },
      pdaAddress.toBytes(),
      employer.publicKey.toBase58(),
    );
    const outputHash = built.transaction.outputHashes[0];
    if (outputHash === undefined || outputHash.byteLength !== 32) throw new Error("fund produced no output hash");
    const proved = await client.proveTransact(built.transaction.encryptWithKeys(viewing), keys);
    const circuit = prover.prove(built.proofInputs).compressedProof;
    if (circuit.a.byteLength !== PROOF_A || circuit.b.byteLength !== PROOF_B || circuit.c.byteLength !== PROOF_C) {
      throw new Error("circuit proof is not 128 bytes");
    }
    const transact = encodeTransactInstructionData(proved);
    const data = Buffer.concat([
      Buffer.from([3]),
      streamKey.toBuffer(),
      indexBytes,
      Buffer.from(outputHash),
      Buffer.from(circuit.a),
      Buffer.from(circuit.b),
      Buffer.from(circuit.c),
      Buffer.from(transact),
    ]);
    const tail = await transactCpiAccounts({
      payer: employer.publicKey.toBase58(),
      inputTree: RING1_TREE,
      outputTree: RING1_TREE,
      ownerSigners: [employer.publicKey.toBase58()],
      signerPdas: [],
      data: proved,
    });
    if (tail[2]?.address !== POOL_ID) throw new Error("pool account is not at tail index 2");
    const period = Keypair.generate();
    const lamports = await conn.getMinimumBalanceForRentExemption(PERIOD_LEN);
    const tailKeys = tail.map(metaToKey);
    const lookup = await activateLookup(tailKeys.map((key) => key.pubkey));
    const instructions = [
      ComputeBudgetProgram.setComputeUnitLimit({ units: COMPUTE_UNIT_LIMIT }),
      SystemProgram.createAccount({
        fromPubkey: employer.publicKey,
        newAccountPubkey: period.publicKey,
        lamports,
        space: PERIOD_LEN,
        programId: programKey,
      }),
      new TransactionInstruction({
        programId: programKey,
        keys: [
          { pubkey: streamKey, isSigner: false, isWritable: true },
          { pubkey: period.publicKey, isSigner: false, isWritable: true },
          { pubkey: employer.publicKey, isSigner: true, isWritable: true },
          { pubkey: CLOCK, isSigner: false, isWritable: false },
          ...tailKeys,
        ],
        data,
      }),
    ];
    const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash("confirmed");
    const message = new TransactionMessage({
      payerKey: employer.publicKey,
      recentBlockhash: blockhash,
      instructions,
    }).compileToV0Message([lookup]);
    const tx = new VersionedTransaction(message);
    tx.sign([employer, period]);
    const simulation = await conn.simulateTransaction(tx, { sigVerify: false });
    if (simulation.value.err) {
      throw new Error(`simulation failed: ${JSON.stringify(simulation.value.err)}\n${(simulation.value.logs ?? []).join("\n")}`);
    }
    const signature = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: false });
    const confirmed = await conn.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
    if (confirmed.value.err) throw new Error(`fund ${signature} failed: ${JSON.stringify(confirmed.value.err)}`);
    const after = await loadStream(conn, streamKey);
    if (after.nextFund !== index + 1) throw new Error(`fund ${signature} did not advance next_fund`);
    console.log(`funded index=${index} period=${period.publicKey.toBase58()} pda=${pda.toBase58()} signature=${signature} commitment=${decoder.decode(outputHash)}`);
  }
} catch (error) {
  console.error(scrub(error?.message ?? error));
  console.error(scrub(error?.cause?.message ?? error?.cause ?? ""));
  process.exit(1);
} finally {
  keys.destroy();
  viewing.destroy();
}
process.exit(0);
