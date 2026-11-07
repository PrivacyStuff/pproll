// One pool per user. Each command is its own script. Viewing secrets are written
// mode 600 and are not printed. The ten period notes keep pproll-pda.json.

import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { inspect } from "node:util";
import { homedir } from "node:os";
import { join as pathJoin } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import type { Address } from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/interface/types.js";
import type { Bytes32 } from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/keypair/bytes.js";
import {
  LocalKeys,
  ShieldedAddress,
  ShieldedKeypair,
  SigningKey,
  Wallet,
  createSprClient,
  syncWallet,
} from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/index.js";
import { SignedTeePolicy } from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/client/index.js";
import { encodeTransactInstructionData } from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/interface/index.js";
import { initializePoseidon, poseidon } from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/hasher/index.js";
import { randomBlinding } from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/keypair/index.js";
import {
  ProgramOwner,
  bindProgramTransaction,
  toProgramWalletUtxo,
  transactCpiAccounts,
} from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/program/index.js";
import { ShieldedPda } from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/program/shielded-pda.js";
import { ViewingKey } from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/keypair/index.js";
import type { ProgramTransaction, ProgramTransactionKeys } from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/program/program-transaction.js";
import type { WalletUtxo } from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/transaction/wallet/state.js";
import type { TransactInstructionData } from "../../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/interface/types.js";
import {
  AddressLookupTableProgram,
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
  type AccountMeta,
  type AddressLookupTableAccount,
} from "@solana/web3.js";
import init, {
  DepositProver,
  InitiateProver,
  JoinProver,
  PayProver,
  ReclaimProver,
  WithdrawProver,
  depositTransaction,
  initiateTransaction,
  joinTransaction,
  payTransaction,
  reclaimTransaction,
  withdrawTransaction,
  type Proof,
} from "../../target/zk/pproll/wasm/node.mjs";
import { be32, limbs } from "./commitment.ts";

const PROGRAM_ID = "5e6tZK4jSgHWUDW64PqRQwJBgN9VpgFEpcYiw5N9Lux6";
const RING1_TREE = "777pvSGe5LaBd9nCczvE2FXEauiwtfGJ5XRpjKyniGor";
const POOL_ID = "ring1GaLCuJnkUMVkX2JeZLTTX17wKsV4fZmPVzXANW";
const ESCROW_NOTE = "xUiK4RZz4JerbRzZjHVaBgaQM46A45eYhZ2uBMggNzY";
const POOL_SEED = "user-pool";
const NOTE_SEED = "payroll";
const SOLANA_OWNER_TAG = 0x53;
const TREE_ID = 0;
const VAULT_LEN = 112;
const PAYROLL_LEN = 264;
const VIEWING_LEN = 33;
const OWNER_HASH_LEN = 32;
const COMMITMENT_LEN = 32;
const CLOCK_UNIX_OFFSET = 32;
const PAY_OFF_START = 8;
const PAY_OFF_PERIOD = 24;
const PAY_OFF_NEXT = 260;
const VAULT_OFF_LIVE = 1;
const LIVE_NOTE = 1;
const COMPUTE_UNIT_LIMIT = 1_400_000;
const PROOF_A = 32;
const PROOF_B = 64;
const PROOF_C = 32;
const FIELD_BYTES = 32;
const CLOCK = new PublicKey("SysvarC1ock11111111111111111111111111111111");
const ROLE_WRITABLE = 1;
const ROLE_READONLY_SIGNER = 2;
const ROLE_WRITABLE_SIGNER = 3;
const ESCROW_NOTE_BYTES = new PublicKey(ESCROW_NOTE).toBytes();
const HERE = fileURLToPath(new URL(".", import.meta.url));
const IX_DEPOSIT = 7;
const IX_JOIN = 8;
const IX_WITHDRAW = 9;
const IX_OPEN_VAULT = 10;
const IX_OPEN_PAYROLL = 11;
const IX_APPROVE = 12;
const IX_INITIATE = 13;
const IX_PAY = 14;
const IX_STOP = 15;
const IX_RECLAIM = 16;
const KEEPS_NOTE = 1;
const RING_PERMISSIONLESS = 1;
const WALLETS_PUBLIC = 1;
const DEFAULT_INSTALLMENT = 10_000_000n;
const DEFAULT_BUDGET = 100_000_000n;
const DEFAULT_PERIOD_SECS = 3_600n;
const DEFAULT_START_IN_SECS = 600n;
const LOOKUP_SLOT_WALK = 64;
const LOOKUP_WAIT_ATTEMPTS = 40;
const LOOKUP_WAIT_MS = 500;
function envPath(name: string, fallback: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) return fallback;
  return value;
}

const EMPLOYER_PATH = envPath("PPROLL_EMPLOYER_KEY", pathJoin(homedir(), ".config/solana/aob.json"));
const PAYEE_PATH = envPath("PPROLL_PAYEE_KEY", pathJoin(homedir(), ".config/solana/yrs.json"));
const EMPLOYER_SEED = envPath("PPROLL_EMPLOYER_SEED", pathJoin(homedir(), ".config/zolana/party-a.json"));
const PAYEE_SEED = envPath("PPROLL_PAYEE_SEED", pathJoin(homedir(), ".config/zolana/party-b.json"));
const OPEN_VAULT_LEN = 1 + OWNER_HASH_LEN + VIEWING_LEN;

const programKey = new PublicKey(PROGRAM_ID);
function bytes32(value: Uint8Array): Bytes32 {
  if (value.byteLength !== FIELD_BYTES) throw new Error("expected 32 bytes");
  // The length check is the runtime boundary. Bytes32 only adds a nominal brand.
  return value as Bytes32;
}

function asAddress(value: string): Address {
  // PublicKey rejects a bad base58 string. Address only adds a nominal brand.
  return new PublicKey(value).toBase58() as Address;
}

type Client = Awaited<ReturnType<typeof createSprClient>>;
type CircuitName = "deposit" | "join" | "withdraw" | "initiate" | "pay" | "reclaim";
type Party = "employer" | "payee";

interface CircuitProver {
  prove(proofInputs: Uint8Array): Proof;
}

interface ProverCtor {
  fromKey(provingKey: Uint8Array, expectedSha256: Uint8Array): CircuitProver;
}

interface VaultFile {
  viewing_secret_hex: string;
  vault: string;
  owner_hash_hex?: string;
}

interface PayrollFile {
  viewing_secret_hex: string;
  payroll: string;
  installment: string;
  installment_blinding_hex: string;
  budget: string;
  budget_blinding_hex: string;
}

interface ProvedMove {
  proved: TransactInstructionData;
  data: Buffer;
}

const PROVERS: Record<CircuitName, ProverCtor> = {
  deposit: DepositProver,
  join: JoinProver,
  withdraw: WithdrawProver,
  initiate: InitiateProver,
  pay: PayProver,
  reclaim: ReclaimProver,
};

function rpcUrl(): string {
  const config = readFileSync(pathJoin(homedir(), ".config/solana/cli/config.yml"), "utf8");
  const line = config.split("\n").find((entry) => entry.startsWith("json_rpc_url:"));
  if (line === undefined) throw new Error("json_rpc_url missing from solana config");
  return line.slice("json_rpc_url:".length).trim();
}

const conn = new Connection(rpcUrl(), "confirmed");

export function scrub(value: unknown): string {
  return String(value).replace(/api-key=[^&\s"]+/g, "api-key=REDACTED");
}

export async function main(action: () => Promise<unknown>): Promise<void> {
  try {
    await action();
  } catch (error: unknown) {
    const detail = inspect(error, { depth: 4, colors: false, maxStringLength: 400 });
    console.error(scrub(detail));
    process.exit(1);
  }
}

function flag(name: string, fallback: string): string {
  const index = process.argv.indexOf(name);
  if (index === -1) return fallback;
  const value = process.argv[index + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${name} needs a value`);
  return value;
}

function heliusApiKey(): string {
  const text = readFileSync(pathJoin(homedir(), ".config/solana/cli/config.yml"), "utf8");
  const match = text.match(/api-key=([0-9a-f-]+)/i);
  const key = match?.[1];
  if (key === undefined) throw new Error("Helius key is not in the Solana CLI config");
  return key;
}

function devnetRpcUrl(apiKey: string): string {
  const url = new URL("https://devnet.helius-rpc.com/");
  url.searchParams.set("api-key", apiKey);
  return url.toString();
}

function freshBlinding(): Buffer {
  const bytes = randomBytes(FIELD_BYTES);
  bytes[0] = 0;
  return bytes;
}

async function commitment(amount: bigint, blinding: Uint8Array): Promise<Buffer> {
  await initializePoseidon();
  return Buffer.from(poseidon([be32(amount), blinding]));
}

function writeSecret(path: string, body: VaultFile | PayrollFile): void {
  writeFileSync(path, `${JSON.stringify(body)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function secretHex(value: unknown): string {
  if (typeof value !== "string" || value.length !== FIELD_BYTES * 2) throw new Error("viewing key file is unreadable");
  return value;
}

function readVault(path: string): VaultFile {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(parsed) || typeof parsed.vault !== "string") throw new Error("vault file is unreadable");
  const ownerHash = parsed.owner_hash_hex;
  if (ownerHash !== undefined && typeof ownerHash !== "string") throw new Error("vault file is unreadable");
  return { viewing_secret_hex: secretHex(parsed.viewing_secret_hex), vault: parsed.vault, owner_hash_hex: ownerHash };
}

function readPayroll(path: string): PayrollFile {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(parsed)) throw new Error("payroll file is unreadable");
  const { payroll, installment, installment_blinding_hex, budget, budget_blinding_hex } = parsed;
  if (
    typeof payroll !== "string" ||
    typeof installment !== "string" ||
    typeof installment_blinding_hex !== "string" ||
    typeof budget !== "string" ||
    typeof budget_blinding_hex !== "string"
  ) {
    throw new Error("payroll file is unreadable");
  }
  return {
    viewing_secret_hex: secretHex(parsed.viewing_secret_hex),
    payroll,
    installment,
    installment_blinding_hex,
    budget,
    budget_blinding_hex,
  };
}

function vaultPath(owner: PublicKey): string {
  return pathJoin(homedir(), ".config/zolana", `user-pool-${owner.toBase58()}.json`);
}

function payrollPath(payroll: PublicKey): string {
  return pathJoin(homedir(), ".config/zolana", `payroll-note-${payroll.toBase58()}.json`);
}

function viewingFrom(saved: { viewing_secret_hex: string }): ViewingKey {
  return ViewingKey.fromBytes(bytes32(Buffer.from(saved.viewing_secret_hex, "hex")));
}

function loadShielded(path: string): ShieldedKeypair {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(parsed) || typeof parsed.funding_secret_hex !== "string") throw new Error("shielded seed file is unreadable");
  const seed = Uint8Array.from(Buffer.from(parsed.funding_secret_hex, "hex"));
  const shielded = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(bytes32(seed)));
  seed.fill(0);
  return shielded;
}

function loadKeypair(path: string): Keypair {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === "number")) {
    throw new Error("keypair file is unreadable");
  }
  return Keypair.fromSecretKey(Uint8Array.from(parsed));
}

function nullifierPublic(): Bytes32 {
  const key = ProgramOwner.nullifierKey();
  const publicKey = bytes32(key.publicKey());
  key.destroy();
  return publicKey;
}

function poolPda(owner: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from(POOL_SEED), owner.toBuffer()], programKey)[0];
}

function notePda(payroll: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from(NOTE_SEED), payroll.toBuffer()], programKey)[0];
}

function pdaAddress(pda: PublicKey, viewing: ViewingKey): ShieldedAddress {
  return ShieldedAddress.forPda({
    pda: bytes32(pda.toBytes()),
    nullifierPublicKey: nullifierPublic(),
    viewingPublicKey: viewing.publicKey(),
  });
}

function userOwner(shielded: ShieldedKeypair, solanaKey: PublicKey): { tag: number; key: Uint8Array; nullifierPk: Bytes32 } {
  return { tag: SOLANA_OWNER_TAG, key: solanaKey.toBuffer(), nullifierPk: shielded.nullifierPublicKey() };
}

function pdaOwner(pda: PublicKey): { tag: number; key: Uint8Array; nullifierPk: Bytes32 } {
  return { tag: SOLANA_OWNER_TAG, key: pda.toBuffer(), nullifierPk: nullifierPublic() };
}

function metaToKey(meta: { address: string; role: number }): AccountMeta {
  return {
    pubkey: new PublicKey(meta.address),
    isSigner: meta.role === ROLE_READONLY_SIGNER || meta.role === ROLE_WRITABLE_SIGNER,
    isWritable: meta.role === ROLE_WRITABLE || meta.role === ROLE_WRITABLE_SIGNER,
  };
}

let lookupAddress: PublicKey | null = null;
let lookupAuthority: string | null = null;
const listed = new Set<string>();

async function sendLegacy(signers: Keypair[], tx: Transaction): Promise<string> {
  const payer = signers[0];
  if (payer === undefined) throw new Error("a transaction needs a fee payer");
  const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash("confirmed");
  tx.recentBlockhash = blockhash;
  tx.feePayer = payer.publicKey;
  tx.sign(...signers);
  const signature = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: false });
  const confirmed = await conn.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
  if (confirmed.value.err) throw new Error(`transaction ${signature} failed: ${JSON.stringify(confirmed.value.err)}`);
  return signature;
}

async function activateLookup(authority: Keypair, addresses: PublicKey[]): Promise<AddressLookupTableAccount> {
  if (lookupAuthority !== authority.publicKey.toBase58()) {
    lookupAddress = null;
    lookupAuthority = authority.publicKey.toBase58();
    listed.clear();
  }
  const missing = addresses.filter((key) => !listed.has(key.toBase58()));
  if (lookupAddress === null) {
    const tip = await conn.getSlot("confirmed");
    let created = false;
    for (let behind = 1; behind <= LOOKUP_SLOT_WALK && !created; behind += 1) {
      const [createIx, table] = AddressLookupTableProgram.createLookupTable({
        authority: authority.publicKey,
        payer: authority.publicKey,
        recentSlot: tip - behind,
      });
      const extendIx = AddressLookupTableProgram.extendLookupTable({
        payer: authority.publicKey,
        authority: authority.publicKey,
        lookupTable: table,
        addresses: missing,
      });
      try {
        await sendLegacy([authority], new Transaction().add(createIx, extendIx));
        lookupAddress = table;
        created = true;
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        if (!message.includes("not a recent slot")) throw error;
      }
    }
    if (!created || lookupAddress === null) throw new Error("lookup table slot was not recent");
  } else if (missing.length > 0) {
    const extendIx = AddressLookupTableProgram.extendLookupTable({
      payer: authority.publicKey,
      authority: authority.publicKey,
      lookupTable: lookupAddress,
      addresses: missing,
    });
    await sendLegacy([authority], new Transaction().add(extendIx));
  }
  for (const key of missing) listed.add(key.toBase58());
  for (let attempt = 0; attempt < LOOKUP_WAIT_ATTEMPTS; attempt += 1) {
    const info = await conn.getAddressLookupTable(lookupAddress);
    const table = info.value;
    if (table === null) {
      await new Promise((resolve) => setTimeout(resolve, LOOKUP_WAIT_MS));
      continue;
    }
    const have = new Set(table.state.addresses.map((key) => key.toBase58()));
    const slot = await conn.getSlot("confirmed");
    if (addresses.every((key) => have.has(key.toBase58())) && slot > table.state.lastExtendedSlot) return table;
    await new Promise((resolve) => setTimeout(resolve, LOOKUP_WAIT_MS));
  }
  throw new Error("address lookup table did not activate");
}

async function sendV0(
  authority: Keypair,
  signers: Keypair[],
  instructions: TransactionInstruction[],
  lookupKeys: PublicKey[],
): Promise<string> {
  const lookup = await activateLookup(authority, lookupKeys);
  const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash("confirmed");
  const message = new TransactionMessage({
    payerKey: authority.publicKey,
    recentBlockhash: blockhash,
    instructions,
  }).compileToV0Message([lookup]);
  const tx = new VersionedTransaction(message);
  tx.sign(signers);
  const simulation = await conn.simulateTransaction(tx, { sigVerify: false });
  if (simulation.value.err) {
    throw new Error(`simulation failed: ${JSON.stringify(simulation.value.err)}\n${(simulation.value.logs ?? []).join("\n")}`);
  }
  const signature = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: false });
  const confirmed = await conn.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
  if (confirmed.value.err) throw new Error(`transaction ${signature} failed: ${JSON.stringify(confirmed.value.err)}`);
  return signature;
}

function proverFor(name: CircuitName): CircuitProver {
  const zkDir = pathJoin(HERE, "../../target/zk/pproll");
  const provingKey = readFileSync(pathJoin(zkDir, `${name}.pk`));
  const keyHashHex = readFileSync(pathJoin(zkDir, `${name}.pk.sha256`), "utf8").slice(0, FIELD_BYTES * 2);
  return PROVERS[name].fromKey(provingKey, Buffer.from(keyHashHex, "hex"));
}

async function spr(): Promise<Client> {
  return createSprClient({
    solanaRpcUrl: devnetRpcUrl(heliusApiKey()),
    proverTee: SignedTeePolicy.forNetwork("devnet"),
  });
}

async function personWallet(client: Client, seedPath: string): Promise<{ shielded: ShieldedKeypair; keys: LocalKeys; wallet: Wallet }> {
  const shielded = loadShielded(seedPath);
  const keys = LocalKeys.fromKeypair(shielded, client.proofService);
  const wallet = new Wallet({ identity: shielded.shieldedAddress() });
  await syncWallet({ client, wallet, keys });
  return { shielded, keys, wallet };
}

async function pdaWallet(
  client: Client,
  pda: PublicKey,
  viewing: ViewingKey,
): Promise<{ identity: ShieldedPda; keys: LocalKeys; wallet: Wallet }> {
  const identity = ShieldedPda.withViewingKey(bytes32(pda.toBytes()), ProgramOwner.nullifierKey(), viewing.clone());
  const keys = LocalKeys.fromKeys(
    {
      address: identity.shieldedAddress(),
      viewingKeys: [identity.viewingKey()],
      nullifierKey: ProgramOwner.nullifierKey(),
    },
    client.proofService,
  );
  const wallet = new Wallet({ identity: identity.shieldedAddress() });
  await syncWallet({ client, wallet, keys });
  return { identity, keys, wallet };
}

function liveNotes(wallet: Wallet): WalletUtxo[] {
  return wallet
    .utxos()
    .filter((utxo) => utxo.outputContext.tree === asAddress(RING1_TREE) && !utxo.spent)
    .filter((utxo) => !Buffer.from(utxo.outputContext.hash).equals(Buffer.from(ESCROW_NOTE_BYTES)));
}

function pickNote(notes: readonly WalletUtxo[], minimum: bigint): WalletUtxo {
  const fits = notes
    .filter((note) => note.utxo.amount > minimum)
    .sort((left, right) => (left.utxo.amount < right.utxo.amount ? -1 : 1));
  const note = fits[0];
  if (note === undefined) throw new Error(`no ring1 note above ${minimum.toString()} lamports`);
  return note;
}

function asProgram(note: WalletUtxo, nullifierPk: Bytes32, registry: Wallet["registry"]): ReturnType<typeof toProgramWalletUtxo> {
  return toProgramWalletUtxo(note, { nullifierPublicKey: nullifierPk, treeId: TREE_ID, assets: registry });
}

async function proveMove(
  client: Client,
  keys: LocalKeys,
  viewing: ProgramTransactionKeys,
  built: ProgramTransaction,
  prover: CircuitProver,
): Promise<ProvedMove> {
  const proved = await client.proveTransact(built.transaction.encryptWithKeys(viewing), keys);
  const circuit = prover.prove(built.proofInputs).compressedProof;
  if (circuit.a.byteLength !== PROOF_A || circuit.b.byteLength !== PROOF_B || circuit.c.byteLength !== PROOF_C) {
    throw new Error("circuit proof is not 128 bytes");
  }
  return {
    proved,
    data: Buffer.concat([Buffer.from(circuit.a), Buffer.from(circuit.b), Buffer.from(circuit.c), Buffer.from(encodeTransactInstructionData(proved))]),
  };
}

async function tailAccounts(payer: PublicKey, ownerSigners: PublicKey[], signerPdas: PublicKey[], proved: TransactInstructionData): Promise<AccountMeta[]> {
  const tail = await transactCpiAccounts({
    payer: asAddress(payer.toBase58()),
    inputTree: asAddress(RING1_TREE),
    outputTree: asAddress(RING1_TREE),
    ownerSigners: ownerSigners.map((key) => asAddress(key.toBase58())),
    signerPdas: signerPdas.map((key) => asAddress(key.toBase58())),
    data: proved,
  });
  const pool = tail[2];
  if (pool?.address !== POOL_ID) throw new Error("pool account is not at tail index 2");
  return tail.map(metaToKey);
}

async function clockNow(): Promise<bigint> {
  const info = await conn.getAccountInfo(CLOCK);
  if (info === null) throw new Error("clock sysvar is missing");
  return info.data.readBigInt64LE(CLOCK_UNIX_OFFSET);
}

function requirePayroll(): PublicKey {
  const value = flag("--payroll", "");
  if (value.length === 0) throw new Error("pass --payroll");
  return new PublicKey(value);
}

function requireVault(owner: PublicKey): { vault: PublicKey; viewing: ViewingKey } {
  const path = vaultPath(owner);
  if (!existsSync(path)) throw new Error("open the vault first");
  const saved = readVault(path);
  return { vault: new PublicKey(saved.vault), viewing: viewingFrom(saved) };
}

function vaultAccounts(vault: PublicKey, owner: PublicKey, tail: AccountMeta[]): AccountMeta[] {
  return [
    { pubkey: vault, isSigner: false, isWritable: true },
    { pubkey: owner, isSigner: true, isWritable: true },
    ...tail,
  ];
}

export async function openVault(): Promise<void> {
  await initializePoseidon();
  const employer = loadKeypair(EMPLOYER_PATH);
  const path = vaultPath(employer.publicKey);
  if (existsSync(path)) {
    const saved = readVault(path);
    console.log(`vault=${saved.vault} pool=${poolPda(employer.publicKey).toBase58()} already recorded`);
    return;
  }
  const viewing = ViewingKey.generate();
  const vault = Keypair.generate();
  try {
    const owner = pdaAddress(poolPda(employer.publicKey), viewing);
    const saved: VaultFile = {
      viewing_secret_hex: Buffer.from(viewing.secretBytes()).toString("hex"),
      vault: vault.publicKey.toBase58(),
      owner_hash_hex: Buffer.from(owner.ownerHash()).toString("hex"),
    };
    writeSecret(path, saved);
    const data = Buffer.concat([Buffer.from([IX_OPEN_VAULT]), Buffer.from(owner.ownerHash()), Buffer.from(viewing.publicKey().toBytes())]);
    if (data.length !== OPEN_VAULT_LEN) throw new Error("open vault instruction has the wrong length");
    const lamports = await conn.getMinimumBalanceForRentExemption(VAULT_LEN);
    const signature = await sendLegacy(
      [employer, vault],
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: employer.publicKey,
          newAccountPubkey: vault.publicKey,
          lamports,
          space: VAULT_LEN,
          programId: programKey,
        }),
        new TransactionInstruction({
          programId: programKey,
          keys: [
            { pubkey: vault.publicKey, isSigner: true, isWritable: true },
            { pubkey: employer.publicKey, isSigner: true, isWritable: true },
          ],
          data,
        }),
      ),
    );
    console.log(`vault=${vault.publicKey.toBase58()} pool=${poolPda(employer.publicKey).toBase58()} signature=${signature}`);
  } finally {
    viewing.destroy();
  }
}

async function movePool(command: "deposit" | "join" | "withdraw"): Promise<void> {
  await initializePoseidon();
  const employer = loadKeypair(EMPLOYER_PATH);
  const { vault, viewing } = requireVault(employer.publicKey);
  const client = await spr();
  await init({ threads: 1 });
  const person = await personWallet(client, EMPLOYER_SEED);
  const pool = poolPda(employer.publicKey);
  const destination = pdaAddress(pool, viewing);
  const recorded = readVault(vaultPath(employer.publicKey)).owner_hash_hex;
  if (recorded !== undefined && recorded !== Buffer.from(destination.ownerHash()).toString("hex")) {
    throw new Error("vault file owner hash does not match this viewing key");
  }
  try {
    if (command === "deposit") {
      const note = pickNote(liveNotes(person.wallet), BigInt(flag("--min", "1")));
      const build = bindProgramTransaction(depositTransaction, { assets: person.wallet.registry });
      const built = await build(
        {
          private: {
            txContext: { blindingSeed: randomBlinding(), outputTreeId: TREE_ID },
            note: [asProgram(note, person.shielded.nullifierPublicKey(), person.wallet.registry)],
            pool: pdaOwner(pool),
          },
          public: { hash: destination.ownerHash() },
        },
        destination.toBytes(),
        employer.publicKey.toBase58(),
      );
      const proved = await proveMove(client, person.keys, viewing, built, proverFor("deposit"));
      const tail = await tailAccounts(employer.publicKey, [employer.publicKey], [], proved.proved);
      const signature = await sendV0(
        employer,
        [employer],
        [
          ComputeBudgetProgram.setComputeUnitLimit({ units: COMPUTE_UNIT_LIMIT }),
          new TransactionInstruction({
            programId: programKey,
            keys: vaultAccounts(vault, employer.publicKey, tail),
            data: Buffer.concat([Buffer.from([IX_DEPOSIT]), proved.data]),
          }),
        ],
        tail.map((key) => key.pubkey),
      );
      console.log(`deposited lamports=${note.utxo.amount.toString()} signature=${signature}`);
      return;
    }
    const pda = await pdaWallet(client, pool, viewing);
    try {
      const poolNote = pickNote(liveNotes(pda.wallet), 0n);
      if (command === "withdraw") {
        const build = bindProgramTransaction(withdrawTransaction, { assets: pda.wallet.registry });
        const built = await build(
          {
            private: {
              txContext: { blindingSeed: randomBlinding(), outputTreeId: TREE_ID },
              note: [asProgram(poolNote, ProgramOwner.nullifierPublicKey(), pda.wallet.registry)],
              owner: userOwner(person.shielded, employer.publicKey),
            },
            public: { hash: destination.ownerHash() },
          },
          person.shielded.shieldedAddress().toBytes(),
          employer.publicKey.toBase58(),
        );
        const proved = await proveMove(client, pda.keys, person.shielded, built, proverFor("withdraw"));
        const tail = await tailAccounts(employer.publicKey, [], [pool], proved.proved);
        const signature = await sendV0(
          employer,
          [employer],
          [
            ComputeBudgetProgram.setComputeUnitLimit({ units: COMPUTE_UNIT_LIMIT }),
            new TransactionInstruction({
              programId: programKey,
              keys: vaultAccounts(vault, employer.publicKey, tail),
              data: Buffer.concat([Buffer.from([IX_WITHDRAW]), proved.data]),
            }),
          ],
          tail.map((key) => key.pubkey),
        );
        console.log(`withdrew signature=${signature}`);
        return;
      }
      const incoming = pickNote(liveNotes(person.wallet), 0n);
      const build = bindProgramTransaction(joinTransaction, { assets: person.wallet.registry });
      const built = await build(
        {
          private: {
            txContext: { blindingSeed: randomBlinding(), outputTreeId: TREE_ID },
            incoming: [asProgram(incoming, person.shielded.nullifierPublicKey(), person.wallet.registry)],
            poolNote: [asProgram(poolNote, ProgramOwner.nullifierPublicKey(), pda.wallet.registry)],
            pool: pdaOwner(pool),
          },
          public: { hash: destination.ownerHash() },
        },
        destination.toBytes(),
        employer.publicKey.toBase58(),
      );
      const proved = await proveMove(client, person.keys, viewing, built, proverFor("join"));
      const tail = await tailAccounts(employer.publicKey, [employer.publicKey], [pool], proved.proved);
      const signature = await sendV0(
        employer,
        [employer],
        [
          ComputeBudgetProgram.setComputeUnitLimit({ units: COMPUTE_UNIT_LIMIT }),
          new TransactionInstruction({
            programId: programKey,
            keys: vaultAccounts(vault, employer.publicKey, tail),
            data: Buffer.concat([Buffer.from([IX_JOIN]), proved.data]),
          }),
        ],
        tail.map((key) => key.pubkey),
      );
      console.log(`joined lamports=${incoming.utxo.amount.toString()} signature=${signature}`);
    } finally {
      pda.keys.destroy();
      pda.identity.destroy();
    }
  } finally {
    person.keys.destroy();
    person.shielded.destroy();
    viewing.destroy();
  }
}

export function deposit(): Promise<void> {
  return movePool("deposit");
}

export function join(): Promise<void> {
  return movePool("join");
}

export function withdraw(): Promise<void> {
  return movePool("withdraw");
}

export async function openPayroll(): Promise<string> {
  await initializePoseidon();
  const employer = loadKeypair(EMPLOYER_PATH);
  const payeeArg = flag("--payee", "");
  if (payeeArg.length === 0) throw new Error("pass --payee");
  const payee = new PublicKey(payeeArg);
  const payeeKey = loadKeypair(PAYEE_PATH);
  if (!payee.equals(payeeKey.publicKey)) throw new Error("the payee keypair is not the wallet passed to --payee");
  const installment = BigInt(flag("--installment", DEFAULT_INSTALLMENT.toString()));
  const budget = BigInt(flag("--budget", DEFAULT_BUDGET.toString()));
  if (installment <= 0n || budget <= installment) throw new Error("the budget must be larger than one installment");
  const period = BigInt(flag("--period", DEFAULT_PERIOD_SECS.toString()));
  const startIn = BigInt(flag("--start-in", DEFAULT_START_IN_SECS.toString()));
  const now = await clockNow();
  const startAt = now + startIn;
  const payroll = Keypair.generate();
  const viewing = ViewingKey.generate();
  const payeeShielded = loadShielded(PAYEE_SEED);
  try {
    const note = notePda(payroll.publicKey);
    const noteAddress = pdaAddress(note, viewing);
    const installmentBlind = freshBlinding();
    const budgetBlind = freshBlinding();
    const body = Buffer.alloc(OWNER_HASH_LEN * 3 + 8 * 3 + COMMITMENT_LEN * 2 + VIEWING_LEN + 2);
    let offset = 0;
    payee.toBuffer().copy(body, offset);
    offset += OWNER_HASH_LEN;
    Buffer.from(payeeShielded.ownerHash()).copy(body, offset);
    offset += OWNER_HASH_LEN;
    Buffer.from(noteAddress.ownerHash()).copy(body, offset);
    offset += OWNER_HASH_LEN;
    body.writeBigInt64LE(startAt, offset);
    offset += 8;
    body.writeBigInt64LE(startAt, offset);
    offset += 8;
    body.writeBigInt64LE(period, offset);
    offset += 8;
    (await commitment(installment, installmentBlind)).copy(body, offset);
    offset += COMMITMENT_LEN;
    (await commitment(budget, budgetBlind)).copy(body, offset);
    offset += COMMITMENT_LEN;
    Buffer.from(viewing.publicKey().toBytes()).copy(body, offset);
    offset += VIEWING_LEN;
    body[offset] = RING_PERMISSIONLESS;
    body[offset + 1] = WALLETS_PUBLIC;
    writeSecret(payrollPath(payroll.publicKey), {
      viewing_secret_hex: Buffer.from(viewing.secretBytes()).toString("hex"),
      payroll: payroll.publicKey.toBase58(),
      installment: installment.toString(),
      installment_blinding_hex: installmentBlind.toString("hex"),
      budget: budget.toString(),
      budget_blinding_hex: budgetBlind.toString("hex"),
    });
    const lamports = await conn.getMinimumBalanceForRentExemption(PAYROLL_LEN);
    const signature = await sendLegacy(
      [employer, payroll],
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: employer.publicKey,
          newAccountPubkey: payroll.publicKey,
          lamports,
          space: PAYROLL_LEN,
          programId: programKey,
        }),
        new TransactionInstruction({
          programId: programKey,
          keys: [
            { pubkey: payroll.publicKey, isSigner: true, isWritable: true },
            { pubkey: employer.publicKey, isSigner: true, isWritable: true },
          ],
          data: Buffer.concat([Buffer.from([IX_OPEN_PAYROLL]), body]),
        }),
      ),
    );
    console.log(`payroll=${payroll.publicKey.toBase58()} note=${note.toBase58()} start=${startAt.toString()} signature=${signature}`);
    return payroll.publicKey.toBase58();
  } finally {
    viewing.destroy();
    payeeShielded.destroy();
  }
}

export async function approvePayroll(): Promise<void> {
  const payroll = requirePayroll();
  const who = flag("--as", "employer");
  if (who !== "employer" && who !== "payee") throw new Error("--as is employer or payee");
  const party: Party = who;
  const signer = loadKeypair(party === "payee" ? PAYEE_PATH : EMPLOYER_PATH);
  const signature = await sendLegacy(
    [signer],
    new Transaction().add(
      new TransactionInstruction({
        programId: programKey,
        keys: [
          { pubkey: payroll, isSigner: false, isWritable: true },
          { pubkey: signer.publicKey, isSigner: true, isWritable: false },
          { pubkey: CLOCK, isSigner: false, isWritable: false },
        ],
        data: Buffer.from([IX_APPROVE]),
      }),
    ),
  );
  console.log(`approved as=${party} payroll=${payroll.toBase58()} signature=${signature}`);
}

export async function initiatePayroll(): Promise<void> {
  await initializePoseidon();
  const employer = loadKeypair(EMPLOYER_PATH);
  const payroll = requirePayroll();
  const terms = readPayroll(payrollPath(payroll));
  const { vault, viewing } = requireVault(employer.publicKey);
  const client = await spr();
  await init({ threads: 1 });
  const pool = poolPda(employer.publicKey);
  const pda = await pdaWallet(client, pool, viewing);
  const payrollViewing = viewingFrom(terms);
  try {
    const budget = BigInt(terms.budget);
    const note = pickNote(liveNotes(pda.wallet), budget);
    const payrollNote = notePda(payroll);
    const destination = pdaAddress(payrollNote, payrollViewing);
    const destinationPool = pdaAddress(pool, viewing);
    const blind = Buffer.from(terms.budget_blinding_hex, "hex");
    const [blind0, blind1, blind2, blind3] = limbs(blind);
    const inputs = {
      private: {
        txContext: { blindingSeed: randomBlinding(), outputTreeId: TREE_ID },
        note: [asProgram(note, ProgramOwner.nullifierPublicKey(), pda.wallet.registry)],
        amount: budget,
        blind0,
        blind1,
        blind2,
        blind3,
        payroll: pdaOwner(payrollNote),
        poolAddress: destinationPool.toBytes(),
      },
      public: { budget: await commitment(budget, blind), note: destination.ownerHash(), keepsNote: BigInt(KEEPS_NOTE) },
    };
    const build = bindProgramTransaction(initiateTransaction, { assets: pda.wallet.registry });
    // The wasm circuit wants a one-note tuple. The helper returns that note.
    const built = await build(
      inputs as unknown as Parameters<typeof initiateTransaction>[0],
      destination.toBytes(),
      employer.publicKey.toBase58(),
    );
    const proved = await proveMove(client, pda.keys, payrollViewing, built, proverFor("initiate"));
    const tail = await tailAccounts(employer.publicKey, [], [pool], proved.proved);
    const signature = await sendV0(
      employer,
      [employer],
      [
        ComputeBudgetProgram.setComputeUnitLimit({ units: COMPUTE_UNIT_LIMIT }),
        new TransactionInstruction({
          programId: programKey,
          keys: [
            { pubkey: payroll, isSigner: false, isWritable: true },
            { pubkey: vault, isSigner: false, isWritable: true },
            { pubkey: employer.publicKey, isSigner: true, isWritable: true },
            ...tail,
          ],
          data: Buffer.concat([Buffer.from([IX_INITIATE, KEEPS_NOTE]), proved.data]),
        }),
      ],
      tail.map((key) => key.pubkey),
    );
    console.log(`initiated payroll=${payroll.toBase58()} signature=${signature}`);
  } finally {
    pda.keys.destroy();
    pda.identity.destroy();
    viewing.destroy();
    payrollViewing.destroy();
  }
}

const DUE_POLL_MS = 5_000;

export async function waitUntilDue(payrollBase58: string): Promise<void> {
  const payroll = new PublicKey(payrollBase58);
  for (;;) {
    const info = await conn.getAccountInfo(payroll);
    if (info === null) throw new Error("payroll account is missing");
    const next = info.data.readUInt32LE(PAY_OFF_NEXT);
    const startAt = info.data.readBigInt64LE(PAY_OFF_START);
    const period = info.data.readBigInt64LE(PAY_OFF_PERIOD);
    const due = startAt + (BigInt(next) + 1n) * period;
    const now = await clockNow();
    if (now >= due) return;
    const waitMs = Number(due - now) * 1_000;
    console.log(`milestone ${next} due at ${due.toString()}, clock ${now.toString()}`);
    await new Promise((resolve) => setTimeout(resolve, Math.min(Math.max(waitMs, DUE_POLL_MS), 30_000)));
  }
}

export async function payPayroll(): Promise<void> {
  await initializePoseidon();
  const payee = loadKeypair(PAYEE_PATH);
  const payroll = requirePayroll();
  const terms = readPayroll(payrollPath(payroll));
  const info = await conn.getAccountInfo(payroll);
  if (info === null) throw new Error("payroll account is missing");
  const next = info.data.readUInt32LE(PAY_OFF_NEXT);
  const startAt = info.data.readBigInt64LE(PAY_OFF_START);
  const period = info.data.readBigInt64LE(PAY_OFF_PERIOD);
  const now = await clockNow();
  const due = startAt + (BigInt(next) + 1n) * period;
  if (now < due) throw new Error(`milestone ${next} is due at ${due.toString()}, clock is ${now.toString()}`);
  const client = await spr();
  await init({ threads: 1 });
  const payrollViewing = viewingFrom(terms);
  const payrollNote = notePda(payroll);
  const pda = await pdaWallet(client, payrollNote, payrollViewing);
  const person = await personWallet(client, PAYEE_SEED);
  try {
    const source = pickNote(liveNotes(pda.wallet), 0n);
    const installment = BigInt(terms.installment);
    const blind = Buffer.from(terms.installment_blinding_hex, "hex");
    const [blind0, blind1, blind2, blind3] = limbs(blind);
    const build = bindProgramTransaction(payTransaction, { assets: pda.wallet.registry });
    const built = await build(
      {
        private: {
          txContext: { blindingSeed: randomBlinding(), outputTreeId: TREE_ID },
          note: [asProgram(source, ProgramOwner.nullifierPublicKey(), pda.wallet.registry)],
          amount: installment,
          blind0,
          blind1,
          blind2,
          blind3,
          payee: userOwner(person.shielded, payee.publicKey),
          payrollAddress: pdaAddress(payrollNote, payrollViewing).toBytes(),
        },
        public: {
          index: BigInt(next),
          due,
          installment: await commitment(installment, blind),
          payee: person.shielded.ownerHash(),
        },
      } as unknown as Parameters<typeof payTransaction>[0],
      person.shielded.shieldedAddress().toBytes(),
      payee.publicKey.toBase58(),
    );
    const proved = await proveMove(client, pda.keys, person.shielded, built, proverFor("pay"));
    const tail = await tailAccounts(payee.publicKey, [], [payrollNote], proved.proved);
    const signature = await sendV0(
      payee,
      [payee],
      [
        ComputeBudgetProgram.setComputeUnitLimit({ units: COMPUTE_UNIT_LIMIT }),
        new TransactionInstruction({
          programId: programKey,
          keys: [
            { pubkey: payroll, isSigner: false, isWritable: true },
            { pubkey: payee.publicKey, isSigner: true, isWritable: true },
            { pubkey: CLOCK, isSigner: false, isWritable: false },
            ...tail,
          ],
          data: Buffer.concat([Buffer.from([IX_PAY]), proved.data]),
        }),
      ],
      tail.map((key) => key.pubkey),
    );
    console.log(`paid index=${next} signature=${signature}`);
  } finally {
    pda.keys.destroy();
    pda.identity.destroy();
    person.keys.destroy();
    person.shielded.destroy();
    payrollViewing.destroy();
  }
}

export async function stopPayroll(): Promise<void> {
  const employer = loadKeypair(EMPLOYER_PATH);
  const payroll = requirePayroll();
  const signature = await sendLegacy(
    [employer],
    new Transaction().add(
      new TransactionInstruction({
        programId: programKey,
        keys: [
          { pubkey: payroll, isSigner: false, isWritable: true },
          { pubkey: employer.publicKey, isSigner: true, isWritable: true },
        ],
        data: Buffer.from([IX_STOP]),
      }),
    ),
  );
  console.log(`stopped payroll=${payroll.toBase58()} signature=${signature}`);
}

export async function reclaimPayroll(): Promise<void> {
  await initializePoseidon();
  const employer = loadKeypair(EMPLOYER_PATH);
  const payroll = requirePayroll();
  const terms = readPayroll(payrollPath(payroll));
  const { vault, viewing } = requireVault(employer.publicKey);
  const vaultInfo = await conn.getAccountInfo(vault);
  if (vaultInfo === null || vaultInfo.data[VAULT_OFF_LIVE] !== LIVE_NOTE) {
    throw new Error("the pool has no note; deposit one, then reclaim");
  }
  const client = await spr();
  await init({ threads: 1 });
  const pool = poolPda(employer.publicKey);
  const payrollViewing = viewingFrom(terms);
  const payrollNote = notePda(payroll);
  const locked = await pdaWallet(client, payrollNote, payrollViewing);
  const pooled = await pdaWallet(client, pool, viewing);
  try {
    const payrollUtxo = pickNote(liveNotes(locked.wallet), 0n);
    const poolUtxo = pickNote(liveNotes(pooled.wallet), 0n);
    const destination = pdaAddress(pool, viewing);
    const build = bindProgramTransaction(reclaimTransaction, { assets: locked.wallet.registry });
    const built = await build(
      {
        private: {
          txContext: { blindingSeed: randomBlinding(), outputTreeId: TREE_ID },
          payrollNote: [asProgram(payrollUtxo, ProgramOwner.nullifierPublicKey(), locked.wallet.registry)],
          poolNote: [asProgram(poolUtxo, ProgramOwner.nullifierPublicKey(), pooled.wallet.registry)],
          pool: pdaOwner(pool),
        },
        public: {
          note: pdaAddress(payrollNote, payrollViewing).ownerHash(),
          pool: destination.ownerHash(),
        },
      },
      destination.toBytes(),
      employer.publicKey.toBase58(),
    );
    const proved = await proveMove(client, locked.keys, viewing, built, proverFor("reclaim"));
    const tail = await tailAccounts(employer.publicKey, [], [payrollNote, pool], proved.proved);
    const signature = await sendV0(
      employer,
      [employer],
      [
        ComputeBudgetProgram.setComputeUnitLimit({ units: COMPUTE_UNIT_LIMIT }),
        new TransactionInstruction({
          programId: programKey,
          keys: [
            { pubkey: payroll, isSigner: false, isWritable: true },
            { pubkey: vault, isSigner: false, isWritable: true },
            { pubkey: employer.publicKey, isSigner: true, isWritable: true },
            ...tail,
          ],
          data: Buffer.concat([Buffer.from([IX_RECLAIM]), proved.data]),
        }),
      ],
      tail.map((key) => key.pubkey),
    );
    console.log(`reclaimed payroll=${payroll.toBase58()} signature=${signature}`);
  } finally {
    locked.keys.destroy();
    locked.identity.destroy();
    pooled.keys.destroy();
    pooled.identity.destroy();
    viewing.destroy();
    payrollViewing.destroy();
  }
}
