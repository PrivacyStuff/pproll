import { readFileSync } from "node:fs";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

export const STREAM_LEN = 104;
export const PERIOD_LEN = 72;
export const PROOF_LEN = 128;
export const CLOCK = new PublicKey("SysvarC1ock11111111111111111111111111111111");
export const SPP = new PublicKey("ring1GaLCuJnkUMVkX2JeZLTTX17wKsV4fZmPVzXANW");

export function rpcUrl() {
  const config = readFileSync(`${process.env.HOME}/.config/solana/cli/config.yml`, "utf8");
  const line = config.split("\n").find((entry) => entry.startsWith("json_rpc_url:"));
  if (!line) {
    throw new Error("json_rpc_url missing from solana config");
  }
  return line.slice("json_rpc_url:".length).trim();
}

export function connection() {
  return new Connection(rpcUrl(), "confirmed");
}

export function loadKeypair(path) {
  const secret = Uint8Array.from(JSON.parse(readFileSync(path, "utf8")));
  return Keypair.fromSecretKey(secret);
}

export function decodeStream(buf) {
  if (buf.length !== STREAM_LEN) {
    throw new Error(`stream length ${buf.length}, expected ${STREAM_LEN}`);
  }
  return {
    tag: buf[0],
    status: buf[1],
    employerApproved: buf[2],
    employeeApproved: buf[3],
    termsFrozen: buf[4],
    ring: buf[5],
    wallets: buf[6],
    startAt: buf.readBigInt64LE(8),
    deadline: buf.readBigInt64LE(16),
    periodSecs: buf.readBigInt64LE(24),
    employer: new PublicKey(buf.subarray(32, 64)),
    employee: new PublicKey(buf.subarray(64, 96)),
    nextFund: buf.readUInt32LE(96),
    nextClaim: buf.readUInt32LE(100),
  };
}

export async function loadStream(conn, stream) {
  const info = await conn.getAccountInfo(stream);
  if (info === null) {
    throw new Error(`stream ${stream.toBase58()} does not exist`);
  }
  return decodeStream(Buffer.from(info.data));
}

export function decodePeriod(buf) {
  if (buf.length !== PERIOD_LEN) {
    throw new Error(`period length ${buf.length}, expected ${PERIOD_LEN}`);
  }
  return {
    tag: buf[0],
    status: buf[1],
    index: buf.readUInt32LE(4),
    stream: new PublicKey(buf.subarray(8, 40)),
    commitment: Buffer.from(buf.subarray(40, 72)),
  };
}

export function flag(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index === -1) {
    return fallback;
  }
  const value = process.argv[index + 1];
  if (value === undefined || value.startsWith("--")) {
    throw new Error(`${name} needs a value`);
  }
  return value;
}

export function readExact(path, length, label) {
  const bytes = readFileSync(path);
  if (bytes.length !== length) {
    throw new Error(`${label} is ${bytes.length} bytes, expected ${length}`);
  }
  return bytes;
}

export function readAccounts(path) {
  const lines = readFileSync(path, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  if (lines.length < 3) {
    throw new Error("accounts file needs at least 3 pubkeys; line 3 must be the privacy program");
  }
  const keys = lines.map((line) => new PublicKey(line));
  if (!keys[2].equals(SPP)) {
    throw new Error("accounts file line 3 must be ring1GaLCuJnkUMVkX2JeZLTTX17wKsV4fZmPVzXANW");
  }
  return keys;
}

export async function send(conn, payer, instructions, signers) {
  const tx = new Transaction().add(...instructions);
  const extra = signers.filter((signer) => !signer.publicKey.equals(payer.publicKey));
  const signature = await sendAndConfirmTransaction(conn, tx, [payer, ...extra], {
    commitment: "confirmed",
  });
  console.log(signature);
  return signature;
}
