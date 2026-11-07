// Devnet lifecycle that does not move a note.
// Create, both approvals, a fund that must fail closed, then decline and close.
// Usage: node devnet_lifecycle.mjs <program-keypair> <employer-keypair> <employee-keypair>

import { readFileSync } from "node:fs";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

const STREAM_LEN = 104;
const PERIOD_LEN = 72;
const CLOCK = new PublicKey("SysvarC1ock11111111111111111111111111111111");
const SPP = new PublicKey("ring1GaLCuJnkUMVkX2JeZLTTX17wKsV4fZmPVzXANW");
const PERIOD_SECS = 86_400n;

const [programPath, employerPath, employeePath] = process.argv.slice(2);
if (!programPath || !employerPath || !employeePath) {
  console.error("usage: node devnet_lifecycle.mjs <program-keypair> <employer-keypair> <employee-keypair>");
  process.exit(2);
}

function rpcUrl() {
  const config = readFileSync(`${process.env.HOME}/.config/solana/cli/config.yml`, "utf8");
  const line = config.split("\n").find((entry) => entry.startsWith("json_rpc_url:"));
  if (!line) {
    throw new Error("json_rpc_url missing from solana config");
  }
  return line.slice("json_rpc_url:".length).trim();
}

function loadKeypair(path) {
  const secret = Uint8Array.from(JSON.parse(readFileSync(path, "utf8")));
  return Keypair.fromSecretKey(secret);
}

function createData(employee, startAt, deadline) {
  const data = Buffer.alloc(1 + 58);
  data[0] = 0;
  employee.toBuffer().copy(data, 1);
  data.writeBigInt64LE(startAt, 1 + 32);
  data.writeBigInt64LE(deadline, 1 + 40);
  data.writeBigInt64LE(PERIOD_SECS, 1 + 48);
  data[1 + 56] = 1;
  data[1 + 57] = 1;
  return data;
}

function decodeStream(buf) {
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
    employer: new PublicKey(buf.subarray(32, 64)).toBase58(),
    employee: new PublicKey(buf.subarray(64, 96)).toBase58(),
    nextFund: buf.readUInt32LE(96),
    nextClaim: buf.readUInt32LE(100),
  };
}

async function send(connection, payer, instructions, signers) {
  const tx = new Transaction().add(...instructions);
  return sendAndConfirmTransaction(connection, tx, [payer, ...signers.filter((signer) => signer.publicKey !== payer.publicKey)], {
    commitment: "confirmed",
  });
}

async function expectFailure(connection, payer, instructions, signers, label) {
  try {
    const signature = await send(connection, payer, instructions, signers);
    throw new Error(`${label} landed ${signature}`);
  } catch (error) {
    if (error.message?.startsWith(`${label} landed`)) {
      throw error;
    }
    const logs = typeof error.getLogs === "function" ? await error.getLogs(connection) : error.logs ?? [];
    return logs.join("\n");
  }
}

const program = loadKeypair(programPath);
const employer = loadKeypair(employerPath);
const employee = loadKeypair(employeePath);
const stranger = Keypair.generate();
const connection = new Connection(rpcUrl(), "confirmed");
const programId = program.publicKey;

const info = await connection.getAccountInfo(programId);
if (info === null || !info.executable) {
  throw new Error("program is not deployed at this id");
}

const now = BigInt(Math.floor(Date.now() / 1000));
const deadline = now + 3_600n;
const startAt = now + 7_200n;

async function openStream(label) {
  const stream = Keypair.generate();
  const lamports = await connection.getMinimumBalanceForRentExemption(STREAM_LEN);
  const signature = await send(
    connection,
    employer,
    [
      SystemProgram.createAccount({
        fromPubkey: employer.publicKey,
        newAccountPubkey: stream.publicKey,
        lamports,
        space: STREAM_LEN,
        programId,
      }),
      new TransactionInstruction({
        programId,
        keys: [
          { pubkey: stream.publicKey, isSigner: false, isWritable: true },
          { pubkey: employer.publicKey, isSigner: true, isWritable: false },
        ],
        data: createData(employee.publicKey, startAt, deadline),
      }),
    ],
    [stream],
  );
  console.log(`${label} create ${stream.publicKey.toBase58()} ${signature}`);
  return stream;
}

function approveIx(stream) {
  return (party) =>
    new TransactionInstruction({
      programId,
      keys: [
        { pubkey: stream, isSigner: false, isWritable: true },
        { pubkey: party, isSigner: true, isWritable: false },
        { pubkey: CLOCK, isSigner: false, isWritable: false },
      ],
      data: Buffer.from([1]),
    });
}

const stream = await openStream("payroll");
const strangerLogs = await expectFailure(
  connection,
  employer,
  [approveIx(stream.publicKey)(stranger.publicKey)],
  [stranger],
  "third-party approve",
);
if (!strangerLogs.includes("custom program error: 0x66")) {
  throw new Error(`third-party approve was not NotAParty (102)\n${strangerLogs}`);
}
console.log("third-party approve rejected 102");

const employerApprove = await send(connection, employer, [approveIx(stream.publicKey)(employer.publicKey)], []);
console.log(`employer approve ${employerApprove}`);
const employeeApprove = await send(connection, employer, [approveIx(stream.publicKey)(employee.publicKey)], [employee]);
console.log(`employee approve ${employeeApprove}`);

const opened = await connection.getAccountInfo(stream.publicKey);
if (opened === null) {
  throw new Error("stream account missing after approve");
}
const decoded = decodeStream(Buffer.from(opened.data));
const expected = {
  tag: 2,
  status: 1,
  employerApproved: 1,
  employeeApproved: 1,
  termsFrozen: 1,
  ring: 1,
  wallets: 1,
  periodSecs: PERIOD_SECS,
  employer: employer.publicKey.toBase58(),
  employee: employee.publicKey.toBase58(),
  nextFund: 0,
  nextClaim: 0,
};
for (const [field, value] of Object.entries(expected)) {
  if (decoded[field] !== value) {
    throw new Error(`${field} is ${decoded[field]}, expected ${value}`);
  }
}
if (decoded.deadline !== deadline || decoded.startAt !== startAt) {
  throw new Error("schedule was not the one created");
}
console.log("frozen stream", decoded);

const period = Keypair.generate();
const periodLamports = await connection.getMinimumBalanceForRentExemption(PERIOD_LEN);
const fundData = Buffer.alloc(1 + 32 + 4 + 32 + 128 + 1);
fundData[0] = 3;
stream.publicKey.toBuffer().copy(fundData, 1);
fundData.writeUInt32LE(0, 1 + 32);
Buffer.alloc(32, 4).copy(fundData, 1 + 36);
const fundKeys = [
  { pubkey: stream.publicKey, isSigner: false, isWritable: true },
  { pubkey: period.publicKey, isSigner: false, isWritable: true },
  { pubkey: employer.publicKey, isSigner: true, isWritable: false },
  { pubkey: CLOCK, isSigner: false, isWritable: false },
  { pubkey: employer.publicKey, isSigner: false, isWritable: false },
  { pubkey: employer.publicKey, isSigner: false, isWritable: false },
  { pubkey: SPP, isSigner: false, isWritable: false },
];
const fundLogs = await expectFailure(
  connection,
  employer,
  [
    SystemProgram.createAccount({
      fromPubkey: employer.publicKey,
      newAccountPubkey: period.publicKey,
      lamports: periodLamports,
      space: PERIOD_LEN,
      programId,
    }),
    new TransactionInstruction({ programId, keys: fundKeys, data: fundData }),
  ],
  [period],
  "fund",
);
if (!fundLogs.includes("custom program error: 0x6f")) {
  throw new Error(`fund was not BadAccount (111) before the pool\n${fundLogs}`);
}
const afterFund = await connection.getAccountInfo(stream.publicKey);
const afterPeriod = await connection.getAccountInfo(period.publicKey);
const afterDecoded = decodeStream(Buffer.from(afterFund.data));
const periodWritten = afterPeriod !== null && afterPeriod.data[0] !== 0;
if (afterDecoded.nextFund !== 0 || afterDecoded.status !== 1 || periodWritten) {
  throw new Error("failed fund wrote the stream or the period");
}
console.log("fund rejected 111 and wrote nothing");

const other = await openStream("declined");
const decline = await send(
  connection,
  employer,
  [
    new TransactionInstruction({
      programId,
      keys: [
        { pubkey: other.publicKey, isSigner: false, isWritable: true },
        { pubkey: employee.publicKey, isSigner: true, isWritable: false },
        { pubkey: CLOCK, isSigner: false, isWritable: false },
      ],
      data: Buffer.from([2]),
    }),
  ],
  [employee],
);
console.log(`decline ${decline}`);
const closeSig = await send(
  connection,
  employer,
  [
    new TransactionInstruction({
      programId,
      keys: [
        { pubkey: other.publicKey, isSigner: false, isWritable: true },
        { pubkey: employer.publicKey, isSigner: true, isWritable: true },
      ],
      data: Buffer.from([6]),
    }),
  ],
  [],
);
console.log(`close ${closeSig}`);
const closed = await connection.getAccountInfo(other.publicKey);
if (closed !== null && closed.lamports !== 0) {
  throw new Error("declined stream still holds lamports");
}
console.log("declined stream closed");
console.log(`open stream ${stream.publicKey.toBase58()}`);
process.exit(0);
