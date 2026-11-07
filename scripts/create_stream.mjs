// Open one hourly stream. The employer signs. The employee is only a pubkey.
// Approval stays open until start_at. Default period is 3600 seconds.
// Usage: node create_stream.mjs <program-keypair> <employer-keypair> <employee-pubkey> <stream-keypair> [--period 3600] [--window 21600]

import { PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import { STREAM_LEN, connection, flag, loadKeypair, send } from "./chain.mjs";

const [programPath, employerPath, employeeArg, streamPath] = process.argv.slice(2);
if (!programPath || !employerPath || !employeeArg || !streamPath || employeeArg.startsWith("--")) {
  console.error(
    "usage: node create_stream.mjs <program-keypair> <employer-keypair> <employee-pubkey> <stream-keypair> [--period 3600] [--window 21600]",
  );
  process.exit(2);
}

const periodSecs = BigInt(flag("--period", "3600"));
const windowSecs = BigInt(flag("--window", "21600"));
if (periodSecs <= 0n || windowSecs <= 0n) {
  throw new Error("period and window must be positive");
}

const program = loadKeypair(programPath);
const employer = loadKeypair(employerPath);
const employee = new PublicKey(employeeArg);
const stream = loadKeypair(streamPath);
const conn = connection();
const now = BigInt(Math.floor(Date.now() / 1000));
const startAt = now + windowSecs;
const deadline = startAt;

const data = Buffer.alloc(1 + 58);
data[0] = 0;
employee.toBuffer().copy(data, 1);
data.writeBigInt64LE(startAt, 1 + 32);
data.writeBigInt64LE(deadline, 1 + 40);
data.writeBigInt64LE(periodSecs, 1 + 48);
data[1 + 56] = 1;
data[1 + 57] = 1;

const lamports = await conn.getMinimumBalanceForRentExemption(STREAM_LEN);
await send(
  conn,
  employer,
  [
    SystemProgram.createAccount({
      fromPubkey: employer.publicKey,
      newAccountPubkey: stream.publicKey,
      lamports,
      space: STREAM_LEN,
      programId: program.publicKey,
    }),
    new TransactionInstruction({
      programId: program.publicKey,
      keys: [
        { pubkey: stream.publicKey, isSigner: false, isWritable: true },
        { pubkey: employer.publicKey, isSigner: true, isWritable: false },
      ],
      data,
    }),
  ],
  [stream],
);

console.log(`stream ${stream.publicKey.toBase58()}`);
console.log(`employer ${employer.publicKey.toBase58()}`);
console.log(`employee ${employee.toBase58()}`);
console.log(`period_secs ${periodSecs}`);
console.log(`approve_until ${new Date(Number(deadline) * 1000).toISOString()}`);
console.log(`first_claim_at ${new Date(Number(startAt + periodSecs) * 1000).toISOString()}`);
process.exit(0);
