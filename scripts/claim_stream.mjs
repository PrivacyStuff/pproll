// Claim the oldest funded period. The employee signs. Rent on the period account returns to the employer.
// The proof is 128 bytes. The transact file is the privacy-program payload.
// The accounts file is one pubkey per line. Line 3 must be the privacy program.
// Usage: node claim_stream.mjs <program-id> <fee-payer-keypair> <employee-keypair> <stream-pubkey> <period-pubkey> --proof <file> --transact <file> --accounts <file>

import { readFileSync } from "node:fs";
import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import {
  CLOCK,
  PROOF_LEN,
  connection,
  decodePeriod,
  flag,
  loadKeypair,
  loadStream,
  readAccounts,
  readExact,
  send,
} from "./chain.mjs";

const [programArg, payerPath, employeePath, streamArg, periodArg] = process.argv.slice(2);
if (!programArg || !payerPath || !employeePath || !streamArg || !periodArg || periodArg.startsWith("--")) {
  console.error(
    "usage: node claim_stream.mjs <program-id> <fee-payer-keypair> <employee-keypair> <stream-pubkey> <period-pubkey> --proof <file> --transact <file> --accounts <file>",
  );
  process.exit(2);
}

const proofPath = flag("--proof", "");
const transactPath = flag("--transact", "");
const accountsPath = flag("--accounts", "");
if (proofPath.length === 0 || transactPath.length === 0 || accountsPath.length === 0) {
  console.error("refusing to send: pass --proof, --transact, and --accounts");
  process.exit(2);
}

const proof = readExact(proofPath, PROOF_LEN, "proof");
const transact = readFileSync(transactPath);
if (transact.length === 0) {
  throw new Error("transact file is empty");
}
const tail = readAccounts(accountsPath);

const program = new PublicKey(programArg);
const payer = loadKeypair(payerPath);
const employee = loadKeypair(employeePath);
const stream = new PublicKey(streamArg);
const period = new PublicKey(periodArg);
const conn = connection();
const decoded = await loadStream(conn, stream);
if (!decoded.employee.equals(employee.publicKey)) {
  throw new Error("this keypair is not the employee stored on the stream");
}
const periodInfo = await conn.getAccountInfo(period);
if (periodInfo === null) {
  throw new Error("period account does not exist");
}
const note = decodePeriod(Buffer.from(periodInfo.data));
if (!note.stream.equals(stream) || note.index !== decoded.nextClaim) {
  throw new Error("period is not the oldest funded note on this stream");
}
if (note.commitment.equals(Buffer.alloc(32))) {
  throw new Error("period has no commitment");
}

const data = Buffer.alloc(1 + 32 + 4 + 32 + PROOF_LEN + transact.length);
data[0] = 4;
stream.toBuffer().copy(data, 1);
data.writeUInt32LE(note.index, 1 + 32);
note.commitment.copy(data, 1 + 36);
proof.copy(data, 1 + 68);
transact.copy(data, 1 + 68 + PROOF_LEN);

console.error(
  "a claim pays the period note to the employee; the proof has to match the stored commitment and the clock",
);
await send(
  conn,
  payer,
  [
    new TransactionInstruction({
      programId: program,
      keys: [
        { pubkey: stream, isSigner: false, isWritable: true },
        { pubkey: period, isSigner: false, isWritable: true },
        { pubkey: employee.publicKey, isSigner: true, isWritable: true },
        { pubkey: CLOCK, isSigner: false, isWritable: false },
        { pubkey: decoded.employer, isSigner: false, isWritable: true },
        ...tail.map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
      ],
      data,
    }),
  ],
  [employee],
);
console.log(`claimed index ${note.index}`);
process.exit(0);
