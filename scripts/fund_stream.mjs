// Fund the next period. The employer signs. The period account is created in this transaction.
// The proof is 128 bytes. The transact file is the privacy-program payload.
// The accounts file is one pubkey per line. Line 3 must be the privacy program.
// Usage: node fund_stream.mjs <program-id> <employer-keypair> <stream-pubkey> <period-keypair> --commitment <hex> --proof <file> --transact <file> --accounts <file>

import { readFileSync } from "node:fs";
import { PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import {
  CLOCK,
  PERIOD_LEN,
  PROOF_LEN,
  connection,
  flag,
  loadKeypair,
  loadStream,
  readAccounts,
  readExact,
  send,
} from "./chain.mjs";

const [programArg, employerPath, streamArg, periodPath] = process.argv.slice(2);
if (!programArg || !employerPath || !streamArg || !periodPath || periodPath.startsWith("--")) {
  console.error(
    "usage: node fund_stream.mjs <program-id> <employer-keypair> <stream-pubkey> <period-keypair> --commitment <hex> --proof <file> --transact <file> --accounts <file>",
  );
  process.exit(2);
}

const commitmentHex = flag("--commitment", "");
const proofPath = flag("--proof", "");
const transactPath = flag("--transact", "");
const accountsPath = flag("--accounts", "");
if (commitmentHex.length === 0 || proofPath.length === 0 || transactPath.length === 0 || accountsPath.length === 0) {
  console.error("refusing to send: pass --commitment, --proof, --transact, and --accounts");
  process.exit(2);
}

const commitment = Buffer.from(commitmentHex, "hex");
if (commitment.length !== 32 || commitment.equals(Buffer.alloc(32))) {
  throw new Error("commitment must be 32 non-zero hex bytes");
}
const proof = readExact(proofPath, PROOF_LEN, "proof");
const transact = readFileSync(transactPath);
if (transact.length === 0) {
  throw new Error("transact file is empty");
}
const tail = readAccounts(accountsPath);

const program = new PublicKey(programArg);
const employer = loadKeypair(employerPath);
const stream = new PublicKey(streamArg);
const period = loadKeypair(periodPath);
const conn = connection();
const decoded = await loadStream(conn, stream);
if (!decoded.employer.equals(employer.publicKey)) {
  throw new Error("this keypair is not the employer stored on the stream");
}

const existing = await conn.getAccountInfo(period.publicKey);
if (existing !== null) {
  throw new Error("period address already exists; pass a new period keypair");
}

const data = Buffer.alloc(1 + 32 + 4 + 32 + PROOF_LEN + transact.length);
data[0] = 3;
stream.toBuffer().copy(data, 1);
data.writeUInt32LE(decoded.nextFund, 1 + 32);
commitment.copy(data, 1 + 36);
proof.copy(data, 1 + 68);
transact.copy(data, 1 + 68 + PROOF_LEN);

const lamports = await conn.getMinimumBalanceForRentExemption(PERIOD_LEN);
console.error(
  "a fund moves one whole note into the next period; the proof has to match this stream and this employer",
);
await send(
  conn,
  employer,
  [
    SystemProgram.createAccount({
      fromPubkey: employer.publicKey,
      newAccountPubkey: period.publicKey,
      lamports,
      space: PERIOD_LEN,
      programId: program,
    }),
    new TransactionInstruction({
      programId: program,
      keys: [
        { pubkey: stream, isSigner: false, isWritable: true },
        { pubkey: period.publicKey, isSigner: false, isWritable: true },
        { pubkey: employer.publicKey, isSigner: true, isWritable: true },
        { pubkey: CLOCK, isSigner: false, isWritable: false },
        ...tail.map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
      ],
      data,
    }),
  ],
  [period],
);
console.log(`funded index ${decoded.nextFund} period ${period.publicKey.toBase58()}`);
process.exit(0);
