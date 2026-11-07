// Close a stream with nothing left to claim. Rent returns to the employer.
// The employer must be the signer. An Active stream has to be stopped first.
// Usage: node close_stream.mjs <program-id> <stream-pubkey> <employer-keypair>

import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { connection, loadKeypair, loadStream, send } from "./chain.mjs";

const [programArg, streamArg, employerPath] = process.argv.slice(2);
if (!programArg || !streamArg || !employerPath) {
  console.error("usage: node close_stream.mjs <program-id> <stream-pubkey> <employer-keypair>");
  process.exit(2);
}

const program = new PublicKey(programArg);
const stream = new PublicKey(streamArg);
const employer = loadKeypair(employerPath);
const conn = connection();
const decoded = await loadStream(conn, stream);
if (!decoded.employer.equals(employer.publicKey)) {
  throw new Error("this keypair is not the employer stored on the stream");
}
if (decoded.nextFund !== decoded.nextClaim) {
  throw new Error("a funded period is still unclaimed");
}

await send(
  conn,
  employer,
  [
    new TransactionInstruction({
      programId: program,
      keys: [
        { pubkey: stream, isSigner: false, isWritable: true },
        { pubkey: employer.publicKey, isSigner: true, isWritable: true },
      ],
      data: Buffer.from([6]),
    }),
  ],
  [],
);

const after = await conn.getAccountInfo(stream);
if (after !== null && after.lamports !== 0) {
  throw new Error("stream still holds lamports");
}
console.log(`closed ${stream.toBase58()}`);
process.exit(0);
