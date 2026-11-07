// One party approves. Accounts: stream, party (signer), Clock.
// Pass --payer when the party has no SOL. The payer pays the fee and the party still signs.
// Usage: node approve_stream.mjs <program-id> <stream-pubkey> <party-keypair> [--payer <keypair>]

import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { CLOCK, connection, flag, loadKeypair, send } from "./chain.mjs";

const [programArg, streamArg, partyPath] = process.argv.slice(2);
if (!programArg || !streamArg || !partyPath) {
  console.error(
    "usage: node approve_stream.mjs <program-id> <stream-pubkey> <party-keypair> [--payer <keypair>]",
  );
  process.exit(2);
}

const program = new PublicKey(programArg);
const stream = new PublicKey(streamArg);
const party = loadKeypair(partyPath);
const payerPath = flag("--payer", "");
const payer = payerPath.length === 0 ? party : loadKeypair(payerPath);
const conn = connection();

await send(
  conn,
  payer,
  [
    new TransactionInstruction({
      programId: program,
      keys: [
        { pubkey: stream, isSigner: false, isWritable: true },
        { pubkey: party.publicKey, isSigner: true, isWritable: true },
        { pubkey: CLOCK, isSigner: false, isWritable: false },
      ],
      data: Buffer.from([1]),
    }),
  ],
  [party],
);
console.log(`approved ${stream.toBase58()} by ${party.publicKey.toBase58()}`);
process.exit(0);
