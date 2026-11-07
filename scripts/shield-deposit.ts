// Shield SOL from the employer wallet into ring1. The amount is lamports on argv.

import { chmodSync } from "node:fs";
import {
  createKeyPairSignerFromPrivateKeyBytes,
  sendTransactionWithoutConfirmingFactory,
  signTransactionWithSigners,
  getSignatureFromTransaction,
} from "./kit-node.mjs";
import {
  ShieldedKeypair,
  SigningKey,
  buildDepositTransaction,
  createSprClient,
} from "../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/index.js";
import type { Bytes32 } from "../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/keypair/bytes.js";
import type { Address, Signature } from "../../pescrow/sdk/node_modules/@heliuslabs/spr/dist/interface/types.js";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const RING1_TREE = "777pvSGe5LaBd9nCczvE2FXEauiwtfGJ5XRpjKyniGor";
const FIELD_BYTES = 32;

function scrub(value: unknown): string {
  return String(value).replace(/api-key=[^&\s"]+/g, "api-key=REDACTED");
}

function heliusApiKey(): string {
  const text = readFileSync(join(homedir(), ".config/solana/cli/config.yml"), "utf8");
  const match = text.match(/api-key=([0-9a-f-]+)/i);
  const key = match?.[1];
  if (key === undefined) throw new Error("Helius key is not in the Solana CLI config");
  return key;
}

const amount = BigInt(process.argv[2] ?? "100000000");
const seedPath = process.env.PPROLL_EMPLOYER_SEED;
if (seedPath === undefined || seedPath.length === 0) throw new Error("PPROLL_EMPLOYER_SEED is missing");
const parsed: unknown = JSON.parse(readFileSync(seedPath, "utf8"));
if (typeof parsed !== "object" || parsed === null || !("funding_secret_hex" in parsed)) {
  throw new Error("employer seed file is unreadable");
}
const hex = parsed.funding_secret_hex;
if (typeof hex !== "string") throw new Error("employer seed file is unreadable");
const seed = Uint8Array.from(Buffer.from(hex, "hex"));
if (seed.byteLength !== FIELD_BYTES) throw new Error("employer seed is not 32 bytes");

const url = new URL("https://devnet.helius-rpc.com/");
url.searchParams.set("api-key", heliusApiKey());
const client = await createSprClient({ solanaRpcUrl: url.toString() });
const signer = await createKeyPairSignerFromPrivateKeyBytes(seed);
const shielded = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed as Bytes32));
seed.fill(0);

try {
  const transaction = await buildDepositTransaction({
    client,
    feePayer: signer.address as Address,
    recipient: shielded.shieldedAddress(),
    amount,
    tree: RING1_TREE as Address,
  });
  const signed = await signTransactionWithSigners([signer], transaction);
  const send = sendTransactionWithoutConfirmingFactory({ rpc: client.solanaRpc });
  await send(signed, { commitment: "confirmed" });
  const signature = getSignatureFromTransaction(signed) as Signature;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const status = await client.solanaRpc.getSignatureStatuses([signature]).send();
    const row = status.value[0];
    if (row?.err) throw new Error(`shield ${signature} failed: ${JSON.stringify(row.err)}`);
    if (row?.confirmationStatus === "confirmed" || row?.confirmationStatus === "finalized") break;
    if (attempt === 29) throw new Error(`shield ${signature} was not confirmed`);
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  console.log(`shielded payer=${signer.address} lamports=${amount.toString()} signature=${signature}`);
} catch (error: unknown) {
  console.error(scrub(error instanceof Error ? error.message : error));
  process.exit(1);
} finally {
  shielded.destroy();
  chmodSync(seedPath, 0o600);
}
