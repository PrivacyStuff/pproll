// Five-minute payroll on fresh wallets.
// Set PPROLL_EMPLOYER_KEY, PPROLL_EMPLOYER_SEED, PPROLL_PAYEE_KEY, PPROLL_PAYEE_SEED,
// and PPROLL_PAYEE_PUBKEY. The payee accepts. The employer does not approve again.

import {
  approvePayroll,
  deposit,
  initiatePayroll,
  main,
  openPayroll,
  openVault,
  payPayroll,
  reclaimPayroll,
  stopPayroll,
  waitUntilDue,
} from "./pool/lib.ts";

const INSTALLMENT = "10000000";
const BUDGET = "50000000";
const PERIOD_SECS = "300";
const START_IN_SECS = "180";
const PAYS = 4;

function payeePubkey(): string {
  const payee = process.env.PPROLL_PAYEE_PUBKEY;
  if (payee === undefined || payee.length === 0) throw new Error("PPROLL_PAYEE_PUBKEY is missing");
  return payee;
}

await main(async () => {
  process.argv.push(
    "--payee",
    payeePubkey(),
    "--installment",
    INSTALLMENT,
    "--budget",
    BUDGET,
    "--period",
    PERIOD_SECS,
    "--start-in",
    START_IN_SECS,
    "--min",
    "1",
    "--as",
    "payee",
  );
  await openVault();
  await deposit();
  const payroll = await openPayroll();
  process.argv.push("--payroll", payroll);
  await approvePayroll();
  await initiatePayroll();
  for (let index = 0; index < PAYS; index += 1) {
    await waitUntilDue(payroll);
    await payPayroll();
  }
  await stopPayroll();
  await reclaimPayroll();
  console.log(`closed payroll=${payroll} pays=${PAYS}`);
});
