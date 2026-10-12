/**
 * `npm run demo`: a scripted tour of VEA-BFT on the Heart dataset (in-process chain).
 * Honest rounds -> Byzantine primary -> poisoned update -> hospital joins (committee reshare) -> audit.
 */
import { Federation, RoundReport } from "../orchestrator/federation";

const line = (r: RoundReport) =>
  `   round ${String(r.round).padStart(2)}  ${r.status.padEnd(9)} view=${r.finalView}  acc=${r.metrics.accuracy.toFixed(3)} loss=${r.metrics.logLoss.toFixed(4)} auc=${r.metrics.auc.toFixed(3)}  S_r=[${r.included}]  gas=${r.gas}  ${r.timers.total.toFixed(0)}ms${r.abortReason ? "  abort: " + r.abortReason : ""}`;
const h = (s: string) => console.log(`\n\x1b[1m── ${s}\x1b[0m`);

async function main() {
  const fed = await Federation.create({ dataset: "heart", reserve: 1, excludePolicy: false });
  fed.on((e) => {
    if (["reject", "view-change", "rotation", "membership", "aborted"].includes(e.kind)) console.log(`   · ${e.msg}`);
  });
  h("1. Honest rounds: encrypted updates, validator-recomputed aggregate, threshold decryption");
  for (let i = 0; i < 3; i++) console.log(line(await fed.runRound()));

  h("2. Byzantine primary V0 tampers with ct_Sigma → honest validators refuse → view change");
  console.log(line(await fed.runRound({ validatorFaults: { 0: "bad-aggregate" } })));

  h("3. One crashed validator (f = 1): the other three still reach a quorum");
  console.log(line(await fed.runRound({ validatorFaults: { 3: "silent" } })));

  h("4. Hospital H1 submits an update scaled by 50 (abort policy, paper Section VIII-C)");
  console.log(line(await fed.runRound({ behaviors: { 0: "oversize" }, attackFactor: 50 })));

  h("5. Hospital H6 joins → committee 3-of-5 becomes 4-of-6 by verifiable resharing; same public key");
  await fed.addHospital(5);
  await fed.rotateCommittee();
  console.log(line(await fed.runRound()));

  h("6. Independent audit of rounds 1, 6 (aborted) and 7 from ledger + content store only");
  for (const r of [1, 6, 7]) {
    const a = await fed.audit(r);
    console.log(`   round ${r}: ${a.ok ? "PASS" : "FAIL"}  (${a.checks.filter((c) => c.ok).length}/${a.checks.length} checks)`);
    for (const c of a.checks.filter((c) => !c.ok)) console.log(`      ✗ ${c.name}: ${c.detail}`);
  }
  const s = await fed.snapshot();
  console.log(`\nledger ${s.chain.ledger}: ${s.chain.txs} transactions, ${s.chain.gas} gas, epoch ${s.chain.epoch}`);
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
