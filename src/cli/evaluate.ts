/**
 * Reproduces the paper's evaluation (Section VII/VIII) on the implemented system and writes
 * results/ (JSON, markdown tables, SVG figures).
 *
 *   npm run evaluate                       # 3 datasets x 30 rounds (a few minutes)
 *   npm run evaluate -- --quick            # 8 rounds, attack at round 4
 *   npm run evaluate -- --datasets heart --rounds 30 --bits 256
 *
 * Runs per dataset:  centralized, plaintext FedAvg, VEA-BFT with an out-of-bound update injected
 * at round 15 (abort policy, the paper's setup), VEA-BFT with no injection (control: isolates
 * the quantisation effect) and VEA-BFT with exclude-and-continue (the paper's unevaluated policy).
 */
import * as fs from "fs";
import * as path from "path";
import { DatasetName, loadPrepared } from "../ml/dataset";
import { Federation } from "../orchestrator/federation";
import { Metrics, centralized, evaluate } from "../ml/logreg";
import { lineChart } from "../report/svg";
import { withDefaults } from "../config";

const arg = (k: string, d?: string) => {
  const i = process.argv.indexOf("--" + k);
  return i >= 0 ? process.argv[i + 1] : d;
};
const quick = process.argv.includes("--quick");
const ROUNDS = Number(arg("rounds", quick ? "8" : "30"));
const ATTACK = Number(arg("attack-round", quick ? "4" : "15"));
const BITS = Number(arg("bits", "256"));
const DATASETS = (arg("datasets", "heart,pima,wdbc")!.split(",") as DatasetName[]);
const OUT = path.resolve(__dirname, "../../results");
fs.mkdirSync(OUT, { recursive: true });

const f3 = (x: number) => x.toFixed(3);
const mean = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / (xs.length || 1);

async function runVea(dataset: DatasetName, opts: { inject: boolean; exclude?: boolean }) {
  const fed = await Federation.create({ dataset, bits: BITS, rounds: ROUNDS, excludePolicy: !!opts.exclude });
  const curve: Metrics[] = [];
  for (let r = 1; r <= ROUNDS; r++) {
    const attack = opts.inject && r === ATTACK;
    const rep = await fed.runRound(attack ? { behaviors: { 0: "oversize" }, attackFactor: 50 } : {});
    curve.push(rep.metrics);
    if (attack) console.log(`   round ${r}: injected x50 update -> ${rep.status}${rep.abortReason ? " (" + rep.abortReason + ")" : ""}, included=[${rep.included}]`);
  }
  return { fed, curve };
}

async function main() {
  const results: any = { rounds: ROUNDS, attackRound: ATTACK, bits: BITS, datasets: {} };
  let md = `# VEA-BFT evaluation\n\n${ROUNDS} rounds, 5 hospitals (non-IID split), ${BITS}-bit Paillier (NOT secure), 4 validators (f=1), committee 3-of-5. Out-of-bound update (x50) injected at round ${ATTACK}.\n\n`;
  const t3: string[] = [], t4: string[] = [];
  for (const ds of DATASETS) {
    console.log(`== ${ds}`);
    const cfg = withDefaults({ dataset: ds, bits: BITS });
    const data = loadPrepared(ds, { seed: cfg.seed, hospitals: cfg.hospitals });
    const centr = evaluate(centralized(data.train, new Array(data.nFeatures).fill(0), { ...cfg.train, epochs: cfg.train.epochs * ROUNDS }), data.test.X, data.test.y);
    const tp = performance.now();
    const plain = Federation.plaintextFedAvg(data, cfg, ROUNDS);
    const plainMs = (performance.now() - tp) / ROUNDS;
    console.log(" VEA-BFT (abort policy, injection)...");
    const vea = await runVea(ds, { inject: true });
    console.log(" VEA-BFT (no injection, control)...");
    const ctl = await runVea(ds, { inject: false });
    console.log(" VEA-BFT (exclude-and-continue, injection)...");
    const exc = await runVea(ds, { inject: true, exclude: true });

    const last = <T,>(a: T[]) => a[a.length - 1];
    const row = (name: string, m: Metrics) => `| ${ds} | ${name} | ${f3(m.accuracy)} | ${f3(m.logLoss)} | ${f3(m.auc)} |`;
    t3.push(row("Centralized", centr), row("Plaintext FedAvg", last(plain.curve)), row("VEA-BFT (abort, injection)", last(vea.curve)), row("VEA-BFT (no injection)", last(ctl.curve)), row("VEA-BFT (exclude-and-continue, injection)", last(exc.curve)));

    const h = vea.fed.history;
    const ok = h.filter((r) => r.status === "decrypted");
    const T = (k: string) => mean(ok.map((r) => r.timers[k] ?? 0));
    const share = T("decrypt.share") / vea.fed.threshold; // per-member share time (sum over t members / t)
    t4.push(
      `| ${ds} | ${plainMs.toFixed(3)} | ${T("train").toFixed(2)} | ${T("encrypt").toFixed(1)} | ${T("prove").toFixed(1)} | ${T("validator.verify.mean").toFixed(1)} | ${T("validator.aggregate.mean").toFixed(2)} | ${(T("decrypt.share") + T("decrypt.verify") + T("decrypt.combine")).toFixed(1)} | ${T("consensus").toFixed(0)} | ${mean(h.map((r) => r.gas)).toFixed(0)} |`
    );
    void share;

    // cause of the small gap to plaintext FedAvg (paper: "we have not isolated the cause")
    const wGapNoInj = Math.max(...ctl.fed.w.map((x, j) => Math.abs(x - plain.w[j])));
    const gap = {
      ctlVsPlainMaxWeightDiff: wGapNoInj,
      ctlVsPlainLogLossDiff: last(ctl.curve).logLoss - last(plain.curve).logLoss,
      injectedVsPlainLogLossDiff: last(vea.curve).logLoss - last(plain.curve).logLoss,
    };
    const attackRep = h[ATTACK - 1];
    results.datasets[ds] = {
      centralized: centr,
      plain: plain.curve,
      vea: vea.curve,
      control: ctl.curve,
      exclude: exc.curve,
      gap,
      timersMs: Object.fromEntries(Object.keys(ok[0].timers).map((k) => [k, T(k)])),
      meanGas: mean(h.map((r) => r.gas)),
      attackRound: { status: attackRep.status, reason: attackRep.abortReason, rejected: attackRep.hospitals.filter((x) => x.reject) },
      excludeRound: { status: exc.fed.history[ATTACK - 1].status, included: exc.fed.history[ATTACK - 1].included },
      audit: await vea.fed.audit(ATTACK - 1),
    };
    md += `### ${ds}\n- control (no injection) vs plaintext FedAvg: max |Δw| = ${wGapNoInj.toExponential(2)}, log-loss diff = ${gap.ctlVsPlainLogLossDiff.toExponential(2)} → the quantisation (s=${cfg.scale}) alone explains at most this much.\n- injected-and-aborted run vs plaintext: log-loss diff = ${gap.injectedVsPlainLogLossDiff.toExponential(2)} → this gap is the round skipped by the abort policy (the model is one step behind).\n- round ${ATTACK}: abort policy → **${attackRep.status}** (${attackRep.abortReason ?? "-"}); exclude-and-continue → **${exc.fed.history[ATTACK - 1].status}** with S_r=[${exc.fed.history[ATTACK - 1].included}].\n\n`;

    const xs = { xlabel: "Round" };
    fs.writeFileSync(path.join(OUT, `fig_accuracy_${ds}.svg`), lineChart({ title: `${ds}: hold-out accuracy`, ylabel: "accuracy", ...xs, vline: ATTACK, series: [
      { name: "Plaintext FedAvg", color: "#2563eb", values: plain.curve.map((m) => m.accuracy) },
      { name: "VEA-BFT (Paillier)", color: "#dc2626", dash: "6 3", values: vea.curve.map((m) => m.accuracy) },
      { name: "Centralized", color: "#6b7280", dash: "2 2", values: plain.curve.map(() => centr.accuracy) } ] }));
    fs.writeFileSync(path.join(OUT, `fig_logloss_${ds}.svg`), lineChart({ title: `${ds}: hold-out log-loss`, ylabel: "log-loss", ...xs, vline: ATTACK, series: [
      { name: "Plaintext FedAvg", color: "#2563eb", values: plain.curve.map((m) => m.logLoss) },
      { name: "VEA-BFT (Paillier)", color: "#dc2626", dash: "6 3", values: vea.curve.map((m) => m.logLoss) } ] }));
  }
  md += `## Table III: hold-out performance after ${ROUNDS} rounds\n\n| Dataset | Method | Accuracy | Log-loss | AUC |\n|---|---|---|---|---|\n${t3.join("\n")}\n\n`;
  md += `## Table IV: mean wall-clock time per round (ms), 5 hospitals, ${BITS}-bit Paillier, single process\n\n| Dataset | Plaintext FedAvg | Local training | Encryption | Proof gen | Proof verify (per validator) | Homomorphic agg (per validator) | Threshold decryption (t members, incl. share proofs) | PBFT incl. all validation (4 validators) | Gas/round |\n|---|---|---|---|---|---|---|---|---|---|\n${t4.join("\n")}\n\n`;
  md += `Unlike the paper's Table IV, proof generation, proof verification, consensus and ledger gas are measured here. All validators run in one process, so the PBFT column is the sum over the four replicas.\n`;
  fs.writeFileSync(path.join(OUT, "results.json"), JSON.stringify(results, null, 1));
  fs.writeFileSync(path.join(OUT, "tables.md"), md);
  console.log("\n" + md);
  console.log("wrote", OUT);
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
