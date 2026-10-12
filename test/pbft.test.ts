import { expect } from "chai";
import { Federation } from "../src/orchestrator/federation";
import { fedAvgRound } from "../src/ml/logreg";
import { RoundStatus } from "../src/chain/ledger";
import { ValidatorFault } from "../src/config";

const BASE = { bits: 128, dataset: "pima" as const };

async function oneRound(faults: Record<number, ValidatorFault>, cfg: any = {}) {
  const fed = await Federation.create({ ...BASE, ...cfg });
  const rep = await fed.runRound({ validatorFaults: faults });
  const ref = fedAvgRound(new Array(fed.dim).fill(0), fed.data.shards.slice(0, 5), fed.cfg.train, fed.cfg.normBound);
  const err = Math.max(...fed.w.map((x, j) => Math.abs(x - ref[j])));
  return { fed, rep, err };
}

describe("PBFT / normal operation", () => {
  it("honest validators decide in view 0 with 2f+1 commits; result equals plaintext FedAvg", async () => {
    const { rep, err } = await oneRound({});
    expect(rep.status).to.equal("decrypted");
    expect(rep.finalView).to.equal(0);
    expect(err).to.be.lessThan(1e-5); // only the quantisation error 1/(2s) per coordinate
    // pre-prepare (4) + prepare (3 backups x 4) + commit (4 x 4) = 4+12+16 messages, minus self-deliveries
    expect(rep.networkMessages).to.equal(3 + 3 * 3 + 4 * 3);
  });
  it("tolerates f = 1 crashed backup", async () => {
    const { rep } = await oneRound({ 3: "silent" });
    expect(rep.status).to.equal("decrypted");
    expect(rep.finalView).to.equal(0);
  });
  it("tolerates a backup that sends garbage commit signatures", async () => {
    const { rep } = await oneRound({ 2: "bad-signature" });
    expect(rep.status).to.equal("decrypted");
    expect(rep.finalView).to.equal(0);
    expect(rep.rejections.some((r) => /invalid COMMIT signature/.test(r.reason))).to.equal(true);
  });
});

describe("PBFT / Byzantine primary -> view change to an honest primary", () => {
  const cases: [string, ValidatorFault, RegExp][] = [
    ["a primary that tampers with ct_Sigma", "bad-aggregate", /recomputed ct_Sigma differs/],
    ["a primary that proposes a wrong noise budget", "wrong-budget", /noise budget/],
    ["a primary that equivocates", "equivocate", /recomputed ct_Sigma differs/],
    ["a crashed primary", "silent", /^$/],
    ["a primary whose own signature is invalid", "bad-signature", /^$/],
  ];
  for (const [name, fault, re] of cases) {
    it(`survives ${name}`, async () => {
      const { rep, err, fed } = await oneRound({ 0: fault });
      expect(rep.status).to.equal("decrypted");
      expect(rep.finalView).to.be.greaterThan(0); // V1 took over
      expect(err).to.be.lessThan(1e-5); // the finalized aggregate is the CORRECT one
      if (re.source !== "^$") expect(rep.rejections.some((r) => re.test(r.reason))).to.equal(true);
      expect((await fed.ledger.getRound(1)).status).to.equal(RoundStatus.Decrypted);
      expect((await fed.ledger.getRound(1)).viewNo).to.equal(BigInt(rep.finalView));
    });
  }
  it("a censoring primary is rejected (exclude-and-continue policy)", async () => {
    const { rep, err } = await oneRound({ 0: "censor" }, { excludePolicy: true });
    expect(rep.status).to.equal("decrypted");
    expect(rep.finalView).to.be.greaterThan(0);
    expect(rep.included.length).to.equal(5);
    expect(err).to.be.lessThan(1e-5);
    expect(rep.rejections.some((r) => /omits valid submission/.test(r.reason))).to.equal(true);
  });
  it("a censoring primary is rejected (abort policy)", async () => {
    const { rep } = await oneRound({ 0: "censor" });
    expect(rep.status).to.equal("decrypted");
    expect(rep.included.length).to.equal(5);
    expect(rep.finalView).to.be.greaterThan(0);
  });
  it("two consecutive bad primaries need two view changes", async () => {
    const { rep, err } = await oneRound({ 0: "bad-aggregate", 1: "wrong-budget" });
    expect(rep.status).to.equal("decrypted");
    expect(rep.finalView).to.equal(2);
    expect(err).to.be.lessThan(1e-5);
  });
});

describe("PBFT / beyond f faults: safety holds, liveness is lost", () => {
  it("with 2 of 4 validators crashed the round stalls and nothing is finalized", async () => {
    const fed = await Federation.create({ ...BASE });
    const rep = await fed.runRound({ validatorFaults: { 2: "silent", 3: "silent" } });
    expect(rep.status).to.equal("stalled");
    expect((await fed.ledger.getRound(1)).status).to.equal(RoundStatus.Closed);
    expect(fed.w.every((x) => x === 0)).to.equal(true);
  });
  it("a Byzantine primary plus a crashed next primary: two view changes, still the correct aggregate", async () => {
    const fed = await Federation.create({ ...BASE });
    const rep = await fed.runRound({ validatorFaults: { 0: "bad-aggregate", 1: "silent" } });
    // view 0: V0 tampers; view 1: V1 is crashed; view 2: V2 is honest and the 3 live validators finish
    expect(rep.status).to.equal("decrypted");
    expect(rep.finalView).to.equal(2);
    const ref = fedAvgRound(new Array(fed.dim).fill(0), fed.data.shards.slice(0, 5), fed.cfg.train, fed.cfg.normBound);
    expect(Math.max(...fed.w.map((x, j) => Math.abs(x - ref[j])))).to.be.lessThan(1e-5);
  });
});

describe("PBFT / larger validator set", () => {
  it("7 validators (f=2) tolerate 2 faulty replicas including the primary", async () => {
    const { rep, err } = await oneRound({ 0: "bad-aggregate", 5: "silent" }, { validators: 7 });
    expect(rep.status).to.equal("decrypted");
    expect(rep.finalView).to.be.greaterThan(0);
    expect(err).to.be.lessThan(1e-5);
  });
});
