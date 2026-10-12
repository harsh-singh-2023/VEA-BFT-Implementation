import { expect } from "chai";
import { Federation } from "../src/orchestrator/federation";
import { fedAvgRound, localTrain, l2norm } from "../src/ml/logreg";
import { RoundStatus } from "../src/chain/ledger";
import { canonicalize } from "../src/storage/serialize";
import { MemoryStore } from "../src/storage/contentStore";
import { expectRevert } from "./helpers";

const BASE = { bits: 128, dataset: "heart" as const };
const maxDiff = (a: number[], b: number[]) => Math.max(...a.map((x, j) => Math.abs(x - b[j])));

describe("federation / honest training", () => {
  it("5 rounds of VEA-BFT track plaintext FedAvg to within quantisation error; every round audits clean", async () => {
    const fed = await Federation.create(BASE);
    let ref = new Array(fed.dim).fill(0);
    for (let r = 1; r <= 5; r++) {
      const rep = await fed.runRound();
      expect(rep.status).to.equal("decrypted");
      ref = fedAvgRound(ref, fed.data.shards.slice(0, 5), fed.cfg.train, fed.cfg.normBound);
      expect(maxDiff(fed.w, ref)).to.be.lessThan(5e-6 * r);
      const a = await fed.audit(r);
      expect(a.checks.filter((c) => !c.ok), JSON.stringify(a.checks.filter((c) => !c.ok))).to.have.length(0);
    }
    const plain = Federation.plaintextFedAvg(fed.data, fed.cfg, 5);
    expect(Math.abs(fed.history[4].metrics.logLoss - plain.curve[4].logLoss)).to.be.lessThan(1e-5);
  });
  it("only ciphertexts, proofs and the aggregate are ever stored off-chain; plaintext updates never are", async () => {
    const store = new MemoryStore();
    const fed = await Federation.create(BASE, { store });
    await fed.runRound();
    // 5 updates + 5 proofs + 1 aggregate + t share blobs + 1 model
    expect(store.size).to.equal(5 + 5 + 1 + fed.threshold + 1);
  });
  it("works with 256-bit Paillier (the paper's evaluation size)", async () => {
    const fed = await Federation.create({ ...BASE, bits: 256, dataset: "wdbc" });
    const rep = await fed.runRound();
    expect(rep.status).to.equal("decrypted");
    expect(fed.pkPub.bits).to.equal(256);
  });
});

describe("federation / adversarial hospitals (P3 robustness)", () => {
  it("paper scenario: a x50 update is rejected and the abort policy leaves w unchanged", async () => {
    const fed = await Federation.create(BASE);
    await fed.runRound();
    const before = fed.w.slice();
    const rep = await fed.runRound({ behaviors: { 0: "oversize" }, attackFactor: 50 });
    expect(rep.status).to.equal("aborted");
    expect(rep.abortReason).to.equal("invalid-submission");
    expect(rep.hospitals[0].reject).to.match(/norm bound exceeded/);
    expect(rep.hospitals.slice(1).every((h) => !h.reject)).to.equal(true);
    expect(fed.w).to.deep.equal(before);
    expect((await fed.ledger.getRound(2)).status).to.equal(RoundStatus.Aborted);
    expect((await fed.audit(2)).ok).to.equal(true);
    // the next round proceeds normally (one malicious hospital can delay but not corrupt the model)
    expect((await fed.runRound()).status).to.equal("decrypted");
  });
  it("exclude-and-continue drops only the offender and the round still produces a model", async () => {
    const fed = await Federation.create({ ...BASE, excludePolicy: true });
    const rep = await fed.runRound({ behaviors: { 0: "oversize" } });
    expect(rep.status).to.equal("decrypted");
    expect(rep.included).to.have.length(4);
    expect(rep.included).to.not.include("H1");
    // equals plaintext FedAvg over the remaining four hospitals
    const ref = fedAvgRound(new Array(fed.dim).fill(0), fed.data.shards.slice(1, 5), fed.cfg.train, fed.cfg.normBound);
    expect(maxDiff(fed.w, ref)).to.be.lessThan(5e-6);
    expect((await fed.audit(1)).ok).to.equal(true);
  });
  it("a copied (replayed) submission cannot be proven: the proof is bound to the hospital", async () => {
    const fed = await Federation.create({ ...BASE, excludePolicy: true });
    const rep = await fed.runRound({ behaviors: { 1: "replay" } });
    expect(rep.hospitals[1].reject).to.match(/proof of knowledge failed/);
    expect(rep.included).to.not.include("H2");
  });
  it("random group elements instead of ciphertexts are rejected", async () => {
    const fed = await Federation.create({ ...BASE, excludePolicy: true });
    const rep = await fed.runRound({ behaviors: { 2: "malformed" } });
    expect(rep.hospitals[2].reject).to.be.a("string");
    expect(rep.included).to.not.include("H3");
    expect(rep.status).to.equal("decrypted");
  });
  it("LIMITATION: a hospital that lies about its norm is NOT caught (stand-in range check)", async () => {
    const fed = await Federation.create({ ...BASE, excludePolicy: true });
    const rep = await fed.runRound({ behaviors: { 0: "lie-norm" }, attackFactor: 50 });
    expect(rep.status).to.equal("decrypted");
    expect(rep.included).to.include("H1"); // poisoned update accepted: needs a real range proof
    const honest = fedAvgRound(new Array(fed.dim).fill(0), fed.data.shards.slice(0, 5), fed.cfg.train, fed.cfg.normBound);
    expect(maxDiff(fed.w, honest)).to.be.greaterThan(1e-3);
  });
  it("a hospital that is offline is simply absent; below k_min the round aborts", async () => {
    const fed = await Federation.create({ ...BASE, excludePolicy: true });
    const ok = await fed.runRound({ behaviors: { 4: "offline" } });
    expect(ok.status).to.equal("decrypted");
    expect(ok.included).to.have.length(4);
    const bad = await fed.runRound({ behaviors: { 2: "offline", 3: "offline", 4: "offline" } });
    expect(bad.status).to.equal("aborted");
    expect(bad.abortReason).to.equal("below-k_min");
  });
  it("update norms of honest hospitals stay inside B (no honest hospital is rejected)", async () => {
    const fed = await Federation.create(BASE);
    for (const s of fed.data.shards) {
      const d = localTrain(new Array(fed.dim).fill(0), s.X, s.y, fed.cfg.train);
      expect(l2norm(d)).to.be.lessThan(fed.cfg.normBound);
    }
  });
});

describe("federation / decryption committee", () => {
  it("up to m - t members may be offline", async () => {
    const fed = await Federation.create(BASE); // 3-of-5
    const rep = await fed.runRound({ offlineCommittee: [1, 2] });
    expect(rep.status).to.equal("decrypted");
  });
  it("with more than m - t members offline the model is not updated (confidentiality over liveness)", async () => {
    const fed = await Federation.create(BASE);
    const rep = await fed.runRound({ offlineCommittee: [1, 2, 3] });
    expect(rep.status).to.equal("finalized"); // certificate is on-chain, but fewer than t members could decrypt
    expect(fed.w.every((x) => x === 0)).to.equal(true);
    expect((await fed.ledger.getRound(1)).status).to.equal(RoundStatus.Finalized);
  });
  it("a member that sends an invalid decryption share is detected and skipped", async () => {
    const fed = await Federation.create(BASE);
    const rep = await fed.runRound({ badShareMembers: [1] });
    expect(rep.status).to.equal("decrypted");
    expect(rep.decryptNotes.join(" ")).to.match(/member 1: decryption share failed its proof/);
    const ref = fedAvgRound(new Array(fed.dim).fill(0), fed.data.shards.slice(0, 5), fed.cfg.train, fed.cfg.normBound);
    expect(maxDiff(fed.w, ref)).to.be.lessThan(5e-6);
  });
});

describe("federation / committee rotation (P4)", () => {
  it("a hospital joins: committee grows 3-of-5 -> 4-of-6, same public key, training continues", async () => {
    const fed = await Federation.create({ ...BASE, reserve: 1 });
    await fed.runRound();
    const pkBefore = fed.pkPub.n;
    await fed.addHospital(5);
    const rot = await fed.rotateCommittee();
    expect([rot.n, rot.t, rot.epoch]).to.deep.equal([6, 4, 2]);
    expect(fed.pkPub.n).to.equal(pkBefore);
    const rep = await fed.runRound();
    expect(rep.status).to.equal("decrypted");
    expect(rep.hospitals).to.have.length(6);
    expect(rep.epoch).to.equal(2);
    const a = await fed.audit(2);
    expect(a.checks.filter((c) => !c.ok)).to.have.length(0);
  });
  it("a hospital leaves: committee shrinks, and ciphertexts from before still decrypt (audit of an old round)", async () => {
    const fed = await Federation.create(BASE);
    await fed.runRound();
    await fed.removeHospital(4);
    await fed.rotateCommittee();
    expect(fed.pub.n).to.equal(4);
    expect((await fed.runRound()).status).to.equal("decrypted");
    expect((await fed.audit(1)).ok, "old round, old epoch").to.equal(true);
    expect((await fed.audit(2)).ok, "new round, new epoch").to.equal(true);
  });
  it("a dealer that sends corrupted sub-shares is detected, excluded, and resharing succeeds", async () => {
    const fed = await Federation.create({ ...BASE, reserve: 1 });
    await fed.addHospital(5);
    await fed.rotateCommittee({ faultyDealers: [1] });
    expect((await fed.runRound()).status).to.equal("decrypted");
    expect(fed.events.some((e) => /old member 1 failed verification/.test(e.msg))).to.equal(true);
  });
  it("two rotations in a row (join, then leave)", async () => {
    const fed = await Federation.create({ ...BASE, reserve: 1 });
    await fed.runRound();
    await fed.addHospital(5);
    await fed.rotateCommittee();
    await fed.runRound();
    await fed.removeHospital(0);
    await fed.rotateCommittee();
    expect((await fed.runRound()).status).to.equal("decrypted");
    for (const r of [1, 2, 3]) expect((await fed.audit(r)).ok, `round ${r}`).to.equal(true);
  });
});

describe("federation / noise budget (P5)", () => {
  const cfg = { ...BASE, carryBudget: true, beta0: 100, tau: 20, costScalarMul: 5, costAdd: 1 }; // 29 per round
  it("the ledger-tracked budget falls each round and exhaustion aborts; bootstrapping restores it", async () => {
    const fed = await Federation.create(cfg);
    const betas: number[] = [];
    for (let r = 1; r <= 2; r++) {
      const rep = await fed.runRound();
      expect(rep.status).to.equal("decrypted");
      betas.push(rep.beta);
    }
    expect(betas).to.deep.equal([71, 42]); // 100 - 29, then 71 - 29
    // a 3rd round would leave 42 - 29 = 13 < tau = 20: no validator will sign it and the contract would refuse it
    const bad = await fed.runRound();
    expect(bad.status).to.equal("aborted");
    expect(bad.abortReason).to.equal("noise-budget-exhausted");
    expect(await fed.ledger.noiseBudget()).to.equal(42n);
    await fed.bootstrapNoise();
    expect(await fed.ledger.noiseBudget()).to.equal(100n);
    expect((await fed.runRound()).status).to.equal("decrypted");
  });
});

describe("federation / audit and tamper evidence", () => {
  it("an auditor detects tampering with stored content (hash mismatch)", async () => {
    const store = new MemoryStore();
    const fed = await Federation.create(BASE, { store });
    await fed.runRound();
    expect((await fed.audit(1)).ok).to.equal(true);
    const sub = await fed.ledger.getSubmission(1, fed.hospitals[0].address);
    store.tamper(sub.ctHash, canonicalize({ round: 1, hospital: fed.hospitals[0].address, cts: [1n] }));
    const a = await fed.audit(1);
    expect(a.ok).to.equal(false);
    expect(a.checks.find((c) => !c.ok)!.detail).to.match(/hash mismatch/);
  });
  it("the ledger refuses lifecycle calls that arrive out of order", async () => {
    const fed = await Federation.create(BASE);
    await expectRevert(fed.ledger.send(fed.chain.wallets[0], "publishModel", (c) => c.publishModel(1, "0x" + "00".repeat(32))), "wrong round status");
  });
});
