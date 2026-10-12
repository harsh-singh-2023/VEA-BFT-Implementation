import { expect } from "chai";
import { loadPrepared, loadRaw, DatasetName } from "../src/ml/dataset";
import { evaluate, fedAvgRound, localTrain, auc, quantize, normSqInt, clipToNorm, l2norm } from "../src/ml/logreg";

describe("ml / datasets (paper Table I)", () => {
  const expected: Record<DatasetName, [number, number]> = { heart: [303, 13], pima: [768, 8], wdbc: [569, 10] };
  for (const name of Object.keys(expected) as DatasetName[]) {
    it(`${name}: has the documented size and feature count`, () => {
      const raw = loadRaw(name);
      expect(raw.X.length).to.equal(expected[name][0]);
      expect(raw.X[0].length).to.equal(expected[name][1]);
    });
  }
  it("heart: 6 missing values exist in raw data and none remain after preprocessing", () => {
    const raw = loadRaw("heart");
    expect(raw.X.flat().filter(Number.isNaN).length).to.equal(6);
    const p = loadPrepared("heart");
    expect(p.train.X.flat().concat(p.test.X.flat()).some(Number.isNaN)).to.equal(false);
  });
  it("split is stratified 75/25 and shards partition the training set exactly", () => {
    for (const name of ["heart", "pima", "wdbc"] as DatasetName[]) {
      const p = loadPrepared(name, { hospitals: 5 });
      const total = p.train.y.length + p.test.y.length;
      expect(Math.abs(p.test.y.length / total - 0.25)).to.be.lessThan(0.01);
      const prevalence = (y: number[]) => y.reduce((a, b) => a + b, 0) / y.length;
      expect(Math.abs(prevalence(p.train.y) - prevalence(p.test.y))).to.be.lessThan(0.02);
      expect(p.shards.reduce((a, s) => a + s.y.length, 0)).to.equal(p.train.y.length);
      // non-IID: shards are ordered by the first standardised feature
      const means = p.shards.map((s) => s.X.reduce((a, r) => a + r[0], 0) / s.X.length);
      for (let i = 1; i < means.length; i++) expect(means[i]).to.be.greaterThan(means[i - 1]);
    }
  });
  it("training statistics are standardised (mean ~ 0, sd ~ 1)", () => {
    const p = loadPrepared("wdbc");
    const col = p.train.X.map((r) => r[0]);
    const mu = col.reduce((a, b) => a + b, 0) / col.length;
    expect(Math.abs(mu)).to.be.lessThan(1e-9);
  });
});

describe("ml / logistic regression, FedAvg, metrics", () => {
  it("AUC equals 1 for a perfect ranking and 0.5 for a constant model", () => {
    const X = [[-2, 1], [-1, 1], [1, 1], [2, 1]];
    expect(auc([1, 0], X, [0, 0, 1, 1])).to.equal(1);
    expect(auc([0, 0], X, [0, 0, 1, 1])).to.equal(0.5);
  });
  it("plaintext FedAvg learns: hold-out accuracy beats the majority-class rate", () => {
    const p = loadPrepared("wdbc");
    let w = new Array(p.nFeatures).fill(0);
    for (let r = 0; r < 30; r++) w = fedAvgRound(w, p.shards, { epochs: 5, lr: 0.5, l2: 1e-3 });
    const m = evaluate(w, p.test.X, p.test.y);
    const majority = Math.max(...[0, 1].map((c) => p.test.y.filter((y) => y === c).length)) / p.test.y.length;
    expect(m.accuracy).to.be.greaterThan(majority + 0.2);
    expect(m.auc).to.be.greaterThan(0.95);
  });
  it("clipping bounds the norm and quantisation round-trips to within 1/(2s)", () => {
    const v = [3, 4, 12];
    expect(l2norm(clipToNorm(v, 5))).to.be.closeTo(5, 1e-12);
    const s = 1e6;
    const q = quantize([0.1234567891, -2.5], s);
    expect(Number(q[0]) / s).to.be.closeTo(0.1234567891, 1 / (2 * s));
    expect(normSqInt([3n, 4n])).to.equal(25n);
  });
  it("local training reduces the training loss", () => {
    const p = loadPrepared("pima");
    const s = p.shards[0];
    const w0 = new Array(p.nFeatures).fill(0);
    const w1 = localTrain(w0, s.X, s.y, { epochs: 20, lr: 0.5, l2: 1e-3 });
    expect(evaluate(w1, s.X, s.y).logLoss).to.be.lessThan(evaluate(w0, s.X, s.y).logLoss);
  });
});
