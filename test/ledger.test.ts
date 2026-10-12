import { expect } from "chai";
import { Federation } from "../src/orchestrator/federation";
import { Ledger, RoundStatus, abortDigest, proposalDigest, reasonCode } from "../src/chain/ledger";
import { connect } from "../src/chain/provider";
import { closedRound, expectRevert, finalizeArgs, sigsFor } from "./helpers";
import { Proposal } from "../src/protocol";

type Agg = Extract<Proposal, { kind: "aggregate" }>;

describe("ledger / genesis and access control", () => {
  it("rejects validator sets that are not 3f+1, and double genesis", async () => {
    const chain = await connect();
    const L = await Ledger.deploy(chain.wallets[0]);
    const p = { pkHash: reasonCode("pk"), sharingRoot: reasonCode("r"), normBound: 1n, scale: 1n, beta0: 10n, tau: 1n, kMin: 1n, costScalarMul: 1n, costAdd: 1n, excludePolicy: false, carryBudget: false };
    const five = chain.wallets.slice(7, 12).map((w) => w.address);
    await expectRevert(L.send(chain.wallets[0], "initGenesis", (c) => c.initGenesis(p, five)), "validators must be 3f+1");
    await expectRevert(L.send(chain.wallets[0], "initGenesis", (c) => c.initGenesis({ ...p, beta0: 1n }, five.slice(0, 4))), "bad params");
    await L.send(chain.wallets[0], "initGenesis", (c) => c.initGenesis(p, five.slice(0, 4)));
    await expectRevert(L.send(chain.wallets[0], "initGenesis", (c) => c.initGenesis(p, five.slice(0, 4))), "genesis done");
    expect(await L.f()).to.equal(1n);
    expect(await L.quorum()).to.equal(3n);
  });

  it("only the owner administers; only active hospitals submit; only validators close", async () => {
    const fed = await Federation.create({ bits: 128 });
    const W = fed.chain.wallets;
    await expectRevert(fed.ledger.send(W[1], "openRound", (c) => c.openRound()), "not owner");
    await expectRevert(fed.ledger.send(W[1], "registerHospital", (c) => c.registerHospital(W[9].address, 5)), "not owner");
    await fed.ledger.send(W[0], "openRound", (c) => c.openRound());
    const h = reasonCode("x");
    await expectRevert(fed.ledger.send(W[15], "submitUpdate", (c) => c.submitUpdate(1, h, h)), "not an active hospital");
    await expectRevert(fed.ledger.send(W[1], "closeSubmissions", (c) => c.closeSubmissions(1)), "not validator");
    await fed.ledger.send(W[1], "submitUpdate", (c) => c.submitUpdate(1, h, h));
    await expectRevert(fed.ledger.send(W[1], "submitUpdate", (c) => c.submitUpdate(1, h, h)), "already submitted");
    await expectRevert(fed.ledger.send(W[0], "openRound", (c) => c.openRound()), "round in progress");
  });
});

describe("ledger / quorum certificates (P2, P3, P5)", () => {
  let fed: Federation;
  let roundId: number;
  let p: Agg;
  before(async () => {
    fed = await Federation.create({ bits: 128, dataset: "pima" });
    roundId = await closedRound(fed);
    p = (await fed.validators[0].propose(0))[0] as Agg;
  });

  it("off-chain digest equals the contract's proposalDigest", async () => {
    const onchain = await fed.ledger.c.proposalDigest(p.roundId, p.view, p.inputsHash, p.aggCid, p.nS, p.betaNew);
    expect(onchain).to.equal(p.digest);
    expect(p.digest).to.equal(proposalDigest(fed.ledger.chainId, fed.ledger.address, BigInt(p.roundId), BigInt(p.view), p.inputsHash, p.aggCid, p.nS, p.betaNew));
  });
  it("2 signatures are not a quorum", async () => {
    const sigs = await sigsFor(fed, p.digest, [0, 1]);
    await expectRevert(fed.ledger.send(fed.validators[0].signer, "finalizeRound", (c) => c.finalizeRound(finalizeArgs(p), sigs)), "quorum not reached");
  });
  it("a duplicated signer is not counted twice", async () => {
    const s = await sigsFor(fed, p.digest, [0, 1]);
    await expectRevert(fed.ledger.send(fed.validators[0].signer, "finalizeRound", (c) => c.finalizeRound(finalizeArgs(p), [s[0], s[1], s[1]])), "duplicate signer");
  });
  it("signatures from non-validators are rejected", async () => {
    const s = await sigsFor(fed, p.digest, [0, 1]);
    const { signDigest } = await import("../src/chain/ledger");
    const bad = await signDigest(fed.chain.wallets[1], p.digest);
    await expectRevert(fed.ledger.send(fed.validators[0].signer, "finalizeRound", (c) => c.finalizeRound(finalizeArgs(p), [...s, bad])), "signer not validator");
  });
  it("2f+1 signatures that exclude the primary of the view are rejected", async () => {
    const s = await sigsFor(fed, p.digest, [1, 2, 3]);
    await expectRevert(fed.ledger.send(fed.validators[0].signer, "finalizeRound", (c) => c.finalizeRound(finalizeArgs(p), s)), "primary of view did not sign");
  });
  it("a certificate over a different proposal does not authorise this one (tampered aggregate hash)", async () => {
    const s = await sigsFor(fed, p.digest, [0, 1, 2]);
    const args = { ...finalizeArgs(p), aggHash: reasonCode("other aggregate") };
    await expectRevert(fed.ledger.send(fed.validators[0].signer, "finalizeRound", (c) => c.finalizeRound(args, s)), "signer not validator");
  });
  it("P5: a quorum over a wrong noise budget is refused", async () => {
    const wrong = proposalDigest(fed.ledger.chainId, fed.ledger.address, BigInt(roundId), 0n, p.inputsHash, p.aggCid, p.nS, p.betaNew + 1n);
    const s = await sigsFor(fed, wrong, [0, 1, 2]);
    await expectRevert(fed.ledger.send(fed.validators[0].signer, "finalizeRound", (c) => c.finalizeRound({ ...finalizeArgs(p), betaNew: p.betaNew + 1n }, s)), "wrong noise budget");
  });
  it("the inclusion set must be strictly ascending and made of real submissions", async () => {
    const rev = [...p.included].reverse();
    const s = await sigsFor(fed, p.digest, [0, 1, 2]);
    await expectRevert(fed.ledger.send(fed.validators[0].signer, "finalizeRound", (c) => c.finalizeRound({ ...finalizeArgs(p), included: rev }, s)), "included not ascending");
    const stranger = [fed.chain.wallets[15].address, ...p.included].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
    await expectRevert(fed.ledger.send(fed.validators[0].signer, "finalizeRound", (c) => c.finalizeRound({ ...finalizeArgs(p), included: stranger }, s)), "included without submission");
  });
  it("abort policy: a quorum-signed proposal that drops a submission is refused by the contract", async () => {
    const dropped = p.included.slice(1);
    const inputs = (await import("../src/chain/ledger")).inputsHashOf(
      await Promise.all(dropped.map(async (h) => ({ hospital: h, ...(await fed.ledger.getSubmission(roundId, h)) })))
    );
    const beta = await fed.ledger.expectedBeta(dropped.length);
    const d = proposalDigest(fed.ledger.chainId, fed.ledger.address, BigInt(roundId), 0n, inputs, p.aggCid, 1n, beta);
    const s = await sigsFor(fed, d, [0, 1, 2]);
    await expectRevert(fed.ledger.send(fed.validators[0].signer, "finalizeRound", (c) => c.finalizeRound({ ...finalizeArgs(p), included: dropped, betaNew: beta }, s)), "abort policy: must include all");
  });
  it("the honest 2f+1 certificate finalizes; replay is refused; decryption gating works", async () => {
    const s = await sigsFor(fed, p.digest, [0, 1, 3]);
    await fed.ledger.send(fed.validators[0].signer, "finalizeRound", (c) => c.finalizeRound(finalizeArgs(p), s));
    expect((await fed.ledger.getRound(roundId)).status).to.equal(RoundStatus.Finalized);
    await expectRevert(fed.ledger.send(fed.validators[0].signer, "finalizeRound", (c) => c.finalizeRound(finalizeArgs(p), s)), "wrong round status");
    const W = fed.chain.wallets;
    await expectRevert(fed.ledger.send(W[9], "postDecryptionShare", (c) => c.postDecryptionShare(roundId, reasonCode("s"))), "not committee member");
    await fed.ledger.send(W[1], "postDecryptionShare", (c) => c.postDecryptionShare(roundId, reasonCode("s1")));
    await expectRevert(fed.ledger.send(W[1], "postDecryptionShare", (c) => c.postDecryptionShare(roundId, reasonCode("s1"))), "share already posted");
    await expectRevert(fed.ledger.send(W[1], "publishModel", (c) => c.publishModel(roundId, reasonCode("m"))), "threshold not reached");
  });
  it("abortRound needs 2f+1 signatures over the abort digest", async () => {
    const fed2 = await Federation.create({ bits: 128, dataset: "pima" });
    const r = await closedRound(fed2);
    const reason = reasonCode("test");
    const d = abortDigest(fed2.ledger.chainId, fed2.ledger.address, BigInt(r), 0n, reason);
    await expectRevert(fed2.ledger.send(fed2.validators[0].signer, "abortRound", (c) => c.abortRound(r, 0, reason, [])), "quorum not reached");
    const s = await sigsFor(fed2, d, [0, 1, 2]);
    await fed2.ledger.send(fed2.validators[0].signer, "abortRound", (c) => c.abortRound(r, 0, reason, s));
    expect((await fed2.ledger.getRound(r)).status).to.equal(RoundStatus.Aborted);
  });
});

describe("ledger / committee gating (P4)", () => {
  it("a membership change blocks new rounds until the committee is rotated", async () => {
    const fed = await Federation.create({ bits: 128, dataset: "pima", reserve: 1 });
    await fed.runRound();
    await fed.addHospital(5);
    await expectRevert(fed.ledger.send(fed.chain.wallets[0], "openRound", (c) => c.openRound()), "rotate committee first");
    await fed.rotateCommittee();
    const rep = await fed.runRound();
    expect(rep.status).to.equal("decrypted");
    expect(rep.hospitals.length).to.equal(6);
  });
});
