/**
 * The federation: wires hospitals, validators, the decryption committee, the content store and
 * the ledger together and runs VEA-BFT rounds (paper Algorithm 1) plus committee rotation,
 * noise-budget bootstrapping and independent audit/replay.
 */
import { keccak256 } from "ethers";
import { Behavior, SimConfig, ValidatorFault, withDefaults } from "../config";
import { ChainConn, connect } from "../chain/provider";
import { Ledger, RoundStatus, TxRecord, bootstrapDigest, inputsHashOf, signDigest } from "../chain/ledger";
import { bigToBytes } from "../crypto/bigmath";
import { PaillierPublicKey, ZERO_CIPHERTEXT, add, scalarMul } from "../crypto/paillier";
import { verifyVector } from "../crypto/sigma";
import {
  DecryptionShare, KeyShare, ReshareDeal, ThresholdPublic, combineShares, commitmentRoot, dealerSetup, dealsRoot,
  finishReshare, nextPublic, partialDecrypt, reshareDeal, verifyDeal, verifyDecryptionShare,
} from "../crypto/threshold";
import { Hospital, SubmitResult } from "../nodes/hospital";
import { ValidatorNode } from "../nodes/validator";
import { CommitteeMember } from "../nodes/committee";
import { LogEntry, runConsensus } from "../consensus/pbft";
import { Metrics, evaluate, fedAvgRound } from "../ml/logreg";
import { Prepared, loadPrepared } from "../ml/dataset";
import { ContentStore, MemoryStore, cidOf } from "../storage/contentStore";
import { canonicalize, parse } from "../storage/serialize";
import { AggBlob, ModelBlob, ProofBlob, ShareBlob, Timer, UpdateBlob, addrCmp, timed } from "../protocol";

export interface RoundOptions {
  /** hospital index -> behaviour, for this round only */
  behaviors?: Record<number, Behavior>;
  /** validator index -> fault, for this round only */
  validatorFaults?: Record<number, ValidatorFault>;
  /** committee member indices (1-based) that are offline during decryption */
  offlineCommittee?: number[];
  /** committee member indices (1-based) that send a corrupted decryption share */
  badShareMembers?: number[];
  attackFactor?: number;
}

export interface RoundReport {
  round: number;
  /** finalized = quorum certificate on-chain but the committee could not decrypt (model unchanged); stalled = no consensus */
  status: "decrypted" | "aborted" | "finalized" | "stalled";
  abortReason?: string;
  finalView: number;
  networkMessages: number;
  rejections: { replica: number; view: number; reason: string }[];
  hospitals: { name: string; address: string; behavior: Behavior; submitted: boolean; honestNorm?: number; sentNorm?: number; included: boolean; reject?: string }[];
  included: string[];
  nS: number;
  beta: number;
  epoch: number;
  metrics: Metrics;
  /** ms, summed over all nodes of that kind unless noted */
  timers: Timer;
  gas: number;
  txs: number;
  consensusLog: LogEntry[];
  decryptNotes: string[];
}

export interface EpochPublicLog { epoch: number; deals: bigint[][]; members: string[]; threshold: number }

export type FedEvent = { t: number; kind: string; msg: string; data?: any };

export class Federation {
  cfg!: SimConfig;
  chain!: ChainConn;
  ledger!: Ledger;
  store!: ContentStore;
  data!: Prepared;
  hospitals: Hospital[] = [];
  validators: ValidatorNode[] = [];
  pkPub!: PaillierPublicKey;
  genesisPub!: ThresholdPublic;
  genesisCommitments!: bigint[];
  pub!: ThresholdPublic;
  committee: CommitteeMember[] = [];
  epochLog: EpochPublicLog[] = [];
  w: number[] = [];
  dim = 0;
  history: RoundReport[] = [];
  events: FedEvent[] = [];
  listeners: ((e: FedEvent) => void)[] = [];
  private active = new Set<number>();
  private rounds = 0;

  static async create(config: Partial<SimConfig> = {}, opts: { chain?: ChainConn; store?: ContentStore } = {}): Promise<Federation> {
    const f = new Federation();
    const cfg = (f.cfg = withDefaults(config));
    const reserve = cfg.reserve ?? 0;
    if (cfg.hospitals + reserve > 6) throw new Error("at most 6 hospital accounts (hardhat accounts 1..6)");
    if (cfg.validators < 4 || (cfg.validators - 1) % 3 !== 0 || cfg.validators > 13) throw new Error("validators must be 3f+1 in [4,13]");
    f.chain = opts.chain ?? (await connect());
    f.store = opts.store ?? new MemoryStore();
    f.data = loadPrepared(cfg.dataset, { seed: cfg.seed, hospitals: cfg.hospitals + reserve });
    f.dim = f.data.nFeatures;
    f.w = new Array(f.dim).fill(0);
    const W = f.chain.wallets;
    f.hospitals = f.data.shards.map((s, i) => new Hospital(i, `H${i + 1}`, W[1 + i], W[1 + i].address, s));
    f.validators = Array.from({ length: cfg.validators }, (_, i) => new ValidatorNode(i, W[7 + i], W[7 + i].address, cfg, null as any, f.store, null as any, f.dim));

    const m = cfg.hospitals;
    const t = cfg.committeeThreshold ?? Math.floor(m / 2) + 1;
    const t0 = performance.now();
    const deal = dealerSetup({ bits: cfg.bits, n: m, t });
    f.emit("setup", `Distributed key generation (trusted-dealer simplification): ${cfg.bits}-bit Paillier, committee ${t}-of-${m} (${(performance.now() - t0).toFixed(0)} ms)`);
    f.pkPub = deal.pub.pk;
    f.genesisPub = f.pub = deal.pub;
    f.genesisCommitments = deal.commitments;
    f.ledger = await Ledger.deploy(W[0], (r) => f.onTx(r));
    for (const v of f.validators) (v as any).ledger = f.ledger, (v as any).pk = f.pkPub;
    const root = commitmentRoot([deal.commitments]);
    const normBound = BigInt(Math.round(cfg.normBound * cfg.scale)) + BigInt(f.dim); // + rounding slack of the quantiser
    await f.ledger.send(W[0], "initGenesis", (c) =>
      c.initGenesis(
        {
          pkHash: keccak256(bigToBytes(f.pkPub.n)), sharingRoot: root, normBound, scale: BigInt(cfg.scale), beta0: BigInt(cfg.beta0),
          tau: BigInt(cfg.tau), kMin: BigInt(cfg.kMin), costScalarMul: BigInt(cfg.costScalarMul), costAdd: BigInt(cfg.costAdd),
          excludePolicy: cfg.excludePolicy, carryBudget: cfg.carryBudget,
        },
        f.validators.map((v) => v.address)
      )
    );
    for (let i = 0; i < m; i++) {
      await f.ledger.send(W[0], "registerHospital", (c) => c.registerHospital(f.hospitals[i].address, f.hospitals[i].nSamples));
      f.active.add(i);
    }
    await f.ledger.send(W[0], "installCommittee", (c) => c.installCommittee(f.hospitals.slice(0, m).map((h) => h.address), t, root));
    f.committee = deal.shares.map((s, i) => ({ hospital: i, address: f.hospitals[i].address, signer: f.hospitals[i].signer, index: s.index, share: s, online: true }));
    f.epochLog.push({ epoch: 1, deals: [deal.commitments], members: f.committee.map((c) => c.address), threshold: t });
    f.emit("setup", `Genesis on ${f.chain.kind} chain ${f.ledger.chainId}: ledger ${f.ledger.address}, ${cfg.validators} validators (f=${Math.floor((cfg.validators - 1) / 3)}), ${m} hospitals, policy=${cfg.excludePolicy ? "exclude-and-continue" : "abort"}`);
    return f;
  }

  // ------------------------------------------------------------ events
  on(l: (e: FedEvent) => void) {
    this.listeners.push(l);
  }
  emit(kind: string, msg: string, data?: any) {
    const e = { t: Date.now(), kind, msg, data };
    this.events.push(e);
    if (this.events.length > 5000) this.events.shift();
    for (const l of this.listeners) l(e);
  }
  private onTx(r: TxRecord) {
    this.emit("tx", `${r.name} gas=${r.gas} block=${r.block}`, r);
  }

  get activeHospitals(): Hospital[] {
    return [...this.active].sort((a, b) => a - b).map((i) => this.hospitals[i]);
  }
  get threshold() {
    return this.pub.t;
  }
  hospitalByAddress = (a: string) => this.hospitals.find((h) => h.address.toLowerCase() === a.toLowerCase());
  nameOf = (a: string) => this.hospitalByAddress(a)?.name ?? a.slice(0, 8);

  // ------------------------------------------------------------ one round
  /** Phase 1: open the round, hospitals train/encrypt/prove/submit, a validator closes submissions. */
  async beginRound(opts: RoundOptions = {}, timers: Timer = {}) {
    const cfg = this.cfg;
    const owner = this.chain.wallets[0];
    await this.ledger.send(owner, "openRound", (c) => c.openRound());
    const roundId = Number(await this.ledger.roundCounter());
    this.rounds = roundId;
    this.emit("round", `Round ${roundId} opened (epoch ${await this.ledger.currentEpoch()})`);

    for (const v of this.validators) {
      v.beginRound(roundId);
      v.timers = {};
      v.fault = opts.validatorFaults?.[v.index] ?? "honest";
    }
    for (const h of this.hospitals) {
      h.behavior = opts.behaviors?.[h.index] ?? "honest";
      if (opts.attackFactor) h.attackFactor = opts.attackFactor;
    }

    // hospitals work sequentially in this single-process simulation
    const results = new Map<number, SubmitResult>();
    const peers: { address: string; ctCid?: string; proofCid?: string }[] = [];
    for (const h of this.activeHospitals) {
      const r = await h.submit(cfg, this.ledger, this.store, this.pkPub, roundId, this.w, timers, peers);
      results.set(h.index, r);
      if (r.submitted && r.behavior === "honest") peers.push({ address: h.address, ctCid: r.ctCid, proofCid: r.proofCid });
      this.emit("submit", `${h.name} ${r.submitted ? "submitted" : "is offline"}${r.behavior !== "honest" ? ` [${r.behavior}]` : ""}`, { hospital: h.name, behavior: r.behavior, honestNorm: r.honestNorm, sentNorm: r.sentNorm });
    }
    const live = this.validators.find((v) => v.fault !== "silent")!;
    await this.ledger.send(live.signer, "closeSubmissions", (c) => c.closeSubmissions(roundId));
    return { roundId, results };
  }

  async runRound(opts: RoundOptions = {}): Promise<RoundReport> {
    const timers: Timer = {};
    const txStart = this.ledger.txs.length;
    const t0 = performance.now();
    const { roundId, results } = await this.beginRound(opts, timers);
    const live = this.validators.find((v) => v.fault !== "silent")!;

    // --- validators run PBFT
    const consensus = await runConsensus(this.validators, roundId);
    timers.consensus = consensus.ms;
    for (const rj of consensus.rejections) this.emit("reject", `validator ${rj.replica} (view ${rj.view}) rejected: ${rj.reason}`, rj);
    if (consensus.finalView > 0) this.emit("view-change", `View change: consensus needed view ${consensus.finalView} (primary V${consensus.finalView % this.validators.length})`);
    this.emit("consensus", `PBFT ${consensus.decision ? "decided" : "FAILED"} in view ${consensus.finalView}, ${consensus.networkMessages} network messages`, { log: consensus.log.length });

    const rep: RoundReport = {
      round: roundId, status: "stalled", finalView: consensus.finalView, networkMessages: consensus.networkMessages, rejections: consensus.rejections,
      hospitals: this.activeHospitals.map((h) => ({ name: h.name, address: h.address, behavior: h.behavior, submitted: results.get(h.index)!.submitted, honestNorm: results.get(h.index)!.honestNorm, sentNorm: results.get(h.index)!.sentNorm, included: false })),
      included: [], nS: 0, beta: 0, epoch: Number(await this.ledger.currentEpoch()), metrics: evaluate(this.w, this.data.test.X, this.data.test.y),
      timers, gas: 0, txs: 0, consensusLog: consensus.log, decryptNotes: [],
    };

    const dec = consensus.decision;
    if (dec) {
      const sigs = dec.sigs.map((s) => s.sig);
      const submitter = this.validators.find((v) => v.fault === "honest") ?? live;
      const p = dec.proposal;
      if (p.kind === "abort") {
        await this.ledger.send(submitter.signer, "abortRound", (c) => c.abortRound(roundId, p.view, p.reason, sigs));
        rep.status = "aborted";
        rep.abortReason = p.reasonText;
        // record which hospitals the validators found invalid
        const exp = await this.validators.find((v) => v.fault === "honest")!.expected();
        for (const bad of exp.inspection.invalid) {
          const row = rep.hospitals.find((x) => x.address === bad.hospital);
          if (row) row.reject = bad.reason;
        }
        this.emit("aborted", `Round ${roundId} ABORTED (${p.reasonText}); global model unchanged`, rep.hospitals.filter((x) => x.reject));
      } else {
        const ts = performance.now();
        await this.ledger.send(submitter.signer, "finalizeRound", (c) =>
          c.finalizeRound({ roundId, viewNo: p.view, included: p.included, aggHash: p.aggCid, betaNew: p.betaNew }, sigs)
        );
        timers.finalizeTx = performance.now() - ts;
        rep.status = "finalized";
        rep.included = p.included.map(this.nameOf);
        for (const row of rep.hospitals) row.included = p.included.some((a) => a.toLowerCase() === row.address.toLowerCase());
        const exp = await this.validators.find((v) => v.fault === "honest")!.expected();
        for (const bad of exp.inspection.invalid) {
          const row = rep.hospitals.find((x) => x.address === bad.hospital);
          if (row) row.reject = bad.reason;
        }
        rep.nS = Number(p.nS);
        rep.beta = Number(p.betaNew);
        this.emit("finalized", `Round ${roundId} finalized: S_r=[${rep.included.join(",")}] n_S=${p.nS} beta=${p.betaNew} (quorum certificate on-chain)`);
        await this.decryptAndPublish(roundId, p.aggCid, p.nS, opts, rep, timers);
      }
    } else {
      this.emit("stalled", `Round ${roundId} STALLED: no quorum (more than f faulty/offline validators)`);
    }
    rep.metrics = evaluate(this.w, this.data.test.X, this.data.test.y);
    // sum validator-side timers
    for (const v of this.validators) for (const [k, ms] of Object.entries(v.timers)) timers["validator." + k] = (timers["validator." + k] ?? 0) + ms;
    const honestVals = this.validators.filter((v) => v.fault !== "silent").length || 1;
    for (const k of ["verify", "aggregate"]) timers["validator." + k + ".mean"] = (timers["validator." + k] ?? 0) / honestVals;
    timers.total = performance.now() - t0;
    const txs = this.ledger.txs.slice(txStart);
    rep.gas = txs.reduce((a, t) => a + Number(t.gas), 0);
    rep.txs = txs.length;
    this.history.push(rep);
    this.emit("round-done", `Round ${roundId} ${rep.status}: acc=${rep.metrics.accuracy.toFixed(3)} loss=${rep.metrics.logLoss.toFixed(3)} auc=${rep.metrics.auc.toFixed(3)} (${timers.total.toFixed(0)} ms, ${rep.gas} gas)`, rep.metrics);
    return rep;
  }

  /** Threshold decryption of ct_Sigma only, model update, and on-chain publication. */
  private async decryptAndPublish(roundId: number, aggCid: string, nS: bigint, opts: RoundOptions, rep: RoundReport, timers: Timer) {
    const agg = parse<AggBlob>(await this.store.get(aggCid));
    const t = this.pub.t;
    const good: { member: CommitteeMember; shares: DecryptionShare[] }[] = [];
    for (const m of this.committee) {
      if (good.length >= t) break;
      if (!m.online || opts.offlineCommittee?.includes(m.index)) {
        rep.decryptNotes.push(`member ${m.index} offline`);
        continue;
      }
      let shares = timed(timers, "decrypt.share", () => agg.cts.map((c) => partialDecrypt(this.pub, m.share, c)));
      if (opts.badShareMembers?.includes(m.index)) shares = shares.map((s, j) => (j === 0 ? { ...s, ci: (s.ci * 7n) % this.pub.pk.n2 } : s));
      const ok = timed(timers, "decrypt.verify", () => shares.every((s, j) => verifyDecryptionShare(this.pub, agg.cts[j], s)));
      if (!ok) {
        rep.decryptNotes.push(`member ${m.index}: decryption share failed its proof and was rejected`);
        this.emit("reject", `Decryption share of committee member ${m.index} rejected (invalid proof)`);
        continue;
      }
      const blob: ShareBlob = { round: roundId, member: m.address, index: m.index, epoch: this.pub.epoch, shares };
      const cid = await this.store.put(canonicalize(blob));
      await this.ledger.send(m.signer, "postDecryptionShare", (c) => c.postDecryptionShare(roundId, cid));
      good.push({ member: m, shares });
    }
    if (good.length < t) {
      rep.decryptNotes.push(`only ${good.length} valid shares < t=${t}: model not updated`);
      this.emit("stalled", `Round ${roundId}: only ${good.length}/${t} valid decryption shares; global model unchanged`);
      return;
    }
    const sums = timed(timers, "decrypt.combine", () => agg.cts.map((c, j) => combineShares(this.pub, c, good.map((g) => g.shares[j]), false)));
    const wNew = this.w.map((x, j) => x + Number(sums[j]) / (this.cfg.scale * Number(nS)));
    const modelCid = await this.store.put(canonicalize({ round: roundId, w: wNew } as ModelBlob));
    await this.ledger.send(good[0].member.signer, "publishModel", (c) => c.publishModel(roundId, modelCid));
    this.w = wNew;
    this.emit("decrypted", `Round ${roundId}: ${t} shares combined, global model updated (model cid ${modelCid.slice(0, 10)}…)`);
    rep.status = "decrypted";
  }

  // ------------------------------------------------------------ noise budget (P5)
  async bootstrapNoise() {
    const nonce = await this.ledger.bootstrapNonce();
    const digest = bootstrapDigest(this.ledger.chainId, this.ledger.address, nonce);
    const vs = this.validators.filter((v) => v.fault !== "silent");
    const need = Number(await this.ledger.quorum());
    const sigs = await Promise.all(vs.slice(0, need).map((v) => signDigest(v.signer, digest)));
    await this.ledger.send(vs[0].signer, "bootstrap", (c) => c.bootstrap(sigs));
    this.emit("bootstrap", `Noise budget bootstrapped by ${sigs.length} validators → ${await this.ledger.noiseBudget()}`);
  }

  // ------------------------------------------------------------ membership + committee rotation (P4)
  async addHospital(index: number) {
    const h = this.hospitals[index];
    if (!h || this.active.has(index)) throw new Error("hospital cannot join");
    await this.ledger.send(this.chain.wallets[0], "registerHospital", (c) => c.registerHospital(h.address, h.nSamples));
    this.active.add(index);
    this.emit("membership", `${h.name} joined (n=${h.nSamples}); committee rotation required before the next round`);
  }
  async removeHospital(index: number) {
    const h = this.hospitals[index];
    if (!h || !this.active.has(index)) throw new Error("hospital is not active");
    await this.ledger.send(this.chain.wallets[0], "removeHospital", (c) => c.removeHospital(h.address));
    this.active.delete(index);
    this.emit("membership", `${h.name} left; committee rotation required before the next round`);
  }

  /**
   * Verifiable resharing to the committee made of all currently active hospitals. The public key
   * and every stored ciphertext are untouched. `faultyDealers` (old member indices) corrupt the
   * sub-shares they send; the receivers detect this, exclude the cheaters and redo the sharing.
   */
  async rotateCommittee(opts: { threshold?: number; faultyDealers?: number[] } = {}) {
    const old = this.committee;
    const oldPub = this.pub;
    const members = this.activeHospitals;
    const newN = members.length;
    const newT = opts.threshold ?? this.cfg.committeeThreshold ?? Math.floor(newN / 2) + 1;
    const excluded = new Set<number>(old.filter((m) => !m.online).map((m) => m.index));
    let deals: ReshareDeal[] = [];
    let S: number[] = [];
    const t0 = performance.now();
    for (;;) {
      const avail = old.map((m) => m.index).filter((i) => !excluded.has(i));
      if (avail.length < oldPub.t) throw new Error("not enough honest old members to reshare");
      S = avail.slice(0, oldPub.t);
      deals = S.map((i) => {
        const d = reshareDeal(oldPub, old.find((m) => m.index === i)!.share, S, newN, newT);
        if (opts.faultyDealers?.includes(i)) d.subshares = d.subshares.map((x) => x + 1n);
        return d;
      });
      const bad = deals.filter((d) => ![...Array(newN).keys()].every((j) => verifyDeal(oldPub, d, S, j + 1, newT)));
      if (!bad.length) break;
      for (const b of bad) {
        excluded.add(b.from);
        this.emit("reject", `Resharing: sub-shares of old member ${b.from} failed verification → excluded, resharing restarted`);
      }
    }
    const next = nextPublic(oldPub, deals, newN, newT);
    const root = dealsRoot(deals);
    const newShares: KeyShare[] = [];
    for (let j = 1; j <= newN; j++) newShares.push(finishReshare(oldPub, deals, S, newN, newT, j));
    const epochId = Number(await this.ledger.currentEpoch()) + 1;
    await this.ledger.send(this.chain.wallets[0], "beginRotation", (c) => c.beginRotation(members.map((h) => h.address), newT, root));
    for (let j = 0; j < newN; j++) {
      await this.ledger.send(members[j].signer, "ackReshare", (c) => c.ackReshare(epochId));
    }
    this.pub = next;
    this.committee = members.map((h, j) => ({ hospital: h.index, address: h.address, signer: h.signer, index: j + 1, share: newShares[j], online: true }));
    this.epochLog.push({ epoch: next.epoch, deals: deals.map((d) => d.commitments), members: members.map((h) => h.address), threshold: newT });
    this.emit("rotation", `Committee rotated to epoch ${next.epoch}: ${newT}-of-${newN} (old dealers ${S.join(",")}), same public key, ${(performance.now() - t0).toFixed(0)} ms`, { epoch: next.epoch, n: newN, t: newT });
    return { epoch: next.epoch, n: newN, t: newT, ms: performance.now() - t0 };
  }

  // ------------------------------------------------------------ independent audit / replay
  /**
   * An auditor holding only the ledger and the content store re-verifies a round: blob integrity,
   * every proof, the inclusion set, the homomorphic recomputation, the quorum certificate and
   * the threshold decryption against the published model.
   */
  async audit(roundId: number): Promise<{ ok: boolean; checks: { name: string; ok: boolean; detail: string }[] }> {
    const checks: { name: string; ok: boolean; detail: string }[] = [];
    const chk = (name: string, ok: boolean, detail = "") => checks.push({ name, ok, detail });
    const L = this.ledger;
    try {
      const r = await L.getRound(roundId);
      const params = await L.params();
      chk("round reached a terminal state", r.status === RoundStatus.Decrypted || r.status === RoundStatus.Aborted, RoundStatus[r.status]);
      chk("public key matches genesis hash", keccak256(bigToBytes(this.pkPub.n)) === params.pkHash);
      if (r.status === RoundStatus.Decrypted) {
        const agg = parse<AggBlob>(await this.store.get(r.aggHash));
        chk("aggregate blob matches its on-chain content id", cidOf(canonicalize(agg)) === r.aggHash);
        const items: { hospital: string; ctHash: string; proofHash: string }[] = [];
        const cts: bigint[][] = [];
        let nS = 0n, proofsOk = true;
        for (const h of agg.included) {
          const s = await L.getSubmission(roundId, h);
          items.push({ hospital: h, ctHash: s.ctHash, proofHash: s.proofHash });
          const ub = parse<UpdateBlob>(await this.store.get(s.ctHash));
          const pb = parse<ProofBlob>(await this.store.get(s.proofHash));
          const v = verifyVector(this.pkPub, { round: roundId, hospital: h }, ub.cts, pb, params.normBound * params.normBound);
          if (!v.ok) proofsOk = false;
          cts.push(ub.cts);
          nS += (await L.hospitalInfo(h)).nSamples;
        }
        chk("every included proof re-verifies", proofsOk, `${agg.included.length} submissions`);
        chk("inclusion set + hashes match inputsHash on-chain", inputsHashOf(items) === r.inputsHash);
        chk("n_S matches the registered sample counts", nS === r.nS, `n_S=${nS}`);
        const dim = agg.cts.length;
        const re: bigint[] = new Array(dim).fill(ZERO_CIPHERTEXT);
        for (let i = 0; i < cts.length; i++) {
          const n = (await L.hospitalInfo(agg.included[i])).nSamples;
          for (let j = 0; j < dim; j++) re[j] = add(this.pkPub, re[j], scalarMul(this.pkPub, cts[i][j], n));
        }
        chk("ct_Sigma recomputed from the committed ciphertexts", re.every((c, j) => c === agg.cts[j]));
        const evs = await L.c.queryFilter(L.c.filters.RoundFinalized(roundId));
        chk("quorum certificate: 2f+1 validator signatures", evs.length === 1 && evs[0].args.signers >= (await L.quorum()), `signers=${evs[0]?.args.signers}`);
        // decryption: rebuild the epoch public key from the public resharing commitments
        let pub = this.genesisPub;
        let rootOk = true;
        for (const e of this.epochLog) {
          if (e.epoch === 1) rootOk &&= commitmentRoot([this.genesisCommitments]) === (await L.getEpoch(1)).root;
          else {
            pub = nextPublic(pub, e.deals.map((c) => ({ from: 0, commitments: c, subshares: [] })), e.members.length, e.threshold);
            rootOk &&= dealsRoot(e.deals.map((c) => ({ from: 0, commitments: c, subshares: [] }))) === (await L.getEpoch(e.epoch)).root;
          }
          if (e.epoch === Number(r.epoch)) break;
        }
        chk("committee epoch rebuilt from public commitments matches on-chain roots", rootOk, `epoch ${r.epoch}`);
        const shEvs = await L.c.queryFilter(L.c.filters.DecryptionSharePosted(roundId));
        const shareSets: DecryptionShare[][] = [];
        let sharesOk = true;
        for (const ev of shEvs) {
          const sb = parse<ShareBlob>(await this.store.get(ev.args.shareHash));
          if (!sb.shares.every((s, j) => verifyDecryptionShare(pub, agg.cts[j], s))) sharesOk = false;
          shareSets.push(sb.shares);
        }
        chk("every posted decryption share carries a valid proof", sharesOk && shEvs.length >= pub.t, `${shEvs.length} shares, t=${pub.t}`);
        const plain = agg.cts.map((c, j) => combineShares(pub, c, shareSets.map((s) => s[j]), false));
        // previous model
        let prev: number[] = new Array(dim).fill(0);
        for (let k = roundId - 1; k >= 1; k--) {
          const rk = await L.getRound(k);
          if (rk.status === RoundStatus.Decrypted) {
            prev = parse<ModelBlob>(await this.store.get(rk.modelHash)).w;
            break;
          }
        }
        const model = parse<ModelBlob>(await this.store.get(r.modelHash));
        const maxErr = Math.max(...model.w.map((x, j) => Math.abs(x - (prev[j] + Number(plain[j]) / (Number(params.scale) * Number(nS))))));
        chk("published model = previous model + decrypted aggregate / (s·n_S)", maxErr < 1e-9, `max error ${maxErr.toExponential(1)}`);
      } else if (r.status === RoundStatus.Aborted) {
        const evs = await L.c.queryFilter(L.c.filters.RoundAborted(roundId));
        chk("abort carries a 2f+1 quorum certificate", evs.length === 1 && evs[0].args.signers >= (await L.quorum()), `signers=${evs[0]?.args.signers}`);
      }
    } catch (e: any) {
      chk("audit completed without errors", false, String(e.message ?? e));
    }
    return { ok: checks.every((c) => c.ok), checks };
  }

  // ------------------------------------------------------------ baselines + state
  /** Plaintext FedAvg over the active hospitals' shards (the non-private baseline of Section VII-C). */
  static plaintextFedAvg(data: Prepared, cfg: SimConfig, rounds: number, activeShards = data.shards.slice(0, cfg.hospitals)) {
    let w = new Array(data.nFeatures).fill(0);
    const curve: Metrics[] = [];
    for (let r = 0; r < rounds; r++) {
      w = fedAvgRound(w, activeShards, cfg.train, cfg.normBound);
      curve.push(evaluate(w, data.test.X, data.test.y));
    }
    return { w, curve };
  }

  async snapshot() {
    const L = this.ledger;
    const [rc, epoch, nb, f, q] = await Promise.all([L.roundCounter(), L.currentEpoch(), L.noiseBudget(), L.f(), L.quorum()]);
    return {
      config: this.cfg,
      chain: { kind: this.chain.kind, chainId: Number(L.chainId), ledger: L.address, rounds: Number(rc), epoch: Number(epoch), noiseBudget: Number(nb), f: Number(f), quorum: Number(q), txs: L.txs.length, gas: L.txs.reduce((a, t) => a + Number(t.gas), 0) },
      hospitals: this.hospitals.map((h) => ({ index: h.index, name: h.name, address: h.address, n: h.nSamples, active: this.active.has(h.index) })),
      validators: this.validators.map((v) => ({ index: v.index, address: v.address })),
      committee: { epoch: this.pub.epoch, t: this.pub.t, n: this.pub.n, members: this.committee.map((m) => ({ index: m.index, hospital: this.hospitals[m.hospital].name })) },
      metrics: evaluate(this.w, this.data.test.X, this.data.test.y),
      history: this.history.map((h) => ({ round: h.round, status: h.status, abortReason: h.abortReason, metrics: h.metrics, included: h.included, finalView: h.finalView, gas: h.gas, ms: h.timers.total, beta: h.beta, epoch: h.epoch })),
    };
  }
}
