/**
 * A validator (paper Sections V-E and V-F). It never trusts the primary: from the ledger and
 * the content store it independently
 *   (i)   verifies every per-hospital proof pi_i,
 *   (ii)  recomputes ct_Sigma = (+)_i n_i (.) ct_i,
 *   (iii) derives the inclusion set S_r and the noise budget beta' from ledger state,
 * and only then votes for a proposal that matches. A primary that censors a hospital, tampers
 * with the aggregate, lies about the budget, or equivocates therefore cannot gather a quorum.
 */
import { Signer } from "ethers";
import { SimConfig, ValidatorFault } from "../config";
import { PaillierPublicKey, add, scalarMul, ZERO_CIPHERTEXT } from "../crypto/paillier";
import { verifyVector } from "../crypto/sigma";
import { Ledger, abortDigest, inputsHashOf, proposalDigest, reasonCode, signDigest } from "../chain/ledger";
import { ContentStore } from "../storage/contentStore";
import { canonicalize, parse } from "../storage/serialize";
import { AggBlob, ProofBlob, Proposal, Timer, UpdateBlob, addrCmp, timedAsync } from "../protocol";
import { ReplicaApp } from "../consensus/pbft";

export const REASON = {
  invalid: "invalid-submission",
  belowK: "below-k_min",
  noise: "noise-budget-exhausted",
};

interface Valid { hospital: string; ctHash: string; proofHash: string; cts: bigint[]; n: bigint }
export interface Inspection {
  valid: Valid[];
  invalid: { hospital: string; reason: string }[];
  submitters: string[];
}

type Expected =
  | { kind: "abort"; reasonText: string; reason: string; inspection: Inspection }
  | { kind: "aggregate"; included: Valid[]; agg: bigint[]; nS: bigint; beta: bigint; inputsHash: string; inspection: Inspection };

export class ValidatorNode implements ReplicaApp {
  fault: ValidatorFault = "honest";
  timers: Timer = {};
  private roundId = 0;
  private cache = new Map<number, Expected>();

  constructor(
    readonly index: number,
    readonly signer: Signer,
    readonly address: string,
    private cfg: SimConfig,
    private ledger: Ledger,
    private store: ContentStore,
    private pk: PaillierPublicKey,
    private dim: number
  ) {}

  beginRound(roundId: number) {
    this.roundId = roundId;
    this.cache.clear();
  }

  // ------------------------------------------------------------ independent verification
  async inspect(roundId: number): Promise<Inspection> {
    const params = await this.ledger.params();
    const normBoundSq = params.normBound * params.normBound;
    const submitters = [...(await this.ledger.getSubmitters(roundId))].sort(addrCmp);
    const valid: Valid[] = [];
    const invalid: Inspection["invalid"] = [];
    for (const h of submitters) {
      const sub = await this.ledger.getSubmission(roundId, h);
      const info = await this.ledger.hospitalInfo(h);
      try {
        const ub = parse<UpdateBlob>(await this.store.get(sub.ctHash)); // hash-checked fetch
        const pb = parse<ProofBlob>(await this.store.get(sub.proofHash));
        if (!Array.isArray(ub.cts) || ub.cts.length !== this.dim) throw new Error(`update has wrong dimension`);
        const v = await timedAsync(this.timers, "verify", async () => verifyVector(this.pk, { round: roundId, hospital: h }, ub.cts, pb, normBoundSq));
        if (!v.ok) invalid.push({ hospital: h, reason: v.reason ?? "proof rejected" });
        else valid.push({ hospital: h, ctHash: sub.ctHash, proofHash: sub.proofHash, cts: ub.cts, n: info.nSamples });
      } catch (e: any) {
        invalid.push({ hospital: h, reason: String(e.message ?? e) });
      }
    }
    return { valid, invalid, submitters };
  }

  private aggregate(sel: Valid[]): bigint[] {
    const out: bigint[] = new Array(this.dim).fill(ZERO_CIPHERTEXT);
    for (const v of sel) for (let j = 0; j < this.dim; j++) out[j] = add(this.pk, out[j], scalarMul(this.pk, v.cts[j], v.n));
    return out;
  }

  /** What an honest proposal for this round must look like, derived only from ledger + store. */
  async expected(): Promise<Expected> {
    const hit = this.cache.get(this.roundId);
    if (hit) return hit;
    const params = await this.ledger.params();
    const ins = await this.inspect(this.roundId);
    const abort = (txt: string): Expected => ({ kind: "abort", reasonText: txt, reason: reasonCode(txt), inspection: ins });
    let res: Expected;
    const included = params.excludePolicy ? ins.valid : ins.invalid.length ? [] : ins.valid;
    if (ins.valid.length < Number(params.kMin)) res = abort(REASON.belowK);
    else if (!params.excludePolicy && ins.invalid.length) res = abort(REASON.invalid);
    else {
      const beta = await this.ledger.expectedBeta(included.length);
      if (beta < params.tau) res = abort(REASON.noise);
      else {
        const agg = await timedAsync(this.timers, "aggregate", async () => this.aggregate(included));
        const nS = included.reduce((a, v) => a + v.n, 0n);
        res = { kind: "aggregate", included, agg, nS, beta, inputsHash: inputsHashOf(included), inspection: ins };
      }
    }
    this.cache.set(this.roundId, res);
    return res;
  }

  // ------------------------------------------------------------ ReplicaApp: validate
  async validate(p: Proposal): Promise<{ ok: boolean; reason?: string }> {
    if (p.roundId !== this.roundId) return { ok: false, reason: "proposal for a different round" };
    const exp = await this.expected();
    if (p.kind === "abort") {
      if (exp.kind !== "abort") return { ok: false, reason: "abort proposed although a valid aggregate exists" };
      if (p.reason !== exp.reason) return { ok: false, reason: `abort reason mismatch (expected ${exp.reasonText})` };
      if (p.digest !== abortDigest(this.ledger.chainId, this.ledger.address, BigInt(p.roundId), BigInt(p.view), p.reason)) return { ok: false, reason: "abort digest mismatch" };
      return { ok: true };
    }
    if (exp.kind === "abort") return { ok: false, reason: `aggregate proposed but round must abort (${exp.reasonText})` };
    const want = exp.included.map((v) => v.hospital);
    const missing = want.filter((h) => !p.included.includes(h));
    if (missing.length) return { ok: false, reason: `S_r omits valid submission(s) ${missing.map((m) => m.slice(0, 8)).join(",")} (censorship)` };
    if (p.included.length !== want.length || p.included.some((h, i) => h !== want[i])) return { ok: false, reason: "inclusion set differs from the valid submissions" };
    if (p.nS !== exp.nS) return { ok: false, reason: "n_S mismatch" };
    if (p.inputsHash !== exp.inputsHash) return { ok: false, reason: "inputs hash mismatch" };
    if (p.betaNew !== exp.beta) return { ok: false, reason: `noise budget ${p.betaNew} != ledger-derived ${exp.beta}` };
    let blob: AggBlob;
    try {
      blob = parse<AggBlob>(await this.store.get(p.aggCid));
    } catch (e: any) {
      return { ok: false, reason: "aggregate blob unavailable: " + e.message };
    }
    if (blob.cts.length !== exp.agg.length || blob.cts.some((c, j) => c !== exp.agg[j])) return { ok: false, reason: "recomputed ct_Sigma differs from the proposed aggregate" };
    const d = proposalDigest(this.ledger.chainId, this.ledger.address, BigInt(p.roundId), BigInt(p.view), p.inputsHash, p.aggCid, p.nS, p.betaNew);
    if (d !== p.digest) return { ok: false, reason: "proposal digest mismatch" };
    return { ok: true };
  }

  sign(digest: string) {
    return signDigest(this.signer, digest);
  }

  // ------------------------------------------------------------ ReplicaApp: propose (primary)
  async propose(view: number, _carried?: Proposal): Promise<Proposal[]> {
    if (this.fault === "silent") return [];
    const exp = await this.expected();
    const chain = this.ledger.chainId, led = this.ledger.address, r = BigInt(this.roundId), v = BigInt(view);
    if (exp.kind === "abort") {
      const digest = abortDigest(chain, led, r, v, exp.reason);
      return [{ kind: "abort", roundId: this.roundId, view, reason: exp.reason, reasonText: exp.reasonText, digest }];
    }
    const make = async (sel: Valid[], agg: bigint[], betaNew: bigint): Promise<Proposal> => {
      const blob: AggBlob = { round: this.roundId, included: sel.map((s) => s.hospital), cts: agg };
      const aggCid = await this.store.put(canonicalize(blob));
      const nS = sel.reduce((a, s) => a + s.n, 0n);
      const inputsHash = inputsHashOf(sel);
      const digest = proposalDigest(chain, led, r, v, inputsHash, aggCid, nS, betaNew);
      return { kind: "aggregate", roundId: this.roundId, view, included: sel.map((s) => s.hospital), aggCid, betaNew, nS, inputsHash, digest };
    };
    const honest = () => make(exp.included, exp.agg, exp.beta);
    const tampered = () => make(exp.included, exp.agg.map((c, j) => (j === 0 ? (c * 2n) % this.pk.n2 : c)), exp.beta);
    switch (this.fault) {
      case "bad-aggregate":
        return [await tampered()];
      case "censor": {
        const sel = exp.included.slice(1);
        const beta = await this.ledger.expectedBeta(sel.length);
        return [await make(sel, this.aggregate(sel), beta)];
      }
      case "wrong-budget":
        return [await make(exp.included, exp.agg, exp.beta + 1n)];
      case "equivocate":
        return [await honest(), await tampered()];
      default:
        return [await honest()];
    }
  }
}
