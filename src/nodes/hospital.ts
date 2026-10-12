/**
 * A hospital: holds its private shard D_i, trains locally, clips, quantises, encrypts every
 * coordinate under the committee's public key, proves well-formedness, and commits the
 * result to the ledger by content id (paper Algorithm 1, lines 2-5).
 */
import { Signer } from "ethers";
import { Behavior, SimConfig } from "../config";
import { encryptWithRandomness, PaillierPublicKey } from "../crypto/paillier";
import { proveVector } from "../crypto/sigma";
import { randBelow, randUnit } from "../crypto/bigmath";
import { clipToNorm, localTrain, l2norm, normSqInt, quantize } from "../ml/logreg";
import type { Split } from "../ml/dataset";
import { ContentStore } from "../storage/contentStore";
import { canonicalize } from "../storage/serialize";
import { Ledger } from "../chain/ledger";
import { ProofBlob, Timer, UpdateBlob, timed, timedAsync } from "../protocol";

export interface SubmitResult {
  submitted: boolean;
  behavior: Behavior;
  ctCid?: string;
  proofCid?: string;
  /** norm of the honest clipped update (before any attack) */
  honestNorm?: number;
  /** norm that actually went into the ciphertext */
  sentNorm?: number;
}

export class Hospital {
  behavior: Behavior = "honest";
  /** attack parameter: scale factor for "oversize" / "lie-norm" */
  attackFactor = 50;

  constructor(
    readonly index: number, // 0-based
    readonly name: string,
    readonly signer: Signer,
    readonly address: string,
    readonly shard: Split
  ) {}

  get nSamples() {
    return this.shard.y.length;
  }

  async submit(
    cfg: SimConfig,
    ledger: Ledger,
    store: ContentStore,
    pk: PaillierPublicKey,
    roundId: number,
    w: number[],
    timers: Timer,
    peers: { address: string; ctCid?: string; proofCid?: string }[]
  ): Promise<SubmitResult> {
    if (this.behavior === "offline") return { submitted: false, behavior: this.behavior };
    const d = w.length;
    const ctx = { round: roundId, hospital: this.address };

    // 1. local training and clipping
    const delta = timed(timers, "train", () => localTrain(w, this.shard.X, this.shard.y, cfg.train).map((x, j) => x - w[j]));
    const clipped = clipToNorm(delta, cfg.normBound);
    const honestNorm = l2norm(clipped);

    let ctCid: string, proofCid: string, sentNorm = honestNorm;

    if (this.behavior === "replay" && peers.length) {
      // copies an honest peer's submission verbatim: its proof is bound to the OTHER hospital
      const victim = peers[0];
      ctCid = victim.ctCid!;
      proofCid = victim.proofCid!;
    } else if (this.behavior === "malformed") {
      const cts = Array.from({ length: d }, () => randBelow(pk.n2));
      const dummy: ProofBlob = { a: cts.slice(), z1: cts.slice(), z2: cts.slice(), claimedNormSq: 0n };
      ctCid = await store.put(canonicalize({ round: roundId, hospital: this.address, cts } as UpdateBlob));
      proofCid = await store.put(canonicalize(dummy));
    } else {
      // 2. optional attack, then quantise (scale s) and encrypt
      let vec = clipped;
      if (this.behavior === "oversize" || this.behavior === "lie-norm") vec = clipped.map((x) => x * this.attackFactor);
      sentNorm = l2norm(vec);
      const q = quantize(vec, cfg.scale);
      const encs = timed(timers, "encrypt", () => q.map((m) => encryptWithRandomness(pk, m)));
      const cts = encs.map((e) => e.c);
      // 3. proof of knowledge of the openings, bound to (round, hospital); norm claim is the stand-in
      const claimed = this.behavior === "lie-norm" ? normSqInt(quantize(clipped, cfg.scale)) : normSqInt(q);
      const proof = timed(timers, "prove", () => proveVector(pk, ctx, cts, q, encs.map((e) => e.r), claimed));
      ctCid = await store.put(canonicalize({ round: roundId, hospital: this.address, cts } as UpdateBlob));
      proofCid = await store.put(canonicalize(proof));
    }

    // 4. commit on-chain
    await timedAsync(timers, "submitTx", () => ledger.send(this.signer, "submitUpdate", (c) => c.submitUpdate(roundId, ctCid, proofCid)));
    return { submitted: true, behavior: this.behavior, ctCid, proofCid, honestNorm, sentNorm };
  }
}

export { randUnit };
