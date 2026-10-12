/** Simulation parameters. Defaults reproduce the setup of paper Section VII. */
import type { DatasetName } from "./ml/dataset";

export type Behavior =
  | "honest"
  | "oversize" // scales its clipped update (paper Section VII-C: factor 50) -> out of norm bound
  | "replay" // copies another hospital's ciphertexts and proof
  | "malformed" // random group elements as "ciphertexts"
  | "lie-norm" // oversize update, but claims a small norm (documented limitation: NOT caught)
  | "offline"; // never submits

export type ValidatorFault =
  | "honest"
  | "silent" // crashed / partitioned
  | "bad-aggregate" // as primary: proposes a tampered ct_Sigma
  | "censor" // as primary: drops one valid hospital from S_r
  | "wrong-budget" // as primary: proposes a wrong noise budget
  | "equivocate" // as primary: different proposals to different replicas
  | "bad-signature"; // as backup: sends commit votes with a garbage signature

export interface SimConfig {
  dataset: DatasetName;
  seed: string;
  /** Paillier modulus size in bits. 256 reproduces the paper; NOT secure. */
  bits: number;
  hospitals: number; // h
  validators: number; // 3f+1
  committeeThreshold?: number; // t; default floor(m/2)+1
  /** hospitals that exist but have not joined yet (they can join later, triggering a committee rotation) */
  reserve?: number;
  rounds: number;
  train: { epochs: number; lr: number; l2: number };
  /** quantisation scale s */
  scale: number;
  /** L2 bound B on a (real-valued) update */
  normBound: number;
  kMin: number;
  beta0: number;
  tau: number;
  costScalarMul: number;
  costAdd: number;
  /** false = abort (paper evaluation), true = exclude-and-continue (paper's intended production policy) */
  excludePolicy: boolean;
  carryBudget: boolean;
}

export const DEFAULT_CONFIG: SimConfig = {
  dataset: "heart",
  seed: "vea-bft",
  bits: 256,
  hospitals: 5,
  validators: 4,
  rounds: 30,
  train: { epochs: 1, lr: 0.1, l2: 0.01 },
  scale: 1_000_000,
  normBound: 0.5,
  kMin: 3,
  beta0: 1000,
  tau: 100,
  costScalarMul: 5,
  costAdd: 1,
  excludePolicy: false,
  carryBudget: false,
};

export const withDefaults = (c: Partial<SimConfig> = {}): SimConfig => ({
  ...DEFAULT_CONFIG,
  ...c,
  train: { ...DEFAULT_CONFIG.train, ...(c.train ?? {}) },
});
