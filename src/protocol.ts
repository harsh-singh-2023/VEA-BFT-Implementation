/** Off-chain blob formats (content-addressed; the ledger keeps only their keccak256 ids). */
import { DecryptionShare } from "./crypto/threshold";
import { VectorProof } from "./crypto/sigma";

export interface UpdateBlob { round: number; hospital: string; cts: bigint[] }
export type ProofBlob = VectorProof;
export interface AggBlob { round: number; included: string[]; cts: bigint[] }
export interface ModelBlob { round: number; w: number[] }
export interface ShareBlob { round: number; member: string; index: number; epoch: number; shares: DecryptionShare[] }

export type Proposal =
  | {
      kind: "aggregate";
      roundId: number;
      view: number;
      included: string[]; // ascending addresses
      aggCid: string;
      betaNew: bigint;
      nS: bigint;
      inputsHash: string;
      digest: string;
    }
  | { kind: "abort"; roundId: number; view: number; reason: string; reasonText: string; digest: string };

export const addrCmp = (a: string, b: string) => (BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0);
export const short = (h: string, n = 6) => (h.length > 2 * n + 2 ? h.slice(0, n + 2) + "…" + h.slice(-4) : h);

export interface Timer {
  [stage: string]: number;
}
export function timed<T>(acc: Timer, stage: string, fn: () => T): T {
  const t0 = performance.now();
  try {
    return fn();
  } finally {
    acc[stage] = (acc[stage] ?? 0) + (performance.now() - t0);
  }
}
export async function timedAsync<T>(acc: Timer, stage: string, fn: () => Promise<T>): Promise<T> {
  const t0 = performance.now();
  try {
    return await fn();
  } finally {
    acc[stage] = (acc[stage] ?? 0) + (performance.now() - t0);
  }
}
