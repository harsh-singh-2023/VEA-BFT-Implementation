/**
 * Per-hospital proof of well-formedness (paper Section V-D), Fiat-Shamir transformed.
 *
 * REAL part:  a batched Sigma protocol proving knowledge of an opening (m_j, r_j) of every
 *             Paillier ciphertext  c_j = (1 + m_j N) r_j^N  in the submitted vector. The
 *             challenge hashes (round, hospital, every c_j, every commitment a_j), so a proof
 *             cannot be replayed in another round or by another hospital, and a ciphertext
 *             that was copied or re-randomised from someone else cannot be proven.
 *
 * STAND-IN:   the norm bound ||delta_i||_2 <= B. The paper's prototype checks it on the
 *             plaintext in the simulation instead of with a zero-knowledge range proof; here
 *             the hospital attaches its quantized squared norm, bound into the transcript, and
 *             validators compare it to B^2. A hospital that LIES about its norm is not caught
 *             (documented limitation; a SNARK/range proof is the production replacement).
 */
import { bigToBytes, gcd, hashToInt, mod, modPow, randBelow, randUnit, Rng, getDefaultRng } from "./bigmath";
import { PaillierPublicKey, encode } from "./paillier";
import { challengeBitsFor } from "./threshold";

export interface ProofContext {
  round: number;
  hospital: string; // address, binds the proof to a hospital identity
}

export interface VectorProof {
  a: bigint[];
  z1: bigint[];
  z2: bigint[];
  /** STAND-IN for the range proof: quantized squared L2 norm of the plaintext update */
  claimedNormSq: bigint;
}

function challenge(pk: PaillierPublicKey, ctx: ProofContext, cts: bigint[], a: bigint[], normSq: bigint): bigint {
  return hashToInt(
    "VEABFT/pok-vector",
    [pk.n, ctx.round, ctx.hospital.toLowerCase(), normSq, ...cts.map((c) => bigToBytes(c)), ...a.map((x) => bigToBytes(x))],
    challengeBitsFor(pk.bits)
  );
}

export function proveVector(
  pk: PaillierPublicKey,
  ctx: ProofContext,
  cts: bigint[],
  plaintexts: bigint[],
  randomness: bigint[],
  claimedNormSq: bigint,
  rng: Rng = getDefaultRng()
): VectorProof {
  const { n, n2 } = pk;
  const s: bigint[] = [];
  const u: bigint[] = [];
  const a: bigint[] = [];
  for (let j = 0; j < cts.length; j++) {
    const sj = randBelow(n, rng);
    const uj = randUnit(n, rng);
    s.push(sj);
    u.push(uj);
    a.push((((1n + sj * n) % n2) * modPow(uj, n, n2)) % n2);
  }
  const e = challenge(pk, ctx, cts, a, claimedNormSq);
  const z1: bigint[] = [];
  const z2: bigint[] = [];
  for (let j = 0; j < cts.length; j++) {
    z1.push(mod(s[j] + e * encode(pk, plaintexts[j]), n));
    z2.push((u[j] * modPow(randomness[j], e, n)) % n);
  }
  return { a, z1, z2, claimedNormSq };
}

export function verifyVector(
  pk: PaillierPublicKey,
  ctx: ProofContext,
  cts: bigint[],
  proof: VectorProof,
  normBoundSq: bigint
): { ok: boolean; reason?: string } {
  const { n, n2 } = pk;
  const D = cts.length;
  if (proof.a.length !== D || proof.z1.length !== D || proof.z2.length !== D) return { ok: false, reason: "proof shape mismatch" };
  if (proof.claimedNormSq > normBoundSq) return { ok: false, reason: "norm bound exceeded (stand-in range check)" };
  const e = challenge(pk, ctx, cts, proof.a, proof.claimedNormSq);
  for (let j = 0; j < D; j++) {
    const c = cts[j];
    if (c <= 0n || c >= n2 || gcd(c, n) !== 1n) return { ok: false, reason: `ciphertext ${j} is not a unit mod N^2` };
    const z2 = proof.z2[j];
    if (z2 <= 0n || z2 >= n || gcd(z2, n) !== 1n) return { ok: false, reason: `bad response z2[${j}]` };
    if (proof.z1[j] < 0n || proof.z1[j] >= n) return { ok: false, reason: `bad response z1[${j}]` };
    const lhs = (((1n + proof.z1[j] * n) % n2) * modPow(z2, n, n2)) % n2;
    const rhs = (proof.a[j] * modPow(c, e, n2)) % n2;
    if (lhs !== rhs) return { ok: false, reason: `proof of knowledge failed at coordinate ${j}` };
  }
  return { ok: true };
}
