/**
 * Threshold Paillier decryption (Shoup / Damgard-Jurik style, s = 1) with
 *   - verifiable decryption shares (Chaum-Pedersen equality-of-discrete-log proofs in the
 *     hidden-order group Z*_{N^2}),
 *   - verifiable secret RESHARING to a new committee of a different size and threshold,
 *     leaving the public key and every stored ciphertext untouched (paper goal P4).
 *
 * Secret sharing is over the integers (no modular reduction), so that Feldman-style
 * commitments v^{coef} in the hidden-order group are exact. The Shamir polynomial's secret
 * is D with  D = 0 (mod m)  and  D = kappa (mod N),   m = p'q'.
 * Initially kappa = 1. Each rotation multiplies kappa by Delta_old = n_old!, which is public
 * state in the ledger, so decryption stays correct:
 *
 *   combine:   prod_i c_i^{2 lambda_i}  =  c^{4 Delta^2 D}  =  1 + 4 Delta^2 kappa M N
 *   =>         M = L(prod) * (4 Delta^2 kappa)^{-1}  (mod N)
 *
 * Simplification stated in the paper (Section V-B): the initial shares come from a TRUSTED
 * DEALER instead of a distributed key generation protocol. The dealer discards p, q, m, d.
 */
import {
  bitLength,
  factorial,
  hashToInt,
  mod,
  modInv,
  modPow,
  modPowSigned,
  randBelow,
  randBits,
  randUnit,
  Rng,
  getDefaultRng,
  toHex,
} from "./bigmath";
import { generateKeyPair, L, PaillierKeyPair, PaillierPublicKey, decode } from "./paillier";
import { keccak256 } from "ethers";

export interface ThresholdPublic {
  pk: PaillierPublicKey;
  /** random square in Z*_{N^2}; base for verification keys and commitments */
  v: bigint;
  /** committee size and threshold */
  n: number;
  t: number;
  /** D = kappa (mod N); public state tracked in the ledger across rotations */
  kappa: bigint;
  /** vks[i-1] = v^{s_i} mod N^2 */
  vks: bigint[];
  epoch: number;
  challengeBits: number;
}

export interface KeyShare {
  index: number; // 1..n
  s: bigint;
}

export interface DecryptionShare {
  index: number;
  ci: bigint; // c^{2 Delta s_i}
  proof: { a1: bigint; a2: bigint; z: bigint };
}

const SIGMA = 80; // statistical hiding parameter in bits

export function challengeBitsFor(modulusBits: number): number {
  // special soundness needs the challenge to be below the smallest prime factor of the
  // group order (~ N^(1/2)/2); keep a safety margin
  return Math.min(128, Math.floor(modulusBits / 2) - 8);
}

// ---------------------------------------------------------------- integer Lagrange
/** lambda_i^S = Delta * prod_{j in S, j != i} j / (j - i), always an integer for Delta = n!. */
export function lagrangeInt(delta: bigint, S: number[], i: number): bigint {
  let num = delta;
  let den = 1n;
  for (const j of S) {
    if (j === i) continue;
    num *= BigInt(j);
    den *= BigInt(j - i);
  }
  if (num % den !== 0n) throw new Error("non-integer Lagrange coefficient");
  return num / den;
}

function evalPoly(coefs: bigint[], x: number): bigint {
  // Horner over the integers
  let r = 0n;
  const bx = BigInt(x);
  for (let k = coefs.length - 1; k >= 0; k--) r = r * bx + coefs[k];
  return r;
}

// ---------------------------------------------------------------- dealer
export interface DealerOutput {
  pub: ThresholdPublic;
  shares: KeyShare[];
  /** Feldman commitments C_k = v^{a_k}, k = 0..t-1 (a_0 = D) */
  commitments: bigint[];
  /** kept only so tests can compare against textbook decryption; a real dealer discards it */
  keypair: PaillierKeyPair;
}

export function dealerSetup(opts: { bits: number; n: number; t: number; rng?: Rng; keypair?: PaillierKeyPair }): DealerOutput {
  const rng = opts.rng ?? getDefaultRng();
  const { n, t } = opts;
  if (!(t >= 1 && t <= n && 2 * t > n)) throw new Error("need m/2 < t <= m");
  const keypair = opts.keypair ?? generateKeyPair(opts.bits, rng);
  const { pk, sk } = keypair;

  const x = randUnit(pk.n, rng);
  const v = (x * x) % pk.n2;

  const coefBits = bitLength(pk.n * sk.m) + SIGMA;
  const coefs: bigint[] = [sk.d];
  for (let k = 1; k < t; k++) coefs.push(randBits(coefBits, rng));

  const shares: KeyShare[] = [];
  const vks: bigint[] = [];
  for (let i = 1; i <= n; i++) {
    const s = evalPoly(coefs, i);
    shares.push({ index: i, s });
    vks.push(modPow(v, s, pk.n2));
  }
  const commitments = coefs.map((a) => modPow(v, a, pk.n2));
  const pub: ThresholdPublic = { pk, v, n, t, kappa: 1n, vks, epoch: 1, challengeBits: challengeBitsFor(pk.bits) };
  return { pub, shares, commitments, keypair };
}

/** v^s == prod_k C_k^{i^k}: a holder checks its own share against the public commitments. */
export function verifyShareAgainstCommitments(pub: ThresholdPublic, commitments: bigint[], share: KeyShare): boolean {
  return modPowSigned(pub.v, share.s, pub.pk.n2) === evalCommitments(pub, commitments, share.index);
}

function evalCommitments(pub: ThresholdPublic, commitments: bigint[], j: number): bigint {
  const n2 = pub.pk.n2;
  let acc = 1n;
  let jk = 1n; // j^k
  const bj = BigInt(j);
  for (const C of commitments) {
    acc = (acc * modPow(C, jk, n2)) % n2;
    jk *= bj;
  }
  return acc;
}

/** Hash of a list of group elements; the value recorded as `root` in the ledger. */
export function commitmentRoot(parts: bigint[][]): string {
  const flat = parts.map((p) => p.map(toHex).join(",")).join("|");
  return keccak256(Buffer.from(flat));
}

// ---------------------------------------------------------------- decryption shares
function dlogEqChallenge(pub: ThresholdPublic, c4: bigint, y1: bigint, y2: bigint, a1: bigint, a2: bigint, index: number): bigint {
  return hashToInt("VEABFT/dec-share", [pub.pk.n, pub.v, c4, y1, y2, a1, a2, index, pub.epoch], pub.challengeBits);
}

export function partialDecrypt(pub: ThresholdPublic, share: KeyShare, c: bigint, rng: Rng = getDefaultRng()): DecryptionShare {
  const { n2 } = pub.pk;
  const delta = factorial(pub.n);
  const x = delta * share.s; // exponent of the proof statement (may be negative after rotations)
  const ci = modPowSigned(c, 2n * x, n2);
  const c4 = modPow(c, 4n, n2);
  const y1 = modPowSigned(pub.v, x, n2);
  const y2 = (ci * ci) % n2;
  const r = randBits(bitLength(x < 0n ? -x : x) + pub.challengeBits + SIGMA, rng);
  const a1 = modPow(pub.v, r, n2);
  const a2 = modPow(c4, r, n2);
  const e = dlogEqChallenge(pub, c4, y1, y2, a1, a2, share.index);
  return { index: share.index, ci, proof: { a1, a2, z: r + e * x } };
}

export function verifyDecryptionShare(pub: ThresholdPublic, c: bigint, ds: DecryptionShare): boolean {
  const { n2 } = pub.pk;
  if (ds.index < 1 || ds.index > pub.n) return false;
  if (ds.ci <= 0n || ds.ci >= n2) return false;
  const delta = factorial(pub.n);
  const c4 = modPow(c, 4n, n2);
  const y1 = modPow(pub.vks[ds.index - 1], delta, n2);
  const y2 = (ds.ci * ds.ci) % n2;
  const e = dlogEqChallenge(pub, c4, y1, y2, ds.proof.a1, ds.proof.a2, ds.index);
  const lhs1 = modPowSigned(pub.v, ds.proof.z, n2);
  const rhs1 = (ds.proof.a1 * modPow(y1, e, n2)) % n2;
  if (lhs1 !== rhs1) return false;
  const lhs2 = modPowSigned(c4, ds.proof.z, n2);
  const rhs2 = (ds.proof.a2 * modPow(y2, e, n2)) % n2;
  return lhs2 === rhs2;
}

/**
 * Combine at least t decryption shares into the signed plaintext. With verify = true every
 * share proof is checked and an invalid share is rejected loudly.
 */
export function combineShares(pub: ThresholdPublic, c: bigint, shares: DecryptionShare[], verify = true): bigint {
  if (shares.length < pub.t) throw new Error(`need ${pub.t} shares, got ${shares.length}`);
  const used = shares.slice(0, pub.t);
  const seen = new Set<number>();
  for (const s of used) {
    if (seen.has(s.index)) throw new Error("duplicate share index");
    seen.add(s.index);
    if (verify && !verifyDecryptionShare(pub, c, s)) throw new Error(`decryption share ${s.index} failed its proof`);
  }
  const { n2, n } = pub.pk;
  const delta = factorial(pub.n);
  const S = used.map((s) => s.index);
  let prod = 1n;
  for (const s of used) {
    const lam = lagrangeInt(delta, S, s.index);
    prod = (prod * modPowSigned(s.ci, 2n * lam, n2)) % n2;
  }
  const raw = L(pub.pk, prod);
  const scale = mod(4n * delta * delta * pub.kappa, n);
  return decode(pub.pk, mod(raw * modInv(scale, n), n));
}

// ---------------------------------------------------------------- resharing (P4)
export interface ReshareDeal {
  /** old holder index i */
  from: number;
  /** C_{i,k} = v^{b_{i,k}} for k = 0..newT-1, with b_{i,0} = lambda_i * s_i */
  commitments: bigint[];
  /** subshares[j-1] = g_i(j), sent over a private channel to new member j */
  subshares: bigint[];
}

export function reshareDeal(
  pub: ThresholdPublic,
  share: KeyShare,
  S: number[],
  newN: number,
  newT: number,
  rng: Rng = getDefaultRng()
): ReshareDeal {
  if (!(newT >= 1 && newT <= newN && 2 * newT > newN)) throw new Error("need m'/2 < t' <= m'");
  if (S.length < pub.t) throw new Error("need at least t old members to reshare");
  const delta = factorial(pub.n);
  const lam = lagrangeInt(delta, S, share.index);
  const b0 = lam * share.s;
  const bound = bitLength(b0 < 0n ? -b0 : b0) + SIGMA;
  const coefs: bigint[] = [b0];
  for (let k = 1; k < newT; k++) coefs.push(randBits(bound, rng));
  const subshares: bigint[] = [];
  for (let j = 1; j <= newN; j++) subshares.push(evalPoly(coefs, j));
  const commitments = coefs.map((b) => modPowSigned(pub.v, b, pub.pk.n2));
  return { from: share.index, commitments, subshares };
}

/** New member j verifies the sub-share it received from old member `deal.from`. */
export function verifyDeal(pub: ThresholdPublic, deal: ReshareDeal, S: number[], newIndex: number, newT: number): boolean {
  const { n2 } = pub.pk;
  if (deal.commitments.length !== newT) return false;
  // (1) sub-share is consistent with the published polynomial commitments
  const sub = deal.subshares[newIndex - 1];
  if (sub === undefined) return false;
  if (modPowSigned(pub.v, sub, n2) !== evalCommitments(pub, deal.commitments, newIndex)) return false;
  // (2) the constant term commits to lambda_i * s_i, which is bound to the OLD verification key
  const delta = factorial(pub.n);
  const lam = lagrangeInt(delta, S, deal.from);
  const expected = modPowSigned(pub.vks[deal.from - 1], lam, n2);
  return deal.commitments[0] === expected;
}

export function finishReshare(
  pub: ThresholdPublic,
  deals: ReshareDeal[],
  S: number[],
  newN: number,
  newT: number,
  newIndex: number
): KeyShare {
  if (deals.length !== S.length) throw new Error("missing deals");
  let s = 0n;
  for (const d of deals) {
    if (!verifyDeal(pub, d, S, newIndex, newT)) throw new Error(`deal from old member ${d.from} failed verification`);
    s += d.subshares[newIndex - 1];
  }
  void newN;
  return { index: newIndex, s };
}

/** Public part of the new epoch, computable by anyone from the published commitments. */
export function nextPublic(pub: ThresholdPublic, deals: ReshareDeal[], newN: number, newT: number): ThresholdPublic {
  const { n2, n } = pub.pk;
  const vks: bigint[] = [];
  for (let j = 1; j <= newN; j++) {
    let acc = 1n;
    for (const d of deals) acc = (acc * evalCommitments(pub, d.commitments, j)) % n2;
    vks.push(acc);
  }
  return {
    ...pub,
    n: newN,
    t: newT,
    kappa: mod(pub.kappa * factorial(pub.n), n),
    vks,
    epoch: pub.epoch + 1,
  };
}

export function dealsRoot(deals: ReshareDeal[]): string {
  return commitmentRoot(deals.map((d) => d.commitments));
}

/** Convenience for tests and the orchestrator: full rotation with every check. */
export function rotateCommittee(
  pub: ThresholdPublic,
  shares: KeyShare[],
  S: number[],
  newN: number,
  newT: number,
  rng: Rng = getDefaultRng()
): { pub: ThresholdPublic; shares: KeyShare[]; deals: ReshareDeal[]; root: string } {
  const deals = S.map((i) => reshareDeal(pub, shares.find((s) => s.index === i)!, S, newN, newT, rng));
  const next = nextPublic(pub, deals, newN, newT);
  const newShares: KeyShare[] = [];
  for (let j = 1; j <= newN; j++) newShares.push(finishReshare(pub, deals, S, newN, newT, j));
  // every new share must match its public verification key
  for (const s of newShares) {
    if (modPowSigned(next.v, s.s, next.pk.n2) !== next.vks[s.index - 1]) throw new Error("new share inconsistent with VK");
  }
  return { pub: next, shares: newShares, deals, root: dealsRoot(deals) };
}

export { randBelow };
