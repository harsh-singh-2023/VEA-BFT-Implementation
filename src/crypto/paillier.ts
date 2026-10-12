/**
 * Paillier additively homomorphic encryption (g = N + 1) with signed-integer encoding.
 *
 *   Enc(m; r) = (1 + m N) * r^N  mod N^2
 *   Enc(a) (+) Enc(b) = Enc(a) * Enc(b)            -> decrypts to a + b
 *   c (.) Enc(a)      = Enc(a)^c                    -> decrypts to c * a
 *
 * Negative values are encoded modulo N, so N must exceed twice the magnitude of any
 * aggregate (paper Section III-A).
 *
 * Key generation produces safe primes (p = 2p'+1, q = 2q'+1). That is what makes the
 * threshold variant of threshold.ts possible. The prototype default is 256 bits to match
 * the paper's evaluation; this is NOT secure. Use >= 2048 bits for any real deployment.
 */
import { mod, modInv, modPow, randUnit, genSafePrime, Rng, getDefaultRng, bitLength } from "./bigmath";

export interface PaillierPublicKey {
  n: bigint;
  n2: bigint;
  bits: number;
}

export interface PaillierSecretKey {
  p: bigint;
  q: bigint;
  /** Sophie-Germain halves: p = 2p'+1, q = 2q'+1 */
  pp: bigint;
  qq: bigint;
  /** m = p' q' */
  m: bigint;
  /** decryption exponent: d = 0 mod m, d = 1 mod N */
  d: bigint;
}

export interface PaillierKeyPair {
  pk: PaillierPublicKey;
  sk: PaillierSecretKey;
}

export function publicKeyFromN(n: bigint): PaillierPublicKey {
  return { n, n2: n * n, bits: bitLength(n) };
}

export function generateKeyPair(bits = 256, rng: Rng = getDefaultRng()): PaillierKeyPair {
  if (bits < 64 || bits % 2) throw new Error("modulus bits must be even and >= 64");
  for (;;) {
    const a = genSafePrime(bits / 2, rng);
    const b = genSafePrime(bits / 2, rng);
    if (a.p === b.p) continue;
    const n = a.p * b.p;
    if (bitLength(n) !== bits) continue;
    const m = a.q * b.q;
    // d = 0 (mod m), d = 1 (mod N)  =>  d = m * (m^{-1} mod N)
    const d = m * modInv(m, n);
    return {
      pk: publicKeyFromN(n),
      sk: { p: a.p, q: b.p, pp: a.q, qq: b.q, m, d },
    };
  }
}

// ---------------------------------------------------------------- encoding
export function encode(pk: PaillierPublicKey, x: bigint): bigint {
  const lim = pk.n / 2n;
  if (x > lim || x < -lim) throw new Error("plaintext out of range for modulus");
  return mod(x, pk.n);
}

export function decode(pk: PaillierPublicKey, x: bigint): bigint {
  x = mod(x, pk.n);
  return x > pk.n / 2n ? x - pk.n : x;
}

// ---------------------------------------------------------------- operations
export interface Encrypted {
  c: bigint;
  /** encryption randomness; kept by the encryptor to build the proof of knowledge */
  r: bigint;
}

export function encryptWithRandomness(pk: PaillierPublicKey, m: bigint, rng: Rng = getDefaultRng()): Encrypted {
  const r = randUnit(pk.n, rng);
  const em = encode(pk, m);
  const c = (((1n + em * pk.n) % pk.n2) * modPow(r, pk.n, pk.n2)) % pk.n2;
  return { c, r };
}

export function encrypt(pk: PaillierPublicKey, m: bigint, rng: Rng = getDefaultRng()): bigint {
  return encryptWithRandomness(pk, m, rng).c;
}

export function add(pk: PaillierPublicKey, a: bigint, b: bigint): bigint {
  return (a * b) % pk.n2;
}

/** k (.) c for k >= 0. Negative scalars are allowed through inversion of c. */
export function scalarMul(pk: PaillierPublicKey, c: bigint, k: bigint): bigint {
  if (k >= 0n) return modPow(c, k, pk.n2);
  return modPow(modInv(c, pk.n2), -k, pk.n2);
}

/** The ciphertext of 0 with randomness 1: neutral element of (+). */
export const ZERO_CIPHERTEXT = 1n;

export function L(pk: PaillierPublicKey, x: bigint): bigint {
  if ((x - 1n) % pk.n !== 0n) throw new Error("L(): input is not 1 mod N (invalid ciphertext or shares)");
  return (x - 1n) / pk.n;
}

/** Textbook decryption with the (dealer-side) secret key. Used only for tests/baselines. */
export function decryptWithSecret(pk: PaillierPublicKey, sk: PaillierSecretKey, c: bigint): bigint {
  // c^{2d} = 1 + 2 m d N = 1 + 2 m N  (mod N^2): the squaring removes the order-2 component
  const x = modPow(c, 2n * sk.d, pk.n2);
  const two = 2n;
  return decode(pk, mod(L(pk, x) * modInv(two, pk.n), pk.n));
}

export function isValidCiphertext(pk: PaillierPublicKey, c: bigint): boolean {
  if (c <= 0n || c >= pk.n2) return false;
  // gcd(c, N) = 1 is necessary; checking via c^? is expensive, test inverse existence
  try {
    modInv(c, pk.n);
    return true;
  } catch {
    return false;
  }
}
