/**
 * Arbitrary-precision helpers on top of native BigInt: modular arithmetic, primality
 * testing, (safe) prime generation, hashing to integers and a seedable RNG so every
 * experiment in the paper can be reproduced exactly.
 */
import { createHash, randomBytes } from "crypto";

// ---------------------------------------------------------------- RNG
export interface Rng {
  bytes(n: number): Uint8Array;
}

export class SecureRng implements Rng {
  bytes(n: number): Uint8Array {
    return new Uint8Array(randomBytes(n));
  }
}

/** SHA-256 counter-mode DRBG. Deterministic: only for reproducible experiments/tests. */
export class SeededRng implements Rng {
  private counter = 0n;
  private buf: Uint8Array = new Uint8Array(0);
  constructor(private seed: string) {}
  bytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let filled = 0;
    while (filled < n) {
      if (this.buf.length === 0) {
        this.buf = new Uint8Array(
          createHash("sha256").update(this.seed).update(String(this.counter++)).digest()
        );
      }
      const take = Math.min(n - filled, this.buf.length);
      out.set(this.buf.subarray(0, take), filled);
      this.buf = this.buf.subarray(take);
      filled += take;
    }
    return out;
  }
  /** Independent child stream, so adding a consumer does not shift other streams. */
  fork(label: string): SeededRng {
    return new SeededRng(this.seed + "/" + label);
  }
}

let defaultRng: Rng = new SecureRng();
export function setDefaultRng(r: Rng) {
  defaultRng = r;
}
export function getDefaultRng(): Rng {
  return defaultRng;
}

// ---------------------------------------------------------------- conversions
export function bytesToBig(b: Uint8Array): bigint {
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return x;
}

export function bigToBytes(x: bigint, len?: number): Uint8Array {
  if (x < 0n) throw new Error("negative bigint");
  let hex = x.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const raw = hex === "00" ? new Uint8Array([0]) : Uint8Array.from(Buffer.from(hex, "hex"));
  if (len === undefined) return raw;
  if (raw.length > len) throw new Error("bigint does not fit in " + len + " bytes");
  const out = new Uint8Array(len);
  out.set(raw, len - raw.length);
  return out;
}

export const toHex = (x: bigint): string => "0x" + x.toString(16);
export const fromHex = (s: string): bigint => BigInt(s.startsWith("0x") ? s : "0x" + s);

export function bitLength(x: bigint): number {
  return x === 0n ? 0 : x.toString(2).length;
}

// ---------------------------------------------------------------- randomness
/** Uniform integer with exactly `bits` random bits (top bit not forced). */
export function randBits(bits: number, rng: Rng = defaultRng): bigint {
  const nBytes = Math.ceil(bits / 8);
  const x = bytesToBig(rng.bytes(nBytes));
  return x & ((1n << BigInt(bits)) - 1n);
}

/** Uniform integer in [0, n). Rejection sampling, no modulo bias. */
export function randBelow(n: bigint, rng: Rng = defaultRng): bigint {
  if (n <= 0n) throw new Error("randBelow: n must be positive");
  const bits = bitLength(n);
  for (;;) {
    const x = randBits(bits, rng);
    if (x < n) return x;
  }
}

/** Uniform unit of Z_n^*. */
export function randUnit(n: bigint, rng: Rng = defaultRng): bigint {
  for (;;) {
    const x = randBelow(n, rng);
    if (x > 1n && gcd(x, n) === 1n) return x;
  }
}

// ---------------------------------------------------------------- modular arithmetic
export function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

export function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b) [a, b] = [b, a % b];
  return a;
}

export function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  let [or, r] = [a, b];
  let [os, s] = [1n, 0n];
  let [ot, t] = [0n, 1n];
  while (r !== 0n) {
    const q = or / r;
    [or, r] = [r, or - q * r];
    [os, s] = [s, os - q * s];
    [ot, t] = [t, ot - q * t];
  }
  return [or, os, ot];
}

export function modInv(a: bigint, m: bigint): bigint {
  const [g, x] = egcd(mod(a, m), m);
  if (g !== 1n) throw new Error("modInv: not invertible");
  return mod(x, m);
}

/** Left-to-right square-and-multiply with a 4-bit window. e must be >= 0. */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  if (m === 1n) return 0n;
  if (exp < 0n) throw new Error("modPow: negative exponent (use modInv first)");
  base = mod(base, m);
  if (exp === 0n) return 1n;
  if (exp < 16n) {
    let r = 1n;
    for (let i = Number(exp); i > 0; i--) r = (r * base) % m;
    return r;
  }
  const W = 4;
  const table: bigint[] = new Array(1 << W);
  table[0] = 1n;
  for (let i = 1; i < table.length; i++) table[i] = (table[i - 1] * base) % m;
  const bits = exp.toString(2);
  const pad = (W - (bits.length % W)) % W;
  const s = "0".repeat(pad) + bits;
  let r = 1n;
  for (let i = 0; i < s.length; i += W) {
    for (let j = 0; j < W; j++) r = (r * r) % m;
    const idx = parseInt(s.substr(i, W), 2);
    if (idx) r = (r * table[idx]) % m;
  }
  return r;
}

/** base^exp mod m for a signed exponent (inverts the base for negative exponents). */
export function modPowSigned(base: bigint, exp: bigint, m: bigint): bigint {
  return exp >= 0n ? modPow(base, exp, m) : modPow(modInv(base, m), -exp, m);
}

export function factorial(n: number): bigint {
  let r = 1n;
  for (let i = 2n; i <= BigInt(n); i++) r *= i;
  return r;
}

// ---------------------------------------------------------------- primes
const SMALL_PRIMES: number[] = (() => {
  const lim = 2000;
  const sieve = new Uint8Array(lim + 1);
  const ps: number[] = [];
  for (let i = 2; i <= lim; i++) {
    if (!sieve[i]) {
      ps.push(i);
      for (let j = i * i; j <= lim; j += i) sieve[j] = 1;
    }
  }
  return ps;
})();

function passesTrialDivision(n: bigint): boolean {
  for (const p of SMALL_PRIMES) {
    const bp = BigInt(p);
    if (n === bp) return true;
    if (n % bp === 0n) return false;
  }
  return true;
}

export function isProbablePrime(n: bigint, rounds = 24, rng: Rng = defaultRng): boolean {
  if (n < 2n) return false;
  if (!passesTrialDivision(n)) return false;
  if (n < 4_000_000n) return true; // trial division by all primes < 2000 covers n < 2000^2
  let d = n - 1n;
  let r = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    r++;
  }
  const nm1 = n - 1n;
  outer: for (let i = 0; i < rounds; i++) {
    const a = 2n + randBelow(n - 3n, rng);
    let x = modPow(a, d, n);
    if (x === 1n || x === nm1) continue;
    for (let j = 1; j < r; j++) {
      x = (x * x) % n;
      if (x === nm1) continue outer;
    }
    return false;
  }
  return true;
}

export function genPrime(bits: number, rng: Rng = defaultRng): bigint {
  for (;;) {
    let c = randBits(bits, rng);
    c |= 1n << BigInt(bits - 1);
    c |= 1n;
    if (isProbablePrime(c, 24, rng)) return c;
  }
}

/** Safe prime p = 2q + 1 with q prime; p has exactly `bits` bits. */
export function genSafePrime(bits: number, rng: Rng = defaultRng): { p: bigint; q: bigint } {
  for (;;) {
    let q = randBits(bits - 1, rng);
    q |= 1n << BigInt(bits - 2);
    q |= 1n;
    const p = 2n * q + 1n;
    // cheap sieve on both q and p before any modular exponentiation
    let ok = true;
    for (const sp of SMALL_PRIMES) {
      const b = BigInt(sp);
      if (q !== b && q % b === 0n) {
        ok = false;
        break;
      }
      if (p !== b && p % b === 0n) {
        ok = false;
        break;
      }
    }
    if (!ok) continue;
    if (isProbablePrime(q, 16, rng) && isProbablePrime(p, 16, rng)) return { p, q };
  }
}

// ---------------------------------------------------------------- hashing
/** Length-prefixed SHA-256 over a list of parts, interpreted as an integer. Domain-separated. */
export function hashToInt(domain: string, parts: (bigint | string | number | Uint8Array)[], bits: number): bigint {
  const h = createHash("sha256");
  const enc = (b: Uint8Array) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b.length);
    h.update(len).update(b);
  };
  enc(Buffer.from(domain));
  for (const p of parts) {
    if (typeof p === "bigint") enc(bigToBytes(p < 0n ? -p : p));
    else if (typeof p === "number") enc(Buffer.from(String(p)));
    else if (typeof p === "string") enc(Buffer.from(p));
    else enc(p);
  }
  let digest = new Uint8Array(h.digest());
  // expand if more than 256 bits are requested
  let out = bytesToBig(digest);
  let have = 256;
  let ctr = 1;
  while (have < bits) {
    const more = createHash("sha256").update(digest).update(String(ctr++)).digest();
    out = (out << 256n) | bytesToBig(new Uint8Array(more));
    have += 256;
  }
  return out >> BigInt(have - bits);
}

export function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}
