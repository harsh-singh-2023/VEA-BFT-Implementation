import { expect } from "chai";
import { SeededRng, setDefaultRng, isProbablePrime, modPow, modInv } from "../src/crypto/bigmath";
import { generateKeyPair, encrypt, encryptWithRandomness, add, scalarMul, decryptWithSecret } from "../src/crypto/paillier";
import {
  dealerSetup, partialDecrypt, combineShares, verifyDecryptionShare, verifyShareAgainstCommitments,
  rotateCommittee, reshareDeal, verifyDeal, DecryptionShare,
} from "../src/crypto/threshold";
import { proveVector, verifyVector } from "../src/crypto/sigma";

const rng = new SeededRng("crypto-tests");
setDefaultRng(rng);
const BITS = 256;

function subsets<T>(arr: T[], k: number): T[][] {
  if (k === 0) return [[]];
  if (arr.length < k) return [];
  const [h, ...rest] = arr;
  return [...subsets(rest, k - 1).map((s) => [h, ...s]), ...subsets(rest, k)];
}

describe("crypto / bigmath", () => {
  it("Miller-Rabin agrees on known primes and composites", () => {
    expect(isProbablePrime(2n ** 127n - 1n)).to.equal(true); // Mersenne prime
    expect(isProbablePrime(2n ** 127n + 1n)).to.equal(false);
    expect(isProbablePrime(561n)).to.equal(false); // Carmichael number
  });
  it("modPow matches repeated multiplication and Fermat", () => {
    const p = 2n ** 89n - 1n;
    expect(modPow(7n, p - 1n, p)).to.equal(1n);
    expect(modPow(3n, 20n, 1000003n)).to.equal(3n ** 20n % 1000003n);
    expect((modInv(12345n, p) * 12345n) % p).to.equal(1n);
  });
});

describe("crypto / Paillier", () => {
  const kp = generateKeyPair(BITS, rng);
  it("modulus has the requested size and safe-prime structure", () => {
    expect(kp.pk.bits).to.equal(BITS);
    expect(kp.sk.p).to.equal(2n * kp.sk.pp + 1n);
    expect(kp.sk.q).to.equal(2n * kp.sk.qq + 1n);
  });
  it("encrypts and decrypts positive, zero and negative integers", () => {
    for (const m of [0n, 1n, 123456789n, -1n, -987654321n]) {
      expect(decryptWithSecret(kp.pk, kp.sk, encrypt(kp.pk, m))).to.equal(m);
    }
  });
  it("is additively homomorphic and supports scalar multiplication", () => {
    const a = 31337n, b = -4242n;
    const ca = encrypt(kp.pk, a), cb = encrypt(kp.pk, b);
    expect(decryptWithSecret(kp.pk, kp.sk, add(kp.pk, ca, cb))).to.equal(a + b);
    expect(decryptWithSecret(kp.pk, kp.sk, scalarMul(kp.pk, ca, 17n))).to.equal(17n * a);
    expect(decryptWithSecret(kp.pk, kp.sk, scalarMul(kp.pk, cb, 5n))).to.equal(5n * b);
  });
  it("is probabilistic: two encryptions of the same value differ", () => {
    expect(encrypt(kp.pk, 5n)).to.not.equal(encrypt(kp.pk, 5n));
  });
});

describe("crypto / threshold Paillier (t-of-m, verifiable shares)", () => {
  const n = 5, t = 3;
  const deal = dealerSetup({ bits: BITS, n, t, rng });
  const m = -123456n;
  const c = encrypt(deal.pub.pk, m);

  it("dealer shares match the public Feldman commitments", () => {
    for (const s of deal.shares) expect(verifyShareAgainstCommitments(deal.pub, deal.commitments, s)).to.equal(true);
  });
  it("every t-subset of the committee decrypts correctly", () => {
    for (const S of subsets([1, 2, 3, 4, 5], t)) {
      const ds = S.map((i) => partialDecrypt(deal.pub, deal.shares[i - 1], c, rng));
      expect(combineShares(deal.pub, c, ds)).to.equal(m);
    }
  });
  it("fewer than t shares cannot be combined", () => {
    const ds = [1, 2].map((i) => partialDecrypt(deal.pub, deal.shares[i - 1], c, rng));
    expect(() => combineShares(deal.pub, c, ds)).to.throw();
  });
  it("homomorphic aggregate decrypts to the weighted sum", () => {
    const ca = encrypt(deal.pub.pk, 1000n), cb = encrypt(deal.pub.pk, -250n);
    const agg = add(deal.pub.pk, scalarMul(deal.pub.pk, ca, 3n), scalarMul(deal.pub.pk, cb, 4n));
    const ds = [2, 4, 5].map((i) => partialDecrypt(deal.pub, deal.shares[i - 1], agg, rng));
    expect(combineShares(deal.pub, agg, ds)).to.equal(3n * 1000n + 4n * -250n);
  });
  it("decryption-share proofs verify, and tampering is detected", () => {
    const ds = partialDecrypt(deal.pub, deal.shares[0], c, rng);
    expect(verifyDecryptionShare(deal.pub, c, ds)).to.equal(true);
    const bad: DecryptionShare = { ...ds, ci: (ds.ci * 2n) % deal.pub.pk.n2 };
    expect(verifyDecryptionShare(deal.pub, c, bad)).to.equal(false);
    const wrongCt = encrypt(deal.pub.pk, 7n);
    expect(verifyDecryptionShare(deal.pub, wrongCt, ds)).to.equal(false);
    const ds3 = [1, 2, 3].map((i) => partialDecrypt(deal.pub, deal.shares[i - 1], c, rng));
    ds3[1] = { ...ds3[1], ci: (ds3[1].ci * 3n) % deal.pub.pk.n2 };
    expect(() => combineShares(deal.pub, c, ds3)).to.throw(/failed its proof/);
  });
  it("matches textbook decryption", () => {
    const x = encrypt(deal.pub.pk, 99999n);
    const ds = [1, 3, 5].map((i) => partialDecrypt(deal.pub, deal.shares[i - 1], x, rng));
    expect(combineShares(deal.pub, x, ds)).to.equal(decryptWithSecret(deal.pub.pk, deal.keypair.sk, x));
  });

  describe("committee rotation by verifiable resharing (P4)", () => {
    it("grows the committee 5 -> 6 with a new threshold; old ciphertexts still decrypt; pk unchanged", () => {
      const stored = encrypt(deal.pub.pk, 424242n); // encrypted BEFORE the rotation
      const r1 = rotateCommittee(deal.pub, deal.shares, [1, 3, 4], 6, 4, rng);
      expect(r1.pub.pk.n).to.equal(deal.pub.pk.n);
      expect(r1.pub.epoch).to.equal(2);
      for (const S of [[1, 2, 3, 4], [3, 4, 5, 6], [1, 2, 5, 6]]) {
        const ds = S.map((i) => partialDecrypt(r1.pub, r1.shares[i - 1], stored, rng));
        expect(combineShares(r1.pub, stored, ds)).to.equal(424242n);
      }
    });
    it("shrinks 5 -> 3 (hospital leaves) and chains a second rotation 3 -> 4", () => {
      const stored = encrypt(deal.pub.pk, -777n);
      const r1 = rotateCommittee(deal.pub, deal.shares, [2, 3, 5], 3, 2, rng);
      const ds1 = [1, 3].map((i) => partialDecrypt(r1.pub, r1.shares[i - 1], stored, rng));
      expect(combineShares(r1.pub, stored, ds1)).to.equal(-777n);
      const r2 = rotateCommittee(r1.pub, r1.shares, [1, 2], 4, 3, rng);
      const ds2 = [2, 3, 4].map((i) => partialDecrypt(r2.pub, r2.shares[i - 1], stored, rng));
      expect(combineShares(r2.pub, stored, ds2)).to.equal(-777n);
      // the ledger state kappa evolves deterministically from public data
      expect(r2.pub.kappa).to.not.equal(1n);
    });
    it("a corrupted sub-share is detected by the receiving member", () => {
      const S = [1, 2, 3];
      const deal1 = reshareDeal(deal.pub, deal.shares[0], S, 5, 3, rng);
      expect(verifyDeal(deal.pub, deal1, S, 2, 3)).to.equal(true);
      const forged = { ...deal1, subshares: deal1.subshares.map((x, i) => (i === 1 ? x + 1n : x)) };
      expect(verifyDeal(deal.pub, forged, S, 2, 3)).to.equal(false);
    });
    it("a dealer that reshares a value other than its real share is detected", () => {
      const S = [1, 2, 3];
      const lie = reshareDeal(deal.pub, { index: 1, s: deal.shares[0].s + 5n }, S, 5, 3, rng);
      expect(verifyDeal(deal.pub, lie, S, 1, 3)).to.equal(false);
    });
    it("old shares of a former member remain a valid old share (documented limitation)", () => {
      const stored = encrypt(deal.pub.pk, 5n);
      const r1 = rotateCommittee(deal.pub, deal.shares, [1, 2, 3], 5, 3, rng);
      // t old shares still decrypt under the OLD sharing: rotation does not revoke them
      const old = [1, 2, 3].map((i) => partialDecrypt(deal.pub, deal.shares[i - 1], stored, rng));
      expect(combineShares(deal.pub, stored, old)).to.equal(5n);
      expect(r1.pub.pk.n).to.equal(deal.pub.pk.n);
    });
  });
});

describe("crypto / Sigma proof of well-formedness", () => {
  const kp = generateKeyPair(BITS, rng);
  const ms = [10n, -20n, 30n, 0n];
  const encs = ms.map((m) => encryptWithRandomness(kp.pk, m, rng));
  const cts = encs.map((e) => e.c);
  const ctx = { round: 7, hospital: "0x00000000000000000000000000000000000000a1" };
  const proof = proveVector(kp.pk, ctx, cts, ms, encs.map((e) => e.r), 1400n, rng);

  it("accepts an honest proof", () => {
    expect(verifyVector(kp.pk, ctx, cts, proof, 10_000n).ok).to.equal(true);
  });
  it("rejects replay in another round", () => {
    expect(verifyVector(kp.pk, { ...ctx, round: 8 }, cts, proof, 10_000n).ok).to.equal(false);
  });
  it("rejects replay by another hospital", () => {
    const other = { ...ctx, hospital: "0x00000000000000000000000000000000000000b2" };
    expect(verifyVector(kp.pk, other, cts, proof, 10_000n).ok).to.equal(false);
  });
  it("rejects a ciphertext that was replaced or re-randomised after proving", () => {
    const forged = [...cts];
    forged[2] = (forged[2] * encrypt(kp.pk, 0n)) % kp.pk.n2;
    expect(verifyVector(kp.pk, ctx, forged, proof, 10_000n).ok).to.equal(false);
  });
  it("rejects a copied ciphertext the prover does not know the opening of", () => {
    const stolen = encryptWithRandomness(kp.pk, 99n, rng).c;
    const cts2 = [...cts]; cts2[0] = stolen;
    expect(verifyVector(kp.pk, ctx, cts2, proof, 10_000n).ok).to.equal(false);
  });
  it("rejects when the stand-in norm check fails", () => {
    const r = verifyVector(kp.pk, ctx, cts, proof, 1000n);
    expect(r.ok).to.equal(false);
    expect(r.reason).to.match(/norm/);
  });
  it("rejects a tampered claimed norm (it is bound into the transcript)", () => {
    expect(verifyVector(kp.pk, ctx, cts, { ...proof, claimedNormSq: 5n }, 10_000n).ok).to.equal(false);
  });
});
