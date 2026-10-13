# VEA-BFT: Verifiable Encrypted Aggregation with BFT validators

Runnable implementation and simulation of the paper *"Enhancement of Privacy-Preserving Federated
Learning for Healthcare Using Verifiable Encrypted Aggregation"* (draft 3, Oct 2026). Hospitals train
logistic-regression models locally, send **Paillier-encrypted** updates with **Fiat–Shamir proofs** to a
permissioned **PBFT** validator set; each validator independently re-verifies the proofs and
**recomputes the homomorphic aggregate** before voting; the aggregate is decrypted by a **t-of-m threshold
committee** that can be **rotated by verifiable resharing**; everything is anchored in a Solidity ledger
that replays any round.

```
npm install
npm test                 # 82 tests: crypto, ML, ledger contract, PBFT, end-to-end federation
npm run demo             # scripted tour: honest rounds, Byzantine primary, poisoned update, rotation, audit
npm run server           # dashboard on http://localhost:3000 (in-process Hardhat chain)
npm run evaluate         # reproduces paper Tables III/IV + Figs 2-5 into results/   (--quick for a fast pass)
npm run dev              # separate `hardhat node` + dashboard against it (RPC_URL)
npm run node & npm run deploy   # deploy + genesis to a standing node, writes deployments/
```

## Architecture

<img width="7198" height="9974" alt="diagram" src="https://github.com/user-attachments/assets/58a6792b-869a-4965-9e3f-be6f0610bcd1" />


```
 Hospital layer              Consensus layer (PBFT, 3f+1)                 Key-management layer
 ─────────────               ───────────────────────────────              ─────────────────────
 local training  Δ_i         primary proposes S_r, ct_Σ, β'               t-of-m threshold decrypt of ct_Σ only
 clip ‖Δ‖≤B, quantise s      every validator: verify π_i, recompute       w ← w + Dec(ct_Σ)/(s·n_S)
 Enc_pk per coordinate       ct_Σ = ⊕ n_i⊙ct_i, check S_r and β' ≥ τ      reshare sk to a new committee when
 proof π_i(round, hospital)  PREPARE → COMMIT (ECDSA over digest)         the hospital cohort changes
        │                                  │ QC = 2f+1 signatures                 ▲
        └── ct_i, π_i → content store ─────┴──► VEABFTLedger.sol (hashes, QC, epochs, noise budget) ──┘
```

* **Off-chain content store** (`src/storage`): content-addressed (keccak256), plays the role of IPFS. Only
  32-byte ids go on chain, so an auditor can fetch and replay everything.
* **Ledger** (`contracts/VEABFTLedger.sol`): round lifecycle, quorum-certificate verification (`ecrecover`
  over 2f+1 distinct validator signatures, primary of the view must be among them), re-derivation of
  inclusion set / n_S / k_min / noise budget, committee epochs and rotation gate, bootstrap.
* **PBFT** runs off-chain between validators; its decision is anchored on chain as the quorum certificate.

## Paper → code

| Paper | Where |
|---|---|
| III-A Paillier, signed encoding | `src/crypto/paillier.ts` |
| V-D per-hospital proof (Fiat–Shamir Σ-protocol, bound to round + hospital) | `src/crypto/sigma.ts` |
| III-D / V-G threshold Paillier, verifiable shares, **resharing** (P4) | `src/crypto/threshold.ts` |
| V-C local training, clip, quantise | `src/nodes/hospital.ts`, `src/ml/logreg.ts` |
| V-E (1) aggregate; validators recompute | `src/nodes/validator.ts` |
| V-F consensus, abort / exclude-and-continue, view change | `src/consensus/pbft.ts`, `src/nodes/validator.ts` |
| V-H noise budget (P5), bootstrap | `VEABFTLedger.sol` (`_checkBudget`, `bootstrap`), `Federation.bootstrapNoise` |
| Algorithm 1 (one round) | `Federation.runRound` in `src/orchestrator/federation.ts` |
| VI security goals P1–P5 | tests in `test/` (see below) |
| VII datasets, preprocessing, non-IID split | `src/ml/dataset.ts` (+ `data/raw`) |
| VIII-C out-of-bound update at round 15 | `npm run evaluate`, `test/federation.test.ts` |
| Replay of a round by an auditor | `Federation.audit` |

## What the tests establish

`test/ledger.test.ts` – the contract refuses: <2f+1 signatures, duplicate or non-validator signers,
quorums that omit the view's primary, certificates over a different proposal, wrong noise budgets, bad
inclusion sets, dropped submissions under the abort policy, out-of-order lifecycle calls, rounds before a
committee rotation. The off-chain digest equals `proposalDigest` on chain.

`test/pbft.test.ts` – decides in view 0 with the expected 24 messages for n=4; tolerates a crashed backup
and garbage signatures; **view change** to an honest primary after a primary that tampers with ct_Σ,
proposes a wrong budget, equivocates, crashes, signs badly or censors a hospital (both policies); two bad
primaries in a row; 2 of 4 crashed ⇒ the round stalls and nothing wrong is finalized; 7 validators (f=2).
In every successful case the decrypted model equals plaintext FedAvg to within the quantisation error.

`test/federation.test.ts` – ×50 update rejected and round aborted with `w` unchanged; exclude-and-continue;
replayed and malformed submissions rejected; offline hospitals and k_min; committee offline/bad share;
committee **join, leave, two rotations in a row, cheating dealer**; noise-budget exhaustion and
bootstrapping; audits pass on every round (across epochs) and detect tampered store content.

## Evaluation (`npm run evaluate`)

Per dataset: centralized, plaintext FedAvg, VEA-BFT with the ×50 update at round 15 (abort policy, the
paper's setup), VEA-BFT **without** injection (control) and VEA-BFT with exclude-and-continue. Output:
`results/tables.md`, `results/results.json`, `results/fig_*.svg`.

The paper left the cause of the small log-loss gap to plaintext FedAvg open ("the norm clip and the
mid-training rejected round are candidates"). The control run isolates it: without injection VEA-BFT and
plaintext FedAvg agree to ~1e-7 in weights, so the gap in the injected run is the **skipped round**
(the abort policy leaves the model one step behind), not the encryption or quantisation. This was checked directly: plaintext FedAvg run for 29 rounds (= 30 with one skipped) matches the injected VEA-BFT run to ≤ 2e-7 log-loss on all three datasets.

Hyper-parameters are not given in the paper; defaults here (1 local epoch, lr 0.1, L2 0.01, B = 0.5,
s = 10^6, k_min = 3) are chosen so that honest updates are never clipped or rejected and a ×50 update is
always out of bound. With one full-batch epoch per round, sample-weighted FedAvg equals centralized
gradient descent exactly, which is why accuracy is identical across methods. Absolute numbers differ from the
paper (different random split and hyper-parameters); the qualitative results do not.

## Honest limitations (inherited from the paper, and a few more)

* **256-bit Paillier is not secure.** Use ≥ 2048 bits in any real deployment (`bits` in `src/config.ts`);
  timings at 256 bits are not representative.
* **Norm bound is a stand-in.** Validators check the *claimed* squared norm bound into the proof transcript; a
  hospital that lies about its norm is not caught (`test/federation.test.ts`, "LIMITATION"). The production
  replacement is a range proof / SNARK over the packing circuit. A SNARK for π_Σ (light clients) and CKKS are not implemented.
* **Noise budget is an accounting model.** Paillier has no noise; the ledger tracks a synthetic budget with
  configurable per-operation costs to demonstrate P5 (floor τ, bootstrapping as a validated action).
* **Trusted dealer** for the initial key generation (stated in the paper); resharing afterwards is
  verifiable (Feldman-style commitments in the hidden-order group, integer sharing, Shoup/Damgård–Jurik).
  Resharing does not revoke old shares (bound of t−1 corrupt members must hold across rotations).
* **PBFT is simulated in-process** on a deterministic FIFO network with a logical timer (fires when the
  network is idle); view change carries prepared proposals but honest primaries re-derive the proposal
  deterministically from ledger state. Safety (no two proposals decided) is asserted on every run.
* A hospital that trains on poor or mislabelled data, or poisons within the norm bound, is accepted.
* Ciphertext blobs are JSON (`bn:` hex), which is simple but bulky; a binary encoding would shrink them.

## Layout

```
contracts/VEABFTLedger.sol     on-chain ledger
src/crypto                     Paillier, threshold + resharing, Σ-proofs, big-int helpers
src/consensus/pbft.ts          PBFT engine (pre-prepare/prepare/commit/view-change)
src/nodes                      hospital, validator, committee member
src/orchestrator/federation.ts rounds, rotation, bootstrap, audit
src/chain                      ethers client + digests, in-process or RPC chain
src/storage                    content-addressed store
src/ml                         datasets, logistic regression, FedAvg, metrics
src/server + web               dashboard (REST + SSE)
src/cli                        demo, evaluate, deploy, dev
test                           mocha tests (run by `hardhat test`)
```
