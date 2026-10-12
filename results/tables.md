# VEA-BFT evaluation

30 rounds, 5 hospitals (non-IID split), 256-bit Paillier (NOT secure), 4 validators (f=1), committee 3-of-5. Out-of-bound update (x50) injected at round 15.

### heart
- control (no injection) vs plaintext FedAvg: max |Δw| = 1.30e-6, log-loss diff = 9.53e-8 → the quantisation (s=1000000) alone explains at most this much.
- injected-and-aborted run vs plaintext: log-loss diff = 1.98e-3 → this gap is the round skipped by the abort policy (the model is one step behind).
- round 15: abort policy → **aborted** (invalid-submission); exclude-and-continue → **decrypted** with S_r=[H4,H2,H3,H5].

### pima
- control (no injection) vs plaintext FedAvg: max |Δw| = 4.17e-7, log-loss diff = -7.24e-9 → the quantisation (s=1000000) alone explains at most this much.
- injected-and-aborted run vs plaintext: log-loss diff = 1.44e-3 → this gap is the round skipped by the abort policy (the model is one step behind).
- round 15: abort policy → **aborted** (invalid-submission); exclude-and-continue → **decrypted** with S_r=[H4,H2,H3,H5].

### wdbc
- control (no injection) vs plaintext FedAvg: max |Δw| = 8.39e-7, log-loss diff = -1.91e-7 → the quantisation (s=1000000) alone explains at most this much.
- injected-and-aborted run vs plaintext: log-loss diff = 2.60e-3 → this gap is the round skipped by the abort policy (the model is one step behind).
- round 15: abort policy → **aborted** (invalid-submission); exclude-and-continue → **decrypted** with S_r=[H4,H2,H3,H5].

## Table III: hold-out performance after 30 rounds

| Dataset | Method | Accuracy | Log-loss | AUC |
|---|---|---|---|---|
| heart | Centralized | 0.829 | 0.397 | 0.923 |
| heart | Plaintext FedAvg | 0.829 | 0.397 | 0.923 |
| heart | VEA-BFT (abort, injection) | 0.829 | 0.399 | 0.923 |
| heart | VEA-BFT (no injection) | 0.829 | 0.397 | 0.923 |
| heart | VEA-BFT (exclude-and-continue, injection) | 0.829 | 0.397 | 0.923 |
| pima | Centralized | 0.693 | 0.552 | 0.787 |
| pima | Plaintext FedAvg | 0.693 | 0.552 | 0.787 |
| pima | VEA-BFT (abort, injection) | 0.693 | 0.553 | 0.786 |
| pima | VEA-BFT (no injection) | 0.693 | 0.552 | 0.787 |
| pima | VEA-BFT (exclude-and-continue, injection) | 0.693 | 0.552 | 0.787 |
| wdbc | Centralized | 0.930 | 0.256 | 0.976 |
| wdbc | Plaintext FedAvg | 0.930 | 0.256 | 0.976 |
| wdbc | VEA-BFT (abort, injection) | 0.937 | 0.258 | 0.976 |
| wdbc | VEA-BFT (no injection) | 0.930 | 0.256 | 0.976 |
| wdbc | VEA-BFT (exclude-and-continue, injection) | 0.937 | 0.256 | 0.976 |

## Table IV: mean wall-clock time per round (ms), 5 hospitals, 256-bit Paillier, single process

| Dataset | Plaintext FedAvg | Local training | Encryption | Proof gen | Proof verify (per validator) | Homomorphic agg (per validator) | Threshold decryption (t members, incl. share proofs) | PBFT incl. all validation (4 validators) | Gas/round |
|---|---|---|---|---|---|---|---|---|---|
| heart | 0.827 | 0.23 | 31.7 | 38.8 | 49.7 | 2.03 | 318.6 | 473 | 1369104 |
| pima | 0.345 | 0.30 | 22.0 | 28.3 | 33.2 | 1.28 | 213.9 | 387 | 1369102 |
| wdbc | 0.127 | 0.23 | 28.6 | 35.6 | 45.0 | 1.72 | 280.9 | 436 | 1369098 |

Unlike the paper's Table IV, proof generation, proof verification, consensus and ledger gas are measured here. All validators run in one process, so the PBFT column is the sum over the four replicas.
