/** Typed client for VEABFTLedger.sol plus the off-chain digest functions validators sign. */
import { AbiCoder, BaseContract, ContractTransactionReceipt, Signer, getBytes, keccak256, solidityPacked, toUtf8Bytes } from "ethers";
import { VEABFTLedger, VEABFTLedger__factory } from "../../typechain-types";

export const DOMAIN_COMMIT = keccak256(toUtf8Bytes("VEABFT/COMMIT/v1"));
export const DOMAIN_ABORT = keccak256(toUtf8Bytes("VEABFT/ABORT/v1"));
export const DOMAIN_BOOTSTRAP = keccak256(toUtf8Bytes("VEABFT/BOOTSTRAP/v1"));
const coder = AbiCoder.defaultAbiCoder();

export enum RoundStatus { None, Open, Closed, Finalized, Aborted, Decrypted }

export interface LedgerParams {
  pkHash: string;
  sharingRoot: string;
  normBound: bigint;
  scale: bigint;
  beta0: bigint;
  tau: bigint;
  kMin: bigint;
  costScalarMul: bigint;
  costAdd: bigint;
  excludePolicy: boolean;
  carryBudget: boolean;
}

export interface TxRecord {
  name: string;
  from: string;
  hash: string;
  gas: bigint;
  block: number;
  ms: number;
}

export interface SubmissionView { exists: boolean; ctHash: string; proofHash: string; time: bigint }
export interface RoundView {
  status: RoundStatus; viewNo: bigint; epoch: bigint; nS: bigint; beta: bigint;
  inputsHash: string; aggHash: string; modelHash: string; sharesPosted: bigint;
}

/** Digest of an aggregate proposal; identical to VEABFTLedger.proposalDigest. */
export function proposalDigest(chainId: bigint, ledger: string, roundId: bigint, viewNo: bigint, inputsHash: string, aggHash: string, nS: bigint, betaNew: bigint): string {
  return keccak256(
    coder.encode(
      ["bytes32", "uint256", "address", "uint256", "uint256", "bytes32", "bytes32", "uint256", "uint256"],
      [DOMAIN_COMMIT, chainId, ledger, roundId, viewNo, inputsHash, aggHash, nS, betaNew]
    )
  );
}

export function abortDigest(chainId: bigint, ledger: string, roundId: bigint, viewNo: bigint, reason: string): string {
  return keccak256(coder.encode(["bytes32", "uint256", "address", "uint256", "uint256", "bytes32"], [DOMAIN_ABORT, chainId, ledger, roundId, viewNo, reason]));
}

export function bootstrapDigest(chainId: bigint, ledger: string, nonce: bigint): string {
  return keccak256(coder.encode(["bytes32", "uint256", "address", "uint256"], [DOMAIN_BOOTSTRAP, chainId, ledger, nonce]));
}

/** inputsHash over the inclusion set (ascending addresses), as _checkInclusion computes it. */
export function inputsHashOf(items: { hospital: string; ctHash: string; proofHash: string }[]): string {
  return keccak256(solidityPacked(items.flatMap(() => ["address", "bytes32", "bytes32"]), items.flatMap((i) => [i.hospital, i.ctHash, i.proofHash])));
}

export const reasonCode = (s: string) => keccak256(toUtf8Bytes(s));

/** Sign a 32-byte digest the way _verifyQuorum expects (EIP-191 personal sign). */
export async function signDigest(signer: Signer, digest: string): Promise<string> {
  return signer.signMessage(getBytes(digest));
}

export type TxHook = (r: TxRecord) => void;

export class Ledger {
  readonly c: VEABFTLedger;
  address = "";
  chainId = 0n;
  txs: TxRecord[] = [];
  onTx?: TxHook;

  private constructor(c: VEABFTLedger) {
    this.c = c;
  }

  static async deploy(owner: Signer, onTx?: TxHook): Promise<Ledger> {
    const t0 = Date.now();
    const c = await new VEABFTLedger__factory(owner).deploy();
    const rc = await c.deploymentTransaction()!.wait();
    const l = new Ledger(c);
    l.onTx = onTx;
    l.address = await c.getAddress();
    l.chainId = (await owner.provider!.getNetwork()).chainId;
    l.record("deploy", rc!, await owner.getAddress(), Date.now() - t0);
    return l;
  }

  static async attach(address: string, signer: Signer): Promise<Ledger> {
    const l = new Ledger(VEABFTLedger__factory.connect(address, signer));
    l.address = address;
    l.chainId = (await signer.provider!.getNetwork()).chainId;
    return l;
  }

  private record(name: string, rc: ContractTransactionReceipt, from: string, ms: number) {
    const r: TxRecord = { name, from, hash: rc.hash, gas: rc.gasUsed, block: rc.blockNumber, ms };
    this.txs.push(r);
    this.onTx?.(r);
  }

  /** Send a state-changing call from `signer`, wait for the receipt and log it. */
  async send(signer: Signer, name: string, fn: (c: VEABFTLedger) => Promise<any>): Promise<ContractTransactionReceipt> {
    const t0 = Date.now();
    const tx = await fn(this.c.connect(signer) as VEABFTLedger);
    const rc = (await tx.wait()) as ContractTransactionReceipt;
    this.record(name, rc, await signer.getAddress(), Date.now() - t0);
    return rc;
  }

  // ------------------------------------------------------------ views
  async params(): Promise<LedgerParams> {
    const p = await this.c.params();
    return {
      pkHash: p.pkHash, sharingRoot: p.sharingRoot, normBound: p.normBound, scale: p.scale, beta0: p.beta0, tau: p.tau,
      kMin: p.kMin, costScalarMul: p.costScalarMul, costAdd: p.costAdd, excludePolicy: p.excludePolicy, carryBudget: p.carryBudget,
    };
  }
  getValidators = () => this.c.getValidators();
  getHospitals = () => this.c.getHospitals();
  getSubmitters = (r: bigint | number) => this.c.getSubmitters(r);
  async getSubmission(r: bigint | number, h: string): Promise<SubmissionView> {
    const s = await this.c.getSubmission(r, h);
    return { exists: s.exists, ctHash: s.ctHash, proofHash: s.proofHash, time: s.time };
  }
  async getRound(r: bigint | number): Promise<RoundView> {
    const x = await this.c.rounds(r);
    return {
      status: Number(x.status) as RoundStatus, viewNo: x.viewNo, epoch: x.epoch, nS: x.nS, beta: x.beta,
      inputsHash: x.inputsHash, aggHash: x.aggHash, modelHash: x.modelHash, sharesPosted: x.sharesPosted,
    };
  }
  async hospitalInfo(h: string) {
    const x = await this.c.hospitals(h);
    return { registered: x.registered, active: x.active, nSamples: x.nSamples };
  }
  expectedBeta = (k: bigint | number) => this.c.expectedBeta(k);
  roundCounter = () => this.c.roundCounter();
  noiseBudget = () => this.c.noiseBudget();
  currentEpoch = () => this.c.currentEpoch();
  async getEpoch(e: bigint | number) {
    const [members, threshold, root, acks, active] = await this.c.getEpoch(e);
    return { members: [...members], threshold, root, acks, active };
  }
  primaryOf = (view: bigint | number) => this.c.primaryOf(view);
  f = () => this.c.f();
  quorum = () => this.c.quorum();
  cohortChanged = () => this.c.cohortChanged();
  bootstrapNonce = () => this.c.bootstrapNonce();
  pendingEpoch = () => this.c.pendingEpoch();
}

export type { BaseContract };
