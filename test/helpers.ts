import { expect } from "chai";
import { Federation } from "../src/orchestrator/federation";
import { signDigest, proposalDigest } from "../src/chain/ledger";
import { Proposal } from "../src/protocol";
import { ValidatorFault } from "../src/config";

/** Assert that a promise rejects with a revert whose reason contains `reason`. */
export async function expectRevert(p: Promise<any>, reason: string) {
  try {
    await p;
  } catch (e: any) {
    const text = [e.reason, e.shortMessage, e.message, e.info?.error?.message].filter(Boolean).join(" | ");
    expect(text, "revert reason").to.contain(reason);
    return;
  }
  expect.fail(`expected revert "${reason}" but the call succeeded`);
}

/** A round in which hospitals submitted and submissions are closed, but nothing is finalized yet. */
export async function closedRound(fed: Federation, faults: Record<number, ValidatorFault> = {}) {
  const { roundId } = await fed.beginRound({ validatorFaults: faults });
  return roundId;
}

export const sigsFor = (fed: Federation, digest: string, who: number[]) => Promise.all(who.map((i) => signDigest(fed.validators[i].signer, digest)));

export function finalizeArgs(p: Extract<Proposal, { kind: "aggregate" }>) {
  return { roundId: p.roundId, viewNo: p.view, included: p.included, aggHash: p.aggCid, betaNew: p.betaNew };
}
export { proposalDigest };
