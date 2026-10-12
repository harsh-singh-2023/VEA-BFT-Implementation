/** Decryption committee member: holds one Shamir share of the Paillier secret (paper Section V-G). */
import { Signer } from "ethers";
import { KeyShare } from "../crypto/threshold";

export interface CommitteeMember {
  hospital: number; // index of the hospital that hosts this member
  address: string;
  signer: Signer;
  /** 1-based index in the current epoch */
  index: number;
  share: KeyShare;
  online: boolean;
}
