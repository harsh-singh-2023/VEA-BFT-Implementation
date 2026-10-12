/**
 * Content-addressed off-chain store (the role IPFS plays in the architecture).
 * The content id is keccak256(bytes) so it fits the ledger's bytes32 fields and can be
 * re-derived by any auditor. Implementations: in-memory and on-disk.
 */
import { keccak256 } from "ethers";
import * as fs from "fs";
import * as path from "path";

export interface ContentStore {
  put(bytes: Uint8Array): Promise<string>;
  get(cid: string): Promise<Uint8Array>;
  has(cid: string): Promise<boolean>;
}

export const cidOf = (bytes: Uint8Array): string => keccak256(bytes);

export class MemoryStore implements ContentStore {
  private m = new Map<string, Uint8Array>();
  async put(bytes: Uint8Array) {
    const cid = cidOf(bytes);
    this.m.set(cid, bytes);
    return cid;
  }
  async get(cid: string) {
    const b = this.m.get(cid);
    if (!b) throw new Error("content not found: " + cid);
    // integrity check: the store may be untrusted, the id is the root of trust
    if (cidOf(b) !== cid) throw new Error("content hash mismatch for " + cid);
    return b;
  }
  async has(cid: string) {
    return this.m.has(cid);
  }
  /** test hook: corrupt stored content to check that auditors notice */
  tamper(cid: string, bytes: Uint8Array) {
    this.m.set(cid, bytes);
  }
  get size() {
    return this.m.size;
  }
}

export class FsStore implements ContentStore {
  constructor(private dir: string) {
    fs.mkdirSync(dir, { recursive: true });
  }
  private file(cid: string) {
    return path.join(this.dir, cid.replace(/^0x/, "") + ".blob");
  }
  async put(bytes: Uint8Array) {
    const cid = cidOf(bytes);
    fs.writeFileSync(this.file(cid), bytes);
    return cid;
  }
  async get(cid: string) {
    const b = new Uint8Array(fs.readFileSync(this.file(cid)));
    if (cidOf(b) !== cid) throw new Error("content hash mismatch for " + cid);
    return b;
  }
  async has(cid: string) {
    return fs.existsSync(this.file(cid));
  }
}
