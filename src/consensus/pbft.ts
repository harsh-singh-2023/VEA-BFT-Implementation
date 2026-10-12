/**
 * Permissioned PBFT between the 3f+1 validators (paper Section V-F), simulated in-process on a
 * deterministic FIFO network. One consensus instance decides one proposal per ledger round:
 *
 *   PRE-PREPARE  primary(view) -> all        (S_r, ct_Sigma, beta')  or  ABORT
 *   PREPARE      backups       -> all        only after the replica validated the proposal itself
 *   COMMIT       replicas      -> all        carries an ECDSA signature over the proposal digest
 *   VIEW-CHANGE  on timeout    -> all        carries the sender's prepared proposal, if any
 *
 * A proposal is "decided" at a replica once it holds 2f+1 valid COMMIT signatures that include
 * the primary's. Those signatures are exactly the quorum certificate the ledger contract checks.
 * The "timer" fires when the network is idle and a replica has not decided: with a logical clock
 * this is the same as an expired timeout under partial synchrony after GST.
 */
import { getBytes, verifyMessage } from "ethers";
import { ValidatorFault } from "../config";
import { Proposal } from "../protocol";

export interface ReplicaApp {
  index: number;
  address: string;
  fault: ValidatorFault;
  /** Called when this replica is primary of `view`. Several proposals = equivocation. */
  propose(view: number, carried?: Proposal): Promise<Proposal[]>;
  /** Independent validation of a proposal (proofs, recomputation, budget, censorship). */
  validate(p: Proposal): Promise<{ ok: boolean; reason?: string }>;
  sign(digest: string): Promise<string>;
}

type Msg =
  | { t: "PRE-PREPARE"; view: number; from: number; proposal: Proposal }
  | { t: "PREPARE"; view: number; from: number; digest: string }
  | { t: "COMMIT"; view: number; from: number; digest: string; sig: string }
  | { t: "VIEW-CHANGE"; view: number; from: number; prepared?: { view: number; proposal: Proposal } };

export interface LogEntry {
  seq: number;
  from: number;
  to: number | "all";
  type: string;
  view: number;
  digest?: string;
  note?: string;
}

export interface Decision {
  view: number;
  proposal: Proposal;
  /** signatures by distinct validators over proposal.digest, primary included */
  sigs: { from: number; sig: string }[];
}

export interface ConsensusResult {
  decision?: Decision;
  decisions: (Decision | undefined)[];
  finalView: number;
  viewChanges: number;
  networkMessages: number;
  rejections: { replica: number; view: number; reason: string }[];
  log: LogEntry[];
  ms: number;
}

class Replica {
  view = 0;
  accepted = new Map<number, Proposal>();
  prepares = new Map<string, Set<number>>(); // key view:digest
  commits = new Map<string, Map<number, string>>();
  committed = new Set<number>(); // views in which this replica already sent COMMIT
  prepared?: { view: number; proposal: Proposal };
  vcs = new Map<number, Map<number, Msg & { t: "VIEW-CHANGE" }>>();
  future: Msg[] = [];
  decided?: Decision;
  proposedIn = new Set<number>();

  constructor(readonly app: ReplicaApp, readonly eng: Engine) {}
  get silent() {
    return this.app.fault === "silent";
  }
  key = (v: number, d: string) => v + ":" + d;
}

class Engine {
  queue: { to: number; msg: Msg }[] = [];
  log: LogEntry[] = [];
  seq = 0;
  networkMessages = 0;
  viewChanges = 0;
  rejections: ConsensusResult["rejections"] = [];
  replicas: Replica[];
  n: number;
  f: number;

  constructor(apps: ReplicaApp[], readonly roundId: number) {
    this.n = apps.length;
    this.f = Math.floor((apps.length - 1) / 3);
    this.replicas = apps.map((a) => new Replica(a, this));
  }
  get quorum() {
    return 2 * this.f + 1;
  }
  primaryOf = (view: number) => view % this.n;

  private note(from: number, to: number | "all", m: Msg, note?: string) {
    if (this.log.length < 3000)
      this.log.push({
        seq: this.seq++, from, to, type: m.t, view: m.view,
        digest: m.t === "PRE-PREPARE" ? m.proposal.digest : m.t === "PREPARE" || m.t === "COMMIT" ? m.digest : undefined,
        note,
      });
  }

  broadcast(from: number, msg: Msg, note?: string) {
    this.note(from, "all", msg, note);
    for (let to = 0; to < this.n; to++) {
      this.queue.push({ to, msg });
      if (to !== from) this.networkMessages++;
    }
  }
  sendTo(from: number, to: number, msg: Msg, note?: string) {
    this.note(from, to, msg, note);
    this.queue.push({ to, msg });
    if (to !== from) this.networkMessages++;
  }

  // ------------------------------------------------------------ per-replica protocol
  async handle(r: Replica, m: Msg) {
    if (r.silent || r.decided) return;
    if (m.t === "VIEW-CHANGE") return this.onViewChange(r, m);
    if (m.view < r.view) return;
    if (m.view > r.view) {
      r.future.push(m);
      return;
    }
    if (m.t === "PRE-PREPARE") return this.onPrePrepare(r, m);
    if (m.t === "PREPARE") {
      const k = r.key(m.view, m.digest);
      if (!r.prepares.has(k)) r.prepares.set(k, new Set());
      r.prepares.get(k)!.add(m.from);
      return this.check(r);
    }
    if (m.t === "COMMIT") {
      let signer = "";
      try {
        signer = verifyMessage(getBytes(m.digest), m.sig);
      } catch {
        /* invalid signature encoding */
      }
      if (signer.toLowerCase() !== this.replicas[m.from].app.address.toLowerCase()) {
        this.rejections.push({ replica: r.app.index, view: m.view, reason: `invalid COMMIT signature from validator ${m.from}` });
        return;
      }
      const k = r.key(m.view, m.digest);
      if (!r.commits.has(k)) r.commits.set(k, new Map());
      r.commits.get(k)!.set(m.from, m.sig);
      return this.check(r);
    }
  }

  private async onPrePrepare(r: Replica, m: Msg & { t: "PRE-PREPARE" }) {
    if (m.from !== this.primaryOf(m.view) || r.accepted.has(m.view)) return;
    if (r.app.index !== m.from) {
      const v = await r.app.validate(m.proposal);
      if (!v.ok) {
        this.rejections.push({ replica: r.app.index, view: m.view, reason: v.reason ?? "invalid proposal" });
        return;
      }
    }
    r.accepted.set(m.view, m.proposal);
    const k = r.key(m.view, m.proposal.digest);
    if (!r.prepares.has(k)) r.prepares.set(k, new Set());
    r.prepares.get(k)!.add(m.from); // the pre-prepare is the primary's prepare
    r.prepares.get(k)!.add(r.app.index);
    if (r.app.index !== m.from) this.broadcast(r.app.index, { t: "PREPARE", view: m.view, from: r.app.index, digest: m.proposal.digest });
    await this.check(r);
  }

  private async check(r: Replica) {
    const p = r.accepted.get(r.view);
    if (!p || r.decided) return;
    const k = r.key(r.view, p.digest);
    if (!r.committed.has(r.view) && (r.prepares.get(k)?.size ?? 0) >= this.quorum) {
      r.committed.add(r.view);
      r.prepared = { view: r.view, proposal: p };
      let sig = await r.app.sign(p.digest);
      if (r.app.fault === "bad-signature") sig = "0x" + "11".repeat(65);
      this.broadcast(r.app.index, { t: "COMMIT", view: r.view, from: r.app.index, digest: p.digest, sig });
    }
    const cm = r.commits.get(k);
    if (cm && cm.size >= this.quorum && cm.has(this.primaryOf(r.view))) {
      r.decided = { view: r.view, proposal: p, sigs: [...cm.entries()].map(([from, sig]) => ({ from, sig })) };
    }
  }

  // ------------------------------------------------------------ view change
  timeout(r: Replica) {
    if (r.silent || r.decided) return;
    const target = Math.max(r.view, ...[...r.vcs.keys()].filter((v) => (r.vcs.get(v)?.has(r.app.index) ?? false))) + 1;
    this.broadcast(r.app.index, { t: "VIEW-CHANGE", view: target, from: r.app.index, prepared: r.prepared }, "timer expired");
  }

  private async onViewChange(r: Replica, m: Msg & { t: "VIEW-CHANGE" }) {
    if (m.view <= r.view) return;
    if (!r.vcs.has(m.view)) r.vcs.set(m.view, new Map());
    r.vcs.get(m.view)!.set(m.from, m);
    if (r.vcs.get(m.view)!.size < this.quorum) return;
    // 2f+1 VIEW-CHANGE messages: enter the new view
    this.viewChanges++;
    r.view = m.view;
    r.vcs.delete(m.view);
    const buffered = r.future.splice(0).filter((x) => x.t !== "VIEW-CHANGE" && x.view >= r.view);
    if (this.primaryOf(r.view) === r.app.index && !r.proposedIn.has(r.view)) {
      r.proposedIn.add(r.view);
      // carry the highest prepared proposal found in the quorum (PBFT new-view rule)
      let carried: Proposal | undefined;
      let best = -1;
      for (const vc of [...(r.vcs.get(m.view)?.values() ?? []), m]) {
        if (vc.prepared && vc.prepared.view > best) {
          best = vc.prepared.view;
          carried = vc.prepared.proposal;
        }
      }
      await this.startView(r, carried);
    }
    for (const b of buffered) await this.handle(r, b);
  }

  /** Primary side: build and send PRE-PREPARE(s) for the replica's current view. */
  async startView(r: Replica, carried?: Proposal) {
    if (r.silent) return;
    const props = await r.app.propose(r.view, carried);
    if (!props.length) return;
    // the primary accepts its own (first) proposal; an equivocator sends variants to different peers
    r.accepted.set(r.view, props[0]);
    const k = r.key(r.view, props[0].digest);
    if (!r.prepares.has(k)) r.prepares.set(k, new Set());
    r.prepares.get(k)!.add(r.app.index);
    for (let to = 0; to < this.n; to++) {
      const p = props[to % props.length];
      this.sendTo(r.app.index, to, { t: "PRE-PREPARE", view: r.view, from: r.app.index, proposal: p }, props.length > 1 ? "equivocating" : undefined);
    }
  }

  async run(maxViews: number): Promise<ConsensusResult> {
    const t0 = performance.now();
    await this.startView(this.replicas[this.primaryOf(0)]);
    for (let guard = 0; guard < maxViews + 1; guard++) {
      while (this.queue.length) {
        const { to, msg } = this.queue.shift()!;
        await this.handle(this.replicas[to], msg);
      }
      const live = this.replicas.filter((r) => !r.silent && r.app.fault !== "bad-signature");
      if (live.every((r) => r.decided)) break;
      for (const r of this.replicas) this.timeout(r);
    }
    const decisions = this.replicas.map((r) => r.decided);
    const honest = this.replicas.filter((r) => r.app.fault === "honest" && r.decided);
    const first = honest[0]?.decided ?? decisions.find(Boolean);
    return {
      decision: first,
      decisions,
      finalView: Math.max(...this.replicas.map((r) => r.view)),
      viewChanges: Math.round(this.viewChanges / this.n),
      networkMessages: this.networkMessages,
      rejections: this.rejections,
      log: this.log,
      ms: performance.now() - t0,
    };
  }
}

export async function runConsensus(apps: ReplicaApp[], roundId: number, maxViews = apps.length * 2): Promise<ConsensusResult> {
  const eng = new Engine(apps, roundId);
  const res = await eng.run(maxViews);
  // safety check: no two honest replicas decide different proposals
  const digests = new Set(res.decisions.filter(Boolean).map((d) => d!.proposal.digest));
  if (digests.size > 1) throw new Error("PBFT safety violation: replicas decided different proposals");
  return res;
}
