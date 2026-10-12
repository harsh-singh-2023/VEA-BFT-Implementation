/**
 * HTTP API + dashboard for the VEA-BFT simulation.
 *   GET  /api/state            current federation snapshot
 *   POST /api/init             (re)create the federation  { dataset, excludePolicy, validators, carryBudget, reserve, ... }
 *   POST /api/round            run one round              { behaviors, validatorFaults, offlineCommittee, badShareMembers, attackFactor }
 *   POST /api/membership       { action: "join" | "leave", index }
 *   POST /api/rotate           { faultyDealers? }          committee rotation (resharing)
 *   POST /api/bootstrap        noise-budget bootstrap
 *   GET  /api/audit/:round     independent replay of a round
 *   GET  /api/round/:n         full report incl. PBFT message log
 *   GET  /api/events           server-sent events (live log)
 */
import express from "express";
import * as path from "path";
import { Federation, RoundOptions } from "../orchestrator/federation";
import { SimConfig } from "../config";

const jsonSafe = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);
const send = (res: express.Response, body: unknown, status = 200) => res.status(status).type("json").send(JSON.stringify(body, jsonSafe));

export async function createApp(initial: Partial<SimConfig> = {}) {
  const app = express();
  app.use(express.json());
  app.use(express.static(path.resolve(__dirname, "../../web")));

  let fed: Federation | undefined;
  let busy = false;
  const clients = new Set<express.Response>();
  const push = (e: unknown) => {
    const line = `data: ${JSON.stringify(e, jsonSafe)}\n\n`;
    for (const c of clients) c.write(line);
  };

  async function init(cfg: Partial<SimConfig>) {
    const f = await Federation.create(cfg);
    f.on((e) => push(e));
    for (const e of f.events) push(e);
    fed = f;
    push({ t: Date.now(), kind: "reset", msg: "new federation" });
  }

  const guard = (fn: (req: express.Request, res: express.Response) => Promise<void>) => async (req: express.Request, res: express.Response) => {
    if (busy) return send(res, { error: "busy: another operation is running" }, 409);
    if (!fed && req.path !== "/api/init") return send(res, { error: "no federation: POST /api/init first" }, 400);
    busy = true;
    try {
      await fn(req, res);
    } catch (e: any) {
      push({ t: Date.now(), kind: "error", msg: String(e.shortMessage ?? e.message ?? e) });
      send(res, { error: String(e.shortMessage ?? e.message ?? e) }, 500);
    } finally {
      busy = false;
    }
  };

  app.get("/api/state", async (_req, res) => {
    if (!fed) return send(res, { initialised: false });
    send(res, { initialised: true, busy, ...(await fed.snapshot()) });
  });
  app.post("/api/init", guard(async (req, res) => {
    await init({ ...initial, ...(req.body ?? {}) });
    send(res, await fed!.snapshot());
  }));
  app.post("/api/round", guard(async (req, res) => {
    const opts = (req.body ?? {}) as RoundOptions;
    const rep = await fed!.runRound(opts);
    send(res, { ...rep, consensusLog: undefined, state: await fed!.snapshot() });
  }));
  app.post("/api/membership", guard(async (req, res) => {
    const { action, index } = req.body ?? {};
    if (action === "join") await fed!.addHospital(Number(index));
    else if (action === "leave") await fed!.removeHospital(Number(index));
    else throw new Error("action must be join or leave");
    send(res, await fed!.snapshot());
  }));
  app.post("/api/rotate", guard(async (req, res) => {
    const r = await fed!.rotateCommittee({ faultyDealers: req.body?.faultyDealers });
    send(res, { ...r, state: await fed!.snapshot() });
  }));
  app.post("/api/bootstrap", guard(async (_req, res) => {
    await fed!.bootstrapNoise();
    send(res, await fed!.snapshot());
  }));
  app.get("/api/audit/:round", guard(async (req, res) => {
    send(res, await fed!.audit(Number(req.params.round)));
  }));
  app.get("/api/round/:n", (req, res) => {
    const r = fed?.history[Number(req.params.n) - 1];
    if (!r) return send(res, { error: "unknown round" }, 404);
    send(res, r);
  });
  app.get("/api/events", (req, res) => {
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
    for (const e of (fed?.events ?? []).slice(-150)) res.write(`data: ${JSON.stringify(e, jsonSafe)}\n\n`);
    clients.add(res);
    req.on("close", () => clients.delete(res));
  });
  return { app, init };
}

if (require.main === module) {
  const port = Number(process.env.PORT ?? 3000);
  createApp().then(async ({ app, init }) => {
    await init({ dataset: (process.env.DATASET as any) ?? "heart", reserve: 1 });
    app.listen(port, () => console.log(`VEA-BFT dashboard: http://localhost:${port}  (chain: ${process.env.RPC_URL ?? "in-process hardhat"})`));
  });
}
