/** `npm run deploy` (with `npm run node` running, RPC_URL=http://127.0.0.1:8545): deploy + genesis, write deployments/. */
import * as fs from "fs";
import * as path from "path";
import { Federation } from "../orchestrator/federation";

async function main() {
  if (!process.env.RPC_URL) process.env.RPC_URL = "http://127.0.0.1:8545";
  const fed = await Federation.create({});
  const s = await fed.snapshot();
  const out = {
    network: s.chain.kind, chainId: s.chain.chainId, ledger: s.chain.ledger,
    hospitals: s.hospitals.map((h) => ({ name: h.name, address: h.address, nSamples: h.n })),
    validators: s.validators.map((v) => v.address),
    committee: s.committee,
    params: JSON.parse(JSON.stringify(await fed.ledger.params(), (_k, v) => (typeof v === "bigint" ? v.toString() : v))),
    gasUsed: s.chain.gas,
  };
  const dir = path.resolve(__dirname, "../../deployments");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `chain-${s.chain.chainId}.json`), JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
