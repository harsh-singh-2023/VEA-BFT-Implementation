/** `npm run dev`: start a local Hardhat JSON-RPC node, then the dashboard against it. */
import { spawn } from "child_process";

const node = spawn("npx", ["hardhat", "node", "--hostname", "127.0.0.1", "--port", "8545"], { stdio: ["ignore", "pipe", "inherit"] });
let started = false;
node.stdout!.on("data", (b: Buffer) => {
  if (!started && /Started HTTP/.test(b.toString())) {
    started = true;
    console.log("hardhat node up on :8545");
    const srv = spawn("npx", ["tsx", "src/server/server.ts"], { stdio: "inherit", env: { ...process.env, RPC_URL: "http://127.0.0.1:8545" } });
    srv.on("exit", () => node.kill());
  }
});
process.on("SIGINT", () => { node.kill(); process.exit(0); });
