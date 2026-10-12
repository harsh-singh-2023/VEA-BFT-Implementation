/**
 * Chain access. By default an in-process Hardhat EVM is used (no node to start). Set RPC_URL
 * (e.g. http://127.0.0.1:8545 from `npm run node`) to talk to an external node instead.
 * Accounts are Hardhat's deterministic dev accounts:
 *   [0] owner, [1..6] hospitals, [7..10] validators (hardhat.config.ts asks for 20).
 */
import { BrowserProvider, HDNodeWallet, JsonRpcProvider, Mnemonic, Provider } from "ethers";

const MNEMONIC = "test test test test test test test test test test test junk";

export interface ChainConn {
  provider: Provider;
  wallets: HDNodeWallet[];
  kind: "in-process" | "rpc";
  /** Advance block time (in-process only); used by timeout scenarios. */
  mine(): Promise<void>;
}

export async function connect(rpcUrl: string | undefined = process.env.RPC_URL): Promise<ChainConn> {
  let provider: Provider;
  let kind: ChainConn["kind"];
  if (rpcUrl) {
    provider = new JsonRpcProvider(rpcUrl, undefined, { cacheTimeout: -1 });
    kind = "rpc";
  } else {
    const hre = (await import("hardhat")).default;
    provider = new BrowserProvider(hre.network.provider as any, undefined, { cacheTimeout: -1 });
    kind = "in-process";
  }
  const m = Mnemonic.fromPhrase(MNEMONIC);
  const wallets: HDNodeWallet[] = [];
  for (let i = 0; i < 20; i++) wallets.push(HDNodeWallet.fromMnemonic(m, `m/44'/60'/0'/0/${i}`).connect(provider));
  return {
    provider,
    wallets,
    kind,
    async mine() {
      await (provider as any).send("evm_mine", []);
    },
  };
}
