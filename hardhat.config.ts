import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: { viaIR: true, optimizer: { enabled: true, runs: 200 }, evmVersion: "paris" },
  },
  networks: {
    hardhat: {
      chainId: 31337,
      // 20 deterministic dev accounts: [0] owner, [1..6] hospitals, [7..10] validators
      accounts: { count: 20 },
      allowUnlimitedContractSize: false,
    },
    localhost: { url: "http://127.0.0.1:8545" },
  },
  paths: { sources: "./contracts", tests: "./test", cache: "./cache", artifacts: "./artifacts" },
  mocha: { timeout: 600000 },
};
export default config;
