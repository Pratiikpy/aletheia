import "dotenv/config";
import { readFileSync } from "node:fs";
import { createWalletClient, createPublicClient, http, defineChain } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const xlayerTestnet = defineChain({
  id: 1952, name: "X Layer Testnet", nativeCurrency: { name: "OKB", symbol: "OKB", decimals: 18 },
  rpcUrls: { default: { http: [process.env.XLAYER_TESTNET_RPC ?? "https://testrpc.xlayer.tech"] } },
});
const pk = process.env.EVM_WALLET_PRIVATE_KEY as `0x${string}`;
const account = privateKeyToAccount(pk);
const wallet = createWalletClient({ account, chain: xlayerTestnet, transport: http() });
const pub = createPublicClient({ chain: xlayerTestnet, transport: http() });

const art = JSON.parse(readFileSync("out/RulingRegistry.sol/RulingRegistry.json", "utf8"));
const bal = await pub.getBalance({ address: account.address });
console.log("deployer:", account.address, "balance:", Number(bal)/1e18, "OKB");
const hash = await wallet.deployContract({ abi: art.abi, bytecode: art.bytecode.object, account, chain: xlayerTestnet });
console.log("deploy tx:", hash);
const rc = await pub.waitForTransactionReceipt({ hash });
console.log("RULING_REGISTRY_ADDRESS=" + rc.contractAddress);
