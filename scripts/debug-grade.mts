import { createWalletClient, createPublicClient, http, keccak256, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { xlayerTestnet } from "../src/attest/registry.js";
import "dotenv/config";
const acct = privateKeyToAccount(process.env.EVM_WALLET_PRIVATE_KEY as `0x${string}`);
const wallet = createWalletClient({ account: acct, chain: xlayerTestnet, transport: http() });
const pub = createPublicClient({ chain: xlayerTestnet, transport: http() });
const REG = process.env.VERITY_REGISTRY_ADDRESS as `0x${string}`;
const ABI = [
 {type:"function",name:"commit",stateMutability:"nonpayable",inputs:[{type:"bytes32"},{type:"address"},{type:"uint8"},{type:"uint8"},{type:"uint8"}],outputs:[]},
 {type:"function",name:"grade",stateMutability:"nonpayable",inputs:[{type:"bytes32"},{type:"bool"}],outputs:[]},
 {type:"function",name:"owner",stateMutability:"view",inputs:[],outputs:[{type:"address"}]},
 {type:"function",name:"attestations",stateMutability:"view",inputs:[{type:"bytes32"}],outputs:[{type:"address"},{type:"uint8"},{type:"uint8"},{type:"uint8"},{type:"uint64"},{type:"bool"},{type:"bool"}]},
] as const;
console.log("owner:", await pub.readContract({address:REG,abi:ABI,functionName:"owner"}), "| me:", acct.address);
const id = keccak256(toHex("debug-"+Date.now()));
const h1 = await wallet.writeContract({address:REG,abi:ABI,functionName:"commit",args:[id,acct.address,1,90,80],account:acct,chain:xlayerTestnet});
const r1 = await pub.waitForTransactionReceipt({hash:h1}); console.log("commit status:", r1.status);
try {
  const h2 = await wallet.writeContract({address:REG,abi:ABI,functionName:"grade",args:[id,true],account:acct,chain:xlayerTestnet});
  const r2 = await pub.waitForTransactionReceipt({hash:h2}); console.log("grade status:", r2.status);
} catch(e:any){ console.log("grade THREW:", e.shortMessage ?? e.message); }
const a = await pub.readContract({address:REG,abi:ABI,functionName:"attestations",args:[id]});
console.log("attestation graded flag:", a[5], "correct:", a[6]);
