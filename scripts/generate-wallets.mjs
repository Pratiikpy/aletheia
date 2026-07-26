// Generates a fresh EVM wallet + Solana wallet for DEV/TESTNET use.
// Appends secrets to .env (gitignored). Prints ONLY public addresses.
import { ethers } from 'ethers';
import { Keypair } from '@solana/web3.js';
import bs58 from 'bs58';
import { appendFileSync, readFileSync } from 'node:fs';

const envPath = new URL('../.env', import.meta.url);

// Guard: don't regenerate if wallets already exist in .env
const existing = readFileSync(envPath, 'utf8');
if (existing.includes('EVM_WALLET_ADDRESS=')) {
  console.error('Wallets already present in .env — aborting to avoid overwrite.');
  process.exit(1);
}

// EVM
const evm = ethers.Wallet.createRandom();

// Solana
const sol = Keypair.generate();
const solSecretB58 = bs58.encode(sol.secretKey);

const block = [
  '',
  '# --- EVM dev wallet (shared across X Layer, Ethereum, BSC, Base, Arbitrum, Polygon) ---',
  `EVM_WALLET_ADDRESS=${evm.address}`,
  `EVM_WALLET_PRIVATE_KEY=${evm.privateKey}`,
  `EVM_WALLET_MNEMONIC="${evm.mnemonic.phrase}"`,
  '',
  '# --- Solana dev wallet ---',
  `SOLANA_WALLET_ADDRESS=${sol.publicKey.toBase58()}`,
  `SOLANA_WALLET_SECRET_KEY_BASE58=${solSecretB58}`,
  '',
].join('\n');

appendFileSync(envPath, block);

console.log(JSON.stringify({
  evm_address: evm.address,
  solana_address: sol.publicKey.toBase58(),
}, null, 2));
