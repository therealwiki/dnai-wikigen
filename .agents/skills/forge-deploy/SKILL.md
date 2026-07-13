---
name: forge-deploy
description: Deploy Solidity smart contracts to Base Sepolia testnet or Base mainnet using Foundry forge scripts. Use when the user wants to deploy contracts, write deployment scripts, or broadcast transactions on-chain.
---

# Forge Deploy — Deploy Contracts to Base Networks

## When to use
- User wants to deploy a contract to Base Sepolia or Base mainnet
- User needs to write a deployment script
- User wants to simulate a deployment before broadcasting

## Prerequisites
- Funded wallet (Base Sepolia ETH from a faucet)
- Keystore account set up (see `cast-wallet` skill)
- `.env` file configured (see `example.env`)

## Environment setup
Foundry automatically reads `.env` in the project root. Required variables:
```bash
ETHERSCAN_API_KEY=your_etherscan_v2_key   # for --verify flag
PRIVATE_KEY=0x...                          # dev only — prefer keystore
BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
BASE_MAINNET_RPC_URL=https://mainnet.base.org
FOUNDRY_KEYSTORE_ACCOUNT=dev              # your keystore account name
```
Use `$BASE_SEPOLIA_RPC_URL` in commands instead of hardcoded URLs when deploying from `.env`.

## Deployment script structure

Create `script/Deploy.s.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {MyContract} from "../src/MyContract.sol";

contract DeployScript is Script {
    function run() external {
        vm.startBroadcast();

        MyContract deployed = new MyContract();
        console.log("Deployed to:", address(deployed));

        vm.stopBroadcast();
    }
}
```

## Deploy commands

### Simulate (dry run — no on-chain tx)
```bash
forge script script/Deploy.s.sol --rpc-url https://sepolia.base.org
```

### Deploy to Base Sepolia with keystore
```bash
forge script script/Deploy.s.sol \
  --rpc-url https://sepolia.base.org \
  --account <KEYSTORE_NAME> \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_API_KEY
```

### Deploy to Base Sepolia with private key (dev only)
```bash
forge script script/Deploy.s.sol \
  --rpc-url https://sepolia.base.org \
  --private-key $PRIVATE_KEY \
  --broadcast
```

### Deploy to local Anvil
```bash
forge script script/Deploy.s.sol \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast
```

## Key flags
- `--broadcast` — actually send transactions (without this, it's a simulation)
- `--verify` — verify on BaseScan after deploy
- `--account <name>` — use keystore account (secure, recommended)
- `--private-key <key>` — use raw private key (dev only)
- `--slow` — send transactions one by one (safer)
- `--resume` — resume a failed deployment
- `--chain base_sepolia` — explicit chain name

## After deployment

Broadcast results are saved to:
```
broadcast/Deploy.s.sol/<chainId>/run-latest.json
```

This contains deployed addresses, transaction hashes, and gas used.

## Network reference
| Network | Chain ID | RPC URL | Explorer |
|---|---|---|---|
| Base Sepolia | 84532 | https://sepolia.base.org | https://sepolia.basescan.org |
| Base Mainnet | 8453 | https://mainnet.base.org | https://basescan.org |
| Local Anvil | 31337 | http://127.0.0.1:8545 | — |

## Security rules
- NEVER use `--private-key` with real funds
- ALWAYS use `--account` (keystore) for testnet/mainnet
- ALWAYS simulate before broadcasting
- ALWAYS verify contracts after deployment
