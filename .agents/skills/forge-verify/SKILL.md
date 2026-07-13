---
name: forge-verify
description: Verify deployed smart contracts on BaseScan (Base block explorer) so source code is publicly readable. Use when the user wants to verify a contract after deployment on Base Sepolia or Base mainnet.
---

# Forge Verify — Verify Contracts on BaseScan

## When to use
- User just deployed a contract and wants to verify it
- User needs to verify an existing deployed contract
- User wants to check verification status

## Prerequisites
- Etherscan API key (V2 keys work for all Etherscan-family explorers including BaseScan)
- Get one at https://etherscan.io/myapikey

## Environment setup
Foundry automatically reads `.env` in the project root:
```bash
ETHERSCAN_API_KEY=your_etherscan_v2_key
```
This is used by `$ETHERSCAN_API_KEY` in commands and `${ETHERSCAN_API_KEY}` in `foundry.toml`.

## Commands

### Verify on Base Sepolia
```bash
forge verify-contract \
  --chain 84532 \
  --rpc-url https://sepolia.base.org \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  <DEPLOYED_ADDRESS> \
  src/MyContract.sol:MyContract
```

### Verify on Base mainnet
```bash
forge verify-contract \
  --chain 8453 \
  --rpc-url https://mainnet.base.org \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  <DEPLOYED_ADDRESS> \
  src/MyContract.sol:MyContract
```

### Verify with constructor arguments
```bash
forge verify-contract \
  --chain 84532 \
  --rpc-url https://sepolia.base.org \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  --constructor-args $(cast abi-encode "constructor(address,uint256)" 0xADDRESS 1000) \
  <DEPLOYED_ADDRESS> \
  src/MyContract.sol:MyContract
```

### Check verification status
```bash
forge verify-check \
  --chain 84532 \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  <GUID>
```

### Auto-verify during deployment
Add `--verify` to your `forge script` command:
```bash
forge script script/Deploy.s.sol \
  --rpc-url https://sepolia.base.org \
  --account dev \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_API_KEY
```

## foundry.toml configuration

Add this to avoid passing flags every time:
```toml
[etherscan]
base_sepolia = { key = "${ETHERSCAN_API_KEY}", chain = 84532, url = "https://api-sepolia.basescan.org/api" }
base_mainnet = { key = "${ETHERSCAN_API_KEY}", chain = 8453, url = "https://api.basescan.org/api" }
```

Then verify with just:
```bash
forge verify-contract --chain base_sepolia <ADDRESS> src/MyContract.sol:MyContract
```

## Common issues
- **"Invalid API key"** — Use an Etherscan V2 key, not a legacy BaseScan key
- **"Contract not found"** — Wait a few blocks after deployment before verifying
- **"Bytecode mismatch"** — Ensure same compiler version and optimizer settings
- **Flattened source needed** — Use `forge flatten src/MyContract.sol` if manual verification is needed

## Explorer URLs
| Network | Explorer |
|---|---|
| Base Sepolia | https://sepolia.basescan.org |
| Base Mainnet | https://basescan.org |
