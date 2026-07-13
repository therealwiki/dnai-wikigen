---
name: anvil-local
description: Run a local Ethereum dev chain using Foundry Anvil for testing smart contracts. Use when the user wants to start a local blockchain, fork Base Sepolia or Base mainnet, or test contract interactions locally without spending gas.
---

# Anvil — Local Development Chain

## When to use
- User wants a local blockchain for development/testing
- User needs to fork Base Sepolia or Base mainnet locally
- User wants to test contracts without spending real testnet ETH
- User needs a local RPC endpoint for frontend development

## Environment setup
When forking, use RPC URLs from `.env` instead of hardcoding:
```bash
source .env
anvil --fork-url $BASE_SEPOLIA_RPC_URL
```

## Commands

### Start a basic local chain
```bash
anvil
```
Starts on `http://127.0.0.1:8545` with 10 pre-funded accounts (10,000 ETH each).

### Fork Base Sepolia
```bash
anvil --fork-url https://sepolia.base.org
```

### Fork Base Sepolia at a specific block
```bash
anvil --fork-url https://sepolia.base.org --fork-block-number 38000000
```

### Fork Base mainnet (read-only testing)
```bash
anvil --fork-url https://mainnet.base.org
```

### Custom configuration
```bash
anvil \
  --port 8545 \
  --chain-id 31337 \
  --block-time 2 \
  --accounts 10 \
  --balance 10000
```

### Start with specific mnemonic (reproducible addresses)
```bash
anvil --mnemonic "test test test test test test test test test test test junk"
```

## Pre-funded dev accounts

Anvil generates 10 accounts. The first one (Account 0) is commonly used:
```
Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
Key:     0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

These are well-known keys. NEVER use them on real networks.

## Common workflows

### Deploy and test locally
```bash
# Terminal 1: start Anvil
anvil

# Terminal 2: deploy to local chain
forge script script/Deploy.s.sol \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast

# Terminal 2: interact with deployed contract
cast call <DEPLOYED_ADDRESS> "getState()(uint8)" --rpc-url http://127.0.0.1:8545
```

### Fork and test against live state
```bash
# Fork Base Sepolia
anvil --fork-url https://sepolia.base.org

# Impersonate any address (useful for testing)
cast rpc anvil_impersonateAccount 0xSomeAddress --rpc-url http://127.0.0.1:8545

# Send tx as that address
cast send <CONTRACT> "fn()" \
  --from 0xSomeAddress \
  --rpc-url http://127.0.0.1:8545 \
  --unlocked
```

### Mine blocks manually
```bash
# Mine 1 block
cast rpc anvil_mine --rpc-url http://127.0.0.1:8545

# Mine 10 blocks
cast rpc anvil_mine 0xa --rpc-url http://127.0.0.1:8545

# Set next block timestamp
cast rpc anvil_setNextBlockTimestamp 1700000000 --rpc-url http://127.0.0.1:8545
```

### Snapshot and revert (save/restore state)
```bash
# Save state
cast rpc anvil_snapshot --rpc-url http://127.0.0.1:8545
# Returns snapshot ID, e.g. "0x1"

# Revert to snapshot
cast rpc anvil_revert 0x1 --rpc-url http://127.0.0.1:8545
```

## Key flags
- `--fork-url <URL>` — fork a live chain
- `--fork-block-number <N>` — fork at specific block
- `--port <N>` — listen port (default 8545)
- `--block-time <N>` — auto-mine interval in seconds
- `--chain-id <N>` — override chain ID
- `--accounts <N>` — number of dev accounts
- `--balance <N>` — ETH per dev account
- `--no-mining` — disable auto-mining (manual only)

## Important notes
- Anvil state is in-memory — it resets when you stop the process
- Forking requires a stable RPC endpoint (public RPCs may rate-limit)
- Use `--block-time 2` to simulate Base's ~2-second block times
