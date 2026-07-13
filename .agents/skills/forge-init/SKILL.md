---
name: forge-init
description: Initialize a new Foundry project or scaffold Solidity contracts for Base/Base Sepolia. Use when the user wants to create a new smart contract project, add forge-std, or set up foundry.toml configuration.
---

# Forge Init — Scaffold a Foundry Project

## When to use
- User wants to create a new smart contract project
- User needs to initialize Foundry in an existing directory
- User needs a foundry.toml configured for Base networks

## Prerequisites
- Foundry installed (`forge --version` to check)
- PATH must include `$HOME/.foundry/bin`
- `.env` file with `ETHERSCAN_API_KEY` (see `example.env`)

## Environment setup
Foundry automatically reads `.env` in the project root. Ensure your `.env` contains:
```bash
ETHERSCAN_API_KEY=your_etherscan_v2_key
```

## Steps

### 1. Initialize the project

```bash
# New project in a subdirectory
forge init <project-name>

# Initialize in current directory (must be empty or use --force)
forge init --force
```

### 2. Configure foundry.toml for Base networks

Create or update `foundry.toml` with Base-specific settings:

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.28"
optimizer = true
optimizer_runs = 200

# Base Sepolia testnet
[rpc_endpoints]
base_sepolia = "https://sepolia.base.org"
base_mainnet = "https://mainnet.base.org"
localhost = "http://127.0.0.1:8545"

# Etherscan verification (Etherscan V2 key works for BaseScan)
[etherscan]
base_sepolia = { key = "${ETHERSCAN_API_KEY}", chain = 84532, url = "https://api-sepolia.basescan.org/api" }
base_mainnet = { key = "${ETHERSCAN_API_KEY}", chain = 8453, url = "https://api.basescan.org/api" }
```

### 3. Project structure

After init, the project contains:
```
src/          — Solidity source files
test/         — Test files (*.t.sol)
script/       — Deployment scripts (*.s.sol)
lib/          — Dependencies (forge-std)
foundry.toml  — Configuration
```

### 4. Install additional dependencies

```bash
forge install OpenZeppelin/openzeppelin-contracts
forge install transmissions11/solmate
```

## Key flags
- `--no-git` — skip git init (useful inside existing repos)
- `--force` — init in non-empty directory
- `--template <url>` — use a template repo

## Network reference
| Network | Chain ID | RPC URL |
|---|---|---|
| Base Sepolia | 84532 | https://sepolia.base.org |
| Base Mainnet | 8453 | https://mainnet.base.org |
