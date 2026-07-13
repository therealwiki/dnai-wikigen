---
name: forge-build
description: Compile Solidity smart contracts using Foundry forge. Use when the user wants to build, compile, or check for compilation errors in their contracts.
---

# Forge Build — Compile Solidity Contracts

## When to use
- User wants to compile contracts
- User needs to check for compilation errors
- User wants to generate ABI or bytecode artifacts

## Commands

### Basic build
```bash
forge build
```

### Build with specific Solidity version
```bash
forge build --use 0.8.28
```

### Build with optimizer
```bash
forge build --optimize --optimizer-runs 200
```

### Output artifacts
After building, artifacts are in `out/<ContractName>.sol/`:
- `<ContractName>.json` — ABI + bytecode + metadata

### View ABI
```bash
forge inspect <ContractName> abi
```

### View bytecode
```bash
forge inspect <ContractName> bytecode
```

### View contract size (useful for Base deployment gas estimates)
```bash
forge build --sizes
```

### Clean and rebuild
```bash
forge clean && forge build
```

## Common issues
- **"Compiler version mismatch"** — Set `solc` in foundry.toml or use `--use <version>`
- **"Import not found"** — Run `forge install` or check remappings with `forge remappings`
- **Contract too large (>24KB)** — Enable optimizer, increase runs, or split contracts

## Formatting
```bash
forge fmt           # format all Solidity files
forge fmt --check   # check without modifying
```
