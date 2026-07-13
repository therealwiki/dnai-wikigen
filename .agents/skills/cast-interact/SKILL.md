---
name: cast-interact
description: Interact with deployed smart contracts on Base or Base Sepolia using Foundry cast. Use when the user wants to call contract functions, send transactions, check balances, decode data, or query on-chain state.
---

# Cast Interact — Read & Write On-Chain State

## When to use
- User wants to call a contract function (read or write)
- User needs to check balances, nonces, or gas prices
- User wants to send ETH or tokens
- User needs to decode transaction data or events

## Environment setup
Foundry automatically reads `.env` in the project root. Key variables:
```bash
BASE_SEPOLIA_RPC_URL=https://sepolia.base.org
BASE_MAINNET_RPC_URL=https://mainnet.base.org
ESCROW_ADDRESS=0x...      # deployed contract address
FOUNDRY_KEYSTORE_ACCOUNT=dev
```
Use `$BASE_SEPOLIA_RPC_URL` instead of hardcoded URLs in commands.

## Read operations (no gas, no signing)

### Check ETH balance
```bash
cast balance <ADDRESS> --rpc-url https://sepolia.base.org
# Human-readable:
cast balance <ADDRESS> --rpc-url https://sepolia.base.org --ether
```

### Call a view/pure function
```bash
cast call <CONTRACT> "functionName(argType)(returnType)" <ARGS> \
  --rpc-url https://sepolia.base.org
```

Example — read escrow state:
```bash
cast call 0xContractAddr "getState(uint256)(uint8)" 1 \
  --rpc-url https://sepolia.base.org
```

### Get storage slot
```bash
cast storage <CONTRACT> <SLOT> --rpc-url https://sepolia.base.org
```

### Get contract ABI from BaseScan
```bash
cast interface <CONTRACT> --chain 84532
```

### Check nonce
```bash
cast nonce <ADDRESS> --rpc-url https://sepolia.base.org
```

### Get gas price
```bash
cast gas-price --rpc-url https://sepolia.base.org
```

### Get block number
```bash
cast block-number --rpc-url https://sepolia.base.org
```

### Get chain ID
```bash
cast chain-id --rpc-url https://sepolia.base.org
```

## Write operations (requires signing)

### Send a transaction (with keystore)
```bash
cast send <CONTRACT> "functionName(argType)" <ARGS> \
  --rpc-url https://sepolia.base.org \
  --account <KEYSTORE_NAME>
```

Example — create an escrow room:
```bash
cast send 0xContractAddr "createRoom(uint256,uint256)" 1000000000000000000 86400 \
  --rpc-url https://sepolia.base.org \
  --account dev
```

### Send ETH to an address
```bash
cast send <TO_ADDRESS> --value 0.1ether \
  --rpc-url https://sepolia.base.org \
  --account dev
```

### Send with specific gas
```bash
cast send <CONTRACT> "fn()" \
  --rpc-url https://sepolia.base.org \
  --account dev \
  --gas-limit 100000
```

### Estimate gas for a call
```bash
cast estimate <CONTRACT> "functionName(argType)" <ARGS> \
  --rpc-url https://sepolia.base.org
```

## Decoding & encoding

### ABI-encode function call
```bash
cast calldata "transfer(address,uint256)" 0xRecipient 1000
```

### ABI-encode constructor args
```bash
cast abi-encode "constructor(address,uint256)" 0xAddr 1000
```

### Decode calldata
```bash
cast calldata-decode "transfer(address,uint256)" 0x...
```

### Decode transaction
```bash
cast tx <TX_HASH> --rpc-url https://sepolia.base.org
```

### Get transaction receipt
```bash
cast receipt <TX_HASH> --rpc-url https://sepolia.base.org
```

### Get event logs
```bash
cast logs --from-block 38000000 --to-block latest \
  --address <CONTRACT> \
  --rpc-url https://sepolia.base.org
```

## Useful conversions
```bash
cast to-wei 1.5 ether          # 1500000000000000000
cast from-wei 1500000000000000000   # 1.500000000000000000
cast to-hex 84532               # 0x14a34
cast keccak "Transfer(address,address,uint256)"  # event topic
```

## Network reference
| Network | Chain ID | RPC URL |
|---|---|---|
| Base Sepolia | 84532 | https://sepolia.base.org |
| Base Mainnet | 8453 | https://mainnet.base.org |
| Local Anvil | 31337 | http://127.0.0.1:8545 |
