---
name: cast-wallet
description: Generate, import, and manage Ethereum wallets and private keys using Foundry cast. Use when the user needs to create a new wallet, import keys to a secure keystore, list accounts, or derive addresses for Base/Base Sepolia deployment.
---

# Cast Wallet — Key & Wallet Management

## When to use
- User needs to generate a new wallet/keypair
- User wants to securely store a private key in the Foundry keystore
- User needs to list or manage keystore accounts
- User needs an address for receiving testnet ETH from a faucet

## Commands

### Generate a new random keypair
```bash
cast wallet new
```
Outputs address and private key. NEVER commit or log the private key.

### Generate a mnemonic (BIP39)
```bash
cast wallet new-mnemonic
```
Outputs a 12-word seed phrase and the first derived account.

### Derive private key from mnemonic
```bash
cast wallet private-key "word1 word2 ... word12"
```

### Import a private key to encrypted keystore (RECOMMENDED)
```bash
cast wallet import <ACCOUNT_NAME> --interactive
```
Prompts for private key and password. The key is encrypted and stored in `~/.foundry/keystores/`.

For scripting (less secure):
```bash
cast wallet import <ACCOUNT_NAME> \
  --private-key <KEY> \
  --unsafe-password <PASSWORD>
```

### List keystore accounts
```bash
cast wallet list
```

### Get address from keystore
```bash
cast wallet address --account <ACCOUNT_NAME>
```

### Remove a keystore account
```bash
cast wallet remove --name <ACCOUNT_NAME>
```

### Get public key from private key
```bash
cast wallet public-key --private-key <KEY>
```

### Convert private key to address
```bash
cast wallet address --private-key <KEY>
```

## Recommended workflow for this project

### 1. Generate a dev wallet
```bash
cast wallet new
```

### 2. Import to keystore
```bash
cast wallet import dev --interactive
# Enter the private key from step 1
# Choose a password
```

### 3. Get testnet ETH
Visit a Base Sepolia faucet with your address:
- https://ethglobal.com/faucet/base-sepolia-84532
- https://www.alchemy.com/faucets/base-sepolia

### 4. Check balance
```bash
cast balance <YOUR_ADDRESS> --rpc-url https://sepolia.base.org
```

### 5. Use keystore for deployment
```bash
forge script script/Deploy.s.sol \
  --rpc-url https://sepolia.base.org \
  --account dev \
  --broadcast
```

## Security rules
- NEVER store private keys in .env files, source code, or git history
- ALWAYS use `cast wallet import` to encrypt keys in the Foundry keystore
- ALWAYS use `--account <name>` flag for deployments (not `--private-key`)
- The ONLY exception is Anvil's pre-funded dev keys for local testing
- Keystore files are stored in `~/.foundry/keystores/` (encrypted with your password)

## Anvil dev keys (local testing only)
These are well-known keys — NEVER use on real networks:
```
Account 0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
Key:       0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```
