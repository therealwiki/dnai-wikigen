---
name: phala-deploy
description: Deploy containerized applications as Confidential VMs (CVMs) on Phala Cloud using Intel TDX TEEs. Use when the user wants to deploy a docker-compose app to Phala, update an existing CVM, or configure TEE deployment settings.
---

# Phala Deploy — Deploy CVMs to Phala Cloud

## When to use
- User wants to deploy a Docker Compose app to Phala Cloud TEE
- User needs to update/redeploy an existing CVM
- User wants to configure instance types, regions, or KMS
- User needs to pass environment variables or secrets to a CVM

## Prerequisites
- Authenticated with Phala Cloud (`phala status`)
- Docker Compose file (`docker-compose.yml`)
- Docker image pushed to a registry (Docker Hub, GHCR, etc.)

## Environment setup
Load deployment config from `.env`:
```bash
source .env  # loads PHALA_CLOUD_API_KEY, DOCKER_IMAGE, APP_NAME, etc.
```

## Docker Compose for TEE
Mount the dstack socket for TEE attestation and key derivation:
```yaml
services:
  app:
    image: your-registry/your-app:latest
    ports:
      - "3000:3000"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    environment:
      - DSTACK_SIMULATOR_ENDPOINT=/var/run/dstack.sock
```

## Deploy commands

### Deploy a new CVM
```bash
phala deploy \
  --name my-app \
  --compose docker-compose.yml \
  --instance-type tdx.medium \
  --env KEY1=value1 \
  --env KEY2=value2
```

### Deploy with env file
```bash
phala deploy \
  --name my-app \
  --compose docker-compose.yml \
  --env .env.production
```

### Deploy and wait for completion
```bash
phala deploy \
  --name my-app \
  --compose docker-compose.yml \
  --wait
```

### Update an existing CVM
```bash
phala deploy \
  --cvm-id <CVM_ID> \
  --compose docker-compose.yml
```

### Deploy with SSH access enabled
```bash
phala deploy \
  --name my-app \
  --compose docker-compose.yml \
  --dev-os \
  --ssh-pubkey ~/.ssh/id_ed25519.pub
```

### Deploy with specific KMS
```bash
# Phala Cloud KMS (default)
phala deploy --name my-app --compose docker-compose.yml --kms phala

# Ethereum KMS
phala deploy --name my-app --compose docker-compose.yml \
  --kms ethereum --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# Base KMS
phala deploy --name my-app --compose docker-compose.yml \
  --kms base --private-key $PRIVATE_KEY --rpc-url $BASE_RPC_URL
```

### Deploy with custom disk size
```bash
phala deploy --name my-app --compose docker-compose.yml --disk-size 40G
```

### Simulate only (dry run)
```bash
phala deploy --name my-app --compose docker-compose.yml --debug
```

## Key flags
| Flag | Short | Default | Purpose |
|------|-------|---------|---------|
| `--name` | `-n` | dir name | CVM name |
| `--compose` | `-c` | `docker-compose.yml` | Compose file path |
| `--instance-type` | `-t` | auto | Machine spec |
| `--region` | `-r` | auto | Deployment region |
| `--env` | `-e` | — | Env vars (`KEY=VALUE` or `.env` path); repeatable |
| `--kms` | | `phala` | KMS: `phala`, `ethereum`/`eth`, `base` |
| `--wait` | | false | Block until deployed |
| `--dev-os` | | false | Enable SSH/SCP access |
| `--ssh-pubkey` | | `~/.ssh/id_rsa.pub` | SSH public key |
| `--disk-size` | | `20G` | Storage allocation |
| `--cvm-id` | | — | Update existing CVM |
| `--listed` | | false | List on Phala Trust Center |
| `--public-logs` | | true | Allow public log access |
| `--image` | | latest | OS image version |
| `--debug` | | false | Verbose output |

## Instance types
| Type | vCPU | Memory | Disk | Price/hr |
|------|------|--------|------|----------|
| `tdx.medium` | 1 | 2 GB | 40 GB | $0.069 |
| `tdx.large` | 2 | 4 GB | 80 GB | $0.139 |
| `tdx.2xlarge` | 4 | 8 GB | 160 GB | $0.279 |

List available types:
```bash
phala instance-types
```

## Link a project to a CVM
After deploying, link for convenience:
```bash
phala link my-app
```
Creates `phala.toml` so subsequent commands auto-target this CVM.

## Secrets & encryption
- Environment variables passed with `--env` are **encrypted client-side** using X25519
- Decrypted only inside the TEE at runtime
- You cannot update individual env vars — all must be passed together on each deploy
- For sensitive secrets, prefer `--env .env.production` over inline values

## Security notes
- ALWAYS review your `docker-compose.yml` before deploying
- NEVER include secrets in Docker images — pass them via `--env`
- Use `--kms phala` (default) unless you need on-chain key governance
- Use `--wait` in CI/CD to ensure deployment succeeds before continuing
