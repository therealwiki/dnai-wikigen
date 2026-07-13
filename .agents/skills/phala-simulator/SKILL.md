---
name: phala-simulator
description: Run a local TEE simulator for Phala/dstack development without deploying to Phala Cloud. Use when the user wants to test TEE attestation, key derivation, or dstack SDK integration locally.
---

# Phala Simulator — Local TEE Development

## When to use
- User wants to test dstack/TEE features locally before deploying
- User needs to develop against the attestation or key derivation APIs
- User wants to verify docker-compose setup works before Phala Cloud deploy
- User needs a local `dstack.sock` endpoint for SDK testing

## Prerequisites
- Phala CLI installed (`phala --help`)
- Docker running locally

## Commands

### Start the local TEE simulator
```bash
phala simulator start
```
Starts on port 8090 by default. Sets the `DSTACK_SIMULATOR_ENDPOINT` environment variable.

### Start on custom port
```bash
phala simulator start --port 9090
```

### Start with verbose output
```bash
phala simulator start --verbose
```

### Stop the simulator
```bash
phala simulator stop
```

## Using with Docker Compose
For local development, point your compose file at the simulator:
```yaml
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DSTACK_SIMULATOR_ENDPOINT=http://host.docker.internal:8090
```

For production (Phala Cloud), use the socket mount instead:
```yaml
services:
  app:
    image: your-registry/your-app:latest
    ports:
      - "3000:3000"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
```

## dstack SDK integration

### JavaScript/TypeScript
```bash
npm install @phala/dstack-sdk
```

```javascript
import { TappdClient } from '@phala/dstack-sdk';

// Connects to simulator or real TEE automatically
const client = new TappdClient();

// Derive a deterministic key
const key = await client.deriveKey('/my-app/signing-key');

// Generate TDX attestation quote
const quote = await client.tdxQuote('custom-report-data');
```

### Python
```bash
uv add dstack-sdk
```

```python
from dstack_sdk import TappdClient

client = TappdClient()

# Derive a deterministic key
key = client.derive_key("/my-app/signing-key")

# Generate TDX attestation quote
quote = client.tdx_quote("custom-report-data")
```

## Environment variables
| Variable | Default | Purpose |
|----------|---------|---------|
| `DSTACK_SIMULATOR_ENDPOINT` | `http://localhost:8090` | Simulator URL (set automatically) |
| `DSTACK_SOCKET` | `/var/run/dstack.sock` | Production TEE socket path |

## Common workflows

### Develop and test locally
```bash
# Terminal 1: start simulator
phala simulator start --verbose

# Terminal 2: run your app
DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090 node app.js
```

### Full local integration test
```bash
# Start simulator
phala simulator start

# Run docker-compose with simulator endpoint
DSTACK_SIMULATOR_ENDPOINT=http://host.docker.internal:8090 \
  docker compose up

# Test attestation endpoint
curl http://localhost:3000/attestation

# Stop everything
docker compose down
phala simulator stop
```

### Verify before deploying to Phala Cloud
```bash
# 1. Test locally with simulator
phala simulator start
docker compose up -d
curl http://localhost:3000/health
docker compose down
phala simulator stop

# 2. Deploy to Phala Cloud
phala deploy --name my-app --compose docker-compose.yml --wait

# 3. Check remote logs
phala logs -f
```

## Notes
- The simulator provides mock attestation — quotes are NOT verifiable on-chain
- Key derivation is deterministic but uses different root keys than production
- Use the simulator for development/testing only — always verify on Phala Cloud before launch
- The simulator requires Docker to be running
