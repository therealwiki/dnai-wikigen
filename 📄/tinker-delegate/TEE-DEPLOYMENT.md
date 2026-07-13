# Production TEE Deployment Spec

**Status**: Not started (all code runs locally with stubs)
**Depends on**: All other components being tested locally first

## Current State

Both services run locally with TEE features stubbed:

| Feature | Local Mode | Production Mode |
|---|---|---|
| TDX attestation | Returns `"stub-tdx-quote"` | Real TDX quote from `/var/run/tappd.sock` |
| KMS key derivation | Config-based encryption key | `TappdClient().derive_key()` |
| IMAP credentials | Config file, manual key | KMS-derived AES key |
| Tinker API key | Env var `TINKER_API_KEY` | KMS-sealed, derived on boot |
| RA-TLS | Not implemented | Mutual TLS with TDX-bound certs |
| Card encryption | X25519 keypair (ephemeral) | Same, but key bound to TDX quote |

Toggle: `DSTACK_ENABLED=true` env var activates TEE features.

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Phala Cloud (Intel TDX)                                 │
│                                                          │
│  CVM 1: Email Oracle                    CVM 2: Tinker    │
│  ┌─────────────────────────┐          ┌──────────────┐  │
│  │ docker-compose.yml      │          │ docker-compose│  │
│  │                         │          │              │  │
│  │ email-oracle:8000    ◄──┼──────────┼── delegate   │  │
│  │ - FastAPI + IMAP        │  RA-TLS  │   :8080      │  │
│  │ - cock.email account    │          │ - FastAPI    │  │
│  │ - AES-256-GCM creds    │          │ - Tinker SDK │  │
│  │                         │          │ - Playwright │  │
│  │ tappd socket            │          │ - Neko CDP   │  │
│  │ /var/run/tappd.sock     │          │              │  │
│  └─────────────────────────┘          │ tappd socket │  │
│                                        └──────────────┘  │
│                                                          │
│  dstack-KMS                                              │
│  - derive_key() for credential encryption                │
│  - RA-TLS certificate issuance                           │
│  - App identity (app_id, compose_hash) management        │
└─────────────────────────────────────────────────────────┘
         │                          │
         │ IMAP (993/TLS)          │ HTTPS
         ▼                          ▼
    mail.cock.li             api.thinkingmachines.ai
                             tinker-console.thinkingmachines.ai
```

## CVM 1: Email Oracle

### docker-compose.yml

```yaml
services:
  email-oracle:
    build: ./email_oracle
    ports:
      - "8000:8000"
    environment:
      - DSTACK_ENABLED=true
      - ORACLE_CRED_STORE_PATH=/data/creds.enc
      # ORACLE_CRED_STORE_KEY derived from KMS at runtime
    volumes:
      - oracle-data:/data
      - /var/run/tappd.sock:/var/run/tappd.sock:ro
    restart: unless-stopped

volumes:
  oracle-data:
```

### Boot Sequence

1. Container starts → connects to tappd socket
2. Derive credential encryption key: `TappdClient().derive_key(path="/email-oracle/creds", subject="credential-store")`
3. Check if `/data/creds.enc` exists:
   - **Yes**: Decrypt with KMS-derived key → load email credentials → connect IMAP
   - **No**: Run genesis flow (create cock.email account) → encrypt and save
4. Start FastAPI server with RA-TLS (if consumers configured)

### Key Derivation

```python
from dstack_sdk import TappdClient

client = TappdClient()

# Credential encryption key — deterministic per app instance
key_resp = client.derive_key(path="/email-oracle/creds", subject="credential-store")
cred_key = key_resp.key[:32]  # 256-bit AES key

# RA-TLS server certificate
cert_resp = client.derive_key(path="/email-oracle/tls", subject="server-cert")
```

The `derive_key` output is deterministic: same `(app_id, path, subject)` → same key. This means credentials survive container restarts within the same CVM instance.

## CVM 2: Tinker Delegate

### docker-compose.yml

```yaml
services:
  neko:
    image: ghcr.io/m1k1o/neko:chromium
    environment:
      - NEKO_SCREEN=1280x720@30
      - NEKO_EPR=52000-52100
      - NEKO_PASSWORD=neko
      - NEKO_PASSWORD_ADMIN=admin
    ports:
      - "9222:9222"
    shm_size: 2gb

  tinker-delegate:
    build: ./tinker_delegate
    ports:
      - "8080:8080"
    environment:
      - DSTACK_ENABLED=true
      - TINKER_CDP_URL=http://neko:9222
      - TINKER_ORACLE_URL=http://email-oracle-cvm:8000  # cross-CVM
      # TINKER_API_KEY sealed in TEE, captured during signup
    volumes:
      - delegate-data:/data
      - /var/run/tappd.sock:/var/run/tappd.sock:ro
    depends_on:
      - neko
    restart: unless-stopped

volumes:
  delegate-data:
```

### Boot Sequence

1. Container starts → connects to tappd socket
2. Derive API key encryption key: `derive_key(path="/tinker-delegate/api-key")`
3. Check if API key exists in encrypted storage:
   - **Yes**: Decrypt → initialize `ControlPlane`
   - **No**: Run signup flow (needs email oracle + neko browser)
4. Generate X25519 keypair for card encryption channel
5. Run orphan cleanup: `ControlPlane.cleanup_orphans()`
6. Start FastAPI server on :8080

### Neko Browser

The Tinker console and Stripe billing require a real browser. Neko provides:
- Headless Chromium with CDP (Chrome DevTools Protocol) on port 9222
- Playwright connects via CDP for automation
- Used for: signup, OTP entry, Stripe card filling, balance checking

## Cross-CVM Networking

The two CVMs communicate over the Phala Cloud internal network. In dstack:

```
# Email Oracle CVM → accessible at its CVM hostname/IP
# Tinker Delegate → TINKER_ORACLE_URL=http://<oracle-cvm-ip>:8000
```

For RA-TLS, both CVMs need:
1. TLS certificates from KMS (bound to their TDX quote)
2. Mutual verification of each other's compose hash

## Deployment Steps

### Step 1: Build Docker Images

```bash
# Email Oracle
cd ⚙️/tee-email-oracle
docker build -t email-oracle:latest .

# Tinker Delegate
cd ⚙️/tinker-delegate
docker build -t tinker-delegate:latest .
```

### Step 2: Compute Compose Hashes

```bash
# Each docker-compose.yml has a deterministic hash
# This hash is what gets registered on-chain for TEE verification
phala compose-hash docker-compose.yml
```

### Step 3: Deploy to Phala Cloud

```bash
# Deploy Email Oracle CVM
phala deploy --compose docker-compose.yml --name email-oracle

# Deploy Tinker Delegate CVM
phala deploy --compose docker-compose.yml --name tinker-delegate
```

### Step 4: Register On-Chain (Optional, for v2)

```bash
# Register compose hashes with DstackKms
cast send $DSTACK_KMS "registerApp(bytes32,address)" $APP_ID $AUTH_CONTRACT
```

### Step 5: Genesis

```bash
# Trigger email account creation (one-time)
curl -X POST http://<oracle-cvm>:8000/genesis

# Trigger Tinker signup (one-time)
curl -X POST http://<delegate-cvm>:8080/signup
```

### Step 6: Billing Setup

```bash
# Get attestation
curl http://<delegate-cvm>:8080/attestation
# Verify TDX quote...
# Encrypt and send card details
```

## Environment Variables

### Email Oracle CVM

| Variable | Description | Default |
|---|---|---|
| `DSTACK_ENABLED` | Enable TDX features | `false` |
| `ORACLE_CRED_STORE_PATH` | Path to encrypted credentials | `/data/creds.enc` |
| `ORACLE_IMAP_HOST` | IMAP server | `mail.cock.li` |
| `ORACLE_IMAP_PORT` | IMAP port | `993` |
| `ORACLE_EMAIL_DOMAIN` | Email domain for account creation | `cock.email` |

### Tinker Delegate CVM

| Variable | Description | Default |
|---|---|---|
| `DSTACK_ENABLED` | Enable TDX features | `false` |
| `TINKER_CDP_URL` | Neko Chrome CDP endpoint | `http://localhost:9222` |
| `TINKER_ORACLE_URL` | Email oracle API | `http://localhost:8000` |
| `TINKER_CONSOLE_URL` | Tinker console URL | `https://tinker-console.thinkingmachines.ai` |

## Security Checklist

- [ ] TDX attestation returns real quotes (not stubs)
- [ ] KMS key derivation used for all credential encryption
- [ ] RA-TLS configured between CVMs
- [ ] Compose hashes registered on-chain
- [ ] Card encryption public key bound to TDX quote
- [ ] Checkpoint TTL enforced (1h-24h)
- [ ] Orphan cleanup runs on boot
- [ ] No plaintext secrets in environment variables
- [ ] Docker images built from pinned base images
- [ ] Neko browser isolated (no external network access except Tinker)

## Remaining Work

| Task | Priority | Effort |
|---|---|---|
| Dockerfiles for both services | High | 1 day |
| KMS key derivation integration | High | 1 day |
| Replace all `DSTACK_ENABLED` stubs with real implementations | High | 2 days |
| RA-TLS between CVMs | High | 2 days |
| Phala Cloud deployment scripts | Medium | 1 day |
| Genesis automation (first-boot account creation) | Medium | 1 day |
| Monitoring and alerting | Medium | 2 days |
| Compose hash computation and registration | Medium | 1 day |
| Network isolation (Neko can only reach Tinker domains) | Medium | 1 day |
| Backup/recovery for credential store | Low | 1 day |
