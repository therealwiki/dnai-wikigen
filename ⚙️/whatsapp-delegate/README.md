# WhatsApp Delegate

Attested WhatsApp data delegation via browser automation inside a TEE.

The user provides their WhatsApp credentials. A neko Chrome browser running
inside an Intel TDX enclave (Phala Cloud) logs into WhatsApp Web on their
behalf, exports message history, and seals it encrypted at rest. The sealed
data can only be accessed through owner-approved ML/data pipelines, and all
pipeline outputs are bounded (no raw message text ever leaves the TEE).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     TEE ENCLAVE (dstack CVM)                        │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  Neko Chrome  │◀──│  Delegate    │───▶│  Sealed Store        │  │
│  │  (CDP 9222)  │    │  (FastAPI)   │    │  AES-256-GCM         │  │
│  │              │    │              │    │  derive_key(          │  │
│  │  WhatsApp    │    │  - login     │    │    "whatsapp/msgs")  │  │
│  │  Web session │    │  - export    │    │                      │  │
│  └──────────────┘    │  - pipeline  │    └──────────┬───────────┘  │
│                      │    gate      │               │              │
│                      └──────────────┘               ▼              │
│                                          ┌──────────────────────┐  │
│                                          │  Pipeline Gate       │  │
│                                          │  - owner approves    │  │
│                                          │    image digests     │  │
│                                          │  - bounded outputs   │  │
│                                          │    only (no raw      │  │
│                                          │    message text)     │  │
│                                          └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start (Local Dev)

```bash
cp .env.example .env
docker compose up -d

# Watch the browser live:
open http://localhost:52200   # password: admin

# Step 1: Start login — returns a linking code
curl -X POST http://localhost:8200/login \
  -H 'Content-Type: application/json' \
  -d '{"phone_number": "+12025551234"}'
# → {"status": "awaiting_link", "linking_code": "6NAC-Y7RA"}

# Step 2: User enters the code on their phone:
#   WhatsApp → Settings → Linked Devices → Link device
#   → "Link with phone number instead" → type the code

# Step 2a: Poll until linked (non-blocking):
curl http://localhost:8200/login/status
# → {"status": "waiting"} or {"status": "logged_in"}

# Step 2b: Or block until linked (up to 120s):
curl -X POST http://localhost:8200/login/wait \
  -H 'Content-Type: application/json' \
  -d '{"timeout_seconds": 120}'

# Step 3: Export and seal messages:
curl -X POST http://localhost:8200/export \
  -H 'Content-Type: application/json' \
  -d '{"max_chats": 50}'
```

## Pipeline Access

Data owners control who can access their sealed data:

```bash
# Approve a pipeline (by docker image digest)
curl -X POST http://localhost:8200/pipeline/approve \
  -H 'Content-Type: application/json' \
  -d '{
    "image_digest": "sha256:abc123...",
    "description": "sentiment analysis pipeline",
    "allowed_outputs": ["aggregate_counts", "sentiment_bands"]
  }'

# Pipeline queries sealed data (bounded output only)
curl -X POST http://localhost:8200/pipeline/query \
  -H 'Content-Type: application/json' \
  -d '{
    "pipeline_digest": "sha256:abc123...",
    "query_type": "aggregate_counts"
  }'

# Revoke access
curl -X POST http://localhost:8200/pipeline/revoke \
  -H 'Content-Type: application/json' \
  -d '{"image_digest": "sha256:abc123..."}'

# Owner destroys all data
curl -X DELETE http://localhost:8200/data
```

## Bounded Output Types

| Query Type | Returns | Never Returns |
|---|---|---|
| `aggregate_counts` | Total messages (banded), per-chat activity bands | Raw message text |
| `activity_timeline` | Hourly message distribution | Message content |
| `contact_summary` | Contact names + activity bands | Conversation text |
| `sentiment_bands` | Coarse sentiment distribution | Actual messages |
| `topic_clusters` | Category labels | Text excerpts |

## TEE Deployment (Phala Cloud)

```bash
docker compose -f docker-compose.yaml -f docker-compose.dstack.yaml up
```

In TEE mode:
- Seal key derived from `dstack derive_key("whatsapp/messages")` — only this CVM can decrypt
- `/attestation` endpoint returns TDX quote for verification
- WhatsApp credentials exist only in browser memory during login
- Sealed data survives CVM restart (same derived key)

## Reference

Inspired by:
- [TokScope](https://github.com/Account-Link/teleport-tokscope) — TikTok data sampling in TEE (🔬/amiller)
- [teleport-gramine-rs](https://github.com/Account-Link/teleport-gramine-rs) — Account delegation via SGX NFTs
- `⚙️/cdp-playground` — Base neko Chrome + CDP automation
- `⚙️/tee-email-oracle` — AES-256-GCM sealed credential store pattern
