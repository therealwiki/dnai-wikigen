# End-to-End Flow: NDAI Attested Diligence Room

**Status**: ~70% implemented
**Core loop works**: Deal creation → funding → artifact upload → evaluation → bounding → result

## System Components

```
┌───────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   On-Chain         │     │   Tinker-Delegate     │     │  Email Oracle    │
│   (Base Sepolia)   │     │   CVM                 │     │  CVM             │
│                    │     │                       │     │                  │
│ DiligenceRoom.sol  │◄───►│ FastAPI (api.py)      │────►│ FastAPI (api.py) │
│ - createDeal       │     │ ControlPlane          │     │ /pin             │
│ - fundDeal         │     │ IsolatedTinkerSession │     │ /health          │
│ - submitResult     │     │ Evaluator             │     │ /attestation     │
│ - acceptDeal       │     │ Billing               │     │                  │
│ - rejectDeal       │     │ Crypto (X25519)       │     │ cock.email IMAP  │
│ - expireDeal       │     │ Signup automation      │     │ AES-256-GCM creds│
└───────────────────┘     └──────────────────────┘     └─────────────────┘
                                    │
                                    ▼
                          ┌──────────────────────┐
                          │   Tinker API          │
                          │   (Thinking Machines)  │
                          │                       │
                          │ LoRA fine-tuning       │
                          │ Sampling/inference     │
                          │ Checkpoint management  │
                          └──────────────────────┘
```

## Phase 0: Bootstrap (One-Time Setup)

### 0a. Email Oracle Genesis

```
Email Oracle CVM boots
  → Derives encryption key from KMS: derive_key("/email-oracle/creds")
  → Creates cock.email account (HTTP POST or browser fallback with captcha solver)
  → Encrypts credentials with KMS-derived key → stores to disk
  → Starts IMAP connection → FastAPI server on :8000
```

**Implemented**: `account_creator.py`, `browser_signup.py`, `cred_store.py`, `imap_client.py`, `api.py`
**Missing**: KMS key derivation (uses config key), RA-TLS auth, genesis CLI command

### 0b. Tinker Delegate Provisioning

```
Tinker-Delegate CVM boots
  → Checks email oracle health: GET oracle:8000/health
  → Signup flow:
    1. Navigate to tinker-console.thinkingmachines.ai via CDP browser
    2. Enter oracle email → magic-code OTP page
    3. Poll oracle /pin for 6-digit code → enter it
    4. Complete onboarding (name, TOS)
    5. Create API key → capture "tml-..." key
  → Store API key in TEE memory
  → Generate X25519 keypair for card encryption channel
  → Start FastAPI server on :8080
```

**Implemented**: `signup.py`, `oracle_client.py`, `config.py`, `main.py`
**Missing**: Persistent API key storage via KMS, auto-restart signup on key expiry

### 0c. Billing Setup (Developer-Initiated)

```
Developer:
  1. GET /attestation → verify TDX quote → extract encryption_public_key
  2. Encrypt card details: X25519 ECDH → HKDF-SHA256 → AES-256-GCM
  3. POST /billing/card/encrypted {ephemeral_public_key, nonce, ciphertext}

TEE:
  4. Decrypt card → fill Stripe form via CDP browser → submit
  5. Zero card from memory
  6. POST /billing/add-balance {amount_dollars: 100}
  7. Optionally configure auto-reload
```

**Implemented**: `crypto.py`, `card_channel.py`, `billing.py`, `api.py` endpoints
**Missing**: Auto-reload tested, balance monitoring/alerting

## Phase 1: Deal Creation

```
Seller:
  1. Calls DiligenceRoom.createDeal(reservePrice, expiry, artifactHash, teeIdentity)
  2. Contract stores deal with State.Created

On-Chain Watcher (NOT YET BUILT):
  3. Detects DealCreated event
  4. Calls TEE: POST /deal/notify-funded (premature — should wait for funding)
```

**Implemented**: `DiligenceRoom.sol:createDeal()`, `api.py:deal_notify_funded()`
**Missing**: On-chain watcher service, event indexing

## Phase 2: Deal Funding

```
Buyer:
  1. Inspects deal on-chain: getDeal(dealId)
  2. Calls DiligenceRoom.fundDeal{value: budgetCap}(dealId)
  3. Contract transitions to State.Funded

On-Chain Watcher:
  4. Detects DealFunded event
  5. POST /deal/notify-funded {deal_id, buyer, seller, budget_cap, reserve_price}

TEE (ControlPlane):
  6. on_deal_funded() → creates IsolatedTinkerSession for this deal
  7. Deal state: PENDING_ARTIFACT
```

**Implemented**: `DiligenceRoom.sol:fundDeal()`, `control_plane.py:on_deal_funded()`
**Missing**: On-chain watcher, automatic trigger from chain events

## Phase 3: Artifact Upload

```
Seller:
  1. Encrypts dataset artifact (TODO: encryption scheme TBD)
  2. POST /deal/{deal_id}/artifact {artifact_hex, artifact_hash}

TEE (ControlPlane):
  3. receive_artifact() → stores bytes in memory
  4. Verifies artifact_hash matches (TODO: not yet verified)
  5. Deal ready for evaluation
```

**Implemented**: `api.py:deal_upload_artifact()`, `control_plane.py:receive_artifact()`
**Missing**: Artifact encryption/decryption, hash verification, size limits

## Phase 4: Evaluation

```
Trigger: POST /deal/{deal_id}/evaluate (or automatic after artifact upload)

TEE (ControlPlane.evaluate):
  1. Get deal context (artifact + session)
  2. Call evaluator_fn(artifact, artifact_type, session, budget_cap, reserve_price)

Evaluator (inside TEE, using IsolatedTinkerSession):
  3. Parse JSONL dataset from artifact
  4. Split train/eval (90/10)
  5. Create LoRA training: session.create_training("meta-llama/Llama-3.1-8B-Instruct", rank=32)
  6. Tokenize with prompt/completion weighting
  7. Training loop: forward_backward + optim_step (up to 200 steps, batch_size=4)
  8. Save checkpoint: session.save_and_get_sampler("eval-checkpoint")
  9. Benchmark: compute perplexity on held-out eval set (tuned vs base)
  10. Return raw metrics: {quality_delta, benchmark, confidence, methodology}

ControlPlane (output bounding):
  11. raw_delta → bound_output() → ScoreBand (Negligible/Low/Medium/High/Exceptional)
  12. ScoreBand → compute_offer() → offer_price (band multiplier * budget_cap)
  13. Build EvaluationResult (the ONLY thing that leaves the TEE)
  14. Attach TDX quote binding result to enclave identity
  15. Deal state: EVALUATED
```

**Implemented**: `evaluator.py` (both stub and real SFT), `control_plane.py:evaluate()`, `control_plane.py:bound_output()`
**Missing**: Budget enforcement during evaluation, evaluator selection (currently hardcoded stub)

### Output Bounding Table

| Raw Delta | ScoreBand | Band Multiplier | Recommendation |
|---|---|---|---|
| >= 20% | Exceptional | 0.90 | Accept |
| 10-20% | High | 0.70 | Accept |
| 5-10% | Medium | 0.50 | Accept |
| 1-5% | Low | 0.30 | Reject |
| < 1% | Negligible | 0.00 | Reject |

## Phase 5: Result Retrieval & Settlement

```
Buyer (or anyone):
  1. GET /deal/{deal_id}/result → EvaluationResultResponse
     {score_band, quality_delta (banded string), offer_price, recommendation,
      confidence, methodology_summary, compute_cost_wei, fee_wei}

TEE → On-Chain:
  2. submitResult(dealId, scoreBand, computeCost, resultHash)
     - Signed by teeIdentity (KMS-derived key)
     - Contract stores result, transitions to State.Evaluated

Buyer Decision:
  3a. acceptDeal(dealId, dealPayment)
      - dealPayment >= reservePrice
      - Settlement: seller gets dealPayment, developer gets computeCost+fee, buyer gets remainder
  3b. rejectDeal(dealId)
      - Settlement: developer gets computeCost+fee, buyer gets remainder, seller gets nothing

Post-Resolution:
  4. On-chain watcher detects DealAccepted/DealRejected
  5. POST /deal/{deal_id}/resolve
  6. TEE cleanup: session.cleanup() (delete checkpoints), zero artifact from memory
```

**Implemented**: `api.py:deal_get_result()`, `DiligenceRoom.sol:submitResult/acceptDeal/rejectDeal`, `control_plane.py:on_deal_resolved()`
**Missing**: TEE → on-chain result submission (needs KMS-derived signing key), on-chain watcher

## What's NOT Built

### Critical Path (Must Have)

| Component | Description | Effort |
|---|---|---|
| **On-chain watcher** | Listen for `DealCreated`, `DealFunded`, `DealAccepted`, `DealRejected` events → call TEE API | 2-3 days |
| **TEE → chain signer** | KMS-derived key for `submitResult()` transactions | 1 day |
| **Artifact encryption** | Seller encrypts artifact to TEE's public key before upload | 1 day |
| **Hash verification** | Verify `artifact_hash` matches uploaded artifact | 30 min |
| **Budget enforcement** | Check `compute_cost_wei < budget_cap` during evaluation | 30 min |
| **Base model sampler fix** | Add `create_base_sampler()` to `IsolatedTinkerSession` | 10 min |

### Important (Should Have)

| Component | Description | Effort |
|---|---|---|
| **RA-TLS auth** | Mutual TDX attestation between oracle and delegate CVMs | 2 days |
| **Evaluator selection** | Choose stub vs SFT evaluator based on artifact type/deal params | 1 day |
| **Error recovery** | Retry logic for Tinker API failures during evaluation | 1 day |
| **Orphan cleanup on boot** | `cleanup_orphans()` is implemented but not called on startup | 30 min |
| **KMS credential storage** | Use `derive_key` for API key encryption instead of env var | 1 day |

### Nice to Have

| Component | Description | Effort |
|---|---|---|
| **On-chain attestation log** | Log TDX quotes and evaluation metadata on-chain | See ATTESTATION-LOGGING.md |
| **Balance monitoring** | Alert when Tinker balance drops below threshold | 1 day |
| **Multi-evaluator support** | Run multiple evaluation strategies per deal | 3 days |
| **Deal dashboard** | Simple web UI showing deal states and results | 2 days |

## Data Flow Summary

```
Seller's Dataset (private)
  ↓ encrypted
TEE memory (artifact bytes)
  ↓ parsed
JSONL records → tokenized → tinker.Datum objects
  ↓ via Tinker API
LoRA fine-tuning (200 steps on Llama-3.1-8B-Instruct)
  ↓
Checkpoint (TTL-bounded, in Tinker's infra)
  ↓
Perplexity benchmark (tuned vs base)
  ↓
raw quality_delta (e.g., 0.137)
  ↓ output bounding
ScoreBand.HIGH (10-20%)          ← this is what leaves the TEE
  ↓
offer_price = budget_cap * 0.70
  ↓
EvaluationResult + TDX quote     ← signed, bounded, attested
  ↓ on-chain
DiligenceRoom.submitResult()
  ↓
Buyer decision (accept/reject)
  ↓
Three-way ETH settlement
```
