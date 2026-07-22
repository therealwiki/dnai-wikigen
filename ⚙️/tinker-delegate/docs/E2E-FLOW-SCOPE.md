# End-to-End Flow Scoping Document

> **Historical design snapshot.** The estimates, “implemented/missing” tables,
> old attestation shape, test counts, and deployment checklist below predate the
> current release architecture. Do not use them to authorize a contract write,
> CVM deployment, or live product label. The current sources of truth are
> `STATUS.md`, `ARCHITECTURE.md`, `web/RELEASE-MANIFEST.md`, and
> `docs/DEPLOYMENT-RUNBOOK.md`.

## Current release delta (2026-07-21)

- The frontend is an eleven-route SolidJS product, not a mockup. EIP-6963 and
  injected EIP-1193 wallets are supported; WalletConnect is conditional on
  public deployment configuration.
- The fresh chain unit is seven contracts: Diligence, Tinker encumbrance,
  royalties, challenges, exact-asset Compute capacity, email authorization,
  and the execution-policy anchor. It has been rehearsed locally but not
  deployed to Base Sepolia from this working tree.
- The fresh TEE unit is seven CVMs: one main runtime, five independent QVL CVMs,
  and one independent deterministic Compute meter. None is deployed for this
  release.
- QVL admission uses signed challenge schema v2 and the active independent
  verdict schema/signing domain v4. A signed, single-use,
  profile/policy-scoped challenge valid for at most 120 seconds occupies the
  second half of exact 64-byte quote report data, and DCAP appraisal must finish
  strictly before expiry. The v4 verdict binds exact release lineage and CVM
  identity and carries the separately reviewed exact 900-second
  activation-evidence lease. That lease may outlive the consumed challenge but
  is not renewed challenge freshness. Post-restart Compute recipient activation
  is schema v3 with an explicit recipient lease of at most 300 seconds; its
  stable recipient-release commitment remains schema v2. Legacy reusable
  verdicts and a QVL's self-asserted identity are rejected.
- The Diligence QVL root also evaluates the separate Email/KMS restart profile.
  It does not create a sixth root or eighth CVM.
- `TinkerAccountEncumbrance` uses one exact account/caps/compose/manager policy,
  a two-day review, atomic activation/freeze, and monotonic narrowing afterward.
- Email boot authorization requires same-CVM bearer possession, the fixed
  `tinker-delegate.signup` capability, two independent HTTPS RPCs agreeing on
  one fresh finalized block and exact authorization state, and a persisted
  restart checkpoint. Whole-volume rollback remains an explicit assumption.
- Production Deal evaluation is disabled: the historical remote SFT helper
  would send artifact-derived tokens outside the CVM. It is not a confidential
  evaluator simply because the caller runs in dstack.
- Paid Compute provider dispatch is disabled until a provider adapter supplies
  stable idempotency and exact crash/restart recovery semantics.
- `ComputeCreditVault` exact-asset capacity and off-chain non-transferable
  service credits are separate ledgers with no conversion. Provider-hosted card
  checkout and signed-webhook credit issuance remain roadmap-only.

Everything below remains useful for historical rationale and failure-mode
brainstorming, but its current-status cells are superseded by this delta.

> **Status**: Draft
> **Date**: 2026-03-10
> **Context**: NDAI Diligence Room — Tinker Delegate
> **Sources**: NDAI paper (arXiv 2502.07924), SPEC.md, current implementation, reference repos (skill-verifier, dstack-openclaw, github-zktls, dstack-tutorial)

---

## 1. Complete Flow Diagram

### 1.1 High-Level Lifecycle

```
 PHASE 0: TEE GENESIS (one-shot, CVM boot)
 ──────────────────────────────────────────
 Email oracle creates cock.email account (cock.li IMAP, domain passes blocklist)
   → Seals credentials via dstack-KMS derive_key("email/creds")
   → Oracle compose hash is authorized on-chain for KMS boot
Browser automation attempts Tinker signup through the magic-code OTP path
   → Current deployed headless path is blocked by Tinker bot/fingerprint checks
   → Once unblocked, captures tml-... API key from console modal
   → Seals API key via dstack-KMS derive_key("tinker/api_key")
Approved consumer app ID + compose hash are registered for OTP access
Production hardening:
   → Freeze oracle code authorization permanently after final audited deploy
   → Optionally freeze consumer registry after final consumer measurement is approved
Developer encrypts credit card to TEE's X25519 public key (from /attestation)
   → Funding path is in progress: TEE should fill Stripe form via browser, then zero card from memory
Control plane starts, emits genesis attestation (TDX quote binding identity)

 PHASE 1: DEAL CREATION (on-chain)
 ──────────────────────────────────
 Seller generates an exact 32-byte random secret and computes:
   artifactHash = keccak256(
     ASCII("dnai-wikigen/artifact-commitment/v2") || 0x00 || secret32 || rawArtifact
   )
 Seller privately saves the strict v2 recovery receipt; secret32 never goes on-chain.
 Seller → DiligenceRoom.createDeal(reservePrice, expiry, artifactHash, teeIdentity)
   → On-chain: State = Created
   → Event: DealCreated(dealId, seller, reservePrice, expiry, artifactHash, teeIdentity)

 PHASE 2: DEAL FUNDING (on-chain)
 ────────────────────────────────
 Buyer → DiligenceRoom.fundDeal{value: budgetCap}(dealId, evaluatorPolicyCommitment)
   → On-chain: State = Funded
   → Event: DealFunded(dealId, buyer, budgetCap)
   → On-chain watcher joins the immutable DealCreated context, then notifies control plane
     → POST /deal/notify-funded
       {deal_id, buyer, seller, budget_cap, reserve_price, artifact_hash,
        evaluator_policy_commitment}

 PHASE 3: ARTIFACT UPLOAD (off-chain, to TEE)
 ─────────────────────────────────────────────
 Seller → POST /deal/{dealId}/artifact/encrypted
   → Authenticated artifact_hash must equal the immutable funded context
     before the service attempts decryption.
   → TEE accepts only the exact 1,048,644-byte AES-GCM ciphertext for
     envelope v3. Its authenticated plaintext is the 16-byte
     `DNAIARTIFACTV3\0\0` magic, uint32be private length, secret32, raw bytes,
     and CSPRNG padding filling one fixed 1,048,576-byte payload area.
   → HKDF/AAD bind Base Sepolia 84532, the fresh DiligenceRoom, canonical
     deal ID, artifactHash, immutable funded evaluatorPolicyCommitment, and the
     exact v3 envelope scheme.
   → TEE recomputes the salted v2 commitment before custody and immediately
     before evaluation. Raw unwrapped bytes and legacy raw hashes fail closed.
   → Exact artifact bytes remain in TEE memory only (never disk).

 PHASE 4: EVALUATION (inside TEE boundary)
 ──────────────────────────────────────────
 Control plane creates IsolatedTinkerSession(deal_id)
 Control plane invokes evaluator agent with (artifact, session, budget_cap, reserve_price)
   → Agent: session.create_training("meta-llama/Llama-3.1-8B-Instruct", rank=32)
   → Agent: parse artifact → tokenize → prepare Datum objects
   → Agent: session.forward_backward(batch, "cross_entropy") × N steps
   → Agent: session.optim_step(AdamParams(lr=1e-4)) × N steps
   → Agent: sampler = session.save_and_get_sampler("eval-checkpoint")
   → Agent: benchmark tuned model vs base model (perplexity on held-out set)
   → Agent: return {quality_delta, benchmark, confidence, methodology}
 Control plane bounds output:
   → raw_delta → ScoreBand (negligible/low/medium/high/exceptional)
   → ScoreBand × budget_cap → offer_price (clamped to reserve_price floor)
   → Attaches TDX quote binding deal_id + score_band + offer_price
 TEE submits result on-chain:
   → DiligenceRoom.submitResult(dealId, scoreBand, policyComputeCost,
                                composeHash, authorizationExpiry, verifierSignature)
   → Contract derives resultHash from the immutable deal + bounded public fields
   → On-chain: State = Evaluated
   → Event: EvaluationSubmitted(dealId, scoreBand, computeCost, resultHash)
 Bounded result available to buyer:
   → GET /deal/{dealId}/result → EvaluationResultResponse

 PHASE 5: RESOLUTION (on-chain + TEE cleanup)
 ─────────────────────────────────────────────
 ACCEPT path:
   Buyer → DiligenceRoom.acceptDeal(dealId, dealPayment)
   → dealPayment >= reservePrice, dealPayment + computeCost + fee <= budgetCap
   → Seller receives: dealPayment
   → Developer receives: computeCost + fee (1% of computeCost)
   → Buyer receives: budgetCap - dealPayment - computeCost - fee
   → On-chain: State = Accepted

 REJECT path:
   Buyer → DiligenceRoom.rejectDeal(dealId)
   → Seller receives: nothing
   → Developer receives: computeCost + fee
   → Buyer receives: budgetCap - computeCost - fee
   → On-chain: State = Rejected

 EXPIRE path:
   Anyone → DiligenceRoom.expireDeal(dealId) [after expiry timestamp]
   → Developer receives: computeCost + fee (if evaluation happened)
   → Buyer receives: remainder
   → On-chain: State = Expired

 For ALL resolution paths:
   → On-chain watcher detects terminal event
   → POST /deal/{dealId}/resolve
   → Control plane: session.cleanup() — deletes ALL checkpoints
   → Control plane: zeroes artifact from memory
   → TTL backstop: Tinker auto-deletes any surviving checkpoints
```

### 1.2 Data Flow Diagram

```
                          ON-CHAIN (Base Sepolia)
                    ┌─────────────────────────────┐
                    │  DiligenceRoom.sol           │
                    │                              │
  Seller ─createDeal──►│  Created ──fundDeal──►    │◄── Buyer
         ─(artifact)─► │  Funded  ──submitResult──►│
                    │  Evaluated──acceptDeal──►    │──► Seller (ETH)
                    │          ──rejectDeal──►     │──► Developer (ETH)
                    │          ──expireDeal──►     │──► Buyer (ETH refund)
                    └────────────┬─────────────────┘
                                 │ Events
                    ┌────────────▼─────────────────┐
                    │  On-chain Watcher             │ ◄── NOT YET BUILT
                    │  (web3.py / ethers.js)        │
                    └────────────┬─────────────────┘
                                 │ HTTP calls
          ┌──────────────────────▼──────────────────────┐
          │        dstack CVM (Intel TDX)                │
          │                                              │
          │  ┌──────────────┐  ┌─────────────────────┐  │
          │  │ Email Oracle  │  │ Neko Chrome (CDP)    │  │
          │  │ cock.email    │  │ Playwright browser   │  │
          │  │ /health /pin  │  │ automation           │  │
          │  └──────┬───────┘  └─────────┬───────────┘  │
          │         │                     │              │
          │  ┌──────▼─────────────────────▼──────────┐  │
          │  │     tinker-delegate FastAPI             │  │
          │  │                                         │  │
          │  │  /health  /attestation  /billing/*      │  │
          │  │  /deal/notify-funded                     │  │
          │  │  /deal/{id}/artifact                     │  │
          │  │  /deal/{id}/evaluate                     │  │
          │  │  /deal/{id}/result                       │  │
          │  │  /deal/{id}/resolve                      │  │
          │  │  /deals                                  │  │
          │  └──────┬──────────────────────────────────┘  │
          │         │                                      │
          │  ┌──────▼──────────────────────────────────┐  │
          │  │  Control Plane                           │  │
          │  │  ├── Session factory                     │  │
          │  │  ├── Artifact ingress (memory-only)      │  │
          │  │  ├── Evaluator orchestration             │  │
          │  │  ├── Output bounding (raw→band)          │  │
          │  │  ├── TDX attestation on results          │  │
          │  │  └── Cleanup enforcement                 │  │
          │  └──────┬──────────────────────────────────┘  │
          │         │                                      │
          │  ┌──────▼──────────────────────────────────┐  │
          │  │  IsolatedTinkerSession                   │  │
          │  │  ├── One training run per deal            │  │
          │  │  ├── Path-checked sampling                │  │
          │  │  ├── Mandatory TTL (1h-24h)               │  │
          │  │  ├── Cost metering (tokens × rate)        │  │
          │  │  └── No download / publish / list          │  │
          │  └──────┬──────────────────────────────────┘  │
          │         │ HTTPS                                │
          │  ┌──────▼──────────────────────────────────┐  │
          │  │  dstack-KMS (sealed storage)             │  │
          │  │  derive_key("tinker/api_key")            │  │
          │  │  derive_key("email/creds")               │  │
          │  └─────────────────────────────────────────┘  │
          └───────────────┬────────────────────────────────┘
                          │ HTTPS
                          ▼
                 Tinker Platform (thinkingmachines.ai)
                 Training + Sampling + Checkpoint management
```

---

## 2. What Works Today vs What is Missing

### 2.1 Implemented (Working)

| Component | File(s) | Status |
|-----------|---------|--------|
| **Tinker signup automation** | `signup.py`, `oracle_client.py` | Implemented, but not production-complete. Handles magic-code OTP in the happy path; current deployed headless path is blocked by Tinker bot/fingerprint checks. |
| **Billing automation** | `billing.py` | Browser automation for Stripe Elements iframe. Card entry, balance add, auto-reload are coded; reliable end-to-end completion through Tinker/Stripe remains in progress. |
| **Encrypted card channel** | `crypto.py`, `card_channel.py` | X25519 + AES-256-GCM. TEE keypair generation, encrypt/decrypt, memory zeroing. |
| **IsolatedTinkerSession** | `session.py` | Session isolation, path-checked sampling, mandatory TTL, cost metering, cleanup. |
| **Control plane** | `control_plane.py` | Deal lifecycle state machine, session factory, artifact ingress, output bounding, orphan cleanup. |
| **Evaluator agents** | `evaluator.py` | Stub (deterministic from artifact hash) + SFT (real LoRA fine-tune + perplexity benchmark). |
| **FastAPI server** | `api.py` | Health, attestation, billing endpoints, deal lifecycle endpoints (notify-funded, artifact, evaluate, result, resolve). |
| **DiligenceRoom.sol** | `contracts/src/DiligenceRoom.sol` | Escrow state machine. 6 states, 5 transitions, three-way settlement, 22 tests passing. |
| **Contract tests** | `contracts/test/DiligenceRoom.t.sol` | Unit tests + fuzz test for settlement conservation. All 22 passing. |
| **Configuration** | `config.py` | Pydantic Settings with TINKER_ env prefix. |

### 2.2 Missing (Not Yet Built)

| Component | Priority | Effort Estimate | Notes |
|-----------|----------|-----------------|-------|
| **On-chain event watcher** | P0 (critical) | 2-3 days | web3.py or ethers.js listening for DealCreated, DealFunded, DealAccepted, DealRejected, DealExpired events. Bridges on-chain state to TEE control plane API. |
| **Contract deployment** | P0 (critical) | < 1 day | Deploy DiligenceRoom.sol to Base Sepolia via forge-deploy. Verify on BaseScan. |
| **dstack-KMS key sealing** | P1 (high) | 1 day | Replace env-var API key with `TappdClient.derive_key("tinker/api_key")`. Currently API key is in plaintext env. |
| **Phala Cloud deployment** | P1 (high) | 2 days | Merge docker-compose with email oracle. Deploy to Phala Cloud. Test real TDX attestation. |
| **Oracle auth contract** | P1 (high) | 1-2 days | Deploy on Base Sepolia. Separate oracle boot authorization from OTP consumer authorization. Add irreversible freeze for oracle code policy. |
| **Local testing with Phala simulator** | P1 (high) | 1 day | Use `phala simulator start` for local dev without real TDX hardware. |
| **SFT evaluator integration test** | P2 (medium) | 1-2 days | Test with real Tinker API key. Verify training, sampling, perplexity comparison, cleanup. |
| **Session isolation unit tests** | P2 (medium) | 1 day | Verify path-checking blocks cross-deal sampling. Verify cleanup deletes all checkpoints. |
| **Base model sampling for comparison** | P3 (low) | < 1 day | Currently SFT evaluator creates a base sampler by bypassing the session (`session._sc.create_sampling_client`). Should be a first-class session method. |
| **Artifact encryption** | P3 (low) | 1 day | Currently artifact uploaded as hex bytes. Should be encrypted to TEE's X25519 key, same as card channel. |
| **TEE-to-chain transaction signing** | P1 (high) | 1-2 days | TEE needs to call `submitResult()` on-chain. Requires KMS-derived Ethereum keypair and transaction signing. |
| **Buyer-facing result verification** | P2 (medium) | 1 day | Buyer needs to verify TDX quote in the EvaluationResult. SDK or script for quote verification. |

---

## 3. Integration Points Between Components

### 3.1 Component Interaction Matrix

```
                    Email    Neko     Tinker    Control   Evaluator  DiligenceRoom  On-chain
                    Oracle   Chrome   Platform  Plane     Agent      .sol           Watcher
Email Oracle        --       --       --        health()  --         --             --
Neko Chrome         OTP←     --       CDP→      --        --         --             --
Tinker Platform     --       signup→  --        --        SDK calls  --             --
Control Plane       --       --       Session→  --        evaluate() --             ←events
Evaluator Agent     --       --       (via sess)←invoke   --         --             --
DiligenceRoom       --       --       --        --        --         --             events→
On-chain Watcher    --       --       --        HTTP→     --         read events    --
```

### 3.2 Key Integration Interfaces

**On-chain Watcher → Control Plane API**

The watcher translates on-chain events into HTTP calls:

| On-chain Event | Watcher Action | HTTP Call |
|----------------|----------------|-----------|
| `DealFunded(dealId, buyer, budgetCap)` | Decode event, look up deal details | `POST /deal/notify-funded {deal_id, buyer, seller, budget_cap, reserve_price}` |
| `DealAccepted(dealId, ...)` | Notify cleanup | `POST /deal/{dealId}/resolve` |
| `DealRejected(dealId, ...)` | Notify cleanup | `POST /deal/{dealId}/resolve` |
| `DealExpired(dealId, ...)` | Notify cleanup | `POST /deal/{dealId}/resolve` |

**Control Plane → Evaluator Agent**

```python
# evaluator_fn signature (both stub and SFT follow this):
async def evaluate(
    artifact: bytes,           # raw artifact bytes
    artifact_type: str,        # "dataset", "recipe", "reward_fn"
    session: IsolatedTinkerSession,
    budget_cap: int,           # wei
    reserve_price: int,        # wei
) -> dict                      # {quality_delta: float, benchmark: str, confidence: str, methodology: str}
```

**Control Plane → On-chain (TEE submits result)**

```python
# TEE needs to sign and submit a transaction:
DiligenceRoom.submitResult(
    dealId,                    # uint256
    scoreBand,                 # ScoreBand enum (0-4)
    computeCost,               # uint256 deterministic public tariff (wei)
    composeHash,               # bytes32 (approved app/compose measurement)
    authorizationExpiry,       # uint256
    verifierSignature          # bytes (resultVerifier authorization)
)
# msg.sender must == deal.teeIdentity (KMS-derived address)
# verifierSignature must bind the contract-derived canonical result hash.
# Callers cannot supply an opaque payload/result/transcript commitment.
```

**Encrypted Card Channel: Developer → TEE**

```
1. Developer: GET /attestation → {mode, encryption_public_key, quote}
2. Developer: verify TDX quote (code measurements match expected)
3. Developer: encrypt_card_payload(card_data, tee_public_key_hex) → {ephemeral_public_key, nonce, ciphertext}
4. Developer: POST /billing/card/encrypted → TEE decrypts → fills Stripe → zeroes memory
```

### 3.3 Data Formats

| Data | Format | Size | Notes |
|------|--------|------|-------|
| Artifact | bytes (hex-encoded over HTTP) | Variable | JSONL for SFT datasets. Future: encrypted to TEE pubkey. |
| Artifact hash | bytes32 | 32 bytes | keccak256 of raw artifact bytes. Set at createDeal time. |
| API key | string | ~80 chars | `tml-[A-Za-z0-9_-]{60+}`. Sealed in KMS after capture. |
| Evaluation result | JSON | ~500 bytes | score_band, quality_delta, offer_price, recommendation, confidence, methodology_summary, compute_cost_wei, fee_wei |
| TDX quote | bytes | ~4KB | Intel TDX attestation. Contains report_data = `{deal_id}:{score_band}:{offer_price}` |
| Score band | enum | 1 byte | negligible(0), low(1), medium(2), high(3), exceptional(4) |
| Deal payment | uint256 | 32 bytes | In wei. Must be >= reservePrice and <= budgetCap - computeCost - fee. |

---

## 4. Testing Strategy: Full Flow Without Real Money

### 4.1 Layer 1: Unit Tests (No External Dependencies)

```bash
# Contract tests — already implemented, 22 tests passing
cd contracts && forge test -vvv

# Python unit tests (to be written)
# - Session isolation: mock tinker.ServiceClient, verify path-checking
# - Cost metering: verify token counting and price calculation
# - Output bounding: verify raw_delta → ScoreBand mapping
# - Offer computation: verify band × budget_cap → offer_price
```

### 4.2 Layer 2: Integration Tests with Anvil + Stub Evaluator

```bash
# 1. Start local Ethereum node
anvil --chain-id 84532 &

# 2. Deploy DiligenceRoom.sol locally
forge script contracts/script/DiligenceRoom.s.sol --rpc-url http://localhost:8545 --broadcast

# 3. Start Phala simulator (mock KMS + attestation)
phala simulator start

# 4. Start email oracle + neko (docker compose)
cd ⚙️/tee-email-oracle && docker compose --profile browser up -d

# 5. Start tinker-delegate API
TINKER_API_KEY="test-key" python -m tinker_delegate.main serve --port 8080

# 6. Simulate full flow with stub evaluator:
#    a. Create deal on local Anvil
#    b. Upload artifact to TEE API
#    c. Fund deal on local Anvil
#    d. Watcher notifies TEE → evaluate with stub_evaluate
#    e. Accept/reject on local Anvil
#    f. Verify cleanup
```

### 4.3 Layer 3: Integration Test with Real Tinker API (No Real ETH)

```bash
# Same as Layer 2 but:
# - Use a real Tinker API key (from a test account)
# - Use sft_evaluate instead of stub_evaluate
# - Verify actual training run creation, checkpoint saves, sampling, cleanup
# - Verify cost metering matches Tinker's billing dashboard
# - Use Anvil for on-chain parts (no real ETH)
```

### 4.4 Layer 4: Testnet End-to-End

```bash
# Deploy DiligenceRoom to Base Sepolia (real testnet, free ETH from faucet)
# Deploy tinker-delegate to Phala Cloud (real TDX)
# Run full flow with real actors:
#   - Seller creates deal with real artifact
#   - Buyer funds with testnet ETH
#   - TEE evaluates with real Tinker compute
#   - Buyer accepts/rejects
#   - Verify three-way settlement on-chain
#   - Verify TDX quotes are verifiable
```

### 4.5 Key Test Assertions

| Assertion | Layer | How to Verify |
|-----------|-------|---------------|
| Session isolation blocks cross-deal sampling | 1 | Mock ServiceClient, attempt sampling from foreign path → PermissionError |
| TTL is set on every checkpoint save | 1 | Inspect call args to save_weights_for_sampler |
| Cost metering matches expected token count | 1 | Known batch size × known steps → expected cost |
| Output bounding maps correctly | 1 | raw_delta=0.15 → ScoreBand.HIGH |
| Contract settlement conserves funds | 1 | Fuzz test (already passing): sum(payouts) == budgetCap |
| Cleanup deletes all checkpoints | 3 | After cleanup(), list_checkpoints returns empty |
| TEE attestation includes deal_id | 4 | Parse TDX quote report_data, verify deal_id present |
| Buyer cannot read raw artifact | 4 | GET /deal/{id}/result returns bounded output only |
| Expired deals auto-cleanup via TTL | 3 | Save checkpoint with ttl=60s, wait 90s, verify inaccessible |

---

## 5. Failure Modes and Recovery

### 5.1 TEE Crash During Evaluation

**Scenario**: CVM crashes or restarts while an evaluator agent is running.

**Impact**: Partial training run exists on Tinker's servers. Session state lost from TEE memory. Artifact lost from memory.

**Recovery**:
1. **TTL backstop**: All checkpoints have mandatory TTL (1h-24h). Tinker auto-deletes them.
2. **Orphan cleanup on boot**: `ControlPlane.cleanup_orphans()` scans Tinker for training runs with `deal_id` metadata that don't have a corresponding active deal in the control plane.
3. **On-chain state**: Deal remains in `Funded` state. After `expiry`, anyone can call `expireDeal()` to refund the buyer.
4. **Re-evaluation**: If CVM reboots before expiry, the watcher can re-detect the Funded deal and restart evaluation (requires re-upload of artifact by seller).

**Gap**: No mechanism for seller to re-upload artifact after TEE crash. The seller would need to monitor for this case and re-upload.

### 5.2 Network Partition (TEE Cannot Reach Chain)

**Scenario**: TEE loses connectivity to Base Sepolia RPC.

**Impact**: Cannot submit evaluation result on-chain. Cannot detect deal resolution events.

**Recovery**:
1. **Evaluation still completes locally**: TEE holds the bounded result in memory.
2. **Retry loop**: Watcher retries event polling on reconnection.
3. **Expiry safety net**: If partition lasts past deal expiry, buyer gets refunded via `expireDeal()`.
4. **Idempotent cleanup**: `session.cleanup()` is idempotent — safe to call multiple times.

**Gap**: If TEE completes evaluation but cannot submit `submitResult()` on-chain, the evaluation is wasted. Need retry logic for on-chain transactions.

### 5.3 Stuck Deals

**Scenario**: Deal is in `Evaluated` state but buyer neither accepts nor rejects.

**Impact**: Seller's artifact derivative (trained model) exists on Tinker servers until TTL expires. Buyer's escrow is locked.

**Recovery**:
1. **TTL backstop**: Checkpoints self-destruct regardless of deal state.
2. **Expiry**: After `expiry` timestamp, anyone can call `expireDeal()`. Developer gets compute cost + fee; buyer gets remainder.
3. **Incentive alignment**: Buyer has incentive to act (their funds are locked). Seller has no ongoing risk (artifact is bounded to score bands).

### 5.4 Tinker Platform Outage

**Scenario**: Tinker API is down during evaluation.

**Impact**: Training fails. No result to submit.

**Recovery**:
1. Deal remains in `Funded` state.
2. Evaluation can be retried when Tinker comes back (if before expiry).
3. If Tinker outage exceeds deal expiry, buyer gets refunded.

**Gap**: No health check for Tinker API availability before starting evaluation. Should probe Tinker before committing to evaluation.

### 5.5 Tinker Account Suspension

**Scenario**: Tinker suspends the TEE's account (ToS violation, abuse detection).

**Impact**: All future evaluations fail. Active training runs may be terminated.

**Recovery**:
1. Existing deals: expiry → refund path.
2. Future deals: system is down until account is restored or new account created.
3. **Mitigation**: Pre-register a second account during genesis (open question in SPEC).
4. **Detection**: Health check polls Tinker API before accepting new deals.

### 5.6 Malicious Artifact (Adversarial Seller)

**Scenario**: Seller uploads a poisoned dataset designed to crash the evaluator or produce misleading results.

**Impact**: Agent may produce incorrect valuation. Agent may crash (NaN loss, OOM).

**Recovery**:
1. Agent-level: SFT evaluator catches empty datasets, low-quality tokenization.
2. Training-level: Loss monitoring can detect divergence (NaN, exploding gradients).
3. Session-level: Training run is isolated — cannot affect other deals.
4. Cleanup: TTL ensures any partial training is cleaned up.
5. Economic: Buyer bears the risk of poor evaluation (per NDAI paper Section 5 — agent error analysis).

### 5.7 TEE Compromise (Side-Channel Attack)

**Scenario**: Attacker extracts secrets from TDX enclave via side-channel.

**Impact**: API key, artifact, trained model weights all exposed.

**Recovery**:
1. This is outside the NDAI paper's security threshold Phi. For high-value secrets where omega > Phi, the paper models partial mitigation.
2. Multi-TEE provisioning (NDAI Section 3.2): Use k distinct TEE providers with threshold encryption.
3. Practical: Rotate API key, revoke compromised account, re-genesis.

---

## 6. What the On-Chain Watcher Needs to Do

### 6.1 Responsibilities

The on-chain watcher is the bridge between the blockchain and the TEE control plane. It is the most critical missing component.

```
┌─────────────────────────────────────────────────────────────────────┐
│  ON-CHAIN WATCHER                                                    │
│                                                                      │
│  INPUTS:                                                             │
│    - Base Sepolia RPC URL                                            │
│    - DiligenceRoom contract address                                  │
│    - TEE control plane URL (http://localhost:8080)                   │
│                                                                      │
│  LISTENS FOR:                                                        │
│    DealCreated   → log for informational display                     │
│    DealFunded    → POST /deal/notify-funded to control plane         │
│    EvaluationSubmitted → (TEE submitted this, just log)              │
│    DealAccepted  → POST /deal/{id}/resolve to control plane          │
│    DealRejected  → POST /deal/{id}/resolve to control plane          │
│    DealExpired   → POST /deal/{id}/resolve to control plane          │
│                                                                      │
│  ALSO:                                                               │
│    - On startup: scan all deals for Funded deals that need eval      │
│    - Periodic: check for expired deals and call expireDeal()         │
│    - Error handling: retry on RPC failures, reorg handling           │
│                                                                      │
│  RUNS:                                                               │
│    Inside the same CVM as the control plane                          │
│    (shares network, can reach control plane at localhost)             │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.2 Event Processing Logic

```python
# Pseudocode for the watcher:

async def watch_events(contract, control_plane_url):
    # On startup: catch up on any missed events
    last_block = load_checkpoint()  # persisted block number

    # Scan for deals in Funded state that haven't been processed
    for deal_id in range(contract.dealCount()):
        deal = contract.getDeal(deal_id)
        if deal.state == State.Funded:
            notify_control_plane_funded(deal)

    # Stream events
    while True:
        events = contract.events.get_all_entries(from_block=last_block)
        for event in events:
            match event.event:
                case "DealFunded":
                    deal = contract.getDeal(event.args.dealId)
                    POST(f"{control_plane_url}/deal/notify-funded", {
                        deal_id=str(event.args.dealId),
                        buyer=deal.buyer,
                        seller=deal.seller,
                        budget_cap=deal.budgetCap,
                        reserve_price=deal.reservePrice,
                    })
                    # After notification, trigger evaluation
                    POST(f"{control_plane_url}/deal/{event.args.dealId}/evaluate")

                case "DealAccepted" | "DealRejected" | "DealExpired":
                    POST(f"{control_plane_url}/deal/{event.args.dealId}/resolve")

        save_checkpoint(latest_block)
        await asyncio.sleep(POLL_INTERVAL)
```

### 6.3 Critical Design Decisions for Watcher

1. **Polling vs WebSocket**: Polling is simpler and more resilient to RPC disconnections. 12-second block time on Base makes polling every 6 seconds reasonable.

2. **Reorg handling**: Base Sepolia has fast finality. Wait for 2-3 confirmations before processing events to avoid acting on reorged blocks.

3. **Idempotency**: Control plane endpoints must be idempotent. If the watcher sends `notify-funded` twice for the same deal, the control plane should not create a duplicate session.

4. **Block checkpoint persistence**: Store the last-processed block number in a file (or KMS-sealed storage). On restart, resume from that block.

5. **TEE identity**: The watcher needs access to the KMS-derived Ethereum keypair to call `submitResult()` on-chain. This key is the `teeIdentity` registered in the deal.

---

## 7. Attestation Flow: TEE to Chain to Buyer

### 7.1 Attestation Chain

```
Step 1: TEE Genesis
  TEE boots → dstack provides TDX quote
  Quote contains:
    - MRTD (measurement of TDX module)
    - RTMR (runtime measurements = compose hash)
    - Report data: genesis identity info

Step 2: Code Verification
  Auditor/buyer can verify:
    git SHA → docker build → docker digest → compose hash → RTMR in TDX quote
  If the chain matches, the auditor knows exactly what code is running in the TEE.

Step 3: Evaluation Attestation
  After evaluation, TEE generates a TDX quote with:
    report_data = f"{deal_id}:{score_band}:{offer_price}"
  This binds the evaluation result to the specific enclave instance.

Step 4: On-chain Submission
  TEE calls DiligenceRoom.submitResult() from its KMS-derived address.
  The contract verifies msg.sender == deal.teeIdentity.
  The contract rejects non-policy compute cost and derives resultHash as the
  domain-separated `DiligenceRoomPublicResult(...)` commitment over chain ID,
  contract, immutable funded-deal fields, compose hash, score band, and tariff.

Step 5: Buyer Verification
  Buyer retrieves:
    a) On-chain: resultHash, scoreBand, computeCost from DiligenceRoom.getDeal()
    b) Off-chain: bounded result + independent TDX/QVL verdict
  Buyer verifies:
    a) canonicalResultHash(...) == resultHash (public policy fields match chain)
    b) TDX quote is valid (Intel signature chain)
    c) Quote's RTMR matches expected compose hash (correct code)
    d) Quote's report_data matches the bounded public projection (correct deal)

Raw evaluator details and private reward transcripts are intentionally not
recoverable from, or committed through a caller-selected field in, resultHash.
```

### 7.2 Current Implementation vs Full Attestation

| Step | Current Status | Gap |
|------|---------------|-----|
| TEE keypair generation | X25519 keypair for card encryption channel. Generated on boot. | Need KMS-derived Ethereum keypair for on-chain transactions. |
| TDX quote generation | Stub in local mode; real via `TappdClient.tdx_quote()` in dstack mode. | Needs testing on Phala Cloud. |
| Compose hash binding | Not yet implemented. | Need reproducible Docker builds pinned by digest, not tag. |
| On-chain TEE identity | Contract has `teeIdentity` field (address). | Need KMS key derivation → Ethereum address derivation. |
| Result attestation | `_get_tdx_quote()` in control_plane.py generates quote with deal info. | Only generates when `DSTACK_ENABLED=true`. Needs integration test. |
| Buyer-side verification | Not implemented. | Need SDK or script for verifying TDX quotes off-chain. |

### 7.3 Reference: How dstack-openclaw Does It

dstack-openclaw uses a **mediating proxy** pattern for domain separation:
- The app container cannot access the real `dstack.sock` directly.
- A proxy container enforces that genesis attestations can only include the correct genesis hash.
- The proxy forwards legitimate attestation requests to the real dstack socket.

**Relevance to our system**: We should consider a similar proxy pattern to prevent the evaluator agent from generating arbitrary attestations. The control plane should be the only component that can request TDX quotes.

---

## 8. Performance Considerations

### 8.1 Estimated Evaluation Time

| Phase | Duration | Notes |
|-------|----------|-------|
| Artifact upload | < 1 second | Depends on artifact size. 1MB dataset = instant. |
| Session creation | ~2 seconds | Tinker API: create LoRA training client. |
| Tokenization | 1-10 seconds | Depends on dataset size. 10K examples ~5s. |
| Training (200 steps, batch 4) | 3-10 minutes | Llama-3.1-8B, LoRA rank 32. ~1-3s per step. |
| Checkpoint save | ~5 seconds | Save weights for sampler. |
| Benchmarking (20 eval examples) | 30-60 seconds | Log-probability computation per example. |
| Output bounding + attestation | < 1 second | Local computation + TDX quote. |
| **Total** | **5-15 minutes** | For a typical SFT evaluation. |

### 8.2 Cost Per Evaluation

Using Llama-3.1-8B-Instruct (the default in the SFT evaluator):

```
Training: 200 steps × 4 examples × 2048 tokens × $0.40/M tokens
        = 200 × 4 × 2048 × 0.40 / 1,000,000
        = $0.655

Sampling (eval): 20 examples × 2048 tokens × $0.13/M tokens (prefill)
              = 20 × 2048 × 0.13 / 1,000,000
              = $0.005

Total Tinker cost: ~$0.66 per evaluation
Fee (1%): ~$0.007
Total with fee: ~$0.67
```

At ETH = $2000, this is approximately 0.000335 ETH (~335,000 gwei) per evaluation.

### 8.3 Concurrency

The system supports concurrent deals because:
- Each deal gets its own `IsolatedTinkerSession`.
- Tinker supports concurrent training runs on a single account.
- Sessions are independent (no shared state beyond the Tinker API key).
- Main constraint: CVM memory for holding multiple artifacts simultaneously.

Practical limit: 3-5 concurrent evaluations per CVM (limited by Tinker account rate limits and CVM memory).

---

## 9. Comparison with Reference Implementations

### 9.1 skill-verifier (Closest Analog)

| Aspect | skill-verifier | Tinker Delegate |
|--------|---------------|-----------------|
| **What is evaluated** | Code skills (run tests) | ML training data (train model, benchmark) |
| **Evaluation method** | Docker container: run test suite, check exit code | Tinker API: LoRA fine-tune, compute perplexity delta |
| **Attestation** | Docker (current), GitHub Actions (soft TEE), dstack TEE (future) | dstack TEE (Intel TDX on Phala Cloud) |
| **Escrow** | Conceptual (ESCROW-AGENT.md). KMS-sealed wallet. Phala contract. | Implemented (DiligenceRoom.sol on Base Sepolia). Three-way settlement. |
| **Certificate format** | Inspection certificate: tests passed/failed + attestation hash | EvaluationResult: score_band + quality_delta + offer_price + TDX quote |
| **Payment trigger** | If tests pass → KMS releases to seller | Buyer explicitly accepts/rejects after seeing bounded result |
| **Key innovation** | Ephemeral execution model (load→run→delete→certificate) | Output bounding (raw metrics never leave TEE, only coarse bands) |
| **Stage of development** | Docker backend working; TEE integration planned | Core components implemented; watcher + TEE deployment pending |

**What we borrow from skill-verifier**:
- The ephemeral execution model: artifact enters TEE, evaluation runs, artifact is destroyed, only certificate persists.
- The escrow agent pattern: TEE holds funds, verifies work, releases based on result.

**Where we diverge**:
- skill-verifier uses binary pass/fail. We use score bands with a buyer decision step.
- skill-verifier plans for automated release on pass. We keep the buyer in the loop (per NDAI paper: buyer's agent makes the accept/reject decision).
- Our evaluation is vastly more expensive (minutes of GPU training vs seconds of test execution).

### 9.2 dstack-openclaw (Domain Separation)

| Aspect | dstack-openclaw | Tinker Delegate |
|--------|----------------|-----------------|
| **Domain separation** | Proxy container enforces genesis immutability. App cannot forge genesis attestations. | Not yet implemented. Control plane and evaluator share same process. |
| **Architecture** | Two containers: app + proxy. Proxy mediates dstack.sock access. | Single process with multiple modules. |
| **Genesis transparency** | Immutable genesis log captured at boot. Hash included in all attestations. | TEE genesis captures email + API key. Not yet attestation-bound. |

**What we should adopt**:
- Domain separation via proxy: evaluator agent should NOT have direct access to dstack.sock. Only the control plane should be able to generate TDX quotes.
- Genesis log pattern: record all initialization inputs (email, API key hash, code version) in an immutable genesis log.

### 9.3 github-zktls (Attestation + Escrow)

| Aspect | github-zktls | Tinker Delegate |
|--------|-------------|-----------------|
| **Trust model** | GitHub Actions as soft TEE. Sigstore attestations. ZK proofs for on-chain verification. | Intel TDX as hardware TEE. Direct TDX quotes. |
| **On-chain verification** | ZK proof of Sigstore attestation (~3M gas, ~10KB proof). | TDX quote verification (not yet on-chain). |
| **Escrow pattern** | SelfJudgingEscrow: Claude evaluates in GH Actions, ZK proof claims bounty. | DiligenceRoom: TEE evaluates, buyer accepts/rejects. |
| **Key innovation** | Permissionless attestation (anyone can fork repo and produce proofs). | Bounded output (never raw metrics). |

**What we could adopt**:
- On-chain TDX quote verification: currently our contract trusts `msg.sender == teeIdentity` without verifying the attestation. Future: verify TDX quote on-chain (similar to how github-zktls verifies Sigstore via ZK proof).
- Self-judging pattern: for simple evaluations, the TEE could auto-accept/reject based on the score band, eliminating the need for buyer action.

### 9.4 dstack-tutorial (DevProof Patterns)

| Aspect | dstack-tutorial | Our System |
|--------|----------------|------------|
| **Security stage** | Teaches Stage 0 → Stage 1 (DevProof). On-chain authorization for upgrades. | Currently Stage 0 (no upgrade transparency). |
| **Reproducible builds** | Tutorial section 02: pin base images by digest, normalize timestamps. | Not yet implemented. Using tags, not digests. |
| **On-chain authorization** | Oracle auth contract governs oracle compose hashes for KMS boot and separately governs which consumer app IDs / compose hashes may request OTPs. | Not yet implemented. Anyone who deploys gets keys and runtime OTP policy is not yet anchored on-chain. |
| **Key derivation** | Tutorial section 03: KMS trust model, deterministic keys per app. | Planned: `derive_key("tinker/api_key")`. Not yet integrated. |

**What we must adopt for production**:
- Reproducible Docker builds (pin by digest).
- AppAuth contract for upgrade authorization.
- On-chain oracle compose-hash registration before deployment.
- Separate consumer app ID + compose-hash registration for OTP access.
- Permanent freeze of oracle code authorization after final audited deployment.
- Timelock on upgrades (per dstack-tutorial section 08) to give users exit opportunity.

---

## 10. Prioritized Remaining Work Items

### P0 — Critical Path (Must-Have for Demo)

| # | Item | Effort | Dependencies |
|---|------|--------|-------------|
| 1 | **Deploy DiligenceRoom.sol to Base Sepolia** | < 1 day | Foundry keystore with funded account |
| 2 | **Build on-chain event watcher** | 2-3 days | Contract address, Base Sepolia RPC |
| 3 | **TEE-to-chain transaction signing** | 1-2 days | KMS-derived Ethereum keypair |
| 4 | **End-to-end smoke test on Anvil** | 1 day | Items 2-3 |

### P1 — High Priority (Required for Testnet Demo)

| # | Item | Effort | Dependencies |
|---|------|--------|-------------|
| 5 | **dstack-KMS key sealing** | 1 day | Phala simulator |
| 6 | **Phala Cloud deployment** | 2 days | Docker images pushed to registry, KMS integration |
| 7 | **Phala simulator local testing** | 1 day | phala CLI installed |
| 8 | **Artifact encryption to TEE pubkey** | 1 day | Already have crypto.py for cards; extend to artifacts |
| 9 | **Reproducible Docker builds** | 1 day | Pin base images by digest |

### P2 — Medium Priority (Quality & Confidence)

| # | Item | Effort | Dependencies |
|---|------|--------|-------------|
| 10 | **SFT evaluator integration test** | 1-2 days | Real Tinker API key |
| 11 | **Session isolation unit tests** | 1 day | Mock Tinker SDK |
| 12 | **Buyer TDX quote verification tool** | 1 day | Phala trust-center or dcap-qvl |
| 13 | **TTL reliability verification** | < 1 day | Real Tinker API key |
| 14 | **Base model sampling in session** | < 1 day | Small code change to session.py |
| 15 | **Health check: probe Tinker before eval** | < 1 day | Tinker API health endpoint |

### P3 — Future / Nice-to-Have

| # | Item | Effort | Dependencies |
|---|------|--------|-------------|
| 16 | **On-chain TDX quote verification** | 3-5 days | ZK circuit for TDX attestation or optimistic verification |
| 17 | **Domain separation proxy** | 2 days | dstack-openclaw pattern |
| 18 | **AppAuth contract for upgrade control** | 2-3 days | dstack-tutorial section 05 |
| 19 | **Multiple evaluator strategies** | 2-3 days | DPO, reward model, custom benchmarks |
| 20 | **Concurrent deal stress test** | 1-2 days | Multiple funded deals simultaneously |
| 21 | **Client-side training data encryption** | Research | Requires Tinker to support encrypted compute |
| 22 | **Multi-TEE provisioning per NDAI Section 3.2** | Research | Multiple TEE providers |

---

## 11. Theories to Test (Assumptions Requiring Validation)

### T1: TTL Reliability on Tinker

**Assumption**: Tinker's `ttl_seconds` parameter on checkpoint saves truly makes checkpoints inaccessible after expiry — not just marked expired but still downloadable via direct URL.

**Test**: Save a checkpoint with `ttl_seconds=60`. Wait 90 seconds. Attempt to access via `create_sampling_client(checkpoint_path)` and via REST API `get_checkpoint_archive_url()`. Both should fail.

**Risk if false**: Trained model derivatives persist indefinitely, violating the cleanup guarantee.

### T2: Cost Metering Accuracy

**Assumption**: Our token-counting approach in `CostMeter` matches Tinker's actual billing to within 5%.

**Test**: Run a known workload (exact token count, exact steps). Compare `session.meter.total_cost_usd` with Tinker billing dashboard.

**Risk if false**: On-chain compute cost reported by TEE could undercharge (developer subsidizes) or overcharge (buyer overpays). Either erodes trust.

### T3: Concurrent Training Runs on Single Account

**Assumption**: Tinker allows multiple concurrent training runs from the same API key without throttling or interference.

**Test**: Create 3 training runs simultaneously. Verify all make progress. Check for rate limiting or queuing.

**Risk if false**: Concurrent deals would need to be serialized, increasing total evaluation time and locking buyer funds longer.

### T4: Output Bounding Sufficiency

**Assumption**: Score bands (5 levels) are coarse enough that the buyer cannot reverse-engineer the exact quality delta from the band + offer price.

**Test**: Information-theoretic analysis. Given score band and offer price, how many bits of information about the raw delta does the buyer gain? The NDAI paper (Section 5) shows budget caps preserve seller leverage, but our specific banding scheme needs validation against the paper's error tolerance thresholds.

**Risk if false**: Buyer gains too much information, reducing the seller's bargaining position below the no-TEE baseline.

### T5: Playwright Stability in Headless TEE

**Assumption**: Browser automation via Playwright over CDP works reliably in a headless neko Chrome instance inside a dstack CVM.

**Test**: Run signup + billing automation 10 times in the CVM environment. Measure success rate, failure modes.

**Risk if false**: Flaky browser automation could cause genesis failures or billing update failures. Need retry logic and screenshot-based debugging.

### T6: KMS Key Determinism

**Assumption**: `dstack_sdk.TappdClient.derive_key("tinker/api_key")` produces the same key across CVM restarts (same enclave, same compose hash).

**Test**: Derive a key, restart CVM, derive again. Keys should match.

**Risk if false**: API key sealed before a restart would be unrecoverable after restart, requiring re-genesis.

### T7: Tinker Account Persistence Without Human Interaction

**Assumption**: A Tinker account created via automated signup remains active indefinitely without periodic human interaction (no "verify you're human" challenges, no session expiry forcing re-auth).

**Test**: Create account, wait 7 days, attempt API call. Also test: does Tinker ever re-challenge with OTP during an active API session?

**Risk if false**: TEE would need periodic re-authentication. Email oracle must remain running for OTP handling. This is already accounted for in the architecture (oracle stays running) but needs empirical confirmation of challenge frequency.

### T8: Gas Costs for Full Lifecycle

**Assumption**: A full deal lifecycle (createDeal + fundDeal + submitResult + acceptDeal) costs less than 1M gas total on Base Sepolia/mainnet.

**Test**: Deploy to Base Sepolia, run full lifecycle, measure gas per transaction.

**Risk if false**: High gas costs could make small deals uneconomical. May need to batch operations or move to a cheaper L2.

### T9: NDAI Mechanism Robustness with Discrete Bands

**Assumption**: The NDAI paper's continuous-valued analysis (Section 5, agent error robustness) still holds when output is quantized to 5 discrete bands.

**Test**: Formal analysis or simulation. Given uniform distribution of artifact quality, do 5 bands preserve the paper's efficiency guarantees (buyer payoff > baseline) for error magnitudes up to E_b^max?

**Risk if false**: The mechanism might need finer bands (10-20 levels) or an alternative pricing function to maintain robustness.

### T10: Escrow Sizing

**Assumption**: Buyer can accurately estimate compute cost before funding, so budgetCap covers dealPayment + computeCost + fee with reasonable headroom.

**Test**: Run 20 evaluations with different dataset sizes. Measure variance in compute cost. Determine minimum safe headroom (e.g., 2x estimated cost).

**Risk if false**: Buyer underfunds escrow → evaluation succeeds but `acceptDeal` reverts because `dealPayment + computeCost + fee > budgetCap`. Need the `/estimate` endpoint (described in SPEC Section 5.4 but not yet implemented).

---

## 12. Appendix: NDAI Paper Key Concepts Mapping

| NDAI Paper Concept | Our Implementation |
|--------------------|--------------------|
| **Seller (S)** | Ethereum address that calls `createDeal()` and uploads artifact |
| **Buyer (B)** | Ethereum address that calls `fundDeal()`, `acceptDeal()`, or `rejectDeal()` |
| **Agent A_B (buyer's agent)** | Evaluator function (`stub_evaluate` or `sft_evaluate`) running inside TEE |
| **Agent A_S (seller's agent)** | Implicit — the seller sets reservePrice and uploads artifact. No autonomous agent yet. |
| **Secure function T** | The entire tinker-delegate CVM: control plane + isolated session + evaluator |
| **Disclosure omega_hat** | The artifact bytes uploaded to the TEE |
| **Security threshold Phi** | TEE security boundary. We use single-TEE (k=1). For omega > Phi, partial disclosure. |
| **Budget cap P_bar** | `budgetCap` in DiligenceRoom.sol (msg.value on fundDeal) |
| **Nash bargaining split theta** | `compute_offer()` in control_plane.py. Band multipliers (0.0-0.9) approximate theta. |
| **Agent error e_b** | Evaluator imprecision. Robust per Corollary 1: budget caps extend error tolerance. |
| **Output bounding** | `bound_output()` maps raw_delta to 5 ScoreBands. Not in paper — our extension. |
| **TTL / cleanup** | Dead man's switch. Not in paper — our operational requirement. |
| **Three-way settlement** | Seller + developer + buyer refund. Developer role not in paper — our business model. |

---

## 13. Appendix: Key File Paths

| File | Purpose |
|------|---------|
| `/Users/wikios/Projects/tinker-deligate/📄/ndai/paper.md` | NDAI paper (full text) |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/SPEC.md` | Full specification document |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/README.md` | Architecture overview + recon findings |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/tinker_delegate/signup.py` | Tinker account signup automation |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/tinker_delegate/billing.py` | Stripe billing automation |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/tinker_delegate/session.py` | IsolatedTinkerSession (SDK wrapper) |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/tinker_delegate/control_plane.py` | Deal lifecycle orchestration |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/tinker_delegate/evaluator.py` | Stub + SFT evaluator agents |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/tinker_delegate/api.py` | FastAPI server |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/tinker_delegate/crypto.py` | X25519 + AES-256-GCM encryption |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/tinker_delegate/card_channel.py` | Secure card delivery channel |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/contracts/src/DiligenceRoom.sol` | Escrow smart contract |
| `/Users/wikios/Projects/tinker-deligate/⚙️/tinker-delegate/contracts/test/DiligenceRoom.t.sol` | Contract test suite (22 tests) |
| `/Users/wikios/Projects/tinker-deligate/🔬/amiller/skill-verifier/` | Reference: inspection certificates + escrow agent |
| `/Users/wikios/Projects/tinker-deligate/🔬/amiller/dstack-openclaw/` | Reference: domain separation proxy |
| `/Users/wikios/Projects/tinker-deligate/🔬/amiller/dstack-tutorial/` | Reference: DevProof patterns (8 sections) |
| `/Users/wikios/Projects/tinker-deligate/🔬/amiller/github-zktls-1/` | Reference: attestation + escrow via ZK proofs |
