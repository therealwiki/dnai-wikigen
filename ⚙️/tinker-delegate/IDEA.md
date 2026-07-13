# Tinker-Delegate: The Idea

> **Status**: Concept
> **Date**: 2026-03-08
> **Context**: NDAI / tinker-deligate hackathon — extending the Attested Diligence Room with Thinking Machines Tinker

---

## The Core Idea (As Stated)

Trap a Thinking Machines Tinker account inside a TEE. No human ever holds the credentials. The evaluator agent from the NDAI paper gets access to the Tinker account as a tool — it can start training runs on the data it's trying to evaluate, sample from the model it trained, and nothing else. When the NDAI deal flow resolves (accept, reject, or expire), the trained model is deleted. The agent can only access the weights it trained, not any others on the account.

A TEE email oracle (already designed — see `⚙️/tee-email-oracle/`) handles the email OTP required to sign up for Tinker, ensuring no human ever touches the account.

### In Plain Terms

1. A Tinker account is born inside a TEE — credentials sealed, no human recovery path
2. The NDAI evaluator agent uses that account to fine-tune a model on the seller's private artifact
3. It samples from the fine-tuned model to measure how good the artifact is
4. It emits a bounded score and offer price — never the raw model, never the raw data
5. When the deal ends, the model is destroyed — because the model IS the disclosure

---

## Why Training Is The Right Evaluation Primitive

The NDAI paper describes an evaluator agent (A_B) that inspects a seller's private artifact inside a TEE and produces a bounded output (quality score, offer price). The paper leaves open *how* the agent evaluates.

For the class of artifacts we care about — datasets, training recipes, reward functions, preference data, prompt templates — **the most honest evaluation is to train on the artifact and measure the result**. You can't know if a dataset is good by looking at it. You know by training on it and seeing what happens.

This means the trained model is a derivative of the seller's private data. If the model leaks, the seller loses the same leverage as if the data leaked directly. The trained model IS partial disclosure in the information-theoretic sense — it contains a compressed representation of the seller's artifact.

Therefore: the model must be treated with the same confidentiality as the artifact itself. It must never leave the TEE boundary. It must be destroyed when the deal resolves.

### Artifact Types That Map to Train-to-Evaluate

| Artifact the Seller Has | What the Agent Does with Tinker | What Leaves the TEE |
|---|---|---|
| Curated dataset | Fine-tune base model, benchmark vs baseline | Quality delta score band |
| Training recipe / methodology | Follow the recipe on a standard dataset | Recipe effectiveness score |
| RL reward function | Run RL training loop, measure policy improvement | Reward signal quality band |
| Preference data (chosen/rejected pairs) | DPO or RLHF training, measure alignment improvement | Alignment delta score |
| Prompt distillation template | Train model to internalize the prompt | Compression efficiency score |

All of these map directly to existing Tinker cookbook recipes (SL, RL, RLHF, DPO).

---

## Why the Email Oracle

Tinker requires an account on `tinker-console.thinkingmachines.ai`. Signing up requires an email address and verification via OTP. If a human holds the email credentials, they can intercept the OTP, recover the Tinker account, and extract the API key — breaking the TEE trust boundary.

The TEE email oracle (spec: `⚙️/tee-email-oracle/`, provider: cock.li) creates an email account inside the TEE with no human recovery path. During Tinker account genesis, the oracle receives the verification OTP and passes it to the signup automation within the same CVM. The Tinker API key is then sealed via dstack-KMS. No human ever sees the email password or the API key.

This is the "Setting Your Pet Rock Free" pattern (Nous Research / Flashbots) applied to a Tinker account.

---

## The Two Hard Constraints

### 1. Session Isolation

The evaluator agent can ONLY access the training run and checkpoints it created for the current NDAI deal. It cannot:

- List or access other training runs on the account (from previous deals)
- Sample from models it didn't train in this session
- Download weights (downloading trained weights IS disclosure)
- Publish checkpoints (would make the seller's data-derivative public)

This is enforced by a wrapper around the Tinker SDK that the agent receives instead of the raw client. The wrapper path-checks every operation.

### 2. Mandatory Cleanup

When the NDAI deal resolves — accept, reject, or expire — ALL checkpoints from the evaluation training run are deleted from Tinker. The trained model ceases to exist.

Backstops:
- Tinker's `ttl_seconds` parameter on checkpoint saves — auto-deletes even if cleanup code never runs
- Cleanup-on-boot — if the CVM restarts, it checks for orphaned training runs and deletes them
- No download path — even if checkpoints linger on Tinker's servers, the control plane never exposes the download URL

### What Is `ttl_seconds`?

Tinker's `save_weights_for_sampler()` and `save_state()` methods accept an optional `ttl_seconds` parameter. When set, the checkpoint is **automatically deleted by Tinker after that many seconds**, regardless of whether our code calls `delete_checkpoint()`. This is our dead man's switch: even if the CVM crashes, the network goes down, or the cleanup code has a bug, the checkpoints self-destruct on Tinker's side after the TTL expires.

The Tinker docs describe `ttl_seconds` as part of `SaveWeightsRequest` and list `expiration` as a field on `Checkpoint` metadata. We set TTL on every save, tied to the deal's on-chain expiry plus a grace period. The trained model cannot outlive the deal.

**Open question**: We need to empirically verify that Tinker actually purges expired checkpoints and that they become inaccessible after expiration — not just marked expired but still downloadable.

---

## How It Fits the NDAI Paper

From Section 4.1 of the paper:

> "A_S reveals ω to A_B; they negotiate; A_B offers payment P̂ < P̄ (accept) or exits; A_S accepts or rejects. On mutual acceptance, ω transfers to buyer and P to seller; on exit, TEE deletes session."

In our implementation:

| Paper Concept | Implementation |
|---|---|
| ω (the artifact) | Seller's dataset / recipe / reward function |
| A_B evaluates ω | Agent fine-tunes a model on ω via Tinker, benchmarks the result |
| Bounded output | Score band + offer price — never raw weights or samples |
| P̄ (budget cap) | Smart contract escrow amount — covers deal payment + Tinker compute cost |
| α₀ω̂ (reserve price) | Seller's minimum acceptable payment, set at deal creation |
| "TEE deletes session" | `delete_checkpoint()` on all trained models + TTL auto-expiry as backstop |
| Agent error robustness | Budget cap prevents overpayment even if evaluation model overestimates quality |

---

## Billing and Cost Model

The Tinker account is **pre-funded by the developers** (us). Credit card and billing details are updated via an encrypted channel to the TEE — the developers can push new payment information into the encumbered account without ever gaining access to the API key or credentials. The TEE receives the card details, automates the billing update via the Tinker console (browser automation or API), and the card details are never stored persistently — used once and discarded.

**The buyer pays for training compute.** When a buyer funds a deal, their escrow covers:
1. The potential payment to the seller (the deal price)
2. The Tinker compute cost for the evaluation training run

We track costs inside the TEE by monitoring tokens processed and training steps executed — Tinker's pricing is deterministic based on model size and step count, so costs are computable from our side. A **1% fee** is charged on top of the raw Tinker API costs. This fee goes to the developer account.

**Flow:**
- Buyer deposits to escrow (covers max deal price + estimated max compute cost + 1% fee)
- Agent trains → control plane meters tokens and steps → computes actual Tinker cost
- On deal resolution: seller gets deal payment (if accepted), developer account gets Tinker cost + 1% fee, remainder refunded to buyer

---

## Evaluation Protocol

**The evaluation protocol is up to the agent and its owner (the buyer).** The buyer configures or deploys their own evaluator agent, which decides autonomously:
- Which base model to fine-tune
- How many training steps to run
- What benchmark suite to use
- How to interpret results

The control plane enforces the hard constraints (session isolation, cleanup, output bounding) but does not dictate evaluation methodology. The buyer's agent is their representative inside the TEE — its competence is the buyer's problem, exactly as the NDAI paper describes (Section 5, agent error robustness).

This maps to the paper's framework: A_B is the buyer's agent, and its quality directly affects the buyer's outcomes. Budget caps and acceptance thresholds make the mechanism robust to agent error regardless of which protocol the agent uses.

---

## What Exists Already

| Component | Status | Location |
|---|---|---|
| TEE email oracle spec | Draft, captcha solver done | `⚙️/tee-email-oracle/` |
| cock.li captcha solver | Working, 100% accuracy | `⚙️/tee-email-oracle/captcha-solver/` |
| Tinker API docs (all 40 pages) | Scraped | `📄/thinking-machines/` |
| Tinker SDK + cookbook | Submodules | `🔬/thinking-machines/` |
| dstack deployment patterns | 25 reference repos | `🔬/` |
| Foundry contract skills | Ready | `.claude/skills/` |
| Phala Cloud deploy skills | Ready | `.claude/skills/` |

## What Needs Building

1. **Tinker console signup automation** — neko browser script for account creation + API key extraction
2. **IsolatedTinkerSession** — SDK wrapper enforcing session isolation + mandatory cleanup
3. **Evaluator agent** — the actual A_B that trains, benchmarks, and produces bounded outputs
4. **Control plane API** — TEE-hosted service that mediates between escrow contract and agent
5. **DiligenceRoom smart contract** — escrow state machine on Base Sepolia
6. **docker-compose.yaml** — email oracle + control plane + agent, dstack-compatible

## Decided Questions

| Question | Decision |
|---|---|
| Who pays Tinker compute? | Buyer pays. Deducted from their escrow. |
| Developer billing? | Account pre-funded by developers. Card updated via encrypted channel to TEE. |
| Fee structure? | 1% on top of Tinker API costs, goes to developer account. |
| Evaluation protocol? | Up to the agent and its owner (the buyer). Agent decides autonomously. |
| `ttl_seconds`? | Mandatory on every checkpoint save. Dead man's switch for cleanup. Needs empirical verification. |

## Open Questions

1. **Tinker console recon** — what does the signup flow actually look like? SPA? Captcha? Phone verification from datacenter IPs? Need to crawl the site and figure out whether to automate with raw API calls or Chrome CDP via neko.
2. **TTL reliability** — does Tinker actually purge expired checkpoints and make them inaccessible? Needs testing.
3. **Credit card update automation** — what does the Tinker billing settings page look like? Can card details be updated via API, or does it require browser automation?
4. **Cost metering precision** — Tinker's pricing model needs to be reverse-engineered or documented so we can accurately compute costs from tokens + steps.
5. **Same-CVM composition** — email oracle + control plane + evaluator agent all in one docker-compose.yaml = shared app_id, simpler key sharing, single attestation. This seems right for the hackathon.
