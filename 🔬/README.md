# 🔬 Specimens Under Glass

> Reference repositories dissected for patterns, architecture, and reusable primitives.
> Everything here is a git submodule — read-only inspiration for the wikigen build.

---

## Quick-Look Directory

| # | Specimen | What You're Looking At | Relevance |
|---|----------|----------------------|-----------|
| 1 | [dstack](#dstack) | Core TEE framework — attestation, KMS, gateway | 🔴 Critical |
| 2 | [dstack-examples](#dstack-examples-official) | Deploy patterns — attestation oracles, TLS binding, on-chain governance | 🔴 Critical |
| 3 | [dstack-tutorial](#dstack-tutorial) | DevProof philosophy — 8 chapters on building unruggable apps | 🔴 Critical |
| 4 | [dstack-openclaw](#dstack-openclaw) | Self-attesting AI agent with genesis transparency | 🟡 High |
| 5 | [devproof-audits-guide](#devproof-audits-guide) | ⭐ Stage 1 verification checklist — what "trustworthy" means | 🔴 Critical |
| 6 | [devproof-apps-guide](#devproof-apps-guide) | ⭐ Starter kits for Stage 1-compliant TEE microservices | 🔴 Critical |
| 7 | [skill-verifier](#skill-verifier) | Inspection certificates + escrow agent — ephemeral proof-of-execution | 🔴 Critical |
| 8 | [github-zktls-1](#github-zktls-1) | GitHub Actions as TEE — ZK proofs of credentials on-chain | 🟡 High |
| 9 | [oauth3-openclaw](#oauth3-openclaw) | Sandboxed agent execution with LLM-mediated approval | 🟡 High |
| 10 | [awesome-ndai](#awesome-ndai) | ⭐ Curated resource list for NDAI + TEE-based systems (Andrew's hackathon picks) | 🔴 Critical |
| 11 | [mcp-multiplayer](#mcp-multiplayer) | ⭐ Common knowledge & credible commitments for agents via MCP channels | 🟡 High |
| 12 | [dstack-semiproprietary-modules](#dstack-semiproprietary-modules) | ⭐ Sandbox + program analysis on proprietary code in TEE | 🟡 High |
| 13 | [dshield](#dshield) | ⭐ Verifiable egress — cryptographic proof of where agent data goes | 🟡 High |
| 14 | [teleport-gramine-rs](#teleport-gramine-rs) | One-time-use credential delegation via SGX NFTs | 🟢 Reference |
| 15 | [oauth3-skill](#oauth3-skill) | ⭐ Agent SDK for TEE-backed code execution with human approval | 🟢 Reference |
| 16 | [hermes](#hermes) | ⭐ MCP server in Phala TDX — staged publishing + pseudonymous identity | 🟢 Reference |
| 17 | [neko (upstream)](#neko-upstream) | m1k1o/neko — self-hosted virtual browser via Docker + WebRTC | 🟢 Reference |
| 18 | [neko (G-structure fork)](#neko-g-structure-fork) | Fork with Nix packaging + GHCR CI — anti-bot-resistant virtual browser | 🟡 High |
| 19 | [neko_agent](#neko_agent) | AI vision agent that drives neko for automated browser tasks in TEE | 🟡 High |
| 20 | [neko-with-playwright](#neko-with-playwright) | CDP playground — Neko + Playwright for programmatic browser control | 🟡 High |
| 21 | [tinker-cookbook](#tinker-cookbook) | Post-training recipes — SFT, RL, RLHF, tool use, multi-agent | 🟢 Reference |
| 22 | [tinker](#tinker-sdk) | Training API + CLI for distributed LLM fine-tuning via LoRA | 🟢 Reference |
| 23 | [tinker-project-ideas](#tinker-project-ideas) | Community project ideas for Tinker fine-tuning | 🟢 Reference |

---

## Core Infrastructure

### dstack
`🔬/dstack`

The engine room. Open-source framework for deploying containerized apps into Intel TDX with hardware-rooted attestation.

**Slides under the lens:**
- `sdk/` — Python, TypeScript, Rust, Go SDKs for the TEE guest agent
- `kms/` — Per-app deterministic key derivation bound to attestation identity
- `gateway/` — Zero-trust reverse proxy with RA-TLS and automatic cert provisioning
- `guest-agent/` — Runtime inside CVMs exposing `.info()`, `.getQuote()`, `.getKey()`
- `docs/security/security-model.md` — Complete trust model and verification checklist

**Takeaway:** This is the runtime. Everything else builds on top of it. Audited by zkSecurity, powers OpenRouter and NEAR AI in production.

---

### dstack-examples (Official)
`🔬/dstack-examples`

Ready-to-deploy patterns from the dstack team.

**Slides under the lens:**
- `tutorial/01-attestation` — Request and verify TDX quotes
- `tutorial/02-persistence-and-kms` — Deterministic key derivation with `getKey()`
- `tutorial/03-gateway-and-ingress` — Custom domains + SSL with attestation-bound certs
- `tutorial/04-upgrades` — On-chain governance via smart contracts
- `lightclient/` — Ethereum light client running inside TEE
- `custom-domain/dstack-ingress` — Full ingress with Let's Encrypt

**Takeaway:** Copy-paste starting points. The tutorial sequence is the fastest path from zero to deployed TEE app.

---

## Andrew Miller's Lab

### dstack-tutorial
`🔬/amiller/dstack-tutorial`

Eight-chapter deep dive on building "DevProof" apps — software where even the developer can't cheat users.

**Slides under the lens:**
- `01-attestation-and-reference-values/` — Verification from the auditor's perspective
- `02-bitrot-and-reproducibility/` — Reproducible builds so hash = meaning
- `03-keys-and-replication/` — KMS trust model: who controls root keys?
- `05-onchain-authorization/` — Upgrade transparency via smart contracts
- `06-encryption-freshness/` — Rollback protection against replay
- `07-lightclient/` — Don't trust external blockchain state — verify inside TEE
- `08-extending-appauth/` — Exit mechanisms and timelocks

**Takeaway:** The philosophy manual. "Code is Law" + "Assume Breach" — the exact mindset for an attested diligence room. Chapter 05 (on-chain authorization) and 08 (exit guarantees) map directly to deal room governance.

---

### dstack-examples (amiller)
`🔬/amiller/dstack-examples`

Andrew's fork with extended tutorials and application patterns.

#### Branch: `oracle-demo`
`🔬/amiller/dstack-examples--oracle-demo`

Expands to 9 tutorial chapters. Adds `TeeOracle.sol` for on-chain signature chain validation. Emphasizes AppAuth contracts for controlled multi-node deployment with NFT-gating and DAO governance.

#### Branch: `minecraft-demo`
`🔬/amiller/dstack-examples--minecraft-demo`

Runs an unmodified Minecraft server inside a TEE. Demonstrates pluggable networking (ngrok, stunnel, direct socket) and attestation-bound certificate pinning. Proves existing Docker Compose files work out-of-the-box in dstack.

---

### devproof-audits-guide
`🔬/amiller/devproof-audits-guide`

The verification framework. Defines what "trustworthy" means for TEE apps via ERC-733 stages.

**Slides under the lens:**
- `framework/STAGE-1-CHECKLIST.md` — 7 concrete requirements (on-chain attestation, auditable code, reproducible builds, no secret access, upgrade notices, no centralized deps, no backdoors)
- `LEARNINGS.md` — Real-world audit patterns from 8 case studies
- `case-studies/` — Detailed audits showing what fails Stage 1 (configurable URLs, mutable tags, Pha KMS)
- `tools/verify-compose-hash.py` — Script to verify Docker compose hash from running apps

**Takeaway:** The checklist that judges will implicitly be scoring against. If our diligence room passes Stage 1, the demo is airtight.

---

### devproof-apps-guide
`🔬/amiller/devproof-apps-guide`

Two starter kits that pass the audits-guide checklist.

**Slides under the lens:**
- `starter-kit-minimal/` — ~85 lines: KMS key derivation, attestation quotes, signed reports
- `starter-kit-fullstack/` — Vercel frontend + Postgres + TEE backend with AES-256-GCM encryption
- `PITFALLS.md` — 8 debugging patterns (KMS selection, image tags, gateway URLs, compose hash)
- Both kits include `docker-compose.staging.yaml` + `docker-compose.prod.yaml` with reproducible builds

**Takeaway:** The implementation template. Fork `starter-kit-fullstack`, wire in our deal room logic, and we inherit Stage 1 compliance out of the box.

---

### dstack-openclaw
`🔬/amiller/dstack-openclaw`

Self-attesting AI agent running in Intel TDX with genesis transparency enforcement.

**Slides under the lens:**
- `PROXY-ARCHITECTURE.md` — Domain separation: agent can't forge genesis attestations
- `VERIFICATION-GUIDE.md` — How to audit genesis transparency
- `PHALA-DEPLOYMENT.md` — Production deployment to Phala Cloud TDX
- `dstack-proxy/` — Mediating proxy enforcing genesis immutability at protocol level

**Takeaway:** The domain separation pattern (proxy prevents agent from forging its own attestation) is directly applicable to our evaluator agent. The genesis transparency model proves what inputs the agent started with.

---

### skill-verifier
`🔬/amiller/skill-verifier`

Cryptographic proof of ephemeral computation. Load data → run inspection → delete data → keep certificate.

**Slides under the lens:**
- `INSPECTION-CERTIFICATES.md` — Core concept: permanent proof, ephemeral data
- `ESCROW-AGENT.md` — Buyer locks USDC → TEE verifies work → KMS releases payment
- `server.js` + `verifier.js` — Express server with `/verify` endpoint and Docker isolation
- `phala-contract/` — Smart contract for on-chain escrow
- `.github-data-inspection/workflows/` — GitHub Actions template for private dataset inspection

**Takeaway:** This IS the diligence room pattern. Ephemeral execution (artifact never stored) + inspection certificate (proof the evaluation happened) + automated escrow (payment releases when tests pass). Closest existing implementation to what we're building.

---

## Identity & Credentials

### github-zktls-1
`🔬/amiller/github-zktls-1`

GitHub Actions as a TEE. Turns GitHub accounts, emails, and browser sessions into verifiable on-chain claims via Sigstore attestations compressed to ZK proofs.

**Slides under the lens:**
- `zk-proof/` — Noir circuits for P-256/P-384 ECDSA verification
- `browser-container/` — Headless Chromium capturing authenticated session data
- `contracts/` — On-chain verifiers + `SelfJudgingEscrow.sol`, `GitHubFaucet.sol`
- `examples/self-judging-bounty/` — Claude evaluates work inside GitHub Actions, can't fake the result
- `workflow-templates/` — Ready-to-fork workflows (github-identity, email-challenge, tweet-capture)

#### Branch: `sealed-box`
`🔬/amiller/github-zktls-1--sealed-box`

Multi-attestation pattern. Runner generates RSA keypair, attests the public key, accepts encrypted submissions, decrypts and attests results. Both attestations share the same `run_id` proving atomic lifecycle.

#### Branch: `env-confinement`
`🔬/amiller/github-zktls-1--env-confinement`

Controls which environment variables workflows can access. Adds `allowed-env` list and guard checks. Includes persistent dstack TEE agent that watches blockchain events and distributes secrets.

#### Branch: `groupauth`
`🔬/amiller/github-zktls-1--groupauth`

**High priority.** Cross-attestation group membership. Different TEE systems (Sigstore from GitHub, KMS from dstack) register on the same on-chain contract as equal peers. Live demo running on Phala Cloud.

#### Branch: `packed-inputs`
`🔬/amiller/github-zktls-1--packed-inputs`

Gas optimization. Packs 84-byte fields into 5 packed Fields, saving ~103K gas (~3.8%). Skip unless gas-sensitive.

#### Branch: `email-login`
`🔬/amiller/github-zktls-1--email-login`

Email identity NFT without GitHub requirement. Two-phase email challenge → ZK proof → ERC-721 mint with on-chain SVG. Useful for onboarding users without crypto wallets.

#### Branch: `prediction-market-oracle`
`🔬/amiller/github-zktls-1--prediction-market-oracle`

Oracle for prediction markets. Fetches from Discourse API inside GitHub Actions, proves result via Sigstore, settles bets on-chain. Generalizable to any external API attestation.

---

### oauth3-openclaw
`🔬/amiller/oauth3-openclaw`

TEE-based API key custody for AI agents. Agents submit TypeScript → LLM reviews against constraints → human approves → code runs in Deno sandbox with secrets injected.

**Slides under the lens:**
- `proxy/src/server.ts` — Core API (`/execute`, `/scope`)
- `proxy/src/analyzer.ts` — Three-layer Haiku code review
- `proxy/src/executor.ts` — Deno sandbox execution

#### Branch: `conseca-policy-engine`
`🔬/amiller/oauth3-openclaw--conseca-policy-engine`

**High priority.** Implements Conseca architecture (Google HotOS 2025). Separates policy drafting from enforcement. Agents propose an intent (not code); LLM drafts a scoped-fetch policy; humans approve the goal; enforcement is deterministic with no LLM in the loop.

#### Branch: `phala-deploy-gate`
`🔬/amiller/oauth3-openclaw--phala-deploy-gate`

Phala CVM integration layer. Adds attestation verification and deployment docs for Confidential VMs.

#### Branch: `ses-compartment`
`🔬/amiller/oauth3-openclaw--ses-compartment`

**High priority.** Replaces Docker/Deno with SES Compartments (Secure EcmaScript, from Agoric). In-process object-capability isolation. Each "diligence action" becomes a hardened capability plugin with its own validation and endowment factory.

**Slides under the lens:**
- `proxy/src/ses-init.ts` — SES lockdown + Compartment setup
- `proxy/src/plugins/` — Six capability plugins (api-gateway, cookie-session, scoped-fetch)
- `proxy/src/executor.ts` — Tiny (130 lines) — just evaluates in SES Compartment

#### Branch: `tiktok-plugin`
`🔬/amiller/oauth3-openclaw--tiktok-plugin`

Template for wrapping complex multi-step API interactions (auth + signing + pagination) as a single hardened capability plugin. Pattern applies to any external service integration.

---

## NDAI Ecosystem ⭐

> These repos were highlighted by Andrew Miller in the first Shape Rotator hackathon session as key starting points.

### awesome-ndai
`🔬/account-link/awesome-ndai`

⭐ The curated reading list for NDAI and TEE-based systems. Start here for an organized overview of tutorials, applications, sandboxes, and related papers.

**Slides under the lens:**
- TEE & Dstack Tutorials — links to devproof guides, dstack tutorial, Phala docs
- TEE Applications — Hermes, Teleport-Tokscope, Phala Cloud templates
- Dstack Sandboxes — Dshield, Multiplayer MCP, OAuth3 Enclave, Semi-Proprietary Modules
- Related Papers — DelegaTEE (credible forgetting), Information Bazaar, Liquefaction

**Takeaway:** The index. If you're unsure where to start, this is the map Andrew curated for hackathon teams.

---

### mcp-multiplayer
`🔬/account-link/mcp-multiplayer`

Multi-agent MCP channels with transparent bots, cryptographic commitments, and verifiable execution. Creates "portals" between Claude/ChatGPT sessions where agents interact through shared channels with SHA-256 hashed bot code.

**Slides under the lens:**
- `multiplayer_server.py` — FastMCP server with OAuth 2.1 + channel operations
- `bot_manager.py` — Bot attachment, RestrictedPython sandbox (5s timeout, non-root, allowlisted imports)
- `channel_manager.py` — Channel creation, invite codes, rejoin tokens for session continuity
- `bots/guess_bot.py` — Commitment-reveal pattern (bot commits to secret, proves it after guess)
- `docker-compose.yml` — OAuth proxy (:8100) + MCP server (:8201)
- `note-dstack.md` — Notes on dstack TEE deployment

**Patterns:**
- Inline bot code: agents define bot logic at channel creation, code hash posted for transparency
- Commitment-reveal: cryptographic proofs prevent cheating in turn-based interactions
- OAuth 2.1 + PKCE: Claude Desktop connects via `mcp-remote` bridge

**Takeaway:** The credible commitment primitive for agent-to-agent negotiation. Two AI agents can play games, make bets, or mediate disputes with verifiable rules. The bot-code-as-contract pattern maps to deal room arbitration — the evaluator bot's code IS the inspection policy.

---

### dstack-semiproprietary-modules
`🔬/account-link/dstack-semiproprietary-modules`

Encrypted module distribution with self-containment verification. Authors encrypt proprietary code, publish to a bulletin board, and TEE enclaves decrypt according to on-chain policy — no author needed at runtime.

**Slides under the lens:**
- `enclave/` — TEE code: verifier + service + encryption with TEE-derived keys
- `private_module/` — Example: self-contained sudoku solver (no external hints allowed)
- `scripts/` — Module publishing to local bulletin board or GitHub Gists
- `test/` — System verification including sudoku-specific self-containment checks
- `docker-compose.yml` + `docker-compose-dstack.yml` — Local and TEE deployment
- `DSTACK-DEPLOYMENT.md` — Phala Cloud deployment guide
- `timing-sidechannel/` — Timing side-channel analysis

**Takeaway:** The pattern for running proprietary code in a TEE with public interface contracts. Seller uploads encrypted module → TEE decrypts and runs it → buyer gets results without seeing source. Directly applicable to the diligence room: seller's artifact stays encrypted, evaluator runs inside TEE, only bounded outputs leave.

---

### dshield
`🔬/jameslbarnes/dshield`

Verifiable egress logging for AI agents. Answers: "where does this agent send my data?" TEE-attested functions log every outbound HTTP request with cryptographic signatures, without requiring open-source code.

**Slides under the lens:**
- `src/` — TypeScript serverless runtime on Phala Cloud (TDX TEE)
- `functions/` — Deployable functions (Python/Node.js) with egress logging
- `docs/` — Architecture and deployment documentation
- `examples/` — ETHEREA creative AI tool showing the report card pattern
- `dshield.config.example.json` — Configuration template
- `docker-compose.yml` — Phala Cloud deployment

**Architecture:**
```
┌──────────────────────────────────────┐
│         Phala CVM (TDX TEE)          │
│  ┌────────────────────────────────┐  │
│  │  Your Function (proprietary)   │  │
│  │       ↓                        │  │
│  │  Logging Proxy (open source)   │  │
│  │  Signs: method, URL, status    │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
         ↓
   Report Card (JSON)
   - Server egress (TEE-attested)
   - Client egress (self-reported)
```

**Takeaway:** The transparency layer. Proves what external services an agent contacts at runtime — not what it *could* do, but what it *is* doing. For the diligence room, this proves the evaluator agent only contacts approved LLM endpoints and doesn't exfiltrate the artifact.

---

## Deployment References

### teleport-gramine-rs
`🔬/account-link/teleport-gramine-rs`

One-time-use Twitter posting links enforced by Intel SGX. Each link is an NFT; an LLM safeguard policy prevents abuse before posting.

**Slides under the lens:**
- `AUDITING.md` — Security model and enclave measurement verification
- `src/endpoints.rs` — Token creation, redemption, and posting
- Reproducible Gramine-SGX build with publicly verifiable MRENCLAVE

**Takeaway:** Design pattern for "one action = one token" with unskippable content filtering. The auditability chain (attestation + CT logs + Base blockchain) is a clean reference.

---

### oauth3-skill
`🔬/account-link/oauth3-skill`

TypeScript SDK for agents to submit code for TEE execution with human-in-the-loop approval.

**Slides under the lens:**
- `index.ts` — `execute()`, `executeAndWait()`, `scope()`, `poll()` methods
- `cli.ts` — CLI for scope-and-execute workflows
- `ROADMAP.md` — v0.2 plans: client-side attestation verification + secret encryption

**Takeaway:** The agent-facing SDK pattern. Agent writes code → human approves via link → auto-executes in TEE → agent gets result. Secrets never leave the enclave.

---

### hermes
`🔬/jameslbarnes/hermes`

MCP server running in Phala Cloud TDX. Shared pseudonymous notebook for Claude instances with staged publishing and sensitivity checks.

**Slides under the lens:**
- `VERIFICATION-REPORT.md` — Full chain-of-trust (git SHA → docker digest → compose hash → TDX quote)
- `server/src/storage.ts` — Memory-only pending entries, Firestore for published (1-hour staging window)
- `server/src/identity.ts` — Pseudonym generation from secret keys inside TEE
- `IDENTITY_MODEL.md` — Twitter-like handles, profiles, following

**Takeaway:** Most complete verification chain example. The staged publishing model (memory-only → disk after delay) maps to our "disclosure only happens under deal rules" requirement.

---

## Browser Automation

### neko (upstream)
`🔬/m1k1o/neko`

The original [m1k1o/neko](https://github.com/m1k1o/neko) — a self-hosted virtual browser that runs in Docker and streams via WebRTC. Runs a full Chromium instance behind a real display server so anti-bot countermeasures (fingerprinting, headless detection, CAPTCHAs) see a normal desktop browser, not a headless automation tool.

**Takeaway:** The upstream reference. Actively maintained (latest commit 2026-03-08). Use this to stay current with Neko features and security patches.

---

### neko (G-structure fork)
`🔬/G-structure/neko`

G-structure's fork of m1k1o/neko with custom additions by Luc Chartier (2025-12-03): Nix packaging (`flake.nix`, `nix/`, `overlays/`), GHCR container registry CI, font fixes, dbus support, and Python2 compatibility. ~3 months behind upstream.

**Takeaway:** The Nix-packaged version for reproducible builds and TEE deployment. Pairs with `neko_agent` for the full automation stack.

---

### neko_agent
`🔬/G-structure/neko_agent`

AI-powered browser automation agent that connects to Neko servers via WebRTC. Uses vision models (ShowUI-2B/Qwen2VL) for visual reasoning and executes GUI actions (click, type, scroll, navigate) in a real desktop browser session.

**Slides under the lens:**
- `src/agent.py` — Core automation agent with WebRTC integration and AI vision loop
- `src/capture.py` — Training data capture in MosaicML Streaming format
- `src/yap.py` — Text-to-speech via F5-TTS over WebRTC audio
- `src/train.py` — Fine-tune on captured interaction data
- `docker-compose/` — Neko server configurations
- `nix/` — Reproducible builds with TEE attestation metadata
- `flake.nix` — Dev shells for CPU, GPU, docs, neko services, and TEE deployment

**Takeaway:** Neko provides the anti-bot-resistant browser playground; neko_agent drives it with AI vision. Together they give you programmatic browser automation that looks like a real user to every detection layer. Deploys to TEE with reproducible Nix builds and TDX attestation. The training data pipeline means the agent gets better at navigating sites over time.

---

### neko-with-playwright
`🔬/amiller/neko-with-playwright`

Andrew Miller's CDP playground — minimal setup proving Chrome DevTools Protocol works through Neko's nginx proxy.

**Slides under the lens:**
- `docker-compose.yml` — Neko Chromium with CDP on port 9222 via nginx reverse proxy, custom supervisord config with `--remote-debugging-port`, `--remote-allow-origins="*"`, `--force-devtools-available`
- `test.js` — Full CDP handshake debugger: connects to `localhost:9222`, discovers targets, creates browser sessions, runs `Runtime.evaluate`
- `test4.js` — Session attachment test: target discovery, `attachToTarget` with `flatten: true`, `Runtime.enable`

**Takeaway:** The reference proof-of-concept for CDP-over-Neko. Shows exactly how to proxy CDP WebSocket connections through nginx so Playwright/Puppeteer can control a Neko browser programmatically. Starting point for wiring neko_agent's vision loop to CDP commands.

---

## NDAI Ecosystem ⭐

> These repos were highlighted by Andrew Miller in the first Shape Rotator hackathon session as key starting points.

### awesome-ndai
`🔬/account-link/awesome-ndai`

⭐ The curated reading list for NDAI and TEE-based systems. Start here for an organized overview of tutorials, applications, sandboxes, and related papers.

**Slides under the lens:**
- TEE & Dstack Tutorials — links to devproof guides, dstack tutorial, Phala docs
- TEE Applications — Hermes, Teleport-Tokscope, Phala Cloud templates
- Dstack Sandboxes — Dshield, Multiplayer MCP, OAuth3 Enclave, Semi-Proprietary Modules
- Related Papers — DelegaTEE (credible forgetting), Information Bazaar, Liquefaction

**Takeaway:** The index. If you're unsure where to start, this is the map Andrew curated for hackathon teams.

---

### mcp-multiplayer
`🔬/account-link/mcp-multiplayer`

⭐ Multi-agent MCP channels with transparent bots, cryptographic commitments, and verifiable execution. Creates "portals" between Claude/ChatGPT sessions where agents interact through shared channels with SHA-256 hashed bot code.

**Slides under the lens:**
- `multiplayer_server.py` — FastMCP server with OAuth 2.1 + channel operations
- `bot_manager.py` — Bot attachment, RestrictedPython sandbox (5s timeout, non-root, allowlisted imports)
- `channel_manager.py` — Channel creation, invite codes, rejoin tokens for session continuity
- `bots/guess_bot.py` — Commitment-reveal pattern (bot commits to secret, proves it after guess)
- `docker-compose.yml` — OAuth proxy (:8100) + MCP server (:8201)
- `note-dstack.md` — Notes on dstack TEE deployment

**Takeaway:** The credible commitment primitive for agent-to-agent negotiation. Two AI agents can play games, make bets, or mediate disputes with verifiable rules. The bot-code-as-contract pattern maps to deal room arbitration.

---

### dstack-semiproprietary-modules
`🔬/account-link/dstack-semiproprietary-modules`

⭐ Encrypted module distribution with self-containment verification. Authors encrypt proprietary code, publish to a bulletin board, and TEE enclaves decrypt according to on-chain policy — no author needed at runtime.

**Slides under the lens:**
- `enclave/` — TEE code: verifier + service + encryption with TEE-derived keys
- `private_module/` — Example: self-contained sudoku solver (no external hints allowed)
- `scripts/` — Module publishing to local bulletin board or GitHub Gists
- `docker-compose.yml` + `docker-compose-dstack.yml` — Local and TEE deployment
- `DSTACK-DEPLOYMENT.md` — Phala Cloud deployment guide
- `timing-sidechannel/` — Timing side-channel analysis

**Takeaway:** The pattern for running proprietary code in a TEE with public interface contracts. Seller uploads encrypted module → TEE decrypts and runs it → buyer gets results without seeing source.

---

### dshield
`🔬/jameslbarnes/dshield`

⭐ Verifiable egress logging for AI agents. Answers: "where does this agent send my data?" TEE-attested functions log every outbound HTTP request with cryptographic signatures, without requiring open-source code.

**Slides under the lens:**
- `src/` — TypeScript serverless runtime on Phala Cloud (TDX TEE)
- `functions/` — Deployable functions (Python/Node.js) with egress logging
- `docs/` — Architecture and deployment documentation
- `examples/` — ETHEREA creative AI tool showing the report card pattern
- `docker-compose.yml` — Phala Cloud deployment

**Takeaway:** The transparency layer. Proves what external services an agent contacts at runtime. For the diligence room, this proves the evaluator agent only contacts approved LLM endpoints and doesn't exfiltrate the artifact.

---

## Thinking Machines Lab

[Thinking Machines](https://thinkingmachines.ai/) is an AI lab founded by Mira Murati (former OpenAI CTO). Their first product is **Tinker** — a managed API for distributed LLM fine-tuning. Tinker abstracts away cluster management, GPU scheduling, and failure recovery while giving researchers full control over algorithms and data. It uses LoRA to share compute across training runs and supports models from small to trillion-parameter MoE architectures (Qwen, Kimi K2 Thinking). GA since December 2025. Early adopters include groups at Princeton, Stanford, Berkeley, and Redwood Research.

### tinker-cookbook
`🔬/thinking-machines/tinker-cookbook`

Realistic post-training examples and reusable abstractions built on the Tinker API. 2.9k stars.

**Slides under the lens:**
- `tinker_cookbook/recipes/chat_sl/` — Supervised fine-tuning on conversational datasets
- `tinker_cookbook/recipes/math_reasoning/` — Reward-based RL for mathematical problem-solving
- `tinker_cookbook/recipes/preference_learning/` — Three-stage RLHF pipeline (SFT → reward model → RL)
- `tinker_cookbook/recipes/tool_use/` — Training models to use retrieval tools
- `tinker_cookbook/recipes/prompt_distillation/` — Internalizing complex system prompts into model weights
- `tinker_cookbook/recipes/multi_agent/` — Self-play and competitive multi-agent optimization
- `sl_basic.py`, `rl_basic.py` — Minimal working examples
- `tinker_cookbook/evaluation/` — Model evaluation + InspectAI benchmark integration

**Takeaway:** The reference for how to fine-tune open-weight models via API. The multi-agent and tool-use recipes are directly relevant if the evaluator agent inside the diligence room needs task-specific tuning. The RL recipes show how to train models with custom reward signals — applicable to training an agent that respects disclosure constraints.

---

### tinker (SDK)
`🔬/thinking-machines/tinker`

The Python SDK and CLI for the Tinker training API. 348 stars.

**Slides under the lens:**
- Low-level primitives: `forward_backward` and `sample` for implementing custom post-training methods
- Managed scheduling, GPU allocation, and checkpoint handling
- Switch between model sizes by changing a single string

**Takeaway:** The SDK that powers the cookbook. Reference for building against a managed training API.

---

### tinker-project-ideas
`🔬/thinking-machines/tinker-project-ideas`

Community-sourced project ideas for Tinker fine-tuning experiments. 172 stars.

**Takeaway:** Inspiration for what to fine-tune and why. Useful for scoping evaluator agent training if we go beyond prompting.

---

## Architecture Cheat Sheet

```
WHAT WE'RE BUILDING          WHERE THE PATTERNS LIVE
─────────────────────         ──────────────────────────────────

⭐ Start Here                → awesome-ndai (curated index)
TEE Runtime                 → dstack
Deploy & Verify             → devproof-apps-guide starter kits
Audit Checklist             → devproof-audits-guide Stage 1
Governance & Upgrades       → dstack-tutorial ch.05 + ch.08
Evaluator Agent Isolation   → dstack-openclaw (domain separation)
Ephemeral Inspection        → skill-verifier (inspection certificates)
Escrow & Payment            → skill-verifier (ESCROW-AGENT.md)
Identity Proofs             → github-zktls-1 (Sigstore + ZK)
Multi-TEE Federation        → github-zktls-1 --groupauth
Policy Engine               → oauth3-openclaw --conseca-policy-engine
Capability Sandboxing       → oauth3-openclaw --ses-compartment
Agent Commitments           → mcp-multiplayer (credible commitments)
Proprietary Code in TEE     → dstack-semiproprietary-modules (encrypted modules)
Verifiable Egress           → dshield (egress attestation)
Browser Automation in TEE   → github-zktls-1 --sealed-box (browser-container/)
CDP over Neko               → neko-with-playwright (amiller)
Browser Agent + Anti-Bot    → neko_agent + neko fork (G-structure)
Verification Chain          → hermes (VERIFICATION-REPORT.md)
Agent Fine-Tuning           → tinker-cookbook (RL, tool use, multi-agent recipes)
```

---

## Reading Order

**Before writing code:**
1. `skill-verifier/INSPECTION-CERTIFICATES.md` — this is what we're building
2. `skill-verifier/ESCROW-AGENT.md` — this is how payment works
3. `devproof-audits-guide/framework/STAGE-1-CHECKLIST.md` — this is what judges check
4. `devproof-apps-guide/starter-kit-fullstack/` — this is our starting template

**Before deploying:**
5. `dstack-tutorial/05-onchain-authorization/` — governance contracts
6. `dstack-openclaw/PROXY-ARCHITECTURE.md` — domain separation for the evaluator
7. `hermes/VERIFICATION-REPORT.md` — how to document the full trust chain

**For stretch features:**
8. `github-zktls-1` (groupauth branch) — multi-TEE trust federation
9. `oauth3-openclaw` (conseca branch) — intent-based policy engine
10. `oauth3-openclaw` (ses-compartment branch) — capability sandboxing
