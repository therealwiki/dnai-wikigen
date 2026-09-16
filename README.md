# NDAI x Wikigen.me = DNAI

> A release-gated diligence room for private technical information — designed so disclosure can occur only inside an independently verified TEE, with economic controls from the [NDAI paper](https://arxiv.org/abs/2502.07924) exposed directly in the product.

Built for the [Shape Rotator Hackathon](https://www.encodeclub.com/programmes/shape-rotator-virtual-hackathon) (March 9–23, 2026) by Wiki Leks.

Current implementation status: see [STATUS.md](STATUS.md)
for what is built, partial, modeled, planned, deployed, blocked, and validated.

## Current release boundary

The repository has moved beyond the mockup: `web/` is a twelve-route SolidJS
product with a health-guide demo, Diligence Rooms, a sealed Bio/DNA Arena, a
release-gated human-review control plane, Data Vaults, a Compute control plane,
a release-gated delegated Tinker account console, safeguards, capabilities,
verification, and a release-gated multi-owner collaboration control plane. It
discovers EIP-6963 and compatible injected wallets (including MetaMask, Rabby,
and Coinbase Wallet) through EIP-1193; WalletConnect is available only when the
public connector ID is configured for that deployment. The health guide is an
explicitly modeled, reload-cleared surface and accepts no health data in this
release.

The Review API and browser UI are implemented in source: they enforce a strict
hash-only queue, release-bound reviewer-wallet challenges, private M-of-N
resolution, fail-closed denial, and a browser-rechecked Base Sepolia rollback
witness. The Collaboration API and UI likewise implement persistent schema-v2
rooms, wallet-owned invitations and membership, owner roles, exact-query
grants, bounded pagination, joint-consent snapshots, and explicit archive.
Both surfaces remain release-gated. Collaboration now has an explicit evidence
split: local HMAC current-state mode is tamper-evident but non-monotonic, while
live dstack mode refuses wallet authentication, reads, and mutations unless
the exact schema-v2 state matches its release/domain-bound Base Sepolia
`ExecutionPolicyAnchor` witness under the explicit single-RPC
reported-finalized model. That is not RPC quorum or a consensus proof. The
control-plane source exists, but this working tree has not activated a fresh
production Collaboration authority or current live witness. The separate
Collaboration execution service is also implemented and tested in source. Its
release-gated path is deterministic royalty prefunding after the complete fresh
owner-grant set; worker admission only after one RPC-reported finalized,
EIP-1898-pinned observation of that exact reservation and the exact Compute
job; bounded Compute execution; an on-demand exact settlement-decision anchor
plus purpose-separated main-runtime and independent-QVL authorizations; a
sponsor-wallet, zero-value `settleReserved` transaction; and finalized
reconciliation against the reservation's permanent settlement state. The
sponsor's wallet funds the exact native/ERC-20 reservation before provider
handoff; an allowance or aggregate contract balance is not execution
authority. Direct `distributeNative` / `distributeERC20` calls remain
compatibility paths, not the authoritative Collaboration path.

That sequence is source/test proof, not a deployment claim. Fresh owner and
reviewer key custody, notifications, operator activation, a new project-owned
Base Sepolia suite, the seven Phala CVMs and their QVL roots, and the matching
Cloudflare release remain open. A DTO, local signer, heartbeat, simulated
receipt, or RPC-reported finalized read is not Intel TDX evidence, independent
QVL evidence, RPC quorum, or a consensus proof.

The fresh release is still **source and local-verification work, not a live
Base Sepolia or Phala release**. No new project-owned contract suite or CVM set
has been deployed for this working tree. The intended release binds:

- seven contracts: `DiligenceRoom`, `TinkerAccountEncumbrance`,
  `RoyaltyDistributor`, `ChallengeRegistry`, `ComputeCreditVault`,
  `EmailOracleAuth`, and `ExecutionPolicyAnchor`;
- seven Phala CVMs: one private main runtime, five independently controlled QVL
  domains (Diligence, Arena, anchor writer, Compute workload, and Compute metering), and one
  independent deterministic Compute meter;
- signed challenge-v2 / verdict-v4 QVL admissions scoped to one release
  policy/profile, exact CVM identity, deployment intent, release authority,
  ceremony nonce, and measurement policy. Each signed DCAP challenge is
  single-use and valid for at most 120 seconds, and appraisal must complete
  strictly before it expires. The active v4 verdict/domain carries the
  separately reviewed exact 900-second activation-evidence lease; that lease
  may outlive the already consumed challenge and does not renew challenge
  freshness. Post-restart Compute recipient activation is schema v3 with an
  explicit recipient-evidence lease of at most 300 seconds, while its stable
  recipient-release commitment remains v2.
  The Diligence QVL root also serves the separate
  Email/KMS restart-evidence profile; that profile does not create a sixth QVL
  root or eighth CVM; and
- an exact `TinkerAccountEncumbrance` policy that is reviewed for two days,
  activated once, and permanently frozen before paid operations can run.

The source activation path treats Arena and Compute as one reviewed
post-measurement main-runtime profile: `arena-runtime,compute-execution`. A
same-process coordinator retains the non-serializable release authority from
seven-CVM evidence through signed Stage B, the encrypted environment patch,
restart, authenticated Phala observation, Arena worker-presence verification,
and fresh Compute recipient activation. The authenticated Arena heartbeat is
schema v2 presence evidence bound to the exact release; it is not an Intel TDX
attestation and every job still needs its independent quote/QVL gate. This
implemented choreography has not been executed as a fresh Phala deployment and
does not authorize live traffic by itself.

Funding has two deliberately separate meanings. `ComputeCreditVault` tracks
non-transferable **exact-asset claims** in the deposited ETH or release-pinned
ERC-20; it does not mint a token or apply an exchange rate. This exact-asset,
pay-as-you-go vault is the production funding lane for the first release:
each job reserves a wallet-authorized maximum, independent metering may debit
no more than that cap, and the remainder stays withdrawable. Closed-loop
**service credits** are off-chain, non-transferable, operator-granted test
units only. Card checkout and purchased service credits are outside v1; this
repository does not collect card details.

---

## What is this?

The **disclosure paradox**: a seller has a valuable idea / dataset / result / SOP, but the buyer needs to see it to value it. Once disclosed, the seller loses leverage. Result? Nobody shares anything.

**NDAI's proposed fix**: put the interaction inside a Trusted Execution
Environment. An AI agent inspects the artifact on the buyer's behalf inside a
hardware-isolated, attested boundary. The intended policy keeps the artifact
inside that boundary and permits only bounded output. This is not
“tamper-proof”: the claim still depends on the measured code, quote and
collateral verification, platform assumptions, and side-channel threat model.

**This repo** implements the source product and fail-closed release machinery
for an **Attested Diligence Room**. Its intended live flow is:

1. Seller uploads a private artifact (code audit, research memo, bug report, dataset, SOP) and sets a reserve price
2. Buyer funds escrow with a budget cap
3. A buyer-side evaluator agent inspects the artifact inside the TEE
4. The agent emits only constrained outputs (score bands, yes/no, offer within cap)
5. If accepted, payment completes and agreed output is revealed. If not, the artifact never leaves the boundary.

The paper's economic controls — **reserve price**, **budget cap**, **bounded disclosure** — are first-class product knobs, not hidden config.

---

## Repo Structure

```
dnai-wikigen/
├── getting-started.md      # Tactical hackathon brief — builders start here
├── quickstart.sh            # One-shot dependency bootstrap
├── example.env              # Environment template
├── .gitignore
├── web/                     # Twelve-route SolidJS product + release generator
├── deployments/             # Append-only Base Sepolia deployment ledger
├── docs/                    # Decisions, runtime specs, and operator contracts
├── scripts/                 # Activation, image, and release-core verification
├── ⚙️/                      # Executable services and contracts
│   ├── tinker-delegate/     # Main runtime, Arena/Compute/Deal workers, Foundry
│   ├── tee-email-oracle/    # Fixed OTP capability + sealed mailbox state
│   ├── attestation-qvl/     # Independent challenge-bound Intel DCAP verifier
│   └── compute-metering/    # Independent deterministic meter
│
├── 📄/                      # Research papers (PDF + markdown)
│   ├── ndai/                #   NDAI — the core paper (arXiv:2502.07924)
│   ├── dstack/              #   dstack — Zero Trust TEE framework (arXiv:2509.11555)
│   └── conseca/             #   ConSECA — contextual agent security (arXiv:2501.17070)
│
└── 🔬/                      # Reference repos (git submodules) — see 🔬/README.md
    ├── dstack/              #   Core TEE framework
    ├── dstack-examples/     #   Official deploy patterns
    ├── amiller/             #   Andrew Miller's lab (13 submodules incl. branch checkouts)
    ├── account-link/        #   Teleport + oauth3-skill
    └── jameslbarnes/        #   Hermes MCP server
```

---

## Quickstart

```bash
# Bootstrap all dependencies (git, docker, node, foundry, rust, phala cli, poppler)
chmod +x quickstart.sh && ./quickstart.sh

# Init submodules (if cloning fresh)
git submodule update --init --recursive
```

### Run the private-reward substrate (no deploy, no Tinker account needed)

Beyond the NDAI escrow flow, this repo is a **private verified-reward substrate**:
sealed data evaluates candidate code inside the boundary and emits only bounded
score bands, hashes, and attestations. These operator CLIs run fully locally and
are exercised by the test suite:

```bash
cd ⚙️/tinker-delegate

# Bounded private-reward demos (each emits a leakage-checked JSON packet):
uv run python -m tinker_delegate.main synthetic-private-reward-demo
uv run python -m tinker_delegate.main denoising-private-reward-demo
uv run python -m tinker_delegate.main bio-assay-qc-reward-demo
uv run python -m tinker_delegate.main dp-bounded-reward-demo   # differential-privacy budget

# Source an env's data through the sealed-envelope path, then run + verify it:
uv run python -m tinker_delegate.main denoising-sealed-dataset-demo --output /tmp/p.json
uv run python -m tinker_delegate.main verify-reward-run --packet /tmp/p.json   # -> "verified": true

# Explain any bounded decision reason code (policy reason, never private content):
uv run python -m tinker_delegate.main explain-decision packet_inconsistent

# Full test suite (Python + Foundry contracts):
uv sync --frozen --extra agent --group dev
uv run --frozen python -m pytest
(cd contracts && forge test)
```

Each local demo's output is bounded by construction (`raw_secret_egress: false`),
passes `verify-reward-run`, and carries a self-explaining decision
`explanation`. The optimizer method is swappable behind a fixed,
leakage-bounded reward interface. That is source-level output-policy evidence,
not proof that a deployed CVM contained real private data.

---

## The Product: Attested Diligence Room

### Demo Flow

```
Seller                          TEE Boundary                         Buyer
──────                          ────────────                         ─────
  │                                  │                                 │
  ├─ Create room ──────────────────► │                                 │
  ├─ Upload artifact ──────────────► │                                 │
  ├─ Set reserve price + expiry ───► │                                 │
  │                                  │ ◄── Fund escrow + budget cap ───┤
  │                                  │ ◄── Set query budget ───────────┤
  │                                  │                                 │
  │                                  │  ┌─────────────────────┐        │
  │                                  │  │ Evaluator agent     │        │
  │                                  │  │ inspects artifact   │        │
  │                                  │  │ emits constrained   │        │
  │                                  │  │ output only         │        │
  │                                  │  └─────────────────────┘        │
  │                                  │                                 │
  │                   Accept ◄───────┤────────► Accept                 │
  │                                  │                                 │
  ├─- Receive payment ◄──────────────┤────────► Receive output ────────┤
  │                                  │                                 │
  │     (or: access expires; service unlinks ciphertext per policy)     │
```

“Unlinks” describes the service-custody boundary: the ciphertext is no longer
retrievable through the service path after the declared terminal-retention
action. It is not a claim that underlying physical media was sanitized or
destroyed.

### Paper → Product Map

| Paper Concept | Product Primitive | Why It Matters |
|---|---|---|
| Disclosure paradox | Confidential diligence room | Seller reveals to the TEE, not to the buyer directly |
| Secure threshold (Φ) | Disclosure / query cap | Full vs partial disclosure is a product choice |
| Bargaining share / price | Offer engine + reserve | This is a market mechanism, not a private chatbot |
| Buyer error | Budget cap | Prevents runaway overpayment in bad model states |
| Seller protection | Acceptance threshold | Stops lowball acceptance from bad agent outputs |

### Killer Feature

An error slider that simulates buyer-agent error with and without a budget cap — makes Figure 1 from the paper tangible and shows judges why the controls matter.

---

## Tech Stack

| Layer | Choice | Why |
|---|---|---|
| **TEE** | [dstack](https://github.com/Dstack-TEE/dstack) on [Phala Cloud](https://docs.phala.com/dstack/overview) | Managed Intel TDX CVMs, attestation, KMS — no self-hosting |
| **Verification** | Release-pinned dstack evidence + five independent Intel DCAP QVL roots | Signed challenge-v2 / verdict-v4 admissions require DCAP appraisal to finish strictly inside a single-use ≤120-second challenge; the separately reviewed exact 900-second activation-evidence lease is not renewed challenge freshness, and browser/runtime gates keep producer evidence and modeled receipts distinct |
| **Contracts** | Seven-contract Base Sepolia suite via [Foundry](https://book.getfoundry.sh/) | Escrow, challenge registry, compute capacity, account encumbrance, oracle auth, royalties, and monotonic policy anchoring |
| **Model / compute** | Scoped Tinker delegate inside the main CVM | Credentials stay sealed and callers receive bounded capabilities; paid dispatch and Deal evaluation remain disabled until provider idempotency and end-to-end artifact confidentiality are proven |
| **Frontend** | SolidJS + Vite + viem | Wallet-native product console with fail-closed release bindings and a first-class verification surface |

---

## Research Papers

All stored in `📄/` with PDF originals and markdown conversions:

| Paper | What It Covers |
|---|---|
| [NDAI](📄/ndai/) | The core mechanism — disclosure paradox, TEE bargaining, agent error robustness |
| [dstack](📄/dstack/) | Zero Trust TEE framework — portable containers, decentralized code management, verifiable domains |
| [ConSECA](📄/conseca/) | Contextual agent security — LLM-drafted policies with deterministic enforcement (Google, HotOS '25) |

---

## Reference Repos

25 git submodules in `🔬/` covering the full dstack/TEE ecosystem. See [`🔬/README.md`](🔬/README.md) for the complete annotated directory with relevance ratings and a reading order.

**Critical** (read before coding):
- `🔬/amiller/skill-verifier` — inspection certificates + escrow agent (closest to what we're building)
- `🔬/amiller/devproof-apps-guide` — starter kits that pass Stage 1 audit
- `🔬/amiller/devproof-audits-guide` — what judges will implicitly check

**High priority** (read for architecture):
- `🔬/amiller/dstack-openclaw` — domain separation pattern for evaluator agents
- `🔬/amiller/github-zktls-1--groupauth` — multi-TEE trust federation
- `🔬/amiller/oauth3-openclaw--conseca-policy-engine` — intent-based policy engine

---

## Original 72-Hour Hackathon Plan

This table is retained as historical planning context. The current product has
moved beyond the mockup; use [STATUS.md](STATUS.md) for the evidence-backed
release boundary and [web/README.md](web/README.md) for the implemented routes,
wallet support, and deployment gate.

| Hours | Milestone |
|---|---|
| **0–6** | Decide artifact type, write deal states, choose evaluator output shape. Fork a dstack example, get local simulator running. |
| **6–24** | Room creation flow, private upload, stub evaluator in TEE, stubbed escrow state machine. |
| **24–48** | Deploy to Phala Cloud, wire real attestation/verification, Base Sepolia escrow contract. Add reserve threshold + budget cap to UI. |
| **48–72** | Polish demo. Add error slider visual. Only then consider stretch features (zkTLS, oauth3, RedPill). |

---

## Pitch

> "We turned the NDAI paper into a release-gated deal-room product for private technical information. It is designed to keep disclosure inside an independently verified TEE, while exposing reserve price, budget cap, and bounded disclosure directly in the product. The current public build is the modeled interface; fresh chain and CVM activation remain separate evidence."

**Talking points:**
- Once independently verified and admitted, the TEE becomes the enforcement boundary for a mechanism-design problem from the paper
- Reserve threshold and budget cap come directly from the paper's robustness analysis on agent error
- TEEs are the practical route the paper recommends; dstack/Phala gives judges a verification path they can actually inspect
- why not FHE/ZK? — because the goal is to ship the market mechanism now, and the paper explicitly positions TEEs as the practical implementation

---

## License

AGPLv3
