# NDAI x Wikigen.me = DNAI

> An attested diligence room for selling private technical information — where disclosure happens only inside a verifiable TEE and economic controls from the [NDAI paper](https://arxiv.org/abs/2502.07924) are exposed directly in the product.

Built for the [Shape Rotator Hackathon](https://www.encodeclub.com/programmes/shape-rotator-virtual-hackathon) (March 9–23, 2026) by Wiki Leks.

Current implementation status: see [STATUS.md](STATUS.md)
for what is built, partial, modeled, planned, deployed, blocked, and validated.

---

## What is this?

The **disclosure paradox**: a seller has a valuable idea / dataset / result / SOP, but the buyer needs to see it to value it. Once disclosed, the seller loses leverage. Result? Nobody shares anything.

**NDAI's fix**: put the interaction inside a Trusted Execution Environment. An AI agent inspects the artifact on the buyer's behalf, inside a tamper-proof boundary. The seller's information never leaves the TEE. If a deal is reached, payment flows; if not, the session is destroyed.

**This repo** is the implementation — an **Attested Diligence Room** where:

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
uv run python -m unittest discover -s tests        # ~1197 tests
(cd contracts && forge test)                       # 136 contract tests
```

Each demo's output is bounded by construction (`raw_secret_egress: false`), passes
`verify-reward-run`, and carries a self-explaining decision `explanation`. The
optimizer method is swappable behind a fixed, verifiable, leakage-bound reward
interface; sealed private data never leaves the boundary.

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
  │              (or: session expires, artifact destroyed)             │
```

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
| **Verification** | Phala attestation + compose-hash verification | Judges can inspect what's actually running |
| **Contracts** | Base Sepolia via [Foundry](https://book.getfoundry.sh/) | Minimal escrow state machine (Created → Evaluated → Accepted/Rejected/Expired) |
| **Model** | OpenAI / Anthropic called from inside TEE | Simplest trust model; RedPill TEE gateway as optional upgrade |
| **Frontend** | TBD | Verification page is part of the product, not back-office |

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

## 72-Hour Plan

| Hours | Milestone |
|---|---|
| **0–6** | Decide artifact type, write deal states, choose evaluator output shape. Fork a dstack example, get local simulator running. |
| **6–24** | Room creation flow, private upload, stub evaluator in TEE, stubbed escrow state machine. |
| **24–48** | Deploy to Phala Cloud, wire real attestation/verification, Base Sepolia escrow contract. Add reserve threshold + budget cap to UI. |
| **48–72** | Polish demo. Add error slider visual. Only then consider stretch features (zkTLS, oauth3, RedPill). |

---

## Pitch

> "We turned the NDAI paper into an attested deal room for private technical information, where disclosure happens only inside a verifiable TEE and economic controls from the paper — reserve price, budget cap, and bounded disclosure — are exposed directly in the product."

**Talking points:**
- The TEE is not for show — it's the enforcement boundary for a mechanism-design problem from the paper
- Reserve threshold and budget cap come directly from the paper's robustness analysis on agent error
- TEEs are the practical route the paper recommends; dstack/Phala gives judges a verification path they can actually inspect
- why not FHE/ZK? — because the goal is to ship the market mechanism now, and the paper explicitly positions TEEs as the practical implementation

---

## License

TBD
