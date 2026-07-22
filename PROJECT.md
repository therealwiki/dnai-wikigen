# PROJECT: dnai-wikigen

Last updated: 2026-07-21
Branch context: active working tree; no production release SHA has been cut

## Status (2026-07-21): complete source product; fresh release ceremony pending

The current repository contains the full SolidJS product, a fresh seven-contract
Base Sepolia suite, hardened delegate and Arena runtimes, an execution-policy
anchor, reproducible release tooling, and fail-closed browser verification. The
implemented product surfaces cover diligence rooms, sealed Bio/DNA challenges,
a source-modeled human release desk, wallet-owned compute capacity, scoped proxy
credentials, a release-gated delegated Tinker account lifecycle, service-credit
previews, safeguards, collaboration with a runtime-pinned royalty pull-payment
panel, capabilities, and layered verification.

That is a source-and-local-verification statement, not a production deployment
claim. This working tree has not yet produced a clean release SHA, no fresh
project-owned contract suite has been broadcast for this release, and no
replacement Phala CVM has been independently quote-verified and admitted by the
new contracts. Live browser mutation remains locked until one exact release
descriptor binds the clean source SHA, runtime bytecode, role owners, image
digests, compose identity, CVM evidence, approval domain, signer root, and frozen
execution-policy writer.

The deployment addresses, CVM identifiers, account balances, and live proofs in
the historical section below belong to a prior operator/release. They are useful
engineering evidence but are not inherited as authorization, custody, or
production state for the new release.

### Canonical product and release shape

The public client is one SolidJS application with eleven canonical hash routes:
Overview, Arena, Diligence Rooms, Release Review, Data Vaults, Compute,
Delegated Tinker Account, Safeguards, Capabilities, Verify, and Collaborate.
Wallet connection uses EIP-6963 and a compatible injected EIP-1193 fallback;
WalletConnect is conditional on a public deployment configuration value. A
connected wallet identifies the selected address and network but is not
automatically authenticated to the delegate: service mutations use their own
one-time, Base-Sepolia-bound signature challenges and scoped tokens.

The fresh chain release is exactly seven contracts: `DiligenceRoom`,
`TinkerAccountEncumbrance`, `RoyaltyDistributor`, `ChallengeRegistry`,
`ComputeCreditVault`, `EmailOracleAuth`, and `ExecutionPolicyAnchor`. The
production TEE topology is exactly seven CVMs: one main private runtime; five
separate, independently controlled QVL CVMs for Diligence, Arena, anchor-writer,
Compute-workload, and Compute-metering evidence; and one independent
deterministic Compute meter. The Diligence QVL also evaluates the separate
Email/KMS restart profile, so that secondary profile does not add a sixth QVL
root or eighth CVM.

Every QVL admission uses signed challenge schema v2 and the active independent
verdict schema/signing domain v4, not a reusable quote summary. The verifier
issues one signed, single-use challenge valid for no more than 120 seconds; the
quote binds that challenge and the static release context in its exact 64-byte
report data; and Intel DCAP appraisal must finish strictly before the challenge
expires. A successful appraisal closes the challenge and starts the separately
reviewed exact 900-second activation-evidence lease carried by the v4 verdict.
That policy-bounded lease may outlive the consumed challenge, but is not renewed
challenge freshness. Post-restart Compute-workload recipient activation is an
exact schema-v3 outer record with an explicit recipient-evidence lease of at
most 300 seconds. Its stable recipient-release commitment remains schema v2;
activation v1 and legacy verdicts remain rejected. None of those source
guarantees is a claim that the new QVL roots or CVMs are already deployed.

Main-runtime activation is also one ordered release operation rather than two
independent feature toggles. The exact replacement profile value is
`arena-runtime,compute-execution`. The source-built same-process activation
coordinator carries opaque release/evidence authority through reviewed final
authority, signed Stage B, encrypted environment patch and restart, then checks
a release-bound Arena worker-capability v2 observation before accepting the
fresh independent Compute-workload recipient activation. The Phala
post-restart attestation response and the HMAC-authenticated Arena heartbeat are
observations, not independent Intel DCAP/QVL verification. Completion emits
bounded journal/receipt authority with `live_traffic_authorized=false`; no
production run of that flow has occurred for this release.

The source-real resident driver,
`scripts/phala-production-activation-driver.mjs`, packages that same authority
chain into one exact `--execute-request` operation over an owned canonical
mode-`0600` request. It remains resident through the non-live seven-CVM launch,
five QVL-identity proofs, two workload verdict proofs, externally supplied
Stage-B signatures, restart, recipient activation, and bounded-output
publication. Its checkpoints and final result forbid capability serialization,
signer-key input, automatic retry, and live-traffic authority. The driver is
locally tested; it has not run against a fresh project-owned production
topology and is not deployment evidence.

Compute funding is intentionally not a token sale. The Base Sepolia vault is an
exact-asset ledger for the deposited ETH or release-pinned ERC-20, with no
oracle, FX, or conversion into service credits. It is the first release's
production pay-as-you-go lane: a job reserves an exact-asset maximum, a
purpose-separated meter can debit only bounded actual usage, and unused value
remains withdrawable. Any wallet may sponsor an exact beneficiary without
acquiring authority over that beneficiary; a user may invalidate older
unsubmitted authorization signatures by advancing the project nonce; and
provider/developer settlement accruals remain separate pull-payment balances.
Closed-loop service credits are separate off-chain,
non-transferable, operator-granted test units. Purchased credits and hosted
card checkout are outside v1 and keep Wikigen outside the raw-card collection
path.

Royalty settlement is deliberately asymmetric in the browser. A connected
owner can inspect and pull its own native ETH or canonical Base Sepolia USDC
balance from a runtime-hash-matched `RoyaltyDistributor`, and anyone can inspect
the exact replay slot for a `(distributor, queryRef)` pair. The browser does not
submit distributions or infer ownership: the contract only conserves the split
supplied by a caller and cannot establish that the underlying query, owners,
price, or allocation are correct.

## Historical 2026-07-13 custody and delegation evidence

> Historical only: the following claims describe the prior operator's deployed
> CVM and account. They do not describe the fresh seven-contract release now
> being prepared.

The foundational claim of the project — that a Tinker account can be **owned by
a TEE**, with its full lifecycle and delegated use running through bounded,
attested control planes and no human key — is now **built and validated live**
on the deployed CVM:

- Full upstream API-key lifecycle (create / named-create / list / delete) via
  in-TEE browser automation against the real Tinker console — bounded receipts,
  account address only ever hashed.
- A **scoped, encrypted, revocable proxy** (`Encumbered Tinker Proxy`, below):
  downstream principals receive only x25519-enveloped, HS256-signed, scope-
  limited JWTs; the sealed `tml-...` key never leaves the enclave. Validated
  end-to-end (issue → decrypt → verify → scope-enforce → revoke).
- A **governed redeploy pipeline** (CI reproducible build → on-chain
  `approveComposeHash` → Phala provision/commit) that preserves sealed key
  custody across new measurements.
- **Delegated training via a scoped proxy token** runs end-to-end through the
  real `/tinker/train` endpoint: verify → scope → spend-limit → create →
  forward/backward + optim per step → checkpoint → bounded receipt. Only the
  compute backend is synthetic; the live CVM reaches the real Tinker SDK inside
  the TEE. Adversarially hardened (proxy JWT attacks fail closed; a real
  key-name egress leak was found and fixed; the spend cap provably aborts
  runaway training).

**By design, end users never touch the upstream account — they hold scoped proxy
JWTs, and that path is built and validated end-to-end.** Running *real* jobs is
operational provisioning, not a gap in the system: the upstream Tinker account
must be billing-active (it is funded at $20 with a card on file; a routine
account step activates it), and the CVM must hold a current valid sealed key. A
raw call to Tinker with the raw upstream key is not the product surface and is
expected to fail. See `TODO.md` "2026-07-13 Milestone".

`dnai-wikigen` is becoming a platform for private evaluation, private reward,
and attested settlement.

The short version:

```text
Private data can be useful without being disclosed.

The data owner puts the data, verifier, reward function, or account credential
inside an attested TEE. Agents, buyers, sponsors, or optimizers may interact
with that protected object only through a narrow interface: bounded rewards,
score bands, pass/hold/deny decisions, hashes, attestations, and settlement.
```

The first pass of the project looked like an NDAI diligence room: seller uploads
a private artifact, buyer funds escrow, a TEE evaluator inspects the artifact,
and only bounded results leave. That is still true, but the project is larger
than a deal room.

The expanded project is a **private verified-reward substrate**:

```text
sealed data + attested reward function + controlled optimization loop
       -> private reward oracle
       -> RL/TTT/LLM/evolution can optimize against it
       -> bounded output and settlement, not raw data
```

The clean motivating example is the biology task in TTT-Discover: generated
computational-bio code is evaluated against single-cell data, and the score is
used as reward while the model improves at test time. In this repo's target
deployment, sensitive biological data and the reward verifier would live inside
an independently verified TEE; the current release accepts no real health data
and has no deployed private-bio worker. The optimization method is intentionally
not the core claim. It can be reinforcement learning, test-time training,
evolutionary search, an LLM repair loop, or a hybrid. The intended claim is that
the reward can be verified and useful while the data that defines it remains
private.

## What The Project Is

`dnai-wikigen` combines four ideas:

1. **NDAI economics**
   A seller or controller has private information. A buyer or sponsor wants to
   value it without receiving it. The deal is mediated by reserve price, budget
   cap, bounded disclosure, and escrow settlement.

2. **TEE custody**
   In the target production system, private artifacts, account credentials,
   reward functions, API keys, browser sessions, and verifier data are held
   inside dstack/Phala Intel TDX CVMs. Operators should not have raw access.

3. **Private verified rewards**
   Agents can optimize candidates against reward functions derived from private
   data. The reward is "verified" because it is computed by measured code over
   a sealed dataset, not by a free-form model opinion.

4. **DevProof verification**
   Users should be able to verify what code is running, what compose hash was
   authorized, what contract accepted the result, and what bounded transcript was
   released.

The project therefore has two product faces:

```text
Attested Diligence Room
  private artifact -> bounded valuation -> escrow settlement

Private Reward Lab
  private verifier/data -> reward oracle -> optimizer improves candidate -> bounded proof
```

Those are not separate systems. The private reward lab is the strongest form of
the diligence room. Instead of merely reading an artifact, the evaluator can
actively test candidate programs, policies, or model updates against the private
data while the data remains sealed.

## Encumbered Tinker Proxy

Tinker should be exposed as an attested proxy, not as a shared upstream account.
The TEE/CVM holds the upstream Tinker API key, `TINKER_PROJECT_ID`, optional
provider endpoint, browser session, payment-method state, and funding controls.
Buyers, sponsors, agents, optimizers, and reviewers receive only scoped
delegate credentials for the proxy.

The proxy credential shape is:

```text
approved user / agent
  -> receives a short-lived scoped JWT
  -> JWT is signed by a key derived from CVM-only key material
  -> JWT is delivered encrypted to the recipient public key
  -> caller invokes only allowlisted proxy operations
  -> proxy returns bounded receipts, hashes, bands, yes/no decisions, and
     attestations
```

The upstream Tinker API key and project id are never user-facing API material.
They are sealed service configuration. The proxy may report whether they are
configured and may return stable hashes or host-family classifications, but it
must not return the raw values. A user-facing proxy token also must not grant a
generic "call arbitrary Tinker SDK method" capability; every operation needs a
named scope, bounded schema, spend policy, and leakage accounting.

For the current implementation this means:

- `TINKER_API_KEY`, `TINKER_PROJECT_ID`, account cookies, card state, and
  funding receipts stay inside the CVM boundary.
- `TINKER_PROJECT_ID` and optional `TINKER_BASE_URL` can be sealed into an
  encrypted Tinker client-config store through a runtime-authenticated
  `tinker-client-config --install` / `PUT /tinker/proxy/client-config` path.
  Status surfaces return only hashes, host-family classification, and store
  readiness; smoke tests and future evaluator sessions resolve SDK client
  config from this sealed store when direct env settings are absent.
- The delegate may issue short-lived scoped JWTs only through an
  operator-approved issuance path, and production issuance should additionally
  bind approved users/agents to policy records. The first source-real policy
  layer is hash-only: a configured issue-policy file can require subject hash,
  recipient public-key hash, scope subset, and TTL cap matches before minting a
  token. For spend-bearing scopes, policy-issued tokens can also carry bounded
  `max_amount_usd` limits that proxy routes enforce before touching browser or
  payment automation. Operators can install this hash-only policy through a
  runtime-authenticated bounded API/CLI, not by exposing raw upstream Tinker
  credentials or plaintext proxy JWTs. Policy grants can also carry hash-only
  lifecycle metadata, so pending, revoked, expired, missing, or future-approved
  grants fail closed without exposing raw reviewer identities. A hash-only
  identity registry can additionally require requesters to be active user/agent
  identities and lifecycle approvers to be active reviewer/admin identities,
  while still exposing only hashes, roles, statuses, and expiries. Source/test
  code can require that registry to be signed by a configured verifier
  Ethereum address before minting, so an operator-supplied JSON file is not
  enough when the signature gate is enabled. The verifier workflow should
  produce signed hash-only registry artifacts and bounded receipts, not raw
  identity exports. Grant lifecycle approval can additionally require an
  Ethereum signed-message signature over a canonical hash-only grant approval
  payload, where the recovered reviewer address must hash to the grant's
  `approved_by_hash`; bounded receipts expose only approval, signer, and
  signature hashes, not signer addresses or raw signatures. A deployment-policy
  gate can also require public
  `TinkerAccountEncumbrance` compose/cap approval before minting spend-bearing
  proxy JWTs; production verifier/reviewer governance and secure recipient
  approval workflow remain separate work.
- JWT delivery should use an attestation-verified encrypted channel to the
  recipient, not plaintext logs, shell history, or documentation.
- JWT issuance and revocation should leave bounded sealed audit records so a
  reviewer can verify the delegated access history without seeing plaintext
  tokens or upstream Tinker credentials. Revocation must fail closed for
  token hashes that were never issued, and retrying revocation for an already
  revoked issued token should be idempotent rather than creating dangling or
  duplicate audit entries.
- Proxy operations return bounded receipts: configured booleans, hashes,
  capability names, score/spend bands, attestation metadata, and audit events.
- Proxy-authorized operation responses should carry only a bounded
  `proxy_auth_context`: auth kind, required scope, subject hash, JWT-id hash,
  granted scopes, expiry, and `raw_secret_egress=false`. That context lets an
  external verifier replay token issue/revoke chronology against operation
  receipts without seeing the plaintext JWT or upstream Tinker credentials.
- Raw samples, run IDs, checkpoint paths, provider messages, card details,
  upstream credentials, and project ids remain non-egress data.

## Current Repo Pieces

The current branch already contains:

- `⚙️/tinker-delegate/contracts/src/DiligenceRoom.sol`
  Escrow state machine with reserve price, budget cap, result submission,
  accept/reject/expire, pull payments, and tests.

- `⚙️/tinker-delegate/contracts/src/EmailOracleAuth.sol`
  App-auth policy for the email oracle and OTP consumers, including compose-hash
  policy, manager delegation, timelocks, and freeze controls.

- `⚙️/tee-email-oracle`
  A FastAPI service intended to hold an email account inside a TEE and provide
  OTP extraction.

- `⚙️/tinker-delegate`
  TEE-side Tinker account automation, encrypted card channel, billing scaffold,
  isolated Tinker sessions, bounded control plane, evaluator scaffold, and API.
  API-key provisioning and billing automation return and persist bounded
  attempt records rather than raw keys, card data, or browser page bodies.
  The client-side encrypted billing harness verifies context-bound attestation
  before posting card ciphertext. A local synthetic room harness now uses a
  fake Tinker backend to exercise encrypted artifact ingress, one-run
  `IsolatedTinkerSession` evaluation, bounded modeled packets, and cleanup
  without requiring a real Tinker project; this is CI/offline modeling, not
  deployed Phala or real Tinker training evidence. A companion local Anvil
  proof now connects that synthetic room to real `DiligenceRoom` result
  submission, `DealAccepted` settlement, pull-payment bands, and cleanup through
  the dstack simulator while emitting only bounded public JSON. Tinker run
  metadata is also treated as an egress channel: evaluator-supplied metadata is
  size-limited, allowlisted, and hash-represented before it reaches the upstream
  SDK.

- `⚙️/props-room`
  Source-controller and sealed-asset control plane stub.

- `⚙️/whatsapp-delegate`
  Browser-mediated private source acquisition and sealed storage pattern.

- `ARCHITECTURE.md`
  The current architecture map.

- `TODO.md`
  The implementation roadmap.

## The Expanded Thesis

The project is built around a single observation:

```text
Interaction with private data is not the same thing as disclosure of private data.
```

That statement is false for arbitrary interaction. If an adversary can ask any
query and receive exact answers forever, it can reconstruct a lot. The statement
becomes true under a constrained interface:

```text
allowed query family
+ measured code
+ TEE confidentiality/integrity
+ authenticated caller policy
+ bounded output reducer
+ query and precision budgets
+ side-channel controls
+ attestable transcript
= useful interaction with controlled leakage
```

The private reward use case is exactly this. A candidate program may be executed
against secret data. It may receive a reward signal. But the reward interface is
not "read the data." It is a narrow oracle whose outputs are budgeted, reduced,
and attested.

## Running Example: Private RLVR For Computational Bio Code

TTT-Discover formulates discovery problems as environments with continuous
rewards. Its biology example uses single-cell denoising: candidate code is
scored on benchmark data, and the optimization process uses that score to find
better code. The paper reports a single-cell analysis task over OpenProblems
datasets and uses metrics related to denoising quality.

In `dnai-wikigen`, the same shape becomes:

```text
Private bio data D
  -> sealed inside TEE

Reward verifier R_D
  -> measured code computes denoising / prediction / utility score

Candidate code c
  -> proposed by RL, TTT, evolutionary search, or LLM loop

Reward R_D(c)
  -> exact value may be used internally
  -> public release is quantized, withheld, noised, or reduced to pass/hold/deny

Final result
  -> bounded score band, method hash, candidate hash, quote, settlement event
```

The optimization method is deliberately interchangeable:

```text
RLVR       policy learns from verified reward
TTT        model adapts at test time on the one problem
LLM loop   candidate -> verifier -> repair prompt -> candidate
evolution  mutation/search over candidates
manual     human proposes candidate, TEE verifies privately
```

The invariant is the same in every case:

```text
The private data and raw verifier stay inside the TEE.
Only the approved reward transcript leaves.
```

## Architecture

```text
                       public / user domain

 seller/controller       buyer/sponsor         reviewer/auditor
        |                     |                       |
        v                     v                       v
+----------------------------------------------------------------+
|                        web client / APIs                       |
| rooms, policies, budgets, attestations, review, settlement     |
+--------------------------+-------------------------------------+
                           |
                           v
+----------------------------------------------------------------+
|                         DNAI layer                             |
| deal lifecycle, access policy, coordination, bounded outputs    |
+-------------+---------------------------+----------------------+
              |                           |
              | OTP / confirmation        | execute / reward / settle
              v                           v
+--------------------------+    +--------------------------------+
| email oracle TEE         |    | tinker/private-reward TEE       |
| no-human-access mailbox  |    |                                |
| OTPs and confirmations   |    | sealed data D                  |
| EmailOracleAuth policy   |    | reward verifier R_D            |
+-------------+------------+    | candidate sandbox              |
              |                 | optimizer or Tinker session    |
              |                 | bounded output reducer         |
              |                 +---------------+----------------+
              |                                 |
              v                                 v
+--------------------------+    +--------------------------------+
| EmailOracleAuth.sol      |    | DiligenceRoom.sol / vNext      |
| compose hash policy      |    | escrow, result hash, payouts   |
| consumer authorization   |    | attested settlement            |
+--------------------------+    +--------------------------------+
                         Base Sepolia / Base-compatible chain
```

## Private Reward Environment

The project should expose a first-class environment abstraction.

```python
class PrivateRewardEnvironment:
    def problem(self) -> PublicProblem:
        """Public problem statement safe to show optimizers."""

    def candidate_schema(self) -> CandidateSchema:
        """Allowed candidate format: code, config, policy, model patch, etc."""

    def reward(self, candidate: Candidate) -> InternalReward:
        """Exact reward computed inside the TEE over sealed data."""

    def reduce(self, internal: InternalReward) -> PublicFeedback:
        """Approved feedback: band, pass/hold/deny, noised value, or nothing."""

    def finalize(self, transcript: Transcript) -> BoundedResult:
        """Final output and settlement payload."""
```

The environment owns:

- private data `D`
- reward function `R_D`
- candidate sandbox
- hidden train/reward/final-validation split
- query budget
- reward precision policy
- optimizer placement policy
- output reducer
- transcript hash
- attestation payload
- settlement payload

Implementation note: `tinker_delegate.private_reward` now contains the base
`PrivateRewardEnvironment`, leakage-budget, optimizer-policy,
bounded-feedback, transcript-hash, leakage-hash, and attestation dataclasses.
The default optimizer mode is external and bounded; exact rewards are exposed
only through an explicit internal or attested optimizer policy. This is the
interface layer only. `tinker_delegate.private_reward_sandbox` adds a local
Python sandbox for toy candidates with subprocess timeout, scratch cwd,
stripped environment, deterministic seed, capped stdout/stderr, timing bands,
public failure-code buckets, and file, network, process, and import guards.
`tinker_delegate.evaluator_sandbox` adds the first source-modeled
process/capability runner for simple third-party evaluators: the evaluator
subprocess sees bounded context only, emits an allowlisted plan, and never
receives the raw Tinker session object. This is not yet hostile-code production
isolation.
`tinker_delegate.private_reward_holdout` adds a hidden-holdout split and
accounting contract with public split commitments, partition counts,
reward-query tracking, per-candidate repeat caps, minimum unique candidates
before final validation, and one-shot final-validation gating.
`tinker_delegate.private_reward_envs.synthetic` wires those contracts into a
toy hidden-keyword environment with bounded reward bands and final validation
over sealed synthetic records. Real RLVR, TTT, bio-validation, domain-specific
anti-overfitting rules, and hardened production candidate-sandbox environments
are still separate implementation work.

## Sealed Data At Rest (Portable Encrypted Datasets)

The reward data `D` that defines a private environment must be able to live in
untrusted, public storage — Hugging Face Hub, S3, IPFS, a git LFS remote —
without becoming public. The invariant is unchanged: raw data is only ever
plaintext *inside the attested boundary*. Storage location is not a trust
boundary; the ciphertext can sit on a fully public host.

The chosen construction is **envelope encryption bound to an attested
measurement**, reusing the two key tiers the repo already has:

```text
DEK  = fresh random AES-256 key (per dataset)
blob = AES-256-GCM(D, DEK)                 # large, chunked, storage-agnostic
wrap = X25519-to-attested-CVM(DEK)         # one per approved recipient measurement
manifest = { dataset_id, task, blob hash+size, plaintext hash,
             wrapped-DEK per measurement, data_sensitivity, owner signature }
```

- The **data-encryption key (DEK)** encrypts the dataset once. The large
  ciphertext blob is content-addressed and can be published anywhere.
- The DEK is **wrapped to each approved CVM's attestation-bound public key**, so
  only a CVM whose measurement matches an approved recipient can unwrap it.
  Adding a new environment/CVM re-wraps the small DEK, never the whole dataset.
- Inside the boundary the CVM unwraps the DEK with its measurement-derived key,
  decrypts to the sealed data volume, verifies the plaintext hash, uses `D`
  for reward computation, and zeroes the buffers. Only bounded reward bands,
  hashes, and attestations leave.

Security reduces exactly to the existing attestation + on-chain
compose-approval chain: the dataset is only as sealed as the measurement
binding of the CVM key derivation. It is therefore labeled `[partial]` until
cryptographic TDX quote parsing binds the unwrap key to an approved
measurement. A `data_sensitivity` label (`public_benchmark` / `private` / `phi`)
keeps claims honest — encrypting public benchmark data such as the OpenProblems
denoising sets exercises the *mechanism* and is not itself a privacy claim.
Any optional owner recovery key weakens the "no human access" invariant and is
explicit and off by default.

## Security Goal

The informal goal:

```text
An adversary can learn no more from the real system than it could learn from an
ideal private reward oracle that reveals only the approved leakage.
```

This is the right kind of claim. It does not say "no information leaks." Reward
queries necessarily leak something. It says the only leakage is the leakage the
system intentionally exposes through the reward interface and final bounded
outputs.

## Formal Model

Let:

- `D` be the private dataset or artifact.
- `C` be the candidate space: code, model patch, prompt, policy, or algorithm.
- `R_D: C -> Y` be the reward function induced by private data `D`.
- `P` be the public problem statement.
- `Q: Y -> Z` be the output reducer: quantization, banding, thresholding,
  noising, or withholding.
- `B` be the budget: max queries, max runtime, max spend, max precision.
- `Pi` be the policy deciding which candidates are admissible.
- `A` be an adaptive adversary/optimizer that proposes candidates.
- `View_A(D)` be everything `A` sees in the real protocol.

The ideal functionality `F_private_reward` works like this:

```text
Setup:
  Store D privately.
  Publish P, policy metadata, environment hash, quote, and contract addresses.

Query(c):
  If query budget exhausted: return reject_budget.
  If Pi(c) rejects: return reject_policy.
  Compute y = R_D(c).
  Store exact y internally.
  Return z = Q(y), or return no public reward if Q withholds feedback.

Finalize:
  Compute bounded result from the internal transcript.
  Return only approved fields:
    result band, confidence band, safety band, candidate hash,
    transcript hash, cost band, quote, and settlement payload.
```

The leakage function is:

```text
L(D) =
  public problem P
  public policy metadata
  number of accepted/rejected queries up to B
  candidate hashes and possibly candidate contents if policy permits
  reduced feedback z_i = Q(R_D(c_i))
  timing/cost bands
  final bounded result
  transcript hash
  attestation and chain events
```

Everything else should be hidden:

```text
D
raw rows / sequences / assays
exact reward values if Q withholds or bands them
hidden holdout split
raw model samples
private gradients
reward-derived optimizer state
checkpoints encoding private reward
API keys, account credentials, card details
upstream project identifiers and proxy signing keys
```

## Main Theorem: Leakage-Only Realization

**Theorem 1.** Assume:

1. The TEE provides confidentiality and integrity for measured code and sealed
   storage.
2. Remote attestation is unforgeable and verifiers check freshness, app ID,
   compose hash, public keys, and policy.
3. Secrets are provisioned only to authorized compose hashes.
4. All candidate execution is sandboxed and cannot use unauthorized I/O.
5. All external outputs pass through `Q` and the transcript logger.
6. Side channels are either out of scope or bounded by the leakage function.
7. The optimizer that sees exact rewards or reward-derived updates is inside the
   trusted boundary. If it is not, exact rewards and reward-derived updates are
   not sent to it.

Then for every probabilistic polynomial-time adversary `A` controlling the
network, optimizer prompts, candidate submissions, public chain reads, and the
untrusted host outside the TEE, there exists a simulator `S` given only `L(D)`
such that:

```text
View_A(real protocol with D)  ~=c  S(L(D))
```

where `~=c` means computational indistinguishability up to the security of the
TEE, attestation scheme, authenticated encryption, signatures, and hash
functions.

### Proof Sketch

The simulator receives the allowed leakage `L(D)`. It fabricates the public
network transcript, chain events, API responses, attestation-shaped records, and
bounded feedback values exactly as described by `L(D)`.

The only places where the real protocol uses private data are:

1. reward computation `R_D(c)`
2. internal optimizer state updates, if the optimizer is inside the TEE
3. final bounded-result reduction
4. sealed storage and cleanup

By assumption, these computations run inside measured TEE code and their raw
inputs/outputs are not externally visible. The real external messages are
therefore either public setup data, adversary-provided candidates, or outputs of
`Q` and the transcript logger. Those are exactly the values in `L(D)`.

If an adversary distinguishes the real view from the simulated view, then one of
the assumptions was broken: TEE confidentiality, attestation unforgeability,
sealed-key policy, sandbox confinement, output mediation, or the declared
side-channel bound.

So the real system reveals no more than the ideal private reward oracle.

## Information Bound

Simulation says the infrastructure leaks only approved outputs. The next
question is how much information those outputs can contain.

Suppose:

- at most `n` reward queries are accepted,
- each public feedback value `z_i` has at most `k` bits of entropy,
- the final bounded result has at most `b` bits of entropy,
- all other public metadata is independent of `D` or separately counted.

Then:

```text
I(D ; public transcript) <= n * k + b
```

This follows from the data processing inequality:

```text
D -> (R_D(c_1), ..., R_D(c_n)) -> (Q(R_D(c_1)), ..., Q(R_D(c_n)), final)
```

and from the entropy bound:

```text
I(D ; Z) <= H(Z)
```

If `Q` returns one of `m` reward bands, then `k <= log2(m)`. If the public
system withholds per-query reward and releases only one final band among `m`
bands, then the reward transcript leaks at most `log2(m)` bits plus separately
counted timing/cost metadata.

This is the clean reason the security model is surprisingly strong:

```text
The optimizer can interact with private data many times inside the TEE, but
outside observers only receive a small, budgeted transcript.
```

The exact rewards can still drive learning internally. They just do not have to
be public.

## Adaptive Queries

The adversary may choose candidate `c_t` after seeing previous public feedback:

```text
c_t = A(P, z_1, ..., z_{t-1})
```

The theorem still holds because the ideal functionality is also adaptive. It
computes the same reduced feedback for each candidate and reveals only `z_t`.

Adaptive querying matters for leakage quantity, not for the simulation theorem.
That is why the environment must enforce:

- query budget
- reward precision budget
- hidden final holdout
- overfitting checks
- side-channel controls
- candidate sandboxing

Without those, an adaptive adversary can turn even a legitimate oracle into a
data-extraction channel.

## Differential Privacy Option

The bounded-transcript guarantee protects against infrastructure leakage. It is
not automatically a patient-level privacy guarantee.

If the reward mechanism released to the outside world is `(eps, delta)`
differentially private with respect to neighboring datasets `D` and `D'`, then
the public reward transcript inherits standard DP composition:

```text
q adaptive releases, each eps-DP
  -> at most q * eps basic composition
```

with the usual stronger bounds available through advanced composition or a
privacy accountant.

This gives a second, statistical privacy layer:

```text
TEE isolation controls where computation happens.
Output reduction controls what the infrastructure reveals.
Differential privacy controls what the released rewards reveal about one record.
```

DP is optional because some use cases are dataset-level IP protection rather
than individual-level privacy. For real PHI or sensitive bio data, the project
should either implement DP accounting or explicitly mark the environment as not
PHI-safe.

## Third-Party Reward Evaluability

Status: substantially `[real]` as of 2026-07-12 — the mechanism-audit verifiers
are built, tested, and shipped as `verify_reward_mechanism` (surfaced as the
`verify-reward-mechanism` CLI and the `POST /verify/reward-mechanism` endpoint).
Real today: attested code-identity binding (`verify_reward_code_binding`),
data-commitment binding to the sealed-dataset manifest + owner/notary signature
(`verify_reward_dataset_binding`), canary calibration
(`verify_canary_calibration`), declared-vs-enforced query/DP/Ladder policy
accounting (inside `verify_reward_run`), and the Ladder overfitting bound (fixed-η
wired into the denoising + synthetic envs, plus the parameter-free paired-t
variant), and the neutral sealing-witness M-of-N quorum (`add_witness_signature` /
`verify_witness_quorum`, enforceable through `verify_reward_dataset_binding`), and
seal-time attested provenance signing (`build_provenance` /
`verify_dataset_provenance`), and the Thresholdout / DP-noised reusable-holdout
gate (`thresholdout.py`, composing with the shared `DpAccountant`). The trust and
overfitting layers of the mechanism-audit story are now all `[real]`; what remains
is env-wiring of the Ladder/Thresholdout gates and the externally-blocked live
frontier. See `TODO.md` "Third-Party Reward Evaluability (Mechanism Audit)" and
`ARCHITECTURE.md`.

The hardest question a counterparty asks: *how can I evaluate this RL
environment — trust the reward is real, honestly computed, un-gamed, and useful
— without ever seeing the sealed data?* In this project's threat model the third
party **reads the environment code** and may **query the black box** within
agreed boundaries, but the data stays sealed. The answer is that they evaluate
the **mechanism, not the data**.

The question decomposes into three axes that are routinely — and wrongly —
treated as one:

```text
trust       Is the oracle honestly running the reward the code says,
            over the data that was actually committed?
leakage     Can repeated queries plus knowledge of the code reconstruct
            the sealed data?
overfitting Can an optimizer grind a fixed holdout into a meaningless
            settlement number WITHOUT ever leaking a record?
```

`leakage` and `overfitting` are both governed by the same output-reduction /
noise / query-budget machinery already in the formal model above (query budget,
reward precision budget, hidden final holdout, DP option). `trust` is the axis
this section adds, and it is answered by attestation + data commitment +
calibration, not by disclosure.

### Trust: audit the machine that produced the reward

Four layers, extending the existing verification chain
(`git SHA -> docker digest -> compose hash -> TDX quote`):

```text
attested code identity  [real] The third party read code C; the attestation says
                        C ran. Verified by `verify_reward_code_binding`.
data commitment         [real] Attestation binds HASH(reward_code) ||
                        dataset_commitment || params -> bounded_result (Attestable
                        Audits A[AC+AD->R]). Reuses the sealed-dataset manifest
                        hash as the root; verified by
                        `verify_reward_dataset_binding` (+ owner/notary signature).
public canary slice     [real] Known-good / known-bad candidates test that the
                        oracle ranks sensibly (`canary.py`); a published report is
                        checked by `verify_canary_calibration`. [planned] a
                        committed public slice per env anchoring the private scale.
sealing witness         [real] A neutral notary or M-of-N quorum witnesses the
                        dataset entering the TEE and co-signs the commitment,
                        defeating the "seller crafts data to favor one bidder"
                        collusion. Built as `add_witness_signature` /
                        `verify_witness_quorum`; enforceable via
                        `verify_reward_dataset_binding(..., witness_quorum=...)`.
attested provenance     [real] Source pipeline, upstream id, license, distribution
                        claim vs. a named public benchmark, committed into the
                        manifest at seal time (`build_provenance`) so a signature
                        binds the claim; checked by `verify_dataset_provenance`
                        (tampering the claim breaks the signature).
```

Data commitment stops the operator swapping in easier data or fabricating
scores; the canary and provenance address "committed does not mean *good*"; the
witness handles adversarial buyer/seller pairs.

### Overfitting: bound adaptive-query holdout reuse

Even with an honest oracle and zero raw leakage, an optimizer querying a fixed
private holdout thousands of times overfits *to it*. Two classical mechanisms,
both reusing the same noise the leakage bound already needs:

```text
Ladder      [real] Release a reward only when a candidate beats the running best
            by a statistically significant margin. Leaderboard error ~
            log(k)^{1/3}/n^{1/3} (logarithmic in query count k), so a fixed-size
            holdout supports effectively unlimited attempts and the number stays
            honest. Built as `ladder_release.py` (fixed-η + paired-t variants);
            fixed-η wired into the denoising + synthetic envs, and paired-t
            (per-cell vector) wired into the denoising env.
Thresholdout / reusable holdout
            [real] Access the holdout only through a DP mechanism (noisy
            threshold): budget is spent only when a candidate diverges from the
            reward-partition statistic the optimizer already knows, giving total
            leakage <= eps * holdout-accesses as a single stated bound. Built as
            `thresholdout.py` (`ThresholdoutGate`), composing with the shared
            `DpAccountant`; the DP noise gates which partition's band to release, so
            only a coarse band index egresses (no un-noised real leaves). Standalone
            mechanism; env-wiring is a follow-up.
```

The elegant part: **the noise that stops reconstruction is the same noise that
stops overfitting.** One mechanism, two guarantees. See
`📄/ladder/paper.md` and `📄/attestable-audits/paper.md`.

### The frontier is the contract

Every knob — output granularity, DP-eps, query budget, Ladder threshold, holdout
rotation — is simultaneously a *utility* dial (how well the third party can
optimize) and a *safety* dial (leakage + overfitting). Choosing the contract
**is** choosing a point on that frontier, and it maps directly onto the
reserve-price / budget-cap / bounded-disclosure economics: the seller is selling
**feedback bandwidth** about a sealed reward, priced by how much the buyer wants.

Residual gaps to state plainly to any counterparty:

```text
TEE hardware root        Trust in the TDX vendor + side channels; mitigate with
                         multi-vendor attestation, optional ZK dispute backstop.
commitment != quality    A hash proves WHICH data, not that it is representative
                         or honestly labeled; canary + provenance + seller stake.
candidate-as-exfiltrator A submitted candidate can smuggle data through the
                         reward value or timing; closed by sandbox + aggregate-
                         only + quantized/noised band (the residual gap named in
                         Attestable Audits' interaction step).
```

## Why This Is Strong Despite Interaction

A naive view says: "If the agent can run code on the data, the data is exposed."

That is true if the agent controls the process. It is false if the agent only
controls candidates submitted to a measured verifier.

The distinction:

```text
Bad: agent gets shell / notebook / database / exact metrics / logs.
Good: agent submits candidate c; TEE returns Q(R_D(c)).
```

In the good case, interaction is mediated by a reward oracle. The security is
not "no interaction." The security is:

```text
No unmediated interaction.
No unbounded reward precision.
No unlimited query count.
No raw verifier logs.
No raw data or exact holdout labels.
No reward-derived state leaving the boundary unless accounted for.
```

This is similar in spirit to cryptographic ideal functionalities. The real
system should behave like a trusted third party holding `D` and answering only
approved reward queries.

## Trusted Boundary Choices

There are three security tiers.

### Tier 1: Full Private Optimizer

```text
candidate generation, reward computation, optimizer updates, and archive
all inside the same TEE
```

This is the strongest tier. Exact rewards and dense gradients may exist, but
only inside the TEE. Public leakage can be just the final bounded result.

### Tier 2: Attested Remote Trainer

```text
reward TEE + trainer TEE + attested channel + policy binding
```

This can support true RL/TTT updates with dense reward, but only if the trainer
is itself attested and included in the trust story. The attestation transcript
must bind both sides.

### Tier 3: External Optimizer With Bounded Feedback

```text
external LLM/optimizer proposes candidates
TEE computes reward
external optimizer receives only bounded feedback
```

This is useful and often enough, but it is not the same as sending dense reward
labels or gradients to an external service. If Tinker is untrusted for a given
environment, the project must not send private reward labels, private
gradients, selected-example traces, or checkpoints that encode the private data.

## Tinker Implication

Tinker is valuable compute for fine-tuning, RL, sampling, and TTT-style loops.
But the security claim depends on what Tinker sees.

Safe patterns:

- Tinker account credentials, project ids, browser sessions, and proxy signing
  keys stay sealed in the TEE.
- Approved users receive only scoped delegate JWTs for the Tinker proxy, not
  the upstream Tinker API key.
- Delegate JWTs are short-lived, scope-limited, CVM-key-derived, and delivered
  through an encrypted channel after attestation/policy checks.
- Tinker receives only non-sensitive prompts/candidates.
- TEE computes private rewards and releases only bounded feedback.
- Tinker is used for candidate generation or public/synthetic training.
- Dense reward training happens only when Tinker is part of the trusted boundary
  or the reward signal is safe to reveal.

Unsafe pattern:

```text
TEE computes exact private reward -> sends dense reward labels or gradients to
an untrusted external trainer -> trainer logs/checkpoints can encode D.
```

That pattern breaks the private reward theorem because reward-derived state has
left the ideal functionality.

So the implementation must label every environment by security tier.

## Candidate Code Security

For computational-bio code, the candidate itself can be adversarial. It may try
to exfiltrate data through stdout, timing, memory pressure, exceptions, output
files, or resource usage.

The candidate sandbox must enforce:

- no network
- no arbitrary file reads
- no access to raw data paths except through verifier-controlled APIs
- bounded stdout/stderr
- bounded return schema
- fixed time/memory limits
- timeout normalization
- deterministic seeds when feasible
- scratch directory only
- no access to attestation socket or secrets
- no outbound browser/CDP
- no environment variables containing secrets

Candidate outputs must then pass through the reducer before release.

## What The Contract Guarantees

Contracts do not hide data. They provide public coordination and settlement.

`DiligenceRoom.sol` and vNext contracts should guarantee:

- buyer budget cap is enforced
- seller reserve is enforced
- compute cost and fees fit inside the budget
- only an authorized attested evaluator can submit results
- result hash binds the transcript
- settlement is pull-payment based
- expiry/reject/accept are well-defined
- public events let auditors verify the lifecycle

`EmailOracleAuth.sol` should guarantee:

- only authorized oracle compose hashes receive email KMS material
- only authorized consumers can request OTPs
- consumer managers cannot modify oracle code policy
- production policy can be frozen
- fresh quotes are checked against stable compose-hash policy

The contracts complete the private reward story by making the reward transcript
economically consequential without putting raw data on-chain.

## What The TEE Guarantees

The TEE and attestation layer should guarantee:

- the reward code is the measured code
- the private data is sealed to that measured code
- callers can establish an encrypted channel to the measured code
- secrets are unavailable to other code measurements
- public keys and quotes are bound to the running app
- outputs are mediated by measured code

This is not magic. It depends on the TEE threat model. Physical attacks,
provider provenance, side channels, malicious host scheduling, and bugs in the
measured code must be handled explicitly or listed as assumptions. Flashbots'
Proof-of-Cloud work is directly relevant here because ordinary TEE attestation
does not fully answer where the hardware is operated.

## What The System Does Not Guarantee Yet

The current repo does not yet guarantee:

- production quote verification for result submission
- runtime enforcement of `EmailOracleAuth` on every OTP endpoint
- production/repeated Tinker account funding; one-off capped operator
  validation funding is real, but hardened custody, compliance approval, and a
  production payment route remain open
- production Tinker account custody through hardened bot-check/browser posture;
  deployed login/API-key sealing and reauth are real in the current validation
  profile, but the CVM still runs with temporary debug surfaces
- real TTT/RL private reward environments
- candidate sandboxing for generated computational-bio code
- differential privacy for individual-level bio data
- real DLP/egress controls
- production human reviewer workflow; the source-modeled reducer and bounded
  review queue can create, persist, expire, release/deny, and audit hold
  tickets without raw review reasons or reviewer identities, but notification,
  UI, M-of-N approval, and production reviewer custody are not production
- production multi-party coordination engine; the source now has a deterministic
  pure ConSECA-style `policy_kernel` for per-corpus AccessRequest/CorpusPolicy
  enforcement, a bounded `policy-gate` CLI proof path, and a pure local reducer
  for fail-closed fan-out, unanimous or M-of-N consent, owner consent
  grant/deny effects, revocation, joint attestations, and royalty meters.
  `consent-decision` now gives those owner consent effects a bounded CLI receipt
  path plus a runtime-authenticated bounded API endpoint. Optional signed owner
  confirmation can bind a hash-only consent payload to an expected
  owner-controlled signer while receipts expose only signature-binding hashes
  and verification status. LLM policy authoring, policy migration/diff review,
  owner/reviewer notification wiring, production owner-key custody,
  tee-email-oracle/DiligenceRoom effect wiring, and production governance
  remain open
- production frontend wired to real APIs
- Proof-of-Cloud or equivalent platform provenance

These are roadmap items, not solved facts.

## Product Modes

### Mode A: Diligence Room

```text
seller artifact -> TEE evaluator -> score band / offer -> escrow settlement
```

Use for private memos, code, datasets, SOPs, benchmarks, or model artifacts.

### Mode B: Private Reward Environment

```text
sealed verifier data -> candidate code -> private reward -> optimizer loop
```

Use for RLVR, TTT-Discover-style tasks, computational-bio code, private
benchmarks, code optimization against proprietary tests, or reward-function
licensing.

### Mode C: Source Custody Room

```text
web2/source account -> TEE browser/export -> sealed artifact -> policy-gated use
```

Use for WhatsApp, email, private repos, data portals, or user-contributed source
data.

### Mode D: Multi-Owner Collaboration

```text
N private corpora -> fan-out gates -> unanimous/quorum consent -> joint result
```

Use for biobank collaboration, sponsor/CRO workflows, and cross-institution
private analysis.

## Relation To Flashbots, Teleport, Andrew Miller, And Wikigen

### Flashbots / Flashbots X

Flashbots' TEE work emphasizes that mutually distrusting parties can share a
confidential execution environment, but also that vanilla attestation is not the
end of the trust story. `dnai-wikigen` should import that seriousness:

- name all roles separately: operator, host/cloud provider, data owner, sponsor,
  evaluator owner, reviewer, auditor
- verify not only code measurement, but also platform provenance where possible
- treat Proof-of-Cloud as a future hardening layer
- keep the contract-facing trust story explicit

### Teleport / Account-Link

Teleport demonstrates scoped use of a web2 account through a TEE: one action,
under policy, without handing over the account. `dnai-wikigen` uses the same
shape:

- one OTP use
- one Tinker compute grant
- one private reward environment
- one bounded evaluation
- one settlement

The account or data is not sold outright. A scoped capability is exercised under
policy.

### Andrew Miller / outh3 / DevProof

The Andrew Miller references in `🔬/amiller` point toward DevProof apps:
reproducible code, attestable deployments, no hidden developer powers,
inspection certificates, escrow, and domain separation. The proof in this file
is written in that style:

```text
Define the ideal functionality.
State the leakage.
Show the real protocol leaks no more.
List the assumptions.
Do not claim side channels or TEE hardware are solved by prose.
```

### Wiki Leks / Wikigen

Wikigen's product insight is that private information has latent value, but
ordinary disclosure destroys leverage. The larger version says:

```text
Private information can become a reward, a verifier, a capability, or an
evaluation market without becoming public data.
```

That is the project.

## Implementation Priorities

The next concrete build should be:

1. Build a synthetic hidden-data reward environment.
2. Add candidate sandboxing.
3. Prove the reducer prevents exact reward egress in public mode.
4. Wire the environment into the existing `control_plane`.
5. Run one end-to-end local test:
   candidate -> private reward -> bounded result -> result hash.
6. Only then connect a real Tinker/TTT loop.

This order keeps the security claim ahead of the optimizer hype. The optimizer
can be swapped later. The private reward boundary is the product.

## References

- TTT-Discover paper: https://arxiv.org/abs/2601.16175
- TTT-Discover code: https://github.com/test-time-training/discover
- TTT-Discover project page: https://test-time-training.github.io/discover/
- Flashbots Proof-of-Cloud discussion:
  https://writings.flashbots.net/mind-the-gap-tee-poc
- Flashbots Sirrah TEE coprocessor:
  https://writings.flashbots.net/suave-tee-coprocessor
- Teleport / Account-Link:
  https://github.com/teleport-computer/teleport-gramine-rs
- Gramine attestation and secret provisioning:
  https://gramine.readthedocs.io/en/latest/attestation.html
- Andrew Miller:
  https://soc1024.ece.illinois.edu/
