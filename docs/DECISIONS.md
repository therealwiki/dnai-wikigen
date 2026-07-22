# Architecture Decisions

This ledger records architecture choices that affect trust boundaries,
deployment topology, funding rails, quote verification, data locality, and
frontend verification. Status labels match `ARCHITECTURE.md`:

- `[real]` implemented and locally verified.
- `[partial]` implemented but not production-complete.
- `[modeled]` specified or stubbed but not enforced end to end.
- `[planned]` target only.

## 2026-07-21: Fresh Release Is Seven Contracts, Seven CVMs, Five QVL Roots

Status: `[real source; deployment pending]`

Decision:

The release unit is one clean source SHA bound to seven Base Sepolia contracts
and seven Phala CVMs. The contracts are `DiligenceRoom`,
`TinkerAccountEncumbrance`, `RoyaltyDistributor`, `ChallengeRegistry`,
`ComputeCreditVault`, `EmailOracleAuth`, and `ExecutionPolicyAnchor`. The CVMs
are:

1. the main private runtime (delegate, internal email oracle, Neko, and the
   disabled-by-default Deal/Arena/Compute workers);
2. Diligence QVL;
3. Arena QVL;
4. execution-policy anchor-writer QVL;
5. Compute-workload QVL;
6. Compute-metering QVL; and
7. the independent deterministic Compute meter.

The five QVL CVMs have distinct app/CVM/compose identities, release policies,
and policy-derived signing roots. A verifier may reuse the reviewed QVL image,
but image reuse never collapses operator custody or trust roots. The Diligence
QVL also evaluates the secondary `email_oracle_kms_restart` profile. That
profile is separately policy-scoped but intentionally does not create a sixth
root or eighth CVM.

Every production QVL decision uses signed challenge schema v2 and the active
independent verdict schema/signing domain v4. The QVL issues an authenticated,
signed, random, single-use challenge for one profile and policy with a lifetime
of at most 120 seconds. Quote report data is exactly 64 bytes: one static
release-context digest and one challenge digest. Intel DCAP appraisal must
complete strictly before challenge expiry; success, rejection, timeout, or
cancellation closes the challenge. A stale, concurrent replay, wrong-profile,
wrong-policy, expired, or consumed challenge fails closed. A QVL identity
response or self-attestation does not make its root trusted; operators
independently verify the QVL's own platform and release evidence before adding
that root to the external allowlist.

Historical intermediate protocol note, 2026-07-21: an earlier source
transcript described `dnai.independent-tdx-verdict.v3` and exact
`dnai.compute.workload-recipient-activation.v2`. That v3/v2 wording is retained
only to interpret the intermediate transcript. It is not an active-release
acceptance rule and cannot authorize a current activation.

Active protocol supersession, 2026-07-21: every consumer accepts only
`dnai.independent-tdx-verdict.v4` under signing domain
`dnai-wikigen/independent-tdx-verdict/v4\0`. The v4 verdict repeats the exact
chain/domain/CVM, deployment-intent, release-authority, ceremony-nonce,
measurement-policy, profile, policy, challenge, evaluated identity, and
timestamps. It also carries the separately reviewed exact 900-second
activation-evidence lease. The lease begins only after the in-window appraisal,
may outlive the already consumed challenge, and is policy-bounded activation
authority—not renewed challenge freshness. Post-restart Compute recipient
activation is exact schema `dnai.compute.workload-recipient-activation.v3`
with an explicit recipient-evidence lease of at most 300 seconds. Its stable
recipient-release commitment deliberately remains
`dnai.compute.workload-recipient-release.v2`; activation v1, active verdict v3,
and release-commitment v1 are rejected. This correction does not change the
deployment-status statement below.

No part of this decision is a deployment claim. The current working tree has
not broadcast the fresh suite or deployed these seven CVMs.

## 2026-07-16: Exact Tinker Release And Dual-RPC Email Boot Authorization

Status: `[real source and local rehearsal; deployment pending]`

Decision:

A fresh `TinkerAccountEncumbrance` starts emergency-halted. One exact nonzero
account commitment, two per-operation caps, one approved compose, and one
distinct manager are proposed as a complete policy. After the immutable two-day
review, activation atomically installs the policy, freezes the release baseline,
clears pending state, and only then unhalts. After freeze, governance may lower
caps, revoke the manager/compose, or halt forever; it may not add or replace
authority, raise a cap, or resume a halted release. The contract never holds
Tinker credentials, card data, provider balance, or user funds.

Email boot/OTP authorization requires the fixed caller capability label
`tinker-delegate.signup`, the same-CVM dstack-derived bearer, and exact on-chain
consumer/app/compose authorization. The label alone is not service identity.
Two HTTPS Base Sepolia RPCs with different normalized hosts must agree on one
fresh finalized block, its hash/parent/timestamp, the exact `EmailOracleAuth`
runtime code, `releaseConfigurationReady()`, and
`isConsumerAuthorized(appId, composeHash)`. The runtime rechecks the block after
contract calls and atomically advances a persisted checkpoint before allowing
the request.

The checkpoint protects ordinary requests and restarts while its volume is
preserved. It is not hardware-backed anti-rollback: restoring the entire
persistent volume can restore the checkpoint. The Diligence QVL's separate
Email/KMS restart profile supplies bounded restart evidence, but it does not
erase that storage assumption.

## 2026-07-21: Royalty UI Is Read-First And Claim-Only

Status: `[real source; fresh contract deployment pending]`

Decision:

The browser may inspect a connected wallet's native ETH and canonical Base
Sepolia USDC pull balances, inspect the exact replay slot for one
`(distributor, queryRef)` pair, and withdraw only the connected wallet's own
nonzero balance after the configured `RoyaltyDistributor` runtime code hash
matches at a pinned block.

The browser does not expose `distributeNative` or `distributeERC20`. The
contract enforces conservation and replay protection for a caller-supplied
split, but it cannot determine ownership, validate a query, set a royalty
price, or justify an allocation. Distribution stays unavailable until a
separate independently justified allocation source and review flow exist.

## 2026-07-21: V1 Compute Funding Uses Exact-Asset Pay-As-You-Go

Status: `[real product decision; provider execution remains activation-gated]`

Decision:

The first production Compute lane uses `ComputeCreditVault` directly. A user
deposits native ETH or the one release-pinned ERC-20, authorizes one job with an
asset-denominated maximum debit, and retains the same-asset claim on everything
not settled. Independent metering may never debit more than the signed maximum.
There is no minted token, exchange rate, oracle conversion, or automatic
provider-account top-up.

The off-chain service-credit ledger is a noncash test-grant lane only for v1.
Credits may be issued by a bounded testnet operator grant, are non-transferable
and non-redeemable, and must not be presented as purchased value. They never
convert into vault assets or represent a claim on Thinking Machines.

Hosted checkout, purchased service credits, and user card funding are outside
v1. If a later release adds them, the payment provider must collect card data
on its own hosted origin and a verified signed webhook must authorize any
closed-loop credit issuance. Wikigen continues to reject raw card payloads.

Rationale:

- Same-asset reserve, debit, release, and withdrawal avoid pretending that a
  volatile asset or test token has a fixed compute exchange rate.
- The on-chain authorization can bind project, job, recipe, policy, maximum
  debit, expiry, and nonce without granting an agent general wallet authority.
- Keeping noncash grants separate preserves a useful test lane without making
  them look like customer funds or a speculative token.

## 2026-07-16: Exact-Asset Capacity And Service Credits Are Separate Ledgers

Status: `[real source for the separate ledgers; hosted checkout roadmap]`

Decision:

`ComputeCreditVault` records non-transferable claims in the exact asset a wallet
deposited: native ETH or the one release-pinned ERC-20. It has no oracle, FX,
synthetic compute unit, mintable token, or automatic conversion into service
credits. A user retains a separately verified withdrawal path even when job
authorization is unavailable.

Closed-loop service credits are off-chain, non-transferable usage units. The
2026-07-21 v1 decision narrows them to operator-granted noncash test units. They
are not an ERC-20, redeemable claim, investment asset, or representation of a
vault deposit. The current UI may model their reservation/settlement lifecycle,
but it must not imply that ETH/USDC deposits mint them or that either ledger
directly tops up the sealed upstream Tinker account.

Customer card funding remains outside v1. If implemented later, a provider-hosted
checkout collects card details outside Wikigen, and a verified signed webhook
may issue service credits after payment confirmation. The static frontend and
Wikigen services do not collect, proxy, log, or store raw card details for that
product path.

## 2026-07-08: Result-Submission Quote Verification Path

Status: `[partial]`

Decision:

`DiligenceRoom.submitResult()` quote verification will proceed in two stages.

1. `[real]` In dstack mode the submitter derives the Ethereum signer inside the
   TEE and fetches a signer-produced evidence envelope whose `report_data`
   binds the signer address, chain ID, and DiligenceRoom contract address. That
   envelope is checked for internal consistency only. It is evidence transport,
   not an Intel TDX verification verdict.
2. `[real]` `DiligenceRoom.sol` requires a configured result-verifier
   signature before accepting `submitResult()`. The authorization binds chain
   ID, contract address, deal ID, TEE identity, compose hash, score band,
   deterministic compute tariff, contract-derived canonical public result
   commitment, and authorization expiry.
3. `[real]` Before spending gas, the production submitter reads the immutable
   on-chain `resultVerifier`, requires it to differ from the TEE signer, and
   recovers the exact authorization signature over the chain/contract/deal/
   result context. A service-produced quote envelope or self-signature cannot
   pass this gate. Only injected test custody on chain 1337/31337 has an
   explicit, publicly labeled local-test bypass.
4. `[partial]` The bounded receipt records the signer attestation hash,
   normalized report data, quote size, compose hash, signer address, chain ID,
   contract address, canonical public result commitment,
   authorization expiry, verifier-signature hash, on-chain verifier address,
   and whether that signature was authenticated. This remains bounded audit
   evidence and does not itself prove Intel TDX.
5. `[partial]` `tinker_delegate.result_verifier` implements the policy/signature
   core but now refuses production authorization from bounded service evidence
   alone. It additionally requires a fresh `intel_tdx_dcap_qvl` verdict bound to
   the same quote hash, report data, compose/app/OS identity, signer, chain, and
   contract; the verdict must be signed by a policy-trusted address distinct
   from the evaluated TEE signer. False, expired, forged, self-asserted, and
   context-mismatched verdicts fail closed.
6. `[partial]` The operator CLI path wraps this module:
   `result-verifier-address` emits the dstack-derived verifier address, and
   `authorize-result` requires both bounded signer-evidence JSON and a signed
   independent-verdict JSON plus explicit trusted verifier/identity allowlists
   before returning the contract signature. No CLI production bypass exists.
7. `[partial; source complete, deployment pending]` The separate
   `⚙️/attestation-qvl` service runs the official `dcap-qvl` verification
   surface against the compiled Phala PCCS origin, enforces a canonical
   read-only release policy, rejects debug/unsafe TCB postures, and signs a
   bounded verdict with a policy-rotating dstack-derived key. It has no
   production bypass and runs in a different CVM trust domain. Real
   measurements, a registry-pinned image, an independently reviewed verifier
   root, and a live Intel quote/collateral proof are still required before the
   repo can claim production quote verification or submit a live result.
8. `[real source; deployment pending]` Governance approval planning consumes
   the complete signed QVL verdict directly. It requires externally supplied
   trusted-verifier roots plus exact chain, contract, TEE signer, compose, app,
   OS, and quote pins; recomputes canonical report data and verdict digest; and
   enforces signature independence and freshness before emitting any calldata.
   Authorization-summary booleans are never accepted as governance evidence.

Rationale:

- The dstack SDK transports quotes but does not independently establish their
  trust. The separate QVL service uses `dcap-qvl` for quote/collateral
  verification and must remain outside the evaluated CVM. Local unit and image
  tests are not a substitute for a fresh production quote and policy proof.
- The pre-broadcast gate prevents malformed or self-signed result
  authorizations from reaching the chain, but the configured independent
  verifier remains responsible for the Intel DCAP/QVL trust decision.
- `DiligenceRoom.sol` now has the verifier-signature hook, which intentionally
  breaks the previous deployed ABI. Fresh deployments must configure
  `DILIGENCE_RESULT_VERIFIER` or explicitly accept the deployer as the local
  smoke-test verifier.

Open follow-ups:

- `[real]` Add a verifier signature format for result submissions.
- `[real]` Add contract enforcement so a bogus bare `teeIdentity` cannot submit
  without a verifier authorization.
- `[real]` Require an authenticated independent-verifier verdict before the
  bounded policy/signature core can authorize a production result.
- `[real]` Wrap the verifier module as a bounded operator CLI path.
- `[real source; deployment pending]` Build the independent DCAP/QVL verifier
  as a bounded service with a reproducible, non-root image and networkless
  policy initializer.
- `[planned]` Publish and provenance-verify the QVL image, deploy a dedicated
  non-dev Phala CVM, authenticate its dstack-derived root, and issue fresh
  Diligence/Arena verdicts from distinct policy roots.
- `[planned]` Repeat the proof from a deployed Phala CVM, not only the local
  simulator.

## 2026-07-11: Historical Main-Runtime Layout — Combined Services

Status: `[historical; superseded as the complete release topology]`

Decision:

Run the email-oracle and the tinker-delegate as one combined dstack CVM for
now, not two separately-attested CVMs. Live evidence (2026-07-11): app
`f6a3219…` / CVM `cvm_1w85mGjo` serves the oracle (port 8000), the delegate
(port 8080), and the Neko/Playwright browser sidecar (9222/52000) under a single
app id and one compose hash, reachable on the `dstack-pha-prod9.phala.network`
gateway.

This remains the logical composition of the new **main runtime only**. This
paragraph records the superseded topology as it stood on 2026-07-16; its former
four-QVL/six-deployment count is not a current release instruction. The current
decision requires five independent QVL CVMs, the independent Compute meter,
and the main runtime: exactly seven fresh CVMs. The 2026-07-11 app/CVM is
historical and is not one of those seven fresh deployments.

Rationale:

- A single CVM lets the delegate reach the oracle's OTP path and the browser
  sidecar over the pod-internal network without cross-CVM RA-TLS, which is not
  built yet.
- The cost is a coarser trust boundary: oracle and delegate share one
  measurement, so a compromise of either is a compromise of both, and
  same-CVM derived-key bearer auth substitutes for attested cross-service auth.

Open follow-ups:

- `[planned]` Split into per-service CVMs with RA-TLS or attestation-backed
  signed requests once the combined flow is proven end to end (see
  `EmailOracleAuth Completion` split-CVM item in `TODO.md`).
- `[partial]` The current CVM still runs `dstack-dev` with `public_logs=true`
  and `os.is_dev=true` — a debugging posture, not production isolation.

## 2026-07-11: Funding Rails — Encumbrance-Gated Browser-Mediated Top-Up

Status: `[historical operator-validation path; not the customer funding model]`

Decision:

Tinker compute is funded by a developer prefund: card details are encrypted to
the TEE, entered through the CVM-held Neko browser session, and converted to a
Tinker balance. Every paid operation is gated on-chain by
`TinkerAccountEncumbrance` (approved compose hash, per-op add-balance cap, spend
cap, emergency halt) before any decryption or browser automation runs. Buyer
compute deposits and developer fees settle through `DiligenceRoom` escrow,
kept conceptually separate from the Tinker account top-up rail.

The 2026-07-16 funding decision supersedes this as product UX: exact-asset vault
capacity and off-chain service credits stay separate, while customer card
funding requires provider-hosted checkout and a verified webhook. Raw-card
browser automation is retained only as historical, capped operator-validation
evidence and must not be exposed as a user funding flow.

Rationale:

- Keeping card material encrypted-to-TEE and gating spend on a frozen on-chain
  policy means no human operator and no unapproved measurement can move money.
- Browser-mediated entry is a bridge until a first-class payment API path
  exists; it is why the Neko sidecar shares the CVM.

Open follow-ups:

- `[partial]` One-off low-value real funding is proven (bounded `$10.00`
  balance read); repeated/production funding, A2A/ACH/card automation, and
  connecting Tinker spend to buyer escrow + developer fee remain open
  (`Milestone 1` funding-rail items in `TODO.md`).
- `[planned]` Emit on-chain events for every funding operation
  (requested/authorized/attempted/succeeded/failed/card-destroyed).

## 2026-07-11: Data Locality — Sealed At Rest, Plaintext Only In Boundary

Status: `[partial]`

Decision:

Private data (reward datasets, artifacts, credentials) may be stored on
untrusted hosts only as ciphertext; plaintext exists only inside the attested
boundary. Datasets use envelope encryption (per-dataset DEK, chunked
AES-256-GCM, DEK wrapped to attestation-bound CVM keys) with a bounded,
owner-signable manifest; artifacts are encrypted to the TEE public key with
per-deal/per-artifact HKDF context and never touch disk unencrypted; OTP-replay
and API-key state persist only through sealed stores.

Rationale:

- This is what lets reward datasets live on Hugging Face / S3 / IPFS while the
  reward oracle stays private, and what lets the diligence room hold an artifact
  without a human seeing it.
- Storage backends are deliberately orthogonal to the crypto path, so adding a
  host never touches encryption.

Open follow-ups:

- `[partial]` The unwrap key is not yet bound to an approved CVM measurement via
  cryptographic TDX quote parsing, so the store stays `[partial]` and inherits
  the attestation + compose-approval chain (shared blocker with quote
  verification). Recipient custody today is a local key file, not dstack-derived.
- `[planned]` CVM-side fetch → sealed-volume write → buffer-zero wiring, and a
  neutral sealing witness for adversarial buyer/seller pairs.

## 2026-07-11: Frontend Deployment Target

Status: `[partial]`

Decision:

The product UI now lives in `web/` as a SolidJS/Vite application and targets
Cloudflare Pages. It implements wallet-scoped Base Sepolia flows, the salted
artifact-commitment v2 recovery-receipt flow, ciphertext-only artifact ingress,
bounded public evidence surfaces, and explicit live/modeled/roadmap labels.
Confidential mutations fail closed unless the build contains independently
approved quote and deployment-policy pins; a service-produced quote envelope is
never treated as Intel TDX verification.

The initial product had nine canonical hash routes. The current source product
has eleven: Overview, Arena, Diligence Rooms, Release Review, Data Vaults,
Compute, Delegated Tinker Account, Safeguards, Capabilities, Verify, and
Collaborate. Release Review is deliberately source-modeled until an
authenticated reviewer backend and pinned threshold authority exist. The
Tinker route documents the full customer lifecycle but leaves account,
funding, delegation, and dispatch mutations release-gated until the fresh
contract/CVM release is active. EIP-6963 discovery plus a compatible injected
EIP-1193 fallback covers browser wallets such as MetaMask, Rabby, and Coinbase
Wallet. WalletConnect is a conditional public connector: the UI labels it
unavailable when the deployment does not provide a project ID. Wallet
connection identifies an address and network; it does not replace the separate
one-time, chain-bound service-auth challenges that establish service authority.

Rationale:

- The trust story only holds if the buyer's own client verifies attestation;
  putting verification in the frontend (not the server) keeps the boundary
  honest.

Open follow-ups:

- `[partial]` Cloudflare Pages is the static deployment target. Production
  artifact ingress still requires a fresh project-owned CVM, exact CORS/CSP
  origins, non-dev Phala OS, private debug surfaces, and an authenticated
  independent Intel DCAP/QVL verdict pipeline that generates the release pins.

## 2026-07-13: Artifact Integrity — Salted Commitment V2 Only

Status: `[real]`

Decision:

Keep the `DiligenceRoom.createDeal(..., bytes32 artifactHash, ...)` ABI, but give
that field one versioned meaning:

```text
keccak256(
  ASCII("dnai-wikigen/artifact-commitment/v2")
  || 0x00
  || secret32
  || exact raw artifact bytes
)
```

`secret32` is exactly 32 cryptographically random bytes. Empty artifacts are
invalid. The seller keeps a strict private recovery receipt with exactly
`schema_version`, `scheme`, `artifact_commitment`, and `commitment_secret`; the
secret is not published on-chain. The TEE-encrypted plaintext is only
`ASCII("dnai-wikigen/artifact-wrapper/v2") || 0x00 || secret32 || rawArtifact`.
Raw unwrapped artifacts and legacy `keccak256(rawArtifact)` commitments have no
compatibility path.

The chain watcher forwards the commitment emitted by `DealCreated` into an
immutable `DealContext`. Ingress compares caller metadata with that on-chain
value before decryption, authenticates the deal ID and commitment in both HKDF
context and AES-GCM AAD, decodes the v2 wrapper, and recomputes the commitment
before accepting custody. The control plane recomputes it again immediately
before evaluator code receives the bytes.

Rationale:

- A public raw hash permits dictionary confirmation for low-entropy artifacts;
  the private random secret makes the on-chain commitment hiding as well as
  binding for practical purposes.
- Checking only a caller-supplied hash is insufficient: an authenticated seller
  could otherwise commit artifact A on-chain and upload a self-consistent
  artifact B. Carrying the event commitment through the watcher closes that gap.
- Domain and wrapper versioning make cross-protocol interpretation explicit and
  allow future schemes to be introduced without silently weakening v2 deals.

Verification:

- Python and Solidity share a fixed cross-language vector for secret bytes
  `00..1f` and artifact `test-artifact`, yielding
  `0x0f5dd8f2c3fba9bcd4d19565c66257757094f11017d8f3fdd264c7b0b5156d80`.
- Backend regressions cover malformed receipts, wrong secrets, raw-wrapper
  downgrade attempts, cross-deal ciphertext replay, pre-decrypt A-versus-B
  rejection, and in-memory mutation immediately before evaluation.

Open follow-ups:

- `[planned]` Bind the finalized browser implementation and recovery-receipt UX
  into an independently verified production TDX quote policy. Local passing
  tests do not turn illustrative or self-reported quote fields into Intel DCAP
  verification evidence.

## 2026-07-13: Escrow Result Hash Is Contract-Derived Public Policy State

Status: `[real source; deployment pending]`

Decision:

`DiligenceRoom.submitResult` accepts only deal ID, bounded score band,
deterministic public compute tariff, compose hash, authorization expiry, and the
independent verifier signature. It does not accept an evaluator/caller result
hash. The contract computes and stores:

```text
keccak256(abi.encode(
  keccak256("DiligenceRoomPublicResult(uint256 chainId,address contractAddress,uint256 dealId,address seller,address buyer,uint256 reservePrice,uint256 budgetCap,uint256 expiry,bytes32 artifactHash,address teeIdentity,bytes32 composeHash,uint8 scoreBand,uint256 computeCost)"),
  chainId, contractAddress, dealId, seller, buyer, reservePrice, budgetCap,
  expiry, artifactHash, teeIdentity, composeHash, scoreBand, computeCost
))
```

Fresh suites permanently enable the on-chain compute-settlement policy and
freeze the 1% fee. Both the verifier and submitter refuse contracts where the
compute policy is not enabled, derive the fixed tariff from public deal state,
and recompute the exact contract hash. Payload result hashes and private reward
transcript commitments remain off-chain evidence; neither can modulate escrow
state or enter the production transaction/receipt path.

Rationale:

- An evaluator-selected exact meter or opaque hash is a high-cardinality covert
  channel from private artifact processing into public chain state.
- A contract-derived commitment has one auditable preimage and cannot be swapped
  by the TEE, verifier, CLI, or relayer.
- The immutable funded-deal fields provide replay/domain context without relying
  on a transaction nonce that is invisible to contract policy.

Verification:

- Solidity and Python share a hard-coded Base Sepolia vector whose canonical
  hash is
  `0xdc2e6afe425b011e7c7e7ca010798dd614579111df20a146fc98d297d279ee37`.
- Unit, fuzz/invariant, dstack-simulator-to-Anvil, and synthetic-room settlement
  proofs verify deterministic compute rejection and verifier/receipt/event hash
  equality.

## 2026-07-13: Email Oracle Pin Endpoint Is A Fixed OTP Capability

Status: `[real source; deployment pending]`

Decision:

Runtime bearer auth and the on-chain consumer registry are necessary but do not
grant a consumer general mailbox-search authority. `POST /pin` is restricted to
the Tinker service, the exact `no-reply@thinkingmachines.ai` sender, no subject
filter, and one fixed six-digit OTP pattern. The IMAP layer rechecks the parsed
sender address before body inspection. Caller-selected regexes, sender/subject
widening, other services, and unknown fields fail before mailbox access.

The response contains the six-digit OTP required by the internal signup flow,
but returns only hashes for email ID, subject, sender, and oracle mailbox. Replay
state is sealed and persisted before the OTP is released.

Rationale:

- An authenticated but compromised consumer must not be able to turn the oracle
  into a mailbox-exfiltration or regex-denial-of-service primitive.
- Returning raw message metadata is unnecessary for OTP entry and widens the
  private-mail boundary without product benefit.

## 2026-07-14: Diligence Admission Is A Closed Release Set

Status: `[real source; deployment pending]`

Decision:

Each new `DiligenceRoom` starts fail-closed with mandatory compose and TEE gates,
zero active admissions, and zero pending admissions. A compose proposal waits an
immutable two-day timelock before activation. Only then may the exact TEE
identity-to-compose binding be proposed; it waits a second two-day timelock.
Release activation requires exactly one active compose, exactly one active TEE
identity, zero pending proposals, and permanent freezes on both addition paths.

Revocation remains callable as an emergency kill switch and immediately blocks
new use of the revoked identity or compose. It does not reopen additions. A
replacement CVM identity, compose rotation, or new release therefore requires a
fresh DiligenceRoom rather than expanding the admission set behind an address
users already approved.

Rationale:

- A frozen gate with a mutable allowlist does not bind an address to one reviewed
  release; governance could admit an unreviewed CVM after browser authorization.
- Exact active and pending counters prevent historical, duplicate, or staged
  entries from being hidden alongside the expected binding.
- Sequential timelocks make both the execution measurement and its signer
  binding observable before activation.
- Emergency revocation must fail closed without creating a privileged rotation
  path that bypasses the original review and release ceremony.

Verification:

- Foundry unit, fuzz, and invariant tests enumerate a finite candidate set and
  prove exact active/pending counters, binding consistency, permanent closure,
  and fail-closed revocation.
- The release configurator enforces the three exact phases and the web gate
  independently reads the complete closed-set tuple at one pinned block before
  enabling or prompting any contract write.

## 2026-07-15: Execution-Policy PASS Requires An External Monotonic Anchor

Status: `[real source and local rehearsal; Base Sepolia/runtime activation pending]`

Decision:

Execution-policy decision records use a fresh `ExecutionPolicyAnchor` as their
external rollback witness. The contract maintains one compare-and-set global
sequence/hash chain, one latest decision head per resource, and a one-time
sequence for every decision digest. It stores only public deterministic
commitments, never raw policy inputs or private artifacts.

Fresh anchors are paused with no writer. The final CVM-controlled writer and its
exact release commitment wait through a two-day timelock. Activation permanently
freezes writer rotation before unpausing; a release or writer change therefore
requires a new anchor. The owner or active writer may emergency-pause, while
only the owner may resume the already-frozen release.

An off-chain PASS is not executable merely because it exists in the local
append-only store. The runtime must serialize writes, persist a pending record,
anchor its exact decision hash, wait for the release-pinned Base Sepolia
confirmation policy, reconcile the on-chain global/resource heads, and only
then mark the record executable. Every protected operation rechecks that the
latest local resource head matches finalized chain state.

Approval schema v3 also commits one explicit `execution_context_hash`. For
exact-asset Compute it is derived only from the authenticated dispatch journal
and release-pinned compiled recipe; for the modeled service-credit lane it is
derived from the immutable authoritative job and reservation projection. The
caller cannot provide that value. The execution lease recomputes and compares
it before mutation, so reusing the same public resource ID with different
intent, recipe, actor, cap, environment, or reservation metadata cannot inherit
an older PASS. Deal and Arena use the reviewed zero-context sentinel in this
release because their release-scoped resource identity remains their complete
execution binding.

Writers and executors coordinate through the same OS-backed policy lease. A
writer holds the exclusive lease from chain preflight through journal append,
anchor finalization, and local finalization. A deal, Arena, or Compute executor
holds a shared lease from its fresh PASS check through the first irreversible
operation (or the full crash-recoverable execution cycle). A revocation that
races an already authorized cycle waits or fails closed; it cannot become
durable between the check and mutation and then be ignored. The next cycle sees
the newer hold or deny.

The chain witness uses the older of the configured confirmation-depth boundary
and the release-pinned RPC's `finalized` block tag. All code and storage reads
are pinned to that one canonical block. This is explicitly a
single-RPC-reported finalized witness, not independent RPC quorum, a light
client, or a consensus-authenticated storage proof. The longer operational
block-age allowance accounts for Base's finalized-tag lag and does not weaken
the exact candidate-block pin.

Writer custody is admitted only with independent evidence. A one-shot command
inside the real dstack CVM derives the purpose-separated writer, commits the
writer, anchor, writer-release commitment, key path, and custody class into
quote report data, and sends the raw quote over bearer-authenticated HTTPS to a
separate QVL. The bounded canonical artifact contains the quote hash/size and
signed verdict, never the quote or key. Release tooling verifies the exact
artifact bytes, report-data derivation, QVL signature, distinct release-pinned
QVL trust domain, writer, and CVM identity before it can promote the anchor.

Rationale:

- A valid HMAC-protected file can still be rolled back to an older valid
  snapshot by infrastructure with storage access.
- Global and per-resource compare-and-set inputs prevent concurrent writers or
  stale processes from silently creating forks.
- Binding chain ID, contract, writer, and writer-release commitment into every
  global head prevents cross-release evidence reuse.
- Binding a server-derived execution context into every Compute signature and
  record prevents a stable job ID from substituting different executable
  metadata after approval.
- Permanently closing writer admission makes an already-approved anchor address
  mean one reviewed release, not a mutable governance allowlist.

Verification:

- Foundry unit and fuzz tests cover authority, timelock, freeze, pause,
  ownership, replay, exact global/resource CAS, domain binding, and non-custody.
- Stateful invariants execute 128,000 calls per run and prove global/reference
  model parity, non-regressing resource heads, and frozen release authority.
- The local Anvil fresh-suite rehearsal proves exact runtime bytecode for all
  seven contracts, activates the synthetic writer after the timelock, freezes
  it, and anchors one decision at sequence 1.
- Cross-process and adversarial tests cover competing coordinators, a persisted
  record racing anchor finalization, revocation racing deal/Arena/Compute
  execution, exact-resource/different-context replay, a stale valid HMAC
  journal, a mismatched resource head, finalized versus depth selection, and
  ambiguous provider recovery.
- An anchor event is explicitly not TDX/QVL evidence. Fresh Base Sepolia
  deployment, distinct-role provisioning, independent QVL deployment, and live
  CVM execution remain release requirements.
