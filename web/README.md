# Wikigen product frontend

The SolidJS application for attested diligence rooms, sealed challenge environments, bounded compute, scoped proxy credentials, funding previews, safeguards, verification, and multi-owner collaboration.

The frontend uses three explicit product states:

- **Live** — backed by the currently configured project-owned contract or service and checked at runtime.
- **Modeled** — a real interaction design or deterministic local primitive without a production mutation path.
- **Roadmap** — a proposed capability with no deployed backing service.

A modeled receipt is never presented as Intel TDX evidence. The safeguards simulator uses the literal `modeled-receipt:` marker and `illustrative-only:not-a-tdx-quote` measurement.

## Product surfaces

The product has twelve canonical hash routes, including the modeled Health
Guide. The separate `#/not-found` entry documents the fail-closed routing
boundary and is not a thirteenth product surface.

| Hash route | Surface | Current behavior |
| --- | --- | --- |
| `#/` | Overview | Runtime deployment readiness, trust architecture, and product entry points |
| `#/health` | Health guide | Modeled, non-diagnostic, page-memory-only evidence navigator; this release accepts no health data and does not run a live LLM |
| `#/arena` | Challenge arena | Canonical DNASeq Safe-IR challenge plus modeled Bio/DNA briefs, ciphertext-only ingress, bounded Ladder ranks, and per-row execution provenance |
| `#/deals` | Diligence rooms | Reads and writes the fresh `DiligenceRoom` contract when configured; otherwise renders an explicit modeled preview, including a bounded lifecycle that does not infer private worker telemetry |
| `#/review` | Release review | Source-implemented, release-gated hash-only API/UI with strict schema parsing, wallet-signed release/deny decisions, private M-of-N reviewer resolution, and a browser-rechecked finalized Base Sepolia rollback witness; an explicitly modeled desk remains when the immutable frontend/CVM release is not configured, while internal enqueue and expiry keep their runtime bearer outside the browser and production reviewer custody/notification remain unactivated |
| `#/vaults` | Data vaults | Modeled governed datasets, version lineage, consent/usage boundaries, and sealed-data publication workflow |
| `#/compute` | Compute console | Wallet-owned projects and proxy credentials; authenticated service-credit job records and cancellation remain distinct from release-held browser reservation creation and from release-gated exact-asset funding, authorization, dispatch, metering, settlement, and proven onchain exits |
| `#/tinker` | Delegated Tinker account | Live-capable, release-gated wallet lifecycle for account requests, durable status recovery, training-only credential issue/list/rotation/revocation, terminal account cancellation/revocation, and an at-most-once bounded built-in training submission, plus a read-only finalized-block `TinkerAccountEncumbrance` inspector; account activation and provider funding remain outside the browser, while authenticated API execution receipts distinguish settled, pre-dispatch released, and reconciliation-held authority from provider billing and explicit handoffs open the purpose-separated Compute tabs |
| `#/safeguards` | Safeguards lab | Release-gated execution-policy operator and bounded status readback plus a separate deterministic browser-local simulator with modeled receipts; neither is presented as TDX evidence |
| `#/capabilities` | Capability catalog | Per-card roadmap/modeled labels, locality catalog, pipeline registry, execution architecture, and developer path; no live health-data service directory is claimed |
| `#/verify` | Trust center | Six-level evidence vocabulary, one-block bytecode presence and optional runtime-code-hash observations, bounded application-envelope checks, local receipt-shape classification, and finalized-block EmailOracleAuth/KMS dynamic-readiness diagnostics; it does not verify Intel collateral, QVL signatures, or release policy, and the Email panel does not validate historical KMS receipts or restart proofs |
| `#/collaborate` | Multi-owner collaboration | Source implements the coordination, execution, reservation, wallet-settlement, reconciliation, and recovery rails. The current unsigned/dev release has no activated Collaboration witness, per-job TDX/QVL evidence, or live payment/settlement effects; the failure lab remains modeled. Local HMAC mode is explicitly non-monotonic, while live dstack mode requires the browser-validated release-bound Base Sepolia `ExecutionPolicyAnchor` witness under a single-RPC reported-finalized model. |
| `#/not-found` | Route boundary | Explicit unknown-route surface; it never silently substitutes Overview or starts a wallet, upload, or service action |

### Human Review source and activation boundary

The Review service and SolidJS client are implemented, not merely wireframes.
The service exposes a rate-limited public hash-only queue, runtime-authenticated
internal enqueue/expiry, one-time allowlisted reviewer-wallet challenges, and
signed release/deny decisions. It privately resolves the reviewer against the
release roster, rejects self-review and duplicate votes, and releases only when
the role-specific M-of-N threshold is met; any deny fails closed. Before the UI
enables a signature, it matches the immutable frontend/runtime release and
rechecks the queue's release-pinned finalized Base Sepolia rollback witness.

Those source capabilities are not evidence that production reviewer authority
is active. The current release still needs a fresh deployed reviewer roster and
key-custody boundary, notification wiring, and a scheduled conservative expiry
worker. When the release pins are absent, the UI displays a modeled desk and
records no decision.

### Collaboration source and activation boundary

The Collaboration service and SolidJS client implement the persistent
wallet-authenticated schema-v2 authority: durable room creation/listing,
invitee-owned accept/decline, creator cancellation, owner-role
activation/revocation, exact-current-query proposals and owner grants, bounded
snapshot-consistent pagination, exact idempotent recovery, joint-consent
snapshots, and explicit quiescent archive. The feature is independently
release-gated by `requested_features.collaboration`.

Rollback truth is mode-specific and parsed fail-closed. Local HMAC
current-state mode is tamper-evident but explicitly non-monotonic. Live dstack
mode requires a release/project/wallet-domain-bound Base Sepolia
`ExecutionPolicyAnchor` witness before wallet auth, reads, or mutations under
the explicit single-RPC reported-finalized model. That is not RPC quorum or a
consensus proof. The client accepts the live label only after strict exact-key
parsing, the shared finalized-anchor checks, release-pin matching, derived
`collaboration_state` resource-hash verification, decision/head/sequence
linkage, and consistent witnesses across list, room, and nested-query
projections. Unknown, conflicting, unavailable, or regressed evidence fails
closed. No fresh release has activated this live authority or produced current
witness evidence.

Coordination signatures alone remain coordination authority, not confidential
execution or spending authority. Source now implements the one-run plan,
challenge, authorization, status, worker handoff, exact reservation/refund,
settlement, reconciliation, and withdrawal rails. The current unsigned/dev
release keeps every mutation gate closed: it has no activated Collaboration
witness, per-job TDX/QVL verdict, or live payment/settlement effect. Browser
DTOs never unlock the worker, and the adjacent failure lab remains modeled.

### Modeled Health Guide evidence boundary

The Health Guide is a deliberately static worked example. It accepts no health
record, has no text prompt or upload intake, calls no health model, writes only
to SolidJS page memory, and clears on reload. It can organize questions and
attach evidence labels, but it cannot diagnose, triage severity, recommend a
treatment, or turn a proprietary trend into clinical evidence. Selecting a
listed emergency warning sign stops product discovery and points to local
emergency services. The listed signs are explicitly a short, incomplete screen:
the always-visible warning says that denying them cannot rule out an emergency.

Its FitBiomics/V•Nella card is a dated source snapshot checked **2026-07-22**,
not a live evidence feed. Product-performance language is attributed to the
manufacturer. [ClinicalTrials.gov NCT06141343](https://clinicaltrials.gov/study/NCT06141343)
is marked completed with 153 enrolled and no registry results posted. A
[FitBiomics-funded trial preprint](https://www.medrxiv.org/content/10.1101/2025.11.03.25339441v2)
reports no between-group difference on its prespecified MFI fatigue outcomes,
while some secondary longitudinal self-reports favored *V. atypica*; the
preprint has not been peer reviewed. A separate
[peer-reviewed seven-person pilot](https://pubmed.ncbi.nlm.nih.gov/38222109/)
found no between-group difference in exhaustion time and no lactate change,
and reported that supplementation was well tolerated. The UI discloses that
this evidence stream is industry-linked, including founder, employee, equity,
advisory, and patent interests. The
[NIH evidence summary](https://www.nih.gov/news-events/nih-research-matters/bacteria-enriched-marathon-runners)
also explains that the reported performance intervention in the 2019 research
was in mice and that more study is needed. None of these findings is presented
as treatment evidence for persistent fatigue. The regulatory label follows the
[FDA explanation](https://www.fda.gov/consumers/consumer-updates/it-really-fda-approved)
that FDA does not approve dietary supplements for safety and effectiveness.
Fatigue and travel routes link to current NIH/NLM and CDC sources for the user
to inspect directly. The regulatory lane is labeled a static source review—not
a comprehensive FDA product search—and the unfetched CDC route is labeled
time-sensitive rather than real-time.

### Deal Room bounded lifecycle

The lifecycle panel names the complete user journey—ciphertext, queued,
awaiting policy, running, bounded result, and settled/expired—while projecting
only public chain state and the current tab's authenticated upload
acknowledgement. An accepted ciphertext response does **not** prove that a job
is queued, has passed policy, or is running. Those phases remain explicitly
`unobserved` until the runtime exposes a separately authorized bounded status;
the browser waits for the result commitment on Base Sepolia.

If a ciphertext POST may have crossed the network boundary but its response is
uncertain, the exact original artifact and private recovery receipt remain
locked in tab memory. The only retry action resends that retained pair. The UI
also distinguishes pre-POST failure, retry in progress, committed bounded
result, buyer decision, and terminal expiry without inventing timing or CVM
evidence.

The canonical Arena URL is versioned and shareable:
`#/arena/dnaseq-variant-qc-safe-ir/1.0.0?tab=rankings`. The `tab` value may be
`rankings`, `queue`, `submissions`, or `spec`; malformed or ambiguous deep links fail
closed instead of silently selecting another challenge. Worker presence and
row evidence are separate signals. A fresh authenticated heartbeat can say a
release-bound worker is present, while each ranking or submission remains
`modeled` until that exact row carries bounded worker-reported provenance.
The worker-capability response is exact schema v2: the browser recomputes its
complete release-binding and heartbeat-binding SHA-256 commitments and rejects
schema v1 rather than synthesizing missing fields. Public submission, queue,
leaderboard, and authenticated owner-submission projections are likewise
bounded schema v2.
That provenance is explicitly not independent browser verification of Intel
TDX: raw quotes, signatures, exact scores, and exact timing do not egress.

Every Compute console section is likewise addressable without putting a
project, job, wallet, or credential identity in the URL:
`#/compute?tab=overview`, `workloads`, `funding`, `dispatch`, `jobs`, or
`credentials`. Missing, duplicate, unknown, or extra query fields fail closed
to Overview. Tab changes use normal hash navigation so browser Back/Forward
history is preserved.

### Compute service-credit reservation hold

The authenticated CVM implements `POST /compute/projects/{project_id}/jobs` as
an atomic, metadata-only reservation of closed-loop, nontransferable noncash
test credits. Its request schema has no prompt, example, dataset, raw output,
card, wallet-key, or upstream-provider-key field, and a successful response
states that provider dispatch was not performed. Wallet sessions are bound to
the exact `compute:console` scope and the service rechecks project membership,
mutating role, operation allowlist, per-job and daily limits, and available
credits. Scoped device credentials require `jobs:create`.

That server primitive is not exposed as a browser create form in this release.
The broad Compute Console feature flag is not a reservation-specific release
capability, the creation response has no versioned ledger-bound receipt, and
there is no durable lookup by public request/idempotency commitment. If a POST
commits but its response is lost, a page reload would lose the only safe retry
key and could let the user create a second reservation. The client parser now
validates the exact current response, request echo, replay contradiction,
no-dispatch claim, project policy, and idempotency-key shape, but the mutation
stays fail closed until the backend publishes a dedicated capability and
ambiguity-reconciliation contract. Existing exactly queued, never-dispatched
jobs remain wallet-cancelable through the versioned hash-chained reversal
receipt already shown by the Jobs tab.

### Delegated Tinker customer lifecycle

The Tinker page reuses the wallet challenge/token flow with the exact
`compute:console` scope. Its bearer, account state, non-exportable delivery
key, unresolved idempotency key, and one-time decrypted credential exist only
in page memory. Account, chain, wallet-authorization-version, or expiry drift
clears all of them and disables every lifecycle mutation. A dedicated
release-derived `VITE_ENABLE_TINKER_CUSTOMER` marker, the delegate origin, and
the exact encumbrance address/code-hash pins must all be present before the
browser can request authorization. That marker is projected only from the
signed `requested_features.tinker_customer` boolean; the broader Compute
Console flag cannot enable this lifecycle.

`POST /tinker/customer/accounts/requests` records either a CVM-account creation
request or a sealed-account-link request. The payload contains only the mode:
it accepts no provider account identifier, account commitment, email, API key,
cookie, card detail, or project ID. A successful request explicitly says
`provisioning_performed=false` and `upstream_account_exists=false`. Activation
is a separately reviewed internal operation. The browser recovers the one
wallet-owned record through `GET /tinker/customer/accounts/current` and may
read its exact status route, but those reads are historical attested records,
not fresh Intel TDX/QVL verification. Every mutation is separately required
to pass the server's current Base Sepolia release gate.

An active account can issue a training-only credential with a lifetime of
60–3,600 seconds and a positive per-operation cap no wider than the immutable
account policy. The cap is entered and validated as a canonical uint256 decimal
string, then serialized as an exact unquoted JSON integer without conversion
through JavaScript `Number`. The browser sends only a freshly generated X25519
public key. It authenticates the returned capsule's AES-GCM associated data,
recipient commitment, account and release lineage, release-policy tuple,
training scope, exact cap, expiry, JWT header/claims, and JWT-ID commitment
before a one-time plaintext reveal. HTTPS still authenticates the service
because the browser does not possess the server's HS256 signing key.

The durable credential list returns metadata only—never a token or capsule—and
uses schema-v2 pages of 16 records by default, with an explicit maximum of 64.
Pages are strictly ordered by issue time and credential ID, newest first, and
retain revoked and expired history. Each continuation cursor is an opaque HMAC
capability bound to the exact wallet-owned account and authenticated store
sequence; tampered, cross-account, or stale cursors produce a restart-required
conflict instead of silently mixing snapshots. The client preserves strict
ordering and deduplication, retries transient page failures, discards responses
from an obsolete wallet/session/authority epoch, and explicitly restarts after
a snapshot conflict. Every page reports exact total/page counts and stays below
256 KiB. Rotation terminally revokes the prior credential before issuing its
replacement, so authority never overlaps; a lost response is retried only with
the same in-memory device key and idempotency key. Credential and account
revocation require explicit confirmation and reconcile uncertain responses
against durable status.

The browser intentionally has no route to the metadata-only
`/tinker/customer/reservations` endpoint or any `/tinker/internal/*`
activation/finalization endpoint. It does expose the separate
`POST /tinker/customer/train` execution contract after one lower-authority
credential is decrypted in page memory. That form accepts only three strict
integers: a 1–5,000,000 micro-USD policy ceiling, 1–50 steps, and a 60–3,600
second TTL. The release-pinned measured service supplies the model, rank,
compose, and built-in bounded examples; the browser cannot submit a prompt,
dataset, example, provider key, or billing credential. This direct customer
route is operator-prefunded validation with fixed authority accounting. It
does not debit a Compute exact-asset vault, buy Tinker balance, or turn an ETH
or ERC-20 deposit into an upstream provider-account top-up.

The client retains one idempotency key per unresolved controls/credential
tuple. The server durably reserves and claims dispatch before entering the
provider boundary. A settled or pre-dispatch-released response is parsed as an
exact signed bounded receipt; an ambiguous post-claim outcome becomes a visible
`reconciliation_required` hold and the browser disables automatic redispatch.
While the exact credential, controls, wallet session, claim receipt, and
original idempotency key remain in page memory, a clearly labeled **Recover
signed result** action repeats only that exact request. The client rejects a
result or repeated hold for a different reservation/workload; missing signed
evidence leaves the original hold visible. Any identity/control/context drift
disables recovery, and clearing the dialog destroys the browser recovery
context without pretending to clear the server-side hold. The displayed fixed ceiling is explicitly authority accounting—not a provider
invoice, price, balance, or authoritative usage measurement. Only an
authenticated response is labeled observed API state; configuration remains
release-gated.

Exact-asset funding, noncash test credits, and future provider-hosted checkout
remain distinct. The exact-asset rail is labeled for Compute inference/training
only and explicitly cannot fund direct customer Tinker validation or top up an
upstream account. This page never accepts card data or mints a redeemable token.
The lower-only allowance button remains disabled until an exact browser API
schema and ambiguity-recovery contract are released.

### Safeguards operator and simulator boundary

The upper Safeguards operator is a release-gated control-plane client, not a
generic policy playground. It accepts a transient strict-JSON bundle only when
the configured delegate, authority pins, rollback anchor, wallet, and Base
Sepolia network are ready. Its runtime bearer authenticates transport only. A
`PASS` still requires explicit approval from the release-authorized recoverable
EOA, and the browser renders only the bounded decision record after the
configured confirmation depth, the observer RPC's finalized-head report, and
an independent re-read. That is a single-RPC observation, not RPC quorum or an
independent TDX/QVL verification.

Before `/policy/evaluate`, the browser derives a domain-separated
`sha256:<digest>` idempotency commitment from the canonical approval-message
hash and retains the exact signed intent in page memory. If delivery becomes
ambiguous, the operator locks the wallet/provider session, Base Sepolia chain,
runtime bearer, release pins, resource and Compute-project references, private
bundle, original expiry, previous head, and signature. Recovery reads bounded
status first: an exact committed record completes without another mutation;
only an unchanged prior head permits a byte-identical replay with the same
idempotency key. A conflicting head, pending anchor, expired intent, changed
authority, or page reload fails closed. The raw bundle, resource reference,
approval message, and signature are never persisted or rendered, and the draft
is cleared only after exact status reconciliation. Every policy transport also
uses a no-store cache mode, omits credentials and referrer data, and rejects
redirects so private request material cannot follow a changed origin.

The lower simulator is a separate deterministic browser-local teaching tool.
It performs no service call or contract mutation and emits only an explicitly
modeled receipt using the `modeled-receipt:` and
`illustrative-only:not-a-tdx-quote` markers. A simulator `PASS` is never a live
execution-policy approval, an Intel TDX quote, or evidence that a CVM ran.

### Release-gated Arena Agent Access

The Agent Access panel asks for a second, on-demand wallet signature whose
short session contains only `challenge:agents:manage`; the ordinary Arena
submit/read session never carries that authority. The delegated bearer gets
only `challenge:submit` and `challenge:submissions:read`, expires within 24
hours, and has a daily submission-attempt cap. It cannot authorize Compute,
Deal, proxy, worker, reward, or settlement actions.

The browser generates a non-exportable X25519 key and receives the bearer only
as a one-time encrypted capsule. Neither the private key nor the decrypted
bearer is written to browser storage. Copy the bearer directly into the agent's
`WIKIGEN_ARENA_TOKEN` process environment, then clear the reveal. Closing or
management-session expiry clears its bearer and one-time plaintext but retains
the same-wallet device key in tab memory, so a fresh explicit signature can
rotate it. Closing/reloading the Arena route loses the key and
recovery/rotation capability; use the wallet to revoke that credential and
issue a new device. The displayed
curl and Python examples reference environment variables and never print or
embed a sample secret.

This surface is hard-labeled **Live-capable auth · release gated**. Wallet
consent, durable challenge-scoped credential records, encrypted one-time
delivery, rotation, revocation, and quote-gated ciphertext ingress are real API
operations only when the release is configured. Rankings, queue execution,
provider work, and rewards remain modeled or evidence-per-row. Key separation,
encrypted delivery, and a durable HMAC-authenticated server store are not TDX
evidence, proof that a job ran, proof of QVL verification, a reward promise, or
rollback protection; an older valid store file can still be restored. See
[`docs/ARENA-BACKEND.md`](../⚙️/tinker-delegate/docs/ARENA-BACKEND.md#modeled-arena-agent-access)
for the exact API and custody boundary.

## Stack

- SolidJS, TypeScript, and Vite. React is not used.
- `viem` for Base Sepolia reads, writes, hashing, and wallet clients.
- EIP-6963 discovery plus an injected EIP-1193 fallback for MetaMask, Coinbase
  Wallet, Rabby, and compatible wallets.
- WalletConnect as a conditional public configuration; the dialog shows a
  truthful unavailable state when the deployment has no project ID.
- Production wallet challenges are pinned to domain `www.wikigen.me`, URI
  `https://www.wikigen.me`, and Base Sepolia. Local development derives its
  loopback domain and URI from the current browser origin, so MetaMask, Rabby,
  Coinbase Wallet, and compatible injected wallets are never asked to sign a
  production-origin message while testing locally.
- X25519, HKDF-SHA256, and AES-256-GCM through Web Crypto for artifact ingress.
- Local Manrope and JetBrains Mono font assets; no remote font dependency.
- Static Cloudflare Pages output; no secret may use a `VITE_` variable.

## Local development

```bash
cd web
npm ci
npm run dev
npm run check
```

The development server defaults to `http://127.0.0.1:5175` when started with `npm run dev -- --host 127.0.0.1`.

## Public deployment configuration

Copy `example.env` to `.env.local` only for public values. Never place a private key, runtime bearer, API key, Stripe secret, Phala key, or upstream Tinker credential in a Vite variable—Vite embeds it in browser assets.

Production live gates must not be edited by hand. The intended fail-closed
workflow is documented in [`RELEASE-MANIFEST.md`](./RELEASE-MANIFEST.md). The
release generator now has two explicit phases: an exact-36 pre-D build that
publishes the hash-only frontend candidate receipt `D`, and an exact-38 replay
that authenticates `L → R → signed B → H → O → D → signed C`. `H` is the
independent dual-RPC Royalty history receipt and remains a distinct input to
both phases. Check-only mode
writes nothing; successful live mode writes only the ignored, no-clobber
`.env.production.local`. This implemented release path does not assert that a
fresh suite is already active: production still requires the current clean
commit, project-owned contracts, seven non-dev CVMs, current independent
verdicts, operator signatures, and live-chain state described by those exact
artifacts.

The release topology is exactly seven CVMs: the main private runtime, five
independently controlled QVL CVMs (Diligence, Arena, anchor writer, Compute
workload, and Compute metering), and the independent deterministic Compute
meter. QVL admission uses signed challenge schema v2 and the active independent
verdict schema/signing domain v4. Each challenge is single-use, valid for at
most 120 seconds, and bound in the quote's exact 64-byte report data; Intel DCAP
appraisal must finish strictly before expiry. The v4 verdict then carries the
separately reviewed exact 900-second activation-evidence lease. That lease may
outlive the consumed challenge, but it is not renewed challenge freshness.
Post-restart Compute-workload recipient activation is exact schema v3 with an
explicit recipient-evidence lease of at most 300 seconds; its stable
recipient-release commitment remains v2 and activation v1 is rejected. The
Diligence QVL also serves the Email/KMS restart-evidence profile, which does not
add a sixth trust root or eighth CVM.

The main runtime's final profile update is exactly
`arena-runtime,compute-execution`. The same-process source coordinator carries
reviewed release authority through signed Stage B, encrypted environment patch,
restart, authenticated Phala observation, Arena worker-capability v2
verification, and fresh Compute recipient activation. Neither the Phala
attestation response nor the HMAC heartbeat is independently verified TDX
evidence, completion grants no live-traffic authority, and this fresh release
has not been activated.

The tested resident source driver keeps that authority chain in one process
from one exact owned canonical mode-`0600` request through the non-live launch,
external proof/signature waits, restart, recipient activation, and bounded
output publication. It cannot reload serialized authority or accept signer
keys, never retries automatically, and always reports
`live_traffic_authorized=false`. It has not been run against a fresh
project-owned production topology.

That driver's bounded post-restart activation observation `O` projects exactly
20 public Compute-workload browser variables. Seven mandatory lineage pins are
`VITE_COMPUTE_WORKLOAD_CVM_ID`,
`VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256`,
`VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256`,
`VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE`,
`VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256`,
`VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256`, and
`VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256`. The release builder and
browser require the full exact 20-key projection from one branded observation;
missing or drifted lineage keeps upload disabled. These values are bounded
public release configuration, not secrets, serialized mutation authority, or
proof of a live activation.

Important gates:

- `VITE_DILIGENCE_ROOM_ADDRESS` and related addresses must name the fresh project-owned suite.
- `VITE_ENABLE_CONTRACT_WRITES` remains `false` until the runtime bytecode hash,
  permanent developer controller, result verifier, both mandatory approval
  flags, approved compose measurement, and TEE identity binding match the
  release manifest. The controller must be distinct from the deployment
  operator, its delayed two-step handoff must be complete, and both pending
  developer getters must be zero under the fixed two-day transfer delay.
- `VITE_DELEGATE_URL`, `VITE_PHALA_COMPOSE_HASH`, and deployment identity fields must describe the replacement CVM, not the prior operator's CVM.
- There is intentionally no `VITE_ORACLE_URL`: the email oracle has no public
  host port or browser route and is reachable only from the authenticated
  delegate over the CVM's private compose network.
- `VITE_ENABLE_ARTIFACT_UPLOAD` remains `false` until the browser ingress policy, exact CORS origin, fresh CVM, expected measurements, and independent quote-verification path are approved together.
- `VITE_ENABLE_TINKER_CUSTOMER` and `VITE_ENABLE_COLLABORATION` default to
  `false` and are projected independently from the exact signed
  `requested_features.tinker_customer` and
  `requested_features.collaboration` booleans. Neither is inferred from
  Compute Console, contract writes, or the other feature lane.
- `VITE_USDC_ADDRESS` must equal Circle's canonical Base Sepolia USDC address;
  it is the only ERC-20 the frontend will create or fund a room with. Arbitrary
  token input and symbol/decimal lookalikes are intentionally unavailable.
- `VITE_COMPUTE_CREDIT_VAULT_ADDRESS` and
  `VITE_COMPUTE_CREDIT_VAULT_CODE_HASH` must pin the exact vault runtime before
  even the raw-funding gate can become actionable. The browser reads every
  readiness fact and wallet balance from one Base Sepolia block.
- `VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION` additionally requires the pinned
  developer and metering roles, frozen fee, frozen and approved compose policy,
  exact TEE binding, and active exact-asset rate-policy commitments. Missing or
  drifting roots block authorization without hiding a separately verified
  withdrawal path.
- The optional Compute-vault ERC20 is all-or-nothing public configuration:
  address, runtime code hash, symbol, decimals, and authorization policy
  commitment must agree with live chain reads. The capacity UI accepts no
  arbitrary token address and never requests an unlimited allowance.
- Exact-asset funding may name any exact EVM beneficiary because the contract
  supports third-party sponsors. The console continues to display only the
  connected wallet's capacity, and never implies that sponsorship grants the
  sponsor authority over the beneficiary's funds or jobs.
- A connected wallet may advance its project nonce to invalidate older,
  unsubmitted job signatures. Provider/developer accrual withdrawal is a
  separate role-neutral pull-payment path: a wallet can claim only its own
  nonzero balance, and the action neither grants a role nor touches customer
  capacity.
- The checked-in CSP enables injected EIP-6963 wallets by default. When a
  WalletConnect project ID is present, the build adds only the exact connect
  and frame origins used by the pinned WalletConnect/Reown packages. Remote
  script, image, and font sources remain blocked; upgrades to those packages
  require reviewing and updating the origin allowlist without wildcards.

Wallet connection alone is not service authentication. Encrypted seller upload uses the delegate's deal-bound flow:

1. `POST /auth/wallet/challenge` with wallet and deal ID.
2. Sign the returned, Base-Sepolia-bound message.
3. `POST /auth/wallet/token` with the one-time nonce and signature.
4. Verify the artifact attestation envelope against the public deployment manifest.
5. Load the seller-held v2 recovery receipt, recompute
   `keccak256("dnai-wikigen/artifact-commitment/v2" || 0x00 || secret32 || raw)`,
   and require it to equal the on-chain commitment.
6. Build the exact v3 constant-size frame (16-byte magic, private uint32 length,
   secret, up to 1 MiB raw bytes, and CSPRNG padding), bind Base Sepolia, the
   fresh room, deal, artifact, and funded evaluator policy in HKDF/AAD, encrypt
   in the browser, and send only the fixed-size ciphertext to
   `/deal/{id}/artifact/encrypted` with the five-minute `artifact:upload` token.
7. Recompute the ciphertext SHA-256 locally and require the delegate's bounded
   acknowledgement to match it. The acknowledgement contains
   `padding_profile=fixed_1m_v3` and `exact_plaintext_size_egress=false`; its
   fixed public ciphertext size is not the private artifact length.

Tokens and recovery receipts are held in memory for the current operation and
are never written to local storage. The user must explicitly download the
recovery receipt before creating a room; the application has no recovery copy.

## Cloudflare Pages

`wrangler.toml` declares `dist` as the Pages output directory and connects this
checkout to the existing `wikigenme` Pages project, whose production domains
are `wikigenme.pages.dev`, `wikigen.me`, and `www.wikigen.me`. Build and deploy
an argument-free modeled release to the explicit `modeled-preview` preview
branch with:

```bash
npm run deploy:cloudflare
```

That command is modeled only when no live `VITE_*` binding or generated
`.env.production.local` is present. Modeled mode accepts no release-evidence
arguments and never receives a live validation receipt.

The production path is supported for a complete current artifact set. Use the
copyable exact flag array in [`RELEASE-MANIFEST.md`](./RELEASE-MANIFEST.md) to:

```bash
# Read-only exact-38 replay; writes nothing.
npm run release:env -- --check-only "${EXACT38[@]}"

# No-clobber publication of the ignored production browser environment.
npm run release:env -- "${EXACT38[@]}"

# Revalidates exact-38 in check-only mode, then builds, audits, and uploads.
npm run deploy:cloudflare -- "${EXACT38[@]}"
```

Before those commands, the exact-36 phase reproducibly builds the browser and
publishes the fixed hash-only `D` receipt at
`../.release/frontend-build-candidate-receipt.json`; signed C is created only
after the independent Royalty receipt H, the bounded activation observation O,
and D exist. The release runner
binds the in-process 19-field semantic receipt to the allowlisted `VITE_*`
environment, a clean exact `HEAD`, the audited dist manifest, the reviewed
production branch, and the same private artifact snapshot before Wrangler is
allowed to run. Both D and `.env.production.local` are no-clobber outputs.
Retired renewable review-envelope flags remain explicitly rejected; they are
not a fallback for signed C or the exact-38 dependency chain.

The stable review URL for the current modeled branch is
`https://modeled-preview.wikigenme.pages.dev`. The edge admits only this
reviewed preview origin and canonical `https://www.wikigen.me`; Cloudflare's
unique per-deployment host redirects to the canonical production origin so it
cannot become another wallet-auth origin. Exact deployment IDs and served-file
manifests are release outputs, not source-code assertions, and are recorded in
the corresponding release handoff after every upload. For historical context,
the 2026-07-21 reference preview was deployment
`f69afba0-81b9-44b2-a4ae-e2d1a0800713`; all 142 of its served files were
verified byte-for-byte and its independent local/remote served-manifest SHA-256
was `604fbce76f4da06029d27a01061585e13bf2793cbc6b020df9c44ce333eb7778`.
The separate production deployment remains
`164b2207-96a9-487f-b4a8-d14bbfbc192d`, and its branch and custom domains were
not changed. The preview
intentionally has no contract/CVM mutation environment and labels its release
identity `unconfigured · modeled`; no working-tree label is allowed to enter a
verification-chain claim. It is a reviewable product preview, not the
provenance-bearing confidential-compute release described in
`RELEASE-MANIFEST.md`.

The deployment script runs the full typecheck, test, build, and dependency-audit
gate before uploading the static output. A no-binding modeled preview may be
published from an active working tree and is explicitly labeled as such. The
moment any release binding or live feature is present, deployment requires the
full generated release SHA to equal a clean `HEAD`, requires all four live
core feature gates plus any requested Compute-vault funding/authorization
gates, and removes Wrangler's dirty-worktree override.

The project seeds `_headers` from `public/`, then regenerates `dist/_headers`
from the exact production environment after every build. A modeled build allows
only self plus the canonical Base Sepolia RPC; a live delegate origin is added
only when the corresponding live feature flags and exact HTTPS origin are
present. Routing is hash-based, so every application route is served from `/`
without a Pages rewrite. `TINKER_CORS_ALLOWED_ORIGINS` must contain only the
three reviewed production origins before enabling any cross-origin mutation.

## Safety boundaries

- No raw artifact enters Cloudflare Pages, public logs, the on-chain contract, or a modeled queue.
- Card details are never collected, returned to, or persisted by this static
  app. Hosted checkout and purchased service credits are outside v1; any later
  integration requires provider-hosted collection and a verified signed webhook.
- Compute Credits are closed-loop, non-transferable, operator-granted noncash
  test units in v1; they are not purchased value, a speculative token, or a
  redeemable claim.
- Base Sepolia Compute capacity is a separate exact-asset ledger: ETH or the
  single release-pinned ERC20 moves directly between the connected wallet and
  the pinned vault. No token is minted, no exchange rate is applied, and no
  deposit is represented as Compute Credits. This is the v1 production
  pay-as-you-go lane: each job reserves a signed asset maximum, independent
  metering may debit only bounded actual usage, and the remainder stays
  withdrawable. Sponsors may fund another exact address without gaining control
  of that address's ledger; users may invalidate older unsubmitted signatures;
  and provider/developer accruals remain separate pull balances. Funding and authorization remain
  hidden unless their live release gates validate; available capacity keeps a
  separately verified withdrawal path.
- The Compute capacity vault is a reviewed, extensively tested testnet
  contract. The interface makes no formal-audit claim. Challenge prizes remain
  separate from both vault capacity and service credits.
- The RoyaltyDistributor panel can read and withdraw only the connected
  wallet's native ETH or canonical Base Sepolia USDC pull balance after the
  configured runtime hash matches. It can inspect one exact global settlement
  ID, but an unused ID does not prove that payment is owed and a consumed ID is
  only an on-chain replay fact. Distribution is intentionally absent from the
  browser: the v2 contract requires the exact room/grant/allocation/evidence
  commitments, a current frozen policy-anchor decision, and independent EIP-712
  signatures from the release-bound settlement CVM and QVL verifier.
- Synthetic-only Bio/DNA surfaces are analysis and quality-control challenges,
  not clinical, pathogen, synthesis, or wet-lab optimization tools. Data Vaults
  are roadmap architecture; this release accepts no health-data intake.
- Public attestation responses are allowlisted. Compose YAML, container environment, system information, and runtime secrets are rejected and never rendered.
- Contract bytecode presence is not treated as source verification, role verification, measurement matching, or end-to-end receipt verification.
- Email Oracle “ready” means only that the runtime-pinned contract, its exact
  membership/freeze facts, and the frozen external KMS proxy and implementation
  read consistently at one RPC-reported finalized Base Sepolia block. The panel
  is read-only: it does not send email, generate or reveal an OTP, mutate
  governance, validate the historical KMS registration receipt, prove restart
  continuity, or independently verify TDX/QVL evidence.

## Build output

The production build is fully static under `dist/`. Imported cinematic assets
are fingerprinted by Vite. Hash routing keeps navigation on the single-page
shell, and immutable caching applies only to fingerprinted `/assets/*` files.
