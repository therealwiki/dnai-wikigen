# dnai-wikigen Status

Last updated: 2026-07-24

Scope: current repository evidence only. This file is a status ledger, not a
production deployment manifest.

## Legend

```text
[real]      Code exists and can be compiled, imported, tested, or run locally.
[partial]   Code exists, but the end-to-end path is incomplete or externally blocked.
[modeled]   The design is documented or stubbed, but enforcement is not complete.
[planned]   Architecture target only.
```

## Current Verdict

### 2026-07-24 current source candidate and release boundary

The current tree is a tested **source candidate**, not a deployed confidential-
compute production release. An earlier twelve-route SolidJS build is published
only as the explicit modeled preview at
`https://modeled-preview.wikigenme.pages.dev`; the canonical production origin
and custom domains were not changed for this source candidate. That preview is
a product/design artifact, not evidence of a fresh contract, CVM, QVL, or TDX
release. An older modeled nine-route production bundle was browser-checked in a
prior release. For the current source candidate, all **612/612** unfiltered
Vitest assertions, TypeScript no-emit checking, the production Vite build, and
the hardened security-header checks pass locally. The complete backend run
records **2,548 passed, 6 skipped**, with **751 subtests passed**; the email
oracle passes **92/92** through its repository-native `unittest` release
runner. The launch/descriptor regression group passes **199/199**, and the
focused activation-preflight group passes **92/92**. The full Foundry suite
passes **444/444** after `forge fmt --check` and `forge build --force --sizes`,
including its fuzz and invariant campaigns.

The last complete root Node run discovered **1,039** tests: **1,020 passed** and
**19 failed**. Two failures were subsequently repaired and reverified with
focused checks: the post-measurement activation plan KAT and the bounded
pending-ready deadline under repository-wide parallel load. The remaining 17
were host-bound evidence failures: eight Phala SDK-adapter cases could not
create their home-directory test roots in the managed sandbox, and nine
opened-file-descriptor verifier cases found that the current macOS
system-version authority bytes no longer match the frozen verifier pin. The
complete root Node suite has not been rerun after the two focused repairs, so
this ledger does not infer a replacement aggregate.

The current complete web release-boundary run ends **279/281** in its Node
phase. Its public-bootstrap TypeScript-parser timeout remains bounded at 30
seconds and passes under the full runner. The other two failures are deliberate
release gates: immutable `git_commit` materialization requires an operator-
authorized commit, and the outer macOS Cloudflare-sandbox proof is not
available inside the managed sandbox. The offline npm audit reports zero known
vulnerabilities.

A 1600×900 in-app-browser pass covered all twelve canonical routes from the
freshly built local production preview: every route had the correct title and
heading, no route overflowed horizontally, and no interactive control was
clipped. A 920×1079 pass covered the same twelve routes without page-level
horizontal overflow and found one compact-menu control per route. Arena's eight
offscreen controls are contained by its intentional table-local leaderboard
scroll region, not page overflow. Desktop visual inspection covered Overview,
Arena, Tinker, Compute, and Collaboration; compact visual inspection covered
Overview and Arena. The browser console remained free of warnings and errors.
The compact navigation opened and closed with all twelve routes present, and
the wallet dialog opened and closed without a provider installed while clearly
reporting WalletConnect as unconfigured and the injected-wallet path as
unavailable; no connection, signature, network switch, or transaction was
attempted. A separate phone-width live visual pass has not been recorded. The
current staging classification contains 380 dirty paths: 369 source-candidate
paths are in scope and 11 user/research paths are excluded, including the dirty
`🔬/jameslbarnes/dshield` gitlink. The bytewise-sorted
`XY<TAB>path<LF>` classification digests are
`9cf7e0a07eb9e0512621b2199716f387a6059c12871f5722688c0db9b49009c2`
for the included set and
`1c98e58850a1ad7ac2c680b562ed6eb1c58410a09a621421cc4a78c3c9418c56`
for the excluded set. Nothing is currently staged.

The read-only `live-activation` preflight currently reports **43 pass, 1 warn,
64 fail** across its exact 108-check contract while proving that it unlocked no
keystore, attempted no broadcast or deployment, printed no secret value, and
mutated no remote state. Its blocking roots include the dirty/uncommitted
source, absent exact release SHA and
reviewed role inputs, unauthenticated Phala CLI, missing fresh deployment and
seven-CVM evidence, and the deliberately absent finalized four-phase
DiligenceRoom controller-acceptance ledger. The current read-only Wrangler
identity probe also fails closed because its saved OAuth token is no longer
accepted; the existing `wikigenme` Pages project and earlier authentication
snapshot are not current activation evidence, and this source candidate has
not been uploaded.

`[real/source]` The frontend now covers the complete product vocabulary: an
explicitly modeled, reload-cleared Health Guide that accepts no health data;
diligence rooms; a GPUMODE-inspired sealed bio challenge Arena; a release-gated
human-review API and browser desk; data vaults; wallet-scoped proxy credentials;
modeled service credits; exact-asset Compute capacity; a release-gated delegated
Tinker account lifecycle; execution safeguards; a capability catalog; layered
verification; and a release-gated schema-v2 multi-owner Collaboration API/UI
plus a runtime-pinned RoyaltyDistributor read/self-claim panel. The browser does
not invent allocations. The v3 contract and Collaboration execution service
implement deterministic exact prefunding reservations; finalized worker
admission; bounded Compute; on-demand exact anchoring and purpose-separated
main/QVL authorization; a sponsor-wallet `settleReserved` handoff; and finalized
reconciliation. Direct distribute calls remain compatibility paths. That path
is implemented and tested in source, but no fresh activated
`RoyaltyDistributor`, settlement CVM, independent Royalty QVL, sponsor deposit,
or settlement is live. The Trust
Center also has a read-only, finalized-block
EmailOracleAuth/KMS readiness panel; its single-RPC contract observation is not
email-delivery, restart, Intel TDX, or independent QVL evidence. Wallet
discovery supports
EIP-6963 and injected EIP-1193 wallets such as MetaMask, Rabby, and Coinbase
Wallet, with an optional release-configured WalletConnect provider. Wallet
connection identifies the selected address and network; exact signed nonce
challenges establish service authorization. Every action is labeled live,
modeled, roadmap, or fail-closed; illustrative receipts are never labeled Intel
TDX evidence.

`[real/source; release gated]` Human Review now includes the strict public
hash-only queue, runtime-authenticated internal enqueue/expiry operations,
release-bound reviewer-wallet challenges, signed release/deny decisions,
private M-of-N resolution, self-review/duplicate-vote rejection, browser UI,
and a browser-rechecked Base Sepolia rollback witness. It is not activated
production reviewer custody: the fresh reviewer roster and keys, notifications,
scheduled expiry worker, and new release deployment remain open.

`[real/source; release gated]` Collaboration schema v2 now includes a persistent
authenticated control plane and browser UI for durable rooms, invitations,
membership and owner-role changes, exact-query grants, bounded pagination,
idempotent recovery, joint-consent snapshots, and quiescent archive. A separate
execution service implements the production-shaped, one-shot continuation:
deterministic reservation after the complete fresh grant set; RPC-reported
finalized EIP-1898 admission of the exact Royalty reservation and Compute job;
bounded Compute; an on-demand exact settlement-decision anchor plus main/QVL
authorizations; sponsor-wallet `settleReserved`; and finalized receipt/state
reconciliation. The public API cannot synthesize that execution context.

This is source/test evidence, not production joint execution or settlement.
Local HMAC mode remains explicitly non-monotonic. Live dstack mode is
source-implemented with a release/project/wallet-domain-bound Base Sepolia
`ExecutionPolicyAnchor` witness under the explicit single-RPC
reported-finalized model, crash-safe pending-state recovery, current-head
rechecks, and fail-closed auth/read/mutation behavior on witness outage,
regression, or state mismatch. This is not RPC quorum or a consensus proof. No
fresh release has activated that authority or produced current live Base
Sepolia, Phala, TDX, independent-QVL, sponsor-funding, settlement, or Cloudflare
evidence.

`[real/source]` The fresh Base Sepolia suite now contains seven contracts:
`DiligenceRoom`, `TinkerAccountEncumbrance`, `RoyaltyDistributor`,
`ChallengeRegistry`, `ComputeCreditVault`, `EmailOracleAuth`, and
`ExecutionPolicyAnchor`. Deployment and staged-release scripts use only the
Foundry `dev` keystore, verify exact creation-bytecode-derived runtime code,
enforce distinct roles, preserve prior deployment history, and start the room,
vault, oracle, and policy anchor fail-closed until their timelocked release
bindings are complete. All local addresses and receipts remain ephemeral; none
of this suite has been broadcast to Base Sepolia.

`[real/source; deployment pending]` The production topology is seven CVMs, not
the historical single-CVM deployment and not a generic shared verifier: one
private main runtime; five separate QVL CVMs for Diligence, Arena,
execution-policy anchor writer, Compute workload, and Compute metering; and one
independent deterministic Compute meter. Those five QVL services use distinct
policy-derived signing roots, signed challenge schema v2, and the active
independent verdict schema/signing domain v4. Each challenge is single-use,
lasts no more than 120 seconds, and is bound with the static release context in
exact 64-byte quote report data. Intel DCAP appraisal must finish strictly
before challenge expiry. Success consumes the challenge and starts the
separately reviewed exact 900-second activation-evidence lease carried by the
v4 verdict; the policy-bounded lease may outlive the closed challenge but never
renews its freshness. Post-restart Compute-workload recipient activation is
schema v3 with an explicit recipient-evidence lease of at most 300 seconds; its
stable recipient-release commitment remains v2. The Diligence root has a
secondary `email_oracle_kms_restart`
profile; it does not create a sixth root or eighth CVM.

`[real/source; deployment pending]` The main runtime's reviewed final activation
uses one exact replacement profile set,
`arena-runtime,compute-execution`. A same-process coordinator retains opaque
release/evidence objects from the completed launch lineage through reviewed
final authority, signed Stage B, the encrypted environment patch, restart,
release-bound Arena worker-capability v2 verification, and a later fresh
Compute-workload recipient activation. The post-restart Phala attestation
response is only an authenticated observation, and the Arena heartbeat is only
HMAC-authenticated worker presence; neither is independently verified TDX
evidence. The source runtime journals each mutation boundary and completion
still reports `live_traffic_authorized=false`. No fresh production coordinator
session has been run against a project-owned seven-CVM deployment.

`[real/source; deployment pending]` The resident
`scripts/phala-production-activation-driver.mjs` now drives that same branded
authority chain in one process from one exact owned canonical mode-`0600`
request. Its ordered checkpoints cover the non-live seven-CVM launch, five QVL
identity proofs, two workload verdict proofs, externally supplied Stage-B
signatures, post-measurement mutation, Compute recipient activation,
finalization, and bounded-output publication. It accepts no serialized
capability or signer-key material, authorizes no automatic retry, and ends with
`live_traffic_authorized=false`. Its source tests pass; the driver has not been
run against a fresh project-owned production topology and is not proof of a
deployment or activation.

`[real/source; deployment pending]` The bounded post-restart activation
observation `O` now projects exactly 20 public Compute-workload browser
variables. Seven are mandatory ceremony-lineage pins added to the previous
surface: main-runtime CVM ID, deployment-intent digest, release-authority
digest, ceremony nonce, measurement-policy-set digest, Compute-workload
measurement-policy digest, and main-runtime-evidence digest. The browser fails
closed if any of the 20 values is absent or drifts. This projection contains
public release bindings only, not secrets or serialized activation authority,
and is not proof that activation ran.

`[real/source; deployment pending]` `TinkerAccountEncumbrance` starts halted,
reviews one exact account/caps/compose/manager policy for two days, and activates
and freezes that policy atomically. Later authority can only narrow or halt.
`EmailOracleAuth` boot authorization uses two distinct HTTPS Base Sepolia RPCs,
requires one common fresh finalized block and identical code/auth results, and
persists a monotonic checkpoint across ordinary restarts. That checkpoint is
not hardware anti-rollback against restoration of the entire persistent volume.

`[real/source]` Approval schema v3 and store schema v6 bind every protected
operation to a canonical hash-only record. Writers hold an OS-backed exclusive
lease from preflight through persistence and anchor finalization; deal, Arena,
and Compute executors hold the matching shared lease through their irreversible
boundary. Compute approvals additionally commit a server-derived immutable
execution context: exact-asset jobs bind the authenticated dispatch intent plus
compiled recipe, and modeled service-credit jobs bind the authoritative job plus
reservation record. A caller cannot supply that context. The browser exact-
asset workflow obtains it only through a wallet-authenticated status lookup,
recomputes it locally, checks the intent owner, and excludes legacy service
credits from that public approval path.

Store v6 keeps local records numbered from one while requiring a non-circular
release marker at on-chain sequence one. The marker decision is the reviewed
final-authority SHA-256 supplied through `TINKER_RELEASE_AUTHORITY_SHA256`; its
resource domain is
`dnai-wikigen/execution-policy/final-release-authority/v1`. Consequently the
first local record anchors at chain sequence two, and Royalty authorization
always carries the chain sequence including that marker offset.

`[real/source; funding pending]` Current final-authority v4 also signs the
exact dstack-derived anchor writer's bounded gas policy: one release marker
plus 32 subsequent anchors, at 500,000 gas and a reviewed 2,000,000,000 wei per
gas, for a minimum `33000000000000000` wei (0.033 ETH). Activation preflight
v4 now emits 110 exact checks. Its readiness snapshot v5 calls
`eth_getBalance` for that writer through both distinct Base Sepolia RPCs at one
common finalized block, requires identical canonical decimal wei, and blocks
release-ceremony/live activation if the response is missing, divergent, or
underfunded. This is 33-transaction runway, not indefinite readiness; no
operator/USDC/QVL/relayer/paymaster/hot-key fallback is accepted.

The rollback witness selects the older of one release-pinned RPC's reported
`finalized` head and the configured confirmation-depth boundary, then pins all
code/storage reads to that exact block. This closes the previous recent-block
and check/use gaps, but it remains one RPC's report—not independent RPC quorum,
a light client, or a consensus-authenticated storage proof. Public wording and
release schemas preserve that limitation.

`[real/source]` Anchor-writer custody can no longer be promoted using an
arbitrary evidence hash. A one-shot real-dstack command derives the exact
purpose-separated writer, binds writer/anchor/release/key path into report data,
sends the raw quote only to an authenticated independent QVL, authenticates its
signed verdict, and emits one canonical bounded artifact. Release generation
hashes the exact bytes and cross-checks the full QVL, writer, CVM, quote, and
release identity. The historically pinned Phala delegate digest predates this
command and module. The new generated production descriptor includes the
ceremony only as an isolated, disabled-by-default, one-shot service with no
delegate or Arena-volume access. Activation still requires a reviewed clean
SHA, a provenance/SBOM-attested linux/amd64 image, proof that the entrypoint
exists, and a new literal digest before that service may be executed.

`[partial]` The deal runtime, capability-free `dnai-safe-ir-v1` Arena worker,
and crash-resumable exact-asset Compute worker are implemented and locally
verified. Compute provider execution is not categorically disconnected: the
compiled Tinker 0.22.7 adapter records a durable at-most-once attempt checkpoint
before its first provider request, never claims upstream idempotent replay, and
never automatically redispatches after that boundary. A restart or
inconclusive post-boundary failure enters a terminal ambiguous-outcome
quarantine with ciphertext retained for separately attested reconciliation.
Production dispatch remains fail closed unless the exact release pins,
recipient activation, project flag, independent metering and settlement
capabilities, and a fresh authenticated worker heartbeat all agree. That
heartbeat proves process presence only, not TDX. The UI projects the exact
capability as modeled, unavailable, or live and does not infer readiness from a
configured endpoint. No fresh CVM/provider activation is claimed here.

`[real/source]` A clean-CI release lane now builds the exact five-image set
(`tinker-delegate`, `tee-email-oracle`, `neko-chrome`, `attestation-qvl`, and
`compute-metering`) for linux/amd64, generates SPDX SBOMs and SLSA provenance,
attests and independently verifies each immutable GHCR subject, and emits one
strict `dnai.tee-image-release.v1` manifest. A separate renderer accepts only
that exact manifest and produces seven digest-pinned Phala descriptors: the main
private runtime, five purpose-separated QVL CVMs, and independent Compute
metering. It also emits a hash-bound topology manifest. The QVL image is reused,
but its five deployments, policies, app/CVM identities, and signing roots are
not. These artifacts are generated with the explicit status
`rendered_not_deployed`; they are neither CVM evidence nor a TDX claim.

The latest recorded verification snapshot was green, but it predates the final
clean release SHA and is not deployment evidence. Counts below are a historical
test snapshot, not a promise that the still-changing working tree is identical:

- Foundry: **290 passed**, 0 failed/skipped across 14 suites; nine invariants
  executed **1,152,000 calls** with zero reverts. All seven production runtimes
  and initcodes are comfortably below EVM size limits.
- Tinker delegate: **1,794 passed**, **6 explicit skips**; Python compile checks
  are clean.
- Independent attestation QVL: **107 passed**; compute metering: **208 passed**;
  email oracle: **56 passed**; auxiliary service compile checks are clean.
- SolidJS: **160/160 Vitest** and **43/43 release-boundary tests**; typecheck and
  production build pass; `npm audit` reports zero vulnerabilities.
- Both source-build dstack compose merges validate, the repository secret scan
  passes, browser console checks are clean, and `git diff --check` is clean.
  One non-functional Starlette/httpx deprecation warning remains in Python test
  clients.
- The five production Dockerfiles complete real local BuildKit no-push builds
  for linux/amd64. Two independent no-cache OCI exports of every image are
  byte-identical; `tinker-delegate`, `tee-email-oracle`, and `neko-chrome` also
  produced stable workflow-style `type=image` subjects across two independent
  exports. Inline BuildKit provenance/SBOM is deliberately disabled because its
  per-run invocation metadata changes the root index; clean CI instead attaches
  signed GitHub provenance and SPDX SBOM attestations to the exact immutable
  registry subject. Aggregate release-manifest and pinned workflow tests pass,
  and the workflow parses as YAML; `actionlint` is not installed locally. A
  synthetic exact manifest renders the then-current production descriptors, and Docker
  Compose parses every generated descriptor.
- The complete seven-contract release workflow also passed an isolated local
  Base-Sepolia-shaped Anvil rehearsal: non-broadcast dry run, local broadcast,
  exact runtime-code proofs, separated initial roles, fail-closed policy,
  monotonic frozen policy-anchor witness, accepted diligence lifecycle, frozen
  and opened Arena challenge, and an evidence manifest outside the repository.
- The read-only activation preflight is independently tested and currently
  returns a blocking result. It confirms the Base
  Sepolia RPC, encrypted `dev` alias, GitHub auth, and Cloudflare auth without
  printing values or unlocking keys; it blocks on the dirty release root,
  absent clean-CI image manifest and generated production descriptors, missing
  independent roles/evidence/credentials, and rejected Phala auth. Historical
  non-operator images and the old combined compose are not accepted as a fresh
  release.

This is still not a live confidential-compute release. The current Cloudflare
build is explicitly modeled; no fresh project-owned Base Sepolia suite,
replacement Phala CVM, or independent production QVL domain was deployed. The
remaining activation gates are:

- commit and review the shared working tree so clean CI can publish immutable,
  provenance-bearing images and a source SHA can become a release root;
- unlock and fund the existing Foundry `dev` keystore without exposing its
  password, then provide distinct operator, diligence-verifier, Compute
  developer, metering-verifier, and QVL/approver trust roots plus the reviewed
  fee, cap, account, compose, and release commitments;
- replace the rejected Phala credential, supply the missing provider and
  registry credentials, deploy non-dev/private-observability CVMs, and obtain
  independent signed QVL evidence for their exact measurements;
- publish and pin the new delegate image containing the writer-evidence and
  worker entrypoints, execute the multi-day on-chain admission ceremonies, and
  only then generate a live browser release environment and publish it.

All older live evidence retained below belongs to prior operators and releases.
It is historical context, not current authorization for this product surface.

## Historical Engineering Ledger (Prior Operators And Releases)

The dated claims in the remainder of this file are intentionally preserved for
audit history. Words such as “current,” “live,” and “deployed” below describe
the dated prior release unless an entry explicitly says otherwise; they do not
override the 2026-07-16 verdict above.

At the time of the following record, the strongest vertical slice was the local
Tinker delegate flow plus sealed artifact ingress:

```text
email OTP -> Tinker login/onboarding -> bounded API-key provisioning metadata
encrypted artifact upload -> TEE-bound attestation report_data -> hash-checked in-memory custody
```

That historical production deployment was partially real on Phala: the combined
email-oracle + tinker-delegate CVM is running from digest-pinned registry
images and has live TDX envelope verification. Low-value operator validation
funding has now produced a bounded `$10.00` Tinker balance read. The live proxy
issue/deployment-policy gate has been deployed, attested, approved on-chain,
and proven with encrypted token delivery for earlier compose hashes. The newest
pinned client-config install compose is live and attested, but it is not yet
approved on-chain for compute spend and still lacks sealed `TINKER_PROJECT_ID`.
The deployed SDK smoke still fails before training creation. Production or repeated
funding, production identity/reviewer governance, full quote-internal TDX
verification, live CVM-originated TEE-to-chain signing, and RLVR/bio-validation
remain incomplete. Phala auth is configured for profile `wikigen` in workspace
`wiki`.

Live re-verification, 2026-07-11 (checked against the running system, not just
recorded evidence):

- Contracts on Base Sepolia respond and match this manifest via public-RPC
  reads: `TinkerAccountEncumbrance` (`0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e`)
  `owner=0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD`, `emergencyHalted=false`,
  `measurementsFrozen=false`; `approvedComposeHashes(0xe682…)=true` (latest
  approved) and `approvedComposeHashes(0x1d6d…)=false` (current funding compose
  still unapproved). `DiligenceRoom` (`0x5d8a…f423`) `developer` and
  `EmailOracleAuth` (`0xf52c…72ff`) `owner` both the operator address.
- CVM `cvm_1w85mGjo` / app `f6a3219…` reports `running` (dstack-dev-0.5.9). The
  delegate is reachable at
  `https://f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717-8080.dstack-pha-prod9.phala.network`.
  `GET /health` returns `status:ok`, `dstack_enabled:true`,
  `api_key_configured:true` (`api_key_source:encrypted_store`),
  `agent_stack_available:true`, oracle `degraded` (no email creds). Authenticated
  bounded `tinker-proxy-status` returns `mode:tee_cvm_delegate`,
  `jwt_signing_key_source:dstack_derived`, `issue_policy_required:true`,
  `deployment_policy_required:true`, `encumbrance_contract_configured:true`,
  `raw_secret_egress:false`.
- Confirmed still-open end-to-end blocker: the live proxy status reports
  `project_id_configured:false` (sealed `TINKER_PROJECT_ID` not installed) and
  the current compose `0x1d6d…` is unapproved on-chain, so a real Tinker SDK
  training/smoke cannot succeed. The current live compose also has the stricter
  governance gates OFF (`grant_lifecycle_required:false`,
  `identity_registry_signature_required:false`) — weaker than the earlier
  signature-required deployment — and remains `dstack-dev` / `public_logs=true`
  (dev posture). Net: infrastructure + policy gates are live and working; a real
  delegated training run is not yet proven.
- 2026-07-11 update: the current live compose
  `0x1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085` was
  approved on-chain in `TinkerAccountEncumbrance` tx
  `0x13e0f37af37fb79c9bf365c8fd0a82c1299c9f85f7b6ec01057d2915768ab6e7`
  (block 44001620). A real capped smoke (`tinker-smoke --require-encumbrance`,
  cap $0.05) against the live CVM then passed the spend policy
  (`compose_approved=true`, `allowed=true`, `metered_cost_band=zero`) but FAILED
  at `ServiceClient` creation with a 4xx. The initial guess (missing
  `project_id`) was WRONG. Root cause, found 2026-07-11 by decrypting the local
  sealed API-key store (`data/tinker_api_key.enc` + `.key`) and driving the
  Tinker SDK directly with the real key: the 400 body is "Your Tinker SDK
  version is no longer supported. Please upgrade to the latest version." The
  deployed CVM image ships `tinker==0.15.0`; the Tinker server now rejects it.
  Fix: pinned `tinker>=0.22` in `pyproject.toml` (local upgrade to 0.22.7 clears
  the version 400). After the upgrade the SDK connects with the real key but the
  account returns 402 "Access ... is blocked due to billing status. Please add
  payment." A capped $10 add-balance on the live CVM succeeded (browser balance
  $10 -> $20, real card), but the 402 PERSISTS at $20 — so it is an account-level
  Tinker billing/activation block, not a balance amount. Remaining blocker for a
  real delegated training run: resolve the Tinker account's billing status on
  the Tinker side (dashboard / account approval); it is not fixable by code,
  project_id, or more credit. The CVM also needs an image rebuild to pick up the
  supported SDK once the account is unblocked.
- 2026-07-11 re-confirmation: a read-only `get_server_capabilities` probe from
  the dev box (real sealed key loads, local SDK `0.22.7`, general internet works
  — GitHub 200) STALLED for 40s+ against the Tinker API, consistent with the
  blocked/unactivated account (a healthy account returns in ~1-2s). This is the
  authoritative remaining blocker and it is external to our stack: the operator
  must activate/enable API access on the Tinker account (or raise it with
  Thinking Machines support). Everything on our side — encumbrance approval,
  spend preflight, sealed key custody, bounded outputs, supported SDK pin — is
  proven up to that call. To stop retries from hanging, the smoke path now
  fail-fast caps the first authenticated SDK calls with a wall-clock deadline
  (`smoke_connect_timeout`, default 45s) and returns a bounded
  `transient_timeout` verdict with
  `operator_action=retry_or_check_tinker_account_activation`.

Latest pinned client-config install deployment, 2026-07-09:

- GitHub Actions run `29058135707` built source
  `3bb9ff4b986e95debbe0d13f9a02edb9c0d03f80` into digest-pinned images
  `tinker-delegate@sha256:a76c2efb9274d2669b98836fdc30450d79a1c96702150079e1ba13bf2d9b8ac6`,
  `tee-email-oracle@sha256:e663c88eb87e880abbc012befe1948a4a45007ea267ae85ab79a953936de9e99`,
  and
  `neko-chrome@sha256:4b36022cc2d0c50a0080c9f460a7252659a9a201ee2b43d8dfcffd033685a88a`;
  GitHub provenance and SPDX SBOM attestations were verified for all three.
- Phala CVM `cvm_1w85mGjo` / app
  `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717` is running app-compose hash
  `1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085`.
  `verify-cvm-attestation` passed against app ID, OS image hash
  `de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`,
  pinned image digests, local raw compose/image-policy hash
  `1db1ee033f333509726d03c325788e0fc5c0803351d6d1496ee42ff14fa83700`,
  rendered compose SHA-256
  `62bd3f65bfd1eb48f3f2ea927800ff21d7d8a83ebcef371117ddb4ac6a0a7cf4`,
  report data
  `8e32280159699041438f7ea35350d4e6b573c4dc2494dbd89a384f3f1c1287f1`,
  and encryption public key
  `1c1b7435172cf3453ed248a8c633f3945999e1e1104c890f00e22da171c95850`.
- Historical 2026-07-09 evidence: the now-retired update helper had a tested
  `--self-compose-hash-env` path. For that deployment it self-bound `TINKER_ENCUMBRANCE_COMPOSE_HASH`
  to the provisioned app-compose hash before encrypted env commit, with a
  twelve-key env surface and key hash
  `a694364185438f7508fe696ccf2fd971fc6060f8fa0c3aad633185c3d8fb7b30`.
  The current helper rejects those legacy flags and is validation-only for a
  complete reviewed seven-CVM batch; this is not a current deployment command.
- Read-only chain state reports
  `approvedComposeHashes(0x1d6db25672bba906c7bfad7ffd4f4413dabb1f6f824190ab9e72259677018085)=false`;
  the latest approved compute compose remains
  `0xe682ddac9de80188c7e68cab84cffe8f461478d87d506159f10cba3e65a342a7`
  from tx
  `0x3bc992cc2979aa8198923bcaf856d2c82d387646e49e750dada1f5cb203b3d17`.
- Live bounded client-config status reports `project_id_configured=false`,
  encrypted dstack-derived store missing, and `raw_secret_egress=false`.
  Bounded balance read reports `balance="$10.00"` without card details.
  Next required actions are to approve the live compose hash, seal
  `TINKER_PROJECT_ID` through `tinker-client-config --install`, and rerun the
  tiny `tinker-smoke`.
- The CVM still reports `dstack-dev-0.5.9`, `os.is_dev=true`, and
  `public_logs=true`; this remains a temporary debugging exception, not a
  production posture.

Latest signature-required proxy registry deployment, 2026-07-09:

- GitHub Actions run `29048558164` built source
  `0aeb8182fe6552e2546d1f9d9b16acb06f655db4` into delegate image
  `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:f3e98cc62009ef1d583545a4fab95651a87648f7f8594a290973dbcdbcb06f73`;
  local `verify-ghcr-image-attestation` verified GitHub provenance and SPDX
  SBOM attestations. Commit `94e3ea1` pins that digest in the
  funding-validation compose. Local `verify-compose-hash --phala-raw-compose`
  computes raw/image-policy hash
  `e682ddac9de80188c7e68cab84cffe8f461478d87d506159f10cba3e65a342a7` and
  rendered compose SHA-256
  `4c99b0f73a14bd40292ee71df343fd5e08f889e1932f4318d64657107e78e595`.
- Phala redeploy provisioned app-compose hash
  `4d62625b62354bae0831fcaf29a600b5a718d4db2ca00461e7dd3743ddfca2fe`
  for app `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717`, but the deploy script
  timed out waiting for that hash to become active while Phala reported an
  intermediate live hash
  `085fde3b8d36f4a4d26db65b1c29b5570f20c5262e6c8d230ef3f87645e6c9f9`.
  The CVM later reported `running`, and the live delegate health endpoint
  responded successfully.
- Live `tinker-proxy-status` proves the stricter proxy gates are active in the
  deployed CVM: `issue_policy_required=true`,
  `deployment_policy_required=true`, `grant_lifecycle_required=true`,
  `identity_registry_required=true`,
  `identity_registry_signature_required=true`,
  `identity_registry_signer_configured=true`, sealed Tinker API key available,
  `project_id_configured=false`, and `raw_secret_egress=false`.
- A fresh operator-validation policy and signed registry were installed through
  the live runtime-authenticated API. Bounded receipts report policy hash
  `47a6c41964ffac98bc90fd03216f419b1c1a0cee7a3a5152f88cbd5a308938d7`,
  registry hash
  `162df4185df255268bb03857d37da10c658240ae5b7067b1ff7eee40477bbb6a`,
  two active identities (`agent`, `reviewer`), verified registry signature
  binding, and `raw_secret_egress=false`.
- The current compose hash was approved on-chain by the operator terminal in
  tx `0x3bc992cc2979aa8198923bcaf856d2c82d387646e49e750dada1f5cb203b3d17`;
  read-only chain state reports
  `approvedComposeHashes(0xe682ddac9de80188c7e68cab84cffe8f461478d87d506159f10cba3e65a342a7)=true`.
  Live encrypted proxy-token issuance then succeeded for `proxy:status` with
  subject hash
  `979fb71132214bf62a7f332696061f0be32b1e60f00d02256d589df198393af8`,
  JWT-id hash
  `0acd4d8ffd865d253d8b200d209213bc7f384b59483f79c95fad240d663d1aee`,
  TTL `300`, `plaintext_token_returned=false`, and `raw_secret_egress=false`.
  Recipient-side decrypt wrote the JWT to ignored local scratch storage with
  token hash
  `c77372674ecb06cef9a1a96bf22f2baa18edc980ce9f739e07906a7c16383d7c`
  and did not return the plaintext token or private key. A live
  `tinker-proxy-status` call using that scoped JWT succeeded and returned a
  bounded `proxy_auth_context` for `proxy:status`.
- This remains operator-validation, not production governance: the registry
  signer is a temporary local verifier key kept in ignored `data/` scratch
  storage, and `TINKER_PROJECT_ID` is still not sealed/configured.
- Source/test-real follow-up after the live deployment adds reviewer-signed
  grant lifecycle approvals for the next proxy build. New flag
  `TINKER_PROXY_REQUIRE_GRANT_LIFECYCLE_SIGNATURE=true` requires an active
  grant lifecycle to carry an Ethereum signed-message signature over a
  canonical hash-only approval payload; the recovered signer address must hash
  to the grant's `approved_by_hash`. `sign-tinker-proxy-grant-lifecycle`
  writes the signed grant to an explicit file and emits only approval hash,
  signer hash, signature hash, output path, and `raw_secret_egress=false`.
  Focused tests prove valid signed grant issuance and missing/wrong reviewer
  fail-closed behavior. This is not yet deployed to Phala; production reviewer
  key custody and approval workflow remain open. Local
  `verify-compose-hash --phala-raw-compose` for the funding-validation compose
  now reports raw/image-policy hash
  `af76ae49abfb8860bed46259de8a631f9f7c6c2056070ea31956f9a034ae0cc8` and
  rendered compose SHA-256
  `49b353c2b3d974e6f0e055ccde8e28b27cb31814351a5108d773ecbb9b2fd601`.

Previous proxy policy deployment, 2026-07-09:

- GitHub Actions run `29043212028` built source
  `d9807a028702ff2b0ee1c077cc0970cafc334475` into delegate image
  `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:b0e7c63d276469d586a574a94bf0fc91feb0a223fa2cdb0dd3d49cd64c41a5ee`;
  the local deployment gate verified GitHub provenance and SPDX SBOM
  attestations.
- The live Phala funding-validation CVM `cvm_1w85mGjo` / app
  `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717` now reports status `running`
  and app-compose hash
  `40f0ca1a366a106a202f655c8dc74f4a14aadf40b7d86f7923a8f96515325ace`.
  The verified local raw/image-policy hash is
  `a860ba168b0334d8317fc56f0d2a971b79ad13bc206f5b43f3d04833d32f8eb7`,
  rendered compose SHA-256 is
  `b718208409a73f0bff4f2ab0efdead239111b7ff8fccc688ff889d103aad69d4`,
  OS image hash is
  `de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`,
  quote size is `5010`, report data is
  `e9f1bff6d81b11d8d88c7b87635e4473b9da37a8e6fba4b6625e662ca7485cf1`,
  and encryption public key is
  `a61ea59bf0c9b7713a5c868da993eb8fde2fad9245c90e5209a4525462394a3b`.
- The runtime env allowlist now includes the policy flags and
  `TINKER_ENCUMBRANCE_COMPOSE_HASH`, so proxy issuance can be self-bound to
  the exact attested compose hash. `TinkerAccountEncumbrance` approved the live
  compose hash in tx
  `0x5eea5735154e18cb94e198c1d7fc7867f1f2f095de4db2b85d7eb051a9dd73d6`
  at block `43928500`; read-only preflight returned `allowed=true`,
  `compose_approved=true`, `$10` max amount, and `raw_secret_egress=false`.
- The deployed operator installed a hash-only issue policy with policy hash
  `e4db29bfded844e0402e7ce61aba51360eb0fbe2aa1bab2013cd200b0164ea16` and
  grant hash
  `c2b23202b441ad6f9b80565f1b2b6cfc8402113b7c969485c76a7135a8a92a84`.
  Live token issuance returned encrypted delivery only, deployment-policy
  evidence, JWT-id hash
  `0891923ea9aa068d058adcdfaf864ec9da88d2027c1cc30f397fb7c111806df7`,
  token hash
  `f795f81f6d399a285fabacb903c3384060f89371d3e918b52d5ce227516ceda4`,
  and `raw_secret_egress=false`; the recipient-decrypted scoped proxy JWT
  successfully called `tinker-proxy-status`.
- Remaining open: production identity/reviewer-controlled grant lifecycle,
  quote-internal TDX parsing/freshness, reverting the temporary dev OS/public
  debug posture before production claims, the email oracle IMAP degradation,
  and the Tinker SDK smoke blocker around project/client configuration.

Latest live funding/debug state, 2026-07-09:

- Source commits `3e0c1e1407166252c879f45a5c092ed8e9bfe70a` and
  `b9a962f64fe0ec4a10ce4fe4bc97787a22f82995` added focused billing-session
  fixes after live packets kept failing closed as `auth_required` at
  `billing_page_loaded`. The second fix retries billing after a same-context
  inline `/auth/reauth` instead of depending only on saved Playwright
  `storage_state`.
- `b9a962f64fe0ec4a10ce4fe4bc97787a22f82995` is built, attested,
  digest-pinned, deployed, and approved on-chain. GitHub Actions run
  `29012433267` produced verified GHCR images
  `tee-email-oracle@sha256:ce0ea569280a796ce2a3d5517e22d03ad72a9d7a316a550d11bd1b155a85a5ce`,
  `tinker-delegate@sha256:1e3da3a88ef037b85678c7122a1a4a11a01ae687a36a57fd38deb1ed8984461e`,
  and
  `neko-chrome@sha256:7c0795e15e660d4501b6324c7f223fd65f22725a7752b683ae30a2874d373d01`.
  The live Phala funding-validation CVM `cvm_1w85mGjo` reports attested compose
  hash `a15af6d8e7262d7d2799fa31968c568933f3468771b808720583a6dc6ed998c5`,
  local image-policy hash
  `4c0bc5a7ae08e358ff2f026d2e6c7ae4326a64f4e686c2c530392b4bf03b3bab`, and
  rendered compose SHA-256
  `f28eb9ef304aa4634f1b3d765b539e33bde91a7b24b308d1146932ba02218855`.
  `verify-cvm-attestation` passed against the app ID, OS image hash, and all
  three image digests. The owner approved that compose hash in
  `TinkerAccountEncumbrance` tx
  `0x186d1ea81d9dfbeb0898485defcf427e8155cbcbb0f9e225326092616bd51c34`
  at block `43913068`; read-only `$10` add-balance preflight returns
  `allowed=true`.
- Live packet `/tmp/dnai-tinker-add-balance-packet-20260709T111135Z` proved
  the reauth leg succeeds (`tinker_auth` outcome `success`, furthest stage
  `authenticated`) and the add-balance leg reaches `add_balance_submitted` with
  `raw_secret_egress=false`. The add-balance receipt still fails closed as
  `unknown_failure` with bounded message `Add-balance completion not confirmed`
  because it did not see explicit success copy. A separate bounded balance read
  immediately afterward returned `balance="$10.00"`, so the low-value operator
  validation account is funded even though the automation receipt remains
  conservative.
- `check-funding-validation-packet --require-add-balance
  --require-deployed-attestation` passed for
  `/tmp/dnai-tinker-add-balance-packet-20260709T111135Z` when replayed with the
  full validation identity: validation ID
  `operator-real-card-reauth-add-balance-10usd-inline-reauth`, app ID
  `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717`, OS image hash
  `de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`, and
  compose hash `a15af6d8e7262d7d2799fa31968c568933f3468771b808720583a6dc6ed998c5`.
- The live CVM is deliberately in a temporary debug posture for this funding
  push: `os.is_dev=true`, `secure_time=false`, `public_logs=true`,
  `public_sysinfo=true`, `public_tcbinfo=true`, and browser/CDP debug ports are
  exposed. This is not production-current and must be reverted before any
  production deployment claim.

Latest Tinker execution buildout, 2026-07-09:

- Source now has the first Tinker proxy credential slice. The intended proxy
  boundary is documented in `PROJECT.md`, `ARCHITECTURE.md`, and `TODO.md`:
  upstream `TINKER_API_KEY`, `TINKER_PROJECT_ID`, browser session, card state,
  and provider endpoint remain sealed inside the CVM, while approved users get
  scoped delegate JWTs. `tinker_delegate.tinker_proxy` signs scoped HS256 JWTs
  from explicit local key material or dstack-derived CVM key material, encrypts
  token delivery to a recipient X25519 public key with AES-256-GCM, and returns
  only scopes, expiry, hashes, and encrypted envelope material. New
  `GET /tinker/proxy/status` and `POST /tinker/proxy/token` endpoints are
  disabled by default; token issuance also requires configured runtime bearer
  auth. Recipient tooling exists as source/test-real:
  `tinker-proxy-recipient-keygen` writes a `0600` X25519 private-key file and
  emits only the public key; `decrypt-tinker-proxy-token` decrypts an issuance
  envelope into a `0600` JWT file and emits only hashes/status. Production user
  approval and production governance remain open; however source now has a
  hash-only issue-policy gate and bounded spend caps for policy-issued proxy
  JWTs. With
  `TINKER_PROXY_REQUIRE_ISSUE_POLICY=true` and
  `TINKER_PROXY_ISSUE_POLICY_PATH`, issuance fails closed unless a policy grant
  matches the subject hash, recipient public-key hash, requested scope subset,
  and TTL cap. Successful responses expose only bounded `policy_binding`
  hashes/scopes/caps and `raw_secret_egress=false`. Spend-bearing scopes can
  also require `scope_limits.max_amount_usd`; policy-issued add-balance tokens
  carry that bounded limit, and `/billing/add-balance` rejects over-cap proxy
  requests before browser/payment automation starts. Runtime operators can now
  install and inspect canonical hash-only issue policies through
  `GET/PUT /tinker/proxy/issue-policy` or `tinker-proxy-issue-policy`; outputs
  are bounded policy/grant summaries, not raw subjects, public keys, bearer
  tokens, or plaintext JWTs. Source now also has an optional deployment-policy
  gate: `TINKER_PROXY_REQUIRE_DEPLOYMENT_POLICY=true` checks the configured
  `TinkerAccountEncumbrance` contract and compose hash before minting
  add-balance or Tinker-smoke scoped JWTs, using only bounded spend caps from
  the issue-policy grant. Live funding-validation deployment, attestation,
  audit replay, compose/contract binding, policy install, pre-mint
  deployment-policy checks, and encrypted proxy-token delivery are now proven
  in the deployed operator-validation slice above. Source/test-real grant
  lifecycle enforcement now exists too:
  `TINKER_PROXY_REQUIRE_GRANT_LIFECYCLE=true` rejects missing, pending,
  revoked, expired, or future-approved grants before JWT minting, and bounded
  outputs expose only lifecycle status, reviewer/approval-event hashes,
  timestamps, and `raw_secret_egress=false`. Source/test-real hash-only
  identity-registry enforcement now exists too:
  `TINKER_PROXY_REQUIRE_IDENTITY_REGISTRY=true` rejects issuance unless the
  requester is an active user/agent identity and the lifecycle approver is an
  active reviewer/admin identity in a schema-v1 registry. Outputs expose only
  registry hash, identity hashes, roles, statuses, expiries, and
  `raw_secret_egress=false`. The source compose now includes disabled
  lifecycle and identity-registry env knobs; local `verify-compose-hash
  --phala-raw-compose` computes raw/image-policy hash
  `d4144c01872da1501d193f3b0b9936d06ebb04912740fd9b6ef90db420fc373d` and
  rendered compose SHA-256
  `a8451734acffd87426d28cdd1d8ba9aa2c2fa8cb2928da1cbb78a649ddfb8ccb`.
  Binding that registry file to a production verifier/reviewer workflow and
  live lifecycle-required Phala deployment remain open.
- First proxy-token authorization wiring is source/test-real:
  `GET /tinker/proxy/status`, `POST /tinker/smoke`,
  `GET /billing/payment-method-status`, and `POST /billing/add-balance` accept
  either the operator runtime bearer token or a proxy JWT with the matching
  scope. Proxy-authorized responses include a bounded top-level
  `proxy_auth_context` with auth kind, required scope, subject hash,
  JWT-id hash, granted scopes, expiry, and `raw_secret_egress=false`; runtime
  operator bearer responses do not. Token issuance, reauth, card add/remove,
  and funding receipts remain operator-only. The `add-balance` CLI now supports
  `--api-url`, `--auth-token-env`, `--output`, and `--receipt-output` for
  remote bounded add-balance attempts, and receipt files copy the bounded proxy
  context when a proxy JWT authorized the call.
- Proxy-token audit and revocation are source/test-real. `ProxyTokenStore`
  persists bounded `issued` and `revoked` records in AES-GCM sealed storage;
  issuance appends an audit record, operator-only API/CLI surfaces can list
  bounded audit records and revoke by `jwt_id_hash`, and proxy-token
  verification rejects revoked JWT IDs. Revocation now fails closed for
  unknown/non-issued JWT-id hashes before writing a record, and retrying
  revocation for an already-revoked issued token returns the existing bounded
  revocation record instead of duplicating audit entries.
  `verify-tinker-proxy-token-audit` is
  now source/test-real: it verifies exported bounded audit JSON and optional
  bounded operation receipts without plaintext JWTs, checking record schema,
  counts, chronology, supported scopes, expiry, revocation timing, receipt
  boundedness, and `proxy_auth_context` binding when present or required.
  Production identity/spend policy binding remains open.
- The previous proxy-token verifier/context build was live on the Phala
  funding-validation CVM before the newer proxy issue/deployment-policy
  deployment recorded above. Source
  `7cce6a2bc7897afba7a1599f9b51a381ac09a7dd` was built by GitHub Actions run
  `29039324890` into delegate image
  `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:3ed351ed41540d7e47970b9b4d6a288d600b3856bc64c6f01996f4507d15b1eb`;
  local `verify-ghcr-image-attestation` verified provenance and SPDX SBOM
  attestations for that digest. The funding-validation compose pins that digest
  and enables only the temporary proxy-token validation surfaces behind runtime
  bearer auth. Direct Phala state and `verify-cvm-attestation` proved live
  app-compose hash
  `5bea582098b3767eec52d05a4f5a6773c59c44b606776421888479f58324956c`,
  raw/image-policy compose hash
  `049c89d04c8e3b5452c12568a4f2c550bd123e7a3fe4489cd1a7c39e854b8489`,
  rendered compose SHA-256
  `e2728a0bf803aff975034db4314d525c2d7092bb5f2c772219e1768a21da4423`,
  app ID `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717`, OS image hash
  `de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`,
  and report data
  `09934d56f646c25d54876f4d9a360c0b8c93d90b096509bcb6b6db8adde897d2`.
  The owner approved that compose hash in `TinkerAccountEncumbrance` tx
  `0x5af4fd76e922afc821c1db847aa3b65cbd44bc328a48786d6f7cca4a0e41d2cb`
  at block `43926723`; `$10` add-balance preflight for that compose returns
  `allowed=true`.
- Live packet `/tmp/dnai-proxy-audit-live-20260709T182943Z` proves the bounded
  proxy-token path without exposing token material: the CVM issued an encrypted
  recipient-bound JWT for subject hash
  `979fb71132214bf62a7f332696061f0be32b1e60f00d02256d589df198393af8`,
  scopes `billing:payment-method-status` and `proxy:status`, and JWT-id hash
  `a9e3ef84944849a117f4f962a4d86f89991a7676a2e6c5709cb54db503a445be`; the
  recipient decrypted it locally to a `0600` temp file, used it against
  bounded `GET /billing/payment-method-status`, and got
  `card_on_file=true` / `payment_method_count_band=one_or_more` with
  `raw_secret_egress=false`. `verify-tinker-proxy-token-audit
  --require-operation-binding` replayed the exported audit plus operation
  receipt and returned `ok=true`, `bound_operation_receipt_count=1`,
  `missing_operation_binding_count=0`, audit hash
  `e7ece7f2381b57c8560ee8cc4fc60bc2853027b016c57a94b02d27fc86aa1f64`, and
  verification hash
  `9d345d4d8e2b399d1279e1835729a12a10ac0b40d15750a9c7c23e7cdf91420c`.
  The temp packet contains a plaintext proxy JWT and recipient private key on
  local disk; those are not committed and are evidence-local only.
- Source now has a bounded real-SDK smoke surface for the funded Tinker account.
  `tinker_delegate.tinker_smoke.run_tinker_sdk_smoke()` uses the sealed API-key
  resolver, checks `TinkerAccountEncumbrance` with `SPEND_TINKER_COMPUTE`,
  enforces a hard `$0.50` smoke cap, runs one tiny train/checkpoint/sample/
  cleanup sequence through `IsolatedTinkerSession`, and returns only bounded
  hashes, cost bands, policy state, sample-observed boolean, and cleanup counts.
  It does not return API keys, raw run IDs, checkpoint paths, checkpoint IDs,
  sample text, weights, or raw model output.
- Operator surfaces are source/test-real and deployment-partial:
  `tinker-smoke` can run in-process inside the CVM/container or call
  `POST /tinker/smoke --api-url`; the HTTP endpoint is disabled by default,
  requires runtime bearer auth when enabled, and is enabled only in the
  temporary funding-validation compose profile for explicit smoke validation.
- Focused validation passed locally with mocked Tinker SDK and API/CLI gates:
  `uv run python -m unittest tests.test_tinker_smoke tests.test_api_tinker_smoke
  tests.test_cli_bounded_outputs tests.test_isolated_session
  tests.test_run_metadata_store
  tests.test_tinker_real_sdk_integration.TinkerRealSdkGateTest`. The
  smoke-capable delegate image has now been built by GitHub Actions, pinned in
  the Phala funding-validation compose, redeployed, and approved on-chain for
  `SPEND_TINKER_COMPUTE` under compose hash
  `c6b446fe9b7ff656c6db799a7461a2a6dba045ae24de16d365c80a6cb83863da` in
  `TinkerAccountEncumbrance`
  `0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e`; approval tx
  `0xc7adf6b22668f3aa15d9d7e81dff444daac3f1f4b8339981f842042ddd7dbb67`.
  The live smoke attempt is still not complete: it passes policy and sealed
  API-key load, then fails closed with `BadRequestError` at `api_key_loaded`
  before Tinker training creation. The bounded deployed receipt at
  `/tmp/dnai-tinker-smoke-diagnostics-20260709T121857Z.json` reports Tinker SDK
  `0.15.0`, `sdk_error.bucket=invalid_request`, HTTP class `4xx`, model family
  `meta-llama`, rank band `<=8`, and no capability probe result from
  `ServiceClient.get_server_capabilities`.
- Source now adds bounded SDK failure diagnostics for the next deployed smoke
  attempt: receipts include an allowlisted `sdk_error.bucket`, normalized
  redacted `sdk_error.message_hash`, coarse `message_length_band`, bounded
  `sdk_diagnostics` covering request shape plus capability probing, enum
  `sdk_error.failure_site`, enum `sdk_error.operator_action`, and optional
  `TINKER_PROJECT_ID` configured/hash evidence without returning the raw project
  id. Focused tests prove raw
  provider-message text, supported model lists, API-key-shaped, email-shaped,
  card-shaped, request-ID-shaped, deal ID, run ID, checkpoint, and sample
  material do not leave the receipt.
- Additional bounded live probes on the same deployed compose tried the
  official quickstart model `Qwen/Qwen3-8B` at ranks `32` and `16`; both failed
  before training creation with the same bounded `BadRequestError` message hash
  as the original Llama/rank-4 attempt. The current working hypothesis is a
  project/account entitlement or service-side account configuration requirement.
  The source default has been moved to `Qwen/Qwen3-8B` rank `32`, but real
  execution remains unproven until a deployed receipt reaches
  `cleanup_completed`.
- The project-aware delegate image is now a verified local deploy candidate, not
  yet successful for real Tinker training. GitHub Actions run `29020924145` built source
  `6f5d557d1dab6641590c12ad96eecad74a101638` into
  `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:d7872a09b7fe28e25a53dafa721a355cb0677d42e2939f4babbbff7e167f306d`.
  Local `verify-ghcr-image-attestation` verified SLSA provenance and SPDX SBOM
  predicates for that digest, and the funding-validation Phala compose pins it.
  Local `verify-compose-hash` computes image-policy compose hash
  `d0aea171db3483ae1dae4ff73294548ca5906481166893114ce048688bf2f3f9`; Phala
  redeploy then moved the live CVM to app-compose hash
  `314cd60b093194dcac0480f3586c8979a9734a56c7a521cd8ef043dee9417816`.
  `verify-cvm-attestation` passed against that live hash, app ID, OS image hash,
  and all three digest-pinned images. `TinkerAccountEncumbrance` approved the
  new compose hash in tx
  `0x17c7064496711ae93c39f0489667fe7555d6455f18f01eae174c1aa5a92fa3f6`;
  runtime preflight for `spend_tinker_compute` at `$0.05` passed. The new live
  smoke receipt
  `/tmp/dnai-tinker-smoke-project-aware-20260709T134058Z.json` still failed
  before training creation, but now reports
  `sdk_error.failure_site=service_client_create`,
  `sdk_error.operator_action=check_sdk_client_configuration`, correct
  Qwen/rank-32 request shape, and `project.configured=false`.
- Source follow-up after that live receipt fixes the next diagnostic blind spot:
  if `ServiceClient` construction fails, receipts now still include accurate
  bounded client configuration evidence for `TINKER_PROJECT_ID` and
  `TINKER_BASE_URL`. The new `client_config` block records only whether the API
  key, project-id, and base-url arguments were provided, plus a base-url host
  family and hash; it never returns the raw project id or endpoint. `ControlPlane`
  now passes the same project/base-url settings to future evaluator sessions, so
  the smoke path and real deal path stay aligned. The gated direct real-SDK
  integration test also uses the same optional settings. GitHub Actions run
  `29023713771` built source
  `76609fbe6617a8c7162c4dbfbbbc060e9b01322e` into
  `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:83e58d165cc30374feb70f475dc6bf30da07d63895f6d871feb4f7828926758b`,
  and local `verify-ghcr-image-attestation` verified provenance and SPDX SBOM
  attestations for that digest. The updated local rendered-compose candidate
  now hashes to
  `fdaf00da9657560705d8f315667201cdebad5cc134e351eecb105f74339e4211` with
  rendered compose SHA
  `49cec4b25620ffb96bf38e57f3ed554a60f0ca4c98c9dc9b017d082a1d971af9`;
  `verify-compose-hash` reported `allowed_envs=[]` for this local check. This
  follow-up has now been redeployed to Phala and approved on-chain. Deploy
  helper provisioned app-compose hash
  `cdd1b3b37a96595bd0859c5970a7e8938db9a67a161640caeab46c4ccebdb180` with
  nine runtime env keys selected by compose refs; the helper timed out while
  polling intermediate hash
  `ddeb603e2af86d3c0c696a714b49e1bb80efdff6ea80e9df0fbaaba56d3219ac`, but
  direct `phala cvms get`, serial logs, `/health`, and
  `verify-cvm-attestation` proved the CVM running the intended app-compose.
  Attestation verification passed against raw compose hash
  `60046a718ba13c71f015a8633b4a9ee6892661762414e9e61636a897327a2d82`, live
  app-compose hash `cdd1b3b37a96595bd0859c5970a7e8938db9a67a161640caeab46c4ccebdb180`,
  app ID, OS image hash, and all three digest-pinned images. On-chain approval
  tx `0xc597c8e2bbfcc58255c6d407ce615ec4befd992b4e4ef2c34854b99a4d4c52b2`
  landed in block `43919367`, and encumbrance preflight for
  `spend_tinker_compute` at `$0.05` passed. Live smoke receipt
  `/tmp/dnai-tinker-smoke-client-config-live-20260709T142413Z.json` still
  fails before training creation at `service_client_create`, but now confirms
  bounded `client_config.api_key_argument=provided`,
  `client_config.project_id_argument=omitted`, and
  `client_config.base_url_argument=sdk_default`, with `raw_secret_egress=false`.
  The blocker is now specifically missing Tinker project/client configuration.
  Follow-up source slice: `tinker-smoke-command-plan` now emits a bounded
  no-secret install/redeploy/attest/approve/preflight/smoke command plan for
  the next retry. It reports `ready=false` until bounded live evidence shows
  project config sealed, emits `next_action`, and includes
  `client_config_install_shell` for the case where the live CVM already exposes
  `/tinker/proxy/client-config`. The plan uses only environment variable names
  plus a new-compose placeholder rather than project IDs, bearer tokens, API
  keys, RPC URLs, run IDs, checkpoint paths, or sample text.
  Follow-up image evidence: GitHub Actions run `29058135707` built source
  `3bb9ff4b986e95debbe0d13f9a02edb9c0d03f80` into
  `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:a76c2efb9274d2669b98836fdc30450d79a1c96702150079e1ba13bf2d9b8ac6`,
  `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:e663c88eb87e880abbc012befe1948a4a45007ea267ae85ab79a953936de9e99`,
  and
  `ghcr.io/g-structure/dnai-wikigen/neko-chrome@sha256:4b36022cc2d0c50a0080c9f460a7252659a9a201ee2b43d8dfcffd033685a88a`.
  Local attestation verification passed for provenance and SBOM on all three
  images. The funding-validation compose is pinned to these digests and has
  local raw compose candidate hash
  `5d469e071e416305b032172683616d72efb12e99ca9b3ee5200cfd60d532f07a`
  with rendered compose SHA-256
  `62bd3f65bfd1eb48f3f2ea927800ff21d7d8a83ebcef371117ddb4ac6a0a7cf4`.
  This candidate is not yet live until redeployed to Phala, attested, and
  approved on-chain for the resulting live compose hash.

Latest Phala evidence, 2026-07-09: GitHub Actions built source commit
`6ff5531aabb952b3266210afa6c0b6bfb8860103` into GHCR digest-pinned
`tee-email-oracle@sha256:f5c346912f3391e699252dba47c673902d06ffe528a8bab9732a76d551ec42ab`,
`tinker-delegate@sha256:f9eb714c5630549441636b8a5525b20c9518e863940a3b8e072dff5a5dcab37d`,
and
`neko-chrome@sha256:525e43d585828d1d9aa1bceaf7c8cfffc2eec47abf67e0b10550bf05338c4a07`
images. Local `verify-ghcr-image-attestation` checks passed for SLSA
provenance and SPDX SBOM attestations on all three GHCR images. The current CVM
`cvm_1w85mGjo` is temporarily running the auth-gated funding-validation profile
for app ID `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717`, not the normal
locked-down compose. The live Phala attested compose hash is
`f4728f219572c09c6ccc013883a4a895f3e366ea6e9654459fd6b0002fe33552`, with local
image-policy hash
`a0045b4a0995f858dde0d473a16b997459a6bd009f78c55b0d5ee471ba58f81f`,
rendered compose SHA-256
`e8938c5c3896376df2219ddcee78dd26c82963c6fc57ab98431ce6b39122302f`, and an
eight-key runtime env surface. The live billing-context TDX envelope reports
report data `51df5f2c0f61dd488a65f82d803fe29a6eb72903b9c1a510b00b1848aa0703fb`,
encryption public key
`d7ce6072bcdffbb82a998ce2c676cf47e8bc4122447fb183272ee0551bc5e474`, and quote
size `5010`. Public logs remain disabled. Health is OK, the oracle is ready,
IMAP is connected, the Tinker API key is available from the encrypted store, and
unauthenticated `/auth/reauth` plus `/billing/add-balance` fail closed with
`401 Bearer token required`.

Browser auth repair result, 2026-07-09: the deployed browser blocker is solved
for the Tinker auth/API-key path. The custom Neko Chrome/CDP image that
previously only existed as a local compose build is now on the GitHub-attested
GHCR path, pinned by digest, and used by the Tinker bootstrap, selector
diagnostics, and funding-validation Phala composes. The old Phala path used an
upstream Neko image plus inline CDP proxy/runtime rewrites and timed out at
page-level CDP (`Page.enable`). The current Phala path uses the custom
`neko-chrome` image with a baked Nginx CDP proxy on `9222`; `/browser/readiness`
and `/browser/selector-probe` both succeed, the bootstrap profile captured and
sealed a Tinker API key with bounded `api_key_captured_and_stored` evidence, and
the funding-validation profile can re-authenticate successfully without raw
secret egress.

Funding profile live result, 2026-07-09: remote preflight for `$5` with
`operator_capped_validation`, the add-balance endpoint requirement, and live
deployment identity configured returned ready for the historical `$5` validation
path. The manifest-driven `funding-command-plan --amount 5` targeted attested
compose hash
`f4728f219572c09c6ccc013883a4a895f3e366ea6e9654459fd6b0002fe33552` plus the
deployed `TinkerAccountEncumbrance`
`0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e`, and returned `ready=true` with
`raw_secret_egress=false`. Authenticated `/auth/reauth` now succeeds and the
browser session store is available for billing. The first bounded,
operator-approved real-card validation attempt did not fund the account: live
`GET /billing/balance` returned `$0.00`, the payment-method receipt reached
`payment_submitted` and saw only bounded card-management copy (`This card can be
removed at any time.`), and the add-balance receipt stopped at
`add_balance_modal_opened` with `selector_missing` /
`Add-balance amount input not found`. Source now has a focused local fix that
treats that card-management copy as payment-method success and adds scoped
amount-input/preset-amount fallbacks for the add-balance modal; it also models
Tinker's `$10` whole-dollar minimum, exposes bounded card-on-file status
(`card_on_file` plus count band only), and adds an authenticated admin/operator
card-removal path with bounded receipts. The source fix is now deployed to
Phala in the temporary funding-validation profile. The deployed
`TinkerAccountEncumbrance` policy has now been updated from `$5` to `$10`
add-balance/spend caps in tx
`0x3ab263bb7cb7758787fa1136dd043cca002db9cf511b29ad20ef4d1216199d3f`
at block `43904511`; local `cast` reads returned
`10000000000000000000` for both `maxAddBalanceWei()` and `maxSpendWei()`.
The refreshed source commit
`8a571347d946fd6c23a84db256fd99f7169061e5` was built by GitHub Actions run
`28998076083` into digest-pinned images
`tee-email-oracle@sha256:beedfc6c3f1f0c9dca8604d6adf6522110e8dc2f15af1e8a9145e0e3227939a9`,
`tinker-delegate@sha256:3e03e4dccde8ef732641fdd091597a683674ca3b065b950a983aab16c6b88878`,
and
`neko-chrome@sha256:fd6a65a894befc66901ed7b915c792f3a669b74ef4ace01813815e1f1030b456`;
local SLSA provenance and SPDX SBOM checks passed for all three. The existing
CVM `cvm_1w85mGjo` / app
`f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717` now reports live attested compose
hash `9f0754be7b7bcd3db9c808e5630f7f0aca39a33bbe37f898b8714de6d9aa4d71`,
local image-policy hash
`880db4987c00ecd8643aedc794415accd83c47a337b4512810d9fe5cadab8e6a`, and
rendered compose SHA-256
`962e0352a468460eaa6085a2a32a6b7005798c7e3e5f3ff71e9799fa0cf67ea7`.
`verify-cvm-attestation` passed against those images, app ID, OS image hash,
and live TDX envelope. Live `/auth/reauth` succeeded and saved session state;
bounded payment-method status returned `card_on_file=false` and
`payment_method_count_band=zero`, so the next real validation must add a card
and then add `$10` credit. The initial on-chain blocker was expected and
fail-closed: before operator approval, `approvedComposeHashes(0x9f0754be...)`
was false and `funding-preflight --amount 10` reported
`compose_hash_not_approved`.
At that checkpoint, production deployment remained partial because the CVM still
reported `dstack-dev-0.5.9` / `is_dev=true`, quote internals were not yet
parsed, the new card-add/add-balance packet still timed out before producing
bounded receipts, and live low-value top-up had not yet succeeded. Later
evidence in this ledger records the funded `$10.00` validation result.

Funding retry follow-up, 2026-07-09: the operator approved the refreshed
compose hash on-chain in tx
`0xb7e6d0fc504146d88005339bd859142a5f2d6c3f99315d81cb00742ebc15d48e` at
block `43905420`, and read-back returned `true`; fresh `$10` preflight then
returned `ready=true` with `tinker_encumbrance=allowed`. Packet
`/tmp/dnai-tinker-funding-validation-packet-20260709T065233Z` was attempted
without reauth, but still timed out before writing `payment-method-receipt.json`
or `add-balance-receipt.json`. A later bounded card-status probe still returned
`card_on_file=false` / count band `zero`, so no card-add or top-up is proven.
Source fix `5ab9e81` improves the operator prompt to echo `*` per typed
character with backspace support and raises the local encrypted-card upload
timeout from 30 seconds to 180 seconds so the client waits for deployed browser
automation. This is a local CLI/client fix; the live CVM does not need redeploy
for it.

Funding retry follow-up 2, 2026-07-09: packet
`/tmp/dnai-tinker-funding-validation-packet-20260709T071145Z` ran with the
masked prompt and long client timeout. The packet wrapper completed and wrote
bounded manifests, but funding still did not succeed. The payment-method
receipt was `transient_browser_failure` at `not_started`: after opening the
billing modal, the fallback attempted to click the background `Payment methods`
tab while Tinker's modal scrim intercepted pointer events. The add-balance
receipt reached `add_balance_submitted` but ended as `unknown_failure`; this is
not a proven charge or top-up. Local source now dismisses an open billing dialog
before tab fallback, keeps browser-exception receipt messages to classified
outcomes instead of raw Playwright/page text, and fixes masked-prompt newlines.
This source-side browser hardening was then built by GitHub Actions run
`29001302688` from source
`658f6020db9972e0f7e1e914f72422ff5d08535f`; the new delegate image
`tinker-delegate@sha256:35bcc693300644445af40e7d4eb5d488848a2006ed2d42b7f56638c60963c92c`
has verified GitHub SLSA provenance and SPDX SBOM attestations. The existing
CVM was redeployed with that delegate image and now reports live attested
compose hash `7edf41c2b7bec5531639df94b90e2d2b5d1ac181f07db17f012c085d8cdb6476`;
`verify-cvm-attestation` passed against the new delegate image, app ID, OS
image hash, and live TDX envelope. `/auth/reauth` succeeded after restart and
bounded card status is again `card_on_file=false` / count band `zero`. The new
compose is deliberately blocked at the on-chain encumbrance layer:
`approvedComposeHashes(0x7edf41...)` is false and
`tinker-encumbrance-preflight --operation add-balance --amount 10` returns
`compose_hash_not_approved`. That checkpoint was blocked until the operator
approved the new compose hash; later entries record the approval and follow-up
funding attempts.

Funding retry follow-up 3, 2026-07-09: the operator approved the modal-fix
compose hash on-chain in tx
`0x0821933345af2d0090ed0ce99e8bc0c4856202b84ef6fbe5dd184dacdba50ad2` at
block `43907277`, and read-back returned `true`. Packet
`/tmp/dnai-tinker-funding-validation-packet-20260709T074049Z` then passed
preflight and produced the first deployed real-card payment-method success:
`payment_method` receipt outcome `success`, furthest stage `payment_submitted`,
`card_payload_destroyed=true`, TDX quote hash present, and `raw_secret_egress=false`.
This proves the deployed encrypted-card/payment-method leg is working. The
same packet did not prove funding: the add-balance receipt reached
`add_balance_submitted` but returned `unknown_failure`, and balance read-back
still returned `unknown`. The live add-balance receipt exposed a bounded-message
bug: the billing error classifier matched ordinary navigation text beginning
with `Payment methods`. Source now narrows that classifier and makes add-balance
fail closed as `Add-balance completion not confirmed` unless explicit success
copy is seen. It also improves bounded card-on-file status by using DOM signals
such as remove-card controls without exposing brand, last4, expiry, or billing
address. This source fix has tests but still needs GitHub-attested build, Phala
redeploy, compose approval, and a fresh add-balance attempt.

Funding retry follow-up 4, 2026-07-09: source
`2ab388103817bfbfaa7e20579a79213ed87fd85a` built successfully in GitHub Actions
run `29002851796`; the new delegate image is
`ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:06c8d0fadd98922f0c6f5bded92b414be2bf423fc3c3e6af1b8e9e36b8c6975f`.
Local `gh attestation verify` passed for both the SLSA provenance predicate and
the SPDX SBOM predicate, tying the image to the `Build TEE Images` workflow,
github-hosted runner, source digest `2ab388103817bfbfaa7e20579a79213ed87fd85a`,
and run `29002851796`. The funding-validation compose was updated to pin that
digest and redeployed to existing CVM/app
`app_f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717`; the update completed in 88s.
Local compose/image-policy hash is
`2eb459e0ff48ff88db0f75fb6ee7f3afb7811a5f0ea2180cc750e4f2115ba6f6`; Phala
raw-compose hash with the eight allowed env keys is
`bc9b8b228629fa726919dae7d9f050e4ae27914f4fde0cacc094fc537176c6cf`;
live TDX attestation reports compose hash
`a3d0a1bc28983731db0fcc27be5680a312d3dc8a84c47e7e30596fe5dfb16fc9`, app ID
`f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717`, OS image hash
`de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`, and
`verify-cvm-attestation` passed against the required digest-pinned images.
`/auth/reauth` succeeded after redeploy and bounded
`/billing/payment-method-status` now returns `card_on_file=true`,
`payment_method_count_band=one_or_more`, `bounded_message=payment_method_count:one_or_more`,
and `raw_secret_egress=false`. On-chain `tinker-encumbrance-preflight` for
`add-balance`, amount `$10`, and compose hash `0xa3d0...6fc9` currently denies
with `compose_hash_not_approved`; the next top-up attempt is blocked until the
operator approves this new compose hash. Later entries record the approval and
the successful `$10.00` validation balance read.

Funding retry follow-up 5, 2026-07-09: the operator approved compose hash
`0xa3d0a1bc28983731db0fcc27be5680a312d3dc8a84c47e7e30596fe5dfb16fc9` on-chain,
and `tinker-encumbrance-preflight --operation add-balance --amount 10` returned
`allowed=true`, `compose_approved=true`, and `raw_secret_egress=false`.
However, the two add-balance packet directories
`/tmp/dnai-tinker-add-balance-packet-20260709T081455Z` and
`/tmp/dnai-tinker-add-balance-packet-20260709T081805Z` did not run reauth or
add-balance browser mutations: both stopped at preflight with
`error_kind=preflight_not_ready`, and both have `add_balance_attempt_run=false`.
No top-up or charge is proven by those packets. The immediate blocker was a
deployed endpoint timeout while fetching billing attestation. The existing CVM
was restarted, then temporarily redeployed with public logs/public sysinfo and
SSH key injection for diagnosis. This is an explicit non-production debug
exception. The debug redeploy reports live compose hash
`a479a1ca1595e7b717e8c8e28ea60dfcef5430bb7792800180453a6b3790aa89`, public
logs/sysinfo enabled, and the same digest-pinned delegate/browser/oracle images
as the prior funding-validation compose. Container logs show delegate internal
health checks and `/attestation?context=billing` returning `200 OK`, but local
HTTP clients receive zero bytes from the public Phala gateway for the Python
delegate/oracle ports even with 60-90 second timeouts. Neko's public port
returns normally, and the public CDP port returns the expected Chrome
host-header rejection, so the current blocker is the Phala gateway/Python
service delivery path rather than the add-balance selector itself. The oracle
also currently reloads sealed mailbox credentials but reports repeated IMAP TLS
EOF failures against `mail.cock.li:993`; reauth and OTP use should be treated
as not ready until this clears. The debug hash is not approved on-chain, and
`verify-cvm-attestation` cannot pass while the public attestation endpoint
times out. Do not run a charge-capable add-balance packet until the gateway
timeout is fixed, attestation fetch passes again, and the resulting compose
hash is approved.

Gateway timeout fix, 2026-07-09: the public zero-byte timeout was reproduced
locally with `uvicorn` on `127.0.0.1`, proving the immediate blocker was not
only Phala ingress. Root cause: several FastAPI handlers were declared
`async def` while doing blocking synchronous work. In particular, `/health`
called the synchronous `OracleClient.health()` path; when oracle health stalled
on IMAP/TLS, the single Uvicorn event loop was blocked and `/attestation` plus
other requests queued behind it. Source now declares blocking/synchronous
handlers (`/health`, `/attestation`, `/billing/funding-policy`,
`/billing/funding-preflight`, and `/billing/funding-receipts`) as plain `def`
handlers so FastAPI runs them in its threadpool. Regression test
`tests/test_api_event_loop.py` starts the real ASGI server, makes oracle health
sleep, and proves `/attestation?context=billing` still returns promptly.
Focused validation passed with `uv run python -m unittest tests.test_api_event_loop
tests.test_api_billing_policy tests.test_funding_policy
tests.test_funding_validation_packet` (41 tests). Local manual reproduction now
shows `/attestation?context=billing` returning in about 11 ms while `/health`
waits about 30 seconds on oracle health. This fix still needs GitHub image
build, Phala redeploy, live attestation verification, on-chain compose approval,
and then a fresh bounded add-balance packet.

Gateway timeout follow-up, 2026-07-09: the delegate event-loop fix was built by
GitHub Actions from source `9e72eec59f5ea784ffbe9d0702e1569bb1ac1a29`, verified
with provenance and SPDX SBOM attestations for delegate digest
`tinker-delegate@sha256:5f53e8d09d53fc76b17155ce40bd51a0333a85c4e77a0e82a511551895f02995`,
pinned in the funding-validation compose in `d4b325c`, and redeployed to the
existing debug-posture Phala CVM. Live public
`/attestation?context=billing` returned `200` in about 1.7 seconds and
`/health` returned quickly instead of hanging behind oracle health. The
remaining runtime blocker is now narrower: the oracle container still reports
IMAP failures against `mail.cock.li:993`, and its healthcheck was reconnecting
IMAP too aggressively. Source now makes oracle `/health` non-mutating and
cache-based, with `/pin` owning real IMAP work and failing closed on mailbox
errors. Validation passed with `uv run python -m unittest tests.test_api_auth`
(22 tests), `uv run python -m unittest discover -s tests` (44 tests), and
`uv run python -m py_compile email_oracle/api.py tests/test_api_auth.py`. This
oracle fix still needs GitHub image build, attestation verification, digest pin,
Phala redeploy, and live health/preflight verification before any new
add-balance attempt.

Oracle health image follow-up, 2026-07-09: GitHub Actions run `29007296878`
built source `2f2a7d9f94ca29261ce0f5352e289e5071c7e38e`; CI run
`29007296962` also passed. Local attestation verification passed for
`tee-email-oracle@sha256:e0f8758018ac779fda402fb22a9fbd282fe107bd81222346307f81770869e1f4`
with GitHub provenance and SPDX SBOM attestations and `raw_secret_egress=false`.
The funding-validation compose now pins that oracle digest alongside the
existing fixed delegate digest
`tinker-delegate@sha256:5f53e8d09d53fc76b17155ce40bd51a0333a85c4e77a0e82a511551895f02995`
and Neko digest
`neko-chrome@sha256:fd6a65a894befc66901ed7b915c792f3a669b74ef4ace01813815e1f1030b456`.
Local image-policy hash is
`40021d9b19956cbe962b8697b04c2f8c6467b80f8f290b2678c8650bd756c71e`, rendered
compose SHA-256 is
`ba674f8267972b2942aa7243127365aab0973812f8533b8abcdb173f59addd44`, and Phala
raw-compose hash is
`4124f22bca1ea7a3a6f8117ccdad4079d8d70c5bcfa930b2abff252b35938d5e`. This pin
still needs Phala redeploy and live health/preflight verification.

Oracle startup blocker follow-up, 2026-07-09: the health-only oracle image was
redeployed to the existing debug-posture Phala CVM. Delegate public
`/attestation?context=billing` returned `200` in about 0.9 seconds and reported
live compose hash
`917caeff047da50b79a4077233ad275d01a5edbbe51b63d19c6a21b58d9f408a`, but
delegate `/health` still reported oracle connection refused and public oracle
`/health` closed without a response. Oracle logs showed the process loaded
sealed credentials and then blocked at `connecting to mail.cock.li:993` during
FastAPI lifespan startup. Source now defers startup IMAP connection entirely:
startup loads sealed credentials, constructs the IMAP client, reports
`status=degraded` / `oracle_ready=false` until IMAP is proven, and leaves the
first real IMAP connection to `/pin`. Regression coverage passed with
`uv run python -m unittest tests.test_api_auth` (23 tests),
`uv run python -m unittest discover -s tests` (45 tests), and
`uv run python -m py_compile email_oracle/api.py tests/test_api_auth.py`. This
startup-deferred oracle fix still needs GitHub image build, attestation
verification, digest pin, Phala redeploy, and live health/preflight
verification.

Startup-deferred oracle image follow-up, 2026-07-09: GitHub Actions run
`29008021529` built source `03e4c356a19e96a51d8027389d99a7ef36c1d48a`; CI run
`29008021545` also passed. Local attestation verification passed for
`tee-email-oracle@sha256:e5d641e1650fe08748017dead5870bf8bb7b844428899da2233030f631b80335`
with GitHub provenance and SPDX SBOM attestations and `raw_secret_egress=false`.
The funding-validation compose now pins that startup-deferred oracle digest.
Local image-policy hash is
`ecb54f8916b279d1e1968c0ca633aee0f6bef31dc2955af9d8351cbc984ab0fc`, rendered
compose SHA-256 is
`1ce5d1422b6de881cbc9e2e80063b031d68b815551039c80f5ccc57ec608f587`, and Phala
raw-compose hash is
`1f16c4a93adb3b09f29f7e6f7c97870ea781c4cca9c2dbf7d72a982a83e5a4b7`. This pin
still needs Phala redeploy and live health/preflight verification.

Startup-deferred oracle live result, 2026-07-09: the existing debug-posture
Phala CVM was redeployed with the startup-deferred oracle image. `phala ps`
reported delegate, oracle, and Neko containers running and healthy. Public
delegate `/attestation?context=billing` returned `200` in about 2.7 seconds,
with app ID `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717`, OS image hash
`de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`, and live
compose hash
`1fc656544b1583b83d65d769f369f3d1ad6d07d7e812073fbd3c1f7f2f84eb28`. Public
oracle `/health` returned `200` in about 0.4 seconds with `status=degraded`,
`oracle_ready=false`, `imap_connected=false`, and the bounded
`oracle_email_hash`; delegate `/health` also returned `200` and surfaced that
bounded oracle state. Oracle logs show `IMAP connection deferred until pin
request` followed by successful `/health` responses, not a startup connection
attempt to `mail.cock.li:993`. Endpoint-level `$10` funding preflight returned
`ready=true` with billing attestation fetch verified. The new live compose hash
was approved in `TinkerAccountEncumbrance` in tx
`0x9caf683b80b3c06a8b5de0f8ebeffcfd44d5a6f0305c285df9f32fdb687e402e` at block
`43910712`; `approvedComposeHashes` now returns `true`, and on-chain
encumbrance preflight returns `allowed=true` for `$10` add-balance with
`raw_secret_egress=false`. A later same-context reauth/add-balance packet and
bounded balance read did show the top-up: the account now reports `$10.00` in
the operator-validation lane.

Add-balance-only packet tooling follow-up, 2026-07-09: packet
`/tmp/dnai-tinker-add-balance-packet-20260709T093900Z` did not reach the live
browser or charge path. It failed locally before any add-balance mutation with
`ValueError: no receipt_json provided and run_card_attempt is false`, because
the packet runner still required payment-method evidence even when the card was
already on file and only `--run-add-balance-attempt` was requested. Source now
allows card-on-file add-balance-only packets: it writes preflight, add-balance
receipt, add-balance manifest, add-balance verification, and summary without
creating payment-method receipt/manifest files. The replay checker also accepts
that shape when `--require-add-balance` is set. Focused validation passed with
`uv run python -m unittest tests.test_funding_validation_packet` and
`uv run python -m py_compile tinker_delegate/funding_validation_packet.py
tests/test_funding_validation_packet.py`. Funding remains unproven until the
fixed command produces a bounded add-balance receipt and balance read-back.
The operator `balance` CLI now also accepts `--api-url`, `--auth-token-env`,
and `--output` for deployed delegate balance reads; the prior
`unrecognized arguments` error was a local CLI gap, not evidence about the
Tinker account balance. A read-only probe with that fixed CLI reached the live
delegate and returned `success=true` with balance `unknown`. A concurrent
`payment-method-status` probe failed in the browser navigation path and exposed
a raw Playwright `Page.goto` / Tinker URL error in the public `error` field.
Source now bounds read-only balance/status exceptions to stable labels such as
`transient_browser_failure` and hashes the raw exception only inside the bounded
receipt evidence. This bounded-error source fix still needs image build,
attestation verification, Phala redeploy, and compose approval before the live
endpoint behavior changes.

Add-balance-only live attempt follow-up, 2026-07-09: packet
`/tmp/dnai-tinker-add-balance-packet-20260709T095232Z` used the approved
compose hash
`1fc656544b1583b83d65d769f369f3d1ad6d07d7e812073fbd3c1f7f2f84eb28` and passed
preflight plus on-chain encumbrance gating. It produced an add-balance-only
receipt/manifest/verification packet with no payment-method receipt files.
Verification passed, `raw_secret_egress=false`, and the receipt outcome was
`auth_required` at `billing_page_loaded` with bounded message
`Tinker auth required before billing`. This proves the add-balance-only packet
shape works against the live endpoint, but it does not prove a charge or
top-up. The next live attempt should refresh Tinker auth in the same packet
with `--run-reauth-attempt` before `--run-add-balance-attempt`, or redeploy the
bounded read-only error fix first if we want status probes corrected before
another charge-capable run.

Reauth-plus-add-balance follow-up, 2026-07-09: packet
`/tmp/dnai-tinker-add-balance-packet-20260709T095444Z` included both
`--run-reauth-attempt` and `--run-add-balance-attempt` against the same
approved live compose hash. Preflight and encumbrance gating passed, the
add-balance-only manifest verified, and `raw_secret_egress=false`, but reauth
returned `unknown_failure` at `not_started` and add-balance again failed closed
as `auth_required` at `billing_page_loaded`. A direct bounded probe of
`POST /auth/reauth` then returned HTTP 500 with a non-JSON body after a long
attempt. Source now adds an API-level `/auth/reauth` fallback receipt: uncaught
browser exceptions classify to bounded outcomes such as
`transient_browser_failure`, update runtime state, and do not return raw
Playwright logs, Tinker URLs, OTPs, or account identifiers. This source fix is
covered by `tests.test_api_reauth` but still needs image build, attestation
verification, Phala redeploy, compose approval, and a fresh reauth/add-balance
attempt before funding can be retried safely.

Encumbrance deployment follow-up, 2026-07-09: the
`TinkerAccountEncumbrance` deploy helper was re-dry-run against Base Sepolia
with the current funding-validation compose hash. Chain ID, balance, and nonce
were read; build passed; `TinkerAccountEncumbrance.t.sol` passed 9 tests; and
the dry-run predicted deployment address
`0x9F2616f3F7B0dc363bBa19F7d72b9061f791a06e` with about
`0.00001471492` ETH required. The operator then broadcast the same no-raw-key
helper from an interactive terminal. The manifest records deployed address
`0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e`, tx
`0x7679df09aa2e939d748be0e017f380f5e7e44331a482531380198e93bdcaed01`, owner
`0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD`, account commitment
`0x535adcedea37ac48af0e43720f390125749053a0a0215b669ce55c746cd10132`,
initial compose hash
`0xb3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`,
approved compose hash true, emergency halt false, and measurements frozen
false. Local `cast` reads also confirmed nonzero bytecode, the owner, and the
approved compose hash. Follow-up operator transaction
`0x3ab263bb7cb7758787fa1136dd043cca002db9cf511b29ad20ef4d1216199d3f`
raised both add-balance and spend caps to `$10`.

Selector diagnostics follow-up, 2026-07-09: a tracked one-shot Phala profile,
`⚙️/tinker-delegate/docker-compose.selector-diagnostics.phala.yaml`, was added
for bounded browser-control evidence on the main CVM. It uses registry images
only, disables Tinker bootstrap and all card/funding mutations, and enables
only `/browser/readiness` plus `/browser/selector-probe`. The first live run
proved the old page-level CDP blocker by timing out at `Page.enable`. The
custom-`neko-chrome` rerun from source
`6ff5531aabb952b3266210afa6c0b6bfb8860103` attested compose hash
`014c4609735797efac76f1e60ba44ba926bd0613ae57b7e6e969dbaa0e840d13`.
Readiness proved CDP metadata, WebSocket upgrade, and a browser-scoped
DevTools command succeed; selector probe succeeded through Playwright without
raw URL, page text, cookie, OTP, API key, card, or account data leaving the TEE
boundary. The CVM was restored to the funding-validation profile afterward;
live attestation now reports
`f4728f219572c09c6ccc013883a4a895f3e366ea6e9654459fd6b0002fe33552`, and both
diagnostic endpoints return `403` disabled in the funding profile.

Billing auth-state classifier follow-up, 2026-07-08: source, tests, and Phala
live evidence now distinguish billing selector drift from auth/session state
before payment-method or add-balance controls are touched. Billing navigation
that lands on sign-in or magic-code surfaces returns bounded `auth_required` at
`billing_page_loaded`; Tinker's access-blocked surface returns bounded
`auth_access_blocked`. The classifier does not expose page text and does not
click billing controls before classifying auth-state failures.

Browser-session follow-up, 2026-07-08: the funding-validation profile now also
includes source/test and Phala-deployed encrypted browser session persistence.
Successful signup/signin/reauth saves Playwright `storage_state` into
`/data/browser_session.enc` using the separate `tinker/browser_session` dstack
key path, and billing loads that sealed state for fresh contexts. The deployed
profile is verified, but the store has not yet captured a useful live session
because `/auth/reauth` still fails with bounded `auth_access_blocked` at
`auth_email_submitted`, before OTP. The next push is to repair the Tinker
post-email-submit auth access-blocked posture so
reauth can reach OTP, save session state, and authenticate billing before any
approved real-card prompt.

Auth-stage receipt follow-up, 2026-07-08: source/tests and Phala now preserve bounded
Tinker auth-flow stage evidence for `auth_access_blocked`. Signup and
`/auth/reauth` can report whether the blocker happened at `auth_page_loaded`,
`auth_email_submitted`, or `auth_otp_page_reached` instead of collapsing the
receipt to `not_started`. These are enum-only public labels; page text, raw
URLs, OTPs, cookies, API keys, and account identifiers still do not leave the
delegate boundary. The live funding-validation CVM returned
`auth_access_blocked` at `auth_email_submitted`, so the next repair target is
the post-email-submit Tinker auth posture, not browser launch or email typing.

## Built

[real] Contracts:

- `⚙️/tinker-delegate/contracts/src/DiligenceRoom.sol` implements the escrow
  state machine for created, funded, evaluated, accepted, rejected, and expired
  deals.
- `⚙️/tinker-delegate/contracts/src/EmailOracleAuth.sol` models on-chain
  app-auth policy for email-oracle consumers: oracle-compose approval with
  upgrade delay, consumer compose-hash registry with non-escalating manager
  delegation, freeze-oracle-code and freeze-consumer-registry switches, an
  immediate emergency consumer kill switch that survives the freeze
  (`emergencyRevokeConsumer` / owner-only `restoreConsumer`), and a hashed
  OTP-delivery audit event (`recordOtpDelivery`, per-consumer ordered sequence,
  never the raw OTP) for dispute resolution.
- `⚙️/tinker-delegate/contracts/src/TinkerAccountEncumbrance.sol` models
  on-chain policy/audit controls for the TEE-owned Tinker account: hashed
  account commitment, exact approved compose/manager roots, per-operation
  add-balance/spend caps, two-day release review, one-way policy freeze,
  emergency halt, bounded operation authorizations, and receipt hashes.
- `⚙️/tinker-delegate/contracts/src/RoyaltyDistributor.sol` provides a
  two-day release-bound settlement-CVM/QVL/policy-anchor authority ceremony,
  deterministic intent-keyed native/ERC-20 reservations, sponsor-only expiry
  refunds, ten-minute EIP-712 settlement authorizations, globally one-shot
  settlement IDs and nonces, exact `settleReserved` consumption, permanent
  reconciliation getters, solvency accounting, and owner pull withdrawals.
- `⚙️/tinker-delegate/contracts/src/ChallengeRegistry.sol` commits versioned
  Arena metadata and release policy without accepting candidate, prize, or
  artifact custody.
- `⚙️/tinker-delegate/contracts/src/ComputeCreditVault.sol` accounts for
  non-transferable exact-asset capacity claims, frozen fees, approved policies,
  independent metering, settlement, and withdrawal.
- `⚙️/tinker-delegate/contracts/src/ExecutionPolicyAnchor.sol` is the external
  compare-and-set rollback witness for hash-only execution decisions.
- Foundry tests exist under `⚙️/tinker-delegate/contracts/test/`.

[real] `tee-email-oracle`:

- FastAPI service with runtime bearer authentication for sensitive routes.
- Optional on-chain `EmailOracleAuth` consumer-registry checks for scoped
  `/pin`. `/inbox` is absent, and authenticated `/email` is commitment-only.
  When `ORACLE_AUTH_REQUIRED=true` or a contract is configured, OTP release
  fails closed before IMAP access unless the configured
  consumer app and compose hash are authorized by the contract.
- Sealed credential store abstraction.
- Attestation-bound encrypted credential provisioning for an existing mailbox:
  `GET /attestation?context=oracle-credentials` exposes a context-bound key,
  `POST /credentials/encrypted` is disabled by default behind a provisioning
  bearer token, and successful writes return only hashes/status.
- Scoped OTP request path so callers receive only the OTP they requested.
- Encrypted OTP replay ledger.
- Redacted diagnostics for secret-like values.

[real] `tinker-delegate` local automation:

- Local Neko/CDP Tinker login, email OTP consumption, onboarding, and API-key
  provisioning have been validated locally.
- API keys are stored encrypted and leave only as bounded metadata such as
  status, hash, and masked prefix.
- Signup/signin stdout and return payloads expose mailbox and browser-route
  hashes rather than raw account email or Tinker URLs; regression tests cover
  stdout and result egress before the deployed-CVM bootstrap path is retried.
- Startup bootstrap now preserves the last bounded attempt record in
  `/health.runtime.last_bootstrap_attempt_record`. It covers successful
  `api_key_provisioning`, selector/API-key-capture failures, and early
  `tinker_auth` failures during account lookup, CDP/browser connection,
  browser context/page setup, authentication, and onboarding. This is now
  Phala-proven for the `8fb6e3a` image: the latest one-shot bootstrap emitted
  a bounded `tinker_auth` `unknown_failure` record at `not_started`, with
  hashes and `raw_secret_egress=false`, not raw mailbox, OTP, browser URL,
  page text, or API key. The top-level
  `/health.runtime.bootstrap_error_kind` now preserves that bounded
  `unknown_failure` outcome when the serve-level catch handles the bubbled
  startup failure.
- `tinker-delegate selector-map` now emits the bounded machine-readable
  selector/frame/auth-flow contract for email auth, OTP, onboarding, API-key
  creation, billing, Stripe iframe, balance top-up, and auto-reload surfaces.
  It includes selector-family counts, evidence labels, and a recomputable map
  hash, with optional `--summary-only` output that omits concrete selectors.
  `tinker-delegate selector-probe` now provides the read-only browser
  observation path for deployed evidence capture: it observes current
  pages/frames without navigation, clicks, typing, screenshots, or page-text
  capture, emits only URL classes/hashes, selector match bands, frame kinds,
  selector-map hash, and `raw_secret_egress=false`, and fails closed with
  bounded `browser_unavailable` JSON if the browser cannot be reached. In
  source/tests, the probe now falls back to a raw-CDP target/frame inventory
  path when Playwright attachment fails: it uses `Target.getTargets`,
  `Target.attachToTarget`, and `Page.getFrameTree` to emit only stage booleans,
  HTTP status band, target/page/frame count bands, URL classes/hashes, frame
  kinds, and bounded error kinds, including bounded raw-CDP fallback failure
  receipts. It is now Phala-proven through target inventory: a one-shot
  `f63dd18` deployment reached CDP metadata, WebSocket status `101`, and
  `Target.getTargets`, returning bounded target count `2+` and page count `1`.
  Source/tests now run bounded DOM selector-family counting through one
  raw-CDP `Runtime.evaluate` command after page attach, returning only declared
  flow/family names and `0`, `1`, `2+`, or `probe_error` bands. Source/tests
  now precede that selector matrix with a constant page-scoped Runtime
  micro-probe and emit only `runtime_micro_probe_command_success`,
  `runtime_micro_probe_success`, and `runtime_micro_probe_error_kind`, so the
  subsequent Phala run could distinguish Runtime transport failure from
  selector-matrix timeout without exposing page-controlled values. A Phala
  one-shot measurement using GitHub-attested `5943c61` images reached
  `probe_backend=raw_cdp`, returned `success=true`, preserved bounded page
  `url_class=other` and `attached=true`, but even the constant page-scoped
  Runtime micro-probe timed out: `partial_error_kind=runtime_micro_probe_timeout`,
  `runtime_micro_probe_command_success=false`,
  `runtime_micro_probe_error_kind=timeout`,
  `runtime_selector_command_success=false`, and `flow_observations=[]`. This
  narrows the blocker to page-scoped Runtime command delivery/evaluation in
  the deployed Neko/CDP path, not selector-expression complexity.
  Source/tests now add the next bounded Runtime/session diagnostic: the raw-CDP
  fallback sends `Runtime.enable` before the constant micro-probe and emits only
  `runtime_enable_command_success`,
  `runtime_execution_context_event_observed`, `runtime_enable_success`,
  `runtime_enable_error_kind`, `runtime_event_before_enable_response`,
  `runtime_event_count_band`, and `runtime_execution_context_created`. Tests
  cover successful execution-context observation and a `Runtime.enable` timeout
  before any micro-probe or selector evaluation. It emits no event payloads,
  context IDs, frame IDs, raw URLs, page text, selectors, cookies, OTPs, API
  keys, or card material. A Phala one-shot measurement using GitHub-attested
  `9d69364` images reached `probe_backend=raw_cdp`, returned `success=true`,
  preserved bounded page `url_class=other` and `attached=true`, and proved
  `Runtime.enable` itself times out before any micro-probe or selector
  evaluation: `partial_error_kind=runtime_enable_timeout`,
  `runtime_enable_command_success=false`,
  `runtime_execution_context_event_observed=false`,
  `runtime_enable_error_kind=timeout`,
  `runtime_event_count_band=0`, `runtime_execution_context_created=false`,
  `runtime_micro_probe_command_success=false`,
  `runtime_selector_command_success=false`, `flow_observations=[]`, and
  `raw_secret_egress=false`. Source/tests now add a direct page-target
  WebSocket route-around candidate: when attached-session `Runtime.enable`
  fails, the raw-CDP fallback fetches bounded page-target inventory from
  `/json/list`, connects directly to the matching page target WebSocket, and
  retries `Runtime.enable`, the constant micro-probe, and selector-family
  matrix. The nested `direct_page_runtime` receipt emits only page-list success,
  page-WebSocket availability, Runtime enable/error/event-count bands,
  micro-probe success/error, selector success/error, and declared
  selector-family count bands. It emits no raw page URLs, WebSocket URLs, event
  payloads, context IDs, frame IDs, page text, selectors, cookies, OTPs, API
  keys, or card material. A Phala one-shot measurement using GitHub-attested
  `bf39f56` images proved the direct page-target path reaches `/json/list` and
  the page WebSocket, but direct `Runtime.enable` still times out:
  `direct_page_runtime_attempted=true`,
  `direct_page_runtime.page_list_success=true`,
  `direct_page_runtime.page_websocket_available=true`,
  `direct_page_runtime_enable_success=false`,
  `direct_page_runtime.runtime_enable_error_kind=timeout`,
  `direct_page_runtime_micro_probe_success=false`,
  `direct_page_runtime_selector_success=false`, empty `flow_observations`, and
  `raw_secret_egress=false`. The blocker is now below attached-session routing:
  the deployed page Runtime domain itself does not complete `Runtime.enable`
  through either the attached session or the direct page target WebSocket.
  Source/tests now add a bounded `Page.enable` discriminator before
  `Runtime.enable` on both attached-session and direct page-target paths. The
  new output fields are limited to `page_enable_command_success`,
  `page_enable_success`, and `page_enable_error_kind`, so the next Phala run
  can tell whether page-domain CDP commands work while Runtime-domain enable
  hangs. This emits no page text, raw URLs, selectors, cookies, OTPs, API keys,
  card material, event payloads, frame IDs, or execution-context IDs. A
  2026-07-08 Phala one-shot measurement using GitHub-attested `556387a`
  images proved that `Page.enable` itself times out on both attached-session
  and direct page-target paths before `Runtime.enable` is attempted:
  `partial_error_kind=page_enable_timeout`,
  `page_enable_command_success=false`,
  `direct_page_runtime.page_list_success=true`,
  `direct_page_runtime.page_websocket_available=true`,
  `direct_page_runtime.page_enable_success=false`,
  `direct_page_runtime.page_enable_error_kind=timeout`,
  no Runtime micro-probe, no selector-family matrix, empty `flow_observations`,
  and `raw_secret_egress=false`. The deployed blocker is now lower than
  Runtime-specific behavior: page-target CDP command delivery through the Phala
  Neko path does not complete even for `Page.enable`.
  The latest restored deployment-bundle verifier ties the current normal compose to
  `tinker-delegate@sha256:72b584ff4228783711ff3108f8674a9d5ab86fec2a072cf1ea3f8b71b697ec38`,
  `tee-email-oracle@sha256:287028f12f7cb596d573f950e6dc1cb2437fe37ea2984101abd8bd451d44eca3`,
  GitHub-signed provenance/SBOM attestations for source `556387a`, app ID
  `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717`, OS image hash
  `de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`,
  local raw compose/image-policy hash
  `1a4870ab818fe2d8d5e59c6c84ada795a36210c3ea5a0d2bc16d342bfdbb87f5`,
  rendered compose SHA-256
  `9c664e88ba1c79108f6f9c2987f667aa2e6ee6fa853b19277c7a8f8abfd43441`,
  and live attested compose hash
  `e9e07417f7df3b0dae2fdc148fc6847751afa240b9167cc81e76883060ecd586`.
  `Page.getFrameTree` still times out before frame inventory. The
  timeout-preserving page observation refinement is now Phala-proven with
  GitHub-attested `a384db2` images:
  `selector-probe` returned `probe_backend=raw_cdp`, `success=true`, target
  count `2+`, page count `1`, `pages_observed=1`, one bounded page URL
  class/hash, `attached=true`, `frame_tree_error_kind=timeout`,
  `partial_error_kind=frame_tree_timeout`, empty frame observations, and
  `raw_secret_egress=false`. Normal compose was restored afterward at compose
  hash `54ee243db5605588550d670fcc767ba17b49407e76613b633ddc7eee44494eb2`,
  with public logs/sysinfo still disabled; both diagnostic endpoints return
  403.
  The matching `GET /browser/selector-probe` endpoint is now Phala-proven as a
  deployed gate/fail-closed path: one-shot compose with GitHub-attested
  `7973b27` images enabled it on top of the bounded bootstrap profile, the live
  response returned bounded `browser_unavailable` JSON with
  `raw_secret_egress=false`, and the restored normal compose returns 403.
  Deployed frame traversal and selector-family match capture remain open until
  the raw-CDP Runtime selector-counting timeout is repaired and remeasured on
  Phala.
- `tinker-delegate browser-readiness` and disabled-by-default
  `GET /browser/readiness` now provide a bounded way to diagnose that deployed
  browser-control failure without logs, SSH, screenshots, page text, cookies,
  or raw browser/CDP URLs. Output is limited to endpoint classes/hashes, CDP
  metadata reachability, raw WebSocket upgrade stage bands, a one-command CDP
  protocol probe, Playwright/CDP handshake status, context-count bands, and
  bounded error kinds. The raw WebSocket diagnostic keeps the advertised
  debugger URL in memory only, sends a single HTTP Upgrade request, and emits
  only URL class/hash, TCP/TLS/upgrade stage booleans, HTTP status band, and
  bounded error kind. The post-upgrade protocol probe is source/test-real: it
  sends exactly one browser-scoped `Browser.getVersion` command after a
  successful Upgrade and emits only command/response booleans, response kind,
  browser family, URL class/hash, status band, and bounded error kind. It does
  not navigate, click, type, screenshot, inspect frames/pages, read page data,
  expose raw URLs/headers, or return the CDP response body.
  Normal Phala compose keeps
  `TINKER_ALLOW_BROWSER_READINESS_ENDPOINT=false`; the one-shot bootstrap
  measurement compose enables it alongside the selector probe. This diagnostic
  is now Phala-proven with GitHub-attested `7973b27` images: the one-shot
  endpoint returned bounded `cdp_timeout` after successful CDP metadata
  discovery, raw WebSocket TCP connect, and HTTP Upgrade status band `101`.
  The post-upgrade protocol probe is now Phala-proven with GitHub-attested
  `59a9eac` images: one browser-scoped `Browser.getVersion` command returned a
  bounded `result` response with Chromium browser family, while Playwright
  `connect_over_cdp` still timed out. The restored normal compose returns 403
  for readiness and selector-probe endpoints. The remaining browser-control
  blocker is Playwright's CDP client path, not the raw CDP WebSocket or basic
  DevTools command path.
- `docker-compose.tinker-bootstrap.phala.yaml` is the bounded one-shot
  main-CVM profile for Tinker OTP/login/API-key provisioning. It enables only
  `TINKER_BOOTSTRAP_SIGNUP=true`, reuses the main `delegate-data` volume, keeps
  `ORACLE_AUTO_GENESIS=false`, keeps credential provisioning and add-balance
  disabled, and uses the headed Neko Chrome CDP endpoint instead of a headless
  Playwright sidecar. It has been Phala-tested and reverted to the normal
  compose; live attempts still fail closed before API-key sealing.
- Browser/control-plane diagnostics are redacted before egress.

[real] `tinker-delegate` funding channel:

- Card details use an encrypted channel by default.
- Plaintext card submission is disabled by default and is also disabled when
  dstack is detected.
- Local Stripe test-card automation reaches the bounded card-decline result.
- Add-balance fails closed when no funded payment method is available.
- Bounded funding receipts are stored encrypted under the delegate data volume
  and reject unknown fields or `raw_secret_egress=true`.
- `TINKER_FUNDING_MODE=manual_prefund` is the default production model and
  denies card/add-balance browser automation before decryption or browser
  launch. `operator_capped_validation` is required for one-off approved
  operator validation attempts, and denied requests persist bounded
  `policy_denied` receipts.
- `tinker-delegate` can now read `TinkerAccountEncumbrance` policy before
  Tinker funding automation. If `TINKER_ENCUMBRANCE_REQUIRED=true` or an
  encumbrance contract address is configured, payment-method and add-balance
  operations fail closed before card decryption/browser launch unless public
  contract reads show the compose hash is approved, emergency halt is off, and
  the add-balance/spend amount is within cap.
- Prompt-based real-card operator CLI paths can now require that same on-chain
  policy before asking for card material. `add-card-encrypted-prompt` and
  `funding-validation-packet --prompt-card --run-card-attempt` support
  `--require-encumbrance` with contract/RPC/compose inputs; add-balance packet
  runs also check the requested amount against the deployed cap before any
  prompt. `tinker-encumbrance-preflight` emits approved public chain fields as
  bounded JSON while preserving the generic secret-shaped output guard for
  card/API-key/OTP material.
- A manifest-driven `funding-command-plan` CLI now emits the future operator
  preflight, encumbrance-preflight, and prompt-packet command templates from
  `deployments/base-sepolia.json`. It references runtime bearer and RPC values
  only by environment-variable name and returns bounded JSON with
  `raw_secret_egress=false`. Against the earlier `$5` validation path it
  reported `ready=true` with the deployed encumbrance contract, approved compose
  hash, and runtime-authenticated endpoint references. The later `$10`
  Tinker-minimum operator-validation lane raised the deployed caps, executed a
  bounded add-balance packet, and verified a `$10.00` balance; production or
  repeated funding remains blocked on hardening and approval.
- A no-raw-key Base Sepolia deploy helper now exists for
  `TinkerAccountEncumbrance`. It uses Foundry `--account dev`, validates
  bytes32 commitments and policy caps, defaults the initial compose hash from
  the deployment manifest, defaults the account commitment to the bounded
  `oracleEmailHash` when not supplied, and updates the manifest only after
  successful broadcast plus on-chain reads. A 2026-07-08 dry-run built the
  contracts, passed 9 focused Foundry tests, and simulated deployment with
  account commitment
  `0x535adcedea37ac48af0e43720f390125749053a0a0215b669ce55c746cd10132`,
  compose hash
  `0xa43a894e6c0a6e0976f94e86f11050301b46093dad03e065ee91fda98fcf456d`,
  and `$5` add-balance/spend caps. The manifest now points at refreshed
  funding-validation compose hash
  `0xb3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7`;
  the next interactive helper run will use that current hash. Non-interactive
  broadcast did not deploy:
  Foundry failed while opening the encrypted keystore prompt with
  `Device not configured`, and chain checks showed nonce `3`, unchanged
  balance, and no code at the predicted address.

[real] `tinker-delegate` bounded run metadata:

- Control-plane deal lifecycle events persist to an encrypted
  `run_metadata.enc` store under the delegate data volume.
- Stored records use hashed deal/account/Tinker-run handles, artifact hashes
  and size bands, score/offer/cost bands, and cleanup counts.
- Raw artifacts, API keys, card fields, checkpoint IDs, raw Tinker run IDs, and
  arbitrary extra fields are rejected by the store schema/tests.

[real] Artifact ingress:

- `GET /attestation?context=artifact` exposes a context-bound public upload key
  and dstack attestation when available.
- Upload clients verify the attestation envelope before sending an artifact.
- Artifact uploads are encrypted client-side to the attested key. The only
  accepted plaintext inside that envelope is the versioned wrapper
  `ASCII("dnai-wikigen/artifact-wrapper/v2") || 0x00 || secret32 || rawArtifact`;
  raw, unwrapped artifact bytes fail closed.
- On-chain `artifactHash` is the salted commitment
  `keccak256(ASCII("dnai-wikigen/artifact-commitment/v2") || 0x00 || secret32 || rawArtifact)`.
  The secret is exactly 32 random bytes and remains in the seller's private
  recovery receipt plus the encrypted wrapper; it is never put on-chain.
- Server-side artifact keys are derived per deal and artifact hash.
- Upload AAD and HKDF context bind the version, `deal_id`, and normalized
  on-chain commitment.
- The chain watcher forwards the `DealCreated.artifactHash` into an immutable
  `DealContext`. The upload endpoint rejects any caller-supplied mismatch before
  decryption, verifies the salted commitment before custody, and re-verifies it
  immediately before evaluation.
- Accepted artifact plaintext remains in TEE process memory. In dstack mode the
  active context is also persisted only as a versioned AES-256-GCM ciphertext
  under a purpose-separated dstack-derived key on the private data volume;
  regression tests verify that the file contains no plaintext artifact and
  fails closed under tamper, wrong key, unsafe mode, or malformed schema.

[real] Supporting CLIs and tests:

- `python -m tinker_delegate.main verify-attestation`
- `python -m tinker_delegate.main upload-artifact`
- `scripts/verify-local.sh` runs the current local quality gate:
  secret-shaped material scan, Foundry build/tests, frozen `uv` sync,
  Python compile checks, and Python unit tests for implemented suites.
- `.github/workflows/ci.yml` runs the same secret scan, Foundry, and Python
  gates in CI for pushes and pull requests.
- The Foundry CI checkout intentionally does not recurse into the read-only
  research submodules; `forge-std` is vendored under the contracts package, and
  avoiding recursive submodules prevents the GitHub runner from failing in the
  emoji-path `🔬/` submodule metadata before Foundry starts.
- Python unit tests for Tinker delegate and email oracle services.
- Mocked-SDK `IsolatedTinkerSession` tests cover one training run per deal,
  TTL on checkpoint save paths, path-checked sampling, cleanup deletion, and
  cost metering without calling real Tinker.
- Cleanup now returns a bounded attestation with deletion counts, retry
  attempts, success/error status, and a hash of checkpoint IDs instead of raw
  IDs; the control plane stores it on deal resolution.
- First-party SFT evaluator code uses wrapper methods only. Its base-model
  sampler path is scoped, and tests reject raw ServiceClient, REST,
  list/download, publish, and delete API usage in evaluator source.
- Skip-by-default real Tinker SDK smoke harness exists for tiny
  training/sampling/cleanup, gated by `TINKER_RUN_REAL_SDK_TESTS=1`,
  `TINKER_API_KEY`, and `TINKER_REAL_SDK_MAX_USD <= 0.50`.

[real] Private reward interface:

- `tinker_delegate.private_reward.PrivateRewardEnvironment` defines the core
  sealed-reward contract: public problem text, candidate schema, acceptance
  policy, internal reward, output reducer, query budget, final bounded result,
  and environment attestation metadata.
- `LeakageBudget` records max queries, feedback mode, reward precision policy,
  candidate-payload release policy, timing bands, and cost bands.
- Public evaluation returns `BoundedFeedback` and appends
  `QueryLeakageRecord` entries containing candidate hashes, decisions, reward
  bands or withheld feedback, timing bands, and transcript hashes.
- `OptimizerPolicy` now names where the optimizer runs: inside the same TEE, in
  an attested remote service, or outside the boundary with bounded feedback
  only.
- The default optimizer policy is external and fail-closed: exact rewards,
  reward-derived state, and private checkpoints are rejected for external
  optimizers.
- Internal dense-reward mode exists for optimizers inside the attested boundary;
  public evaluation still returns bounded feedback.
- Exact `InternalReward` values remain in the environment; tests cover bounded
  feedback, budget exhaustion, policy rejection, pass/hold/deny precision
  reduction, reducer hash mismatch fail-closed behavior, optimizer policy
  enforcement, internal dense-reward access, and final transcript/leakage
  hashes.

[real] Local candidate sandbox:

- `tinker_delegate.private_reward_sandbox.PythonCandidateSandbox` runs UTF-8
  Python candidate source in a subprocess with a scratch working directory,
  stripped environment, deterministic random seed, timeout, best-effort
  CPU/memory limits, max source bytes, and capped stdout/stderr.
- Static preflight rejects file, network, process, import, builtin-import,
  dunder-attribute, and direct `open`/`eval`/`exec` style escape attempts.
- Public sandbox results expose candidate hash, bounded outcome, failure-code
  bucket, exit code, timeout flag, elapsed timing band, capped stdout/stderr,
  and truncation flags without echoing the source.
- Failure traces are bucketed into policy, syntax, runtime, and timeout classes
  instead of returning raw exception strings or preflight details.

[real] Hidden holdout accounting:

- `tinker_delegate.private_reward_holdout.HiddenHoldoutSet` creates deterministic
  train, reward, and final-validation partitions over TEE-held records.
- Public holdout manifests expose split commitment, split policy, partition
  counts, reward-query counts, unique candidate counts, maximum repeated
  candidate-query count, final-validation count, and whether reward queries are
  closed.
- Public manifests do not include raw record IDs, payloads, labels, or split
  membership.
- Reward-query accounting enforces a configured query budget, and final
  validation is gated to one-shot use by default; once final validation starts,
  additional reward queries fail closed.
- Generic adaptive-query guards enforce per-candidate repeat caps and a minimum
  number of unique reward candidates before final validation can run.

[real] Synthetic private reward environment:

- `tinker_delegate.private_reward_envs.synthetic.SyntheticHiddenKeywordEnvironment`
  extends `PrivateRewardEnvironment` and uses `HiddenHoldoutSet` for reward and
  final-validation partitions over sealed synthetic records.
- Candidate payloads are bounded UTF-8 keywords; invalid keywords fail policy
  before any holdout query is recorded.
- Public feedback exposes only bounded reward bands and transcript hashes, not
  exact scores, candidate text, match counts, record IDs, or payloads.
- Finalization uses the final-validation holdout once, caches the bounded final
  result, and closes later reward queries.
- `python -m tinker_delegate.main synthetic-private-reward-demo` runs a
  replayable synthetic hidden-dataset reward demo and emits only optimizer view,
  bounded feedback, final bounded result, transcript/leakage hashes, and
  attestation metadata.

[real] Private verified-reward substrate (local + tested; not RLVR-proven on a
real Tinker trainer, which stays blocked — see Current Blockers):

- Swappable optimizer loop (`private_reward_loop.run_private_reward_loop`) with
  `RandomSearchOptimizer`, `HillClimbOptimizer`, `LLMRepairOptimizer`, and a real
  population-based `EvolutionaryOptimizer` (dedup + fail-closed halt), all driven
  by the public band signal only. `LoopOutcome.certified_public_export()` gates
  publication through the fail-closed egress guard.
- Proof-carrying transcripts: `reward_transcript.RewardTranscript` commits the
  per-round records into a domain-separated Merkle tree with inclusion proofs;
  `transcript_log.TranscriptLogger` is an append-only hash chain driven live from
  `PrivateRewardEnvironment.evaluate` and published as `transcript_chain_head` in
  the attestation. `reproducibility.certify_loop_run` binds the transcript
  commitment into the certificate hash; `run_verification.verify_reward_run`
  (the `verify-reward-run` CLI and the auth-gated `POST /verify/reward-run`
  endpoint) re-checks the whole chain from public bytes.
  All three private-reward demos emit a bound certificate + commitment.
- Bounded security/economics gates, each fail-closed and egress-checked:
  `cost_metering` (settlement-safe reconciliation, wired into
  `ControlPlane.evaluate`), `canary` (leaderboard-overfitting kill probes +
  surprising-score review), `disclosure_policy` (BLOCKED/HASH_ONLY/ESCROW/PUBLIC
  ladder, wired into the diligence flow, with `solution_escrow` physically
  sealing the ESCROW mode under per-escrow HKDF keys released only on
  authorization), `dp_accounting` (epsilon/delta budget,
  wired into the bio release gate and into the reward loop via
  `PrivateRewardEnvironment.set_dp_budget` — reward queries spend privacy budget
  and fail closed when exhausted), and `session_state` (stale-session vs
  login-loop OTP-refresh decision).
- Sealed retention now uses an HKDF per-corpus/per-deal key hierarchy
  (`sealed_retention`), not one static key; `otp_delivery` computes the bounded
  on-chain OTP-delivery commitment without exposing the raw code.

## Partial

[partial] Deployed Tinker automation:

- The selector/UI repair, OTP login, onboarding, API-key provisioning, and
  test-card decline are validated locally with Neko/CDP.
- API-key provisioning now has fallback selector families for current key
  creation labels plus aria-label/data-testid variants, emits bounded
  `api_key_provisioning` attempt records including `selector_missing` instead
  of raw page state, and has replayable mock-page tests for successful key
  extraction and selector-drift failures.
- Tinker re-auth now has a bounded local helper/CLI and opt-in API endpoint for
  future OTP challenges. It returns `tinker_auth` attempt records only and does
  not return account email, OTP, browser URL, API key, or raw page text.
- The `tinker-delegate` Dockerfile now copies `uv.lock` and installs with
  `uv sync --frozen --no-dev --extra agent`; a local build/run of
  `dnai-tinker-delegate-agent-extra:local` returned
  `/health.agent_stack_available=true`.
- `⚙️/tinker-delegate/scripts/verify-agent-image.sh` is the repeatable local
  proof command for this packaging path: it rebuilds the image and runs an
  in-image `import tinker` plus `agent_stack_available` check with bounded JSON
  output.
- The same flow still needs fresh validation inside a deployed Phala CVM.
- Reusable payment-method token/reference capture is not implemented; if an
  official or tokenized funding path becomes available, that state still needs
  sealed-store integration and live validation.
- `⚙️/tinker-delegate/docs/TINKER-AUTOMATION-ROUTE.md` records the acceptable
  automation route: prefer official/support-approved Tinker workflows; allow
  browser automation only as bounded TEE custody for this project's own account.
- Runtime policy tests reject common stealth, CAPTCHA-solving, rotating-proxy,
  and automation-control masking dependencies or flags in the Tinker delegate
  runtime package, dependency manifest, and compose files.
- Real Tinker SDK training/sampling/cleanup tests have not been run here; they
  remain gated on credentials, budget cap, and deployed CVM validation.
- Cleanup attestations are local wrapper/control-plane evidence; deployed
  Tinker deletion and TTL expiry are still unproven.
- Arbitrary third-party evaluator code is not yet sandboxed against Python
  introspection; that remains a separate P0 before untrusted evaluators are
  accepted.

[partial] Account funding:

- A minimal `TinkerAccountEncumbrance.sol` contract now exists locally with
  tests proving managers cannot exceed owner-set caps or change owner-only
  policy. The runtime now has a read-only policy preflight and optional
  fail-closed card/add-balance gate, prompt-time real-card encumbrance checks,
  a manifest-driven funding command plan, plus a validated no-raw-key deploy
  helper, but the contract is not yet deployed or recorded in the Base Sepolia
  manifest.
- Test-card billing reaches a clear declined-card outcome.
- Payment-method and add-balance operations return bounded attempt records with
  outcome class, furthest stage, issued timestamp, evidence hash, amount/balance
  bands, TDX quote hash when present, and card-payload destruction status.
- Billing automation has selector fallback families for balance/payment
  controls, payment-method submission, cardholder/address fields, add-balance
  amount input, and top-up confirmation. Mock-page tests cover current selectors
  plus data-testid/aria-style drift, and missing top-up controls return bounded
  `selector_missing` receipts without exposing page text.
- Bounded funding receipts are persisted in encrypted/sealed delegate storage
  under a separate funding-receipt key path and exposed through
  `GET /billing/funding-receipts`.
- Add-balance automation enforces `TINKER_MAX_ADD_BALANCE_USD` before launching
  browser automation. Non-finite, non-positive, or over-cap requests return
  bounded `policy_denied` receipts at `not_started` with amount bands.
- The active funding mode is inspectable through `GET /billing/funding-policy`
  and `python -m tinker_delegate.main funding-policy`.
- Operator funding preflight is inspectable through
  `GET /billing/funding-preflight` and `python -m tinker_delegate.main
  funding-preflight`; it checks validation mode, amount cap, optional
  add-balance endpoint flag, encrypted receipt-store availability, and billing
  attestation policy without card material or browser launch.
- `python -m tinker_delegate.main funding-manifest` builds a bounded audit
  manifest from saved funding-preflight and funding-receipt JSON. It publishes
  only hashes, bands, outcome, TDX quote hash, card-destruction /
  no-raw-egress booleans, and an optional attestation-policy hash, and rejects
  raw card/API-key/secret-shaped inputs.
- `python -m tinker_delegate.main verify-funding-manifest` replay-verifies a
  saved preflight, receipt, manifest, validation ID, and attestation-policy
  tuple. It returns named bounded pass/fail checks and does not echo packet
  bodies.
- Operator CLIs can write validation artifacts directly:
  `funding-preflight --output` writes bounded preflight JSON, and billing
  receipt-producing commands support `--receipt-output` for bounded attempt
  records. CLI output fails closed if a response contains submitted card
  material or secret-shaped fields.
- `python -m tinker_delegate.main funding-validation-packet` creates a
  bounded packet directory containing preflight, receipt, manifest,
  verification, and summary JSON. It can bind an existing bounded receipt, or
  run encrypted card submission only when `--run-card-attempt` is explicitly
  set.
- `funding-validation-packet --prompt-card --run-card-attempt` prompts
  interactively for approved operator card details instead of reading them from
  command-line flags. Prompt mode is mutually exclusive with test-card fields
  and rejects missing deployed compose/app/OS-image attestation expectations
  before asking for card material unless local-development attestation is
  explicitly allowed.
- Operator-only mutation endpoints now support runtime bearer auth. When
  `TINKER_RUNTIME_AUTH_REQUIRED=true`, `/auth/reauth`,
  `/billing/card/encrypted`, `/billing/add-balance`,
  `/billing/funding-receipts`, and the explicitly local plaintext card endpoint
  require a bearer token; the funding CLIs read it from
  `TINKER_RUNTIME_AUTH_TOKEN` by default so the secret does not have to appear
  in command-line arguments.
- Reauth/session continuity is now source/test-real and Phala-deployed: successful
  signup/signin/reauth saves Playwright `storage_state` into an encrypted
  browser-session store under `/data/browser_session.enc`, using the separate
  `tinker/browser_session` dstack key path. Billing loads that sealed state when
  it must create a fresh browser context, so the operator can run `/auth/reauth`
  before encrypted-card/add-balance attempts without relying on a throwaway
  browser context. Tests prove the encrypted file does not contain raw
  cookie/localStorage values. Phala redeploy and live probes are complete, and
  the current funding-validation profile reports authenticated `/auth/reauth`
  success with raw secret egress false.
- Funding validation packets can include a separate add-balance evidence lane:
  `--add-balance-receipt-json` binds an existing bounded top-up receipt, and
  `--run-add-balance-attempt` posts only the amount to `/billing/add-balance`
  before writing add-balance manifest and verification JSON.
- Source now includes
  `⚙️/tinker-delegate/docker-compose.tinker-funding-validation.phala.yaml`, a
  temporary one-shot Phala profile for the approved low-value real-card test.
  It disables signup/bootstrap and plaintext card input, enables only
  runtime-authenticated reauth/encrypted-card/add-balance endpoints, sets
  `operator_capped_validation` with `TINKER_MIN_ADD_BALANCE_USD=10.0` and
  `TINKER_MAX_ADD_BALANCE_USD=10.0`, and uses the custom GitHub-attested
  `neko-chrome` CDP path. The current live CVM still reflects the previous
  deployment until this source fix is rebuilt and redeployed. The profile is
  live at attested compose hash
  `f4728f219572c09c6ccc013883a4a895f3e366ea6e9654459fd6b0002fe33552`;
  authenticated `/auth/reauth` succeeds, the API key is available from the
  encrypted store. The next bounded operator action is not another `$5`
  validation packet; it is the `$10` encumbrance policy update plus redeploy,
  followed by bounded card-on-file status and add-balance validation.
- `python -m tinker_delegate.main check-funding-validation-packet` replay-checks
  packet directories and returns bounded pass/fail checks. It can require
  add-balance evidence and can require live deployed TDX attestation evidence;
  local packets remain internally checkable but are not production proof.
- The HTTP `POST /billing/add-balance` mutation endpoint is disabled by default
  behind `TINKER_ALLOW_ADD_BALANCE_ENDPOINT`; the capped CLI/internal path also
  requires `TINKER_FUNDING_MODE=operator_capped_validation` for deliberate
  operator validation attempts.
- Stripe/PCI stance is recorded in
  `⚙️/tinker-delegate/docs/STRIPE-PCI-FUNDING-SCOPE.md`: the encrypted raw-card
  channel is limited to a one-off operator-owned capped validation path, while
  production/repeated funding should use an official Tinker route,
  Stripe-hosted/tokenized collection, SetupIntent / PaymentMethod style reuse
  with consent, or manual/developer prefunding until compliance review approves
  otherwise.
- The encrypted card client/harness verifies context-bound billing attestation,
  posts only ciphertext to `/billing/card/encrypted`, and was locally exercised
  against the Neko/Tinker/Stripe test-card path. It returned bounded
  `card_declined` and persisted one funding receipt.
- A fresh local FastAPI smoke on 2026-07-08 used
  `TINKER_FUNDING_MODE=operator_capped_validation`,
  `TINKER_MAX_ADD_BALANCE_USD=5`, local billing attestation, and a Stripe test
  card. `GET /billing/funding-preflight` returned ready for `$5`; `$10` plus
  `require_add_balance_endpoint=true` returned not ready because the amount was
  over cap and the HTTP add-balance mutation was disabled. The encrypted
  test-card submission reached `payment_submitted`, returned only a bounded
  `payment_method` receipt, set `card_payload_destroyed=true` and
  `raw_secret_egress=false`, and persisted one encrypted receipt. A binary
  string scan of that temp receipt did not find the test card number, CVC,
  cardholder name, postal code, or raw card field names.
- `python -m tinker_delegate.main add-card-encrypted-prompt` prompts for card
  fields interactively instead of taking them as command-line flags, requires
  deployed compose/app/OS-image attestation expectations unless explicitly run
  in local-development mode, zeros the in-memory card dictionary after upload,
  and emits only bounded response/receipt JSON.
- Payment-method screenshots after card entry/submission are suppressed even
  when debug screenshots are enabled; non-secret billing screenshots remain
  explicit debug artifacts only.
- Card submission attempts purge known secret-bearing browser debug artifacts
  such as trace archives, HARs, videos, and card/Stripe screenshots when an
  explicit debug artifact directory is configured.
- Tinker delegate Python entrypoints disable core dumps with `RLIMIT_CORE=0`,
  and local/Phala compose services set `ulimits.core: 0` for the delegate and
  browser path.
- Real card funding is intentionally not attempted until deployed Tinker
  auth/session continuity is repaired and an approved operator enters card
  details through the interactive, attestation-bound prompt.
- Production or repeated card funding still needs legal/compliance approval.
- Payment-method token/reference handling and the sealed long-lived funding
  token/session state still need an official/tokenized route plus production
  retention and rotation policy.
- `verify-deployed-log-safety` is source/test-real and scans deployed log text
  for card-shaped values, unredacted card/CVC fields, Tinker API keys,
  bearer/JWT tokens, OTP fields, and private-key-shaped values while returning
  only counts/classes/line hashes. Live operator-validation scan of
  `phala logs --cvm-id cvm_1w85mGjo --tail 1000` covered 236 lines /
  10KB-100KB and returned `success=true`, `finding_count=0`,
  `log_snippets_returned=false`, and `raw_secret_egress=false`. This is
  evidence for the current debug/operator-validation posture, not a production
  logging claim until public logs/dev OS are removed.

[partial] TEE attestation:

- The artifact ingress binds a dstack report to the upload key through
  `report_data`.
- The verifier checks the attestation envelope, public-key binding, and
  exposed `quote_report_data` equality when the endpoint provides it.
- `verify-cvm-attestation` and `scripts/verify-cvm-attestation.sh` now combine
  local Phala compose-hash verification with live `/attestation?context=...`
  checks, including required digest-pinned image references or sha256 image
  digests, app ID, OS image hash, report data, public key, and client fetch
  freshness.
- `verify-deployment-bundle` now combines GitHub image-attestation verification
  with live CVM attestation verification in one bounded JSON certificate:
  GitHub-signed SLSA provenance and SPDX SBOM attestations for digest-pinned
  GHCR oracle/delegate images, required Phala compose image refs, required
  sidecar image digests, app ID, OS image hash, report data, public key, and
  client fetch freshness.
- Full cryptographic Intel TDX quote parsing, quote-internal freshness,
  signer allowlists, and anti-replay checks are still incomplete.

[partial] Contracts and settlement:

- Core escrow and auth contracts exist with tests.
- A local chain watcher exists in `tinker_delegate.chain_watcher`: it decodes
  the six public `DiligenceRoom` lifecycle events from JSON-RPC logs, posts
  every event to bounded `/deal/chain-event` audit metadata, calls
  `/deal/notify-funded` when a `DealFunded` event has matching prior
  `DealCreated` context, and calls `/deal/{deal_id}/resolve` for accepted,
  rejected, or expired events. The `watch-chain` CLI exposes the same path for
  operator/CVM use.
- `⚙️/tinker-delegate/scripts/prove-chain-watcher-anvil.py` proves the watcher
  against a real local Anvil contract log: it starts ephemeral Anvil, deploys
  `DiligenceRoom` through an unlocked local account, emits `DealCreated` and
  `DealFunded`, runs the watcher over JSON-RPC, and verifies a bounded
  control-plane stub receives funded state for deal `0` without manual curl
  calls or raw private-key flags.
- `ChainCursorStore` plus the deal-runtime v2 journal give the watcher durable
  restart state: they store the next block, confirmation depth, contract
  address hash summary, public `DealCreated` context, canonical block-hash
  checkpoints, and the exact prepared transaction hash/nonce/result binding.
  Restart tests and the Anvil proof show a later
  `DealFunded` can still notify funded state after the created context has
  crossed a process boundary. The watcher advances the cursor only after
  successful dispatch and only scans confirmation-safe blocks. A checkpoint
  mismatch quarantines private state and rewinds to the original scan anchor.
- `tinker_delegate.chain_submitter` and `tinker_delegate.deal_runtime` provide
  TEE-to-chain signing and ambiguity-reconciliation plumbing: in dstack mode
  they derive an Ethereum signer from dstack key
  material, has no raw-private-key CLI/env path, verifies the public
  `deals(dealId)` state before signing, requires the signer to match
  `teeIdentity`, checks funded state and compute budget, signs
  `submitResult()` in memory, broadcasts through JSON-RPC, and returns only
  bounded receipt metadata. The contract, not the caller, derives `resultHash`
  from a domain-separated canonical encoding of chain ID, contract, deal ID,
  immutable funded-deal fields, compose hash, score band, and deterministic
  public compute tariff. The verifier and submitter recompute that same hash;
  neither accepts a payload result hash or reward-transcript commitment. Current
  tests include a hard-coded Solidity/Python parity vector, crash-after-prepare
  recovery, exact nonce/hash reconciliation, public-field sensitivity, and
  bounded receipt shape without raw keys.
- `DiligenceRoom.sol` now requires a result-verifier signature before accepting
  `submitResult()`. The signed authorization binds chain ID, contract address,
  deal ID, TEE identity, compose hash, score band, compute cost, replay-bound
  result commitment, and authorization expiry. Contract tests cover wrong
  verifier, expired authorization, and zero compose hash.
- `tinker_delegate.result_verifier` implements the bounded verifier
  authorization path that should issue those signatures: it validates signer
  attestation evidence against signer address, chain ID, contract, report data,
  quote report data, approved compose hashes, approved app IDs, optional OS
  image hashes, revoked quote hashes, revoked TEE signers, distinct
  verifier/TEE keys, and a short authorization TTL before signing the exact
  `DiligenceRoom` authorization digest. Tests cover accepted authorization and
  fail-closed policy, context, revocation, self-approval, and non-dstack custody
  cases.
- The verifier path is exposed through bounded operator CLIs:
  `result-verifier-address` prints the dstack-derived verifier address for
  deployment, and `authorize-result` consumes bounded signer-attestation JSON
  plus explicit compose/app/OS-image allowlists and revocation lists before
  emitting authorization metadata and the public verifier signature needed by
  the contract. CLI help tests assert these commands do not expose
  raw-private-key, seed, or mnemonic flags.
- The `submit-result` path now uses a pre-broadcast off-chain verifier gate:
  it fetches dstack signer quote evidence whose report data binds the signer
  address, chain ID, and contract address; rejects signer/chain/contract/report
  data/compose mismatches; and records only bounded quote hash, report data,
  quote size, authorization expiry, and verifier-signature hash in the receipt.
  This is the chosen current quote-verification path documented in
  `docs/DECISIONS.md`.
- `⚙️/tinker-delegate/scripts/prove-chain-submitter-dstack-anvil.py` proves the
  submitter against Phala/dstack simulator key derivation and real local Anvil:
  it derives the signer through the same dstack path used by the CLI, funds that
  signer on ephemeral Anvil, derives the result verifier through the
  `result-verifier-address` CLI, deploys `DiligenceRoom` with that verifier,
  creates and funds a deal whose `teeIdentity` is the derived signer, obtains a
  verifier signature through `authorize-result`, runs `tinker-delegate
  submit-result`, and verifies the real `EvaluationSubmitted` event carries the
  same contract-derived canonical public commitment authorized off-chain, with
  signer attestation metadata, verifier-signature hash, and
  `raw_secret_egress=false`.
- The watcher is not yet deployed as a fresh Phala/CVM process and does not
  include chain-lag alerting. Source-level deep-reorg handling is conservative:
  canonical hash divergence destroys active private authority and fully rewinds
  rather than attempting a semantic inverse transition.
- A deployed-CVM proof of verifier-authorized `submitResult()` broadcast has
  not yet been run. The verifier policy/signature module and operator CLI path
  are real, but they have not yet been deployed as a verifier service and full
  cryptographic Intel TDX quote parsing/freshness is still incomplete. Full
  settlement-event integration is still incomplete.

[partial] Data custody:

- The upload endpoint keeps accepted plaintext in TEE memory. Dstack mode also
  writes an authenticated encrypted active-deal snapshot; the public runtime
  journal and logs contain no artifact bytes, commitment secret, raw quote, or
  signed transaction.
- The downstream evaluator, Tinker SDK/browser handoff, heap lifetime, crash
  logs, browser download directory, and deployed debug tooling still need a
  full no-disk/no-egress audit.
- Active-deal restart sealing and separate policy-controlled sealed retention
  are implemented in source. Fresh CVM deployment evidence and an operational
  backup/rollback policy remain open.

[partial] Private reward environments:

- The base interface, leakage accounting, one synthetic toy environment, and a
  bounded synthetic hidden-dataset CLI packet are real.
- Real RLVR, TTT, computational-bio, code-audit, or model-evaluation
  environments are not implemented.
- Candidate sandboxing has a local Python runner for toy candidates, but
  hardened OS/container isolation for arbitrary third-party code is not
  implemented.
- Local sandbox side-channel controls exist, but deployed reward side-channel
  hardening for real evaluator/Tinker/browser paths remains open.
- Hidden-holdout split/accounting and generic adaptive-query guards are wired
  into the synthetic environment, but real environments still need
  domain-specific anti-overfitting checks.
- Integration of optimizer policy with real Tinker/browser execution remains
  open P0 work.

[partial] Frontend and product surface:

- The project has service and contract surfaces, but no production-ready
  integrated buyer/seller frontend for the full diligence-room path.
- Gate-health and manual operation affordances are still separate or planned.

## Modeled

[modeled] Private verified rewards:

- The architecture preserves the larger substrate vision: private data,
  verifier code, reward functions, and credentials live inside an attested
  boundary, while agents and optimizers receive bounded outputs only.
- The optimizer is intentionally swappable: RL, TTT, LLM repair loops,
  evolutionary search, or hybrids.
- `PrivateRewardEnvironment` is the real code-level interface for this model,
  while concrete production environments remain partial or planned.

[modeled] RLVR and bio-validation:

- Bio-validation over sealed datasets is conceptual and stub-level only.
- Risk screening, reviewer queues, dual-use controls, bounded biological
  schemas, and fail-closed policies are not implemented.

[modeled] Multi-party governance:

- Corpus policy intersection, consent/revocation, royalty metering,
  production-room account custody, and third-party reviewer lanes remain design
  targets rather than enforced production flows.

## Planned

[partial] Deployment and verification:

- `verify-compose-hash` renders registry-image compose files, rejects local
  `build:` services and mutable tag-only images, emits the digest-pinned image
  manifest, and computes the Phala Cloud-style compose hash over the rendered
  app-compose object. It also supports the Phala raw-compose/allowed-env mode
  needed to check local image policy when Phala's full app-compose hash includes
  platform metadata not reproduced by the public compose file alone.
- The Phala Playwright sidecar image is pinned by amd64 digest.
- The deploy-critical `tinker-delegate` and `tee-email-oracle` Dockerfiles now
  pin the Python runtime and `uv` helper images by versioned digest.
- `.github/workflows/build-tee-images.yml` builds those two images on
  GitHub-hosted runners, pushes `linux/amd64` images to GHCR, attaches
  BuildKit SBOM/provenance attestations, generates SPDX SBOMs, and emits
  GitHub-signed provenance and SBOM attestations.
- `⚙️/tinker-delegate/scripts/verify-ghcr-image-attestation.sh` verifies a
  digest-pinned GHCR image against this repo, the TEE image workflow, expected
  source commit, SLSA provenance predicate, SPDX SBOM predicate, and
  non-self-hosted-runner policy before the image digest is allowed into Phala
  deployment inputs.
- `python -m tinker_delegate.main verify-deployment-bundle` verifies the
  current deployment as one bounded certificate by combining the GitHub image
  attestation gate, digest-pinned compose policy, sidecar digest requirements,
  and live Phala CVM attestation envelope.
- GitHub Actions run `28974675082` built the current deploy-critical images on
  GitHub-hosted workers from source commit
  `556387a9e673e91d3ea4991cdaee96ead3e52922` and attached GitHub-signed SLSA
  provenance plus SPDX SBOM attestations. The local deploy gate verified both
  image digests with
  `⚙️/tinker-delegate/scripts/verify-ghcr-image-attestation.sh`.
- Current deploy-critical image digests:
  - Oracle:
    `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:287028f12f7cb596d573f950e6dc1cb2437fe37ea2984101abd8bd451d44eca3`.
  - Delegate:
    `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:72b584ff4228783711ff3108f8674a9d5ab86fec2a072cf1ea3f8b71b697ec38`.
- Local `verify-ghcr-image-attestation` checks passed for both current image
  indexes with source commit `556387a9e673e91d3ea4991cdaee96ead3e52922`,
  verified provenance attestation, verified SBOM attestation, and
  `raw_secret_egress=false`.
- The current Phala compose hardcodes these deploy-critical image refs and the
  disabled secret-bearing gates directly. An intermediate redeploy on
  2026-07-08 showed that changing encrypted image env values alone did not
  change the live attested compose hash, so env-provided image refs are not
  treated as quote-bound deployment evidence.
- Full reproducible container images for every side service, apt package
  pinning, timestamp normalization, and published digest evidence for
  non-critical side services remain open.
- Current Phala deployment:
  - CVM ID: `670b3b21-4338-4d4e-ae72-7c8922579f59` / `cvm_1w85mGjo`
  - App ID: `f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717`
  - Status: `running`
  - Live compose hash:
    `e9e07417f7df3b0dae2fdc148fc6847751afa240b9167cc81e76883060ecd586`
  - Gateway base: `dstack-pha-prod9.phala.network`
  - Public logs/sysinfo: `false` / `false`.
  - Historical runtime env surface: narrowed on 2026-07-08 using the retired
    helper's `--runtime-env-policy compose-refs`, which selected 7 allowed env
    keys for the current normal compose instead of the previous broad 90-key
    `.env` surface, and prints only policy, key count, and a key-set SHA-256
    unless `--print-runtime-env-keys` is explicitly requested. A live
    `phala cvms get` read showed `allowed_env_count=7`; deployment-bundle
    verification passed against the narrowed allowed-env policy with
    `raw_secret_egress=false`. The current helper no longer accepts that flag;
    it validates reviewed per-descriptor key classifications and cannot yet
    execute a production commit.
  - Temporary public-log debug exception on the main CVM: reverted on
    2026-07-08. Public logs and public sysinfo are disabled.
    `ORACLE_AUTO_GENESIS=false`,
    `TINKER_BOOTSTRAP_SIGNUP=false`,
    `TINKER_ALLOW_ADD_BALANCE_ENDPOINT=false`, and
    `TINKER_ALLOW_BROWSER_READINESS_ENDPOINT=false`,
    `TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT=false`,
    `ORACLE_ALLOW_CREDENTIAL_PROVISIONING_ENDPOINT=false` are still bound
    directly in compose so no mailbox genesis, Tinker login, credential
    provisioning, add-balance endpoint, browser-readiness endpoint, or
    selector-probe endpoint is active.
  - OS posture: still partial. `phala cvms get` reports
    `dstack-dev-0.5.9`, `is_dev=true`, and OS image hash
    `de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`
    after the current bounded-image update. Attempts to update the existing CVM to
    `dstack-0.5.10-4c9bd024` or `dstack-0.5.10` with `--no-dev-os` failed in
    the Phala CLI/API with a required `correlationId` validation error; a later
    compose/image update using `--no-dev-os` completed, but the live CVM still
    reported the dev OS afterward.
  - OS image hash:
    `de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`
  - Attested compose hash:
    `000ac9ba94fc8cf1870786f9a9a3f7b1586ce74ad21f23143ce4e3d88941318e`
  - Local raw-compose/image-policy hash:
    `63b4b43e50ba1938bf0f1d266eff60a67a431ccc4b4d0e1829d3f738d53e4993`
  - Rendered compose SHA-256:
    `9e331b4e42f3474278fe6e1b9465e2ba2e8091af13b9af1073983b6c82f0c916`
  - Delegate endpoint:
    `https://f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717-8080.dstack-pha-prod9.phala.network`
  - Oracle endpoint:
    `https://f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717-8000.dstack-pha-prod9.phala.network`
  - Delegate `/health`: `status=ok`, `agent_stack_available=true`,
    `api_key_configured=false`, `bootstrap_attempted=false`,
    `last_bootstrap_attempt_record=null`.
  - Oracle `/health` after the main-CVM mailbox genesis proof:
    `status=ok`, `oracle_email=""`,
    `oracle_email_hash=535adcedea37ac48af0e43720f390125749053a0a0215b669ce55c746cd10132`,
    `oracle_ready=true`, `imap_connected=true`, `dstack_enabled=true`.
  - Current captcha/genesis finding: an explicit temporary
    `dnai-wikigen-oracle-genesis-debug` Phala CVM was deployed with the
    log-hardened oracle image, `ORACLE_AUTO_GENESIS=true`, public logs, public
    sysinfo, and dev OS access, while Tinker bootstrap, billing, and credential
    provisioning were absent/disabled. Its app ID was
    `8958416343d338e1e95f1c0a78a1747970d57cb5` and compose hash was
    `2cf555237c0e3ed7dee2fbced583721cb00cb75bfdced14cd9cf6a155c4e43b0`.
    The oracle derived a dstack key at `email/creds-debug`, found no
    credentials, ran auto-genesis, parsed/solved three HTTP cock.li captchas,
    and cock.li rejected all three as incorrect. Browser fallback then reached
    `ws://172.20.0.3:9223/devtools/browser/...` but timed out in
    `BrowserType.connect_over_cdp`. The debug CVM was deleted after collecting
    this bounded evidence, so no temporary public-log/dev-OS debug CVM is left
    running.
  - Current source-level genesis fix: live form inspection showed cock.li's real
    password confirmation field is currently `password_confinm`, while
    `password_confirm` is a tabindex `-1` honeypot. The oracle HTTP payload now
    fills `password_confinm`, mirrors `csrf_valid`, and leaves
    `password_confirm` empty; the browser fallback now fills
    `password_confinm`.
  - Current Phala proof after the form-contract fix: GitHub-built oracle image
    `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:19c4aae35b0e9ab2758b7f680c2638f838c8c5a08da1c37f7f1b3bd192bfa1e2`
    from commit `ca1b17cd5d7478e54020fa91065ce9ebcef49223` verified
    provenance/SBOM locally, then an explicit temporary auto-genesis debug CVM
    with app ID `4c92eec94e2d7b6e8c8a7940cb0b6eb4a0e8e1bd` and compose hash
    `142408b66a30aecac87cb172b615ca12675de1f764a0eaa71d7cc8bc30197a58`
    reached IMAP verification and loaded credentials with email hash
    `a97ad16221ab3a550c42be406ff01638b68659c18eaf507461a399fe8874edd3`.
    The temporary public-log/dev-OS debug CVM was deleted immediately after
    evidence collection.
  - Debug-surface finding from that proof: successful genesis made public
    `/health` expose a raw generated mailbox address. The debug CVM was deleted,
    and source now bounds public `/health` and `/attestation` to readiness plus
    `oracle_email_hash`; raw address retrieval has moved to runtime-authenticated
    `/email`.
  - Current bounded-health Phala proof: GitHub-built oracle image
    `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:99ce7765558a00699e265a8ca7cdcdc8f402dd93c50cf8ddb52a1ef175dffefe`
    from commit `64739e48f1ac2af63a6f1c19053eaa281790fa6a` verified
    provenance/SBOM locally, then an explicit temporary auto-genesis debug CVM
    with app ID `18ab03c040c9c327b9333230b6a405bbccd90bec` and compose hash
    `fe20b736b9db9b3b4b3e8d9ddbcdfffabecc4cdf3311ead6be1fb922a8892c41`
    reached IMAP verification and loaded credentials with email hash
    `ac5745b07e812ca450e7e16a51cea0cb3b6dcf5d6168cee96e7931312a68be81`.
    Public `/health` returned `oracle_email=""`, `oracle_ready=true`,
    `imap_connected=true`, and only that hash; public
    `/attestation?context=attestation` returned `oracle_email=""`, the same
    hash/readiness fields, compose hash, and a verified TDX quote;
    unauthenticated `/email` returned `401 Bearer token required`. The temporary
    public-log/SSH/dev-OS debug CVM was deleted after evidence collection.
    This proof did not run Tinker bootstrap, billing, API-key provisioning, OTP
    retrieval, or card handling.
  - Historical temporary-public-log evidence from before the 2026-07-08 revert
    confirmed the oracle derived the dstack storage key, found no credentials,
    started in degraded mode, and loaded zero OTP replay entries; delegate logs
    confirmed no Tinker API key was configured. No genesis, captcha, OTP, Tinker
    login, API-key capture, or billing flow ran during that debug window.
  - Source-level email-oracle log hardening and bounded public email surfaces
    are now in the main Phala CVM's pinned oracle image. Public `/health` and
    `/attestation?context=oracle-credentials` return `oracle_email=""` and
    only hash/readiness fields for the sealed mailbox.
  - Main-CVM mailbox genesis proof: a one-shot
    `docker-compose.mailbox-genesis.phala.yaml` update enabled
    `ORACLE_AUTO_GENESIS=true` while keeping `TINKER_BOOTSTRAP_SIGNUP=false`,
    `TINKER_ALLOW_ADD_BALANCE_ENDPOINT=false`, and credential provisioning
    disabled. Its local raw-compose/image-policy hash was
    `90f4f45c12b645b3b43f6e56c5d5708f2be4c488999a65cd6c391fd09209c027`,
    rendered compose SHA-256 was
    `88f39d901797c5839a8b9cbf11bfa2bb680b54e92fa84e794e79c5a717d0bad3`,
    and live attested compose hash was
    `0541c599acc399f943c6b1804cbf0e8b15aedbf2efeea98d9b2ac856b826f101`.
    `verify-deployment-bundle` passed for that one-shot deployment. The CVM
    was then redeployed back to `docker-compose.all.phala.yaml`; final
    `phala cvms get` showed `auto_genesis=false`, `bootstrap_signup=false`,
    public logs/sysinfo disabled, and the sealed mailbox still ready with the
    same public email hash.
    The one-shot mailbox-genesis compose file has since been refreshed to the
    current GitHub-built oracle/delegate image digests; its local
    raw-compose/image-policy hash is
    `93171544e7dcad7738df2b623625e6fb97ea16557d0e5af6e6fcf9cf9b7a8cac`
    and rendered compose SHA-256 is
    `3bb385928598d63e5697f06d3c34a5ffab23ac547f0c633ac62bf921c7f73d88`.
    That refreshed one-shot profile has not been re-run live because the main
    CVM mailbox is already sealed and ready.
  - Main-CVM Tinker bootstrap proofs: one-shot
    `docker-compose.tinker-bootstrap.phala.yaml` updates enabled only
    `TINKER_BOOTSTRAP_SIGNUP=true` while keeping `ORACLE_AUTO_GENESIS=false`,
    `TINKER_ALLOW_ADD_BALANCE_ENDPOINT=false`, and credential provisioning
    disabled. The first live run used the pinned headless Playwright sidecar:
    local raw-compose/image-policy hash
    `ae49a564f5b2a49a5ef4942230f293d6437a30c30f9d9e5bce1a5bc21eff6975`,
    rendered compose SHA-256
    `6a6ecc35faa323f9506b259677b4a9747c483ee7c3087f931a5b450f019b5664`,
    and live attested compose hash
    `1a5dc7877d02f15b920736469c1fd4cde750f10f68773b74365257647629c42f`.
    It reached the Tinker auth surface and failed closed with
    `bootstrap_error_kind=auth_access_blocked`; no API key was configured or
    stored. The second live run removed the Playwright sidecar from the
    bootstrap profile and forced the delegate through headed Neko CDP:
    local raw-compose/image-policy hash
    `eabfc81083c93d7ba215a85f23d082641b4e13856cb1c15fe89b40ba8939465b`,
    rendered compose SHA-256
    `07d945588defbf49b1446db916c6bb5a9da1c2aaf2851bfacc6d62848bb26ea1`,
    and live attested compose hash
    `72f91374633541d1f02e467df87473bcd4a7c6e3b539c49be905ae7867023a4c`.
    The third live run used GitHub-attested oracle/delegate images from commit
    `74ad4b6d7359d418507d131a5f30ad7e541987af` with bounded early-stage
    bootstrap instrumentation: local raw-compose/image-policy hash
    `c6da04d12d7bdbfcca6b63a992efed38b2efa1cfc57b7d8e91cec7c15a9f77cc`,
    rendered compose SHA-256
    `70743002dcec8d10d7bacab0da0d0b6c08c54477383edd8a50465fb3f86e5cb8`,
    and live attested compose hash
    `57bbe96fa774fc2e9cfc266ee94526ab6177902654c833b32fced8bc1c801443`.
    `verify-deployment-bundle` passed for all one-shot deployments. In the
    latest headed-Neko run,
    `/health` showed `browser_ws_endpoint=""`,
    `cdp_url=http://172.20.0.3:9223`, `api_key_source=bootstrap`,
    `bootstrap_success=false`, and `bootstrap_error_kind=bootstrap_error`,
    and captured a bounded `last_bootstrap_attempt_record` with
    `surface=tinker_auth`, `outcome=unknown_failure`,
    `furthest_stage=not_started`, and `raw_secret_egress=false`. The outer
    `bootstrap_error_kind` still flattened to `bootstrap_error` in that run.
    The fourth live run used GitHub-attested oracle/delegate images from commit
    `8fb6e3a7dac3ef58f1e4c1e902a36ebd612b910e` and proved the preservation
    fix in Phala: local raw-compose/image-policy hash
    `7773f9be4bfcc5da7eea12f98f49361729879c2aef0c2ba345b6a8cd515215e7`,
    rendered compose SHA-256
    `a71def49759337daf47ed9cb5467614bdfa8970611f4761a9d6494e613eea5aa`,
    live attested compose hash
    `a1d5b65bd12a1a7842cf0999cffea0d3ce665be3e419aeb87e6f9110b4431d34`,
    and `/health.runtime.bootstrap_error_kind=unknown_failure` alongside the
    same bounded nested `tinker_auth` receipt. The oracle stayed ready with
    `oracle_email=""` and the existing mailbox hash, `/pin` still returned 401
    without bearer auth, `/credentials/encrypted` returned 403 while disabled,
    and `/billing/add-balance` returned 403 while disabled. The CVM was then
    redeployed back to `docker-compose.all.phala.yaml`; final health showed
    `api_key_configured=false`, `api_key_source=none`, and
    `bootstrap_attempted=false`.
    The fifth live run used GitHub-attested oracle/delegate images from commit
    `ca877db2d02ee4498d30560f19d4d394cf165676` and enabled
    `TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT=true` only in the one-shot bootstrap
    profile. Its local raw-compose/image-policy hash was
    `329c9bb241f3ab8c068e38e0321ee7c3a0cc182e1b33f17d06b0521e71316293`,
    rendered compose SHA-256 was
    `5b93911f98626d33ec4d8ca5c42ec031e7d8700ff1e024756f071e8941f58e37`,
    and live attested compose hash was
    `276cf111536f8ac1bdfe628a1e5d7451ea43a8bd895a8e120dd47d16ef7a98d9`.
    `/health` again showed bounded `tinker_auth` `unknown_failure` bootstrap
    evidence with `raw_secret_egress=false`. `GET /browser/selector-probe`
    returned HTTP 503 with bounded `browser_unavailable`,
    `bounded_output=true`, `read_only=true`, and `raw_secret_egress=false`;
    no page text, account identifier, OTP, API key, card material, cookie, or
    raw browser URL was returned. The CVM was then redeployed back to
    `docker-compose.all.phala.yaml`; final health showed
    `api_key_configured=false`, `api_key_source=none`,
    `bootstrap_attempted=false`, and `/browser/selector-probe` returned 403.
    The sixth live run used GitHub-attested oracle/delegate images from commit
    `a2e14b542314a16e07f20a17694e9da1a67b1f1c` and enabled
    `TINKER_ALLOW_BROWSER_READINESS_ENDPOINT=true` plus
    `TINKER_ALLOW_SELECTOR_PROBE_ENDPOINT=true` only in the one-shot bootstrap
    profile. Its local raw-compose/image-policy hash was
    `f027c95bcbeea220735450cfdd5c09e4952bc6924449fa202be42f6729053e0b`,
    rendered compose SHA-256 was
    `8c8e4bc1ee4bc41ee5a15723d1e4bcb389cc4e5bf296523376d90df2bea530e1`,
    and live attested compose hash was
    `165f6710cd59b342b162121c691fa46886b5975c1624b1d0a7893769d604b116`.
    `GET /browser/readiness` returned HTTP 200 with bounded
    `error_kind=cdp_timeout`: CDP metadata was reachable, JSON-shaped, and
    advertised Chromium WebSocket metadata, but `connect_over_cdp` timed out.
    `GET /browser/selector-probe` still returned HTTP 503 with bounded
    `browser_unavailable`. The CVM was then redeployed back to
    `docker-compose.all.phala.yaml`; final health showed
    `api_key_configured=false`, `api_key_source=none`,
    `bootstrap_attempted=false`, and both diagnostic endpoints returned 403.
    The seventh live run used GitHub-attested oracle/delegate images from
    commit `7973b27d27a3d3fba3a24efcc23c89498e8a04bf` and enabled the same
    two one-shot diagnostic endpoints. Its local raw-compose/image-policy hash
    was `3c999ed959b3a87ea95879cfb6cc4e93b76cf684ce73b6a2d9fde603961d450e`,
    rendered compose SHA-256 was
    `eda52d403243a309abfa2b7626e9fc2958f14373ba691e4575dad3bc5ad4d176`, and
    live attested compose hash was
    `e1af69be64ffd1f589a4b8a480c14eda082fda26c63424b08d09faecae1accc2`.
    `GET /browser/readiness` returned HTTP 200 with bounded
    `error_kind=cdp_timeout`: CDP metadata was reachable, the advertised
    WebSocket URL stayed hashed/classed, raw TCP connect succeeded, the HTTP
    Upgrade request was sent, HTTP status band was `101`, and Playwright
    `connect_over_cdp` still timed out. `GET /browser/selector-probe` still
    returned HTTP 503 with bounded `browser_unavailable`. The CVM was then
    redeployed back to `docker-compose.all.phala.yaml`; final health showed
    `api_key_configured=false`, `api_key_source=none`,
    `bootstrap_attempted=false`, and both diagnostic endpoints returned 403.
    The eighth live run used GitHub-attested oracle/delegate images from commit
    `f63dd1825b625300940d7a01805de17f287fe729` and enabled the same two
    one-shot diagnostic endpoints. Both images verified local GitHub SLSA
    provenance and SPDX SBOM attestations before deployment:
    oracle `ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:8b175d8c7af344433c2c3880325292a80e135242e0c805443c9377f775fb7bc5`;
    delegate `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:a038fdd9b5092b8d1be2c59d8b835180a8c41afdebe7d900c0ac643d98ef2793`.
    Its local raw-compose/image-policy hash was
    `597e1e12e0d9c07604eef61eb7af8869f3e66ea13f808d6e2154d6a90948e7ff`,
    rendered compose SHA-256 was
    `a6af14aa640c50f9bf6f55878fd48620e7730181dde5a3744ca6f781b96006d9`,
    and live attested compose hash was
    `6264dca2ae413e84e39500ca60ce70f5b97756d413d57be9050a30733ff56dd0`.
    `GET /browser/readiness` again returned HTTP 200 with bounded
    `error_kind=cdp_timeout` and a successful one-command CDP protocol probe:
    metadata succeeded, WebSocket Upgrade status band was `101`,
    `Browser.getVersion` returned bounded `result`, and browser family was
    `chromium`. `GET /browser/selector-probe` returned HTTP 200 with
    bounded raw-CDP fallback output: `probe_backend=raw_cdp`,
    `metadata_success=true`, `upgrade_success=true`,
    `target_command_success=true`, HTTP status band `101`,
    `target_count_band=2+`, `page_count_band=1`,
    `fallback_from_backend=playwright`, `fallback_reason_kind=timeout`,
    `raw_secret_egress=false`, and no pages because `Page.getFrameTree` timed
    out before frame inventory. The CVM was then redeployed back to
    `docker-compose.all.phala.yaml` using the same verified images; the normal
    local raw-compose/image-policy hash is
    `80f6ac6dac895e06b6787d09ed7ecb4d412a51c27f3205bd39129be1b0d22894`,
    rendered compose SHA-256 is
    `8e95cd75efbe2154dc9d2f8da0fdecc08cd7e12a85eb1e608859e93a79fbd87b`,
    and live restored compose hash is
    `cdff9896cb67cf97127928348871e312d8d7a82e9c130f8e4c6160c3023f8c97`.
    Final health showed `api_key_configured=false`, `api_key_source=none`,
    `bootstrap_attempted=false`; `/browser/readiness` and
    `/browser/selector-probe` returned 403; `/billing/add-balance` returned
    405; `/credentials/encrypted` returned 404; public logs/sysinfo remained
    false. `verify-deployment-bundle` then succeeded against the restored
    delegate endpoint: both GHCR image refs verified GitHub provenance/SBOM
    attestations for source commit
    `f63dd1825b625300940d7a01805de17f287fe729`, the rendered compose included
    the expected Neko and Playwright sidecar digests, and the live CVM
    attestation matched app ID, live attested compose hash
    `cdff9896cb67cf97127928348871e312d8d7a82e9c130f8e4c6160c3023f8c97`,
    OS image hash
    `de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9`,
    report data
    `4e9f44d5f19f17701ff866570f30dca930fdeef06bc06ce4131aa551f87740e9`,
    encryption public key
    `b98deca07d8d5e1c9ad00872f48151e82045bb65c1c185a3b2ba63e3141d1451`,
    and quote size `5010`.
  - Public logs are disabled; OTP, Tinker API-key, or card-bearing flows must
    still use only bounded interfaces and disabled endpoint gates must be
    intentionally reopened with fresh evidence.
  - Oracle `/pin` without bearer auth returns `401 Bearer token required`.
  - Public CDP gateway `/json/version` returns host-header rejection rather than
    a usable browser-control response.
  - `verify-cvm-attestation` succeeded against delegate
    `/attestation?context=artifact`: mode `tdx`, quote size `5010`, report data
    `670328b0232c9ed5c7d5dea1b64d4f34a4fcc9c15d3f732466331c31f1a94240`,
    encryption public key
    `44faa46a2b7e25c60899d9f59a7b1e5eb202a5f98653a1e8f31caf0d0f676500`,
    and the attested compose/app/OS-image/image-digest policy above.
  - `verify-deployment-bundle` succeeded against the same delegate endpoint:
    both deploy-critical GHCR image refs verified GitHub SLSA provenance and
    SPDX SBOM attestations for source commit
    `7973b27d27a3d3fba3a24efcc23c89498e8a04bf`, the rendered compose included
    those exact oracle/delegate refs plus required Neko and Playwright sidecar
    digests, and the live CVM attestation matched app ID, attested compose hash,
    OS image hash, report data
    `6f4097de14dfae4c1c24a51dee1bbfc8b2c87efb0dd9c6eefdba11c7f0294105`,
    public key
    `1fed47f377a7b7d921553ee3bdf2553e46bac60eb41406edca7fc741e20b0c35`,
    and quote size `5010`.
  - Oracle `/attestation?context=oracle-credentials` now returns a live TDX
    credential-ingress envelope with report data
    `561e8fd43159ed838406827fb19531880c82e795ddb636dd0fec08f99b91203e`,
    encryption public key
    `6b56f04928d2fe1a6150d3fa48d2591a87a92ebb8d614ef79508ff21dabf5215`,
    quote size `5010`,
    `oracle_email_hash=535adcedea37ac48af0e43720f390125749053a0a0215b669ce55c746cd10132`,
    `oracle_ready=true`, `oracle_email=""`, and no raw credential output.
    `POST /credentials/encrypted` rejects while disabled by default.
  - Delegate `POST /billing/add-balance` rejects while disabled by default
    with a bounded `403` policy error, and no card material is accepted through
    the public endpoint in the current compose.
- `deployments/base-sepolia.json` is the machine-readable deployment ledger. It
  retains prior-operator Base Sepolia contracts and transaction hashes as
  history; those records are not the current release.
- Historical prior-operator Base Sepolia contracts include:
  `DiligenceRoom` at `0x5d8a18628b4c8427eea89aa5498d81ff5ad3f423` and
  `EmailOracleAuth` at `0xf52c18a33bd172ae94282132649d80bcd4b872ff`.
  Historical on-chain reads confirmed that release's Foundry deployer was the
  `DiligenceRoom` developer and `EmailOracleAuth` owner.
- That historical Base Sepolia `DiligenceRoom` deployment predates the
  verifier-signature `submitResult()` ABI in this branch. A fresh deployment
  with `DILIGENCE_RESULT_VERIFIER` recorded in the manifest is required before
  claiming the live contract enforces result-verifier authorization.
- A historical Phala CVM with a recorded CVM ID, app ID, compose hash, image
  digests, gateway endpoint, and public dstack quote envelope was revalidated
  with `verify-deployment-bundle`; full Intel TDX quote-internal parsing remains
  incomplete.
- Docker compose validation, docs stale-phrase checks, and broader container
  build CI remain open beyond the current local/CI verification gate.

[planned] Security hardening:

- Full TDX quote verifier.
- Contract-bound attestation policy.
- DLP/egress enforcement beyond bounded route design and redaction tests.
- Reviewer approval flows for widened access.
- Fail-closed bio/dual-use result schema.

## Historical Deployed Resources — No Current Release Deployment

Deployment manifest: `deployments/base-sepolia.json`.

`example.env` intentionally leaves these deployment outputs blank:

```text
ESCROW_ADDRESS=
JUDGE_ADDRESS=
PHALA_CVM_ID=
```

Historical prior-operator Base Sepolia contracts:

```text
DiligenceRoom:   0x5d8a18628b4c8427eea89aa5498d81ff5ad3f423
Deployment tx:   0xfa50ada33f0a2c9f434c58b6cadf98defa01302b7c3e444116c021370d28169e
Developer:       0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD

EmailOracleAuth: 0xf52c18a33bd172ae94282132649d80bcd4b872ff
Deployment tx:   0xa29d749517a69f868db1785c7f091ea75f60a76ef657badedb0848e44be7a349
Owner:           0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD

TinkerAccountEncumbrance: 0x9f2616f3f7b0dc363bba19f7d72b9061f791a06e
Deployment tx:             0x7679df09aa2e939d748be0e017f380f5e7e44331a482531380198e93bdcaed01
Owner:                     0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD
Initial compose hash:      0xb3fc9840dc7db51d2ba835f349564fbace5b64a0a122025c9c1c5923f88686f7
Latest approved compose:   0x40f0ca1a366a106a202f655c8dc74f4a14aadf40b7d86f7923a8f96515325ace
Latest approval tx:        0x5eea5735154e18cb94e198c1d7fc7867f1f2f095de4db2b85d7eb051a9dd73d6
Latest approval block:     43928500
```

On-chain verification reads from the deploy helper:

```text
DiligenceRoom:   0x5d8a18628b4c8427eea89aa5498d81ff5ad3f423
  developer:     0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD
  tx:            0xfa50ada33f0a2c9f434c58b6cadf98defa01302b7c3e444116c021370d28169e
EmailOracleAuth: 0xf52c18a33bd172ae94282132649d80bcd4b872ff
  owner:         0xEd1Ade0bC26BD63A6e509Da3F5cDf6617369F4dD
  allowAny:      true
  delay:         172800
  tx:            0xa29d749517a69f868db1785c7f091ea75f60a76ef657badedb0848e44be7a349
```

The historical Base Sepolia `DiligenceRoom` and `EmailOracleAuth` addresses are
now superseded and remain useful only as legacy evidence in older runbooks and
broadcast artifacts.

A deployment is considered production-current only after the manifest records
chain, transaction hashes, verified contract links, Phala CVM ID, app ID,
compose hash, image digest, endpoint, quote evidence, and the commands used to
reproduce or verify them. Missing values must stay `null`, `partial`, or
explicitly legacy.

## Current Blockers

- One-off operator-owned Tinker funding validation succeeded with bounded
  `$10.00` balance evidence, but production/repeated funding is still not
  approved or hardened.
- Production or repeated card funding needs legal/compliance approval; raw-card
  encrypted delivery remains limited to an operator-owned capped validation
  path.
- Generic deployed credential provisioning remains disabled by default and has
  not been run as a production provisioning flow. The funding-validation CVM has
  sealed Tinker API-key state sufficient to reach `api_key_loaded`, but this is
  still an operator-validation posture, not production credential custody.
- Cock.li account genesis inside Phala is source-fixed and debug-proven for the
  standalone oracle-genesis compose. That historical proof covered bounded
  public `/health` and `/attestation` plus a runtime-authenticated raw `/email`;
  current source supersedes the latter with commitment-only `/email` and no
  `/inbox` route. The main combined Phala
  CVM now consumes the bounded oracle image. In the current steady profile
  `ORACLE_AUTO_GENESIS=false` means the main CVM is not auto-generating fresh
  mailbox credentials, but deployed Tinker login/API-key sealing has already
  been proven for the operator-validation account. The live combined oracle
  health remains degraded with IMAP disconnected, so email-oracle production
  readiness is still open.
- The main Phala CVM still runs a dev OS image (`dstack-dev-0.5.9`,
  `is_dev=true`). For the current funding debug push, public logs/sysinfo/TCB
  info are also enabled. Production wrap-up must disable those debug surfaces
  and move to a non-dev dstack OS image or record a Phala-side blocker; earlier
  `--image dstack-0.5.10* --no-dev-os` attempts failed with a Phala
  `correlationId` validation error, and the latest successful compose/image
  update with `--no-dev-os` still left the CVM reporting dev OS.
- Deployed headed-Neko browser packaging is now proven on Phala for Tinker
  login/API-key capture, reauth, and the low-value funding lane. The earlier
  selector/readiness diagnostics remain useful history: they reached CDP
  metadata, confirmed Chromium WebSocket metadata exists, and proved the raw
  WebSocket HTTP Upgrade returns status band `101`, before the custom Neko/CDP
  image fixed the deployed page-control path.
- Full Intel TDX quote-internal parsing and quote freshness checking need
  implementation; current verifier checks the public dstack envelope and
  report-data binding only.
- Registry images, pinned digests, SBOM/provenance attestations, and
  compose-hash evidence are complete only for the deploy-critical oracle and
  delegate images, not every side service.
- Real Tinker SDK training/sampling/cleanup inside a deployed CVM is not yet
  proven.
- The deployed Tinker SDK smoke path is now past image/redeploy/compose-approval
  prerequisites, but the live run fails closed with `BadRequestError` at
  `service_client_create` before training creation. The current diagnostic
  receipt classifies the failure as `invalid_request` / `4xx` from Tinker SDK
  `0.15.0` and confirms
  `client_config.project_id_argument=omitted`; older `Qwen/Qwen3-8B` rank `16`
  and rank `32` retries failed with the same bounded hash before this
  client-config receipt was live. The new `tinker-smoke-command-plan` CLI makes
  the next retry reproducible but does not itself prove Tinker training. No
  deployed Tinker run ID, checkpoint, sample, cleanup receipt, or spend proof
  exists yet.
- Bio-validation must remain fail-closed until risk screening, reviewer queues,
  and bounded schemas exist.

## Validation Commands

Focused commands used for the currently built surfaces:

```bash
cd "⚙️/tinker-delegate" && uv run python -m unittest tests.test_browser_diagnostics -v
cd "⚙️/tinker-delegate" && uv run python -m unittest tests.test_browser_diagnostics tests.test_selector_map tests.test_compose_hardening -v
cd "⚙️/tinker-delegate" && uv run python -m unittest discover -s tests -v
cd "⚙️/tinker-delegate" && uv run python -m compileall tinker_delegate
cd "⚙️/tinker-delegate" && uv lock --check
cd "⚙️/tinker-delegate" && docker build -t dnai-tinker-delegate-agent-extra:local .
cd "⚙️/tinker-delegate" && docker run --rm -d --name dnai-tinker-delegate-agent-extra-check -p 18080:8080 dnai-tinker-delegate-agent-extra:local
cd "⚙️/tinker-delegate" && curl --retry 12 --retry-delay 1 --retry-connrefused --silent --show-error http://127.0.0.1:18080/health
cd "⚙️/tinker-delegate" && docker stop dnai-tinker-delegate-agent-extra-check
cd "⚙️/tinker-delegate" && uv run python -m tinker_delegate.main verify-attestation --help
cd "⚙️/tinker-delegate" && uv run python -m tinker_delegate.main verify-cvm-attestation --help
cd "⚙️/tinker-delegate" && uv run python -m tinker_delegate.main verify-deployment-bundle --help
cd "⚙️/tinker-delegate" && scripts/verify-cvm-attestation.sh --help
cd "⚙️/tinker-delegate" && scripts/verify-ghcr-image-attestation.sh --help
cd "⚙️/tinker-delegate" && uv run python -m tinker_delegate.main verify-compose-hash --help
cd "⚙️/tinker-delegate" && uv run python -m tinker_delegate.main upload-artifact --help
cd "⚙️/tinker-delegate" && uv run python -m tinker_delegate.main funding-preflight --help

cd "⚙️/tee-email-oracle" && uv run python -m unittest discover -s tests -v
cd "⚙️/tee-email-oracle" && uv run python -m compileall email_oracle

cd "⚙️/tinker-delegate" && \
  scripts/verify-ghcr-image-attestation.sh \
    ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:287028f12f7cb596d573f950e6dc1cb2437fe37ea2984101abd8bd451d44eca3 \
    --source-digest 556387a9e673e91d3ea4991cdaee96ead3e52922 \
    --repo G-structure/dnai-wikigen

cd "⚙️/tinker-delegate" && \
  scripts/verify-ghcr-image-attestation.sh \
    ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:72b584ff4228783711ff3108f8674a9d5ab86fec2a072cf1ea3f8b71b697ec38 \
    --source-digest 556387a9e673e91d3ea4991cdaee96ead3e52922 \
    --repo G-structure/dnai-wikigen

cd "⚙️/tinker-delegate" && \
  uv run python -m tinker_delegate.main verify-cvm-attestation \
    https://f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717-8080.dstack-pha-prod9.phala.network \
    --compose docker-compose.all.phala.yaml \
    --env-file ../../.env \
    --phala-raw-compose \
    --allowed-env ORACLE_RUNTIME_AUTH_KEY_PATH \
    --allowed-env TINKER_DSTACK_KEY_PATH \
    --allowed-env TINKER_FUNDING_MODE \
    --allowed-env TINKER_FUNDING_RECEIPT_KEY_PATH \
    --allowed-env TINKER_MAX_ADD_BALANCE_USD \
    --allowed-env TINKER_ORACLE_AUTH_KEY_PATH \
    --allowed-env TINKER_RUN_METADATA_KEY_PATH \
    --expected-compose-hash 1a4870ab818fe2d8d5e59c6c84ada795a36210c3ea5a0d2bc16d342bfdbb87f5 \
    --attested-compose-hash e9e07417f7df3b0dae2fdc148fc6847751afa240b9167cc81e76883060ecd586 \
    --app-id f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717 \
    --os-image-hash de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9 \
    --require-image ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:287028f12f7cb596d573f950e6dc1cb2437fe37ea2984101abd8bd451d44eca3 \
    --require-image ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:72b584ff4228783711ff3108f8674a9d5ab86fec2a072cf1ea3f8b71b697ec38 \
    --require-image-digest sha256:320c62313c38fd3e6567eef6c8ee78e1d115deb0b88ba60ef02cc4ea7d6ebbea \
    --require-image-digest sha256:e3dca7b3c921ce1ebf45a50a6ac77982532c987e5926eb06535b5f56b363b94f

cd "⚙️/tinker-delegate" && \
  uv run python -m tinker_delegate.main verify-deployment-bundle \
    https://f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717-8080.dstack-pha-prod9.phala.network \
    --compose docker-compose.all.phala.yaml \
    --env-file ../../.env \
    --allowed-env ORACLE_RUNTIME_AUTH_KEY_PATH \
    --allowed-env TINKER_DSTACK_KEY_PATH \
    --allowed-env TINKER_FUNDING_MODE \
    --allowed-env TINKER_FUNDING_RECEIPT_KEY_PATH \
    --allowed-env TINKER_MAX_ADD_BALANCE_USD \
    --allowed-env TINKER_ORACLE_AUTH_KEY_PATH \
    --allowed-env TINKER_RUN_METADATA_KEY_PATH \
    --image ghcr.io/g-structure/dnai-wikigen/tee-email-oracle@sha256:287028f12f7cb596d573f950e6dc1cb2437fe37ea2984101abd8bd451d44eca3 \
    --image ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:72b584ff4228783711ff3108f8674a9d5ab86fec2a072cf1ea3f8b71b697ec38 \
    --source-digest 556387a9e673e91d3ea4991cdaee96ead3e52922 \
    --repo G-structure/dnai-wikigen \
    --phala-raw-compose \
    --expected-compose-hash 1a4870ab818fe2d8d5e59c6c84ada795a36210c3ea5a0d2bc16d342bfdbb87f5 \
    --attested-compose-hash e9e07417f7df3b0dae2fdc148fc6847751afa240b9167cc81e76883060ecd586 \
    --app-id f6a3219ce4b3c13e1c8bbbb56ce2217f9ebd7717 \
    --os-image-hash de9c74f0c85d0820ce075cb4a99f8e39f7b681be632907c5bf8bdc95ea72feb9 \
    --require-image-digest sha256:320c62313c38fd3e6567eef6c8ee78e1d115deb0b88ba60ef02cc4ea7d6ebbea \
    --require-image-digest sha256:e3dca7b3c921ce1ebf45a50a6ac77982532c987e5926eb06535b5f56b363b94f

cd "⚙️/tee-email-oracle" && uv run python -m unittest discover -s tests -v
cd "⚙️/tee-email-oracle" && uv run python -m compileall email_oracle
cd "⚙️/tee-email-oracle" && uv run python -m email_oracle.main provision-credentials-encrypted-prompt --help

cd "⚙️/tinker-delegate/contracts" && forge test

git diff --check
```

Before claiming production deployment, also record the deployed-resource
manifest described above and update `ARCHITECTURE.md` from `[partial]` or
`[planned]` to `[real]` only for evidence-backed paths.
