# dnai-wikigen contracts

Foundry contracts for the attested diligence room and its non-custodial public
registries on Base Sepolia.

## Audited-scope suite

- `DiligenceRoom.sol` — native/ERC-20 diligence escrow with bounded, verifier-
  authorized TEE results and pull-payment settlement. Result authorizations are
  domain-bound to chain, contract, deal, TEE identity, compose measurement,
  bounded output, deterministic cost, an on-chain canonical public-result hash,
  and expiry; callers cannot supply an opaque result hash, and non-canonical
  high-s signatures fail closed. The fresh suite permanently
  freezes its audited 100 bps protocol fee and enables the one-way 100 bps
  deterministic compute-settlement policy before exposure. It also enables both
  compose and TEE-identity approval gates, then irreversibly freezes those
  requirements while their admission sets are still empty. This makes a new
  release fail closed until the exact compose hash and TEE identity complete two
  sequential two-day admission timelocks. Final activation requires exactly one
  active compose, exactly one active TEE identity, zero pending proposals, and
  permanent freezes on both addition paths. Emergency revocation remains
  available, but a revoked closed release cannot admit a replacement; rotation
  requires a freshly deployed room. Its unchanged `bytes32 artifactHash` ABI denotes only
  `keccak256(ASCII("dnai-wikigen/artifact-commitment/v2") || 0x00 || secret32 || rawArtifact)`,
  where `secret32` is exactly 32 private random bytes and `rawArtifact` is the
  exact non-empty artifact byte sequence; there is no legacy raw-keccak mode.
- `TinkerAccountEncumbrance.sol` — non-custodial policy/audit commitments for
  bounded Tinker account operations. Fresh contracts are emergency halted; the
  constructor account and caps are only an observable draft, while the
  canonical fresh deployment starts both compose and manager authority sets
  empty.
  Production requires one exact, canonical account/caps/compose/manager policy
  to remain pending for two days before atomic activation, permanent freeze,
  and unhalt. The contract exposes current, pending, and frozen-baseline roots
  and cardinalities. After freeze, governance can only lower per-operation caps,
  revoke managers or compose hashes, or halt forever; an authority increase
  requires a new reviewed deployment. Only an approved manager can authorize or
  settle active operation records; the owner has no execution fallback and
  retains only governance and emergency controls. The legacy `Wei` field suffix
  denotes unitless integer policy units, not ETH or a token balance. Both caps
  must be nonzero, the spend cap cannot exceed the add-balance cap, and neither
  can exceed the hard `10e18` policy-unit ceiling. It never holds user funds or
  Tinker credentials, and each cap applies independently per operation rather
  than as a cumulative account budget.
- `RoyaltyDistributor.sol` — per-query royalty pull payments with exact ERC-20
  deposit checks and query replay protection.
- `ChallengeRegistry.sol` — versioned public metadata and sealed-artifact,
  evaluator, and release-policy commitments. Every newly published version must
  remain reviewable for two days before configuration can freeze and Open.
  Controller and governance pause latches are independent, so neither authority
  can clear the other's emergency stop. Lifecycle and emergency revocation
  remain available. It has no prize, bond, submission, token, or payout custody.
- `ComputeCreditVault.sol` — same-asset, non-transferable compute-capacity
  accounting for native ETH and exact-transfer allowlisted ERC-20 assets. A
  wallet's EIP-712 v2 authorization binds the project/job IDs, asset, nonce,
  maximum debit, expiry, rate policy, sealed workload, manifest, and canonical
  dispatch intent. The admitted execution TEE cannot inject opaque start or
  usage hashes: the vault derives both from the complete on-chain job and block
  time. Settlement requires two distinct low-s raw EIP-712 signatures over the
  same derived usage and fresh attestation-evidence commitment—one from the
  frozen metering signer and one from the frozen metering QVL signer—with a
  receipt lifetime capped at ten minutes. Funding remains withdrawable by its
  owning wallet; provider and developer proceeds use pull-payment accruals.
  Fresh deployment is paused with empty admission sets and no signer binding,
  so it is not executable until the sequential timelocked release ceremony and
  independent CVM evidence are complete.
- `EmailOracleAuth.sol` — dedicated dstack KMS/oracle policy registry. The fresh
  suite deploys a new instance owned by the explicit operator, with a mandatory
  upgrade timelock and no oracle, device, or consumer allowlist. Its final policy
  is configured only after the replacement CVMs are attested.
- `ExecutionPolicyAnchor.sol` — public monotonic witness for opaque execution-
  policy decision commitments. It compare-and-sets one global hash chain and
  one head per resource, prevents decision-digest replay, and binds writes to a
  timelocked writer/release pair. Fresh deployments have no writer and start
  paused. Production activation permanently freezes writer rotation before
  unpausing; events are not TDX or QVL evidence.

The vault has adversarial unit, fuzz, and invariant coverage but has not received
a third-party formal audit. Do not describe that coverage as an audit, and do
not add a challenge bond or prize-custody contract to this release.

## Build and test

Use the repository Foundry skills instead of ad-hoc commands:

```bash
forge fmt --check
forge build --sizes
forge test
```

`ChallengeRegistry` tests include unit and fuzz coverage for immutable version
history, the full version-review delay (including delay restart on a new
version), lifecycle transitions, independent governance/controller pause
latches, irreversible configuration freeze, authority transfer, malformed
commitments, URI bounds, monotonic IDs, and rejection of native value.

## Base Sepolia deployment

Follow `../docs/DEPLOYMENT-RUNBOOK.md` and the `/forge-deploy` workflow. Populate
the untracked root `.env` from `example.env`, then dry-run:

```bash
./scripts/deploy-base-sepolia.sh
```

The helper defaults to `BROADCAST=false`, requires explicit operator/verifier,
separate compute-developer, metering-signer, and metering-QVL roots, Tinker commitment, and
EmailOracle upgrade-delay inputs, and is restricted to the encrypted Foundry
keystore account named `dev`. It contains no raw-key path.
After review, set `BROADCAST=true`; optionally set `VERIFY=true` with
`ETHERSCAN_API_KEY`.

The manifest updater preserves unrelated deployment and Phala evidence and
appends the previous current-contract snapshot to deployment history. It records
exact creation-reexecution runtime code hashes for all seven contracts. It labels
DiligenceRoom `fail_closed_pending_cvm_binding`, TinkerAccountEncumbrance
`operations_fail_closed_pending_exact_timelocked_release_policy`, ComputeCreditVault
`execution_fail_closed_pending_timelocked_release_binding`, EmailOracleAuth
`deny_all_pending_cvm_binding`, and ExecutionPolicyAnchor
`anchoring_fail_closed_pending_timelocked_release_writer`; it does not claim a
CVM allowlist, executable compute policy, oracle-code freeze, or live monotonic
anchor before the post-attestation governance transactions happen.

After the final CVM identity is independently reviewed, configure DiligenceRoom
with `scripts/configure-diligence-release.sh`. Its three broadcast phases propose
the compose hash, activate it and propose the TEE binding after two days, then
activate the TEE and permanently close both addition paths after another two
days. Browser writes remain disabled until the exact final cardinalities and
binding pass the release gate.

All six production configuration helpers (ChallengeRegistry, Diligence,
Compute, Email, execution-policy anchor, and Tinker) require the same absolute deployment-
intent core, final-release-authority core, and renewable authority-review
envelope, together with each artifact's exact canonical SHA-256 digest. Before
any chain read, keystore access, Forge simulation, or broadcast, the shared
guard validates the immutable deployment intent, semantically validates and
domain-hashes the final authority, verifies the review envelope's exact subject
binding, and checks the one-way final-authority-to-intent and release-SHA
bindings. Legacy `OPERATOR_POLICY_PACKET_*` inputs and arbitrary projection JSON
are rejected. Ceremony-field projection is deliberately fail-closed until a
complete cryptographic projector derives every public configuration value from
the validated authority artifacts; the helpers do not trust operator-supplied
JSON as authority.

Realize the reviewed Arena genesis catalog with
`scripts/configure-challenge-registry-release.sh`. Its code-owned projector
imports the canonical final-authority parser and emits the complete ordered
catalog; operators never copy challenge tuples into environment variables.
Phase 1 requires the pristine fresh registry and creates exact version-1
records at contiguous IDs `1..N`. After every recorded two-day review window,
phase 2 refuses any count, controller, pending-transfer, pause, timestamp,
version, URI, or commitment drift, then permanently freezes and Opens each
record. The helper validates every mined calldata item and receipt in order and
waits for a finalized checkpoint before appending the authority catalog,
receipt block hashes, finalized block-pinned post-state, and an exact `latest`
recheck to `challengeRegistryReleaseHistory`. For `BROADCAST=true`, both
`DEPLOYMENT_MANIFEST_PATH` and `FOUNDRY_BROADCAST` must be canonical absolute
paths outside the checkout; this preserves the identical clean reviewed commit
across the two-day wait. `RELEASE_CEREMONY_LOCK_ROOT` must also name a canonical
external mode-0700 directory. Every release writer shares the
release-SHA-scoped `dnai.release-ceremony-lock.v1`; abnormal exit leaves a stale
lock that only the explicit two-reviewer reconciliation flow may remove. Phase
2 independently re-fetches and matches all
phase-1 evidence before keystore unlock. Review envelopes may renew between
phases without rewriting their historical hashes. A missing, partial, drifted,
or noncanonical phase remains fail closed and requires an explicit recovery or
pristine-registry redeployment; it is never replayed or silently completed by
the helper.

Configure the Tinker account policy separately with
`scripts/configure-tinker-release.sh`. Phase 1 verifies the exact runtime hash,
owner, halted fresh draft, zero existing/pending release, and empty active
compose and manager sets before staging the reviewed account commitment,
positive per-operation policy-unit caps at or below the hard `10e18` ceiling,
one-compose root, and exactly one nonzero delegated manager
distinct from the operator and contract. That manager must be the reviewed
main-runtime TEE identity committed by the same final authority. After the
immutable two-day delay, phase 2 refuses any drift, activates that exact
commitment, permanently closes authority-increasing paths, and unhalts. The
helper uses only encrypted account `dev`, rechecks a clean `RELEASE_SHA`
immediately before and after keystore unlock, verifies every current, baseline,
and pending field, and appends transaction/block evidence to
`tinkerReleaseHistory`. Each phase records the immutable
`finalAuthoritySha256` and the independently renewable
`reviewEnvelopeSha256`; renewing review never changes the final authority being
activated. Every Tinker uint256 cap in the ledger is a canonical
base-10 JSON string (never a JSON number), including current, frozen-baseline,
and pending-zero values, so values above JavaScript's exact-integer range
remain lossless.

Configure the execution-policy writer separately with
`scripts/configure-execution-policy-anchor.sh`. Phase 1 proposes the exact
writer/release commitment. After the immutable two-day delay, phase 2 activates
the writer, permanently freezes rotation, and unpauses a still-empty anchor.
See `../docs/EXECUTION-POLICY-ANCHOR.md` for the runtime reconciliation protocol
and explicit limitations.

`script/EmailOracleAuth.s.sol` remains available for local development only and
rejects Base Sepolia and Base mainnet. Base releases must use the fresh-suite
helper so signer checks, exact runtime verification, append-only evidence, and
source verification cannot be bypassed.
