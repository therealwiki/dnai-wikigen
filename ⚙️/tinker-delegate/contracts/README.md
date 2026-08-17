# dnai-wikigen contracts

Foundry contracts for the attested diligence room and its non-custodial public
registries, designed for Base Sepolia. The current suite is source/local-test
evidence; this README does not assert that the fresh suite has been broadcast,
activated, verified on BaseScan, or connected to measured Phala CVMs.

## Reviewed source suite

- `DiligenceRoom.sol` — native/ERC-20 diligence escrow with bounded, verifier-
  authorized TEE results and pull-payment settlement. Result authorizations are
  domain-bound to chain, contract, deal, TEE identity, compose measurement,
  bounded output, deterministic cost, an on-chain canonical public-result hash,
  and expiry; callers cannot supply an opaque result hash, and non-canonical
  high-s signatures fail closed. The fresh suite permanently
  freezes its reviewed 100 bps protocol fee and enables the one-way 100 bps
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
- `RoyaltyDistributor.sol` — release-bound Collaboration royalty pull payments.
  Fresh instances are owner-controlled, paused, and have no signing authority.
  A two-day ceremony binds two distinct authorities (the settlement CVM and an
  independent QVL verifier) plus a third, distinct writer in the frozen
  `ExecutionPolicyAnchor` release. The v3 authoritative Collaboration flow uses
  deterministic prefunding. After fresh owner grants fix the allocation, the
  sponsor calls `reserveNative` or `reserveERC20` with an exact
  request binding sponsor, settlement ID/nonce, release, room/state, query,
  grants, allocation, sorted owner/amount hash, asset/total, execution
  commitment, and refund deadline. The compact
  `collaborationFundingReservation` getter is intended for finalized EIP-1898
  worker admission; aggregate balance or ERC-20 allowance is not authority.

  After bounded execution, every EIP-712 authorization adds the exact
  result/usage/attestation evidence and current anchor decision/sequence. The
  settlement verifier and QVL verifier authorize purpose-separated digests,
  and the sponsor wallet may broadcast the zero-value `settleReserved` call.
  Reservation consumption, global settlement-ID/nonce replay markers, and all
  owner credits are atomic. `fundingReservationSettlementState` retains the
  consumed/replay/asset/total/owner-hash fields for finalized reconciliation.
  An unused reservation is refundable only to its sponsor at or after the
  committed deadline. `totalReserved[asset] + totalPending[asset]` is checked
  against exact asset balances. Recipient lists are positive, strictly sorted,
  unique, and capped at 16; exact ERC-20 ingress and egress reject
  fee-on-transfer or dishonest-balance tokens. Emergency pause/revocation
  blocks new reservations and settlements without trapping refunds or an
  owner's already-accrued withdrawal.

  `distributeNative` and `distributeERC20` remain compatibility entry points
  for zero-reservation authorizations; the release-gated Collaboration service
  uses reservations and `settleReserved`. Neither path determines ownership,
  query validity, price, or allocation on chain. Those commitments come from
  the fresh-grant execution Basis and the later anchor/main-QVL authorization.
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

### Royalty activation boundary

`DeployFreshSuite.s.sol` deploys the v3 distributor paused, owner-pinned, and
authority-empty. `ConfigureRoyaltyRelease.s.sol` implements and tests the exact
two-phase ceremony: phase 1 proposes the distinct settlement/QVL/anchor tuple;
phase 2 may activate only after the two-day timelock and then unpause, including
recovery when activation mined but unpause did not.

`scripts/configure-royalty-release.sh` is the only production entry point for
that Forge script. It first reconstructs the fresh-deployment and current
reviewer context, verifies the exact two-reviewer phase plan, and derives every
Solidity environment input and intended transaction from the verification
receipt. Only then may it replay the external ceremony ledger, compare the two
Base Sepolia RPC authorities at one common finalized block, and run the Forge
tests and simulation. `BROADCAST` defaults to `false`; the simulation does not
inspect or unlock a keystore. Phase 2 additionally recomputes the SHA-256 of
the canonical deep-key-sorted phase-1 history record and its embedded finalized
authority receipt, then derives `phase_one_finalized_at` from that receipt's
common-finalized block timestamp. All three values must equal the signed plan;
opaque or stale predecessor digests cannot authorize RPC or Forge access.
The same simulation emits one machine-readable Base Sepolia gas projection for
the exact classified one- or two-transaction slice. The wrapper uses a
code-owned 130% gas-unit multiplier, requires twice the projected wei cost
immediately before signer access and again before broadcast, and pins broadcast
to the simulated gas price. A merely nonzero operator balance is not release
readiness.

For an explicitly approved broadcast, the wrapper accepts only the encrypted
Foundry account literally named `dev`, rejects every supported raw-key
environment spelling, writes a private pre-broadcast recovery
capsule, sends the exact phase with `--slow`, and refuses to update the ledger
until two distinct HTTPS providers reproduce the reviewed transactions and
exact post-state at one finalized checkpoint. Phase-plan replay, skipped phase
1, an unelapsed timelock, a stale nonce, implicit Forge resume, and every
contract/runtime/role drift fail closed. `reconcile` can attach finalized
evidence after an interrupted execution without sending another transaction;
it cannot authorize an expired plan or invent missing transaction evidence.

This is ceremony machinery, not evidence that the ceremony happened. No
Royalty phase has been broadcast from this working tree, and the current suite
must remain described as paused until the external reviewer, wallet-custody,
Base Sepolia finality, and post-activation history artifacts all exist.

The vault has adversarial unit, fuzz, and invariant coverage but has not received
a third-party formal audit. Do not describe that coverage as an audit, and do
not add a challenge bond or prize-custody contract to this release.
The v1 product decision is exact-asset, non-transferable compute capacity only.
Minted/transferable compute tokens, ETH challenge bonds, automated prizes, and
token/fiat conversion remain roadmap work that requires a separately reviewed
contract release.

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

For a fresh-suite broadcast, nonzero operator balance is not treated as gas
sufficiency. The helper parses one machine-readable Forge simulation for the
exact ordered 13-transaction plan, uses the pinned 130% gas estimate, requires
the live balance to cover a further code-owned 2x margin, pins the simulated
gas price, and rechecks balance and nonce immediately before keystore unlock.
Malformed or missing projection evidence blocks before any transaction.

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

The deployment output and post-authority working ledger are deliberately two
different files. `DEPLOYMENT_MANIFEST_PATH` names the exact fresh-suite receipt
created once at mode `0444`. Before any configuration phase, create separate
canonical operator-owned mode-`0700` parent/evidence/lock directories outside
the checkout, set `RELEASE_CEREMONY_LEDGER_PATH`,
`RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT`, and
`RELEASE_CEREMONY_LOCK_ROOT`, then initialize once:

```bash
./scripts/initialize-release-ceremony-ledger.sh
```

Initialization takes the same release-wide lock used by every configuration
writer, copies the immutable receipt byte-for-byte to the distinct mode-`0600`
working ledger, and publishes an immutable initialization receipt. It uses
create-only publication: running it again fails instead of resetting ceremony
history. The seven configuration helpers read and validate
`DEPLOYMENT_MANIFEST_PATH`, but apply every JSON mutation only to the single
`RELEASE_CEREMONY_LEDGER_PATH` through CAS revision receipts while holding the
shared release-SHA lock. They never chmod, normalize, or replace the immutable
fresh receipt. Missing paths are hard errors; `deployments/base-sepolia.json`
is historical evidence and is not a fallback.

After the final CVM identity is independently reviewed, configure DiligenceRoom
with `scripts/configure-diligence-release.sh`. Its first three broadcast phases
propose the compose hash, activate it and propose the TEE binding after two days,
then activate the TEE, permanently close both addition paths, and propose the
exact deployment-intent and final-authority-reviewed governance controller after
another two days. The room constructor immutably binds that controller as the
production fee recipient. Once phase 4 accepts the controller, production
governance is final: `proposeDeveloper` rejects every later transfer. Emergency
shutdown remains available through frozen-set revocation, so rotating away from
the reviewed controller is neither necessary nor permitted. Phase 4
is executed only by that controller through its reviewed EOA or contract-wallet
ceremony after a final two-day delay. The production helper never tries to make
the distinct controller share or replace the operator's encrypted `dev`
keystore: phase 4 is a finalized-receipt and live-state verifier, with an exact
outer-call proof for an EOA or an explicitly bounded event+state, no-trace claim
for a Safe/contract controller. Browser writes remain disabled until the exact
final cardinalities, binding, completed governance handoff, and zero pending
developer state pass the release gate and the acceptance evidence is appended.
Each `diligenceReleaseHistory` entry retains the immutable deployment-intent,
Diligence deployment-transaction, runtime, source, and final-authority lineage,
but records the independently renewable review envelope used for that phase.
Phases 1-3 also record every ordered operator transaction—respectively 3, 6,
and 4 calls—with sender, target, function, calldata SHA-256, receipt status,
block number, and block hash, plus the SHA-256 of the canonical transaction
array. Phase 4 records an empty operator array and the separately finalized
controller-acceptance evidence; it never disguises that external wallet action
as an operator Forge broadcast.

The six non-Royalty production configuration helpers (ChallengeRegistry,
Diligence, Compute, Email, execution-policy anchor, and Tinker) require the same
absolute deployment-intent core, current final-release-authority core, and
renewable authority-review envelope, together with each artifact's exact
canonical SHA-256 digest. Before any chain read, keystore access, Forge
simulation, or broadcast, the shared guard validates the immutable deployment
intent, semantically validates and domain-hashes the final authority, verifies
the review envelope's exact subject binding, and checks the one-way
final-authority-to-intent and release-SHA bindings. Legacy
`OPERATOR_POLICY_PACKET_*` inputs and arbitrary projection JSON are rejected.
`scripts/ceremony-authority-projector.mjs` now derives exactly 36 named public
configuration assertions from the validated authority artifacts; any missing,
extra, or mismatched assertion fails closed before chain reads or keystore
access. The helpers do not trust operator-supplied JSON as authority.

Royalty is the deliberate non-circular exception. Before its ceremony, its
authority is the immutable fresh receipt, prescriptive Royalty binding, current
reviewer lineage, replay-bound working ledger, and one exact short-lived phase
plan signed by two current reviewers. Final-authority v4 and the canonical
Royalty history receipt H are post-ceremony facts: they are materialized and
reconciled only after the finalized Royalty history exists and must never
authorize the transactions that create that history.

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
recheck to `challengeRegistryReleaseHistory`. For `BROADCAST=true`, the
immutable `DEPLOYMENT_MANIFEST_PATH`, mutable
`RELEASE_CEREMONY_LEDGER_PATH`, ceremony evidence root, and
`FOUNDRY_BROADCAST` must be canonical explicit paths; every mutable ceremony
path remains outside the checkout. This preserves the identical clean reviewed
commit across the two-day wait. `RELEASE_CEREMONY_LOCK_ROOT` must also name a
canonical external mode-0700 directory. Every release writer shares the
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
source-verification submission cannot be bypassed. A successful submission
receipt is `submitted_not_confirmed`; source publication on all seven BaseScan
pages remains a separate production-routing gate.
