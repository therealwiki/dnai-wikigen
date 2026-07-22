# Exact-asset Compute runtime

This document defines the production boundary between the SolidJS Compute
Console, `ComputeCreditVault`, the execution CVM, the independent metering CVM,
and Thinking Machines Tinker. It is a release contract, not evidence that the
runtime is already deployed.

## Product model

Users do not receive a transferable token and the system does not promise a
fiat or ETH exchange rate. A deposit creates a non-transferable claim for the
same asset inside `ComputeCreditVault`:

- ETH in becomes ETH-denominated available capacity.
- An allowlisted exact-transfer ERC20 in becomes capacity in that same ERC20.
- Capacity is scoped by `projectId`, user, and asset. It cannot be transferred.
- An unused available balance can always be pulled back by its owning wallet,
  including while the vault is paused.
- A job authorization reserves a maximum exact-asset debit. Only actual usage
  can settle; the unused reservation returns to available capacity.

The browser must call this **exact-asset capacity**, not a minted coin, stable
value, provider balance, or provider invoice. Card funding is a separate
roadmap adapter and must use hosted checkout; card data never enters the app or
CVM.

## Trust separation

```text
wallet / scoped device
        |
        | bounded public recipe metadata
        v
execution CVM (Tinker key + private workload custody)
        |                          |
        | startJob / settle tx     +--> Tinker provider
        |
        | signed bounded usage envelope
        v
independent metering CVM
        |  checked debit + raw ComputeMeteringReceipt signature
        +---- fresh quote + exact receipt fields ---->
        |              independent compute-metering QVL
        |              fresh DCAP verdict + raw ComputeMeteringQvlReceipt signature
        |<------------------------------------------------
        |
        | both distinct raw EIP-712 signatures
        v
ComputeCreditVault on Base Sepolia
```

The execution identity, metering signer, and metering-QVL signer must be three
different dstack-derived Ethereum addresses in different CVMs. None may be the
vault owner, developer recipient, or rate-policy provider recipient. The owner
controls timelocked admission and emergency revocation, but cannot forge a user
authorization or either metering signature. The two receipt signatures use
distinct EIP-712 typehashes, so one signer cannot replay its signature in the
other authorization domain.

## Canonical identifiers

Human-readable console identifiers are not placed on chain directly.

```text
projectId = keccak256(utf8("dnai.wikigen.compute.project.v1:" + projectReference))
jobId     = keccak256(utf8("dnai.wikigen.compute.job.v1:" + jobReference))
```

A reference is either an existing non-zero `bytes32` or an ASCII identifier
matching `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`. The web, API, worker, metering
service, and tests must use byte-for-byte identical rules.

## Production job flow

1. The authenticated browser seals a private workload through the bounded
   workload-ingress surface. Only its non-zero workload and manifest
   commitments, schema, allowlisted operation/model/recipe/result policy, and
   bounded resource limits become authorization metadata. Raw prompts,
   examples, datasets, payment data, upstream credentials, and arbitrary
   executable programs never enter the dispatch metadata API or chain.
2. The browser verifies the vault runtime hash and all release roots from one
   pinned Base Sepolia block, derives the canonical dispatch-intent commitment
   from the exact workload metadata plus the proposed asset/nonce/cap/expiry,
   and asks the user to sign EIP-712 v2 `ComputeJobAuthorization`. The signed
   authorization includes the non-zero workload, manifest, and dispatch-intent
   commitments. `authorizeJob` moves the maximum debit from available to
   reserved.
3. After confirming the job's complete 21-field `Authorized` tuple at one new
   pinned block, the browser passes a commitment-protected in-memory handoff to
   the dispatch panel. The authenticated Compute API creates the metadata-only
   dispatch intent and independently derives its workload, manifest, and intent
   commitments from the sealed workload record. Any difference from the
   on-chain authorization fails closed.
4. Before every actionable worker cycle, the execution CVM refreshes the shared
   HMAC policy journal, verifies it against the release-pinned read-only
   `ExecutionPolicyAnchor`, and requires a current `compute_dispatch` PASS for
   the intent's exact canonical `bytes32` job ID **and** the server-derived
   execution-context hash. That context commits the authenticated journal's
   exact intent commitment and the release-pinned compiled-recipe commitment;
   a client cannot supply or override it. The approval domain, canonical
   approver root/set, anchor runtime, active frozen writer, writer release,
   compose hash, and dstack app ID must all belong to the same release.
5. The execution worker re-reads one pinned chain snapshot and requires the
   exact intent identifiers, wallet, asset, nonce, cap, rate policy, expiry,
   workload/manifest/dispatch commitments, approved compose hash, and
   dstack-derived TEE identity.
6. Before any provider dispatch, the execution CVM submits
   `startJob(jobId, composeHash)`. The vault derives the non-zero start
   commitment itself from the complete authorized job, chain/vault domain,
   admitted TEE, frozen metering-policy hash, and on-chain `startedAt`; the TEE
   cannot supply an opaque start value. Once started, the user cannot cancel
   work, but anyone can release the full reservation after authorization
   expiry.
7. The worker executes only a compiled allowlisted recipe. Private examples or
   datasets arrive through the separately authenticated sealed-workload ingress
   and remain inside the execution CVM. They are never accepted by the metadata
   API or metering service.
8. The worker creates a bounded v2 usage envelope containing counters,
   timestamps, and commitments only. It signs the envelope with the same
   dstack-derived TEE identity that called `startJob`.
9. The independent metering CVM authenticates that signature, reads the vault
   and job at one explicit Base Sepolia block, verifies the exact runtime hash
   and release policy, and recomputes the debit using integer arithmetic from a
   canonical rate-policy file. It never trusts a caller-supplied debit.
10. The metering CVM derives the on-chain usage commitment from the complete
   job, debit, billable units, exact on-chain start/end times, and fresh
   quote-evidence hash. It independently computes the complete
   `ComputeMeteringReceipt` and `ComputeMeteringQvlReceipt` EIP-712 v2 digests,
   calls all three vault derivation helpers at the same pinned block, and
   requires exact equality. It raw-signs the meter digest with its dstack key.
11. For the same decision, the meter obtains a fresh challenge-bound TDX quote.
   The independent compute-metering QVL verifies the quote/evidence, enforces
   the bounded receipt expiry, and raw-signs the distinct QVL digest over the
   same exact fields. Prefixed, high-s, stale, cross-contract, cross-chain, or
   cross-workload signatures fail closed.
12. The execution identity submits `submitMeteringReceipt` with both signatures.
   The vault re-derives the usage commitment, verifies both signer domains, accrues
   the exact asset to the provider/developer recipients and releases unused
   capacity. A bounded receipt may leave the CVM; provider IDs, prompts,
   examples, outputs, credentials, and raw SDK traces may not.

## Deterministic metering policy

The metering policy set uses exact integers. It cannot fetch a price oracle or
convert between assets. The canonical set pins:

- chain ID, vault address, and vault runtime code hash;
- both exact release assets and, for each, one provider recipient and one
  on-chain `ratePolicyCommitment`;
- one execution TEE identity and compose hash;
- an allowlisted model/recipe matrix;
- exact asset units per one million prefill, sample, and training tokens;
- maximum counters and maximum total debit;
- issuance lifetime and confirmations/finality policy;
- policy schema/version and canonical policy hash.

The debit is:

```text
numerator = prefillTokens * prefillUnitsPerMillion
          + sampleTokens  * sampleUnitsPerMillion
          + trainingTokens * trainingUnitsPerMillion
debit     = ceil(numerator / 1_000_000)
```

All multiplication and addition must be checked against explicit bounds before
signing. A zero-token failure receipt may settle zero; it still has a non-zero
usage commitment and is replay protected. Provider pricing is governance input
to a future rate policy, not dynamically scraped at settlement time.

The resulting claim is **attested deterministic metering**. It is not a
provider-authoritative invoice unless a future provider API supplies a signed
usage record and the release policy explicitly validates it.

## Failure and replay behavior

- No provider dispatch is allowed before the `JobStarted` transaction reaches
  the configured confirmation depth.
- One cross-process execution-cycle lease serializes selection and all stage
  transitions for a worker process set. Inside it, the read-only policy
  coordinator holds the shared policy lease from fresh journal/chain
  verification through the complete `run_once` boundary.
- A HOLD/DENY racing an already-authorized cycle waits for that leased cycle to
  reach its durable boundary, then blocks the next cycle. If revocation lands
  after `startJob` broadcast but before a dispatch ID, provider work never
  starts. If usage was already durably finalized, recovery preserves that usage
  and requires a fresh PASS before metering or settlement resumes; it never
  reruns the provider.
- A durable record is written before each irreversible boundary: chain start,
  provider dispatch, usage finalization, metering decision, and settlement.
- A worker recovery must resume the next boundary; it must never dispatch the
  same job twice.
- The metering service returns the exact prior decision for an identical replay
  and rejects the same job/usage commitment with different counters or context.
- If metering or settlement is unavailable after provider work, the worker
  retries the stored bounded envelope and does not rerun the provider job.
- If no valid receipt is submitted before authorization expiry, the
  permissionless `expireJob` path returns the complete reservation to the user.
- Pausing the vault blocks funding, authorization, start, and settlement, but
  does not block unused-balance withdrawal or permissionless expiry.

## Public capability gates

`VITE_ENABLE_COMPUTE_VAULT_FUNDING=true` requires a generated release
environment that independently checks the vault bytecode, unpaused state, and
exact allowlisted assets. It does not imply provider dispatch.

`VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION=true` additionally requires the
execution CVM, independent metering CVM, compose and TEE admission, frozen
developer fee and compose requirement, active exact rate policies, the distinct
frozen metering-signer and metering-QVL-signer tuple, and an exact
one-TEE/one-compose release set with zero pending admissions, plus an end-to-end
synthetic dual-signature job proof. If any root is absent or mismatched, job
authorization stays disabled while safety withdrawal remains available.

The frontend must always distinguish:

- **Live**: runtime evidence was release-generated and rechecked on chain.
- **Modeled**: deterministic browser/API behavior without a deployed mutation
  path.
- **Roadmap**: design intent with no backing implementation or deployment.

## Implemented execution-CVM boundary

The `tinker-delegate` service now contains the production-shaped exact-asset
half of this protocol:

- `POST /compute/projects/{projectReference}/dispatch-intents` accepts only
  chain authorization metadata and compiled public-recipe limits. `prompt`,
  `examples`, arbitrary programs, payment material, and provider credentials
  are rejected as extra fields. Project membership is checked in the console
  directory, but the route never invokes its legacy service-credit job or
  ledger mutation methods.
- Project and job references use the canonical identifier rules in this
  document. The response returns both references and derived `bytes32` IDs.
- The separate HMAC-authenticated `ComputeExecutionJournal` is mode `0600`,
  atomically replaced, fsynced, and checkpointed before signed transaction
  broadcast, provider dispatch, metering handoff, and settlement broadcast.
- The Base Sepolia adapter checks chain ID and runtime bytecode, then reads
  bytecode, compose admission, TEE admission, rate policy, verifier, and the
  complete job using one EIP-1898 canonical block-hash pin. A transaction is
  considered confirmed only after receipt status, canonical block hash, and
  confirmation depth all match.
- Start and settlement transactions are signed by the same purpose-separated
  dstack-derived Ethereum identity. The exact raw transaction is persisted
  before broadcast and identical bytes are reused after an ambiguous response.
- Provider work cannot begin until `startJob` is confirmed. The compiled
  provider adapter must guarantee idempotent replay of the stable `dispatchId`;
  an adapter without that property is rejected before `startJob`.
- After provider work, the worker pins a fresh started-job block and persists
  the exact independent-metering request before egress. Retries reuse that
  byte-for-byte semantic envelope and never rerun provider work.
- Worker construction now requires an `AnchoredComputeExecutionAuthorizer`;
  there is no unguarded production mode. The authorizer uses a read-only anchor
  gateway, exact `surface=compute_dispatch`, the canonical on-chain job ID as
  the policy resource ID, the current release's domain/signer roots, and the
  exact server-derived execution-context hash. For exact-asset work that hash is
  `sha256("dnai-wikigen/compute-execution-policy-context/v1\0" || canonical_json({schema, job_id, intent_commitment, recipe_policy_commitment}))`,
  where both inner commitments are recomputed from the authenticated journal
  and compiled allowlist. A PASS with the right job ID but a different intent or
  recipe commitment therefore fails closed before any chain/provider mutation.
  The legacy modeled service-credit start path applies the same rule to an
  immutable projection of its authoritative job plus reservation record. A
  missing, stale, drifted, context-mismatched, HOLD, or DENY decision produces a
  bounded non-mutating result.
- Public cycle status separates definitive `provider_dispatched` (durable usage
  exists) from `provider_dispatch_may_have_occurred` (the stable dispatch ID was
  checkpointed but a crash may have preceded usage persistence).

The independent metering wire contract is exactly:

```text
POST /meter
schema: dnai.compute-metering-request.v2
usage schema: dnai.compute-usage-envelope.v2
usage commitment: sha256("dnai-wikigen/compute-usage/v1\0" || canonical usage claims)
signature: EIP-191 personal-sign of the 32-byte usage commitment
on-chain usage commitment: vault-derived from the full job, debit, units, times, policy, and evidence
decision schema: dnai.compute-metering-decision.v2
classification: attested_dual_verified_metering
receipt signatures: distinct raw low-s EIP-712 v2 meter + QVL signatures
provider_authoritative_invoice: false
```

Counters and other `uint256` values on that boundary are canonical decimal
strings; the token field is `training_tokens`. The outer request contains the
exact pinned block number and hash. The worker requires the returned policy-set
hash, rate-policy commitment, asset, job, usage commitment, execution identity,
compose hash, pinned block, metering verifier, and on-chain receipt digest
attestation-evidence hash, bounded receipt expiry, both distinct signer
addresses, both receipt digests, and both raw signatures before it signs a
settlement transaction.

The installed command supports one-shot verification with
`tinker-compute-runtime --once` and the serialized service loop with
`tinker-compute-runtime --poll`. Its only production construction path rejects
the dstack simulator, derives both journal and chain identity keys inside
dstack, compares fresh quote report data and compose/app identity to the same
release that pins the policy anchor, requires authenticated HTTPS RPC/metering,
and never accepts a raw key or provider module from command-line arguments. The
source-build dstack compose overlays expose this loop through the explicit
`compute-execution` profile and mount the same `delegate-data` volume as the
API, so the policy journal and adjacent inode lease are actually shared.

## Ordered main-runtime activation

`compute-execution` is not an independently mutable production toggle. The
reviewed final main-runtime environment uses the exact replacement value
`COMPOSE_PROFILES=arena-runtime,compute-execution`, binding both Arena and
Compute to one post-measurement activation plan and signed Stage B.

The source-built production activation coordinator keeps the completed
seven-CVM evidence, reviewed final authority, deferred environment authority,
plan, and signer exchange in one process; public JSON receipts cannot be loaded
elsewhere as mutation authority. It patches the encrypted environment, restarts
the exact main CVM, records an authenticated Phala attestation observation,
and verifies the release-bound Arena worker-capability v2 presence proof. Only
then can it consume the lease-valid, appraisal-bound Compute-workload recipient
activation. The underlying independent QVL verdict uses the active v4 schema
and signing domain: DCAP appraisal completed strictly before the single-use
challenge-v2 expired (challenge lifetime at most 120 seconds), then began the
separately reviewed exact 900-second activation-evidence lease. That lease may
outlive the consumed challenge and never renews challenge freshness. The
post-restart outer activation is schema
`dnai.compute.workload-recipient-activation.v3`, carries an explicit recipient
evidence lease of at most 300 seconds, and preserves the stable
`dnai.compute.workload-recipient-release.v2` commitment. Its authenticated and
verified times must not predate the Arena proof. The Phala observation and
Arena heartbeat are not independent Intel TDX/DCAP verification. The durable
completion artifacts explicitly authorize no live traffic, and no fresh
project-owned production run has completed.

The locally tested resident driver keeps this entire authority chain in one
process from one exact owned canonical mode-`0600` request through non-live
launch, the external evidence and Stage-B waits, restart, recipient activation,
and bounded-output publication. It accepts no serialized authority or signer
key, authorizes neither automatic retry nor live traffic, and has not run
against a fresh project-owned production topology.

Its bounded activation observation `O` deterministically projects exactly 20
public browser variables. The seven ceremony-lineage additions are
`VITE_COMPUTE_WORKLOAD_CVM_ID`,
`VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256`,
`VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256`,
`VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE`,
`VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256`,
`VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256`, and
`VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256`. All 20 values must derive
from the same branded observation; missing, extra, or drifted lineage keeps
browser upload fail-closed. These are bounded public release pins, never a
serialized capability or deployment claim.

## Explicit release blocker

The rollback-resistant execution-policy gate is implemented and tested,
including release/root drift and adversarial revocation races. There is still
not yet a proven Thinking Machines/Tinker provider idempotency contract for
replaying the same external dispatch identifier after a process crash. The
locked Tinker 0.22.7 SDK does contain a low-level `X-Idempotency-Key` transport
hook, but its supported public model/training workflow does not accept the
worker's durable dispatch ID at each paid step. Official documentation also
does not state the key retention, scope, payload-conflict, concurrent-replay,
or post-restart result-recovery guarantees required to safely build on the
private transport surface. The exact audit and required fault-injection proof
are recorded in
[`TINKER-PROVIDER-IDEMPOTENCY.md`](../⚙️/tinker-delegate/docs/TINKER-PROVIDER-IDEMPOTENCY.md).

Consequently the installed CLI currently reports
`idempotent_tinker_provider_adapter_unavailable` and performs no chain or
provider mutation. Test fakes are explicitly test-only. This is deliberate:
marking a provider checkpoint without upstream replay semantics could either
double-dispatch paid work or lose a completed usage receipt after a crash.

Do not enable the `compute-execution` compose profile or browser job
authorization until the compiled adapter exists and a fresh reproducible
execution image, compose hash,
runtime code hash, metering policy-set hash, dstack identity admission, and
end-to-end synthetic proof have all been generated and frozen. The vault is
reviewed and extensively tested but is not represented as formally audited.
