# Execution-policy authorization

Status: **implemented and locally verified; production activation pending**.

This layer turns the deterministic policy kernel into an execution control. A
kernel result is not merely advisory: a fresh, integrity-checked decision must
be bound to the exact deal, Arena submission, or Compute job before protected
work can begin.

It does **not** make local or simulator evidence Intel TDX evidence. A release
still needs a freshly deployed contract suite, real Phala/dstack custody,
independent Intel TDX QVL evidence, and the release-specific trust roots below.

## Authorization model

The three execution surfaces are:

| Surface | Resource | Enforcement point |
| --- | --- | --- |
| `deal_evaluation` | DiligenceRoom deal ID | Lease spans the complete awaited `ControlPlane.evaluate`, including artifact-state reads and evaluation side effects |
| `arena_execution` | Arena submission ID | In the separate worker, after live dstack/QVL revalidation and before the first queue mutation |
| `compute_dispatch` | Legacy job ID or exact canonical `bytes32` job ID plus its server-derived immutable execution context | Lease spans the legacy internal start mutation; the exact-asset worker re-verifies and leases every serialized chain/provider/metering cycle |

The runtime bearer authenticates an internal caller, but it is deliberately
insufficient to create a `pass` decision. A pass requires an Ethereum
`personal_sign` signature from an address listed in
`TINKER_EXECUTION_POLICY_APPROVED_SIGNERS`. This release-authority role is
explicitly **EOA-only** today: 65-byte ECDSA recovery is enforced, so ERC-1271
contract-wallet signatures are not presented as supported for policy approval.
Other application wallet flows can still use any connector that exposes the
required EIP-1193 account methods.

The exact signed message is canonical and hash-only. It binds:

- the v3 approval schema, execution surface, and
  `policy-kernel-canonicalization/v2` byte-level hashing contract;
- a domain-separated hash of the resource ID;
- the kernel decision, request hash, policy hash, and explicit execution-context
  hash;
- an expiry;
- the previous decision hash for compare-and-append replay protection;
- the canonical sorted approver-set root; and
- a domain-separated hash of `TINKER_EXECUTION_POLICY_APPROVAL_DOMAIN`.

The approval domain is not free-form. It must use this exact release-derived
Base Sepolia shape:

```text
base-sepolia:84532:<release-manifest-commitment-64>:<compose-hash-0x64>:<sha256-phala-app-id-64>:<approver-root-64>
```

Only the domain hash leaves the protected runtime or enters the decision store.
Changing this domain invalidates signatures from a different local, staging, or
production deployment and prevents cross-deployment replay. Enforcement points
also compare every unexpired stored pass with the **current** approval-domain
hash, canonical signer set, and signer-root commitment. The runtime refuses to
issue approvals or execute when the environment set, configured root, and
domain-embedded root disagree. Any signer change therefore requires an
explicit release/domain rotation and revokes older passes; expiry is not the
only revocation mechanism.

The execution-context hash is not caller authority. For exact-asset Compute the
API and worker independently derive it from the HMAC-authenticated dispatch
journal's canonical intent commitment plus the release-pinned compiled-recipe
commitment. For the modeled service-credit lane they derive it from an
immutable projection of the authoritative job and its one reservation ledger
record. A PASS for the same public job ID but different intent, recipe, actor,
cap, environment, or reservation therefore fails closed. Deal and Arena carry
the explicit all-zero context sentinel because their release-scoped resource ID
is their complete execution binding in this release.

`hold` and `deny` records do not accept approval evidence. An authenticated
runtime may move work to a safer state without an owner signature, while it
cannot move work into execution. The newest record always supersedes older
records, so a later hold/deny immediately revokes an earlier pass. Approval
preview returns the current per-resource decision head and evaluation must
submit that exact head. The store compares it while holding the append lock, so
stale PASS, HOLD, and DENY previews cannot silently supersede a newer decision
and only one concurrent writer can win.

## Operator flow

1. Send the strict request/policy bundle to `POST /policy/approval-message`
   over the authenticated operator channel.
2. Before any signature prompt, the browser independently evaluates the same
   deterministic gate and recomputes the request, policy, resource, purpose,
   pipeline, output-schema, and corpus-reference hashes using the release-pinned
   canonicalization version. It also requires the returned approval-domain hash
   to equal `VITE_EXECUTION_POLICY_APPROVAL_DOMAIN_HASH` from the normalized
   release descriptor, recomputes
   `VITE_EXECUTION_POLICY_APPROVER_ROOT_HASH` from the canonical public
   `VITE_EXECUTION_POLICY_APPROVER_HASHES_JSON` set, and proves the connected
   approver belongs to that set before opening a wallet prompt. For exact-asset
   Compute it additionally uses a short-lived wallet-authenticated Console
   session to fetch the strict public dispatch status, recomputes the intent and
   compiled-recipe context locally, and requires the intent user to equal the
   connected Base Sepolia wallet. The browser never accepts a typed context
   hash, and the public browser workflow does not claim legacy service-credit
   approval support.
3. If any decision, outcome, hash, schema version, or release domain differs,
   stop before `personal_sign`. If they all match and the decision is `pass`,
   reconstruct the exact v3 canonical hash-only message locally, require a byte
   match with the delegate response, and sign it with a configured independent
   wallet.
4. Send the same request/policy/expiry plus `approver_address` and
   `approval_signature` to `POST /policy/evaluate`.
5. The CVM independently recomputes the kernel result, recovers the signer,
   checks the immutable allowlist/root and exact deployment domain, compares
   the previewed resource head, then durably appends the bounded record. Before
   returning success it compare-and-sets that exact decision into the
   release-pinned Base Sepolia monotonic anchor and verifies the
   global/resource/decision heads at the older of one RPC's reported
   `finalized` tag and the configured confirmation-depth boundary.
6. Read `POST /policy/status` for a bounded current-state projection. Workers
   consume status or freshly open the same integrity-protected store and verify
   it against a fresh same-RPC reported-finalized plus confirmation-depth
   anchor snapshot; they do not call the approval
   endpoints, hold a chain writer, or auto-approve themselves.

The operator UI may keep an explicitly entered runtime bearer in memory for a
single administrative session, but it must never persist, log, embed, or ship
that bearer in the public frontend bundle. A production browser workflow should
place the runtime bearer behind an authenticated server-side operator gateway;
the static Cloudflare site alone is not a secret store.

## Protected execution lease boundaries

The API uses one fail-closed `_authorized_execution_policy_lease` helper rather
than separating a PASS check from its mutation. The Compute internal start
route holds the lease across `ComputeStore.start_job`. The deal route resolves
its configured evaluator first, then holds the lease across the full awaited
`ControlPlane.evaluate` call. A concurrent policy writer cannot persist a newer
HOLD/DENY in the gap because there is no longer a check/use gap.

The exact-asset Compute runtime has a second, read-only enforcement path. It
selects one canonical journal intent under a dedicated cross-process execution
cycle lock, then opens `authorized_execution_lease` with:

- `surface=compute_dispatch`;
- `resource_id=<intent.job_id>`, where `intent.job_id` is the exact canonical
  non-zero `bytes32` identifier used by `ComputeCreditVault`;
- `expected_execution_context_hash=sha256("dnai-wikigen/compute-execution-policy-context/v1\\0" || canonical_json({schema, job_id, intent_commitment, recipe_policy_commitment}))`,
  with both inner commitments recomputed from the authenticated journal and
  release-pinned compiled recipe before every leased cycle;
- the release-derived approval-domain hash, canonical approver-root hash, and
  exact approved approver-hash set; and
- a read-only gateway pinned to the anchor address/runtime, active frozen
  writer, writer release, Base Sepolia finality/depth policy, live compose hash,
  and dstack app ID from that same approval domain.

That shared policy lease remains held through the complete worker cycle:
on-chain start preparation/broadcast, a later start confirmation, the durable
provider-dispatch checkpoint, provider execution, bounded usage persistence,
metering handoff, or settlement boundary reached by that invocation. A
HOLD/DENY racing a cycle waits; it becomes authoritative before the next cycle.
This gives explicit recovery semantics:

- Revocation after `startJob` broadcast but before the dispatch-ID checkpoint
  prevents provider execution on the next cycle.
- Revocation after a dispatch ID but before durable usage is treated as
  ambiguous: status says only `provider_dispatch_may_have_occurred`.
- Revocation after durable usage blocks later metering/settlement until a fresh
  PASS, while the saved usage is reused and provider work is never repeated.

The API, Arena worker, and exact-asset Compute worker must mount the same policy
journal and adjacent lock inode. The source-build dstack compose overlays do so
through `delegate-data`; independent-volume replicas are not a supported
release topology.

## Durable record boundary

`ExecutionPolicyStore` is an append-only, HMAC-SHA256-authenticated JSON store:

- mode `0600`;
- temporary-file write, file `fsync`, atomic `os.replace`, directory `fsync`;
- purpose-separated dstack key derivation in a real CVM;
- explicit local key only for development/tests;
- 20,000-record and 8 MiB caps;
- reserved record/byte capacity for later HOLD/DENY revocations, with global
  execution failure once the final revocation reserve is exhausted;
- maximum decision TTL of 30 days;
- strict schema, global sequence, per-resource previous-decision chain,
  decision-hash, future-time, and root-integrity validation.

Persisted/public records contain only:

- execution surface and resource hash;
- bounded decision and reason code;
- request, policy, approver, signature, approval-domain, canonical approver-root,
  execution-context, and decision hashes;
- the exact policy canonicalization version used to derive those hashes;
- recorded-at and expiry integers; and
- explicit `raw_policy_egress=false` and `raw_resource_id_egress=false` flags.

The store never persists a raw resource ID, wallet address, signature, policy,
request, corpus reference, purpose, category, pipeline, operation, or artifact.
Missing configuration, missing state, corruption, expiry, hold, or deny all fail
closed.

Store schema v5 places both `approver_root_hash` and
`execution_context_hash` inside the canonical decision core, so the signed
release authority root and immutable execution binding are transitively
committed by the on-chain `decisionHash`. The v3 approval message signs that
same context hash. PASS records require the exact current root and enforcement
points additionally require the record's context to match the current
authoritative Compute job. HOLD and DENY records require approval evidence to
be empty; their context is still explicit and bounded. Deal and Arena use the
all-zero sentinel. Compute revocations bind the current server-derived context
when the resource exists and may use the sentinel only to fail closed when an
unknown resource cannot be resolved.

The file HMAC and internal hash chains authenticate content but, by themselves,
do **not** prove freshness against restoration of an older HMAC-valid volume
snapshot. The runtime therefore requires the release-pinned Base Sepolia
`ExecutionPolicyAnchor` before approval preview, persistence success, status,
or execution. The local sequence maps one-to-one to the contract global
sequence. A chain sequence ahead of the local file proves rollback and fails
globally closed; a same-sequence head mismatch also fails closed. The only
recoverable intermediate state is one exact locally persisted final record
ahead of the selected RPC-observed chain boundary, which the writer reconciles idempotently before
any new append. Production activation remains disabled without an active,
frozen, unpaused writer release in the descriptor and on chain.

All stable policy/resource/category hashes are deterministic commitments. They
avoid raw-field egress but are not encryption: low-entropy identifiers and
small taxonomies can be dictionary-enumerated.

## Configuration

```text
TINKER_EXECUTION_POLICY_STORE_PATH=/data/execution_policy_state.json
TINKER_EXECUTION_POLICY_STORE_INTEGRITY_KEY=
TINKER_EXECUTION_POLICY_STORE_INTEGRITY_KEY_PATH=tinker/execution_policy_store_integrity
TINKER_EXECUTION_POLICY_APPROVED_SIGNERS=0x...
TINKER_EXECUTION_POLICY_APPROVER_ROOT_HASH=<64 lowercase SHA-256 hex>
TINKER_EXECUTION_POLICY_APPROVAL_DOMAIN=base-sepolia:84532:<release-64>:<compose-0x64>:<app-id-hash-64>:<approver-root-64>
VITE_EXECUTION_POLICY_APPROVAL_DOMAIN_HASH=<64 lowercase SHA-256 hex>
VITE_EXECUTION_POLICY_APPROVER_ROOT_HASH=<same approver root>
VITE_EXECUTION_POLICY_APPROVER_HASHES_JSON=["<sorted signer-address commitment>"]
```

The monotonic-witness settings are listed in
`docs/EXECUTION-POLICY-ANCHOR.md`. They pin the RPC, chain contract, runtime
bytecode, active writer, writer release, confirmation depth, freshness caps,
and distinct dstack writer key path. No raw-key setting exists.

In dstack/Phala, leave the explicit integrity key empty. The service derives a
purpose-separated key at the configured dstack path. The signer list and
approval domain are public release trust roots, not secrets, but both must be
reviewed and fixed for the deployment. The browser domain hash, approver root,
and exact sorted signer-hash set are generated from the same normalized release
descriptor; operators must not hand-copy values from an untrusted delegate
response.

## Failure behavior

- Missing/invalid runtime authentication: fixed `401`/`403` before evaluation.
- Missing signer roots or approval domain: bounded `503`.
- Missing, malformed, unapproved, mismatched, or cross-domain pass signature:
  bounded `400`; no record is written.
- Malformed kernel input: bounded deterministic `deny`; raw rejected material
  is not echoed.
- Missing/expired/non-pass record at an enforcement point: fixed `403` or a
  bounded worker `blocked` state; protected execution does not start.
- Stored pass created under a previous approval domain or by a signer removed
  from the current allowlist: fixed `403` or bounded worker `blocked` state,
  even when the record has not expired.
- Compute pass with a missing, caller-supplied, stale, or mismatched
  execution-context hash: fixed `400`/`403` or bounded worker `blocked` state;
  no chain, provider, metering, or service-credit mutation begins.
- Corrupt/unavailable store: bounded service/worker failure; no fallback to an
  in-memory allow.
- Missing, stale, future-dated, outside the selected RPC-reported finality and
  confirmation boundary, paused, unfrozen, wrong-code,
  wrong-writer, wrong-release, rolled-back, or head-mismatched anchor: bounded
  `503`/worker blocked failure; the writer never falls back and protected work
  does not start.

## Verification

The focused tests cover bearer-only pass attempts, missing trust roots,
unapproved and mismatched signers, cross-deployment replay, exact hash-only API
responses, newer holds superseding passes, expiry, tampering, local/dstack key
separation, deal evaluation, Compute dispatch, and the separate Arena worker
adapter. These are local/source-level proofs, not claims about a deployed CVM.
The anchor suite additionally covers canonical block-hash pinning, wrong
chain/code/release/writer/governance state, stale/future blocks, transaction
replay, crash-after-persist reconciliation, restored older HMAC snapshots,
global/resource head drift, and a read-only Arena worker.
They also cover concurrent coordinators, the cross-process authorization lease,
the older-of-finalized-tag-and-depth selection, and exact single-RPC/no-proof
status semantics.
The same checked-in pass, hold, deny, default-field, ordered-operation, Unicode,
and exact-asset Compute context vectors are executed by both Python and
TypeScript so a serializer, `0x` normalization, or hashing drift fails CI before
a release can ask a wallet to sign.
