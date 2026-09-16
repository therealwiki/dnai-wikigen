# Arena candidate runtime and worker boundary

Status: **internal worker service and source-built real-dstack overlays
implemented; registry-image Phala activation remains release-blocked**.

The Arena now has two explicitly different candidate paths:

| Challenge | Candidate contract | Current truth |
| --- | --- | --- |
| `synthetic-bio-assay-qc@1.0.0` | Python source defining `process` | Local AST/subprocess demo only. It is non-hardened and must never receive hostile public code. |
| `synthetic-bio-assay-qc-safe-ir@1.0.0` | Canonical `dnai.bio-assay-safe-ir.v1` JSON | Capability-free interpreter, per-job signed-QVL activation, durable claim/recovery, and an internal single-worker run loop are implemented and wired into the source-built real-dstack overlays. The primary digest-pinned Phala compose is not yet release-eligible. |

Both catalog entries remain `product_status=modeled`,
`execution_assurance=projection_only_no_hardened_executor`,
`hostile_code_ready=false`, `live_execution=false`, and
`worker_connected=false`. The production release manifest must continue to set
`hostile_candidate_execution_enabled=false`.

The modeled source catalog is intentionally not rewritten by process liveness.
The on-chain registry may also grow after launch. Neither surface is execution
authority: the reviewed release commits a separate finite, domain-separated
approved challenge-set digest over exact `id@version` bindings. New registry
entries remain public candidates only until a later reviewed release includes
them; the current worker and browser fail closed rather than discovering them.
A
separate operational endpoint,
`GET /arena/challenges/{id}/versions/{version}/worker-capability`, may project
the safe-IR worker as live only when the reviewed deployment enables the gate
and a fresh HMAC-authenticated heartbeat exactly matches the release SHA, image
digest, release-manifest digest, release-approved challenge-set digest and
selected key, release-policy commitment, catalog manifest,
runtime policy, compose hash, app ID, and OS image hash. Capability schema v2
publishes the complete release binding plus separate domain-separated
`release_binding_sha256` and `heartbeat_binding_sha256` commitments; schema v1
is rejected rather than upgraded or synthesized. The Python challenge always
remains modeled. The heartbeat is explicitly classified as
`authenticated_worker_presence_not_tdx_attestation`; it cannot assert TDX.
Every selected job still obtains its own quote and independently signed QVL
verdict before queue mutation.

## Authenticated owner projection

The Arena wallet challenge signs one exact two-scope session:
`challenge:submit` and `challenge:submissions:read`, bound to one immutable
challenge version. `GET .../submissions/mine` derives the owner solely from the
verified token subject. It has no wallet or project selector, returns at most
100 rows per page, and accepts only a cursor from the same authenticated page.
Owner rows omit the encrypted object reference, raw candidate, exact private
size, queue timestamps, exact score/reward, evaluator errors, and transition
history. The worker-only runtime projection remains separately authenticated.

The shared wallet verifier supports either local EOA recovery or EIP-1271 when
the operator configures a trusted HTTPS Base Sepolia RPC. No browser/API field
can select that endpoint. Contract detection, EIP-191 hashing, and the exact
`0x1626ba7e` `isValidSignature(bytes32,bytes)` result are required; chain/RPC
failures fail closed and a successful nonce is still consumed exactly once.

## Why safe IR instead of accepting Python

Filtering Python syntax does not remove the Python runtime's ambient authority.
The existing subprocess sandbox is useful for deterministic local demos, but it
is not an isolation boundary for adversarial code.

`dnai-safe-ir-v1` is deliberately not a general-purpose language. Candidate
bytes are data parsed into a small closed instruction set. The interpreter
contains no candidate-controlled import, name lookup, callback, dynamic
evaluation, module loading, syscall, or host function. Its module imports no
filesystem, network, environment, process, clock, or entropy API.

Supported instructions operate independently on the positive and negative
control lanes:

- `sort`
- `trim` with bounded integer `low` and `high`
- `mad_filter` with a bounded integer `threshold_milli`
- `head` and `tail` with a bounded integer `count`
- `stride` with bounded integer `step` and `offset`

Every output is a subset of the corresponding input multiset. A candidate
cannot fabricate a measurement, move a positive control into the negative
lane, return arbitrary bytes, print, or call a host API. The evaluator rejects
outputs with fewer than two controls per lane.

## Exact candidate representation

Candidates must be UTF-8 canonical JSON: ASCII escaping, lexicographically
sorted object keys, `,` and `:` separators with no whitespace, no duplicate
keys, and no trailing bytes. One semantic program therefore has one byte
representation and one SHA-256 commitment.

Example (shown across lines for documentation only; submit the canonical
one-line encoding):

```json
{
  "negative_pipeline": [{"op": "sort"}, {"high": 1, "low": 1, "op": "trim"}],
  "positive_pipeline": [{"op": "sort"}, {"high": 1, "low": 1, "op": "trim"}],
  "schema": "dnai.bio-assay-safe-ir.v1"
}
```

The fixed runtime policy is committed by
`SAFE_IR_POLICY_COMMITMENT` in
`⚙️/tinker-delegate/tinker_delegate/arena_safe_ir.py`. An opcode, operand rule,
or limit change requires a new schema/runtime version; it must not silently
change `v1`.

## Deterministic resource bounds

- Candidate bytes: at most 4,096.
- JSON structural depth: at most 8, checked before decoding.
- Instructions: at most 12 per lane.
- Sealed inputs: 2–512 finite numbers per lane.
- Output: at most 1,024 selected controls in total and at least 2 per lane.
- Fuel: at most 100,000 deterministic units. Sorting is charged by a fixed
  `n log n` upper bound; other operations are charged by bounded input length.
- Candidate-visible time, randomness, environment, filesystem, network,
  process, and stdout/stderr: none.

These are semantic and resource guarantees of the interpreter. They are not a
claim that the current website has a live attested execution service.

## Encrypted worker flow

`ArenaSafeIrWorker` and `run_arena_worker_process` are internal and have no HTTP
route or listening port. The service entrypoint is dependency-injected rather
than accepting a self-asserted activation environment variable. The
source-built `docker-compose.dstack.yaml` and
`docker-compose.all.dstack.yaml` overlays run exactly one `arena-worker`
container beside the authenticated delegate API. Both processes share only the
durable queue/ciphertext/policy `/data` volume and the required
purpose-separated dstack derivation paths. A second read-only `/sealed` volume
is mounted only into the worker. The
implemented path performs this sequence:

1. Select one queue item using a read-only store operation. An idle poll does
   not request or retain a quote.
2. Require real dstack key custody and reject local keys, raw private-key
   overrides, a configured simulator endpoint, and precomputed verdict files.
3. Collect exactly one live quote for the stable Arena X25519 ingress
   `report_data`, recompute the quote hash and byte count locally, and compare
   every stable expectation to the release-manifest pins.
4. POST that same raw quote and bounded expectation to the authenticated HTTPS
   independent QVL using signed challenge schema v2 and the active verdict
   schema/signing domain v4. The single-use DCAP challenge is valid for at most
   120 seconds, and appraisal must complete strictly before it expires.
   Authenticate the returned v4 verdict against the dynamic quote hash,
   recipient report data, compose/app/OS measurements, TEE signer, Base
   Sepolia chain, ChallengeRegistry, and externally configured QVL roots. The
   reviewed release requires the separate exact 900-second
   activation-evidence lease; it may outlive the consumed challenge, is not
   renewed challenge freshness, and any stricter worker age limit can only
   shorten its usable window. This completes before any queue mutation.
5. Require an exact persisted execution-policy pass through the bounded
   `ArenaExecutionPolicyGate` adapter; absence, denial, or adapter failure stops
   before the first queue mutation.
6. Enter `policy_screen`, load the server-generated `sealed://arena/...`
   reference, and re-verify the challenge, submission manifest, hashed identity,
   key ID, report data, AAD, ciphertext length, and plaintext SHA-256.
7. Decrypt only inside that gated worker process, parse canonical safe IR, run a
   fixed public conformance input, then run the sealed synthetic evaluator.
8. Atomically persist `queued -> provisioning` as the worker claim, then hand
   the exact internal score directly to the existing Ladder reducer.
9. Persist only the quantized Ladder release and queue transitions, zero the
   mutable plaintext buffer, and return a bounded internal receipt.

The worker resumes safely from `policy_screen`, `queued`, `provisioning`,
`public_tests`, or `sealed_eval`. A crash after the Ladder write does not score
again. Terminal retries are idempotent. The JSON store now uses a same-directory
cross-process `flock`, reloads before every operation, and makes the claim
transition atomic across API and worker processes. A separate kernel-released
lifetime lease permits exactly one evaluator process; a second worker refuses
to start, while a replacement can resume after a crash. This is intentionally a
single-worker design, not a claim of transactional multi-worker scheduling.

The service emits canonical, allowlisted status lines only when work completes,
fails, becomes blocked, stops, or first becomes idle. Status omits candidate
bytes, ciphertext, controls, exact scores, exact timing, and exception detail.

When public live projection is enabled, a separate status sink refreshes the
durable `0600` heartbeat on every idle poll as well as after work. The record is
atomically replaced, HMAC-SHA256 authenticated under the distinct
`tinker/arena_worker_heartbeat` dstack key path, and expires after a bounded
TTL. Missing, stale, future-dated, malformed, tampered, mismatched, or
unavailable state fails closed to the modeled projection. The public response
releases no heartbeat timestamp or internal failure detail.

`PersistedArenaExecutionPolicyGate` is the production adapter seam. It opens a
fresh integrity-checked `ExecutionPolicyStore` view for every decision and
requires the newest unexpired `arena_execution` pass for the exact submission
ID. A newer hold or deny therefore supersedes an older pass even when the API
and worker are separate long-running processes.

Candidate policy failures, AES-GCM failures, commitment mismatches, and runtime
failures all collapse to `execution_failed`; candidate text and exception detail
do not enter the receipt. Durable ciphertext corruption propagates as an
operator/storage fault and is never mislabeled as a candidate failure.

## Bounded public result

The only ranking result that may leave is the existing fixed-eta Ladder release:

- submission index;
- accepted/not accepted;
- integer leaderboard step over a public denominator;
- bounded improvement count.

The worker receipt explicitly marks raw candidate, selected controls, exact
score, ciphertext, timing, resource trace, and exception-detail egress as
false. Neither the raw source nor the decrypted safe-IR program is persisted in
Arena state.

The raw TDX quote is likewise ephemeral. Release schema
`dnai.arena.safe-worker-release.v3` contains stable measurements, the exact
release-approved challenge set, its digest, and trust roots
but no quote hash. The raw quote exists only in the in-memory packet and HTTPS
request for one selected job; it has no serializer, is excluded from safe
representations, is never written to `/data`, and transport/parser exceptions
are collapsed before supervisor output.

The public submission, queue, leaderboard, and authenticated owner-submission
projections use bounded schema version 2. They publish ordered state
transitions and per-row worker-reported provenance but omit exact creation,
transition, update, and Ladder-release timestamps. A row remains modeled until
that exact row has provenance; worker presence cannot promote historical or
unobserved rows. Exact times remain sealed in the durable state for recovery
and sorting, and every public queue/ranking response declares
`exact_timing_egress: false`.

## Combined post-measurement activation

The reviewed production shape activates the main runtime with the exact Compose
profile replacement `arena-runtime,compute-execution`. The source coordinator
keeps its release/evidence authority in one process through reviewed final
authority, signed Stage B, encrypted environment patch and restart. After the
restart it authenticates the Phala observation, verifies capability schema v2
and its two commitments against the reviewed activation plan, and only then
permits a fresh independent Compute-workload recipient activation to complete
the ordered release record. The Phala attestation response and Arena heartbeat
do not become an independent TDX verdict, and completion does not authorize
live traffic. This flow is implemented and tested in source; it has not been
run against a fresh project-owned Phala topology.

## CVM service topology and configuration

The source-built dstack overlays add these process boundaries:

```text
Phala encrypted env
        |
        v
arena-policy-init (one shot, network none)
        |
        +----> /sealed/arena/* (rw only during init, regular 0600)
                              |
                              | read only
                              v
browser -> delegate:8080 -> /data/arena_state.json
                           /data/arena_candidates/*
                           /data/execution_policy_state.json
                                  ^
                                  |
                     arena-worker (no ports)
                       |       |
                dstack.sock    +--> HTTPS Base Sepolia RPC
                       |
                       +----------> authenticated HTTPS independent QVL
```

The delegate remains the only externally published application service. Its
runtime-only HTTP routes continue to require runtime authentication. The
worker does not expose an HTTP server and currently consumes the same durable
queue/ciphertext/policy stores directly through the shared named volume, so the
runtime API bearer is not copied into the worker container. The sealed
evaluator volume and every `TINKER_ARENA_PROVISION_*` input are not mounted or
copied into the public delegate container. The worker receives the sealed
volume read-only, but it does not receive the provision authentication key,
tag, or base64 payload environment values.

The worker compose block hard-codes empty simulator, local-key, raw-key, and
verdict-file settings. A future production launch must provide the v3 release
payload SHA-256 at the reviewed compatibility mount path, an HTTPS Base
Sepolia RPC URL, QVL HTTPS URL, QVL bearer,
deployment-unique execution-policy domain, and approved policy signer
addresses. `phala deploy --env` is forbidden: the diagnostic CLI cannot supply
the reviewed fresh prepare/validate/commit boundary and must never be used as a
manual bypass. Secret delivery is future-only through a sealed, pinned SDK
adapter that independently authenticates each predicted app ID and KMS
environment public key before client-side X25519 encryption. That adapter is
not implemented or executable today, so this document does not authorize CVM
provisioning, secret upload, service start, or TDX claims.

The v3 release manifest retains `/sealed/arena/release-v2.json` as a
compatibility mount path for the reviewed Compose overlays; the sealed
evaluator defaults to `/sealed/arena/sealed-evaluator-v1.json`. The
`arena-policy-init` service now creates them before the worker can start. It is
a read-only, capability-dropped, one-shot container with `network_mode: none`;
its only explicit volume is the worker-only sealed volume mounted read-write.
The worker has two independent Compose gates: the delegate must be healthy and
the initializer must have completed successfully. The sealed volume is then
mounted read-only in the worker.

Provisioning accepts no payload-bearing CLI arguments. It consumes these six
environment values and removes them from its Python process environment before
validation:

- `TINKER_ARENA_PROVISION_RELEASE_B64`
- `TINKER_ARENA_PROVISION_EVALUATOR_B64`
- `TINKER_ARENA_PROVISION_RELEASE_SHA256` (wired to the worker's release pin)
- `TINKER_ARENA_PROVISION_EVALUATOR_SHA256`
- `TINKER_ARENA_PROVISION_AUTH_KEY_B64`
- `TINKER_ARENA_PROVISION_AUTH_TAG`

The payload encodings are canonical unpadded base64url. Decoded JSON is limited
to 65,536 bytes per file and must be ASCII repository-canonical JSON: sorted
keys, no insignificant whitespace, no duplicate object keys, and no NaN or
infinite values. Both exact-byte `sha256:` pins are checked before parsing. The
authentication key decodes to exactly 32 bytes. The tag is HMAC-SHA256 over the
domain-separated `dnai.arena.sealed-policy-provision.v1` envelope, which binds
both hashes, both byte lengths, both fixed output names, and the provision
schema. Deployment tooling can use
`tinker_delegate.arena_policy_provisioner.provision_auth_tag` to compute this
tag without placing the key on a command line.

The HMAC is a mix-and-match and corruption barrier within Phala's authenticated
encrypted-environment delivery; it is not represented as an independent
reviewer signature. The deployment operator and encrypted-env channel remain
the provisioning trust root.

Only after the envelope authenticates does the initializer stage `0600`
regular files inside a `0700` directory. It runs the worker's exact release and
evaluator loaders against those staged files, including the Base Sepolia,
schema, safe-IR, release-policy, evaluator-policy, and sealed-artifact
commitment checks. It rejects overlapping attempts with an exclusive `0600`
lock, publishes the evaluator and hash-pinned release using same-directory
atomic renames, syncs the directory, and emits only a bounded Boolean status. No
payload, secret, hash, commitment, or exception detail is logged. The worker
repeats the exact release SHA-256 and evaluator commitment checks at startup.

## Remaining production gates

Do not flip the execution capability or release-manifest flag until all of the
following are complete:

- a fresh project-owned linux/amd64 worker image is built from a clean release
  commit in reproducible CI, its provenance/SBOM are reviewed, and its literal
  registry digest replaces the current delegate digest in the primary Phala
  compose. The presently pinned digest was inspected and does not contain the
  Arena worker module or console entrypoint;
- the implemented encrypted-env initializer and its deployment packaging are
  reviewed against the actual Phala release. Its source-built overlay is wired,
  but it cannot make the stale primary image digest release-eligible;
- the Arena store is initialized fresh or passed through an explicit,
  reviewed catalog migration; the current store intentionally rejects a
  persisted catalog whose exact versioned manifests differ, so adding the
  safe-IR challenge is not an implicit in-place data migration;
- the primary digest-pinned `docker-compose.all.phala.yaml` adds the same
  internal-only worker block after the new image digest and sealed-file path
  exist. The source-built dstack overlays are wired now, but are not a
  substitute for a provenance-pinned Phala release;
- sealed evaluator/dataset commitments and `SAFE_IR_POLICY_COMMITMENT` are
  frozen in the exact `ChallengeRegistry` version;
- the independent QVL release policy uses
  `report_data_binding.kind=arena_candidate_ingress_v1` and externally pins the
  exact stable ingress X25519 public key and canonical key ID. It must not use
  the diligence-result signer binding for Arena;
- app ID, OS image, compose hash, report data, quote hash, recipient key, and
  runtime code/image digest all match the release evidence;
- the synthetic-only data policy, abuse/risk screen, reviewer path, rate limits,
  and query budget are connected;
- an external security review and deployment-level adversarial test verify the
  container/CVM, key custody, logs, crash behavior, and resource isolation;
- the frontend's exact ChallengeRegistry binding includes this safe-IR
  challenge and re-verifies it immediately before ciphertext submission.

The safe IR materially removes arbitrary-code host authority. It does not
replace TDX verification, deployment provenance, durable queue coordination,
or product-policy authorization.
