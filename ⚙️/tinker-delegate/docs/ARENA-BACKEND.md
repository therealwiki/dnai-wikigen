# Arena Backend Slice

The Arena backend is a durable, bounded projection for versioned sealed
challenges. It provides a real public catalog, wallet-authenticated/idempotent
submission ingress, queue state, and Ladder-gated leaderboard state for a
Python assay-QC preview and the canonical DNASeq variant-QC Safe-IR challenge.

It is **not a live hostile-code executor**. Catalog manifests and their generic
execution capabilities remain fixed to modeled/non-hardened. Queue,
leaderboard, and wallet-owner pages use a per-row projection instead:

```json
{
  "product_status": "per_row",
  "execution_assurance": "per_submission_execution_provenance"
}
```

An individual row is `modeled` with `execution_provenance.status=not_executed`
unless the gated Safe-IR worker atomically finalizes that exact row. Such a row
is labeled `live`, but its evidence classification is exactly
`worker_reported_qvl_binding_not_independently_verified`; it never claims that
the browser independently verified Intel TDX. Raw quotes, verdict signatures,
exact scores, and exact timing never enter the public record. The separate
worker-capability endpoint reports authenticated worker presence only and
cannot upgrade any row.

The local AST/subprocess sandbox remains a deterministic development tool and
must not execute arbitrary public candidates. The DNASeq runtime is a closed,
capability-free JSON instruction set rather than general Python. Production
execution still requires the separately reviewed release, fresh CVM, QVL,
registry, and persisted execution-policy gates described below.

## Public challenges

The built-in Python preview manifest is:

- challenge ID: `synthetic-bio-assay-qc`
- version: `1.0.0`
- synthetic data only
- candidate kind: `python_assay_qc_program`
- runtime: `python3.11`
- entrypoint: `process`
- maximum declared source size: 8,192 bytes
- metric: sealed Z-prime factor
- public release: fixed-eta Ladder with denominator 20
- raw data egress: false
- exact reward egress: false

The manifest hash covers the candidate contract, data/egress policy, Ladder
policy, and the explicit non-live execution capability. A submission must bind
to that exact hash and version.

The live-capable source path is the second immutable manifest:

- challenge ID: `dnaseq-variant-qc-safe-ir`
- version: `1.0.0`
- environment: `synthetic_dnaseq_variant_qc`
- candidate kind: `json_dnaseq_variant_qc_program`
- runtime: `dnai-safe-ir-v1`
- entrypoint: `select_variant_evidence`
- metric: sealed per-variant quality Z-prime separation
- public release: fixed-eta Ladder with denominator 20
- candidate input: canonical JSON containing only allowlisted bounded opcodes
- sealed lanes: truth-supported synthetic calls and simulated sequencing/calling artifacts
- never disclosed: bases, reads, alleles, loci, sample IDs, exact labels, exact scores, or timing

The runtime policy commitment is versioned separately from the catalog
manifest. Any opcode, limit, schema, or entrypoint change requires a new
runtime/schema rather than mutating `1.0.0` in place.

## HTTP surface

Public allowlisted reads:

```text
GET /attestation?context=arena
GET /arena/candidate-encryption-contract
GET /arena/challenges
GET /arena/challenges/{challenge_id}/versions/{version}
GET /arena/challenges/{challenge_id}/versions/{version}/queue
GET /arena/challenges/{challenge_id}/versions/{version}/leaderboard
GET /arena/challenges/{challenge_id}/versions/{version}/worker-capability
GET /arena/submissions/{submission_id}
```

Wallet exchange for an exact challenge version:

```text
POST /auth/arena/challenge
POST /auth/arena/token
```

Authenticated/idempotent submission:

```text
POST /arena/challenges/{challenge_id}/versions/{version}/submissions
Authorization: Bearer <short-lived challenge:submit token>
Idempotency-Key: <bounded caller-generated key>
```

Runtime-worker-only state operations:

```text
GET  /arena/internal/submissions/{submission_id}
POST /arena/internal/submissions/{submission_id}/transition
POST /arena/internal/submissions/{submission_id}/ladder-release
```

The internal routes require configured runtime bearer authentication. They do
not fail open when runtime auth is absent. The internal submission read is the
only worker-only HTTP response that includes the opaque server-generated
encrypted-object reference. No public response includes that reference or a
reconstructible object ID.

Exact submission, queue-transition, evaluator, and Ladder-release timestamps
are likewise internal-only. Public submissions, queues, and leaderboards emit
`exact_timing_egress: false` and preserve transition order without timestamps;
otherwise candidate-dependent evaluation latency could become a side channel
once a confidential worker is connected. The durable store keeps exact times
solely for ordering, idempotency, and crash recovery.

`GET /arena/candidate-encryption-contract` is public and returns exactly these
top-level fields:

```text
surface, schema_version, product_status, execution_assurance,
protocol, encoding_rules, aad, recipient, limits, submission_gate,
envelope_exact_fields, raw_secret_egress
```

`protocol` contains the exact algorithm, encoding, X25519 key size, HKDF
parameters, and AES-GCM parameters. `aad` contains the exact ordered field list
and hash formulas. `recipient` contains `encryption_public_key`, `key_id`,
`report_context`, `report_data`, `attestation_report_data_sha256`, and the exact
`report_data_contract`. `limits`
contains the AAD/ciphertext/plaintext/envelope/idempotency limits.
`submission_gate` contains only boolean gates and remains explicit that fresh
CVM verification is required, the API's attestation flag is not a policy
verdict, the sealed reference is server-generated, plaintext is rejected, and
hostile execution is disabled. The response has `Cache-Control: no-store,
max-age=0` so a browser cannot carry a recipient across a CVM rotation.

## Wallet authentication

Arena authentication is cryptographically separate from diligence-deal seller
upload authentication:

- exact scopes: `challenge:submit challenge:submissions:read`
- challenge resource: exact challenge ID and semantic version
- Base Sepolia chain ID: `84532`
- separate JWT issuer and audience
- separate JWT key ID
- separate dstack key path: `tinker/arena_wallet_auth`
- single-use, expiring personal-sign nonce
- short-lived token, five minutes by default
- EOA recovery locally, or EIP-1271 verification through two independently
  configured Base Sepolia RPCs when `TINKER_WALLET_AUTH_RPC_URL` and
  `TINKER_WALLET_AUTH_RPC_URL_SECONDARY` are configured

The contract-wallet path is server-selected and bounded: clients cannot supply
an RPC URL. Both distinct providers must report `eth_chainId == 84532`, agree
on one finalized block number/hash and exact wallet bytecode, and accept the
same EIP-191 digest with `0x1626ba7e` from
`isValidSignature(bytes32,bytes)`. Either RPC failing, diverging, reverting, or
returning malformed/wrong-magic data fails closed with no provider fallback.
RPC response bytes, time, global concurrency, and `eth_call` gas are bounded.
Each nonce permits at most three sequential attempts and only one in-flight
verification outside the nonce-store lock; compare-and-delete then consumes a
successful nonce exactly once.

An Arena token cannot authorize `artifact:upload`, operator/runtime routes, or
Tinker proxy operations. A seller-upload, runtime, or proxy token cannot
authorize an Arena submission.

Challenge and token request shapes:

```json
{
  "address": "0x1111111111111111111111111111111111111111",
  "challenge_id": "synthetic-bio-assay-qc",
  "challenge_version": "1.0.0"
}
```

```json
{
  "nonce": "0123456789abcdef0123456789abcdef",
  "signature": "0x..."
}
```

The service does not yet have a project-membership registry. It therefore
derives an internal personal-project identifier from the authenticated wallet
instead of trusting a caller-supplied organization ID. Public projections emit
only domain-separated wallet and project hashes.

The browser signs this exact EIP-191 `personal_sign` message template (line
breaks are significant):

```text
{domain} wants you to sign in with your Ethereum account:
{normalized_lowercase_wallet}

Authorize encrypted candidate submissions and read only your bounded submission status for the specified Arena challenge version during this short session. This request will not trigger a blockchain transaction.

URI: {uri}
Version: 1
Chain ID: 84532
Nonce: {32_lowercase_hex}
Issued At: {unix_seconds}
Expiration Time: {unix_seconds}
Resources:
- urn:dnai:arena:challenge:{challenge_id}:version:{challenge_version}
- urn:dnai:scope:challenge:submit
- urn:dnai:scope:challenge:submissions:read
```

The challenge response is exactly `address`, `challenge_id`,
`challenge_version`, `scope`, `nonce`, `message`, `issued_at`, and
`expires_at`. The token response is exactly `access_token`, `token_type`,
`address`, `challenge_id`, `challenge_version`, `scopes`, `issued_at`, and
`expires_at`. The HS256 JWT has `kid=dstack-arena-wallet-v1`; its payload is
limited to the configured issuer/audience, wallet subject, exact challenge ID
and version, the two exact ordered Arena scopes, `iat=nbf`, `exp`, and a 32-hex
`jti`.
Challenge TTL is at most 600 seconds; token TTL is at most 900 seconds. The
configured defaults are 300 seconds for each. A challenge nonce is consumed
atomically and cannot be exchanged twice.

## Submission boundary

The browser first fetches both the Arena attestation and encryption contract.
The attestation returns the stable Arena-specific X25519 public key bound into
`report_data`; the contract returns the same key plus the byte-exact protocol.
The browser must independently verify the fresh CVM quote and measurement
policy before encrypting. The API's `verified` field remains `false` even when
a quote is present because quote retrieval alone is not full Intel TDX policy
verification.

The submission body deliberately has no source, code, prompt, artifact,
caller-supplied object reference, URL, or raw candidate field:

```json
{
  "candidate_commitment": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "manifest": {
    "schema_version": 1,
    "challenge_manifest_hash": "<64 lowercase hex characters>",
    "candidate_kind": "python_assay_qc_program",
    "runtime": "python3.11",
    "entrypoint": "process",
    "source_bytes": 512,
    "mode": "leaderboard"
  },
  "envelope": {
    "schema_version": 1,
    "algorithm": "X25519-HKDF-SHA256-AES-256-GCM",
    "encoding": "base64url-nopad",
    "key_id": "sha256:<64 lowercase hex>",
    "attestation_report_data": "<64 lowercase hex>",
    "aad": "<unpadded base64url canonical AAD>",
    "ephemeral_public_key": "<43 unpadded base64url characters>",
    "nonce": "<16 unpadded base64url characters>",
    "ciphertext": "<unpadded base64url ciphertext including the GCM tag>"
  }
}
```

The server validates the envelope and persists ciphertext only. It then creates
an internal `sealed://arena/candidate-<request_hash>` reference and passes that
reference to the durable queue store. `source_bytes` and decoded ciphertext
length remain internal inputs used only for caps and the exact GCM-length
check. The public receipt contains the blob and ciphertext SHA-256 commitments,
key ID, replay state, and `private_size_egress=false`; it omits exact source and
ciphertext byte counts, the reference, and the object ID. The public submission
manifest likewise omits `source_bytes`. Its public manifest hash is computed
from the allowlisted non-size metadata plus `private_size_egress=false`, so an
observer cannot brute-force the exact source length from that hash. If queue
persistence fails after a new ciphertext write, the ingress write is rolled
back. An exact replay never rewrites the ciphertext file.

The successful submission response has exactly the top-level fields
`surface`, `created`, `idempotent_replay`, `candidate_ingress`, `submission`,
`raw_candidate_accepted`, `encrypted_reference_egress`, and
`raw_secret_egress`. `candidate_ingress` has exactly `surface`,
`schema_version`, `blob_sha256`, `ciphertext_sha256`, `key_id`, `created`,
`idempotent_replay`, `sealed_reference_public`,
`plaintext_candidate_accepted`, `product_status`, `execution_assurance`, and
`raw_secret_egress`, and `private_size_egress`. No exact private size, sealed
reference, or object ID is in either public object.

The decoded ciphertext limit is exactly 65,536 bytes including the 16-byte
AES-GCM tag, so the global plaintext ceiling is 65,520 bytes. The versioned BIO
challenge is stricter: `source_bytes <= 8,192`, therefore its ciphertext is at
most 8,208 bytes. A decoded ciphertext must equal
`manifest.source_bytes + 16` exactly. AAD is at most 4,096 bytes; the ephemeral
X25519 public key is exactly 32 bytes; the nonce is exactly 12 bytes; the raw
`Idempotency-Key` is at most 128 bytes; and the durable ingress has at most
10,000 envelopes. Base64url must be RFC 4648 canonical, unpadded, and round-trip
exactly.

The API's request-validation handler omits rejected input values. If a client
accidentally sends candidate or credential material in an unsupported field,
the 422 response retains only bounded error type/location/message metadata and
does not reflect the submitted value.

The envelope uses ephemeral X25519 ECDH. It derives 32 AES key bytes with
HKDF-SHA256, `salt=SHA256(canonical_aad_bytes)`, and
`info=utf8("dnai-wikigen/arena-candidate-ingress/v1")`. AES-256-GCM uses the
fresh 12-byte nonce and the exact canonical AAD bytes as additional
authenticated data.

### Canonical AAD

Canonicalization is exactly:

```python
json.dumps(
    aad_object,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
    allow_nan=False,
).encode("utf-8")
```

No alternate whitespace, key ordering, Unicode rendering, non-finite number,
extra field, or padded base64 representation is accepted. The allowlisted AAD
object is exactly:

```json
{
  "service": "dnai-wikigen",
  "context": "arena_candidate_ingress",
  "schema_version": 1,
  "challenge_id": "<exact challenge id>",
  "challenge_version": "<exact semver>",
  "challenge_manifest_hash": "<64 lowercase hex>",
  "submission_manifest_hash": "sha256:<canonical submission-manifest JSON>",
  "candidate_commitment": "sha256:<raw candidate bytes>",
  "identity": {
    "wallet_address_hash": "<64 lowercase hex>",
    "project_id_hash": "<64 lowercase hex>"
  },
  "idempotency_key_hash": "sha256:<canonical challenge, identity, and raw retry key>",
  "key_id": "sha256:<raw 32-byte Arena public key>",
  "attestation_report_data_sha256": "sha256:<raw 32-byte report_data>"
}
```

`submission_manifest_hash` is `"sha256:" + SHA256(canonical JSON of the exact
seven-field submission manifest)`. The two public identity hashes reuse the
Arena store's domain separation:

```text
wallet hash  = SHA256(utf8("arena_public_wallet") || 0x00 || canonical_json(lowercase_wallet))
project hash = SHA256(utf8("arena_public_project") || 0x00 || canonical_json(project_id))
project_id   = "personal-" + first_32_hex(SHA256(utf8("arena-personal-project:") || utf8(lowercase_wallet)))
```

The idempotency hash is `"sha256:" + SHA256(canonical JSON of
{challenge_id, challenge_version, identity, idempotency_key})`. The envelope's
raw `attestation_report_data` must also match the current recipient exactly.
The 32 raw report-data bytes are exactly `SHA256(canonical JSON)` of:

```json
{
  "context": "arena",
  "encryption_public_key": "<64 lowercase hex for the raw X25519 public key>",
  "key_id": "sha256:<64 lowercase hex>",
  "protocol": "arena_candidate_ingress_v1",
  "service": "dnai-wikigen"
}
```

That exact object is returned under `recipient.report_data_contract` so the
browser/verifier does not need to infer the binding formula.

### Byte-exact interoperability vector

The executable vector is in `tests/test_arena_ingress.py`. Its fixed inputs
are:

```text
wallet = 0xabababababababababababababababababababab
project = personal-cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
Idempotency-Key = candidate-vector-1
recipient private bytes = 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
ephemeral private bytes = 2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
nonce = 000102030405060708090a0b
source UTF-8 = "def process(positive_wells, negative_wells):\n    return positive_wells, negative_wells\n"
source bytes = 87
```

Derived key/report values:

```text
recipient public = 07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c
ephemeral public = 5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b
key_id = sha256:aaa8fff703b50b2297f4f6e13508f72420d96fd01ebb84cb074449caaef64041
report_data = 547f9dc53ff63308863384e30462af2f5a7fec064f21d41309c9a50cd913654c
submission_manifest_hash = sha256:2e8c09afe968dda26f6df31c6949109d3e4508d891e7e276ce6feaf907d317ba
```

The exact 914 AAD bytes are this single UTF-8 line:

```json
{"attestation_report_data_sha256":"sha256:4be27ebd9f45b86d00689cb48249afabaa8e0c20e6441052b90f32fe8faf8263","candidate_commitment":"sha256:6a6176d27189b7397583025ebc8cea88c93956d09073995be5dcdbfb1f081162","challenge_id":"synthetic-bio-assay-qc","challenge_manifest_hash":"d381d2c9bbaad6ed756f0083d2a6004f76990d351754e492f96fa7c7f2d17345","challenge_version":"1.0.0","context":"arena_candidate_ingress","idempotency_key_hash":"sha256:7a57ba69f49f62a10aeb2b6cdebd0da66d2bda435744834c39415eaefc9d0856","identity":{"project_id_hash":"0b84b7e2e9845831a7d6e22e73d203234e6e3169518e14c74bbd5f52dd126e02","wallet_address_hash":"7c881fa2a5c15b14c4c72f50881110d574b578390ae7cc57e4d9b8f9215e3c51"},"key_id":"sha256:aaa8fff703b50b2297f4f6e13508f72420d96fd01ebb84cb074449caaef64041","schema_version":1,"service":"dnai-wikigen","submission_manifest_hash":"sha256:2e8c09afe968dda26f6df31c6949109d3e4508d891e7e276ce6feaf907d317ba"}
```

```text
SHA256(AAD) = 4eada942d9141e41452db4f96ac103c205073f76eba52daa994bfaad4a648d29
ciphertext base64url = Z2lVlXulAvxvTyHXtW08jXVQ3cozmLfP5skOUA60bvy7_sNgz9ftPDWxXZ2xGMxl1fKLWQOQAoD_H9To87aULUrrZu0V1G_Hb9vM7ibVonysWSmM43JfzMBVuHVihBvzAFWZ9tyNyw
decoded ciphertext bytes = 103
```

## Idempotency and durability

Idempotency is scoped to:

- authenticated wallet
- derived project
- challenge ID
- challenge version
- caller key

The raw `Idempotency-Key` is never persisted. Both stores record only bounded
hashes. The candidate-ingress request hash covers the exact AAD binding and
complete encryption envelope; the queue request hash covers the server-created
sealed reference and bounded manifest. Replaying an identical request returns
the original ciphertext/submission with `created=false` and performs no blob
rewrite. Reusing the key for a different commitment, manifest, identity,
recipient, AAD, nonce, ephemeral key, or ciphertext returns HTTP 409.

Arena queue state is an allowlisted JSON document written through a
same-directory temporary file, `fsync`, atomic `os.replace`, and
parent-directory `fsync`. Ciphertext blobs are write-once `0600` files with an
atomic `0600` index. The local recipient key is a distinct restart-stable
32-byte `0600` file; in dstack it is derived only from
`tinker/arena_candidate_ingress`. Writes use copy-on-write state: a failed
durable write does not mutate the in-memory view. Loading fails closed on:

- malformed JSON
- duplicate JSON keys
- NaN/infinity constants
- unknown or missing fields
- invalid hashes or state transitions
- catalog drift
- candidate-egress marker tampering
- oversized files or record counts
- inconsistent idempotency or Ladder history
- missing, extra, symlinked, permission-broadened, or hash-mismatched ciphertext blobs
- envelope/index recipient, AAD, ciphertext-size, and object-ID inconsistencies

The JSON implementation uses an in-process lock, not a distributed or
multi-process transaction. Run one delegate API worker for this slice. A future
multi-worker deployment must move Arena state to a sealed transactional store
with equivalent exact-schema and atomicity checks.

## Queue model

The state graph is:

```text
submitted
  -> policy_screen
  -> queued
  -> provisioning
  -> public_tests
  -> sealed_eval
  -> review_hold (when required)
  -> completed
```

Bounded terminal alternatives are `failed`, `withheld`, `cancelled`, `expired`,
and `dead_letter`. Each destination accepts only its matching reason code.
Timestamps cannot regress, terminal states cannot transition, and leaderboard
mode cannot complete until a bounded Ladder release is attached.

Creating or using the generic transition routes does not prove code execution.
Those rows remain modeled even if a runtime operator manually advances them to
`completed`. Only `ArenaStore.finalize_safe_ir_execution(...)`, called by the
gated DNASeq Safe-IR worker, can atomically attach bounded provenance and a
terminal worker outcome. It requires the exact challenge manifest/runtime
binding and, for a completed leaderboard row, an existing sealed-evaluation
Ladder release.

Public provenance retains commitments to the runtime policy, catalog manifest,
compose, app, OS image, quote, independent verifier, verdict, TEE signer, Base
Sepolia chain, and ChallengeRegistry. It deliberately omits the raw TDX quote,
verdict signature, exact evaluator score, controls, source, ciphertext,
resource trace, and timing. Consumers must authenticate the corresponding QVL
artifact themselves before describing a row as independently verified.

## Ladder projection

For the DNASeq challenge, the worker evaluates the selected subsets from the
two sealed synthetic per-variant quality lanes, computes the exact Z-prime
score inside the boundary, and
reduces it with the existing `LadderLeaderboard`. Exact scores are not accepted
by any HTTP route. The internal HTTP route accepts only the resulting bounded:

```json
{
  "submission_index": 1,
  "accepted": true,
  "leaderboard_step_index": 12,
  "step_denominator": 20,
  "improvement_steps_so_far": 1
}
```

The store validates release ordering, denominator, monotonic best state, and
improvement counters. It persists only that release. The public leaderboard
contains completed, accepted improvements and never includes the exact score,
per-example values, hidden-set output, stderr, or encrypted candidate reference.

For a future in-process evaluator integration,
`ArenaStore.evaluate_ladder_submission(...)` accepts an exact internal score,
passes it directly to `LadderLeaderboard`, and persists/returns only the bounded
release. This method is intentionally not exposed over HTTP.

## Configuration

```text
TINKER_ARENA_STORE_PATH=/data/arena_state.json
TINKER_ARENA_WALLET_AUTH_KEY_PATH=tinker/arena_wallet_auth
TINKER_ARENA_WALLET_AUTH_CHALLENGE_TTL_SECONDS=300
TINKER_ARENA_WALLET_AUTH_TOKEN_TTL_SECONDS=300
TINKER_ARENA_WALLET_AUTH_MAX_PENDING_CHALLENGES=1024
TINKER_ARENA_WALLET_AUTH_ISSUER=dnai-wikigen:arena-wallet-auth
TINKER_ARENA_WALLET_AUTH_AUDIENCE=dnai-wikigen:arena
TINKER_ARENA_CANDIDATE_INGRESS_STORE_PATH=/data/arena_candidates
TINKER_ARENA_CANDIDATE_INGRESS_KEY_PATH=tinker/arena_candidate_ingress
TINKER_ARENA_CANDIDATE_INGRESS_LOCAL_KEY_FILE=/data/arena_candidate_ingress.key
TINKER_ARENA_CANDIDATE_INGRESS_MAX_ENVELOPES=10000
TINKER_ARENA_WORKER_LIVE_CAPABILITY_ENABLED=false
TINKER_ARENA_WORKER_RELEASE_SHA=<40 lowercase hex from reviewed release>
TINKER_ARENA_WORKER_IMAGE_DIGEST=sha256:<64 lowercase hex>
TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256=sha256:<64 lowercase hex>
TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256=sha256:<64 lowercase hex>
TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT=0x<64 lowercase hex>
TINKER_ARENA_WORKER_COMPOSE_HASH=<64 lowercase hex>
TINKER_ARENA_WORKER_APP_ID=<exact Phala app id>
TINKER_ARENA_WORKER_OS_IMAGE_HASH=<64 lowercase hex>
TINKER_ARENA_WORKER_HEARTBEAT_PATH=/data/arena_worker_heartbeat.json
TINKER_ARENA_WORKER_HEARTBEAT_TTL_SECONDS=30
TINKER_ARENA_WORKER_HEARTBEAT_KEY_PATH=tinker/arena_worker_heartbeat
```

An empty `TINKER_ARENA_STORE_PATH` keeps the immutable public catalog readable
but disables auth challenge issuance, submission writes, queue reads, and
leaderboard reads fail-closed. An empty candidate-ingress store disables the
Arena attestation, browser encryption contract, and submission endpoint. Local
development must use a dedicated `0600` key file so queued ciphertext survives
a restart. Dstack ignores local/explicit key material and derives at the
distinct Arena path. The production compose mounts both stores under the
delegate data volume.

The `dnai.arena.safe-worker-release.v3` manifest carries the complete finite
`approved_challenge_bindings` map plus its domain-separated
`approved_challenge_set_sha256`. Worker bootstrap recomputes that digest,
requires its selected `challenge_binding` to match one exact `id@version`
member, and then rechecks that member against one fresh Base Sepolia block.
The public registry remains extensible: a newly created registry row is not
executable by this release unless a later reviewed release explicitly includes
it and emits a new approved-set digest.

The manifest also pins the exact execution
policy trust context committed into the on-chain Arena release policy:

- `execution_policy_canonicalization_version` is exactly
  `policy-kernel-canonicalization/v2`;
- `execution_policy_approval_schema` is exactly
  `dnai-wikigen/execution-policy-approval/v3`;
- `execution_policy_api_schema_version` is exactly `3` and
  `execution_policy_store_schema_version` is exactly `5`; the v3 approval and
  authenticated v5 decision bind the hash-only execution context so an
  approved intent cannot be reused for a different compiled recipe;
- the full Base Sepolia release approval domain and its domain-separated
  SHA-256 hash;
- the lowercase, sorted, unique approver-hash set and its recomputed
  domain-separated root; and
- an exact `dnai.execution-policy-rollback-anchor.v1` descriptor with
  `status=verified_active_frozen_release_writer`, chain `84532`, nonzero
  contract and runtime-code hash, release-manifest commitment, nonzero evidence
  digest, exact dstack-derived writer and key path, and the same release
  commitment in `writer_release_commitment`; and
- immutable chain-read bounds: 2 through 256 confirmations, 30 through 3600
  seconds maximum block age, and 0 through 300 seconds maximum future skew; and
- `verification_model=single_rpc_reported_finalized_with_confirmation_depth`,
  with `independent_rpc_quorum_verified=false` and
  `consensus_proof_verified=false`.

The nonzero rollback-anchor `evidence_sha256` is the release-verified hash of
the exact canonical `dnai.execution-policy-anchor-writer-qvl-evidence.v2`
artifact, not a declarative custody marker. Before this manifest can be
generated, release tooling recomputes the writer report data, checks the exact
chain/anchor/writer/release/key-path and main-CVM app/compose/OS bindings, and
authenticates the short-lived EIP-191 verdict against the distinct
release-pinned anchor-writer QVL root. A self-produced dstack envelope or an
arbitrary nonzero evidence digest cannot promote the anchor to the verified
status committed here.

The release and compose-facing operational default is the allowed maximum of
3600 seconds because Base Sepolia's same-RPC `finalized` tag can lag `latest`
by more than five minutes. This affects only the freshness window: the worker
still pins and reads the exact selected candidate block, uses a single RPC, and
makes no independent-quorum or consensus-finality claim.

Worker bootstrap recomputes these hashes, compares the manifest signer set and
root to the current runtime trust context, requires the runtime anchor address,
code hash, writer, release commitment, key path, confirmations, and freshness
bounds to equal the manifest. Using one configured RPC, it chooses the older
of that RPC's `finalized` block tag and
`latest - (confirmations - 1)`, then verifies the selected fresh snapshot has
the exact active unpaused writer with no pending rotation and permanently
frozen writer admission. This is neither QVL verification, an independent RPC
quorum, nor a consensus-finality proof. It supplies the same verifier to every
execution-time policy read. Missing, reordered, generic, self-added, mutable,
paused, stale, or unavailable values fail startup closed. A rollback-anchor
draft with zero placeholder evidence is documentation only and is never a live
manifest.

The final Cloudflare origin must be present exactly in
`TINKER_CORS_ALLOWED_ORIGINS`, and the edge should rate-limit public wallet
challenge issuance and submission attempts. Cloudflare Queues/R2 integration
does not exist in this slice; the current durable ciphertext store is the
single-worker backend. No frontend should claim Cloudflare queue execution. A
worker-presence signal is not row evidence, and worker-reported row provenance
is not independently verified TDX evidence.

## Fresh-CVM go-live gate

The frontend must keep submission disabled after every new deployment until
all of the following are true for the operator's own fresh CVM:

1. `GET /attestation?context=arena` returns `mode=tdx`, a non-empty quote, the
   expected fresh app/compose/OS measurements, and `report_context=arena`.
2. An independent verifier validates the quote and measurement policy. The API
   intentionally does not turn quote presence into `verified=true`.
3. The verifier recomputes report data from the service, context, protocol,
   public key, and key ID, then checks it against the quote's report data.
4. The attestation key/report exactly match the uncached (`Cache-Control:
   no-store`) browser encryption contract fetched immediately before submit.
5. The exact challenge version and manifest hash are still present, wallet auth
   is bound to that version, and the same `Idempotency-Key` is used for AAD and
   submission.
6. The immutable catalog continues to label execution `modeled`. Worker
   presence may become `live` only after its reviewed descriptor pins and fresh
   authenticated heartbeat match. An individual Safe-IR row may become `live`
   only when the gated worker attaches its exact bounded provenance; this still
   reads `independently_verified_by_client=false`. General Python and hostile
   code remain disabled.

Local mode, an absent quote, stale measurements, a historical recipient key,
or any report/contract mismatch is a hard UI gate, not a warning.

## Deliberately absent

- arbitrary hostile-code execution
- plaintext candidate upload or caller-supplied encrypted-object references
- public exact scores or private evaluator reports
- Cloudflare queue/R2 worker integration (ciphertext uses the sealed local volume)
- multi-process shared persistence
- compute-credit charging
- ETH/USDC bonds
- prize custody or payouts
- card funding
- real patient/pathogen datasets
- production reviewer workflow

Those capabilities remain roadmap work and must not be inferred from the
existence of a durable queue projection.
