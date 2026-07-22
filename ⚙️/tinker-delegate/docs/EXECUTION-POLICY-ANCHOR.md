# Execution-policy monotonic anchor

Status: **implemented and locally rehearsed; Base Sepolia deployment and CVM
writer binding remain pending the fresh release ceremony**.

`ExecutionPolicyAnchor` is a public monotonic witness for execution-policy
decision commitments. It closes a specific rollback gap: a sealed or local
append-only file can be restored to an older valid snapshot, while the CVM
cannot rewrite the Base Sepolia contract head observed by its configured RPC.
The current verifier uses one RPC's reported `finalized` tag plus a minimum
confirmation depth; it is not independent-RPC quorum or a consensus proof. The
contract is not a policy engine, does not inspect artifacts, and is not Intel
TDX, DCAP, or QVL evidence.

## Public data boundary

Only two application commitments enter the contract:

- `resourceHash`: a domain-separated commitment to the protected resource;
- `decisionHash`: the exact deterministic digest of one persisted policy
  decision record.

These values are public deterministic commitments, not encryption and not a
confidentiality boundary. Low-entropy inputs may be dictionary-enumerable. Raw
artifacts, prompts, policy inputs, evaluator output, signatures, and user data
must never be placed in calldata or events.

Every emitted event is fixed-width. There are no strings, byte arrays, URIs, or
unbounded collections in the write path.

## Monotonic model

The contract stores:

- one `globalSequence` and `globalHead` for a total order across all resources;
- one latest `resourceDecisionHead` and `resourceSequence` per resource;
- one `decisionSequence` per anchored decision digest, which prevents a digest
  from being replayed under another resource.

`anchorDecision` compare-and-sets all of the caller-observed state:

```text
expected global sequence
expected global head
resource hash
expected resource head
new decision hash
expected writer release commitment
```

Any stale global sequence, stale global head, stale resource head, repeated
decision hash, wrong writer, wrong release, zero commitment, or paused state
reverts without changing storage. There is one writer, so callers must serialize
anchor transactions; racing a stale state cannot silently fork either chain.

The next global head is:

```text
keccak256(abi.encode(
  ANCHOR_TYPEHASH,
  block.chainid,
  address(anchor),
  newSequence,
  previousGlobalHead,
  resourceHash,
  previousResourceHead,
  decisionHash,
  writer,
  writerReleaseCommitment
))
```

`ANCHOR_TYPEHASH` is the keccak digest of:

```text
ExecutionPolicyAnchor(uint256 chainId,address anchor,uint256 sequence,bytes32 previousGlobalHead,bytes32 resourceHash,bytes32 previousResourceHead,bytes32 decisionHash,address writer,bytes32 writerReleaseCommitment)
```

`computeAnchorHead` exposes the same calculation for independent clients.
Chain ID, contract address, writer, and release commitment make a head from one
release unusable as evidence for another.

## Release-bound writer governance

A fresh suite deploys the anchor with:

- the explicit deployment operator as owner;
- no writer and no writer-release commitment;
- no pending writer proposal;
- `paused=true`;
- `writerRotationsFrozen=false`;
- zero global sequence and head.

There is no implicit operator writer. The final CVM-controlled writer and its
exact nonzero release commitment must complete the immutable two-day timelock.
Production activation then permanently freezes writer rotations before
unpausing. The contract enforces that unpausing is impossible until this freeze
is set. After the freeze, writer recovery or release rotation requires a fresh
anchor and an explicit migration; an owner cannot silently replace the live
writer.

The owner or writer may emergency-pause anchoring. Only the owner may resume,
and the frozen release conditions are rechecked. Governance ownership transfer
is two-step and can never collide with the active or pending writer.

The two release roots intentionally have different jobs. The frozen on-chain
`writerReleaseCommitment` is `0x` plus the domain-separated digest of the
reviewed post-contract, pre-Phala CVM launch intent. It admits a writer under
the exact seven descriptors without depending on CVM identities that do not yet
exist. After those CVMs and the final authority are measured, the writer's
first confirmed anchor head commits the domain-separated final-authority
digest. Treating the final-authority digest as the writer-release commitment
would recreate the deployment cycle and is rejected by release validation.

The full activation ceremony is ordered and fail-closed:

1. Deploy the fresh suite. Confirm the anchor is paused, writer-unset,
   rotation-unfrozen, and empty using the deployment ledger.
2. Launch the project-owned bootstrap CVM with the exact anchor address,
   nonzero writer release commitment, and fixed
   `tinker/execution_policy_anchor_writer` path. Configure the exact separate
   anchor-writer QVL HTTPS `/verify` endpoint, its externally reviewed verifier
   address and canonical policy hash, and deliver the bearer only through the
   Phala encrypted environment. The policy API remains unavailable at this
   point by design.
3. Inside that CVM, run the one-shot, non-HTTP command:

   ```bash
   tinker-execution-policy-anchor-writer
   ```

   With the compose overlay available, the equivalent explicit container
   command is:

   ```bash
   docker compose -f docker-compose.yaml -f docker-compose.dstack.yaml \
     --profile anchor-writer-ceremony \
     run --rm --no-deps anchor-writer-evidence
   ```

   That command is a source-build dstack rehearsal path, not the current
   digest-pinned Phala production path. The delegate image presently pinned in
   `docker-compose.all.phala.yaml`,
   `sha256:262938c3620a2c4931b7ff0e5da1f321e564e2deade4550bd41104a3885f0b98`,
   was inspected directly and has neither the command entrypoint nor the
   `tinker_delegate.execution_policy_anchor_cli` module. SSH/exec cannot make
   missing code appear, and injecting the anchor-writer QVL bearer into the
   long-running delegate environment is forbidden.

   Production writer evidence therefore remains fail-closed until this exact
   ordered image ceremony is complete:

   1. Commit and review one clean source SHA containing the CLI and tests.
   2. Let clean CI publish the linux/amd64 delegate image and prove its GitHub
      provenance and SPDX SBOM; verify the entrypoint in that exact image.
   3. Pin the resulting literal `repository@sha256:<digest>` in the Phala
      compose. A mutable tag or encrypted-environment image substitution is
      not release evidence.
   4. Add a profile-gated `anchor-writer-evidence` service using that same
      literal image. Give it only the dstack socket, reviewed public
      anchor/writer/release/QVL pins, and the one-shot Phala-encrypted QVL
      bearer. Give it no `/data`, sealed volume, port, or long-running restart.
   5. Deploy the exact compose, invoke only that profile, capture the single
      canonical artifact line under `umask 077`, and leave the encrypted value
      scoped only to that stopped profile service. Never add that bearer to
      `delegate`, Arena, or Compute service environments. Removing or rotating
      any main-CVM environment value after the quote is collected may change
      the attested compose identity; treat such a change as a new release that
      requires new writer evidence rather than silently mutating this one.

   Until step 5 succeeds, do not configure or unpause the on-chain writer and
   do not label the release `verified_active_frozen_release_writer`.

   It runs only in real dstack, derives no configurable raw key, collects one
   quote, and sends that raw quote only in a bounded bearer-authenticated HTTPS
   request to the separate QVL. The QVL independently checks DCAP collateral,
   exact app/compose/OS and TDX measurements, the non-debug bit, the writer
   allowlist, and report data derived from the chain, anchor, writer, release,
   literal key path, and custody label. The command authenticates the returned
   short-lived EIP-191 verdict against the externally configured verifier root
   before emitting one canonical
   `dnai.execution-policy-anchor-writer-qvl-evidence.v2` JSON line. The output
   contains the signed verdict and quote hash/size, never the raw quote, bearer,
   dstack key response, or private key. Redirect it under `umask 077` to the
   ceremony evidence file supplied later to `--anchor-writer-evidence`.
4. Put that exact lowercase address into the reviewed release inputs and run
   phase 1 below to propose the writer/release pair.
5. Wait at least the immutable two-day timelock, then run phase 2. Phase 2
   activates the pair, permanently freezes rotations, and unpauses.
6. Re-read active contract bytecode/state at one canonical Base Sepolia block,
   update the deployment ledger, and rerun the command in the final CVM so its
   fresh verdict binds the final writer plus app/compose/OS/TDX release.
7. Build `verified_active_frozen_release_writer` only by passing those exact
   canonical artifact bytes to `--anchor-writer-evidence`. Release tooling
   hashes the file, recomputes report data, checks every field and QVL policy
   root, and authenticates the signature. An arbitrary nonzero evidence hash
   or the former self-produced envelope is rejected.

Configure the reviewed on-chain release in its two governance phases:

```bash
cd "⚙️/tinker-delegate/contracts"
EXECUTION_POLICY_ANCHOR_RELEASE_PHASE=1 \
  ./scripts/configure-execution-policy-anchor.sh

# Wait at least 172800 seconds, then:
EXECUTION_POLICY_ANCHOR_RELEASE_PHASE=2 \
  ./scripts/configure-execution-policy-anchor.sh
```

Required explicit inputs are:

```dotenv
EXECUTION_POLICY_ANCHOR_ADDRESS=0x...
EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH=0x...
EXECUTION_POLICY_ANCHOR_WRITER=0x...
EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT=0x...
EXECUTION_POLICY_ANCHOR_RELEASE_PHASE=1
```

The helper is Base-Sepolia-only, checks exact runtime code and owner, requires a
pristine empty anchor, uses literal encrypted Foundry account `dev`, and never
accepts a raw key. Each invocation dry-runs unless `BROADCAST=true`.

## Runtime transaction protocol

The Python runtime implements the durable integration in
`execution_policy_anchor.py`. The required order is:

1. Acquire the cross-process exclusive policy lease. The API holds it from the
   authenticated journal refresh through append and anchor confirmation.
2. Ask the configured RPC for both `latest` and `finalized`, then choose the
   older of the RPC-reported finalized block and
   `latest - (minimum confirmations - 1)`.
3. Persist the exact decision record locally before any broadcast.
4. Submit `anchorDecision` from the release-bound writer.
5. Wait for the release-pinned, same-RPC reported-finalized plus confirmation-
   depth policy.
6. Re-read runtime bytecode, the global head, resource head, decision sequence,
   writer, release commitment, pending writer tuple, pause, and freeze state at
   one sufficiently confirmed canonical block hash.
7. Return success only after the local sequence and complete deterministic
   global projection exactly reproduce that selected RPC-observed contract
   state. A PASS decision is executable only after this step.

No mutable `pending_anchor` flag is needed: local sequence exactly equals the
contract global sequence. The sole recoverable intermediate state is a local
journal exactly one record ahead. If a process crashes after persistence or
transaction submission, recovery reconciles that exact final record against
`decisionSequence`, the resource head, and the deterministic global head. It
first checks the unfinalized head, accepts only the exact target if already
mined, and otherwise submits the compare-and-set call for those same stored
hashes. It never appends another local decision while this gap exists. A failed,
reverted, missing, reorged, not yet inside the selected RPC boundary, paused,
or mismatched anchor always
means fail closed: no inference, training, evaluation, or side-effecting
dispatch may consume that PASS.

The executor acquires the corresponding shared cross-process lease, freshly
authenticates the journal, compares its latest resource decision hash to the
selected contract head, and keeps that lease through protected execution. A
new HOLD/DENY cannot be persisted between authorization and the executable
queue claim. Backend and browser release
descriptors must pin the Base Sepolia chain ID, anchor address, runtime code
hash, active writer, writer release commitment, frozen rotation state, and
confirmation policy.

The lease is a filesystem inode lease. Every API writer and executor must mount
the same policy journal and lock directory. The current release permits one API
writer deployment and one leased Arena worker against that shared volume;
horizontal replicas with independent volumes are forbidden until a shared
transactional store/lease replaces this boundary. Independent-volume replicas
fail on detected chain/journal drift but cannot close the pre-finality race.

Production configuration is release-generated and uses these backend fields:

```dotenv
TINKER_EXECUTION_POLICY_ANCHOR_RPC_URL=https://sepolia.base.org
TINKER_EXECUTION_POLICY_ANCHOR_ADDRESS=0x...
TINKER_EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH=0x...
TINKER_EXECUTION_POLICY_ANCHOR_WRITER_ADDRESS=0x...
TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT=0x...
TINKER_EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH=tinker/execution_policy_anchor_writer
TINKER_EXECUTION_POLICY_ANCHOR_CONFIRMATIONS=12
TINKER_EXECUTION_POLICY_ANCHOR_POLL_INTERVAL_SECONDS=1
TINKER_EXECUTION_POLICY_ANCHOR_CONFIRMATION_WAIT_SECONDS=60
TINKER_EXECUTION_POLICY_ANCHOR_MAX_BLOCK_AGE_SECONDS=3600
TINKER_EXECUTION_POLICY_ANCHOR_MAX_FUTURE_BLOCK_SKEW_SECONDS=30
TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_URL=https://<separate-qvl>/verify
TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_VERIFIER_ADDRESS=0x...
TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_RELEASE_POLICY_HASH=0x...
TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_MAX_VERDICT_AGE_SECONDS=300
# Phala encrypted environment only; never commit or include in evidence.
TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN=...
```

There is intentionally no raw-key setting. The API writer refuses to start
outside real dstack. The Arena worker constructs the same verifier read-only
and cannot prepare, sign, broadcast, or reconcile an unanchored decision. The
dstack compose overlays therefore pass the writer key path only to the
delegate; Arena workers receive the required public address, bytecode, writer,
release, and finality pins but no anchor signer path or private key material.

Every bounded runtime snapshot reports the chosen `block_number`/`block_hash`,
`latest_block_number`, `rpc_finalized_block_number`,
`rpc_finalized_block_hash`, `minimum_confirmation_depth`, and
`observed_confirmation_depth`. Its status is
`rpc_reported_finalized_release_match`, its model is
`single_rpc_reported_finalized_with_confirmation_depth`, and both
`independent_rpc_quorum_verified` and `consensus_proof_verified` are `false`.
Those fields let an observer re-query the public chain boundary without
mislabeling one provider's response as consensus-authenticated finality.

## Evidence and limitations

The local rehearsal deploys all seven contracts, proves exact creation-runtime
reexecution, checks the anchor's empty paused state, completes the two-day
writer admission, freezes rotations, unpauses, and anchors one synthetic
decision at global sequence 1. That is local Anvil evidence only.

The following remain required before labeling anchoring live:

- deploy and verify the fresh anchor on Base Sepolia;
- derive the writer inside the project-owned CVM release;
- bind the exact release commitment through the governance ceremony;
- configure the live CVM with the release-generated runtime pins and validate
  the dstack-derived address before proposing it on chain;
- expose only truthful BaseScan transaction/state evidence in the UI.

An anchor event proves that the authorized address wrote a commitment in a
specific contract state. It does not prove how the decision was computed, that
the writer ran inside TDX, or that a QVL accepted an attestation quote. Those are
separate release-chain checks.

The runtime also cross-checks the approval domain's release commitment,
compose hash, and app-ID hash against the configured anchor release and fresh
same-CVM dstack producer evidence before constructing the API coordinator.
That detects release drift; because the evidence is not independently QVL-
verified in this path, it must not be presented as an attestation verdict.
