# Deal runtime service

`tinker-deal-runtime` is the production-oriented control loop that was missing
between the individual chain watcher, internal deal API, evaluator, result
verifier, and chain submitter components. It does not replace those components;
it composes their existing trust boundaries.

## Runtime flow

Each cycle performs these steps in order:

1. Read `DiligenceRoom` logs only through the configured confirmation-safe tip.
2. Deliver every decoded event to the runtime-authenticated internal API. A
   `DealFunded` notification recreates the in-TEE `DealContext`; resolution
   notifications trigger cleanup.
3. Persist the bounded deal journal, then advance the chain cursor. This write
   order means a crash can replay idempotent notifications but cannot advance a
   cursor past a funded deal that was never scheduled.
4. For each confirmed funded deal, call authenticated `POST /policy/status`
   with `surface=deal_evaluation`. The response's exact resource hash, current
   pass, and raw-egress flags are verified. A missing, expired, held, denied, or
   malformed decision stays `awaiting_execution_policy`. The runtime has no
   policy approval or signing path.
5. Read `GET /deal/{id}/result` before triggering evaluation. This recovers a
   completed bounded result after an HTTP timeout and prevents duplicate paid
   evaluation. If no result exists, call the protected
   `POST /deal/{id}/evaluate`; that endpoint performs the same policy check and
   resolves the configured evaluator. Production releases configure only
   `TINKER_EVALUATOR_MODE=deterministic`. The exact on-chain policy commitment
   selects one of three bounded, no-network recipes; the retained SFT provider
   implementation is never selectable in any custody mode. Synthetic
   evaluation remains local-test-only.
6. Strictly parse the fixed public result projection. Unknown fields,
   evaluator-authored methodology, exact private metrics, negative costs, a
   mismatched deal ID, or a non-enumerated score/quality band fail closed.
7. Read the immutable funded deal, fee, deterministic compute policy, compose
   approval, and `resultVerifier` from the target contract. The dstack result
   verifier identity must match the contract and must differ from the dstack
   transaction signer.
8. Produce one signer-bound dstack quote. The same raw quote is sent in memory
   to the configured HTTPS DCAP/QVL service; it is never journaled or printed.
   The returned strict `intel_tdx_dcap_qvl` verdict is authenticated against the
   explicitly configured verifier-address allowlist and exact quote, report
   data, compose, app, OS, signer, chain, and contract bindings.
9. Mint the short-lived exact result authorization, then call
   `DiligenceRoom.submitResult` through the dstack-derived signer. There is no
   private-key CLI option or environment-key signing fallback.
10. Observe `EvaluationSubmitted` and resolution events on confirmed blocks.
    An ambiguous broadcast is never resent automatically; the journal remains
    `submission_uncertain` until chain observation or explicit operator
    reconciliation.

Cycle output contains only counts, scanned block bounds, the fixed reorg policy,
and `raw_secret_egress=false`. The `0600` journal contains public chain hashes
and the same bounded evaluation projection. It never stores artifacts, raw
quotes, runtime/QVL bearer tokens, Tinker credentials, dstack key material,
private evaluator metrics, or verifier private keys.

## Production invocation shape

The service is installed by the project entry point:

```bash
uv run tinker-deal-runtime \
  --rpc-url "$TINKER_CHAIN_RPC_URL" \
  --contract-address "$TINKER_CHAIN_CONTRACT_ADDRESS" \
  --api-url http://delegate:8080 \
  --from-block "$DILIGENCE_DEPLOYMENT_BLOCK" \
  --confirmations 2 \
  --cursor-store /data/chain_watcher_cursor.json \
  --state-store /data/deal_runtime_state.json \
  --qvl-url https://independent-qvl.example/v1/verify \
  --allow-compose-hash 0xAPPROVED_COMPOSE_HASH \
  --allow-app-id APPROVED_DSTACK_APP_ID \
  --allow-os-image-hash APPROVED_OS_IMAGE_HASH \
  --trusted-attestation-verifier-address 0xINDEPENDENT_QVL_SIGNER
```

The internal API bearer is resolved from the existing fixed
`TINKER_RUNTIME_AUTH_TOKEN` or dstack-derived runtime-auth key path. An optional
QVL bearer can only come from the fixed `TINKER_QVL_AUTH_TOKEN` environment
name; callers cannot select an unrelated environment variable. The API may use
plain HTTP only on loopback, private/link-local addresses, single-label compose
service names, or `.internal` names. The QVL endpoint requires HTTPS outside an
explicit local structural test.

Base Sepolia is the default expected chain (`84532`). A production chain
requires at least two confirmations, a real non-simulator dstack runtime, a
non-empty compose/app allowlist, an independently trusted QVL signer, and a
contract whose immutable result verifier matches the dstack-derived verifier
identity. Startup fails before event processing when any binding is absent.

## Non-circular evaluator release authority

An evaluator policy never embeds the final OCI digest of the image containing
that policy. Doing so would be self-referential: changing the embedded digest
would change the image digest again. The v1 policy instead binds
`evaluator_bundle_digest_sha256`, a domain-separated SHA-256 over canonical JSON
describing these exact, lexically ordered source assets:

- `policies/diligence-evaluator-input-v1.json`
- `policies/diligence-evaluator-output-v1.json`
- `pyproject.toml`
- `tinker_delegate/deterministic_diligence_evaluator.py`
- `tinker_delegate/diligence_evaluator_registry.py`
- `tinker_delegate/evaluator.py`
- `uv.lock`

Each descriptor record contains the relative path, byte length, and raw-file
SHA-256. The digest preimage is
`"dnai.diligence-evaluator-source-bundle.v1\0" || canonical_json_with_LF`.
The stable-read builder rejects symlinks, oversized inputs, or inode, size,
mtime, or ctime drift. `tinker-diligence-evaluator-release` uses that single
snapshot to derive the bundle, entrypoint, input-schema, and output-schema
digests; compile three canonical policies; and emit the exact manifest bytes,
manifest SHA-256, three commitments, and Solidity policy-set root. Separately,
the release core binds the final OCI digest and CVM compose identity. Neither
authority substitutes for the other.

The manifest is materialized only through `diligence-policy-init`. Release
tooling projects its canonical base64url bytes, SHA-256, fixed sealed path, and
policy-set root into the main-CVM launch authority. The initializer has
`network_mode: none`, accepts no payload CLI arguments, validates canonical JSON
and all three policies/root, and atomically writes mode-0600 bytes to the
dedicated `diligence-evaluator-policy` volume. `delegate` depends on successful
completion and mounts that volume read-only at `/sealed/diligence`. With real
dstack enabled, `Settings` requires the exact manifest path, Base Sepolia,
nonzero room, matching chain-watcher contract, and eagerly revalidates the file
SHA/root before the API starts. Missing, substituted, partial, symlinked,
noncanonical, hash-drifted, or root-drifted authority therefore keeps the
runtime unavailable.

The three frozen on-chain policy commitments still select executable behavior;
the artifact v3 AAD separately binds chain ID, DiligenceRoom, deal ID, artifact
hash, and selected policy commitment. The checked-in digest in
`docker-compose.all.phala.yaml` is historical scaffolding and predates these
entrypoints. It is not a live claim: a clean-CI image and corresponding release
core, manifest, CVM, TDX/QVL evidence, and contract ceremony must be produced
before settlement is enabled.

`--allow-unverified-local-attestation` is restricted by both the runtime and
result-verifier implementation to local chain IDs `1337` or `31337`. It exists
only for dstack-simulator/Anvil structural tests and never produces a claim of
Intel TDX verification.

## Restart and idempotency behavior

- Event delivery is replay-safe. `on_deal_funded` accepts an identical immutable
  funded context and rejects conflicting context. Resolution cleanup is
  idempotent.
- The cursor is bound to one contract. Restarting with another address fails;
  lowering the confirmation depth after a cursor has advanced also fails.
- The bounded result is fetched before every evaluation attempt. If evaluation
  completed but its HTTP response was lost, the process recovers the existing
  result instead of repeating evaluator work.
- If the API process restarted and lost its in-memory deal dictionary, a 404
  causes the runtime to reread seller, buyer, reserve, budget, and artifact
  commitment from `DiligenceRoom` and replay `notify-funded`. The seller must
  then upload a new ciphertext to the new attested ingress key.
- QVL transport failure is retryable but makes no submission claim. Invalid
  signatures, policy mismatches, unapproved compose measurements, non-policy
  compute cost, wrong signer, or wrong contract state fail closed.
- An ambiguous transaction broadcast is not automatically retried. The worker
  only marks it submitted after an on-chain state/event observation.

## Remaining production gaps

The service closes the local orchestration gap, but it does not make the current
repository a live settlement deployment by itself:

1. **Independent QVL operator:** the client protocol and strict verdict
   authentication are implemented, but an independently operated Intel
   DCAP/QVL service, its HTTPS endpoint, trusted signing identity, collateral
   refresh/TCB policy, monitoring, and key-rotation process are not deployed.
2. **Private crash recovery:** the control plane keeps active artifacts,
   commitment secrets, evaluator sessions, and bounded results in process
   memory. Public funded context can be reconstructed from chain, but private
   bytes cannot and should not be placed in the public runtime journal. After a
   CVM/API restart, the seller must verify the fresh quote and re-upload the
   artifact. Seamless recovery requires a separately designed dstack-sealed,
   versioned, integrity-protected active-deal store with explicit destruction
   and migration semantics.
3. **Pending transaction recovery:** the submitter returns a hash after JSON-RPC
   acceptance, but there is no durable nonce/receipt state machine that can
   prove whether a connection-lost broadcast entered the mempool. The runtime
   safely stops automatic resubmission; an operator must reconcile an uncertain
   nonce until a receipt/confirmed event observer is added.
4. **Deep reorg rollback:** the watcher preserves the existing
   confirmed-blocks-only policy and blocks confirmation downgrades. It does not
   retain block hashes or reverse internal notifications after a reorg deeper
   than the configured confirmation window. A production indexer needs durable
   block-hash checkpoints plus compensating state transitions.
5. **Single-writer coordination:** cursor and journal writes are atomic for one
   process but have no distributed lease. Run exactly one deal-runtime replica
   until a dstack-sealed leader lease or transactional shared store is added.
6. **Artifact upload wake-up:** the worker polls bounded deal state; there is no
   durable internal artifact-ready event. Polling is safe but adds latency. A
   future queue must carry only deal IDs/commitments, never artifact bytes.
7. **Deployment evidence:** the deterministic evaluator and its networkless
   manifest initializer are wired into the release compose, but the checked-in
   historical image is not release-eligible. A clean reproducible image, fresh
   Phala deployment, exact release-core/manifest projection, contract
   deployment, compose/policy approval, QVL evidence, and Base Sepolia
   lifecycle proof are still required before enabling live settlement.

These gaps are not papered over with modeled signatures or simulator claims.
Until the required external services and fresh deployment bindings exist, live
result settlement remains fail-closed.
