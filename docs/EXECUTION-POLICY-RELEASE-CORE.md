# Final release authority core

Last updated: 2026-07-23

The execution-policy anchor writer is admitted for one exact release. Its
on-chain `writerReleaseCommitment` is not an operator-chosen label: it is the
domain-separated SHA-256 digest of the separately reviewed canonical CVM
launch intent. The final-authority digest remains the release-manifest
commitment used by the final candidate and confirmed release evidence.

This artifact breaks the release dependency cycle. The final web release
describes the active, frozen anchor writer, while the writer must be admitted
under a commitment before that downstream activation evidence can exist. The
authority therefore contains only stable facts available before the anchor
ceremony. Final validation projects the release candidate back onto those
facts and byte-compares it with the supplied authority.

A renewable review envelope binds the authority digest externally. Review
times, reviewers, evidence hashes, and envelope hashes never enter the
authority digest. Renewing a review therefore cannot invalidate an otherwise
unchanged on-chain release authority.

## Commitment

The bare lowercase digest is:

```text
SHA256(
  UTF8("dnai-wikigen/final-release-authority-core/v4\0") ||
  canonical_final_authority_bytes
)
```

`canonical_final_authority_bytes` is compact, recursively key-sorted JSON with
no insignificant whitespace or final newline. Strings use ASCII JSON escapes,
including UTF-16 surrogate-pair escapes for astral Unicode, matching Python
`json.dumps(..., ensure_ascii=True, sort_keys=True, separators=(",", ":"))`.

The operator-facing artifact must be the exact normalized object serialized as
recursively key-sorted, two-space-indented JSON plus one final newline. The reader refuses aliases,
symbolic-link paths, non-regular files, unstable reads, noncanonical bytes,
extra fields, unsafe numbers, unpaired surrogates, and oversized input.

The current JavaScript known-answer vector is:

```text
vector: dnai.final-release-authority-core.v4/known-answer-1
digest: 2b0d68ced175dd7dad8e1354e668f52607256fd12bb29ba78c2fe7568d0a211b
```

The digest includes authenticated store schema v6, mandatory release-marker
genesis, marker-offset chain sequences, and the exact anchor-writer gas-reserve
policy described below. Changing any one of those facts rotates the v4 digest.

Historical replay retains separate explicit v3 and v2 parsers and frozen KATs:

```text
vector: dnai.final-release-authority-core.v3/known-answer-1
digest: 2e2c02e0748b66690eaee79e451ab5506246ef758fb0cf08437f75ef836f48f8

vector: dnai.final-release-authority-core.v2/known-answer-1
digest: d1bab06a461597c4b0d12d9bbf50ea37549c2023b8c37b3e8ef7638b8c874fce
```

Activation-facing JavaScript normalization accepts v4 only. The v3 and v2
parsers are reachable only through explicitly named historical replay modules;
schema inspection must never silently downgrade a current release. The Python
compatibility implementation intentionally verifies only the frozen v3/v2
cross-language history and reads the immutable v3 fixture. It is not current
v4 release authority.

The version boundary also freezes validation semantics, not only field names.
Historical v2 preserves its original rule that
`contracts.diligence_room.developer == operator_address` and its broader
canonical HTTPS-origin grammar (including an IP literal or non-default port).
Historical v3 requires the permanent Diligence developer to be distinct from
the operator and room contract, includes that developer in control-plane role
separation, and accepts only canonical public multi-label DNS HTTPS origins
without a port. Current v4 preserves those safety rules while adding the
Royalty, Collaboration execution, wallet-adoption, marker, authenticated-store,
and gas-reserve authority. Historical tests remain version-pinned so current
hardening cannot retroactively invalidate archived bytes.

## Committed facts

The authority has these exact top-level keys:

```json
{
  "schema": "dnai.final-release-authority-core.v4",
  "release_sha": "<40 lowercase hex>",
  "network": {},
  "operator_address": "0x...",
  "deployment_intent_sha256": "sha256:<64 lowercase hex>",
  "cvm_launch_intent_sha256": "sha256:<64 lowercase hex>",
  "seven_cvm_release_verification_authority_sha256": "sha256:<64 lowercase hex>",
  "shared_release_lineage": {},
  "contracts": {},
  "cvm": {},
  "arena_registry_bindings": {},
  "wallet_auth": {},
  "requested_features": {},
  "execution_policy": {},
  "royalty_release_authority": {},
  "royalty_release_active_state": {},
  "royalty_release_active_state_sha256": "sha256:<64 lowercase hex>",
  "royalty_release_history_sha256": "sha256:<64 lowercase hex>",
  "royalty_release_history_receipt_sha256": "sha256:<64 lowercase hex>",
  "royalty_settlement_release_binding_template": {},
  "collaboration_execution": {},
  "compute_workload_wallet_adoption": {}
}
```

It commits:

- the clean source SHA and canonical Base Sepolia network;
- the stable predeployment-intent digest that authorized bootstrap choices;
- the reviewed CVM launch-intent digest that authorized the exact rendered
  launch descriptors before Phala assigned runtime identities;
- the operator and all seven application contract addresses and runtime hashes;
- the exact nonempty Arena genesis catalog, including contiguous registry IDs,
  current versions, controllers, open/unpaused/frozen lifecycle, public
  metadata commitments, sealed-artifact commitments, evaluator commitments,
  and release-policy commitments;
- the intended ChallengeRegistry active state, empty pending owner, exact
  two-day version-review delay, and exact genesis challenge count;
- frozen Diligence verifier/QVL bindings and the exact one-compose,
  one-TEE admission set;
- frozen Compute metering bindings, TEE/compose roots, and full native/ERC20
  rate-policy tuples, including each asset, payout recipient, developer fee,
  and commitment;
- the exact active Tinker account, compose, manager, and per-operation policy;
- the Email consumer, oracle/consumer compose admissions, bounded upgrade
  delay, KMS/boot roots, and restart proof;
- the main CVM identity, private production posture, and compose/OS roots;
- exact digest-pinned image provenance and SPDX status;
- browser origins, wallet-auth domain, and the exact requested feature flags
  `contract_writes`, `artifact_upload`, `compute_console`,
  `tinker_customer`, `collaboration`, `compute_vault_funding`,
  `compute_vault_authorization`, `compute_workload_upload`, and
  `arena_submission`, plus the distinct v4 decisions
  `collaboration_execution`, `royalty_settlement`, and
  `compute_workload_wallet_adoption`;
- the optional public WalletConnect project identifier, represented explicitly
  as either the empty string or exactly 32 lowercase hexadecimal characters;
  and
- execution-policy versions, approver set/root, and the intended anchor target,
  writer identity, launch-intent-bound writer release, custody path, and
  explicitly bounded RPC trust model;
- authenticated execution-policy store schema v6, including local contiguous
  sequence semantics and the separate marker-inclusive on-chain
  `chain_sequence` carried by Royalty records;
- the mandatory non-circular release marker at global sequence `1`, with local
  store record `1` mapping to on-chain sequence `2`; and
- `dnai.execution-policy-anchor-writer-gas-reserve.v1`: one release-marker
  transaction plus 32 subsequent policy/Royalty anchor transactions, at no
  more than 500,000 gas each and a reviewed 2,000,000,000 wei-per-gas budget,
  producing the exact minimum reserve `33000000000000000` wei (0.033 ETH).

The runtime controls record current fail-closed limitations, including disabled
provider dispatch, hostile candidate execution, deal settlement, and remote
artifact evaluation, plus the raw-secret-egress prohibition.

Changing any committed fact requires a new authority and a new anchor release.
The frozen writer ceremony prevents silently retargeting an activated release.

The v2 schema deliberately replaced the incomplete v1 Compute commitment
fields. Historical v3 retains those facts and adds required, exact, independent
`tinker_customer` and `collaboration` booleans. Both default to `false` in the
review fixture and neither can be inferred from `compute_console`, another
feature flag, a route, or endpoint availability. A policy commitment does not
determine its on-chain payout recipient, so both provider addresses remain
first-class authority facts. Both providers must be distinct from one another
and from governance, application contracts, the main TEE, verifiers, metering
control, and anchor roles. Current v4 adds exact Royalty release state and
history, shared seven-CVM lineage, Collaboration execution, wallet adoption,
store-v6/marker semantics, and the bounded writer reserve without rewriting
the historical v3 bytes.

The five configuration helpers consume no operator-authored projection JSON.
`scripts/ceremony-authority-projector.mjs` validates deployment-intent v6 and
current final-authority v4, enforces their constructor/static and numeric equality
bindings, and emits exactly 36 named public ceremony assertions. The anchor
writer release commitment is `0x` plus the reviewed CVM launch-intent digest;
both the launch-intent pin and that exact writer release are embedded in the
hashed final authority.

## Deliberately excluded facts

The authority excludes every value that is self-referential, renewable, or
created only after its digest exists:

- its own `final_authority_sha256`;
- `review_envelope_sha256`, `review_evidence_sha256`, reviewer declarations,
  approval/expiry timestamps, and all other review-envelope material;
- `release_manifest_commitment`;
- the derived approval domain and approval-domain hash;
- active anchor state, sequence, heads, and anchor evidence;
- the anchor-writer QVL artifact, signature, and verdict;
- independent verdict envelopes and fresh quote observations;
- observed ChallengeRegistry timestamps and transaction receipts, the final
  deployment ledger, and user, job, or runtime records. The prescriptive Arena
  genesis catalog is committed; its later live-chain realization is separate
  evidence.

These exclusions are enforced relationally during final validation:

```text
candidate.operator_policy.final_authority_sha256
  == "sha256:" + final_authority_digest

candidate.execution_policy.rollback_anchor.release_manifest_commitment
  == final_authority_digest

candidate.execution_policy.rollback_anchor.writer_release_commitment
  == "0x" + bare(candidate.cvm_launch_intent_sha256)
```

The review hashes must be valid nonzero lowercase SHA-256 pins, but changing
them cannot change `final_authority_digest`.

## Candidate evidence

The `dnai.web-release.v4` candidate carries both
`deployment_intent_sha256` and `cvm_launch_intent_sha256` at the top level so
it can reproduce the authority exactly. Renewable evidence is a separate
object:

```json
{
  "schema": "dnai.final-release-authority-evidence.v1",
  "final_authority_sha256": "sha256:<authority digest>",
  "review_envelope_sha256": "sha256:<current envelope digest>",
  "review_evidence_sha256": "sha256:<current external evidence digest>"
}
```

The final-authority hash is stable. The review-envelope and review-evidence
hashes may be renewed together without redeploying contracts, reconfiguring the
anchor, or rewriting historical evidence.

## Ceremony

The authority is computed after the stable deployment intent, reviewed CVM
launch intent, clean image subjects, fresh contract suite, measured CVM
identities, Diligence QVL binding, and Compute metering binding are known, but
before the Arena genesis catalog and other timelocked release mutations are
executed. The catalog is prescriptive authority at this stage, not a claim that
its challenges already exist on-chain.

1. Create the exact normalized pretty-JSON authority at an absolute,
   non-symlink path. It must contain no review or final-authority hash fields.
2. Validate the exact ceremony tuple and extract the launch-intent-bound writer
   commitment with the compatibility CLI:

   ```bash
   node scripts/execution-policy-release-core-cli.mjs \
     --artifact /absolute/path/final-release-authority-core.json \
     --release-sha "$RELEASE_SHA" \
     --operator "$DEPLOYMENT_OPERATOR" \
     --anchor "$EXECUTION_POLICY_ANCHOR_ADDRESS" \
     --anchor-code-hash "$EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH" \
     --writer "$EXECUTION_POLICY_ANCHOR_WRITER"
   ```

   Success prints only `0x<cvm-launch-intent digest>`. It deliberately does
   not print the final-authority digest as the writer release; those two roots
   have different positions in the non-cyclic ceremony.
3. Create or renew an authority review envelope whose subject is the exact
   final-authority bytes. `init-review`/`check-review` require the exact
   deployment-intent and CVM-launch-intent dependency files, revalidate their
   digest links and transitive reviewer independence, and derive the
   domain-separated `sha256:<final-authority digest>` from the subject.
4. Realize the exact `arena_registry_bindings` catalog through
   `⚙️/tinker-delegate/contracts/scripts/configure-challenge-registry-release.sh`.
   Phase 1 creates contiguous version-1 challenge IDs only in the pristine
   fresh registry. After every exact on-chain two-day review window, phase 2
   revalidates the complete catalog, freezes each configuration, transitions it
   to Open, and appends ordered calldata/receipt/post-state evidence. The helper
   derives its variable-length input with the canonical final-authority parser;
   it accepts no operator-authored catalog projection. Broadcast phases keep the
   working ledger and Forge artifacts at explicit canonical paths outside the
   checkout so the same clean release SHA survives the two-day boundary, and
   holds the release-SHA-scoped shared ceremony lock through durable ledger
   replacement and directory fsync. Each
   phase waits for finalized receipt blocks, records a finalized block-pinned
   post-state plus a latest-state recheck, and phase 2 independently proves the
   historical phase-1 calldata/receipt/state chain before unlocking the signer.
   Review-envelope hashes may renew between phases; the final-authority and
   catalog-projection digests may not.
5. Configure the anchor through the reviewed two-phase helper. The helper must
   take the writer release from the launch-intent digest already cross-bound in
   the canonical final authority instead of accepting an unbound operator
   label. The final-authority digest separately becomes the candidate's
   `release_manifest_commitment`.
6. Fund the exact final-authority writer with Base Sepolia ETH. Collect
   independent anchor-writer QVL evidence and a two-RPC common-finalized-block
   `eth_getBalance` observation proving at least `33000000000000000` canonical
   decimal wei. A merely nonzero balance, operator balance, contract/USDC
   balance, QVL authorization, relayer, paymaster, or hot key is not accepted.
7. Build the final web candidate with the stable authority hash and current
   review hashes, then run semantic validation with the same authority artifact.

## Live-activation completion gate

`scripts/activation-preflight.mjs --stage live-activation` additionally
requires the completed DiligenceRoom ceremony for this exact release. The
preflight replays the durable external ledger revision chain before and after
its other checks, requires the replay to be finalized with a mode-`0444`
working ledger, and binds that ledger back to the immutable mode-`0444`
`DEPLOYMENT_MANIFEST_PATH`.

The current report schema is `dnai.activation-preflight.v4` and emits exactly
110 checks. Its `chain.anchor_writer_gas_reserve` check is mandatory at
`release_ceremony` and `live_activation`. The read-only collector calls
`eth_getBalance` for the exact dstack-derived writer through both distinct
Base Sepolia RPC authorities at the same common finalized block. Both RPC
quantities must canonicalize to the same decimal wei string and meet the v4
minimum. `dnai.activation-readiness-snapshot.v5` binds the writer, block,
balance, both observation digests, reserve policy, final-authority digest, and
all descriptor hashes for at most 120 seconds. The current signed
final-authority stage fixes the writer and policy; the readiness snapshot is
ephemeral read-only evidence and never grants mutation authority by itself.

The live gate requires all four archived phase-specific review envelopes:

```text
DILIGENCE_RELEASE_PHASE_1_REVIEW_ENVELOPE_PATH
DILIGENCE_RELEASE_PHASE_2_REVIEW_ENVELOPE_PATH
DILIGENCE_RELEASE_PHASE_3_REVIEW_ENVELOPE_PATH
DILIGENCE_RELEASE_PHASE_4_REVIEW_ENVELOPE_PATH
```

Each envelope is independently revalidated with `check-review` against the
same final authority, deployment intent, and CVM-launch intent. It must still
be valid, contain two separated reviewer declarations at the pre-transaction
checkpoint, and match the review digest recorded for its own phase. Four
distinct envelope digests are mandatory; the renewable current review path
cannot stand in for this phase history.

The completed ledger must contain exactly phases 1 through 4 for the current
source, controller, DiligenceRoom, runtime, authority, and deployment lineage.
Phases 1 through 3 must carry the 13 ordered operator transaction records with
their canonical bundle digests. Phase 4 must carry no operator transaction
bundle and must instead record finalized external-controller acceptance as
either `eoa_direct_call` or `contract_event_and_state`, with the exact
mode-specific claim and a matching active/frozen dual-RPC contract snapshot.

Running phase 4 in its default verification-only mode does not append this
acceptance record and therefore cannot satisfy live activation. Likewise,
`not_applicable` evidence, an unfinalized revision chain, one current review
substituted four times, or an otherwise valid three-phase ledger remains
fail-closed. Earlier preflight stages do not claim that this completed
post-ceremony evidence already exists.

## Trust boundary

The final-authority digest is a configuration commitment, not TDX evidence. It
does not prove that a CVM exists, Intel DCAP/QVL accepted a quote, a container
ran, a same-RPC finalized tag is consensus-final, or a job executed. Those
claims require separately labeled live-chain, CVM, QVL, and runtime evidence.
A modeled frontend must never present the authority core alone as attestation.

Historical filenames, function aliases, environment variables, and CLI flags
still use `execution-policy-release-core` during migration. Their schema,
domain separator, digest, and validation semantics are the final-authority
definitions above; compatibility naming does not preserve the obsolete design
that hashed packet or review evidence.
