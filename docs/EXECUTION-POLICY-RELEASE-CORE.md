# Final release authority core

Last updated: 2026-07-21

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
  UTF8("dnai-wikigen/final-release-authority-core/v2\0") ||
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

The cross-language known-answer vector is:

```text
vector: dnai.final-release-authority-core.v2/known-answer-1
digest: 04672b23f0eba977245ebc953c242d51859f4c81050587025afc707060730362
```

Node and Python tests must continue to produce that exact digest.

## Committed facts

The authority has these exact top-level keys:

```json
{
  "schema": "dnai.final-release-authority-core.v2",
  "release_sha": "<40 lowercase hex>",
  "network": {},
  "operator_address": "0x...",
  "deployment_intent_sha256": "sha256:<64 lowercase hex>",
  "cvm_launch_intent_sha256": "sha256:<64 lowercase hex>",
  "contracts": {},
  "cvm": {},
  "arena_registry_bindings": {},
  "wallet_auth": {},
  "requested_features": {},
  "execution_policy": {}
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
- browser origins, wallet-auth domain, and requested feature flags;
- the optional public WalletConnect project identifier, represented explicitly
  as either the empty string or exactly 32 lowercase hexadecimal characters;
  and
- execution-policy versions, approver set/root, and the intended anchor target,
  writer identity, launch-intent-bound writer release, custody path, and
  explicitly bounded RPC trust model.

The runtime controls record current fail-closed limitations, including disabled
provider dispatch, hostile candidate execution, deal settlement, and remote
artifact evaluation, plus the raw-secret-egress prohibition.

Changing any committed fact requires a new authority and a new anchor release.
The frozen writer ceremony prevents silently retargeting an activated release.

The v2 schema deliberately replaced the incomplete v1 Compute commitment
fields. A policy commitment does not determine its on-chain payout recipient,
so both provider addresses are first-class authority facts. Both providers
must be distinct from one another and from governance, application contracts,
the main TEE, verifiers, metering control, and anchor roles.

The five configuration helpers consume no operator-authored projection JSON.
`scripts/ceremony-authority-projector.mjs` validates deployment-intent v6 and
final-authority v2, enforces their constructor/static and numeric equality
bindings, and emits exactly 31 named public ceremony assertions. The anchor
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
6. Collect independent anchor-writer QVL evidence and the final chain snapshot.
7. Build the final web candidate with the stable authority hash and current
   review hashes, then run semantic validation with the same authority artifact.

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
