# Deployment Runbook

Last updated: 2026-07-22

This file records Base Sepolia and Phala deployment evidence for the tinker
delegate stack. It is a runbook, not a trust source by itself. The
machine-readable ledger for a fresh release is immutable and release-scoped:

```text
deployments/fresh-contract-suites/$RELEASE_SHA/base-sepolia.json
```

`deployments/base-sepolia.json` is historical evidence only. The fresh deploy
helper rejects that path as either input authority or writable output, refuses
to replace an existing release-scoped ledger, and contains no fallback operator
address. Populate only the pre-deployment inputs below in the untracked `.env`
before even dry-running it:

```dotenv
BASE_SEPOLIA_RPC_URL=...
BASE_SEPOLIA_SECONDARY_RPC_URL=... # HTTPS; normalized host:port must differ from primary
FOUNDRY_KEYSTORE_ACCOUNT=dev
RELEASE_SHA=... # exact nonzero lowercase 40-hex reviewed commit
# Optional absolute override. Empty derives the release-scoped repository path
# deployments/fresh-contract-suites/$RELEASE_SHA/base-sepolia.json.
DEPLOYMENT_MANIFEST_PATH=
DEPLOYMENT_INTENT_PATH=/absolute/path/deployment-intent-core.json
DEPLOYMENT_INTENT_SHA256=sha256:... # immutable reviewed pre-deployment intent
# These legacy-named variables carry the exact deployment-intent review
# envelope; they never identify an operator-policy packet or projection.
OPERATOR_POLICY_REVIEW_ENVELOPE_PATH=/absolute/path/deployment-intent.review-envelope.json
OPERATOR_POLICY_REVIEW_ENVELOPE_SHA256=sha256:...
RELEASE_REVIEWER_AUTHORITY_GENESIS_PATH=/absolute/path/reviewer-authority-genesis.json
RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PATH=/absolute/path/reviewer-authority-genesis-acceptance.json
RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PATH=/absolute/path/reviewer-current-status.json
RELEASE_REVIEWER_AUTHORITY_STATUS_HISTORY_PATH=/absolute/path/reviewer-status-history.json
DEPLOYMENT_OPERATOR=0x...
DILIGENCE_GOVERNANCE_CONTROLLER=0x... # immutable; nonzero and distinct from operator/developer
COMPUTE_VAULT_DEVELOPER=0x...
COMPUTE_VAULT_DEVELOPER_FEE_BPS=100 # explicit; deployment cap is 100 bps
TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT=0x... # derived only by the two-reviewer ceremony below
TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI=5000000000000000000 # policy units; not ETH
TINKER_ENCUMBRANCE_MAX_SPEND_WEI=5000000000000000000 # policy units; not ETH
EMAIL_ORACLE_UPGRADE_DELAY=172800 # explicit; minimum 2 days
BROADCAST=false
VERIFY=false
# Safe process/default environment value. The reviewed production renderer
# replaces this with the release-pinned deterministic, no-network lane.
TINKER_EVALUATOR_MODE=disabled
```

`OPERATOR_POLICY_PACKET_PATH`, `OPERATOR_POLICY_PACKET_SHA256`,
`OPERATOR_POLICY_PROJECTION_PATH`, `FINAL_RELEASE_AUTHORITY_CORE_PATH`, and
`OPERATOR_POLICY_FINAL_AUTHORITY_SHA256` must all be absent during fresh
contract deployment. Final authority and every CVM-derived role exist only
after the contract ledger and measured CVM evidence exist; supplying them at
this stage is a causal-cycle failure, not extra assurance.

## Single activation preflight

First download `dnai-tee-image-release.json` and
`dnai-tee-image-release.bundle.json` from the same clean GitHub Actions
`refs/heads/main` release job for the exact reviewed `RELEASE_SHA`. The
production operator path is main-only: a tag-built or other-ref artifact is not
accepted by the pinned Sigstore receipt verifier. The artifact contains exactly
the five operator-owned linux/amd64 image digests, the exact downloaded SPDX
documents, their GitHub verification bindings, and the signed provenance bundle
for the aggregate manifest. Create and validate the reviewer
genesis/status/acceptance artifacts using the current workflow in
`deployments/operator-authority-artifacts.md`. The account commitment is not an
arbitrary nonzero word and must not be an email, provider account identifier,
or hash of either. Derive it with the two-reviewer ceremony below before
authoring the deployment-intent core. The script filename
`operator-policy-packet.mjs` is retained for its supported intent/review
artifact subcommands only. The retired monolithic packet, `project` command,
and operator-role projection are not accepted:

### Two-reviewer opaque account-binding ceremony

Create a new operator-owned mode-`0700` `.release` directory before deriving
the commitment. Never reuse a previous directory or binding root. Each of the
two active reviewers must independently generate one nonzero 32-byte share
with an operating-system CSPRNG, retain it under separate custody, and provide
it to the ceremony as an already-open mode-`0600`, single-link regular-file
descriptor. The CLI deliberately accepts no share path, encoded share, seed,
stdin, environment value, signer key, RPC URL, or output override:

```bash
set -euo pipefail
REPOSITORY_ROOT="$(cd "$(git rev-parse --show-toplevel)" && pwd -P)"
RELEASE_DIRECTORY="$REPOSITORY_ROOT/.release"
if [[ -e "$RELEASE_DIRECTORY" || -L "$RELEASE_DIRECTORY" ]]; then
  printf '%s\n' \
    "refusing to reuse $RELEASE_DIRECTORY; quarantine the previous generation first" \
    >&2
  exit 1
fi
mkdir -m 0700 "$RELEASE_DIRECTORY"

# Open one independently generated binary share from each custody boundary.
# Only the harmless local paths appear here; the 32 secret bytes never enter
# argv, stdin, an environment variable, an RPC request, or calldata.
exec 3</absolute/reviewer-one-custody/tinker-binding-share.bin
exec 4</absolute/reviewer-two-custody/tinker-binding-share.bin
node "$REPOSITORY_ROOT/scripts/tinker-account-binding-ceremony.mjs" \
  intent-create \
  --release-sha "$RELEASE_SHA" \
  --reviewer-genesis "$RELEASE_REVIEWER_AUTHORITY_GENESIS_PATH" \
  --genesis-acceptance "$RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PATH" \
  --current-status "$RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PATH" \
  --status-history "$RELEASE_REVIEWER_AUTHORITY_STATUS_HISTORY_PATH" \
  --share-fd 3 \
  --share-fd 4
exec 3<&-
exec 4<&-

TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT="$(jq -er \
  '.account_commitment' \
  "$RELEASE_DIRECTORY/tinker-account-binding-intent-core.json")"
export TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT
```

The ceremony can prove exact file posture, share length, nonzero/distinct
values, reviewer assignments, and reviewer declarations; no algorithm can
prove that unknown input bytes actually came from a CSPRNG. Independent
generation and custody are therefore an operational reviewer responsibility.
Reusing the same binding root on Base Sepolia is linkable even though the root
and shares remain private.

Copy only the public commitment into
`staticContractInputs.tinkerAccountEncumbrance.accountCommitment` while
authoring the canonical deployment intent. The intent must bind the same
release SHA, reviewer genesis acceptance, current-status epoch, and
current-status digest. Then produce the normal two-reviewer deployment-intent
review envelope and run both validators:

```bash
node scripts/operator-policy-packet.mjs check-intent \
  --in "$DEPLOYMENT_INTENT_PATH" \
  --receipt-out /absolute/path/deployment-intent.validation-receipt.json

node scripts/operator-policy-packet.mjs check-review \
  --subject "$DEPLOYMENT_INTENT_PATH" \
  --in "$OPERATOR_POLICY_REVIEW_ENVELOPE_PATH" \
  --receipt-out /absolute/path/deployment-intent.review-receipt.json
```

Both reviewers next sign the exact EIP-191 message and payload digest in
`.release/tinker-account-binding-intent.receipt.json`. Assemble those two
address-sorted signatures in a canonical
`dnai.tinker-account-binding-external-signatures.v1` JSON file with the exact
reviewer address/controller pairs and purpose
`tinker_account_binding_intent_reviewer_authorization`. No signer credential
enters the repository ceremony process. Attach, verify, and recheck the fixed
artifacts:

```bash
node scripts/tinker-account-binding-ceremony.mjs ceremony-attach \
  --reviewer-genesis "$RELEASE_REVIEWER_AUTHORITY_GENESIS_PATH" \
  --genesis-acceptance "$RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PATH" \
  --current-status "$RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PATH" \
  --status-history "$RELEASE_REVIEWER_AUTHORITY_STATUS_HISTORY_PATH" \
  --deployment-intent "$DEPLOYMENT_INTENT_PATH" \
  --reviewer-signatures /absolute/path/tinker-binding-reviewer-signatures.json

node scripts/tinker-account-binding-ceremony.mjs ceremony-verify \
  --reviewer-genesis "$RELEASE_REVIEWER_AUTHORITY_GENESIS_PATH" \
  --genesis-acceptance "$RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PATH" \
  --current-status "$RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PATH" \
  --status-history "$RELEASE_REVIEWER_AUTHORITY_STATUS_HISTORY_PATH" \
  --deployment-intent "$DEPLOYMENT_INTENT_PATH"

node scripts/tinker-account-binding-ceremony.mjs ceremony-check \
  --reviewer-genesis "$RELEASE_REVIEWER_AUTHORITY_GENESIS_PATH" \
  --genesis-acceptance "$RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PATH" \
  --current-status "$RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PATH" \
  --status-history "$RELEASE_REVIEWER_AUTHORITY_STATUS_HISTORY_PATH" \
  --deployment-intent "$DEPLOYMENT_INTENT_PATH" >/dev/null
```

`ceremony-check` is read-only. Fresh attachment, verification, rendering, and
contract deployment require the intent-pinned reviewer status to be current.
Later activation checks may cryptographically replay the signed ceremony
against an authenticated advanced status history, but that historical replay
proves only that the signed declared timestamp was inside the old status
window; it never re-labels an old status as current.

Render the seven production CVM descriptors directly from the canonical
deployment intent, verified binding-ceremony receipt, and two clean-CI image
artifacts. The renderer preserves the four fixed ceremony artifacts already in
the new `.release` directory and measures the receipt's canonical
`tinker_account_binding_ceremony_receipt_sha256` into both one-shot genesis
services:

```bash
set -euo pipefail
REPOSITORY_ROOT="$(cd "$(git rev-parse --show-toplevel)" && pwd -P)"
cd "$REPOSITORY_ROOT/⚙️/tinker-delegate"
uv run --frozen tinker-release-composes \
  --manifest /absolute/path/dnai-tee-image-release.json \
  --manifest-attestation-bundle /absolute/path/dnai-tee-image-release.bundle.json \
  --deployment-intent "$DEPLOYMENT_INTENT_PATH" \
  --account-binding-ceremony-receipt \
    "$RELEASE_DIRECTORY/tinker-account-binding-ceremony.receipt.json" \
  --release-sha "$RELEASE_SHA" \
  --output-dir "$RELEASE_DIRECTORY"
```

Do not automatically remove, overwrite, or rename an existing `.release`
directory. Review its immutable receipt and generation first, then manually
quarantine the whole directory before creating the new empty mode-`0700`
directory. The atomic `mkdir` also fails if a path appears after the explicit
check.

The production renderer sequence accepts only `therealwiki/dnai-wikigen`, the
repository's pinned TEE-image workflow, `refs/heads/main`, one exact source SHA,
linux/amd64, and the canonical five-image order. Although the lower-level
renderer also recognizes a `v*` tag for non-production tooling, the production
receipt verifier deliberately does not. The renderer rejects extra fields,
mutable tags, digest drift, or incomplete attestation metadata before writing.
It publishes these generation-bound artifacts:

```text
.release/dnai-main-runtime.phala.yaml
.release/dnai-diligence-qvl.phala.yaml
.release/dnai-arena-qvl.phala.yaml
.release/dnai-anchor-writer-qvl.phala.yaml
.release/dnai-compute-workload-qvl.phala.yaml
.release/dnai-compute-metering-qvl.phala.yaml
.release/dnai-independent-metering.phala.yaml
.release/dnai-tee-image-release.json
.release/dnai-tee-image-release.bundle.json
.release/dnai-deployment-intent-core.json
.release/dnai-cvm-topology.json
```

Before activation preflight, cryptographically verify the exact copied
manifest and bundle and persist the canonical production receipt:

```bash
REPOSITORY_ROOT="$(cd "$(git rev-parse --show-toplevel)" && pwd -P)"
node "$REPOSITORY_ROOT/scripts/release-manifest-sigstore-verification-cli.mjs" \
  --repository-root "$REPOSITORY_ROOT" \
  --release-sha "$RELEASE_SHA"
```

The producer accepts no manifest, bundle, or output path overrides. It reads
the two exact filenames above, invokes the repository-pinned `gh` runtime with
the exact repository, workflow, source-ref, source-SHA, SLSA predicate, and
GitHub-hosted-runner policy, then writes only:

```text
.release/dnai-tee-image-release-manifest-sigstore-verification.json
```

The `.release` directory must be the new canonical, operator-owned `0700`
directory created above. The receipt is canonical JSON, mode `0600`,
single-link, durable, and create-only. An existing regular file, symlink, or
hard link is never replaced. If the target nevertheless exists, stop and
quarantine the entire generation, then render again into a newly created empty
`0700` directory; do not delete or overwrite only the receipt merely to make
the command pass. The success
output contains only public release hashes and receipt commitments. Captured
`gh` output, credentials, environment secrets, and absolute operator paths are
not projected.

The current production receipt authority is intentionally operator-platform
specific: macOS on Apple silicon with Homebrew `gh` at
`/opt/homebrew/Cellar/gh/2.87.3/bin/gh`, version `2.87.3`, and binary digest
`sha256:67b51ba8ca861e0fcd4749d47eba740e8db8c799a8b18645833e904e09f7fb70`.
An absent executable or any path, version, or digest drift fails closed. This
does not claim a reviewed Linux tool pin.

The verifier never executes the mutable Homebrew pathname after inspecting it.
It runs both version and attestation commands from one randomized,
operator-owned private copy of the verified bytes, then removes that copy
before returning a receipt. The deterministic `verification_command_sha256`
commits the reviewed logical pathname, exact pinned executable digest, fixed
`dnai.pinned-gh-execution.private-verified-copy.v1` execution policy, and exact
arguments. The randomized private pathname is ephemeral and is intentionally
not represented as the command authority in the receipt.

The renderer requires exact canonical `dnai.deployment-intent-core.v6` bytes,
re-runs the fixed intent checker, re-reads the file to close the checker/use
race, and requires the same release SHA as the image manifest. It independently
bounds the public QVL and metering numeric maps, checks their timeout arithmetic
and relational bindings, then pins those exact values into the runtime service
environment instead of leaving mutable Compose defaults. Each isolated QVL and
metering descriptor carries its own public `x-dnai-runtime-policy` numeric map.
The external topology commits to the deployment-intent digest and exact copied
intent bytes, copies the six-domain policy bindings, and hashes every rendered
descriptor.

The deployment-intent hash is deliberately **not** substituted for any runtime
compose hash.
`releaseBindings.mainRuntime.composeHash` is the eventual platform-attested
runtime compose hash used by the contract allowlists; placing an authority hash
back into the bytes that determine that compose hash would create a
cryptographic cycle. The release therefore keeps four distinct commitments:
the topology's raw descriptor-file SHA-256, the local Phala app-compose hash,
the rendered `docker compose config` SHA-256, and the platform-attested runtime
compose hash. Activation must verify those named fields at their own evidence
boundaries instead of treating them as interchangeable. These are audit
commitments, not proof of reviewer signatures, key control, deployment, or TDX.

Publication is fail-closed but is not one ten-file filesystem transaction.
Every referenced file is written with a synced temporary file and atomic
replacement; `dnai-cvm-topology.json` is always replaced last as the generation
commit marker, then the output directory is synced. If a write fails before the
last step, no new topology is published. A prior topology may remain beside
newer individual files, but its recorded hashes will not match, so activation
must reject the mixed directory. Operators must never deploy loose files from
the directory without first passing the topology/hash checks in the activation
preflight.

The renderer's copied deployment intent is a public, immutable authority input,
not a credential or activation receipt. The later launch-intent builder must
match it to the immutable fresh-contract receipt, release-scoped ledger, and
topology-bound copy. A structurally valid intent from another release cannot be
substituted, and rendering alone proves neither deployment nor TDX.

The image workflow treats the pushed linux/amd64 image manifest as the stable
subject and attaches supply-chain evidence to that exact digest. Buildx
`v0.29.1`, BuildKit `v0.25.2`, the BuildKit image digest, the base images, `uv`,
and Syft `v1.44.0` are all explicit inputs. A fixed source-controlled
`SOURCE_DATE_EPOCH` controls the image config, OCI label, wheel/tar metadata,
and exporter timestamp rewriting. Debian packages resolve only from the
snapshot dates recorded in the digest-pinned bases; top-level packages are also
exact-version requests. Python projects are installed from `uv.lock` as
non-editable wheels and their virtualenv metadata is canonicalized.

BuildKit's inline provenance and SBOM exporters are intentionally disabled:
their per-run invocation IDs and build timestamps would change the root image
index even when the runnable manifest and config are identical. Instead, the
pinned Anchore action emits the exact SPDX artifact and two pinned
`actions/attest` invocations publish signed SLSA provenance and SPDX predicates
against `${{ steps.build.outputs.digest }}`. The release job independently runs
`gh attestation verify` for both predicates on each literal
`repository@sha256:digest` before it will aggregate the manifest. This preserves
verifiable per-run evidence without mislabeling the evidence-bearing registry
objects themselves as bit-reproducible.

Aggregation also reopens exactly five canonical SPDX files, rejects symlinks,
non-SPDX input, extra files, and size violations, and compares every exact byte
hash with the image descriptor produced in its build job. GitHub then attests
the aggregate manifest and the release artifact carries the resulting Sigstore
bundle under the deterministic name above. The renderer treats that bundle as
opaque signed evidence, copies it with a no-follow bounded read, and records its
SHA-256 in the v6 topology. The online activation preflight is the cryptographic
gate: it verifies the exact copied manifest bytes against that bundle, the
pinned workflow, source SHA/ref, SLSA predicate, and GitHub-hosted runner policy.

Compare rebuilds with the same exporter. An OCI archive uses OCI manifest media
types, while the workflow's `type=image` GHCR exporter uses Docker distribution
media types by default; those manifest digests differ even when the config and
every ordered layer digest are identical. The subject signed and verified by
GitHub is always the literal `${{ steps.build.outputs.digest }}` emitted by the
registry exporter, never a digest copied from a separate OCI archive.

The main descriptor contains Neko, the email oracle, delegate, Arena policy
initializer/worker, the one-shot anchor-writer evidence ceremony, and the
profile-gated Compute worker. Diligence, Arena, anchor-writer, Compute-workload,
and Compute-metering QVL plus the independent deterministic meter are six
separate CVM descriptors outside the main runtime. The Compute profile remains labeled
`release_pinned_provider_runtime_gated`; rendering a descriptor does not
enable or deploy it. Every output remains `rendered_not_deployed` and explicitly
claims neither TDX verification nor deployment.

### Challenge-bound QVL release gate

Deploy five independently controlled QVL CVMs: Diligence, Arena, anchor-writer,
Compute-workload, and Compute-metering. Reusing the `attestation-qvl` image is
expected; reusing an app/CVM identity, policy hash, signer root, bearer, or HTTPS
origin is not. The Diligence policy may additionally enable the exact
`email_oracle_kms_restart` profile; that profile shares only the Diligence root
and does not create a sixth QVL root or eighth CVM.

For every workload proof, send the exact
`dnai.attestation-qvl-challenge-request.v2` lineage tuple and authenticate
`POST /challenge`. Verify the returned
`dnai.attestation-qvl-challenge.v2` signature, Base Sepolia chain, QVL
domain/profile, CVM ID, deployment intent, release authority, ceremony nonce,
measurement policy, policy hash, trusted verifier, and lifetime against
persisted release authority. Bind its challenge digest in quote report-data
bytes 32–63; bytes 0–31 contain the independently recomputed static release
digest. Submit that exact raw quote only to authenticated `POST /verify` and
accept only `dnai.independent-tdx-verdict.v4` under signing domain
`dnai-wikigen/independent-tdx-verdict/v4\0`, with the full lineage,
challenge/profile/policy/workload fields, canonical Phala app/compose/OS
measurements, and signature reverified. The signed challenge is single-use and
valid for at most 120 seconds. DCAP appraisal must complete strictly before its
expiry; success, rejection, timeout, and cancellation consume it. A successful
v4 appraisal carries the separately reviewed exact 900-second
activation-evidence lease. That policy-bounded lease may outlive the consumed
challenge but does not renew challenge freshness. Never cache a challenge or
reuse a verdict as freshness evidence for another release action.

After the reviewed restart, Compute ingress accepts only
`dnai.compute.workload-recipient-activation.v3`. Its explicit
`recipient_evidence_lease_expires_at` must equal activation expiry and may be
at most 300 seconds after issuance. The stable recipient-release commitment
remains `dnai.compute.workload-recipient-release.v2`; do not relabel that stable
commitment as activation v3 or treat it as a fresh QVL challenge.

Before trusting any QVL root, an external activation verifier must send an
exact `dnai.qvl-identity-attestation-request.v3` challenge to authenticated
`POST /attestation` and independently DCAP-verify the
`dnai.qvl-identity-attestation-response.v3` raw quote. Require the response to
echo the externally supplied full lineage and canonical Phala app/compose/OS
measurements; require its own verifier address and release-policy hash in the
static report-data digest; and require the external challenge digest in bytes
32–63 of the exact 64-byte report data. The external verifier owns the
single-use challenge ledger. `GET /identity`, a local policy hash, environment
validation, or a QVL verifying its own quote is not root-admission evidence.
Until all five QVL roots pass this external ceremony, the release remains
blocked.

Keep launch-time lineage values in their canonical lifecycle classes. The
deployment intent, ceremony nonce, and linked measurement-policy roots are
bootstrap-static inputs. The main-runtime and independent-metering CVM IDs are
provisioning results derived from the validated Phala prepare response, never
operator-authored descriptor inputs. Release-authority roots and the
main-runtime-evidence digest are post-measurement values: initial services stay
fail-closed with empty late-bound placeholders until an authenticated encrypted
environment update installs them and the relevant profile/service is restarted.
This ordering prevents a descriptor or deployment-intent hash from circularly
committing to evidence that can only be created after that descriptor launches.

### Resident production activation driver

Prepare the driver's four private filesystem authorities with a canonical,
recursively key-sorted request containing exactly one trailing newline:

```json
{
  "authorities": {
    "evidenceExchangePath": "/absolute/private/evidence",
    "outputPath": "/absolute/private/outputs",
    "postlaunchAuthorityExchangePath": "/absolute/private/postlaunch-authority",
    "signingExchangePath": "/absolute/private/signing"
  },
  "schema": "dnai.phala-production-authority-workspace-prepare-request.v2"
}
```

The request must be an owned, regular, single-link mode-`0600` file. Run the
non-authorizing filesystem setup for the reviewed paths:

```bash
node scripts/phala-production-authority-workspace-prepare.mjs \
  --prepare-request /absolute/private-workspace-request.json
```

The tool creates or strictly reopens only four empty mode-`0700` directories,
pins their filesystem identities, and prints a path-plus-anchor receipt. It
mints no capability, authorizes no activation mutation, automatic retry, or
live traffic, and proves no deployment or TDX evidence. Independently review
that receipt and seal its exact path-plus-anchor pairs into the resident request
before invoking the source-real driver as one exact operation:

```bash
node scripts/phala-production-activation-driver.mjs \
  --execute-request /absolute/private-resident-request.json
```

The `dnai.phala-production-activation-driver-request.v3` resident request must
be canonical recursively sorted JSON in an owned, single-link, mode-`0600` file
and contain only prelaunch bindings. It has no `reviewerStatusHistory` field;
request v2 and a v3 request carrying that legacy extra field are
non-authorizing. Stage A consumes exactly the epoch-one genesis acceptance with
an empty predecessor array. The request also excludes every reviewed
final-authority, deferred-review, ceremony, and immutable-manifest dependency.
The process retains the non-serializable authority chain from the non-live
seven-CVM launch through five QVL-identity proofs and two workload verdict
proofs, then durably persists L and its private historical transcript before
its first final-authority read.

The driver then publishes only canonical L plus the allowlisted non-authorizing
`postlaunch-final-authority-input.json` and
`postlaunch-authority-request.json` files in the evidence exchange. The latter
is `dnai.phala-production-postlaunch-authority-request.v2` and requires
`dnai.phala-production-postlaunch-activation-input-manifest.v2`. It waits for
one exact canonical mode-`0600`
`postlaunch-activation-input-manifest.json` in the independently pinned,
initially empty postlaunch exchange. That manifest binds the reviewed
final-authority, deferred-review, ceremony, and immutable-manifest paths and
digests plus `stageBReviewerStatusHistory` to the exact release, batch,
evidence, L, projection, and request lineage. The history binding names an
operator-owned, regular, single-link, exact mode-`0600` canonical bare array,
not the wrapped reviewer-history CLI artifact. Use exactly `[]` while the
epoch-one root is current; selecting a successor requires the exact pinned root
followed by every guardian-signed successor through the current head. The
detailed exact manifest shape is in
`deployments/operator-authority-artifacts.md`.

The driver computes one exact canonical-millisecond
`manifest_acceptance_deadline` before request publication as the
earlier of the configured postlaunch-authority timeout and L's minimum evidence
lease expiry. It writes that same timestamp to the request and public
checkpoint. Copy it byte-for-byte into manifest v2: the waiter and helper do
not recompute or refresh it, and arrival at or after the deadline fails closed.
Manifest v1 cannot mint the one-shot capability.

Build the complete canonical manifest as an owned, single-link, exact
mode-`0600` source file outside the exchange, then use only the non-signing
attachment helper to validate and publish it:

```bash
node scripts/phala-production-postlaunch-attach.mjs \
  --source /absolute/private/postlaunch-activation-input-manifest.source.json \
  --request /absolute/private/evidence/postlaunch-authority-request.json \
  --projection /absolute/private/evidence/postlaunch-final-authority-input.json \
  --exchange /absolute/private/postlaunch-authority \
  --expected-anchor-sha256 'sha256:<exact-workspace-receipt-anchor>'
```

The helper computes the exact raw request/projection digests, validates every
bound dependency including the retained history raw digest, and accepts no key,
signer, RPC, credential, callback, or raw secret. Its final basename is created
once at mode `0200`; the exact bytes and directory entry are fsynced before the
same inode changes to `0600` as the readiness commit. The resident waiter never
parses `0200`. The helper checks the fixed deadline immediately before the
readiness transition; because the clock check and `chmod` are not one
kernel-atomic operation, the resident reader independently rechecks that same
deadline and rejects a scheduler-delayed transition. An interrupted pending
inode, inode replacement, wrong mode, unexpected entry, or deadline is terminal
for that evidence session; do not edit, remove, replace, or retry it.

Only after stable no-follow validation of that manifest and all dependencies
does the same process enter externally signed Stage B, encrypted-environment
mutation and restart, post-restart Compute recipient activation, finalization,
and bounded-output publication. Raw quotes remain confined to the private
evidence exchange and durable private historical transcript; none enter L's
public projection or the postlaunch request. Phase secrets, raw private
artifacts, and encrypted-environment ciphertext never enter that projection.
The validated manifest becomes only an opaque same-process one-shot capability
bound to the exact evidence session and persisted L checkpoint. The coordinator
burns it before interpreting proof-array references and before reading reviewed
final authority. Any timeout, extra exchange entry, symlink,
mode/hash/lineage drift, dependency mutation, post-mint driver failure, or
coordinator rejection burns that capability and disposes the session before
post-measurement mutation.

After capability consumption and semantic validation against the reviewed
deployment intent, the resident driver publishes
`dnai.phala-production-stage-b-attachment-manifest.v2` in the pinned signing
exchange. It binds the retained history's raw file digest and the Stage-B
review payload's exact current reviewer-status epoch and digest. Supply the two
external signatures in the code-named canonical input, then attach them with:

```bash
node scripts/phala-production-stage-b-attach.mjs \
  --exchange /absolute/private/signing \
  --expected-anchor-sha256 'sha256:<exact-workspace-receipt-anchor>'
```

The resulting `dnai.phala-production-stage-b-attachment-receipt.v2` repeats
those three values only as transport/replay bindings. The helper does not sign,
accept key material, deploy, activate, or establish TDX evidence; the same
process must still validate signed B, whose expiry is capped by the selected
reviewer status's signed expiry.

Checkpoints forbid automatic retry and live traffic; the final result also
records `capability_serialized=false` and
`signer_key_material_accepted=false`.

This driver is implemented and locally tested. It has not run against a fresh
project-owned seven-CVM production topology, does not deploy anything merely by
existing, and does not authorize live traffic. Treat its result as bounded
non-live activation evidence only.

Arena ChallengeRegistry admission follows three separate launch-authority
classes; do not populate its environment from an operator-authored map. The
`TINKER_ARENA_REGISTRY_RPC_URL` is a secret in the
`final_authority_runtime` class and is installed only through Phala's encrypted
environment. `TINKER_ARENA_REGISTRY_ADDRESS`,
`TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH`,
`TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON`, and
`TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256` are deferred public
values. `scripts/challenge-registry-authority-projector.mjs` derives them from
the canonical final-release-authority bytes, carries an in-process provenance
brand, and binds the result to the final-authority digest, release SHA,
deployment intent, and CVM launch intent before the deferred public-environment
projector can accept it. A structurally valid operator-authored copy does not
regain that provenance. The approved bindings are canonical finite-catalog JSON
and the approved-set digest is recomputed from those bindings.

`TINKER_ARENA_REGISTRY_MAX_BLOCK_AGE_SECONDS=300` and
`TINKER_ARENA_REGISTRY_MAX_FUTURE_BLOCK_SKEW_SECONDS=30` are fixed descriptor
defaults. They are deliberately outside Phala's encrypted operator-overridable
environment. Leave the pre-release placeholders empty until the canonical
secret and public authority projectors install their exact values; the Arena
API must remain fail-closed before then. Never invent, hand-copy, or infer any
of these launch values from browser state or an earlier deployment.

### Email oracle runtime release gate

The email oracle is not release-ready merely because `EmailOracleAuth` was
deployed or because its CVM produced a quote. The final runtime descriptor must
bind `EMAIL_ORACLE_AUTH_ADDRESS` to one exact, nonzero contract address,
`EMAIL_ORACLE_AUTH_RUNTIME_CODE_HASH` to the Ethereum `keccak256` hash of the
code returned by `eth_getCode` for that address,
`EMAIL_ORACLE_CONSUMER_APP_ID` to one nonzero consumer app address, and
`EMAIL_ORACLE_CONSUMER_COMPOSE_HASH` to one nonzero consumer compose hash. Do
not use the creation bytecode hash, deployment transaction hash, source hash,
or a hash copied from an older deployment as
`EMAIL_ORACLE_AUTH_RUNTIME_CODE_HASH`.

`BASE_SEPOLIA_RPC_URL` and `BASE_SEPOLIA_RPC_URL_SECONDARY` must be HTTPS
endpoints with different normalized `host:port` values. Use independently
operated providers so one provider failure is not duplicated behind two DNS
names. The startup configuration mechanically rejects HTTP, embedded URL
credentials, fragments, missing hosts, or the same normalized host for both
inputs. RPC URLs commonly contain provider credentials: keep them only in the
untracked `0600` deployment environment and never print a rendered descriptor
or `docker compose config --environment` in a log.

Both source variants carry the same exact release policy:

- `docker-compose.all.phala.yaml` is the historical digest-pinned Phala
  descriptor.
- `docker-compose.all.dstack.yaml` is an overlay, never a standalone compose.
  The fresh release renderer combines its reviewed settings with the Phala
  template, replaces every image with the clean-CI release digest, and emits
  `.release/dnai-main-runtime.phala.yaml`. The documented
  `docker-compose.all.yaml` plus dstack overlay remains a source-build
  rehearsal, not production deployment evidence.

The profile-gated `collaboration-execution-worker` intentionally exists only
in the current dstack overlay and the renderer's emitted main-runtime
descriptor. Its absence from the historical Phala base is expected; deploying
that base by itself cannot enable Collaboration execution. The renderer copies
the worker into the existing `main_runtime_cvm`, pins its release image, and
validates its isolated egress, exact environment holders, and read-only dstack
socket. It does not create an eighth CVM.

For a syntax/merge check without reading real secrets, populate every required
`${NAME:?message}` input with a syntactically valid, non-secret placeholder in
a process-scoped environment. Use two different `https://*.invalid` RPC hosts,
distinct non-default Neko placeholder passwords, nonzero placeholder addresses,
and nonzero placeholder bytes32 values. Then validate quietly:

```bash
cd "⚙️/tinker-delegate"
docker compose -f docker-compose.all.phala.yaml config --quiet
docker compose \
  -f docker-compose.all.phala.yaml \
  -f docker-compose.all.dstack.yaml \
  config --quiet
```

`--quiet` is mandatory in shared logs because the full rendered output would
contain resolved environment values. A successful parse proves only Compose
syntax and interpolation. It does not prove the placeholder values, images,
contract, KMS registration, or CVM are a valid release; run the release
renderer and activation preflight with reviewed evidence for that claim.

At process startup, production settings fail closed unless all of the following
remain exact:

- dstack mode, same-CVM runtime bearer authentication, and on-chain
  `EmailOracleAuth` checks are enabled; static runtime bearer material is empty
  and the derived-key path is exactly `oracle/runtime-auth`;
- automatic mailbox genesis and the credential-provisioning endpoint are
  disabled, its token is empty, credential and OTP replay stores are exactly
  `/data/credentials.enc` and `/data/otp_replay.enc`, their static keys are
  empty, and their dstack key paths are exactly `email/creds` and
  `email/otp_replay`;
- chain ID is exactly Base Sepolia `84532`, the two distinct HTTPS RPC hosts
  agree on one common finalized block, the block is at most 900 seconds old and
  no more than 30 seconds in the future, and the code bytes and exact runtime
  code hash agree at that block;
- both RPCs return identical `releaseConfigurationReady() == true` and
  `isConsumerAuthorized(appId, composeHash) == true` values at that same block,
  and the block is unchanged when re-read after the contract calls; and
- the request carries the canonical scope label `tinker-delegate.signup` and
  the finalized-block checkpoint is readable and atomically writable at
  `/data/email_auth_checkpoint.json` on the named `oracle-data:/data` volume.

The caller label is not an attestation or a cryptographic identity assertion.
The same-CVM dstack-derived bearer proves possession of the shared runtime
secret; the fixed label narrows that authenticated capability to the signup
path; and the configured app ID plus compose hash are the values checked
on-chain. Do not describe the body field alone as service identity proof.

The durable checkpoint rejects a lower finalized height or a different hash at
the same height across normal requests and process/CVM restarts that preserve
`oracle-data`. It is not hardware-backed anti-rollback. An administrator or
host able to restore the entire CVM persistent volume to an older snapshot can
also restore the checkpoint. Distinct RPC agreement and the 900-second
freshness bound limit the useful rollback window but do not remove that
residual. A production claim of storage anti-rollback requires an external
monotonic anchor or equivalent independently durable state; until then record
this persistent-volume rollback capability as an explicit trust assumption.

Before any contract broadcast, CVM deployment, release activation, or
Cloudflare Pages deployment, run the bounded repository-root preflight for the
exact next authority stage. `--stage` is mandatory at the CLI boundary; the
tool never guesses that a predeployment checkout is already at live activation:

```bash
node scripts/activation-preflight.mjs \
  --stage fresh-deployment \
  --deployment-intent "$DEPLOYMENT_INTENT_PATH"
```

The preflight intentionally does **not** accept
`--authority-review-envelope` or `--authority-review-evidence`. Those retired
renewable-envelope flags are an unknown-argument failure, not a way to supply
current stage authority. The fresh deployment helper separately validates the
exact operator-policy review receipt and evidence named by the
`OPERATOR_POLICY_REVIEW_ENVELOPE_*` environment inputs before broadcast; do
not pass those files to this read-only preflight.

After each irreversible boundary, rerun the same command with exactly one of
`--stage cvm-launch`, `--stage release-ceremony`, or
`--stage live-activation` and the artifacts for that stage. A final-stage
report is not a substitute for the earlier transition gates, and expected
postdeployment evidence must not be fabricated to make an earlier report look
complete.

By default the preflight reads the exact producer filenames
`.release/dnai-deployment-intent-core.json`,
`.release/cvm-launch-intent-core.json`, the five-image manifest, its bundle and
pinned-Sigstore verification receipt, the seven-CVM topology, the seven
rendered Compose descriptors, and the other stage-specific generated files
under `.release`. Retired review-envelope files are not preflight authority.
When `DEPLOYMENT_INTENT_PATH` or `DEPLOYMENT_MANIFEST_PATH` is populated, it is
an absolute-path environment override of that default. The deploy helper consumes
`OPERATOR_POLICY_REVIEW_ENVELOPE_PATH` at its separate mutation boundary. A
different explicit CLI path and environment path is an ambiguity failure; the
operator must choose one exact input. When neither `--ledger` nor
`DEPLOYMENT_MANIFEST_PATH` is supplied, the preflight derives
`deployments/fresh-contract-suites/$RELEASE_SHA/base-sepolia.json` only after
`RELEASE_SHA` exactly matches Git HEAD. The historical root
`deployments/base-sepolia.json` is rejected even when named explicitly.

Use
`--compose`, `--diligence-qvl-compose`, `--arena-qvl-compose`,
`--anchor-writer-qvl-compose`, `--compute-workload-qvl-compose`,
`--compute-metering-qvl-compose`,
`--metering-compose`, `--image-release`,
`--image-release-attestation-bundle`,
`--image-release-sigstore-verification-receipt`, and `--topology` only to point
at another reviewed release directory. Override the manifest, bundle, and
receipt together; never mix those three files across directories. It
independently rechecks all literal digest pins, platform pins, service topology,
one-shot/profile gates, image-manifest binding, and the hashes of all seven
compose files. A historical `docker-compose.all.phala.yaml` is deliberately not
the default and cannot satisfy the fresh-release topology.

Other stage-specific evidence paths may be supplied through
`ACTIVATION_RELEASE_CANDIDATE_PATH`,
`ACTIVATION_ARTIFACT_EVIDENCE_PATH`,
`ACTIVATION_ARENA_EVIDENCE_PATH`, and
`ACTIVATION_ANCHOR_WRITER_EVIDENCE_PATH` in the untracked `0600` `.env`.
Use `--json` for a machine-readable handoff or `--skip-network` for an offline
structural report. A blocked report exits 1; a preflight-internal failure exits
2. The report is deliberately bounded and contains check IDs rather than
credential values, wallet addresses, RPC URLs, CLI stderr, or remote account
details.

`VERIFY=true` is blocking only at `fresh-deployment`, where all seven source-
verification submissions must accompany the reviewed broadcast. The helper's
create-new `dnai.basescan-verification-submission-receipt.v1` proves only that
the submission commands returned successfully; its status is deliberately
`submitted_not_confirmed`. It does not prove that BaseScan has published or
matched the source. Confirm all seven explorer pages separately before routing
production traffic. At later stages `VERIFY` is informational and ignored;
their authority comes from the immutable receipt and independent chain
evidence. `BROADCAST` remains ignored by preflight at every stage.

The legacy assignment names `JUDGE_PRIVATE_KEY` and `KMS_PRIVATE_KEY` are
forbidden even when empty. Their presence fails environment hygiene without
reading or printing either value. Remove the assignments and use the encrypted
Foundry `dev` keystore plus the documented dstack derivation paths.

The probe command has a source-level command allowlist. It reads git state,
checks that the encrypted `dev` alias exists without unlocking it, reads the
Base Sepolia chain ID, performs `gh auth status`, `phala status`, and
`wrangler whoami`, and verifies GitHub SLSA/SPDX attestations for exact image
digests when the source tree is clean. It never invokes a Foundry script,
`--account`, `--broadcast`, `phala deploy`, `wrangler pages deploy`, a login
command, a registry push, or any remote mutation. Even if `BROADCAST=true` is
present, it is reported and ignored.

`READY` means that the inputs visible to this non-unlocking, read-only gate are
complete. It does not authorize a deployment and cannot prove that the
encrypted `dev` key resolves to `DEPLOYMENT_OPERATOR`; the production helper
performs that one remaining signer check immediately before the separately
approved broadcast. Likewise, the exact release generator and live post-state
checks remain mandatory; do not treat this summary as TDX/QVL evidence.

`DEPLOYMENT_OPERATOR` must equal the address derived from the encrypted Foundry
keystore account named `dev`. At the fresh-deployment and CVM-launch gates, only
that operator and `COMPUTE_VAULT_DEVELOPER` are constructor-stage roles; they
must be nonzero and distinct. `DILIGENCE_RESULT_VERIFIER`,
`COMPUTE_VAULT_METERING_VERIFIER`, and
`COMPUTE_VAULT_METERING_QVL_VERIFIER` are bound later by the canonical reviewed
post-deployment helpers, so they are not accepted as early-stage authority.
Release-ceremony and live-activation gates require all five roles to be nonzero
and pairwise distinct. The remaining QVL and execution-policy approver roots
are established from independently reviewed release evidence and are distinct
again. A broadcast also requires a clean git worktree so the recorded source
commit identifies the exact deployed code.

Run the default dry-run first:

```bash
cd "⚙️/tinker-delegate/contracts"
./scripts/deploy-base-sepolia.sh
```

The helper builds and tests everything, verifies the RPC reports chain ID 84532,
dry-runs `DeployFreshSuite.s.sol`, and exits without changing chain or manifest
state because `BROADCAST=false`. After reviewing the simulation, explicitly set
`BROADCAST=true`. A broadcast uses literal Foundry `--account dev`; it unlocks
that encrypted keystore, checks the derived signer against
`DEPLOYMENT_OPERATOR`, and never accepts a raw key or `--private-key` flag.
Before the helper lists a wallet, starts that dry run, or reaches any broadcast
branch, it runs the read-only `ceremony-check` against the four fixed
`.release/tinker-account-binding-*` artifacts, the exact deployment intent,
and the absolute reviewer genesis, signed genesis acceptance, current-status,
and complete status-history paths named by `RELEASE_REVIEWER_AUTHORITY_GENESIS_PATH`,
`RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PATH`,
`RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PATH`, and
`RELEASE_REVIEWER_AUTHORITY_STATUS_HISTORY_PATH`. That deployment gate accepts
only a fresh, current two-reviewer receipt whose public account commitment,
deployment-intent digest, reviewer lineage, chain ID `84532`, and provider
namespace all match. A historically replayable receipt is useful at later
activation stages, but cannot authorize a new simulation or broadcast.
When `BROADCAST=true`, the helper repeats that full current-authority replay
after the reviewed dry run, nonce check, and balance check and immediately
before unlocking `dev`. The second canonical receipt must be byte-identical to
the first, so status expiry or authority/artifact drift during compilation and
simulation fails before signer access.
The read-only activation preflight deliberately reports signer and gas
sufficiency as unproven; a merely nonzero balance is not readiness evidence.
The fresh-suite helper closes that operational gate from the same immutable
release worktree: it requires Forge's machine-readable dry-run artifact to be
the exact ordered 13-transaction plan, pins the gas-unit estimate multiplier at
130%, derives the required wei from Forge's internally consistent gas-price and
amount projection, applies a further code-owned 2x balance margin, and re-reads
both balance and nonce immediately before unlock/broadcast. The broadcast pins
the simulated gas price. If any projection is absent, malformed, inconsistent,
or exceeds the operator balance, no transaction is attempted. This is a
bounded deployment-gas gate, not a promise that future governance phases are
funded; each later phase must be simulated and funded separately.

The reviewed testnet suite deploys:

1. `DiligenceRoom` with no result verifier or pending verifier proposal, its
   reviewed 100 bps protocol fee permanently frozen, and the one-way
   deterministic 100 bps compute-settlement policy enabled before exposure.
   The result verifier, QVL binding, compose, and TEE identity are admitted only
   through the post-deployment timelocked release ceremony. Both TEE approval
   gates are enabled and their requirements are irreversibly frozen with empty
   allowlists, so the release is fail-closed pending verified CVM binding. The
   deployment operator is only the initial developer. The reviewed deployment
   intent and constructor immutably pin `DILIGENCE_GOVERNANCE_CONTROLLER` as the
   sole initial handoff target and production fee recipient; the measured final
   release authority must repeat the same address. The ceremony proposes it only
   after every Diligence authority set is frozen, and the room stays fail-closed
   until that exact controller accepts after another two-day review window.
2. `TinkerAccountEncumbrance` with an explicit account commitment and positive
   per-operation policy-unit caps no greater than the hard `10e18` ceiling,
   halted with empty compose and manager authority sets. The spend cap cannot
   exceed the add-balance cap. It cannot authorize an operation until the
   complete exact release policy, including the first compose and manager set,
   survives its separate two-day review ceremony.
3. `RoyaltyDistributor`, owned by `DEPLOYMENT_OPERATOR` but deployed paused
   with no settlement verifier, QVL verifier, policy anchor, release policy, or
   pending authority. Its constructor binds the operator; runtime reconstruction
   and the deployment ledger therefore use `constructor(address)`. The contract
   cannot accept a settlement until the separate royalty release ceremony
   admits three distinct roles: settlement CVM, independent QVL verifier, and
   the already-frozen `ExecutionPolicyAnchor` writer.
4. `ChallengeRegistry`, an owner-controlled, versioned metadata/commitment
   registry with forward-only lifecycle, independent governance/controller
   emergency pause latches, a two-day public review delay after every version,
   and irreversible per-challenge configuration freeze.
5. `ComputeCreditVault`, with distinct developer and independent metering roots,
   an immediately frozen developer fee, non-transferable exact-asset credits,
   and empty compose/TEE/rate admission so execution starts fail-closed.
6. `EmailOracleAuth`, owned by the same explicit operator and initialized with
   the explicit upgrade delay, `allowAnyDevice=false`, no oracle compose hash,
   no device ID, and no consumer binding.
7. `ExecutionPolicyAnchor`, owned by the explicit operator but deployed paused
   with no writer, no writer-release commitment, no pending proposal, and zero
   global/resource heads. It cannot anchor anything until the final CVM writer
   completes its separate timelocked release ceremony.

It deliberately does **not** deploy a challenge prize escrow, bond, or candidate
custody contract. `ChallengeRegistry` rejects native value and stores only
public metadata references and commitments. `ComputeCreditVault` is a reviewed,
testnet funding rail rather than a transferable token; it has no oracle, FX, or
unit conversion, and must remain execution-disabled until its independent
metering and TEE release roots are bound. Private holdouts, submissions, and
exact evaluation outputs must never be put on-chain.

This is the explicit v1 product decision. Minted or transferable compute tokens,
ETH challenge bonds, automated prize custody, and token/fiat conversion are
roadmap designs that require a new threat model, reviewed contracts, tests, and
deployment authority; none may be inferred from the v1 credit ledger.

After a successful broadcast, the helper verifies runtime code and the on-chain
operator and fail-closed zero-authority state before durably creating the new
immutable release ledger at
`deployments/fresh-contract-suites/$RELEASE_SHA/base-sepolia.json`. It never
reads, merges, or rewrites the historical `deployments/base-sepolia.json`. For
every one of the seven contracts, it
re-executes the exact creation bytecode with the release sender and constructor
arguments, resolves immutable references, and compares the full expected runtime
code hash to the deployed code. The ledger is published create-new only after
all seven transactions, receipts, block hashes, runtime hashes, authority
commitments, and fail-closed poststates agree. A partial broadcast is a recovery
event requiring chain inspection; it is never repaired by borrowing history
from the prior-operator ledger.

Only after that immutable post-contract ledger exists, build and independently
recheck the pre-Phala CVM launch intent. These outputs are create-new; an
existing output is a stop condition, not permission to overwrite it:

```bash
REPOSITORY_ROOT="$(cd "$(git rev-parse --show-toplevel)" && pwd -P)"
TINKER_BINDING_RECEIPT_SHA256="$(
  jq -er \
    '.tinker_account_binding_ceremony_receipt_sha256
     | select(test("^sha256:[0-9a-f]{64}$"))' \
    "$REPOSITORY_ROOT/.release/tinker-account-binding-ceremony.receipt.json"
)"

node "$REPOSITORY_ROOT/scripts/cvm-launch-intent.mjs" build \
  --topology "$REPOSITORY_ROOT/.release/dnai-cvm-topology.json" \
  --ledger "$REPOSITORY_ROOT/deployments/fresh-contract-suites/$RELEASE_SHA/base-sepolia.json" \
  --tinker-account-binding-ceremony-receipt-sha256 "$TINKER_BINDING_RECEIPT_SHA256" \
  --out "$REPOSITORY_ROOT/.release/cvm-launch-intent-core.json" \
  --contract-receipt-out "$REPOSITORY_ROOT/.release/fresh-contract-deployment-receipt.json"

node "$REPOSITORY_ROOT/scripts/cvm-launch-intent.mjs" check \
  --in "$REPOSITORY_ROOT/.release/cvm-launch-intent-core.json" \
  --receipt-out "$REPOSITORY_ROOT/.release/cvm-launch-intent.receipt.json"

node "$REPOSITORY_ROOT/scripts/cvm-launch-intent.mjs" hash \
  --in "$REPOSITORY_ROOT/.release/cvm-launch-intent-core.json"

node "$REPOSITORY_ROOT/scripts/activation-preflight.mjs" \
  --stage cvm-launch
```

The build order is causal: the topology exists before contract broadcast, but
`cvm-launch-intent-core.json` and its normalized
`fresh-contract-deployment-receipt.json` can be created only after the fresh
ledger exists. `cvm-launch-intent.receipt.json` is the detached structural
validation receipt; the `hash` command prints the domain-separated launch-intent
digest for independent comparison. Do not substitute the historical
`deployments/base-sepolia.json` ledger.

Every production post-deployment helper named below consumes the same immutable
deployment intent, measured final-release-authority core, and renewable review
envelope before it can read Base Sepolia, inspect account `dev`, run a Forge
simulation, or broadcast. The shared guard checks all three canonical digests,
the final authority's one-way binding to the deployment intent and release SHA,
and the review envelope's exact final-authority subject. Legacy
`OPERATOR_POLICY_PACKET_*` values and arbitrary projection JSON are rejected.
The helpers use `scripts/ceremony-authority-projector.mjs` to derive and compare
exactly 36 named Diligence, Compute, Email, anchor, and Tinker public inputs from
those validated artifacts. A missing, extra, or mismatched assertion fails
before chain reads or keystore access; shell environment values are never
accepted as independent reviewed authority.

The fresh Tinker encumbrance remains
`operations_fail_closed_pending_exact_timelocked_release_policy`. Its current
account and caps are a draft, both compose and manager authority sets are empty,
and `emergencyHalted=true`. Configure the exact policy in two phases:

```bash
cd "⚙️/tinker-delegate/contracts"
TINKER_ENCUMBRANCE_RELEASE_PHASE=1 \
  ./scripts/configure-tinker-release.sh
```

Phase 1 verifies Base Sepolia, the ledger-pinned runtime code hash, exact owner,
zero pending ownership transfer, the unchanged fresh draft, zero active or
pending release commitment, and no active compose or manager. It
then proposes the complete account commitment, both per-operation ceilings, the
canonical one-compose set, and exactly one explicit delegated manager distinct
from the operator and contract. The final authority fixes that sole manager to
the reviewed main-runtime TEE identity; zero or any alternate address is
rejected.
Both ceilings must be positive integer policy
units at or below `10000000000000000000`, and the spend ceiling cannot exceed
the add-balance ceiling. Record the phase-1 transaction, block, policy commitment, roots,
cardinalities, and `pendingReleasePolicyActivatesAt` in the ledger. Stop: do not
unhalt the contract or route any funding/spend operation during the review
window. Every appended `tinkerReleaseHistory` phase record must retain the exact
immutable `finalAuthoritySha256` and the review used for that ceremony as
`reviewEnvelopeSha256`; the current contract snapshot mirrors them as
`latestReleaseFinalAuthoritySha256` and
`latestReleaseReviewEnvelopeSha256`. A review envelope may be renewed between
phases, but its subject must remain the same final-authority digest, so renewed
review cannot substitute a different release policy.

After the immutable two-day delay, rerun with phase 2. The helper refuses any
pending or current-state drift, atomically activates the exact staged policy,
permanently freezes the release baseline, clears all pending fields, and only
then unhalts. The final ledger must retain both the frozen baseline roots/caps
and current roots/caps so later cap reductions or emergency revocations are
visible. Encode every current, frozen-baseline, and pending Tinker uint256 cap
as a canonical base-10 JSON string, including zero; never encode these values
as JSON numbers because they may exceed JavaScript's exact-integer range.
Post-freeze governance can only lower a cap, revoke a manager or compose hash,
or halt forever. It cannot add or replace authority, raise a cap, or resume a
halted release; those changes require a new contract release. Only a currently
approved manager can authorize or settle operation records after activation.
The owner does not inherit either execution path; it retains proposal,
timelock, monotonic-reduction, revocation, ownership, and emergency-halt powers.
After phase 2, `.contracts.tinkerAccountEncumbrance` is the active frozen
snapshot, not the original draft. Validate the pristine halted draft from the
matching `deploymentHistory[].deployedContracts.tinkerAccountEncumbrance`
entry, and validate both governance broadcasts in order from
`tinkerReleaseHistory`. Each phase record is bound to chain ID, encumbrance
address, and runtime code hash so history from an older deployment cannot be
reused. The current object's `sourceCommit` remains the deployment source, while
`latestReleaseSourceCommit` identifies the most recent governance ceremony;
never accept the draft as the current production record.
The legacy `maxAddBalanceWei` and `maxSpendWei` names preserve an existing ABI;
their values are unitless integer policy units, not wei or ETH. They are
positive per-operation ceilings with a hard `10e18` policy-unit maximum, not a
cumulative budget, balance, token, or escrow. Multiple distinct operations may
each use the full applicable ceiling. The contract never holds Tinker
credentials, card data, or user funds.

The execution-policy anchor remains
`anchoring_fail_closed_pending_timelocked_release_writer` after suite
deployment. Once the final CVM release has an independently verified writer
address and exact release commitment, configure it in two phases:

```bash
cd "⚙️/tinker-delegate/contracts"
EXECUTION_POLICY_ANCHOR_RELEASE_PHASE=1 \
  ./scripts/configure-execution-policy-anchor.sh
```

After the immutable two-day timelock, run phase 2. That phase refuses any
nonempty anchor or mismatched proposal, activates the exact writer/release pair,
permanently freezes writer rotations, and only then unpauses. A frozen writer
cannot be rotated in place; writer recovery requires a fresh anchor release.
Append both governance transactions and an exact post-state snapshot to the
deployment ledger before enabling any execution-policy PASS. The CVM runtime
must also implement the confirmed-anchor reconciliation protocol in
`EXECUTION-POLICY-ANCHOR.md`; deploying and configuring the contract alone does
not close local-store rollback.

The writer-evidence ceremony is not runnable from the currently pinned
production delegate image. Direct inspection of
`ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:262938c3620a2c4931b7ff0e5da1f321e564e2deade4550bd41104a3885f0b98`
confirmed that both `tinker-execution-policy-anchor-writer` and
`tinker_delegate.execution_policy_anchor_cli` are absent. The source-build
dstack overlay is useful for rehearsal, but it is not digest-pinned Phala
release evidence. Do not inject the QVL bearer into the existing long-running
delegate and do not reuse a stale image under a new service name.

The production gate is strictly ordered:

1. Commit and review a clean SHA containing the writer-evidence implementation.
2. Use clean CI to publish a linux/amd64 delegate image with GitHub provenance
   and SPDX SBOM attestations, then prove the entrypoint exists in that exact
   image.
3. Pin the literal `repository@sha256:<digest>` in the production Phala compose;
   never substitute a tag or encrypted-environment image reference.
4. Add and deploy a profile-gated, restart-disabled
   `anchor-writer-evidence` service using that literal image. Mount only
   `/var/run/dstack.sock`; expose no ports and mount no delegate-data or sealed
   volume. Deliver only its QVL bearer through Phala encrypted environment,
   never through `delegate`, Arena, or Compute.
5. Run the profile once, capture its canonical bounded artifact with mode
   `0600`, leave the encrypted bearer scoped only to that stopped profile
   service, and verify the exact raw-byte artifact hash/signature/policy root
   before beginning the two-phase on-chain writer activation. Do not remove or
   rotate a main-CVM environment value after quoting unless the resulting
   compose identity is treated as a new release with new writer evidence.

Until all five steps pass, the deployment status remains
`anchoring_fail_closed_pending_independent_writer_evidence`.

The newly deployed DiligenceRoom starts
`fail_closed_pending_cvm_binding`. Both compose and TEE-identity approval gates
are enabled and irreversibly frozen during the deployment transaction while both
admission sets are empty. At this initial point all four active/pending counters
are zero and both addition-freeze getters are false, so the room rejects deals
but can still execute the reviewed timelocked admission sequence.

After the replacement CVM's final compose hash and TEE identity are independently
reviewed, configure the room in four phases:

```bash
cd "⚙️/tinker-delegate/contracts"
DILIGENCE_RELEASE_PHASE=1 ./scripts/configure-diligence-release.sh
```

For phases 1-3, each invocation is a dry run unless `BROADCAST=true`, and every
Foundry broadcast uses only encrypted account `dev`. Phase 4 never uses the
operator keystore and never broadcasts from this helper: the distinct reviewed
controller executes `acceptDeveloper()` through its own wallet ceremony, then
the helper verifies the finalized receipt and exact live state before it may
append evidence. Every phase requires a clean worktree whose `HEAD` equals
`RELEASE_SHA`, the exact ledger-pinned `DILIGENCE_RUNTIME_CODE_HASH`, the
final-authority-pinned `DILIGENCE_GOVERNANCE_CONTROLLER`, and all
mandatory/frozen settlement gates. The phases are:

1. Propose the exact compose hash.
2. After the immutable two-day timelock, activate that compose hash and propose
   its exact TEE-identity binding.
3. After the second immutable two-day timelock, activate the TEE identity and
   permanently freeze both compose and TEE-identity additions, then propose the
   exact permanent governance controller.
4. After the final immutable two-day developer-transfer delay, the exact pending
   controller accepts governance through its reviewed EOA, Safe, or other
   contract-wallet flow. The old deployment operator cannot accept on its
   behalf, and zero/self/verifier/TEE controller values are rejected. Acceptance
   is permanent: every later production `proposeDeveloper` call reverts. Use the
   frozen-set emergency revocations to stop activity; changing the reviewed
   controller requires a fresh DiligenceRoom deployment and release ceremony.

For phase 4, first obtain the exact no-argument calldata without exposing a key:

```bash
cast calldata 'acceptDeveloper()'
```

Submit that call from the final-authority-pinned controller using its normal
reviewed wallet or multisig ceremony. Do not replace the Foundry `dev` keystore
with a controller key. After the transaction is finalized, verify it without a
ledger write:

```bash
DILIGENCE_RELEASE_PHASE=4 \
  DILIGENCE_GOVERNANCE_ACCEPTANCE_MODE=contract_event_and_state \
  DILIGENCE_GOVERNANCE_ACCEPTANCE_TX_HASH=0x... \
  DILIGENCE_GOVERNANCE_ACCEPTANCE_RECORD=false \
  BROADCAST=false \
  ./scripts/configure-diligence-release.sh
```

Use `eoa_direct_call` only when the controller has no runtime code. That mode
requires the outer transaction sender to equal the controller, its target to
equal DiligenceRoom, and its calldata to equal only `acceptDeveloper()`. Use
`contract_event_and_state` for a Safe or other contract controller. A normal
Safe transaction is addressed to the Safe and may originate from an owner or
relayer, so this mode deliberately makes no outer-call or trace claim. Instead
it requires live controller code, a successful finalized receipt containing
exactly one DiligenceRoom log—the indexed
`DeveloperTransferred(oldOperator, controller)` event—and the exact final live
state with both pending-developer getters zero. Both modes bind the receipt to
the exact phase-3 activation deadline recorded in the append-only ledger.

Once the verification-only invocation passes, repeat it with
`DILIGENCE_GOVERNANCE_ACCEPTANCE_RECORD=true` to append the mode-specific,
explicitly bounded receipt evidence under the release-wide lock. `BROADCAST`
must remain `false`; phase 4 performs no chain action.

The completed ledger has exactly four ordered
`diligenceReleaseHistory` entries. Every entry repeats the immutable
deployment-intent digest, Diligence deployment transaction, runtime hash,
source commit, final-authority digest, deployment operator, and governance
controller. Its `reviewEnvelopeSha256` is phase-specific: the review may be
renewed between the six-day ceremony phases, but every envelope must validate
the same final-authority subject. Phases 1-3 contain exact ordered
`operatorTransactions` arrays of 3, 6, and 4 successful calls. Every item binds
`sequence`, `transactionHash`, `sender`, `target`, `functionSignature`,
`calldataSha256`, `receiptStatus`, `blockNumber`, and `blockHash`; the
`operatorTransactionsSha256` is the SHA-256 of the compact key-sorted array
emitted by `jq -cS`, including its trailing newline. Phase 4 has count `0`, an
empty array, and a null operator-array digest because its controller acceptance
is recorded separately. The shared ceremony lock, compare-and-swap revision
receipt, and durable replacement protocol guard every append.

Do not route users to the room until phase 4 proves exactly one active compose,
exactly one active TEE identity, zero pending compose/TEE proposals, both
addition freezes, the exact compose-to-TEE binding, developer equal to the
reviewed governance controller, and no pending developer transfer. A pending
handoff keeps deal creation, funding, and result submission fail-closed. This
Diligence path's minimum is six days. Revocation remains available as an
emergency kill switch, but the closed set cannot admit a replacement; a new
release or identity rotation requires a fresh DiligenceRoom deployment. Append
all thirteen operator release-policy transactions, the controller's finalized
acceptance transaction, its explicit EOA-call or contract event+state evidence
mode, and a pinned final state snapshot to the ceremony ledger before enabling
browser writes.

The newly deployed `ComputeCreditVault` is also intentionally unusable for job
authorization. After the execution and independent metering CVMs have final,
reviewed identities, activate the exact policy with the three-phase helper:

```bash
cd "⚙️/tinker-delegate/contracts"
COMPUTE_RELEASE_PHASE=1 ./scripts/configure-compute-release.sh
```

Each invocation is a dry run unless `BROADCAST=true`. A broadcast is restricted
to encrypted Foundry account `dev`, requires a clean worktree whose `HEAD`
equals `RELEASE_SHA`, requires `COMPUTE_VAULT_RUNTIME_CODE_HASH` to match the
fresh-suite ledger and live extcodehash, and re-reads the live Base Sepolia
owner. The phases are:

1. Propose canonical Base Sepolia USDC, the native rate policy, and the exact
   execution-CVM compose hash.
2. After the first immutable two-day timelock, activate those three entries and
   propose the USDC rate policy.
3. After the second two-day timelock, activate the USDC rate policy, bind the
   exact execution TEE, and permanently freeze asset additions, rate-policy
   additions, and the mandatory compose gate.

The last phase refuses to run unless the live registry cardinalities are
exactly one allowed ERC20, two active rate policies, and one approved compose
hash, with exactly one registered execution TEE and zero pending asset,
rate-policy, or compose proposals. Every phase also rechecks the exact provider
recipient staged by the preceding phase. This prevents an active, historical
TEE, or not-yet-activated admission from being hidden alongside the expected
entries. Revocation remains available for incident response. The helper checks
clean `RELEASE_SHA` provenance again immediately before unlocking `dev`, after
the build, tests, and dry run. Append every governance transaction and the
pinned post-state block, including all active and pending counters, to the
deployment ledger before enabling browser authorization.

The reviewed Arena genesis catalog is also a real two-phase ceremony. Run the
guarded helper from the contracts directory:

```bash
install -d -m 700 /absolute/release-evidence/forge-broadcast
install -d -m 700 /absolute/release-evidence/locks
install -m 600 \
  "../../../deployments/fresh-contract-suites/$RELEASE_SHA/base-sepolia.json" \
  /absolute/release-evidence/base-sepolia.json
export DEPLOYMENT_MANIFEST_PATH=/absolute/release-evidence/base-sepolia.json
export FOUNDRY_BROADCAST=/absolute/release-evidence/forge-broadcast
export RELEASE_CEREMONY_LOCK_ROOT=/absolute/release-evidence/locks
CHALLENGE_REGISTRY_RELEASE_PHASE=1 \
  ./scripts/configure-challenge-registry-release.sh
```

Replace `/absolute/release-evidence` with one existing canonical, non-symlink
directory outside the Git checkout. `BROADCAST=true` refuses the repository
manifest default and refuses Forge's repository-local broadcast directory. The
external ledger and external Forge evidence preserve the identical clean
`RELEASE_SHA` and final-authority subject across the two-day boundary. The
helper participates in the release-SHA-scoped
`dnai.release-ceremony-lock.v1` protocol shared by every release writer and
holds it until durable ledger replacement and directory fsync complete. An
abnormal exit after acquisition deliberately leaves a stale lock; removal
requires the explicit two-distinct-reviewer recovery authority after chain,
nonce, and every release ledger have been reconciled. Keep `BROADCAST=false`
unless all ledger writers use that shared protocol. Do not edit, commit, copy back, or publish
the working ledger between phases. After phase 2 and the remaining release
gates succeed, copy and anchor the completed evidence as a distinct
post-ceremony publication step.

The helper imports the canonical final-authority parser through
`scripts/challenge-registry-authority-projector.mjs`; it does not accept an
operator-authored catalog file or per-challenge environment values. Phase 1
requires the pristine fresh registry, an empty pending owner, active registry,
exact runtime/owner/source pins, and then creates the complete version-1 catalog
at contiguous IDs `1..N`. It records every creation transaction/block and each
exact `reviewEligibleAt(challengeId)` value. Stop for the full on-chain
`MIN_VERSION_REVIEW_DELAY()` (two days) for every entry. A later version resets
that entry's eligibility timestamp, so any change restarts the review window.
Do not fabricate same-run live evidence by advancing a production clock, and do
not freeze or open a challenge in phase 1.

Only after the live chain timestamp reaches every recorded eligibility may
`CHALLENGE_REGISTRY_RELEASE_PHASE=2` run. It re-reads the exact count, IDs,
controllers, zero pending controllers, untouched Draft timestamps, version-1
URI and four commitments, and both source-specific pause latches before calling
`freezeChallengeConfiguration(challengeId)` and transitioning each challenge to
Open. It then compares every mined transaction's calldata with the reviewed
entry, verifies every receipt, proves the exact frozen/open/unpaused post-state,
waits until all phase receipts are covered by the RPC's `finalized` checkpoint,
records every receipt block hash and one block-pinned finalized post-state,
rechecks the same exact state at `latest`, and appends the full ordered evidence
set to `challengeRegistryReleaseHistory`. Before phase 2 can unlock `dev`, it
independently re-fetches every phase-1 transaction, calldata tuple, receipt,
canonical block hash, finalized post-state, and latest-state check from the
external ledger. A renewed, currently valid review envelope is allowed between
phases; historical entries retain their original review-envelope hashes while
the release SHA, final-authority digest, runtime, and catalog projection remain
identical.
Governance and controller pause state are independent: neither party can clear
the other party's halt. The local Anvil rehearsal may advance its ephemeral
clock to prove this sequence; that local timing is never production review
evidence.

Each phase is a sequence of governance transactions, not one atomic
transaction. If a broadcast is interrupted after any transaction is accepted,
keep browser authorization disabled and stop. The helper deliberately rejects a
partial phase on rerun; do not bypass that refusal or manually advance to the
next phase. If phase 1 is complete on-chain but its external ledger record cannot
be independently matched to every mined calldata item, receipt, canonical block
hash, finalized post-state, and current exact draft, phase 2 remains disabled.
There is no implicit evidence-reconstruction mode. Perform a separately
reviewed recovery or redeploy a pristine ChallengeRegistry before any challenge
is published. A partial phase-2 freeze/open sequence likewise requires explicit
recovery or registry replacement; never manufacture the missing history entry.
A successful process exit without the exact post-state tuple is not release
evidence.

The newly deployed EmailOracleAuth likewise starts in a fail-closed
`deny_all_pending_cvm_binding` state. The deployment ledger must continue to
report `oracleCodeFrozen=false`, `consumerRegistryFrozen=false`, and no initial
allowlist; those values are accurate, not a production-ready claim. After the
replacement main runtime and Diligence-root Email/KMS restart evidence are
independently verified:

1. Propose the final oracle compose hash and wait the full immutable upgrade
   delay before activation.
2. Restrict devices if the verified Phala device identity is part of the policy;
   never enable `allowAnyDevice` as a shortcut.
3. Add only the final delegate consumer app ID and compose hash, optionally
   delegating consumer management to a distinct operational address.
4. Register the EmailOracleAuth app with the verified dstack KMS deployment.
5. Exercise boot authorization, OTP delivery, emergency consumer revocation,
   and recovery while the consumer registry is still mutable.
6. Freeze oracle code authorization after the final compose-hash transition.
   Freeze the consumer registry only if permanent consumer membership is the
   intended governance policy.
7. Read every resulting value back on-chain and append the governance
transactions to the deployment ledger before calling the email path live.

Schedule the parallel contract ceremonies from the projected on-chain epochs,
not from a wall-clock promise. Record phase 1's
`pendingOracleComposeHashes(EMAIL_ORACLE_COMPOSE_HASH)` epoch and phase 3's
`pendingKmsBindingActivatesAt()` epoch, and require each later phase's finalized
block timestamp to meet the recorded value. With the Diligence and Compute
two-stage admission waits running in parallel, the protocol-only critical path
is `max(4 days, 2 * EMAIL_ORACLE_UPGRADE_DELAY)` from their first proposals.
External KMS/restart evidence collection, finality, interruptions, or a later
proposal can only move the actual completion epoch later.

Production Phala composes pin `TINKER_EVALUATOR_MODE=deterministic`. That lane
runs the release-pinned three-recipe evaluator inside the main CVM, accepts only
the buyer's exact on-chain policy commitment, and performs no provider,
network, subprocess, filesystem, clock, randomness, or logging I/O while
evaluating private artifact bytes. The Deal runtime remains profile- and
release-gated as `release_pinned_deterministic_evaluator`; this label describes
the reviewed executable lane, not proof that a CVM has been deployed or that
settlement is live.

The API resolver rejects `sft` in every custody mode because that retained
research helper sends artifact-derived tokens to a non-attested external
provider. It also rejects `stub` whenever dstack custody is active. Never replace
the production value with `stub` or `sft`. Local compose may default to `stub`
for developer flows, and the process/environment safe default remains
`disabled`; only the reviewed release renderer pins `deterministic`. Deal
settlement must remain unavailable until the exact evaluator manifest and
policy root, clean image, topology-v6 descriptor set, fresh contract bindings,
measured main CVM, independent QVL evidence, and ceremony authority all agree.

## Base Sepolia

### Historical DiligenceRoom

- Contract: `DiligenceRoom`
- Address: `0xe51A3C5fd564c625C9D72D2283878Ab4296b3844`
- Network: Base Sepolia (`chainId = 84532`)
- BaseScan: `https://sepolia.basescan.org/address/0xe51A3C5fd564c625C9D72D2283878Ab4296b3844`
- Deployment tx: `0x9407f7989c11ac1161397c85aa41bf3752ebca8124e5ecb7fafe05c6dbd899e4`
- Deployment block: `38837040`
- Deployer / developer fee recipient: `0x111dB654eCD8756188e03746C1bcff74FD749791`
- Current-operator controlled: no
- Compiler: `solc 0.8.28`
- Optimizer runs: `200`
- Historical source-publication note: previously reported as visible on
  BaseScan; this is not a fresh-suite submission receipt or authority for the
  current release. Fresh receipts prove submission only until every explorer
  page is independently confirmed.
- Current on-chain `dealCount()`: `0`

#### Security changes made before deployment

The original escrow contract was not safe enough to deploy unchanged. The deployed version includes these hardening changes:

1. Settlement now uses pull payments.
   - `acceptDeal`, `rejectDeal`, and `expireDeal` credit balances into `pendingWithdrawals`.
   - Recipients withdraw via `withdraw()`.
   - A reverting seller, buyer, or developer can no longer brick settlement.

2. TEE result submission is budget-checked.
   - `submitResult()` now reverts with `ComputeCostOverBudget()` if `computeCost + fee > budgetCap`.
   - This prevents `rejectDeal()` and `expireDeal()` from becoming permanently uncallable.

3. Deal creation now validates critical inputs.
   - `expiry` must be in the future.
   - `artifactHash` must be non-zero. Current clients must encode only the
     domain-separated salted v2 commitment
     `keccak256(ASCII("dnai-wikigen/artifact-commitment/v2") || 0x00 || secret32 || rawArtifact)`;
     the `bytes32` ABI is unchanged, but raw `keccak256(rawArtifact)` values are
     not accepted by the off-chain ingress protocol.
   - `teeIdentity` must be non-zero.

#### Historical contract interface snapshot

This is the ABI of the historical address above, not the fresh-suite ABI.

- `createDeal(uint256 reservePrice, uint256 expiry, bytes32 artifactHash, address teeIdentity)`
- `fundDeal(uint256 dealId)` payable
- `submitResult(uint256 dealId, ScoreBand scoreBand, uint256 computeCost, bytes32 resultHash, bytes32 composeHash, uint256 authorizationExpiry, bytes verifierSignature)`
- `acceptDeal(uint256 dealId, uint256 dealPayment)`
- `rejectDeal(uint256 dealId)`
- `expireDeal(uint256 dealId)`
- `withdraw()`
- `pendingWithdrawals(address account) -> uint256`
- `getDeal(uint256 dealId) -> Deal`

#### Test status at deploy time

- Command: `forge test --gas-report`
- Result: `39` tests passed, `0` failed
- Includes:
  - unit coverage for all lifecycle transitions
  - fuzz coverage for settlement conservation
  - adversarial test proving a reverting seller cannot block `acceptDeal`
  - budget safety test proving over-budget compute is rejected

### Historical EmailOracleAuth

- Contract: `EmailOracleAuth`
- Address: `0xd21706E1AfF482F1d23664be5768ceaD63ccdBfF`
- Network: Base Sepolia (`chainId = 84532`)
- BaseScan: `https://sepolia.basescan.org/address/0xd21706E1AfF482F1d23664be5768ceaD63ccdBfF`
- Owner: `0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38`
- Current-operator controlled: no
- Oracle upgrade delay: `172800` seconds (`2 days`)
- `allowAnyDevice()`: `true`
- `oracleCodeFrozen()`: `false`
- `consumerRegistryFrozen()`: `false`

#### Purpose

`EmailOracleAuth` governs two different trust domains:

1. Oracle boot authorization.
   - Which oracle compose hashes may boot and receive KMS material.

2. OTP consumer authorization.
   - Which consumer app IDs and compose hashes may request OTPs from the oracle.

#### Operational note

The oracle contract is still mutable. Before production freeze:

1. Register the final oracle compose hash.
2. Register the final approved consumer app ID and compose hash.
3. Call `freezeOracleCodeAuth()`.
4. Optionally call `freezeConsumerRegistry()`.

Because the historical owner is not the current operator deployer, do not use
the historical `EmailOracleAuth` as the production policy root for this branch.
Deploy a fresh instance from the current Foundry `dev` keystore account, then
register the final oracle and consumer compose hashes once the current Phala CVM
has been rebuilt and verified.

## Phala

### Historical CVM Record

- CVM name: `tinker-email-oracle`
- CVM id: `cvm_j2kD1EZn`
- App id: `29d78795d77408a705d2c77c42d1bc10c59d0671`
- Status reported by Phala: `running`
- Compose hash: `97818b3dbac8227ea3016e26c16886083f2fe25592fc0f33900e037c6003acd6`
- Instance type: `tdx.medium`
- Node: `prod5`
- dstack OS: `0.5.7`
- Gateway base domain: `dstack-pha-prod5.phala.network`

### Historical endpoints

- Oracle API: `https://29d78795d77408a705d2c77c42d1bc10c59d0671-8000.dstack-pha-prod5.phala.network`
- Delegate API: `https://29d78795d77408a705d2c77c42d1bc10c59d0671-8080.dstack-pha-prod5.phala.network`
- Chrome CDP: `https://29d78795d77408a705d2c77c42d1bc10c59d0671-9222.dstack-pha-prod5.phala.network`
- Neko UI: `https://29d78795d77408a705d2c77c42d1bc10c59d0671-52000.dstack-pha-prod5.phala.network`

### Historical images

- Oracle image: `ttl.sh/therealwiki-tinker-oracle-20260313-8b76c1d@sha256:6d521ae4da405250adbab51a8597ac83fdff4addfe930921293ccadad6d12352`
- Delegate image: `ttl.sh/therealwiki-tinker-delegate-20260313-8b76c1d-r6@sha256:6563c94382f82dc43dfe4de1f615189c8c3a6806061bb366c0efd0403017e115`
- Delegate browser sidecar: `mcr.microsoft.com/playwright:v1.58.0-noble@sha256:e3dca7b3c921ce1ebf45a50a6ac77982532c987e5926eb06535b5f56b363b94f`

### Historical live state

- Oracle API is live and healthy at the public `:8000` endpoint.
- The delegate stack now boots with registry images instead of local `build:` contexts.
- The delegate service no longer needs to crash the whole CVM if bootstrap fails; `/health` exposes runtime bootstrap status.

### Important current blocker

The recorded March 2026 blocker was Tinker auth automation, not Phala
deployment. This record must be revalidated with the current Phala profile and
current image digests before being treated as a live deployment.

On March 17, 2026, direct tests showed:

1. A headed local Chrome session reaches the Tinker `magic-code` page with a `gmail.com` control.
2. The deployed delegate path, which currently uses a headless Playwright browser server, is blocked with:
   - `Access blocked, please contact support.`
3. The Tinker auth page now ships explicit bot-check machinery:
   - hidden `signals` / bot token handling in the server-rendered form
   - `Fingerprint`
   - `BotCheckClient`
   - `BotCheckTokenInput`

This means the previous assumption that `cock.email` alone explained the failure is stale. The email domain is not the primary blocker now; the deployed browser posture is.

### What remains to finish fully automatic bootstrap

1. Replace the current headless Playwright sidecar with a headed browser path that survives Phala packaging.
2. Re-validate signup against the live Tinker auth flow from inside the CVM.
3. Once signup succeeds, verify:
   - OTP retrieval from the email oracle
   - onboarding completion
   - API key creation and encrypted storage at `/data/tinker_api_key.enc`
4. Freeze docs around the new browser requirement and stop claiming `cock.email` alone is sufficient.

## Commands used

### Test and build

```bash
cd "⚙️/tinker-delegate/contracts"
set -a; . ../../../.env; set +a
forge build
forge test --gas-report
```

### Compose hash verification

```bash
cd "⚙️/tinker-delegate"
uv run python -m tinker_delegate.main verify-compose-hash \
  --compose docker-compose.all.phala.yaml \
  --phala-raw-compose \
  --expected-hash EXPECTED_PHALA_COMPOSE_HASH
```

For deploy-critical TEE images, keep digest-pinned image refs literal in the
Phala compose. Do not treat encrypted-env image substitutions as quote-bound
deployment evidence unless a separate verifier proves the encrypted env values
that Phala applied.

### Dry-run and deploy the fresh contract suite

```bash
cd "⚙️/tinker-delegate/contracts"
./scripts/deploy-base-sepolia.sh

# Only after reviewing the dry-run and explicit trust roots:
BROADCAST=true VERIFY=true ./scripts/deploy-base-sepolia.sh
```

The helper deploys the seven reviewed-scope contracts listed above, performs
on-chain trust-root reads, and creates the immutable release-scoped ledger at
`deployments/fresh-contract-suites/$RELEASE_SHA/base-sepolia.json`.
`VERIFY=true` requires `ETHERSCAN_API_KEY`. The helper first broadcasts, verifies
runtime/trust-root state, and records the addresses in the manifest; only then
does it submit seven explicit `forge verify-contract` requests. This ordering
ensures an explorer outage cannot leave successfully broadcast contracts absent
from the deployment ledger. Constructor arguments and transactions remain in
`broadcast/DeployFreshSuite.s.sol/84532/run-latest.json`.

### Admit the Collaboration royalty release

Fresh deployment does not make the royalty rail executable. First complete the
`ExecutionPolicyAnchor` ceremony and confirm its third, distinct writer is
active, rotation-frozen, and unpaused. A Royalty phase is not authorized by
copying addresses into a shell. Two current independent reviewers sign one
short-lived `royalty-release-phase-plan.v2`; the production wrapper reconstructs
the fresh deployment and reviewer lineage, verifies that plan, and derives the
exact contract, runtime, role, calldata, order, value, and nonce projection.

Set absolute, canonical artifact paths for the reviewed inputs:

```bash
DEPLOYMENT_INTENT_PATH=/absolute/operator-evidence/deployment-intent.json
ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_PATH=/absolute/operator-evidence/royalty-prescription.json
ROYALTY_RELEASE_PHASE_PLAN_PATH=/absolute/operator-evidence/royalty-phase-plan.json
ROYALTY_RELEASE_REVIEWER_GENESIS_PATH=/absolute/operator-evidence/reviewer-genesis.json
ROYALTY_RELEASE_REVIEWER_GENESIS_ACCEPTANCE_PATH=/absolute/operator-evidence/reviewer-genesis-acceptance.json
ROYALTY_RELEASE_REVIEWER_CURRENT_STATUS_PATH=/absolute/operator-evidence/reviewer-current-status.json
ROYALTY_RELEASE_REVIEWER_STATUS_HISTORY_PATH=/absolute/operator-evidence/reviewer-status-history.json
TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256=sha256:...
```

Construct the unsigned phase core with the code-owned projector; do not copy
contract addresses, reviewer pins, calldata, or predecessor digests into a
handwritten core. The only operator proposal is a canonical request containing
the phase/mode, short validity window, and first transaction nonce:

```json
{
  "execution_mode": "stage_authority",
  "expires_at": "2026-08-17T12:14:00.000Z",
  "first_transaction_nonce": "42",
  "phase": 1,
  "schema": "dnai.royalty-release-phase-plan-generation-request.v1",
  "truth_status": "operator_supplied_window_and_nonce_only_not_reviewed_signed_or_chain_observed",
  "valid_after": "2026-08-17T12:00:00.000Z"
}
```

First capture the output of the supported ledger `replay` command into an
operator-owned canonical `0600` JSON file under the external evidence root.
Use a create-only temporary path and `jq -S`; never reuse an earlier replay
after the working ledger changes. Then generate one create-only unsigned core:

```bash
node "$ROOT/⚙️/tinker-delegate/contracts/scripts/royalty-release-phase-plan.mjs" \
  generate-core \
  --deployment-intent "$DEPLOYMENT_INTENT_PATH" \
  --fresh-deployment-manifest "$DEPLOYMENT_MANIFEST_PATH" \
  --reviewer-genesis "$ROYALTY_RELEASE_REVIEWER_GENESIS_PATH" \
  --reviewer-genesis-acceptance "$ROYALTY_RELEASE_REVIEWER_GENESIS_ACCEPTANCE_PATH" \
  --reviewer-current-status "$ROYALTY_RELEASE_REVIEWER_CURRENT_STATUS_PATH" \
  --reviewer-status-history "$ROYALTY_RELEASE_REVIEWER_STATUS_HISTORY_PATH" \
  --royalty-release-prescription "$ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_PATH" \
  --tinker-account-binding-ceremony-receipt-sha256 \
    "$TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256" \
  --generation-request "$ROYALTY_RELEASE_PHASE_GENERATION_REQUEST_PATH" \
  --ledger "$RELEASE_CEREMONY_LEDGER_PATH" \
  --ledger-replay "$ROYALTY_RELEASE_LEDGER_REPLAY_PATH" \
  --out "$ROYALTY_RELEASE_PHASE_CORE_PATH"
```

For normal phase 2 the request uses `phase: 2` and
`execution_mode: "activate_and_unpause"`; the projector derives the entire
phase-one prerequisite from the unique finalized ledger record and exact
replay tip. Recovery uses `execution_mode: "recover_reverted_unpause"` and adds
`--recovery-evidence /absolute/reviewer-recovery-evidence.json`; the projector
structurally validates and recomputes that evidence digest and derives the sole
retry nonce. This authoring check does not itself make an RPC finality claim;
the production wrapper independently authenticates the activation and reverted
unpause through both RPCs before it can execute the retry. The generated file
still has `status: "proposed_for_review"`. Continue with `payload`, obtain two
independent current-reviewer EIP-191 signatures, then use `attach` to write
`ROYALTY_RELEASE_PHASE_PLAN_PATH`. `generate-core` accepts neither final-v4 nor
H: those remain post-ceremony evidence.

The pre-ceremony wrapper deliberately does not require final-authority v4 or H:
those are post-ceremony facts and using them to authorize their own transactions
would be circular. It requires the immutable fresh-deployment receipt, the
distinct external working ledger and evidence/lock roots, and two distinct
Base Sepolia HTTPS RPCs. Keep Foundry's broadcast,
artifact, and cache directories outside the checkout so a reviewed clean source
tree remains stable throughout the two-day interval:

```bash
DEPLOYMENT_MANIFEST_PATH=/absolute/operator-evidence/fresh/base-sepolia.json
RELEASE_CEREMONY_LEDGER_PATH=/absolute/operator-evidence/ceremony/ledger.json
RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT=/absolute/operator-evidence/ceremony/evidence
RELEASE_CEREMONY_LOCK_ROOT=/absolute/operator-evidence/ceremony/locks
FOUNDRY_BROADCAST=/absolute/operator-evidence/foundry/broadcast
FOUNDRY_OUT=/absolute/operator-evidence/foundry/out
FOUNDRY_CACHE_PATH=/absolute/operator-evidence/foundry/cache
BASE_SEPOLIA_RPC_URL=https://...
BASE_SEPOLIA_SECONDARY_RPC_URL=https://...
FOUNDRY_KEYSTORE_ACCOUNT=dev
```

The operator, distributor, both royalty signers, anchor contract, and anchor
writer must be pairwise distinct. Phase 1 requires the exact fresh paused and
authority-empty distributor. Review the verified plan summary and simulate it;
the default does not inspect or unlock the keystore:

The anchor writer is a dstack-derived EOA and still needs Base Sepolia ETH to
pay for the release marker and each subsequent policy/Royalty anchor. This gas
reserve is separate from the deployment operator balance, Royalty reservation
asset, and both settlement signatures. Do not activate post-Compute Royalty
settlement until dual-RPC activation evidence proves the exact reviewed writer
address has at least `33000000000000000` wei at one common finalized block.
That v4 minimum budgets one marker plus 32 later anchors at 500,000 gas each
and 2,000,000,000 wei per gas; it is bounded runway, not indefinite readiness.
A nonzero balance by itself is not a sufficiency proof. This release has no
relayer, paymaster, hot private-key fallback, or additional CVM.

```bash
cd "⚙️/tinker-delegate/contracts"
ROYALTY_RELEASE_OPERATION=inspect ./scripts/configure-royalty-release.sh
./scripts/configure-royalty-release.sh
```

Only after the reviewers approve that exact phase and the simulation output,
set `BROADCAST=true`. The wrapper acquires the release-wide lock, reruns the
entire authority and ledger verification, rechecks common-finalized state and
nonce, then unlocks only the encrypted keystore account literally named `dev`.
The exact classified dry run must also emit one internally consistent gas
projection. Its gas units include the code-owned 130% multiplier; the owner
must hold at least twice the resulting wei cost both before keystore access and
immediately before broadcast. Broadcast pins that simulated gas price and the
durable pre-broadcast capsule records the raw projection digest, price,
estimated cost, required balance, and observed balance. A nonzero balance alone
is not readiness:

```bash
BROADCAST=true ./scripts/configure-royalty-release.sh
```

After phase 1 is finalized and durably recorded, create a new short-lived phase
2 plan whose prerequisite binds the exact phase-1 finality and ledger revision.
The signed `phase_one_history_record_sha256` is the raw SHA-256 of the canonical
deep-key-sorted phase-1 history JSON plus one trailing newline;
`finalized_authority_receipt_sha256` applies the same encoding to that record's
embedded finalized-authority receipt. `phase_one_finalized_at` is the canonical
millisecond UTC rendering of the receipt's common-finalized block timestamp,
not the later mutable ledger publication time. The wrapper recomputes all three
from the external ledger before either RPC or Forge access.
The wrapper will not proceed until the two-day activation timestamp has elapsed
at the common finalized chain checkpoint. Normal phase 2 activates the exact
staged binding and only then unpauses settlement. If activation finalized but a
later unpause reverted, do not rerun or use Forge resume: create the separately
reviewed `recover_reverted_unpause` plan whose evidence binds that activation,
revert, and next nonce. If a broadcast completed but publication was
interrupted, provide its external Forge receipt and reconcile without sending:

```bash
ROYALTY_RELEASE_OPERATION=reconcile \
ROYALTY_RELEASE_BROADCAST_RECEIPT_PATH=/absolute/operator-evidence/foundry/broadcast/ConfigureRoyaltyRelease.s.sol/84532/run-latest.json \
  ./scripts/configure-royalty-release.sh
```

There is one narrowly bounded same-plan continuation: if the original current
`activate_and_unpause` plan still passes reviewer and freshness checks, both
RPCs prove its activation finalized, the distributor is exact active-paused,
no unpause is pending or replaced, and the live nonce is the reviewed unpause
nonce, the wrapper may run only that reviewed unpause suffix. Supply the
activation-only Forge artifact through
`ROYALTY_RELEASE_BROADCAST_RECEIPT_PATH`. If any predicate fails or the signed
window expired, stop and require a future separately signed
`recover_missing_unpause` mode; never mislabel it as
`recover_reverted_unpause`.

The wrapper never performs blind resume. Missing or pending finality, an expired
plan, active-but-paused state without the matching recovery authority, any
runtime/role/policy drift, or ledger disagreement remains a hard stop. A signed
settlement is valid for at most ten minutes, must still be the current anchor
decision, and cannot be replayed under another funder because settlement ID and
nonce are global.

The fresh DiligenceRoom result ABI is
`submitResult(uint256,ScoreBand,uint256,bytes32,uint256,bytes)`: deal ID, bounded
score band, public compute tariff, compose hash, authorization expiry, and
verifier signature. There is no caller-supplied `resultHash`. The contract
derives and stores the exact domain-separated
`DiligenceRoomPublicResult(...)` hash, exposes it through
`canonicalResultHash(uint256,bytes32,ScoreBand,uint256)`, and exposes the exact
signature digest through
`resultAuthorizationDigest(uint256,bytes32,ScoreBand,uint256,uint256)`.

EmailOracleAuth is folded into the suite only as a new operator-owned, deny-all
policy root. Its final oracle device, compose, consumer, KMS registration, and
freeze policy still depend on the replacement CVMs and must be configured
through the post-CVM governance sequence above.

### Useful verification reads

```bash
CURRENT_DILIGENCE_ADDRESS="$(jq -r '.contracts.diligenceRoom.address' "$DEPLOYMENT_MANIFEST_PATH")"
cast call "$CURRENT_DILIGENCE_ADDRESS" "composeApprovalRequired()(bool)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call "$CURRENT_DILIGENCE_ADDRESS" "teeIdentityApprovalRequired()(bool)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call "$CURRENT_DILIGENCE_ADDRESS" "approvalRequirementsFrozen()(bool)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call "$CURRENT_DILIGENCE_ADDRESS" "approvedComposeCount()(uint256)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call "$CURRENT_DILIGENCE_ADDRESS" "approvedTeeIdentityCount()(uint256)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call "$CURRENT_DILIGENCE_ADDRESS" "pendingComposeCount()(uint256)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call "$CURRENT_DILIGENCE_ADDRESS" "pendingTeeIdentityCount()(uint256)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call "$CURRENT_DILIGENCE_ADDRESS" "composeAdditionsFrozen()(bool)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call "$CURRENT_DILIGENCE_ADDRESS" "teeIdentityAdditionsFrozen()(bool)" --rpc-url "$BASE_SEPOLIA_RPC_URL"

# Historical reads retained for comparison only:
cast call 0xe51A3C5fd564c625C9D72D2283878Ab4296b3844 "developer()(address)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call 0xe51A3C5fd564c625C9D72D2283878Ab4296b3844 "dealCount()(uint256)" --rpc-url "$BASE_SEPOLIA_RPC_URL"

cast call 0xd21706E1AfF482F1d23664be5768ceaD63ccdBfF "owner()(address)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call 0xd21706E1AfF482F1d23664be5768ceaD63ccdBfF "ORACLE_UPGRADE_DELAY()(uint256)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
cast call 0xd21706E1AfF482F1d23664be5768ceaD63ccdBfF "allowAnyDevice()(bool)" --rpc-url "$BASE_SEPOLIA_RPC_URL"
```

## Rollback And Recovery

Rollback is policy-specific because deployed contracts and CVM attestations are
part of the verification chain.

Safe to redeploy during test phases:

- `DiligenceRoom` while no production deals depend on the previous address.
- `ChallengeRegistry` while no published challenge points at the previous
  registry/version commitments.
- `RoyaltyDistributor` while no unsettled query or pending withdrawal depends on
  the previous address.
- `EmailOracleAuth` while oracle code authorization is not frozen and no
  production KMS/app policy depends on the previous address.
- Phala CVMs that have not been advertised as the final endpoint or policy root.
- Frontend/static verifier pages, as long as the deployment manifest is updated.

Must not be silently rolled back:

- A DiligenceRoom whose compose/TEE addition paths are permanently frozen. An
  emergency revocation disables the closed release; it does not authorize
  replacement admission at the same address.
- A frozen `EmailOracleAuth` oracle compose-hash policy.
- A consumer registry that reviewers or users have already relied on.
- Any deployed `DiligenceRoom` with funded or evaluated deals.
- A Phala CVM/image/compose hash that has been published as the attested
  production boundary.
- Any funding, Tinker API-key, email, or private-artifact sealed state.

Rollback procedure:

1. Pause new room creation and Tinker execution at the API/UI layer if those
   controls are available.
2. Record the failing address, CVM ID, compose hash, image digest, transaction
   hash, or endpoint in the external release-evidence working ledger before
   replacing it. Never mutate `deployments/base-sepolia.json` or the immutable
   fresh-suite deployment receipt.
3. Deploy the replacement from a Foundry keystore account, never a raw private
   key.
4. Verify bytecode, owner/developer addresses, compose hash, image digest, and
   TDX quote evidence before routing users to the replacement.
5. Leave old contracts callable for withdrawals or expiries when funds are
   present. Do not strand user funds by hiding the old address.
6. Notify users/reviewers when a published trust root, compose hash, image
   digest, app ID, endpoint, or contract address changes.
7. Update `ARCHITECTURE.md`, `STATUS.md`, and the deployment manifest in the
   same change so docs do not imply the old trust root is still current.

Emergency-only actions:

- Revoke oracle consumers if OTP or account-custody policy is suspect.
- Freeze oracle code authorization only after the intended compose hash is
  verified, because this cannot be undone.
- Stop or delete a CVM only after sealed data migration or intentional data
  destruction has been decided and recorded.
