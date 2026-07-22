# Deployment intent and signed release authority

The former monolithic operator-policy packet and its role projection, reviewer
genesis v1, and final-release wrapper are retired. The
`operator-policy-packet.mjs` filename remains for the bounded intent/review
artifact commands documented below; there is no supported `project` command or
packet/projection authority. None of the retired artifacts can authorize a
deployment, ceremony, activation, or Cloudflare release.

Reviewer authority is a three-artifact model:

1. `dnai.release-reviewer-authority-genesis.v2` commits a finite inventory of
   preauthorized reviewer keys, a minimum active-reviewer count, and exactly two
   distinct status guardians. Genesis is immutable and release-scoped.
2. `dnai.release-reviewer-authority-current-status.v1` selects active reviewer
   keys only from that finite inventory. Both guardians must sign it. Status
   windows are non-overlapping, last at most 15 minutes, form a complete
   predecessor chain, and carry monotonic revocations.
3. `dnai.release-reviewer-authority-genesis-acceptance.v2` is signed by every
   active reviewer and embeds the exact guardian-signed status. The deployment
   intent independently pins that status epoch and digest plus the acceptance
   digest.

This design does **not** claim an instant-revocation oracle. A successor cannot
overlap the pinned status, and omitting a successor cannot extend the pinned
status beyond its signed expiry. The maximum reviewer-revocation latency is
therefore 15 minutes. A later status requires its complete history and a new
deployment-intent head for the release that consumes it.

The canonical live dependency direction is:

```text
genesis v2 -> guardian-signed current status v1 -> all-reviewer acceptance v2
                                             |
                                             v
deployment intent -> fresh contract receipt -> signed non-live bootstrap A
                                                               |
                                                               v
                           seven-CVM launch completion L
                                                               |
                                                               v
                  pre-ceremony runtime authority R (separate from release core)
                                                               |
                                                               v
                     signed ceremony authorization B
                                                               |
                                                               v
                  compute-workload activation observation O
                                                               |
                                                               v
                     frontend build candidate receipt D
                                                               |
                                                               v
                       signed live activation authority C
```

The operational stages are exact and one-way:

1. `fresh_deployment`
2. `cvm_launch`
3. `release_ceremony`
4. `live_activation`

L and O are freshness-sensitive when first produced. Restart/preflight replay
must validate their exact persisted transcripts historically at the recorded
collection times; it must never refresh, remint, or backdate them. R binds L,
B signs R, O is produced by the measured launch path after B, D binds the exact
environment and deterministic build-manifest digest, and C signs B/O/D. No
Stage-B artifact, modeled UI, or unsigned declaration makes the release live.

## Files and boundaries

The tracked templates are intentionally invalid and secret-free:

- [`release-reviewer-roster.template.json`](./release-reviewer-roster.template.json)
- [`release-reviewer-authority-genesis.template.json`](./release-reviewer-authority-genesis.template.json)
- [`release-reviewer-authority-current-status-proposal.template.json`](./release-reviewer-authority-current-status-proposal.template.json)
- [`release-reviewer-authority-current-status-signing-payload.template.json`](./release-reviewer-authority-current-status-signing-payload.template.json)
- [`release-reviewer-authority-current-status.template.json`](./release-reviewer-authority-current-status.template.json)
- [`release-reviewer-authority-current-status-history.template.json`](./release-reviewer-authority-current-status-history.template.json)
- [`release-reviewer-authority-genesis-acceptance-signing-payload.template.json`](./release-reviewer-authority-genesis-acceptance-signing-payload.template.json)
- [`release-reviewer-authority-external-signatures.template.json`](./release-reviewer-authority-external-signatures.template.json)
- [`release-reviewer-authority-genesis-acceptance.template.json`](./release-reviewer-authority-genesis-acceptance.template.json)
- [`deployment-intent-core.template.json`](./deployment-intent-core.template.json)
- [`cvm-launch-intent-core.template.json`](./cvm-launch-intent-core.template.json)
- [`authority-review-envelope.template.json`](./authority-review-envelope.template.json)

Their structural JSON Schemas are:

- [`release-reviewer-roster.schema.json`](./release-reviewer-roster.schema.json)
- [`release-reviewer-authority-genesis.schema.json`](./release-reviewer-authority-genesis.schema.json)
- [`release-reviewer-authority-current-status-proposal.schema.json`](./release-reviewer-authority-current-status-proposal.schema.json)
- [`release-reviewer-authority-current-status-signing-payload.schema.json`](./release-reviewer-authority-current-status-signing-payload.schema.json)
- [`release-reviewer-authority-current-status.schema.json`](./release-reviewer-authority-current-status.schema.json)
- [`release-reviewer-authority-current-status-history.schema.json`](./release-reviewer-authority-current-status-history.schema.json)
- [`release-reviewer-authority-genesis-acceptance-signing-payload.schema.json`](./release-reviewer-authority-genesis-acceptance-signing-payload.schema.json)
- [`release-reviewer-authority-external-signatures.schema.json`](./release-reviewer-authority-external-signatures.schema.json)
- [`release-reviewer-authority-genesis-acceptance.schema.json`](./release-reviewer-authority-genesis-acceptance.schema.json)
- [`deployment-intent-core.schema.json`](./deployment-intent-core.schema.json)
- [`cvm-launch-intent-core.schema.json`](./cvm-launch-intent-core.schema.json)
- [`authority-review-envelope.schema.json`](./authority-review-envelope.schema.json)

JSON Schema is not an activation receipt. The JavaScript checker additionally
enforces exact keys, canonical encodings, numeric relations, QVL time budgets,
empty dynamic-runtime authority sets, subject-byte equality, review freshness,
canonical reviewer order, and reviewer separation.

Completed artifacts and receipts belong in the ignored `.release/` workspace.
Never put an RPC URL, API key, bearer, password, private key, wallet seed,
encrypted environment, card data, or private artifact into these public files.

## 1. Create genesis, guardian status, and reviewer acceptance

First copy the intentionally incomplete reviewer-roster template into the
ignored `.release/` workspace and fill in the real public reviewer addresses
and controller declarations. The CLI never creates reviewer identities:

```bash
mkdir -p "$PWD/.release"
cp deployments/release-reviewer-roster.template.json \
  "$PWD/.release/release-reviewer-roster.json"

node scripts/release-reviewer-authority-cli.mjs genesis-init \
  --release-sha "$(git rev-parse HEAD)" \
  --roster "$PWD/.release/release-reviewer-roster.json" \
  --out "$PWD/.release/release-reviewer-authority-genesis.json"
```

Fill a current-status proposal with an at-most-15-minute window. Epoch 1 uses
the zero predecessor digest; successors start no earlier than their
predecessor's expiry and require the complete canonical history. Generate the
guardian payload, collect both low-s guardian signatures in an external
signature envelope with purpose
`reviewer_current_status_guardian_authorization`, attach, and verify:

```bash
node scripts/release-reviewer-authority-cli.mjs current-status-payload \
  --reviewer-genesis "$PWD/.release/release-reviewer-authority-genesis.json" \
  --status-proposal "$PWD/.release/reviewer-current-status-proposal.json" \
  --out "$PWD/.release/reviewer-current-status-signing-payload.json"

node scripts/release-reviewer-authority-cli.mjs current-status-attach \
  --reviewer-genesis "$PWD/.release/release-reviewer-authority-genesis.json" \
  --signing-payload "$PWD/.release/reviewer-current-status-signing-payload.json" \
  --guardian-signatures "$PWD/.release/reviewer-current-status-guardian-signatures.json" \
  --out "$PWD/.release/reviewer-current-status.json"

node scripts/release-reviewer-authority-cli.mjs current-status-verify \
  --reviewer-genesis "$PWD/.release/release-reviewer-authority-genesis.json" \
  --current-status "$PWD/.release/reviewer-current-status.json"
```

Generate the acceptance payload. Every guardian-selected active reviewer must
independently sign the full embedded status:

```bash
node scripts/release-reviewer-authority-cli.mjs acceptance-payload \
  --reviewer-genesis "$PWD/.release/release-reviewer-authority-genesis.json" \
  --current-status "$PWD/.release/reviewer-current-status.json" \
  --out "$PWD/.release/reviewer-genesis-acceptance-signing-payload.json"
```

Place the externally produced low-s signatures into a canonical copy of
`release-reviewer-authority-external-signatures.template.json`, in the exact
address-sorted genesis order. Attach and verify them without exposing any key
material to the CLI:

```bash
node scripts/release-reviewer-authority-cli.mjs acceptance-attach \
  --reviewer-genesis "$PWD/.release/release-reviewer-authority-genesis.json" \
  --current-status "$PWD/.release/reviewer-current-status.json" \
  --signing-payload "$PWD/.release/reviewer-genesis-acceptance-signing-payload.json" \
  --reviewer-signatures "$PWD/.release/reviewer-genesis-acceptance-signatures.json" \
  --out "$PWD/.release/release-reviewer-authority-genesis-acceptance.json"

node scripts/release-reviewer-authority-cli.mjs acceptance-verify \
  --reviewer-genesis "$PWD/.release/release-reviewer-authority-genesis.json" \
  --acceptance "$PWD/.release/release-reviewer-authority-genesis-acceptance.json"
```

Every output is create-new, symlink-free, durably published, and frozen at
mode `0444`. The CLI rejects private-key, mnemonic, keystore, account, signer
command, RPC, and credential flags. It does not broadcast, call Phala, or
deploy Cloudflare. The acceptance digest—not the unsigned reviewer core—must
be copied into the deployment intent together with the exact current-status
epoch and digest. The final validator independently enforces that immutable
head and the status time window; this create-only CLI is not a latest-head or
freshness oracle.

## 2. Create and validate deployment intent

The legacy-named `operator-policy-packet.mjs` script is supported here only for
its exact `init-intent`, `check-intent`, `hash-intent`, `init-review`,
`check-review`, and `hash-review` artifact operations. It does not create a
monolithic operator-policy packet, has no `project` operation, and produces no
operator-role projection.

Create a new draft:

```bash
node scripts/operator-policy-packet.mjs init-intent \
  --out "$PWD/.release/deployment-intent-core.json"
```

Fill only the documented public fields, then validate and hash the exact bytes:

```bash
node scripts/operator-policy-packet.mjs check-intent \
  --in "$PWD/.release/deployment-intent-core.json" \
  --receipt-out "$PWD/.release/deployment-intent.receipt.json"

node scripts/operator-policy-packet.mjs hash-intent \
  --in "$PWD/.release/deployment-intent-core.json"
```

`check-intent` returns
`dnai.deployment-intent-validation-receipt.v6`, including
`deploymentIntentSha256`, `reviewerAuthorityCurrentStatusEpoch`, and
`reviewerAuthorityCurrentStatusSha256`. The receipt does not echo the operator
address or either reviewer key.

The intent contains only facts available before deployment:

- exact release SHA and Base Sepolia network;
- the exact signed reviewer-authority genesis acceptance and current-status
  epoch/head that must still be current at the later ceremony boundary;
- the canonical seven-contract and seven-CVM scope;
- the encrypted Foundry `dev` deployment operator and public controller ID;
- the exact immutable `ComputeCreditVault` developer address;
- the exact immutable `TinkerAccountEncumbrance` account commitment;
- contract, QVL, and independent-metering numeric policy.

The static constructor inputs live at
`staticContractInputs.computeCreditVault.developer` and
`staticContractInputs.tinkerAccountEncumbrance.accountCommitment`. The former
must be a lowercase nonzero Ethereum address; the latter must be a lowercase
nonzero `0x`-prefixed bytes32. They are reviewed before broadcast because the
deployed contracts cannot honestly recover or replace an omitted constructor
choice later. The validation receipt records `staticContractInputCount: 2`
without echoing either value.

`dynamicRuntimeAuthorities` contains five explicit empty arrays:

- `contractAddresses`
- `cvmIdentities`
- `roleAddresses`
- `releaseCommitments`
- `downstreamAnchorState`

A non-empty member is rejected. Placeholder contract addresses, fabricated CVM
identities, future anchor heads, and guessed runtime commitments are not honest
pre-deployment intent.

## 3. Build and validate the post-contract CVM launch intent

After the fresh contract ledger and canonical `dnai.cvm-topology.v5` generation
exist, build the immutable pre-Phala authority:

```bash
node scripts/cvm-launch-intent.mjs build \
  --topology "$PWD/.release/dnai-cvm-topology.json" \
  --ledger "$PWD/deployments/fresh-contract-suites/$RELEASE_SHA/base-sepolia.json" \
  --out "$PWD/.release/cvm-launch-intent-core.json" \
  --contract-receipt-out "$PWD/.release/fresh-contract-deployment-receipt.json"

node scripts/cvm-launch-intent.mjs check \
  --in "$PWD/.release/cvm-launch-intent-core.json" \
  --receipt-out "$PWD/.release/cvm-launch-intent.receipt.json"

node scripts/cvm-launch-intent.mjs hash \
  --in "$PWD/.release/cvm-launch-intent-core.json"
```

Do not substitute the root `deployments/base-sepolia.json`; it is prior-operator
historical evidence, not the immutable fresh-suite ledger for this release.

`build` rereads bounded non-symlink files and verifies the topology's copied
deployment intent, image manifest, attestation bundle, and seven descriptor byte
hashes. The fresh ledger must prove Base Sepolia chain 84532, exact creation
reexecution runtime hashes, successful and pairwise-distinct deployment
transactions, exact blocks and block hashes, the shared `dev`-keystore
operator, the same release and intent, and the fail-closed post-contract state.
The online readiness collector does not trust those expected hashes by itself.
Its `dnai.activation-readiness-snapshot.v3` evidence selects one common
finalized block through two distinct HTTPS RPC origins. Each origin must
independently fetch and agree on all thirteen transactions and receipts,
including value, gas, transaction index, creation/call linkage, and calldata;
the associated historical blocks and block hashes; all seven deployed runtime
code hashes; and all six stateful-contract poststate observation sets. The
collector then rereads the common finalized block before publication. The
detached, clean release checkout and v3-pinned build toolchain must also
independently reconstruct the same transaction and runtime subjects. A missing
secondary provider, same-origin alias, receipt or historical-block gap,
finality disagreement, poststate mismatch, or reconstruction drift keeps every
post-contract stage blocked.
It then projects only Base Sepolia, release, intent, operator/keystore/proof,
and seven exact address/runtime/transaction/block receipts. The domain-separated
`contract_deployment_receipt_sha256` excludes deployment-review renewal fields,
unrelated history, and all Phala/CVM data; the raw ledger-file hash is never
launch authority. Descriptor SHA fields are raw file hashes and are
explicitly not Phala platform compose hashes.
The build publishes the exact canonical normalized contract receipt used for
that digest through the mandatory, distinct `--contract-receipt-out` path.
Both outputs use create-new/no-symlink publication; if either cannot be
published, the command removes the companion it created and never overwrites
an operator-owned file. Pass that receipt unchanged to the mandatory
transitive launch-review dependency check.

Each descriptor records the exact diagnostic Phala CLI identity
`v1.1.19+d2300dd`, but fresh CLI deployment is forbidden: that CLI's
`--prepare-only` does not provide the required uncommitted fresh-CVM boundary.
The reviewed seven-CVM design is implemented by the repository's guarded
`@phala/cloud` `0.2.10` production executor as the exact sequence named
`provisionCvm_validate_all_seven_then_commitCvmProvision`. It prepares all
seven applications without starting them, validates every
predicted/returned app ID, independently authenticated environment public key,
compose hash, OS/device fact, hardened visibility flag, descriptor byte hash,
and current authorization receipt, and only then attempts the explicitly
journaled, non-atomic commit batch. Availability of this bootstrap executor is
not live-traffic authority: post-measurement environment activation, the
ceremony, and final live activation remain separate fail-closed checkpoints.

The production control plane is pinned to
`https://cloud-api.phala.network/api/v1` and API version `2026-01-21`.
Redirects, origin drift, `PHALA_CLOUD_API_PREFIX`, SDK defaults, and a workspace
identity different from a separately reviewed account/workspace target are not
authority. The pinned adapter requires `DEBUG` to be absent or empty before
importing the SDK; selector parsing is not an allowlist because expressions
such as `*`, `phala::*`, and mixed inclusion/exclusion lists can still enable
`phala::api-client`. Captured stdout and stderr must prove zero secret bytes.

Each descriptor binds a non-executable AppCompose candidate reconstructed from
the exact stable-read descriptor bytes and allowed-environment keys. It
explicitly sets manifest version 2, `docker-compose`, PHALA KMS, gateway on,
deprecated tproxy off, secure time on, `ext4`, and public log/sysinfo/TCB flags
off. Request-level `listed: false` is excluded from the hashed AppCompose.
Expected compose hashes use only `@phala/dstack-sdk/get-compose-hash` version
`0.5.8`, normalization disabled, and bare lowercase SHA-256 output. The exact
hashed object has thirteen reviewed fields and excludes request-only `listed`,
image, resource, placement, KMS-ID, nonce, and app-ID fields. No internal Cloud
SDK serializer is a fallback.

The logical reviewed AppCompose deliberately sets `gateway_enabled: true` and
`tproxy_enabled: false`; it is not claimed to be byte-equal to the SDK wire
body. The pinned `@phala/cloud` `0.2.10` package has npm integrity
`sha512-eQXJxbBlJ8xA4e+MmB3AZd9jgdbO3tFh+qu7KL6CS5Ta64LNKlrV3vdke3oUvB22xbc/qqKQ6dIkJx5pTdY7gA==`.
Its `ProvisionCvmRequestSchema.parse` step is followed by
`handleGatewayCompatibility`, which deletes
`compose_file.tproxy_enabled` when both gateway and tproxy fields are boolean.
The exact expected wire body therefore keeps gateway enabled and has no
`compose_file.tproxy_enabled` member. The launch core binds that one transform,
forbids any additional transform, and accepts no pre-transform, expected-wire,
captured-wire, server, or staging-receipt digest as launch evidence. A later
compatibility receipt must bind stable installed package/module bytes, capture
the canonical actual POST body immediately before send, prove it equals the
independently expected post-transform body, record the authenticated staging
result, and bind the server-observed compose-hash proof. All seven returned
prepare hashes must still match before any commit. There is no logical-to-wire
byte-equality claim: the staging and server evidence must prove that the
transformed wire body preserves gateway on and tproxy off.

Resource values are reviewed candidates, not catalog observations: the main
runtime targets `tdx.large` with 40 GB, and each support CVM targets `tdx.small`
with 20 GB, for 160 GB total. Node and region are omitted only under the bound
automatic-best-match policy. Authenticated resource, quota, KMS, and workspace
evidence must validate them before the final provision-request digest can
exist; unresolved KMS ID, nonce, and app ID remain null and non-executable.
The reviewed `key_provider_mode` is exactly `kms`, the only SDK-schema mode
consistent with the selected PHALA KMS and deterministic `nextAppIds` flow.
Request defaults and unreviewed extra fields are forbidden, and each final
per-domain request digest remains null until those three dynamic authorities
are independently projected.

The exported production entry point is executable only as
`scripts/phala-production-executor.mjs --execute-request` with one canonical,
caller-owned `0600` request file. It accepts neither caller-supplied clients nor
callbacks and has no manual CLI/SDK mutation bypass. The runtime itself loads
the pinned SDK adapter, canonical readiness collector, reviewed workspace and
target authorities, verified GitHub release-manifest evidence, authenticated
OS/KMS/resource/quota observations, signed app-environment keys, exact
compose-hash and wire-transform proofs, bootstrap public-environment authority,
reviewer-genesis acceptance and anchor, cryptographic non-live bootstrap
authorization, and a durable recovery journal. It records each prepare and
commit transition and fails closed on replay or incomplete recovery.

Before running the resident production activation driver, prepare its three
private filesystem authorities with the dedicated non-authorizing setup tool.
Create a recursively key-sorted canonical JSON request with exactly one
trailing newline:

```json
{
  "authorities": {
    "evidenceExchangePath": "/absolute/private/evidence",
    "outputPath": "/absolute/private/outputs",
    "signingExchangePath": "/absolute/private/signing"
  },
  "schema": "dnai.phala-production-authority-workspace-prepare-request.v1"
}
```

The request must be an owned, regular, single-link mode-`0600` file. Then run:

```bash
node scripts/phala-production-authority-workspace-prepare.mjs \
  --prepare-request /absolute/private-workspace-request.json
```

This operation creates or strictly reopens only three empty mode-`0700`
directories, pins their filesystem identities, and prints a path-plus-anchor
preparation receipt. It mints no capability, authorizes no activation mutation,
automatic retry, or live traffic, and proves no Phala deployment or TDX
evidence. Independently review the receipt and seal its exact path-plus-anchor
pairs into the resident activation request before invoking the driver:

```bash
node scripts/phala-production-activation-driver.mjs \
  --execute-request /absolute/private-resident-request.json
```

That driver is source- and test-real, but it has not run against a fresh
project-owned seven-CVM production topology. The commands above are preparation
and guarded execution entry points, not deployment evidence or a live claim.

The read-only `--status-json` operation reports bootstrap executor
`availability: true`; it does not authenticate Phala, read credentials, call an
API, or authorize a launch. A real execution request still fails unless all of
the preceding authorities are present and mutually bound. The executor never
emits or shells out to `phala deploy`. Passing descriptor or plan validation
alone therefore proves descriptor consistency, not CVM creation, platform
observation, TDX evidence, or launch readiness. After bootstrap, the separate
post-measurement and live-activation blocker sets continue to require deferred
public-value projection, ceremony authorization, and a reviewed live-activation
authority before any live claim.

The canonical list is an ordered union of three causal subsets. CVM
prepare/provision/commit readiness consumes only the bootstrap subset, which
requires the fresh contract/launch chain and cryptographic non-live bootstrap
authorization but expressly excludes Stage 1, deferred-live projection, and
Stage 2. Post-measurement and live-activation blockers apply only at their later
checkpoints. Requiring Stage 1 or Stage 2 before CVM creation would be a causal
cycle and is rejected.

The v2 launch core copies that exact ordered policy from the single
dependency-free source `scripts/phala-production-execution-policy.mjs` into
`sealed_production_execution_policy`; consumers must not maintain a second
blocker list. Its validation receipt reports `productionExecutionEnabled:
true`, the canonical bootstrap blocker count (currently zero because those
controls are implemented in the guarded runtime), and the canonical policy
digest. Post-measurement and live-activation blockers are deliberately reported
separately and are never erased by bootstrap availability. Any caller-supplied
execution hook or manual CLI/SDK bypass changes canonical bytes and is rejected.

All seven descriptors require a fresh CVM and the equivalent of `--no-dev-os`,
`--no-public-logs`, `--no-public-sysinfo`, and `--no-listed`, followed by exact
assertions that dev OS, listing, public logs/sysinfo, and public TCB info are all
false. Public classifications contain sorted key names only. Encrypted-secret
names are split into four exact, pairwise-disjoint sets:
`bootstrap_provision`, `post_measurement_policy_bootstrap`,
`final_authority_runtime`, and `anchor_writer_ceremony`. The initial prepare
may receive only that descriptor's `bootstrap_provision` set; Arena, Diligence,
QVL, metering, and anchor-writer bearers or bundles are rejected there.
Defaulted descriptor keys remain separately exact and cannot be injected
through the allowed encrypted environment set.

The initially active delegate's EIP-1271 verifier is the only production
`/auth/*` HTTP surface, so `TINKER_WALLET_AUTH_RPC_URL` and
`TINKER_WALLET_AUTH_RPC_URL_SECONDARY` are encrypted `bootstrap_provision`
inputs, analogous to the other credential-bearing Base Sepolia RPC URLs. The
production descriptor requires both with strict nonempty interpolation; no
public value or value hash enters the launch core or receipt. Runtime
configuration requires distinct provider origins, and verification denies
unless both providers agree at one finalized Base Sepolia block on its hash,
exact wallet bytecode, and any EIP-1271 result.
Its bounded network controls are descriptor-byte-bound, non-injectable public
defaults: `TINKER_WALLET_AUTH_RPC_TIMEOUT_SECONDS=3.0`,
`TINKER_WALLET_AUTH_RPC_MAX_RESPONSE_BYTES=131072`, and
`TINKER_WALLET_AUTH_MAX_SIGNATURE_BYTES=4096`.

The launch settings also bind the exact reviewed production, non-GPU Phala OS
catalog entry: selector `dstack-0.5.10`, slug `dstack-0.5.10-4c9bd024`, version
`0.5.10`, and OS image hash
`4c9bd0249cf8a1f79f7b558867b0791d628d7a89dcba84a963338fc5539255fc`.
The fresh provisioner must re-query the authenticated production catalog, pass
that exact selector as the SDK `image`, and verify the returned hash with
`is_dev=false` and `requires_gpu=false` for all seven prepared CVMs before the
first commit. These reviewed expectations are not represented as observed TDX
or post-deployment facts.

The main CVM's `EMAIL_ORACLE_CONSUMER_APP_ID` and every referenced platform
compose hash are provisioning-result inputs. `COMPOSE_PROFILES` is a public
post-measurement phase control, never a secret. QVL release-policy and metering
policy-set base64 payloads are encrypted
`post_measurement_policy_bootstrap` inputs, not pre-measurement public facts.
Bootstrap secrets and prepare-derived provisioning results use `${KEY:?}`.
Post-measurement, the runtime phase historically named `final_authority_runtime`,
and ceremony inputs use only the exact empty
default `${KEY:-}` while their reviewed profiles are disabled, because Compose
interpolates before profile selection. A phase transition must supply every
late value as nonempty, set the exact reviewed `COMPOSE_PROFILES` value, and
re-render and revalidate the descriptor before any service start. A key cannot
mix strict, empty-default, or nonempty-fallback modes; comments and escaped
container-shell variables cannot satisfy this check. Missing, empty, or
sentinel values never cross a phase gate.
No value, value hash, ciphertext, token length, `PHALA_CLOUD_API_KEY`, CVM ID,
app ID value, TEE identity, quote, endpoint, OS measurement, platform compose
hash, QVL result, legacy final-release-authority digest, or Stage 2
live-activation digest may appear.
The launch core has no Stage 1 or Stage 2 authority-digest field at all; those
authorities are created only at their later one-way checkpoints.

Version 2 adds a value-free `public_environment_value_authority` contract to
every descriptor. It binds the exact key-name sets and their digests, required
source-authority references, stage checkpoints, and fail-closed status, but it
does not contain or validate a runtime value. The bootstrap-static and
post-measurement-deferred projectors are explicitly `required_not_implemented`;
the validation receipt therefore reports
`publicEnvironmentValueAuthorityComplete: false`, a nonzero blocker count, and
`environmentValueCount: 0`. Provisioning-result keys are marked
`required_derive_and_exactly_validate_from_prepare_not_operator_input`, and
`COMPOSE_PROFILES` is policy-derived rather than operator free-form. The
launch-intent receipt alone therefore cannot authorize any environment value.
The guarded executor enforces the separate canonical authority artifacts at
their causal checkpoints: bootstrap execution consumes the signed bootstrap
authority, while post-measurement updates consume separately reviewed deferred
and private environment assemblies. This descriptor section remains a gate
specification, not runtime-value authority or evidence of a deployment.

The later bootstrap public-environment authority follows that same causal
order. It may bind the fresh contract receipt, CVM launch intent and review,
reviewed production target, and pinned SDK wire-transform staging evidence,
then receive an explicitly non-live bootstrap authorization. It must not bind
measured-CVM facts, a ceremony or final ledger, Stage 1 authorization, or Stage
2 live-activation authority: none of those can exist before the bootstrap that
creates the fresh CVMs. Post-measurement and post-ceremony projectors remain
separate one-way successors.

The main descriptor starts in `bootstrap_provision` with only `delegate`,
`neko`, and `oracle`; arena, deal settlement, compute execution, and anchor
arrays must all remain empty. Each QVL and the independent metering descriptor
also starts in `bootstrap_provision` with no initial services; `qvl-runtime`
and `metering-runtime` remain disabled until the measured policy phase supplies
the exact secret set and activates the reviewed `COMPOSE_PROFILES` value. Those
facts are measured later into the legacy runtime-authority dependency and the
separate ceremony/live stages rather than guessed before deployment.

## 4. Create a review envelope

The current review initializer reads and hashes the exact canonical subject
file. It accepts a valid deployment intent, CVM launch intent, or semantically
valid legacy final-release runtime-authority dependency:

```bash
node scripts/operator-policy-packet.mjs init-review \
  --subject "$PWD/.release/deployment-intent-core.json" \
  --out "$PWD/.release/deployment-intent.review-envelope.json"
```

After recording the two public reviewer declarations, evidence digest, and UTC
approval window, validate it against the same subject bytes:

```bash
node scripts/operator-policy-packet.mjs check-review \
  --subject "$PWD/.release/deployment-intent-core.json" \
  --in "$PWD/.release/deployment-intent.review-envelope.json" \
  --receipt-out "$PWD/.release/deployment-intent.review-receipt.json"

node scripts/operator-policy-packet.mjs hash-review \
  --subject "$PWD/.release/deployment-intent-core.json" \
  --in "$PWD/.release/deployment-intent.review-envelope.json"
```

Review dependencies are mandatory and digest-linked; they are not optional
identity hints. A CVM-launch-intent review additionally requires
`--deployment-intent FILE --contract-receipt FILE`. A legacy final-release-authority review
requires `--deployment-intent FILE --cvm-launch-intent FILE`. The checker
revalidates each dependency and proves the subject's embedded digests, release,
operator, static constructor inputs, and numeric contract policy before it can
accept reviewer declarations. Omitting a required dependency fails closed.

Before stage-3 release ceremonies, repeat the review commands with the exact
canonical legacy final-release-authority file as `--subject`, the exact
deployment intent as `--deployment-intent`, and the exact reviewed launch
intent as `--cvm-launch-intent`. That validates only the runtime-authority
dependency. Stage 1 `dnai.ceremony-authorization-core.v1` must then be created,
signed, and reviewed separately with status `pre_ceremony_authorized`. After
the exact ceremony revision is mined, final, and frozen, Stage 2
`dnai.live-activation-authority.v1` must independently bind Stage 1 and receive
a fresh review with status `live_activation_authorized`. No generic legacy
final-authority review is accepted as either stage.

Every input is read with bounded, stable, regular-file, no-symlink semantics.
Every object must be recursively key-sorted two-space JSON with exactly one
trailing newline. Output files use create-new publication and are never
overwritten.

## Exact subject policies

Deployment-intent review uses:

- `subject_kind`: `deployment_intent`
- `checkpoint`: `before_any_contract_broadcast_or_cvm_deployment`
- `action_scope`, in order:
  1. `release_source_and_network`
  2. `deployment_operator_control`
  3. `static_contract_inputs`
  4. `contract_numeric_policy`
  5. `qvl_numeric_policy`
  6. `metering_numeric_policy`
  7. `dynamic_runtime_authorities_empty`

Legacy final-release runtime-authority review uses (never Stage 2):

- `subject_kind`: `final_release_authority`
- `checkpoint`: `after_measured_cvms_before_any_release_ceremony_transaction`
- `action_scope`, in order:
  1. `release_source_and_network`
  2. `deployment_intent_binding`
  3. `cvm_launch_intent_binding`
  4. `contract_suite`
  5. `arena_genesis_catalog`
  6. `cvm_topology`
  7. `runtime_authorities`
  8. `release_policy`

CVM-launch-intent review uses:

- `subject_kind`: `cvm_launch_intent`
- `checkpoint`:
  `after_verified_fresh_contract_suite_before_any_phala_cvm_provision_or_commit`
- `action_scope`, in order:
  1. `deployment_intent_and_release_source`
  2. `verified_contract_poststate`
  3. `exact_image_subjects`
  4. `six_descriptor_hashes`
  5. `production_phala_posture`
  6. `public_runtime_numeric_policy`
  7. `encrypted_env_key_contract`
  8. `staged_bootstrap_and_deferred_bindings`

The declaration is exactly
`out_of_band_review_collected_not_signature_verified`. The checker validates
the declaration and evidence digest; it does not verify reviewer signatures or
claim address control.

Review approval may be at most five minutes ahead of check time. Expiry must be
after approval, no more than seven days later, and still in the future. Renewal
creates a new envelope and receipt against the same immutable subject digest.

## Authority digest rules

Deployment intent uses the SHA-256 digest of its canonical artifact bytes.
CVM launch intent hashes the explicit UTF-8 domain
`dnai-wikigen/cvm-launch-intent-core/v2\0` followed by compact recursively
key-sorted normalized JSON. Its tracked artifact remains pretty two-space JSON
with one trailing newline; hashing the pretty file is not the authority digest.
The repository's deterministic v2 known-answer fixture produces
`c03cdae8fd4022e83b9fd3ed2ae123e8d7c2eebbe18eaadd4b5bf6f04c715439`.
The legacy final-release runtime-authority dependency deliberately uses the
authoritative domain-separated digest from `finalReleaseAuthorityCoreDigest`,
not a second hash of its pretty JSON file. `check-review` imports that
normalizer and digest function, validates the legacy core, requires its
authoritative canonical serialization, and places the resulting
`sha256:<digest>` in the review receipt. This rule does not create or stand in
for the separately reviewed Stage 1 or Stage 2 authority.

This makes the envelope subject hash identical to the release-candidate and
ExecutionPolicyAnchor commitment. A raw file hash is not a substitute.

## Evidence boundary

Successful checks prove only public shape, bounds, canonical bytes, exact
subject binding, and a live out-of-band review declaration. They do not prove:

- Foundry signer control;
- reviewer signatures or controller custody;
- clean Git source or image provenance;
- a contract broadcast or chain state;
- CVM deployment, TDX identity, or QVL evidence;
- execution-anchor state or final activation.

Those remain separate fail-closed gates.
