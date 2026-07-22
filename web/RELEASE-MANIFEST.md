# Production web release manifest

The browser release is intended to be generated from evidence; operators do
not hand-edit live `VITE_ENABLE_*` flags. In this revision,
`npm run release:env` is deliberately sealed before output: it authenticates
the exact 37-input Model-A boundary and then exits without writing
`web/.env.production.local`. That boundary must remain visibly distinct from
the operational argument-free modeled preview.

The existing `deployments/base-sepolia.json` ledger is an input, not an
authorization. In particular, its historical `currentOperatorControlled`
markers and service-produced attestation envelopes can never enable a browser
mutation by themselves.

## Current live-release boundary

There is currently no supported production release command. Do not reconstruct
one from an older eight-artifact example, and do not bypass the wrapper with a
raw Wrangler upload. The parser intentionally rejects the retired
`--authority-review-envelope` option; after loading all exact-37 inputs,
`build-release-env.mjs` terminates with
`Model-A exact-37 semantic validator integration is incomplete` before any
dotenv write or Cloudflare invocation.

A production command can be documented only after the exact reviewed source is
committed, images are built from that commit, fresh contracts and all seven
non-dev CVMs are deployed, on-chain approval/freeze transactions are final,
fresh independent DCAP/QVL verdicts exist, and the Model-A exact-37 validator
can emit its in-process hash-only semantic receipt. The live runner is designed
to require that receipt to equal the exact allowlisted `VITE_*` environment and
to bind the stable deployment intent, final authority, current review evidence,
clean release SHA, and production branch. Semantic drift, stale review,
unexpected Vite keys, a dirty worktree, or SHA mismatch must abort before
Wrangler runs. The argument-free path remains reserved for the explicitly
modeled preview and cannot consume live evidence.

`TRUSTED_ATTESTATION_VERIFIER_ADDRESSES` is deliberately external to the JSON
manifest. It is the human-reviewed trust-root input established only after the
five QVL CVMs' own platform/release evidence has been independently checked. A
candidate cannot make a self-signed verifier trusted by listing it inside its
own descriptor or identity response. Multiple previously reviewed verifier
addresses may be comma-separated during a controlled rotation, but the exact
Diligence, Arena, anchor-writer, Compute-workload, and Compute-metering
descriptor addresses must all be present.

The deployment operator, main dstack-derived execution signer, diligence result
verifier, purpose-separated anchor writer, Compute developer, Diligence QVL
signer, Arena QVL signer, anchor-writer QVL signer, Compute-workload QVL signer,
Compute-metering QVL signer, and independent Compute-meter signer are all
distinct identities. Their
main/QVL/metering app IDs, CVM IDs, compose hashes, and HTTPS origins are also
separate. An address string alone is insufficient to enable QVL trust or
Compute authorization.

The generator also runs GitHub's attestation verifier for every image and uses
`BASE_SEPOLIA_RPC_URL` for live reads. The RPC value is never copied to the web
bundle; the generated client always uses the public canonical
`https://sepolia.base.org` endpoint.

## Exact candidate shape

The candidate has schema `dnai.web-release.v4` and exactly these top-level
fields:

```json
{
  "schema": "dnai.web-release.v4",
  "release_sha": "<40 lowercase hex>",
  "network": {
    "chain_id": 84532,
    "public_rpc_url": "https://sepolia.base.org"
  },
  "operator_address": "0x<fresh suite operator>",
  "deployment_intent_sha256": "sha256:<stable predeployment intent>",
  "cvm_launch_intent_sha256": "sha256:<reviewed exact CVM launch intent>",
  "operator_policy": {
    "schema": "dnai.final-release-authority-evidence.v1",
    "final_authority_sha256": "sha256:<domain-separated final-authority digest>",
    "review_envelope_sha256": "sha256:<current renewable envelope digest>",
    "review_evidence_sha256": "sha256:<current external evidence digest>"
  },
  "contracts": {},
  "cvm": {},
  "trust_domains": {
    "diligence_qvl": {},
    "arena_qvl": {},
    "anchor_writer_qvl": {},
    "compute_metering_qvl": {},
    "compute_metering": {}
  },
  "wallet_auth": {
    "domain": "dnai-wikigen",
    "uri": "urn:dnai:wikigen"
  },
  "execution_policy": {},
  "attestations": {},
  "arena_registry_bindings": {},
  "requested_features": {
    "contract_writes": true,
    "artifact_upload": true,
    "compute_console": true,
    "compute_vault_funding": true,
    "compute_vault_authorization": true,
    "arena_submission": true
  }
}
```

`deployment_intent_sha256` and `cvm_launch_intent_sha256` are committed inside
the canonical `dnai.final-release-authority-core.v2`. The candidate's
`operator_policy.final_authority_sha256` must equal `sha256:` plus the bare
`execution_policy.rollback_anchor.release_manifest_commitment`. The current
review envelope binds that same authority hash. Its envelope/evidence hashes
are deliberately outside the authority core so a truthful review renewal does
not require a contract redeployment or a new anchor commitment. Independently,
the anchor `writer_release_commitment` must equal `0x` plus the bare reviewed
CVM launch-intent digest; it is intentionally not the final-authority digest.

## Execution-policy trust descriptor

`execution_policy` is an exact immutable release descriptor. It is the sole
source for the public browser pins
`VITE_EXECUTION_POLICY_ANCHOR_ADDRESS`,
`VITE_EXECUTION_POLICY_ANCHOR_CODE_HASH`,
`VITE_EXECUTION_POLICY_ANCHOR_WRITER`,
`VITE_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT`,
`VITE_EXECUTION_POLICY_ANCHOR_CONFIRMATIONS`,
`VITE_EXECUTION_POLICY_ANCHOR_MAX_BLOCK_AGE_SECONDS`,
`VITE_EXECUTION_POLICY_ANCHOR_MAX_FUTURE_BLOCK_SKEW_SECONDS`,
`VITE_EXECUTION_POLICY_APPROVAL_DOMAIN_HASH`,
`VITE_EXECUTION_POLICY_APPROVER_ROOT_HASH`, and
`VITE_EXECUTION_POLICY_APPROVER_HASHES_JSON`; the release environment
serializer rejects missing keys and any operator-added environment key. The
descriptor shape is:

```json
{
  "canonicalization_version": "policy-kernel-canonicalization/v2",
  "approval_schema": "dnai-wikigen/execution-policy-approval/v3",
  "api_schema_version": 3,
  "store_schema_version": 5,
  "approval_domain": "base-sepolia:84532:<release-manifest-commitment>:0x<compose-hash>:<sha256-app-id>:<approver-root>",
  "approval_domain_hash": "<64 lowercase hex>",
  "approver_hashes": ["<64 lowercase hex, sorted and unique>"],
  "approver_root_hash": "<64 lowercase hex>",
  "rollback_anchor": {
    "schema": "dnai.execution-policy-rollback-anchor.v1",
    "status": "verified_active_frozen_release_writer",
    "chain_id": 84532,
    "contract_address": "0x<nonzero Base Sepolia anchor>",
    "runtime_code_hash": "0x<keccak256 exact runtime bytecode>",
    "release_manifest_commitment": "<64 lowercase hex>",
    "evidence_sha256": "sha256:<64 lowercase hex>",
    "writer_address": "0x<nonzero dstack-derived writer>",
    "writer_release_commitment": "0x<bare cvm_launch_intent_sha256 digest>",
    "writer_custody": "dstack_derived_execution_policy_anchor_writer",
    "writer_key_path": "tinker/execution_policy_anchor_writer",
    "confirmations": 12,
    "max_block_age_seconds": 3600,
    "max_future_block_skew_seconds": 30,
    "verification_model": "single_rpc_reported_finalized_with_confirmation_depth",
    "independent_rpc_quorum_verified": false,
    "consensus_proof_verified": false
  }
}
```

The approver root is SHA-256 over the UTF-8 domain prefix
`dnai-wikigen/execution-policy-approver-root/v1\0` followed by Python-canonical
JSON for the exact sorted hash array (ASCII, sorted keys, no insignificant
whitespace). The approval-domain hash is SHA-256 over the separate UTF-8 domain
prefix `dnai-wikigen/execution-policy-approval-domain/v1\0` followed by the
exact ASCII approval domain. The generator recomputes both values; it does not
trust candidate-supplied digests.

The approval domain is also recomputed exactly from Base Sepolia chain ID, the
rollback anchor's release-manifest commitment, the main CVM's `0x`-prefixed
compose hash, SHA-256 of its exact app ID, and the approver root. This prevents
approval reuse across a different suite, CVM release, or signer set. The Arena
worker release manifest commits the same versions, domain, hash set, root, and
anchor descriptor into its frozen registry release-policy commitment.

Approval schema v3 and authenticated store schema v5 additionally bind the
runtime-derived hash-only `execution_context_hash` to each PASS approval and
decision record. For Compute this context is derived from both the exact intent
commitment and exact compiled-recipe commitment, so a valid approval for one
recipe cannot authorize a substituted provider/model/parameter recipe. The
context is runtime data rather than a new release-descriptor field; the reviewed
derivation code is transitively pinned by the exact image, compose, and release
commitments above. API schema v3 exposes the bounded context hash so every
consumer can require it at the execution boundary.

The rollback anchor is a bounded same-RPC observation, not a QVL result,
independent-RPC quorum, consensus proof, or generic claim of chain finality.
During release, the generator asks the same configured Base Sepolia RPC for
both the latest block and its `finalized` block tag. It computes the
confirmation-depth block as `latest - (confirmations - 1)` and selects the
older block number of that result and the RPC-reported `finalized` block. The
descriptor names this exact model
`single_rpc_reported_finalized_with_confirmation_depth`, while
`independent_rpc_quorum_verified` and `consensus_proof_verified` are
immutably `false`.

The anchor's nonzero address is then queried at the exact
`contracts.executionPolicyAnchor.releaseSnapshotBlockNumber` recorded in the
ledger, and that number must equal the selected older block. Runtime bytecode
and every current anchor field are read at that block and must match the
ledger: exact nonzero writer and release commitment, no pending writer,
permanently frozen writer rotation, and `paused=false`. Sequence/head may both
be empty immediately after activation or both nonempty after anchoring begins;
a zero/nonzero mismatch is rejected. The matching fresh-deployment history
continues to prove constructor provenance separately: zero writer, zero head,
rotations open, and `paused=true`.

`evidence_sha256` is not an operator assertion. It is SHA-256 over the exact
canonical bytes, including the final newline, of the required
`dnai.execution-policy-anchor-writer-qvl-evidence.v2` artifact supplied through
`--anchor-writer-evidence`. The generator rejects a merely nonzero hash, a
self-produced dstack envelope, noncanonical bytes, extra fields, a raw quote,
or any artifact whose independently signed verdict fails the release checks
below.

The writer release commitment is exactly `0x` plus the bare
`cvm_launch_intent_sha256` digest. The separate
`release_manifest_commitment` remains the canonical final-authority digest.
Its custody label and key path are fixed, not operator-selectable.
Confirmations must be 2 through 256, maximum block age 30 through 3600 seconds,
and future skew 0 through 300 seconds. These same values are committed into the
Arena worker policy and emitted to the browser, so a different finality or
freshness policy cannot be introduced at one layer.
The release example and compose-facing default use the full 3600-second maximum
because Base Sepolia's same-RPC `finalized` tag can trail `latest` by more than
five minutes. This wider liveness window does not change the exact candidate
block pinning or upgrade the observation into an independent-RPC quorum or a
consensus-finality proof.

Until real deployment evidence exists, an
operator may draft only this explicit unavailable placeholder for review:

```json
{
  "schema": "dnai.execution-policy-rollback-anchor.v1",
  "status": "unavailable",
  "chain_id": 84532,
  "contract_address": "0x0000000000000000000000000000000000000000",
  "runtime_code_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "release_manifest_commitment": "0000000000000000000000000000000000000000000000000000000000000000",
  "evidence_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "writer_address": "0x0000000000000000000000000000000000000000",
  "writer_release_commitment": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "writer_custody": "unavailable",
  "writer_key_path": "unavailable",
  "confirmations": 12,
  "max_block_age_seconds": 3600,
  "max_future_block_skew_seconds": 30,
  "verification_model": "single_rpc_reported_finalized_with_confirmation_depth",
  "independent_rpc_quorum_verified": false,
  "consensus_proof_verified": false
}
```

That placeholder is intentionally rejected by `npm run release:env`; it can
never generate a live browser build.

Every contract entry contains an `address` and the `keccak256` of its exact
runtime bytecode in `runtime_code_hash`. Additional exact fields are:

| Contract key | Additional fields |
| --- | --- |
| `diligence_room` | `developer`, `result_verifier`, immutable attestation verifier/policy binding; final-authority v2 additionally commits the exact one-compose/one-TEE frozen admission set |
| `challenge_registry` | `owner` |
| `royalty_distributor` | none |
| `tinker_account_encumbrance` | `owner`, `account_commitment` |
| `compute_credit_vault` | `owner`, `developer`, `metering_verifier`, `developer_fee_bps`, `tee_identity`, `compose_hash`, `native_rate_policy_commitment`, `native_provider`, `erc20_asset_address`, `erc20_rate_policy_commitment`, `erc20_provider`; final-authority v2 projects these into complete native/ERC20 policy tuples |
| `email_oracle_auth` | `owner`, `consumer_address`, `upgrade_delay_seconds`, plus exact `release` compose/device/KMS/boot/restart/evidence bindings |
| `usdc` | Circle's canonical Base Sepolia address, `symbol: "USDC"`, `decimals: 6` |

The CVM object has exactly this shape:

```json
{
  "app_id": "<fresh Phala app id>",
  "cvm_id": "<fresh Phala CVM id>",
  "compose_hash": "<64 lowercase hex, no 0x>",
  "local_compose_hash": "<64 lowercase hex, no 0x>",
  "rendered_compose_sha256": "<64 lowercase hex, no 0x>",
  "os_image_hash": "<64 lowercase hex, no 0x>",
  "os_is_dev": false,
  "public_logs": false,
  "public_sysinfo": false,
  "public_tcbinfo": false,
  "tee_identity": "0x<dstack-derived signer>",
  "delegate_url": "https://<exact delegate host>",
  "images": [],
  "allowed_browser_origins": [
    "https://wikigen.me",
    "https://www.wikigen.me",
    "https://wikigenme.pages.dev"
  ],
  "runtime_controls": {
    "wallet_auth_required": true,
    "runtime_bearer_required": true,
    "durable_compute_store": true,
    "durable_arena_store": true,
    "durable_arena_ingress_store": true,
    "artifact_ciphertext_only": true,
    "plaintext_artifact_endpoint_disabled": true,
    "plaintext_card_endpoint_disabled": true,
    "bootstrap_fail_open_disabled": true,
    "browser_ports_internal_only": true,
    "nondefault_browser_credentials_required": true,
    "project_owned_browser_images": true,
    "oracle_internal_only": true,
    "oracle_runtime_auth_required": true,
    "oracle_health_liveness_only": true,
    "oracle_pin_response_minimized": true,
    "oracle_private_metadata_egress_prohibited": true,
    "oracle_replay_fail_closed": true,
    "provider_dispatch_enabled": false,
    "hostile_candidate_execution_enabled": false,
    "raw_secret_egress_prohibited": true
  }
}
```

The three `allowed_browser_origins` values shown above are an exact production
allowlist, not a minimum: preview, wildcard, localhost, path-bearing, and extra
origins are rejected.

The oracle deliberately has no candidate field, browser environment variable,
or public ledger endpoint. In the production compose it has no host `ports`
mapping and is reachable only by the delegate on the private CVM network. Its
unauthenticated health route proves process liveness only; mailbox readiness
and OTP release require the same-CVM bearer. OTP responses are exact,
metadata-minimized envelopes, and replay-ledger persistence fails closed before
any code is released.

Each image entry has exactly `service`, `image`, `source_digest`, `source_ref`,
`repo`, `signer_workflow`, `provenance_attestation`, and `sbom_attestation`.
The image set is exactly `delegate`, `oracle`, and `neko`; extra helpers,
playgrounds, debug services, and relabeled repositories are rejected. Each
service must use its matching project-owned repository (`tinker-delegate`,
`tee-email-oracle`, or `neko-chrome`) and an immutable `@sha256:` digest. The
source digest must equal the release commit; the source ref must be
`refs/heads/main` or a version tag; and both attestation markers must be
`verified` for all three images. The generator then independently reruns
`gh attestation verify` for every image's SLSA provenance and SPDX SBOM
predicates, with self-hosted runners denied and the repository/workflow
identities pinned in code.

## Separate CVM trust-domain descriptors

`trust_domains` has exactly `diligence_qvl`, `arena_qvl`,
`anchor_writer_qvl`, `compute_metering_qvl`, and `compute_metering`. These are
five separate Phala CVMs, not services added to the main evaluated-CVM compose;
with the main CVM the release total is six. Each descriptor has the following
exact deployment fields, plus the context-specific `identity` fields below:

```json
{
  "schema": "<context-specific release descriptor schema>",
  "platform": "phala_cloud",
  "release_sha": "<same clean 40-character release SHA>",
  "app_id": "<separate Phala app id>",
  "cvm_id": "<separate Phala CVM id>",
  "compose_hash": "<64 lowercase hex, no 0x>",
  "local_compose_hash": "<64 lowercase hex, no 0x>",
  "rendered_compose_sha256": "<64 lowercase hex, no 0x>",
  "os_image_hash": "<64 lowercase hex, no 0x>",
  "os_is_dev": false,
  "public_logs": false,
  "public_sysinfo": false,
  "public_tcbinfo": false,
  "ssh_enabled": false,
  "endpoint": "https://<exact separate host>/<verify-or-meter>",
  "endpoint_authentication": "bearer_required",
  "image": {
    "image": "ghcr.io/therealwiki/dnai-wikigen/<attestation-qvl-or-compute-metering>@sha256:<digest>",
    "source_digest": "<same release SHA>",
    "source_ref": "refs/heads/main",
    "repo": "therealwiki/dnai-wikigen",
    "signer_workflow": "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
    "provenance_attestation": "verified",
    "sbom_attestation": "verified"
  },
  "identity_evidence_classification": "deployment_pins_require_external_platform_verification",
  "identity": {}
}
```

The five QVL descriptors use schema `dnai.release-qvl-cvm.v1`, authenticated
`/challenge`, `/verify`, and `/attestation` endpoints, and one of the literal
primary profiles `diligence`, `arena`, `execution_policy_anchor_writer`,
`compute_workload`, or `compute_metering`. The Diligence policy may additionally
enable exactly the secondary `email_oracle_kms_restart` profile. No other
multi-profile policy is accepted.
Their identity object is the exact public `GET /identity` shape:

```json
{
  "schema": "dnai.attestation-qvl-identity.v1",
  "verifier_address": "0x<policy-derived QVL signer>",
  "release_policy_hash": "0x<SHA-256 of the complete canonical QVL policy>",
  "signer_custody": "dstack_derived_separate_cvm",
  "raw_secret_egress": false
}
```

Each QVL descriptor also has an exact `policy_binding`. The Compute-workload
descriptor is deliberately dynamic-recipient-specific and accepts only
`{"kind":"compute_workload_recipient_v1"}`. The other four repeat the canonical
policy's Base Sepolia chain, evaluated contract, evaluated-CVM app/compose/OS
identity, allowed execution signer, and context-specific report-data kind:

```json
{
  "chain_id": 84532,
  "contract_address": "0x<fresh DiligenceRoom, ChallengeRegistry, ExecutionPolicyAnchor, or ComputeCreditVault>",
  "evaluated_app_id": "<main evaluated-CVM app id>",
  "evaluated_compose_hash": "0x<main evaluated-CVM compose hash>",
  "evaluated_os_image_hash": "<main evaluated-CVM OS image hash>",
  "allowed_signer_address": "0x<context-specific dstack-derived signer>",
  "report_data_binding_kind": "<diligence_result_signer_v1, arena_candidate_ingress_v1, execution_policy_anchor_writer_v1, or compute_metering_signer_v1>"
}
```

The anchor-writer binding additionally repeats the exact
`writer_release_commitment`, literal
`tinker/execution_policy_anchor_writer` key path, and
`dstack_derived_execution_policy_anchor_writer` custody label. Those values
enter the independently recomputed quote report-data digest; request assertions
cannot change them.

The Compute-workload QVL binding authenticates the separately attested workload
recipient activation before that recipient may accept encrypted inputs. Its
identity and challenge-bound verdict remain part of the seven-CVM evidence set;
the later recipient-activation observation is a separately branded post-release
fact and is not smuggled into that evidence set.

The Compute-metering QVL binding evaluates the separate independent meter, not
the main runtime. Its static digest binds the exact meter signer, vault, meter
policy-set hash, release compose/app/OS identity, and
`compute_metering_signer_v1` profile. The meter cannot certify itself merely by
returning a signature or `/identity` response; the QVL's challenge-bound v4
verdict and current activation-evidence lease are a separate required trust
layer.

The Diligence QVL's optional Email/KMS restart binding commits the email-oracle
app and compose identity, exact `EmailOracleAuth` address/runtime hash, consumer
app and compose, KMS app/proxy/implementation addresses and implementation code
hash, release binding hash, and the fixed profile
`email_oracle_kms_restart`. It reuses only the Diligence policy/root/CVM and
challenge store; a Diligence-result challenge cannot authorize this profile.

The five QVL policy hashes and signer addresses must differ. The generator
requires each verdict signer to equal its context's descriptor address and also
to be present in the external human-reviewed allowlist. It does **not** treat
the QVL's own `/identity` or optional self-attestation response as proof of that
QVL CVM. `identity_evidence_classification` is deliberately non-promotional:
the descriptor is a set of release pins whose QVL platform identity still must
be verified out of band before its address enters the external trust-root input.
This avoids a circular “QVL attests itself, therefore trust its verdict” chain.

The independent Compute-meter descriptor uses schema
`dnai.release-compute-metering-cvm.v1` and
the exact authenticated `/meter` endpoint. Its identity object matches the
bounded metering service:

```json
{
  "schema": "dnai.compute-metering-identity.v1",
  "classification": "attested_deterministic_metering",
  "provider_authoritative_invoice": false,
  "chain_id": 84532,
  "vault_address": "0x<fresh ComputeCreditVault>",
  "policy_set_hash": "0x<SHA-256 of the complete canonical immutable policy set>",
  "metering_verifier": "0x<policy-set-derived metering signer>",
  "assets": [
    {
      "asset": "0x0000000000000000000000000000000000000000",
      "provider": "0x<reviewed native-policy provider recipient>",
      "rate_policy_commitment": "0x<native policy commitment>"
    },
    {
      "asset": "0x<canonical Base Sepolia USDC>",
      "provider": "0x<reviewed USDC-policy provider recipient>",
      "rate_policy_commitment": "0x<USDC policy commitment>"
    }
  ],
  "signer_custody": "dstack_derived_independent_cvm",
  "raw_secret_egress": false
}
```

`assets` is a sorted, nonempty one-or-two-entry set with unique assets and
commitments. Each entry also pins the public provider recipient used by that
canonical rate card; a provider cannot overlap a control-plane role. When browser authorization is requested, it must contain both the
native and canonical-USDC entries and match every authorization-enabled
frontend commitment. Funding and safety withdrawals remain independently gated
and may stay available when authorization is disabled. The descriptor's
`metering_verifier` must equal the immutable on-chain
`ComputeCreditVault.meteringVerifier`; a manifest address, an `/identity`
response, or an on-chain address by itself cannot enable authorization. The
classification is deterministic bounded metering, not a provider-authoritative
invoice.

When authorization is requested, the pinned live-state read also requires one
allowed ERC20, two active policies, one approved compose hash, exactly one
registered execution TEE, and zero pending asset, rate-policy, or compose
proposals. The same cardinalities are literal fields in the canonical metering
policy set, so the browser release gate and independent CVM cannot disagree
about a hidden pending or historical admission.

All six independent descriptors' image subjects are passed through the same
GitHub SLSA-provenance and SPDX-SBOM checks as the main CVM images. All five QVL
instances must use the `attestation-qvl` image repository, and metering must use
`compute-metering`; relabeled images, mutable tags, fork provenance, source-SHA
drift, self-hosted workflow provenance, dev/public/SSH posture, endpoint query
parameters, and missing policy roots fail closed. The top-level release SHA is
then compared to clean `HEAD`, so every descriptor is bound to the same clean
source state rather than merely carrying an arbitrary commit string.

The artifact and Arena deployment-evidence inputs are fresh bounded outputs
from their context-specific verifier/identity ceremonies. Their explicit
producer-side status remains `evidence_checked_tdx_unverified`: the generator
uses these files to bind the digest-pinned local compose and rendered compose
to the live envelope, image set, report data, app, OS, and attested compose
hash, but never promotes their service-local trust label. It requires their
original false TDX/production claims, then separately authenticates a current
activation-evidence lease in a challenge-bound v4 verdict from the correct
external QVL root. Evidence outside the reviewed signed lease is rejected.
Anchor-writer and Email/KMS evidence are loaded
as separate canonical bounded artifacts and validated under the rules below.

## Independent TDX verdicts

`attestations` contains exactly `artifact`, `arena`, and `compute_metering`.
Each object contains the QVL-issued challenge, quote hash, and one signed v4
verdict. The raw quote is sent only to the authenticated QVL and is never
serialized into the browser candidate. Email/KMS restart proof is instead a
separate canonical `dnai.email-oracle-external-release-evidence.v1` artifact;
its exact byte hash is pinned at
`contracts.email_oracle_auth.release.external_evidence_sha256`, and its nested
QVL verdict uses the Diligence root's separately scoped
`email_oracle_kms_restart` profile.

```json
{
  "artifact": {
    "context": "artifact",
    "quote_sha256": "sha256:<64 lowercase hex>",
    "verdict": {
      "schema": "dnai.independent-tdx-verdict.v4",
      "verification_method": "intel_tdx_dcap_qvl",
      "verified": true,
      "chain_id": 84532,
      "domain": "main_runtime_cvm",
      "profile": "diligence",
      "cvm_id": "<exact lowercase evaluated CVM id>",
      "deployment_intent_sha256": "sha256:<exact deployment-intent digest>",
      "release_authority_sha256": "sha256:<exact seven-CVM release-authority digest>",
      "ceremony_nonce": "0x<exact nonzero ceremony nonce>",
      "measurement_policy_sha256": "sha256:<exact QVL measurement-policy digest>",
      "release_policy_hash": "0x<exact QVL policy hash>",
      "challenge_id": "0x<random nonzero 32-byte challenge id>",
      "challenge_digest": "0x<signed challenge digest>",
      "challenge_issued_at": 0,
      "challenge_expires_at": 0,
      "quote_hash": "0x<same quote SHA-256>",
      "report_data": "0x<static 32-byte release/profile digest>",
      "compose_hash": "0x<release compose hash>",
      "app_id": "<exact nonzero bare lowercase 40-hex Phala app id>",
      "os_image_hash": "<release OS image hash>",
      "signer_address": "0x<release TEE identity>",
      "contract_address": "0x<fresh DiligenceRoom>",
      "issued_at": 0,
      "activation_evidence_lease_expires_at": 0,
      "expires_at": 0,
      "verifier_address": "0x<external trusted verifier>",
      "verifier_signature": "0x<65-byte canonical low-s signature>"
    }
  }
}
```

The Arena, anchor-writer, Compute-metering, and Email/KMS restart verdicts have
the same exact signed v4 lineage and lease fields but use their exact
domains, profiles, CVM IDs, measurement policies, and evaluated
contracts/workloads. The generator authenticates the QVL challenge signature
before quote collection, re-derives the challenge digest and the exact 64-byte
quote report data (`static_digest || challenge_digest`), authenticates the final
EIP-191 verdict, and requires the correct descriptor plus external allowlist.
Challenges are single-use and at most 120 seconds; Intel DCAP/QVL appraisal
must finish strictly before challenge expiry, and success, rejection, timeout,
and cancellation all consume the challenge. The separately signed
`activation_evidence_lease_expires_at` is an exact alias of `expires_at`, may
outlive the consumed challenge, and is capped at the reviewed 900-second
activation-evidence lease. A wrong profile/policy, replay, challenge-boundary
completion, expired or oversized lease, alias mismatch, or verifier that
overlaps an execution/control role fails closed.

The separately loaded anchor-writer artifact has exact schema
`dnai.execution-policy-anchor-writer-qvl-evidence.v2`. It contains only the
Base Sepolia chain, anchor/writer/release/key-path/custody bindings, main-CVM
app/compose/OS identity, recomputed 32-byte report data, quote hash and bounded
size, release-pinned QVL policy hash and verifier address, and the same exact
signed verdict shape above. It also fixes
`tdx_measurement_policy=exact_release_pinned_measurements`,
`raw_quote_egress=authenticated_https_qvl_only`,
`raw_quote_in_artifact=false`, and `raw_private_key_egress=false`.

The release generator hashes the artifact's exact canonical bytes, recomputes
the report-data digest from the descriptor rather than the artifact, requires
the verdict's quote/report/CVM/writer/chain/anchor values to match, recovers the
canonical low-s EIP-191 signer, and requires that signer and policy hash to
match the distinct `anchor_writer_qvl` descriptor and external trust-root
input. The QVL release policy independently pins the full TDX measurement map
and accepts only DCAP status `OK`; its policy-derived dstack signer makes the
reviewed policy hash/root part of the trust chain. The raw quote is sent by the
real-dstack one-shot command only in the bearer-authenticated HTTPS `/verify`
request and never appears in the artifact, stdout error path, or browser build.

### Compute-workload recipient activation

Compute-workload upload additionally requires one exact
`dnai.compute.workload-recipient-activation.v3` object. There is no activation
v1/v2 compatibility path. Its outer record contains exactly the Base Sepolia
`chain_id`, `main_runtime_cvm` domain, `compute_workload` profile, main-runtime
`cvm_id`, `deployment_intent_sha256`, `release_authority_sha256`, nonzero
`ceremony_nonce`, `measurement_policy_set_sha256`, the dedicated
Compute-workload QVL `measurement_policy_sha256`, and the branded
`main_runtime_evidence_sha256`, followed by the recipient key/report,
main-runtime app/compose/OS identity, release policy, quote/verifier/verdict
digests and times, explicit `recipient_evidence_lease_expires_at`,
recipient-release commitment, recipient attestation, and the complete
authenticated verdict-v4 object. Missing fields, extra fields,
legacy schemas, alternate domains/profiles, noncanonical CVM IDs, and any
outer/inner lineage disagreement fail closed.

The stable recipient commitment is exactly
`SHA-256("dnai-wikigen/compute-workload-recipient-release/v2\0" ||
canonical_ascii_json(payload))`. The payload schema is
`dnai.compute.workload-recipient-release.v2` and includes every outer release
lineage field, recipient key/report and runtime measurement, the QVL method,
verdict signer and contract, plus the exact normalized recipient attestation.
There is no release-commitment v1 fallback. The browser also recomputes the
verdict-v4 EIP-191 digest under
`dnai-wikigen/independent-tdx-verdict/v4\0`, authenticates the configured
purpose-separated QVL signer, verifies the recipient report-data binding, and
checks every duplicated activation/verdict field before accepting ciphertext.
The recipient lease must exactly equal both the activation `expires_at` and the
verdict's activation-evidence lease, remains capped at 300 seconds for this
post-restart recipient epoch, and—not the already-consumed QVL challenge—is the
freshness boundary used by the browser.

The private recipient-verification proof separately carries the initial
main-runtime lease, initial Compute-workload-QVL lease, recipient lease, and a
`terminal_evidence_lease_expires_at` equal to their minimum. O then caps that
terminal again by the activation plan's aggregate lease across all seven CVMs.
This ceremony-only terminal is enforced while minting the signed build
authority; it is not copied into a soon-expiring compile-time browser variable.

The private compute-workload activation observation carries the verifier's
fully normalized activation as `source_activation`; it is not a second schema
that may reinterpret or remint the evidence. Before projecting the fixed
twenty public workload Vite bindings, release validation must compare that
source activation to the canonical seven-CVM release authority: deployment
intent, release-authority digest, ceremony nonce, measurement-policy-set
digest, exact main-runtime descriptor and evidence digest, exact
Compute-workload-QVL measurement policy and identity, fresh ComputeCreditVault
authority, and signed verdict lineage must all agree. The public projection
adds exact non-secret pins for the main-runtime CVM ID, deployment intent,
release authority, ceremony nonce, measurement-policy set, Compute-workload
measurement policy, and main-runtime evidence. The browser compares all seven
against the authenticated endpoint instead of trusting endpoint self-agreement.
It does not add raw quotes, private authority artifacts, or unreviewed Vite
keys.

## Arena registry bindings

The build pins each API catalog version to one frozen current Open on-chain
version. The key is `<catalog-challenge-id>@<semantic-version>` and the value is:

```json
{
  "registry_challenge_id": "1",
  "registry_version": 1,
  "catalog_manifest_hash": "<64 lowercase hex>",
  "metadata_uri": "ipfs://<immutable metadata CID>",
  "metadata_hash": "0x<same catalog manifest hash>",
  "sealed_artifact_commitment": "0x<64 lowercase hex>",
  "evaluator_commitment": "0x<64 lowercase hex>",
  "release_policy_commitment": "0x<64 lowercase hex>"
}
```

The generator reads every binding on Base Sepolia and requires the registry and
challenge to be unpaused, the lifecycle to be `Open`, the configuration to be
frozen, the bound version to be current, and every URI/commitment to match. The
browser repeats the same single-block authorization before encryption and again
immediately before posting ciphertext.

The generator also emits
`VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256`, a domain-separated SHA-256 over the
complete canonical binding set. The derived per-challenge
`release_policy_commitment` is excluded from that set hash to avoid a hash
cycle; each selected policy commitment includes the approved-set digest and is
then checked separately against the frozen on-chain version. The browser
recomputes the set digest before selecting an `id@version`. `ChallengeRegistry`
is intentionally extensible, so later unrelated registry rows may exist; they
do not enter the running release and cannot unlock encryption or execution
until a later reviewed release explicitly includes them and emits a new digest.

## Live checks before output

No environment file is written unless all of the following pass:

- The worktree is clean and `HEAD` equals the full release SHA.
- All five independent-CVM descriptors repeat that release SHA, pin canonical
  repository/workflow provenance and digest-only images, use separate
  app/CVM/compose/HTTPS identities, and preserve a non-dev, non-SSH, private
  Phala diagnostic posture. Their image attestations are independently checked
  with GitHub CLI rather than trusted from manifest strings.
- The ledger contains the matching fresh reviewed-suite history entry, uses Foundry
  account `dev`, records no raw private key, and all current addresses/source
  commits match, including a freshly deployed `EmailOracleAuth`.
- The ledger and candidate describe the same hardened replacement CVM, exact
  endpoints, exact image digests, and release source; no debug exception is
  active.
- Every configured address has bytecode with exactly the pinned runtime hash.
- The current ledger `ExecutionPolicyAnchor` entry is a post-timelock snapshot
  at one positive `releaseSnapshotBlockNumber`: exact nonzero dstack writer,
  exact release commitment, zero pending writer fields, permanently frozen
  writer rotations, and unpaused. Its sequence/head pair must be both empty or
  both nonempty and must equal the live contract at that same block. The fresh
  suite and append-only deployment-history records must still prove the
  separate fail-closed constructor state rather than being rewritten.
- The release snapshot number is exactly the older of the configured RPC's
  `finalized` tag and `latest - (confirmations - 1)`. This is explicitly a
  single-RPC-reported finalized/depth model with no independent RPC quorum and
  no consensus proof; release copy and evidence must not call it QVL or
  consensus finality.
- `DiligenceRoom` has the exact developer/result verifier, a permanently frozen
  100 bps protocol fee, the one-way 100 bps artifact-independent compute tariff
  enabled, mandatory compose and TEE gates enabled and irreversibly frozen, the
  exact compose approved, and the exact TEE identity compose-bound. The live
  pinned-block snapshot must also prove exactly one approved compose, exactly
  one approved TEE identity, zero pending compose/TEE proposals, and permanent
  freezes on both addition paths. Both the current ledger entry and matching
  fresh-suite deployment-history entry must record the initial all-zero,
  additions-open fail-closed posture as well as the fixed settlement and gate
  requirements.
- Every project-owned contract in both the current ledger and latest deployment
  history has the exact runtime bytecode hash pinned by the release candidate;
  an address plus source-commit claim is not accepted as deployment evidence.
- `ChallengeRegistry` has the exact owner and all pinned versions pass the Arena
  checks above.
- `TinkerAccountEncumbrance` is the active post-ceremony ledger record, not its
  constructor draft: exact owner with no pending transfer; exact account
  commitment; canonical decimal-string per-operation caps; exactly one compose
  and one distinct manager; exact current and frozen-baseline roots/counts/caps;
  no pending policy; immutable two-day delay; `releasePolicyFrozen=true`; and
  `emergencyHalted=false`. Matching deployment history retains the pristine
  halted draft, and ordered release history retains both governance phases.
- `ComputeCreditVault` matches its exact owner, separated developer and
  independent metering-verifier roots, frozen fee, and runtime hash. Funding is
  enabled only while the vault is unpaused and canonical Base Sepolia USDC is
  allowlisted. Job authorization additionally requires the release compose and
  TEE binding, an irreversibly required compose gate, frozen asset/rate-policy
  additions, exactly one ERC20 asset, exactly two active rate policies, exactly
  one approved compose hash, and exact active native and USDC commitments.
  Authorization additionally requires the
  separate metering-CVM descriptor, its dstack custody label, exact vault and
  immutable verifier, canonical policy-set hash, and the sorted complete native
  plus canonical-USDC asset/commitment set. Credits remain non-transferable
  exact-asset claims; the release adds no oracle, FX, synthetic compute unit, or
  provider-invoice claim.
- `EmailOracleAuth` has the exact owner/consumer, disables allow-any-device,
  approves the release compose hash, authorizes the consumer, and freezes both
  oracle-code and consumer registries. The runtime also proves that two distinct
  HTTPS Base Sepolia RPCs agreed on one fresh finalized block, exact runtime
  code, and authorization results, then advanced the restart-preserved
  checkpoint. The Diligence-root `email_oracle_kms_restart` v4 verdict binds the
  exact Email/KMS release tuple; neither claim is whole-volume anti-rollback.
- The payment token is Circle's canonical Base Sepolia USDC address, has the
  pinned runtime bytecode, and reports exactly `USDC` with six decimals; an
  operator-deployed metadata lookalike is rejected.
- All five purpose-separated QVL roots are externally reviewed, and every
  required challenge-bound v4 verdict has a current, authenticated, bounded
  activation-evidence lease after its single-use DCAP challenge, and is exactly
  bound to the release chain, domain, CVM ID, deployment intent,
  release authority, ceremony nonce, measurement policy, contracts, profile,
  release policy, challenge, context-specific TEE signer, app, compose, OS,
  quote, and report data. The
  anchor-writer verdict also
  commits the exact writer release, key path, and custody through recomputed
  report data. Each is signed by its correct distinct QVL descriptor root and
  present in the external human-reviewed trust-root input. Compute-workload
  authenticates the dynamic recipient-activation protocol; Compute-metering
  evaluates the independent meter; Email/KMS restart uses the Diligence root's
  separately scoped secondary profile.
- Every live bytecode and contract-state read above is pinned to one explicit
  Base Sepolia block, preventing a mixed-state release decision while governance
  changes are being mined.

Only after those checks does the script serialize its fixed public Vite
allowlist. Unknown fields, newline injection, secrets, and arbitrary RPC values
cannot enter the generated file. WalletConnect configuration is emitted only
from the final authority core's exact optional lowercase 32-hex project ID;
an empty value explicitly disables WalletConnect for that release.
