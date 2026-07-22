import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { knownVector } from "../../scripts/execution-policy-release-core.fixture.mjs";
import {
  normalizeFinalReleaseAuthorityCore,
} from "../../scripts/execution-policy-release-core.mjs";
import {
  CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
  CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
  CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS,
  CLOUDFLARE_EXTERNAL_BUILD_FILES,
} from "./cloudflare-external-build-closure-core.mjs";
import {
  FRONTEND_BUILD_AUTHORITY_ROOT_FIELDS,
  FRONTEND_BUILD_CANDIDATE_SCHEMA,
  FRONTEND_BUILD_CANDIDATE_STATUS,
  FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
  FRONTEND_BUILD_INPUT_MANIFEST_SCHEMA,
  FRONTEND_BUILD_INPUT_MANIFEST_TRUTH_STATUS,
  FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS,
  FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS,
  FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS,
  HISTORICAL_CLOUDFLARE_D_BUILD_CONTROL_PATHS,
  HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
  HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
  __historicalFrontendReleaseCoreTest,
  assertHistoricalFinalCvmTopologyMatchesCandidate,
  assertFrontendBuildCandidateLineage,
  createFrontendBuildPreDPrivateInputs,
  finalReleaseAuthorityCoreFromHistoricalCandidate,
  frontendBuildCandidateReceiptSha256,
  frontendBuildInputManifestSha256,
  frontendBuildProjectedEnvSha256,
  historicalFinalReleaseAuthorityCoreSha256,
  historicalLiveReleaseCandidatePrebuildProjectionSha256,
  normalizeFrontendBuildCandidateReceipt,
  normalizeFrontendBuildInputManifest,
  normalizeHistoricalFrontendReleaseCandidate,
  projectHistoricalLiveReleaseCandidateToPrebuild,
  validateHistoricalFinalReleaseAuthorityCoreBinding,
} from "./frontend-release-historical-core.mjs";

const RELEASE_SHA = "a".repeat(40);
const SERIALIZED_ENV = `VITE_RELEASE_SHA=${RELEASE_SHA}\n`;
const pin = (byte) => `sha256:${byte.toString(16).padStart(2, "0").repeat(32)}`;
const address = (index) => `0x${index.toString(16).padStart(40, "0")}`;

const LINEAGE = Object.freeze(Object.fromEntries(
  FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS.map((field, index) => [
    field,
    pin(80 + index),
  ]),
));
const AUTHORITY_ROOTS = Object.freeze({
  contract_release_set_sha256:
    LINEAGE.fresh_contract_deployment_receipt_sha256,
  cvm_release_set_sha256:
    LINEAGE.seven_cvm_launch_completion_receipt_sha256,
  qvl_measurement_policy_set_sha256:
    LINEAGE.qvl_measurement_policy_set_sha256,
});
const BINDING = Object.freeze({
  deploymentIntentSha256: LINEAGE.deployment_intent_sha256,
  reviewerAuthorityGenesisAcceptanceSha256:
    LINEAGE.reviewer_authority_genesis_acceptance_sha256,
  ceremonyAuthorizationSha256: LINEAGE.ceremony_authorization_sha256,
  runtimeAuthorityDependencySha256:
    LINEAGE.runtime_authority_dependency_sha256,
  computeWorkloadActivationObservationSha256:
    LINEAGE.compute_workload_activation_observation_sha256,
  frontendBuildSha256: pin(200),
});

function aggregateExternalClosure(value) {
  const payload = {
    schema: value.schema,
    truth_status: value.truth_status,
    entrypoints: value.entrypoints,
    files: value.files,
    raw_secret_egress: value.raw_secret_egress,
  };
  return {
    ...value,
    aggregate_sha256: `sha256:${createHash("sha256")
      .update(__historicalFrontendReleaseCoreTest.EXTERNAL_AGGREGATE_DOMAIN, "utf8")
      .update("\0", "ascii")
      .update(`${JSON.stringify(payload, null, 2)}\n`, "utf8")
      .digest("hex")}`,
  };
}

function externalClosure() {
  return aggregateExternalClosure({
    schema: HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
    truth_status: HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
    entrypoints: __historicalFrontendReleaseCoreTest.EXTERNAL_ENTRYPOINTS.map(
      ({ kind, path: entryPath }) => ({ kind, path: entryPath }),
    ),
    files: __historicalFrontendReleaseCoreTest.EXTERNAL_FILES.map(
      ({ kind, path: entryPath }, index) => ({
        kind,
        path: entryPath,
        mode: 0o600,
        size: index + 1,
        sha256: pin(10 + index),
      }),
    ),
    aggregate_sha256: pin(250),
    raw_secret_egress: false,
  });
}

function preDPrivateInputs() {
  return createFrontendBuildPreDPrivateInputs({
    liveCandidatePrebuildProjectionSha256: pin(1),
    rawSha256ByFlag: Object.fromEntries(
      FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS.map((flag, index) => [
        flag,
        pin(2 + index),
      ]),
    ),
  });
}

function manifest() {
  return normalizeFrontendBuildInputManifest({
    schema: FRONTEND_BUILD_INPUT_MANIFEST_SCHEMA,
    truth_status: FRONTEND_BUILD_INPUT_MANIFEST_TRUTH_STATUS,
    release_sha: RELEASE_SHA,
    git_source: {
      clean_worktree: true,
      git_tree_oid: `sha1:${"b".repeat(40)}`,
      source_fingerprint_sha256: pin(150),
    },
    pre_D_private_inputs: preDPrivateInputs(),
    semantic_lineage: LINEAGE,
    projected_env_sha256: frontendBuildProjectedEnvSha256(SERIALIZED_ENV),
    primary_rpc_url: "https://sepolia.base.org",
    secondary_rpc_url: "https://base-sepolia-rpc.publicnode.com",
    qvl_verifier_roots: [1, 2, 3, 4, 5].map(address),
    authority_roots: AUTHORITY_ROOTS,
    build_controls: HISTORICAL_CLOUDFLARE_D_BUILD_CONTROL_PATHS.map(
      (controlPath, index) => ({ path: controlPath, sha256: pin(160 + index) }),
    ),
    external_build_closure: externalClosure(),
    frontend_dist_included: false,
    raw_secret_egress: false,
  });
}

function receipt() {
  const inputManifest = manifest();
  return normalizeFrontendBuildCandidateReceipt({
    schema: FRONTEND_BUILD_CANDIDATE_SCHEMA,
    status: FRONTEND_BUILD_CANDIDATE_STATUS,
    truth_status: FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
    release_sha: RELEASE_SHA,
    chain_id: 84_532,
    deployment_intent_sha256: BINDING.deploymentIntentSha256,
    reviewer_authority_genesis_acceptance_sha256:
      BINDING.reviewerAuthorityGenesisAcceptanceSha256,
    ceremony_authorization_sha256: BINDING.ceremonyAuthorizationSha256,
    runtime_authority_dependency_sha256:
      BINDING.runtimeAuthorityDependencySha256,
    compute_workload_activation_observation_sha256:
      BINDING.computeWorkloadActivationObservationSha256,
    frontend_build_sha256: BINDING.frontendBuildSha256,
    release_inputs_sha256: frontendBuildInputManifestSha256(inputManifest),
    release_env_sha256: frontendBuildProjectedEnvSha256(SERIALIZED_ENV),
    raw_secret_egress: false,
  });
}

function historicalCandidateFixture() {
  let core = structuredClone(knownVector());
  core.release_sha = RELEASE_SHA;
  core.cvm.app_id = "a0".repeat(20);
  for (const image of core.cvm.images) image.source_digest = RELEASE_SHA;
  core = normalizeFinalReleaseAuthorityCore(core);
  const runtimeAuthoritySha256 = `sha256:${"fa".repeat(32)}`;
  const contracts = structuredClone(core.contracts);
  delete contracts.diligence_room.release_admission;
  const ratePolicies = contracts.compute_credit_vault.rate_policies;
  contracts.compute_credit_vault = {
    address: contracts.compute_credit_vault.address,
    runtime_code_hash: contracts.compute_credit_vault.runtime_code_hash,
    owner: contracts.compute_credit_vault.owner,
    developer: contracts.compute_credit_vault.developer,
    metering_verifier: contracts.compute_credit_vault.metering_verifier,
    metering_qvl_verifier: contracts.compute_credit_vault.metering_qvl_verifier,
    metering_policy_set_hash: contracts.compute_credit_vault.metering_policy_set_hash,
    metering_binding_frozen: contracts.compute_credit_vault.metering_binding_frozen,
    developer_fee_bps: contracts.compute_credit_vault.developer_fee_bps,
    tee_identity: contracts.compute_credit_vault.tee_identity,
    compose_hash: contracts.compute_credit_vault.compose_hash,
    native_rate_policy_commitment: ratePolicies.native.commitment,
    native_provider: ratePolicies.native.provider,
    erc20_asset_address: ratePolicies.erc20.asset,
    erc20_rate_policy_commitment: ratePolicies.erc20.commitment,
    erc20_provider: ratePolicies.erc20.provider,
  };
  delete contracts.email_oracle_auth.release.oracle_compose_hash;
  delete contracts.email_oracle_auth.release.consumer_compose_hash;
  const qvl = (index, key) => ({
    schema: "dnai.release-qvl-cvm.v1",
    platform: "phala_cloud",
    release_sha: RELEASE_SHA,
    app_id: (0xa0 + index).toString(16).repeat(20),
    cvm_id: `cvm_${key}_release`,
    compose_hash: (0x40 + index).toString(16).repeat(32),
    local_compose_hash: (0x50 + index).toString(16).repeat(32),
    rendered_compose_sha256: (0x60 + index).toString(16).repeat(32),
    os_image_hash: (0x70 + index).toString(16).repeat(32),
    os_is_dev: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
    ssh_enabled: false,
    endpoint: `https://${key}.release.wikigen.me/verify`,
    endpoint_authentication: "bearer_required",
    image: { image: `ghcr.io/example/${key}@sha256:${"8".repeat(64)}` },
    identity_evidence_classification:
      "deployment_pins_require_external_platform_verification",
    context: key,
    identity: {
      schema: "dnai.attestation-qvl-identity.v1",
      verifier_address: address(30 + index),
      release_policy_hash: `0x${(0x80 + index).toString(16).repeat(32)}`,
      signer_custody: "dstack_derived_separate_cvm",
      raw_secret_egress: false,
    },
    policy_binding: { kind: `${key}_v1` },
  });
  const trustDomains = {
    diligence_qvl: qvl(1, "diligence_qvl"),
    arena_qvl: qvl(2, "arena_qvl"),
    anchor_writer_qvl: qvl(3, "anchor_writer_qvl"),
    compute_metering_qvl: qvl(4, "compute_metering_qvl"),
    compute_workload_qvl: qvl(5, "compute_workload_qvl"),
    compute_metering: {
      ...qvl(6, "compute_metering"),
      schema: "dnai.release-compute-metering-cvm.v1",
      identity: {
        schema: "dnai.compute-metering-identity.v1",
        classification: "attested_deterministic_metering",
        provider_authoritative_invoice: false,
        chain_id: 84_532,
        vault_address: core.contracts.compute_credit_vault.address,
        policy_set_hash: core.contracts.compute_credit_vault.metering_policy_set_hash,
        metering_verifier: core.contracts.compute_credit_vault.metering_verifier,
        assets: [],
        signer_custody: "dstack_derived_independent_cvm",
        raw_secret_egress: false,
      },
    },
  };
  delete trustDomains.compute_metering.context;
  delete trustDomains.compute_metering.policy_binding;
  const anchor = structuredClone(core.execution_policy.rollback_anchor_target);
  const candidate = {
    schema: "dnai.web-release.v4",
    release_sha: RELEASE_SHA,
    network: core.network,
    operator_address: core.operator_address,
    deployment_intent_sha256: core.deployment_intent_sha256,
    cvm_launch_intent_sha256: core.cvm_launch_intent_sha256,
    operator_policy: {
      schema: "dnai.live-activation-authority-evidence.v1",
      ceremony_authorization_sha256: `sha256:${"fb".repeat(32)}`,
      live_activation_authority_sha256: `sha256:${"fc".repeat(32)}`,
      runtime_authority_dependency_sha256: runtimeAuthoritySha256,
    },
    contracts,
    cvm: core.cvm,
    trust_domains: trustDomains,
    wallet_auth: core.wallet_auth,
    execution_policy: {
      canonicalization_version: core.execution_policy.canonicalization_version,
      approval_schema: core.execution_policy.approval_schema,
      api_schema_version: core.execution_policy.api_schema_version,
      store_schema_version: core.execution_policy.store_schema_version,
      approval_domain: "base-sepolia:fixture",
      approval_domain_hash: "1".repeat(64),
      approver_hashes: core.execution_policy.approver_hashes,
      approver_root_hash: core.execution_policy.approver_root_hash,
      rollback_anchor: {
        ...anchor,
        status: "verified_active_frozen_release_writer",
        release_manifest_commitment: runtimeAuthoritySha256.slice(7),
        evidence_sha256: `sha256:${"fd".repeat(32)}`,
      },
    },
    attestations: {
      artifact: { context: "artifact" },
      arena: { context: "arena" },
      compute_metering: { context: "compute_metering" },
    },
    arena_registry_bindings: core.arena_registry_bindings,
    requested_features: core.requested_features,
  };
  return {
    candidate,
    core,
    runtimeAuthoritySha256,
    runtimeAuthority: {
      release_sha: RELEASE_SHA,
      deployment_intent_sha256: core.deployment_intent_sha256,
      cvm_launch_intent_sha256: core.cvm_launch_intent_sha256,
    },
  };
}

test("historical D replay independently matches the current external closure recipe", () => {
  assert.equal(
    HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
    CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
  );
  assert.equal(
    HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
    CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
  );
  assert.equal(__historicalFrontendReleaseCoreTest.EXTERNAL_ENTRYPOINTS.length, 17);
  assert.equal(__historicalFrontendReleaseCoreTest.EXTERNAL_FILES.length, 29);
  assert.deepEqual(
    __historicalFrontendReleaseCoreTest.EXTERNAL_ENTRYPOINTS,
    CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS,
  );
  assert.deepEqual(
    __historicalFrontendReleaseCoreTest.EXTERNAL_FILES,
    CLOUDFLARE_EXTERNAL_BUILD_FILES,
  );
});

test("pure D replay preserves the v2 manifest KAT and exact 35-input recipe", () => {
  const value = manifest();
  assert.equal(value.pre_D_private_inputs.length, 35);
  assert.deepEqual(
    value.pre_D_private_inputs.map(({ flag }) => flag),
    FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS,
  );
  assert.deepEqual(Object.keys(value.semantic_lineage),
    FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS);
  assert.deepEqual(Object.keys(value.authority_roots),
    FRONTEND_BUILD_AUTHORITY_ROOT_FIELDS);
  assert.equal(
    frontendBuildInputManifestSha256(value),
    "sha256:46c6df9b1871b3683b502429d58120c1b3e73c2be6f47a033d5fdb95f04cf9b7",
  );
});

test("pure D receipt replay exact-binds environment, manifest, and B/R/O lineage", () => {
  const value = receipt();
  assert.deepEqual(assertFrontendBuildCandidateLineage({
    receipt: value,
    serializedEnv: SERIALIZED_ENV,
    inputManifest: manifest(),
    authorityBinding: BINDING,
  }), value);
  assert.match(frontendBuildCandidateReceiptSha256(value), /^sha256:[0-9a-f]{64}$/);

  const drift = structuredClone(manifest());
  drift.pre_D_private_inputs[4].sha256 = pin(245);
  assert.throws(() => assertFrontendBuildCandidateLineage({
    receipt: value,
    serializedEnv: SERIALIZED_ENV,
    inputManifest: drift,
    authorityBinding: BINDING,
  }), /reprojected lineage/);
  assert.throws(() => frontendBuildProjectedEnvSha256(
    `${SERIALIZED_ENV}VITE_LIVE_ACTIVATION_AUTHORITY=forbidden\n`,
  ), /cannot be frontend env inputs/);
});

test("historical candidate binds byte-for-byte to the independently normalized release core and R", () => {
  const fixture = historicalCandidateFixture();
  const normalized = normalizeHistoricalFrontendReleaseCandidate(fixture.candidate);
  assert.deepEqual(
    finalReleaseAuthorityCoreFromHistoricalCandidate(normalized),
    fixture.core,
  );
  const binding = validateHistoricalFinalReleaseAuthorityCoreBinding({
    candidateValue: normalized,
    coreValue: fixture.core,
    runtimeAuthorityValue: fixture.runtimeAuthority,
    authenticatedRuntimeAuthoritySha256: fixture.runtimeAuthoritySha256,
  });
  assert.equal(binding.coreSha256,
    historicalFinalReleaseAuthorityCoreSha256(fixture.core));

  const drift = structuredClone(fixture.candidate);
  drift.contracts.compute_credit_vault.native_provider = address(99);
  assert.throws(() => validateHistoricalFinalReleaseAuthorityCoreBinding({
    candidateValue: drift,
    coreValue: fixture.core,
    runtimeAuthorityValue: fixture.runtimeAuthority,
    authenticatedRuntimeAuthoritySha256: fixture.runtimeAuthoritySha256,
  }), /does not exactly match/);
});

test("prebuild projection removes only signed C and pure final-CVM replay matches the v3 topology shape", () => {
  const fixture = historicalCandidateFixture();
  const projection = projectHistoricalLiveReleaseCandidateToPrebuild(fixture.candidate);
  assert.equal(projection.operator_policy.schema,
    "dnai.pre-live-activation-authority-evidence.v1");
  assert.equal(Object.hasOwn(
    projection.operator_policy,
    "live_activation_authority_sha256",
  ), false);
  assert.match(historicalLiveReleaseCandidatePrebuildProjectionSha256(
    fixture.candidate,
  ), /^sha256:[0-9a-f]{64}$/);

  const candidate = normalizeHistoricalFrontendReleaseCandidate(fixture.candidate);
  const topology = [
    ["main_runtime_cvm", candidate.cvm, candidate.cvm.tee_identity],
    ["diligence_qvl_cvm", candidate.trust_domains.diligence_qvl,
      candidate.trust_domains.diligence_qvl.identity.verifier_address],
    ["arena_qvl_cvm", candidate.trust_domains.arena_qvl,
      candidate.trust_domains.arena_qvl.identity.verifier_address],
    ["anchor_writer_qvl_cvm", candidate.trust_domains.anchor_writer_qvl,
      candidate.trust_domains.anchor_writer_qvl.identity.verifier_address],
    ["compute_workload_qvl_cvm", candidate.trust_domains.compute_workload_qvl,
      candidate.trust_domains.compute_workload_qvl.identity.verifier_address],
    ["compute_metering_qvl_cvm", candidate.trust_domains.compute_metering_qvl,
      candidate.trust_domains.compute_metering_qvl.identity.verifier_address],
    ["independent_metering_cvm", candidate.trust_domains.compute_metering,
      candidate.trust_domains.compute_metering.identity.metering_verifier],
  ];
  const finalCvms = topology.map(([key, descriptor, teeIdentity], index) => ({
      cvm_key: key,
      app_id: descriptor.app_id,
      cvm_id: descriptor.cvm_id,
      compose_hash_sha256: `sha256:${descriptor.compose_hash}`,
      tee_identity: teeIdentity,
      attestation_evidence_sha256: pin(210 + index),
    }));
  assert.equal(assertHistoricalFinalCvmTopologyMatchesCandidate(
    finalCvms,
    candidate,
  ), true);
  finalCvms[5].cvm_id = "cvm_forged_release";
  assert.throws(() => assertHistoricalFinalCvmTopologyMatchesCandidate(
    finalCvms,
    candidate,
  ), /compute_metering_qvl_cvm identity/);
});

test("historical candidate and D replay reject accessors, prototypes, and cyclic graphs", () => {
  const accessor = structuredClone(manifest());
  Object.defineProperty(accessor.semantic_lineage, "release_core_sha256", {
    enumerable: true,
    get() {
      throw new Error("untrusted getter executed");
    },
  });
  assert.throws(() => normalizeFrontendBuildInputManifest(accessor),
    /accessors and non-enumerable data fields are forbidden/);

  const custom = historicalCandidateFixture().candidate;
  Object.setPrototypeOf(custom.trust_domains, { forged: true });
  assert.throws(() => normalizeHistoricalFrontendReleaseCandidate(custom),
    /custom prototypes are forbidden/);

  const cyclic = structuredClone(manifest());
  cyclic.git_source.loop = cyclic;
  assert.throws(() => normalizeFrontendBuildInputManifest(cyclic),
    /cycles are forbidden/);
});

test("recursive historical-core import closure is acyclic and capability-free", () => {
  const root = fileURLToPath(new URL(
    "./frontend-release-historical-core.mjs",
    import.meta.url,
  ));
  const local = new Map();
  const visiting = new Set();
  const visited = new Set();
  const external = new Set();
  const importPattern = /(?:import|export)\s+(?:[^"']*?\s+from\s+)?["']([^"']+)["']/g;
  function visit(file) {
    if (visiting.has(file)) throw new Error(`cycle:${file}`);
    if (visited.has(file)) return;
    visiting.add(file);
    const source = readFileSync(file, "utf8");
    assert.doesNotMatch(source, /\bDate\.now\s*\(/);
    assert.doesNotMatch(source, /\bprocess(?:\.|\[)/);
    assert.doesNotMatch(source, /\bimport\s*\(/);
    const imports = [...source.matchAll(importPattern)].map((match) => match[1]);
    local.set(file, imports);
    for (const specifier of imports) {
      if (!specifier.startsWith(".")) {
        external.add(specifier);
        continue;
      }
      const resolved = fileURLToPath(new URL(specifier, pathToFileURL(file)));
      visit(resolved);
    }
    visiting.delete(file);
    visited.add(file);
  }
  visit(root);
  assert.deepEqual([...external].sort(), ["node:crypto", "node:util"]);
  assert.deepEqual([...visited].map((file) => path.relative(
    path.resolve(path.dirname(root), "../.."),
    file,
  )).sort(), [
    "scripts/canonical-authority-graph.mjs",
    "scripts/cvm-launch-intent-core.mjs",
    "scripts/ethereum-keccak.mjs",
    "scripts/execution-policy-release-core.mjs",
    "scripts/phala-post-measurement-activation-receipt-core.mjs",
    "scripts/phala-production-execution-policy.mjs",
    "scripts/phala-seven-cvm-measurement-policy.mjs",
    "scripts/release-authority-historical-core.mjs",
    "web/scripts/frontend-release-historical-core.mjs",
  ]);
  for (const imports of local.values()) {
    assert.equal(imports.some((specifier) => /(?:viem|node:(?:fs|path|os|child_process|net|http|https|module|worker_threads))/.test(specifier)), false);
  }
});
