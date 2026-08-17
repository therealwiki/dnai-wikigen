import assert from "node:assert/strict";
import test from "node:test";

import {
  CVM_LAUNCH_DOMAINS,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  PHALA_CONTROL_PLANE_AUTHORITY,
  PHALA_CVM_RESOURCE_TARGETS,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_API_CANDIDATE_VERSIONS,
  PHALA_COMPATIBILITY_RECEIPT_SCHEMA,
  PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA,
  PHALA_READ_ONLY_COMPATIBILITY_CALLS,
  PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA,
  PHALA_COLLABORATION_LAUNCH_GATE_POLICY,
  assertPhalaProductionTargetCollaborationLaunchGatePolicy,
  assertPhalaTargetFreshForCheckpoint,
  assertSecretFreePhalaAuthorityArtifact,
  canonicalPhalaCompatibilityReceiptText,
  canonicalPhalaProductionTargetAuthorityText,
  createPhalaCompatibilityProbePlan,
  normalizePhalaCompatibilityReceipt,
  normalizePhalaProductionTargetAuthority,
  normalizePhalaSdkWireTransformStagingReceipt,
  phalaCompatibilityReceiptDigest,
  phalaProductionTargetAuthorityDigest,
  phalaSdkWireTransformStagingReceiptDigest,
} from "./phala-production-target-authority.mjs";

const digest = (character) => `sha256:${character.repeat(64)}`;

function compatibilityFixture() {
  return {
    schema: PHALA_COMPATIBILITY_RECEIPT_SCHEMA,
    truth_status:
      "authenticated_read_only_compatibility_observation_not_launch_authority",
    checked_at: "2026-07-21T12:00:00Z",
    expires_at: "2026-07-21T12:30:00Z",
    api_origin: PHALA_CONTROL_PLANE_AUTHORITY.api_origin,
    probed_versions: PHALA_API_CANDIDATE_VERSIONS.map((version) => ({
      version,
      authenticated: version === PHALA_CONTROL_PLANE_AUTHORITY.api_version,
      strict_schema_valid: version === PHALA_CONTROL_PLANE_AUTHORITY.api_version,
      response_origin_valid: version === PHALA_CONTROL_PLANE_AUTHORITY.api_version,
      read_only_calls_complete: version === PHALA_CONTROL_PLANE_AUTHORITY.api_version,
    })),
    selected_api_version: PHALA_CONTROL_PLANE_AUTHORITY.api_version,
    read_only_calls: [...PHALA_READ_ONLY_COMPATIBILITY_CALLS],
    workspace: {
      workspace_id: "workspace-production-1",
      account_subject_sha256: digest("1"),
      authenticated: true,
    },
    sdk_identity: {
      phala_cli_version: "1.1.19",
      phala_cli_manifest_sha256: digest("2"),
      phala_cloud_version: "0.2.10",
      phala_cloud_manifest_sha256: digest("3"),
      phala_cloud_npm_dist_integrity_sha512:
        "sha512-eQXJxbBlJ8xA4e+MmB3AZd9jgdbO3tFh+qu7KL6CS5Ta64LNKlrV3vdke3oUvB22xbc/qqKQ6dIkJx5pTdY7gA==",
      phala_cloud_module_sha256: digest("4"),
      dstack_sdk_version: "0.5.8",
      dstack_sdk_manifest_sha256: digest("5"),
      dstack_verify_module_sha256: digest("6"),
      dstack_compose_hash_module_sha256: digest("7"),
      dstack_encryption_module_sha256: digest("8"),
    },
    kms: {
      id: "kms-production-1",
      slug: "phala",
      url: "https://kms.phala.network/",
      version: "0.5.8",
      chain_id: null,
      kms_contract_address: null,
      gateway_app_id: "1".repeat(40),
      catalog_match_count: 1,
    },
    os_image: { ...PHALA_OS_IMAGE_CATALOG_ENTRY },
    resource_catalog: [
      {
        name: "tdx.large",
        default_disk_size_gb: 20,
        maximum_disk_size_gb: 2_048,
        requires_gpu: false,
      },
      {
        name: "tdx.small",
        default_disk_size_gb: 20,
        maximum_disk_size_gb: 2_048,
        requires_gpu: false,
      },
    ],
    quota: {
      max_instances: 7,
      max_disk_gb: 160,
      catalog_reports_sufficient_capacity: true,
    },
    staging_provision_performed: false,
    mutation_calls: [],
  };
}

function stagingFixture(compatibilityReceipt = compatibilityFixture()) {
  return {
    schema: PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA,
    truth_status:
      "authenticated_staging_wire_capture_not_production_cvm_commit_tdx_attestation_or_launch_authority",
    compatibility_receipt_sha256:
      phalaCompatibilityReceiptDigest(compatibilityReceipt),
    captured_at: "2026-07-21T12:01:00Z",
    expires_at: "2026-07-21T12:20:00Z",
    api_origin: compatibilityReceipt.api_origin,
    api_version: compatibilityReceipt.selected_api_version,
    workspace: {
      workspace_id: compatibilityReceipt.workspace.workspace_id,
      account_subject_sha256: compatibilityReceipt.workspace.account_subject_sha256,
    },
    sdk_identity: structuredClone(compatibilityReceipt.sdk_identity),
    capture_method:
      "authenticated_transport_interceptor_after_sdk_transform_before_http_serialization",
    staging_account_isolated: true,
    provision_call_count: 7,
    commit_calls: [],
    cleanup_receipt_sha256: digest("f"),
    domains: CVM_LAUNCH_DOMAINS.map((domain, index) => {
      const pre = (index + 8).toString(16);
      const post = (index + 1).toString(16);
      const response = ((index + 7) % 15 + 1).toString(16);
      return {
        domain,
        pre_transform_request_sha256: digest(pre),
        expected_post_transform_body_sha256: digest(post),
        captured_post_transform_body_sha256: digest(post),
        pre_transform_compose_hash: pre.repeat(64),
        expected_post_transform_compose_hash: post.repeat(64),
        prepare_server_compose_hash: post.repeat(64),
        prepare_response_sha256: digest(response),
      };
    }),
  };
}

function targetFixture(
  compatibilityReceipt = compatibilityFixture(),
  stagingReceipt = stagingFixture(compatibilityReceipt),
) {
  const resourceTargets = Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => [
    domain,
    {
      ...structuredClone(PHALA_CVM_RESOURCE_TARGETS[domain]),
      authority_status: "reviewed_authenticated_catalog_and_quota_validated",
    },
  ]));
  const appComposeProfiles = Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => [
    domain,
    {
      name: CVM_LAUNCH_DESCRIPTOR_POLICY[domain].app_compose_candidate.name,
      manifest_version: 2,
      runner: "docker-compose",
      kms_enabled: true,
      gateway_enabled: true,
      tproxy_enabled: false,
      skip_gateway: false,
      storage_fs: "ext4",
      secure_time: true,
      public_logs: false,
      public_sysinfo: false,
      public_tcbinfo: false,
    },
  ]));
  return {
    schema: PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA,
    truth_status:
      "reviewed_target_authority_not_phala_deployment_attestation_or_execution_receipt",
    release_sha: "a".repeat(40),
    cvm_launch_intent_sha256: digest("5"),
    review_envelope_sha256: digest("6"),
    review_evidence_sha256: digest("7"),
    compatibility_receipt_sha256:
      phalaCompatibilityReceiptDigest(compatibilityReceipt),
    staging_compose_hash_receipt_sha256:
      phalaSdkWireTransformStagingReceiptDigest(stagingReceipt, {
        compatibilityReceipt,
      }),
    api: {
      origin: PHALA_CONTROL_PLANE_AUTHORITY.api_origin,
      version: PHALA_CONTROL_PLANE_AUTHORITY.api_version,
      timeout_ms: 20_000,
      retry: 0,
      redirect: "error",
    },
    workspace: {
      workspace_id: compatibilityReceipt.workspace.workspace_id,
      account_subject_sha256: compatibilityReceipt.workspace.account_subject_sha256,
    },
    sdk_identity: structuredClone(compatibilityReceipt.sdk_identity),
    kms: {
      id: compatibilityReceipt.kms.id,
      slug: compatibilityReceipt.kms.slug,
      url: compatibilityReceipt.kms.url,
      version: compatibilityReceipt.kms.version,
      chain_id: null,
      kms_contract_address: null,
      gateway_app_id: compatibilityReceipt.kms.gateway_app_id,
      env_encrypt_signer_k256: `0x02${"9".repeat(64)}`,
      signer_provenance_sha256: digest("a"),
      valid_from: "2026-07-21T00:00:00Z",
      valid_until: "2026-08-21T00:00:00Z",
    },
    os_image: { ...PHALA_OS_IMAGE_CATALOG_ENTRY },
    resource_targets: resourceTargets,
    app_compose_profiles: appComposeProfiles,
    reviewed_at: "2026-07-21T12:02:00Z",
    expires_at: "2026-07-21T12:10:00Z",
  };
}

test("compatibility plan is exact, read-only, and secret-free", () => {
  const plan = createPhalaCompatibilityProbePlan();
  assert.equal(plan.api_origin, "https://cloud-api.phala.network/api/v1");
  assert.deepEqual(plan.candidate_api_versions, PHALA_API_CANDIDATE_VERSIONS);
  assert.deepEqual(plan.read_only_calls_per_version, PHALA_READ_ONLY_COMPATIBILITY_CALLS);
  assert.deepEqual(plan.mutation_calls, []);
  assert.equal(plan.request_policy.retry, 0);
  assert.equal(plan.request_policy.redirect, "error");
  assert.equal(JSON.stringify(plan).includes("phak_"), false);
});

test("compatibility receipt requires both probes and one reviewed exact version", () => {
  const receipt = compatibilityFixture();
  const normalized = normalizePhalaCompatibilityReceipt(receipt);
  assert.equal(normalized.selected_api_version, "2026-01-21");
  assert.equal(normalized.workspace.authenticated, true);
  assert.match(phalaCompatibilityReceiptDigest(receipt), /^sha256:[0-9a-f]{64}$/);
  assert.equal(
    canonicalPhalaCompatibilityReceiptText(receipt),
    canonicalPhalaCompatibilityReceiptText(normalized),
  );

  const newestByAssumption = structuredClone(receipt);
  newestByAssumption.selected_api_version = "2026-05-22";
  assert.throws(
    () => normalizePhalaCompatibilityReceipt(newestByAssumption),
    /selected API version|read-only compatibility/,
  );

  const hiddenMutation = structuredClone(receipt);
  hiddenMutation.mutation_calls.push("provisionCvm");
  assert.throws(
    () => normalizePhalaCompatibilityReceipt(hiddenMutation),
    /read-only call boundary/,
  );
});

test("target authority timestamps require real calendar seconds and accept a leap-day month boundary", () => {
  for (const impossible of [
    "2026-02-29T12:00:00Z",
    "2026-02-30T12:00:00Z",
  ]) {
    const invalid = compatibilityFixture();
    invalid.checked_at = impossible;
    assert.throws(
      () => normalizePhalaCompatibilityReceipt(invalid),
      /canonical UTC second/,
    );
  }

  const compatibility = compatibilityFixture();
  compatibility.checked_at = "2024-02-29T23:58:00Z";
  compatibility.expires_at = "2024-03-01T00:30:00Z";
  const staging = stagingFixture(compatibility);
  staging.captured_at = "2024-02-29T23:59:00Z";
  staging.expires_at = "2024-03-01T00:20:00Z";
  const target = targetFixture(compatibility, staging);
  target.kms.valid_from = "2024-02-01T00:00:00Z";
  target.kms.valid_until = "2024-04-01T00:00:00Z";
  target.reviewed_at = "2024-02-29T23:59:30Z";
  target.expires_at = "2024-03-01T00:09:30Z";
  assert.equal(
    normalizePhalaProductionTargetAuthority(target, {
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    }).expires_at,
    "2024-03-01T00:09:30Z",
  );
  assert.equal(assertPhalaTargetFreshForCheckpoint({
    targetAuthority: target,
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
    checkpoint: "before_each_commit",
    now: "2024-03-01T00:00:00Z",
  }).checked_at, "2024-03-01T00:00:00Z");
});

test("staging receipt binds exact SDK transform capture, server hash, cleanup, and zero commits", () => {
  const compatibility = compatibilityFixture();
  const receipt = stagingFixture(compatibility);
  const normalized = normalizePhalaSdkWireTransformStagingReceipt(receipt, {
    compatibilityReceipt: compatibility,
  });
  assert.deepEqual(normalized, receipt);
  assert.match(
    phalaSdkWireTransformStagingReceiptDigest(receipt, {
      compatibilityReceipt: compatibility,
    }),
    /^sha256:[0-9a-f]{64}$/,
  );
  assert.equal(normalized.provision_call_count, 7);
  assert.deepEqual(normalized.commit_calls, []);

  for (const [label, mutate] of [
    ["captured body", (copy) => {
      copy.domains[0].captured_post_transform_body_sha256 = digest("e");
    }],
    ["server hash", (copy) => {
      copy.domains[0].prepare_server_compose_hash = "e".repeat(64);
    }],
    ["commit", (copy) => { copy.commit_calls.push("commitCvmProvision"); }],
    ["SDK", (copy) => { copy.sdk_identity.phala_cloud_module_sha256 = digest("e"); }],
  ]) {
    const drift = structuredClone(receipt);
    mutate(drift);
    assert.throws(
      () => normalizePhalaSdkWireTransformStagingReceipt(drift, {
        compatibilityReceipt: compatibility,
      }),
      undefined,
      label,
    );
  }
});

test("target authority binds origin, account, KMS signer, OS, quota, resources, and AppCompose", () => {
  assert.deepEqual(
    assertPhalaProductionTargetCollaborationLaunchGatePolicy(),
    PHALA_COLLABORATION_LAUNCH_GATE_POLICY,
  );
  assert.deepEqual(PHALA_COLLABORATION_LAUNCH_GATE_POLICY, {
    environment_key: "TINKER_COLLABORATION_ENABLED",
    bootstrap_default: "false",
    runtime_authority:
      "current_final_release_authority_v3_requested_features_collaboration",
    operator_mutable: false,
  });
  const compatibility = compatibilityFixture();
  const staging = stagingFixture(compatibility);
  const target = targetFixture(compatibility, staging);
  const normalized = normalizePhalaProductionTargetAuthority(target, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  });
  assert.equal(normalized.api.retry, 0);
  assert.equal(normalized.api.redirect, "error");
  assert.equal(normalized.kms.env_encrypt_signer_k256, `0x02${"9".repeat(64)}`);
  assert.equal(
    Object.values(normalized.resource_targets).reduce(
      (total, resource) => total + resource.disk_size,
      0,
    ),
    160,
  );
  assert.match(
    phalaProductionTargetAuthorityDigest(target, {
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    }),
    /^sha256:[0-9a-f]{64}$/,
  );
  assert.equal(
    canonicalPhalaProductionTargetAuthorityText(target, {
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    }),
    canonicalPhalaProductionTargetAuthorityText(normalized, {
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    }),
  );
});

test("target authority fails closed on every mutable platform default", () => {
  const compatibility = compatibilityFixture();
  const staging = stagingFixture(compatibility);
  const cases = [
    ["origin", (target) => { target.api.origin = "https://cloud-api.phala.com/api/v1"; }],
    ["retry", (target) => { target.api.retry = 1; }],
    ["redirect", (target) => { target.api.redirect = "follow"; }],
    ["workspace", (target) => { target.workspace.workspace_id = "wrong-workspace"; }],
    ["KMS signer", (target) => { target.kms.env_encrypt_signer_k256 = `0x04${"9".repeat(64)}`; }],
    ["public logs", (target) => { target.app_compose_profiles.main_runtime_cvm.public_logs = true; }],
    ["runner", (target) => { target.app_compose_profiles.main_runtime_cvm.runner = "bash"; }],
    ["storage", (target) => { target.app_compose_profiles.main_runtime_cvm.storage_fs = "zfs"; }],
    ["placement", (target) => { target.resource_targets.main_runtime_cvm.placement.node_id = 7; }],
  ];
  for (const [label, mutate] of cases) {
    const target = targetFixture(compatibility, staging);
    mutate(target);
    assert.throws(
      () => normalizePhalaProductionTargetAuthority(target, {
        compatibilityReceipt: compatibility,
        sdkWireTransformStagingReceipt: staging,
      }),
      undefined,
      label,
    );
  }
});

test("resource targets remain blocked when authenticated quota is insufficient", () => {
  const compatibility = compatibilityFixture();
  compatibility.quota.max_disk_gb = 139;
  const staging = stagingFixture(compatibility);
  const target = targetFixture(compatibility, staging);
  assert.throws(
    () => normalizePhalaProductionTargetAuthority(target, {
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    }),
    /exceed authenticated quota/,
  );
});

test("target cannot outlive compatibility even when its KMS signer is long-lived", () => {
  const compatibility = compatibilityFixture();
  compatibility.expires_at = "2026-07-21T12:05:00Z";
  const staging = stagingFixture(compatibility);
  staging.expires_at = "2026-07-21T12:05:00Z";
  const target = targetFixture(compatibility, staging);
  target.expires_at = "2026-07-21T12:06:00Z";
  target.kms.valid_until = "2027-07-21T12:00:00Z";
  assert.throws(
    () => normalizePhalaProductionTargetAuthority(target, {
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    }),
    /outlives the KMS signer pin|stale against compatibility/,
  );
});

test("freshness is revalidated at every prediction, prepare, provision, and commit checkpoint", () => {
  const compatibility = compatibilityFixture();
  const staging = stagingFixture(compatibility);
  const target = targetFixture(compatibility, staging);
  for (const checkpoint of [
    "before_prediction",
    "before_each_prepare",
    "before_each_provision",
    "before_each_commit",
  ]) {
    const receipt = assertPhalaTargetFreshForCheckpoint({
      targetAuthority: target,
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
      checkpoint,
      now: "2026-07-21T12:04:00Z",
    });
    assert.equal(receipt.checkpoint, checkpoint);
    assert.equal(receipt.fresh, true);
    assert.equal(receipt.mutation_performed, false);
  }
  assert.throws(
    () => assertPhalaTargetFreshForCheckpoint({
      targetAuthority: target,
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
      checkpoint: "before_each_commit",
      now: target.expires_at,
    }),
    /fresh authenticated compatibility/,
  );
  assert.throws(
    () => assertPhalaTargetFreshForCheckpoint({
      targetAuthority: target,
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
      checkpoint: "before_mutation",
      now: "2026-07-21T12:04:00Z",
    }),
    /checkpoint is not exact/,
  );
});

test("authority artifacts reject secret-bearing fields and values", () => {
  assert.throws(
    () => assertSecretFreePhalaAuthorityArtifact({
      api_key: ["phak_", "not-allowed-12345"].join(""),
    }),
    /secret-bearing field/,
  );
  assert.throws(
    () => assertSecretFreePhalaAuthorityArtifact({
      value: ["phak_", "not-allowed-12345"].join(""),
    }),
    /secret-shaped value/,
  );
});
