import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
  PHALA_CONTROL_PLANE_AUTHORITY,
  PHALA_CVM_RESOURCE_TARGETS,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  normalizeCvmReleaseDescriptorSetReceipt,
} from "./cvm-release-descriptor-set-v3.mjs";
import {
  buildExactProvisionRequest,
  buildExplicitAppCompose,
} from "./phala-production-executor-core.mjs";
import {
  assertPinnedPhalaPreProvisionStagingSession,
} from "./phala-production-sdk-adapter.mjs";
import {
  PHALA_COMPATIBILITY_RECEIPT_SCHEMA,
  PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA,
  PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA,
  assertSecretFreePhalaAuthorityArtifact,
  normalizePhalaCompatibilityReceipt,
  normalizePhalaProductionTargetAuthority,
  normalizePhalaSdkWireTransformStagingReceipt,
  phalaCompatibilityReceiptDigest,
  phalaProductionTargetReviewInputProjectionDigest,
  phalaProductionTargetAuthorityDigest,
  phalaSdkWireTransformStagingReceiptDigest,
} from "./phala-production-target-authority.mjs";
import {
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
  normalizeBootstrapPublicEnvironmentAuthority,
} from "./phala-bootstrap-public-environment-authority-core.mjs";

const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const COMPRESSED_K256 = /^0x0[23][0-9a-f]{64}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const TARGET_INPUT_FIELDS = Object.freeze([
  "release_sha",
  "cvm_launch_intent_sha256",
  "review_envelope_sha256",
  "review_evidence_sha256",
  "compatibility_receipt_sha256",
  "api",
  "workspace",
  "sdk_identity",
  "kms",
  "os_image",
  "resource_targets",
  "app_compose_profiles",
]);
const BOOTSTRAP_LINEAGE_FIELDS = Object.freeze([
  "deployment_intent_sha256",
  "deployment_transaction_plan_sha256",
  "fresh_contract_deployment_receipt_sha256",
  "image_release_sigstore_verification_receipt_sha256",
  "cvm_launch_intent_sha256",
  "cvm_launch_review_receipt_sha256",
  "qvl_measurement_policy_set_sha256",
]);

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  assertCanonicalPlainDataGraph(value, { label });
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} must contain exactly the reviewed fields`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

export function canonicalPhalaProducerJsonText(value) {
  assertCanonicalPlainDataGraph(value, { label: "Phala producer artifact" });
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function digest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(JSON.stringify(sorted(value)), "utf8")
    .digest("hex")}`;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactTimestamp(value, label) {
  if (typeof value !== "string" || !ISO_SECOND.test(value)
    || !Number.isFinite(Date.parse(value))
    || new Date(Date.parse(value)).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  return value;
}

function compatibilityTargetProjection(compatibility) {
  return {
    api: {
      origin: PHALA_CONTROL_PLANE_AUTHORITY.api_origin,
      version: PHALA_CONTROL_PLANE_AUTHORITY.api_version,
      timeout_ms: 20_000,
      retry: 0,
      redirect: "error",
    },
    workspace: {
      workspace_id: compatibility.workspace.workspace_id,
      account_subject_sha256: compatibility.workspace.account_subject_sha256,
    },
    sdk_identity: structuredClone(compatibility.sdk_identity),
    os_image: { ...PHALA_OS_IMAGE_CATALOG_ENTRY },
    resource_targets: Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => [
      domain,
      {
        ...structuredClone(PHALA_CVM_RESOURCE_TARGETS[domain]),
        authority_status: "reviewed_authenticated_catalog_and_quota_validated",
      },
    ])),
    app_compose_profiles: Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => {
      const candidate = CVM_LAUNCH_DESCRIPTOR_POLICY[domain].app_compose_candidate;
      return [domain, {
        name: candidate.name,
        manifest_version: 2,
        runner: "docker-compose",
        kms_enabled: true,
        gateway_enabled: candidate.gateway_enabled,
        tproxy_enabled: false,
        skip_gateway: !candidate.gateway_enabled,
        storage_fs: "ext4",
        secure_time: true,
        public_logs: false,
        public_sysinfo: false,
        public_tcbinfo: false,
      }];
    })),
  };
}

export function createPhalaProductionTargetReviewInput({
  compatibilityReceipt,
  releaseSha,
  cvmLaunchIntentSha256,
  reviewEnvelopeSha256,
  reviewEvidenceSha256,
  kmsSignerK256,
  kmsSignerProvenanceSha256,
  kmsSignerValidFrom,
  kmsSignerValidUntil,
} = {}) {
  const compatibility = normalizePhalaCompatibilityReceipt(compatibilityReceipt);
  if (typeof releaseSha !== "string" || !SHA40.test(releaseSha)) {
    throw new Error("target input release SHA is invalid");
  }
  if (typeof kmsSignerK256 !== "string" || !COMPRESSED_K256.test(kmsSignerK256)) {
    throw new Error("target input KMS signer is not a compressed k256 key");
  }
  const validFrom = exactTimestamp(kmsSignerValidFrom, "KMS signer valid_from");
  const validUntil = exactTimestamp(kmsSignerValidUntil, "KMS signer valid_until");
  if (Date.parse(validUntil) <= Date.parse(validFrom)) {
    throw new Error("target input KMS signer validity window is invalid");
  }
  const projection = compatibilityTargetProjection(compatibility);
  const value = {
    release_sha: releaseSha,
    cvm_launch_intent_sha256: exactSha256(
      cvmLaunchIntentSha256,
      "target input launch intent",
    ),
    review_envelope_sha256: exactSha256(
      reviewEnvelopeSha256,
      "target input review envelope",
    ),
    review_evidence_sha256: exactSha256(
      reviewEvidenceSha256,
      "target input review evidence",
    ),
    compatibility_receipt_sha256:
      phalaCompatibilityReceiptDigest(compatibility),
    api: projection.api,
    workspace: projection.workspace,
    sdk_identity: projection.sdk_identity,
    kms: {
      ...structuredClone(compatibility.kms),
      catalog_match_count: undefined,
      env_encrypt_signer_k256: kmsSignerK256,
      signer_provenance_sha256: exactSha256(
        kmsSignerProvenanceSha256,
        "target input KMS signer provenance",
      ),
      valid_from: validFrom,
      valid_until: validUntil,
    },
    os_image: projection.os_image,
    resource_targets: projection.resource_targets,
    app_compose_profiles: projection.app_compose_profiles,
  };
  delete value.kms.catalog_match_count;
  return normalizePhalaProductionTargetReviewInput(value, {
    compatibilityReceipt: compatibility,
  });
}

export function normalizePhalaProductionTargetReviewInput(value, {
  compatibilityReceipt,
} = {}) {
  const compatibility = normalizePhalaCompatibilityReceipt(compatibilityReceipt);
  const parsed = exactRecord(value, TARGET_INPUT_FIELDS, "Phala target review input");
  if (typeof parsed.release_sha !== "string" || !SHA40.test(parsed.release_sha)
    || parsed.compatibility_receipt_sha256
      !== phalaCompatibilityReceiptDigest(compatibility)) {
    throw new Error("Phala target review input release or compatibility binding is invalid");
  }
  for (const field of [
    "cvm_launch_intent_sha256",
    "review_envelope_sha256",
    "review_evidence_sha256",
  ]) exactSha256(parsed[field], `target review input ${field}`);
  const expected = compatibilityTargetProjection(compatibility);
  for (const field of [
    "api", "workspace", "sdk_identity", "os_image", "resource_targets", "app_compose_profiles",
  ]) {
    if (JSON.stringify(sorted(parsed[field])) !== JSON.stringify(sorted(expected[field]))) {
      throw new Error(`Phala target review input ${field} drifted from compatibility or launch policy`);
    }
  }
  const kms = exactRecord(parsed.kms, [
    "id", "slug", "url", "version", "chain_id", "kms_contract_address",
    "gateway_app_id", "env_encrypt_signer_k256", "signer_provenance_sha256",
    "valid_from", "valid_until",
  ], "Phala target review input KMS");
  for (const field of [
    "id", "slug", "url", "version", "chain_id", "kms_contract_address", "gateway_app_id",
  ]) {
    if (kms[field] !== compatibility.kms[field]) {
      throw new Error("Phala target review input KMS catalog binding drifted");
    }
  }
  if (!COMPRESSED_K256.test(kms.env_encrypt_signer_k256)) {
    throw new Error("Phala target review input KMS signer is invalid");
  }
  exactSha256(kms.signer_provenance_sha256, "target review input signer provenance");
  const validFrom = exactTimestamp(kms.valid_from, "target review input signer valid_from");
  const validUntil = exactTimestamp(kms.valid_until, "target review input signer valid_until");
  if (Date.parse(validUntil) <= Date.parse(validFrom)) {
    throw new Error("Phala target review input signer interval is invalid");
  }
  assertSecretFreePhalaAuthorityArtifact(parsed, "Phala target review input");
  return deepFreezeCanonicalPlainDataGraph(structuredClone(parsed), {
    label: "normalized Phala target review input",
  });
}

export function phalaProductionTargetReviewInputDigest(value, options) {
  return phalaProductionTargetReviewInputProjectionDigest(
    normalizePhalaProductionTargetReviewInput(value, options),
  );
}

export async function capturePhalaSdkWireTransformStagingReceipt({
  compatibilityReceipt,
  targetReviewInput,
  descriptorMaterials,
  stagingSession,
} = {}) {
  const compatibility = normalizePhalaCompatibilityReceipt(compatibilityReceipt);
  const target = normalizePhalaProductionTargetReviewInput(targetReviewInput, {
    compatibilityReceipt: compatibility,
  });
  assertPinnedPhalaPreProvisionStagingSession(stagingSession);
  if (!Array.isArray(descriptorMaterials)
    || descriptorMaterials.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("staging capture requires seven authenticated descriptor materials");
  }
  const materialByDomain = new Map(descriptorMaterials.map((entry) => [entry.domain, entry]));
  if (materialByDomain.size !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("staging descriptor materials are duplicated or incomplete");
  }
  const reservations = await stagingSession.reserveAppIds();
  const invocations = CVM_LAUNCH_DOMAINS.map((domain, index) => {
    const material = materialByDomain.get(domain);
    if (!material || typeof material.docker_compose_file !== "string"
      || !Array.isArray(material.allowed_environment_keys)) {
      throw new Error("staging descriptor material is incomplete");
    }
    const compose = buildExplicitAppCompose({
      profile: target.app_compose_profiles[domain],
      dockerComposeFile: material.docker_compose_file,
      allowedEnvironmentKeys: material.allowed_environment_keys,
    });
    return {
      domain,
      request: buildExactProvisionRequest({
        domain,
        applicationName: target.app_compose_profiles[domain].name,
        resourceTarget: target.resource_targets[domain],
        appCompose: compose,
        activeEnvironmentKeys: material.allowed_environment_keys,
        appId: reservations[index].app_id,
        nonce: reservations[index].nonce,
        kmsId: target.kms.id,
      }),
    };
  });
  const capture = await stagingSession.captureProvisionBatch(invocations);
  const domains = capture?.domains;
  if (!Array.isArray(domains) || domains.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("staging session returned an incomplete seven-request capture");
  }
  const capturedAtMs = capture.completed_at_ms;
  if (!Number.isSafeInteger(capturedAtMs)) {
    throw new Error("staging session omitted its bounded completion time");
  }
  const expiresAtMs = Math.min(
    Date.parse(compatibility.expires_at),
    capturedAtMs + 10 * 60 * 1_000,
  );
  if (capturedAtMs < Date.parse(compatibility.checked_at)
    || expiresAtMs <= capturedAtMs) {
    throw new Error("staging observation completed outside compatibility lifetime");
  }
  return normalizePhalaSdkWireTransformStagingReceipt({
    schema: PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA,
    truth_status:
      "authenticated_empty_operator_designated_staging_workspace_wire_capture_not_exclusive_isolation_proof_production_cvm_commit_tdx_attestation_or_launch_authority",
    compatibility_receipt_sha256: phalaCompatibilityReceiptDigest(compatibility),
    captured_at: new Date(capturedAtMs).toISOString().replace(".000Z", "Z"),
    expires_at: new Date(expiresAtMs).toISOString().replace(".000Z", "Z"),
    api_origin: compatibility.api_origin,
    api_version: compatibility.selected_api_version,
    workspace: {
      workspace_id: compatibility.workspace.workspace_id,
      account_subject_sha256: compatibility.workspace.account_subject_sha256,
    },
    sdk_identity: structuredClone(compatibility.sdk_identity),
    capture_method:
      "authenticated_transport_interceptor_after_sdk_transform_before_http_serialization",
    target_review_input_sha256: phalaProductionTargetReviewInputDigest(target, {
      compatibilityReceipt: compatibility,
    }),
    workspace_preflight: capture.workspace_preflight,
    provision_call_count: CVM_LAUNCH_DOMAINS.length,
    commit_calls: [],
    journal_final_sha256: capture.journal_final_sha256,
    journal_successful_prepare_count: capture.journal_successful_prepare_count,
    server_cleanup_claimed: false,
    pending_server_state_status:
      "seven_prepares_succeeded_uncommitted_operator_reconciliation_required",
    domains,
  }, { compatibilityReceipt: compatibility });
}

export function finalizePhalaProductionTargetAuthority({
  compatibilityReceipt,
  sdkWireTransformStagingReceipt,
  targetReviewInput,
  nowMs = Date.now(),
} = {}) {
  const compatibility = normalizePhalaCompatibilityReceipt(compatibilityReceipt);
  const staging = normalizePhalaSdkWireTransformStagingReceipt(
    sdkWireTransformStagingReceipt,
    { compatibilityReceipt: compatibility },
  );
  const input = normalizePhalaProductionTargetReviewInput(targetReviewInput, {
    compatibilityReceipt: compatibility,
  });
  if (staging.target_review_input_sha256
      !== phalaProductionTargetReviewInputDigest(input, {
        compatibilityReceipt: compatibility,
      })) {
    throw new Error("staging receipt does not bind the exact target review input");
  }
  if (!Number.isSafeInteger(nowMs)) throw new Error("target finalization clock is invalid");
  const reviewedAtMs = Math.floor(nowMs / 1_000) * 1_000;
  const expiresAtMs = Math.min(
    reviewedAtMs + 10 * 60 * 1_000,
    Date.parse(compatibility.expires_at),
    Date.parse(staging.expires_at),
    Date.parse(input.kms.valid_until),
  );
  if (reviewedAtMs < Date.parse(staging.captured_at)
    || reviewedAtMs < Date.parse(compatibility.checked_at)
    || reviewedAtMs < Date.parse(input.kms.valid_from)
    || expiresAtMs <= reviewedAtMs) {
    throw new Error("target finalization is outside its reviewed dependency lifetime");
  }
  return normalizePhalaProductionTargetAuthority({
    schema: PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA,
    truth_status:
      "reviewed_target_authority_not_phala_deployment_attestation_or_execution_receipt",
    ...structuredClone(input),
    compatibility_receipt_sha256: phalaCompatibilityReceiptDigest(compatibility),
    staging_compose_hash_receipt_sha256:
      phalaSdkWireTransformStagingReceiptDigest(staging, {
        compatibilityReceipt: compatibility,
      }),
    reviewed_at: new Date(reviewedAtMs).toISOString().replace(".000Z", "Z"),
    expires_at: new Date(expiresAtMs).toISOString().replace(".000Z", "Z"),
  }, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  });
}

function bootstrapKeys(domain) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const allowed = new Set(policy.exact_allowed_environment_keys);
  return policy.public_environment_key_classification.descriptor_static_keys
    .filter((key) => allowed.has(key));
}

export function createBootstrapPublicEnvironmentReviewInput({
  descriptorSetReceipt,
  compatibilityReceipt,
  sdkWireTransformStagingReceipt,
  productionTargetAuthority,
  lineage,
} = {}) {
  const descriptors = normalizeCvmReleaseDescriptorSetReceipt(descriptorSetReceipt);
  const compatibility = normalizePhalaCompatibilityReceipt(compatibilityReceipt);
  const staging = normalizePhalaSdkWireTransformStagingReceipt(
    sdkWireTransformStagingReceipt,
    { compatibilityReceipt: compatibility },
  );
  const target = normalizePhalaProductionTargetAuthority(productionTargetAuthority, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  });
  const pins = exactRecord(lineage, BOOTSTRAP_LINEAGE_FIELDS, "bootstrap lineage input");
  for (const field of BOOTSTRAP_LINEAGE_FIELDS) exactSha256(pins[field], field);
  if (target.release_sha !== descriptors.release_sha
    || target.cvm_launch_intent_sha256 !== pins.cvm_launch_intent_sha256) {
    throw new Error("bootstrap target, descriptors, and lineage are cross-release");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    release_sha: target.release_sha,
    deployment_intent_sha256: pins.deployment_intent_sha256,
    deployment_transaction_plan_sha256:
      pins.deployment_transaction_plan_sha256,
    fresh_contract_deployment_receipt_sha256:
      pins.fresh_contract_deployment_receipt_sha256,
    image_release_manifest_sha256: descriptors.image_manifest_sha256,
    image_release_sigstore_verification_receipt_sha256:
      pins.image_release_sigstore_verification_receipt_sha256,
    topology_sha256: descriptors.topology_sha256,
    cvm_launch_intent_sha256: pins.cvm_launch_intent_sha256,
    cvm_launch_review_receipt_sha256: pins.cvm_launch_review_receipt_sha256,
    production_target_authority_sha256:
      phalaProductionTargetAuthorityDigest(target, {
        compatibilityReceipt: compatibility,
        sdkWireTransformStagingReceipt: staging,
      }),
    sdk_wire_transform_staging_receipt_sha256:
      phalaSdkWireTransformStagingReceiptDigest(staging, {
        compatibilityReceipt: compatibility,
      }),
    qvl_measurement_policy_set_sha256:
      pins.qvl_measurement_policy_set_sha256,
    reviewed_at: null,
    valid_until: null,
    domains: CVM_LAUNCH_DOMAINS.map((domain) => ({
      domain,
      descriptor_sha256: descriptors.descriptor_sha256_by_domain[domain],
      values: Object.fromEntries(bootstrapKeys(domain).map((key) => [key, "placeholder"])),
    })),
  }, { label: "bootstrap public-environment review input" });
}

export function finalizeBootstrapPublicEnvironmentAuthority({
  reviewInput,
  compatibilityReceipt,
  sdkWireTransformStagingReceipt,
  productionTargetAuthority,
  nowMs = Date.now(),
  lifetimeSeconds = 600,
} = {}) {
  assertCanonicalPlainDataGraph(reviewInput, {
    label: "bootstrap public-environment review input",
  });
  const compatibility = normalizePhalaCompatibilityReceipt(compatibilityReceipt);
  const staging = normalizePhalaSdkWireTransformStagingReceipt(
    sdkWireTransformStagingReceipt,
    { compatibilityReceipt: compatibility },
  );
  const target = normalizePhalaProductionTargetAuthority(productionTargetAuthority, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  });
  if (!Number.isSafeInteger(nowMs)
    || !Number.isSafeInteger(lifetimeSeconds)
    || lifetimeSeconds < 1 || lifetimeSeconds > 600) {
    throw new Error("bootstrap authority clock or lifetime is outside the ten-minute bound");
  }
  const expectedTarget = phalaProductionTargetAuthorityDigest(target, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  });
  const expectedStaging = phalaSdkWireTransformStagingReceiptDigest(staging, {
    compatibilityReceipt: compatibility,
  });
  if (reviewInput.release_sha !== target.release_sha
    || reviewInput.production_target_authority_sha256 !== expectedTarget
    || reviewInput.sdk_wire_transform_staging_receipt_sha256 !== expectedStaging) {
    throw new Error("bootstrap review input drifted from exact target dependencies");
  }
  const reviewedAtMs = Math.floor(nowMs / 1_000) * 1_000;
  const validUntilMs = Math.min(
    reviewedAtMs + lifetimeSeconds * 1_000,
    Date.parse(target.expires_at),
  );
  if (reviewedAtMs < Date.parse(target.reviewed_at)
    || reviewedAtMs >= Date.parse(target.expires_at)
    || validUntilMs <= reviewedAtMs) {
    throw new Error("bootstrap authority cannot outlive the production target review");
  }
  const candidate = {
    ...structuredClone(reviewInput),
    reviewed_at: new Date(reviewedAtMs).toISOString().replace(".000Z", "Z"),
    valid_until: new Date(validUntilMs).toISOString().replace(".000Z", "Z"),
  };
  const normalized = normalizeBootstrapPublicEnvironmentAuthority(candidate);
  assertSecretFreePhalaAuthorityArtifact(normalized, "bootstrap public environment authority");
  return normalized;
}

export const PHALA_PRODUCER_EXPECTED_BOOTSTRAP_PUBLIC_VALUE_KEYS = Object.freeze(
  Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => [domain, bootstrapKeys(domain)])),
);
