import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
  PHALA_CONTROL_PLANE_AUTHORITY,
  PHALA_CVM_RESOURCE_TARGETS,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
  canonicalFreshContractDeploymentReceiptText,
  freshContractDeploymentReceiptDigest,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
  PHALA_PHASE_SECRET_INPUT_SCHEMA,
  bootstrapPublicEnvironmentAuthorityDigest,
  canonicalBootstrapPublicEnvironmentAuthorityText,
  projectProvisioningEnvironmentAuthority,
  privateEnvironmentEntries,
} from "./phala-production-environment-authority.mjs";
import {
  PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH,
  PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE,
  assertCryptographicallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt,
  assertHistoricallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt,
  assertPersistedPhalaNonLiveBootstrapAuthorizationReceipt,
  assertFreshPhalaNonLiveBootstrapAuthorizationReceipt,
  assertVerifiedPhalaNonLiveBootstrapImmediateRecheck,
  canonicalPhalaNonLiveBootstrapAuthorizationReceiptText,
  canonicalPhalaNonLiveBootstrapAuthorizationText,
  createPhalaNonLiveBootstrapSigningPayload,
  phalaNonLiveBootstrapAuthorizationId,
  phalaNonLiveBootstrapAuthorizationReceiptSha256,
  phalaNonLiveBootstrapSigningDigest,
  phalaNonLiveBootstrapSigningMessage,
  readAndVerifyPhalaNonLiveBootstrapAuthorization,
  readAndValidateFreshContractDeploymentAnchorEvidence,
  readReverifyAndCheckpointPhalaNonLiveBootstrapAuthorization,
  reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch,
  verifyPhalaNonLiveBootstrapAuthorization,
  verifyHistoricalPhalaNonLiveBootstrapAuthorization,
} from "./phala-nonlive-bootstrap-authorization.mjs";
import {
  assembleAuthorizedPrivateBootstrapEnvironment,
} from "./phala-authorized-private-bootstrap-environment.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  normalizeExpectedReviewerAuthority,
  reviewerSetSha256,
} from "./release-authority-signature-verifier.mjs";
import {
  createFinalizedPhalaMutationGate,
} from "./phala-production-executor-core.mjs";
import {
  PHALA_API_CANDIDATE_VERSIONS,
  PHALA_COMPATIBILITY_RECEIPT_SCHEMA,
  PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA,
  PHALA_READ_ONLY_COMPATIBILITY_CALLS,
  PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA,
  canonicalPhalaCompatibilityReceiptText,
  canonicalPhalaProductionTargetAuthorityText,
  canonicalPhalaSdkWireTransformStagingReceiptText,
  phalaCompatibilityReceiptDigest,
  phalaProductionTargetAuthorityDigest,
  phalaSdkWireTransformStagingReceiptDigest,
} from "./phala-production-target-authority.mjs";
import {
  canonicalArtifactSha256,
  canonicalArtifactText,
  createDraftDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
  canonicalReleaseReviewerAuthorityGenesisArtifactText,
  releaseReviewerAuthorityGenesisSha256,
  reviewerControllerSetSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
  createReleaseReviewerAuthorityCurrentStatusSigningPayload,
  createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload,
  canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityCurrentStatusSigningMessage,
  releaseReviewerAuthorityCurrentStatusSigningPayloadSha256,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
  releaseReviewerAuthorityGenesisAcceptanceSigningMessage,
  releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  syntheticFreshContractDeploymentReceiptFixture,
} from "./fresh-contract-deployment-receipt.fixture.mjs";
import {
  RELEASE_MANIFEST_SIGSTORE_BLOCKER,
} from "./release-manifest-sigstore-verifier.mjs";

const TEST_ALPHA = privateKeyToAccount(`0x${"11".repeat(32)}`);
const TEST_BRAVO = privateKeyToAccount(`0x${"22".repeat(32)}`);
const TEST_FORGED = privateKeyToAccount(`0x${"33".repeat(32)}`);
const TEST_GUARDIAN_ALPHA = privateKeyToAccount(`0x${"44".repeat(32)}`);
const TEST_GUARDIAN_BRAVO = privateKeyToAccount(`0x${"55".repeat(32)}`);
const sha = (digit) => `sha256:${String(digit).repeat(64)}`;
const bare = (digit) => String(digit).repeat(64);
const app = (digit) => String(digit).repeat(40);
const address = (digit) => `0x${String(digit).repeat(40)}`;
const BATCH_ID = sha("b");

function canonicalFileIdentity(text) {
  const bytes = Buffer.from(text, "utf8");
  return {
    sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
    size: bytes.length,
  };
}

function publicValue(key) {
  if (key === "TINKER_WALLET_AUTH_DOMAIN") return "www.wikigen.me";
  if (key === "TINKER_WALLET_AUTH_URI") return "https://www.wikigen.me";
  if (key.endsWith("_ADDRESS")) return address("a");
  if (key.endsWith("_URL") || key.endsWith("_URI")) {
    return `https://authority.example/${key.toLowerCase()}`;
  }
  if (key === "TINKER_CORS_ALLOWED_ORIGINS") {
    return "https://wikigen.me,https://wikigenme.pages.dev,https://www.wikigen.me";
  }
  if (key === "TINKER_FUNDING_PREFLIGHT_ALLOWED_HOSTS") return "api.tinker.example";
  if (key === "TINKER_EXECUTION_POLICY_APPROVED_SIGNERS") {
    return [TEST_ALPHA.address, TEST_BRAVO.address]
      .map((value) => value.toLowerCase()).sort().join(",");
  }
  if (key === "TINKER_WALLET_AUTH_CHAIN_ID") return "84532";
  if (key === "TINKER_CHAIN_START_BLOCK") return "12345678";
  if (key.endsWith("_RUNTIME_CODE_HASH")) return `0x${bare("a")}`;
  if (key.endsWith("_EPOCH")) return "1";
  if (key.endsWith("_SHA256")) return sha("a");
  if (key.endsWith("_HASH")) return bare("a");
  return `reviewed-${key.toLowerCase()}`;
}

function bootstrapKeys(domain) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const allowed = new Set(policy.exact_allowed_environment_keys);
  return policy.public_environment_key_classification.descriptor_static_keys
    .filter((key) => allowed.has(key));
}

function bootstrapAuthority({
  deploymentIntentSha256 = sha("1"),
  productionTargetAuthoritySha256 = sha("8"),
  sdkWireTransformStagingReceiptSha256 = sha("9"),
} = {}) {
  return {
    schema: PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    release_sha: "a".repeat(40),
    deployment_intent_sha256: deploymentIntentSha256,
    deployment_transaction_plan_sha256: sha("2"),
    fresh_contract_deployment_receipt_sha256: sha("3"),
    image_release_manifest_sha256: sha("4"),
    image_release_sigstore_verification_receipt_sha256: sha("e"),
    topology_sha256: sha("5"),
    cvm_launch_intent_sha256: sha("6"),
    cvm_launch_review_receipt_sha256: sha("7"),
    production_target_authority_sha256: productionTargetAuthoritySha256,
    sdk_wire_transform_staging_receipt_sha256:
      sdkWireTransformStagingReceiptSha256,
    qvl_measurement_policy_set_sha256: sha("d"),
    reviewed_at: "2026-07-21T10:00:00Z",
    valid_until: "2026-07-21T11:00:00Z",
    domains: CVM_LAUNCH_DOMAINS.map((domain, index) => ({
      domain,
      descriptor_sha256: sha(String(index + 1)),
      values: Object.fromEntries(
        bootstrapKeys(domain).map((key) => [key, publicValue(key)]),
      ),
    })),
  };
}

function compatibilityFixture() {
  return {
    schema: PHALA_COMPATIBILITY_RECEIPT_SCHEMA,
    truth_status:
      "authenticated_read_only_compatibility_observation_not_launch_authority",
    checked_at: "2026-07-21T10:00:00Z",
    expires_at: "2026-07-21T10:10:00Z",
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
      account_subject_sha256: sha("1"),
      authenticated: true,
    },
    sdk_identity: {
      phala_cli_version: "1.1.19",
      phala_cli_manifest_sha256: sha("2"),
      phala_cloud_version: "0.2.10",
      phala_cloud_manifest_sha256: sha("3"),
      phala_cloud_npm_dist_integrity_sha512:
        "sha512-eQXJxbBlJ8xA4e+MmB3AZd9jgdbO3tFh+qu7KL6CS5Ta64LNKlrV3vdke3oUvB22xbc/qqKQ6dIkJx5pTdY7gA==",
      phala_cloud_module_sha256: sha("4"),
      dstack_sdk_version: "0.5.8",
      dstack_sdk_manifest_sha256: sha("5"),
      dstack_verify_module_sha256: sha("6"),
      dstack_compose_hash_module_sha256: sha("7"),
      dstack_encryption_module_sha256: sha("8"),
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

function stagingFixture(compatibilityReceipt) {
  return {
    schema: PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA,
    truth_status:
      "authenticated_staging_wire_capture_not_production_cvm_commit_tdx_attestation_or_launch_authority",
    compatibility_receipt_sha256:
      phalaCompatibilityReceiptDigest(compatibilityReceipt),
    captured_at: "2026-07-21T10:01:00Z",
    expires_at: "2026-07-21T10:10:00Z",
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
    cleanup_receipt_sha256: sha("f"),
    domains: CVM_LAUNCH_DOMAINS.map((domain, index) => {
      const pre = ((index + 9) % 15 + 1).toString(16);
      const post = (index + 1).toString(16);
      const response = ((index + 7) % 15 + 1).toString(16);
      return {
        domain,
        pre_transform_request_sha256: sha(pre),
        expected_post_transform_body_sha256: sha(post),
        captured_post_transform_body_sha256: sha(post),
        pre_transform_compose_hash: pre.repeat(64),
        expected_post_transform_compose_hash: post.repeat(64),
        prepare_server_compose_hash: post.repeat(64),
        prepare_response_sha256: sha(response),
      };
    }),
  };
}

function targetFixture(compatibilityReceipt, stagingReceipt) {
  return {
    schema: PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA,
    truth_status:
      "reviewed_target_authority_not_phala_deployment_attestation_or_execution_receipt",
    release_sha: "a".repeat(40),
    cvm_launch_intent_sha256: sha("6"),
    review_envelope_sha256: sha("6"),
    review_evidence_sha256: sha("7"),
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
      signer_provenance_sha256: sha("a"),
      valid_from: "2026-07-21T00:00:00Z",
      valid_until: "2026-08-21T00:00:00Z",
    },
    os_image: { ...PHALA_OS_IMAGE_CATALOG_ENTRY },
    resource_targets: Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => [
      domain,
      {
        ...structuredClone(PHALA_CVM_RESOURCE_TARGETS[domain]),
        authority_status: "reviewed_authenticated_catalog_and_quota_validated",
      },
    ])),
    app_compose_profiles: Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => [
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
    ])),
    reviewed_at: "2026-07-21T10:02:00Z",
    expires_at: "2026-07-21T10:10:00Z",
  };
}

function reviewerFixture() {
  const identities = [
    {
      account: TEST_ALPHA,
      address: TEST_ALPHA.address.toLowerCase(),
      controller_id: "reviewer-alpha",
    },
    {
      account: TEST_BRAVO,
      address: TEST_BRAVO.address.toLowerCase(),
      controller_id: "reviewer-bravo",
    },
  ].sort((left, right) => left.address.localeCompare(right.address));
  const approvedReviewers = identities.map(({ address: value, controller_id }) => ({
    address: value,
    controller_id,
  }));
  const hashes = approvedReviewers
    .map(({ address: value }) => executionPolicyReviewerHash(value)).sort();
  const root = executionPolicyReviewerRootHash(hashes);
  const setSha = reviewerSetSha256(approvedReviewers);
  const value = {
    approved_reviewers: approvedReviewers,
    approved_reviewer_hashes: hashes,
    reviewer_root_hash: root,
    reviewer_set_sha256: setSha,
  };
  const authority = normalizeExpectedReviewerAuthority(value, {
    expectedReviewerRootHash: root,
    expectedReviewerSetSha256: setSha,
  });
  const reviewerControllers = approvedReviewers.map((entry) => ({
    controller_id: entry.controller_id,
    preauthorized_addresses: [entry.address],
  })).sort((left, right) => left.controller_id.localeCompare(right.controller_id));
  const guardianAccounts = [TEST_GUARDIAN_ALPHA, TEST_GUARDIAN_BRAVO];
  const statusGuardians = guardianAccounts.map((account, index) => ({
    address: account.address.toLowerCase(),
    controller_id: `status-guardian-${index + 1}`,
  })).sort((left, right) => left.address.localeCompare(right.address));
  const guardianHashes = statusGuardians
    .map((entry) => executionPolicyReviewerHash(entry.address)).sort();
  const genesis = {
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
    truth_status: RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
    release_sha: "a".repeat(40),
    chain_id: 84_532,
    minimum_active_reviewers: RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
    reviewer_controllers: reviewerControllers,
    reviewer_controller_set_sha256: reviewerControllerSetSha256(reviewerControllers),
    status_guardians: statusGuardians,
    status_guardian_hashes: guardianHashes,
    status_guardian_root_hash: executionPolicyReviewerRootHash(guardianHashes),
    status_guardian_set_sha256: reviewerSetSha256(statusGuardians),
  };
  return { authority, guardianAccounts, identities, root, setSha, value, genesis };
}

function validQvlPolicy() {
  return {
    challengeCapacity: 1_024,
    challengeTtlSeconds: 60,
    maxConcurrency: 4,
    rateCapacity: 30,
    rateRefillPerSecond: "0.5",
    requestBodyTimeoutSeconds: "5",
    verificationTimeoutSeconds: "20",
  };
}

function deploymentIntentFixture(genesisAcceptanceSha256, currentStatus, genesis) {
  const intent = createDraftDeploymentIntentCore();
  intent.release.releaseSha = "a".repeat(40);
  intent.release.reviewerAuthorityGenesisAcceptanceSha256 =
    genesisAcceptanceSha256;
  intent.release.reviewerAuthorityCurrentStatusEpoch = currentStatus.epoch;
  intent.release.reviewerAuthorityCurrentStatusSha256 =
    releaseReviewerAuthorityCurrentStatusSha256(
      currentStatus,
      { reviewerGenesis: genesis },
    );
  intent.deploymentControl.controllerId = "deployment-operator-01";
  intent.deploymentControl.operatorAddress = address("1");
  intent.staticContractInputs.diligenceRoom.governanceController = address("4");
  intent.staticContractInputs.computeCreditVault.developer = address("2");
  intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment =
    `0x${bare("3")}`;
  intent.numericPolicy.contract = {
    computeDeveloperFeeBps: 100,
    emailOracleUpgradeDelaySeconds: 172_800,
    tinkerMaxAddBalanceWei: "5000000000000000000",
    tinkerMaxSpendWei: "2000000000000000000",
  };
  intent.numericPolicy.metering = {
    maxConcurrency: 4,
    rateCapacity: 30,
    rateRefillPerSecond: "0.5",
    requestBodyTimeoutSeconds: "5",
    rpcTimeoutSeconds: "8",
  };
  for (const name of Object.keys(intent.numericPolicy.qvl)) {
    intent.numericPolicy.qvl[name] = validQvlPolicy();
  }
  return intent;
}

async function currentStatusFixture(reviewers) {
  const activeReviewers = reviewers.value.approved_reviewers;
  const options = { reviewerGenesis: reviewers.genesis };
  const payload = createReleaseReviewerAuthorityCurrentStatusSigningPayload({
    epoch: 1,
    not_before: "2026-07-21T09:55:00Z",
    expires_at: "2026-07-21T10:10:00Z",
    previous_status_sha256: `sha256:${"0".repeat(64)}`,
    active_reviewers: activeReviewers,
    revoked_controller_ids: [],
    revoked_reviewer_addresses: [],
  }, options);
  const message = releaseReviewerAuthorityCurrentStatusSigningMessage(payload, options);
  const byAddress = new Map(
    reviewers.guardianAccounts.map((account) => [account.address.toLowerCase(), account]),
  );
  return {
    ...payload,
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
    signing_payload_sha256:
      releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(payload, options),
    guardian_signatures: await Promise.all(
      reviewers.genesis.status_guardians.map(async (entry) => ({
        ...entry,
        signature: (await byAddress.get(entry.address)
          .signMessage({ message })).toLowerCase(),
      })),
    ),
  };
}

async function genesisAcceptanceFixture(reviewers, currentStatus) {
  const payload = createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
    reviewers.genesis,
    { reviewerCurrentStatus: currentStatus },
  );
  const message = releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
    payload,
    { reviewerGenesis: reviewers.genesis },
  );
  const byAddress = new Map(
    reviewers.identities.map((entry) => [entry.address, entry.account]),
  );
  return {
    ...payload,
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
    signing_payload_sha256:
      releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
        payload,
        { reviewerGenesis: reviewers.genesis },
      ),
    acceptances: await Promise.all(
      currentStatus.active_reviewers.map(async (entry) => ({
      ...entry,
      signature: (await byAddress.get(entry.address).signMessage({ message }))
        .toLowerCase(),
      })),
    ),
  };
}

async function signedAuthorization({
  bootstrap = bootstrapAuthority(),
  reviewers = reviewerFixture(),
  batchId = BATCH_ID,
  issuedAt = "2026-07-21T10:01:00Z",
  expiresAt = "2026-07-21T10:11:00Z",
  signerAccounts = null,
} = {}) {
  const bootstrapDigest = bootstrapPublicEnvironmentAuthorityDigest(bootstrap);
  const payload = createPhalaNonLiveBootstrapSigningPayload({
    schema: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA,
    status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS,
    truth_status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH,
    authorization_id: phalaNonLiveBootstrapAuthorizationId({
      releaseSha: bootstrap.release_sha,
      batchId,
      bootstrapPublicEnvironmentAuthoritySha256: bootstrapDigest,
    }),
    chain_id: 84_532,
    release_sha: bootstrap.release_sha,
    batch_id: batchId,
    bootstrap_public_environment_authority_sha256: bootstrapDigest,
    deployment_intent_sha256: bootstrap.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      bootstrap.fresh_contract_deployment_receipt_sha256,
    image_release_sigstore_verification_receipt_sha256:
      bootstrap.image_release_sigstore_verification_receipt_sha256,
    cvm_launch_intent_sha256: bootstrap.cvm_launch_intent_sha256,
    cvm_launch_review_receipt_sha256: bootstrap.cvm_launch_review_receipt_sha256,
    production_target_authority_sha256:
      bootstrap.production_target_authority_sha256,
    sdk_wire_transform_staging_receipt_sha256:
      bootstrap.sdk_wire_transform_staging_receipt_sha256,
    qvl_measurement_policy_set_sha256:
      bootstrap.qvl_measurement_policy_set_sha256,
    action_scope: [...PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE],
    forbidden_scope: [...PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE],
    issued_at: issuedAt,
    expires_at: expiresAt,
    reviewer_root_hash: reviewers.root,
    reviewer_set_sha256: reviewers.setSha,
    reviewers: reviewers.identities.map(({ address: value, controller_id }) => ({
      address: value,
      controller_id,
    })),
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
  }, { bootstrapAuthority: bootstrap });
  const digest = phalaNonLiveBootstrapSigningDigest(payload, {
    bootstrapAuthority: bootstrap,
  });
  const message = phalaNonLiveBootstrapSigningMessage(payload, {
    bootstrapAuthority: bootstrap,
  });
  const accounts = signerAccounts ?? reviewers.identities.map(({ account }) => account);
  const rawSignatures = await Promise.all(
    accounts.map((account) => account.signMessage({ message })),
  );
  return {
    bootstrap,
    reviewers,
    authorization: {
      ...payload,
      signed_payload_sha256: digest,
      signatures: reviewers.identities.map(({ address: value, controller_id }, index) => ({
        address: value,
        controller_id,
        signature: rawSignatures[index].toLowerCase(),
      })),
    },
  };
}

function prepareObservations() {
  return CVM_LAUNCH_DOMAINS.map((domain, index) => ({
    domain,
    app_id: app(String(index + 1)),
    compose_hash: bare(String(index + 1)),
    os_image_hash: bare("a"),
    prepare_response_sha256: sha(String(index + 1)),
  }));
}

test("two transitively pinned signatures authorize one non-live bootstrap batch", async () => {
  const fixture = await signedAuthorization();
  const receipt = verifyPhalaNonLiveBootstrapAuthorization({
    authorization: fixture.authorization,
    bootstrapAuthority: fixture.bootstrap,
    reviewerAuthority: fixture.reviewers.authority,
    nowMs: Date.parse("2026-07-21T10:05:00Z"),
  });
  assert.equal(receipt.status, "non_live_bootstrap_signatures_verified");
  assert.equal(
    receipt.schema,
    PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
  );
  assert.equal(receipt.authorization_id, fixture.authorization.authorization_id);
  assert.equal(receipt.signer_count, 2);
  assert.equal(receipt.live_traffic_authorized, false);
  assert.equal(receipt.late_secret_activation_authorized, false);
  assert.equal(receipt.mutation_performed, false);
  assert.equal(
    receipt.image_release_manifest_sha256,
    fixture.bootstrap.image_release_manifest_sha256,
  );
  assert.equal(receipt.topology_sha256, fixture.bootstrap.topology_sha256);
  assert.deepEqual(
    receipt.descriptor_sha256_by_domain,
    Object.fromEntries(fixture.bootstrap.domains.map((entry) => [
      entry.domain,
      entry.descriptor_sha256,
    ])),
  );
  assert.equal(receipt.signers.every((entry) => !Object.hasOwn(entry, "signature")), true);
  assert.match(
    phalaNonLiveBootstrapAuthorizationReceiptSha256(receipt),
    /^sha256:[0-9a-f]{64}$/,
  );
  const immutableReceiptSha256 =
    phalaNonLiveBootstrapAuthorizationReceiptSha256(receipt);
  assert.throws(() => {
    receipt.signers[0].controller_id = "mutated-controller";
  }, TypeError);
  assert.throws(() => {
    receipt.action_scope.push("phala.unreviewed");
  }, TypeError);
  assert.throws(() => {
    receipt.signature_verifier.tool = "unreviewed";
  }, TypeError);
  assert.throws(() => {
    receipt.descriptor_sha256_by_domain.main_runtime_cvm = sha("f");
  }, TypeError);
  assert.equal(
    phalaNonLiveBootstrapAuthorizationReceiptSha256(receipt),
    immutableReceiptSha256,
  );
  assert.equal(
    canonicalPhalaNonLiveBootstrapAuthorizationReceiptText(receipt),
    canonicalPhalaNonLiveBootstrapAuthorizationReceiptText(
      JSON.parse(canonicalPhalaNonLiveBootstrapAuthorizationReceiptText(receipt)),
    ),
  );
  const persistedReceipt = JSON.parse(
    canonicalPhalaNonLiveBootstrapAuthorizationReceiptText(receipt),
  );
  assert.deepEqual(
    assertPersistedPhalaNonLiveBootstrapAuthorizationReceipt({
      persistedReceipt,
      verifiedReceipt: receipt,
    }),
    receipt,
  );
  const omittedDescriptor = structuredClone(persistedReceipt);
  delete omittedDescriptor.descriptor_sha256_by_domain.main_runtime_cvm;
  assert.throws(() => assertPersistedPhalaNonLiveBootstrapAuthorizationReceipt({
    persistedReceipt: omittedDescriptor,
    verifiedReceipt: receipt,
  }), /exactly the reviewed fields/);
  const substitutedDescriptor = structuredClone(persistedReceipt);
  substitutedDescriptor.descriptor_sha256_by_domain.main_runtime_cvm = sha("f");
  assert.throws(() => assertPersistedPhalaNonLiveBootstrapAuthorizationReceipt({
    persistedReceipt: substitutedDescriptor,
    verifiedReceipt: receipt,
  }), /differs from the cryptographically verified/);
  const recheck = assertFreshPhalaNonLiveBootstrapAuthorizationReceipt({
    receipt,
    checkpoint: "before_each_provision",
    nowMs: Date.parse("2026-07-21T10:06:00Z"),
    expectedBatchId: BATCH_ID,
    expectedAuthorizationId: fixture.authorization.authorization_id,
    expectedTargetAuthoritySha256: fixture.bootstrap.production_target_authority_sha256,
    expectedStagingReceiptSha256:
      fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
  });
  assert.equal(recheck.fresh, true);
  assert.equal(recheck.live_traffic_authorized, false);
  assert.equal(recheck.status, "non_live_bootstrap_signatures_reverified");
  assert.equal(recheck.stable_file_reread, false);
  assert.equal(assertVerifiedPhalaNonLiveBootstrapImmediateRecheck({
    recheck,
    checkpoint: "before_each_provision",
    expectedBatchId: BATCH_ID,
    expectedAuthorizationId: fixture.authorization.authorization_id,
  }), recheck);
  assert.throws(() => assertVerifiedPhalaNonLiveBootstrapImmediateRecheck({
    recheck: structuredClone(recheck),
    checkpoint: "before_each_provision",
    expectedBatchId: BATCH_ID,
    expectedAuthorizationId: fixture.authorization.authorization_id,
  }), /branded/);
  assert.throws(
    () => assertFreshPhalaNonLiveBootstrapAuthorizationReceipt({
      receipt: structuredClone(receipt),
      checkpoint: "before_each_commit",
      nowMs: Date.parse("2026-07-21T10:06:00Z"),
      expectedBatchId: BATCH_ID,
      expectedAuthorizationId: fixture.authorization.authorization_id,
      expectedTargetAuthoritySha256: fixture.bootstrap.production_target_authority_sha256,
      expectedStagingReceiptSha256:
        fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
    }),
    /branded/,
  );
});

test("expired signed A is historical evidence but never renewed mutation authority", async (t) => {
  const fixture = await signedAuthorization();
  let verifierNowMs = Date.parse("2026-07-21T10:05:00Z");
  t.mock.method(Date, "now", () => verifierNowMs);
  assert.throws(() => verifyHistoricalPhalaNonLiveBootstrapAuthorization({
    authorization: fixture.authorization,
    bootstrapAuthority: fixture.bootstrap,
    reviewerAuthority: fixture.reviewers.authority,
  }), /has not expired/);
  assert.throws(() => verifyHistoricalPhalaNonLiveBootstrapAuthorization({
    authorization: fixture.authorization,
    bootstrapAuthority: fixture.bootstrap,
    reviewerAuthority: fixture.reviewers.authority,
    nowMs: Date.parse("2026-07-21T12:00:00Z"),
  }), /current process clock/);
  verifierNowMs = Date.parse("2026-07-21T10:11:00Z");
  const historical = verifyHistoricalPhalaNonLiveBootstrapAuthorization({
    authorization: fixture.authorization,
    bootstrapAuthority: fixture.bootstrap,
    reviewerAuthority: fixture.reviewers.authority,
  });
  assert.equal(historical.authorization_id, fixture.authorization.authorization_id);
  assert.deepEqual(
    assertHistoricallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt(historical),
    historical,
  );
  assert.throws(() => assertFreshPhalaNonLiveBootstrapAuthorizationReceipt({
    receipt: historical,
    checkpoint: "before_each_commit",
    nowMs: Date.parse("2026-07-21T12:00:00Z"),
    expectedBatchId: BATCH_ID,
    expectedAuthorizationId: fixture.authorization.authorization_id,
    expectedTargetAuthoritySha256:
      fixture.bootstrap.production_target_authority_sha256,
    expectedStagingReceiptSha256:
      fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
  }), /branded|fresh/);
  assert.throws(() => verifyPhalaNonLiveBootstrapAuthorization({
    authorization: fixture.authorization,
    bootstrapAuthority: fixture.bootstrap,
    reviewerAuthority: fixture.reviewers.authority,
    nowMs: Date.parse("2026-07-21T10:11:00Z"),
  }), /not fresh/);
});

test("persisted signed A replays signatures at L completion without consulting current time or minting a brand", async (t) => {
  const fixture = await signedAuthorization();
  const original = verifyPhalaNonLiveBootstrapAuthorization({
    authorization: fixture.authorization,
    bootstrapAuthority: fixture.bootstrap,
    reviewerAuthority: fixture.reviewers.authority,
    nowMs: Date.parse("2026-07-21T10:05:00Z"),
  });
  const authorizationFileIdentity = canonicalFileIdentity(
    canonicalPhalaNonLiveBootstrapAuthorizationText(fixture.authorization, {
      bootstrapAuthority: fixture.bootstrap,
    }),
  );
  const bootstrapAuthorityFileIdentity = canonicalFileIdentity(
    canonicalBootstrapPublicEnvironmentAuthorityText(fixture.bootstrap),
  );
  t.mock.method(Date, "now", () => Date.parse("2099-01-01T00:00:00Z"));
  const result =
    reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch({
      authorization: fixture.authorization,
      bootstrapAuthority: fixture.bootstrap,
      reviewerAuthority: fixture.reviewers.authority,
      persistedReceipt: structuredClone(original),
      authorizationFileIdentity,
      bootstrapAuthorityFileIdentity,
      launchCompletedAt:
        Math.floor(Date.parse("2026-07-21T10:09:00Z") / 1_000),
    });
  assert.equal(result.signature_verification_performed, true);
  assert.equal(result.independent_signature_replay_performed, true);
  assert.equal(result.original_signature_verifier_reexecuted, false);
  assert.deepEqual(
    result.original_signature_verifier,
    PINNED_CAST_SIGNATURE_VERIFIER,
  );
  assert.match(result.replay_signature_verifier.tool, /@noble\/curves/);
  assert.notDeepEqual(
    result.replay_signature_verifier,
    result.original_signature_verifier,
  );
  assert.equal(result.current_clock_consulted, false);
  assert.equal(result.freshness_renewed, false);
  assert.equal(result.production_brand_minted, false);
  assert.equal(result.live_traffic_authorized, false);
  assert.deepEqual(result.historical_bootstrap_authorization_binding, {
    authorization_id: original.authorization_id,
    batch_id: original.batch_id,
    receipt_sha256:
      phalaNonLiveBootstrapAuthorizationReceiptSha256(original),
    issued_at: original.issued_at,
    expires_at: original.expires_at,
  });
  assert.throws(
    () => assertCryptographicallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt(
      result.receipt,
    ),
    /has not been cryptographically reconstructed/,
  );
  assert.throws(
    () => reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch({
      authorization: fixture.authorization,
      bootstrapAuthority: fixture.bootstrap,
      reviewerAuthority: fixture.reviewers.authority,
      persistedReceipt: structuredClone(original),
      authorizationFileIdentity,
      bootstrapAuthorityFileIdentity,
      launchCompletedAt:
        Math.floor(Date.parse(original.expires_at) / 1_000),
    }),
    /outside signed A's original mutation window/,
  );
  const drifted = structuredClone(original);
  drifted.mutation_performed = true;
  assert.throws(
    () => reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch({
      authorization: fixture.authorization,
      bootstrapAuthority: fixture.bootstrap,
      reviewerAuthority: fixture.reviewers.authority,
      persistedReceipt: drifted,
      authorizationFileIdentity,
      bootstrapAuthorityFileIdentity,
      launchCompletedAt:
        Math.floor(Date.parse("2026-07-21T10:09:00Z") / 1_000),
    }),
  );
});

test("copied test-adapter Sigstore fields cannot forge launch checkpoint A", async () => {
  const fixture = await signedAuthorization();
  const receipt = verifyPhalaNonLiveBootstrapAuthorization({
    authorization: fixture.authorization,
    bootstrapAuthority: fixture.bootstrap,
    reviewerAuthority: fixture.reviewers.authority,
    nowMs: Date.parse("2026-07-21T10:05:00Z"),
  });
  const recheck = assertFreshPhalaNonLiveBootstrapAuthorizationReceipt({
    receipt,
    checkpoint: "before_each_provision",
    nowMs: Date.parse("2026-07-21T10:06:00Z"),
    expectedBatchId: BATCH_ID,
    expectedAuthorizationId: fixture.authorization.authorization_id,
    expectedTargetAuthoritySha256:
      fixture.bootstrap.production_target_authority_sha256,
    expectedStagingReceiptSha256:
      fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
  });
  const copiedTestAdapterRecheck = Object.freeze({
    ...recheck,
    release_manifest_sigstore_cryptographically_verified: true,
    release_manifest_sigstore_blocker_code:
      RELEASE_MANIFEST_SIGSTORE_BLOCKER,
    release_manifest_sigstore_blocker_status: "cleared_by_this_receipt",
    release_manifest_sigstore_verification_receipt_sha256:
      fixture.bootstrap.image_release_sigstore_verification_receipt_sha256,
    release_manifest_sigstore_verification_receipt_artifact_file_sha256:
      sha("7"),
    release_manifest_sha256: fixture.bootstrap.image_release_manifest_sha256,
    release_manifest_sigstore_bundle_sha256: sha("8"),
    sigstore_verified_identity_sha256: sha("9"),
    test_adapter_receipt_status:
      "test_adapter_verified_not_release_authority",
  });
  assert.throws(
    () => assertVerifiedPhalaNonLiveBootstrapImmediateRecheck({
      recheck: copiedTestAdapterRecheck,
      checkpoint: "before_each_provision",
      expectedBatchId: BATCH_ID,
      expectedAuthorizationId: fixture.authorization.authorization_id,
      requireReleaseManifestSigstoreValidation: true,
    }),
    /branded|Sigstore receipt/,
  );
});

test("legacy/live/cross-batch/drifted and forged bootstrap authorities fail closed", async () => {
  const fixture = await signedAuthorization();
  const verify = (authorization, reviewerAuthority = fixture.reviewers.authority) => (
    verifyPhalaNonLiveBootstrapAuthorization({
      authorization,
      bootstrapAuthority: fixture.bootstrap,
      reviewerAuthority,
      nowMs: Date.parse("2026-07-21T10:05:00Z"),
    })
  );
  for (const mutate of [
    (copy) => { copy.schema = "dnai.final-release-authority-core.v2"; },
    (copy) => { copy.status = "live_activation_authorized"; },
    (copy) => { copy.action_scope.push("cloudflare.deploy.pages"); },
    (copy) => { copy.batch_id = sha("c"); },
    (copy) => { copy.production_target_authority_sha256 = sha("d"); },
    (copy) => { copy.signature_verifier.executable_sha256 = sha("e"); },
    (copy) => { delete copy.signature_verifier.executable_user_relative_path; },
  ]) {
    const drift = structuredClone(fixture.authorization);
    mutate(drift);
    assert.throws(() => verify(drift));
  }
  const forged = await signedAuthorization({ signerAccounts: [TEST_FORGED, TEST_BRAVO] });
  assert.throws(
    () => verify(forged.authorization),
    /verification failed/,
  );

  const forgedIdentities = [
    {
      address: TEST_FORGED.address.toLowerCase(),
      controller_id: "reviewer-forged",
    },
    fixture.reviewers.value.approved_reviewers[1],
  ].sort((left, right) => left.address.localeCompare(right.address));
  const hashes = forgedIdentities
    .map(({ address: value }) => executionPolicyReviewerHash(value)).sort();
  const selfSelected = {
    approved_reviewers: forgedIdentities,
    approved_reviewer_hashes: hashes,
    reviewer_root_hash: executionPolicyReviewerRootHash(hashes),
    reviewer_set_sha256: reviewerSetSha256(forgedIdentities),
  };
  assert.throws(
    () => normalizeExpectedReviewerAuthority(selfSelected, {
      expectedReviewerRootHash: fixture.reviewers.root,
      expectedReviewerSetSha256: fixture.reviewers.setSha,
    }),
    /transitive root\/set pins/,
  );
});

test("fresh contract anchor evidence is stable-read, externally pinned, and domain-bound", (t) => {
  const deploymentIntentSha256 = sha("1");
  const reviewerAuthorityGenesisAcceptanceSha256 = sha("2");
  const fixture = syntheticFreshContractDeploymentReceiptFixture({
    releaseSha: "a".repeat(40),
    deploymentIntentSha256,
    reviewerAuthorityGenesisAcceptanceSha256,
  });
  const receiptSha256 = `sha256:${freshContractDeploymentReceiptDigest(
    fixture.receipt,
    fixture.authorityPins,
  )}`;
  const directory = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-contract-anchor-evidence-")),
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const receiptPath = path.join(directory, "fresh-contract-receipt.json");
  fs.writeFileSync(
    receiptPath,
    canonicalFreshContractDeploymentReceiptText(
      fixture.receipt,
      fixture.authorityPins,
    ),
    { mode: 0o400 },
  );
  const input = {
    freshContractDeploymentReceiptPath: receiptPath,
    bootstrapAuthorityEvidence: {
      release_sha: "a".repeat(40),
      fresh_contract_deployment_receipt_sha256: receiptSha256,
    },
    reviewerAuthorityEvidence: {
      deployment_intent_sha256: deploymentIntentSha256,
      reviewer_authority_genesis_acceptance_sha256:
        reviewerAuthorityGenesisAcceptanceSha256,
    },
    expectedTinkerAccountBindingCeremonyReceiptSha256:
      fixture.authorityPins.expectedTinkerAccountBindingCeremonyReceiptSha256,
  };
  const evidence = readAndValidateFreshContractDeploymentAnchorEvidence(input);
  assert.equal(evidence.freshContractDeploymentReceiptSha256, receiptSha256);
  assert.equal(
    evidence.executionPolicyAnchorAuthorityCommitmentReadProof,
    "primary_and_secondary_rpc_exact_getter_match_at_deployment_block",
  );
  assert.ok(evidence.executionPolicyAnchorDeploymentBlock > 0);
  assert.match(evidence.executionPolicyAnchorDeploymentBlockHash, /^0x[0-9a-f]{64}$/);

  assert.throws(
    () => readAndValidateFreshContractDeploymentAnchorEvidence({
      ...input,
      bootstrapAuthorityEvidence: {
        ...input.bootstrapAuthorityEvidence,
        fresh_contract_deployment_receipt_sha256: sha("f"),
      },
    }),
    /does not equal the signed bootstrap subject/,
  );
  assert.throws(
    () => readAndValidateFreshContractDeploymentAnchorEvidence({
      ...input,
      reviewerAuthorityEvidence: {
        ...input.reviewerAuthorityEvidence,
        reviewer_authority_genesis_acceptance_sha256: sha("f"),
      },
    }),
    /external reviewed pins|authority commitments/,
  );
  const linkPath = path.join(directory, "fresh-contract-receipt-link.json");
  fs.symlinkSync(receiptPath, linkPath);
  assert.throws(
    () => readAndValidateFreshContractDeploymentAnchorEvidence({
      ...input,
      freshContractDeploymentReceiptPath: linkPath,
    }),
    /canonical, and symlink-free/,
  );
});

test("stable canonical files bind the branded receipt and reject aliases or rewrites", async (t) => {
  const reviewers = reviewerFixture();
  const currentStatus = await currentStatusFixture(reviewers);
  const genesisAcceptance = await genesisAcceptanceFixture(
    reviewers,
    currentStatus,
  );
  const deploymentIntent = deploymentIntentFixture(
    releaseReviewerAuthorityGenesisAcceptanceSha256(genesisAcceptance, {
      reviewerGenesis: reviewers.genesis,
    }),
    currentStatus,
    reviewers.genesis,
  );
  const compatibility = compatibilityFixture();
  const staging = stagingFixture(compatibility);
  const target = targetFixture(compatibility, staging);
  const bootstrap = bootstrapAuthority({
    deploymentIntentSha256: canonicalArtifactSha256(deploymentIntent),
    productionTargetAuthoritySha256: phalaProductionTargetAuthorityDigest(
      target,
      {
        compatibilityReceipt: compatibility,
        sdkWireTransformStagingReceipt: staging,
      },
    ),
    sdkWireTransformStagingReceiptSha256:
      phalaSdkWireTransformStagingReceiptDigest(staging, {
        compatibilityReceipt: compatibility,
      }),
  });
  const fixture = await signedAuthorization({ bootstrap, reviewers });
  const directory = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-phala-bootstrap-auth-")),
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const bootstrapPath = path.join(directory, "bootstrap.json");
  const authorizationPath = path.join(directory, "authorization.json");
  const deploymentIntentPath = path.join(directory, "deployment-intent.json");
  const reviewerAuthorityGenesisPath = path.join(directory, "reviewer-genesis.json");
  const reviewerAuthorityGenesisAcceptancePath = path.join(
    directory,
    "reviewer-genesis-acceptance.json",
  );
  const compatibilityReceiptPath = path.join(directory, "compatibility.json");
  const sdkWireTransformStagingReceiptPath = path.join(directory, "staging.json");
  const productionTargetAuthorityPath = path.join(directory, "target.json");
  const targetAuthorityPaths = {
    compatibilityReceiptPath,
    sdkWireTransformStagingReceiptPath,
    productionTargetAuthorityPath,
  };
  fs.writeFileSync(
    bootstrapPath,
    canonicalBootstrapPublicEnvironmentAuthorityText(fixture.bootstrap),
    { mode: 0o400 },
  );
  fs.writeFileSync(
    compatibilityReceiptPath,
    canonicalPhalaCompatibilityReceiptText(compatibility),
    { mode: 0o400 },
  );
  fs.writeFileSync(
    sdkWireTransformStagingReceiptPath,
    canonicalPhalaSdkWireTransformStagingReceiptText(staging, {
      compatibilityReceipt: compatibility,
    }),
    { mode: 0o400 },
  );
  fs.writeFileSync(
    productionTargetAuthorityPath,
    canonicalPhalaProductionTargetAuthorityText(target, {
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    }),
    { mode: 0o400 },
  );
  fs.writeFileSync(
    authorizationPath,
    canonicalPhalaNonLiveBootstrapAuthorizationText(fixture.authorization, {
      bootstrapAuthority: fixture.bootstrap,
    }),
    { mode: 0o400 },
  );
  fs.writeFileSync(deploymentIntentPath, canonicalArtifactText(deploymentIntent), {
    mode: 0o400,
  });
  fs.writeFileSync(
    reviewerAuthorityGenesisPath,
    canonicalReleaseReviewerAuthorityGenesisArtifactText(reviewers.genesis),
    { mode: 0o400 },
  );
  fs.writeFileSync(
    reviewerAuthorityGenesisAcceptancePath,
    canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
      genesisAcceptance,
      { reviewerGenesis: reviewers.genesis },
    ),
    { mode: 0o400 },
  );
  const verified = readAndVerifyPhalaNonLiveBootstrapAuthorization({
    authorizationPath,
    bootstrapAuthorityPath: bootstrapPath,
    deploymentIntentPath,
    reviewerAuthorityGenesisPath,
    reviewerAuthorityGenesisAcceptancePath,
    nowMs: Date.parse("2026-07-21T10:05:00Z"),
  });
  const { receipt } = verified;
  assert.match(receipt.authorization_artifact_file_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.match(receipt.bootstrap_authority_artifact_file_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(
    verified.reviewer_authority_evidence.reviewer_authority_genesis_sha256,
    releaseReviewerAuthorityGenesisSha256(reviewers.genesis),
  );
  assert.equal(
    verified.reviewer_authority_evidence.reviewer_genesis_independently_anchored,
    false,
  );
  assert.equal(
    verified.reviewer_authority_evidence
      .reviewer_genesis_acceptance_cryptographically_verified,
    true,
  );

  for (const checkpoint of [
    "before_prediction",
    "before_each_prepare",
    "before_each_provision",
    "before_each_commit",
  ]) {
    const checked = readReverifyAndCheckpointPhalaNonLiveBootstrapAuthorization({
      ...targetAuthorityPaths,
      authorizationPath,
      bootstrapAuthorityPath: bootstrapPath,
      deploymentIntentPath,
      reviewerAuthorityGenesisPath,
      reviewerAuthorityGenesisAcceptancePath,
      checkpoint,
      nowMs: Date.parse("2026-07-21T10:05:00Z"),
      expectedBatchId: BATCH_ID,
      expectedAuthorizationId: fixture.authorization.authorization_id,
      expectedTargetAuthoritySha256:
        fixture.bootstrap.production_target_authority_sha256,
      expectedStagingReceiptSha256:
        fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
    });
    assert.equal(checked.recheck.checkpoint, checkpoint);
    assert.equal(checked.recheck.stable_file_reread, true);
    assert.equal(checked.recheck.target_authority_validated, true);
    assert.equal(
      checked.target_authority_evidence.productionTargetAuthoritySha256,
      fixture.bootstrap.production_target_authority_sha256,
    );
    assert.equal(
      checked.target_authority_evidence.sdkWireTransformStagingReceiptSha256,
      fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
    );
    assert.equal(
      bootstrapPublicEnvironmentAuthorityDigest(
        checked.bootstrap_public_environment_authority,
      ),
      checked.receipt.bootstrap_public_environment_authority_sha256,
    );
    assert.deepEqual(
      checked.bootstrap_public_environment_authority,
      fixture.bootstrap,
    );
    assert.equal(
      Object.isFrozen(checked.bootstrap_public_environment_authority),
      true,
    );
    assert.notEqual(
      checked.bootstrap_public_environment_authority,
      checked.bootstrap_authority_evidence,
    );
    assert.equal(assertVerifiedPhalaNonLiveBootstrapImmediateRecheck({
      recheck: checked.recheck,
      checkpoint,
      expectedBatchId: BATCH_ID,
      expectedAuthorizationId: fixture.authorization.authorization_id,
      requireStableFileReread: true,
      requireTargetAuthorityValidation: true,
    }), checked.recheck);
    assert.throws(() => assertVerifiedPhalaNonLiveBootstrapImmediateRecheck({
      recheck: checked.recheck,
      checkpoint,
      expectedBatchId: BATCH_ID,
      expectedAuthorizationId: fixture.authorization.authorization_id,
      requireStableFileReread: true,
      requireDescriptorSetValidation: true,
    }), /descriptor set/);
    assert.throws(() => assertVerifiedPhalaNonLiveBootstrapImmediateRecheck({
      recheck: checked.recheck,
      checkpoint,
      expectedBatchId: BATCH_ID,
      expectedAuthorizationId: fixture.authorization.authorization_id,
      requireStableFileReread: true,
      requireTargetAuthorityValidation: true,
      requireReleaseManifestSigstoreValidation: true,
    }), /Sigstore receipt/);
  }
  const driftedTarget = { ...structuredClone(target), cvm_launch_intent_sha256: sha("d") };
  const driftedTargetPath = path.join(directory, "target-drifted.json");
  fs.writeFileSync(
    driftedTargetPath,
    canonicalPhalaProductionTargetAuthorityText(driftedTarget, {
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    }),
    { mode: 0o400 },
  );
  assert.throws(
    () => readReverifyAndCheckpointPhalaNonLiveBootstrapAuthorization({
      ...targetAuthorityPaths,
      productionTargetAuthorityPath: driftedTargetPath,
      authorizationPath,
      bootstrapAuthorityPath: bootstrapPath,
      deploymentIntentPath,
      reviewerAuthorityGenesisPath,
      reviewerAuthorityGenesisAcceptancePath,
      checkpoint: "before_each_provision",
      nowMs: Date.parse("2026-07-21T10:05:00Z"),
      expectedBatchId: BATCH_ID,
      expectedAuthorizationId: fixture.authorization.authorization_id,
      expectedTargetAuthoritySha256:
        fixture.bootstrap.production_target_authority_sha256,
      expectedStagingReceiptSha256:
        fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
    }),
    /does not equal the signed bootstrap subject/,
  );
  const mutationCheckpoint = readReverifyAndCheckpointPhalaNonLiveBootstrapAuthorization({
    ...targetAuthorityPaths,
    authorizationPath,
    bootstrapAuthorityPath: bootstrapPath,
    deploymentIntentPath,
    reviewerAuthorityGenesisPath,
    reviewerAuthorityGenesisAcceptancePath,
    checkpoint: "before_each_provision",
    nowMs: Date.parse("2026-07-21T10:05:00Z"),
    expectedBatchId: BATCH_ID,
    expectedAuthorizationId: fixture.authorization.authorization_id,
    expectedTargetAuthoritySha256:
      fixture.bootstrap.production_target_authority_sha256,
    expectedStagingReceiptSha256:
      fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
  });
  assert.throws(() => createFinalizedPhalaMutationGate({
    authorizationRecheck: mutationCheckpoint.recheck,
    action: "provisionCvm",
    domain: CVM_LAUNCH_DOMAINS[0],
    readinessSha256: sha("d"),
    snapshotBlockNumber: 123,
    snapshotBlockHash: `0x${bare("e")}`,
    checkedAt: "2026-07-21T10:05:00Z",
    expiresAt: "2026-07-21T10:10:00Z",
    nowMs: Date.parse("2026-07-21T10:05:00Z"),
    minimumRemainingMs: 30_000,
  }), /branded|anchor/);
  assert.throws(
    () => readReverifyAndCheckpointPhalaNonLiveBootstrapAuthorization({
      ...targetAuthorityPaths,
      authorizationPath,
      bootstrapAuthorityPath: bootstrapPath,
      deploymentIntentPath,
      reviewerAuthorityGenesisPath,
      reviewerAuthorityGenesisAcceptancePath,
      checkpoint: "before_prediction",
      nowMs: Date.parse("2026-07-21T10:11:00Z"),
      expectedBatchId: BATCH_ID,
      expectedAuthorizationId: fixture.authorization.authorization_id,
      expectedTargetAuthoritySha256:
        fixture.bootstrap.production_target_authority_sha256,
      expectedStagingReceiptSha256:
        fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
    }),
    /not fresh|expired/,
  );

  const linkPath = path.join(directory, "authorization-link.json");
  fs.symlinkSync(authorizationPath, linkPath);
  assert.throws(
    () => readAndVerifyPhalaNonLiveBootstrapAuthorization({
      authorizationPath: linkPath,
      bootstrapAuthorityPath: bootstrapPath,
      deploymentIntentPath,
      reviewerAuthorityGenesisPath,
      reviewerAuthorityGenesisAcceptancePath,
      nowMs: Date.parse("2026-07-21T10:05:00Z"),
    }),
    /canonical, and symlink-free/,
  );
  fs.chmodSync(authorizationPath, 0o600);
  fs.writeFileSync(authorizationPath, JSON.stringify(fixture.authorization));
  fs.chmodSync(authorizationPath, 0o400);
  assert.throws(
    () => readAndVerifyPhalaNonLiveBootstrapAuthorization({
      authorizationPath,
      bootstrapAuthorityPath: bootstrapPath,
      deploymentIntentPath,
      reviewerAuthorityGenesisPath,
      reviewerAuthorityGenesisAcceptancePath,
      nowMs: Date.parse("2026-07-21T10:05:00Z"),
    }),
    /canonical sorted JSON bytes/,
  );
  assert.throws(
    () => readReverifyAndCheckpointPhalaNonLiveBootstrapAuthorization({
      ...targetAuthorityPaths,
      authorizationPath,
      bootstrapAuthorityPath: bootstrapPath,
      deploymentIntentPath,
      reviewerAuthorityGenesisPath,
      reviewerAuthorityGenesisAcceptancePath,
      checkpoint: "before_each_commit",
      nowMs: Date.parse("2026-07-21T10:05:00Z"),
      expectedBatchId: BATCH_ID,
      expectedAuthorizationId: fixture.authorization.authorization_id,
      expectedTargetAuthoritySha256:
        fixture.bootstrap.production_target_authority_sha256,
      expectedStagingReceiptSha256:
        fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
    }),
    /canonical sorted JSON bytes/,
  );
});

test("authorized private assembly requires a fresh branded A receipt at the exact checkpoint", async () => {
  const fixture = await signedAuthorization();
  const receipt = verifyPhalaNonLiveBootstrapAuthorization({
    authorization: fixture.authorization,
    bootstrapAuthority: fixture.bootstrap,
    reviewerAuthority: fixture.reviewers.authority,
    nowMs: Date.parse("2026-07-21T10:05:00Z"),
  });
  const provisioning = projectProvisioningEnvironmentAuthority({
    batchId: BATCH_ID,
    targetAuthoritySha256: fixture.bootstrap.production_target_authority_sha256,
    cvmLaunchIntentSha256: fixture.bootstrap.cvm_launch_intent_sha256,
    bootstrapAuthoritySha256:
      bootstrapPublicEnvironmentAuthorityDigest(fixture.bootstrap),
    preparedAt: "2026-07-21T10:04:00Z",
    prepareObservations: prepareObservations(),
  });
  const secretKeys = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm
    .encrypted_secret_environment_keys_by_phase.bootstrap_provision;
  const secretInput = {
    schema: PHALA_PHASE_SECRET_INPUT_SCHEMA,
    domain: "main_runtime_cvm",
    phase: "bootstrap_provision",
    batch_id: BATCH_ID,
    cvm_launch_intent_sha256: fixture.bootstrap.cvm_launch_intent_sha256,
    values: Object.fromEntries(secretKeys.map((key) => [
      key,
      key === "TINKER_WALLET_AUTH_RPC_URL"
        ? "https://wallet-primary.example/rpc"
        : key === "TINKER_WALLET_AUTH_RPC_URL_SECONDARY"
          ? "https://wallet-secondary.example/rpc"
          : `private-${key}`,
    ])),
  };
  const assembly = assembleAuthorizedPrivateBootstrapEnvironment({
    authorizationReceipt: receipt,
    checkpoint: "before_each_commit",
    nowMs: Date.parse("2026-07-21T10:06:00Z"),
    expectedAuthorizationId: receipt.authorization_id,
    expectedTargetAuthoritySha256: fixture.bootstrap.production_target_authority_sha256,
    expectedStagingReceiptSha256:
      fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
    environmentAssembly: {
      domain: "main_runtime_cvm",
      now: "2026-07-21T10:06:00Z",
      bootstrapAuthority: fixture.bootstrap,
      provisioningAuthority: provisioning,
      secretInput,
    },
  });
  assert.equal(
    privateEnvironmentEntries(assembly).EMAIL_ORACLE_CONSUMER_APP_ID,
    app("1"),
  );
  assert.throws(
    () => assembleAuthorizedPrivateBootstrapEnvironment({
      authorizationReceipt: receipt,
      checkpoint: "before_each_commit",
      nowMs: Date.parse("2026-07-21T10:11:00Z"),
      expectedAuthorizationId: receipt.authorization_id,
      expectedTargetAuthoritySha256: fixture.bootstrap.production_target_authority_sha256,
      expectedStagingReceiptSha256:
        fixture.bootstrap.sdk_wire_transform_staging_receipt_sha256,
      environmentAssembly: {
        domain: "main_runtime_cvm",
        now: "2026-07-21T10:06:00Z",
        bootstrapAuthority: fixture.bootstrap,
        provisioningAuthority: provisioning,
        secretInput,
      },
    }),
    /fresh exact non-live bootstrap authorization/,
  );
});
