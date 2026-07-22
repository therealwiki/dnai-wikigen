import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  canonicalCvmLaunchIntentCoreArtifactText,
  canonicalFreshContractDeploymentReceiptText,
  createPhalaDstackComposeHashInput,
  createDraftCvmLaunchIntentCore,
  CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
  CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_LAUNCH_INTENT_DOMAIN,
  CVM_LAUNCH_INTENT_RECEIPT_SCHEMA,
  CVM_LAUNCH_INTENT_CORE_SCHEMA,
  CVM_LAUNCH_OS_IMAGE_CATALOG_ENTRY_DOMAIN,
  CVM_LAUNCH_SECRET_PHASES,
  CVM_PUBLIC_ENVIRONMENT_VALUE_AUTHORITY_TRUTH_STATUS,
  CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
  FRESH_CONTRACT_BROADCAST_PROOF,
  FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
  FRESH_CONTRACT_CREATION_INPUT_PROOF,
  FRESH_CONTRACT_DEPLOYMENT_RECEIPT_DOMAIN,
  FRESH_CONTRACT_DEPLOYMENT_RECEIPT_SCHEMA,
  FRESH_DEPLOYMENT_TRANSACTION_SPEC,
  freshContractDeploymentReceiptDigest,
  cvmLaunchEnvironmentKeysDigest,
  cvmLaunchIntentCoreDigest,
  cvmLaunchIntentValidationReceipt,
  normalizeCvmLaunchIntentCore,
  normalizeFreshContractDeploymentReceipt,
  parseCvmLaunchIntentCoreText,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
  PHALA_CONTROL_PLANE_AUTHORITY,
  PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY,
  PHALA_DSTACK_APP_COMPOSE_HASH_INPUT_KEYS,
  PHALA_DSTACK_COMPOSE_HASH_AUTHORITY,
  PHALA_CVM_RESOURCE_TARGETS,
  PHALA_PROVISION_REQUEST_AUTHORITY,
  PHALA_SDK_DEBUG_SECRET_LOGGING_POLICY,
  PHALA_WORKSPACE_ACCOUNT_TARGET_AUTHORITY,
  phalaDstackComposeHash,
  phalaProductionExecutionPolicyDigest,
  phalaOsImageCatalogEntryDigest,
  projectFreshContractDeploymentReceipt,
  rawSha256,
} from "./cvm-launch-intent-core.mjs";
import {
  CVM_MAIN_EXACT_ENVIRONMENT_REFERENCE_ALIAS_CONTRACT,
  buildCvmLaunchIntentFromFiles,
  runCvmLaunchIntentCli,
} from "./cvm-launch-intent.mjs";
import {
  PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_EXECUTION_POLICY,
} from "./phala-production-execution-policy.mjs";
import {
  canonicalArtifactText,
  createDraftDeploymentIntentCore,
  parseFreshContractDeploymentReceiptText,
} from "./operator-policy-packet-core.mjs";

const RELEASE_SHA = "a".repeat(40);
const ROOT = path.resolve(import.meta.dirname, "..");
const TEMPLATE_PATH = path.join(
  ROOT,
  "deployments",
  "cvm-launch-intent-core.template.json",
);
const SCHEMA_PATH = path.join(
  ROOT,
  "deployments",
  "cvm-launch-intent-core.schema.json",
);
const DIGESTS = Object.freeze({
  deployment: `sha256:${"1".repeat(64)}`,
  contractReceipt: `sha256:${"2".repeat(64)}`,
  topology: `sha256:${"3".repeat(64)}`,
  manifest: `sha256:${"4".repeat(64)}`,
  bundle: `sha256:${"5".repeat(64)}`,
});

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((item) => sortedObject(item));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalJson(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

function bytes32(index) {
  return `0x${index.toString(16).padStart(64, "0")}`;
}

function freshBroadcastEvidence(contracts, operatorAddress) {
  const transactions = FRESH_DEPLOYMENT_TRANSACTION_SPEC.map((spec, sequence) => {
    const contract = contracts[spec.contract_key];
    const create = spec.transaction_type === "CREATE";
    const inputSha256 = `sha256:${(500 + sequence).toString(16).padStart(64, "0")}`;
    if (create) contract.creationInputSha256 = inputSha256;
    return {
      sequence,
      contractKey: spec.contract_key,
      contractName: spec.name,
      transactionType: spec.transaction_type,
      functionSignature: spec.function_signature,
      transactionHash: create ? contract.deploymentTx : bytes32(200 + sequence),
      transactionFrom: operatorAddress,
      transactionTo: create ? null : contract.address,
      transactionNonce: 700 + sequence,
      transactionInputSha256: inputSha256,
      receiptStatus: "success",
      receiptContractAddress: create ? contract.address : null,
      blockNumber: create ? contract.deploymentBlock : 12_346_000 + sequence,
      blockHash: create ? contract.deploymentBlockHash : bytes32(300 + sequence),
    };
  });
  const normalized = transactions.map((entry) => ({
    sequence: entry.sequence,
    contract_key: entry.contractKey,
    contract_name: entry.contractName,
    transaction_type: entry.transactionType,
    function_signature: entry.functionSignature,
    transaction_hash: entry.transactionHash,
    transaction_from: entry.transactionFrom,
    transaction_to: entry.transactionTo,
    transaction_nonce: entry.transactionNonce,
    transaction_input_sha256: entry.transactionInputSha256,
    receipt_status: entry.receiptStatus,
    receipt_contract_address: entry.receiptContractAddress,
    block_number: entry.blockNumber,
    block_hash: entry.blockHash,
  }));
  return {
    transactions,
    sha256: rawSha256(Buffer.from(JSON.stringify(sortedObject(normalized)), "utf8")),
  };
}

function refreshLedgerBroadcastDigest(ledger) {
  const transactions = ledger.freshDeployment.contractSuite.broadcastTransactions;
  const normalized = transactions.map((entry) => ({
    sequence: entry.sequence,
    contract_key: entry.contractKey,
    contract_name: entry.contractName,
    transaction_type: entry.transactionType,
    function_signature: entry.functionSignature,
    transaction_hash: entry.transactionHash,
    transaction_from: entry.transactionFrom,
    transaction_to: entry.transactionTo,
    transaction_nonce: entry.transactionNonce,
    transaction_input_sha256: entry.transactionInputSha256,
    receipt_status: entry.receiptStatus,
    receipt_contract_address: entry.receiptContractAddress,
    block_number: entry.blockNumber,
    block_hash: entry.blockHash,
  }));
  const digest = rawSha256(Buffer.from(JSON.stringify(sortedObject(normalized)), "utf8"));
  ledger.freshDeployment.contractSuite.broadcastTransactionsSha256 = digest;
  ledger.deploymentHistory[0].broadcastTransactionsSha256 = digest;
  return digest;
}

function validIntent() {
  const value = createDraftDeploymentIntentCore();
  value.release.releaseSha = RELEASE_SHA;
  value.release.reviewerAuthorityGenesisAcceptanceSha256 =
    `sha256:${"91".repeat(32)}`;
  value.release.reviewerAuthorityCurrentStatusEpoch = 1;
  value.release.reviewerAuthorityCurrentStatusSha256 =
    `sha256:${"92".repeat(32)}`;
  value.deploymentControl.controllerId = "launch-operator-01";
  value.deploymentControl.operatorAddress = address(1);
  value.staticContractInputs.computeCreditVault.developer = address(2);
  value.staticContractInputs.tinkerAccountEncumbrance.accountCommitment = bytes32(3);
  value.numericPolicy.contract = {
    computeDeveloperFeeBps: 100,
    emailOracleUpgradeDelaySeconds: 172_800,
    tinkerMaxAddBalanceWei: "5000000000000000000",
    tinkerMaxSpendWei: "2000000000000000000",
  };
  value.numericPolicy.metering = {
    maxConcurrency: 4,
    rateCapacity: 30,
    rateRefillPerSecond: "0.5",
    requestBodyTimeoutSeconds: "5",
    rpcTimeoutSeconds: "8",
  };
  const qvl = {
    challengeCapacity: 1_024,
    challengeTtlSeconds: 60,
    maxConcurrency: 4,
    rateCapacity: 30,
    rateRefillPerSecond: "0.5",
    requestBodyTimeoutSeconds: "5",
    verificationTimeoutSeconds: "20",
  };
  for (const name of Object.keys(value.numericPolicy.qvl)) value.numericPolicy.qvl[name] = { ...qvl };
  return value;
}

function validLaunchIntent() {
  const value = createDraftCvmLaunchIntentCore();
  value.release_sha = RELEASE_SHA;
  value.deployment_intent_sha256 = DIGESTS.deployment;
  value.contract_deployment_receipt_sha256 = DIGESTS.contractReceipt;
  value.topology_sha256 = DIGESTS.topology;
  value.image_release_manifest_sha256 = DIGESTS.manifest;
  value.image_attestation_bundle_sha256 = DIGESTS.bundle;
  value.descriptors.forEach((descriptor, index) => {
    descriptor.descriptor_sha256 = `sha256:${(index + 8).toString(16).repeat(64)}`;
    descriptor.app_compose_candidate.docker_compose_file_sha256 =
      descriptor.descriptor_sha256;
    descriptor.app_compose_candidate.docker_compose_file_byte_length = 1_000 + index;
    descriptor.app_compose_candidate.expected_compose_hash =
      (index + 1).toString(16).repeat(64);
  });
  return value;
}

test("tracked launch template and schema match the canonical v3 seven-CVM boundary", async () => {
  const template = await readFile(TEMPLATE_PATH, "utf8");
  assert.equal(template, canonicalJson(createDraftCvmLaunchIntentCore()));
  assert.throws(() => parseCvmLaunchIntentCoreText(template));
  const schema = JSON.parse(await readFile(SCHEMA_PATH, "utf8"));
  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(schema.properties.schema.const, CVM_LAUNCH_INTENT_CORE_SCHEMA);
  assert.ok(schema.properties.contract_deployment_receipt_sha256);
  assert.deepEqual(
    schema.properties.sealed_production_execution_policy.const,
    PHALA_PRODUCTION_EXECUTION_POLICY,
  );
  assert.deepEqual(
    schema.properties.phala_control_plane_authority.const,
    PHALA_CONTROL_PLANE_AUTHORITY,
  );
  assert.deepEqual(
    schema.properties.phala_workspace_account_target_authority.const,
    PHALA_WORKSPACE_ACCOUNT_TARGET_AUTHORITY,
  );
  assert.deepEqual(
    schema.properties.phala_sdk_debug_secret_logging_policy.const,
    PHALA_SDK_DEBUG_SECRET_LOGGING_POLICY,
  );
  assert.deepEqual(
    schema.properties.phala_cloud_sdk_wire_transform_authority.const,
    PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY,
  );
  assert.deepEqual(
    schema.properties.phala_provision_request_authority.const,
    PHALA_PROVISION_REQUEST_AUTHORITY,
  );
  assert.deepEqual(
    schema.properties.compose_hash_authority.const,
    PHALA_DSTACK_COMPOSE_HASH_AUTHORITY,
  );
  assert.equal(schema.properties.contract_ledger_sha256, undefined);
  assert.equal(schema.properties.descriptors.minItems, 7);
  assert.equal(schema.properties.descriptors.maxItems, 7);
  assert.equal(schema.properties.descriptors.prefixItems.length, 7);
  for (const [index, domain] of CVM_LAUNCH_DOMAINS.entries()) {
    const descriptor = schema.properties.descriptors.prefixItems[index].properties;
    const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
    assert.equal(descriptor.trust_domain.const, domain);
    assert.equal(descriptor.descriptor_file.const, policy.descriptor_file);
    assert.deepEqual(descriptor.launch_settings.const, policy.launch_settings);
    assert.deepEqual(
      descriptor.public_environment_key_classification.const,
      policy.public_environment_key_classification,
    );
    assert.deepEqual(
      descriptor.public_environment_value_authority.const,
      policy.public_environment_value_authority,
    );
    assert.equal(descriptor.app_compose_candidate.properties.listed, undefined);
    assert.equal(
      descriptor.app_compose_candidate.properties.tproxy_enabled.const,
      false,
    );
    assert.equal(
      descriptor.app_compose_candidate.properties.provision_wire_transform_source.const,
      "PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY",
    );
    assert.deepEqual(
      descriptor.encrypted_secret_environment_keys_by_phase.const,
      policy.encrypted_secret_environment_keys_by_phase,
    );
    assert.deepEqual(
      descriptor.exact_allowed_environment_keys.const,
      policy.exact_allowed_environment_keys,
    );
    assert.equal(
      descriptor.exact_allowed_environment_keys_sha256.const,
      policy.exact_allowed_environment_keys_sha256,
    );
  }
  assert.equal(schema.additionalProperties, false);
});

test("launch core has a stable explicit-NUL compact canonical digest", () => {
  const value = validLaunchIntent();
  const normalized = normalizeCvmLaunchIntentCore(value);
  const expected = createHash("sha256")
    .update(Buffer.from("dnai-wikigen/cvm-launch-intent-core/v3\0", "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(normalized)), "utf8"))
    .digest("hex");
  assert.equal(CVM_LAUNCH_INTENT_DOMAIN.endsWith("\0"), true);
  assert.equal(cvmLaunchIntentCoreDigest(value), expected);
  assert.equal(
    expected,
    "2df005cd2c7b00521f010db689953635c0a9d506d0c184e913ba86b2bb05e903",
  );
  assert.notEqual(
    expected,
    createHash("sha256")
      .update(Buffer.from(CVM_LAUNCH_INTENT_DOMAIN, "utf8"))
      .update(Buffer.from(canonicalCvmLaunchIntentCoreArtifactText(value), "utf8"))
      .digest("hex"),
  );
  assert.equal(
    parseCvmLaunchIntentCoreText(canonicalCvmLaunchIntentCoreArtifactText(value)).schema,
    CVM_LAUNCH_INTENT_CORE_SCHEMA,
  );
});

test("launch core freezes seven descriptor policies and contains names but no values", () => {
  const value = normalizeCvmLaunchIntentCore(validLaunchIntent());
  assert.deepEqual(
    value.sealed_production_execution_policy,
    PHALA_PRODUCTION_EXECUTION_POLICY,
  );
  assert.equal(value.sealed_production_execution_policy.availability, true);
  assert.equal(value.sealed_production_execution_policy.reason_code, null);
  assert.deepEqual(
    value.sealed_production_execution_policy.blocker_codes,
    PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
  );
  assert.deepEqual(value.phala_control_plane_authority, PHALA_CONTROL_PLANE_AUTHORITY);
  assert.deepEqual(
    value.phala_workspace_account_target_authority,
    PHALA_WORKSPACE_ACCOUNT_TARGET_AUTHORITY,
  );
  assert.deepEqual(
    value.phala_sdk_debug_secret_logging_policy,
    PHALA_SDK_DEBUG_SECRET_LOGGING_POLICY,
  );
  assert.equal(
    value.phala_sdk_debug_secret_logging_policy.required_debug_environment_state,
    "absent_or_empty",
  );
  assert.deepEqual(
    value.phala_cloud_sdk_wire_transform_authority,
    PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY,
  );
  assert.equal(
    value.phala_cloud_sdk_wire_transform_authority.package.npm_dist_integrity_sha512,
    "sha512-eQXJxbBlJ8xA4e+MmB3AZd9jgdbO3tFh+qu7KL6CS5Ta64LNKlrV3vdke3oUvB22xbc/qqKQ6dIkJx5pTdY7gA==",
  );
  assert.equal(
    value.phala_cloud_sdk_wire_transform_authority
      .provision_transform.additional_transform_allowed,
    false,
  );
  assert.deepEqual(
    value.phala_provision_request_authority,
    PHALA_PROVISION_REQUEST_AUTHORITY,
  );
  assert.equal(value.phala_provision_request_authority.listed, false);
  assert.equal(value.phala_provision_request_authority.key_provider_mode, "kms");
  assert.equal(value.phala_provision_request_authority.kms_id, null);
  assert.deepEqual(value.phala_provision_request_authority.unresolved_fields, [
    "kms_id",
    "nonce",
    "app_id",
    "exact_request_sha256",
  ]);
  assert.equal(
    Object.keys(value.phala_provision_request_authority.candidates).length,
    7,
  );
  assert.deepEqual(value.descriptors.map(({ trust_domain }) => trust_domain), CVM_LAUNCH_DOMAINS);
  for (const descriptor of value.descriptors) {
    const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[descriptor.trust_domain];
    assert.equal(descriptor.descriptor_file, policy.descriptor_file);
    assert.equal(descriptor.descriptor_hash_semantics, "raw_descriptor_bytes_sha256_not_phala_compose_hash");
    assert.equal(descriptor.launch_settings.platform, "phala_cloud");
    assert.equal(descriptor.launch_settings.phala_cli_version, "v1.1.19+d2300dd");
    assert.equal(descriptor.launch_settings.phala_cloud_sdk_version, "0.2.10");
    assert.deepEqual(
      descriptor.launch_settings.cvm_resource_target,
      PHALA_CVM_RESOURCE_TARGETS[descriptor.trust_domain],
    );
    assert.equal(descriptor.launch_settings.phala_os_image, "dstack-0.5.10");
    assert.equal(
      descriptor.launch_settings.phala_os_image_hash,
      "4c9bd0249cf8a1f79f7b558867b0791d628d7a89dcba84a963338fc5539255fc",
    );
    assert.deepEqual(
      descriptor.launch_settings.phala_os_image_catalog_entry,
      PHALA_OS_IMAGE_CATALOG_ENTRY,
    );
    assert.equal(
      descriptor.launch_settings.phala_os_image_catalog_entry_sha256,
      phalaOsImageCatalogEntryDigest(PHALA_OS_IMAGE_CATALOG_ENTRY),
    );
    assert.equal(descriptor.launch_settings.fresh_cli_deploy_forbidden, true);
    assert.equal(
      descriptor.launch_settings.provisioning_api,
      "provisionCvm_validate_all_seven_then_commitCvmProvision",
    );
    assert.deepEqual(descriptor.launch_settings.deployment_flags, {
      no_dev_os: true,
      no_listed: true,
      no_public_logs: true,
      no_public_sysinfo: true,
    });
    assert.equal(descriptor.launch_settings.post_create_assertions.public_tcbinfo, false);
    assert.equal(descriptor.app_compose_candidate.tproxy_enabled, false);
    assert.equal(Object.hasOwn(descriptor.app_compose_candidate, "listed"), false);
    assert.equal(
      descriptor.app_compose_candidate.provision_wire_transform_source,
      "PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY",
    );
    assert.equal(descriptor.exact_allowed_environment_keys.includes("PHALA_CLOUD_API_KEY"), false);
    assert.equal(
      descriptor.public_environment_value_authority.truth_status,
      CVM_PUBLIC_ENVIRONMENT_VALUE_AUTHORITY_TRUTH_STATUS,
    );
    assert.equal(
      descriptor.public_environment_value_authority.projector_schema,
      CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    );
    assert.equal(descriptor.public_environment_value_authority.values_present, false);
    assert.equal(descriptor.public_environment_value_authority.values_validated, false);
    assert.equal(
      descriptor.public_environment_value_authority.phase_control.key_count,
      1,
    );
    assert.equal(
      descriptor.public_environment_value_authority.phase_control.key_names_sha256,
      cvmLaunchEnvironmentKeysDigest(["COMPOSE_PROFILES"]),
    );
    assert.equal(
      descriptor.public_environment_value_authority.phase_control.authority_status,
      "policy_derived_exact_value_not_operator_free_form",
    );
  }
  const qvl = value.descriptors[1];
  assert.deepEqual(
    qvl.public_environment_key_classification.post_measurement_deferred_keys,
    [],
  );
  assert.deepEqual(
    qvl.public_environment_key_classification.post_measurement_phase_control_keys,
    ["COMPOSE_PROFILES"],
  );
  assert.deepEqual(qvl.encrypted_secret_environment_keys_by_phase, {
    bootstrap_provision: [],
    post_measurement_policy_bootstrap: ["QVL_AUTH_TOKEN", "QVL_RELEASE_POLICY_B64"],
    final_authority_runtime: [],
    anchor_writer_ceremony: [],
  });
  assert.deepEqual(qvl.exact_allowed_environment_keys, [
    "COMPOSE_PROFILES",
    "QVL_AUTH_TOKEN",
    "QVL_RELEASE_POLICY_B64",
  ]);
  const main = value.descriptors[0];
  const mainClassification = main.public_environment_key_classification;
  const mainValueAuthority = main.public_environment_value_authority;
  assert.deepEqual(Object.keys(main.encrypted_secret_environment_keys_by_phase), [
    ...CVM_LAUNCH_SECRET_PHASES,
  ]);
  assert.deepEqual(
    main.encrypted_secret_environment_keys_by_phase.bootstrap_provision,
    [
      "BASE_SEPOLIA_RPC_URL",
      "BASE_SEPOLIA_RPC_URL_SECONDARY",
      "NEKO_PASSWORD",
      "NEKO_PASSWORD_ADMIN",
      "TINKER_WALLET_AUTH_RPC_URL",
      "TINKER_WALLET_AUTH_RPC_URL_SECONDARY",
    ],
  );
  assert.equal(
    main.encrypted_secret_environment_keys_by_phase.final_authority_runtime.includes(
      "TINKER_WALLET_AUTH_RPC_URL",
    ),
    false,
  );
  assert.equal(
    main.encrypted_secret_environment_keys_by_phase.final_authority_runtime.includes(
      "TINKER_WALLET_AUTH_RPC_URL_SECONDARY",
    ),
    false,
  );
  assert.equal(
    Object.values(main.public_environment_key_classification)
      .flat()
      .includes("TINKER_WALLET_AUTH_RPC_URL"),
    false,
  );
  assert.equal(
    Object.values(main.public_environment_key_classification)
      .flat()
      .includes("TINKER_WALLET_AUTH_RPC_URL_SECONDARY"),
    false,
  );
  assert.equal(
    mainValueAuthority.descriptor_embedded_static.key_count,
    mainClassification.descriptor_defaulted_keys.length + 1,
  );
  assert.equal(
    mainValueAuthority.descriptor_embedded_static.key_names_sha256,
    cvmLaunchEnvironmentKeysDigest([
      ...mainClassification.descriptor_defaulted_keys,
      "TINKER_COMPUTE_WORKLOAD_CHAIN_ID",
    ].sort()),
  );
  for (const key of [
    "TINKER_WALLET_AUTH_MAX_SIGNATURE_BYTES",
    "TINKER_WALLET_AUTH_RPC_MAX_RESPONSE_BYTES",
    "TINKER_WALLET_AUTH_RPC_TIMEOUT_SECONDS",
    "TINKER_WALLET_AUTH_CHALLENGE_ADDRESS_LIMIT",
    "TINKER_WALLET_AUTH_CHALLENGE_CLIENT_IP_HEADER",
    "TINKER_WALLET_AUTH_CHALLENGE_GLOBAL_LIMIT",
    "TINKER_WALLET_AUTH_CHALLENGE_LIMIT_WINDOW_SECONDS",
    "TINKER_WALLET_AUTH_CHALLENGE_PEER_LIMIT",
    "TINKER_WALLET_AUTH_CHALLENGE_TRUSTED_PROXY_CIDRS",
  ]) {
    assert.equal(mainClassification.descriptor_defaulted_keys.includes(key), true);
    assert.equal(main.exact_allowed_environment_keys.includes(key), false);
  }
  assert.deepEqual(
    main.encrypted_secret_environment_keys_by_phase.anchor_writer_ceremony,
    ["TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN"],
  );
  assert.equal(
    main.encrypted_secret_environment_keys_by_phase.final_authority_runtime.includes(
      "TINKER_ARENA_WORKER_QVL_AUTH_TOKEN",
    ),
    true,
  );
  assert.equal(
    main.encrypted_secret_environment_keys_by_phase.final_authority_runtime.includes(
      "TINKER_ARENA_REGISTRY_RPC_URL",
    ),
    true,
  );
  assert.equal(
    mainClassification.descriptor_static_keys.includes(
      "TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256",
    ),
    true,
  );
  assert.equal(
    main.exact_allowed_environment_keys.includes(
      "TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256",
    ),
    true,
  );
  assert.equal(
    Object.values(mainClassification).flat().includes("TINKER_ARENA_REGISTRY_RPC_URL"),
    false,
  );
  assert.equal(
    Object.values(mainClassification).flat().includes(
      "TINKER_ARENA_WORKER_LIVE_CAPABILITY_ENABLED",
    ),
    false,
  );
  assert.equal(
    main.exact_allowed_environment_keys.includes(
      "TINKER_ARENA_WORKER_LIVE_CAPABILITY_ENABLED",
    ),
    false,
  );
  for (const key of [
    "TINKER_ARENA_REGISTRY_ADDRESS",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
    "TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH",
  ]) {
    assert.equal(mainClassification.post_measurement_deferred_keys.includes(key), true);
    assert.equal(main.exact_allowed_environment_keys.includes(key), true);
  }
  for (const key of [
    "TINKER_ARENA_REGISTRY_MAX_BLOCK_AGE_SECONDS",
    "TINKER_ARENA_REGISTRY_MAX_FUTURE_BLOCK_SKEW_SECONDS",
  ]) {
    assert.equal(mainClassification.descriptor_defaulted_keys.includes(key), true);
    assert.equal(main.exact_allowed_environment_keys.includes(key), false);
  }
  assert.equal(
    mainClassification.provisioning_result_keys.includes("EMAIL_ORACLE_CONSUMER_APP_ID"),
    true,
  );
  assert.equal(
    mainValueAuthority.bootstrap_static.key_count,
    mainClassification.descriptor_static_keys.length - 1,
  );
  assert.equal(
    mainValueAuthority.bootstrap_static.key_names_sha256,
    cvmLaunchEnvironmentKeysDigest(
      mainClassification.descriptor_static_keys.filter(
        (key) => key !== "TINKER_COMPUTE_WORKLOAD_CHAIN_ID",
      ),
    ),
  );
  assert.equal(
    mainValueAuthority.bootstrap_static.authority_status,
    "required_not_implemented",
  );
  assert.deepEqual(mainValueAuthority.bootstrap_static.source_authority_refs, [
    "contract_deployment_receipt_sha256",
    "deployment_intent_sha256",
    "image_release_manifest_sha256",
    "release_sha",
    "topology_sha256",
  ]);
  assert.equal(
    mainValueAuthority.provisioning_results.authority_status,
    "required_derive_and_exactly_validate_from_prepare_not_operator_input",
  );
  assert.equal(
    mainValueAuthority.provisioning_results.key_names_sha256,
    cvmLaunchEnvironmentKeysDigest(mainClassification.provisioning_result_keys),
  );
  assert.equal(
    mainValueAuthority.post_measurement_deferred.authority_status,
    "required_not_implemented",
  );
  assert.equal(
    mainValueAuthority.post_measurement_deferred.key_names_sha256,
    cvmLaunchEnvironmentKeysDigest(mainClassification.post_measurement_deferred_keys),
  );
  assert.equal(
    mainClassification.post_measurement_deferred_keys.includes("EMAIL_ORACLE_CONSUMER_APP_ID"),
    false,
  );
  const composeHashKeys = main.exact_allowed_environment_keys.filter(
    (key) => key.endsWith("_COMPOSE_HASH"),
  );
  assert.deepEqual(composeHashKeys, [
    "EMAIL_ORACLE_CONSUMER_COMPOSE_HASH",
    "TINKER_ARENA_WORKER_COMPOSE_HASH",
    "TINKER_COMPUTE_VAULT_COMPOSE_HASH",
    "TINKER_DILIGENCE_ALLOWED_COMPOSE_HASH",
  ]);
  for (const key of composeHashKeys) {
    assert.equal(mainClassification.provisioning_result_keys.includes(key), true);
    assert.equal(mainClassification.descriptor_static_keys.includes(key), false);
    assert.equal(mainClassification.post_measurement_deferred_keys.includes(key), false);
  }
  for (const key of [
    "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
    "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
    "TINKER_COMPUTE_METERING_POLICY_SET_HASH",
  ]) {
    assert.equal(mainClassification.descriptor_static_keys.includes(key), false);
    assert.equal(mainClassification.post_measurement_deferred_keys.includes(key), true);
  }
  for (const descriptor of value.descriptors) {
    assert.deepEqual(
      descriptor.public_environment_key_classification.post_measurement_phase_control_keys,
      ["COMPOSE_PROFILES"],
    );
    assert.equal(
      descriptor.public_environment_key_classification.post_measurement_deferred_keys
        .includes("COMPOSE_PROFILES"),
      false,
    );
    if (descriptor.trust_domain !== "main_runtime_cvm") {
      assert.deepEqual(descriptor.launch_settings.initial_services, []);
      assert.equal(descriptor.launch_settings.initially_disabled_profiles.length, 1);
    }
  }
  assert.equal(
    qvl.public_environment_value_authority.bootstrap_static.authority_status,
    "not_required_no_keys",
  );
  assert.equal(qvl.public_environment_value_authority.bootstrap_static.key_count, 0);
  assert.equal(
    qvl.public_environment_value_authority.descriptor_embedded_static.authority_status,
    "descriptor_bytes_bound_not_injectable",
  );
  assert.equal(
    qvl.public_environment_value_authority.descriptor_embedded_static.key_names_sha256,
    cvmLaunchEnvironmentKeysDigest(
      qvl.public_environment_key_classification.descriptor_static_keys,
    ),
  );
  const metering = value.descriptors.find(
    ({ trust_domain }) => trust_domain === "independent_metering_cvm",
  );
  assert.equal(
    metering.public_environment_value_authority.post_measurement_deferred.authority_status,
    "required_not_implemented",
  );
  assert.equal(
    metering.public_environment_value_authority.post_measurement_deferred.key_names_sha256,
    cvmLaunchEnvironmentKeysDigest(
      metering.public_environment_key_classification.post_measurement_deferred_keys,
    ),
  );
  assert.equal(JSON.stringify(value).includes('"environment_value":'), false);
  for (const forbiddenValue of ["3.0", "131072", "4096"]) {
    assert.equal(JSON.stringify(value).includes(JSON.stringify(forbiddenValue)), false);
  }
  assert.equal(JSON.stringify(value).includes(":?"), false);
});

test("main final activation owns one exact combined profile replacement value", () => {
  assert.deepEqual(CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES, [
    "arena-runtime",
    "compute-execution",
  ]);
  assert.equal(
    CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
    "arena-runtime,compute-execution",
  );
  assert.deepEqual(CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY, {
    profile_names: ["arena-runtime", "compute-execution"],
    compose_profiles_value: "arena-runtime,compute-execution",
  });
  assert.equal(Object.isFrozen(CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES), true);
  assert.equal(Object.isFrozen(CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY), true);

  const disabled = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm
    .launch_settings.initially_disabled_profiles;
  for (const profile of CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES) {
    assert.equal(disabled.includes(profile), true);
  }
  for (const forbidden of ["anchor-writer-ceremony", "deal-settlement"]) {
    assert.equal(CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES.includes(forbidden), false);
  }
});

test("main environment aliases are one deeply frozen exact path contract", () => {
  assert.deepEqual(CVM_MAIN_EXACT_ENVIRONMENT_REFERENCE_ALIAS_CONTRACT, [
    {
      source_environment_key: "TINKER_COMPUTE_WORKLOAD_CVM_ID",
      occurrences: [
        {
          service: "delegate",
          destination_environment_key: "TINKER_COMPUTE_WORKLOAD_CVM_ID",
          path: "$.services.delegate.environment.TINKER_COMPUTE_WORKLOAD_CVM_ID",
          interpolation_suffix: ":?Canonical main runtime CVM ID required",
        },
        {
          service: "arena-worker",
          destination_environment_key: "TINKER_MAIN_RUNTIME_CVM_ID",
          path: "$.services.arena-worker.environment.TINKER_MAIN_RUNTIME_CVM_ID",
          interpolation_suffix: ":?Canonical main runtime CVM ID required",
        },
      ],
    },
    {
      source_environment_key: "TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
      occurrences: [
        {
          service: "delegate",
          destination_environment_key:
            "TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
          path: "$.services.delegate.environment.TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
          interpolation_suffix: ":?Signed seven-CVM deployment intent required",
        },
        {
          service: "arena-worker",
          destination_environment_key: "TINKER_RELEASE_DEPLOYMENT_INTENT_SHA256",
          path: "$.services.arena-worker.environment.TINKER_RELEASE_DEPLOYMENT_INTENT_SHA256",
          interpolation_suffix: ":?Signed seven-CVM deployment intent required",
        },
      ],
    },
    {
      source_environment_key: "TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
      occurrences: [
        {
          service: "delegate",
          destination_environment_key: "TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
          path: "$.services.delegate.environment.TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
          interpolation_suffix: ":-",
        },
        {
          service: "arena-worker",
          destination_environment_key: "TINKER_RELEASE_AUTHORITY_SHA256",
          path: "$.services.arena-worker.environment.TINKER_RELEASE_AUTHORITY_SHA256",
          interpolation_suffix: ":-",
        },
      ],
    },
    {
      source_environment_key: "TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE",
      occurrences: [
        {
          service: "delegate",
          destination_environment_key: "TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE",
          path: "$.services.delegate.environment.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE",
          interpolation_suffix: ":?Release ceremony nonce required",
        },
        {
          service: "arena-worker",
          destination_environment_key: "TINKER_RELEASE_CEREMONY_NONCE",
          path: "$.services.arena-worker.environment.TINKER_RELEASE_CEREMONY_NONCE",
          interpolation_suffix: ":?Release ceremony nonce required",
        },
      ],
    },
    {
      source_environment_key: "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
      occurrences: [
        {
          service: "delegate",
          destination_environment_key:
            "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
          path: "$.services.delegate.environment.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
          interpolation_suffix: ":-",
        },
        {
          service: "delegate",
          destination_environment_key:
            "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256",
          path: "$.services.delegate.environment.TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256",
          interpolation_suffix: ":-",
        },
        {
          service: "arena-worker",
          destination_environment_key:
            "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256",
          path: "$.services.arena-worker.environment.TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256",
          interpolation_suffix: ":-",
        },
      ],
    },
    {
      source_environment_key: "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
      occurrences: [
        {
          service: "delegate",
          destination_environment_key: "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
          path: "$.services.delegate.environment.TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
          interpolation_suffix: ":-",
        },
        {
          service: "arena-policy-init",
          destination_environment_key: "TINKER_ARENA_PROVISION_RELEASE_SHA256",
          path: "$.services.arena-policy-init.environment.TINKER_ARENA_PROVISION_RELEASE_SHA256",
          interpolation_suffix: ":-",
        },
        {
          service: "arena-worker",
          destination_environment_key: "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
          path: "$.services.arena-worker.environment.TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
          interpolation_suffix: ":-",
        },
      ],
    },
    {
      source_environment_key: "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
      occurrences: [
        {
          service: "delegate",
          destination_environment_key: "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
          path: "$.services.delegate.environment.TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
          interpolation_suffix: ":-",
        },
        {
          service: "arena-worker",
          destination_environment_key: "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
          path: "$.services.arena-worker.environment.TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
          interpolation_suffix: ":-",
        },
      ],
    },
  ]);

  const assertDeepFrozen = (value) => {
    if (!value || typeof value !== "object") return;
    assert.equal(Object.isFrozen(value), true);
    for (const nested of Object.values(value)) assertDeepFrozen(nested);
  };
  assertDeepFrozen(CVM_MAIN_EXACT_ENVIRONMENT_REFERENCE_ALIAS_CONTRACT);
  assert.deepEqual(CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS, [
    "TINKER_ARENA_REGISTRY_ADDRESS",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
    "TINKER_ARENA_REGISTRY_RPC_URL",
    "TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH",
    "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
    "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
    "TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256",
    "TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN",
    "TINKER_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH",
    "TINKER_COMPUTE_WORKLOAD_QVL_URL",
    "TINKER_COMPUTE_WORKLOAD_QVL_VERIFIER_ADDRESS",
    "TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
  ]);
  for (const forbidden of [
    "TINKER_EXECUTION_POLICY_ANCHOR_ADDRESS",
    "TINKER_EXECUTION_POLICY_ANCHOR_RPC_URL",
    "TINKER_EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH",
    "TINKER_DEAL_SETTLEMENT_AUTH_TOKEN",
  ]) {
    assert.equal(CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS.includes(forbidden), false);
  }
});

test("launch intent fail-closes on every mandatory QVL lineage environment key", () => {
  const expectedClasses = {
    main_runtime_cvm: {
      descriptor_static_keys: [
        "TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE",
        "TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
        "TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256",
        "TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256",
      ],
      provisioning_result_keys: [
        "TINKER_COMPUTE_WORKLOAD_CVM_ID",
      ],
      post_measurement_deferred_keys: [
        "TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256",
        "TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
      ],
    },
    independent_metering_cvm: {
      descriptor_static_keys: [
        "METERING_CEREMONY_NONCE",
        "METERING_DEPLOYMENT_INTENT_SHA256",
        "METERING_QVL_MEASUREMENT_POLICY_SHA256",
      ],
      provisioning_result_keys: [
        "METERING_CVM_ID",
      ],
      post_measurement_deferred_keys: [
        "METERING_RELEASE_AUTHORITY_SHA256",
      ],
    },
  };
  const value = normalizeCvmLaunchIntentCore(validLaunchIntent());
  for (const [domain, classes] of Object.entries(expectedClasses)) {
    const descriptor = value.descriptors.find(
      ({ trust_domain }) => trust_domain === domain,
    );
    for (const [classification, keys] of Object.entries(classes)) {
      for (const key of keys) {
        assert.equal(descriptor.exact_allowed_environment_keys.includes(key), true, key);
        assert.equal(
          descriptor.public_environment_key_classification[classification].includes(key),
          true,
          `${key} must remain ${classification}`,
        );
      }
    }
  }

  const mandatoryKeys = Object.entries(expectedClasses).flatMap(([domain, classes]) =>
    Object.values(classes).flatMap((keys) => keys.map((key) => [domain, key])),
  );
  for (const [domain, key] of mandatoryKeys) {
    const missing = validLaunchIntent();
    const descriptor = missing.descriptors.find(
      ({ trust_domain }) => trust_domain === domain,
    );
    descriptor.exact_allowed_environment_keys =
      descriptor.exact_allowed_environment_keys.filter((candidate) => candidate !== key);
    descriptor.exact_allowed_environment_keys_sha256 = cvmLaunchEnvironmentKeysDigest(
      descriptor.exact_allowed_environment_keys,
    );
    descriptor.app_compose_candidate.allowed_envs_count =
      descriptor.exact_allowed_environment_keys.length;
    descriptor.app_compose_candidate.allowed_envs_sha256 =
      descriptor.exact_allowed_environment_keys_sha256;
    assert.throws(() => normalizeCvmLaunchIntentCore(missing), /environment|policy/i);
  }

  const extra = validLaunchIntent();
  const extraMetering = extra.descriptors.find(
    ({ trust_domain }) => trust_domain === "independent_metering_cvm",
  );
  extraMetering.exact_allowed_environment_keys.push("METERING_UNREVIEWED_LINEAGE");
  extraMetering.exact_allowed_environment_keys.sort();
  extraMetering.exact_allowed_environment_keys_sha256 = cvmLaunchEnvironmentKeysDigest(
    extraMetering.exact_allowed_environment_keys,
  );
  extraMetering.app_compose_candidate.allowed_envs_count =
    extraMetering.exact_allowed_environment_keys.length;
  extraMetering.app_compose_candidate.allowed_envs_sha256 =
    extraMetering.exact_allowed_environment_keys_sha256;
  assert.throws(() => normalizeCvmLaunchIntentCore(extra), /environment|policy/i);

  const drift = validLaunchIntent();
  const driftMain = drift.descriptors.find(
    ({ trust_domain }) => trust_domain === "main_runtime_cvm",
  );
  driftMain.public_environment_key_classification.descriptor_static_keys =
    driftMain.public_environment_key_classification.descriptor_static_keys.filter(
      (key) => key !== "TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE",
    );
  driftMain.public_environment_key_classification.post_measurement_deferred_keys.push(
    "TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE",
  );
  driftMain.public_environment_key_classification.post_measurement_deferred_keys.sort();
  assert.throws(() => normalizeCvmLaunchIntentCore(drift), /environment|policy/i);
});

test("launch authority commits the exact reviewed Phala production OS catalog entry", () => {
  const expected = createHash("sha256")
    .update(Buffer.from(CVM_LAUNCH_OS_IMAGE_CATALOG_ENTRY_DOMAIN, "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(PHALA_OS_IMAGE_CATALOG_ENTRY)), "utf8"))
    .digest("hex");
  assert.equal(CVM_LAUNCH_OS_IMAGE_CATALOG_ENTRY_DOMAIN.endsWith("\0"), true);
  assert.equal(
    phalaOsImageCatalogEntryDigest(PHALA_OS_IMAGE_CATALOG_ENTRY),
    `sha256:${expected}`,
  );
  assert.throws(
    () => phalaOsImageCatalogEntryDigest({
      ...PHALA_OS_IMAGE_CATALOG_ENTRY,
      is_dev: true,
    }),
    /not the exact reviewed production catalog value/,
  );
  const value = validLaunchIntent();
  value.descriptors[0].launch_settings.phala_os_image =
    PHALA_OS_IMAGE_CATALOG_ENTRY.slug;
  assert.throws(
    () => normalizeCvmLaunchIntentCore(value),
    /OS selector\/hash must bind the reviewed non-dev non-GPU catalog entry|not the reviewed launch setting/,
  );
});

test("local compose hash projector matches @phala/dstack-sdk 0.5.8 normalize=false", () => {
  const candidate = {
    name: "dnai-main-runtime",
    manifest_version: 2,
    runner: "docker-compose",
    kms_enabled: true,
    gateway_enabled: true,
    secure_time: true,
    storage_fs: "ext4",
    tproxy_enabled: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
  };
  const descriptorText = "services:\n  demo:\n    image: example@sha256:abc\n";
  const appCompose = createPhalaDstackComposeHashInput(
    candidate,
    descriptorText,
    ["A", "B"],
  );
  assert.deepEqual(Object.keys(appCompose), PHALA_DSTACK_APP_COMPOSE_HASH_INPUT_KEYS);
  for (const requestOnlyField of [
    "listed",
    "instance_type",
    "image",
    "disk_size",
    "node_id",
    "region",
    "kms_id",
    "key_provider_mode",
    "nonce",
    "app_id",
  ]) {
    assert.equal(Object.hasOwn(appCompose, requestOnlyField), false);
  }
  assert.equal(
    phalaDstackComposeHash(appCompose),
    "6075ce94161b8474c97f902ed6d39269024ebe38886acc465b8ae797630133c7",
  );
  assert.throws(
    () => phalaDstackComposeHash({ ...appCompose, listed: false }),
    /fields are not exact/,
  );
  assert.notEqual(
    phalaDstackComposeHash({ ...appCompose, docker_compose_file: `${appCompose.docker_compose_file}\n` }),
    phalaDstackComposeHash(appCompose),
  );
});

test("launch core rejects uppercase pins, dynamic facts, extras, and policy drift", () => {
  for (const mutate of [
    (value) => { value.contract_deployment_receipt_sha256 = `sha256:${"A".repeat(64)}`; },
    (value) => { value.release_sha = "A".repeat(40); },
    (value) => { value.descriptors[0].descriptor_sha256 = `sha256:${"B".repeat(64)}`; },
    (value) => { value.dynamic_runtime_authorities.phala_cvm_ids.push("cvm-forbidden"); },
    (value) => { value.review_evidence_sha256 = `sha256:${"c".repeat(64)}`; },
    (value) => { value.descriptors[0].exact_allowed_environment_keys.push("UNREVIEWED_KEY"); },
    (value) => { value.descriptors[0].launch_settings.deployment_flags.no_public_logs = false; },
    (value) => { value.phala_control_plane_authority.api_origin = "https://api.phala.network"; },
    (value) => { value.phala_workspace_account_target_authority.workspace_id_present = true; },
    (value) => { value.phala_sdk_debug_secret_logging_policy.required_debug_environment_state = "selector_filtered"; },
    (value) => { value.phala_cloud_sdk_wire_transform_authority.provision_transform.additional_transform_allowed = true; },
    (value) => { value.phala_provision_request_authority.listed = true; },
    (value) => { value.phala_provision_request_authority.key_provider_mode = "local"; },
    (value) => { value.phala_provision_request_authority.candidates.main_runtime_cvm.app_id = "0x1234"; },
    (value) => { value.descriptors[0].launch_settings.cvm_resource_target.instance_type = "tdx.small"; },
    (value) => { value.descriptors[0].app_compose_candidate.tproxy_enabled = true; },
    (value) => { value.descriptors[0].app_compose_candidate.listed = false; },
    (value) => { value.sealed_production_execution_policy.availability = false; },
    (value) => { value.sealed_production_execution_policy.blocker_codes.push("unreviewed"); },
    (value) => { value.descriptors[0].public_environment_value_authority.values_validated = true; },
    (value) => {
      value.descriptors[0].public_environment_value_authority.bootstrap_static.authority_status =
        "operator_supplied";
    },
  ]) {
    const value = validLaunchIntent();
    mutate(value);
    assert.throws(() => normalizeCvmLaunchIntentCore(value));
  }
  const noncanonical = JSON.stringify(validLaunchIntent());
  assert.throws(() => parseCvmLaunchIntentCoreText(noncanonical), /canonical|normalized/);
  assert.throws(
    () => parseCvmLaunchIntentCoreText(" ".repeat(98_305)),
    /between 1 and 98304/,
  );
});

test("validation receipt is hash-only and excludes all renewable review material", () => {
  const value = validLaunchIntent();
  const receipt = cvmLaunchIntentValidationReceipt(value);
  assert.equal(receipt.schema, CVM_LAUNCH_INTENT_RECEIPT_SCHEMA);
  assert.equal(receipt.cvmLaunchIntentSha256, `sha256:${cvmLaunchIntentCoreDigest(value)}`);
  assert.equal(receipt.descriptorCount, 7);
  assert.equal(receipt.publicEnvironmentValueAuthorityComplete, false);
  assert.equal(receipt.publicEnvironmentValueAuthorityBlockerCount, 4);
  assert.equal(receipt.phalaApiOrigin, "https://cloud-api.phala.network/api/v1");
  assert.equal(receipt.phalaApiVersion, "2026-01-21");
  assert.equal(receipt.phalaControlPlaneAdapterReady, false);
  assert.equal(receipt.phalaWorkspaceAccountTargetBound, false);
  assert.equal(receipt.phalaSdkDebugSecretLoggingGuardComplete, false);
  assert.equal(receipt.phalaProvisionRequestFinalAuthorityComplete, false);
  assert.equal(receipt.phalaProvisionRequestCandidateCount, 7);
  assert.equal(receipt.phalaProvisionRequestListed, false);
  assert.equal(receipt.phalaProvisionRequestKeyProviderMode, "kms");
  assert.equal(receipt.cvmResourceProfileEnforcementComplete, false);
  assert.equal(receipt.cvmResourceTargetCount, 7);
  assert.equal(receipt.cvmResourceTargetTotalDiskSizeGb, 160);
  assert.equal(receipt.composeHashAuthorityComplete, false);
  assert.equal(receipt.composeHashExpectedCount, 7);
  assert.equal(receipt.composeHashStagingServerSemanticsEvidenceComplete, false);
  assert.equal(receipt.productionExecutionEnabled, true);
  assert.equal(receipt.productionExecutionBlockerCount, 0);
  assert.equal(
    receipt.productionExecutionBlockerCount,
    PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES.length,
  );
  assert.equal(
    receipt.productionExecutionPolicySha256,
    phalaProductionExecutionPolicyDigest(PHALA_PRODUCTION_EXECUTION_POLICY),
  );
  assert.equal(receipt.environmentValueCount, 0);
  assert.equal(receipt.postDeploymentIdentityCount, 0);
  assert.equal(receipt.reviewMaterialCount, 0);
  assert.equal(JSON.stringify(value).includes("review_envelope_sha256"), false);
  assert.equal(JSON.stringify(value).includes("review_evidence_sha256"), false);
  assert.equal(JSON.stringify(value).includes("approved_at"), false);
});

test("fresh contract receipt projection excludes renewable review and all CVM history", async () => {
  const fixture = await buildFixture();
  try {
    const ledger = JSON.parse(await readFile(fixture.ledgerPath, "utf8"));
    const authorityPins = {
      expectedDeploymentIntentSha256: fixture.intentHash,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        fixture.reviewerAuthorityGenesisAcceptanceSha256,
    };
    const options = {
      releaseSha: RELEASE_SHA,
      ...authorityPins,
    };
    const receipt = projectFreshContractDeploymentReceipt(ledger, options);
    const digest = freshContractDeploymentReceiptDigest(receipt, authorityPins);
    assert.deepEqual(
      normalizeFreshContractDeploymentReceipt(receipt, authorityPins),
      receipt,
    );
    assert.throws(
      () => normalizeFreshContractDeploymentReceipt(receipt),
      /expected fresh receipt deployment intent SHA-256/,
    );
    assert.throws(
      () => normalizeFreshContractDeploymentReceipt(receipt, {
        ...authorityPins,
        expectedReviewerAuthorityGenesisAcceptanceSha256:
          `sha256:${"f".repeat(64)}`,
      }),
      /external reviewed pins/,
    );
    assert.equal(receipt.schema, FRESH_CONTRACT_DEPLOYMENT_RECEIPT_SCHEMA);
    assert.equal(FRESH_CONTRACT_DEPLOYMENT_RECEIPT_DOMAIN.endsWith("\0"), true);
    assert.deepEqual(Object.keys(receipt).sort(), [
      "broadcast_transaction_proof",
      "broadcast_transactions",
      "broadcast_transactions_sha256",
      "contracts",
      "deployment_intent_sha256",
      "exact_creation_proof",
      "keystore_account",
      "network",
      "operator_address",
      "release_sha",
      "reviewer_authority_genesis_acceptance_sha256",
      "schema",
    ]);
    assert.equal(receipt.contracts.length, 7);
    assert.equal(receipt.broadcast_transactions.length, 13);
    assert.equal(receipt.exact_creation_proof, FRESH_CONTRACT_CREATION_INPUT_PROOF);
    assert.equal(receipt.broadcast_transaction_proof, FRESH_CONTRACT_BROADCAST_PROOF);
    assert.equal(
      receipt.contracts.every(({ creation_input_sha256 }) => (
        /^sha256:[0-9a-f]{64}$/.test(creation_input_sha256)
      )),
      true,
    );
    assert.equal(
      receipt.reviewer_authority_genesis_acceptance_sha256,
      fixture.reviewerAuthorityGenesisAcceptanceSha256,
    );
    const anchorReceipt = receipt.contracts.find(
      ({ name }) => name === "ExecutionPolicyAnchor",
    );
    assert.equal(
      anchorReceipt.deployment_intent_sha256_bytes32,
      `0x${fixture.intentHash.slice("sha256:".length)}`,
    );
    assert.equal(
      anchorReceipt.reviewer_authority_genesis_acceptance_sha256_bytes32,
      `0x${fixture.reviewerAuthorityGenesisAcceptanceSha256.slice("sha256:".length)}`,
    );
    assert.equal(
      anchorReceipt.authority_commitment_read_proof,
      FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
    );
    assert.equal(JSON.stringify(receipt).includes("review_envelope"), false);
    assert.equal(JSON.stringify(receipt).includes("review_evidence"), false);
    assert.equal(JSON.stringify(receipt).includes("phala"), false);

    const anchorCommitmentDrift = structuredClone(receipt);
    anchorCommitmentDrift.contracts.find(
      ({ name }) => name === "ExecutionPolicyAnchor",
    ).reviewer_authority_genesis_acceptance_sha256_bytes32 =
      `0x${"f".repeat(64)}`;
    assert.throws(
      () => freshContractDeploymentReceiptDigest(
        anchorCommitmentDrift,
        authorityPins,
      ),
      /authority commitment evidence mismatch/,
    );

    const reorderedReceipt = structuredClone(receipt);
    [
      reorderedReceipt.broadcast_transactions[0],
      reorderedReceipt.broadcast_transactions[1],
    ] = [
      reorderedReceipt.broadcast_transactions[1],
      reorderedReceipt.broadcast_transactions[0],
    ];
    assert.throws(
      () => freshContractDeploymentReceiptDigest(reorderedReceipt, authorityPins),
      /canonical order/,
    );
    const receiptDigestDrift = structuredClone(receipt);
    receiptDigestDrift.broadcast_transactions_sha256 = `sha256:${"f".repeat(64)}`;
    assert.throws(
      () => freshContractDeploymentReceiptDigest(receiptDigestDrift, authorityPins),
      /broadcast transaction SHA-256 mismatch/,
    );
    const receiptCreateInputDrift = structuredClone(receipt);
    receiptCreateInputDrift.contracts[0].creation_input_sha256 =
      `sha256:${"e".repeat(64)}`;
    assert.throws(
      () => freshContractDeploymentReceiptDigest(receiptCreateInputDrift, authorityPins),
      /CREATE evidence mismatch/,
    );

    const malformedBroadcasts = [
      {
        label: "canonical transaction order",
        mutate: (value) => {
          [
            value.freshDeployment.contractSuite.broadcastTransactions[0],
            value.freshDeployment.contractSuite.broadcastTransactions[1],
          ] = [
            value.freshDeployment.contractSuite.broadcastTransactions[1],
            value.freshDeployment.contractSuite.broadcastTransactions[0],
          ];
        },
        error: /canonical order/,
      },
      {
        label: "consecutive nonces",
        mutate: (value) => {
          value.freshDeployment.contractSuite.broadcastTransactions[1].transactionNonce += 1;
        },
        error: /nonces must be exact and consecutive/,
      },
      {
        label: "distinct transaction hashes",
        mutate: (value) => {
          value.freshDeployment.contractSuite.broadcastTransactions[1].transactionHash =
            value.freshDeployment.contractSuite.broadcastTransactions[0].transactionHash;
        },
        error: /transaction hashes must be pairwise distinct/,
      },
      {
        label: "CALL target linkage",
        mutate: (value) => {
          value.freshDeployment.contractSuite.broadcastTransactions[1].transactionTo = address(99);
        },
        error: /CALL linkage is invalid/,
      },
      {
        label: "CREATE target linkage",
        mutate: (value) => {
          value.freshDeployment.contractSuite.broadcastTransactions[0].transactionTo =
            value.contracts.diligenceRoom.address;
        },
        error: /CREATE linkage is invalid/,
      },
      {
        label: "CREATE input linkage",
        mutate: (value) => {
          value.freshDeployment.contractSuite.broadcastTransactions[0]
            .transactionInputSha256 = `sha256:${"e".repeat(64)}`;
        },
        error: /exact CREATE evidence/,
      },
      {
        label: "ordered transaction digest",
        mutate: (value) => {
          value.freshDeployment.contractSuite.broadcastTransactionsSha256 =
            `sha256:${"d".repeat(64)}`;
        },
        error: /ordered broadcast transaction digest mismatch/,
      },
      {
        label: "history transaction digest",
        mutate: (value) => {
          value.deploymentHistory[0].broadcastTransactionsSha256 =
            `sha256:${"c".repeat(64)}`;
        },
        error: /ordered broadcast transaction digest mismatch/,
      },
      {
        label: "full transaction evidence",
        mutate: (value) => {
          value.freshDeployment.contractSuite.broadcastTransactions.pop();
        },
        error: /exactly 13 ordered broadcast transactions/,
      },
      {
        label: "exact proof declaration",
        mutate: (value) => {
          value.freshDeployment.contractSuite.broadcastTransactionProof =
            "operator_asserted_transactions";
        },
        error: /exact fresh fail-closed suite deployment/,
      },
    ];
    for (const { label, mutate, error } of malformedBroadcasts) {
      const malformed = structuredClone(ledger);
      mutate(malformed);
      assert.throws(
        () => projectFreshContractDeploymentReceipt(malformed, options),
        error,
        label,
      );
    }

    const renewableDrift = structuredClone(ledger);
    renewableDrift.freshDeployment.contractSuite.deploymentReviewEnvelopeSha256 =
      `sha256:${"a".repeat(64)}`;
    renewableDrift.freshDeployment.contractSuite.deploymentReviewEvidenceSha256 =
      `sha256:${"b".repeat(64)}`;
    renewableDrift.deploymentHistory[0].deploymentReviewEnvelopeSha256 =
      `sha256:${"c".repeat(64)}`;
    renewableDrift.deploymentHistory.push({ kind: "unrelated_review_renewal" });
    renewableDrift.phala = {
      cvmId: "cvm_must_not_bind",
      appId: "app_must_not_bind",
      composeHash: "platform_hash_must_not_bind",
    };
    renewableDrift.unrelatedHistory = [{ review: "rotated" }];
    const renewableReceipt = projectFreshContractDeploymentReceipt(
      renewableDrift,
      options,
    );
    assert.deepEqual(renewableReceipt, receipt);
    assert.equal(
      freshContractDeploymentReceiptDigest(renewableReceipt, authorityPins),
      digest,
    );

    const operatorDrift = structuredClone(ledger);
    operatorDrift.currentOperatorDeployer.address = address(90);
    for (const entry of Object.values(operatorDrift.contracts)) {
      entry.deploymentTxFrom = address(90);
    }
    for (const entry of operatorDrift.freshDeployment.contractSuite.broadcastTransactions) {
      entry.transactionFrom = address(90);
    }
    operatorDrift.contracts.challengeRegistry.owner = address(90);
    refreshLedgerBroadcastDigest(operatorDrift);
    assert.notEqual(
      freshContractDeploymentReceiptDigest(
        projectFreshContractDeploymentReceipt(operatorDrift, options),
        authorityPins,
      ),
      digest,
    );
    const runtimeChanged = structuredClone(ledger);
    runtimeChanged.contracts.challengeRegistry.runtimeCodeHash = bytes32(91);
    assert.notEqual(
      freshContractDeploymentReceiptDigest(
        projectFreshContractDeploymentReceipt(runtimeChanged, options),
        authorityPins,
      ),
      digest,
    );
    for (const mutate of [
      (entry) => { entry.address = address(91); entry.deploymentReceiptContractAddress = address(91); },
      (entry) => { entry.deploymentTx = bytes32(92); },
      (entry) => { entry.deploymentBlock += 1; },
      (entry) => { entry.deploymentBlockHash = bytes32(93); },
      (entry) => { entry.creationInputSha256 = `sha256:${"9".repeat(64)}`; },
    ]) {
      const changed = structuredClone(ledger);
      mutate(changed.contracts.challengeRegistry);
      assert.throws(
        () => projectFreshContractDeploymentReceipt(changed, options),
        /CREATE evidence|CREATE linkage|transaction sender or receipt contract address/,
      );
    }
    for (const mutate of [
      (entry) => { entry.deploymentReceiptStatus = "reverted"; },
      (entry) => { entry.deploymentTxFrom = address(99); },
      (entry) => { entry.deploymentReceiptContractAddress = address(99); },
    ]) {
      const changed = structuredClone(ledger);
      mutate(changed.contracts.challengeRegistry);
      assert.throws(() => projectFreshContractDeploymentReceipt(changed, options));
    }
    for (const field of ["address", "deploymentTx"]) {
      const collision = structuredClone(ledger);
      const first = collision.contracts.challengeRegistry;
      const second = collision.contracts.computeCreditVault;
      second[field] = first[field];
      if (field === "address") second.deploymentReceiptContractAddress = first.address;
      assert.throws(
        () => projectFreshContractDeploymentReceipt(collision, options),
        /pairwise distinct/,
      );
    }
    const extraContract = structuredClone(ledger);
    extraContract.contracts.unreviewed = structuredClone(
      extraContract.contracts.challengeRegistry,
    );
    assert.throws(
      () => projectFreshContractDeploymentReceipt(extraContract, options),
      /exactly the canonical seven-contract scope/,
    );
    for (const mutate of [
      (entry) => { entry.challengeCount = 1; },
      (entry) => { entry.registryPaused = true; },
      (entry) => { entry.status = "deployed_nonempty_registry"; },
      (entry) => { entry.nextChallengeId = 2; },
    ]) {
      const nonpristine = structuredClone(ledger);
      mutate(nonpristine.contracts.challengeRegistry);
      assert.throws(
        () => projectFreshContractDeploymentReceipt(nonpristine, options),
        /pristine active fresh registry/,
      );
    }
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("fresh contract receipt projector rejects legacy v1 and non-authority markers", async () => {
  const fixture = await buildFixture();
  try {
    const ledger = JSON.parse(await readFile(fixture.ledgerPath, "utf8"));
    const options = {
      releaseSha: RELEASE_SHA,
      expectedDeploymentIntentSha256: fixture.intentHash,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        fixture.reviewerAuthorityGenesisAcceptanceSha256,
    };
    const legacyV1 = structuredClone(ledger);
    legacyV1.schemaVersion = 1;
    assert.throws(
      () => projectFreshContractDeploymentReceipt(legacyV1, options),
      /schemaVersion must be 2/,
    );
    for (const [marker, value] of [
      ["notAuthorityForFreshRelease", true],
      ["notAuthorityForFreshRelease", false],
      ["supersededBoundary", "historical release evidence only"],
    ]) {
      const marked = structuredClone(ledger);
      marked[marker] = value;
      assert.throws(
        () => projectFreshContractDeploymentReceipt(marked, options),
        /legacy non-authority marker/,
      );
    }
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

function fixtureReferenceSuffix(key, late) {
  const contract = CVM_MAIN_EXACT_ENVIRONMENT_REFERENCE_ALIAS_CONTRACT.find(
    ({ source_environment_key: source }) => source === key,
  );
  const canonical = contract?.occurrences.find((occurrence) => (
    occurrence.service === "delegate"
    && occurrence.destination_environment_key === key
  ));
  return canonical?.interpolation_suffix
    ?? (late ? ":-" : `:?fixture requires ${key}`);
}

function fixtureAliasLines(service) {
  return CVM_MAIN_EXACT_ENVIRONMENT_REFERENCE_ALIAS_CONTRACT.flatMap(
    (contract) => contract.occurrences
      .filter((occurrence) => (
        occurrence.service === service
        && !(occurrence.service === "delegate"
          && occurrence.destination_environment_key
            === contract.source_environment_key)
      ))
      .map((occurrence) => (
        `      ${occurrence.destination_environment_key}: `
        + `\${${contract.source_environment_key}`
        + `${occurrence.interpolation_suffix}}`
      )),
  );
}

function descriptorText(domain) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const lateKeys = new Set([
    ...policy.public_environment_key_classification.post_measurement_deferred_keys,
    ...Object.entries(policy.encrypted_secret_environment_keys_by_phase)
      .filter(([phase]) => phase !== "bootstrap_provision")
      .flatMap(([, keys]) => keys),
  ]);
  const strictAndDefaulted = [];
  const activeServiceLate = [];
  const late = [];
  for (const key of policy.exact_allowed_environment_keys) {
    if (key === "COMPOSE_PROFILES") continue;
    const target = lateKeys.has(key)
      ? (domain === "main_runtime_cvm"
          && CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS.includes(key)
        ? activeServiceLate
        : late)
      : strictAndDefaulted;
    target.push(
      `      ${key}: \${${key}${fixtureReferenceSuffix(
        key,
        lateKeys.has(key),
      )}}`,
    );
  }
  for (const key of policy.public_environment_key_classification.descriptor_defaulted_keys) {
    strictAndDefaulted.push(`      ${key}: \${${key}:-fixture-default}`);
  }
  for (const key of policy.public_environment_key_classification.descriptor_static_keys) {
    if (!policy.exact_allowed_environment_keys.includes(key)) {
      strictAndDefaulted.push(`      ${key}: \"1\"`);
    }
  }
  const lines = [`name: ${policy.app_compose_candidate.name}`, "services:"];
  for (const [index, service] of policy.launch_settings.initial_services.entries()) {
    lines.push(`  ${service}:`, "    environment:");
    if (index === 0) lines.push(...strictAndDefaulted);
    if (domain === "main_runtime_cvm" && service === "delegate") {
      lines.push(...activeServiceLate);
      lines.push(...fixtureAliasLines("delegate"));
    }
  }
  for (const [index, profile] of policy.launch_settings.initially_disabled_profiles.entries()) {
    const serviceName = domain === "main_runtime_cvm" && profile === "arena-runtime"
      ? "arena-worker"
      : `fixture-${profile}`;
    lines.push(
      `  ${serviceName}:`,
      "    profiles:",
      `      - ${profile}`,
      "    environment:",
    );
    if (domain === "main_runtime_cvm" && serviceName === "arena-worker") {
      lines.push(...fixtureAliasLines("arena-worker"));
    }
    if (index === 0) {
      lines.push(...late);
      if (!policy.launch_settings.initial_services.length) {
        lines.push(...strictAndDefaulted);
      }
    }
  }
  if (domain === "main_runtime_cvm") {
    lines.push(
      "  arena-policy-init:",
      "    profiles:",
      "      - arena-runtime",
      "    environment:",
      ...fixtureAliasLines("arena-policy-init"),
    );
  }
  lines.push(`x-domain-marker: ${domain}`, "");
  return lines.join("\n");
}

async function buildFixture() {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "dnai-launch-")));
  const deploymentIntent = validIntent();
  const reviewerAuthorityGenesisAcceptanceSha256 =
    deploymentIntent.release.reviewerAuthorityGenesisAcceptanceSha256;
  const intentText = canonicalArtifactText(deploymentIntent);
  const intentHash = rawSha256(Buffer.from(intentText));
  await writeFile(path.join(directory, "dnai-deployment-intent-core.json"), intentText);
  const manifestText = '{"fixture":"five exact image subjects"}\n';
  const bundleText = '{"fixture":"attestation bundle"}\n';
  await writeFile(path.join(directory, "dnai-tee-image-release.json"), manifestText);
  await writeFile(path.join(directory, "dnai-tee-image-release.bundle.json"), bundleText);
  const trustDomains = {};
  for (const domain of CVM_LAUNCH_DOMAINS) {
    const text = descriptorText(domain);
    const filename = CVM_LAUNCH_DESCRIPTOR_POLICY[domain].descriptor_file;
    await writeFile(path.join(directory, filename), text);
    trustDomains[domain] = {
      compose: filename,
      sha256: rawSha256(Buffer.from(text)).slice("sha256:".length),
    };
  }
  const topology = {
    schema: "dnai.cvm-topology.v6",
    status: "rendered_not_deployed",
    release_sha: RELEASE_SHA,
    source_ref: "refs/heads/main",
    generated_at: "2026-07-21T12:00:00.000Z",
    deploymentIntentSha256: intentHash,
    deploymentIntent: {
      file: "dnai-deployment-intent-core.json",
      sha256: intentHash.slice("sha256:".length),
      schema: "dnai.deployment-intent-core.v6",
    },
    image_manifest: {
      file: "dnai-tee-image-release.json",
      sha256: rawSha256(Buffer.from(manifestText)).slice("sha256:".length),
      schema: "dnai.tee-image-release.v1",
    },
    image_manifest_attestation: {
      file: "dnai-tee-image-release.bundle.json",
      sha256: rawSha256(Buffer.from(bundleText)).slice("sha256:".length),
      predicate_type: "https://slsa.dev/provenance/v1",
    },
    trust_domains: trustDomains,
    checks: {
      deployment_attempted: false,
      literal_digest_pins: true,
      linux_amd64_only: true,
      local_build_contexts: false,
      purpose_separated_qvl_descriptors: true,
      raw_secret_values_embedded: false,
      seven_cvm_descriptors: true,
      tdx_verification_claimed: false,
    },
  };
  const topologyPath = path.join(directory, "dnai-cvm-topology.json");
  await writeFile(topologyPath, canonicalJson(topology));
  const contractNames = [
    "challengeRegistry",
    "computeCreditVault",
    "diligenceRoom",
    "emailOracleAuth",
    "executionPolicyAnchor",
    "royaltyDistributor",
    "tinkerAccountEncumbrance",
  ];
  const contracts = Object.fromEntries(contractNames.map((name, index) => [name, {
    address: address(10 + index),
    runtimeCodeHash: bytes32(20 + index),
    sourceCommit: RELEASE_SHA,
    deploymentTx: bytes32(30 + index),
    deploymentBlock: 12_345_000 + index,
    deploymentBlockHash: bytes32(40 + index),
    deploymentReceiptStatus: "success",
    deploymentTxFrom: address(1),
    deploymentReceiptContractAddress: address(10 + index),
  }]));
  Object.assign(contracts.challengeRegistry, {
    status: "deployed_empty_active_registry",
    owner: address(1),
    registryPaused: false,
    challengeCount: 0,
  });
  Object.assign(contracts.executionPolicyAnchor, {
    deploymentIntentSha256Bytes32: `0x${intentHash.slice("sha256:".length)}`,
    reviewerAuthorityGenesisAcceptanceSha256Bytes32:
      `0x${reviewerAuthorityGenesisAcceptanceSha256.slice("sha256:".length)}`,
    authorityCommitmentReadProof:
      FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
    authorityCommitmentReadBlock: contracts.executionPolicyAnchor.deploymentBlock,
    authorityCommitmentReadBlockHash:
      contracts.executionPolicyAnchor.deploymentBlockHash,
  });
  const broadcast = freshBroadcastEvidence(contracts, address(1));
  const ledger = {
    schemaVersion: 2,
    status: "fresh_contract_suite_deployed_pending_cvm_binding",
    network: {
      name: "Base Sepolia",
      chainId: 84_532,
      rpcEnv: "BASE_SEPOLIA_RPC_URL",
      explorerBaseUrl: "https://sepolia.basescan.org",
    },
    currentOperatorDeployer: {
      address: address(1),
      keystoreAccount: "dev",
      privateKeyMaterial: "not_used",
    },
    freshDeployment: {
      contractSuite: {
        status: "broadcast_complete_pending_cvm_binding",
        sourceCommit: RELEASE_SHA,
        deploymentIntentSha256: intentHash,
        reviewerAuthorityGenesisAcceptanceSha256,
        keystoreAccount: "dev",
        runtimeCodeProof: "exact_creation_reexecution_match_all_contracts",
        exactCreationInputProof: FRESH_CONTRACT_CREATION_INPUT_PROOF,
        broadcastTransactionProof: FRESH_CONTRACT_BROADCAST_PROOF,
        broadcastTransactionCount: FRESH_DEPLOYMENT_TRANSACTION_SPEC.length,
        broadcastTransactionsSha256: broadcast.sha256,
        broadcastTransactions: broadcast.transactions,
      },
    },
    contracts,
    deploymentHistory: [{
      kind: "fresh_reviewed_scope_contract_suite",
      sourceCommit: RELEASE_SHA,
      deploymentIntentSha256: intentHash,
      reviewerAuthorityGenesisAcceptanceSha256,
      broadcastTransactionsSha256: broadcast.sha256,
    }],
  };
  const ledgerPath = path.join(directory, "base-sepolia.json");
  await writeFile(ledgerPath, JSON.stringify(ledger, null, 2));
  return {
    directory,
    topologyPath,
    ledgerPath,
    intentHash,
    reviewerAuthorityGenesisAcceptanceSha256,
  };
}

async function writeMainDescriptorMutation(fixture, mutate) {
  const descriptorName =
    CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.descriptor_file;
  const descriptorPath = path.join(fixture.directory, descriptorName);
  const original = await readFile(descriptorPath, "utf8");
  const mutated = mutate(original);
  assert.notEqual(mutated, original, "fixture mutation must change the descriptor");
  await writeFile(descriptorPath, mutated);

  const topology = JSON.parse(await readFile(fixture.topologyPath, "utf8"));
  topology.trust_domains.main_runtime_cvm.sha256 = rawSha256(
    Buffer.from(mutated),
  ).slice("sha256:".length);
  await writeFile(fixture.topologyPath, canonicalJson(topology));
}

test("builder binds topology, fresh ledger, seven raw descriptors, images, and key names", async () => {
  const fixture = await buildFixture();
  try {
    const artifact = await buildCvmLaunchIntentFromFiles({
      topologyPath: fixture.topologyPath,
      ledgerPath: fixture.ledgerPath,
    });
    assert.equal(artifact.deployment_intent_sha256, fixture.intentHash);
    const ledger = JSON.parse(await readFile(fixture.ledgerPath, "utf8"));
    const contractReceipt = projectFreshContractDeploymentReceipt(ledger, {
      releaseSha: RELEASE_SHA,
      expectedDeploymentIntentSha256: fixture.intentHash,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        fixture.reviewerAuthorityGenesisAcceptanceSha256,
    });
    const authorityPins = {
      expectedDeploymentIntentSha256: fixture.intentHash,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        fixture.reviewerAuthorityGenesisAcceptanceSha256,
    };
    assert.equal(
      artifact.contract_deployment_receipt_sha256,
      `sha256:${freshContractDeploymentReceiptDigest(contractReceipt, authorityPins)}`,
    );
    assert.equal(artifact.topology_sha256, rawSha256(await readFile(fixture.topologyPath)));
    assert.equal(artifact.descriptors.length, 7);
    assert.deepEqual(artifact.dynamic_runtime_authorities, {
      endpoint_origins: [],
      os_image_hashes: [],
      phala_app_ids: [],
      phala_cvm_ids: [],
      platform_compose_hashes: [],
      qvl_release_policy_hashes: [],
      tee_identities: [],
      verifier_addresses: [],
    });
    assert.equal(JSON.stringify(artifact).includes("fixture requires"), false);

    const output = path.join(fixture.directory, "launch.json");
    const contractReceiptOutput = path.join(
      fixture.directory,
      "fresh-contract-deployment-receipt.json",
    );
    let stdout = "";
    let code = await runCvmLaunchIntentCli([
      "build", "--topology", fixture.topologyPath, "--ledger", fixture.ledgerPath,
      "--out", output, "--contract-receipt-out", contractReceiptOutput,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 0, stdout);
    assert.equal(JSON.parse(stdout).descriptorCount, 7);
    assert.equal(JSON.parse(stdout).contractReceiptOutput, contractReceiptOutput);
    assert.equal(
      JSON.parse(stdout).contractDeploymentReceiptSha256,
      artifact.contract_deployment_receipt_sha256,
    );
    const outputText = await readFile(output, "utf8");
    assert.deepEqual(parseCvmLaunchIntentCoreText(outputText), artifact);
    const contractReceiptText = await readFile(contractReceiptOutput, "utf8");
    assert.equal(
      contractReceiptText,
      canonicalFreshContractDeploymentReceiptText(contractReceipt, authorityPins),
    );
    const reviewDependency = parseFreshContractDeploymentReceiptText(
      contractReceiptText,
      authorityPins,
    );
    assert.equal(reviewDependency.ok, true);
    assert.deepEqual(reviewDependency.receipt, contractReceipt);
    const unpinnedReviewDependency = parseFreshContractDeploymentReceiptText(
      contractReceiptText,
    );
    assert.equal(unpinnedReviewDependency.ok, false);
    assert.match(
      unpinnedReviewDependency.errors[0].message,
      /expected fresh receipt deployment intent SHA-256/,
    );

    stdout = "";
    code = await runCvmLaunchIntentCli(["check", "--in", output], {
      stdout: (value) => { stdout += value; }, stderr: () => {},
    });
    assert.equal(code, 0, stdout);
    assert.equal(JSON.parse(stdout).cvmLaunchIntentSha256, `sha256:${cvmLaunchIntentCoreDigest(artifact)}`);

    stdout = "";
    code = await runCvmLaunchIntentCli(["hash", "--in", output], {
      stdout: (value) => { stdout += value; }, stderr: () => {},
    });
    assert.equal(code, 0, stdout);
    assert.equal(JSON.parse(stdout).sha256, `sha256:${cvmLaunchIntentCoreDigest(artifact)}`);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("builder enforces every main environment alias as an exact closed occurrence set", async (t) => {
  const cvmIdWorkerLine =
    "      TINKER_MAIN_RUNTIME_CVM_ID: "
    + "${TINKER_COMPUTE_WORKLOAD_CVM_ID:?Canonical main runtime CVM ID required}\n";
  const deploymentIntentWorkerLine =
    "      TINKER_RELEASE_DEPLOYMENT_INTENT_SHA256: "
    + "${TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256:?Signed seven-CVM deployment intent required}\n";
  const releaseAuthorityWorkerLine =
    "      TINKER_RELEASE_AUTHORITY_SHA256: "
    + "${TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256:-}\n";
  const challengeWorkerLine =
    "      TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256: "
    + "${TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:-}\n";
  const manifestProvisionLine =
    "      TINKER_ARENA_PROVISION_RELEASE_SHA256: "
    + "${TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256:-}\n";
  const workerPolicyLine =
    "      TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT: "
    + "${TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT:-}\n";
  const computeExecutionHeader =
    "  fixture-compute-execution:\n"
    + "    profiles:\n"
    + "      - compute-execution\n"
    + "    environment:\n";
  const cases = [
    {
      name: "missing worker alias",
      mutate: (text) => text.replace(cvmIdWorkerLine, ""),
    },
    {
      name: "renamed destination",
      mutate: (text) => text.replace(
        cvmIdWorkerLine,
        cvmIdWorkerLine.replace("TINKER_MAIN_RUNTIME_CVM_ID", "RENAMED_MAIN_RUNTIME_CVM_ID"),
      ),
    },
    {
      name: "alias moved to a different service",
      mutate: (text) => text
        .replace(cvmIdWorkerLine, "")
        .replace(computeExecutionHeader, `${computeExecutionHeader}${cvmIdWorkerLine}`),
    },
    {
      name: "extra command occurrence",
      mutate: (text) => text.replace(
        "  delegate:\n",
        "  delegate:\n"
          + "    command: [\"sh\", \"-c\", \"echo "
          + "${TINKER_COMPUTE_WORKLOAD_CVM_ID:?Canonical main runtime CVM ID required}\"]\n",
      ),
    },
    {
      name: "extra environment destination",
      mutate: (text) => text.replace(
        cvmIdWorkerLine,
        cvmIdWorkerLine
          + "      UNREVIEWED_MAIN_RUNTIME_ALIAS: "
          + "${TINKER_COMPUTE_WORKLOAD_CVM_ID:?Canonical main runtime CVM ID required}\n",
      ),
    },
    {
      name: "strict error message drift",
      mutate: (text) => text.replace(
        deploymentIntentWorkerLine,
        deploymentIntentWorkerLine.replace(
          "Signed seven-CVM deployment intent required",
          "different strict requirement",
        ),
      ),
    },
    {
      name: "interpolation embedded inside a larger scalar",
      mutate: (text) => text.replace(
        releaseAuthorityWorkerLine,
        releaseAuthorityWorkerLine.replace(
          "${TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256:-}",
          "prefix-${TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256:-}",
        ),
      ),
    },
    {
      name: "challenge set missing one of three destinations",
      mutate: (text) => text.replace(challengeWorkerLine, ""),
    },
    {
      name: "release manifest missing its initializer destination",
      mutate: (text) => text.replace(manifestProvisionLine, ""),
    },
    {
      name: "release policy missing its worker comparison destination",
      mutate: (text) => {
        const workerStart = text.indexOf("  arena-worker:\n");
        assert.notEqual(workerStart, -1);
        const prefix = text.slice(0, workerStart);
        const workerAndRest = text.slice(workerStart);
        return prefix + workerAndRest.replace(workerPolicyLine, "");
      },
    },
    {
      name: "canonical destination relocated",
      mutate: (text) => text.replace(
        "      TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE: "
          + "${TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE:?Release ceremony nonce required}\n",
        "      RELOCATED_COMPUTE_WORKLOAD_CEREMONY_NONCE: "
          + "${TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE:?Release ceremony nonce required}\n",
      ),
    },
    {
      name: "duplicate destination shadowed by a constant",
      mutate: (text) => text.replace(
        cvmIdWorkerLine,
        cvmIdWorkerLine + "      TINKER_MAIN_RUNTIME_CVM_ID: attacker-controlled\n",
      ),
    },
    {
      name: "duplicate environment mapping shadows the contracted mapping",
      mutate: (text) => text.replace(
        "  arena-worker:\n",
        "  arena-worker:\n"
          + "    environment:\n"
          + "      TINKER_MAIN_RUNTIME_CVM_ID: attacker-controlled\n",
      ),
      error: /declares environment more than once/,
    },
  ];

  for (const {
    name,
    mutate,
    error = /must use only its exact immutable canonical-and-alias reference contract/,
  } of cases) {
    await t.test(name, async () => {
      const fixture = await buildFixture();
      try {
        await writeMainDescriptorMutation(fixture, mutate);
        await assert.rejects(
          buildCvmLaunchIntentFromFiles({
            topologyPath: fixture.topologyPath,
            ledgerPath: fixture.ledgerPath,
          }),
          error,
        );
      } finally {
        await rm(fixture.directory, { recursive: true, force: true });
      }
    });
  }
});

test("builder rejects a topology that downgrades the exact v6 deployment intent", async () => {
  const fixture = await buildFixture();
  try {
    const topology = JSON.parse(await readFile(fixture.topologyPath, "utf8"));
    topology.deploymentIntent.schema = "dnai.deployment-intent-core.v5";
    await writeFile(fixture.topologyPath, canonicalJson(topology));
    await assert.rejects(
      buildCvmLaunchIntentFromFiles({
        topologyPath: fixture.topologyPath,
        ledgerPath: fixture.ledgerPath,
      }),
      /deployment-intent binding is inconsistent/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("build CLI requires distinct create-new launch and contract-receipt outputs", async () => {
  const fixture = await buildFixture();
  try {
    const output = path.join(fixture.directory, "paired-launch.json");
    const contractReceiptOutput = path.join(fixture.directory, "paired-contract-receipt.json");
    let stdout = "";
    let code = await runCvmLaunchIntentCli([
      "build", "--topology", fixture.topologyPath, "--ledger", fixture.ledgerPath,
      "--out", output,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 1, stdout);
    await assert.rejects(readFile(output, "utf8"), /ENOENT/);

    stdout = "";
    code = await runCvmLaunchIntentCli([
      "build", "--topology", fixture.topologyPath, "--ledger", fixture.ledgerPath,
      "--out", output, "--contract-receipt-out", output,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 1, stdout);
    assert.match(JSON.parse(stdout).message, /distinct paths/);
    await assert.rejects(readFile(output, "utf8"), /ENOENT/);

    await writeFile(output, "operator-owned-existing-output\n");
    stdout = "";
    code = await runCvmLaunchIntentCli([
      "build", "--topology", fixture.topologyPath, "--ledger", fixture.ledgerPath,
      "--out", output, "--contract-receipt-out", contractReceiptOutput,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 1, stdout);
    assert.equal(await readFile(output, "utf8"), "operator-owned-existing-output\n");
    await assert.rejects(readFile(contractReceiptOutput, "utf8"), /ENOENT/);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("builder rejects descriptor drift and a non-fresh ledger before output", async () => {
  const fixture = await buildFixture();
  try {
    const main = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.descriptor_file;
    await writeFile(path.join(fixture.directory, main), `${descriptorText("main_runtime_cvm")}\n# drift\n`);
    await assert.rejects(
      buildCvmLaunchIntentFromFiles({
        topologyPath: fixture.topologyPath,
        ledgerPath: fixture.ledgerPath,
      }),
      /topology hash/,
    );
    const fresh = await buildFixture();
    try {
      const ledger = JSON.parse(await readFile(fresh.ledgerPath, "utf8"));
      ledger.freshDeployment.contractSuite.status = "historical";
      await writeFile(fresh.ledgerPath, JSON.stringify(ledger, null, 2));
      await assert.rejects(
        buildCvmLaunchIntentFromFiles({
          topologyPath: fresh.topologyPath,
          ledgerPath: fresh.ledgerPath,
        }),
        /fresh fail-closed suite/,
      );
    } finally {
      await rm(fresh.directory, { recursive: true, force: true });
    }
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("builder rejects an unclassified optional descriptor interpolation", async () => {
  const fixture = await buildFixture();
  try {
    const mainName = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.descriptor_file;
    const mainPath = path.join(fixture.directory, mainName);
    const mainText = await readFile(mainPath, "utf8");
    const mutated = mainText.replace(
      "    environment:\n",
      "    environment:\n      UNREVIEWED_KEY: ${UNREVIEWED_KEY:-default}\n",
    );
    await writeFile(mainPath, mutated);
    const topology = JSON.parse(await readFile(fixture.topologyPath, "utf8"));
    topology.trust_domains.main_runtime_cvm.sha256 =
      rawSha256(Buffer.from(mutated)).slice("sha256:".length);
    await writeFile(fixture.topologyPath, canonicalJson(topology));
    await assert.rejects(
      buildCvmLaunchIntentFromFiles({
        topologyPath: fixture.topologyPath,
        ledgerPath: fixture.ledgerPath,
      }),
      /allowed-plus-defaulted key contract/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("builder keeps bootstrap and provisioning keys strict nonempty", async () => {
  const fixture = await buildFixture();
  try {
    const main = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.descriptor_file;
    const descriptorPath = path.join(fixture.directory, main);
    const original = await readFile(descriptorPath, "utf8");
    const weakened = original.replace(
      "${EMAIL_ORACLE_CONSUMER_APP_ID:?fixture requires EMAIL_ORACLE_CONSUMER_APP_ID}",
      "${EMAIL_ORACLE_CONSUMER_APP_ID:-sentinel}\n"
        + "      # ${EMAIL_ORACLE_CONSUMER_APP_ID:?inert comment cannot satisfy policy}",
    );
    assert.notEqual(weakened, original);
    await writeFile(descriptorPath, weakened);
    const topology = JSON.parse(await readFile(fixture.topologyPath, "utf8"));
    topology.trust_domains.main_runtime_cvm.sha256 = rawSha256(
      Buffer.from(weakened),
    ).slice("sha256:".length);
    await writeFile(fixture.topologyPath, canonicalJson(topology));
    await assert.rejects(
      buildCvmLaunchIntentFromFiles({
        topologyPath: fixture.topologyPath,
        ledgerPath: fixture.ledgerPath,
      }),
      /strict nonempty.*KEY:\?/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("builder requires late phase keys to use exact empty-default interpolation", async () => {
  const fixture = await buildFixture();
  try {
    const main = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.descriptor_file;
    const descriptorPath = path.join(fixture.directory, main);
    const original = await readFile(descriptorPath, "utf8");
    const strictLate = original.replace(
      "${TINKER_DILIGENCE_QVL_AUTH_TOKEN:-}",
      "${TINKER_DILIGENCE_QVL_AUTH_TOKEN:?incorrectly required before measurement}",
    );
    assert.notEqual(strictLate, original);
    await writeFile(descriptorPath, strictLate);
    const topology = JSON.parse(await readFile(fixture.topologyPath, "utf8"));
    topology.trust_domains.main_runtime_cvm.sha256 = rawSha256(
      Buffer.from(strictLate),
    ).slice("sha256:".length);
    await writeFile(fixture.topologyPath, canonicalJson(topology));
    await assert.rejects(
      buildCvmLaunchIntentFromFiles({
        topologyPath: fixture.topologyPath,
        ledgerPath: fixture.ledgerPath,
      }),
      /post-measurement.*exact empty-default.*KEY:-/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("builder rejects a nonempty default for a late phase key", async () => {
  const fixture = await buildFixture();
  try {
    const main = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.descriptor_file;
    const descriptorPath = path.join(fixture.directory, main);
    const original = await readFile(descriptorPath, "utf8");
    const weakened = original.replace(
      "${TINKER_DILIGENCE_QVL_AUTH_TOKEN:-}",
      "${TINKER_DILIGENCE_QVL_AUTH_TOKEN:-unsafe-default}",
    );
    assert.notEqual(weakened, original);
    await writeFile(descriptorPath, weakened);
    const topology = JSON.parse(await readFile(fixture.topologyPath, "utf8"));
    topology.trust_domains.main_runtime_cvm.sha256 = rawSha256(
      Buffer.from(weakened),
    ).slice("sha256:".length);
    await writeFile(fixture.topologyPath, canonicalJson(topology));
    await assert.rejects(
      buildCvmLaunchIntentFromFiles({
        topologyPath: fixture.topologyPath,
        ledgerPath: fixture.ledgerPath,
      }),
      /post-measurement.*exact empty-default.*KEY:-/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("builder rejects a late key moved into an initially active service", async () => {
  const fixture = await buildFixture();
  try {
    const main = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.descriptor_file;
    const descriptorPath = path.join(fixture.directory, main);
    const original = await readFile(descriptorPath, "utf8");
    const lateLine = "      TINKER_DILIGENCE_QVL_AUTH_TOKEN: ${TINKER_DILIGENCE_QVL_AUTH_TOKEN:-}\n";
    const moved = original
      .replace(lateLine, "")
      .replace("  delegate:\n    environment:\n", `  delegate:\n    environment:\n${lateLine}`);
    assert.notEqual(moved, original);
    await writeFile(descriptorPath, moved);
    const topology = JSON.parse(await readFile(fixture.topologyPath, "utf8"));
    topology.trust_domains.main_runtime_cvm.sha256 = rawSha256(
      Buffer.from(moved),
    ).slice("sha256:".length);
    await writeFile(fixture.topologyPath, canonicalJson(topology));
    await assert.rejects(
      buildCvmLaunchIntentFromFiles({
        topologyPath: fixture.topologyPath,
        ledgerPath: fixture.ledgerPath,
      }),
      /must occur only inside a service with one exact initially-disabled profile/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("builder rejects duplicate active-service late inputs outside the exact delegate environment mapping", async () => {
  const surfaces = [
    "    command: [\"sh\", \"-c\", \"echo ${TINKER_ARENA_REGISTRY_ADDRESS:-}\"]\n",
    "    entrypoint: [\"sh\", \"${TINKER_ARENA_REGISTRY_ADDRESS:-}\"]\n",
    "    healthcheck:\n      test: [\"CMD\", \"${TINKER_ARENA_REGISTRY_ADDRESS:-}\"]\n",
    "    labels:\n      audit-copy: ${TINKER_ARENA_REGISTRY_ADDRESS:-}\n",
  ];
  for (const surface of surfaces) {
    const fixture = await buildFixture();
    try {
      const main = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.descriptor_file;
      const descriptorPath = path.join(fixture.directory, main);
      const original = await readFile(descriptorPath, "utf8");
      const mutated = original.replace("  delegate:\n", `  delegate:\n${surface}`);
      assert.notEqual(mutated, original);
      await writeFile(descriptorPath, mutated);
      const topology = JSON.parse(await readFile(fixture.topologyPath, "utf8"));
      topology.trust_domains.main_runtime_cvm.sha256 = rawSha256(
        Buffer.from(mutated),
      ).slice("sha256:".length);
      await writeFile(fixture.topologyPath, canonicalJson(topology));
      await assert.rejects(
        buildCvmLaunchIntentFromFiles({
          topologyPath: fixture.topologyPath,
          ledgerPath: fixture.ledgerPath,
        }),
        /active-service late input TINKER_ARENA_REGISTRY_ADDRESS must occur exactly once/,
        surface,
      );
    } finally {
      await rm(fixture.directory, { recursive: true, force: true });
    }
  }
});

test("builder rejects an active-service late input whose environment mapping key is relocated", async () => {
  const fixture = await buildFixture();
  try {
    const main = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.descriptor_file;
    const descriptorPath = path.join(fixture.directory, main);
    const original = await readFile(descriptorPath, "utf8");
    const mutated = original.replace(
      "      TINKER_ARENA_REGISTRY_ADDRESS: ${TINKER_ARENA_REGISTRY_ADDRESS:-}\n",
      "      RELOCATED_ARENA_REGISTRY_ADDRESS: ${TINKER_ARENA_REGISTRY_ADDRESS:-}\n",
    );
    assert.notEqual(mutated, original);
    await writeFile(descriptorPath, mutated);
    const topology = JSON.parse(await readFile(fixture.topologyPath, "utf8"));
    topology.trust_domains.main_runtime_cvm.sha256 = rawSha256(
      Buffer.from(mutated),
    ).slice("sha256:".length);
    await writeFile(fixture.topologyPath, canonicalJson(topology));
    await assert.rejects(
      buildCvmLaunchIntentFromFiles({
        topologyPath: fixture.topologyPath,
        ledgerPath: fixture.ledgerPath,
      }),
      /mapping key equal to TINKER_ARENA_REGISTRY_ADDRESS/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("builder rejects an unreviewed or inert profile marker", async () => {
  const fixture = await buildFixture();
  try {
    const main = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.descriptor_file;
    const descriptorPath = path.join(fixture.directory, main);
    const original = await readFile(descriptorPath, "utf8");
    const drifted = original.replace(
      "      - arena-runtime\n",
      "      - unreviewed-runtime\n# arena-runtime is an inert comment\n",
    );
    assert.notEqual(drifted, original);
    await writeFile(descriptorPath, drifted);
    const topology = JSON.parse(await readFile(fixture.topologyPath, "utf8"));
    topology.trust_domains.main_runtime_cvm.sha256 = rawSha256(
      Buffer.from(drifted),
    ).slice("sha256:".length);
    await writeFile(fixture.topologyPath, canonicalJson(topology));
    await assert.rejects(
      buildCvmLaunchIntentFromFiles({
        topologyPath: fixture.topologyPath,
        ledgerPath: fixture.ledgerPath,
      }),
      /exact initially-disabled profile|exact initially-disabled profile set/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("builder rejects mixed strict and fallback interpolation for one key", async () => {
  const fixture = await buildFixture();
  try {
    const main = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm.descriptor_file;
    const descriptorPath = path.join(fixture.directory, main);
    const original = await readFile(descriptorPath, "utf8");
    const mixed = original.replace(
      "    environment:\n",
      "    environment:\n"
        + "      EMAIL_ORACLE_CONSUMER_APP_ID_FALLBACK: "
        + "${EMAIL_ORACLE_CONSUMER_APP_ID:-sentinel}\n",
    );
    await writeFile(descriptorPath, mixed);
    const topology = JSON.parse(await readFile(fixture.topologyPath, "utf8"));
    topology.trust_domains.main_runtime_cvm.sha256 = rawSha256(
      Buffer.from(mixed),
    ).slice("sha256:".length);
    await writeFile(fixture.topologyPath, canonicalJson(topology));
    await assert.rejects(
      buildCvmLaunchIntentFromFiles({
        topologyPath: fixture.topologyPath,
        ledgerPath: fixture.ledgerPath,
      }),
      /cannot mix strict and fallback interpolation modes/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("builder rejects ambiguous duplicate-key ledger JSON", async () => {
  const fixture = await buildFixture();
  try {
    const ledgerText = await readFile(fixture.ledgerPath, "utf8");
    const ambiguous = ledgerText.replace(
      '  "status": "fresh_contract_suite_deployed_pending_cvm_binding",',
      '  "status": "fresh_contract_suite_deployed_pending_cvm_binding",\n'
        + '  "status": "fresh_contract_suite_deployed_pending_cvm_binding",',
    );
    await writeFile(fixture.ledgerPath, ambiguous);
    await assert.rejects(
      buildCvmLaunchIntentFromFiles({
        topologyPath: fixture.topologyPath,
        ledgerPath: fixture.ledgerPath,
      }),
      /unambiguous JSON without duplicate keys/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});
