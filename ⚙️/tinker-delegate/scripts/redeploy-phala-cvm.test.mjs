import assert from "node:assert/strict";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PHALA_CLOUD_API_VERSION,
  PHALA_CLOUD_API_ORIGIN,
  PHALA_CLOUD_SDK_VERSION,
  PHALA_CLI_VERSION,
  PHALA_CLI_PACKAGE_VERSION,
  PHALA_CVM_LAUNCH_RECEIPT_SCHEMA,
  PHALA_FRESH_CLI_DEPLOY_FORBIDDEN,
  PHALA_FRESH_CREATE_COMMAND_PLAN_SCHEMA,
  PHALA_FUTURE_SEALED_AUTHORITY_SEQUENCE,
  PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_EXECUTION_DISABLED_CODE,
  assertProductionCvmInfo,
  buildFreshCreateCommandPlan,
  buildHardenedAppCompose,
  buildReviewedPhaseTransitionPlan,
  canonicalPhalaCvmLaunchReceiptText,
  executeReviewedFreshCvmBatch,
  executeReviewedPostCreateCommit,
  extractComposeEnvironmentReferences,
  inspectInstalledPhalaPackageIdentity,
  parseArgs,
  parseCanonicalKeyFileText,
  parseStrictEnvText,
  readStableBoundedFile,
  runtimeEnvKeyHash,
  validateComposeEnvironmentContract,
  validateLaunchInputsFromFiles,
  validateRuntimeEnvironmentLifecycle,
} from "./redeploy-phala-cvm.mjs";
import * as redeployPhalaModule from "./redeploy-phala-cvm.mjs";
import {
  CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_LAUNCH_SECRET_PHASES,
  FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
  FRESH_CONTRACT_BROADCAST_PROOF,
  FRESH_CONTRACT_CREATION_INPUT_PROOF,
  FRESH_DEPLOYMENT_TRANSACTION_SPEC,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
  canonicalCvmLaunchIntentCoreArtifactText,
  createPhalaDstackComposeHashInput,
  createDraftCvmLaunchIntentCore,
  cvmLaunchEnvironmentKeysDigest,
  cvmLaunchIntentCoreDigest,
  cvmLaunchIntentValidationReceipt,
  freshContractDeploymentReceiptDigest,
  phalaDstackComposeHash,
  projectFreshContractDeploymentReceipt,
  rawSha256,
} from "../../../scripts/cvm-launch-intent-core.mjs";
import {
  canonicalArtifactSha256,
  canonicalArtifactText,
  createDraftAuthorityReviewEnvelope,
  createDraftDeploymentIntentCore,
  describeAuthorityReviewSubjectText,
} from "../../../scripts/operator-policy-packet-core.mjs";
import {
  ACTIVATION_READINESS_MAX_LIFETIME_MS,
  BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS,
  CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS,
  CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE,
  createActivationReadinessSnapshot,
} from "../../../scripts/activation-preflight-core.mjs";

const RELEASE_SHA = "a".repeat(40);
const CHECKED_AT_MS = Math.floor(Date.now() / 1_000) * 1_000;
const MAIN_APP_ID = "a".repeat(40);
const MAIN_COMPOSE_HASH = "1".repeat(64);
const MAIN_OS_IMAGE_HASH = PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash;

async function writeInstalledPhalaPackageFixture(directory) {
  const binDirectory = path.join(directory, "bin");
  const packageDirectory = path.join(directory, "lib", "node_modules", "phala");
  const executable = path.join(packageDirectory, "dist", "index.js");
  const sdkDirectory = path.join(
    packageDirectory,
    "node_modules",
    "@phala",
    "cloud",
  );
  const executionSentinel = path.join(directory, "cli-was-executed");
  await mkdir(path.dirname(executable), { recursive: true });
  await mkdir(sdkDirectory, { recursive: true });
  await mkdir(binDirectory, { recursive: true });
  await writeFile(
    executable,
    `#!/bin/sh\nprintf executed > ${JSON.stringify(executionSentinel)}\n`,
    "utf8",
  );
  await chmod(executable, 0o755);
  await symlink(
    path.relative(binDirectory, executable),
    path.join(binDirectory, "phala"),
  );
  await writeFile(path.join(packageDirectory, "package.json"), JSON.stringify({
    name: "phala",
    version: PHALA_CLI_PACKAGE_VERSION,
    bin: { phala: "./dist/index.js" },
  }));
  const sdkManifestPath = path.join(sdkDirectory, "package.json");
  await writeFile(sdkManifestPath, JSON.stringify({
    name: "@phala/cloud",
    version: PHALA_CLOUD_SDK_VERSION,
  }));
  return { binDirectory, executionSentinel, sdkManifestPath };
}


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

function timestamp(milliseconds) {
  return new Date(milliseconds).toISOString().replace(".000Z", "Z");
}

function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

function bytes32(index) {
  return `0x${index.toString(16).padStart(64, "0")}`;
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

function validDeploymentIntent() {
  const intent = createDraftDeploymentIntentCore();
  intent.release.releaseSha = RELEASE_SHA;
  intent.release.reviewerAuthorityGenesisAcceptanceSha256 =
    `sha256:${"91".repeat(32)}`;
  intent.deploymentControl.controllerId = "launch-operator-01";
  intent.deploymentControl.operatorAddress = address(1);
  intent.staticContractInputs.computeCreditVault.developer = address(2);
  intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment = bytes32(3);
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

function freshContractLedger(
  deploymentIntentSha256,
  reviewerAuthorityGenesisAcceptanceSha256,
) {
  const contracts = Object.fromEntries(
    CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({ ledger_key: ledgerKey }, index) => [
      ledgerKey,
      {
        address: address(10 + index),
        runtimeCodeHash: bytes32(20 + index),
        sourceCommit: RELEASE_SHA,
        deploymentTx: bytes32(30 + index),
        deploymentBlock: 12_345_000 + index,
        deploymentBlockHash: bytes32(40 + index),
        deploymentReceiptStatus: "success",
        deploymentTxFrom: address(1),
        deploymentReceiptContractAddress: address(10 + index),
      },
    ]),
  );
  Object.assign(contracts.challengeRegistry, {
    status: "deployed_empty_active_registry",
    owner: address(1),
    registryPaused: false,
    challengeCount: 0,
  });
  Object.assign(contracts.executionPolicyAnchor, {
    deploymentIntentSha256Bytes32:
      `0x${deploymentIntentSha256.slice("sha256:".length)}`,
    reviewerAuthorityGenesisAcceptanceSha256Bytes32:
      `0x${reviewerAuthorityGenesisAcceptanceSha256.slice("sha256:".length)}`,
    authorityCommitmentReadProof:
      FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
    authorityCommitmentReadBlock:
      contracts.executionPolicyAnchor.deploymentBlock,
    authorityCommitmentReadBlockHash:
      contracts.executionPolicyAnchor.deploymentBlockHash,
  });
  const broadcast = freshBroadcastEvidence(contracts, address(1));
  return {
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
        deploymentIntentSha256,
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
      deploymentIntentSha256,
      reviewerAuthorityGenesisAcceptanceSha256,
      broadcastTransactionsSha256: broadcast.sha256,
    }],
  };
}

function descriptorText(domain) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const lines = ["services:", "  runtime:", "    environment:"];
  const phaseControlKeys = new Set(
    policy.public_environment_key_classification.post_measurement_phase_control_keys,
  );
  const lateInputKeys = new Set([
    ...policy.public_environment_key_classification.post_measurement_deferred_keys,
    ...CVM_LAUNCH_SECRET_PHASES
      .filter((phase) => phase !== "bootstrap_provision")
      .flatMap((phase) => policy.encrypted_secret_environment_keys_by_phase[phase]),
  ]);
  for (const key of policy.exact_allowed_environment_keys) {
    if (phaseControlKeys.has(key)) continue;
    lines.push(lateInputKeys.has(key)
      ? `      ${key}: \${${key}:-}`
      : `      ${key}: \${${key}:?fixture requires ${key}}`);
  }
  for (const key of policy.public_environment_key_classification.descriptor_defaulted_keys) {
    lines.push(`      ${key}: \${${key}:-fixture-default}`);
  }
  for (const key of policy.public_environment_key_classification.descriptor_static_keys) {
    if (!policy.exact_allowed_environment_keys.includes(key)) {
      lines.push(`      ${key}: "1"`);
    }
  }
  if (policy.launch_settings.initially_disabled_profiles.length) {
    lines.push("x-disabled-profiles:");
    for (const profile of policy.launch_settings.initially_disabled_profiles) {
      lines.push(`  - ${profile}`);
    }
  }
  lines.push(`x-domain-marker: ${domain}`, "");
  return lines.join("\n");
}

function populateAppComposeCandidate(descriptor, composeText) {
  const candidate = descriptor.app_compose_candidate;
  candidate.docker_compose_file_sha256 = descriptor.descriptor_sha256;
  candidate.docker_compose_file_byte_length = Buffer.byteLength(composeText, "utf8");
  candidate.expected_compose_hash = phalaDstackComposeHash(
    createPhalaDstackComposeHashInput(
      candidate,
      composeText,
      descriptor.exact_allowed_environment_keys,
    ),
  );
}

function allSecretKeys(descriptor) {
  return [...new Set(CVM_LAUNCH_SECRET_PHASES.flatMap(
    (phase) => descriptor.encrypted_secret_environment_keys_by_phase[phase],
  ))].sort();
}

function bootstrapRuntimeEntries(descriptor, launchSha256) {
  const classification = descriptor.public_environment_key_classification;
  const keys = [...new Set([
    ...classification.descriptor_static_keys.filter(
      (key) => descriptor.exact_allowed_environment_keys.includes(key),
    ),
    ...descriptor.encrypted_secret_environment_keys_by_phase.bootstrap_provision,
  ])].sort();
  const appIdKeys = new Set([
    "EMAIL_ORACLE_CONSUMER_APP_ID",
    "TINKER_ARENA_WORKER_APP_ID",
    "TINKER_DILIGENCE_ALLOWED_APP_ID",
  ]);
  const composeHashKeys = new Set([
    "EMAIL_ORACLE_CONSUMER_COMPOSE_HASH",
    "TINKER_ARENA_WORKER_COMPOSE_HASH",
    "TINKER_COMPUTE_VAULT_COMPOSE_HASH",
    "TINKER_DILIGENCE_ALLOWED_COMPOSE_HASH",
  ]);
  const osHashKeys = new Set([
    "TINKER_ARENA_WORKER_OS_IMAGE_HASH",
    "TINKER_DILIGENCE_ALLOWED_OS_IMAGE_HASH",
  ]);
  return keys.map((key) => {
    let value = `fixture-value-for-${key.toLowerCase()}`;
    if (appIdKeys.has(key)) value = MAIN_APP_ID;
    if (composeHashKeys.has(key)) value = MAIN_COMPOSE_HASH;
    if (osHashKeys.has(key)) value = MAIN_OS_IMAGE_HASH;
    if (key === "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT") {
      value = `0x${launchSha256.slice("sha256:".length)}`;
    }
    return { key, value };
  });
}

function runtimeEntriesForPhase(descriptor, phase, launchSha256) {
  const classification = descriptor.public_environment_key_classification;
  const phaseIndex = CVM_LAUNCH_SECRET_PHASES.indexOf(phase);
  const keys = [
    ...classification.descriptor_static_keys.filter(
      (key) => descriptor.exact_allowed_environment_keys.includes(key),
    ),
    ...classification.provisioning_result_keys,
  ];
  for (let index = 0; index <= phaseIndex; index += 1) {
    keys.push(...descriptor.encrypted_secret_environment_keys_by_phase[
      CVM_LAUNCH_SECRET_PHASES[index]
    ]);
  }
  const policyPhaseReached = phaseIndex >= CVM_LAUNCH_SECRET_PHASES.indexOf(
    "post_measurement_policy_bootstrap",
  );
  const finalPhaseReached = phaseIndex >= CVM_LAUNCH_SECRET_PHASES.indexOf(
    "final_authority_runtime",
  );
  if ((descriptor.trust_domain !== "main_runtime_cvm" && policyPhaseReached)
    || (descriptor.trust_domain === "main_runtime_cvm" && finalPhaseReached)) {
    keys.push(...classification.post_measurement_deferred_keys);
    keys.push(...classification.post_measurement_phase_control_keys);
  }
  const appIdKeys = new Set([
    "EMAIL_ORACLE_CONSUMER_APP_ID",
    "TINKER_ARENA_WORKER_APP_ID",
    "TINKER_DILIGENCE_ALLOWED_APP_ID",
  ]);
  const composeHashKeys = new Set([
    "EMAIL_ORACLE_CONSUMER_COMPOSE_HASH",
    "TINKER_ARENA_WORKER_COMPOSE_HASH",
    "TINKER_COMPUTE_VAULT_COMPOSE_HASH",
    "TINKER_DILIGENCE_ALLOWED_COMPOSE_HASH",
  ]);
  const osHashKeys = new Set([
    "TINKER_ARENA_WORKER_OS_IMAGE_HASH",
    "TINKER_DILIGENCE_ALLOWED_OS_IMAGE_HASH",
  ]);
  return [...new Set(keys)].sort().map((key) => {
    let value = `bound-value-for-${key.toLowerCase()}`;
    if (appIdKeys.has(key)) value = MAIN_APP_ID;
    if (composeHashKeys.has(key)) value = `0x${MAIN_COMPOSE_HASH}`;
    if (osHashKeys.has(key)) value = MAIN_OS_IMAGE_HASH;
    if (key === "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT") {
      value = `0x${launchSha256.slice("sha256:".length)}`;
    }
    if (key === "COMPOSE_PROFILES") {
      const profiles = descriptor.trust_domain !== "main_runtime_cvm"
        ? descriptor.launch_settings.initially_disabled_profiles
        : phase === "final_authority_runtime"
          ? descriptor.launch_settings.initially_disabled_profiles.filter(
            (profile) => profile !== "anchor-writer-ceremony",
          )
          : descriptor.launch_settings.initially_disabled_profiles;
      value = profiles.join(",");
    }
    return { key, value };
  });
}

function envText(entries) {
  return entries.length
    ? `${entries.map(({ key, value }) => `${key}=${value}`).join("\n")}\n`
    : "";
}

function keyFileText(keys) {
  return keys.length ? `${keys.join("\n")}\n` : "";
}

function readinessChainEvidence(contractDeploymentReceipt) {
  return {
    secondaryRpcEndpointSha256: `sha256:${"7".repeat(64)}`,
    rpcOriginSha256: `sha256:${"a".repeat(64)}`,
    secondaryRpcOriginSha256: `sha256:${"b".repeat(64)}`,
    independentReconstructionRpcAgreement: true,
    broadcastTransactionRpcAgreement: true,
    poststateRpcAgreement: true,
    snapshotBlockNumber: 12_346_000,
    snapshotBlockHash: `0x${"8".repeat(64)}`,
    snapshotFinality: "rpc_finalized",
    finalizedRecheckBlockNumber: 12_346_000,
    finalizedRecheckBlockHash: `0x${"8".repeat(64)}`,
    immutableProvenance: CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({ name }) => ({
      name,
      ...Object.fromEntries(
        CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS.map((field) => [field, true]),
      ),
    })),
    broadcastTransactionsSha256:
      contractDeploymentReceipt.broadcast_transactions_sha256,
    broadcastTransactionProvenance: FRESH_DEPLOYMENT_TRANSACTION_SPEC.map(
      (entry, sequence) => ({
        sequence,
        contractKey: entry.contract_key,
        transactionType: entry.transaction_type,
        ...Object.fromEntries(
          BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS.map(
            (field) => [field, true],
          ),
        ),
      }),
    ),
    primaryBroadcastTransactionObservationsSha256: `sha256:${"c".repeat(64)}`,
    secondaryBroadcastTransactionObservationsSha256: `sha256:${"c".repeat(64)}`,
    independentReconstructionSha256: `sha256:${"9".repeat(64)}`,
    poststateMode: "fresh_fail_closed",
    primaryPoststateObservationsSha256: `sha256:${"d".repeat(64)}`,
    secondaryPoststateContractCount: 6,
    secondaryPoststateValid: true,
    secondaryPoststateObservationsSha256: `sha256:${"d".repeat(64)}`,
    poststates: Object.entries(
      CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE.fresh_fail_closed,
    ).map(([name, assertions]) => ({ name, valid: true, assertions: [...assertions] })),
  };
}

function reviewEnvelope(launchText, reviewEvidenceSha256) {
  const subject = describeAuthorityReviewSubjectText(launchText);
  assert.equal(subject.ok, true);
  const envelope = createDraftAuthorityReviewEnvelope(
    subject.subjectKind,
    subject.subjectSha256,
  );
  envelope.approved_at = timestamp(CHECKED_AT_MS - 30_000);
  envelope.expires_at = timestamp(CHECKED_AT_MS + 10 * 60_000);
  envelope.review_evidence_sha256 = reviewEvidenceSha256;
  envelope.reviewers = [
    { address: address(40), controllerId: "reviewer-root-01" },
    { address: address(41), controllerId: "reviewer-root-02" },
  ];
  return envelope;
}

async function writeFixtureFile(filePath, text, mode) {
  await writeFile(filePath, text, "utf8");
  if (mode !== undefined) await chmod(filePath, mode);
  return filePath;
}

async function createFixture() {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "dnai-redeploy-")));
  const deploymentIntent = validDeploymentIntent();
  const deploymentIntentText = canonicalArtifactText(deploymentIntent);
  const deploymentIntentSha256 = canonicalArtifactSha256(deploymentIntent);
  const deploymentIntentPath = await writeFixtureFile(
    path.join(directory, "dnai-deployment-intent-core.json"),
    deploymentIntentText,
  );
  const contractDeploymentReceipt = projectFreshContractDeploymentReceipt(
    freshContractLedger(
      deploymentIntentSha256,
      deploymentIntent.release.reviewerAuthorityGenesisAcceptanceSha256,
    ),
    {
      releaseSha: RELEASE_SHA,
      expectedDeploymentIntentSha256: deploymentIntentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        deploymentIntent.release.reviewerAuthorityGenesisAcceptanceSha256,
    },
  );
  const contractDeploymentReceiptText = canonicalArtifactText(contractDeploymentReceipt);
  const contractDeploymentReceiptSha256 = `sha256:${freshContractDeploymentReceiptDigest(
    contractDeploymentReceipt,
    {
      expectedDeploymentIntentSha256: deploymentIntentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        deploymentIntent.release.reviewerAuthorityGenesisAcceptanceSha256,
    },
  )}`;
  const contractDeploymentReceiptPath = await writeFixtureFile(
    path.join(directory, "dnai-fresh-contract-deployment-receipt.json"),
    contractDeploymentReceiptText,
  );

  const composeTexts = Object.fromEntries(
    CVM_LAUNCH_DOMAINS.map((domain) => [domain, descriptorText(domain)]),
  );
  const launch = createDraftCvmLaunchIntentCore();
  launch.release_sha = RELEASE_SHA;
  launch.deployment_intent_sha256 = deploymentIntentSha256;
  launch.contract_deployment_receipt_sha256 = contractDeploymentReceiptSha256;
  launch.topology_sha256 = `sha256:${"3".repeat(64)}`;
  launch.image_release_manifest_sha256 = `sha256:${"4".repeat(64)}`;
  launch.image_attestation_bundle_sha256 = `sha256:${"5".repeat(64)}`;
  launch.descriptors.forEach((descriptor) => {
    descriptor.descriptor_sha256 = rawSha256(
      Buffer.from(composeTexts[descriptor.trust_domain], "utf8"),
    );
    populateAppComposeCandidate(
      descriptor,
      composeTexts[descriptor.trust_domain],
    );
  });
  const launchText = canonicalCvmLaunchIntentCoreArtifactText(launch);
  const launchSha256 = `sha256:${cvmLaunchIntentCoreDigest(launch)}`;
  const launchPath = await writeFixtureFile(
    path.join(directory, "dnai-cvm-launch-intent-core.json"),
    launchText,
  );
  const launchReceipt = cvmLaunchIntentValidationReceipt(launch);
  const launchReceiptPath = await writeFixtureFile(
    path.join(directory, "dnai-cvm-launch-intent-receipt.json"),
    `${JSON.stringify(launchReceipt, null, 2)}\n`,
  );

  const reviewEvidenceText = "public two-reviewer evidence fixture\n";
  const reviewEvidenceSha256 = rawSha256(Buffer.from(reviewEvidenceText, "utf8"));
  const reviewEvidencePath = await writeFixtureFile(
    path.join(directory, "dnai-cvm-launch-review-evidence.txt"),
    reviewEvidenceText,
  );
  const envelope = reviewEnvelope(launchText, reviewEvidenceSha256);
  const reviewEnvelopePath = await writeFixtureFile(
    path.join(directory, "dnai-cvm-launch-review-envelope.json"),
    canonicalArtifactText(envelope),
  );

  const descriptorSha256ByDomain = Object.fromEntries(
    launch.descriptors.map((descriptor) => [
      descriptor.trust_domain,
      descriptor.descriptor_sha256,
    ]),
  );
  const readinessEvidence = createActivationReadinessSnapshot({
    stage: "cvm_launch",
    releaseSha: RELEASE_SHA,
    rpcEndpointSha256: `sha256:${"6".repeat(64)}`,
    deploymentIntentSha256,
    contractDeploymentReceiptSha256,
    cvmLaunchIntentSha256: launchSha256,
    chainEvidence: readinessChainEvidence(contractDeploymentReceipt),
    descriptorSha256ByDomain,
    checkedAt: timestamp(CHECKED_AT_MS - 20_000),
    expiresAt: timestamp(CHECKED_AT_MS + 80_000),
  });
  const readinessEvidencePath = await writeFixtureFile(
    path.join(directory, "dnai-cvm-launch-readiness.json"),
    canonicalJson(readinessEvidence),
  );

  const domains = [];
  for (const domain of CVM_LAUNCH_DOMAINS) {
    const descriptor = launch.descriptors.find((entry) => entry.trust_domain === domain);
    const classification = descriptor.public_environment_key_classification;
    const composePath = await writeFixtureFile(
      path.join(directory, descriptor.descriptor_file),
      composeTexts[domain],
    );
    const runtimeEntries = bootstrapRuntimeEntries(descriptor, launchSha256);
    const runtimeEnvPath = await writeFixtureFile(
      path.join(directory, `${domain}.env`),
      envText(runtimeEntries),
      0o600,
    );
    const keyBindings = {
      descriptorStaticKeys: classification.descriptor_static_keys,
      descriptorDefaultedKeys: classification.descriptor_defaulted_keys,
      provisioningResultKeys: classification.provisioning_result_keys,
      postMeasurementDeferredKeys: classification.post_measurement_deferred_keys,
      postMeasurementPhaseControlKeys: classification.post_measurement_phase_control_keys,
      encryptedSecretKeys: allSecretKeys(descriptor),
    };
    const keyPaths = {};
    for (const [property, keys] of Object.entries(keyBindings)) {
      keyPaths[property] = await writeFixtureFile(
        path.join(directory, `${domain}.${property}.keys`),
        keyFileText(keys),
      );
    }
    domains.push({
      domain,
      descriptor,
      runtimeEntries,
      args: {
        deploymentIntent: deploymentIntentPath,
        contractDeploymentReceipt: contractDeploymentReceiptPath,
        launchIntent: launchPath,
        launchIntentReceipt: launchReceiptPath,
        reviewEnvelope: reviewEnvelopePath,
        reviewEvidence: reviewEvidencePath,
        readinessEvidence: readinessEvidencePath,
        domain,
        phase: "bootstrap_provision",
        compose: composePath,
        runtimeEnv: runtimeEnvPath,
        ...keyPaths,
      },
    });
  }
  return {
    directory,
    deploymentIntent,
    contractDeploymentReceipt,
    launch,
    launchSha256,
    launchReceipt,
    reviewEvidenceText,
    readinessEvidence,
    domains,
  };
}

async function validateFixture(fixture) {
  const validated = [];
  for (const domain of fixture.domains) {
    validated.push(await validateLaunchInputsFromFiles(domain.args, {
      checkedAtMs: CHECKED_AT_MS,
    }));
  }
  return validated;
}

function argsToArgv(args) {
  return [
    "--deployment-intent", args.deploymentIntent,
    "--contract-deployment-receipt", args.contractDeploymentReceipt,
    "--launch-intent", args.launchIntent,
    "--launch-intent-receipt", args.launchIntentReceipt,
    "--review-envelope", args.reviewEnvelope,
    "--review-evidence", args.reviewEvidence,
    "--readiness-evidence", args.readinessEvidence,
    "--domain", args.domain,
    "--phase", args.phase,
    "--compose", args.compose,
    "--runtime-env", args.runtimeEnv,
    "--descriptor-static-keys", args.descriptorStaticKeys,
    "--descriptor-defaulted-keys", args.descriptorDefaultedKeys,
    "--provisioning-result-keys", args.provisioningResultKeys,
    "--post-measurement-deferred-keys", args.postMeasurementDeferredKeys,
    "--post-measurement-phase-control-keys", args.postMeasurementPhaseControlKeys,
    "--encrypted-secret-keys", args.encryptedSecretKeys,
  ];
}


test("fresh-only CLI arguments require every reviewed input and reject legacy mutation flags", () => {
  const values = Object.fromEntries([
    "deploymentIntent",
    "contractDeploymentReceipt",
    "launchIntent",
    "launchIntentReceipt",
    "reviewEnvelope",
    "reviewEvidence",
    "readinessEvidence",
    "compose",
    "runtimeEnv",
    "descriptorStaticKeys",
    "descriptorDefaultedKeys",
    "provisioningResultKeys",
    "postMeasurementDeferredKeys",
    "postMeasurementPhaseControlKeys",
    "encryptedSecretKeys",
  ].map((name) => [name, `/tmp/${name}`]));
  values.domain = "main_runtime_cvm";
  values.phase = "bootstrap_provision";
  assert.deepEqual(parseArgs(argsToArgv(values)), values);
  assert.deepEqual(parseArgs(["--help"]), { help: true });
  for (const argv of [
    ["--app-id", "forbidden"],
    ["--cvm-id", "forbidden"],
    ["--runtime-env-policy", "all"],
    ["--mode", "existing-update"],
    ["--launch-intent=/tmp/intent"],
  ]) {
    assert.throws(() => parseArgs(argv), /unknown flag|separate --flag value/);
  }
  assert.throws(() => parseArgs(argsToArgv(values).slice(0, -2)), /missing required/);
  assert.throws(
    () => parseArgs([...argsToArgv(values), "--domain", "main_runtime_cvm"]),
    /duplicate flag/,
  );
});

test("strict environment and key-file parsers reject ambiguity, duplicates, and placeholders", () => {
  assert.deepEqual(
    [...parseStrictEnvText("A=one\nB=two=three\n")],
    [["A", "one"], ["B", "two=three"]],
  );
  assert.deepEqual([...parseStrictEnvText("")], []);
  for (const text of [
    "A=one\nA=two\n",
    "B=two\nA=one\n",
    "A=one",
    "# comment\n",
    "export A=one\n",
    " A=one\n",
    "A=\n",
    "A=placeholder\n",
    "A=one\r\n",
    "A=one\u0000\n",
  ]) {
    assert.throws(() => parseStrictEnvText(text));
  }
  assert.deepEqual(parseCanonicalKeyFileText("A\nB\n"), ["A", "B"]);
  assert.deepEqual(parseCanonicalKeyFileText(""), []);
  for (const text of ["B\nA\n", "A\nA\n", "A", "# A\n", "A=value\n", " A\n"]) {
    assert.throws(() => parseCanonicalKeyFileText(text));
  }
  assert.equal(runtimeEnvKeyHash(["A", "B"]), runtimeEnvKeyHash([
    { key: "A", value: "secret-one" },
    { key: "B", value: "secret-two" },
  ]));
  assert.throws(() => runtimeEnvKeyHash(["A", "A"]), /duplicate-free/);
});

test("compose reference extraction and lifecycle validation enforce the reviewed key contract", () => {
  assert.deepEqual(
    extractComposeEnvironmentReferences("${B:?required} ${A:-default} ${B:+yes}"),
    ["A", "B"],
  );
  const launch = createDraftCvmLaunchIntentCore();
  launch.release_sha = RELEASE_SHA;
  launch.deployment_intent_sha256 = `sha256:${"1".repeat(64)}`;
  launch.contract_deployment_receipt_sha256 = `sha256:${"2".repeat(64)}`;
  launch.topology_sha256 = `sha256:${"3".repeat(64)}`;
  launch.image_release_manifest_sha256 = `sha256:${"4".repeat(64)}`;
  launch.image_attestation_bundle_sha256 = `sha256:${"5".repeat(64)}`;
  launch.descriptors.forEach((descriptor, index) => {
    descriptor.descriptor_sha256 = `sha256:${(index + 10).toString(16).padStart(64, "0")}`;
    populateAppComposeCandidate(descriptor, descriptorText(descriptor.trust_domain));
  });
  const launchSha256 = `sha256:${cvmLaunchIntentCoreDigest(launch)}`;
  for (const domain of CVM_LAUNCH_DOMAINS) {
    const descriptor = launch.descriptors.find((entry) => entry.trust_domain === domain);
    const runtimeEntries = bootstrapRuntimeEntries(descriptor, launchSha256);
    const runtimeEnv = new Map(runtimeEntries.map(({ key, value }) => [key, value]));
    assert.doesNotThrow(() => validateComposeEnvironmentContract({
      composeText: descriptorText(domain), runtimeEnv, descriptor,
    }));
    const lifecycle = validateRuntimeEnvironmentLifecycle({
      runtimeEnv, descriptor, phase: "bootstrap_provision", launchIntentSha256: launchSha256,
    });
    assert.deepEqual(lifecycle.inputKeys, runtimeEntries.map(({ key }) => key));
    assert.deepEqual(
      lifecycle.derivedProvisioningKeys,
      descriptor.public_environment_key_classification.provisioning_result_keys,
    );
    assert.equal(
      descriptor.exact_allowed_environment_keys_sha256,
      cvmLaunchEnvironmentKeysDigest(descriptor.exact_allowed_environment_keys),
    );
  }
  const main = launch.descriptors[0];
  const mainRuntime = new Map(
    bootstrapRuntimeEntries(main, launchSha256).map(({ key, value }) => [key, value]),
  );
  const injectedDerivedRuntime = new Map(mainRuntime);
  injectedDerivedRuntime.set(
    main.public_environment_key_classification.provisioning_result_keys[0],
    "PROVISIONING_RESULT_PENDING",
  );
  assert.throws(
    () => validateRuntimeEnvironmentLifecycle({
      runtimeEnv: injectedDerivedRuntime,
      descriptor: main,
      phase: "bootstrap_provision",
      launchIntentSha256: launchSha256,
    }),
    /exact active lifecycle set/,
  );
  mainRuntime.set(main.public_environment_key_classification.post_measurement_deferred_keys[0], "premature");
  assert.throws(
    () => validateRuntimeEnvironmentLifecycle({
      runtimeEnv: mainRuntime,
      descriptor: main,
      phase: "bootstrap_provision",
      launchIntentSha256: launchSha256,
    }),
    /exact active lifecycle set/,
  );
  const qvl = launch.descriptors[1];
  assert.throws(
    () => validateRuntimeEnvironmentLifecycle({
      runtimeEnv: new Map([["QVL_AUTH_TOKEN", "premature-secret"]]),
      descriptor: qvl,
      phase: "bootstrap_provision",
      launchIntentSha256: launchSha256,
    }),
    /exact active lifecycle set/,
  );
  assert.throws(
    () => validateRuntimeEnvironmentLifecycle({
      runtimeEnv: new Map([["PHALA_CLOUD_API_KEY", "phak_never"]]),
      descriptor: qvl,
      phase: "bootstrap_provision",
      launchIntentSha256: launchSha256,
    }),
    /must never enter/,
  );
  const missingReference = descriptorText("diligence_qvl_cvm").replace(
    "      QVL_AUTH_TOKEN: ${QVL_AUTH_TOKEN:-}\n",
    "",
  );
  assert.throws(
    () => validateComposeEnvironmentContract({
      composeText: missingReference,
      runtimeEnv: new Map(),
      descriptor: qvl,
    }),
    /do not equal the reviewed descriptor contract/,
  );
  assert.throws(
    () => validateComposeEnvironmentContract({
      composeText: `${descriptorText("diligence_qvl_cvm")}x: ${"${PHALA_CLOUD_API_KEY:?never}"}\n`,
      runtimeEnv: new Map(),
      descriptor: qvl,
    }),
    /control-plane credential/,
  );
  assert.throws(
    () => validateComposeEnvironmentContract({
      composeText: descriptorText("diligence_qvl_cvm").replace(
        "${QVL_AUTH_TOKEN:-}",
        "${QVL_AUTH_TOKEN:?must-not-be-strict-before-profile-enable}",
      ),
      runtimeEnv: new Map(),
      descriptor: qvl,
    }),
    /late profile inputs.*empty.*fallback/,
  );
  const provisioningKey = main.public_environment_key_classification
    .provisioning_result_keys[0];
  assert.throws(
    () => validateComposeEnvironmentContract({
      composeText: descriptorText("main_runtime_cvm").replace(
        `\${${provisioningKey}:?fixture requires ${provisioningKey}}`,
        `\${${provisioningKey}:-}`,
      ),
      runtimeEnv: new Map(bootstrapRuntimeEntries(main, launchSha256).map(
        ({ key, value }) => [key, value],
      )),
      descriptor: main,
    }),
    /bootstrap and derived provisioning inputs.*only.*:\?/,
  );
});

test("hardened compose reconstruction uses a closed metadata whitelist", () => {
  const next = buildHardenedAppCompose({
    name: "reviewed-name",
    manifest_version: 2,
    kms_enabled: true,
    gateway_enabled: true,
    storage_fs: "zfs",
    runner: "malicious-runner",
    pre_launch_script: "curl attacker",
    bash_script: "exfiltrate",
    public_logs: true,
    public_sysinfo: true,
    public_tcbinfo: true,
    arbitrary_server_field: "must-not-survive",
  }, "services: {}\n", ["A", "B"]);
  assert.deepEqual(next, {
    name: "reviewed-name",
    manifest_version: 2,
    kms_enabled: true,
    gateway_enabled: true,
    storage_fs: "zfs",
    docker_compose_file: "services: {}\n",
    allowed_envs: ["A", "B"],
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
  });
  assert.equal("pre_launch_script" in next, false);
  assert.equal("arbitrary_server_field" in next, false);
  assert.throws(
    () => buildHardenedAppCompose({}, "services: {}\n", ["B", "A"]),
    /sorted and duplicate-free/,
  );
});

test("production CVM inspection requires every privacy, KMS, app, and compose fact", () => {
  const valid = {
    os: { is_dev: false },
    listed: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
    kms_type: "PHALA",
    app_id: MAIN_APP_ID,
    compose_hash: MAIN_COMPOSE_HASH,
  };
  assert.equal(assertProductionCvmInfo(valid, {
    appId: MAIN_APP_ID, composeHash: MAIN_COMPOSE_HASH,
  }), valid);
  for (const mutate of [
    (value) => { value.os.is_dev = true; },
    (value) => { value.listed = true; },
    (value) => { value.public_logs = true; },
    (value) => { value.public_sysinfo = true; },
    (value) => { value.public_tcbinfo = true; },
    (value) => { delete value.public_tcbinfo; },
  ]) {
    const value = structuredClone(valid);
    mutate(value);
    assert.throws(() => assertProductionCvmInfo(value), /production privacy posture/);
  }
  assert.throws(
    () => assertProductionCvmInfo({ ...valid, kms_type: "ethereum" }),
    /not using Phala KMS/,
  );
  assert.throws(
    () => assertProductionCvmInfo(valid, { appId: "b".repeat(40) }),
    /app id differs/,
  );
  assert.throws(
    () => assertProductionCvmInfo(valid, { composeHash: "f".repeat(64) }),
    /compose hash differs/,
  );
});

test("all seven canonical bootstrap bundles validate exact intent, dependency, review, readiness, and key files", async () => {
  const fixture = await createFixture();
  try {
    const validated = await validateFixture(fixture);
    assert.deepEqual(validated.map(({ domain }) => domain), CVM_LAUNCH_DOMAINS);
    assert.equal(validated.every(({ phase }) => phase === "bootstrap_provision"), true);
    assert.equal(new Set(validated.map(({ launchSha256 }) => launchSha256)).size, 1);
    assert.equal(
      validated[0].deploymentIntentSha256,
      canonicalArtifactSha256(fixture.deploymentIntent),
    );
    assert.equal(
      validated[0].freshContractDeploymentReceiptSha256,
      fixture.launch.contract_deployment_receipt_sha256,
    );
    assert.equal(validated[0].reviewReceipt.subjectKind, "cvm_launch_intent");
    assert.equal(validated[0].readinessEvidence.stage, "cvm_launch");
    assert.equal(
      validated[0].readinessEvidence.final_authority_sha256,
      null,
      "pre-Phala readiness must not carry Stage 2 live-activation authority",
    );
    assert.equal(
      validated[0].runtimeEntries.some(({ key }) => key === "PHALA_CLOUD_API_KEY"),
      false,
    );
    assert.equal(validated[1].activeEnvironmentKeys.length, 0);
    assert.equal(validated.at(-1).activeEnvironmentKeys.length, 0);
    assert.equal(validated[0].activeEnvironmentKeys.length > 0, true);
    for (const entry of validated) {
      assert.equal(
        entry.descriptor.exact_allowed_environment_keys_sha256,
        cvmLaunchEnvironmentKeysDigest(entry.descriptor.exact_allowed_environment_keys),
      );
      assert.match(entry.readinessEvidenceSha256, /^sha256:[0-9a-f]{64}$/);
      assert.deepEqual(
        extractComposeEnvironmentReferences(entry.descriptorFile.text),
        [...new Set([
          ...entry.descriptor.exact_allowed_environment_keys.filter(
            (key) => !entry.descriptor.public_environment_key_classification
              .post_measurement_phase_control_keys.includes(key),
          ),
          ...entry.descriptor.public_environment_key_classification.descriptor_defaulted_keys,
        ])].sort(),
      );
    }
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("validation rejects drift in every authority dependency and strict file boundary", async (t) => {
  const cases = [
    ["deployment intent", async (fixture, args) => {
      await writeFile(args.deploymentIntent, `${await readFile(args.deploymentIntent, "utf8")} `);
    }, /deployment intent dependency/],
    ["contract receipt", async (fixture, args) => {
      await writeFile(args.contractDeploymentReceipt, `${await readFile(args.contractDeploymentReceipt, "utf8")} `);
    }, /deployment receipt dependency/],
    ["launch receipt", async (fixture, args) => {
      await writeFile(args.launchIntentReceipt, `${await readFile(args.launchIntentReceipt, "utf8")} `);
    }, /exact canonical receipt/],
    ["review evidence", async (fixture, args) => {
      await writeFile(args.reviewEvidence, "different public evidence\n");
    }, /review evidence bytes/],
    ["readiness evidence", async (fixture, args) => {
      const changed = structuredClone(fixture.readinessEvidence);
      changed.release_sha = "b".repeat(40);
      await writeFile(args.readinessEvidence, canonicalJson(changed));
    }, /does not bind the reviewed CVM launch/],
    ["classification key", async (fixture, args) => {
      await writeFile(args.postMeasurementPhaseControlKeys, "COMPOSE_PROFILES\nEXTRA_KEY\n");
    }, /does not equal the reviewed classification/],
    ["runtime mode", async (fixture, args) => {
      await chmod(args.runtimeEnv, 0o644);
    }, /mode 0600/],
    ["bootstrap provisioning sentinel", async (fixture, args) => {
      const domain = fixture.domains.find((entry) => entry.domain === args.domain);
      const provisioningKey = domain.descriptor.public_environment_key_classification
        .provisioning_result_keys[0];
      const entries = [...domain.runtimeEntries, {
        key: provisioningKey,
        value: "PROVISIONING_RESULT_PENDING",
      }].sort((left, right) => left.key.localeCompare(right.key));
      await writeFile(args.runtimeEnv, envText(entries));
    }, /exact active lifecycle set/],
  ];
  for (const [name, mutate, pattern] of cases) {
    await t.test(name, async () => {
      const fixture = await createFixture();
      try {
        const args = fixture.domains[0].args;
        await mutate(fixture, args);
        await assert.rejects(
          validateLaunchInputsFromFiles(args, { checkedAtMs: CHECKED_AT_MS }),
          pattern,
        );
      } finally {
        await rm(fixture.directory, { recursive: true, force: true });
      }
    });
  }
});

test("safe file reads reject descriptor symlinks without following them", async () => {
  const fixture = await createFixture();
  try {
    const args = fixture.domains[0].args;
    const target = path.join(fixture.directory, "same-descriptor-target.yaml");
    await writeFile(target, await readFile(args.compose));
    await unlink(args.compose);
    await symlink(target, args.compose);
    await assert.rejects(
      validateLaunchInputsFromFiles(args, { checkedAtMs: CHECKED_AT_MS }),
      /could not be read safely/,
    );
    await assert.rejects(
      readStableBoundedFile(args.compose, { label: "symlink", maxBytes: 204_800 }),
      /could not be read safely/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("Phala package identity inspection is manifest-only and never executes the CLI", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "dnai-phala-packages-"));
  try {
    const { binDirectory, executionSentinel, sdkManifestPath } =
      await writeInstalledPhalaPackageFixture(directory);

    const identity = await Promise.race([
      inspectInstalledPhalaPackageIdentity({ PATH: binDirectory }),
      new Promise((_, reject) => setTimeout(
        () => reject(new Error("manifest inspection did not terminate")),
        1_000,
      )),
    ]);
    assert.deepEqual(identity, {
      schema: "dnai.phala-installed-package-identity.v1",
      source: "installed_package_manifests_no_executable_probe",
      cli: {
        name: "phala",
        version: PHALA_CLI_PACKAGE_VERSION,
        manifest_sha256: identity.cli.manifest_sha256,
      },
      sdk: {
        name: "@phala/cloud",
        version: PHALA_CLOUD_SDK_VERSION,
        manifest_sha256: identity.sdk.manifest_sha256,
      },
    });
    assert.match(identity.cli.manifest_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.match(identity.sdk.manifest_sha256, /^sha256:[0-9a-f]{64}$/);
    await assert.rejects(stat(executionSentinel), /ENOENT/);

    await writeFile(sdkManifestPath, JSON.stringify({
      name: "@phala/cloud",
      version: "0.2.9",
    }));
    await assert.rejects(
      inspectInstalledPhalaPackageIdentity({ PATH: binDirectory }),
      /exact installed Phala CLI and SDK package manifests are unavailable/,
    );
    const source = await readFile(
      new URL("./redeploy-phala-cvm.mjs", import.meta.url),
      "utf8",
    );
    assert.equal(source.includes("node:child_process"), false);
    assert.equal(source.includes("execFile"), false);
    assert.equal(source.includes("version_probe_argv: ["), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("fresh-create plans are non-executable, version-pinned, canonical, and secret-free for all seven domains", async () => {
  const fixture = await createFixture();
  try {
    const validated = await validateFixture(fixture);
    const packageFixture = await writeInstalledPhalaPackageFixture(
      path.join(fixture.directory, "package-identity"),
    );
    const packageIdentity = await inspectInstalledPhalaPackageIdentity({
      PATH: packageFixture.binDirectory,
    });
    for (const entry of validated) {
      const plan = buildFreshCreateCommandPlan(entry, {
        installedPackageIdentity: packageIdentity,
      });
      assert.equal(plan.schema, PHALA_FRESH_CREATE_COMMAND_PLAN_SCHEMA);
      assert.equal(
        plan.cli.launch_intent_pinned_build_identity,
        "v1.1.19+d2300dd",
      );
      assert.equal(plan.cli.installed_package_version, "1.1.19");
      assert.equal(plan.cli.installed_package_manifest_sha256, packageIdentity.cli.manifest_sha256);
      assert.equal(plan.cli.identity_source, packageIdentity.source);
      assert.equal(plan.cli.installed_manifest_proves_build_suffix, false);
      assert.equal(plan.cli.executable_version_probe_argv, null);
      assert.equal(plan.cli.executable_probe_used, false);
      assert.equal(plan.cli.deploy_argv, null);
      assert.equal(plan.cli.fresh_deploy_forbidden, true);
      assert.equal(plan.sdk.exact_version, "0.2.10");
      assert.equal(plan.sdk.api_origin, "https://cloud-api.phala.network/api/v1");
      assert.equal(plan.sdk.api_version, "2026-01-21");
      assert.equal(plan.sdk.redirects_allowed, false);
      assert.equal(plan.sdk.origin_drift_allowed, false);
      assert.equal(
        plan.sdk.phala_cloud_api_prefix_environment_override_allowed,
        false,
      );
      assert.equal(
        plan.sdk.wire_transform_authority.package.npm_dist_integrity_sha512,
        "sha512-eQXJxbBlJ8xA4e+MmB3AZd9jgdbO3tFh+qu7KL6CS5Ta64LNKlrV3vdke3oUvB22xbc/qqKQ6dIkJx5pTdY7gA==",
      );
      assert.equal(
        plan.sdk.wire_transform_authority
          .provision_transform.additional_transform_allowed,
        false,
      );
      assert.equal(
        plan.sdk.proposed_future_sequence_not_executable[0],
        "stable_read_verify_bootstrap_target_wire_staging_contract_anchor_sigstore_and_clean_ci_seven_descriptor_set:before_prediction",
      );
      assert.deepEqual(
        plan.sdk.proposed_future_sequence_not_executable,
        PHALA_FUTURE_SEALED_AUTHORITY_SEQUENCE,
      );
      assert.deepEqual(
        plan.sdk.sealed_authority_dependencies.stable_file_recheck_checkpoints,
        [
          "before_prediction",
          "before_each_prepare",
          "before_each_provision",
          "before_each_commit",
        ],
      );
      assert.equal(
        plan.sdk.sealed_authority_dependencies
          .independently_anchored_reviewer_genesis_required,
        true,
      );
      assert.equal(
        plan.sdk.sealed_authority_dependencies
          .exact_clean_ci_seven_descriptor_set_required,
        true,
      );
      assert.equal(
        plan.sdk.sealed_authority_dependencies
          .exact_target_compatibility_wire_staging_stable_reread_required,
        true,
      );
      assert.equal(
        plan.sdk.sealed_authority_dependencies
          .fresh_contract_anchor_receipt_required,
        true,
      );
      assert.equal(
        plan.sdk.sealed_authority_dependencies
          .production_sigstore_receipt_rerun_required,
        true,
      );
      assert.equal(
        plan.sdk.sealed_authority_dependencies.dependency_invoked,
        false,
      );
      assert.ok(plan.sdk.proposed_future_sequence_not_executable.includes(
        "safeGetAppEnvEncryptPubKey_signed_fetch_for_each_exact_predicted_app_id",
      ));
      assert.ok(plan.sdk.proposed_future_sequence_not_executable.includes(
        "dstack_verifyEnvEncryptPublicKeyLegacy_recover_and_compare_exact_kms_identity",
      ));
      assert.ok(plan.sdk.proposed_future_sequence_not_executable.includes(
        "reject_zero_invalid_duplicate_substituted_or_unbound_app_env_pubkeys",
      ));
      assert.equal(plan.production_execution.available, false);
      assert.equal(
        plan.production_execution.reason_code,
        PHALA_PRODUCTION_EXECUTION_DISABLED_CODE,
      );
      assert.deepEqual(
        plan.production_execution.blocker_codes,
        PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
      );
      assert.deepEqual(
        plan.production_execution.bootstrap_blocker_codes,
        PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES,
      );
      assert.equal(plan.production_execution.caller_supplied_callbacks_accepted, false);
      assert.equal(plan.production_execution.caller_supplied_clients_accepted, false);
      assert.equal(plan.production_execution.test_harness_present_in_production_module, false);
      assert.deepEqual(plan.all_seven_domains_required_for_execution, CVM_LAUNCH_DOMAINS);
      assert.equal("all_six_domains_required_for_execution" in plan, false);
      assert.equal(plan.launch_receipt.schema, PHALA_CVM_LAUNCH_RECEIPT_SCHEMA);
      assert.equal(plan.launch_receipt.command_executed, false);
      assert.equal(plan.launch_receipt.phala_api_called, false);
      assert.equal(plan.launch_receipt.remote_state_mutated, false);
      assert.equal(
        plan.launch_receipt.phala_cloud_api_origin,
        "https://cloud-api.phala.network/api/v1",
      );
      assert.equal(plan.launch_receipt.phala_cloud_api_version, "2026-01-21");
      assert.equal(plan.launch_receipt.phala_workspace_account_target_bound, false);
      assert.equal(
        plan.launch_receipt.phala_sdk_debug_secret_logging_guard_complete,
        false,
      );
      assert.equal(
        plan.launch_receipt.phala_sdk_wire_transform_capture_complete,
        false,
      );
      assert.equal(
        plan.launch_receipt.phala_provision_request_final_authority_complete,
        false,
      );
      assert.equal(plan.launch_receipt.production_execution_available, false);
      assert.deepEqual(
        plan.launch_receipt.production_execution_blocker_codes,
        PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
      );
      assert.equal(plan.launch_receipt.runtime_value_authority_bound, false);
      assert.equal(
        plan.launch_receipt.phala_os_image,
        PHALA_OS_IMAGE_CATALOG_ENTRY.name,
      );
      assert.equal(
        plan.launch_receipt.phala_os_image_hash,
        PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
      );
      assert.match(
        plan.launch_receipt.phala_os_image_catalog_entry_sha256,
        /^sha256:[0-9a-f]{64}$/,
      );
      const serialized = JSON.stringify(plan);
      assert.doesNotMatch(
        serialized,
        /--cvm-id|--app-id|--private-key|--prepare-only|PHALA_CLOUD_API_KEY/,
      );
      for (const { value } of entry.runtimeEntries) {
        assert.equal(serialized.includes(value), false);
      }
      const receiptText = canonicalPhalaCvmLaunchReceiptText(plan.launch_receipt);
      assert.equal(receiptText, canonicalJson(plan.launch_receipt));
      assert.equal(JSON.parse(receiptText).schema, PHALA_CVM_LAUNCH_RECEIPT_SCHEMA);
    }
    for (const mutate of [
      () => {},
      (identity) => { identity.source = "executable_probe"; },
      (identity) => { identity.cli.name = "attacker-cli"; },
      (identity) => { identity.cli.version = "1.1.18"; },
      (identity) => { identity.cli.manifest_sha256 = `sha256:${"0".repeat(64)}`; },
      (identity) => { identity.sdk.name = "attacker-sdk"; },
      (identity) => { identity.sdk.version = "0.2.9"; },
      (identity) => { identity.sdk.manifest_sha256 = "not-a-digest"; },
    ]) {
      const invalid = structuredClone(packageIdentity);
      mutate(invalid);
      assert.throws(
        () => buildFreshCreateCommandPlan(validated[0], {
          installedPackageIdentity: invalid,
        }),
        /exact installed Phala package-manifest identity/,
      );
    }
    assert.throws(
      () => canonicalPhalaCvmLaunchReceiptText({ schema: "wrong" }),
      /schema is invalid/,
    );
    assert.equal(PHALA_FRESH_CLI_DEPLOY_FORBIDDEN, true);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("phase plans bind reviewed public structure without rendered secret bytes", async () => {
  const fixture = await createFixture();
  try {
    const validated = await validateFixture(fixture);
    for (const index of [1, 5]) {
      const entry = validated[index];
      const runtimeEntries = runtimeEntriesForPhase(
        entry.descriptor,
        "post_measurement_policy_bootstrap",
        fixture.launchSha256,
      );
      const runtimeEnv = new Map(runtimeEntries.map(({ key, value }) => [key, value]));
      const plan = buildReviewedPhaseTransitionPlan({
        validated: entry,
        nextPhase: "post_measurement_policy_bootstrap",
        runtimeEnv,
      });
      assert.equal(plan.schema, "dnai.phala-cvm-phase-transition-plan.v1");
      assert.equal(
        plan.status,
        "validated_key_lifecycle_plan_only_service_start_forbidden",
      );
      assert.equal(plan.domain, entry.domain);
      assert.equal(plan.from_phase, "bootstrap_provision");
      assert.equal(plan.to_phase, "post_measurement_policy_bootstrap");
      assert.deepEqual(
        plan.compose_profiles,
        entry.descriptor.launch_settings.initially_disabled_profiles,
      );
      assert.equal(
        plan.descriptor_raw_bytes_sha256,
        entry.descriptor.descriptor_sha256,
      );
      assert.match(plan.public_structural_commitment_sha256, /^sha256:[0-9a-f]{64}$/);
      assert.match(
        plan.active_environment_key_names_sha256,
        /^sha256:[0-9a-f]{64}$/,
      );
      assert.equal(plan.active_environment_key_count, runtimeEnv.size);
      assert.equal(plan.environment_values_in_plan, false);
      assert.equal(plan.environment_value_hashes_in_plan, false);
      assert.equal(plan.runtime_value_authority_bound, false);
      assert.equal(plan.static_public_environment_authority_projection_bound, false);
      assert.equal(
        plan.deferred_public_environment_final_authority_projection_bound,
        false,
      );
      assert.deepEqual(
        plan.execution_blocker_codes,
        PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
      );
      assert.equal(plan.service_start_authorized, false);
      assert.equal(plan.phala_api_called, false);
      const serialized = JSON.stringify(plan);
      assert.equal(serialized.includes("rendered_descriptor"), false);
      for (const { key, value } of runtimeEntries) {
        if (key !== "COMPOSE_PROFILES") assert.equal(serialized.includes(value), false);
      }
      const secretKey = entry.descriptor.encrypted_secret_environment_keys_by_phase
        .post_measurement_policy_bootstrap[0];
      const changedRuntime = new Map(runtimeEnv);
      changedRuntime.set(secretKey, `${runtimeEnv.get(secretKey)}-changed`);
      const changedPlan = buildReviewedPhaseTransitionPlan({
        validated: entry,
        nextPhase: "post_measurement_policy_bootstrap",
        runtimeEnv: changedRuntime,
      });
      assert.equal(
        changedPlan.public_structural_commitment_sha256,
        plan.public_structural_commitment_sha256,
      );
      assert.equal(JSON.stringify(changedPlan), JSON.stringify(plan));
    }

    const qvlFixture = fixture.domains[1];
    const postEntries = runtimeEntriesForPhase(
      qvlFixture.descriptor,
      "post_measurement_policy_bootstrap",
      fixture.launchSha256,
    );
    await writeFile(qvlFixture.args.runtimeEnv, envText(postEntries));
    const postValidated = await validateLaunchInputsFromFiles({
      ...qvlFixture.args,
      phase: "post_measurement_policy_bootstrap",
    }, { checkedAtMs: CHECKED_AT_MS });
    const finalEntries = runtimeEntriesForPhase(
      qvlFixture.descriptor,
      "final_authority_runtime",
      fixture.launchSha256,
    );
    const finalPlan = buildReviewedPhaseTransitionPlan({
      validated: postValidated,
      nextPhase: "final_authority_runtime",
      runtimeEnv: new Map(finalEntries.map(({ key, value }) => [key, value])),
    });
    assert.equal(finalPlan.from_phase, "post_measurement_policy_bootstrap");
    assert.equal(finalPlan.to_phase, "final_authority_runtime");
    assert.equal(finalPlan.service_start_authorized, false);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("every public phase-plan byte is invariant under every active secret value", async () => {
  const fixture = await createFixture();
  try {
    const bootstrapValidated = await validateFixture(fixture);
    let examinedSecrets = 0;
    for (let domainIndex = 0; domainIndex < fixture.domains.length; domainIndex += 1) {
      const domainFixture = fixture.domains[domainIndex];
      let currentValidated = bootstrapValidated[domainIndex];
      for (let phaseIndex = 1; phaseIndex < CVM_LAUNCH_SECRET_PHASES.length; phaseIndex += 1) {
        const nextPhase = CVM_LAUNCH_SECRET_PHASES[phaseIndex];
        const runtimeEntries = runtimeEntriesForPhase(
          domainFixture.descriptor,
          nextPhase,
          fixture.launchSha256,
        );
        const runtimeEnv = new Map(
          runtimeEntries.map(({ key, value }) => [key, value]),
        );
        const baselinePlan = buildReviewedPhaseTransitionPlan({
          validated: currentValidated,
          nextPhase,
          runtimeEnv,
        });
        const baselineBytes = Buffer.from(JSON.stringify(baselinePlan), "utf8");
        const baselineText = baselineBytes.toString("utf8");
        assert.equal(baselineText.includes("rendered_descriptor"), false);
        assert.equal(baselineText.includes("environment_value_sha256"), false);

        const activeSecretKeys = CVM_LAUNCH_SECRET_PHASES
          .slice(0, phaseIndex + 1)
          .flatMap(
            (phase) => domainFixture.descriptor
              .encrypted_secret_environment_keys_by_phase[phase],
          );
        for (const secretKey of activeSecretKeys) {
          examinedSecrets += 1;
          const originalSecret = runtimeEnv.get(secretKey);
          assert.equal(typeof originalSecret, "string");
          assert.equal(baselineText.includes(originalSecret), false);
          assert.equal(
            baselineText.includes(rawSha256(Buffer.from(originalSecret, "utf8"))),
            false,
          );
          const changedRuntime = new Map(runtimeEnv);
          changedRuntime.set(secretKey, `${originalSecret}-rotated-${examinedSecrets}`);
          const changedPlan = buildReviewedPhaseTransitionPlan({
            validated: currentValidated,
            nextPhase,
            runtimeEnv: changedRuntime,
          });
          assert.deepEqual(
            Buffer.from(JSON.stringify(changedPlan), "utf8"),
            baselineBytes,
            `${domainFixture.descriptor.trust_domain}/${nextPhase}/${secretKey}`,
          );
        }

        if (phaseIndex < CVM_LAUNCH_SECRET_PHASES.length - 1) {
          await writeFile(domainFixture.args.runtimeEnv, envText(runtimeEntries));
          currentValidated = await validateLaunchInputsFromFiles({
            ...domainFixture.args,
            phase: nextPhase,
          }, { checkedAtMs: CHECKED_AT_MS });
        }
      }
    }
    assert.ok(examinedSecrets > 0);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("phase plans reject forgery, missing late values, profile drift, and phase skips", async () => {
  const fixture = await createFixture();
  try {
    const validated = await validateFixture(fixture);
    const qvl = validated[1];
    const qvlEntries = runtimeEntriesForPhase(
      qvl.descriptor,
      "post_measurement_policy_bootstrap",
      fixture.launchSha256,
    );
    const qvlRuntime = new Map(qvlEntries.map(({ key, value }) => [key, value]));
    assert.throws(
      () => buildReviewedPhaseTransitionPlan({
        validated: structuredClone(qvl),
        nextPhase: "post_measurement_policy_bootstrap",
        runtimeEnv: qvlRuntime,
      }),
      /not produced by full stable-file validation/,
    );
    for (const nextPhase of [
      "bootstrap_provision",
      "final_authority_runtime",
      "anchor_writer_ceremony",
    ]) {
      assert.throws(
        () => buildReviewedPhaseTransitionPlan({
          validated: qvl,
          nextPhase,
          runtimeEnv: qvlRuntime,
        }),
        /advance exactly one canonical phase/,
      );
    }
    const lateKey = qvl.descriptor.encrypted_secret_environment_keys_by_phase
      .post_measurement_policy_bootstrap[0];
    const missing = new Map(qvlRuntime);
    missing.delete(lateKey);
    assert.throws(
      () => buildReviewedPhaseTransitionPlan({
        validated: qvl,
        nextPhase: "post_measurement_policy_bootstrap",
        runtimeEnv: missing,
      }),
      /exact active lifecycle set/,
    );
    const empty = new Map(qvlRuntime);
    empty.set(lateKey, "");
    assert.throws(
      () => buildReviewedPhaseTransitionPlan({
        validated: qvl,
        nextPhase: "post_measurement_policy_bootstrap",
        runtimeEnv: empty,
      }),
      /not provisionable/,
    );
    const wrongProfile = new Map(qvlRuntime);
    wrongProfile.set("COMPOSE_PROFILES", "wrong-profile");
    assert.throws(
      () => buildReviewedPhaseTransitionPlan({
        validated: qvl,
        nextPhase: "post_measurement_policy_bootstrap",
        runtimeEnv: wrongProfile,
      }),
      /exact reviewed phase profile set/,
    );
    const main = validated[0];
    const mainPostRuntime = new Map(runtimeEntriesForPhase(
      main.descriptor,
      "post_measurement_policy_bootstrap",
      fixture.launchSha256,
    ).map(({ key, value }) => [key, value]));
    mainPostRuntime.set("COMPOSE_PROFILES", "premature-profile");
    assert.throws(
      () => buildReviewedPhaseTransitionPlan({
        validated: main,
        nextPhase: "post_measurement_policy_bootstrap",
        runtimeEnv: mainPostRuntime,
      }),
      /exact active lifecycle set|premature/,
    );
    assert.throws(
      () => validateComposeEnvironmentContract({
        composeText: qvl.descriptorFile.text.replace(
          "${QVL_AUTH_TOKEN:-}",
          "${QVL_AUTH_TOKEN:-unsafe-fallback}",
        ),
        runtimeEnv: new Map(),
        descriptor: qvl.descriptor,
      }),
      /late profile inputs.*empty.*fallback/,
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("runtime public-value substitutions remain explicitly unauthorized plans", async (t) => {
  const fixture = await createFixture();
  try {
    const validated = await validateFixture(fixture);
    const main = validated[0];
    const mainEntries = runtimeEntriesForPhase(
      main.descriptor,
      "post_measurement_policy_bootstrap",
      fixture.launchSha256,
    );
    const mainRuntime = new Map(mainEntries.map(({ key, value }) => [key, value]));
    const baselineMainPlan = buildReviewedPhaseTransitionPlan({
      validated: main,
      nextPhase: "post_measurement_policy_bootstrap",
      runtimeEnv: mainRuntime,
    });
    const staticSubstitutions = [
      ["contract address", "EMAIL_ORACLE_AUTH_ADDRESS", `0x${"f".repeat(40)}`],
      ["runtime code hash", "EMAIL_ORACLE_AUTH_RUNTIME_CODE_HASH", `0x${"e".repeat(64)}`],
      ["worker image digest", "TINKER_ARENA_WORKER_IMAGE_DIGEST", `sha256:${"d".repeat(64)}`],
      ["numeric start block", "TINKER_CHAIN_START_BLOCK", "attacker-not-a-block"],
      ["origin policy", "TINKER_CORS_ALLOWED_ORIGINS", "https://attacker.invalid"],
    ];
    for (const [label, key, attackerValue] of staticSubstitutions) {
      await t.test(label, () => {
        assert.equal(mainRuntime.has(key), true);
        const substituted = new Map(mainRuntime);
        substituted.set(key, attackerValue);
        const plan = buildReviewedPhaseTransitionPlan({
          validated: main,
          nextPhase: "post_measurement_policy_bootstrap",
          runtimeEnv: substituted,
        });
        assert.deepEqual(plan, baselineMainPlan);
        assert.equal(plan.runtime_value_authority_bound, false);
        assert.equal(plan.static_public_environment_authority_projection_bound, false);
        assert.equal(plan.service_start_authorized, false);
        assert.ok(plan.execution_blocker_codes.includes(
          "static_public_environment_authority_projection_required",
        ));
      });
    }

    const qvl = validated.at(-1);
    const qvlEntries = runtimeEntriesForPhase(
      qvl.descriptor,
      "post_measurement_policy_bootstrap",
      fixture.launchSha256,
    );
    const qvlRuntime = new Map(qvlEntries.map(({ key, value }) => [key, value]));
    const baselineQvlPlan = buildReviewedPhaseTransitionPlan({
      validated: qvl,
      nextPhase: "post_measurement_policy_bootstrap",
      runtimeEnv: qvlRuntime,
    });
    const deferredKeys = qvl.descriptor.public_environment_key_classification
      .post_measurement_deferred_keys;
    const deferredSubstitutions = [
      ["deferred URL", deferredKeys.find((key) => key.endsWith("_URL")), "https://attacker.invalid"],
      ["deferred verifier", deferredKeys.find((key) => key.endsWith("_VERIFIER_ADDRESS")), `0x${"c".repeat(40)}`],
      ["deferred policy hash", deferredKeys.find((key) => key.endsWith("_POLICY_SET_HASH") || key.endsWith("_POLICY_HASH")), `0x${"b".repeat(64)}`],
    ];
    for (const [label, key, attackerValue] of deferredSubstitutions) {
      await t.test(label, () => {
        assert.equal(typeof key, "string");
        assert.equal(qvlRuntime.has(key), true);
        const substituted = new Map(qvlRuntime);
        substituted.set(key, attackerValue);
        const plan = buildReviewedPhaseTransitionPlan({
          validated: qvl,
          nextPhase: "post_measurement_policy_bootstrap",
          runtimeEnv: substituted,
        });
        assert.deepEqual(plan, baselineQvlPlan);
        assert.equal(
          plan.deferred_public_environment_final_authority_projection_bound,
          false,
        );
        assert.equal(plan.service_start_authorized, false);
        assert.ok(plan.execution_blocker_codes.includes(
          "deferred_public_environment_final_authority_projection_required",
        ));
      });
    }
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("production module exposes no injectable callback or client capability", async (t) => {
  for (const forbiddenExport of [
    "exerciseReviewedFreshCvmBatchWithMockAdapters",
    "revalidateReadinessBeforeMutation",
    "PHALA_MOCK_LAUNCH_EXERCISE_SCHEMA",
    "PHALA_PARTIAL_TOPOLOGY_RECOVERY_RECEIPT_SCHEMA",
    "PHALA_COMMIT_BATCH_REVIEW_SAFETY_MARGIN_MS",
  ]) {
    assert.equal(Object.hasOwn(redeployPhalaModule, forbiddenExport), false);
  }
  const source = await readFile(
    new URL("./redeploy-phala-cvm.mjs", import.meta.url),
    "utf8",
  );
  for (const forbiddenImplementation of [
    "collectCurrentReadinessEvidence",
    "runFreshCvmBatchWithInjectedMockAdapters",
    "app_env_encrypt_pubkey",
    "bounded_reason",
    "journal_path_sha256",
    "partialTopologyReceipt",
  ]) {
    assert.equal(source.includes(forbiddenImplementation), false);
  }
  for (const linkedButUnreachableDependency of [
    "readReverifyDescriptorSetAndCheckpointPhalaBootstrap",
    "assertTrackedDescriptorMaterializationSources",
    "validateCanonicalGeneratedCvmDescriptorSet",
    "verifyExactTrackedSourceDescriptorReproduction",
  ]) {
    assert.doesNotMatch(
      source,
      new RegExp(`${linkedButUnreachableDependency}\\s*\\(`),
    );
  }
  assert.equal(PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES.length, 23);
  assert.equal(
    new Set(PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES).size,
    PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES.length,
  );
  for (const blocker of [
    "pinned_phala_api_origin_and_version_adapter_required",
    "reviewed_phala_workspace_account_target_required",
    "phala_sdk_debug_secret_logging_guard_required",
    "release_manifest_sigstore_bundle_not_cryptographically_verified",
    "pinned_phala_sdk_wire_transform_and_capture_proof_required",
    "staging_provision_compose_hash_semantics_evidence_required",
    "authenticated_cvm_resource_catalog_and_quota_evidence_required",
    "reviewer_genesis_acceptance_not_cryptographically_verified",
    "reviewer_genesis_not_independently_anchored",
    "separately_reviewed_live_activation_authority_required",
  ]) {
    assert.equal(PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES.includes(blocker), true);
  }
  const expectedError = `${PHALA_PRODUCTION_EXECUTION_DISABLED_CODE}:`
    + PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES.join(",");
  const secret = "SECRET_ECHO_MUST_NEVER_EGRESS";
  const ciphertext = "CIPHERTEXT_ECHO_MUST_NEVER_EGRESS";
  const privatePath = "/private/operator/recovery-journal.jsonl";
  const attackSurfaces = [
    "collectCurrentReadinessEvidence",
    "fetchPhalaOsImageCatalog",
    "persistRecoveryReceipt",
    "encryptEnvVars",
    "getComposeHash",
    "validatePreparedOs",
    "fetchCvmInfo",
    "now",
    "client.nextAppIds",
    "client.provisionCvm",
    "client.commitCvmProvision",
    "app_env_encrypt_pubkey",
  ];

  function makeAttackObject(surface, mode, onEffect) {
    const parts = surface.split(".");
    const root = {};
    let cursor = root;
    for (const part of parts.slice(0, -1)) {
      cursor[part] = {};
      cursor = cursor[part];
    }
    const last = parts.at(-1);
    if (mode === "callback") {
      cursor[last] = () => {
        onEffect();
        throw new Error(`${secret}:${ciphertext}:${privatePath}`);
      };
    } else {
      Object.defineProperty(cursor, last, {
        enumerable: true,
        get() {
          onEffect();
          throw new Error(`${secret}:${ciphertext}:${privatePath}`);
        },
      });
    }
    return root;
  }

  for (const mode of ["callback", "getter"]) {
    for (const surface of attackSurfaces) {
      await t.test(`${mode}:${surface}`, async () => {
        let effects = 0;
        const attack = makeAttackObject(surface, mode, () => { effects += 1; });
        for (const executor of [
          executeReviewedFreshCvmBatch,
          executeReviewedPostCreateCommit,
        ]) {
          await assert.rejects(
            executor([], attack),
            (error) => {
              assert.equal(error.message, expectedError);
              assert.equal(error.message.includes(secret), false);
              assert.equal(error.message.includes(ciphertext), false);
              assert.equal(error.message.includes(privatePath), false);
              assert.equal(error.partialTopologyRecoveryReceipt, undefined);
              return true;
            },
          );
        }
        assert.equal(effects, 0);
      });
    }
  }
});


test("readiness lifetime is deliberately tight", () => {
  assert.equal(ACTIVATION_READINESS_MAX_LIFETIME_MS, 120_000);
  assert.equal(PHALA_CLI_VERSION, "v1.1.19+d2300dd");
  assert.equal(PHALA_CLOUD_SDK_VERSION, "0.2.10");
  assert.equal(PHALA_CLOUD_API_ORIGIN, "https://cloud-api.phala.network/api/v1");
  assert.equal(PHALA_CLOUD_API_VERSION, "2026-01-21");
});
