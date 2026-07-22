import assert from "node:assert/strict";
import {
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  AUTHORITY_REVIEW_ENVELOPE_SCHEMA,
  AUTHORITY_REVIEW_RECEIPT_SCHEMA,
  canonicalArtifactSha256,
  canonicalArtifactText,
  createDraftAuthorityReviewEnvelope,
  createDraftDeploymentIntentCore,
  CANONICAL_CVMS,
  DEPLOYMENT_INTENT_ACTION_SCOPE,
  DEPLOYMENT_INTENT_CORE_SCHEMA,
  DEPLOYMENT_INTENT_RECEIPT_SCHEMA,
  deploymentIntentReviewerAuthorityCurrentStatusBinding,
  describeAuthorityReviewSubjectText,
  FINAL_RELEASE_AUTHORITY_ACTION_SCOPE,
  FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
  MAX_PACKET_BYTES,
  QVL_POLICY_KEYS,
  REVIEWER_AUTHORITY_CURRENT_STATUS_MAX_EPOCH,
  parseAuthorityReviewEnvelopeText,
  parseDeploymentIntentCoreText,
  REVIEW_SUBJECT_POLICY,
  validateAuthorityReviewEnvelope,
  validateDeploymentIntentCore,
  validationErrorDocument,
} from "./operator-policy-packet-core.mjs";
import {
  canonicalFinalReleaseAuthorityCoreArtifactText,
  normalizeFinalReleaseAuthorityCore,
} from "./execution-policy-release-core.mjs";
import { knownVector } from "./execution-policy-release-core.fixture.mjs";
import {
  canonicalCvmLaunchIntentCoreArtifactText,
  CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS,
  createDraftCvmLaunchIntentCore,
  CVM_LAUNCH_INTENT_CORE_SCHEMA,
  cvmLaunchIntentCoreDigest,
  FRESH_CONTRACT_BROADCAST_PROOF,
  FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
  FRESH_CONTRACT_CREATION_INPUT_PROOF,
  freshContractDeploymentReceiptDigest,
  FRESH_CONTRACT_DEPLOYMENT_RECEIPT_SCHEMA,
  FRESH_DEPLOYMENT_TRANSACTION_SPEC,
  rawSha256,
} from "./cvm-launch-intent-core.mjs";
import { runOperatorPolicyPacketCli } from "./operator-policy-packet.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const INTENT_TEMPLATE = path.join(
  ROOT,
  "deployments",
  "deployment-intent-core.template.json",
);
const INTENT_SCHEMA = path.join(
  ROOT,
  "deployments",
  "deployment-intent-core.schema.json",
);
const REVIEW_TEMPLATE = path.join(
  ROOT,
  "deployments",
  "authority-review-envelope.template.json",
);
const REVIEW_SCHEMA = path.join(
  ROOT,
  "deployments",
  "authority-review-envelope.schema.json",
);
const CHECKED_AT_MS = Math.floor(Date.now() / 1_000) * 1_000;
const VALID_INTENT_V6_KAT_SHA256 =
  "sha256:e4f4f11299b587d72093c12b59733c229f3a5c922dae69a2f068a75745a16380";

function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

function bytes32(index) {
  return `0x${index.toString(16).padStart(64, "0")}`;
}

function timestamp(milliseconds) {
  return new Date(milliseconds).toISOString().replace(".000Z", "Z");
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((item) => sortedObject(item));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
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

function validIntent() {
  const intent = createDraftDeploymentIntentCore();
  intent.release.releaseSha = "a".repeat(40);
  intent.release.reviewerAuthorityGenesisAcceptanceSha256 = `sha256:${"91".repeat(32)}`;
  intent.release.reviewerAuthorityCurrentStatusEpoch = 7;
  intent.release.reviewerAuthorityCurrentStatusSha256 = `sha256:${"92".repeat(32)}`;
  intent.deploymentControl.controllerId = "operator-control-01";
  intent.deploymentControl.operatorAddress = address(1);
  intent.staticContractInputs.computeCreditVault.developer = address(30);
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

test("deployment intent freezes the exact seven-CVM topology and five QVL budgets", () => {
  assert.deepEqual(CANONICAL_CVMS, [
    "main_runtime",
    "diligence_qvl",
    "arena_qvl",
    "anchor_writer_qvl",
    "compute_workload_qvl",
    "compute_metering_qvl",
    "independent_metering",
  ]);
  assert.deepEqual(QVL_POLICY_KEYS, [
    "diligence",
    "arena",
    "anchorWriter",
    "computeWorkload",
    "computeMetering",
  ]);
  const result = validateDeploymentIntentCore(validIntent());
  assert.equal(result.ok, true);
  assert.equal(result.receipt.canonicalCvmCount, 7);
  assert.equal(result.receipt.qvlNumericPolicyCount, 5);

  const retired = validIntent();
  retired.scope.cvms.splice(4, 1);
  delete retired.numericPolicy.qvl.computeWorkload;
  const rejected = validateDeploymentIntentCore(retired);
  assert.equal(rejected.ok, false);
  assert.match(
    rejected.errors.map(({ message }) => message).join("\n"),
    /must equal the canonical ordered list|must contain exactly the documented fields/,
  );
});

function validLaunchIntent() {
  const value = createDraftCvmLaunchIntentCore();
  value.release_sha = "a".repeat(40);
  value.deployment_intent_sha256 = `sha256:${"1".repeat(64)}`;
  value.contract_deployment_receipt_sha256 = `sha256:${"2".repeat(64)}`;
  value.topology_sha256 = `sha256:${"3".repeat(64)}`;
  value.image_release_manifest_sha256 = `sha256:${"4".repeat(64)}`;
  value.image_attestation_bundle_sha256 = `sha256:${"5".repeat(64)}`;
  value.descriptors.forEach((descriptor, index) => {
    descriptor.descriptor_sha256 =
      `sha256:${(index + 10).toString(16).padStart(2, "0").repeat(32)}`;
    descriptor.app_compose_candidate.docker_compose_file_sha256 =
      descriptor.descriptor_sha256;
    descriptor.app_compose_candidate.docker_compose_file_byte_length = 1_000 + index;
    descriptor.app_compose_candidate.expected_compose_hash =
      (index + 1).toString(16).repeat(64);
  });
  return value;
}

function validFreshContractDeploymentReceipt(intent) {
  const contracts = CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({
    ledger_key: contractKey,
    name,
  }, index) => {
    const creationSequence = FRESH_DEPLOYMENT_TRANSACTION_SPEC.findIndex((spec) => (
      spec.contract_key === contractKey && spec.transaction_type === "CREATE"
    ));
    const contract = {
      name,
      address: address(100 + index),
      runtime_code_hash: bytes32(200 + index),
      deployment_tx_hash: bytes32(300 + index),
      deployment_block: 1_000 + index,
      deployment_block_hash: bytes32(400 + index),
      creation_input_sha256:
        `sha256:${(500 + creationSequence).toString(16).padStart(64, "0")}`,
      receipt_status: "success",
    };
    if (name === "ExecutionPolicyAnchor") {
      contract.deployment_intent_sha256_bytes32 =
        `0x${canonicalArtifactSha256(intent).slice("sha256:".length)}`;
      contract.reviewer_authority_genesis_acceptance_sha256_bytes32 =
        `0x${intent.release.reviewerAuthorityGenesisAcceptanceSha256.slice("sha256:".length)}`;
      contract.authority_commitment_read_proof =
        FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF;
      contract.authority_commitment_read_block = contract.deployment_block;
      contract.authority_commitment_read_block_hash = contract.deployment_block_hash;
    }
    return contract;
  });
  const byKey = Object.fromEntries(
    CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({ ledger_key: key, name }) => [
      key,
      contracts.find((contract) => contract.name === name),
    ]),
  );
  const broadcastTransactions = FRESH_DEPLOYMENT_TRANSACTION_SPEC.map((spec, sequence) => {
    const contract = byKey[spec.contract_key];
    const create = spec.transaction_type === "CREATE";
    return {
      sequence,
      contract_key: spec.contract_key,
      contract_name: spec.name,
      transaction_type: spec.transaction_type,
      function_signature: spec.function_signature,
      transaction_hash: create ? contract.deployment_tx_hash : bytes32(700 + sequence),
      transaction_from: intent.deploymentControl.operatorAddress,
      transaction_to: create ? null : contract.address,
      transaction_nonce: 900 + sequence,
      transaction_input_sha256:
        `sha256:${(500 + sequence).toString(16).padStart(64, "0")}`,
      receipt_status: "success",
      receipt_contract_address: create ? contract.address : null,
      block_number: create ? contract.deployment_block : 2_000 + sequence,
      block_hash: create ? contract.deployment_block_hash : bytes32(600 + sequence),
    };
  });
  return {
    schema: FRESH_CONTRACT_DEPLOYMENT_RECEIPT_SCHEMA,
    network: { chain_id: 84_532, name: "base-sepolia" },
    release_sha: intent.release.releaseSha,
    deployment_intent_sha256: canonicalArtifactSha256(intent),
    reviewer_authority_genesis_acceptance_sha256:
      intent.release.reviewerAuthorityGenesisAcceptanceSha256,
    operator_address: intent.deploymentControl.operatorAddress,
    keystore_account: "dev",
    exact_creation_proof: FRESH_CONTRACT_CREATION_INPUT_PROOF,
    broadcast_transaction_proof: FRESH_CONTRACT_BROADCAST_PROOF,
    broadcast_transactions_sha256: rawSha256(
      Buffer.from(JSON.stringify(sortedObject(broadcastTransactions)), "utf8"),
    ),
    broadcast_transactions: broadcastTransactions,
    contracts,
  };
}

function validLaunchReviewContext() {
  const deploymentIntent = validIntent();
  const freshContractDeploymentReceipt = validFreshContractDeploymentReceipt(
    deploymentIntent,
  );
  const launch = validLaunchIntent();
  launch.release_sha = deploymentIntent.release.releaseSha;
  launch.deployment_intent_sha256 = canonicalArtifactSha256(deploymentIntent);
  launch.contract_deployment_receipt_sha256 =
    `sha256:${freshContractDeploymentReceiptDigest(freshContractDeploymentReceipt, {
      expectedDeploymentIntentSha256: canonicalArtifactSha256(deploymentIntent),
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        deploymentIntent.release.reviewerAuthorityGenesisAcceptanceSha256,
    })}`;
  return {
    launch,
    dependencies: { deploymentIntent, freshContractDeploymentReceipt },
  };
}

function validFinalReviewContext() {
  const { launch, dependencies: launchDependencies } = validLaunchReviewContext();
  const finalAuthority = knownVector();
  const deploymentIntent = launchDependencies.deploymentIntent;
  finalAuthority.release_sha = deploymentIntent.release.releaseSha;
  for (const image of finalAuthority.cvm.images) {
    image.source_digest = deploymentIntent.release.releaseSha;
  }
  finalAuthority.operator_address = deploymentIntent.deploymentControl.operatorAddress;
  finalAuthority.deployment_intent_sha256 = canonicalArtifactSha256(deploymentIntent);
  finalAuthority.cvm_launch_intent_sha256 = `sha256:${cvmLaunchIntentCoreDigest(launch)}`;
  finalAuthority.execution_policy.rollback_anchor_target.writer_release_commitment =
    `0x${cvmLaunchIntentCoreDigest(launch)}`;
  finalAuthority.contracts.compute_credit_vault.developer =
    deploymentIntent.staticContractInputs.computeCreditVault.developer;
  finalAuthority.contracts.compute_credit_vault.developer_fee_bps =
    deploymentIntent.numericPolicy.contract.computeDeveloperFeeBps;
  finalAuthority.contracts.compute_credit_vault.rate_policies.native.developer_fee_bps =
    deploymentIntent.numericPolicy.contract.computeDeveloperFeeBps;
  finalAuthority.contracts.compute_credit_vault.rate_policies.erc20.developer_fee_bps =
    deploymentIntent.numericPolicy.contract.computeDeveloperFeeBps;
  finalAuthority.contracts.email_oracle_auth.upgrade_delay_seconds =
    deploymentIntent.numericPolicy.contract.emailOracleUpgradeDelaySeconds;
  finalAuthority.contracts.tinker_account_encumbrance.account_commitment =
    deploymentIntent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment;
  finalAuthority.contracts.tinker_account_encumbrance.max_add_balance_wei =
    deploymentIntent.numericPolicy.contract.tinkerMaxAddBalanceWei;
  finalAuthority.contracts.tinker_account_encumbrance.max_spend_wei =
    deploymentIntent.numericPolicy.contract.tinkerMaxSpendWei;
  finalAuthority.contracts.tinker_account_encumbrance.release_max_add_balance_wei =
    deploymentIntent.numericPolicy.contract.tinkerMaxAddBalanceWei;
  finalAuthority.contracts.tinker_account_encumbrance.release_max_spend_wei =
    deploymentIntent.numericPolicy.contract.tinkerMaxSpendWei;
  return {
    finalAuthority: normalizeFinalReleaseAuthorityCore(finalAuthority),
    dependencies: { deploymentIntent, cvmLaunchIntent: launch },
  };
}

function descriptorFor(subject) {
  return describeAuthorityReviewSubjectText(canonicalArtifactText(subject));
}

function validEnvelope(descriptor, {
  checkedAtMs = CHECKED_AT_MS,
  evidence = `sha256:${"b".repeat(64)}`,
} = {}) {
  const envelope = createDraftAuthorityReviewEnvelope(
    descriptor.subjectKind,
    descriptor.subjectSha256,
  );
  envelope.approved_at = timestamp(checkedAtMs - 60_000);
  envelope.expires_at = timestamp(checkedAtMs + 24 * 60 * 60 * 1_000);
  envelope.review_evidence_sha256 = evidence;
  envelope.reviewers = [
    { address: address(40), controllerId: "reviewer-root-01" },
    { address: address(41), controllerId: "reviewer-root-02" },
  ];
  return envelope;
}

function errorText(result) {
  return (result.errors || []).map(({ path: field, message }) => `${field}: ${message}`).join("\n");
}

test("tracked templates are canonical, secret-free, and intentionally incomplete", async () => {
  const intentText = await readFile(INTENT_TEMPLATE, "utf8");
  assert.equal(intentText, canonicalArtifactText(createDraftDeploymentIntentCore()));
  let result = parseDeploymentIntentCoreText(intentText);
  assert.equal(result.ok, false);
  assert.match(errorText(result), /releaseSha/);
  assert.match(errorText(result), /reviewerAuthorityCurrentStatusEpoch/);
  assert.match(errorText(result), /reviewerAuthorityCurrentStatusSha256/);
  assert.match(errorText(result), /operatorAddress/);
  assert.match(errorText(result), /staticContractInputs\.computeCreditVault\.developer/);
  assert.match(errorText(result), /staticContractInputs\.tinkerAccountEncumbrance\.accountCommitment/);

  const reviewText = await readFile(REVIEW_TEMPLATE, "utf8");
  assert.equal(reviewText, canonicalArtifactText(createDraftAuthorityReviewEnvelope()));
  const serialized = `${intentText}\n${reviewText}`;
  assert.doesNotMatch(serialized, /private.?key|bearer|password|rpc.?url/i);
});

test("tracked schemas describe separate intent and renewable-envelope artifacts", async () => {
  const intentSchema = JSON.parse(await readFile(INTENT_SCHEMA, "utf8"));
  const reviewSchema = JSON.parse(await readFile(REVIEW_SCHEMA, "utf8"));
  assert.equal(intentSchema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(intentSchema.$id, "https://wikigen.me/schemas/deployment-intent-core.v6.json");
  assert.equal(intentSchema.properties.schema.const, DEPLOYMENT_INTENT_CORE_SCHEMA);
  assert.equal(intentSchema.additionalProperties, false);
  assert.equal(
    intentSchema.properties.staticContractInputs.properties.computeCreditVault
      .properties.developer.$ref,
    "#/$defs/address",
  );
  assert.equal(
    intentSchema.properties.staticContractInputs.properties.tinkerAccountEncumbrance
      .properties.accountCommitment.$ref,
    "#/$defs/bytes32",
  );
  assert.equal(
    intentSchema.properties.release.properties.reviewerAuthorityCurrentStatusEpoch.minimum,
    1,
  );
  assert.equal(
    intentSchema.properties.release.properties.reviewerAuthorityCurrentStatusEpoch.maximum,
    REVIEWER_AUTHORITY_CURRENT_STATUS_MAX_EPOCH,
  );
  assert.equal(
    intentSchema.properties.release.properties.reviewerAuthorityCurrentStatusSha256.pattern,
    "^sha256:[0-9a-f]{64}$",
  );
  assert.equal(
    intentSchema.$defs.emptySet.maxItems,
    0,
  );
  assert.equal(reviewSchema.properties.schema.const, AUTHORITY_REVIEW_ENVELOPE_SCHEMA);
  assert.deepEqual(
    reviewSchema.properties.subject_kind.enum,
    ["deployment_intent", "cvm_launch_intent", "final_release_authority"],
  );
  assert.equal(
    reviewSchema.properties.declaration.const,
    "out_of_band_review_collected_not_signature_verified",
  );
  assert.equal(reviewSchema.additionalProperties, false);
});

test("valid deployment intent has a stable hash-only receipt", () => {
  const intent = validIntent();
  const result = parseDeploymentIntentCoreText(canonicalArtifactText(intent));
  assert.equal(result.ok, true, errorText(result));
  assert.equal(result.receipt.schema, DEPLOYMENT_INTENT_RECEIPT_SCHEMA);
  assert.equal(result.receipt.status, "valid");
  assert.equal(result.receipt.dynamicRuntimeAuthorityCount, 0);
  assert.equal(result.receipt.staticContractInputCount, 2);
  assert.equal(result.receipt.reviewerAuthorityCurrentStatusEpoch, 7);
  assert.equal(
    result.receipt.reviewerAuthorityCurrentStatusSha256,
    `sha256:${"92".repeat(32)}`,
  );
  assert.equal(result.receipt.deploymentIntentSha256, canonicalArtifactSha256(intent));
  assert.equal(result.receipt.deploymentIntentSha256, VALID_INTENT_V6_KAT_SHA256);
  assert.match(result.receipt.deploymentIntentSha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(result.receipt).includes(address(1)), false);
});

test("deployment intent requires exact lowercase nonzero static constructor inputs", () => {
  const cases = [
    [
      "zero developer",
      (intent) => {
        intent.staticContractInputs.computeCreditVault.developer = `0x${"0".repeat(40)}`;
      },
      /lowercase nonzero Ethereum address/,
    ],
    [
      "uppercase developer",
      (intent) => {
        intent.staticContractInputs.computeCreditVault.developer = `0x${"A".repeat(40)}`;
      },
      /lowercase nonzero Ethereum address/,
    ],
    [
      "zero account commitment",
      (intent) => {
        intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment =
          `0x${"0".repeat(64)}`;
      },
      /lowercase nonzero 0x-prefixed bytes32/,
    ],
    [
      "uppercase account commitment",
      (intent) => {
        intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment =
          `0x${"B".repeat(64)}`;
      },
      /lowercase nonzero 0x-prefixed bytes32/,
    ],
  ];
  for (const [label, mutate, expected] of cases) {
    const intent = validIntent();
    mutate(intent);
    const result = validateDeploymentIntentCore(intent);
    assert.equal(result.ok, false, label);
    assert.match(errorText(result), expected, label);
  }

  const extra = validIntent();
  extra.staticContractInputs.computeCreditVault.futureRole = address(4);
  const result = validateDeploymentIntentCore(extra);
  assert.equal(result.ok, false);
  assert.match(errorText(result), /staticContractInputs\.computeCreditVault/);
  assert.match(errorText(result), /exactly the documented fields/);
});

test("deployment intent v6 pins the exact Foundry and Solidity build authority", () => {
  const intent = validIntent();
  assert.equal(validateDeploymentIntentCore(intent).ok, true);

  for (const mutate of [
    (value) => { value.schema = "dnai.deployment-intent-core.v2"; },
    (value) => { value.release.toolchain.foundry.commitSha = "c".repeat(40); },
    (value) => { value.release.toolchain.foundry.buildProfile = "debug"; },
    (value) => { value.release.toolchain.solidity.compilerVersion = "0.8.28"; },
    (value) => { value.release.toolchain.solidity.optimizerRuns = 201; },
    (value) => { value.release.toolchain.solidity.evmVersion = "cancun"; },
    (value) => { value.release.toolchain.solidity.libraries = ["unexpected"] },
  ]) {
    const changed = structuredClone(intent);
    mutate(changed);
    assert.equal(validateDeploymentIntentCore(changed).ok, false);
  }
});

test("deployment intent v6 independently pins the reviewer current-status head", () => {
  const intent = validIntent();
  assert.deepEqual(
    deploymentIntentReviewerAuthorityCurrentStatusBinding(intent),
    {
      reviewerAuthorityCurrentStatusEpoch: 7,
      reviewerAuthorityCurrentStatusSha256: `sha256:${"92".repeat(32)}`,
    },
  );

  const originalDigest = canonicalArtifactSha256(intent);
  const nextEpoch = structuredClone(intent);
  nextEpoch.release.reviewerAuthorityCurrentStatusEpoch = 8;
  assert.notEqual(canonicalArtifactSha256(nextEpoch), originalDigest);
  const nextHead = structuredClone(intent);
  nextHead.release.reviewerAuthorityCurrentStatusSha256 = `sha256:${"93".repeat(32)}`;
  assert.notEqual(canonicalArtifactSha256(nextHead), originalDigest);

  for (const [label, mutate, pattern] of [
    [
      "missing epoch",
      (value) => { delete value.release.reviewerAuthorityCurrentStatusEpoch; },
      /exactly the documented fields/,
    ],
    [
      "zero epoch",
      (value) => { value.release.reviewerAuthorityCurrentStatusEpoch = 0; },
      /integer between 1/,
    ],
    [
      "fractional epoch",
      (value) => { value.release.reviewerAuthorityCurrentStatusEpoch = 1.5; },
      /integer between 1/,
    ],
    [
      "oversized epoch",
      (value) => {
        value.release.reviewerAuthorityCurrentStatusEpoch =
          REVIEWER_AUTHORITY_CURRENT_STATUS_MAX_EPOCH + 1;
      },
      /integer between 1/,
    ],
    [
      "missing digest",
      (value) => { delete value.release.reviewerAuthorityCurrentStatusSha256; },
      /exactly the documented fields/,
    ],
    [
      "zero digest",
      (value) => {
        value.release.reviewerAuthorityCurrentStatusSha256 = `sha256:${"0".repeat(64)}`;
      },
      /exact nonzero guardian-signed reviewer current-status artifact digest/,
    ],
    [
      "bare digest",
      (value) => { value.release.reviewerAuthorityCurrentStatusSha256 = "92".repeat(32); },
      /exact nonzero guardian-signed reviewer current-status artifact digest/,
    ],
  ]) {
    const changed = structuredClone(intent);
    mutate(changed);
    const result = validateDeploymentIntentCore(changed);
    assert.equal(result.ok, false, label);
    assert.match(errorText(result), pattern, label);
    assert.throws(
      () => deploymentIntentReviewerAuthorityCurrentStatusBinding(changed),
      /valid v6 artifact/,
      label,
    );
  }

  const downgraded = structuredClone(intent);
  downgraded.schema = "dnai.deployment-intent-core.v5";
  assert.equal(validateDeploymentIntentCore(downgraded).ok, false);
});

test("deployment intent cannot contain post-deploy authority facts", () => {
  const cases = [
    ["contract address", "contractAddresses", address(10)],
    ["CVM identity", "cvmIdentities", address(11)],
    ["role address", "roleAddresses", address(12)],
    ["release commitment", "releaseCommitments", `sha256:${"c".repeat(64)}`],
    ["anchor state", "downstreamAnchorState", "head-1"],
  ];
  for (const [label, field, value] of cases) {
    const intent = validIntent();
    intent.dynamicRuntimeAuthorities[field].push(value);
    const result = validateDeploymentIntentCore(intent);
    assert.equal(result.ok, false, label);
    assert.match(errorText(result), new RegExp(field), label);
    assert.match(errorText(result), /explicit empty array/, label);
  }
});

test("deployment intent excludes review, self hash, release commitment, and final anchor state", () => {
  const intent = validIntent();
  const text = canonicalArtifactText(intent);
  assert.equal(text.includes("deploymentIntentSha256"), false);
  assert.equal(text.includes("deployment_intent_sha256"), false);
  assert.equal(text.includes("approved_at"), false);
  assert.equal(text.includes("reviewers"), false);
  assert.equal(text.includes("releaseManifestCommitment"), false);
  assert.equal(text.includes("final_authority_sha256"), false);

  intent.deployment_intent_sha256 = canonicalArtifactSha256(intent);
  const result = validateDeploymentIntentCore(intent);
  assert.equal(result.ok, false);
  assert.match(errorText(result), /exactly the documented fields/);
});

test("deployment intent retains strict numeric and QVL bounds", () => {
  const intent = validIntent();
  intent.numericPolicy.contract.tinkerMaxSpendWei = "5000000000000000001";
  let result = validateDeploymentIntentCore(intent);
  assert.equal(result.ok, false);
  assert.match(errorText(result), /must not exceed the reviewed add-balance cap/);

  const overBudget = validIntent();
  for (const policy of Object.values(overBudget.numericPolicy.qvl)) {
    policy.verificationTimeoutSeconds = "20.000001";
  }
  result = validateDeploymentIntentCore(overBudget);
  assert.equal(result.ok, false);
  assert.match(errorText(result), /at most 25 seconds/);

  const inconsistent = validIntent();
  inconsistent.numericPolicy.qvl.arena.rateCapacity = 31;
  result = validateDeploymentIntentCore(inconsistent);
  assert.equal(result.ok, false);
  assert.match(errorText(result), /same reviewed numeric request budget/);
});

test("review subject descriptor validates intent and rejects incomplete final authority", () => {
  const intentDescriptor = descriptorFor(validIntent());
  assert.equal(intentDescriptor.ok, true, errorText(intentDescriptor));
  assert.equal(intentDescriptor.subjectKind, "deployment_intent");
  assert.equal(intentDescriptor.semanticValidation, "deployment_intent_validated");

  const finalAuthority = {
    schema: FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
    deployment_intent_sha256: intentDescriptor.subjectSha256,
    release_sha: "a".repeat(40),
  };
  const finalDescriptor = descriptorFor(finalAuthority);
  assert.equal(finalDescriptor.ok, false);
  assert.match(errorText(finalDescriptor), /final authority subject failed semantic validation/);
});

test("review subject descriptor validates the canonical CVM launch intent", () => {
  const launch = validLaunchIntent();
  const descriptor = describeAuthorityReviewSubjectText(
    canonicalCvmLaunchIntentCoreArtifactText(launch),
  );
  assert.equal(descriptor.ok, true, errorText(descriptor));
  assert.equal(descriptor.subjectKind, "cvm_launch_intent");
  assert.equal(descriptor.subjectSchema, CVM_LAUNCH_INTENT_CORE_SCHEMA);
  assert.equal(descriptor.semanticValidation, "cvm_launch_intent_validated");
  assert.equal(descriptor.subjectSha256, `sha256:${cvmLaunchIntentCoreDigest(launch)}`);
  assert.deepEqual(
    createDraftAuthorityReviewEnvelope(
      descriptor.subjectKind,
      descriptor.subjectSha256,
    ).action_scope,
    REVIEW_SUBJECT_POLICY.cvm_launch_intent.actionScope,
  );
  assert.equal(
    REVIEW_SUBJECT_POLICY.cvm_launch_intent.checkpoint,
    "after_verified_fresh_contract_suite_before_any_phala_cvm_provision_or_commit",
  );
});

test("review envelope binds exact kind, subject bytes, action scope, and checkpoint", () => {
  const descriptor = descriptorFor(validIntent());
  const envelope = validEnvelope(descriptor);
  let result = validateAuthorityReviewEnvelope(envelope, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, true, errorText(result));
  assert.equal(result.receipt.schema, AUTHORITY_REVIEW_RECEIPT_SCHEMA);
  assert.equal(result.receipt.subjectKind, "deployment_intent");
  assert.equal(result.receipt.subjectSha256, descriptor.subjectSha256);
  assert.equal(result.receipt.reviewEnvelopeSha256, canonicalArtifactSha256(envelope));

  envelope.action_scope = [...envelope.action_scope].reverse();
  result = validateAuthorityReviewEnvelope(envelope, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /canonical ordered list/);

  const checkpoint = validEnvelope(descriptor);
  checkpoint.checkpoint = "after_broadcast";
  result = validateAuthorityReviewEnvelope(checkpoint, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /canonical checkpoint/);
});

test("final-authority envelope uses its exact full action scope", () => {
  const { finalAuthority, dependencies } = validFinalReviewContext();
  const descriptor = describeAuthorityReviewSubjectText(
    canonicalFinalReleaseAuthorityCoreArtifactText(finalAuthority),
  );
  const envelope = validEnvelope(descriptor);
  assert.deepEqual(envelope.action_scope, FINAL_RELEASE_AUTHORITY_ACTION_SCOPE);
  assert.equal(envelope.checkpoint, REVIEW_SUBJECT_POLICY.final_release_authority.checkpoint);
  let result = validateAuthorityReviewEnvelope(envelope, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /exact validated dependencies/);
  result = validateAuthorityReviewEnvelope(envelope, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
    authorityDependencies: dependencies,
  });
  assert.equal(result.ok, true, errorText(result));
  assert.equal(result.receipt.actionScopeCount, 8);
});

test("renewable CVM launch review material is excluded from the immutable launch core", () => {
  const { launch, dependencies } = validLaunchReviewContext();
  const descriptor = describeAuthorityReviewSubjectText(
    canonicalCvmLaunchIntentCoreArtifactText(launch),
  );
  const first = validEnvelope(descriptor, {
    checkedAtMs: CHECKED_AT_MS,
    evidence: `sha256:${"b".repeat(64)}`,
  });
  const renewalTime = CHECKED_AT_MS + 2 * 24 * 60 * 60 * 1_000;
  const renewed = validEnvelope(descriptor, {
    checkedAtMs: renewalTime,
    evidence: `sha256:${"c".repeat(64)}`,
  });
  const firstResult = validateAuthorityReviewEnvelope(first, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
    authorityDependencies: dependencies,
  });
  const renewedResult = validateAuthorityReviewEnvelope(renewed, {
    checkedAtMs: renewalTime,
    subjectDescriptor: descriptor,
    authorityDependencies: dependencies,
  });
  assert.equal(firstResult.ok, true, errorText(firstResult));
  assert.equal(renewedResult.ok, true, errorText(renewedResult));
  assert.equal(firstResult.receipt.actionScopeCount, 8);
  assert.equal(firstResult.receipt.subjectSha256, renewedResult.receipt.subjectSha256);
  assert.notEqual(
    firstResult.receipt.reviewEnvelopeSha256,
    renewedResult.receipt.reviewEnvelopeSha256,
  );
  const launchText = canonicalCvmLaunchIntentCoreArtifactText(launch);
  assert.equal(launchText.includes("review_evidence_sha256"), false);
  assert.equal(launchText.includes("review_envelope_sha256"), false);
  assert.equal(launchText.includes("approved_at"), false);
});

test("renewing review changes only envelope hash, never immutable subject hash", () => {
  const intent = validIntent();
  const descriptor = descriptorFor(intent);
  const originalSubjectHash = descriptor.subjectSha256;
  const first = validEnvelope(descriptor, {
    checkedAtMs: CHECKED_AT_MS,
    evidence: `sha256:${"b".repeat(64)}`,
  });
  const renewalTime = CHECKED_AT_MS + 2 * 24 * 60 * 60 * 1_000;
  const renewed = validEnvelope(descriptor, {
    checkedAtMs: renewalTime,
    evidence: `sha256:${"c".repeat(64)}`,
  });
  const firstResult = validateAuthorityReviewEnvelope(first, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
  });
  const renewalResult = validateAuthorityReviewEnvelope(renewed, {
    checkedAtMs: renewalTime,
    subjectDescriptor: descriptor,
  });
  assert.equal(firstResult.ok, true, errorText(firstResult));
  assert.equal(renewalResult.ok, true, errorText(renewalResult));
  assert.notEqual(
    firstResult.receipt.reviewEnvelopeSha256,
    renewalResult.receipt.reviewEnvelopeSha256,
  );
  assert.equal(firstResult.receipt.subjectSha256, originalSubjectHash);
  assert.equal(renewalResult.receipt.subjectSha256, originalSubjectHash);
  assert.equal(canonicalArtifactSha256(intent), originalSubjectHash);
});

test("review envelope fails closed without exact subject bytes or on digest drift", () => {
  const descriptor = descriptorFor(validIntent());
  const envelope = validEnvelope(descriptor);
  let result = validateAuthorityReviewEnvelope(envelope, { checkedAtMs: CHECKED_AT_MS });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /exact canonical subject bytes/);

  envelope.subject_sha256 = `sha256:${"d".repeat(64)}`;
  result = validateAuthorityReviewEnvelope(envelope, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /does not match/);
});

test("review envelope validation requires an explicit caller-observed time", async () => {
  const descriptor = descriptorFor(validIntent());
  const envelope = validEnvelope(descriptor);
  let result = validateAuthorityReviewEnvelope(envelope, {
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /checkedAtMs.*supplied explicitly/);

  result = parseAuthorityReviewEnvelopeText(canonicalArtifactText(envelope), {
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /checkedAtMs.*supplied explicitly/);

  const coreSource = await readFile(
    new URL("./operator-policy-packet-core.mjs", import.meta.url),
    "utf8",
  );
  assert.equal(coreSource.includes("Date.now("), false);
});

test("review time, declaration, order, and reviewer separation remain strict", () => {
  const intent = validIntent();
  const descriptor = descriptorFor(intent);
  const expired = validEnvelope(descriptor);
  expired.expires_at = timestamp(CHECKED_AT_MS);
  let result = validateAuthorityReviewEnvelope(expired, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /must still be active/);

  const falseClaim = validEnvelope(descriptor);
  falseClaim.declaration = "signatures_verified";
  result = validateAuthorityReviewEnvelope(falseClaim, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /not-signature-verified/);

  const reversed = validEnvelope(descriptor);
  reversed.reviewers.reverse();
  result = validateAuthorityReviewEnvelope(reversed, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /canonical controller-id/);

  const collision = validEnvelope(descriptor);
  collision.reviewers[0].address = intent.deploymentControl.operatorAddress;
  result = validateAuthorityReviewEnvelope(collision, {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /must not reuse an address/);
});

test("launch review independence includes validated transitive deployment authority", () => {
  const { launch, dependencies } = validLaunchReviewContext();
  const deploymentIntent = dependencies.deploymentIntent;
  const descriptor = describeAuthorityReviewSubjectText(
    canonicalCvmLaunchIntentCoreArtifactText(launch),
  );
  let result = validateAuthorityReviewEnvelope(validEnvelope(descriptor), {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /exact validated dependencies/);

  const collisions = [
    {
      reviewer: {
        address: deploymentIntent.deploymentControl.operatorAddress,
        controllerId: "reviewer-root-00",
      },
      message: /validated authority dependencies/,
    },
    {
      reviewer: {
        address: deploymentIntent.staticContractInputs.computeCreditVault.developer,
        controllerId: "reviewer-root-00",
      },
      message: /validated authority dependencies/,
    },
    {
      reviewer: {
        address: address(39),
        controllerId: deploymentIntent.deploymentControl.controllerId,
      },
      message: /controller identifier.*validated authority dependencies/,
    },
  ];
  for (const { reviewer, message } of collisions) {
    const envelope = validEnvelope(descriptor);
    envelope.reviewers[0] = reviewer;
    result = validateAuthorityReviewEnvelope(envelope, {
      checkedAtMs: CHECKED_AT_MS,
      subjectDescriptor: descriptor,
      authorityDependencies: dependencies,
    });
    assert.equal(result.ok, false);
    assert.match(errorText(result), message);
  }

  const driftedDependencies = structuredClone(dependencies);
  driftedDependencies.freshContractDeploymentReceipt.operator_address = address(77);
  for (const transaction of driftedDependencies.freshContractDeploymentReceipt
    .broadcast_transactions) {
    transaction.transaction_from = address(77);
  }
  driftedDependencies.freshContractDeploymentReceipt.broadcast_transactions_sha256 =
    rawSha256(Buffer.from(JSON.stringify(sortedObject(
      driftedDependencies.freshContractDeploymentReceipt.broadcast_transactions,
    )), "utf8"));
  result = validateAuthorityReviewEnvelope(validEnvelope(descriptor), {
    checkedAtMs: CHECKED_AT_MS,
    subjectDescriptor: descriptor,
    authorityDependencies: driftedDependencies,
  });
  assert.equal(result.ok, false);
  assert.match(errorText(result), /digest, release, intent, and deployment operator/);
});

test("canonical parser rejects extra fields, duplicate keys, depth, and size", () => {
  const extra = validIntent();
  extra.review = {};
  let result = validateDeploymentIntentCore(extra);
  assert.equal(result.ok, false);
  assert.match(errorText(result), /exactly the documented fields/);

  result = parseDeploymentIntentCoreText(JSON.stringify(validIntent()));
  assert.equal(result.ok, false);
  assert.match(errorText(result), /canonical sorted two-space JSON/);

  const canonical = canonicalArtifactText(validIntent());
  const duplicate = canonical.replace(
    `  "schema": "${DEPLOYMENT_INTENT_CORE_SCHEMA}",`,
    `  "schema": "${DEPLOYMENT_INTENT_CORE_SCHEMA}",\n  "schema": "${DEPLOYMENT_INTENT_CORE_SCHEMA}",`,
  );
  result = parseDeploymentIntentCoreText(duplicate);
  assert.equal(result.ok, false);
  assert.match(errorText(result), /canonical sorted two-space JSON/);

  const nested = '{"x":'.repeat(18) + "null" + "}".repeat(18) + "\n";
  result = parseDeploymentIntentCoreText(nested);
  assert.equal(result.ok, false);
  assert.match(errorText(result), /nesting or node count/);

  result = parseDeploymentIntentCoreText(" ".repeat(MAX_PACKET_BYTES + 1));
  assert.equal(result.ok, false);
  assert.match(errorText(result), new RegExp(`between 1 and ${MAX_PACKET_BYTES}`));
});

test("invalid documents expose paths and rules but not rejected values", () => {
  const rejected = "0xfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed";
  const intent = validIntent();
  intent.deploymentControl.operatorAddress = rejected;
  const result = validateDeploymentIntentCore(intent);
  const serialized = JSON.stringify(validationErrorDocument(result.errors));
  assert.equal(serialized.includes(rejected), false);
  assert.match(serialized, /no_deployment_or_activation_authority_created/);
});

test("CLI intent init/check/hash use create-new and non-symlink semantics", async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "dnai-intent-")));
  try {
    const draftPath = path.join(directory, "intent.json");
    let stdout = "";
    let stderr = "";
    let code = await runOperatorPolicyPacketCli(["init-intent", "--out", draftPath], {
      stdout: (value) => { stdout += value; },
      stderr: (value) => { stderr += value; },
    });
    assert.equal(code, 0, stderr);
    assert.equal(await readFile(draftPath, "utf8"), await readFile(INTENT_TEMPLATE, "utf8"));
    code = await runOperatorPolicyPacketCli(["init-intent", "--out", draftPath], {
      stdout: () => {}, stderr: () => {},
    });
    assert.equal(code, 1);

    const intentPath = path.join(directory, "valid.json");
    const receiptPath = path.join(directory, "receipt.json");
    await writeFile(intentPath, canonicalArtifactText(validIntent()), "utf8");
    stdout = "";
    code = await runOperatorPolicyPacketCli([
      "check-intent", "--in", intentPath, "--receipt-out", receiptPath,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 0, stdout);
    assert.deepEqual(JSON.parse(stdout), JSON.parse(await readFile(receiptPath, "utf8")));

    stdout = "";
    code = await runOperatorPolicyPacketCli(["hash-intent", "--in", intentPath], {
      stdout: (value) => { stdout += value; }, stderr: () => {},
    });
    assert.equal(code, 0, stdout);
    assert.equal(JSON.parse(stdout).sha256, canonicalArtifactSha256(validIntent()));

    const linkPath = path.join(directory, "intent-link.json");
    await symlink(intentPath, linkPath);
    stdout = "";
    code = await runOperatorPolicyPacketCli(["check-intent", "--in", linkPath], {
      stdout: (value) => { stdout += value; }, stderr: () => {},
    });
    assert.equal(code, 1);
    assert.match(stdout, /non-symlink|symbolic links|ELOOP/);

    const directoryLink = path.join(directory, "directory-link");
    await symlink(directory, directoryLink);
    stdout = "";
    code = await runOperatorPolicyPacketCli([
      "check-intent", "--in", path.join(directoryLink, "valid.json"),
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 1);
    assert.match(stdout, /must not contain symbolic links/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("CLI review init/check/hash binds exact canonical deployment-intent bytes", async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "dnai-review-")));
  try {
    const intent = validIntent();
    const intentDescriptor = descriptorFor(intent);
    const subjectPath = path.join(directory, "deployment-intent.json");
    const reviewPath = path.join(directory, "review.json");
    await writeFile(subjectPath, canonicalArtifactText(intent), "utf8");
    let stdout = "";
    let code = await runOperatorPolicyPacketCli([
      "init-review", "--subject", subjectPath, "--out", reviewPath,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 0, stdout);
    const draft = JSON.parse(await readFile(reviewPath, "utf8"));
    assert.equal(draft.subject_kind, "deployment_intent");
    assert.equal(draft.subject_sha256, canonicalArtifactSha256(intent));

    const descriptor = descriptorFor(intent);
    await writeFile(reviewPath, canonicalArtifactText(validEnvelope(descriptor)), "utf8");
    stdout = "";
    code = await runOperatorPolicyPacketCli([
      "check-review", "--subject", subjectPath, "--in", reviewPath,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 0, stdout);
    const receipt = JSON.parse(stdout);
    assert.equal(receipt.subjectKind, "deployment_intent");
    assert.equal(receipt.subjectSemanticValidation, "deployment_intent_validated");

    stdout = "";
    code = await runOperatorPolicyPacketCli([
      "hash-review", "--subject", subjectPath, "--in", reviewPath,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 0, stdout);
    assert.equal(
      JSON.parse(stdout).sha256,
      canonicalArtifactSha256(validEnvelope(descriptor)),
    );

    intent.release.releaseSha = "c".repeat(40);
    intent.release.reviewerAuthorityGenesisAcceptanceSha256 = `sha256:${"91".repeat(32)}`;
    await writeFile(subjectPath, canonicalArtifactText(intent), "utf8");
    stdout = "";
    code = await runOperatorPolicyPacketCli([
      "check-review", "--subject", subjectPath, "--in", reviewPath,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 1);
    assert.match(stdout, /does not match/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("CLI requires digest-linked transitive dependencies for launch and final reviews", async () => {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "dnai-review-deps-")));
  try {
    const { launch, dependencies } = validLaunchReviewContext();
    const launchDescriptor = describeAuthorityReviewSubjectText(
      canonicalCvmLaunchIntentCoreArtifactText(launch),
    );
    const launchPath = path.join(directory, "launch.json");
    const intentPath = path.join(directory, "intent.json");
    const receiptPath = path.join(directory, "contract-receipt.json");
    const launchReviewPath = path.join(directory, "launch-review.json");
    await writeFile(launchPath, canonicalCvmLaunchIntentCoreArtifactText(launch), "utf8");
    await writeFile(intentPath, canonicalArtifactText(dependencies.deploymentIntent), "utf8");
    await writeFile(
      receiptPath,
      canonicalArtifactText(dependencies.freshContractDeploymentReceipt),
      "utf8",
    );

    let stdout = "";
    let code = await runOperatorPolicyPacketCli([
      "init-review", "--subject", launchPath, "--out", launchReviewPath,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 1);
    assert.match(stdout, /requires exactly --deployment-intent and --contract-receipt/);

    stdout = "";
    code = await runOperatorPolicyPacketCli([
      "init-review",
      "--subject", launchPath,
      "--deployment-intent", intentPath,
      "--contract-receipt", receiptPath,
      "--out", launchReviewPath,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 0, stdout);
    await writeFile(
      launchReviewPath,
      canonicalArtifactText(validEnvelope(launchDescriptor)),
      "utf8",
    );

    stdout = "";
    code = await runOperatorPolicyPacketCli([
      "check-review", "--subject", launchPath, "--in", launchReviewPath,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 1);
    assert.match(stdout, /requires exactly --deployment-intent and --contract-receipt/);

    stdout = "";
    code = await runOperatorPolicyPacketCli([
      "check-review",
      "--subject", launchPath,
      "--deployment-intent", intentPath,
      "--contract-receipt", receiptPath,
      "--in", launchReviewPath,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 0, stdout);

    const { finalAuthority, dependencies: finalDependencies } = validFinalReviewContext();
    const finalPath = path.join(directory, "final.json");
    const finalLaunchPath = path.join(directory, "final-launch.json");
    const finalIntentPath = path.join(directory, "final-intent.json");
    const finalReviewPath = path.join(directory, "final-review.json");
    const finalDescriptor = describeAuthorityReviewSubjectText(
      canonicalFinalReleaseAuthorityCoreArtifactText(finalAuthority),
    );
    await writeFile(finalPath, canonicalFinalReleaseAuthorityCoreArtifactText(finalAuthority), "utf8");
    await writeFile(
      finalLaunchPath,
      canonicalCvmLaunchIntentCoreArtifactText(finalDependencies.cvmLaunchIntent),
      "utf8",
    );
    await writeFile(finalIntentPath, canonicalArtifactText(finalDependencies.deploymentIntent), "utf8");
    await writeFile(finalReviewPath, canonicalArtifactText(validEnvelope(finalDescriptor)), "utf8");

    stdout = "";
    code = await runOperatorPolicyPacketCli([
      "check-review",
      "--subject", finalPath,
      "--deployment-intent", finalIntentPath,
      "--cvm-launch-intent", finalLaunchPath,
      "--in", finalReviewPath,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 0, stdout);

    const collidingEnvelope = validEnvelope(launchDescriptor);
    collidingEnvelope.reviewers[0] = {
      address: dependencies.deploymentIntent.deploymentControl.operatorAddress,
      controllerId: "reviewer-root-00",
    };
    await writeFile(launchReviewPath, canonicalArtifactText(collidingEnvelope), "utf8");
    stdout = "";
    code = await runOperatorPolicyPacketCli([
      "check-review",
      "--subject", launchPath,
      "--deployment-intent", intentPath,
      "--contract-receipt", receiptPath,
      "--in", launchReviewPath,
    ], { stdout: (value) => { stdout += value; }, stderr: () => {} });
    assert.equal(code, 1);
    assert.match(stdout, /validated authority dependencies/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("legacy packet commands fail explicitly instead of creating ambiguous authority", async () => {
  let stderr = "";
  const code = await runOperatorPolicyPacketCli(["init", "--out", "/tmp/never"], {
    stdout: () => {},
    stderr: (value) => { stderr += value; },
  });
  assert.equal(code, 2);
  assert.match(stderr, /unknown or retired command/);
  assert.deepEqual(DEPLOYMENT_INTENT_ACTION_SCOPE, REVIEW_SUBJECT_POLICY.deployment_intent.actionScope);
  assert.equal(
    DEPLOYMENT_INTENT_ACTION_SCOPE[1],
    "precommitted_signed_reviewer_authority_genesis_acceptance",
  );
  assert.equal(
    DEPLOYMENT_INTENT_ACTION_SCOPE[2],
    "precommitted_guardian_signed_reviewer_authority_current_status_head",
  );
  assert.equal(DEPLOYMENT_INTENT_ACTION_SCOPE[5], "static_contract_inputs");
});
