import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS,
  CANONICAL_SEVEN_CVM_AUTHORITY_FRESH_MODE,
  CANONICAL_SEVEN_CVM_AUTHORITY_FRESH_TRUTH,
  CANONICAL_SEVEN_CVM_AUTHORITY_HISTORICAL_MODE,
  CANONICAL_SEVEN_CVM_AUTHORITY_HISTORICAL_TRUTH,
  CANONICAL_SEVEN_CVM_AUTHORITY_VALIDATION_SOURCE,
  CANONICAL_SEVEN_CVM_AUTHORITY_VALIDATION_STATUS,
  CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS,
  CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE,
  CONTRACT_STATELESS_POSTSTATE_EXCEPTION,
  CVM_COMPOSE_PHASE_GATE_SCHEMA,
  CVM_TOPOLOGY_SCHEMA,
  FORBIDDEN_LEGACY_PRIVATE_KEY_NAMES,
  INTERNAL_RUNTIME_CREDENTIAL_GROUPS,
  PHALA_RELEASE_MANIFEST_SIGSTORE_VERIFICATION_MISSING,
  REQUIRED_RUNTIME_CREDENTIALS,
  REQUIRED_PRODUCTION_SERVICES,
  activationReadinessRpcEndpointDigest,
  activationReadinessRpcOriginDigest,
  activationReadinessSnapshotDigest,
  createActivationReadinessSnapshot,
  assertReportContainsNoSensitiveValues,
  buildPreflightReport,
  formatHumanReport,
  inspectCvmTopology,
  inspectCompose,
  inspectImageRelease,
  parseEnvText,
  sensitiveValues,
} from "./activation-preflight-core.mjs";
import {
  CLOUDFLARE_AUTH_PROBE_TIMEOUT_MS,
  SEMANTIC_VALIDATOR_INPUT_FLAGS,
  assertReadOnlyInvocation,
  githubAttestationArgs,
  githubReleaseManifestAttestationArgs,
  finalPoststatePolicies,
  inspectFreshContractDeploymentReceipt,
  inspectFile,
  parseArgs as parsePreflightArgs,
  parseSemanticValidationReceipt,
  probeCloudflareAuthentication,
  releaseScopedLedgerPath,
  resolveEvidencePaths,
  inspectInstalledCliVersion,
  resolveExecutablePath,
  runSemanticReleaseValidation,
  runStableSemanticReleaseValidation,
  semanticValidationEnvironment,
  semanticValidatorArgs,
  validateAuthorityReviewEvidence,
  validateProjectedEnvironment,
  validateStableFileBindings,
  verifyContractDeploymentChainEvidence,
  verifyContractDeploymentChainEvidenceWithTestAdapters,
} from "./activation-preflight.mjs";
import { knownVector as finalAuthorityFixture } from "./execution-policy-release-core.fixture.mjs";
import {
  DEPLOYMENT_TOOLCHAIN_AUTHORITY,
  DEPLOYMENT_INTENT_CORE_SCHEMA,
} from "./operator-policy-packet-core.mjs";
import {
  FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
} from "./execution-policy-release-core.mjs";
import {
  LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
  RELEASE_SCHEMA,
  SEMANTIC_VALIDATION_SCHEMA,
  SEMANTIC_VALIDATION_STATUS,
  SEMANTIC_VALIDATION_TRUTH_STATUS,
} from "../web/scripts/release-env-core.mjs";
import {
  FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
  FRESH_CONTRACT_BROADCAST_PROOF,
  FRESH_CONTRACT_CREATION_INPUT_PROOF,
  FRESH_DEPLOYMENT_TRANSACTION_SPEC,
  freshContractDeploymentReceiptDigest,
  projectFreshContractDeploymentReceipt,
  rawSha256,
} from "./cvm-launch-intent-core.mjs";
import {
  FRESH_CONTRACT_RELEASE_RECONSTRUCTION_SCHEMA,
  FRESH_CONTRACT_RELEASE_RECONSTRUCTION_TRUTH_STATUS,
  freshContractReleaseReconstructionDigest,
} from "./fresh-contract-release-reconstruction.mjs";

const SHA = "a".repeat(40);
const DEPLOYMENT_INTENT_SHA256 = `sha256:${"a1".repeat(32)}`;
const REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256 =
  `sha256:${"c1".repeat(32)}`;
const FRESH_RECEIPT_AUTHORITY_PINS = Object.freeze({
  expectedDeploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
  expectedReviewerAuthorityGenesisAcceptanceSha256:
    REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
});
const FINAL_AUTHORITY_SHA256 = `sha256:${"a2".repeat(32)}`;
const CEREMONY_AUTHORIZATION_SHA256 = `sha256:${"c2".repeat(32)}`;
const LIVE_ACTIVATION_AUTHORITY_SHA256 = `sha256:${"c3".repeat(32)}`;
const RELEASE_INPUTS_SHA256 = `sha256:${"c4".repeat(32)}`;
const RELEASE_ENV_SHA256 = `sha256:${"c5".repeat(32)}`;
const FRONTEND_BUILD_SHA256 = `sha256:${"c6".repeat(32)}`;
const COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SHA256 =
  `sha256:${"c7".repeat(32)}`;
const COMPUTE_WORKLOAD_BROWSER_BINDING_SHA256 = `sha256:${"c8".repeat(32)}`;
const FRONTEND_BUILD_CANDIDATE_RECEIPT_SHA256 = `sha256:${"c9".repeat(32)}`;
const REVIEW_ENVELOPE_SHA256 = `sha256:${"a3".repeat(32)}`;
const REVIEW_EVIDENCE_SHA256 = `sha256:${"a4".repeat(32)}`;
const CVM_LAUNCH_INTENT_SHA256 = `sha256:${"a5".repeat(32)}`;
const CVM_LAUNCH_REVIEW_ENVELOPE_SHA256 = `sha256:${"b3".repeat(32)}`;
const CVM_LAUNCH_REVIEW_EVIDENCE_SHA256 = `sha256:${"b4".repeat(32)}`;
const RELEASE_MANIFEST_SIGSTORE_RECEIPT_SHA256 =
  `sha256:${"b5".repeat(32)}`;
const RELEASE_MANIFEST_SIGSTORE_RECEIPT_FILE_SHA256 = "b6".repeat(32);
const TEST_RPC_ENDPOINT = "https://primary.base-sepolia.fixture.invalid/rpc";
const TEST_SECONDARY_RPC_ENDPOINT =
  "https://secondary.base-sepolia.fixture.invalid/rpc";
const TEST_RPC_ORIGIN = "https://primary.base-sepolia.fixture.invalid";
const TEST_SECONDARY_RPC_ORIGIN =
  "https://secondary.base-sepolia.fixture.invalid";
const semanticAuthorityExpectation = () => ({
  releaseSha: SHA,
  deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
  reviewerAuthorityGenesisAcceptanceSha256:
    REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
  ceremonyAuthorizationSha256: CEREMONY_AUTHORIZATION_SHA256,
  liveActivationAuthoritySha256: LIVE_ACTIVATION_AUTHORITY_SHA256,
  runtimeAuthorityDependencySha256: FINAL_AUTHORITY_SHA256,
  computeWorkloadActivationObservationSha256:
    COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SHA256,
  computeWorkloadBrowserBindingSha256:
    COMPUTE_WORKLOAD_BROWSER_BINDING_SHA256,
  frontendBuildCandidateReceiptSha256:
    FRONTEND_BUILD_CANDIDATE_RECEIPT_SHA256,
});
const semanticReceiptFixture = () => ({
  schema: SEMANTIC_VALIDATION_SCHEMA,
  status: SEMANTIC_VALIDATION_STATUS,
  truth_status: SEMANTIC_VALIDATION_TRUTH_STATUS,
  release_sha: SHA,
  chain_id: 84_532,
  deployment_intent_sha256: DEPLOYMENT_INTENT_SHA256,
  reviewer_authority_genesis_acceptance_sha256:
    REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
  ceremony_authorization_sha256: CEREMONY_AUTHORIZATION_SHA256,
  live_activation_authority_sha256: LIVE_ACTIVATION_AUTHORITY_SHA256,
  runtime_authority_dependency_sha256: FINAL_AUTHORITY_SHA256,
  compute_workload_activation_observation_sha256:
    COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SHA256,
  compute_workload_browser_binding_sha256:
    COMPUTE_WORKLOAD_BROWSER_BINDING_SHA256,
  frontend_build_candidate_receipt_sha256:
    FRONTEND_BUILD_CANDIDATE_RECEIPT_SHA256,
  release_inputs_sha256: RELEASE_INPUTS_SHA256,
  release_env_sha256: RELEASE_ENV_SHA256,
  frontend_build_sha256: FRONTEND_BUILD_SHA256,
  raw_secret_egress: false,
});
const semanticPathKey = (flag) => flag.slice(2).replace(
  /-([a-z])/g,
  (_match, letter) => letter.toUpperCase(),
);
function semanticPaths(directory = "/tmp/dnai-preflight-exact37") {
  return Object.fromEntries(SEMANTIC_VALIDATOR_INPUT_FLAGS.map((flag) => [
    semanticPathKey(flag),
    path.join(directory, `${flag.slice(2)}.json`),
  ]));
}
const address = (digit) => `0x${digit.repeat(40)}`;
const bytes32 = (digit) => `0x${digit.repeat(64)}`;
const image = (name, digit) =>
  `ghcr.io/therealwiki/dnai-wikigen/${name}@sha256:${digit.repeat(64)}`;
const internalCredential = (digit) => `secret_${digit.repeat(36)}`;
const canonicalSevenCvmAuthorityValidation = ({
  authorityStage = "live_activation",
} = {}) => {
  const fresh = authorityStage === "release_ceremony";
  return {
    source: CANONICAL_SEVEN_CVM_AUTHORITY_VALIDATION_SOURCE,
    status: CANONICAL_SEVEN_CVM_AUTHORITY_VALIDATION_STATUS,
    truthStatus: fresh
      ? CANONICAL_SEVEN_CVM_AUTHORITY_FRESH_TRUTH
      : CANONICAL_SEVEN_CVM_AUTHORITY_HISTORICAL_TRUTH,
    evidenceMode: fresh
      ? CANONICAL_SEVEN_CVM_AUTHORITY_FRESH_MODE
      : CANONICAL_SEVEN_CVM_AUTHORITY_HISTORICAL_MODE,
    chainId: 84_532,
    releaseSha: SHA,
    deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
    ceremonyNonce: bytes32("1"),
    authorityChainSubjectSha256: `sha256:${"11".repeat(32)}`,
    dependencyGraphSha256: `sha256:${"12".repeat(32)}`,
    descriptorRuntimeAuthoritySha256: `sha256:${"13".repeat(32)}`,
    historicalTranscriptFileSetSha256: `sha256:${"14".repeat(32)}`,
    measurementPolicySetSha256: `sha256:${"15".repeat(32)}`,
    releaseAuthoritySha256: `sha256:${"16".repeat(32)}`,
    sevenCvmLaunchCompletionReceiptSha256: `sha256:${"17".repeat(32)}`,
    sevenCvmVerifiedEvidenceSetSha256: `sha256:${"18".repeat(32)}`,
    allSevenMachineVerified: true,
    canonicalDependencyChainVerified: true,
    rawQuotePersisted: false,
    rawSecretEgress: false,
  };
};

function imageReleaseManifest() {
  const names = [
    ["tinker-delegate", "7"],
    ["tee-email-oracle", "9"],
    ["neko-chrome", "8"],
    ["attestation-qvl", "b"],
    ["compute-metering", "c"],
  ];
  return {
    schema: "dnai.tee-image-release.v1",
    release_sha: SHA,
    source_ref: "refs/heads/main",
    generated_at: "2026-07-15T12:00:00.000Z",
    source_repository: "therealwiki/dnai-wikigen",
    signer_workflow: "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
    workflow_run_id: "12345",
    workflow_run_url: "https://github.com/therealwiki/dnai-wikigen/actions/runs/12345",
    platform: "linux/amd64",
    images: names.map(([name, digit], index) => {
      const repository = `ghcr.io/therealwiki/dnai-wikigen/${name}`;
      const digest = `sha256:${digit.repeat(64)}`;
      return {
        name,
        repository,
        digest,
        image: `${repository}@${digest}`,
        platform: "linux/amd64",
        sbom_artifact: {
          filename: `${name}.spdx.json`,
          sha256: String((index + 1) % 10).repeat(64),
        },
        provenance_subject: { name: repository, digest },
        attestations: {
          provenance: {
            predicate_type: "https://slsa.dev/provenance/v1",
            id: String(index + 1),
            url: `https://github.com/therealwiki/dnai-wikigen/attestations/${index + 1}`,
          },
          sbom: {
            predicate_type: "https://spdx.dev/Document/v2.3",
            id: String(index + 11),
            url: `https://github.com/therealwiki/dnai-wikigen/attestations/${index + 11}`,
          },
        },
        verification: {
          repo: "therealwiki/dnai-wikigen",
          signer_workflow: "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
          source_digest: SHA,
          source_ref: "refs/heads/main",
          provenance_attestation: "verified",
          sbom_attestation: "verified",
        },
      };
    }),
  };
}

function releaseMetadata(domain) {
  return {
    schema: CVM_TOPOLOGY_SCHEMA,
    release_sha: SHA,
    source_ref: "refs/heads/main",
    platform: "linux/amd64",
    trust_domain: domain,
    deployment_status: "rendered_not_deployed",
  };
}

function inspectedCompose(document) {
  return {
    valid: true,
    document,
    services: Object.fromEntries(Object.entries(document.services).map(([name, service]) => [
      name,
      { ...service, raw: JSON.stringify(service) },
    ])),
  };
}

function hardened(imageRef, extra = {}) {
  return {
    image: imageRef,
    platform: "linux/amd64",
    read_only: true,
    cap_drop: ["ALL"],
    security_opt: ["no-new-privileges:true"],
    ...extra,
  };
}

function freshContractLedgerFixture() {
  const operator = address("1");
  const names = [
    "challengeRegistry",
    "computeCreditVault",
    "diligenceRoom",
    "emailOracleAuth",
    "executionPolicyAnchor",
    "royaltyDistributor",
    "tinkerAccountEncumbrance",
  ];
  const digits = ["2", "3", "4", "5", "6", "7", "8"];
  const hex32 = (value) => `0x${value.toString(16).padStart(64, "0")}`;
  const contracts = Object.fromEntries(names.map((name, index) => [name, {
    address: address(digits[index]),
    runtimeCodeHash: bytes32(digits[index]),
    deploymentTx: hex32(100 + index),
    deploymentBlock: 1_000 + index,
    deploymentBlockHash: hex32(200 + index),
    deploymentReceiptStatus: "success",
    deploymentTxFrom: operator,
    deploymentReceiptContractAddress: address(digits[index]),
    sourceCommit: SHA,
  }]));
  Object.assign(contracts.challengeRegistry, {
    status: "deployed_empty_active_registry",
    owner: operator,
    registryPaused: false,
    challengeCount: 0,
    nextChallengeId: 1,
  });
  Object.assign(contracts.executionPolicyAnchor, {
    deploymentIntentSha256Bytes32:
      `0x${DEPLOYMENT_INTENT_SHA256.slice("sha256:".length)}`,
    reviewerAuthorityGenesisAcceptanceSha256Bytes32:
      `0x${REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256.slice("sha256:".length)}`,
    authorityCommitmentReadProof: FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
    authorityCommitmentReadBlock: contracts.executionPolicyAnchor.deploymentBlock,
    authorityCommitmentReadBlockHash:
      contracts.executionPolicyAnchor.deploymentBlockHash,
  });
  const broadcastTransactions = FRESH_DEPLOYMENT_TRANSACTION_SPEC.map(
    (spec, sequence) => {
      const contract = contracts[spec.contract_key];
      const create = spec.transaction_type === "CREATE";
      const input = fixtureTransactionInput(sequence);
      const transactionInputSha256 = rawSha256(Buffer.from(input.slice(2), "hex"));
      if (create) contract.creationInputSha256 = transactionInputSha256;
      return {
        sequence,
        contractKey: spec.contract_key,
        contractName: spec.name,
        transactionType: spec.transaction_type,
        functionSignature: spec.function_signature,
        transactionHash: create ? contract.deploymentTx : hex32(300 + sequence),
        transactionFrom: operator,
        transactionTo: create ? null : contract.address,
        transactionNonce: 400 + sequence,
        transactionInputSha256,
        receiptStatus: "success",
        receiptContractAddress: create ? contract.address : null,
        blockNumber: create ? contract.deploymentBlock : 1_100 + sequence,
        blockHash: create ? contract.deploymentBlockHash : hex32(500 + sequence),
      };
    },
  );
  const normalizedBroadcastTransactions = broadcastTransactions.map((entry) => ({
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
  const sortedObject = (value) => {
    if (Array.isArray(value)) return value.map((item) => sortedObject(item));
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
    );
  };
  const broadcastTransactionsSha256 = rawSha256(Buffer.from(
    JSON.stringify(sortedObject(normalizedBroadcastTransactions)),
    "utf8",
  ));
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
      address: operator,
      keystoreAccount: "dev",
      privateKeyMaterial: "not_used",
    },
    freshDeployment: {
      contractSuite: {
        status: "broadcast_complete_pending_cvm_binding",
        sourceCommit: SHA,
        deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
        reviewerAuthorityGenesisAcceptanceSha256:
          REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
        keystoreAccount: "dev",
        runtimeCodeProof: "exact_creation_reexecution_match_all_contracts",
        exactCreationInputProof: FRESH_CONTRACT_CREATION_INPUT_PROOF,
        broadcastTransactionProof: FRESH_CONTRACT_BROADCAST_PROOF,
        broadcastTransactionCount: FRESH_DEPLOYMENT_TRANSACTION_SPEC.length,
        broadcastTransactionsSha256,
        broadcastTransactions,
      },
    },
    contracts,
    deploymentHistory: [{
      kind: "fresh_reviewed_scope_contract_suite",
      sourceCommit: SHA,
      deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
      reviewerAuthorityGenesisAcceptanceSha256:
        REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
      broadcastTransactionsSha256,
    }],
  };
}

function fixtureTransactionInput(sequence) {
  return `0x${(700 + sequence).toString(16).padStart(8, "0")}`;
}

function independentReconstructionFixture(receipt) {
  const payload = {
    schema: FRESH_CONTRACT_RELEASE_RECONSTRUCTION_SCHEMA,
    truth_status: FRESH_CONTRACT_RELEASE_RECONSTRUCTION_TRUTH_STATUS,
    release_sha: SHA,
    deployment_intent_sha256: DEPLOYMENT_INTENT_SHA256,
    reviewer_authority_genesis_acceptance_sha256:
      REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
    network: {
      chain_id: 84_532,
      name: "base-sepolia",
      snapshot_block: 2_000,
      snapshot_block_hash: bytes32("d"),
    },
    operator_address: address("1"),
    source_proof: {
      canonical_forge_script:
        "⚙️/tinker-delegate/contracts/script/DeployFreshSuite.s.sol",
      clean_worktree: true,
      detached_head: true,
      submodules_clean: true,
      toolchain: structuredClone(DEPLOYMENT_TOOLCHAIN_AUTHORITY),
      worktree_head: SHA,
    },
    transactions: FRESH_DEPLOYMENT_TRANSACTION_SPEC.map((spec, sequence) => {
      const create = spec.transaction_type === "CREATE";
      const contract = create
        ? receipt.contracts.find(({ name }) => name === spec.name)
        : null;
      const expectedInput = fixtureTransactionInput(sequence);
      return {
        sequence,
        contract_key: spec.contract_key,
        contract_name: spec.name,
        transaction_type: spec.transaction_type,
        function_signature: spec.function_signature,
        expected_input: expectedInput,
        expected_input_sha256: rawSha256(Buffer.from(expectedInput.slice(2), "hex")),
        expected_runtime_code_hash: create ? contract.runtime_code_hash : null,
      };
    }),
  };
  return {
    ...payload,
    reconstruction_sha256: freshContractReleaseReconstructionDigest(payload),
  };
}

function contractDeploymentChainEvidenceFixture(poststateMode = "final_active_frozen") {
  const immutableProvenance = [
    "ChallengeRegistry",
    "ComputeCreditVault",
    "DiligenceRoom",
    "EmailOracleAuth",
    "ExecutionPolicyAnchor",
    "RoyaltyDistributor",
    "TinkerAccountEncumbrance",
  ].map((name) => ({
    name,
    ...Object.fromEntries(
      CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS.map((field) => [field, true]),
    ),
  }));
  const poststates = Object.entries(CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE[poststateMode])
    .map(([name, assertions]) => ({ name, valid: true, assertions: [...assertions] }));
  const receipt = projectFreshContractDeploymentReceipt(freshContractLedgerFixture(), {
    releaseSha: SHA,
    ...FRESH_RECEIPT_AUTHORITY_PINS,
  });
  const broadcastTransactionProvenance = FRESH_DEPLOYMENT_TRANSACTION_SPEC.map(
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
  );
  return {
    evidenceSource: "production_collector",
    valid: true,
    readOnly: true,
    chainId: 84_532,
    secondaryChainId: 84_532,
    rpcEndpointSha256: activationReadinessRpcEndpointDigest(TEST_RPC_ENDPOINT),
    secondaryRpcEndpointSha256: activationReadinessRpcEndpointDigest(
      TEST_SECONDARY_RPC_ENDPOINT,
    ),
    rpcOriginSha256: activationReadinessRpcOriginDigest(TEST_RPC_ORIGIN),
    secondaryRpcOriginSha256: activationReadinessRpcOriginDigest(
      TEST_SECONDARY_RPC_ORIGIN,
    ),
    rpcEndpointsDistinct: true,
    secondaryFinalizedSnapshotVerified: true,
    secondaryFinalizedTagRechecked: true,
    snapshotBlockNumber: 2_000,
    snapshotBlockHash: bytes32("d"),
    snapshotFinality: "rpc_finalized",
    finalizedTagRechecked: true,
    finalizedRecheckBlockNumber: 2_000,
    finalizedRecheckBlockHash: bytes32("d"),
    snapshotBlockHashVerified: true,
    commonSnapshotBlock: true,
    contractCount: 7,
    transactionCount: 7,
    deployerMatchCount: 7,
    creationTransactionCount: 7,
    receiptCount: 7,
    successfulReceiptCount: 7,
    contractAddressMatchCount: 7,
    deploymentBlockMatchCount: 7,
    deploymentBlockHashMatchCount: 7,
    runtimeCodeMatchCount: 7,
    immutableProvenanceContractCount: 7,
    immutableProvenanceValid: true,
    immutableProvenance,
    broadcastTransactionCount: FRESH_DEPLOYMENT_TRANSACTION_SPEC.length,
    broadcastTransactionValidCount: FRESH_DEPLOYMENT_TRANSACTION_SPEC.length,
    broadcastTransactionsSha256: receipt.broadcast_transactions_sha256,
    broadcastTransactionProvenanceValid: true,
    broadcastTransactionProvenance,
    primaryBroadcastTransactionObservationsSha256: `sha256:${"7".repeat(64)}`,
    secondaryBroadcastTransactionObservationsSha256: `sha256:${"7".repeat(64)}`,
    broadcastTransactionRpcAgreement: true,
    independentReconstructionValid: true,
    independentReconstructionSha256: `sha256:${"6".repeat(64)}`,
    independentReconstructionRpcAgreement: true,
    secondaryRuntimeCodeMatchCount: 7,
    poststateMode,
    poststateContractCount: 6,
    poststateValid: true,
    poststates,
    primaryPoststateObservationsSha256: `sha256:${"8".repeat(64)}`,
    secondaryPoststateContractCount: 6,
    secondaryPoststateValid: true,
    secondaryPoststateObservationsSha256: `sha256:${"8".repeat(64)}`,
    poststateRpcAgreement: true,
    statelessPoststateException: CONTRACT_STATELESS_POSTSTATE_EXCEPTION,
  };
}

function freshDeploymentIntentForChainFixture() {
  return {
    release: {
      reviewerAuthorityGenesisAcceptanceSha256:
        REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
    },
    network: { chainId: 84_532 },
    deploymentControl: { operatorAddress: address("1") },
    scope: { contracts: ["ChallengeRegistry"] },
    dynamicRuntimeAuthorities: { contractAddresses: [], roleAddresses: [] },
    staticContractInputs: {
      computeCreditVault: { developer: address("3") },
      tinkerAccountEncumbrance: { accountCommitment: bytes32("5") },
    },
    numericPolicy: {
      contract: {
        computeDeveloperFeeBps: 100,
        diligenceFeeBps: 100,
        emailOracleUpgradeDelaySeconds: 172_800,
        tinkerMaxAddBalanceWei: "5000000000000000000",
        tinkerMaxSpendWei: "5000000000000000000",
      },
    },
  };
}

function freshChainRunner(receipt, {
  challengeNextId = "1",
  codeHashDrift = false,
  secondaryCodeHashDrift = false,
  secondaryChainIdDrift = false,
  secondaryInitialFinalizedHeaderDrift = false,
  secondarySnapshotHeaderDrift = false,
  secondaryHistoricalBlockHeaderDrift = false,
  inputDriftSequence = null,
  snapshotHashDrift = false,
  omitConsensusRoots = false,
  primaryFinalityRetreat = false,
  secondaryFinalityRetreat = false,
  secondaryTxDrift = null,
  secondaryReceiptDrift = null,
  secondaryPoststateDrift = false,
  secondaryHistoricalStateUnavailable = false,
} = {}) {
  const byAddress = new Map(receipt.contracts.map((entry) => [entry.address, entry]));
  const byTx = new Map(receipt.broadcast_transactions.map((entry) => [
    entry.transaction_hash,
    entry,
  ]));
  let snapshotReads = 0;
  let primaryFinalizedReads = 0;
  let secondaryFinalizedReads = 0;
  // Structurally complete synthetic headers exercise the verifier only. Their
  // hashes are intentionally not presented as authentic network observations.
  const blockFixture = (number, hash, { stateRoot = bytes32("2"), receiptsRoot = bytes32("4") } = {}) => ({
    number,
    hash,
    ...(omitConsensusRoots ? {} : {
      parentHash: bytes32("1"),
      stateRoot,
      transactionsRoot: bytes32("3"),
      receiptsRoot,
    }),
  });
  const callValue = (name, signature) => {
    if (signature === "owner()(address)") return receipt.operator_address;
    if (signature === "developer()(address)") {
      return name === "ComputeCreditVault" ? address("3") : receipt.operator_address;
    }
    if (signature.endsWith("(address)")) return address("0");
    if (signature === "accountCommitment()(bytes32)") return bytes32("5");
    if (["approvedComposeRoot()(bytes32)", "computeComposeRoot(bytes32[])(bytes32)"].includes(signature)) {
      return bytes32("e");
    }
    if (["managerRoot()(bytes32)", "computeManagerRoot(address[])(bytes32)"].includes(signature)) {
      return bytes32("f");
    }
    if (signature === "evaluatorPolicies()(bytes32[3])") {
      return [[bytes32("0"), bytes32("0"), bytes32("0")]];
    }
    if (signature.endsWith("(bytes32)")) return bytes32("0");
    if (signature === "nextChallengeId()(uint256)") return challengeNextId;
    if (signature === "ORACLE_UPGRADE_DELAY()(uint256)") return "172800";
    if ([
      "developerFeeBps()(uint16)",
      "feeBps()(uint256)",
      "DEFAULT_FEE_BPS()(uint256)",
      "COMPUTE_SETTLEMENT_BPS()(uint256)",
    ].includes(signature)) return "100";
    if (["maxAddBalanceWei()(uint256)", "maxSpendWei()(uint256)"].includes(signature)) {
      return "5000000000000000000";
    }
    if (signature.endsWith("(uint256)") || signature.endsWith("(uint64)")) return "0";
    const trueSignatures = new Set([
      "approvalRequirementsFrozen()(bool)",
      "composeApprovalRequired()(bool)",
      "computeSettlementPolicyEnabled()(bool)",
      "developerFeeFrozen()(bool)",
      "emergencyHalted()(bool)",
      "feeBpsFrozen()(bool)",
      "productionRelease()(bool)",
      "teeIdentityApprovalRequired()(bool)",
    ]);
    if (signature === "paused()(bool)") {
      return ["ComputeCreditVault", "ExecutionPolicyAnchor"].includes(name) ? "true" : "false";
    }
    if (signature.endsWith("(bool)")) return trueSignatures.has(signature) ? "true" : "false";
    throw new Error(`unhandled fresh view ${name}.${signature}`);
  };
  return (command, args) => {
    assertReadOnlyInvocation(command, args);
    assert.equal(command, "cast");
    const secondary = args.at(-1) === TEST_SECONDARY_RPC_ENDPOINT;
    if (args[0] === "chain-id") {
      return {
        ok: true,
        stdout: secondary && secondaryChainIdDrift ? "1\n" : "84532\n",
      };
    }
    if (args[0] === "block") {
      let number = args[1] === "finalized" ? 2_000 : Number(args[1]);
      if (args[1] === "finalized") {
        if (secondary) {
          secondaryFinalizedReads += 1;
          if (secondaryFinalityRetreat && secondaryFinalizedReads > 1) number = 1_999;
        } else {
          primaryFinalizedReads += 1;
          if (primaryFinalityRetreat && primaryFinalizedReads > 1) number = 1_999;
        }
      }
      if (args[1] === "finalized" || number === 2_000) {
        snapshotReads += 1;
        const hash = snapshotHashDrift && snapshotReads > 1
          ? bytes32("e")
          : number === 2_000
            ? bytes32("d")
            : bytes32("c");
        return {
          ok: true,
          stdout: JSON.stringify(blockFixture(number, hash, {
            stateRoot: secondary && (
              secondarySnapshotHeaderDrift
              || (secondaryInitialFinalizedHeaderDrift
                && args[1] === "finalized"
                && secondaryFinalizedReads === 1)
            )
              ? bytes32("f")
              : bytes32("2"),
          })),
        };
      }
      const transaction = receipt.broadcast_transactions.find(
        (entry) => entry.block_number === number,
      );
      if (secondary && secondaryHistoricalStateUnavailable && transaction) {
        return { ok: false, stdout: "" };
      }
      return {
        ok: Boolean(transaction),
        stdout: transaction
          ? JSON.stringify(blockFixture(number, transaction.block_hash, {
            receiptsRoot: secondary && secondaryHistoricalBlockHeaderDrift
              ? bytes32("f")
              : bytes32("4"),
          }))
          : "",
      };
    }
    if (args[0] === "tx" || args[0] === "receipt") {
      const transaction = byTx.get(args[1]);
      if (!transaction) return { ok: false, stdout: "" };
      const input = inputDriftSequence === transaction.sequence
        ? "0xdeadbeef"
        : fixtureTransactionInput(transaction.sequence);
      const common = {
        from: receipt.operator_address,
        to: transaction.transaction_to,
        blockNumber: transaction.block_number,
        blockHash: transaction.block_hash,
      };
      const tx = {
        ...common,
        hash: transaction.transaction_hash,
        nonce: transaction.transaction_nonce,
        value: "0x0",
        gas: "0x100000",
        transactionIndex: `0x${transaction.sequence.toString(16)}`,
        input,
      };
      const receiptValue = {
        ...common,
        transactionHash: transaction.transaction_hash,
        status: "0x1",
        contractAddress: transaction.receipt_contract_address,
        gasUsed: "0x10000",
        cumulativeGasUsed: "0x20000",
        transactionIndex: `0x${transaction.sequence.toString(16)}`,
      };
      if (secondary && secondaryTxDrift?.sequence === transaction.sequence) {
        const replacements = {
          hash: bytes32("f"),
          from: address("9"),
          to: address("9"),
          nonce: transaction.transaction_nonce + 1,
          value: "0x1",
          gas: "0x100001",
          transactionIndex: `0x${(transaction.sequence + 1).toString(16)}`,
          input: "0xdeadbeef",
          blockNumber: transaction.block_number + 1,
          blockHash: bytes32("f"),
        };
        tx[secondaryTxDrift.field] = replacements[secondaryTxDrift.field];
      }
      if (secondary && secondaryReceiptDrift?.sequence === transaction.sequence) {
        const replacements = {
          transactionHash: bytes32("f"),
          from: address("9"),
          to: address("9"),
          contractAddress: address("9"),
          status: "0x0",
          gasUsed: "0x10001",
          cumulativeGasUsed: "0x20001",
          transactionIndex: `0x${(transaction.sequence + 1).toString(16)}`,
          blockNumber: transaction.block_number + 1,
          blockHash: bytes32("f"),
        };
        receiptValue[secondaryReceiptDrift.field] =
          replacements[secondaryReceiptDrift.field];
      }
      return {
        ok: true,
        stdout: JSON.stringify(args[0] === "tx" ? tx : receiptValue),
      };
    }
    if (args[0] === "codehash") {
      const contract = byAddress.get(args[1]);
      const drift = (codeHashDrift || (secondary && secondaryCodeHashDrift))
        && contract?.name === "ChallengeRegistry";
      return { ok: Boolean(contract), stdout: drift ? `${bytes32("f")}\n` : `${contract.runtime_code_hash}\n` };
    }
    if (args[0] === "call") {
      const contract = byAddress.get(args[1]);
      if (!contract) return { ok: false, stdout: "" };
      if (secondary
        && secondaryPoststateDrift
        && args[2] === "nextChallengeId()(uint256)") {
        return { ok: true, stdout: "2\n" };
      }
      const value = callValue(contract.name, args[2]);
      return {
        ok: true,
        stdout: args.includes("--json") ? `${JSON.stringify(value)}\n` : `${value}\n`,
      };
    }
    throw new Error(`unhandled cast command ${args[0]}`);
  };
}

function attachActivationReadinessSnapshot(snapshot) {
  const checkedAt = "2026-07-21T00:00:00Z";
  const expiresAt = "2026-07-21T00:02:00Z";
  const readiness = createActivationReadinessSnapshot({
    stage: snapshot.authorityStage,
    releaseSha: snapshot.releaseAuthority.releaseSha,
    rpcEndpointSha256: snapshot.contractDeploymentChainEvidence.rpcEndpointSha256,
    deploymentIntentSha256: snapshot.releaseAuthority.deploymentIntentSha256,
    contractDeploymentReceiptSha256:
      snapshot.cvmLaunchAuthority.contractDeploymentReceiptSha256,
    cvmLaunchIntentSha256: snapshot.cvmLaunchAuthority.sha256,
    finalAuthoritySha256: snapshot.authorityStage === "cvm_launch"
      ? null
      : snapshot.releaseAuthority.finalAuthoritySha256,
    chainEvidence: snapshot.contractDeploymentChainEvidence,
    descriptorSha256ByDomain: snapshot.cvmLaunchAuthority.descriptorSha256ByDomain,
    checkedAt,
    expiresAt,
  });
  snapshot.activationReadinessSnapshot = readiness;
  snapshot.activationReadinessSnapshotSha256 =
    `sha256:${activationReadinessSnapshotDigest(readiness)}`;
  snapshot.activationReadinessValidationNowMs = Date.parse(checkedAt);
  snapshot.releaseAuthority.checkedAtMs = Date.parse(checkedAt);
  snapshot.cvmLaunchAuthority.checkedAtMs = Date.parse(checkedAt);
  return snapshot;
}

function phaseGate(profile) {
  return {
    schema: CVM_COMPOSE_PHASE_GATE_SCHEMA,
    initial_phase: "bootstrap_provision",
    initial_services: [],
    initial_compose_profiles: [],
    post_measurement_phase: "post_measurement_policy_bootstrap",
    activation_environment: {
      key: "COMPOSE_PROFILES",
      exact_value: profile,
    },
    interpolation_policy:
      "late_values_use_exact_empty_default_until_nonempty_validated_profile_activation",
  };
}

function completeSnapshot() {
  const ledgerValue = freshContractLedgerFixture();
  const contractDeploymentReceipt = projectFreshContractDeploymentReceipt(
    ledgerValue,
    { releaseSha: SHA, ...FRESH_RECEIPT_AUTHORITY_PINS },
  );
  const contractDeploymentReceiptSha256 =
    `sha256:${freshContractDeploymentReceiptDigest(
      contractDeploymentReceipt,
      FRESH_RECEIPT_AUTHORITY_PINS,
    )}`;
  const env = {
    BASE_SEPOLIA_RPC_URL: TEST_RPC_ENDPOINT,
    BASE_SEPOLIA_SECONDARY_RPC_URL: TEST_SECONDARY_RPC_ENDPOINT,
    DEPLOYMENT_OPERATOR: address("1"),
    DILIGENCE_RESULT_VERIFIER: address("2"),
    COMPUTE_VAULT_DEVELOPER: address("3"),
    COMPUTE_VAULT_METERING_VERIFIER: address("4"),
    COMPUTE_VAULT_METERING_QVL_VERIFIER: address("b"),
    COMPUTE_VAULT_DEVELOPER_FEE_BPS: "100",
    TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: bytes32("5"),
    TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH: bytes32("6"),
    TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI: "5000000000000000000",
    TINKER_ENCUMBRANCE_MAX_SPEND_WEI: "5000000000000000000",
    EMAIL_ORACLE_UPGRADE_DELAY: "172800",
    RELEASE_SHA: SHA,
    FOUNDRY_KEYSTORE_ACCOUNT: "dev",
    BROADCAST: "false",
    VERIFY: "true",
    ETHERSCAN_API_KEY: "SUPER_SECRET_ETHERSCAN",
    TINKER_DILIGENCE_QVL_AUTH_TOKEN: internalCredential("1"),
    TINKER_ARENA_WORKER_QVL_AUTH_TOKEN: internalCredential("2"),
    TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN: internalCredential("3"),
    TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN: internalCredential("4"),
    TINKER_COMPUTE_METERING_QVL_AUTH_TOKEN: internalCredential("5"),
    METERING_QVL_AUTH_TOKEN: internalCredential("5"),
    METERING_AUTH_TOKEN: internalCredential("6"),
    TINKER_COMPUTE_METERING_AUTH_TOKEN: internalCredential("6"),
    NEKO_PASSWORD: internalCredential("7"),
    NEKO_PASSWORD_ADMIN: internalCredential("8"),
    PHALA_CLOUD_API_KEY: ["phak_", "SUPER_SECRET_PHALA"].join(""),
    DOCKER_REGISTRY_USERNAME: "operator",
    DOCKER_REGISTRY_PASSWORD: "SUPER_SECRET_REGISTRY",
    GITHUB_TOKEN: "SUPER_SECRET_GITHUB",
    CLOUDFLARE_API_TOKEN: "SUPER_SECRET_CLOUDFLARE",
  };
  const delegateImage = image("tinker-delegate", "7");
  const mainServices = {};
  for (const service of REQUIRED_PRODUCTION_SERVICES) {
    const serviceImage = service === "neko"
      ? image("neko-chrome", "8")
      : service === "oracle"
        ? image("tee-email-oracle", "9")
        : delegateImage;
    mainServices[service] = hardened(serviceImage, { networks: ["tee-net"] });
  }
  delete mainServices.neko.read_only;
  mainServices.neko.cap_add = ["SYS_ADMIN"];
  mainServices.delegate.ports = ["8080:8080"];
  mainServices.delegate.networks = { "tee-net": {}, "deal-control": {} };
  mainServices.delegate.environment = { TINKER_EVALUATOR_MODE: "deterministic" };
  mainServices["arena-policy-init"].network_mode = "none";
  mainServices["arena-policy-init"].networks = [];
  mainServices["arena-worker"].environment = {
    TINKER_ARENA_WORKER_QVL_AUTH_TOKEN: "${TINKER_ARENA_WORKER_QVL_AUTH_TOKEN:?required}",
  };
  mainServices["anchor-writer-evidence"] = hardened(delegateImage, {
    profiles: ["anchor-writer-ceremony"],
    environment: {
      TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN:
        "${TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN:?required}",
    },
    volumes: ["/var/run/dstack.sock:/var/run/dstack.sock:ro"],
    networks: ["writer-egress"],
  });
  mainServices["deal-runtime"] = hardened(delegateImage, {
    profiles: ["deal-settlement"],
    "x-dnai-capability-status": "release_pinned_deterministic_evaluator",
    command: [
      "tinker-deal-runtime",
      "--expected-chain-id",
      "84532",
      "--qvl-url",
      "${TINKER_DILIGENCE_QVL_URL:?Separate Diligence QVL HTTPS /verify URL required}",
      "--allow-compose-hash",
      "${TINKER_DILIGENCE_ALLOWED_COMPOSE_HASH:?Reviewed main CVM compose hash required}",
      "--allow-app-id",
      "${TINKER_DILIGENCE_ALLOWED_APP_ID:?Reviewed main CVM app ID required}",
      "--allow-os-image-hash",
      "${TINKER_DILIGENCE_ALLOWED_OS_IMAGE_HASH:?Reviewed main CVM OS image hash required}",
      "--trusted-attestation-verifier-address",
      "${TINKER_DILIGENCE_QVL_VERIFIER_ADDRESS:?Reviewed Diligence QVL verifier address required}",
      "--attestation-release-policy-hash",
      "${TINKER_DILIGENCE_QVL_RELEASE_POLICY_HASH:?Reviewed Diligence QVL release policy hash required}",
    ],
    environment: {
      TINKER_QVL_AUTH_TOKEN:
        "${TINKER_DILIGENCE_QVL_AUTH_TOKEN:?Phala-encrypted Diligence QVL bearer required}",
    },
    volumes: [
      "delegate-data:/data",
      "/var/run/dstack.sock:/var/run/dstack.sock:ro",
    ],
    networks: ["deal-control", "deal-egress"],
  });
  mainServices["compute-execution-worker"].profiles = ["compute-execution"];
  mainServices["compute-execution-worker"]["x-dnai-capability-status"] =
    "disabled_provider_contract_unavailable";
  const mainCompose = inspectedCompose({
    name: "dnai-main-runtime",
    services: mainServices,
    networks: {
      "tee-net": {},
      "writer-egress": { driver: "bridge" },
      "deal-control": { driver: "bridge", internal: true },
      "deal-egress": { driver: "bridge" },
    },
    "x-dnai-release": releaseMetadata("main_runtime_cvm"),
  });

  const qvlImage = image("attestation-qvl", "b");
  const meteringImage = image("compute-metering", "c");
  const qvlComposes = Object.fromEntries([
    ["diligence_qvl_cvm", "dnai-diligence-attestation-qvl"],
    ["arena_qvl_cvm", "dnai-arena-attestation-qvl"],
    ["anchor_writer_qvl_cvm", "dnai-anchor-writer-attestation-qvl"],
    ["compute_workload_qvl_cvm", "dnai-compute-workload-attestation-qvl"],
    ["compute_metering_qvl_cvm", "dnai-compute-metering-attestation-qvl"],
  ].map(([domain, name]) => [domain, inspectedCompose({
    name,
    services: {
      "policy-init": hardened(qvlImage, {
        network_mode: "none",
        volumes: [{ type: "volume", source: "qvl-policy", target: "/run/qvl" }],
      }),
      qvl: hardened(qvlImage, {
        ports: ["8443:8443"],
        volumes: [{
          type: "bind",
          source: "/var/run/dstack.sock",
          target: "/var/run/dstack.sock",
          read_only: true,
        }],
      }),
    },
    "x-dnai-release": releaseMetadata(domain),
  })]));
  const meteringCompose = inspectedCompose({
    name: "dnai-independent-compute-metering",
    services: {
      "policy-init": hardened(meteringImage, { network_mode: "none" }),
      "state-init": hardened(meteringImage, {
        network_mode: "none",
        cap_add: ["CHOWN"],
      }),
      metering: hardened(meteringImage, {
        ports: ["8443:8443"],
        volumes: [{
          type: "bind",
          source: "/var/run/dstack.sock",
          target: "/var/run/dstack.sock",
          read_only: true,
        }],
      }),
    },
    "x-dnai-release": releaseMetadata("independent_metering_cvm"),
  });
  const releaseManifest = imageReleaseManifest();
  const imageRelease = inspectImageRelease(releaseManifest);
  const releaseImages = imageRelease.images;
  const qvlRuntimePolicy = {
    QVL_CHALLENGE_CAPACITY: "4096",
    QVL_CHALLENGE_TTL_SECONDS: "60",
    QVL_MAX_CONCURRENCY: "16",
    QVL_RATE_CAPACITY: "128",
    QVL_RATE_REFILL_PER_SECOND: "16",
    QVL_REQUEST_BODY_TIMEOUT_SECONDS: "5",
    QVL_VERIFICATION_TIMEOUT_SECONDS: "20",
  };
  const meteringRuntimePolicy = {
    METERING_MAX_CONCURRENCY: "16",
    METERING_RATE_CAPACITY: "128",
    METERING_RATE_REFILL_PER_SECOND: "16",
    METERING_REQUEST_BODY_TIMEOUT_SECONDS: "5",
    METERING_RPC_TIMEOUT_SECONDS: "15",
  };
  const topologyValue = {
    schema: CVM_TOPOLOGY_SCHEMA,
    status: "rendered_not_deployed",
    release_sha: SHA,
    source_ref: "refs/heads/main",
    generated_at: "2026-07-15T12:00:00.000Z",
    deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
    deploymentIntent: {
      file: "dnai-deployment-intent-core.json",
      sha256: DEPLOYMENT_INTENT_SHA256.slice("sha256:".length),
      schema: DEPLOYMENT_INTENT_CORE_SCHEMA,
    },
    image_manifest: {
      file: "dnai-tee-image-release.json",
      sha256: "d".repeat(64),
      schema: "dnai.tee-image-release.v1",
    },
    image_manifest_attestation: {
      file: "dnai-tee-image-release.bundle.json",
      sha256: "6".repeat(64),
      predicate_type: "https://slsa.dev/provenance/v1",
    },
    trust_domains: {
      main_runtime_cvm: {
        compose: "dnai-main-runtime.phala.yaml",
        sha256: "e".repeat(64),
        services: [...REQUIRED_PRODUCTION_SERVICES],
        images: releaseImages.slice(0, 3),
        compute_execution: "disabled_provider_contract_unavailable",
        deal_settlement: "release_pinned_deterministic_evaluator",
        email_oracle_consumer_policy: "required_onchain_exact_release_binding",
      },
      diligence_qvl_cvm: {
        compose: "dnai-diligence-qvl.phala.yaml",
        sha256: "f".repeat(64),
        services: ["policy-init", "qvl"],
        images: [qvlImage],
        qvl_context: "diligence",
        runtime_policy: { ...qvlRuntimePolicy },
        phase_gate: phaseGate("qvl-runtime"),
      },
      arena_qvl_cvm: {
        compose: "dnai-arena-qvl.phala.yaml",
        sha256: "2".repeat(64),
        services: ["policy-init", "qvl"],
        images: [qvlImage],
        qvl_context: "arena",
        runtime_policy: { ...qvlRuntimePolicy },
        phase_gate: phaseGate("qvl-runtime"),
      },
      anchor_writer_qvl_cvm: {
        compose: "dnai-anchor-writer-qvl.phala.yaml",
        sha256: "3".repeat(64),
        services: ["policy-init", "qvl"],
        images: [qvlImage],
        qvl_context: "execution_policy_anchor_writer",
        runtime_policy: { ...qvlRuntimePolicy },
        phase_gate: phaseGate("qvl-runtime"),
      },
      compute_workload_qvl_cvm: {
        compose: "dnai-compute-workload-qvl.phala.yaml",
        sha256: "5".repeat(64),
        services: ["policy-init", "qvl"],
        images: [qvlImage],
        qvl_context: "compute_workload",
        runtime_policy: { ...qvlRuntimePolicy },
        phase_gate: phaseGate("qvl-runtime"),
      },
      compute_metering_qvl_cvm: {
        compose: "dnai-compute-metering-qvl.phala.yaml",
        sha256: "4".repeat(64),
        services: ["policy-init", "qvl"],
        images: [qvlImage],
        qvl_context: "compute_metering",
        runtime_policy: { ...qvlRuntimePolicy },
        phase_gate: phaseGate("qvl-runtime"),
      },
      independent_metering_cvm: {
        compose: "dnai-independent-metering.phala.yaml",
        sha256: "1".repeat(64),
        services: ["policy-init", "state-init", "metering"],
        images: [meteringImage],
        runtime_policy: { ...meteringRuntimePolicy },
        phase_gate: phaseGate("metering-runtime"),
      },
    },
    checks: {
      literal_digest_pins: true,
      linux_amd64_only: true,
      local_build_contexts: false,
      seven_cvm_descriptors: true,
      purpose_separated_qvl_descriptors: true,
      raw_secret_values_embedded: false,
      deployment_attempted: false,
      tdx_verification_claimed: false,
    },
  };
  const snapshot = {
    env,
    tools: Object.fromEntries(
      ["git", "forge", "cast", "jq", "gh", "phala", "wrangler", "uv"].map((tool) => [tool, true]),
    ),
    toolVersions: {
      phala: { valid: true, version: "1.1.19", source: "installed_package_manifest" },
    },
    git: { head: SHA, dirty: false },
    probes: {
      devKeystoreListed: true,
      rpcAttempted: true,
      rpcChainId: "84532",
      githubAuth: true,
      phalaAuth: true,
      cloudflareAuth: true,
    },
    files: {
      env: { exists: true, mode: 0o600 },
      releaseCandidate: {
        valid: true,
        value: {
          schema: RELEASE_SCHEMA,
          release_sha: SHA,
          deployment_intent_sha256: DEPLOYMENT_INTENT_SHA256,
          cvm_launch_intent_sha256: CVM_LAUNCH_INTENT_SHA256,
          operator_policy: {
            schema: LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
            ceremony_authorization_sha256: CEREMONY_AUTHORIZATION_SHA256,
            live_activation_authority_sha256:
              LIVE_ACTIVATION_AUTHORITY_SHA256,
            runtime_authority_dependency_sha256: FINAL_AUTHORITY_SHA256,
          },
        },
      },
      releaseCore: {
        valid: true,
        value: {
          schema: FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
          release_sha: SHA,
          deployment_intent_sha256: DEPLOYMENT_INTENT_SHA256,
          cvm_launch_intent_sha256: CVM_LAUNCH_INTENT_SHA256,
        },
      },
      ledger: {
        valid: true,
        sha256: "a6".repeat(32),
        value: ledgerValue,
      },
      artifactEvidence: { valid: true },
      arenaEvidence: { valid: true },
      anchorWriterEvidence: { valid: true, mode: 0o600 },
      emailOracleEvidence: { valid: true },
      imageRelease: { valid: true, sha256: "d".repeat(64), value: releaseManifest },
      imageReleaseAttestationBundle: {
        exists: true,
        valid: true,
        sha256: "6".repeat(64),
      },
      imageReleaseSigstoreVerificationReceipt: {
        exists: true,
        valid: true,
        sha256: RELEASE_MANIFEST_SIGSTORE_RECEIPT_FILE_SHA256,
      },
      topology: { valid: true, sha256: "5".repeat(64), value: topologyValue },
      deploymentIntent: {
        valid: true,
        sha256: "a1".repeat(32),
        value: { schema: DEPLOYMENT_INTENT_CORE_SCHEMA },
      },
      authorityReviewEnvelope: { valid: true, sha256: "a3".repeat(32) },
      authorityReviewEvidence: { valid: true, sha256: "a4".repeat(32) },
      cvmLaunchIntent: { valid: true, sha256: "a5".repeat(32) },
      mainCompose: { valid: true, sha256: "e".repeat(64) },
      diligenceQvlCompose: { valid: true, sha256: "f".repeat(64) },
      arenaQvlCompose: { valid: true, sha256: "2".repeat(64) },
      anchorWriterQvlCompose: { valid: true, sha256: "3".repeat(64) },
      computeWorkloadQvlCompose: { valid: true, sha256: "5".repeat(64) },
      computeMeteringQvlCompose: { valid: true, sha256: "4".repeat(64) },
      meteringCompose: { valid: true, sha256: "1".repeat(64) },
    },
    compose: mainCompose,
    diligenceQvlCompose: qvlComposes.diligence_qvl_cvm,
    arenaQvlCompose: qvlComposes.arena_qvl_cvm,
    anchorWriterQvlCompose: qvlComposes.anchor_writer_qvl_cvm,
    computeWorkloadQvlCompose: qvlComposes.compute_workload_qvl_cvm,
    computeMeteringQvlCompose: qvlComposes.compute_metering_qvl_cvm,
    meteringCompose,
    imageRelease,
    topology: inspectCvmTopology(topologyValue),
    authorityStage: "live_activation",
    contractDeploymentChainEvidence: contractDeploymentChainEvidenceFixture(),
    releaseAuthority: {
      deploymentIntentValid: true,
      deploymentIntentFileHashBound: true,
      deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
      reviewerAuthorityGenesisAcceptanceSha256:
        REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
      releaseSha: SHA,
      gitObjectIsCommit: true,
      commitTime: 1_784_092_800,
      deploymentIntentEnvironmentProjection: {
        ok: true,
        checkedKeys: Array.from({ length: 46 }),
        mismatchKeys: [],
      },
      deploymentIntentFreshChallengeStateValid: true,
      finalAuthorityValid: true,
      finalAuthorityFileHashBound: true,
      finalAuthoritySha256: FINAL_AUTHORITY_SHA256,
      finalAuthorityDeploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
      finalAuthorityCvmLaunchIntentSha256: CVM_LAUNCH_INTENT_SHA256,
      reviewEnvelopeValid: true,
      reviewEnvelopeFileHashBound: true,
      reviewEnvelopeSha256: REVIEW_ENVELOPE_SHA256,
      reviewSubjectKind: "final_release_authority",
      reviewSubjectSha256: FINAL_AUTHORITY_SHA256,
      reviewEvidenceValid: true,
      reviewEvidenceFileHashBound: true,
      reviewEvidenceSha256: REVIEW_EVIDENCE_SHA256,
      approvedAt: "2026-07-16T00:00:00Z",
      expiresAt: "2026-07-23T00:00:00Z",
      checkedAtMs: Date.parse("2026-07-21T00:00:00Z"),
    },
    cvmLaunchAuthority: {
      valid: true,
      fileHashBound: true,
      sha256: CVM_LAUNCH_INTENT_SHA256,
      deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
      releaseSha: SHA,
      reviewEnvelopeValid: true,
      reviewEnvelopeFileHashBound: true,
      reviewEnvelopeSha256: CVM_LAUNCH_REVIEW_ENVELOPE_SHA256,
      reviewSubjectKind: "cvm_launch_intent",
      reviewSubjectSha256: CVM_LAUNCH_INTENT_SHA256,
      reviewEvidenceValid: true,
      reviewEvidenceFileHashBound: true,
      reviewEvidenceSha256: CVM_LAUNCH_REVIEW_EVIDENCE_SHA256,
      approvedAt: "2026-07-16T00:00:00Z",
      expiresAt: "2026-07-23T00:00:00Z",
      checkedAtMs: Date.parse("2026-07-21T00:00:00Z"),
      contractDeploymentReceipt,
      contractDeploymentReceiptValid: true,
      contractDeploymentReceiptSha256,
      imageReleaseManifestSha256: `sha256:${"d".repeat(64)}`,
      imageAttestationBundleSha256: `sha256:${"6".repeat(64)}`,
      topologySha256: `sha256:${"5".repeat(64)}`,
      descriptorSha256ByDomain: {
        main_runtime_cvm: `sha256:${"e".repeat(64)}`,
        diligence_qvl_cvm: `sha256:${"f".repeat(64)}`,
        arena_qvl_cvm: `sha256:${"2".repeat(64)}`,
        anchor_writer_qvl_cvm: `sha256:${"3".repeat(64)}`,
        compute_workload_qvl_cvm: `sha256:${"5".repeat(64)}`,
        compute_metering_qvl_cvm: `sha256:${"4".repeat(64)}`,
        independent_metering_cvm: `sha256:${"1".repeat(64)}`,
      },
      artifactBindingsValid: true,
      contractDeploymentContractCount: 7,
      imageReleaseValid: true,
      imageCount: 5,
      topologyValid: true,
      descriptorCount: 7,
      descriptorHashesDistinct: true,
      productionPostureValid: true,
    },
    releaseImages,
    attestations: Array.from({ length: releaseImages.length * 2 }, () => ({ ok: true })),
    releaseManifestAttestation: {
      ok: true,
      productionVerified: true,
      status: "verified_by_pinned_gh_sigstore",
      blockerCode: PHALA_RELEASE_MANIFEST_SIGSTORE_VERIFICATION_MISSING,
      blockerStatus: "cleared_by_this_receipt",
      receiptSha256: RELEASE_MANIFEST_SIGSTORE_RECEIPT_SHA256,
      receiptArtifactFileSha256:
        `sha256:${RELEASE_MANIFEST_SIGSTORE_RECEIPT_FILE_SHA256}`,
      releaseSha: SHA,
      releaseManifestSha256: `sha256:${"d".repeat(64)}`,
      releaseManifestSigstoreBundleSha256: `sha256:${"6".repeat(64)}`,
    },
    canonicalSevenCvmAuthorityValidation:
      canonicalSevenCvmAuthorityValidation({ authorityStage: "live_activation" }),
    semanticEvidenceValidated: true,
    semanticValidationReceipt: semanticReceiptFixture(),
  };
  return attachActivationReadinessSnapshot(snapshot);
}

test("bounded report redacts every secret and credential-bearing URL", () => {
  const snapshot = completeSnapshot();
  const report = buildPreflightReport(snapshot);
  assert.equal(
    report.verdict,
    "READY",
  );
  assert.deepEqual(
    report.checks.filter((item) => item.status === "fail").map((item) => item.id),
    [],
  );
  assert.doesNotThrow(() => assertReportContainsNoSensitiveValues(report, snapshot.env));
  const human = formatHumanReport(report);
  const json = JSON.stringify(report);
  for (const value of [
    snapshot.env.BASE_SEPOLIA_RPC_URL,
    snapshot.env.ETHERSCAN_API_KEY,
    snapshot.env.PHALA_CLOUD_API_KEY,
    snapshot.env.GITHUB_TOKEN,
    snapshot.env.CLOUDFLARE_API_TOKEN,
    ...REQUIRED_RUNTIME_CREDENTIALS
      .map(([, key]) => snapshot.env[key])
      .filter(Boolean),
  ]) {
    assert.equal(human.includes(value), false);
    assert.equal(json.includes(value), false);
  }
  assert.equal(report.checks.length, 103);
  assert.equal(report.root_cause_projection.source_check_count, 103);
  assert.equal(report.root_cause_projection.source_fail_count, 0);
  assert.equal(report.root_cause_projection.mapping_complete, true);
  assert.deepEqual(report.root_causes, []);
  assert.deepEqual(report.blocked_by, []);
  assert.ok(report.next_actions.length <= 20);
  assert.equal(report.checks.some((item) => item.id === "credential.openrouter"), false);
});

test("secret classification excludes public auth and key configuration controls", () => {
  const env = {
    ORACLE_RUNTIME_AUTH_REQUIRED: "true",
    ORACLE_AUTH_REQUIRED: "false",
    ORACLE_AUTH_CHAIN_ID: "84532",
    TINKER_RUNTIME_AUTH_REQUIRED: "true",
    TINKER_WALLET_AUTH_CHAIN_ID: "84532",
    TINKER_ALLOW_TINKER_PROXY_TOKEN_ISSUANCE: "false",
    TINKER_PURGE_SECRET_DEBUG_ARTIFACTS: "true",
    TINKER_ALLOW_KEY_MANAGEMENT_ENDPOINT: "false",
    EMAIL_ORACLE_AUTH_ADDRESS: address("1"),
    TINKER_COMPUTE_CREDENTIAL_AUDIENCE: "dnai-wikigen:compute-jobs",
    TINKER_WALLET_AUTH_KEY_PATH: "tinker/wallet_auth",
    TINKER_API_KEY_STORE_PATH: "/data/tinker_api_key.enc",
    BASE_SEPOLIA_RPC_URL: "https://provider.invalid/credential",
    PHALA_CLOUD_API_KEY: ["phak_", "private-test-credential"].join(""),
    GITHUB_TOKEN: "github-private-test-credential",
    CLOUDFLARE_API_TOKEN: "cloudflare-private-test-credential",
    AWS_SECRET_ACCESS_KEY: "aws-private-test-credential",
    WEBHOOK_SECRET: "webhook-private-test-credential",
    TINKER_RUNTIME_AUTH_TOKEN: "runtime-private-test-credential",
    TINKER_COMPUTE_STORE_INTEGRITY_KEY: "integrity-private-test-credential",
    TINKER_COMPUTE_WORKLOAD_INGRESS_PRIVATE_KEY_HEX:
      "11".repeat(32),
    TINKER_ARENA_PROVISION_EVALUATOR_B64: "sealed-private-test-payload",
  };

  assert.deepEqual(sensitiveValues(env), [
    env.BASE_SEPOLIA_RPC_URL,
    env.PHALA_CLOUD_API_KEY,
    env.GITHUB_TOKEN,
    env.CLOUDFLARE_API_TOKEN,
    env.AWS_SECRET_ACCESS_KEY,
    env.WEBHOOK_SECRET,
    env.TINKER_RUNTIME_AUTH_TOKEN,
    env.TINKER_COMPUTE_STORE_INTEGRITY_KEY,
    env.TINKER_COMPUTE_WORKLOAD_INGRESS_PRIVATE_KEY_HEX,
    env.TINKER_ARENA_PROVISION_EVALUATOR_B64,
  ]);
  const boundedPublicReport = {
    auth_required: true,
    chain_id: 84_532,
    token_issuance_enabled: false,
    key_management_enabled: false,
  };
  assert.doesNotThrow(() =>
    assertReportContainsNoSensitiveValues(boundedPublicReport, env));
});

test("CVM execution readiness reports the available reviewed boundary", () => {
  const report = buildPreflightReport(completeSnapshot());
  const boundary = report.checks.find(
    (item) => item.id === "authority.cvm_execution_boundary_availability",
  );
  assert.equal(boundary.status, "pass");
  assert.match(boundary.message, /executor implementation is present in source/);
  assert.match(boundary.message, /not Phala authentication or reachability evidence/);
});

test("legacy private-key assignment names fail closed without projecting values", () => {
  const snapshot = completeSnapshot();
  const legacyValues = [
    "SUPER_SECRET_LEGACY_JUDGE_VALUE",
    "SUPER_SECRET_LEGACY_KMS_VALUE",
  ];
  for (const [index, name] of FORBIDDEN_LEGACY_PRIVATE_KEY_NAMES.entries()) {
    snapshot.env[name] = legacyValues[index];
  }
  const report = buildPreflightReport(snapshot);
  const hygiene = report.checks.find(
    (item) => item.id === "safety.legacy_private_key_names",
  );
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(hygiene.status, "fail");
  assert.match(hygiene.message, /2 prohibited legacy raw-private-key assignment/);
  for (const value of legacyValues) {
    assert.equal(JSON.stringify(report).includes(value), false);
  }
  assert.doesNotThrow(() => assertReportContainsNoSensitiveValues(report, snapshot.env));
});

test("VERIFY is blocking only at the fresh-deployment boundary", () => {
  for (const stage of [
    "fresh_deployment",
    "cvm_launch",
    "release_ceremony",
    "live_activation",
  ]) {
    const snapshot = completeSnapshot();
    snapshot.authorityStage = stage;
    snapshot.env.VERIFY = "false";
    const verify = buildPreflightReport(snapshot).checks.find(
      (item) => item.id === "contract_policy.verify",
    );
    assert.equal(verify.status, stage === "fresh_deployment" ? "fail" : "pass", stage);
    if (stage !== "fresh_deployment") assert.match(verify.message, /ignored/);
  }
});

test("staged release authority is fail closed across intent, final authority, review, and artifacts", () => {
  const cases = [
    ["stage", (snapshot) => { snapshot.authorityStage = "unsupported"; }],
    ["deployment_intent", (snapshot) => {
      snapshot.releaseAuthority.deploymentIntentValid = false;
    }],
    ["deployment_intent_source", (snapshot) => {
      snapshot.releaseAuthority.gitObjectIsCommit = false;
    }],
    ["deployment_intent_environment_projection", (snapshot) => {
      snapshot.releaseAuthority.deploymentIntentEnvironmentProjection.ok = false;
    }],
    ["final_release_authority", (snapshot) => {
      snapshot.releaseAuthority.finalAuthorityValid = false;
    }],
    ["current_review_envelope", (snapshot) => {
      snapshot.releaseAuthority.reviewEnvelopeValid = false;
    }],
    ["review_evidence", (snapshot) => {
      snapshot.releaseAuthority.reviewEvidenceValid = false;
    }],
    ["release_artifact_binding", (snapshot) => {
      snapshot.files.releaseCandidate.value.operator_policy
        .runtime_authority_dependency_sha256 =
        `sha256:${"f".repeat(64)}`;
    }],
  ];
  for (const [suffix, mutate] of cases) {
    const snapshot = completeSnapshot();
    mutate(snapshot);
    const report = buildPreflightReport(snapshot);
    assert.equal(report.verdict, "BLOCKED", suffix);
    assert.equal(
      report.checks.find((item) => item.id === `authority.${suffix}`).status,
      "fail",
      suffix,
    );
  }
});

test("fresh deployment becomes ready without postdeployment authority or evidence", () => {
  const snapshot = completeSnapshot();
  snapshot.authorityStage = "fresh_deployment";
  delete snapshot.env.DILIGENCE_RESULT_VERIFIER;
  delete snapshot.env.COMPUTE_VAULT_METERING_VERIFIER;
  delete snapshot.env.COMPUTE_VAULT_METERING_QVL_VERIFIER;
  delete snapshot.env.TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH;
  snapshot.releaseAuthority.finalAuthorityValid = false;
  snapshot.releaseAuthority.finalAuthorityFileHashBound = false;
  snapshot.releaseAuthority.finalAuthoritySha256 = "";
  snapshot.releaseAuthority.finalAuthorityDeploymentIntentSha256 = "";
  snapshot.releaseAuthority.reviewSubjectKind = "deployment_intent";
  snapshot.releaseAuthority.reviewSubjectSha256 = DEPLOYMENT_INTENT_SHA256;
  for (const name of [
    "releaseCandidate",
    "releaseCore",
    "cvmLaunchIntent",
    "ledger",
    "artifactEvidence",
    "arenaEvidence",
    "anchorWriterEvidence",
    "emailOracleEvidence",
  ]) {
    snapshot.files[name] = { valid: false };
  }
  snapshot.semanticEvidenceValidated = false;
  snapshot.semanticValidationReceipt = null;
  snapshot.semanticEvidenceReason =
    "canonical_semantic_validator_not_applicable_fresh_deployment";
  snapshot.canonicalSevenCvmAuthorityValidation = null;
  snapshot.cvmLaunchAuthority = {};

  const report = buildPreflightReport(snapshot);
  assert.equal(report.verdict, "READY");
  for (const key of [
    "diligence_result_verifier",
    "compute_vault_metering_verifier",
    "compute_vault_metering_qvl_verifier",
  ]) {
    assert.equal(
      report.checks.find((item) => item.id === `contract_input.${key}`)?.status,
      "pass",
      key,
    );
  }
  assert.equal(
    report.checks.find((item) => item.id === "roles.pairwise_distinct")?.status,
    "pass",
  );
  for (const id of [
    "authority.final_release_authority",
    "evidence.semantic_release_authority",
    "evidence.ledger",
    "evidence.artifact_evidence",
    "evidence.arena_evidence",
    "evidence.anchor_writer_evidence",
  ]) {
    assert.notEqual(report.checks.find((item) => item.id === id)?.status, "fail", id);
  }
});

test("CVM launch becomes ready only after the reviewed executor and authority checks pass", () => {
  const snapshot = completeSnapshot();
  snapshot.authorityStage = "cvm_launch";
  snapshot.contractDeploymentChainEvidence =
    contractDeploymentChainEvidenceFixture("fresh_fail_closed");
  delete snapshot.env.DILIGENCE_RESULT_VERIFIER;
  delete snapshot.env.COMPUTE_VAULT_METERING_VERIFIER;
  delete snapshot.env.COMPUTE_VAULT_METERING_QVL_VERIFIER;
  delete snapshot.env.TINKER_ENCUMBRANCE_INITIAL_COMPOSE_HASH;
  snapshot.releaseAuthority.finalAuthorityValid = false;
  snapshot.releaseAuthority.finalAuthorityFileHashBound = false;
  snapshot.releaseAuthority.finalAuthoritySha256 = "";
  snapshot.releaseAuthority.finalAuthorityDeploymentIntentSha256 = "";
  snapshot.releaseAuthority.finalAuthorityCvmLaunchIntentSha256 = "";
  for (const name of [
    "releaseCandidate",
    "releaseCore",
    "artifactEvidence",
    "arenaEvidence",
    "anchorWriterEvidence",
    "emailOracleEvidence",
  ]) {
    snapshot.files[name] = { valid: false };
  }
  snapshot.semanticEvidenceValidated = false;
  snapshot.semanticValidationReceipt = null;
  snapshot.semanticEvidenceReason =
    "canonical_semantic_validator_not_applicable_cvm_launch";
  snapshot.canonicalSevenCvmAuthorityValidation = null;
  attachActivationReadinessSnapshot(snapshot);

  let report = buildPreflightReport(snapshot);
  assert.equal(report.verdict, "READY");
  for (const key of [
    "diligence_result_verifier",
    "compute_vault_metering_verifier",
    "compute_vault_metering_qvl_verifier",
  ]) {
    assert.equal(
      report.checks.find((item) => item.id === `contract_input.${key}`)?.status,
      "pass",
      key,
    );
  }
  assert.equal(
    report.checks.find((item) => item.id === "roles.pairwise_distinct")?.status,
    "pass",
  );
  assert.equal(
    report.checks.find(
      (item) => item.id === "authority.cvm_execution_boundary_availability",
    )?.status,
    "pass",
  );
  for (const id of [
    "authority.cvm_launch_intent",
    "authority.current_review_envelope",
    "authority.release_artifact_binding",
  ]) {
    assert.equal(report.checks.find((item) => item.id === id)?.status, "pass", id);
  }
  assert.notEqual(
    report.checks.find((item) => item.id === "authority.final_release_authority")?.status,
    "fail",
  );
  assert.notEqual(
    report.checks.find((item) => item.id === "evidence.semantic_release_authority")?.status,
    "fail",
  );

  const crossedReview = structuredClone(snapshot);
  crossedReview.cvmLaunchAuthority.reviewSubjectKind = "deployment_intent";
  crossedReview.cvmLaunchAuthority.reviewSubjectSha256 = DEPLOYMENT_INTENT_SHA256;
  report = buildPreflightReport(crossedReview);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "authority.current_review_envelope")?.status,
    "fail",
  );

  const driftedDescriptor = structuredClone(snapshot);
  driftedDescriptor.cvmLaunchAuthority.artifactBindingsValid = false;
  report = buildPreflightReport(driftedDescriptor);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "authority.release_artifact_binding")?.status,
    "fail",
  );
});

test("authority review evidence is bound only by its exact independently read bytes", () => {
  const file = { valid: true, sha256: "a4".repeat(32) };
  assert.equal(validateAuthorityReviewEvidence(file, REVIEW_EVIDENCE_SHA256), true);
  assert.equal(
    validateAuthorityReviewEvidence(file, `sha256:${"f".repeat(64)}`),
    false,
  );
  assert.equal(
    validateAuthorityReviewEvidence({ ...file, valid: false }, REVIEW_EVIDENCE_SHA256),
    false,
  );
  assert.equal(
    validateAuthorityReviewEvidence(file, `sha256:${"0".repeat(64)}`),
    false,
  );
});

test("deployment-intent projection compares exact public inputs without reflecting values", () => {
  const projection = {
    assertions: {
      DEPLOYMENT_OPERATOR: {
        projectionName: "DEPLOYMENT_OPERATOR",
        value: address("1"),
      },
      RELEASE_SHA: { projectionName: "RELEASE_SHA", value: SHA },
    },
  };
  assert.deepEqual(
    validateProjectedEnvironment(projection, {
      DEPLOYMENT_OPERATOR: address("1"),
      RELEASE_SHA: SHA,
    }),
    {
      ok: true,
      checkedKeys: ["DEPLOYMENT_OPERATOR", "RELEASE_SHA"],
      mismatchKeys: [],
    },
  );
  const mismatch = validateProjectedEnvironment(projection, {
    DEPLOYMENT_OPERATOR: address("2"),
    RELEASE_SHA: SHA,
  });
  assert.equal(mismatch.ok, false);
  assert.deepEqual(mismatch.mismatchKeys, ["DEPLOYMENT_OPERATOR"]);
  assert.equal(JSON.stringify(mismatch).includes(address("2")), false);
});

test("CVM launch accepts only the exact fresh seven-contract ledger posture", () => {
  const ledger = freshContractLedgerFixture();
  const inspected = inspectFreshContractDeploymentReceipt(
    ledger,
    DEPLOYMENT_INTENT_SHA256,
    SHA,
    REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
  );
  assert.equal(inspected.valid, true);
  assert.equal(inspected.contractCount, 7);
  assert.match(inspected.sha256, /^sha256:[0-9a-f]{64}$/);

  const renewableHistory = structuredClone(ledger);
  renewableHistory.deploymentHistory.push({ kind: "renewed_review_only" });
  renewableHistory.freshDeployment.contractSuite.deploymentReviewEnvelopeSha256 =
    REVIEW_ENVELOPE_SHA256;
  assert.equal(
    inspectFreshContractDeploymentReceipt(
      renewableHistory,
      DEPLOYMENT_INTENT_SHA256,
      SHA,
      REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
    ).sha256,
    inspected.sha256,
  );

  const missingContract = structuredClone(ledger);
  delete missingContract.contracts.emailOracleAuth;
  assert.deepEqual(
    inspectFreshContractDeploymentReceipt(
      missingContract,
      DEPLOYMENT_INTENT_SHA256,
      SHA,
      REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
    ),
    { valid: false, receipt: null, sha256: "", contractCount: 0 },
  );

  const staleIntent = structuredClone(ledger);
  staleIntent.freshDeployment.contractSuite.deploymentIntentSha256 =
    `sha256:${"f".repeat(64)}`;
  assert.equal(
    inspectFreshContractDeploymentReceipt(
      staleIntent,
      DEPLOYMENT_INTENT_SHA256,
      SHA,
      REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
    ).valid,
    false,
  );

  const runtimeDrift = structuredClone(ledger);
  runtimeDrift.contracts.challengeRegistry.runtimeCodeHash = bytes32("f");
  assert.notEqual(
    inspectFreshContractDeploymentReceipt(
      runtimeDrift,
      DEPLOYMENT_INTENT_SHA256,
      SHA,
      REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
    ).sha256,
    inspected.sha256,
  );
});

test("online fresh-chain verifier pins one block and rejects state, code, or hash drift", () => {
  const receipt = projectFreshContractDeploymentReceipt(
    freshContractLedgerFixture(),
    { releaseSha: SHA, ...FRESH_RECEIPT_AUTHORITY_PINS },
  );
  const input = {
    contractDeploymentReceipt: receipt,
    deploymentIntent: freshDeploymentIntentForChainFixture(),
    deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
    releaseSha: SHA,
    independentReconstruction: independentReconstructionFixture(receipt),
    secondaryIndependentReconstruction: independentReconstructionFixture(receipt),
    authorityStage: "cvm_launch",
    rpcUrl: TEST_RPC_ENDPOINT,
    secondaryRpcUrl: TEST_SECONDARY_RPC_ENDPOINT,
    castAvailable: true,
  };
  const valid = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    runner: freshChainRunner(receipt),
  });
  assert.equal(valid.valid, true);
  assert.equal(valid.chainId, 84_532);
  assert.equal(valid.secondaryChainId, 84_532);
  assert.equal(valid.rpcEndpointSha256, activationReadinessRpcEndpointDigest(TEST_RPC_ENDPOINT));
  assert.equal(
    valid.secondaryRpcEndpointSha256,
    activationReadinessRpcEndpointDigest(TEST_SECONDARY_RPC_ENDPOINT),
  );
  assert.equal(valid.rpcEndpointsDistinct, true);
  assert.equal(
    valid.rpcOriginSha256,
    activationReadinessRpcOriginDigest(TEST_RPC_ORIGIN),
  );
  assert.equal(
    valid.secondaryRpcOriginSha256,
    activationReadinessRpcOriginDigest(TEST_SECONDARY_RPC_ORIGIN),
  );
  assert.equal(valid.secondaryFinalizedSnapshotVerified, true);
  assert.equal(valid.secondaryFinalizedTagRechecked, true);
  assert.equal(valid.independentReconstructionRpcAgreement, true);
  assert.equal(valid.secondaryRuntimeCodeMatchCount, 7);
  assert.equal(valid.snapshotBlockHash, bytes32("d"));
  assert.equal(valid.immutableProvenanceContractCount, 7);
  assert.equal(valid.broadcastTransactionCount, 13);
  assert.equal(valid.broadcastTransactionValidCount, 13);
  assert.equal(valid.broadcastTransactionProvenanceValid, true);
  assert.equal(valid.broadcastTransactionRpcAgreement, true);
  assert.equal(
    valid.primaryBroadcastTransactionObservationsSha256,
    valid.secondaryBroadcastTransactionObservationsSha256,
  );
  assert.equal(valid.poststateContractCount, 6);
  assert.equal(valid.poststates.every((entry) => entry.valid), true);
  assert.equal(valid.secondaryPoststateContractCount, 6);
  assert.equal(valid.secondaryPoststateValid, true);
  assert.equal(valid.poststateRpcAgreement, true);
  assert.equal(
    valid.primaryPoststateObservationsSha256,
    valid.secondaryPoststateObservationsSha256,
  );

  const stateDrift = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    runner: freshChainRunner(receipt, { challengeNextId: "2" }),
  });
  assert.equal(stateDrift.valid, false);
  assert.equal(
    stateDrift.poststates.find((entry) => entry.name === "ChallengeRegistry")?.valid,
    false,
  );

  const codeDrift = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    runner: freshChainRunner(receipt, { codeHashDrift: true }),
  });
  assert.equal(codeDrift.valid, false);
  assert.equal(codeDrift.runtimeCodeMatchCount, 6);

  const inputDrift = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    runner: freshChainRunner(receipt, { inputDriftSequence: 8 }),
  });
  assert.equal(inputDrift.valid, false);
  assert.equal(inputDrift.broadcastTransactionValidCount, 12);
  assert.equal(inputDrift.broadcastTransactionProvenance[8].inputMatches, false);

  const equivocation = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    runner: freshChainRunner(receipt, { snapshotHashDrift: true }),
  });
  assert.equal(equivocation.valid, false);
  assert.equal(equivocation.commonSnapshotBlock, false);
  assert.equal(equivocation.snapshotBlockHashVerified, false);

  const offline = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    skipNetwork: true,
  });
  assert.equal(offline.valid, false);
  assert.equal(offline.immutableProvenance.length, 0);
  assert.equal(offline.poststates.length, 0);

  const aliasedRpc = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    secondaryRpcUrl: TEST_RPC_ENDPOINT,
    runner: freshChainRunner(receipt),
  });
  assert.equal(aliasedRpc.valid, false);
  assert.equal(aliasedRpc.rpcEndpointsDistinct, false);

  const sameProviderOrigin = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    secondaryRpcUrl: `${TEST_RPC_ENDPOINT}/alias`,
    runner: freshChainRunner(receipt),
  });
  assert.equal(sameProviderOrigin.valid, false);
  assert.equal(sameProviderOrigin.rpcEndpointsDistinct, false);
});

test("dual-RPC verifier rejects chain, consensus-header, and finality divergence", () => {
  const receipt = projectFreshContractDeploymentReceipt(
    freshContractLedgerFixture(),
    { releaseSha: SHA, ...FRESH_RECEIPT_AUTHORITY_PINS },
  );
  const input = {
    contractDeploymentReceipt: receipt,
    deploymentIntent: freshDeploymentIntentForChainFixture(),
    deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
    releaseSha: SHA,
    independentReconstruction: independentReconstructionFixture(receipt),
    secondaryIndependentReconstruction: independentReconstructionFixture(receipt),
    authorityStage: "cvm_launch",
    rpcUrl: TEST_RPC_ENDPOINT,
    secondaryRpcUrl: TEST_SECONDARY_RPC_ENDPOINT,
    castAvailable: true,
  };

  const wrongSecondaryChain = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    runner: freshChainRunner(receipt, { secondaryChainIdDrift: true }),
  });
  assert.equal(wrongSecondaryChain.valid, false);
  assert.equal(wrongSecondaryChain.chainId, 84_532);
  assert.equal(wrongSecondaryChain.secondaryChainId, 1);

  const missingConsensusRoots = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    runner: freshChainRunner(receipt, { omitConsensusRoots: true }),
  });
  assert.equal(missingConsensusRoots.valid, false);
  assert.equal(missingConsensusRoots.secondaryFinalizedSnapshotVerified, false);

  const snapshotHeaderDrift = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    runner: freshChainRunner(receipt, { secondarySnapshotHeaderDrift: true }),
  });
  assert.equal(snapshotHeaderDrift.valid, false);
  assert.equal(snapshotHeaderDrift.secondaryFinalizedSnapshotVerified, false);

  const initialFinalizedHeaderDrift =
    verifyContractDeploymentChainEvidenceWithTestAdapters({
      ...input,
      runner: freshChainRunner(receipt, {
        secondaryInitialFinalizedHeaderDrift: true,
      }),
    });
  assert.equal(initialFinalizedHeaderDrift.valid, false);
  assert.equal(
    initialFinalizedHeaderDrift.secondaryFinalizedSnapshotVerified,
    false,
  );

  for (const option of ["primaryFinalityRetreat", "secondaryFinalityRetreat"]) {
    const finalityRetreat = verifyContractDeploymentChainEvidenceWithTestAdapters({
      ...input,
      runner: freshChainRunner(receipt, { [option]: true }),
    });
    assert.equal(finalityRetreat.valid, false, option);
    assert.equal(finalityRetreat.snapshotBlockHashVerified, false, option);
  }
});

test("dual-RPC release reconstruction disagreement fails closed", () => {
  const receipt = projectFreshContractDeploymentReceipt(
    freshContractLedgerFixture(),
    { releaseSha: SHA, ...FRESH_RECEIPT_AUTHORITY_PINS },
  );
  const secondary = independentReconstructionFixture(receipt);
  secondary.network.snapshot_block_hash = bytes32("e");
  secondary.reconstruction_sha256 = freshContractReleaseReconstructionDigest(secondary);
  const evidence = verifyContractDeploymentChainEvidenceWithTestAdapters({
    contractDeploymentReceipt: receipt,
    deploymentIntent: freshDeploymentIntentForChainFixture(),
    deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
    releaseSha: SHA,
    independentReconstruction: independentReconstructionFixture(receipt),
    secondaryIndependentReconstruction: secondary,
    authorityStage: "cvm_launch",
    rpcUrl: TEST_RPC_ENDPOINT,
    secondaryRpcUrl: TEST_SECONDARY_RPC_ENDPOINT,
    castAvailable: true,
    runner: freshChainRunner(receipt),
  });
  assert.equal(evidence.valid, false);
  assert.equal(evidence.independentReconstructionRpcAgreement, false);
});

test("secondary RPC must independently match every transaction, receipt, historical block, and poststate field", () => {
  const receipt = projectFreshContractDeploymentReceipt(
    freshContractLedgerFixture(),
    { releaseSha: SHA, ...FRESH_RECEIPT_AUTHORITY_PINS },
  );
  const input = {
    contractDeploymentReceipt: receipt,
    deploymentIntent: freshDeploymentIntentForChainFixture(),
    deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
    releaseSha: SHA,
    independentReconstruction: independentReconstructionFixture(receipt),
    secondaryIndependentReconstruction: independentReconstructionFixture(receipt),
    authorityStage: "cvm_launch",
    rpcUrl: TEST_RPC_ENDPOINT,
    secondaryRpcUrl: TEST_SECONDARY_RPC_ENDPOINT,
    castAvailable: true,
  };
  const transactionFields = [
    "hash",
    "from",
    "to",
    "nonce",
    "value",
    "gas",
    "transactionIndex",
    "input",
    "blockNumber",
    "blockHash",
  ];
  for (const field of transactionFields) {
    const evidence = verifyContractDeploymentChainEvidenceWithTestAdapters({
      ...input,
      runner: freshChainRunner(receipt, {
        secondaryTxDrift: { sequence: 1, field },
      }),
    });
    assert.equal(evidence.valid, false, `secondary transaction ${field} drift`);
    assert.equal(evidence.broadcastTransactionRpcAgreement, false);
    assert.equal(
      evidence.broadcastTransactionProvenance[1].providerObservationsMatch,
      false,
    );
  }

  const receiptFields = [
    "transactionHash",
    "from",
    "to",
    "contractAddress",
    "status",
    "gasUsed",
    "cumulativeGasUsed",
    "transactionIndex",
    "blockNumber",
    "blockHash",
  ];
  for (const field of receiptFields) {
    const evidence = verifyContractDeploymentChainEvidenceWithTestAdapters({
      ...input,
      runner: freshChainRunner(receipt, {
        secondaryReceiptDrift: { sequence: 1, field },
      }),
    });
    assert.equal(evidence.valid, false, `secondary receipt ${field} drift`);
    assert.equal(evidence.broadcastTransactionRpcAgreement, false);
    assert.equal(
      evidence.broadcastTransactionProvenance[1].providerObservationsMatch,
      false,
    );
  }

  const pruned = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    runner: freshChainRunner(receipt, {
      secondaryHistoricalStateUnavailable: true,
    }),
  });
  assert.equal(pruned.valid, false);
  assert.equal(pruned.broadcastTransactionRpcAgreement, false);

  const poststateDrift = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    runner: freshChainRunner(receipt, { secondaryPoststateDrift: true }),
  });
  assert.equal(poststateDrift.valid, false);
  assert.equal(poststateDrift.poststateValid, true);
  assert.equal(poststateDrift.secondaryPoststateValid, false);
  assert.equal(poststateDrift.poststateRpcAgreement, false);
  assert.notEqual(
    poststateDrift.primaryPoststateObservationsSha256,
    poststateDrift.secondaryPoststateObservationsSha256,
  );

  const codeDrift = verifyContractDeploymentChainEvidenceWithTestAdapters({
    ...input,
    runner: freshChainRunner(receipt, { secondaryCodeHashDrift: true }),
  });
  assert.equal(codeDrift.valid, false);
  assert.equal(codeDrift.runtimeCodeMatchCount, 7);
  assert.equal(codeDrift.secondaryRuntimeCodeMatchCount, 6);

  const historicalBlockHeaderDrift =
    verifyContractDeploymentChainEvidenceWithTestAdapters({
      ...input,
      runner: freshChainRunner(receipt, {
        secondaryHistoricalBlockHeaderDrift: true,
      }),
    });
  assert.equal(historicalBlockHeaderDrift.valid, false);
  assert.equal(historicalBlockHeaderDrift.broadcastTransactionRpcAgreement, false);
  assert.equal(
    historicalBlockHeaderDrift.broadcastTransactionProvenance.every(
      ({ secondaryBlockHashMatches, providerObservationsMatch }) => (
        secondaryBlockHashMatches === false && providerObservationsMatch === false
      ),
    ),
    true,
  );
});

test("production chain collector does not accept injected test adapters", () => {
  let invoked = false;
  const evidence = verifyContractDeploymentChainEvidence({
    authorityStage: "cvm_launch",
    rpcUrl: TEST_RPC_ENDPOINT,
    secondaryRpcUrl: TEST_SECONDARY_RPC_ENDPOINT,
    skipNetwork: true,
    castAvailable: true,
    runner: () => { invoked = true; throw new Error("must not run"); },
    independentReconstruction: { attacker: true },
    secondaryIndependentReconstruction: { attacker: true },
  });
  assert.equal(invoked, false);
  assert.equal(evidence.evidenceSource, "production_collector");
  assert.equal(evidence.valid, false);
});

test("offline test-adapter evidence cannot become activation-preflight authority", () => {
  const receipt = projectFreshContractDeploymentReceipt(
    freshContractLedgerFixture(),
    { releaseSha: SHA, ...FRESH_RECEIPT_AUTHORITY_PINS },
  );
  const adapterEvidence = verifyContractDeploymentChainEvidenceWithTestAdapters({
    contractDeploymentReceipt: receipt,
    deploymentIntent: freshDeploymentIntentForChainFixture(),
    deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
    releaseSha: SHA,
    independentReconstruction: independentReconstructionFixture(receipt),
    secondaryIndependentReconstruction: independentReconstructionFixture(receipt),
    authorityStage: "cvm_launch",
    rpcUrl: TEST_RPC_ENDPOINT,
    secondaryRpcUrl: TEST_SECONDARY_RPC_ENDPOINT,
    castAvailable: true,
    runner: freshChainRunner(receipt),
  });
  assert.equal(adapterEvidence.valid, true);
  assert.equal(adapterEvidence.evidenceSource, "test_adapter_not_release_authority");

  const snapshot = completeSnapshot();
  snapshot.authorityStage = "cvm_launch";
  snapshot.contractDeploymentChainEvidence = adapterEvidence;
  attachActivationReadinessSnapshot(snapshot);
  const report = buildPreflightReport(snapshot);
  assert.equal(
    report.checks.find(
      ({ id }) => id === "authority.contract_deployment_chain_evidence",
    )?.status,
    "fail",
  );
  assert.equal(
    report.checks.find(({ id }) => id === "authority.release_artifact_binding")
      ?.status,
    "fail",
  );
});

test("live ChallengeRegistry policy binds the approved set while permitting unrelated later rows", () => {
  const finalAuthority = finalAuthorityFixture();
  const binding = Object.values(finalAuthority.arena_registry_bindings)[0];
  const values = new Map([
    ["owner()(address)", finalAuthority.operator_address],
    ["pendingOwner()(address)", address("0")],
    ["registryPaused()(bool)", false],
    ["MIN_VERSION_REVIEW_DELAY()(uint64)", 172_800],
    ["challengeExists(uint256)(bool)", true],
    ["challengeCount()(uint256)", 1],
    ["nextChallengeId()(uint256)", 2],
    ["controllerChallengePaused(uint256)(bool)", false],
    ["governanceChallengePaused(uint256)(bool)", false],
    ["reviewEligibleAt(uint256)(uint64)", 173_800],
    [
      "getChallenge(uint256)((address,address,uint8,uint64,uint64,uint32,bool,bool))",
      [[binding.controller_address, address("0"), 1, 900, 1_000, 1, false, true]],
    ],
    [
      "getVersion(uint256,uint32)((string,bytes32,bytes32,bytes32,bytes32,uint64))",
      [[
        binding.metadata_uri,
        binding.metadata_hash,
        binding.sealed_artifact_commitment,
        binding.evaluator_commitment,
        binding.release_policy_commitment,
        1_000,
      ]],
    ],
  ]);
  const read = (signature) => values.get(signature);
  const challengePolicy = finalPoststatePolicies(
    finalAuthority,
    FINAL_AUTHORITY_SHA256,
  ).ChallengeRegistry;
  assert.deepEqual(
    Object.keys(challengePolicy),
    CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE.final_active_frozen.ChallengeRegistry,
  );
  assert.equal(Object.values(challengePolicy).every((assertion) => assertion(read)), true);

  values.set("challengeCount()(uint256)", 2);
  values.set("nextChallengeId()(uint256)", 3);
  assert.equal(Object.values(challengePolicy).every((assertion) => assertion(read)), true);
  values.set("nextChallengeId()(uint256)", 4);
  assert.equal(challengePolicy.active_challenge_count_at_least_one(read), false);
  values.set("challengeCount()(uint256)", 1);
  values.set("nextChallengeId()(uint256)", 2);

  const driftedRead = (signature) => signature.startsWith("getVersion")
    ? [[
      binding.metadata_uri,
      bytes32("f"),
      binding.sealed_artifact_commitment,
      binding.evaluator_commitment,
      binding.release_policy_commitment,
      1_000,
    ]]
    : values.get(signature);
  assert.equal(
    challengePolicy.genesis_catalog_matches_final_authority(driftedRead),
    false,
  );
});

test("every internal activation credential is mandatory and structurally validated", () => {
  const internalRows = REQUIRED_RUNTIME_CREDENTIALS.filter(
    ([, key]) => key !== "ETHERSCAN_API_KEY",
  );
  assert.equal(internalRows.length, 10);
  assert.equal(INTERNAL_RUNTIME_CREDENTIAL_GROUPS.length, 8);

  for (const [id, key] of internalRows) {
    const missing = completeSnapshot();
    delete missing.env[key];
    let report = buildPreflightReport(missing);
    assert.equal(report.verdict, "BLOCKED");
    assert.equal(report.checks.find((item) => item.id === id).status, "fail");

    const malformed = completeSnapshot();
    malformed.env[key] = "short";
    report = buildPreflightReport(malformed);
    assert.equal(report.verdict, "BLOCKED");
    assert.equal(report.checks.find((item) => item.id === id).status, "fail");
    assert.equal(formatHumanReport(report).includes("short"), false);
  }

  for (const invalidValue of [
    `${"a".repeat(31)} `,
    `${"a".repeat(31)}é`,
    `line${"a".repeat(28)}\n`,
  ]) {
    const snapshot = completeSnapshot();
    snapshot.env.TINKER_DILIGENCE_QVL_AUTH_TOKEN = invalidValue;
    const report = buildPreflightReport(snapshot);
    assert.equal(
      report.checks.find((item) => item.id === "credential.diligence_qvl").status,
      "fail",
    );
    assert.doesNotThrow(() => assertReportContainsNoSensitiveValues(report, snapshot.env));
  }
});

test("activation authority requires two distinct HTTPS Base Sepolia RPC origins", () => {
  const aliased = completeSnapshot();
  aliased.env.BASE_SEPOLIA_SECONDARY_RPC_URL =
    `${TEST_RPC_ENDPOINT}/same-provider-alias`;
  let check = buildPreflightReport(aliased).checks.find(
    (item) => item.id === "contract_input.base_sepolia_secondary_rpc_url",
  );
  assert.equal(check?.status, "fail");

  const insecure = completeSnapshot();
  insecure.env.BASE_SEPOLIA_SECONDARY_RPC_URL = "http://secondary.invalid/rpc";
  check = buildPreflightReport(insecure).checks.find(
    (item) => item.id === "contract_input.base_sepolia_secondary_rpc_url",
  );
  assert.equal(check?.status, "fail");
});

test("activation credential aliases and trust domains fail closed", () => {
  const splitAlias = completeSnapshot();
  splitAlias.env.METERING_QVL_AUTH_TOKEN = internalCredential("8");
  let report = buildPreflightReport(splitAlias);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "credential.internal_alias_binding").status,
    "fail",
  );
  assert.doesNotThrow(() => assertReportContainsNoSensitiveValues(report, splitAlias.env));

  const reusedDomain = completeSnapshot();
  reusedDomain.env.TINKER_ARENA_WORKER_QVL_AUTH_TOKEN =
    reusedDomain.env.TINKER_DILIGENCE_QVL_AUTH_TOKEN;
  report = buildPreflightReport(reusedDomain);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "credential.internal_domain_separation").status,
    "fail",
  );
  assert.doesNotThrow(() => assertReportContainsNoSensitiveValues(report, reusedDomain.env));

  const defaultNeko = completeSnapshot();
  defaultNeko.env.NEKO_PASSWORD = "neko";
  defaultNeko.env.NEKO_PASSWORD_ADMIN = "admin";
  report = buildPreflightReport(defaultNeko);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "credential.neko_policy").status,
    "fail",
  );

  const identicalNeko = completeSnapshot();
  identicalNeko.env.NEKO_PASSWORD_ADMIN = identicalNeko.env.NEKO_PASSWORD;
  report = buildPreflightReport(identicalNeko);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "credential.neko_policy").status,
    "fail",
  );
});

test("activation readiness requires the canonical signed-C seven-CVM dependency validation", () => {
  const missing = completeSnapshot();
  missing.canonicalSevenCvmAuthorityValidation = null;
  let report = buildPreflightReport(missing);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "evidence.canonical_seven_cvm_authority").status,
    "fail",
  );

  const crossRelease = completeSnapshot();
  crossRelease.canonicalSevenCvmAuthorityValidation.deploymentIntentSha256 =
    `sha256:${"ff".repeat(32)}`;
  report = buildPreflightReport(crossRelease);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "evidence.canonical_seven_cvm_authority").status,
    "fail",
  );

  const remintedFreshness = completeSnapshot();
  remintedFreshness.canonicalSevenCvmAuthorityValidation.evidenceMode =
    CANONICAL_SEVEN_CVM_AUTHORITY_FRESH_MODE;
  remintedFreshness.canonicalSevenCvmAuthorityValidation.truthStatus =
    CANONICAL_SEVEN_CVM_AUTHORITY_FRESH_TRUTH;
  report = buildPreflightReport(remintedFreshness);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "evidence.canonical_seven_cvm_authority").status,
    "fail",
  );
});

test("production evaluation accepts only the release-pinned deterministic in-CVM lane", () => {
  for (const mode of ["disabled", "sft", "stub", "", undefined, "unreviewed-provider"]) {
    const snapshot = completeSnapshot();
    if (mode === undefined) {
      delete snapshot.compose.document.services.delegate.environment.TINKER_EVALUATOR_MODE;
    } else {
      snapshot.compose.document.services.delegate.environment.TINKER_EVALUATOR_MODE = mode;
    }
    const report = buildPreflightReport(snapshot);
    assert.equal(report.verdict, "BLOCKED");
    assert.equal(
      report.checks.find((item) => item.id === "phala.confidential_evaluator_boundary").status,
      "fail",
    );
  }

  const duplicate = completeSnapshot();
  duplicate.compose.document.services["deal-runtime"].environment.TINKER_EVALUATOR_MODE =
    "deterministic";
  const report = buildPreflightReport(duplicate);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "phala.confidential_evaluator_boundary").status,
    "fail",
  );
});

test("pairwise role collisions block activation without exposing addresses", () => {
  const snapshot = completeSnapshot();
  snapshot.env.COMPUTE_VAULT_DEVELOPER = snapshot.env.DEPLOYMENT_OPERATOR;
  const report = buildPreflightReport(snapshot);
  const collision = report.checks.find((item) => item.id === "roles.pairwise_distinct");
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(collision.status, "fail");
  assert.match(collision.message, /DEPLOYMENT_OPERATOR \+ COMPUTE_VAULT_DEVELOPER/);
  assert.equal(formatHumanReport(report).includes(snapshot.env.DEPLOYMENT_OPERATOR), false);
});

test("dirty or SHA-drifted source blocks every live release", () => {
  const dirty = completeSnapshot();
  dirty.git.dirty = true;
  let report = buildPreflightReport(dirty);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(report.checks.find((item) => item.id === "source.clean").status, "fail");

  const drifted = completeSnapshot();
  drifted.env.RELEASE_SHA = "d".repeat(40);
  report = buildPreflightReport(drifted);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(report.checks.find((item) => item.id === "source.release_sha").status, "fail");
});

test("missing Phala, GitHub, and Cloudflare auth is explicit and blocking", () => {
  const snapshot = completeSnapshot();
  snapshot.probes.phalaAuth = false;
  snapshot.probes.githubAuth = false;
  snapshot.probes.cloudflareAuth = false;
  const report = buildPreflightReport(snapshot);
  assert.equal(report.verdict, "BLOCKED");
  for (const id of ["auth.phala", "auth.github", "auth.cloudflare"]) {
    assert.equal(report.checks.find((item) => item.id === id).status, "fail");
  }
});

test("read-only command allowlist rejects deploy, broadcast, login, and keystore unlocks", () => {
  assert.doesNotThrow(() => assertReadOnlyInvocation("gh", ["auth", "status"]));
  assert.doesNotThrow(() => assertReadOnlyInvocation("phala", ["status"]));
  assert.doesNotThrow(() => assertReadOnlyInvocation("cast", [
    "call",
    address("1"),
    "getChallenge(uint256)((address,address,uint8,uint64,uint64,uint32,bool,bool))",
    "1",
    "--json",
    "--block",
    "2000",
    "--rpc-url",
    "https://sepolia.base.org",
  ]));
  assert.doesNotThrow(() => assertReadOnlyInvocation("cast", [
    "call",
    address("1"),
    "getVersion(uint256,uint32)((string,bytes32,bytes32,bytes32,bytes32,uint64))",
    "1",
    "1",
    "--json",
    "--block",
    "2000",
    "--rpc-url",
    "https://sepolia.base.org",
  ]));
  assert.throws(
    () => assertReadOnlyInvocation("cast", [
      "call",
      address("1"),
      "getChallenge(uint256)((address,address,uint8,uint64,uint64,uint32,bool,bool))",
      "1",
      "--rpc-url",
      "https://sepolia.base.org",
    ]),
    /allowlist/,
  );
  assert.throws(
    () => assertReadOnlyInvocation("cast", [
      "call",
      address("1"),
      "setRegistryPaused(bool)",
      "false",
      "--block",
      "2000",
      "--rpc-url",
      "https://sepolia.base.org",
    ]),
    /allowlist/,
  );
  assert.throws(() => assertReadOnlyInvocation("phala", ["deploy"]), /unsafe|allowlist/);
  assert.throws(() => assertReadOnlyInvocation("phala", ["login"]), /unsafe|allowlist/);
  assert.throws(
    () => assertReadOnlyInvocation("forge", ["script", "Deploy.s.sol", "--broadcast"]),
    /unsafe|allowlist/,
  );
  assert.throws(
    () => assertReadOnlyInvocation("cast", ["wallet", "address", "--account", "dev"]),
    /unsafe|allowlist/,
  );
});

test("tool presence and Phala identity are bounded without executing a hanging CLI", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-tool-probe-"));
  try {
    const bin = path.join(directory, "bin");
    await mkdir(bin);
    const executable = path.join(bin, "phala");
    await writeFile(executable, "#!/bin/sh\nexit 99\n");
    await chmod(executable, 0o755);
    await writeFile(path.join(directory, "package.json"), `${JSON.stringify({
      name: "phala",
      version: "1.1.19",
    })}\n`);
    const environment = { PATH: bin };
    assert.equal(resolveExecutablePath("phala", environment), await realpath(executable));
    assert.deepEqual(inspectInstalledCliVersion("phala", "phala", environment), {
      valid: true,
      version: "1.1.19",
      source: "installed_package_manifest",
    });
    assert.equal(resolveExecutablePath("missing", environment), "");
    assert.equal(
      inspectInstalledCliVersion("phala", "unreviewed-package", environment).valid,
      false,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Cloudflare OAuth probe accepts bounded delayed success without projecting output", () => {
  let invocation;
  const result = probeCloudflareAuthentication(
    {
      CLOUDFLARE_API_TOKEN: "test-secret-token",
      CLOUDFLARE_ACCOUNT_ID: "test-account-id",
    },
    (command, args, options) => {
      invocation = { command, args, options };
      return {
        ok: true,
        stdout: "authenticated response that must not be projected",
      };
    },
  );
  assert.equal(result, true);
  assert.equal(invocation.command, "wrangler");
  assert.deepEqual(invocation.args, ["whoami"]);
  assert.equal(invocation.options.timeout, CLOUDFLARE_AUTH_PROBE_TIMEOUT_MS);
  assert.equal(invocation.options.timeout >= 120_000, true);
  assert.deepEqual(invocation.options.env, {
    CLOUDFLARE_API_TOKEN: "test-secret-token",
    CLOUDFLARE_ACCOUNT_ID: "test-account-id",
  });
});

test("activation preflight rejects duplicate path and mode flags", () => {
  assert.throws(
    () => parsePreflightArgs(["--release", "/tmp/one.json", "--release", "/tmp/two.json"]),
    /duplicate argument: --release/,
  );
  assert.throws(
    () => parsePreflightArgs(["--json", "--json"]),
    /duplicate argument: --json/,
  );
  const parsed = parsePreflightArgs([
    "--image-release-attestation-bundle",
    "/tmp/release.bundle.json",
    "--image-release-sigstore-verification-receipt",
    "/tmp/release.sigstore-verification.json",
  ]);
  assert.equal(parsed.imageReleaseAttestationBundle, "/tmp/release.bundle.json");
  assert.equal(
    parsed.imageReleaseSigstoreVerificationReceipt,
    "/tmp/release.sigstore-verification.json",
  );
  const authorityArgs = parsePreflightArgs([
    "--deployment-intent",
    "/tmp/deployment-intent.json",
    "--cvm-launch-intent",
    "/tmp/cvm-launch-intent.json",
    "--authority-review-envelope",
    "/tmp/final-authority.review.json",
    "--authority-review-evidence",
    "/tmp/final-authority.review-evidence.json",
    "--stage",
    "fresh-deployment",
  ]);
  assert.equal(authorityArgs.deploymentIntent, "/tmp/deployment-intent.json");
  assert.equal(authorityArgs.cvmLaunchIntent, "/tmp/cvm-launch-intent.json");
  assert.equal(authorityArgs.authorityReviewEnvelope, "/tmp/final-authority.review.json");
  assert.equal(
    authorityArgs.authorityReviewEvidence,
    "/tmp/final-authority.review-evidence.json",
  );
  assert.equal(authorityArgs.authorityStage, "fresh_deployment");
  assert.equal(authorityArgs.authorityStageExplicit, true);
  assert.deepEqual(
    authorityArgs.explicitPathKeys,
    [
      "deploymentIntent",
      "cvmLaunchIntent",
      "authorityReviewEnvelope",
      "authorityReviewEvidence",
    ],
  );
  const defaultAuthorityArgs = parsePreflightArgs([]);
  assert.equal(defaultAuthorityArgs.authorityStage, "live_activation");
  assert.equal(defaultAuthorityArgs.authorityStageExplicit, false);
  assert.equal(defaultAuthorityArgs.ledger, "");
  assert.match(defaultAuthorityArgs.deploymentIntent, /deployment-intent-core\.json$/);
  assert.match(defaultAuthorityArgs.cvmLaunchIntent, /cvm-launch-intent-core\.json$/);
  assert.match(
    defaultAuthorityArgs.authorityReviewEnvelope,
    /final-authority\.review-envelope\.json$/,
  );
  assert.match(
    parsePreflightArgs(["--stage", "cvm-launch"]).authorityReviewEnvelope,
    /cvm-launch-intent\.review-envelope\.json$/,
  );
  const ceremonyArgs = parsePreflightArgs(["--stage", "release-ceremony"]);
  assert.equal(ceremonyArgs.authorityStage, "release_ceremony");
  assert.match(
    ceremonyArgs.authorityReviewEnvelope,
    /final-authority\.review-envelope\.json$/,
  );
  assert.throws(
    () => parsePreflightArgs(["--stage", "preview"]),
    /fresh-deployment, cvm-launch, release-ceremony, or live-activation/,
  );
  assert.throws(
    () => parsePreflightArgs([
      "--stage",
      "fresh-deployment",
      "--stage",
      "live-activation",
    ]),
    /duplicate argument: --stage/,
  );
  for (const retiredFlag of ["--operator-policy", "--operator-review-evidence"]) {
    assert.throws(
      () => parsePreflightArgs([retiredFlag, "/tmp/retired.json"]),
      /unknown argument/,
    );
  }
  assert.throws(
    () => parsePreflightArgs([
      "--image-release-attestation-bundle",
      "/tmp/one.bundle.json",
      "--image-release-attestation-bundle",
      "/tmp/two.bundle.json",
    ]),
    /duplicate argument: --image-release-attestation-bundle/,
  );
  assert.throws(
    () => parsePreflightArgs([
      "--image-release-sigstore-verification-receipt",
      "/tmp/one.receipt.json",
      "--image-release-sigstore-verification-receipt",
      "/tmp/two.receipt.json",
    ]),
    /duplicate argument: --image-release-sigstore-verification-receipt/,
  );
});

test("preflight path resolution uses release-scoped defaults and rejects CLI/env ambiguity", () => {
  const repositoryRoot = "/tmp/dnai-preflight-path-contract";
  const args = parsePreflightArgs(["--stage", "fresh-deployment"]);
  const env = { RELEASE_SHA: SHA };
  assert.equal(
    releaseScopedLedgerPath(SHA, SHA, repositoryRoot),
    path.join(
      repositoryRoot,
      "deployments",
      "fresh-contract-suites",
      SHA,
      "base-sepolia.json",
    ),
  );
  assert.equal(releaseScopedLedgerPath(SHA, "f".repeat(40), repositoryRoot), "");
  assert.equal(releaseScopedLedgerPath("not-a-sha", SHA, repositoryRoot), "");

  const defaults = resolveEvidencePaths(args, env, { gitHead: SHA, repositoryRoot });
  assert.equal(
    defaults.ledger,
    path.join(
      repositoryRoot,
      "deployments",
      "fresh-contract-suites",
      SHA,
      "base-sepolia.json",
    ),
  );
  assert.equal(
    defaults.deploymentIntent,
    path.join(repositoryRoot, ".release", "deployment-intent-core.json"),
  );
  assert.equal(
    defaults.cvmLaunchIntent,
    path.join(repositoryRoot, ".release", "cvm-launch-intent-core.json"),
  );

  const envBound = resolveEvidencePaths(args, {
    ...env,
    DEPLOYMENT_MANIFEST_PATH: "/tmp/operator-ledger.json",
    DEPLOYMENT_INTENT_PATH: "/tmp/operator-deployment-intent.json",
    OPERATOR_POLICY_REVIEW_ENVELOPE_PATH: "/tmp/operator-review-envelope.json",
  }, { gitHead: SHA, repositoryRoot });
  assert.equal(envBound.ledger, "/tmp/operator-ledger.json");
  assert.equal(envBound.deploymentIntent, "/tmp/operator-deployment-intent.json");
  assert.equal(envBound.authorityReviewEnvelope, "/tmp/operator-review-envelope.json");

  const explicit = parsePreflightArgs([
    "--stage",
    "fresh-deployment",
    "--ledger",
    "/tmp/cli-ledger.json",
    "--deployment-intent",
    "/tmp/cli-deployment-intent.json",
  ]);
  assert.equal(
    resolveEvidencePaths(explicit, env, { gitHead: SHA, repositoryRoot }).ledger,
    "/tmp/cli-ledger.json",
  );
  assert.throws(
    () => resolveEvidencePaths(explicit, {
      ...env,
      DEPLOYMENT_MANIFEST_PATH: "/tmp/different-ledger.json",
    }, { gitHead: SHA, repositoryRoot }),
    /ledger is ambiguous between the CLI flag and DEPLOYMENT_MANIFEST_PATH/,
  );
  assert.throws(
    () => resolveEvidencePaths(explicit, {
      ...env,
      DEPLOYMENT_INTENT_PATH: "/tmp/different-deployment-intent.json",
    }, { gitHead: SHA, repositoryRoot }),
    /deploymentIntent is ambiguous between the CLI flag and DEPLOYMENT_INTENT_PATH/,
  );

  const historical = parsePreflightArgs([
    "--stage",
    "fresh-deployment",
    "--ledger",
    path.join(repositoryRoot, "deployments", "base-sepolia.json"),
  ]);
  assert.throws(
    () => resolveEvidencePaths(historical, env, { gitHead: SHA, repositoryRoot }),
    /historical deployments\/base-sepolia\.json ledger is not activation authority/,
  );
  assert.throws(
    () => resolveEvidencePaths(args, {
      ...env,
      DEPLOYMENT_INTENT_PATH: "relative/deployment-intent.json",
    }, { gitHead: SHA, repositoryRoot }),
    /DEPLOYMENT_INTENT_PATH must be a canonical absolute path/,
  );
});

test("env parser treats command syntax as inert text", () => {
  const env = parseEnvText([
    "TOKEN='SUPER_SECRET#VALUE'",
    "RPC_URL=https://rpc.example/path # comment",
    "DANGEROUS=$(touch /tmp/activation-preflight-must-not-exist)",
  ].join("\n"));
  assert.equal(env.TOKEN, "SUPER_SECRET#VALUE");
  assert.equal(env.RPC_URL, "https://rpc.example/path");
  assert.equal(env.DANGEROUS, "$(touch /tmp/activation-preflight-must-not-exist)");
});

test("parseable evidence alone is never release authority", () => {
  const snapshot = completeSnapshot();
  snapshot.semanticEvidenceValidated = false;
  for (const key of [
    "releaseCandidate",
    "artifactEvidence",
    "arenaEvidence",
    "anchorWriterEvidence",
  ]) {
    snapshot.files[key] = { ...snapshot.files[key], valid: true, value: {} };
  }
  const report = buildPreflightReport(snapshot);
  assert.equal(report.verdict, "BLOCKED");
  const semantic = report.checks.find(
    (item) => item.id === "evidence.semantic_release_authority",
  );
  assert.equal(semantic.status, "fail");
  assert.match(semantic.message, /structural_presence_only_not_release_authority/);
  for (const key of [
    "evidence.release_candidate",
    "evidence.ledger",
    "evidence.artifact_evidence",
    "evidence.arena_evidence",
    "evidence.anchor_writer_evidence",
  ]) {
    assert.equal(report.checks.find((item) => item.id === key).status, "warn");
  }
});

test("manifest URLs bind the exact workflow and attestation IDs", () => {
  for (const mutate of [
    (value) => { value.workflow_run_url += "/extra"; },
    (value) => { value.workflow_run_url += "?attempt=2"; },
    (value) => { value.images[0].attestations.provenance.url += "0"; },
    (value) => { value.images[0].attestations.sbom.url += "?raw=1"; },
  ]) {
    const value = structuredClone(imageReleaseManifest());
    mutate(value);
    assert.equal(inspectImageRelease(value).valid, false);
  }
});

test("seven topology descriptors must remain hash-distinct", () => {
  const topology = structuredClone(completeSnapshot().files.topology.value);
  topology.trust_domains.arena_qvl_cvm.sha256 =
    topology.trust_domains.diligence_qvl_cvm.sha256;
  assert.equal(inspectCvmTopology(topology).valid, false);
});

test("topology phase gates are exact, empty-bootstrap, profile-specific authority", () => {
  const mutations = [
    (topology) => {
      delete topology.trust_domains.diligence_qvl_cvm.phase_gate;
    },
    (topology) => {
      topology.trust_domains.arena_qvl_cvm.phase_gate.initial_services = ["qvl"];
    },
    (topology) => {
      topology.trust_domains.compute_workload_qvl_cvm
        .phase_gate.activation_environment.exact_value = "metering-runtime";
    },
    (topology) => {
      topology.trust_domains.independent_metering_cvm
        .phase_gate.activation_environment.exact_value = "qvl-runtime";
    },
    (topology) => {
      topology.trust_domains.compute_metering_qvl_cvm.phase_gate.unreviewed = true;
    },
  ];
  for (const mutate of mutations) {
    const topology = structuredClone(completeSnapshot().files.topology.value);
    mutate(topology);
    assert.equal(inspectCvmTopology(topology).valid, false);
  }
});

test("release-manifest provenance and bundle hash are independent readiness gates", () => {
  const missing = completeSnapshot();
  missing.files.imageReleaseAttestationBundle = {
    exists: false,
    valid: false,
    sha256: "",
  };
  missing.releaseManifestAttestation = { ok: false };
  let report = buildPreflightReport(missing);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "image.release_manifest_provenance").status,
    "fail",
  );
  assert.equal(
    report.checks.find((item) => item.id === "evidence.cvm_topology_binding").status,
    "fail",
  );

  const failedVerification = completeSnapshot();
  failedVerification.releaseManifestAttestation = { ok: false };
  report = buildPreflightReport(failedVerification);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "image.release_manifest_provenance").status,
    "fail",
  );

  const drifted = completeSnapshot();
  drifted.files.imageReleaseAttestationBundle.sha256 = "7".repeat(64);
  drifted.releaseManifestAttestation = { ok: false };
  report = buildPreflightReport(drifted);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "evidence.cvm_topology_binding").status,
    "fail",
  );
});

test("a copied test-adapter Sigstore receipt cannot clear activation provenance", () => {
  const snapshot = completeSnapshot();
  snapshot.releaseManifestAttestation = {
    ...snapshot.releaseManifestAttestation,
    status: "test_adapter_verified_not_release_authority",
  };
  const report = buildPreflightReport(snapshot);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "image.release_manifest_provenance").status,
    "fail",
  );
});

test("an extra main sidecar cannot hide behind an allowed image or matching hash", () => {
  const snapshot = completeSnapshot();
  const sidecar = hardened(image("tinker-delegate", "7"), { networks: ["tee-net"] });
  snapshot.compose.document.services.sidecar = sidecar;
  snapshot.compose.services.sidecar = { ...sidecar, raw: JSON.stringify(sidecar) };
  const report = buildPreflightReport(snapshot);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "phala.main_service_topology").status,
    "fail",
  );
  assert.equal(
    report.checks.find((item) => item.id === "evidence.cvm_topology_binding").status,
    "fail",
  );
});

test("privilege, writable host mounts, and unreviewed ports block activation", () => {
  const cases = [
    (snapshot) => { snapshot.compose.document.services.delegate.privileged = true; },
    (snapshot) => {
      snapshot.compose.document.services.delegate.volumes = ["/etc:/host-etc:rw"];
    },
    (snapshot) => { snapshot.compose.document.services["deal-runtime"].ports = ["9000:9000"]; },
    (snapshot) => { snapshot.compose.document.services["arena-worker"].build = "."; },
  ];
  for (const mutate of cases) {
    const snapshot = completeSnapshot();
    mutate(snapshot);
    const report = buildPreflightReport(snapshot);
    assert.equal(report.verdict, "BLOCKED");
    assert.equal(
      report.checks.find((item) => item.id === "phala.compose_security").status,
      "fail",
    );
  }
});

test("writer and Deal bearer networks are fail-closed", () => {
  const snapshot = completeSnapshot();
  snapshot.compose.document.services["anchor-writer-evidence"].networks = ["tee-net"];
  snapshot.compose.services["anchor-writer-evidence"].networks = ["tee-net"];
  const report = buildPreflightReport(snapshot);
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "phala.main_release_profiles").status,
    "fail",
  );
});

test("compose inspection accepts only generated canonical JSON/YAML", () => {
  const document = {
    services: {
      delegate: hardened(image("tinker-delegate", "7")),
    },
  };
  const header = [
    "# Generated by tinker-release-composes. Do not edit by hand.",
    `# Input image manifest sha256: ${"a".repeat(64)}`,
    "# Status: rendered_not_deployed; deployment and TDX verification are separate gates.",
  ].join("\n");
  const canonical = `${header}\n${JSON.stringify(document, null, 2)}\n`;
  assert.equal(inspectCompose(canonical).valid, true);
  assert.equal(inspectCompose("services:\n  delegate:\n    image: latest\n").valid, false);
  const duplicate = `${header}\n{\n  "services": {},\n  "services": {}\n}\n`;
  assert.equal(inspectCompose(duplicate).valid, false);
});

test("file inspection hashes one no-follow descriptor and rejects symlinks", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-preflight-"));
  try {
    const target = path.join(directory, "evidence.json");
    const link = path.join(directory, "evidence-link.json");
    await writeFile(target, `${JSON.stringify({ schema: "test" }, null, 2)}\n`);
    await chmod(target, 0o600);
    await symlink(target, link);
    const inspected = await inspectFile(target, { json: true, mode0600: true });
    assert.equal(inspected.valid, true);
    assert.match(inspected.sha256, /^[0-9a-f]{64}$/);
    assert.equal((await inspectFile(link, { json: true })).valid, false);

    const noncanonical = path.join(directory, "noncanonical.json");
    await writeFile(noncanonical, '{"schema":"test"}\n');
    assert.equal((await inspectFile(noncanonical, { json: true })).valid, false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("GitHub attestation verification is source-ref bound and exactly allowlisted", () => {
  const args = githubAttestationArgs(
    image("tinker-delegate", "7"),
    SHA,
    "refs/heads/main",
    "https://slsa.dev/provenance/v1",
  );
  assert.doesNotThrow(() => assertReadOnlyInvocation("gh", args));
  assert.deepEqual(args.slice(10, 12), ["--source-ref", "refs/heads/main"]);
  const withoutRef = [...args.slice(0, 10), ...args.slice(12)];
  assert.throws(() => assertReadOnlyInvocation("gh", withoutRef), /allowlist/);
  const wrongRef = [...args];
  wrongRef[11] = "refs/heads/unreviewed";
  assert.throws(() => assertReadOnlyInvocation("gh", wrongRef), /allowlist/);

  const manifestArgs = githubReleaseManifestAttestationArgs(
    "/tmp/dnai-tee-image-release.json",
    "/tmp/dnai-tee-image-release.bundle.json",
    SHA,
    "refs/heads/main",
  );
  assert.doesNotThrow(() => assertReadOnlyInvocation("gh", manifestArgs));
  assert.deepEqual(manifestArgs.slice(5, 7), [
    "--bundle",
    "/tmp/dnai-tee-image-release.bundle.json",
  ]);
  const mutableBundleFetch = [...manifestArgs];
  mutableBundleFetch[5] = "--bundle-from-oci";
  assert.throws(
    () => assertReadOnlyInvocation("gh", mutableBundleFetch),
    /allowlist/,
  );
  const wrongPredicate = [...manifestArgs];
  wrongPredicate[15] = "https://spdx.dev/Document/v2.3";
  assert.throws(() => assertReadOnlyInvocation("gh", wrongPredicate), /allowlist/);
  assert.throws(
    () => githubReleaseManifestAttestationArgs(
      "relative.json",
      "/tmp/dnai-tee-image-release.bundle.json",
      SHA,
      "refs/heads/main",
    ),
    /bounded absolute paths/,
  );
});

test("semantic release validation uses one exact check-only allowlisted invocation", () => {
  const paths = semanticPaths();
  const args = semanticValidatorArgs(paths);
  assert.doesNotThrow(() => assertReadOnlyInvocation(process.execPath, args));
  assert.equal(SEMANTIC_VALIDATOR_INPUT_FLAGS.length, 37);
  assert.equal(args.length, 76);
  assert.equal(args.includes("--output"), false);
  assert.equal(args.includes("--check-only"), true);
  assert.deepEqual(args.slice(2), SEMANTIC_VALIDATOR_INPUT_FLAGS.flatMap(
    (flag) => [flag, paths[semanticPathKey(flag)]],
  ));
  assert.equal(args.includes("--authority-review-envelope"), false);

  const reordered = [...args];
  [reordered[2], reordered[4]] = [reordered[4], reordered[2]];
  assert.throws(
    () => assertReadOnlyInvocation(process.execPath, reordered),
    /allowlist/,
  );
  const differentScript = [...args];
  differentScript[0] = "/tmp/unreviewed-validator.mjs";
  assert.throws(
    () => assertReadOnlyInvocation(process.execPath, differentScript),
    /allowlist/,
  );
  assert.throws(
    () => semanticValidatorArgs({ ...paths, ledger: "relative.json" }),
    /canonical absolute input path --ledger/,
  );
  const omitted = { ...paths };
  delete omitted.computeWorkloadQvlIdentityRequest;
  assert.throws(
    () => semanticValidatorArgs(omitted),
    /--compute-workload-qvl-identity-request/,
  );
});

test("semantic validation fails closed when an input mutates during the validator subprocess", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-preflight-toctou-"));
  try {
    const paths = semanticPaths(directory);
    const names = Object.keys(paths);
    await Promise.all(Object.values(paths).map((filePath) => writeFile(filePath, "{}\n")));
    const initial = Object.fromEntries(await Promise.all(names.map(async (name) => [
      name,
      await inspectFile(paths[name]),
    ])));
    const bindings = names.map((name) => ({ path: paths[name], initial: initial[name] }));
    assert.equal(await validateStableFileBindings(bindings), true);

    const result = await runStableSemanticReleaseValidation({
      paths,
      env: {},
      expectedAuthority: semanticAuthorityExpectation(),
    }, bindings, () => {
      writeFileSync(paths.ledger, "{\"mutated\":true}\n");
      return { ok: true, stdout: `${JSON.stringify(semanticReceiptFixture())}\n` };
    });
    assert.deepEqual(result, {
      valid: false,
      reason: "canonical_semantic_validator_inputs_changed",
    });
    assert.equal(await validateStableFileBindings(bindings), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("semantic validator receipt is exact, bounded, release-bound, and hash-only", () => {
  const receipt = semanticReceiptFixture();
  const expected = semanticAuthorityExpectation();
  const encoded = `${JSON.stringify(receipt)}\n`;
  assert.equal(
    parseSemanticValidationReceipt(encoded, expected).valid,
    true,
  );
  assert.equal(
    parseSemanticValidationReceipt(
      `${JSON.stringify({ ...receipt, release_sha: "b".repeat(40) })}\n`,
      expected,
    ).valid,
    false,
  );
  assert.equal(
    parseSemanticValidationReceipt(
      `${JSON.stringify({ ...receipt, secret: "must-not-pass" })}\n`,
      expected,
    ).valid,
    false,
  );
  for (const field of [
    "deployment_intent_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
    "ceremony_authorization_sha256",
    "live_activation_authority_sha256",
    "runtime_authority_dependency_sha256",
  ]) {
    const missingAuthorityHash = { ...receipt };
    delete missingAuthorityHash[field];
    assert.equal(
      parseSemanticValidationReceipt(
        `${JSON.stringify(missingAuthorityHash)}\n`,
        expected,
      ).valid,
      false,
      field,
    );
    assert.equal(
      parseSemanticValidationReceipt(
        `${JSON.stringify({
          ...receipt,
          [field]: `sha256:${"b2".repeat(32)}`,
        })}\n`,
        expected,
      ).valid,
      false,
      field,
    );
  }
  for (const field of [
    "compute_workload_activation_observation_sha256",
    "compute_workload_browser_binding_sha256",
    "frontend_build_candidate_receipt_sha256",
    "release_inputs_sha256",
    "release_env_sha256",
    "frontend_build_sha256",
  ]) {
    assert.equal(
      parseSemanticValidationReceipt(
        `${JSON.stringify({ ...receipt, [field]: `sha256:${"0".repeat(64)}` })}\n`,
        expected,
      ).valid,
      false,
      field,
    );
  }
  assert.equal(
    parseSemanticValidationReceipt(`${encoded}noise`, expected).valid,
    false,
  );
  assert.equal(
    parseSemanticValidationReceipt(encoded, {
      ...expected,
      deploymentIntentSha256: `sha256:${"0".repeat(64)}`,
    }).valid,
    false,
  );
});

test("semantic readiness can only come from the canonical validator receipt", () => {
  const paths = semanticPaths();
  const env = {
    GH_TOKEN: "secret-gh",
    GITHUB_TOKEN: "secret-github",
    BASE_SEPOLIA_RPC_URL: "https://rpc.example/secret",
    TRUSTED_ATTESTATION_VERIFIER_ADDRESSES:
      `${address("5")},${address("6")},${address("7")}`,
    PHALA_CLOUD_API_KEY: "must-not-cross-boundary",
    OPENROUTER_API_KEY: "must-not-cross-boundary",
  };
  let observed;
  const result = runSemanticReleaseValidation(
    {
      paths,
      env,
      expectedAuthority: semanticAuthorityExpectation(),
    },
    (command, args, options) => {
      observed = { command, args, options };
      return {
        ok: true,
        stdout: `${JSON.stringify({
          ...semanticReceiptFixture(),
          release_env_sha256: `sha256:${"d".repeat(64)}`,
        })}\n`,
      };
    },
  );
  assert.equal(result.valid, true);
  assert.equal(observed.command, process.execPath);
  assert.doesNotThrow(() => assertReadOnlyInvocation(observed.command, observed.args));
  assert.deepEqual(observed.options.env, semanticValidationEnvironment(env));
  assert.equal("PHALA_CLOUD_API_KEY" in observed.options.env, false);
  assert.equal("OPENROUTER_API_KEY" in observed.options.env, false);

  const rejected = runSemanticReleaseValidation(
    {
      paths,
      env,
      expectedAuthority: semanticAuthorityExpectation(),
    },
    () => ({ ok: false, stdout: "" }),
  );
  assert.equal(rejected.valid, false);
  const malformed = runSemanticReleaseValidation(
    {
      paths,
      env,
      expectedAuthority: semanticAuthorityExpectation(),
    },
    () => ({ ok: true, stdout: `${JSON.stringify({ validated: true })}\n` }),
  );
  assert.equal(malformed.valid, false);
});
