#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  accessSync,
  constants,
  readFileSync,
  realpathSync,
  statSync,
} from "node:fs";
import { open } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  ACTIVATION_READINESS_ANCHOR_WRITER_GAS_CLAIM,
  ACTIVATION_READINESS_ANCHOR_WRITER_GAS_SCHEMA,
  ACTIVATION_READINESS_MAX_LIFETIME_MS,
  BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS,
  CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS,
  CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE,
  EXPECTED_GITHUB_REPOSITORY,
  EXPECTED_GITHUB_WORKFLOW,
  SEMANTIC_VALIDATION_SCHEMA,
  SEMANTIC_VALIDATION_STATUS,
  SEMANTIC_VALIDATION_TRUTH_STATUS,
  buildPreflightReport,
  activationReadinessRpcEndpointDigest,
  activationReadinessRpcOriginDigest,
  activationReadinessAnchorWriterGasObservationDigest,
  activationReadinessSnapshotDigest,
  assertReportContainsNoSensitiveValues,
  clean,
  collectDigestImages,
  createActivationReadinessSnapshot,
  defaultAnchorWriterQvlComposePath,
  defaultArenaQvlComposePath,
  defaultComposePath,
  defaultComputeMeteringQvlComposePath,
  defaultComputeWorkloadQvlComposePath,
  defaultDiligenceQvlComposePath,
  defaultImageReleaseAttestationBundlePath,
  defaultImageReleasePath,
  defaultImageReleaseSigstoreVerificationReceiptPath,
  defaultMeteringComposePath,
  defaultTopologyPath,
  formatHumanReport,
  inspectCvmTopology,
  inspectCompose,
  inspectImageRelease,
  parseEnvText,
} from "./activation-preflight-core.mjs";
import {
  CURRENT_FRONTEND_EXACT38_INPUT_FLAGS,
  CURRENT_FRONTEND_PRE_D_EXACT36_INPUT_FLAGS,
} from "../web/scripts/build-release-env.mjs";

export const SEMANTIC_VALIDATOR_INPUT_FLAGS =
  CURRENT_FRONTEND_EXACT38_INPUT_FLAGS;
export {
  CURRENT_FRONTEND_EXACT38_INPUT_FLAGS,
  CURRENT_FRONTEND_PRE_D_EXACT36_INPUT_FLAGS,
};
import {
  describeAuthorityReviewSubjectText,
  parseDeploymentIntentCoreText,
} from "./operator-policy-packet-core.mjs";
import {
  inspectCompletedDiligenceReleaseCeremony,
} from "./diligence-release-activation-gate.mjs";
import {
  projectDeploymentIntentEnvironment,
} from "./ceremony-authority-projector.mjs";
import {
  normalizeFreshContractReleaseReconstruction,
  reconstructFreshContractRelease,
} from "./fresh-contract-release-reconstruction.mjs";
import {
  CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS,
  CVM_LAUNCH_DOMAINS,
  FRESH_DEPLOYMENT_TRANSACTION_SPEC,
  PHALA_CONTROL_PLANE_AUTHORITY,
  cvmLaunchIntentValidationReceipt,
  freshContractDeploymentReceiptDigest,
  normalizeFreshContractDeploymentReceipt,
  parseCvmLaunchIntentCoreText,
  projectFreshContractDeploymentReceipt,
} from "./cvm-launch-intent-core.mjs";
import {
  projectFinalReleaseAuthorityRuntimeFeatureValues,
} from "./phala-production-environment-authority.mjs";
import {
  PHALA_COLLABORATION_LAUNCH_GATE_POLICY,
  assertPhalaProductionTargetCollaborationLaunchGatePolicy,
} from "./phala-production-target-authority.mjs";
import {
  RELEASE_MANIFEST_SIGSTORE_BLOCKER,
  assertProductionReleaseManifestSigstoreVerificationReceipt,
  canonicalReleaseManifestSigstoreVerificationReceiptText,
  releaseManifestSigstoreVerificationReceiptSha256,
  verifyReleaseManifestSigstoreAttestation,
} from "./release-manifest-sigstore-verifier.mjs";
import { ethereumKeccak256Hex } from "./ethereum-keccak.mjs";
import {
  TINKER_ACCOUNT_BINDING_TYPEHASH,
  TINKER_PROVIDER_NAMESPACE,
} from "./tinker-account-binding-core.mjs";
import {
  TINKER_ACCOUNT_BINDING_CEREMONY_BASENAME,
  TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME,
  normalizeTinkerAccountBindingCeremonyReceipt,
  verifyTinkerAccountBindingCeremonyArtifact,
  verifyTinkerAccountBindingCeremonyHistoricalReplay,
} from "./tinker-account-binding-ceremony.mjs";
import {
  replayReleaseCeremonyLedgerRevisionChain,
} from "./release-ceremony-ledger.mjs";
import {
  normalizeRoyaltyReleaseAuthority,
} from "./royalty-release-authority-core.mjs";
import {
  EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY,
} from "./execution-policy-release-core.mjs";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const semanticValidatorScript = path.join(rootDir, "web", "scripts", "build-release-env.mjs");
const operatorPolicyPacketScript = path.join(
  rootDir,
  "scripts",
  "operator-policy-packet.mjs",
);
const contractsProject = path.join(rootDir, "⚙️", "tinker-delegate", "contracts");
const historicalLedger = path.join(rootDir, "deployments", "base-sepolia.json");
const defaultDeploymentIntent = path.join(
  rootDir,
  ".release",
  "dnai-deployment-intent-core.json",
);
const defaultCvmLaunchIntent = path.join(rootDir, ".release", "cvm-launch-intent-core.json");
const defaultTinkerAccountBindingCeremony = path.join(
  rootDir,
  ".release",
  TINKER_ACCOUNT_BINDING_CEREMONY_BASENAME,
);
const defaultTinkerAccountBindingCeremonyReceipt = path.join(
  rootDir,
  ".release",
  TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME,
);
const MAX_INPUT_BYTES = 2 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = 20_000;
const CONTRACT_RECONSTRUCTION_TIMEOUT_MS = 60_000;
const SEMANTIC_VALIDATION_TIMEOUT_MS = 180_000;
export const CLOUDFLARE_AUTH_PROBE_TIMEOUT_MS = 120_000;
export {
  SEMANTIC_VALIDATION_SCHEMA,
  SEMANTIC_VALIDATION_STATUS,
  SEMANTIC_VALIDATION_TRUTH_STATUS,
};
const FORBIDDEN_TOKENS = new Set([
  "--account",
  "--broadcast",
  "--private-key",
  "create",
  "delete",
  "deploy",
  "login",
  "logout",
  "publish",
  "push",
  "send",
  "update",
]);
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const LOWER_ADDRESS = /^0x[0-9a-f]{40}$/;
const LOWER_BYTES32 = /^0x[0-9a-f]{64}$/;
const SAFE_BLOCK_NUMBER = /^(?:[1-9][0-9]{0,15})$/;
const SAFE_UINT256_ARGUMENT = /^(?:0|[1-9][0-9]{0,77})$/;
export const EXECUTION_POLICY_ANCHOR_TYPE =
  "ExecutionPolicyAnchor(uint256 chainId,address anchor,uint256 sequence,bytes32 previousGlobalHead,bytes32 resourceHash,bytes32 previousResourceHead,bytes32 decisionHash,address writer,bytes32 writerReleaseCommitment)";
export const EXECUTION_POLICY_ANCHOR_TYPEHASH = ethereumKeccak256Hex(
  Buffer.from(EXECUTION_POLICY_ANCHOR_TYPE, "utf8"),
);
export const EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_DOMAIN =
  "dnai-wikigen/execution-policy/final-release-authority/v1";
export const EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_HASH = ethereumKeccak256Hex(
  Buffer.from(EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_DOMAIN, "utf8"),
);
export const EXECUTION_POLICY_DECISION_ANCHORED_EVENT =
  "DecisionAnchored(uint256 indexed sequence,bytes32 indexed resourceHash,bytes32 indexed decisionHash,bytes32 previousGlobalHead,bytes32 newGlobalHead,bytes32 previousResourceHead,address writer,bytes32 writerReleaseCommitment)";
export const EXECUTION_POLICY_DECISION_ANCHORED_TOPIC = ethereumKeccak256Hex(
  Buffer.from(
    "DecisionAnchored(uint256,bytes32,bytes32,bytes32,bytes32,bytes32,address,bytes32)",
    "utf8",
  ),
);
const EXECUTION_POLICY_ANCHOR_DECISION_SIGNATURE =
  "anchorDecision(uint256,bytes32,bytes32,bytes32,bytes32,bytes32)";
const EXECUTION_POLICY_ANCHOR_DECISION_SELECTOR = ethereumKeccak256Hex(
  Buffer.from(EXECUTION_POLICY_ANCHOR_DECISION_SIGNATURE, "utf8"),
).slice(0, 10);
const CONTRACT_POSTSTATE_VIEW_SIGNATURES = new Set([
  "ACCOUNT_BINDING_TYPEHASH()(bytes32)",
  "ANCHOR_TYPEHASH()(bytes32)",
  "COMPUTE_SETTLEMENT_BPS()(uint256)",
  "DEFAULT_FEE_BPS()(uint256)",
  "MIN_VERSION_REVIEW_DELAY()(uint64)",
  "ORACLE_UPGRADE_DELAY()(uint256)",
  "accountCommitment()(bytes32)",
  "activeRatePolicyCount()(uint256)",
  "allowAnyDevice()(bool)",
  "allowedAssetCount()(uint256)",
  "allowedAssets(address)(bool)",
  "allowedDeviceIdCount()(uint256)",
  "allowedDeviceIds(bytes32)(bool)",
  "allowedOracleComposeHashCount()(uint256)",
  "allowedOracleComposeHashes(bytes32)(bool)",
  "approvedComposeCount()(uint256)",
  "approvedComposeHashes(bytes32)(bool)",
  "approvedComposeRoot()(bytes32)",
  "approvedEvaluatorPolicies(bytes32)(bool)",
  "approvedEvaluatorPolicyCount()(uint256)",
  "approvedTeeIdentityCount()(uint256)",
  "anchorWriterEverConfigured(address)(bool)",
  "anchorWriterReleaseCommitment()(bytes32)",
  "approvalRequirementsFrozen()(bool)",
  "assetAdditionsFrozen()(bool)",
  "attestationBindingFrozen()(bool)",
  "attestationReleasePolicyHash()(bytes32)",
  "attestationVerifier()(address)",
  "authorityNonce()(uint256)",
  "challengeCount()(uint256)",
  "challengeExists(uint256)(bool)",
  "composeAdditionsFrozen()(bool)",
  "composeApprovalRequired()(bool)",
  "composePolicyFrozen()(bool)",
  "computeComposeRoot(bytes32[])(bytes32)",
  "computeManagerRoot(address[])(bytes32)",
  "computeReleasePolicyCommitment(uint256,address,address,address,bytes32)(bytes32)",
  "computeSettlementPolicyEnabled()(bool)",
  "consumerComposeHashCount(address)(uint256)",
  "consumerEmergencyRevoked(address)(bool)",
  "consumerManagerAdditionsFrozen()(bool)",
  "consumerManagerCount()(uint256)",
  "consumerManagers(address)(bool)",
  "consumerRegistryFrozen()(bool)",
  "controllerChallengePaused(uint256)(bool)",
  "dealCount()(uint256)",
  "DEVELOPER_TRANSFER_DELAY()(uint256)",
  "developer()(address)",
  "developerFeeBps()(uint16)",
  "developerFeeFrozen()(bool)",
  "emergencyHalted()(bool)",
  "evaluatorPolicies()(bytes32[3])",
  "evaluatorPolicySetFrozen()(bool)",
  "evaluatorPolicySetRoot()(bytes32)",
  "executionPolicyAnchor()(address)",
  "feeBps()(uint256)",
  "feeBpsFrozen()(bool)",
  "globalHead()(bytes32)",
  "globalSequence()(uint256)",
  "getChallenge(uint256)((address,address,uint8,uint64,uint64,uint32,bool,bool))",
  "getVersion(uint256,uint32)((string,bytes32,bytes32,bytes32,bytes32,uint64))",
  "governanceChallengePaused(uint256)(bool)",
  "isConsumerAuthorized(address,bytes32)(bool)",
  "isConsumerComposeHashRegistered(address,bytes32)(bool)",
  "kmsBindingFrozen()(bool)",
  "kmsContract()(address)",
  "kmsImplementation()(address)",
  "kmsImplementationRuntimeCodeHash()(bytes32)",
  "kmsRegistrationBlock()(uint64)",
  "kmsRegistrationBlockHash()(bytes32)",
  "kmsRegistrationTxHash()(bytes32)",
  "kmsRuntimeCodeHash()(bytes32)",
  "managerCount()(uint256)",
  "managerRoot()(bytes32)",
  "managers(address)(bool)",
  "maxAddBalanceWei()(uint256)",
  "maxSpendWei()(uint256)",
  "meteringBindingFrozen()(bool)",
  "meteringPolicySetHash()(bytes32)",
  "meteringQvlVerifier()(address)",
  "meteringVerifier()(address)",
  "nextChallengeId()(uint256)",
  "oracleCodeFrozen()(bool)",
  "owner()(address)",
  "paused()(bool)",
  "pendingAccountCommitment()(bytes32)",
  "pendingAssetActivations(address)(uint64)",
  "pendingAssetCount()(uint256)",
  "pendingAnchorWriterReleaseCommitment()(bytes32)",
  "pendingAuthorityActivatesAt()(uint64)",
  "pendingAuthorityNonce()(uint256)",
  "pendingAuthorityRevocation()(bool)",
  "pendingAttestationBindingActivatesAt()(uint64)",
  "pendingAttestationReleasePolicyHash()(bytes32)",
  "pendingAttestationVerifier()(address)",
  "pendingComposeActivations(bytes32)(uint64)",
  "pendingComposeActivations(bytes32)(uint256)",
  "pendingComposeCount()(uint256)",
  "pendingComposeRoot()(bytes32)",
  "pendingDeveloper()(address)",
  "pendingDeveloperActivatesAt()(uint256)",
  "initialDeveloper()(address)",
  "releaseGovernanceController()(address)",
  "protocolFeeRecipient()(address)",
  "pendingEvaluatorPolicyActivations(bytes32)(uint256)",
  "pendingEvaluatorPolicyCount()(uint256)",
  "pendingExecutionPolicyAnchor()(address)",
  "pendingKmsBindingActivatesAt()(uint256)",
  "pendingKmsContract()(address)",
  "pendingKmsImplementation()(address)",
  "pendingKmsImplementationRuntimeCodeHash()(bytes32)",
  "pendingKmsRegistrationBlock()(uint64)",
  "pendingKmsRegistrationBlockHash()(bytes32)",
  "pendingKmsRegistrationTxHash()(bytes32)",
  "pendingKmsRuntimeCodeHash()(bytes32)",
  "pendingManagerCount()(uint256)",
  "pendingManagerRoot()(bytes32)",
  "pendingMaxAddBalanceWei()(uint256)",
  "pendingMaxSpendWei()(uint256)",
  "pendingMeteringBindingActivatesAt()(uint64)",
  "pendingMeteringPolicySetHash()(bytes32)",
  "pendingMeteringQvlVerifier()(address)",
  "pendingMeteringVerifier()(address)",
  "pendingOracleComposeHashCount()(uint256)",
  "pendingOracleComposeHashes(bytes32)(uint256)",
  "pendingOwner()(address)",
  "pendingQvlVerifier()(address)",
  "pendingRatePolicies(bytes32)(address,address,uint16,uint64)",
  "pendingRatePolicyCount()(uint256)",
  "pendingReleasePolicyActivatesAt()(uint64)",
  "pendingReleasePolicyCommitment()(bytes32)",
  "pendingRestartKeyDerivationProofHash()(bytes32)",
  "pendingResultVerifier()(address)",
  "pendingResultVerifierActivatesAt()(uint256)",
  "pendingSettlementVerifier()(address)",
  "pendingTargetBootInfoHash()(bytes32)",
  "pendingTeeIdentityActivations(address)(uint64)",
  "pendingTeeIdentityActivations(address)(uint256)",
  "pendingTeeIdentityComposeHash(address)(bytes32)",
  "pendingTeeIdentityCount()(uint256)",
  "pendingWriter()(address)",
  "pendingWriterActivatesAt()(uint64)",
  "pendingWriterReleaseCommitment()(bytes32)",
  "productionRelease()(bool)",
  "qvlVerifier()(address)",
  "qvlVerifierEverConfigured(address)(bool)",
  "ratePolicies(bytes32)(address,address,uint16,bool)",
  "ratePolicyAdditionsFrozen()(bool)",
  "registryPaused()(bool)",
  "releaseComposeCount()(uint256)",
  "releaseComposeRoot()(bytes32)",
  "releaseConfigurationReady()(bool)",
  "releaseConsumerAppId()(address)",
  "releaseConsumerComposeHash()(bytes32)",
  "releaseConsumerManager()(address)",
  "releaseDeviceId()(bytes32)",
  "releaseManagerCount()(uint256)",
  "releaseManagerRoot()(bytes32)",
  "releaseMaxAddBalanceWei()(uint256)",
  "releaseMaxSpendWei()(uint256)",
  "releaseOracleComposeHash()(bytes32)",
  "releasePolicyCommitment()(bytes32)",
  "releasePolicyFrozen()(bool)",
  "resourceDecisionHead(bytes32)(bytes32)",
  "resourceSequence(bytes32)(uint256)",
  "restartKeyDerivationProofHash()(bytes32)",
  "resultVerifier()(address)",
  "reviewEligibleAt(uint256)(uint64)",
  "resultVerifierFrozen()(bool)",
  "settlementVerifier()(address)",
  "settlementVerifierEverConfigured(address)(bool)",
  "targetBootInfoHash()(bytes32)",
  "TINKER_PROVIDER_NAMESPACE()(bytes32)",
  "teeIdentityAdditionsFrozen()(bool)",
  "teeIdentityApprovalRequired()(bool)",
  "teeIdentityComposeHash(address)(bytes32)",
  "totalConsumerComposeHashCount()(uint256)",
  "writer()(address)",
  "writerReleaseCommitment()(bytes32)",
  "writerRotationsFrozen()(bool)",
  "decisionSequence(bytes32)(uint256)",
  "computeAnchorHead(uint256,bytes32,bytes32,bytes32,bytes32,address,bytes32)(bytes32)",
]);

function usage() {
  return [
    "Usage:",
    "  node scripts/activation-preflight.mjs [options]",
    "",
    "Options:",
    "  --env FILE                       Untracked operator env (default: .env)",
    "  --compose FILE                   Main runtime Phala compose",
    "  --diligence-qvl-compose FILE     Diligence QVL Phala compose",
    "  --arena-qvl-compose FILE         Arena QVL Phala compose",
    "  --anchor-writer-qvl-compose FILE Anchor-writer QVL Phala compose",
    "  --compute-workload-qvl-compose FILE Compute-workload QVL Phala compose",
    "  --compute-metering-qvl-compose FILE Compute-metering QVL Phala compose",
    "  --metering-compose FILE          Independent metering Phala compose",
    "  --image-release FILE             Canonical five-image CI manifest",
    "  --image-release-attestation-bundle FILE Signed provenance bundle for that manifest",
    "  --image-release-sigstore-verification-receipt FILE Canonical pinned-gh Sigstore verification receipt",
    "  --topology FILE                  Hash-bound seven-CVM topology descriptor",
    "  --release FILE                   Canonical web release candidate",
    "  --release-core FILE              Canonical final release authority core",
    "  --ledger FILE                    Canonical fresh-suite deployment ledger",
    "  --deployment-intent FILE         Canonical immutable predeployment intent",
    "  --cvm-launch-intent FILE         Canonical post-contract pre-CVM launch intent",
    "  --reviewer-current-status FILE   Latest authenticated reviewer status",
    "  --reviewer-status-history FILE   Complete authenticated reviewer-status history",
    "  --diligence-phase-1-review-envelope FILE  Phase-1 final-authority review",
    "  --diligence-phase-2-review-envelope FILE  Phase-2 final-authority review",
    "  --diligence-phase-3-review-envelope FILE  Phase-3 final-authority review",
    "  --diligence-phase-4-review-envelope FILE  Phase-4 final-authority review",
    "  Live activation also requires RELEASE_CEREMONY_LEDGER_PATH,",
    "  RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT, and RELEASE_CEREMONY_LOCK_ROOT.",
    "  Live activation additionally requires every current exact-38 semantic-validator input flag.",
    "  A single current review cannot replace the four phase-specific envelopes.",
    "  --artifact-evidence FILE         Independent diligence deployment evidence",
    "  --arena-evidence FILE            Independent Arena deployment evidence",
    "  --anchor-writer-evidence FILE    Canonical bounded writer QVL artifact",
    "  --email-oracle-evidence FILE     Canonical bounded Email/KMS/restart evidence",
    "  --stage MODE                     Required: fresh-deployment, cvm-launch, release-ceremony, or live-activation",
    "  --skip-network                   Skip read-only RPC/auth/attestation probes",
    "  --json                           Emit bounded JSON instead of text",
    "  --help                           Show this help",
    "",
    "Safety:",
    "  This command never unlocks a keystore, broadcasts, deploys, logs in,",
    "  prints secret values, writes a release env, or mutates remote state.",
    "  Network work is limited to identity/status, chain, contract-state, QVL",
    "  evidence, and GitHub attestation verification reads.",
  ].join("\n");
}

export function parseArgs(argv) {
  const args = {
    env: path.join(rootDir, ".env"),
    compose: defaultComposePath(rootDir),
    diligenceQvlCompose: defaultDiligenceQvlComposePath(rootDir),
    arenaQvlCompose: defaultArenaQvlComposePath(rootDir),
    anchorWriterQvlCompose: defaultAnchorWriterQvlComposePath(rootDir),
    computeWorkloadQvlCompose: defaultComputeWorkloadQvlComposePath(rootDir),
    computeMeteringQvlCompose: defaultComputeMeteringQvlComposePath(rootDir),
    meteringCompose: defaultMeteringComposePath(rootDir),
    imageRelease: defaultImageReleasePath(rootDir),
    imageReleaseAttestationBundle: defaultImageReleaseAttestationBundlePath(rootDir),
    imageReleaseSigstoreVerificationReceipt:
      defaultImageReleaseSigstoreVerificationReceiptPath(rootDir),
    topology: defaultTopologyPath(rootDir),
    ledger: "",
    deploymentIntent: defaultDeploymentIntent,
    cvmLaunchIntent: defaultCvmLaunchIntent,
    tinkerAccountBindingCeremony: defaultTinkerAccountBindingCeremony,
    tinkerAccountBindingCeremonyReceipt:
      defaultTinkerAccountBindingCeremonyReceipt,
    reviewerCurrentStatus: "",
    reviewerStatusHistory: "",
    diligencePhase1ReviewEnvelope: "",
    diligencePhase2ReviewEnvelope: "",
    diligencePhase3ReviewEnvelope: "",
    diligencePhase4ReviewEnvelope: "",
    authorityStage: "live_activation",
    authorityStageExplicit: false,
    explicitPathKeys: [],
    json: false,
    skipNetwork: false,
  };
  const pathFlags = new Map([
    ["--env", "env"],
    ["--compose", "compose"],
    ["--diligence-qvl-compose", "diligenceQvlCompose"],
    ["--arena-qvl-compose", "arenaQvlCompose"],
    ["--anchor-writer-qvl-compose", "anchorWriterQvlCompose"],
    ["--compute-workload-qvl-compose", "computeWorkloadQvlCompose"],
    ["--compute-metering-qvl-compose", "computeMeteringQvlCompose"],
    ["--metering-compose", "meteringCompose"],
    ["--image-release", "imageRelease"],
    ["--image-release-attestation-bundle", "imageReleaseAttestationBundle"],
    [
      "--image-release-sigstore-verification-receipt",
      "imageReleaseSigstoreVerificationReceipt",
    ],
    ["--topology", "topology"],
    ["--release", "release"],
    ["--release-core", "releaseCore"],
    ["--ledger", "ledger"],
    ["--deployment-intent", "deploymentIntent"],
    ["--cvm-launch-intent", "cvmLaunchIntent"],
    ["--reviewer-current-status", "reviewerCurrentStatus"],
    ["--reviewer-status-history", "reviewerStatusHistory"],
    [
      "--diligence-phase-1-review-envelope",
      "diligencePhase1ReviewEnvelope",
    ],
    [
      "--diligence-phase-2-review-envelope",
      "diligencePhase2ReviewEnvelope",
    ],
    [
      "--diligence-phase-3-review-envelope",
      "diligencePhase3ReviewEnvelope",
    ],
    [
      "--diligence-phase-4-review-envelope",
      "diligencePhase4ReviewEnvelope",
    ],
    ["--artifact-evidence", "artifactEvidence"],
    ["--arena-evidence", "arenaEvidence"],
    ["--anchor-writer-evidence", "anchorWriterEvidence"],
    ["--email-oracle-evidence", "emailOracleEvidence"],
  ]);
  for (const flag of SEMANTIC_VALIDATOR_INPUT_FLAGS) {
    if (!pathFlags.has(flag)) {
      pathFlags.set(flag, semanticValidatorPathKey(flag));
    }
  }
  const seenFlags = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (seenFlags.has(flag)) throw new Error(`duplicate argument: ${flag}`);
    seenFlags.add(flag);
    if (flag === "--help") {
      args.help = true;
      continue;
    }
    if (flag === "--json") {
      args.json = true;
      continue;
    }
    if (flag === "--skip-network") {
      args.skipNetwork = true;
      continue;
    }
    if (flag === "--stage") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error("missing value for --stage");
      if (!new Set([
        "fresh-deployment",
        "cvm-launch",
        "release-ceremony",
        "live-activation",
      ]).has(value)) {
        throw new Error(
          "--stage must be fresh-deployment, cvm-launch, release-ceremony, or live-activation",
        );
      }
      args.authorityStage = value.replace("-", "_");
      args.authorityStageExplicit = true;
      index += 1;
      continue;
    }
    if (!pathFlags.has(flag)) throw new Error(`unknown argument: ${flag}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${flag}`);
    const key = pathFlags.get(flag);
    args[key] = path.resolve(value);
    args.explicitPathKeys.push(key);
    index += 1;
  }
  return args;
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function safeAbsoluteReadPath(value) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 4_096
    && path.isAbsolute(value)
    && path.resolve(value) === value
    && path.normalize(value) === value
    && !/[\u0000\r\n]/.test(value);
}

function semanticValidatorPathKey(flag) {
  return flag.slice(2).replace(/-([a-z])/g, (_match, letter) => (
    letter.toUpperCase()
  ));
}

export function semanticValidatorArgs(paths = {}) {
  const pairs = SEMANTIC_VALIDATOR_INPUT_FLAGS.flatMap((flag) => {
    const value = paths[semanticValidatorPathKey(flag)];
    if (!safeAbsoluteReadPath(value)) {
      throw new Error(
        `semantic release validation requires canonical absolute input path ${flag}`,
      );
    }
    return [flag, value];
  });
  return [semanticValidatorScript, "--check-only", ...pairs];
}

export function diligencePhaseReviewCheckArgs({
  reviewEnvelopePath,
  finalAuthorityPath,
  deploymentIntentPath,
  cvmLaunchIntentPath,
}) {
  for (const [label, value] of [
    ["phase review envelope", reviewEnvelopePath],
    ["final authority", finalAuthorityPath],
    ["deployment intent", deploymentIntentPath],
    ["CVM-launch intent", cvmLaunchIntentPath],
  ]) {
    if (!safeAbsoluteReadPath(value)) {
      throw new Error(`Diligence ${label} path must be canonical and absolute`);
    }
  }
  return [
    operatorPolicyPacketScript,
    "check-review",
    "--subject",
    finalAuthorityPath,
    "--in",
    reviewEnvelopePath,
    "--deployment-intent",
    deploymentIntentPath,
    "--cvm-launch-intent",
    cvmLaunchIntentPath,
  ];
}

function exactDiligenceReviewReceipt(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const fields = [
    "actionScopeCount",
    "checkpoint",
    "reviewEnvelopeSha256",
    "reviewEvidenceSha256",
    "reviewerDeclarationCount",
    "schema",
    "status",
    "subjectKind",
    "subjectSemanticValidation",
    "subjectSha256",
    "truthStatus",
  ];
  if (JSON.stringify(Object.keys(value).sort())
    !== JSON.stringify([...fields].sort())) return null;
  return value;
}

export function validateDiligencePhaseReviewEnvelopes({
  reviewEnvelopePaths,
  finalAuthorityPath,
  deploymentIntentPath,
  cvmLaunchIntentPath,
}, execute = runReadOnly) {
  if (!Array.isArray(reviewEnvelopePaths)
    || reviewEnvelopePaths.length !== 4) return [];
  const receipts = [];
  for (let index = 0; index < reviewEnvelopePaths.length; index += 1) {
    try {
      const result = execute(
        process.execPath,
        diligencePhaseReviewCheckArgs({
          reviewEnvelopePath: reviewEnvelopePaths[index],
          finalAuthorityPath,
          deploymentIntentPath,
          cvmLaunchIntentPath,
        }),
        { timeout: COMMAND_TIMEOUT_MS },
      );
      if (result?.ok !== true) return [];
      const receipt = exactDiligenceReviewReceipt(
        JSON.parse(String(result.stdout || "")),
      );
      if (!receipt) return [];
      receipts.push({ phase: index + 1, valid: true, ...receipt });
    } catch {
      return [];
    }
  }
  return receipts;
}

export function assertReadOnlyInvocation(command, args) {
  if (FORBIDDEN_TOKENS.has(command)) {
    throw new Error("unsafe preflight command rejected");
  }
  for (const token of args) {
    if (FORBIDDEN_TOKENS.has(String(token).toLowerCase())) {
      throw new Error("unsafe preflight argument rejected");
    }
  }

  const versionProbe = args.length === 1 && ["--version", "-V"].includes(args[0]);
  if (versionProbe && ["git", "forge", "cast", "jq", "gh", "phala", "wrangler", "uv"].includes(command)) {
    return;
  }
  if (command === "git" && (
    arraysEqual(args, ["-C", rootDir, "rev-parse", "HEAD"])
    || arraysEqual(args, ["-C", rootDir, "status", "--porcelain", "--untracked-files=normal"])
    || (
      args.length === 5
      && args[0] === "-C"
      && args[1] === rootDir
      && args[2] === "cat-file"
      && args[3] === "-t"
      && /^[0-9a-f]{40}$/.test(args[4])
    )
    || (
      args.length === 6
      && args[0] === "-C"
      && args[1] === rootDir
      && args[2] === "show"
      && args[3] === "-s"
      && args[4] === "--format=%ct"
      && /^[0-9a-f]{40}$/.test(args[5])
    )
  )) return;
  if (command === "cast" && arraysEqual(args, ["wallet", "list"])) return;
  const safeRpcUrl = (value) => typeof value === "string"
    && value.length > 0
    && value.length <= 4_096
    && /^https?:\/\/[^\s\r\n]+$/.test(value);
  if (
    command === "cast"
    && args.length === 3
    && args[0] === "chain-id"
    && args[1] === "--rpc-url"
    && safeRpcUrl(args[2])
  ) return;
  if (
    command === "cast"
    && args.length === 6
    && args[0] === "rpc"
    && args[1] === "eth_getBalance"
    && LOWER_ADDRESS.test(args[2])
    && /^0x[1-9a-f][0-9a-f]{0,15}$/.test(args[3])
    && args[4] === "--rpc-url"
    && safeRpcUrl(args[5])
  ) return;
  if (
    command === "cast"
    && arraysEqual(args.slice(0, 2), ["block-number", "--rpc-url"])
    && args.length === 3
    && safeRpcUrl(args[2])
  ) return;
  if (
    command === "cast"
    && args.length === 5
    && args[0] === "block"
    && (SAFE_BLOCK_NUMBER.test(args[1]) || args[1] === "finalized")
    && args[2] === "--json"
    && args[3] === "--rpc-url"
    && safeRpcUrl(args[4])
  ) return;
  const reconstructionContracts = new Set(
    CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({ name }) => name),
  );
  if (
    command === "forge"
    && args.length === 5
    && args[0] === "inspect"
    && args[1] === "--root"
    && args[2] === contractsProject
    && reconstructionContracts.has(args[3])
    && args[4] === "bytecode"
  ) return;
  const reconstructionConstructorSignatures = new Set([
    "constructor(bool,address)",
    "constructor(address,bytes32,bytes32,uint256,uint256)",
    "constructor(address)",
    "constructor(address,address,uint16)",
    "constructor(address,uint256,bool,bytes32,bytes32,bool)",
  ]);
  const reconstructionCallSignatures = new Set(
    FRESH_DEPLOYMENT_TRANSACTION_SPEC
      .filter(({ transaction_type }) => transaction_type === "CALL")
      .map(({ function_signature }) => function_signature),
  );
  const safeReconstructionArgument = (value) => value === "true"
    || value === "false"
    || LOWER_ADDRESS.test(value)
    || LOWER_BYTES32.test(value)
    || (SAFE_UINT256_ARGUMENT.test(value) && (() => {
      try {
        return BigInt(value) < (1n << 256n);
      } catch {
        return false;
      }
    })());
  if (
    command === "cast"
    && args[0] === "abi-encode"
    && reconstructionConstructorSignatures.has(args[1])
    && args.length >= 2
    && args.length <= 8
    && args.slice(2).every(safeReconstructionArgument)
  ) return;
  if (
    command === "cast"
    && args[0] === "calldata"
    && reconstructionCallSignatures.has(args[1])
    && args.length >= 2
    && args.length <= 3
    && args.slice(2).every(safeReconstructionArgument)
  ) return;
  if (
    command === "cast"
    && args[0] === "call"
    && args[1] === "--from"
    && LOWER_ADDRESS.test(args[2])
    && args[3] === "--rpc-url"
    && safeRpcUrl(args[4])
    && args[5] === "--block"
    && SAFE_BLOCK_NUMBER.test(args[6])
    && args[7] === "--create"
    && typeof args[8] === "string"
    && args[8].length <= 256 * 1024
    && /^0x(?:[0-9a-f]{2})+$/.test(args[8])
    && (
      args.length === 9
      || (
        reconstructionConstructorSignatures.has(args[9])
        && args.length <= 16
        && args.slice(10).every(safeReconstructionArgument)
      )
    )
  ) return;
  if (
    command === "cast"
    && args.length === 2
    && args[0] === "keccak"
    && typeof args[1] === "string"
    && args[1].length <= 256 * 1024
    && /^0x(?:[0-9a-f]{2})+$/.test(args[1])
  ) return;
  if (
    command === "cast"
    && args.length === 6
    && args[0] === "codehash"
    && LOWER_ADDRESS.test(args[1])
    && args[2] === "--block"
    && SAFE_BLOCK_NUMBER.test(args[3])
    && args[4] === "--rpc-url"
    && safeRpcUrl(args[5])
  ) return;
  if (
    command === "cast"
    && args.length === 5
    && ["receipt", "tx"].includes(args[0])
    && LOWER_BYTES32.test(args[1])
    && args[2] === "--json"
    && args[3] === "--rpc-url"
    && safeRpcUrl(args[4])
  ) return;
  if (
    command === "cast"
    && args.length === 14
    && args[0] === "logs"
    && args[1] === EXECUTION_POLICY_DECISION_ANCHORED_EVENT
    && args[2] === "1"
    && args[3] === EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_HASH
    && LOWER_BYTES32.test(args[4])
    && args[5] === "--from-block"
    && SAFE_BLOCK_NUMBER.test(args[6])
    && args[7] === "--to-block"
    && SAFE_BLOCK_NUMBER.test(args[8])
    && args[9] === "--address"
    && LOWER_ADDRESS.test(args[10])
    && args[11] === "--json"
    && args[12] === "--rpc-url"
    && safeRpcUrl(args[13])
  ) return;
  if (command === "cast" && args[0] === "call" && args.length >= 7) {
    const blockIndex = args.indexOf("--block");
    const rpcIndex = args.indexOf("--rpc-url");
    const jsonIndex = args.indexOf("--json");
    const optionStart = jsonIndex >= 0 ? jsonIndex : blockIndex;
    const callArguments = args.slice(3, optionStart);
    const optionsValid = blockIndex === (jsonIndex >= 0 ? jsonIndex + 1 : optionStart)
      && rpcIndex === blockIndex + 2
      && rpcIndex + 1 === args.length - 1
      && (jsonIndex < 0 || jsonIndex === optionStart)
      && SAFE_BLOCK_NUMBER.test(args[blockIndex + 1])
      && safeRpcUrl(args[rpcIndex + 1]);
    if (
      LOWER_ADDRESS.test(args[1])
      && CONTRACT_POSTSTATE_VIEW_SIGNATURES.has(args[2])
      && callArguments.length <= (
        args[2]
          === "computeAnchorHead(uint256,bytes32,bytes32,bytes32,bytes32,address,bytes32)(bytes32)"
          ? 7
          : 2
      )
      && callArguments.every((value) => (
        LOWER_ADDRESS.test(value)
        || LOWER_BYTES32.test(value)
        || (SAFE_UINT256_ARGUMENT.test(value) && (() => {
          try {
            return BigInt(value) < (1n << 256n);
          } catch {
            return false;
          }
        })())
        || value === "[]"
      ))
      && optionsValid
    ) return;
  }
  if (command === "gh" && arraysEqual(args, ["auth", "status"])) return;
  if (command === "phala" && arraysEqual(args, ["status"])) return;
  if (command === "wrangler" && arraysEqual(args, ["whoami"])) return;
  if (
    command === "gh"
    && args.length === 16
    && args[0] === "attestation"
    && args[1] === "verify"
    && safeAbsoluteReadPath(args[2])
    && args[3] === "--repo"
    && args[4] === EXPECTED_GITHUB_REPOSITORY
    && args[5] === "--bundle"
    && safeAbsoluteReadPath(args[6])
    && args[7] === "--signer-workflow"
    && args[8] === EXPECTED_GITHUB_WORKFLOW
    && args[9] === "--source-digest"
    && /^[0-9a-f]{40}$/.test(args[10])
    && args[11] === "--source-ref"
    && /^(?:refs\/heads\/main|refs\/tags\/v[0-9][0-9A-Za-z._-]*)$/.test(args[12])
    && args[13] === "--deny-self-hosted-runners"
    && args[14] === "--predicate-type"
    && args[15] === "https://slsa.dev/provenance/v1"
  ) return;
  if (
    command === "gh"
    && args.length === 15
    && args[0] === "attestation"
    && args[1] === "verify"
    && /^oci:\/\/ghcr\.io\/therealwiki\/dnai-wikigen\/[a-z0-9._-]+@sha256:[0-9a-f]{64}$/.test(args[2])
    && args[3] === "--repo"
    && args[4] === EXPECTED_GITHUB_REPOSITORY
    && args[5] === "--bundle-from-oci"
    && args[6] === "--signer-workflow"
    && args[7] === EXPECTED_GITHUB_WORKFLOW
    && args[8] === "--source-digest"
    && /^[0-9a-f]{40}$/.test(args[9])
    && args[10] === "--source-ref"
    && /^(?:refs\/heads\/main|refs\/tags\/v[0-9][0-9A-Za-z._-]*)$/.test(args[11])
    && args[12] === "--deny-self-hosted-runners"
    && args[13] === "--predicate-type"
    && ["https://slsa.dev/provenance/v1", "https://spdx.dev/Document/v2.3"].includes(args[14])
  ) return;
  if (command === process.execPath
    && args.length === 2 + (SEMANTIC_VALIDATOR_INPUT_FLAGS.length * 2)
    && args[0] === semanticValidatorScript
    && args[1] === "--check-only") {
    const exactInputs = SEMANTIC_VALIDATOR_INPUT_FLAGS.every((flag, index) => (
      args[2 + (index * 2)] === flag
      && safeAbsoluteReadPath(args[3 + (index * 2)])
    ));
    if (exactInputs) return;
  }
  if (
    command === process.execPath
    && args.length === 10
    && args[0] === operatorPolicyPacketScript
    && args[1] === "check-review"
    && args[2] === "--subject"
    && safeAbsoluteReadPath(args[3])
    && args[4] === "--in"
    && safeAbsoluteReadPath(args[5])
    && args[6] === "--deployment-intent"
    && safeAbsoluteReadPath(args[7])
    && args[8] === "--cvm-launch-intent"
    && safeAbsoluteReadPath(args[9])
  ) return;
  throw new Error("command is not in the activation preflight read-only allowlist");
}

function minimalEnvironment(extra = {}) {
  return {
    PATH: process.env.PATH || "",
    HOME: process.env.HOME || "",
    TMPDIR: process.env.TMPDIR || "/tmp",
    LANG: process.env.LANG || "C.UTF-8",
    LC_ALL: process.env.LC_ALL || "C.UTF-8",
    ...Object.fromEntries(
      Object.entries(extra).filter(([, value]) => clean(value).length > 0),
    ),
  };
}

function runReadOnly(command, args, { env = {}, timeout = COMMAND_TIMEOUT_MS } = {}) {
  assertReadOnlyInvocation(command, args);
  const result = spawnSync(command, args, {
    cwd: rootDir,
    env: minimalEnvironment(env),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    timeout,
    maxBuffer: 256 * 1024,
  });
  return {
    ok: result.status === 0 && !result.error,
    stdout: String(result.stdout || "").slice(0, 32 * 1024),
  };
}

export function semanticValidationEnvironment(env) {
  return {
    GH_TOKEN: clean(env.GH_TOKEN || env.GITHUB_TOKEN),
    GITHUB_TOKEN: clean(env.GITHUB_TOKEN),
    BASE_SEPOLIA_RPC_URL: clean(env.BASE_SEPOLIA_RPC_URL),
    BASE_SEPOLIA_SECONDARY_RPC_URL: clean(
      env.BASE_SEPOLIA_SECONDARY_RPC_URL,
    ),
    TRUSTED_ATTESTATION_VERIFIER_ADDRESSES: clean(
      env.TRUSTED_ATTESTATION_VERIFIER_ADDRESSES,
    ),
  };
}

function exactReceiptObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const expected = [
    "ceremony_authorization_sha256",
    "chain_id",
    "compute_workload_activation_observation_sha256",
    "compute_workload_browser_binding_sha256",
    "deployment_intent_sha256",
    "frontend_build_candidate_receipt_sha256",
    "frontend_build_sha256",
    "live_activation_authority_sha256",
    "raw_secret_egress",
    "release_env_sha256",
    "release_inputs_sha256",
    "release_sha",
    "reviewer_authority_genesis_acceptance_sha256",
    "royalty_release_history_receipt_sha256",
    "royalty_release_history_sha256",
    "runtime_authority_dependency_sha256",
    "schema",
    "status",
    "truth_status",
  ];
  const actual = Object.keys(value).sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

export function parseSemanticValidationReceipt(
  stdout,
  expectedAuthority,
) {
  const raw = String(stdout ?? "");
  const expected = expectedAuthority || {};
  const expectedReleaseSha = clean(expected.releaseSha).toLowerCase();
  const expectedHashes = {
    deployment_intent_sha256: clean(expected.deploymentIntentSha256).toLowerCase(),
    reviewer_authority_genesis_acceptance_sha256:
      clean(expected.reviewerAuthorityGenesisAcceptanceSha256).toLowerCase(),
    ceremony_authorization_sha256:
      clean(expected.ceremonyAuthorizationSha256).toLowerCase(),
    live_activation_authority_sha256:
      clean(expected.liveActivationAuthoritySha256).toLowerCase(),
    runtime_authority_dependency_sha256:
      clean(expected.runtimeAuthorityDependencySha256).toLowerCase(),
    royalty_release_history_sha256:
      clean(expected.royaltyReleaseHistorySha256).toLowerCase(),
    royalty_release_history_receipt_sha256:
      clean(expected.royaltyReleaseHistoryReceiptSha256).toLowerCase(),
  };
  if (
    raw.length < 2
    || raw.length > 4_096
    || !/^[0-9a-f]{40}$/.test(expectedReleaseSha)
    || Object.values(expectedHashes).some((value) => (
      !/^sha256:[0-9a-f]{64}$/.test(value)
      || value === `sha256:${"0".repeat(64)}`
    ))
  ) {
    return { valid: false };
  }
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    return { valid: false };
  }
  if (
    !exactReceiptObject(value)
    || `${JSON.stringify(value)}\n` !== raw
    || value.schema !== SEMANTIC_VALIDATION_SCHEMA
    || value.status !== SEMANTIC_VALIDATION_STATUS
    || value.truth_status !== SEMANTIC_VALIDATION_TRUTH_STATUS
    || value.release_sha !== expectedReleaseSha
    || value.chain_id !== 84_532
    || Object.entries(expectedHashes).some(([key, expectedValue]) => (
      value[key] !== expectedValue
    ))
    || [
      value.compute_workload_activation_observation_sha256,
      value.compute_workload_browser_binding_sha256,
      value.frontend_build_candidate_receipt_sha256,
      value.release_inputs_sha256,
      value.release_env_sha256,
      value.frontend_build_sha256,
    ].some((digest) => (
      !/^sha256:[0-9a-f]{64}$/.test(digest)
      || digest === `sha256:${"0".repeat(64)}`
    ))
    || value.royalty_release_history_sha256
      === value.royalty_release_history_receipt_sha256
    || value.raw_secret_egress !== false
  ) return { valid: false };
  return { valid: true, receipt: value };
}

export function validateProjectedEnvironment(projection, env) {
  const assertions = projection?.assertions;
  if (!assertions || typeof assertions !== "object" || Array.isArray(assertions)) {
    return { ok: false, checkedKeys: [], mismatchKeys: ["invalid_projection"] };
  }
  const checkedKeys = Object.keys(assertions).sort();
  const mismatchKeys = checkedKeys.filter((name) => {
    const entry = assertions[name];
    return !entry
      || entry.projectionName !== name
      || clean(env?.[name]) !== String(entry.value ?? "");
  });
  return {
    ok: checkedKeys.length > 0 && mismatchKeys.length === 0,
    checkedKeys,
    mismatchKeys,
  };
}

export function validateDeploymentIntentFreshChallengeState(intent) {
  return intent?.network?.chainId === 84_532
    && LOWER_ADDRESS.test(clean(intent?.deploymentControl?.operatorAddress).toLowerCase())
    && clean(intent?.deploymentControl?.operatorAddress).toLowerCase() !== ZERO_ADDRESS
    && Array.isArray(intent?.scope?.contracts)
    && intent.scope.contracts.includes("ChallengeRegistry")
    && Array.isArray(intent?.dynamicRuntimeAuthorities?.contractAddresses)
    && intent.dynamicRuntimeAuthorities.contractAddresses.length === 0
    && Array.isArray(intent?.dynamicRuntimeAuthorities?.roleAddresses)
    && intent.dynamicRuntimeAuthorities.roleAddresses.length === 0;
}

export function runSemanticReleaseValidation(
  { paths, env, expectedAuthority },
  execute = runReadOnly,
) {
  try {
    const args = semanticValidatorArgs(paths);
    const result = execute(process.execPath, args, {
      env: semanticValidationEnvironment(env),
      timeout: SEMANTIC_VALIDATION_TIMEOUT_MS,
    });
    if (!result?.ok) {
      return { valid: false, reason: "canonical_semantic_validator_rejected_release" };
    }
    const receipt = parseSemanticValidationReceipt(
      result.stdout,
      expectedAuthority,
    );
    return receipt.valid
      ? {
        valid: true,
        reason: "canonical_semantic_validator_authenticated_release",
        receipt: receipt.receipt,
      }
      : { valid: false, reason: "canonical_semantic_validator_receipt_invalid" };
  } catch {
    return { valid: false, reason: "canonical_semantic_validator_unavailable" };
  }
}

export function inspectedFileSnapshotMatches(initial, current) {
  const common = initial?.exists === true
    && initial?.valid === true
    && current?.exists === true
    && current?.valid === true
    && Number.isInteger(initial.mode)
    && initial.mode === current.mode
    && /^[0-9a-f]{64}$/.test(clean(initial.sha256).toLowerCase())
    && clean(initial.sha256).toLowerCase() === clean(current.sha256).toLowerCase();
  if (!common) return false;
  if (initial.strictReleaseEvidence !== true) {
    return current.strictReleaseEvidence !== true;
  }
  return current.strictReleaseEvidence === true
    && [
      "canonicalPath",
      "fileDev",
      "fileIno",
      "fileUid",
      "fileNlink",
      "releaseDirectoryPath",
      "releaseDirectoryDev",
      "releaseDirectoryIno",
      "releaseDirectoryUid",
      "releaseDirectoryMode",
    ].every((field) => initial[field] === current[field]);
}

export async function validateStableFileBindings(bindings) {
  if (!Array.isArray(bindings) || bindings.length === 0 || bindings.length > 64) {
    return false;
  }
  try {
    const rereads = await Promise.all(bindings.map((binding) => inspectFile(
      binding.path,
      binding.options || {},
    )));
    return bindings.every((binding, index) => (
      inspectedFileSnapshotMatches(binding.initial, rereads[index])
    ));
  } catch {
    return false;
  }
}

export async function runStableSemanticReleaseValidation(
  input,
  stableBindings,
  execute = runReadOnly,
) {
  const validation = runSemanticReleaseValidation(input, execute);
  const filesStable = await validateStableFileBindings(stableBindings);
  return filesStable
    ? validation
    : { valid: false, reason: "canonical_semantic_validator_inputs_changed" };
}

function strictReleaseEvidencePathSnapshot(filePath) {
  if (!safeAbsoluteReadPath(filePath)
    || typeof process.getuid !== "function") {
    throw new Error("strict release evidence path is invalid");
  }
  const releaseDirectory = path.dirname(filePath);
  if (path.basename(releaseDirectory) !== ".release"
    || realpathSync(releaseDirectory) !== releaseDirectory
    || realpathSync(filePath) !== filePath) {
    throw new Error("strict release evidence must use one canonical .release path");
  }
  const expectedUid = BigInt(process.getuid());
  const directory = statSync(releaseDirectory, { bigint: true });
  const file = statSync(filePath, { bigint: true });
  if (!directory.isDirectory()
    || (directory.mode & 0o777n) !== 0o700n
    || directory.uid !== expectedUid
    || !file.isFile()
    || file.nlink !== 1n
    || (file.mode & 0o777n) !== 0o600n
    || file.uid !== expectedUid) {
    throw new Error("strict release evidence ownership or mode is invalid");
  }
  return {
    canonicalPath: filePath,
    file,
    releaseDirectoryPath: releaseDirectory,
    directory,
  };
}

function sameBigIntStat(left, right, fields) {
  return fields.every((field) => left[field] === right[field]);
}

export async function inspectFile(filePath, {
  json = false,
  mode0600 = false,
  strictReleaseEvidence = false,
} = {}) {
  if (!filePath) return { exists: false, valid: false, mode: null, value: null };
  let handle;
  try {
    const strictBefore = strictReleaseEvidence
      ? strictReleaseEvidencePathSnapshot(filePath)
      : null;
    handle = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const mode = Number(before.mode & 0o777n);
    if (!before.isFile() || before.size < 2n || before.size > BigInt(MAX_INPUT_BYTES)) {
      return { exists: true, valid: false, mode, value: null };
    }
    if (strictBefore && !sameBigIntStat(before, strictBefore.file, [
      "dev",
      "ino",
      "mode",
      "nlink",
      "uid",
      "size",
      "mtimeNs",
      "ctimeNs",
    ])) {
      return { exists: true, valid: false, mode, value: null };
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const stable = ["dev", "ino", "size", "mtimeNs", "ctimeNs"]
      .every((field) => before[field] === after[field]);
    if (!stable || BigInt(bytes.length) !== before.size) {
      return { exists: true, valid: false, mode, value: null };
    }
    let value = null;
    const text = bytes.toString("utf8");
    if (json) {
      value = JSON.parse(text);
      if (`${JSON.stringify(value, null, 2)}\n` !== text) {
        return { exists: true, valid: false, mode, value: null };
      }
    }
    const strictAfter = strictReleaseEvidence
      ? strictReleaseEvidencePathSnapshot(filePath)
      : null;
    if (strictBefore && (
      !sameBigIntStat(strictBefore.file, strictAfter.file, [
        "dev",
        "ino",
        "mode",
        "nlink",
        "uid",
        "size",
        "mtimeNs",
        "ctimeNs",
      ])
      || !sameBigIntStat(strictBefore.directory, strictAfter.directory, [
        "dev",
        "ino",
        "mode",
        "uid",
        "mtimeNs",
        "ctimeNs",
      ])
      || !sameBigIntStat(after, strictAfter.file, [
        "dev",
        "ino",
        "mode",
        "nlink",
        "uid",
        "size",
        "mtimeNs",
        "ctimeNs",
      ])
    )) {
      return { exists: true, valid: false, mode, value: null };
    }
    return {
      exists: true,
      valid: (!mode0600 || mode === 0o600)
        && (!strictReleaseEvidence || mode === 0o600),
      mode,
      value,
      text,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      ...(strictBefore ? {
        strictReleaseEvidence: true,
        canonicalPath: strictBefore.canonicalPath,
        fileDev: String(before.dev),
        fileIno: String(before.ino),
        fileUid: String(before.uid),
        fileNlink: String(before.nlink),
        releaseDirectoryPath: strictBefore.releaseDirectoryPath,
        releaseDirectoryDev: String(strictBefore.directory.dev),
        releaseDirectoryIno: String(strictBefore.directory.ino),
        releaseDirectoryUid: String(strictBefore.directory.uid),
        releaseDirectoryMode: Number(strictBefore.directory.mode & 0o777n),
      } : {}),
    };
  } catch {
    return { exists: false, valid: false, mode: null, value: null };
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

export function inspectFreshContractDeploymentReceipt(
  value,
  expectedIntentSha256,
  expectedReleaseSha,
  expectedReviewerAuthorityGenesisAcceptanceSha256,
  expectedTinkerAccountBindingCeremonyReceiptSha256,
) {
  try {
    const authorityPins = {
      expectedDeploymentIntentSha256: expectedIntentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256,
      expectedTinkerAccountBindingCeremonyReceiptSha256,
    };
    const receipt = projectFreshContractDeploymentReceipt(value, {
      releaseSha: expectedReleaseSha,
      ...authorityPins,
    });
    return {
      valid: true,
      receipt,
      sha256: `sha256:${freshContractDeploymentReceiptDigest(receipt, authorityPins)}`,
      contractCount: receipt.contracts.length,
    };
  } catch {
    return { valid: false, receipt: null, sha256: "", contractCount: 0 };
  }
}

function canonicalScalar(value) {
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return String(value);
  }
  const normalized = clean(value);
  return /^(?:0x[0-9a-fA-F]+)$/.test(normalized)
    ? normalized.toLowerCase()
    : normalized;
}

function exactScalar(actual, expected) {
  return canonicalScalar(actual) === canonicalScalar(expected);
}

function uint256Word(value, label) {
  let normalized;
  try {
    normalized = BigInt(value);
  } catch {
    throw new TypeError(`${label} is not an unsigned 256-bit integer`);
  }
  if (normalized < 0n || normalized >= (1n << 256n)) {
    throw new TypeError(`${label} is not an unsigned 256-bit integer`);
  }
  return Buffer.from(normalized.toString(16).padStart(64, "0"), "hex");
}

function bytes32Word(value, label) {
  const normalized = clean(value).toLowerCase();
  if (!LOWER_BYTES32.test(normalized)) {
    throw new TypeError(`${label} is not bytes32`);
  }
  return Buffer.from(normalized.slice(2), "hex");
}

function addressWord(value, label) {
  const normalized = clean(value).toLowerCase();
  if (!LOWER_ADDRESS.test(normalized) || normalized === ZERO_ADDRESS) {
    throw new TypeError(`${label} is not a nonzero address`);
  }
  return Buffer.concat([
    Buffer.alloc(12),
    Buffer.from(normalized.slice(2), "hex"),
  ]);
}

/**
 * Prescribe the one non-circular release marker that must be the first anchor
 * decision. The reviewed final-authority digest is already domain-separated
 * by final-release-authority-core/v3 and is not serialized inside its own
 * document. It can therefore become the marker decision only after those
 * canonical bytes and their external review exist.
 */
export function executionPolicyReleaseMarker({
  finalAuthoritySha256,
  contractAddress,
  writerAddress,
  writerReleaseCommitment,
  chainId = 84_532,
} = {}) {
  const finalAuthority = clean(finalAuthoritySha256).toLowerCase();
  const anchor = clean(contractAddress).toLowerCase();
  const writer = clean(writerAddress).toLowerCase();
  const release = clean(writerReleaseCommitment).toLowerCase();
  if (
    !/^sha256:[0-9a-f]{64}$/.test(finalAuthority)
    || finalAuthority === `sha256:${"0".repeat(64)}`
    || !LOWER_ADDRESS.test(anchor)
    || anchor === ZERO_ADDRESS
    || !LOWER_ADDRESS.test(writer)
    || writer === ZERO_ADDRESS
    || !LOWER_BYTES32.test(release)
    || release === ZERO_BYTES32
    || chainId !== 84_532
  ) {
    throw new TypeError("execution-policy release marker inputs are invalid");
  }
  const decisionHash = `0x${finalAuthority.slice("sha256:".length)}`;
  const encodedHead = Buffer.concat([
    bytes32Word(EXECUTION_POLICY_ANCHOR_TYPEHASH, "anchor typehash"),
    uint256Word(chainId, "anchor chain ID"),
    addressWord(anchor, "anchor address"),
    uint256Word(1, "marker sequence"),
    bytes32Word(ZERO_BYTES32, "marker previous global head"),
    bytes32Word(
      EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_HASH,
      "marker resource hash",
    ),
    bytes32Word(ZERO_BYTES32, "marker previous resource head"),
    bytes32Word(decisionHash, "marker decision hash"),
    addressWord(writer, "marker writer"),
    bytes32Word(release, "marker writer release"),
  ]);
  const newGlobalHead = ethereumKeccak256Hex(encodedHead);
  const calldata = Buffer.concat([
    Buffer.from(EXECUTION_POLICY_ANCHOR_DECISION_SELECTOR.slice(2), "hex"),
    uint256Word(0, "expected marker global sequence"),
    bytes32Word(ZERO_BYTES32, "expected marker global head"),
    bytes32Word(
      EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_HASH,
      "marker resource hash",
    ),
    bytes32Word(ZERO_BYTES32, "expected marker resource head"),
    bytes32Word(decisionHash, "marker decision hash"),
    bytes32Word(release, "marker writer release"),
  ]);
  const eventData = Buffer.concat([
    bytes32Word(ZERO_BYTES32, "marker previous global head"),
    bytes32Word(newGlobalHead, "marker new global head"),
    bytes32Word(ZERO_BYTES32, "marker previous resource head"),
    addressWord(writer, "marker writer"),
    bytes32Word(release, "marker writer release"),
  ]);
  return Object.freeze({
    chainId,
    contractAddress: anchor,
    sequence: 1,
    previousGlobalHead: ZERO_BYTES32,
    resourceHash: EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_HASH,
    previousResourceHead: ZERO_BYTES32,
    decisionHash,
    writerAddress: writer,
    writerReleaseCommitment: release,
    anchorTypehash: EXECUTION_POLICY_ANCHOR_TYPEHASH,
    newGlobalHead,
    calldata: `0x${calldata.toString("hex")}`,
    eventTopics: Object.freeze([
      EXECUTION_POLICY_DECISION_ANCHORED_TOPIC,
      `0x${uint256Word(1, "marker event sequence").toString("hex")}`,
      EXECUTION_POLICY_RELEASE_MARKER_RESOURCE_HASH,
      decisionHash,
    ]),
    eventData: `0x${eventData.toString("hex")}`,
  });
}

function scalarAssertions(specs) {
  return (read) => specs.every(([signature, args, expected]) => (
    exactScalar(read(signature, args), expected)
  ));
}

function tupleAssertion(signature, args, expected) {
  return (read) => {
    const value = read(signature, args, { json: true });
    return Array.isArray(value)
      && value.length === expected.length
      && value.every((entry, index) => exactScalar(entry, expected[index]));
  };
}

function castTuple(value, expectedLength) {
  const tuple = Array.isArray(value)
    && value.length === 1
    && Array.isArray(value[0])
    ? value[0]
    : value;
  return Array.isArray(tuple) && tuple.length === expectedLength ? tuple : null;
}

function exactPositiveUint(actual, expected) {
  try {
    const left = BigInt(String(actual));
    const right = BigInt(String(expected));
    return left > 0n && left === right;
  } catch {
    return false;
  }
}

function freshPoststatePolicies(intent, receipt) {
  const operator = receipt.operator_address;
  const contractPolicy = intent?.numericPolicy?.contract || {};
  const staticInputs = intent?.staticContractInputs || {};
  return {
    ChallengeRegistry: {
      owner_matches_operator: scalarAssertions([["owner()(address)", [], operator]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      registry_unpaused: scalarAssertions([["registryPaused()(bool)", [], false]]),
      challenge_count_zero: scalarAssertions([["challengeCount()(uint256)", [], 0]]),
      next_challenge_id_one: scalarAssertions([["nextChallengeId()(uint256)", [], 1]]),
    },
    ComputeCreditVault: {
      owner_matches_operator: scalarAssertions([["owner()(address)", [], operator]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      developer_matches_intent: scalarAssertions([[
        "developer()(address)",
        [],
        staticInputs.computeCreditVault?.developer,
      ]]),
      developer_fee_matches_intent_and_frozen: scalarAssertions([
        ["developerFeeBps()(uint16)", [], contractPolicy.computeDeveloperFeeBps],
        ["developerFeeFrozen()(bool)", [], true],
      ]),
      paused: scalarAssertions([["paused()(bool)", [], true]]),
      metering_binding_unset: scalarAssertions([
        ["meteringVerifier()(address)", [], ZERO_ADDRESS],
        ["meteringQvlVerifier()(address)", [], ZERO_ADDRESS],
        ["meteringPolicySetHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingMeteringVerifier()(address)", [], ZERO_ADDRESS],
        ["pendingMeteringQvlVerifier()(address)", [], ZERO_ADDRESS],
        ["pendingMeteringPolicySetHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingMeteringBindingActivatesAt()(uint64)", [], 0],
      ]),
      metering_binding_not_frozen: scalarAssertions([[
        "meteringBindingFrozen()(bool)", [], false,
      ]]),
      active_admission_counts_zero: scalarAssertions([
        ["allowedAssetCount()(uint256)", [], 0],
        ["approvedComposeCount()(uint256)", [], 0],
        ["approvedTeeIdentityCount()(uint256)", [], 0],
      ]),
      pending_admission_counts_zero: scalarAssertions([
        ["pendingAssetCount()(uint256)", [], 0],
        ["pendingComposeCount()(uint256)", [], 0],
        ["pendingTeeIdentityCount()(uint256)", [], 0],
      ]),
      asset_and_rate_policy_counts_zero: scalarAssertions([
        ["activeRatePolicyCount()(uint256)", [], 0],
        ["pendingRatePolicyCount()(uint256)", [], 0],
      ]),
      admission_and_policy_additions_open: scalarAssertions([
        ["assetAdditionsFrozen()(bool)", [], false],
        ["ratePolicyAdditionsFrozen()(bool)", [], false],
        ["composePolicyFrozen()(bool)", [], false],
        ["teeIdentityAdditionsFrozen()(bool)", [], false],
      ]),
    },
    DiligenceRoom: {
      developer_matches_operator: scalarAssertions([
        ["developer()(address)", [], operator],
        ["initialDeveloper()(address)", [], operator],
      ]),
      release_governance_matches_intent: scalarAssertions([
        [
          "releaseGovernanceController()(address)",
          [],
          staticInputs.diligenceRoom?.governanceController,
        ],
        [
          "protocolFeeRecipient()(address)",
          [],
          staticInputs.diligenceRoom?.governanceController,
        ],
      ]),
      developer_transfer_unstaged_and_delayed: scalarAssertions([
        ["pendingDeveloper()(address)", [], ZERO_ADDRESS],
        ["pendingDeveloperActivatesAt()(uint256)", [], 0],
        ["DEVELOPER_TRANSFER_DELAY()(uint256)", [], 2 * 24 * 60 * 60],
      ]),
      constructor_bound_production_posture: scalarAssertions([
        ["productionRelease()(bool)", [], true],
        ["dealCount()(uint256)", [], 0],
      ]),
      result_verifier_unset: scalarAssertions([["resultVerifier()(address)", [], ZERO_ADDRESS]]),
      pending_result_verifier_unset: scalarAssertions([
        ["pendingResultVerifier()(address)", [], ZERO_ADDRESS],
        ["pendingResultVerifierActivatesAt()(uint256)", [], 0],
      ]),
      result_verifier_not_frozen: scalarAssertions([[
        "resultVerifierFrozen()(bool)", [], false,
      ]]),
      fee_policy_matches_intent_and_frozen: scalarAssertions([
        ["feeBps()(uint256)", [], contractPolicy.diligenceFeeBps ?? 100],
        ["DEFAULT_FEE_BPS()(uint256)", [], contractPolicy.diligenceFeeBps ?? 100],
        ["feeBpsFrozen()(bool)", [], true],
        ["COMPUTE_SETTLEMENT_BPS()(uint256)", [], 100],
        ["computeSettlementPolicyEnabled()(bool)", [], true],
      ]),
      approval_requirements_enforced_and_frozen: scalarAssertions([
        ["composeApprovalRequired()(bool)", [], true],
        ["teeIdentityApprovalRequired()(bool)", [], true],
        ["approvalRequirementsFrozen()(bool)", [], true],
      ]),
      attestation_binding_unset: scalarAssertions([
        ["attestationVerifier()(address)", [], ZERO_ADDRESS],
        ["attestationReleasePolicyHash()(bytes32)", [], ZERO_BYTES32],
      ]),
      pending_attestation_binding_unset: scalarAssertions([
        ["pendingAttestationVerifier()(address)", [], ZERO_ADDRESS],
        ["pendingAttestationReleasePolicyHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingAttestationBindingActivatesAt()(uint64)", [], 0],
      ]),
      attestation_binding_not_frozen: scalarAssertions([[
        "attestationBindingFrozen()(bool)", [], false,
      ]]),
      evaluator_policy_set_unset: (read) => (
        scalarAssertions([
          ["approvedEvaluatorPolicyCount()(uint256)", [], 0],
          ["pendingEvaluatorPolicyCount()(uint256)", [], 0],
          ["evaluatorPolicySetFrozen()(bool)", [], false],
          ["evaluatorPolicySetRoot()(bytes32)", [], ZERO_BYTES32],
        ])(read)
        && (() => {
          const policies = castTuple(
            read("evaluatorPolicies()(bytes32[3])", [], { json: true }),
            3,
          );
          return Boolean(policies)
            && policies.every((value) => exactScalar(value, ZERO_BYTES32));
        })()
      ),
      active_admission_counts_zero: scalarAssertions([
        ["approvedComposeCount()(uint256)", [], 0],
        ["approvedTeeIdentityCount()(uint256)", [], 0],
        ["approvedComposeHashes(bytes32)(bool)", [ZERO_BYTES32], false],
        ["teeIdentityComposeHash(address)(bytes32)", [ZERO_ADDRESS], ZERO_BYTES32],
      ]),
      pending_admission_counts_zero: scalarAssertions([
        ["pendingComposeCount()(uint256)", [], 0],
        ["pendingTeeIdentityCount()(uint256)", [], 0],
      ]),
      admission_additions_open: scalarAssertions([
        ["composeAdditionsFrozen()(bool)", [], false],
        ["teeIdentityAdditionsFrozen()(bool)", [], false],
      ]),
    },
    EmailOracleAuth: {
      owner_matches_operator: scalarAssertions([["owner()(address)", [], operator]]),
      constructor_bound_production_posture: scalarAssertions([[
        "productionRelease()(bool)", [], true,
      ]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      upgrade_delay_matches_intent: scalarAssertions([[
        "ORACLE_UPGRADE_DELAY()(uint256)",
        [],
        contractPolicy.emailOracleUpgradeDelaySeconds,
      ]]),
      deny_all: scalarAssertions([
        ["allowAnyDevice()(bool)", [], false],
        ["allowedOracleComposeHashes(bytes32)(bool)", [ZERO_BYTES32], false],
        ["allowedDeviceIds(bytes32)(bool)", [ZERO_BYTES32], false],
      ]),
      release_not_ready: scalarAssertions([
        ["releaseConfigurationReady()(bool)", [], false],
        ["releaseOracleComposeHash()(bytes32)", [], ZERO_BYTES32],
        ["releaseDeviceId()(bytes32)", [], ZERO_BYTES32],
        ["releaseConsumerManager()(address)", [], ZERO_ADDRESS],
        ["releaseConsumerAppId()(address)", [], ZERO_ADDRESS],
        ["releaseConsumerComposeHash()(bytes32)", [], ZERO_BYTES32],
        ["kmsContract()(address)", [], ZERO_ADDRESS],
        ["kmsRuntimeCodeHash()(bytes32)", [], ZERO_BYTES32],
        ["kmsImplementation()(address)", [], ZERO_ADDRESS],
        ["kmsImplementationRuntimeCodeHash()(bytes32)", [], ZERO_BYTES32],
        ["kmsRegistrationTxHash()(bytes32)", [], ZERO_BYTES32],
        ["kmsRegistrationBlock()(uint64)", [], 0],
        ["kmsRegistrationBlockHash()(bytes32)", [], ZERO_BYTES32],
        ["targetBootInfoHash()(bytes32)", [], ZERO_BYTES32],
        ["restartKeyDerivationProofHash()(bytes32)", [], ZERO_BYTES32],
      ]),
      active_admission_counts_zero: scalarAssertions([
        ["allowedOracleComposeHashCount()(uint256)", [], 0],
        ["allowedDeviceIdCount()(uint256)", [], 0],
        ["consumerManagerCount()(uint256)", [], 0],
        ["totalConsumerComposeHashCount()(uint256)", [], 0],
      ]),
      pending_admission_counts_zero: scalarAssertions([
        ["pendingOracleComposeHashCount()(uint256)", [], 0],
        ["pendingKmsContract()(address)", [], ZERO_ADDRESS],
        ["pendingKmsRuntimeCodeHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingKmsImplementation()(address)", [], ZERO_ADDRESS],
        ["pendingKmsImplementationRuntimeCodeHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingKmsRegistrationTxHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingKmsRegistrationBlock()(uint64)", [], 0],
        ["pendingKmsRegistrationBlockHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingTargetBootInfoHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingRestartKeyDerivationProofHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingKmsBindingActivatesAt()(uint256)", [], 0],
      ]),
      release_freezes_open: scalarAssertions([
        ["oracleCodeFrozen()(bool)", [], false],
        ["kmsBindingFrozen()(bool)", [], false],
        ["consumerManagerAdditionsFrozen()(bool)", [], false],
        ["consumerRegistryFrozen()(bool)", [], false],
      ]),
    },
    ExecutionPolicyAnchor: {
      owner_matches_operator: scalarAssertions([["owner()(address)", [], operator]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      paused: scalarAssertions([["paused()(bool)", [], true]]),
      writer_unset: scalarAssertions([
        ["writer()(address)", [], ZERO_ADDRESS],
        ["writerReleaseCommitment()(bytes32)", [], ZERO_BYTES32],
      ]),
      pending_writer_unset: scalarAssertions([
        ["pendingWriter()(address)", [], ZERO_ADDRESS],
        ["pendingWriterReleaseCommitment()(bytes32)", [], ZERO_BYTES32],
        ["pendingWriterActivatesAt()(uint64)", [], 0],
      ]),
      writer_rotations_not_frozen: scalarAssertions([[
        "writerRotationsFrozen()(bool)", [], false,
      ]]),
      global_sequence_zero: scalarAssertions([["globalSequence()(uint256)", [], 0]]),
      global_head_zero: scalarAssertions([["globalHead()(bytes32)", [], ZERO_BYTES32]]),
    },
    RoyaltyDistributor: {
      owner_matches_operator: scalarAssertions([["owner()(address)", [], operator]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      paused: scalarAssertions([["paused()(bool)", [], true]]),
      active_authority_empty: scalarAssertions([
        ["settlementVerifier()(address)", [], ZERO_ADDRESS],
        ["qvlVerifier()(address)", [], ZERO_ADDRESS],
        ["executionPolicyAnchor()(address)", [], ZERO_ADDRESS],
        ["anchorWriterReleaseCommitment()(bytes32)", [], ZERO_BYTES32],
        ["releasePolicyCommitment()(bytes32)", [], ZERO_BYTES32],
        ["authorityNonce()(uint256)", [], 0],
      ]),
      pending_authority_empty: scalarAssertions([
        ["pendingSettlementVerifier()(address)", [], ZERO_ADDRESS],
        ["pendingQvlVerifier()(address)", [], ZERO_ADDRESS],
        ["pendingExecutionPolicyAnchor()(address)", [], ZERO_ADDRESS],
        ["pendingAnchorWriterReleaseCommitment()(bytes32)", [], ZERO_BYTES32],
        ["pendingReleasePolicyCommitment()(bytes32)", [], ZERO_BYTES32],
        ["pendingAuthorityNonce()(uint256)", [], 0],
        ["pendingAuthorityActivatesAt()(uint64)", [], 0],
        ["pendingAuthorityRevocation()(bool)", [], false],
      ]),
      authority_history_empty: scalarAssertions([["authorityNonce()(uint256)", [], 0]]),
    },
    TinkerAccountEncumbrance: {
      owner_matches_operator: scalarAssertions([["owner()(address)", [], operator]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      opaque_account_binding_domain_is_exact: scalarAssertions([
        ["ACCOUNT_BINDING_TYPEHASH()(bytes32)", [], TINKER_ACCOUNT_BINDING_TYPEHASH],
        ["TINKER_PROVIDER_NAMESPACE()(bytes32)", [], TINKER_PROVIDER_NAMESPACE],
      ]),
      deployment_policy_matches_intent: scalarAssertions([
        [
          "accountCommitment()(bytes32)",
          [],
          staticInputs.tinkerAccountEncumbrance?.accountCommitment,
        ],
        ["maxAddBalanceWei()(uint256)", [], contractPolicy.tinkerMaxAddBalanceWei],
        ["maxSpendWei()(uint256)", [], contractPolicy.tinkerMaxSpendWei],
      ]),
      emergency_halted: scalarAssertions([["emergencyHalted()(bool)", [], true]]),
      active_authority_empty: (read) => (
        exactScalar(read("approvedComposeCount()(uint256)", []), 0)
        && exactScalar(read("managerCount()(uint256)", []), 0)
        && exactScalar(
          read("approvedComposeRoot()(bytes32)", []),
          read("computeComposeRoot(bytes32[])(bytes32)", ["[]"]),
        )
        && exactScalar(
          read("managerRoot()(bytes32)", []),
          read("computeManagerRoot(address[])(bytes32)", ["[]"]),
        )
      ),
      pending_authority_empty: scalarAssertions([
        ["pendingAccountCommitment()(bytes32)", [], ZERO_BYTES32],
        ["pendingMaxAddBalanceWei()(uint256)", [], 0],
        ["pendingMaxSpendWei()(uint256)", [], 0],
        ["pendingComposeRoot()(bytes32)", [], ZERO_BYTES32],
        ["pendingComposeCount()(uint256)", [], 0],
        ["pendingManagerRoot()(bytes32)", [], ZERO_BYTES32],
        ["pendingManagerCount()(uint256)", [], 0],
        ["pendingReleasePolicyCommitment()(bytes32)", [], ZERO_BYTES32],
        ["pendingReleasePolicyActivatesAt()(uint64)", [], 0],
      ]),
      release_authority_empty: scalarAssertions([
        ["releasePolicyCommitment()(bytes32)", [], ZERO_BYTES32],
        ["releaseMaxAddBalanceWei()(uint256)", [], 0],
        ["releaseMaxSpendWei()(uint256)", [], 0],
        ["releaseComposeRoot()(bytes32)", [], ZERO_BYTES32],
        ["releaseComposeCount()(uint256)", [], 0],
        ["releaseManagerRoot()(bytes32)", [], ZERO_BYTES32],
        ["releaseManagerCount()(uint256)", [], 0],
      ]),
      release_policy_not_frozen: scalarAssertions([[
        "releasePolicyFrozen()(bool)", [], false,
      ]]),
    },
  };
}

function normalizedRoyaltyAuthority(value) {
  try {
    return normalizeRoyaltyReleaseAuthority(value);
  } catch {
    return null;
  }
}

function royaltyActiveAuthorityEmpty(read) {
  return scalarAssertions([
    ["settlementVerifier()(address)", [], ZERO_ADDRESS],
    ["qvlVerifier()(address)", [], ZERO_ADDRESS],
    ["executionPolicyAnchor()(address)", [], ZERO_ADDRESS],
    ["anchorWriterReleaseCommitment()(bytes32)", [], ZERO_BYTES32],
    ["releasePolicyCommitment()(bytes32)", [], ZERO_BYTES32],
    ["authorityNonce()(uint256)", [], 0],
  ])(read);
}

function royaltyPendingAuthorityEmpty(read) {
  return scalarAssertions([
    ["pendingSettlementVerifier()(address)", [], ZERO_ADDRESS],
    ["pendingQvlVerifier()(address)", [], ZERO_ADDRESS],
    ["pendingExecutionPolicyAnchor()(address)", [], ZERO_ADDRESS],
    ["pendingAnchorWriterReleaseCommitment()(bytes32)", [], ZERO_BYTES32],
    ["pendingReleasePolicyCommitment()(bytes32)", [], ZERO_BYTES32],
    ["pendingAuthorityNonce()(uint256)", [], 0],
    ["pendingAuthorityActivatesAt()(uint64)", [], 0],
    ["pendingAuthorityRevocation()(bool)", [], false],
  ])(read);
}

function royaltyReleasePolicyRecomputes(read, royalty) {
  return Boolean(royalty) && exactScalar(read(
    "computeReleasePolicyCommitment(uint256,address,address,address,bytes32)(bytes32)",
    [
      String(royalty.authority_nonce),
      royalty.settlement_verifier,
      royalty.qvl_verifier,
      royalty.execution_policy_anchor,
      royalty.anchor_writer_release_commitment,
    ],
  ), royalty.release_policy_commitment);
}

export function royaltyPhaseOnePoststatePolicies(royaltyReleaseAuthority) {
  const royalty = normalizedRoyaltyAuthority(royaltyReleaseAuthority);
  return {
    RoyaltyDistributor: {
      owner_matches_release_authority: (read) => Boolean(royalty)
        && exactScalar(read("owner()(address)", []), royalty.owner),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      paused: scalarAssertions([["paused()(bool)", [], true]]),
      active_authority_empty: royaltyActiveAuthorityEmpty,
      pending_authority_matches_release_authority: (read) => Boolean(royalty)
        && scalarAssertions([
          ["pendingSettlementVerifier()(address)", [], royalty.settlement_verifier],
          ["pendingQvlVerifier()(address)", [], royalty.qvl_verifier],
          ["pendingExecutionPolicyAnchor()(address)", [], royalty.execution_policy_anchor],
          ["pendingAnchorWriterReleaseCommitment()(bytes32)", [], royalty.anchor_writer_release_commitment],
          ["pendingReleasePolicyCommitment()(bytes32)", [], royalty.release_policy_commitment],
          ["pendingAuthorityNonce()(uint256)", [], royalty.authority_nonce],
          ["pendingAuthorityRevocation()(bool)", [], false],
        ])(read)
        && (() => {
          try {
            return BigInt(String(read("pendingAuthorityActivatesAt()(uint64)", []))) > 0n;
          } catch {
            return false;
          }
        })(),
      release_policy_recomputes_exactly: (read) =>
        royaltyReleasePolicyRecomputes(read, royalty),
      authority_history_empty: (read) => Boolean(royalty)
        && scalarAssertions([
          ["settlementVerifierEverConfigured(address)(bool)", [royalty.settlement_verifier], false],
          ["qvlVerifierEverConfigured(address)(bool)", [royalty.qvl_verifier], false],
          ["anchorWriterEverConfigured(address)(bool)", [royalty.anchor_writer], false],
        ])(read),
    },
  };
}

export function finalPoststatePolicies(
  finalAuthority,
  finalAuthoritySha256,
  royaltyReleaseAuthority,
) {
  const diligence = finalAuthority?.contracts?.diligence_room || {};
  const compute = finalAuthority?.contracts?.compute_credit_vault || {};
  const email = finalAuthority?.contracts?.email_oracle_auth || {};
  const tinker = finalAuthority?.contracts?.tinker_account_encumbrance || {};
  const challenge = finalAuthority?.contracts?.challenge_registry || {};
  const anchor = finalAuthority?.execution_policy?.rollback_anchor_target || {};
  const royalty = normalizedRoyaltyAuthority(royaltyReleaseAuthority);
  const operator = finalAuthority?.operator_address;
  const diligenceCompose = `0x${clean(diligence.release_admission?.compose_hash)}`;
  const computeCompose = `0x${clean(compute.compose_hash)}`;
  const finalAuthorityCommitment = /^sha256:[0-9a-f]{64}$/.test(finalAuthoritySha256)
    ? `0x${finalAuthoritySha256.slice("sha256:".length)}`
    : "";
  let releaseMarker = null;
  try {
    releaseMarker = executionPolicyReleaseMarker({
      finalAuthoritySha256,
      contractAddress: anchor.contract_address,
      writerAddress: anchor.writer_address,
      writerReleaseCommitment: anchor.writer_release_commitment,
      chainId: anchor.chain_id,
    });
  } catch {
    releaseMarker = null;
  }
  const nativePolicy = compute.rate_policies?.native || {};
  const erc20Policy = compute.rate_policies?.erc20 || {};
  const emailRelease = email.release || {};
  const arenaBindings = Object.values(finalAuthority?.arena_registry_bindings || {});
  const challengeState = (read, binding) => castTuple(read(
    "getChallenge(uint256)((address,address,uint8,uint64,uint64,uint32,bool,bool))",
    [String(binding.registry_challenge_id)],
    { json: true },
  ), 8);
  const challengeVersion = (read, binding) => castTuple(read(
    "getVersion(uint256,uint32)((string,bytes32,bytes32,bytes32,bytes32,uint64))",
    [String(binding.registry_challenge_id), String(binding.registry_version)],
    { json: true },
  ), 6);
  const exactArenaCatalog = (predicate) => (read) => (
    arenaBindings.length > 0
    && arenaBindings.length === challenge.expected_challenge_count
    && arenaBindings.every((binding) => predicate(read, binding))
  );
  return {
    ChallengeRegistry: {
      owner_matches_final_authority: scalarAssertions([[
        "owner()(address)", [], challenge.owner || operator,
      ]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      registry_unpaused: scalarAssertions([["registryPaused()(bool)", [], false]]),
      arena_registry_bindings_match_final_authority: exactArenaCatalog((read, binding) => {
        const state = challengeState(read, binding);
        return Boolean(state)
          && exactScalar(read(
            "MIN_VERSION_REVIEW_DELAY()(uint64)",
            [],
          ), challenge.minimum_version_review_delay_seconds)
          && exactScalar(read(
            "challengeExists(uint256)(bool)",
            [String(binding.registry_challenge_id)],
          ), true)
          && exactScalar(state[0], binding.controller_address)
          && exactScalar(state[1], binding.pending_controller_address)
          && exactScalar(state[2], 1);
      }),
      genesis_catalog_matches_final_authority: exactArenaCatalog((read, binding) => {
        const version = challengeVersion(read, binding);
        if (!version) return false;
        const reviewEligibleAt = read(
          "reviewEligibleAt(uint256)(uint64)",
          [String(binding.registry_challenge_id)],
        );
        try {
          return exactScalar(version[0], binding.metadata_uri)
            && exactScalar(version[1], binding.metadata_hash)
            && exactScalar(version[2], binding.sealed_artifact_commitment)
            && exactScalar(version[3], binding.evaluator_commitment)
            && exactScalar(version[4], binding.release_policy_commitment)
            && BigInt(String(version[5])) > 0n
            && BigInt(String(reviewEligibleAt))
              === BigInt(String(version[5]))
                + BigInt(challenge.minimum_version_review_delay_seconds);
        } catch {
          return false;
        }
      }),
      active_challenge_count_at_least_one: (read) => (
        Number.isSafeInteger(challenge.expected_challenge_count)
        && challenge.expected_challenge_count > 0
        && (() => {
          try {
            const observedCount = BigInt(String(read("challengeCount()(uint256)", [])));
            const observedNext = BigInt(String(read("nextChallengeId()(uint256)", [])));
            return observedCount >= BigInt(challenge.expected_challenge_count)
              && observedNext === observedCount + 1n;
          } catch {
            return false;
          }
        })()
      ),
      active_version_count_at_least_one: exactArenaCatalog((read, binding) => {
        const state = challengeState(read, binding);
        return Boolean(state) && exactPositiveUint(state[5], binding.registry_version);
      }),
      active_challenges_unpaused: exactArenaCatalog((read, binding) => {
        const state = challengeState(read, binding);
        const id = String(binding.registry_challenge_id);
        return Boolean(state)
          && exactScalar(state[6], false)
          && exactScalar(read("controllerChallengePaused(uint256)(bool)", [id]), false)
          && exactScalar(read("governanceChallengePaused(uint256)(bool)", [id]), false);
      }),
      active_challenge_configurations_frozen: exactArenaCatalog((read, binding) => {
        const state = challengeState(read, binding);
        return Boolean(state) && exactScalar(state[7], true);
      }),
    },
    ComputeCreditVault: {
      owner_matches_final_authority: scalarAssertions([["owner()(address)", [], compute.owner]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      developer_and_fee_match_final_authority: scalarAssertions([
        ["developer()(address)", [], compute.developer],
        ["developerFeeBps()(uint16)", [], compute.developer_fee_bps],
        ["developerFeeFrozen()(bool)", [], true],
      ]),
      metering_binding_matches_final_authority: scalarAssertions([
        ["meteringVerifier()(address)", [], compute.metering_verifier],
        ["meteringQvlVerifier()(address)", [], compute.metering_qvl_verifier],
        ["meteringPolicySetHash()(bytes32)", [], compute.metering_policy_set_hash],
      ]),
      metering_binding_frozen: scalarAssertions([[
        "meteringBindingFrozen()(bool)", [], true,
      ]]),
      admission_matches_final_authority: scalarAssertions([
        ["allowedAssetCount()(uint256)", [], 1],
        ["activeRatePolicyCount()(uint256)", [], 2],
        ["approvedComposeCount()(uint256)", [], 1],
        ["approvedTeeIdentityCount()(uint256)", [], 1],
        ["approvedComposeHashes(bytes32)(bool)", [computeCompose], true],
        ["teeIdentityComposeHash(address)(bytes32)", [compute.tee_identity], computeCompose],
      ]),
      rate_policies_match_final_authority: (read) => (
        tupleAssertion(
          "ratePolicies(bytes32)(address,address,uint16,bool)",
          [nativePolicy.commitment],
          [nativePolicy.asset, nativePolicy.provider, nativePolicy.developer_fee_bps, true],
        )(read)
        && tupleAssertion(
          "ratePolicies(bytes32)(address,address,uint16,bool)",
          [erc20Policy.commitment],
          [erc20Policy.asset, erc20Policy.provider, erc20Policy.developer_fee_bps, true],
        )(read)
      ),
      assets_and_providers_match_final_authority: scalarAssertions([
        ["allowedAssets(address)(bool)", [erc20Policy.asset], true],
      ]),
      all_additions_and_fee_frozen: scalarAssertions([
        ["assetAdditionsFrozen()(bool)", [], true],
        ["ratePolicyAdditionsFrozen()(bool)", [], true],
        ["composePolicyFrozen()(bool)", [], true],
        ["teeIdentityAdditionsFrozen()(bool)", [], true],
        ["developerFeeFrozen()(bool)", [], true],
      ]),
      unpaused: scalarAssertions([["paused()(bool)", [], false]]),
      no_pending_authority: (read) => (
        scalarAssertions([
          ["pendingAssetCount()(uint256)", [], 0],
          ["pendingRatePolicyCount()(uint256)", [], 0],
          ["pendingComposeCount()(uint256)", [], 0],
          ["pendingTeeIdentityCount()(uint256)", [], 0],
          ["pendingMeteringVerifier()(address)", [], ZERO_ADDRESS],
          ["pendingMeteringQvlVerifier()(address)", [], ZERO_ADDRESS],
          ["pendingMeteringPolicySetHash()(bytes32)", [], ZERO_BYTES32],
          ["pendingMeteringBindingActivatesAt()(uint64)", [], 0],
          ["pendingAssetActivations(address)(uint64)", [erc20Policy.asset], 0],
          ["pendingComposeActivations(bytes32)(uint64)", [computeCompose], 0],
          ["pendingTeeIdentityComposeHash(address)(bytes32)", [compute.tee_identity], ZERO_BYTES32],
          ["pendingTeeIdentityActivations(address)(uint64)", [compute.tee_identity], 0],
        ])(read)
        && tupleAssertion(
          "pendingRatePolicies(bytes32)(address,address,uint16,uint64)",
          [nativePolicy.commitment],
          [ZERO_ADDRESS, ZERO_ADDRESS, 0, 0],
        )(read)
        && tupleAssertion(
          "pendingRatePolicies(bytes32)(address,address,uint16,uint64)",
          [erc20Policy.commitment],
          [ZERO_ADDRESS, ZERO_ADDRESS, 0, 0],
        )(read)
      ),
    },
    DiligenceRoom: {
      developer_matches_final_authority: scalarAssertions([
        ["developer()(address)", [], diligence.developer],
        ["initialDeveloper()(address)", [], operator],
        ["releaseGovernanceController()(address)", [], diligence.developer],
        ["protocolFeeRecipient()(address)", [], diligence.developer],
      ]),
      developer_transfer_complete_and_delayed: scalarAssertions([
        ["pendingDeveloper()(address)", [], ZERO_ADDRESS],
        ["pendingDeveloperActivatesAt()(uint256)", [], 0],
        ["DEVELOPER_TRANSFER_DELAY()(uint256)", [], 2 * 24 * 60 * 60],
      ]),
      constructor_bound_production_posture: scalarAssertions([
        ["productionRelease()(bool)", [], true],
        ["dealCount()(uint256)", [], 0],
      ]),
      result_verifier_matches_final_authority: scalarAssertions([[
        "resultVerifier()(address)", [], diligence.result_verifier,
      ]]),
      result_verifier_frozen: scalarAssertions([
        ["resultVerifierFrozen()(bool)", [], true],
        ["pendingResultVerifier()(address)", [], ZERO_ADDRESS],
        ["pendingResultVerifierActivatesAt()(uint256)", [], 0],
      ]),
      attestation_binding_matches_final_authority: scalarAssertions([
        ["attestationVerifier()(address)", [], diligence.attestation_verifier],
        [
          "attestationReleasePolicyHash()(bytes32)",
          [],
          diligence.attestation_release_policy_hash,
        ],
      ]),
      attestation_binding_frozen: scalarAssertions([
        ["attestationBindingFrozen()(bool)", [], true],
        ["pendingAttestationVerifier()(address)", [], ZERO_ADDRESS],
        ["pendingAttestationReleasePolicyHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingAttestationBindingActivatesAt()(uint64)", [], 0],
      ]),
      evaluator_policy_set_matches_final_authority: (read) => {
        const policies = diligence.evaluator_policy_commitments;
        const observed = castTuple(
          read("evaluatorPolicies()(bytes32[3])", [], { json: true }),
          3,
        );
        return scalarAssertions([
          ["approvedEvaluatorPolicyCount()(uint256)", [], 3],
          ["pendingEvaluatorPolicyCount()(uint256)", [], 0],
          ["evaluatorPolicySetFrozen()(bool)", [], true],
          ["evaluatorPolicySetRoot()(bytes32)", [], diligence.evaluator_policy_set_root],
          ...policies.flatMap((policy) => [
            ["approvedEvaluatorPolicies(bytes32)(bool)", [policy], true],
            ["pendingEvaluatorPolicyActivations(bytes32)(uint256)", [policy], 0],
          ]),
        ])(read)
          && Boolean(observed)
          && observed.every((value, index) => exactScalar(value, policies[index]));
      },
      release_admission_matches_final_authority: scalarAssertions([
        [
          "approvedComposeCount()(uint256)",
          [],
          diligence.release_admission?.approved_compose_count,
        ],
        [
          "approvedTeeIdentityCount()(uint256)",
          [],
          diligence.release_admission?.approved_tee_identity_count,
        ],
        ["approvedComposeHashes(bytes32)(bool)", [diligenceCompose], true],
        [
          "teeIdentityComposeHash(address)(bytes32)",
          [diligence.release_admission?.tee_identity],
          diligenceCompose,
        ],
        ["composeApprovalRequired()(bool)", [], true],
        ["teeIdentityApprovalRequired()(bool)", [], true],
        ["approvalRequirementsFrozen()(bool)", [], true],
        ["feeBpsFrozen()(bool)", [], true],
        ["computeSettlementPolicyEnabled()(bool)", [], true],
      ]),
      release_admission_additions_frozen: scalarAssertions([
        ["composeAdditionsFrozen()(bool)", [], true],
        ["teeIdentityAdditionsFrozen()(bool)", [], true],
      ]),
      no_pending_authority: scalarAssertions([
        ["pendingComposeCount()(uint256)", [], 0],
        ["pendingTeeIdentityCount()(uint256)", [], 0],
        ["pendingComposeActivations(bytes32)(uint256)", [diligenceCompose], 0],
        [
          "pendingTeeIdentityActivations(address)(uint256)",
          [diligence.release_admission?.tee_identity],
          0,
        ],
        [
          "pendingTeeIdentityComposeHash(address)(bytes32)",
          [diligence.release_admission?.tee_identity],
          ZERO_BYTES32,
        ],
      ]),
    },
    EmailOracleAuth: {
      owner_matches_final_authority: scalarAssertions([["owner()(address)", [], email.owner]]),
      constructor_bound_production_posture: scalarAssertions([[
        "productionRelease()(bool)", [], true,
      ]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      release_tuple_matches_final_authority: scalarAssertions([
        ["ORACLE_UPGRADE_DELAY()(uint256)", [], email.upgrade_delay_seconds],
        ["allowAnyDevice()(bool)", [], false],
        ["releaseOracleComposeHash()(bytes32)", [], emailRelease.oracle_compose_hash],
        ["releaseDeviceId()(bytes32)", [], emailRelease.device_id],
        ["releaseConsumerManager()(address)", [], email.consumer_address],
        ["releaseConsumerAppId()(address)", [], email.consumer_address],
        ["releaseConsumerComposeHash()(bytes32)", [], emailRelease.consumer_compose_hash],
        ["allowedOracleComposeHashes(bytes32)(bool)", [emailRelease.oracle_compose_hash], true],
        ["allowedDeviceIds(bytes32)(bool)", [emailRelease.device_id], true],
      ]),
      kms_tuple_matches_final_authority: scalarAssertions([
        ["kmsContract()(address)", [], emailRelease.kms_contract_address],
        ["kmsRuntimeCodeHash()(bytes32)", [], emailRelease.kms_runtime_code_hash],
        ["kmsImplementation()(address)", [], emailRelease.kms_implementation_address],
        [
          "kmsImplementationRuntimeCodeHash()(bytes32)",
          [],
          emailRelease.kms_implementation_runtime_code_hash,
        ],
        ["kmsRegistrationTxHash()(bytes32)", [], emailRelease.kms_registration_tx_hash],
        ["kmsRegistrationBlock()(uint64)", [], emailRelease.kms_registration_block],
        ["kmsRegistrationBlockHash()(bytes32)", [], emailRelease.kms_registration_block_hash],
        ["targetBootInfoHash()(bytes32)", [], emailRelease.target_boot?.info_hash],
        [
          "restartKeyDerivationProofHash()(bytes32)",
          [],
          emailRelease.restart_key_derivation_proof_hash,
        ],
      ]),
      consumer_tuple_matches_final_authority: scalarAssertions([
        ["consumerManagers(address)(bool)", [email.consumer_address], true],
        ["consumerManagerCount()(uint256)", [], 1],
        ["consumerComposeHashCount(address)(uint256)", [email.consumer_address], 1],
        [
          "isConsumerComposeHashRegistered(address,bytes32)(bool)",
          [email.consumer_address, emailRelease.consumer_compose_hash],
          true,
        ],
        [
          "isConsumerAuthorized(address,bytes32)(bool)",
          [email.consumer_address, emailRelease.consumer_compose_hash],
          true,
        ],
        ["consumerEmergencyRevoked(address)(bool)", [email.consumer_address], false],
        ["totalConsumerComposeHashCount()(uint256)", [], 1],
        ["allowedOracleComposeHashCount()(uint256)", [], 1],
        ["allowedDeviceIdCount()(uint256)", [], 1],
      ]),
      release_freezes_closed: scalarAssertions([
        ["oracleCodeFrozen()(bool)", [], true],
        ["kmsBindingFrozen()(bool)", [], true],
        ["consumerManagerAdditionsFrozen()(bool)", [], true],
        ["consumerRegistryFrozen()(bool)", [], true],
      ]),
      release_ready: scalarAssertions([["releaseConfigurationReady()(bool)", [], true]]),
      no_pending_authority: scalarAssertions([
        ["pendingOracleComposeHashCount()(uint256)", [], 0],
        ["pendingOracleComposeHashes(bytes32)(uint256)", [emailRelease.oracle_compose_hash], 0],
        ["pendingKmsContract()(address)", [], ZERO_ADDRESS],
        ["pendingKmsRuntimeCodeHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingKmsImplementation()(address)", [], ZERO_ADDRESS],
        ["pendingKmsImplementationRuntimeCodeHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingKmsRegistrationTxHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingKmsRegistrationBlock()(uint64)", [], 0],
        ["pendingKmsRegistrationBlockHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingTargetBootInfoHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingRestartKeyDerivationProofHash()(bytes32)", [], ZERO_BYTES32],
        ["pendingKmsBindingActivatesAt()(uint256)", [], 0],
      ]),
    },
    ExecutionPolicyAnchor: {
      owner_matches_final_authority: scalarAssertions([["owner()(address)", [], operator]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      writer_matches_final_authority: scalarAssertions([[
        "writer()(address)", [], anchor.writer_address,
      ]]),
      writer_release_commitment_matches_final_authority: scalarAssertions([[
        "writerReleaseCommitment()(bytes32)", [], anchor.writer_release_commitment,
      ]]),
      writer_rotations_frozen: scalarAssertions([[
        "writerRotationsFrozen()(bool)", [], true,
      ]]),
      unpaused: scalarAssertions([["paused()(bool)", [], false]]),
      no_pending_writer: scalarAssertions([
        ["pendingWriter()(address)", [], ZERO_ADDRESS],
        ["pendingWriterReleaseCommitment()(bytes32)", [], ZERO_BYTES32],
        ["pendingWriterActivatesAt()(uint64)", [], 0],
      ]),
      anchor_typehash_matches_release_protocol: scalarAssertions([[
        "ANCHOR_TYPEHASH()(bytes32)", [], EXECUTION_POLICY_ANCHOR_TYPEHASH,
      ]]),
      release_authority_marker_is_exact_first_state: (read) => (
        Boolean(releaseMarker)
        && exactScalar(read("globalSequence()(uint256)", []), 1)
        && exactScalar(
          read("globalHead()(bytes32)", []),
          releaseMarker.newGlobalHead,
        )
      ),
      release_authority_marker_keccak_head_matches: (read) => (
        Boolean(releaseMarker)
        && exactScalar(
          read(
            "computeAnchorHead(uint256,bytes32,bytes32,bytes32,bytes32,address,bytes32)(bytes32)",
            [
              "1",
              releaseMarker.previousGlobalHead,
              releaseMarker.resourceHash,
              releaseMarker.previousResourceHead,
              releaseMarker.decisionHash,
              releaseMarker.writerAddress,
              releaseMarker.writerReleaseCommitment,
            ],
          ),
          releaseMarker.newGlobalHead,
        )
      ),
      release_authority_marker_indexes_match: (read) => (
        Boolean(releaseMarker)
        && exactScalar(
          read("resourceDecisionHead(bytes32)(bytes32)", [releaseMarker.resourceHash]),
          finalAuthorityCommitment,
        )
        && exactScalar(
          read("resourceSequence(bytes32)(uint256)", [releaseMarker.resourceHash]),
          1,
        )
        && exactScalar(
          read("decisionSequence(bytes32)(uint256)", [releaseMarker.decisionHash]),
          1,
        )
      ),
      release_authority_marker_receipt_and_event_finalized: (read) => (
        Boolean(releaseMarker)
        && typeof read.releaseMarkerEvidence === "function"
        && read.releaseMarkerEvidence(releaseMarker)?.valid === true
      ),
    },
    RoyaltyDistributor: {
      release_authority_matches_v3_anchor: () => Boolean(royalty)
        && royalty.owner === operator
        && royalty.distributor_address
          === finalAuthority?.contracts?.royalty_distributor?.address
        && royalty.execution_policy_anchor === anchor.contract_address
        && royalty.anchor_writer === anchor.writer_address
        && royalty.anchor_writer_release_commitment
          === anchor.writer_release_commitment,
      owner_matches_release_authority: (read) => Boolean(royalty)
        && exactScalar(read("owner()(address)", []), royalty.owner),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      unpaused: scalarAssertions([["paused()(bool)", [], false]]),
      active_authority_matches_release_authority: (read) => Boolean(royalty)
        && scalarAssertions([
          ["settlementVerifier()(address)", [], royalty.settlement_verifier],
          ["qvlVerifier()(address)", [], royalty.qvl_verifier],
          ["executionPolicyAnchor()(address)", [], royalty.execution_policy_anchor],
          ["anchorWriterReleaseCommitment()(bytes32)", [], royalty.anchor_writer_release_commitment],
          ["releasePolicyCommitment()(bytes32)", [], royalty.release_policy_commitment],
          ["authorityNonce()(uint256)", [], royalty.authority_nonce],
        ])(read),
      release_policy_recomputes_exactly: (read) =>
        royaltyReleasePolicyRecomputes(read, royalty),
      pending_authority_empty: royaltyPendingAuthorityEmpty,
      authority_history_matches_release_authority: (read) => Boolean(royalty)
        && scalarAssertions([
          ["settlementVerifierEverConfigured(address)(bool)", [royalty.settlement_verifier], true],
          ["qvlVerifierEverConfigured(address)(bool)", [royalty.qvl_verifier], true],
          ["anchorWriterEverConfigured(address)(bool)", [royalty.anchor_writer], true],
        ])(read),
    },
    TinkerAccountEncumbrance: {
      owner_matches_final_authority: scalarAssertions([["owner()(address)", [], tinker.owner]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
      opaque_account_binding_domain_is_exact: scalarAssertions([
        ["ACCOUNT_BINDING_TYPEHASH()(bytes32)", [], TINKER_ACCOUNT_BINDING_TYPEHASH],
        ["TINKER_PROVIDER_NAMESPACE()(bytes32)", [], TINKER_PROVIDER_NAMESPACE],
      ]),
      active_policy_matches_final_authority: scalarAssertions([
        ["accountCommitment()(bytes32)", [], tinker.account_commitment],
        ["maxAddBalanceWei()(uint256)", [], tinker.max_add_balance_wei],
        ["maxSpendWei()(uint256)", [], tinker.max_spend_wei],
        ["approvedComposeRoot()(bytes32)", [], tinker.approved_compose_root],
        ["approvedComposeCount()(uint256)", [], tinker.approved_compose_count],
        ["managerRoot()(bytes32)", [], tinker.manager_root],
        ["managerCount()(uint256)", [], tinker.manager_count],
        ["approvedComposeHashes(bytes32)(bool)", [tinker.approved_compose_hashes?.[0]], true],
        ["managers(address)(bool)", [tinker.managers?.[0]], true],
      ]),
      release_policy_matches_final_authority: scalarAssertions([
        ["releasePolicyCommitment()(bytes32)", [], tinker.release_policy_commitment],
        ["releaseMaxAddBalanceWei()(uint256)", [], tinker.release_max_add_balance_wei],
        ["releaseMaxSpendWei()(uint256)", [], tinker.release_max_spend_wei],
        ["releaseComposeRoot()(bytes32)", [], tinker.release_compose_root],
        ["releaseComposeCount()(uint256)", [], tinker.release_compose_count],
        ["releaseManagerRoot()(bytes32)", [], tinker.release_manager_root],
        ["releaseManagerCount()(uint256)", [], tinker.release_manager_count],
      ]),
      release_policy_frozen: scalarAssertions([["releasePolicyFrozen()(bool)", [], true]]),
      emergency_unhalted: scalarAssertions([["emergencyHalted()(bool)", [], false]]),
      no_pending_authority: scalarAssertions([
        ["pendingAccountCommitment()(bytes32)", [], ZERO_BYTES32],
        ["pendingMaxAddBalanceWei()(uint256)", [], 0],
        ["pendingMaxSpendWei()(uint256)", [], 0],
        ["pendingComposeRoot()(bytes32)", [], ZERO_BYTES32],
        ["pendingComposeCount()(uint256)", [], 0],
        ["pendingManagerRoot()(bytes32)", [], ZERO_BYTES32],
        ["pendingManagerCount()(uint256)", [], 0],
        ["pendingReleasePolicyCommitment()(bytes32)", [], ZERO_BYTES32],
        ["pendingReleasePolicyActivatesAt()(uint64)", [], 0],
      ]),
      per_operation_caps_enforced: () => tinker.per_operation_caps === true,
      noncustodial: () => tinker.custodies_funds === false,
    },
  };
}

function emptyContractDeploymentChainEvidence(
  poststateMode = "",
  rpcEndpointSha256 = "",
  secondaryRpcEndpointSha256 = "",
  rpcOriginSha256 = "",
  secondaryRpcOriginSha256 = "",
  evidenceSource = "production_collector",
) {
  return {
    evidenceSource,
    valid: false,
    readOnly: true,
    chainId: 0,
    secondaryChainId: 0,
    rpcEndpointSha256,
    secondaryRpcEndpointSha256,
    rpcOriginSha256,
    secondaryRpcOriginSha256,
    rpcEndpointsDistinct: false,
    secondaryFinalizedSnapshotVerified: false,
    secondaryFinalizedTagRechecked: false,
    snapshotBlockNumber: 0,
    snapshotBlockHash: "",
    snapshotFinality: "",
    finalizedTagRechecked: false,
    finalizedRecheckBlockNumber: 0,
    finalizedRecheckBlockHash: "",
    snapshotBlockHashVerified: false,
    commonSnapshotBlock: false,
    anchorWriterGasReadiness: null,
    contractCount: 0,
    transactionCount: 0,
    deployerMatchCount: 0,
    creationTransactionCount: 0,
    receiptCount: 0,
    successfulReceiptCount: 0,
    contractAddressMatchCount: 0,
    deploymentBlockMatchCount: 0,
    deploymentBlockHashMatchCount: 0,
    runtimeCodeMatchCount: 0,
    immutableProvenanceContractCount: 0,
    immutableProvenanceValid: false,
    immutableProvenance: [],
    broadcastTransactionCount: 0,
    broadcastTransactionValidCount: 0,
    broadcastTransactionsSha256: "",
    broadcastTransactionProvenanceValid: false,
    broadcastTransactionProvenance: [],
    primaryBroadcastTransactionObservationsSha256: "",
    secondaryBroadcastTransactionObservationsSha256: "",
    broadcastTransactionRpcAgreement: false,
    independentReconstructionValid: false,
    independentReconstructionSha256: "",
    independentReconstructionRpcAgreement: false,
    secondaryRuntimeCodeMatchCount: 0,
    poststateMode,
    poststateContractCount: 0,
    poststateValid: false,
    poststates: [],
    primaryPoststateObservationsSha256: "",
    secondaryPoststateContractCount: 0,
    secondaryPoststateValid: false,
    secondaryPoststateObservationsSha256: "",
    poststateRpcAgreement: false,
  };
}

function parseJsonOutput(result) {
  if (result?.ok !== true) return null;
  try {
    return JSON.parse(String(result.stdout || ""));
  } catch {
    return null;
  }
}

function safeBlockNumber(value) {
  try {
    const parsed = typeof value === "number" ? BigInt(value) : BigInt(String(value));
    return parsed > 0n && parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : 0;
  } catch {
    return 0;
  }
}

function transactionInputSha256(value) {
  const normalized = clean(value).toLowerCase();
  if (!/^0x(?:[0-9a-f]{2})+$/.test(normalized)) return "";
  return `sha256:${createHash("sha256")
    .update(Buffer.from(normalized.slice(2), "hex"))
    .digest("hex")}`;
}

function normalizedRpcQuantity(value, { positive = false } = {}) {
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value)) return "";
    const parsed = BigInt(String(value));
    if (parsed < 0n || parsed >= (1n << 256n) || (positive && parsed === 0n)) return "";
    return `0x${parsed.toString(16)}`;
  } catch {
    return "";
  }
}

function canonicalRpcWeiBalance(result) {
  if (result?.ok !== true) return "";
  let value = clean(result.stdout).toLowerCase();
  if (/^"0x[0-9a-f]+"$/.test(value)) {
    try {
      value = JSON.parse(value);
    } catch {
      return "";
    }
  }
  if (!/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value)) return "";
  try {
    const parsed = BigInt(value);
    return parsed >= 0n && parsed < (1n << 256n)
      ? parsed.toString(10)
      : "";
  } catch {
    return "";
  }
}

function canonicalObservationValue(value) {
  if (Array.isArray(value)) return value.map(canonicalObservationValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalObservationValue(value[key])]),
  );
}

function observationSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(Buffer.from(`${domain}\0`, "utf8"))
    .update(Buffer.from(JSON.stringify(canonicalObservationValue(value)), "utf8"))
    .digest("hex")}`;
}

function normalizedConsensusBlockObservation(block) {
  const number = safeBlockNumber(block?.number);
  const normalizedBytes32 = (value) => {
    const normalized = clean(value).toLowerCase();
    return LOWER_BYTES32.test(normalized) && normalized !== ZERO_BYTES32
      ? normalized
      : "";
  };
  const observation = {
    number,
    hash: normalizedBytes32(block?.hash),
    parent_hash: normalizedBytes32(block?.parentHash),
    state_root: normalizedBytes32(block?.stateRoot),
    transactions_root: normalizedBytes32(block?.transactionsRoot),
    receipts_root: normalizedBytes32(block?.receiptsRoot),
  };
  return number > 0 && Object.entries(observation).every(([key, value]) => (
    key === "number" || Boolean(value)
  )) ? observation : null;
}

function consensusBlockObservationSha256(block) {
  const observation = normalizedConsensusBlockObservation(block);
  return observation
    ? observationSha256(
      "dnai-wikigen/activation-readiness-consensus-block-observation/v1",
      observation,
    )
    : "";
}

function normalizedTransactionObservation(transaction, transactionReceipt, canonicalBlock) {
  return {
    transaction_hash: clean(transaction?.hash).toLowerCase(),
    transaction_from: clean(transaction?.from).toLowerCase(),
    transaction_to: normalizedNullableAddress(transaction?.to),
    transaction_nonce: normalizedRpcQuantity(transaction?.nonce),
    transaction_value: normalizedRpcQuantity(transaction?.value),
    transaction_input_sha256: transactionInputSha256(
      transaction?.input ?? transaction?.data,
    ),
    transaction_gas_limit: normalizedRpcQuantity(
      transaction?.gas ?? transaction?.gasLimit,
      { positive: true },
    ),
    transaction_block_number: safeBlockNumber(transaction?.blockNumber),
    transaction_block_hash: clean(transaction?.blockHash).toLowerCase(),
    transaction_index: normalizedRpcQuantity(transaction?.transactionIndex),
    receipt_transaction_hash: clean(transactionReceipt?.transactionHash).toLowerCase(),
    receipt_from: clean(transactionReceipt?.from).toLowerCase(),
    receipt_to: normalizedNullableAddress(transactionReceipt?.to),
    receipt_contract_address: normalizedNullableAddress(
      transactionReceipt?.contractAddress,
    ),
    receipt_status: normalizedRpcQuantity(transactionReceipt?.status),
    receipt_gas_used: normalizedRpcQuantity(transactionReceipt?.gasUsed, {
      positive: true,
    }),
    receipt_cumulative_gas_used: normalizedRpcQuantity(
      transactionReceipt?.cumulativeGasUsed,
      { positive: true },
    ),
    receipt_block_number: safeBlockNumber(transactionReceipt?.blockNumber),
    receipt_block_hash: clean(transactionReceipt?.blockHash).toLowerCase(),
    receipt_transaction_index: normalizedRpcQuantity(
      transactionReceipt?.transactionIndex,
    ),
    canonical_block_number: safeBlockNumber(canonicalBlock?.number),
    canonical_block_hash: clean(canonicalBlock?.hash).toLowerCase(),
    canonical_block_header_sha256: consensusBlockObservationSha256(canonicalBlock),
  };
}

function normalizedLogIndex(value) {
  const normalized = normalizedRpcQuantity(value);
  return normalized || "";
}

function blockContainsTransaction(block, transactionHash) {
  if (!Array.isArray(block?.transactions)) return false;
  return block.transactions.some((entry) => (
    typeof entry === "string"
      ? clean(entry).toLowerCase() === transactionHash
      : clean(entry?.hash).toLowerCase() === transactionHash
  ));
}

export function collectExecutionPolicyReleaseMarkerEvidence({
  marker,
  contract,
  snapshotBlockNumber,
  rpcUrl,
  runner,
}) {
  const invalid = (details = {}) => ({
    valid: false,
    logCount: 0,
    transactionHash: "",
    blockNumber: 0,
    blockHash: "",
    transactionIndex: "",
    logIndex: "",
    eventTupleMatches: false,
    transactionMatches: false,
    receiptMatches: false,
    canonicalBlockMatches: false,
    ...details,
  });
  if (
    !marker
    || !contract
    || !Number.isSafeInteger(contract.deployment_block)
    || contract.deployment_block < 1
    || !Number.isSafeInteger(snapshotBlockNumber)
    || snapshotBlockNumber < contract.deployment_block
    || contract.address !== marker.contractAddress
  ) {
    return invalid();
  }
  let logsResult;
  try {
    logsResult = runner("cast", [
      "logs",
      EXECUTION_POLICY_DECISION_ANCHORED_EVENT,
      "1",
      marker.resourceHash,
      marker.decisionHash,
      "--from-block",
      String(contract.deployment_block),
      "--to-block",
      String(snapshotBlockNumber),
      "--address",
      marker.contractAddress,
      "--json",
      "--rpc-url",
      rpcUrl,
    ], { timeout: COMMAND_TIMEOUT_MS });
  } catch {
    return invalid();
  }
  const logs = parseJsonOutput(logsResult);
  if (!Array.isArray(logs) || logs.length !== 1) {
    return invalid({ logCount: Array.isArray(logs) ? logs.length : 0 });
  }
  const log = logs[0];
  const transactionHash = clean(log?.transactionHash).toLowerCase();
  const blockHash = clean(log?.blockHash).toLowerCase();
  const blockNumber = safeBlockNumber(log?.blockNumber);
  const transactionIndex = normalizedLogIndex(log?.transactionIndex);
  const logIndex = normalizedLogIndex(log?.logIndex);
  const topics = Array.isArray(log?.topics)
    ? log.topics.map((value) => clean(value).toLowerCase())
    : [];
  const eventTupleMatches = clean(log?.address).toLowerCase() === marker.contractAddress
    && log?.removed === false
    && transactionHash !== ZERO_BYTES32
    && LOWER_BYTES32.test(transactionHash)
    && LOWER_BYTES32.test(blockHash)
    && blockHash !== ZERO_BYTES32
    && blockNumber >= contract.deployment_block
    && blockNumber <= snapshotBlockNumber
    && transactionIndex !== ""
    && logIndex !== ""
    && JSON.stringify(topics) === JSON.stringify(marker.eventTopics)
    && clean(log?.data).toLowerCase() === marker.eventData;
  if (!eventTupleMatches) {
    return invalid({
      logCount: 1,
      transactionHash,
      blockNumber,
      blockHash,
      transactionIndex,
      logIndex,
    });
  }

  let transaction;
  let receipt;
  let canonicalBlock;
  try {
    transaction = parseJsonOutput(runner("cast", [
      "tx", transactionHash, "--json", "--rpc-url", rpcUrl,
    ], { timeout: COMMAND_TIMEOUT_MS }));
    receipt = parseJsonOutput(runner("cast", [
      "receipt", transactionHash, "--json", "--rpc-url", rpcUrl,
    ], { timeout: COMMAND_TIMEOUT_MS }));
    canonicalBlock = parseJsonOutput(runner("cast", [
      "block", String(blockNumber), "--json", "--rpc-url", rpcUrl,
    ], { timeout: COMMAND_TIMEOUT_MS }));
  } catch {
    return invalid({
      logCount: 1,
      transactionHash,
      blockNumber,
      blockHash,
      transactionIndex,
      logIndex,
      eventTupleMatches: true,
    });
  }
  const transactionMatches = clean(transaction?.hash).toLowerCase() === transactionHash
    && clean(transaction?.from).toLowerCase() === marker.writerAddress
    && clean(transaction?.to).toLowerCase() === marker.contractAddress
    && clean(transaction?.blockHash).toLowerCase() === blockHash
    && safeBlockNumber(transaction?.blockNumber) === blockNumber
    && normalizedLogIndex(transaction?.transactionIndex) === transactionIndex
    && normalizedRpcQuantity(transaction?.value) === "0x0"
    && clean(transaction?.input ?? transaction?.data).toLowerCase() === marker.calldata;
  const receiptMatches = clean(receipt?.transactionHash).toLowerCase()
      === transactionHash
    && clean(receipt?.from).toLowerCase() === marker.writerAddress
    && clean(receipt?.to).toLowerCase() === marker.contractAddress
    && receipt?.contractAddress === null
    && normalizedRpcQuantity(receipt?.status) === "0x1"
    && clean(receipt?.blockHash).toLowerCase() === blockHash
    && safeBlockNumber(receipt?.blockNumber) === blockNumber
    && normalizedLogIndex(receipt?.transactionIndex) === transactionIndex;
  const normalizedBlock = normalizedConsensusBlockObservation(canonicalBlock);
  const canonicalBlockMatches = Boolean(normalizedBlock)
    && normalizedBlock.number === blockNumber
    && normalizedBlock.hash === blockHash
    && blockContainsTransaction(canonicalBlock, transactionHash);
  return {
    valid: eventTupleMatches
      && transactionMatches
      && receiptMatches
      && canonicalBlockMatches,
    logCount: 1,
    transactionHash,
    blockNumber,
    blockHash,
    transactionIndex,
    logIndex,
    eventTupleMatches,
    transactionMatches,
    receiptMatches,
    canonicalBlockMatches,
  };
}

function normalizedNullableAddress(value) {
  if (value === null) return null;
  const normalized = clean(value).toLowerCase();
  return LOWER_ADDRESS.test(normalized) ? normalized : "";
}

function evaluateContractPoststates({
  mode,
  receipt,
  deploymentIntent,
  finalAuthority,
  finalAuthoritySha256,
  royaltyReleaseAuthority,
  snapshotBlockNumber,
  rpcUrl,
  runner,
}) {
  const expectedMap = CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE[mode] || {};
  const policies = mode === "fresh_fail_closed"
    ? freshPoststatePolicies(deploymentIntent, receipt)
    : mode === "royalty_phase_one_pending"
      ? royaltyPhaseOnePoststatePolicies(royaltyReleaseAuthority)
      : finalPoststatePolicies(
        finalAuthority,
        finalAuthoritySha256,
        royaltyReleaseAuthority,
      );
  const contracts = new Map(receipt.contracts.map((entry) => [entry.name, entry]));
  const observationsByContract = [];
  const poststates = Object.entries(expectedMap).map(([name, assertionNames]) => {
    const contract = contracts.get(name);
    const cache = new Map();
    const observations = [];
    const read = (signature, args = [], { json = false } = {}) => {
      const key = JSON.stringify([signature, args, json]);
      if (cache.has(key)) return cache.get(key);
      if (!contract || !LOWER_ADDRESS.test(contract.address)) {
        cache.set(key, null);
        return null;
      }
      const commandArgs = [
        "call",
        contract.address,
        signature,
        ...args,
        ...(json ? ["--json"] : []),
        "--block",
        String(snapshotBlockNumber),
        "--rpc-url",
        rpcUrl,
      ];
      let value = null;
      try {
        const result = runner("cast", commandArgs, { timeout: COMMAND_TIMEOUT_MS });
        if (result?.ok === true) {
          if (json) {
            value = parseJsonOutput(result);
          } else {
            const output = clean(result.stdout);
            value = output ? output.split(/\s+/)[0] : null;
          }
        }
      } catch {
        value = null;
      }
      cache.set(key, value);
      observations.push({
        signature,
        args: [...args],
        json,
        value: canonicalObservationValue(value),
      });
      return value;
    };
    read.releaseMarkerEvidence = (marker) => {
      const key = JSON.stringify(["execution_policy_release_marker", marker]);
      if (cache.has(key)) return cache.get(key);
      const value = collectExecutionPolicyReleaseMarkerEvidence({
        marker,
        contract,
        snapshotBlockNumber,
        rpcUrl,
        runner,
      });
      cache.set(key, value);
      observations.push({
        signature: "DecisionAnchored+transaction+receipt+canonicalBlock",
        args: [marker?.resourceHash || "", marker?.decisionHash || ""],
        json: true,
        value: canonicalObservationValue(value),
      });
      return value;
    };
    const policy = policies[name] || {};
    const royaltyAddressMatches = name !== "RoyaltyDistributor"
      || mode === "fresh_fail_closed"
      || normalizedRoyaltyAuthority(royaltyReleaseAuthority)
        ?.distributor_address === contract?.address;
    const valid = Boolean(contract)
      && royaltyAddressMatches
      && assertionNames.every((assertionName) => {
        const assertion = policy[assertionName];
        if (typeof assertion !== "function") return false;
        try {
          return assertion(read) === true;
        } catch {
          return false;
        }
      });
    observationsByContract.push({ name, reads: observations });
    return { name, valid, assertions: [...assertionNames] };
  });
  return {
    poststates,
    poststateContractCount: poststates.length,
    poststateValid: poststates.length === Object.keys(expectedMap).length
      && poststates.length > 0
      && poststates.every((entry) => entry.valid),
    observationSha256: observationSha256(
      "dnai-wikigen/activation-readiness-poststate-observations/v1",
      observationsByContract,
    ),
  };
}

function verifyContractDeploymentChainEvidenceInternal({
  contractDeploymentReceipt,
  deploymentIntent,
  deploymentIntentText = "",
  deploymentIntentSha256 = "",
  expectedTinkerAccountBindingCeremonyReceiptSha256 = "",
  releaseSha = "",
  releaseWorktree = rootDir,
  reconstructionCommandRunner,
  secondaryReconstructionCommandRunner,
  independentReconstruction = null,
  secondaryIndependentReconstruction = null,
  finalAuthority,
  finalAuthoritySha256 = "",
  royaltyReleaseAuthority = null,
  authorityStage,
  rpcUrl,
  secondaryRpcUrl,
  skipNetwork = false,
  castAvailable = true,
  runner = runReadOnly,
  evidenceSource = "production_collector",
} = {}) {
  const poststateMode = authorityStage === "live_activation"
    ? "final_active_frozen"
    : new Set(["cvm_launch", "release_ceremony"]).has(authorityStage)
      ? "fresh_fail_closed"
      : "";
  let rpcEndpointSha256 = "";
  let secondaryRpcEndpointSha256 = "";
  let rpcOriginSha256 = "";
  let secondaryRpcOriginSha256 = "";
  let rpcOrigin = "";
  let secondaryRpcOrigin = "";
  let rpcSchemesValid = false;
  try {
    rpcEndpointSha256 = activationReadinessRpcEndpointDigest(rpcUrl);
    secondaryRpcEndpointSha256 = activationReadinessRpcEndpointDigest(
      secondaryRpcUrl,
    );
    const primaryEndpoint = new URL(clean(rpcUrl));
    const secondaryEndpoint = new URL(clean(secondaryRpcUrl));
    rpcOrigin = primaryEndpoint.origin.toLowerCase();
    secondaryRpcOrigin = secondaryEndpoint.origin.toLowerCase();
    rpcSchemesValid = primaryEndpoint.protocol === "https:"
      && secondaryEndpoint.protocol === "https:"
      && !primaryEndpoint.username
      && !primaryEndpoint.password
      && !primaryEndpoint.hash
      && !secondaryEndpoint.username
      && !secondaryEndpoint.password
      && !secondaryEndpoint.hash;
    if (rpcSchemesValid) {
      rpcOriginSha256 = activationReadinessRpcOriginDigest(rpcOrigin);
      secondaryRpcOriginSha256 = activationReadinessRpcOriginDigest(
        secondaryRpcOrigin,
      );
    }
  } catch {
    rpcEndpointSha256 = "";
    secondaryRpcEndpointSha256 = "";
    rpcOrigin = "";
    secondaryRpcOrigin = "";
    rpcOriginSha256 = "";
    secondaryRpcOriginSha256 = "";
    rpcSchemesValid = false;
  }
  const rpcEndpointsDistinct = Boolean(rpcEndpointSha256)
    && Boolean(secondaryRpcEndpointSha256)
    && rpcEndpointSha256 !== secondaryRpcEndpointSha256
    && rpcSchemesValid
    && Boolean(rpcOrigin)
    && Boolean(secondaryRpcOrigin)
    && rpcOrigin !== secondaryRpcOrigin;
  const empty = emptyContractDeploymentChainEvidence(
    poststateMode,
    rpcEndpointSha256,
    secondaryRpcEndpointSha256,
    rpcOriginSha256,
    secondaryRpcOriginSha256,
    evidenceSource,
  );
  if (!poststateMode
    || skipNetwork
    || !castAvailable
    || !clean(rpcUrl)
    || !clean(secondaryRpcUrl)
    || !rpcEndpointsDistinct) return empty;

  let receipt;
  try {
    receipt = normalizeFreshContractDeploymentReceipt(contractDeploymentReceipt, {
      expectedDeploymentIntentSha256: clean(deploymentIntentSha256).toLowerCase(),
      expectedReviewerAuthorityGenesisAcceptanceSha256: clean(
        deploymentIntent?.release?.reviewerAuthorityGenesisAcceptanceSha256,
      ).toLowerCase(),
      expectedTinkerAccountBindingCeremonyReceiptSha256: clean(
        expectedTinkerAccountBindingCeremonyReceiptSha256,
      ).toLowerCase(),
    });
  } catch {
    return empty;
  }

  const runCastAt = (endpoint, args) => {
    try {
      return runner(
        "cast",
        [...args, "--rpc-url", endpoint],
        { timeout: COMMAND_TIMEOUT_MS },
      );
    } catch {
      return { ok: false, stdout: "" };
    }
  };
  const runCast = (args) => runCastAt(rpcUrl, args);
  const runSecondaryCast = (args) => runCastAt(secondaryRpcUrl, args);
  const chainProbe = runCast(["chain-id"]);
  const secondaryChainProbe = runSecondaryCast(["chain-id"]);
  const chainId = chainProbe.ok ? Number(clean(chainProbe.stdout)) : 0;
  const secondaryChainId = secondaryChainProbe.ok
    ? Number(clean(secondaryChainProbe.stdout))
    : 0;
  const primaryFinalizedHead = parseJsonOutput(runCast([
    "block", "finalized", "--json",
  ]));
  const secondaryFinalizedHead = parseJsonOutput(runSecondaryCast([
    "block", "finalized", "--json",
  ]));
  const primaryFinalizedNumber = safeBlockNumber(primaryFinalizedHead?.number);
  const secondaryFinalizedNumber = safeBlockNumber(secondaryFinalizedHead?.number);
  const primaryFinalizedObservation = normalizedConsensusBlockObservation(
    primaryFinalizedHead,
  );
  const secondaryFinalizedObservation = normalizedConsensusBlockObservation(
    secondaryFinalizedHead,
  );
  const snapshotBlockNumber = primaryFinalizedNumber > 0
    && secondaryFinalizedNumber > 0
    ? Math.min(primaryFinalizedNumber, secondaryFinalizedNumber)
    : 0;
  const snapshotBlock = parseJsonOutput(runCast([
    "block", String(snapshotBlockNumber), "--json",
  ]));
  const secondarySnapshotBlock = parseJsonOutput(runSecondaryCast([
    "block", String(snapshotBlockNumber), "--json",
  ]));
  const snapshotBlockHash = clean(snapshotBlock?.hash).toLowerCase();
  const snapshotBlockObservation = normalizedConsensusBlockObservation(snapshotBlock);
  const secondarySnapshotBlockObservation = normalizedConsensusBlockObservation(
    secondarySnapshotBlock,
  );
  const initialSnapshotBlockHashVerified = snapshotBlockNumber > 0
    && primaryFinalizedObservation?.number === primaryFinalizedNumber
    && secondaryFinalizedObservation?.number === secondaryFinalizedNumber
    && snapshotBlockObservation?.number === snapshotBlockNumber
    && secondarySnapshotBlockObservation?.number === snapshotBlockNumber
    && snapshotBlockObservation?.hash === snapshotBlockHash
    && secondarySnapshotBlockObservation?.hash === snapshotBlockHash
    && JSON.stringify(snapshotBlockObservation)
      === JSON.stringify(secondarySnapshotBlockObservation)
    && (primaryFinalizedNumber !== snapshotBlockNumber
      || JSON.stringify(primaryFinalizedObservation)
        === JSON.stringify(snapshotBlockObservation))
    && (secondaryFinalizedNumber !== snapshotBlockNumber
      || JSON.stringify(secondaryFinalizedObservation)
        === JSON.stringify(snapshotBlockObservation));
  const secondaryFinalizedSnapshotVerified = initialSnapshotBlockHashVerified
    && secondaryFinalizedNumber >= snapshotBlockNumber;
  if (chainId !== 84_532
    || secondaryChainId !== 84_532
    || !secondaryFinalizedSnapshotVerified) {
    return {
      ...empty,
      chainId,
      secondaryChainId,
      rpcEndpointsDistinct,
      secondaryFinalizedSnapshotVerified,
      snapshotBlockNumber,
      snapshotBlockHash: LOWER_BYTES32.test(snapshotBlockHash) ? snapshotBlockHash : "",
      snapshotFinality: "rpc_finalized",
    };
  }

  const anchorWriterGasRequired = new Set([
    "release_ceremony",
    "live_activation",
  ]).has(authorityStage);
  let anchorWriterGasReadiness = null;
  if (anchorWriterGasRequired) {
    const anchor = finalAuthority?.execution_policy?.rollback_anchor_target;
    const policy = anchor?.writer_gas_reserve_policy;
    const writerAddress = clean(anchor?.writer_address).toLowerCase();
    const blockTag = `0x${snapshotBlockNumber.toString(16)}`;
    const primaryBalanceWei = canonicalRpcWeiBalance(runCast([
      "rpc",
      "eth_getBalance",
      writerAddress,
      blockTag,
    ]));
    const secondaryBalanceWei = canonicalRpcWeiBalance(runSecondaryCast([
      "rpc",
      "eth_getBalance",
      writerAddress,
      blockTag,
    ]));
    const observationDigest = (balanceWei) => {
      try {
        return activationReadinessAnchorWriterGasObservationDigest({
          rpc_method: "eth_getBalance",
          writer_address: writerAddress,
          balance_wei: balanceWei,
          block_number: snapshotBlockNumber,
          block_hash: snapshotBlockHash,
        });
      } catch {
        return "";
      }
    };
    const primaryObservationSha256 = observationDigest(primaryBalanceWei);
    const secondaryObservationSha256 = observationDigest(secondaryBalanceWei);
    const dualRpcAgreement = Boolean(primaryBalanceWei)
      && primaryBalanceWei === secondaryBalanceWei
      && Boolean(primaryObservationSha256)
      && primaryObservationSha256 === secondaryObservationSha256;
    let policyValid = false;
    let reserveSatisfied = false;
    try {
      const expectedPolicy = EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY;
      const computedMinimum = (
        BigInt(policy.release_marker_transaction_count
          + policy.expected_subsequent_anchor_count)
        * BigInt(policy.maximum_gas_per_transaction)
        * BigInt(policy.reviewed_max_fee_per_gas_wei)
      ).toString(10);
      policyValid = anchor.schema === "dnai.execution-policy-rollback-anchor.v2"
        && anchor.writer_custody
          === "dstack_derived_execution_policy_anchor_writer"
        && anchor.writer_key_path === "tinker/execution_policy_anchor_writer"
        && JSON.stringify(policy) === JSON.stringify(expectedPolicy)
        && computedMinimum === policy.minimum_reserve_wei;
      reserveSatisfied = policyValid
        && dualRpcAgreement
        && BigInt(primaryBalanceWei) >= BigInt(policy.minimum_reserve_wei);
    } catch {
      policyValid = false;
      reserveSatisfied = false;
    }
    anchorWriterGasReadiness = {
      schema: ACTIVATION_READINESS_ANCHOR_WRITER_GAS_SCHEMA,
      rpc_method: "eth_getBalance",
      writer_address: writerAddress,
      primary_balance_wei: primaryBalanceWei,
      secondary_balance_wei: secondaryBalanceWei,
      canonical_balance_wei: dualRpcAgreement ? primaryBalanceWei : "",
      minimum_reserve_wei: clean(policy?.minimum_reserve_wei),
      release_marker_transaction_count:
        policy?.release_marker_transaction_count ?? 0,
      expected_subsequent_anchor_count:
        policy?.expected_subsequent_anchor_count ?? 0,
      maximum_gas_per_transaction:
        policy?.maximum_gas_per_transaction ?? 0,
      reviewed_max_fee_per_gas_wei:
        clean(policy?.reviewed_max_fee_per_gas_wei),
      balance_block_number: snapshotBlockNumber,
      balance_block_hash: snapshotBlockHash,
      primary_observation_sha256: primaryObservationSha256,
      secondary_observation_sha256: secondaryObservationSha256,
      dual_rpc_agreement: dualRpcAgreement,
      reserve_satisfied: reserveSatisfied,
      readiness_claim: ACTIVATION_READINESS_ANCHOR_WRITER_GAS_CLAIM,
    };
  }

  const collectReconstruction = ({ supplied, endpoint, commandRunner }) => {
    try {
      const reconstruction = normalizeFreshContractReleaseReconstruction(
        supplied || reconstructFreshContractRelease({
          releaseWorktree,
          expectedReleaseSha: clean(releaseSha).toLowerCase(),
          deploymentIntentText,
          rpcUrl: endpoint,
          snapshotBlock: snapshotBlockNumber,
          snapshotBlockHash,
          ...(commandRunner ? { commandRunner } : {}),
        }),
      );
      return {
        valid: true,
        reconstruction,
        sha256: reconstruction.reconstruction_sha256,
      };
    } catch {
      return { valid: false, reconstruction: null, sha256: "" };
    }
  };
  const reconstructionResult = collectReconstruction({
    supplied: independentReconstruction,
    endpoint: rpcUrl,
    commandRunner: reconstructionCommandRunner,
  });
  const secondaryReconstructionResult = collectReconstruction({
    supplied: secondaryIndependentReconstruction,
    endpoint: secondaryRpcUrl,
    commandRunner: secondaryReconstructionCommandRunner,
  });
  const reconstruction = reconstructionResult.reconstruction;
  const secondaryReconstruction = secondaryReconstructionResult.reconstruction;
  const reconstructionMatchesAuthority = (candidate) => Boolean(candidate)
    && candidate.release_sha === clean(releaseSha).toLowerCase()
    && candidate.deployment_intent_sha256
      === clean(deploymentIntentSha256).toLowerCase()
    && candidate.operator_address
      === clean(deploymentIntent?.deploymentControl?.operatorAddress).toLowerCase()
    && candidate.network.snapshot_block === snapshotBlockNumber
    && candidate.network.snapshot_block_hash === snapshotBlockHash
    && receipt.operator_address === candidate.operator_address;
  const independentReconstructionRpcAgreement = reconstructionResult.valid === true
    && secondaryReconstructionResult.valid === true
    && reconstructionResult.sha256 === secondaryReconstructionResult.sha256;
  const independentReconstructionValid = independentReconstructionRpcAgreement
    && reconstructionMatchesAuthority(reconstruction)
    && reconstructionMatchesAuthority(secondaryReconstruction);
  if (!independentReconstructionValid) {
    return {
      ...empty,
      chainId,
      secondaryChainId,
      rpcEndpointsDistinct,
      secondaryFinalizedSnapshotVerified,
      snapshotBlockNumber,
      snapshotBlockHash,
      snapshotFinality: "rpc_finalized",
      snapshotBlockHashVerified: false,
      independentReconstructionValid: false,
      independentReconstructionSha256: reconstructionResult.sha256,
      independentReconstructionRpcAgreement,
    };
  }

  const primaryBlockCache = new Map([[snapshotBlockNumber, snapshotBlock]]);
  const secondaryBlockCache = new Map([[snapshotBlockNumber, secondarySnapshotBlock]]);
  const blockAt = (number, cache, providerRun) => {
    if (cache.has(number)) return cache.get(number);
    const value = parseJsonOutput(providerRun([
      "block",
      String(number),
      "--json",
    ]));
    cache.set(number, value);
    return value;
  };
  const primaryBlockAt = (number) => blockAt(number, primaryBlockCache, runCast);
  const secondaryBlockAt = (number) => blockAt(
    number,
    secondaryBlockCache,
    runSecondaryCast,
  );

  const broadcastObservations = receipt.broadcast_transactions.map((expected, index) => {
    const independentlyExpected = reconstruction.transactions[index];
    const transaction = parseJsonOutput(runCast([
      "tx",
      expected.transaction_hash,
      "--json",
    ]));
    const transactionReceipt = parseJsonOutput(runCast([
      "receipt",
      expected.transaction_hash,
      "--json",
    ]));
    const secondaryTransaction = parseJsonOutput(runSecondaryCast([
      "tx",
      expected.transaction_hash,
      "--json",
    ]));
    const secondaryTransactionReceipt = parseJsonOutput(runSecondaryCast([
      "receipt",
      expected.transaction_hash,
      "--json",
    ]));
    const block = primaryBlockAt(expected.block_number);
    const secondaryBlock = secondaryBlockAt(expected.block_number);
    const primaryObservation = normalizedTransactionObservation(
      transaction,
      transactionReceipt,
      block,
    );
    const secondaryObservation = normalizedTransactionObservation(
      secondaryTransaction,
      secondaryTransactionReceipt,
      secondaryBlock,
    );
    const expectedTo = expected.transaction_to;
    const expectedReceiptContractAddress = expected.receipt_contract_address;
    const receiptGasValid = Boolean(primaryObservation.receipt_gas_used)
      && Boolean(primaryObservation.receipt_cumulative_gas_used)
      && BigInt(primaryObservation.receipt_cumulative_gas_used)
        >= BigInt(primaryObservation.receipt_gas_used);
    const secondaryReceiptGasValid = Boolean(secondaryObservation.receipt_gas_used)
      && Boolean(secondaryObservation.receipt_cumulative_gas_used)
      && BigInt(secondaryObservation.receipt_cumulative_gas_used)
        >= BigInt(secondaryObservation.receipt_gas_used);
    const provenance = {
      sequence: expected.sequence,
      contractKey: expected.contract_key,
      transactionType: expected.transaction_type,
      transactionFound: primaryObservation.transaction_hash
        === expected.transaction_hash,
      senderMatches: primaryObservation.transaction_from
        === expected.transaction_from,
      targetMatches: primaryObservation.transaction_to === expectedTo,
      nonceMatches: primaryObservation.transaction_nonce
        === normalizedRpcQuantity(expected.transaction_nonce),
      valueZero: primaryObservation.transaction_value === "0x0",
      inputMatches: primaryObservation.transaction_input_sha256
        === independentlyExpected.expected_input_sha256
        && expected.transaction_input_sha256
          === independentlyExpected.expected_input_sha256,
      gasLimitValid: Boolean(primaryObservation.transaction_gas_limit),
      transactionIndexValid: Boolean(primaryObservation.transaction_index),
      receiptFound: primaryObservation.receipt_transaction_hash
        === expected.transaction_hash,
      receiptSuccessful: primaryObservation.receipt_status === "0x1",
      receiptSenderMatches: primaryObservation.receipt_from
        === expected.transaction_from,
      receiptTargetMatches: primaryObservation.receipt_to === expectedTo,
      receiptContractAddressMatches:
        primaryObservation.receipt_contract_address === expectedReceiptContractAddress,
      receiptGasValid,
      receiptTransactionIndexMatches:
        primaryObservation.receipt_transaction_index
          === primaryObservation.transaction_index,
      blockMatches: primaryObservation.transaction_block_number
        === expected.block_number
        && primaryObservation.receipt_block_number === expected.block_number
        && primaryObservation.canonical_block_number === expected.block_number
        && expected.block_number <= snapshotBlockNumber,
      blockHashMatches:
        Boolean(primaryObservation.canonical_block_header_sha256)
        && primaryObservation.canonical_block_hash === expected.block_hash
        && primaryObservation.transaction_block_hash === expected.block_hash
        && primaryObservation.receipt_block_hash === expected.block_hash,
      secondaryTransactionFound:
        secondaryObservation.transaction_hash === expected.transaction_hash,
      secondarySenderMatches:
        secondaryObservation.transaction_from === expected.transaction_from,
      secondaryTargetMatches: secondaryObservation.transaction_to === expectedTo,
      secondaryNonceMatches:
        secondaryObservation.transaction_nonce === primaryObservation.transaction_nonce,
      secondaryValueMatches:
        secondaryObservation.transaction_value === "0x0"
        && secondaryObservation.transaction_value
          === primaryObservation.transaction_value,
      secondaryInputMatches:
        secondaryObservation.transaction_input_sha256
          === independentlyExpected.expected_input_sha256
        && secondaryObservation.transaction_input_sha256
          === primaryObservation.transaction_input_sha256,
      secondaryGasLimitMatches:
        Boolean(secondaryObservation.transaction_gas_limit)
        && secondaryObservation.transaction_gas_limit
          === primaryObservation.transaction_gas_limit,
      secondaryTransactionIndexMatches:
        Boolean(secondaryObservation.transaction_index)
        && secondaryObservation.transaction_index
          === primaryObservation.transaction_index,
      secondaryReceiptFound:
        secondaryObservation.receipt_transaction_hash === expected.transaction_hash,
      secondaryReceiptSuccessful: secondaryObservation.receipt_status === "0x1",
      secondaryReceiptSenderMatches:
        secondaryObservation.receipt_from === expected.transaction_from,
      secondaryReceiptTargetMatches:
        secondaryObservation.receipt_to === expectedTo,
      secondaryReceiptContractAddressMatches:
        secondaryObservation.receipt_contract_address
          === expectedReceiptContractAddress,
      secondaryReceiptGasMatches:
        secondaryReceiptGasValid
        && secondaryObservation.receipt_gas_used
          === primaryObservation.receipt_gas_used
        && secondaryObservation.receipt_cumulative_gas_used
          === primaryObservation.receipt_cumulative_gas_used,
      secondaryReceiptTransactionIndexMatches:
        secondaryObservation.receipt_transaction_index
          === secondaryObservation.transaction_index
        && secondaryObservation.receipt_transaction_index
          === primaryObservation.receipt_transaction_index,
      secondaryBlockMatches:
        secondaryObservation.transaction_block_number === expected.block_number
        && secondaryObservation.receipt_block_number === expected.block_number
        && secondaryObservation.canonical_block_number === expected.block_number
        && secondaryObservation.transaction_block_number
          === primaryObservation.transaction_block_number,
      secondaryBlockHashMatches:
        Boolean(secondaryObservation.canonical_block_header_sha256)
        && secondaryObservation.canonical_block_header_sha256
          === primaryObservation.canonical_block_header_sha256
        && secondaryObservation.canonical_block_hash === expected.block_hash
        && secondaryObservation.transaction_block_hash === expected.block_hash
        && secondaryObservation.receipt_block_hash === expected.block_hash
        && secondaryObservation.canonical_block_hash
          === primaryObservation.canonical_block_hash,
      providerObservationsMatch:
        JSON.stringify(secondaryObservation) === JSON.stringify(primaryObservation),
    };
    return {
      expected,
      transaction,
      transactionReceipt,
      secondaryTransaction,
      secondaryTransactionReceipt,
      primaryObservation,
      secondaryObservation,
      provenance,
    };
  });
  const broadcastTransactionProvenance = broadcastObservations.map(
    ({ provenance }) => provenance,
  );
  const broadcastTransactionValidCount = broadcastTransactionProvenance.filter(
    (entry) => BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS.every(
      (field) => entry[field] === true,
    ),
  ).length;
  const broadcastTransactionProvenanceValid =
    broadcastTransactionProvenance.length === receipt.broadcast_transactions.length
    && broadcastTransactionValidCount === receipt.broadcast_transactions.length;
  const primaryBroadcastTransactionObservationsSha256 = observationSha256(
    "dnai-wikigen/activation-readiness-broadcast-observations/v2",
    broadcastObservations.map(({ primaryObservation }) => primaryObservation),
  );
  const secondaryBroadcastTransactionObservationsSha256 = observationSha256(
    "dnai-wikigen/activation-readiness-broadcast-observations/v2",
    broadcastObservations.map(({ secondaryObservation }) => secondaryObservation),
  );
  const broadcastTransactionRpcAgreement = broadcastTransactionProvenanceValid
    && primaryBroadcastTransactionObservationsSha256
      === secondaryBroadcastTransactionObservationsSha256;
  const broadcastObservationByHash = new Map(broadcastObservations.map((entry) => [
    entry.expected.transaction_hash,
    entry,
  ]));

  let secondaryRuntimeCodeMatchCount = 0;
  const immutableProvenance = receipt.contracts.map((contract) => {
    const observation = broadcastObservationByHash.get(contract.deployment_tx_hash);
    const transaction = observation?.transaction;
    const transactionReceipt = observation?.transactionReceipt;
    const broadcast = observation?.provenance;
    const liveCodeHashProbe = runCast([
      "codehash",
      contract.address,
      "--block",
      String(snapshotBlockNumber),
    ]);
    const liveCodeHash = liveCodeHashProbe.ok
      ? clean(liveCodeHashProbe.stdout).toLowerCase()
      : "";
    const secondaryLiveCodeHashProbe = runSecondaryCast([
      "codehash",
      contract.address,
      "--block",
      String(snapshotBlockNumber),
    ]);
    const secondaryLiveCodeHash = secondaryLiveCodeHashProbe.ok
      ? clean(secondaryLiveCodeHashProbe.stdout).toLowerCase()
      : "";
    const block = primaryBlockAt(contract.deployment_block);
    const transactionFound = broadcast?.transactionFound === true;
    const receiptFound = broadcast?.receiptFound === true;
    const deployerMatches = broadcast?.senderMatches === true
      && broadcast?.receiptSenderMatches === true;
    const creationTransaction = observation?.expected.transaction_type === "CREATE"
      && broadcast?.targetMatches === true
      && broadcast?.receiptTargetMatches === true;
    const receiptSuccessful = broadcast?.receiptSuccessful === true;
    const contractAddressMatches = broadcast?.receiptContractAddressMatches === true;
    const deploymentBlockMatches = broadcast?.blockMatches === true
      && observation?.expected.block_number === contract.deployment_block;
    const actualDeploymentBlockHash = clean(block?.hash).toLowerCase();
    const deploymentBlockHashMatches = broadcast?.blockHashMatches === true
      && actualDeploymentBlockHash === contract.deployment_block_hash
      && observation?.expected.block_hash === contract.deployment_block_hash;
    const reconstructedContract = reconstruction.transactions.find(
      (entry) => entry.contract_name === contract.name
        && entry.transaction_type === "CREATE",
    );
    const runtimeCodeMatches = Boolean(reconstructedContract)
      && liveCodeHash === reconstructedContract.expected_runtime_code_hash
      && contract.runtime_code_hash === reconstructedContract.expected_runtime_code_hash;
    const secondaryRuntimeCodeMatches = Boolean(reconstructedContract)
      && secondaryLiveCodeHash === reconstructedContract.expected_runtime_code_hash
      && secondaryLiveCodeHash === liveCodeHash;
    if (secondaryRuntimeCodeMatches) secondaryRuntimeCodeMatchCount += 1;
    return {
      name: contract.name,
      transactionFound,
      deployerMatches,
      creationTransaction,
      receiptFound,
      receiptSuccessful,
      contractAddressMatches,
      deploymentBlockMatches,
      deploymentBlockHashMatches,
      runtimeCodeMatches,
    };
  });

  const count = (field) => immutableProvenance.filter((entry) => entry[field] === true).length;
  const immutableProvenanceContractCount = immutableProvenance.filter((entry) => (
    CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS.every((field) => entry[field] === true)
  )).length;
  const immutableProvenanceValid = immutableProvenance.length === 7
    && immutableProvenanceContractCount === 7;
  const poststate = evaluateContractPoststates({
    mode: poststateMode,
    receipt,
    deploymentIntent,
    finalAuthority,
    finalAuthoritySha256,
    royaltyReleaseAuthority,
    snapshotBlockNumber,
    rpcUrl,
    runner,
  });
  const secondaryPoststate = evaluateContractPoststates({
    mode: poststateMode,
    receipt,
    deploymentIntent,
    finalAuthority,
    finalAuthoritySha256,
    royaltyReleaseAuthority,
    snapshotBlockNumber,
    rpcUrl: secondaryRpcUrl,
    runner,
  });
  const poststateRpcAgreement = poststate.poststateValid
    && secondaryPoststate.poststateValid
    && poststate.poststateContractCount === secondaryPoststate.poststateContractCount
    && poststate.observationSha256 === secondaryPoststate.observationSha256
    && JSON.stringify(poststate.poststates) === JSON.stringify(secondaryPoststate.poststates);
  const finalSnapshotBlock = parseJsonOutput(runCast([
    "block",
    String(snapshotBlockNumber),
    "--json",
  ]));
  const secondaryFinalSnapshotBlock = parseJsonOutput(runSecondaryCast([
    "block",
    String(snapshotBlockNumber),
    "--json",
  ]));
  const finalSnapshotBlockObservation = normalizedConsensusBlockObservation(
    finalSnapshotBlock,
  );
  const secondaryFinalSnapshotBlockObservation = normalizedConsensusBlockObservation(
    secondaryFinalSnapshotBlock,
  );
  const canonicalSnapshotObservation = JSON.stringify(snapshotBlockObservation);
  const commonSnapshotBlock = Boolean(snapshotBlockObservation)
    && canonicalSnapshotObservation === JSON.stringify(secondarySnapshotBlockObservation)
    && canonicalSnapshotObservation === JSON.stringify(finalSnapshotBlockObservation)
    && canonicalSnapshotObservation
      === JSON.stringify(secondaryFinalSnapshotBlockObservation);
  const finalizedRecheckBlock = parseJsonOutput(runCast([
    "block",
    "finalized",
    "--json",
  ]));
  const finalizedRecheckBlockNumber = safeBlockNumber(finalizedRecheckBlock?.number);
  const finalizedRecheckBlockHash = clean(finalizedRecheckBlock?.hash).toLowerCase();
  const finalizedRecheckBlockObservation = normalizedConsensusBlockObservation(
    finalizedRecheckBlock,
  );
  const finalizedTagRechecked = finalizedRecheckBlockNumber >= snapshotBlockNumber
    && finalizedRecheckBlockObservation?.number === finalizedRecheckBlockNumber
    && finalizedRecheckBlockObservation?.hash === finalizedRecheckBlockHash
    && (finalizedRecheckBlockNumber !== snapshotBlockNumber
      || JSON.stringify(finalizedRecheckBlockObservation)
        === canonicalSnapshotObservation);
  const secondaryFinalizedRecheckBlock = parseJsonOutput(runSecondaryCast([
    "block",
    "finalized",
    "--json",
  ]));
  const secondaryFinalizedRecheckBlockNumber = safeBlockNumber(
    secondaryFinalizedRecheckBlock?.number,
  );
  const secondaryFinalizedRecheckBlockHash = clean(
    secondaryFinalizedRecheckBlock?.hash,
  ).toLowerCase();
  const secondaryFinalizedRecheckBlockObservation = normalizedConsensusBlockObservation(
    secondaryFinalizedRecheckBlock,
  );
  const secondaryFinalizedTagRechecked =
    secondaryFinalizedRecheckBlockNumber >= snapshotBlockNumber
    && secondaryFinalizedRecheckBlockObservation?.number
      === secondaryFinalizedRecheckBlockNumber
    && secondaryFinalizedRecheckBlockObservation?.hash
      === secondaryFinalizedRecheckBlockHash
    && (secondaryFinalizedRecheckBlockNumber !== snapshotBlockNumber
      || JSON.stringify(secondaryFinalizedRecheckBlockObservation)
        === canonicalSnapshotObservation);
  const snapshotBlockHashVerified = initialSnapshotBlockHashVerified
    && commonSnapshotBlock
    && finalizedTagRechecked
    && secondaryFinalizedTagRechecked;
  const anchorWriterGasValid = !anchorWriterGasRequired || (
    anchorWriterGasReadiness?.dual_rpc_agreement === true
    && anchorWriterGasReadiness?.reserve_satisfied === true
  );
  const valid = immutableProvenanceValid
    && broadcastTransactionProvenanceValid
    && broadcastTransactionRpcAgreement
    && independentReconstructionValid
    && independentReconstructionRpcAgreement
    && secondaryRuntimeCodeMatchCount === receipt.contracts.length
    && poststateRpcAgreement
    && snapshotBlockHashVerified
    && anchorWriterGasValid;
  return {
    evidenceSource,
    valid,
    readOnly: true,
    chainId,
    secondaryChainId,
    rpcEndpointSha256,
    secondaryRpcEndpointSha256,
    rpcOriginSha256,
    secondaryRpcOriginSha256,
    rpcEndpointsDistinct,
    secondaryFinalizedSnapshotVerified,
    secondaryFinalizedTagRechecked,
    snapshotBlockNumber,
    snapshotBlockHash,
    snapshotFinality: "rpc_finalized",
    finalizedTagRechecked,
    finalizedRecheckBlockNumber,
    finalizedRecheckBlockHash:
      LOWER_BYTES32.test(finalizedRecheckBlockHash) ? finalizedRecheckBlockHash : "",
    snapshotBlockHashVerified,
    commonSnapshotBlock,
    anchorWriterGasReadiness,
    contractCount: receipt.contracts.length,
    transactionCount: count("transactionFound"),
    deployerMatchCount: count("deployerMatches"),
    creationTransactionCount: count("creationTransaction"),
    receiptCount: count("receiptFound"),
    successfulReceiptCount: count("receiptSuccessful"),
    contractAddressMatchCount: count("contractAddressMatches"),
    deploymentBlockMatchCount: count("deploymentBlockMatches"),
    deploymentBlockHashMatchCount: count("deploymentBlockHashMatches"),
    runtimeCodeMatchCount: count("runtimeCodeMatches"),
    immutableProvenanceContractCount,
    immutableProvenanceValid,
    immutableProvenance,
    broadcastTransactionCount: receipt.broadcast_transactions.length,
    broadcastTransactionValidCount,
    broadcastTransactionsSha256: receipt.broadcast_transactions_sha256,
    broadcastTransactionProvenanceValid,
    broadcastTransactionProvenance,
    primaryBroadcastTransactionObservationsSha256,
    secondaryBroadcastTransactionObservationsSha256,
    broadcastTransactionRpcAgreement,
    independentReconstructionValid,
    independentReconstructionSha256: reconstructionResult.sha256,
    independentReconstructionRpcAgreement,
    secondaryRuntimeCodeMatchCount,
    poststateMode,
    poststateContractCount: poststate.poststateContractCount,
    poststateValid: poststate.poststateValid,
    poststates: poststate.poststates,
    primaryPoststateObservationsSha256: poststate.observationSha256,
    secondaryPoststateContractCount: secondaryPoststate.poststateContractCount,
    secondaryPoststateValid: secondaryPoststate.poststateValid,
    secondaryPoststateObservationsSha256: secondaryPoststate.observationSha256,
    poststateRpcAgreement,
  };
}

export function verifyContractDeploymentChainEvidence(options = {}) {
  return verifyContractDeploymentChainEvidenceInternal({
    contractDeploymentReceipt: options.contractDeploymentReceipt,
    deploymentIntent: options.deploymentIntent,
    deploymentIntentText: options.deploymentIntentText,
    deploymentIntentSha256: options.deploymentIntentSha256,
    expectedTinkerAccountBindingCeremonyReceiptSha256:
      options.expectedTinkerAccountBindingCeremonyReceiptSha256,
    releaseSha: options.releaseSha,
    releaseWorktree: rootDir,
    finalAuthority: options.finalAuthority,
    finalAuthoritySha256: options.finalAuthoritySha256,
    royaltyReleaseAuthority: options.royaltyReleaseAuthority,
    authorityStage: options.authorityStage,
    rpcUrl: options.rpcUrl,
    secondaryRpcUrl: options.secondaryRpcUrl,
    skipNetwork: options.skipNetwork,
    castAvailable: options.castAvailable,
    runner: runReadOnly,
    evidenceSource: "production_collector",
  });
}

export function verifyContractDeploymentChainEvidenceWithTestAdapters(options = {}) {
  return verifyContractDeploymentChainEvidenceInternal({
    ...options,
    evidenceSource: "test_adapter_not_release_authority",
  });
}

export function resolveExecutablePath(command, environment = process.env) {
  if (typeof command !== "string" || !/^[a-z][a-z0-9-]{0,63}$/.test(command)) {
    return "";
  }
  const pathValue = typeof environment?.PATH === "string" ? environment.PATH : "";
  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory || !path.isAbsolute(directory)) continue;
    const candidate = path.join(directory, command);
    try {
      accessSync(candidate, constants.X_OK);
      const resolved = realpathSync(candidate);
      if (statSync(resolved).isFile()) return resolved;
    } catch {
      // Continue through the bounded PATH candidates without executing them.
    }
  }
  return "";
}

export function inspectInstalledCliVersion(command, expectedPackageName, environment = process.env) {
  const executable = resolveExecutablePath(command, environment);
  if (!executable) return { valid: false, version: "", source: "installed_package_manifest" };
  let directory = path.dirname(executable);
  for (let depth = 0; depth < 6; depth += 1) {
    const manifestPath = path.join(directory, "package.json");
    try {
      const stats = statSync(manifestPath);
      if (!stats.isFile() || stats.size < 2 || stats.size > 65_536) throw new Error("invalid");
      const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
      const version = clean(manifest?.version);
      if (manifest?.name === expectedPackageName
        && /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
        return { valid: true, version, source: "installed_package_manifest" };
      }
    } catch {
      // A package manifest is optional at each bounded ancestor.
    }
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  return { valid: false, version: "", source: "installed_package_manifest" };
}

function toolPresence() {
  const tools = {};
  for (const tool of ["git", "forge", "cast", "jq", "gh", "phala", "wrangler", "uv"]) {
    tools[tool] = Boolean(resolveExecutablePath(tool));
  }
  return tools;
}

function authEnvironment(env) {
  return {
    GH_TOKEN: clean(env.GH_TOKEN || env.GITHUB_TOKEN),
    GITHUB_TOKEN: clean(env.GITHUB_TOKEN),
  };
}

function phalaEnvironment(env) {
  return {
    PHALA_CLOUD_API_KEY: clean(env.PHALA_CLOUD_API_KEY),
    PHALA_CLOUD_API_PREFIX: PHALA_CONTROL_PLANE_AUTHORITY.api_origin,
    PHALA_CLOUD_DIR: clean(env.PHALA_CLOUD_DIR),
  };
}

function cloudflareEnvironment(env) {
  return {
    CLOUDFLARE_API_TOKEN: clean(env.CLOUDFLARE_API_TOKEN),
    CLOUDFLARE_ACCOUNT_ID: clean(env.CLOUDFLARE_ACCOUNT_ID),
  };
}

export function probeCloudflareAuthentication(
  env,
  execute = runReadOnly,
) {
  try {
    const result = execute("wrangler", ["whoami"], {
      env: cloudflareEnvironment(env),
      timeout: CLOUDFLARE_AUTH_PROBE_TIMEOUT_MS,
    });
    return result?.ok === true;
  } catch {
    return false;
  }
}

export function githubAttestationArgs(image, sourceSha, sourceRef, predicateType) {
  return [
    "attestation",
    "verify",
    `oci://${image}`,
    "--repo",
    EXPECTED_GITHUB_REPOSITORY,
    "--bundle-from-oci",
    "--signer-workflow",
    EXPECTED_GITHUB_WORKFLOW,
    "--source-digest",
    sourceSha,
    "--source-ref",
    sourceRef,
    "--deny-self-hosted-runners",
    "--predicate-type",
    predicateType,
  ];
}

export function githubReleaseManifestAttestationArgs(
  manifestPath,
  bundlePath,
  sourceSha,
  sourceRef,
) {
  if (!safeAbsoluteReadPath(manifestPath) || !safeAbsoluteReadPath(bundlePath)) {
    throw new Error("release-manifest attestation verification requires bounded absolute paths");
  }
  return [
    "attestation",
    "verify",
    manifestPath,
    "--repo",
    EXPECTED_GITHUB_REPOSITORY,
    "--bundle",
    bundlePath,
    "--signer-workflow",
    EXPECTED_GITHUB_WORKFLOW,
    "--source-digest",
    sourceSha,
    "--source-ref",
    sourceRef,
    "--deny-self-hosted-runners",
    "--predicate-type",
    "https://slsa.dev/provenance/v1",
  ];
}

function explicitPathProvided(args, key) {
  if (Array.isArray(args.explicitPathKeys)) {
    return args.explicitPathKeys.includes(key);
  }
  // Compatibility for internal callers that construct the argument object
  // directly instead of using parseArgs().
  return clean(args[key]).length > 0;
}

function normalizedOperatorPath(value, label, { requireAbsolute = false } = {}) {
  const candidate = clean(value);
  if (!candidate) return "";
  if (/[\u0000\r\n]/.test(candidate)) {
    throw new Error(`${label} contains an invalid path character`);
  }
  if (requireAbsolute && (!path.isAbsolute(candidate) || path.normalize(candidate) !== candidate)) {
    throw new Error(`${label} must be a canonical absolute path`);
  }
  return path.resolve(candidate);
}

function resolvePathBinding({
  args,
  key,
  env,
  envKey = "",
  fallback = "",
  requireAbsoluteEnv = false,
}) {
  const cliExplicit = explicitPathProvided(args, key);
  const cliPath = clean(args[key]) ? path.resolve(clean(args[key])) : "";
  const envPath = envKey
    ? normalizedOperatorPath(env[envKey], envKey, { requireAbsolute: requireAbsoluteEnv })
    : "";
  if (cliExplicit && envPath && cliPath !== envPath) {
    throw new Error(`${key} is ambiguous between the CLI flag and ${envKey}`);
  }
  if (cliExplicit) return cliPath;
  if (envPath) return envPath;
  return fallback || cliPath;
}

export function releaseScopedLedgerPath(
  releaseShaValue,
  gitHeadValue,
  repositoryRoot = rootDir,
) {
  const releaseSha = clean(releaseShaValue).toLowerCase();
  const gitHead = clean(gitHeadValue).toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(releaseSha) || releaseSha !== gitHead) return "";
  return path.join(
    repositoryRoot,
    "deployments",
    "fresh-contract-suites",
    releaseSha,
    "base-sepolia.json",
  );
}

export function resolveEvidencePaths(
  args,
  env,
  { gitHead = "", repositoryRoot = rootDir } = {},
) {
  const defaultLedger = releaseScopedLedgerPath(env.RELEASE_SHA, gitHead, repositoryRoot);
  const resolved = {
    release: resolvePathBinding({
      args,
      key: "release",
      env,
      envKey: "ACTIVATION_RELEASE_CANDIDATE_PATH",
    }),
    releaseCore: resolvePathBinding({
      args,
      key: "releaseCore",
      env,
      envKey: "FINAL_RELEASE_AUTHORITY_CORE_PATH",
      requireAbsoluteEnv: true,
    }),
    deploymentIntent: resolvePathBinding({
      args,
      key: "deploymentIntent",
      env,
      envKey: "DEPLOYMENT_INTENT_PATH",
      fallback: path.join(
        repositoryRoot,
        ".release",
        "dnai-deployment-intent-core.json",
      ),
      requireAbsoluteEnv: true,
    }),
    cvmLaunchIntent: resolvePathBinding({
      args,
      key: "cvmLaunchIntent",
      env,
      fallback: path.join(repositoryRoot, ".release", "cvm-launch-intent-core.json"),
    }),
    tinkerAccountBindingCeremony: resolvePathBinding({
      args,
      key: "tinkerAccountBindingCeremony",
      env,
      fallback: path.join(
        repositoryRoot,
        ".release",
        TINKER_ACCOUNT_BINDING_CEREMONY_BASENAME,
      ),
    }),
    tinkerAccountBindingCeremonyReceipt: resolvePathBinding({
      args,
      key: "tinkerAccountBindingCeremonyReceipt",
      env,
      fallback: path.join(
        repositoryRoot,
        ".release",
        TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME,
      ),
    }),
    reviewerCurrentStatus: resolvePathBinding({
      args,
      key: "reviewerCurrentStatus",
      env,
      envKey: "RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PATH",
      requireAbsoluteEnv: true,
    }),
    reviewerStatusHistory: resolvePathBinding({
      args,
      key: "reviewerStatusHistory",
      env,
      envKey: "RELEASE_REVIEWER_AUTHORITY_STATUS_HISTORY_PATH",
      requireAbsoluteEnv: true,
    }),
    diligencePhase1ReviewEnvelope: resolvePathBinding({
      args,
      key: "diligencePhase1ReviewEnvelope",
      env,
      envKey: "DILIGENCE_RELEASE_PHASE_1_REVIEW_ENVELOPE_PATH",
      requireAbsoluteEnv: true,
    }),
    diligencePhase2ReviewEnvelope: resolvePathBinding({
      args,
      key: "diligencePhase2ReviewEnvelope",
      env,
      envKey: "DILIGENCE_RELEASE_PHASE_2_REVIEW_ENVELOPE_PATH",
      requireAbsoluteEnv: true,
    }),
    diligencePhase3ReviewEnvelope: resolvePathBinding({
      args,
      key: "diligencePhase3ReviewEnvelope",
      env,
      envKey: "DILIGENCE_RELEASE_PHASE_3_REVIEW_ENVELOPE_PATH",
      requireAbsoluteEnv: true,
    }),
    diligencePhase4ReviewEnvelope: resolvePathBinding({
      args,
      key: "diligencePhase4ReviewEnvelope",
      env,
      envKey: "DILIGENCE_RELEASE_PHASE_4_REVIEW_ENVELOPE_PATH",
      requireAbsoluteEnv: true,
    }),
    ledger: resolvePathBinding({
      args,
      key: "ledger",
      env,
      envKey: "DEPLOYMENT_MANIFEST_PATH",
      fallback: defaultLedger,
      requireAbsoluteEnv: true,
    }),
    releaseCeremonyLedger: resolvePathBinding({
      args,
      key: "releaseCeremonyLedger",
      env,
      envKey: "RELEASE_CEREMONY_LEDGER_PATH",
      requireAbsoluteEnv: true,
    }),
    releaseCeremonyLedgerEvidenceRoot: resolvePathBinding({
      args,
      key: "releaseCeremonyLedgerEvidenceRoot",
      env,
      envKey: "RELEASE_CEREMONY_LEDGER_EVIDENCE_ROOT",
      requireAbsoluteEnv: true,
    }),
    releaseCeremonyLockRoot: resolvePathBinding({
      args,
      key: "releaseCeremonyLockRoot",
      env,
      envKey: "RELEASE_CEREMONY_LOCK_ROOT",
      requireAbsoluteEnv: true,
    }),
    artifactEvidence: resolvePathBinding({
      args,
      key: "artifactEvidence",
      env,
      envKey: "ACTIVATION_ARTIFACT_EVIDENCE_PATH",
    }),
    arenaEvidence: resolvePathBinding({
      args,
      key: "arenaEvidence",
      env,
      envKey: "ACTIVATION_ARENA_EVIDENCE_PATH",
    }),
    anchorWriterEvidence: resolvePathBinding({
      args,
      key: "anchorWriterEvidence",
      env,
      envKey: "ACTIVATION_ANCHOR_WRITER_EVIDENCE_PATH",
    }),
    emailOracleEvidence: resolvePathBinding({
      args,
      key: "emailOracleEvidence",
      env,
      envKey: "ACTIVATION_EMAIL_ORACLE_EVIDENCE_PATH",
    }),
  };
  const semanticEnvironmentPaths = Object.freeze({
    runtimeAuthorityDependency: "PRE_CEREMONY_RUNTIME_AUTHORITY_PATH",
    contractReceipt: "FRESH_CONTRACT_DEPLOYMENT_RECEIPT_PATH",
    reviewerAuthorityGenesis: "RELEASE_REVIEWER_AUTHORITY_GENESIS_PATH",
    reviewerAuthorityGenesisAcceptance:
      "RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PATH",
    bootstrapAuthority: "PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_PATH",
    bootstrapAuthorization: "PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_PATH",
    bootstrapAuthorizationReceipt:
      "PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_PATH",
    sevenCvmLaunchCompletionReceipt:
      "PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_PATH",
    imageReleaseSigstoreVerificationReceipt:
      "IMAGE_RELEASE_SIGSTORE_VERIFICATION_RECEIPT_PATH",
    cvmDescriptorSetReceipt: "CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_PATH",
    phalaExecutorFinalState: "PHALA_EXECUTOR_FINAL_STATE_PATH",
    ceremonyAuthorization: "CEREMONY_AUTHORIZATION_PATH",
    liveActivationAuthority: "LIVE_ACTIVATION_AUTHORITY_PATH",
    royaltyReleaseHistoryReceipt:
      "ROYALTY_RELEASE_HISTORY_RECEIPT_PATH",
    computeWorkloadActivationObservation:
      "COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_PATH",
    frontendBuildCandidateReceipt:
      "FRONTEND_BUILD_CANDIDATE_RECEIPT_PATH",
  });
  for (const flag of SEMANTIC_VALIDATOR_INPUT_FLAGS) {
    const key = semanticValidatorPathKey(flag);
    if (clean(resolved[key])) continue;
    resolved[key] = resolvePathBinding({
      args,
      key,
      env,
      envKey: semanticEnvironmentPaths[key] || "",
      fallback: key === "frontendBuildCandidateReceipt"
        ? path.join(
          repositoryRoot,
          ".release",
          "frontend-build-candidate-receipt.json",
        )
        : "",
      requireAbsoluteEnv: Boolean(semanticEnvironmentPaths[key]),
    });
  }
  const repositoryHistoricalLedger = path.join(
    repositoryRoot,
    "deployments",
    "base-sepolia.json",
  );
  if (resolved.ledger === repositoryHistoricalLedger || resolved.ledger === historicalLedger) {
    throw new Error("the historical deployments/base-sepolia.json ledger is not activation authority");
  }
  return resolved;
}

const TINKER_BINDING_HISTORICAL_VARIANT_FIELDS = new Set([
  "environment_commitment_matched",
  "historical_replay",
  "status",
  "tinker_account_binding_ceremony_receipt_sha256",
  "truth_status",
]);

function accountBindingReceiptInvariantProjection(receipt) {
  return Object.fromEntries(Object.entries(receipt).filter(
    ([key]) => !TINKER_BINDING_HISTORICAL_VARIANT_FIELDS.has(key),
  ));
}

export function validateTinkerAccountBindingCeremonyForStage({
  authorityStage,
  ceremonyFile,
  ceremonyReceiptFile,
  deploymentIntentPath,
  environment,
  now = () => new Date(),
  reviewerCurrentStatusPath,
  reviewerGenesisAcceptancePath,
  reviewerGenesisPath,
  reviewerStatusHistoryPath,
}) {
  try {
    if (!new Set([
      "fresh_deployment",
      "cvm_launch",
      "release_ceremony",
      "live_activation",
    ]).has(authorityStage)) {
      throw new TypeError("unsupported account-binding verification stage");
    }
    if (ceremonyFile?.valid !== true
      || ceremonyReceiptFile?.valid !== true
      || ceremonyFile.strictReleaseEvidence !== true
      || ceremonyReceiptFile.strictReleaseEvidence !== true
      || ceremonyFile.releaseDirectoryPath
        !== ceremonyReceiptFile.releaseDirectoryPath
      || path.basename(ceremonyFile.canonicalPath || "")
        !== TINKER_ACCOUNT_BINDING_CEREMONY_BASENAME
      || path.basename(ceremonyReceiptFile.canonicalPath || "")
        !== TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME) {
      throw new TypeError("account-binding ceremony artifacts are unavailable");
    }
    for (const value of [
      deploymentIntentPath,
      reviewerCurrentStatusPath,
      reviewerGenesisAcceptancePath,
      reviewerGenesisPath,
      reviewerStatusHistoryPath,
    ]) {
      if (!safeAbsoluteReadPath(value)) {
        throw new TypeError("account-binding authority path is invalid");
      }
    }
    const persistedReceipt = normalizeTinkerAccountBindingCeremonyReceipt(
      ceremonyReceiptFile.value,
    );
    if (`${JSON.stringify(persistedReceipt, null, 2)}\n`
      !== ceremonyReceiptFile.text
      || persistedReceipt.historical_replay !== false) {
      throw new TypeError("fixed account-binding receipt is not the fresh receipt");
    }
    const inputs = {
      ceremony: ceremonyFile.value,
      deploymentIntent: deploymentIntentPath,
      environment,
      reviewerCurrentStatus: reviewerCurrentStatusPath,
      reviewerGenesisAcceptance: reviewerGenesisAcceptancePath,
      reviewerGenesis: reviewerGenesisPath,
      statusHistory: reviewerStatusHistoryPath,
    };
    const currentStage = authorityStage === "fresh_deployment";
    const verified = currentStage
      ? verifyTinkerAccountBindingCeremonyArtifact({ ...inputs, now })
      : verifyTinkerAccountBindingCeremonyHistoricalReplay(inputs);
    if (`${JSON.stringify(verified.ceremony, null, 2)}\n`
      !== ceremonyFile.text) {
      throw new TypeError("account-binding ceremony bytes are noncanonical");
    }
    const replayReceipt = normalizeTinkerAccountBindingCeremonyReceipt(
      verified.receipt,
    );
    if (currentStage) {
      if (JSON.stringify(replayReceipt) !== JSON.stringify(persistedReceipt)) {
        throw new TypeError("fresh account-binding receipt drifted");
      }
    } else if (JSON.stringify(accountBindingReceiptInvariantProjection(replayReceipt))
      !== JSON.stringify(accountBindingReceiptInvariantProjection(persistedReceipt))) {
      throw new TypeError("historical account-binding replay drifted");
    }
    return Object.freeze({
      accountCommitment: replayReceipt.account_commitment,
      deploymentIntentSha256: replayReceipt.deployment_intent_sha256,
      historicalReplay: replayReceipt.historical_replay,
      persistedCeremonyReceiptSha256:
        persistedReceipt.tinker_account_binding_ceremony_receipt_sha256,
      replayCeremonyReceiptSha256:
        replayReceipt.tinker_account_binding_ceremony_receipt_sha256,
      reviewerAuthorityCurrentStatusSha256:
        replayReceipt.reviewer_authority_current_status_sha256,
      reviewerAuthorityGenesisAcceptanceSha256:
        replayReceipt.reviewer_authority_genesis_acceptance_sha256,
      truthStatus: replayReceipt.truth_status,
      valid: true,
      verificationMode: currentStage
        ? "fresh_current_two_reviewer_ceremony"
        : "authenticated_historical_two_reviewer_replay",
    });
  } catch {
    return Object.freeze({
      accountCommitment: "",
      deploymentIntentSha256: "",
      historicalReplay: authorityStage === "fresh_deployment" ? false : true,
      persistedCeremonyReceiptSha256: "",
      replayCeremonyReceiptSha256: "",
      reviewerAuthorityCurrentStatusSha256: "",
      reviewerAuthorityGenesisAcceptanceSha256: "",
      truthStatus: "",
      valid: false,
      verificationMode: authorityStage === "fresh_deployment"
        ? "fresh_current_two_reviewer_ceremony_rejected"
        : "authenticated_historical_two_reviewer_replay_rejected",
    });
  }
}

/**
 * Inspect the immutable Collaboration launch gate and, when available, the
 * current signed final-authority projection. This is policy evidence only: it
 * does not claim that a Phala runtime environment update occurred.
 */
export function inspectCollaborationLaunchGate({
  cvmLaunchIntent,
  mainCompose,
  finalAuthority = null,
} = {}) {
  const key = PHALA_COLLABORATION_LAUNCH_GATE_POLICY.environment_key;
  let bootstrapDefault = null;
  let launchPolicyValid = false;
  try {
    const targetPolicy =
      assertPhalaProductionTargetCollaborationLaunchGatePolicy();
    bootstrapDefault = targetPolicy.bootstrap_default;
    const mainDescriptor = cvmLaunchIntent?.descriptors?.find(
      (descriptor) => descriptor?.trust_domain === "main_runtime_cvm",
    );
    const classification =
      mainDescriptor?.public_environment_key_classification;
    const secretPhases =
      mainDescriptor?.encrypted_secret_environment_keys_by_phase;
    const services = mainCompose?.document?.services;
    const holders = services && typeof services === "object"
      ? Object.entries(services).filter(([, service]) => (
        service?.environment
        && typeof service.environment === "object"
        && Object.hasOwn(service.environment, key)
      ))
      : [];
    const excludedClassificationKeys = [
      ...(classification?.descriptor_static_keys || []),
      ...(classification?.descriptor_defaulted_keys || []),
      ...(classification?.provisioning_result_keys || []),
      ...(classification?.post_measurement_phase_control_keys || []),
    ];
    const secretKeys = secretPhases && typeof secretPhases === "object"
      ? Object.values(secretPhases).flatMap(
        (values) => Array.isArray(values) ? values : [key],
      )
      : [key];
    launchPolicyValid = mainCompose?.valid === true
      && targetPolicy === PHALA_COLLABORATION_LAUNCH_GATE_POLICY
      && targetPolicy.operator_mutable === false
      && targetPolicy.runtime_authority
        === "current_final_release_authority_v3_requested_features_collaboration"
      && bootstrapDefault === "false"
      && Array.isArray(classification?.post_measurement_deferred_keys)
      && classification.post_measurement_deferred_keys.includes(key)
      && Array.isArray(mainDescriptor?.exact_allowed_environment_keys)
      && mainDescriptor.exact_allowed_environment_keys.includes(key)
      && !excludedClassificationKeys.includes(key)
      && !secretKeys.includes(key)
      && holders.length === 1
      && holders[0][0] === "delegate"
      && holders[0][1].environment[key]
        === "${TINKER_COLLABORATION_ENABLED:-false}";
  } catch {
    launchPolicyValid = false;
    bootstrapDefault = null;
  }

  let finalAuthorityCollaborationRequested = null;
  let finalAuthorityCollaborationEnvironmentValue = null;
  let runtimeProjectionValid = false;
  if (finalAuthority !== null && finalAuthority !== undefined) {
    try {
      const projected =
        projectFinalReleaseAuthorityRuntimeFeatureValues(finalAuthority);
      finalAuthorityCollaborationRequested =
        finalAuthority.requested_features.collaboration;
      finalAuthorityCollaborationEnvironmentValue = projected[key];
      runtimeProjectionValid =
        typeof finalAuthorityCollaborationRequested === "boolean"
        && finalAuthorityCollaborationEnvironmentValue
          === (finalAuthorityCollaborationRequested ? "true" : "false");
    } catch {
      finalAuthorityCollaborationRequested = null;
      finalAuthorityCollaborationEnvironmentValue = null;
      runtimeProjectionValid = false;
    }
  }

  return Object.freeze({
    launchPolicyValid,
    bootstrapDefault,
    finalAuthorityCollaborationRequested,
    finalAuthorityCollaborationEnvironmentValue,
    runtimeProjectionValid,
  });
}

function rejectedDiligenceReleaseCeremony(reason) {
  return Object.freeze({
    valid: false,
    status: "rejected",
    reason,
  });
}

export async function collectCompletedDiligenceReleaseCeremony({
  authorityStage,
  evidencePaths,
  sourceManifestFile,
  releaseCeremonyLedgerFile,
  reviewEnvelopeFiles,
  deploymentIntentFile,
  cvmLaunchIntentFile,
  finalAuthorityFile,
  deploymentIntentResult,
  cvmLaunchIntentResult,
  finalAuthorityDescriptor,
  deploymentIntentSha256,
  finalAuthoritySha256,
  reviewerAuthorityGenesisAcceptanceSha256,
  tinkerAccountBindingCeremonyReceiptSha256,
  contractDeploymentChainEvidence,
  finalInputFilesStable,
}, execute = runReadOnly) {
  if (authorityStage !== "live_activation") {
    return rejectedDiligenceReleaseCeremony(
      "not_applicable_before_live_activation",
    );
  }
  try {
    if (finalInputFilesStable !== true
      || sourceManifestFile?.valid !== true
      || releaseCeremonyLedgerFile?.valid !== true
      || releaseCeremonyLedgerFile.mode !== 0o444
      || deploymentIntentFile?.valid !== true
      || cvmLaunchIntentFile?.valid !== true
      || finalAuthorityFile?.valid !== true
      || !Array.isArray(reviewEnvelopeFiles)
      || reviewEnvelopeFiles.length !== 4
      || reviewEnvelopeFiles.some((file) => file?.valid !== true)
      || deploymentIntentResult?.ok !== true
      || cvmLaunchIntentResult?.ok !== true
      || finalAuthorityDescriptor?.ok !== true
      || finalAuthorityDescriptor.subjectKind !== "final_release_authority") {
      return rejectedDiligenceReleaseCeremony(
        "completed_ceremony_inputs_unavailable",
      );
    }
    const reviewEnvelopePaths = [
      evidencePaths.diligencePhase1ReviewEnvelope,
      evidencePaths.diligencePhase2ReviewEnvelope,
      evidencePaths.diligencePhase3ReviewEnvelope,
      evidencePaths.diligencePhase4ReviewEnvelope,
    ];
    const stableBindings = [
      {
        path: evidencePaths.ledger,
        initial: sourceManifestFile,
        options: { json: true },
      },
      {
        path: evidencePaths.releaseCeremonyLedger,
        initial: releaseCeremonyLedgerFile,
        options: { json: true },
      },
      {
        path: evidencePaths.deploymentIntent,
        initial: deploymentIntentFile,
      },
      {
        path: evidencePaths.cvmLaunchIntent,
        initial: cvmLaunchIntentFile,
      },
      {
        path: evidencePaths.releaseCore,
        initial: finalAuthorityFile,
        options: { json: true },
      },
      ...reviewEnvelopePaths.map((reviewPath, index) => ({
        path: reviewPath,
        initial: reviewEnvelopeFiles[index],
        options: { json: true },
      })),
    ];
    if ([
      evidencePaths.ledger,
      evidencePaths.releaseCeremonyLedger,
      evidencePaths.releaseCeremonyLedgerEvidenceRoot,
      evidencePaths.releaseCeremonyLockRoot,
      evidencePaths.deploymentIntent,
      evidencePaths.cvmLaunchIntent,
      evidencePaths.releaseCore,
      ...reviewEnvelopePaths,
    ].some((value) => !safeAbsoluteReadPath(value))) {
      return rejectedDiligenceReleaseCeremony(
        "completed_ceremony_path_binding_invalid",
      );
    }
    const replayOptions = {
      repositoryRoot: rootDir,
      sourceManifestPath: evidencePaths.ledger,
      ledgerPath: evidencePaths.releaseCeremonyLedger,
      evidenceRoot: evidencePaths.releaseCeremonyLedgerEvidenceRoot,
      lockRoot: evidencePaths.releaseCeremonyLockRoot,
      releaseSha: deploymentIntentResult.receipt.releaseSha,
      deploymentIntentSha256,
      reviewerAuthorityGenesisAcceptanceSha256,
      tinkerAccountBindingCeremonyReceiptSha256,
    };
    const replayBefore = replayReleaseCeremonyLedgerRevisionChain(replayOptions);
    const reviewReceipts = validateDiligencePhaseReviewEnvelopes({
      reviewEnvelopePaths,
      finalAuthorityPath: evidencePaths.releaseCore,
      deploymentIntentPath: evidencePaths.deploymentIntent,
      cvmLaunchIntentPath: evidencePaths.cvmLaunchIntent,
    }, execute);
    const finalAuthority = finalAuthorityDescriptor.subject;
    const diligence = finalAuthority?.contracts?.diligence_room;
    const deploymentIntent = deploymentIntentResult.intent;
    const governanceController = deploymentIntent?.staticContractInputs
      ?.diligenceRoom?.governanceController;
    if (clean(finalAuthority?.release_sha).toLowerCase()
        !== clean(deploymentIntentResult.receipt.releaseSha).toLowerCase()
      || clean(finalAuthorityDescriptor.subjectSha256).toLowerCase()
        !== clean(finalAuthoritySha256).toLowerCase()
      || clean(diligence?.developer).toLowerCase()
        !== clean(governanceController).toLowerCase()) {
      return rejectedDiligenceReleaseCeremony(
        "final_authority_governance_lineage_invalid",
      );
    }
    const input = {
      ledger: releaseCeremonyLedgerFile.value,
      ledgerFileSha256:
        `sha256:${clean(releaseCeremonyLedgerFile.sha256).toLowerCase()}`,
      replay: replayBefore,
      expected: {
        chainId: 84_532,
        releaseSha: clean(deploymentIntentResult.receipt.releaseSha).toLowerCase(),
        deploymentIntentSha256,
        finalAuthoritySha256,
        deploymentOperator:
          deploymentIntent.deploymentControl?.operatorAddress,
        governanceController,
        diligenceRoomAddress: diligence?.address,
        runtimeCodeHash: diligence?.runtime_code_hash,
        teeIdentity: diligence?.release_admission?.tee_identity,
        composeHash: diligence?.release_admission?.compose_hash,
        resultVerifier: diligence?.result_verifier,
        evaluatorPolicyCommitments:
          diligence?.evaluator_policy_commitments,
        evaluatorPolicySetRoot: diligence?.evaluator_policy_set_root,
        attestationVerifier: diligence?.attestation_verifier,
        attestationReleasePolicyHash:
          diligence?.attestation_release_policy_hash,
      },
      reviewReceipts,
      chainEvidence: contractDeploymentChainEvidence,
    };
    const firstInspection =
      inspectCompletedDiligenceReleaseCeremony(input);
    if (firstInspection.valid !== true) return firstInspection;
    const filesStable = await validateStableFileBindings(stableBindings);
    const replayAfter = replayReleaseCeremonyLedgerRevisionChain(replayOptions);
    if (!filesStable
      || JSON.stringify(replayAfter) !== JSON.stringify(replayBefore)) {
      return rejectedDiligenceReleaseCeremony(
        "completed_ceremony_inputs_changed_during_preflight",
      );
    }
    return inspectCompletedDiligenceReleaseCeremony({
      ...input,
      replay: replayAfter,
    });
  } catch {
    return rejectedDiligenceReleaseCeremony(
      "completed_ceremony_replay_or_validation_failed",
    );
  }
}

export async function collectSnapshot(args) {
  const envFile = await inspectFile(args.env);
  const fileEnv = envFile.exists ? parseEnvText(envFile.text) : {};
  const env = { ...fileEnv, ...process.env };
  const tools = toolPresence();
  const toolVersions = {
    phala: inspectInstalledCliVersion("phala", "phala"),
  };
  const headProbe = tools.git
    ? runReadOnly("git", ["-C", rootDir, "rev-parse", "HEAD"])
    : { ok: false, stdout: "" };
  const dirtyProbe = tools.git
    ? runReadOnly("git", ["-C", rootDir, "status", "--porcelain", "--untracked-files=normal"])
    : { ok: false, stdout: "" };
  const evidencePaths = resolveEvidencePaths(args, env, {
    gitHead: headProbe.ok ? clean(headProbe.stdout) : "",
  });

  const [
    composeFile,
    diligenceQvlComposeFile,
    arenaQvlComposeFile,
    anchorWriterQvlComposeFile,
    computeWorkloadQvlComposeFile,
    computeMeteringQvlComposeFile,
    meteringComposeFile,
    imageReleaseFile,
    imageReleaseAttestationBundleFile,
    imageReleaseSigstoreVerificationReceiptFile,
    topologyFile,
    deploymentIntentFile,
    cvmLaunchIntentFile,
    tinkerAccountBindingCeremonyFile,
    tinkerAccountBindingCeremonyReceiptFile,
    reviewerAuthorityGenesisFile,
    reviewerCurrentStatusFile,
    reviewerStatusHistoryFile,
    releaseCandidate,
    releaseCore,
    ledger,
    artifactEvidence,
    arenaEvidence,
    anchorWriterEvidence,
    emailOracleEvidence,
  ] =
    await Promise.all([
      inspectFile(args.compose),
      inspectFile(args.diligenceQvlCompose),
      inspectFile(args.arenaQvlCompose),
      inspectFile(args.anchorWriterQvlCompose),
      inspectFile(args.computeWorkloadQvlCompose),
      inspectFile(args.computeMeteringQvlCompose),
      inspectFile(args.meteringCompose),
      inspectFile(args.imageRelease, { json: true }),
      inspectFile(args.imageReleaseAttestationBundle),
      inspectFile(args.imageReleaseSigstoreVerificationReceipt, { json: true }),
      inspectFile(args.topology, { json: true }),
      inspectFile(evidencePaths.deploymentIntent),
      inspectFile(evidencePaths.cvmLaunchIntent),
      inspectFile(evidencePaths.tinkerAccountBindingCeremony, {
        json: true,
        mode0600: true,
        strictReleaseEvidence: true,
      }),
      inspectFile(evidencePaths.tinkerAccountBindingCeremonyReceipt, {
        json: true,
        mode0600: true,
        strictReleaseEvidence: true,
      }),
      inspectFile(evidencePaths.reviewerAuthorityGenesis, {
        json: true,
        mode0600: true,
      }),
      inspectFile(evidencePaths.reviewerCurrentStatus, {
        json: true,
        mode0600: true,
      }),
      inspectFile(evidencePaths.reviewerStatusHistory, {
        json: true,
        mode0600: true,
      }),
      inspectFile(evidencePaths.release, { json: true }),
      inspectFile(evidencePaths.releaseCore, { json: true }),
      inspectFile(evidencePaths.ledger, { json: true }),
      inspectFile(evidencePaths.artifactEvidence, { json: true }),
      inspectFile(evidencePaths.arenaEvidence, { json: true }),
      inspectFile(evidencePaths.anchorWriterEvidence, { json: true, mode0600: true }),
      inspectFile(evidencePaths.emailOracleEvidence),
    ]);
  const [
    releaseCeremonyLedgerFile,
    ...diligencePhaseReviewEnvelopeFiles
  ] = await Promise.all([
    inspectFile(evidencePaths.releaseCeremonyLedger, { json: true }),
    inspectFile(evidencePaths.diligencePhase1ReviewEnvelope, { json: true }),
    inspectFile(evidencePaths.diligencePhase2ReviewEnvelope, { json: true }),
    inspectFile(evidencePaths.diligencePhase3ReviewEnvelope, { json: true }),
    inspectFile(evidencePaths.diligencePhase4ReviewEnvelope, { json: true }),
  ]);
  const semanticInputFiles = Object.freeze(Object.fromEntries(
    await Promise.all(SEMANTIC_VALIDATOR_INPUT_FLAGS.map(async (flag) => {
      const key = semanticValidatorPathKey(flag);
      return [key, await inspectFile(evidencePaths[key], { json: true })];
    })),
  ));

  const deploymentIntentResult = deploymentIntentFile.valid === true
    ? parseDeploymentIntentCoreText(deploymentIntentFile.text || "")
    : { ok: false, errors: [] };
  let cvmLaunchIntentResult = { ok: false, errors: [] };
  if (cvmLaunchIntentFile.valid === true) {
    try {
      const intent = parseCvmLaunchIntentCoreText(cvmLaunchIntentFile.text || "");
      cvmLaunchIntentResult = {
        ok: true,
        intent,
        receipt: cvmLaunchIntentValidationReceipt(intent),
      };
    } catch {
      cvmLaunchIntentResult = { ok: false, errors: [] };
    }
  }
  const finalAuthorityDescriptor = releaseCore.valid === true
    ? describeAuthorityReviewSubjectText(releaseCore.text || "")
    : { ok: false, errors: [] };
  const deploymentIntentDescriptor = deploymentIntentResult.ok === true
    ? describeAuthorityReviewSubjectText(deploymentIntentFile.text || "")
    : { ok: false, errors: [] };
  const cvmLaunchIntentDescriptor = cvmLaunchIntentResult.ok === true
    ? describeAuthorityReviewSubjectText(cvmLaunchIntentFile.text || "")
    : { ok: false, errors: [] };
  const authorityReleaseSha = clean(deploymentIntentResult?.receipt?.releaseSha).toLowerCase();
  const authorityObjectProbe = tools.git && /^[0-9a-f]{40}$/.test(authorityReleaseSha)
    ? runReadOnly("git", ["-C", rootDir, "cat-file", "-t", authorityReleaseSha])
    : { ok: false, stdout: "" };
  const authorityCommitTimeProbe = tools.git && authorityObjectProbe.ok
    ? runReadOnly("git", ["-C", rootDir, "show", "-s", "--format=%ct", authorityReleaseSha])
    : { ok: false, stdout: "" };
  const walletProbe = tools.cast
    ? runReadOnly("cast", ["wallet", "list"])
    : { ok: false, stdout: "" };

  const probes = {
    devKeystoreListed:
      walletProbe.ok && walletProbe.stdout.split(/\r?\n/).some((line) => /^dev(?:\s|\()/.test(line)),
    rpcAttempted: false,
    rpcChainId: "",
    githubAuth: false,
    phalaAuth: false,
    cloudflareAuth: false,
  };

  if (!args.skipNetwork) {
    if (tools.cast && clean(env.BASE_SEPOLIA_RPC_URL)) {
      const rpcProbe = runReadOnly(
        "cast",
        ["chain-id", "--rpc-url", clean(env.BASE_SEPOLIA_RPC_URL)],
      );
      probes.rpcAttempted = true;
      probes.rpcChainId = rpcProbe.ok ? clean(rpcProbe.stdout) : "";
    }
    probes.githubAuth = tools.gh
      && runReadOnly("gh", ["auth", "status"], { env: authEnvironment(env) }).ok;
    probes.phalaAuth = tools.phala
      && runReadOnly("phala", ["status"], { env: phalaEnvironment(env) }).ok;
    probes.cloudflareAuth = tools.wrangler
      && probeCloudflareAuthentication(env);
  }

  const compose = inspectCompose(composeFile.text || "");
  const diligenceQvlCompose = inspectCompose(diligenceQvlComposeFile.text || "");
  const arenaQvlCompose = inspectCompose(arenaQvlComposeFile.text || "");
  const anchorWriterQvlCompose = inspectCompose(anchorWriterQvlComposeFile.text || "");
  const computeWorkloadQvlCompose = inspectCompose(
    computeWorkloadQvlComposeFile.text || "",
  );
  const computeMeteringQvlCompose = inspectCompose(
    computeMeteringQvlComposeFile.text || "",
  );
  const meteringCompose = inspectCompose(meteringComposeFile.text || "");
  const imageRelease = inspectImageRelease(imageReleaseFile.value);
  const topology = inspectCvmTopology(topologyFile.value);
  const deploymentIntentSha256 = clean(
    deploymentIntentResult?.receipt?.deploymentIntentSha256,
  ).toLowerCase();
  const reviewerAuthorityGenesisAcceptanceSha256 = clean(
    deploymentIntentResult?.intent?.release
      ?.reviewerAuthorityGenesisAcceptanceSha256,
  ).toLowerCase();
  const tinkerAccountBindingCeremony =
    validateTinkerAccountBindingCeremonyForStage({
      authorityStage: args.authorityStage,
      ceremonyFile: tinkerAccountBindingCeremonyFile,
      ceremonyReceiptFile: tinkerAccountBindingCeremonyReceiptFile,
      deploymentIntentPath: evidencePaths.deploymentIntent,
      environment: env,
      reviewerCurrentStatusPath: evidencePaths.reviewerCurrentStatus,
      reviewerGenesisAcceptancePath:
        evidencePaths.reviewerAuthorityGenesisAcceptance,
      reviewerGenesisPath: evidencePaths.reviewerAuthorityGenesis,
      reviewerStatusHistoryPath: evidencePaths.reviewerStatusHistory,
    });
  const finalAuthoritySha256 = finalAuthorityDescriptor?.subjectKind
      === "final_release_authority"
    ? clean(finalAuthorityDescriptor.subjectSha256).toLowerCase()
    : "";
  let deploymentIntentEnvironmentProjection = {
    ok: false,
    checkedKeys: [],
    mismatchKeys: ["invalid_deployment_intent"],
  };
  if (deploymentIntentResult.ok === true) {
    try {
      deploymentIntentEnvironmentProjection = validateProjectedEnvironment(
        projectDeploymentIntentEnvironment(deploymentIntentResult.intent),
        env,
      );
    } catch {
      deploymentIntentEnvironmentProjection = {
        ok: false,
        checkedKeys: [],
        mismatchKeys: ["deployment_intent_projection_failed"],
      };
    }
  }
  const cvmLaunchReceipt = cvmLaunchIntentResult.ok === true
    ? cvmLaunchIntentResult.receipt
    : null;
  const cvmLaunchIntentSha256 = clean(cvmLaunchReceipt?.cvmLaunchIntentSha256).toLowerCase();
  const descriptorSha256ByDomain = Object.fromEntries(
    (cvmLaunchIntentResult.intent?.descriptors || []).map((descriptor) => [
      descriptor.trust_domain,
      clean(descriptor.descriptor_sha256).toLowerCase(),
    ]),
  );
  const descriptorFilesByDomain = {
    main_runtime_cvm: composeFile,
    diligence_qvl_cvm: diligenceQvlComposeFile,
    arena_qvl_cvm: arenaQvlComposeFile,
    anchor_writer_qvl_cvm: anchorWriterQvlComposeFile,
    compute_workload_qvl_cvm: computeWorkloadQvlComposeFile,
    compute_metering_qvl_cvm: computeMeteringQvlComposeFile,
    independent_metering_cvm: meteringComposeFile,
  };
  const descriptorInspectionsByDomain = {
    main_runtime_cvm: compose,
    diligence_qvl_cvm: diligenceQvlCompose,
    arena_qvl_cvm: arenaQvlCompose,
    anchor_writer_qvl_cvm: anchorWriterQvlCompose,
    compute_workload_qvl_cvm: computeWorkloadQvlCompose,
    compute_metering_qvl_cvm: computeMeteringQvlCompose,
    independent_metering_cvm: meteringCompose,
  };
  const actualDescriptorSha256ByDomain = Object.fromEntries(
    Object.entries(descriptorFilesByDomain).map(([domain, file]) => [
      domain,
      `sha256:${clean(file?.sha256).toLowerCase()}`,
    ]),
  );
  const topologyDescriptorSha256ByDomain = Object.fromEntries(
    Object.entries(topology.domains || {}).map(([domain, descriptor]) => [
      domain,
      `sha256:${clean(descriptor?.sha256).toLowerCase()}`,
    ]),
  );
  const collaborationLaunchGate = inspectCollaborationLaunchGate({
    cvmLaunchIntent: cvmLaunchIntentResult.intent,
    mainCompose: compose,
    finalAuthority: finalAuthorityDescriptor.ok === true
        && finalAuthorityDescriptor.subjectKind === "final_release_authority"
      ? finalAuthorityDescriptor.subject
      : null,
  });
  const cvmLaunchDescriptorBindingsValid = cvmLaunchIntentResult.ok === true
    && CVM_LAUNCH_DOMAINS.every((domain) => (
      descriptorSha256ByDomain[domain] === actualDescriptorSha256ByDomain[domain]
      && descriptorSha256ByDomain[domain] === topologyDescriptorSha256ByDomain[domain]
    ));
  const contractDeploymentReceipt = deploymentIntentResult.ok === true
      && tinkerAccountBindingCeremony.valid === true
    ? inspectFreshContractDeploymentReceipt(
      ledger.value,
      clean(deploymentIntentResult.receipt?.deploymentIntentSha256).toLowerCase(),
      clean(deploymentIntentResult.receipt?.releaseSha).toLowerCase(),
      clean(
        deploymentIntentResult.intent?.release
          ?.reviewerAuthorityGenesisAcceptanceSha256,
      ).toLowerCase(),
      tinkerAccountBindingCeremony.persistedCeremonyReceiptSha256,
    )
    : { valid: false, receipt: null, sha256: "", contractCount: 0 };
  const cvmLaunchArtifactBindingsValid = cvmLaunchIntentResult.ok === true
    && cvmLaunchReceipt.deploymentIntentSha256 === deploymentIntentSha256
    && cvmLaunchReceipt.releaseSha === authorityReleaseSha
    && contractDeploymentReceipt.valid === true
    && cvmLaunchReceipt.contractDeploymentReceiptSha256
      === contractDeploymentReceipt.sha256
    && cvmLaunchReceipt.imageReleaseManifestSha256
      === `sha256:${clean(imageReleaseFile.sha256).toLowerCase()}`
    && cvmLaunchReceipt.imageAttestationBundleSha256
      === `sha256:${clean(imageReleaseAttestationBundleFile.sha256).toLowerCase()}`
    && cvmLaunchReceipt.topologySha256
      === `sha256:${clean(topologyFile.sha256).toLowerCase()}`
    && topology.deploymentIntentSha256 === deploymentIntentSha256
    && cvmLaunchDescriptorBindingsValid;
  const cvmLaunchProductionPostureValid = cvmLaunchIntentResult.ok === true
    && topology.valid === true
    && collaborationLaunchGate.launchPolicyValid === true
    && Object.values(descriptorFilesByDomain).every((file) => file?.valid === true)
    && Object.values(descriptorInspectionsByDomain).every((inspection) => (
      inspection?.valid === true
    ));
  let royaltyReleaseAuthority = null;
  let royaltyReleaseHistorySha256 = "";
  let royaltyReleaseHistoryReceiptSha256 = "";
  if (args.authorityStage === "live_activation") {
    try {
      const royaltyContractState = semanticInputFiles.liveActivationAuthority
        ?.value?.contract_state;
      royaltyReleaseAuthority = normalizeRoyaltyReleaseAuthority(
        royaltyContractState?.royalty_release_history?.authority,
      );
      royaltyReleaseHistorySha256 = clean(
        royaltyContractState?.royalty_release_history_sha256,
      ).toLowerCase();
      royaltyReleaseHistoryReceiptSha256 = clean(
        royaltyContractState?.royalty_release_history_receipt_sha256,
      ).toLowerCase();
    } catch {
      royaltyReleaseAuthority = null;
      royaltyReleaseHistorySha256 = "";
      royaltyReleaseHistoryReceiptSha256 = "";
    }
  }
  const contractDeploymentChainEvidence = verifyContractDeploymentChainEvidence({
    contractDeploymentReceipt: contractDeploymentReceipt.receipt,
    deploymentIntent: deploymentIntentResult.intent,
    deploymentIntentText: deploymentIntentFile.text || "",
    deploymentIntentSha256,
    expectedTinkerAccountBindingCeremonyReceiptSha256:
      tinkerAccountBindingCeremony.persistedCeremonyReceiptSha256,
    releaseSha: authorityReleaseSha,
    finalAuthority: finalAuthorityDescriptor.subject,
    finalAuthoritySha256,
    royaltyReleaseAuthority,
    authorityStage: args.authorityStage,
    rpcUrl: clean(env.BASE_SEPOLIA_RPC_URL),
    secondaryRpcUrl: clean(env.BASE_SEPOLIA_SECONDARY_RPC_URL),
    skipNetwork: args.skipNetwork,
    castAvailable: tools.cast === true,
  });
  const chainEvidenceCheckedAtMs = Date.now();
  let activationReadinessSnapshot = null;
  let activationReadinessSnapshotSha256 = "";
  if (args.authorityStage !== "fresh_deployment"
    && contractDeploymentChainEvidence.valid === true
    && cvmLaunchDescriptorBindingsValid) {
    try {
      const checkedAtSecondMs = Math.floor(chainEvidenceCheckedAtMs / 1_000) * 1_000;
      const expiresAtSecondMs = checkedAtSecondMs + ACTIVATION_READINESS_MAX_LIFETIME_MS;
      const canonicalUtcSecond = (milliseconds) => (
        new Date(milliseconds).toISOString().replace(".000Z", "Z")
      );
      activationReadinessSnapshot = createActivationReadinessSnapshot({
        stage: args.authorityStage,
        releaseSha: authorityReleaseSha,
        rpcEndpointSha256: contractDeploymentChainEvidence.rpcEndpointSha256,
        deploymentIntentSha256,
        contractDeploymentReceiptSha256: contractDeploymentReceipt.sha256,
        cvmLaunchIntentSha256,
        finalAuthoritySha256: args.authorityStage === "cvm_launch"
          ? null
          : finalAuthoritySha256,
        chainEvidence: contractDeploymentChainEvidence,
        descriptorSha256ByDomain,
        checkedAt: canonicalUtcSecond(checkedAtSecondMs),
        expiresAt: canonicalUtcSecond(expiresAtSecondMs),
      });
      activationReadinessSnapshotSha256 =
        `sha256:${activationReadinessSnapshotDigest(activationReadinessSnapshot)}`;
    } catch {
      activationReadinessSnapshot = null;
      activationReadinessSnapshotSha256 = "";
    }
  }
  const releaseImages = [
    ...(releaseCandidate.value ? collectDigestImages(releaseCandidate.value) : []),
    ...(imageRelease.valid ? imageRelease.images : []),
  ];
  const composeImages = [
    compose,
    diligenceQvlCompose,
    arenaQvlCompose,
    anchorWriterQvlCompose,
    computeWorkloadQvlCompose,
    computeMeteringQvlCompose,
    meteringCompose,
  ]
    .flatMap((domain) => Object.values(domain.services))
    .map((service) => clean(service.image).toLowerCase())
    .filter((image) => /^ghcr\.io\/[^\s@]+@sha256:[0-9a-f]{64}$/.test(image));
  const ownedImages = [...new Set([...composeImages, ...releaseImages])]
    .filter((image) => image.startsWith("ghcr.io/therealwiki/dnai-wikigen/"))
    .slice(0, 16);

  const attestations = [];
  const sourceSha = clean(env.RELEASE_SHA).toLowerCase();
  const sourceRef = imageRelease.valid ? imageRelease.sourceRef : "";
  const mayVerifyAttestations = !args.skipNetwork
    && tools.gh
    && probes.githubAuth
    && dirtyProbe.ok
    && clean(dirtyProbe.stdout) === ""
    && /^[0-9a-f]{40}$/.test(sourceSha)
    && sourceSha === clean(headProbe.stdout).toLowerCase()
    && imageRelease.valid === true
    && imageRelease.releaseSha === sourceSha;
  if (mayVerifyAttestations) {
    for (const image of ownedImages) {
      for (const predicateType of [
        "https://slsa.dev/provenance/v1",
        "https://spdx.dev/Document/v2.3",
      ]) {
        const result = runReadOnly(
          "gh",
          githubAttestationArgs(image, sourceSha, sourceRef, predicateType),
          { env: authEnvironment(env), timeout: 30_000 },
        );
        attestations.push({ ok: result.ok });
      }
    }
  }
  let releaseManifestAttestation = { ok: false };
  const mayVerifyReleaseManifestAttestation = mayVerifyAttestations
    && imageReleaseFile.valid === true
    && imageReleaseAttestationBundleFile.valid === true
    && imageReleaseSigstoreVerificationReceiptFile.valid === true
    && topology.valid === true
    && topology.manifestSha256 === clean(imageReleaseFile.sha256)
    && topology.manifestAttestationSha256
      === clean(imageReleaseAttestationBundleFile.sha256);
  if (mayVerifyReleaseManifestAttestation) {
    try {
      const verified = assertProductionReleaseManifestSigstoreVerificationReceipt(
        await verifyReleaseManifestSigstoreAttestation({
          manifestPath: args.imageRelease,
          bundlePath: args.imageReleaseAttestationBundle,
          expectedReleaseSha: sourceSha,
        }),
      );
      const persisted = assertProductionReleaseManifestSigstoreVerificationReceipt(
        imageReleaseSigstoreVerificationReceiptFile.value,
      );
      const canonicalVerified =
        canonicalReleaseManifestSigstoreVerificationReceiptText(verified);
      const canonicalPersisted =
        canonicalReleaseManifestSigstoreVerificationReceiptText(persisted);
      const manifestInputsStable = await validateStableFileBindings([
        {
          path: args.imageRelease,
          initial: imageReleaseFile,
          options: { json: true },
        },
        {
          path: args.imageReleaseAttestationBundle,
          initial: imageReleaseAttestationBundleFile,
        },
        {
          path: args.imageReleaseSigstoreVerificationReceipt,
          initial: imageReleaseSigstoreVerificationReceiptFile,
          options: { json: true },
        },
      ]);
      const exactProductionReceipt = canonicalPersisted
        === imageReleaseSigstoreVerificationReceiptFile.text
        && canonicalPersisted === canonicalVerified
        && persisted.release_sha === sourceSha
        && persisted.release_manifest_sha256
          === `sha256:${clean(imageReleaseFile.sha256).toLowerCase()}`
        && persisted.release_manifest_sigstore_bundle_sha256
          === `sha256:${clean(
            imageReleaseAttestationBundleFile.sha256,
          ).toLowerCase()}`
        && persisted.blocker_code === RELEASE_MANIFEST_SIGSTORE_BLOCKER
        && persisted.blocker_status === "cleared_by_this_receipt"
        && persisted.status === "verified_by_pinned_gh_sigstore";
      if (manifestInputsStable && exactProductionReceipt) {
        releaseManifestAttestation = {
          ok: true,
          productionVerified: true,
          status: persisted.status,
          blockerCode: persisted.blocker_code,
          blockerStatus: persisted.blocker_status,
          receiptSha256:
            releaseManifestSigstoreVerificationReceiptSha256(persisted),
          receiptArtifactFileSha256:
            `sha256:${clean(
              imageReleaseSigstoreVerificationReceiptFile.sha256,
            ).toLowerCase()}`,
          releaseSha: persisted.release_sha,
          releaseManifestSha256: persisted.release_manifest_sha256,
          releaseManifestSigstoreBundleSha256:
            persisted.release_manifest_sigstore_bundle_sha256,
        };
      }
    } catch {
      releaseManifestAttestation = { ok: false };
    }
  }

  const deploymentIntentFileHashBound = deploymentIntentResult.ok === true
    && deploymentIntentSha256 === `sha256:${clean(deploymentIntentFile.sha256).toLowerCase()}`;
  const finalAuthorityFileHashBound = releaseCore.valid === true
    && finalAuthorityDescriptor.ok === true
    && finalAuthorityDescriptor.subjectKind === "final_release_authority";
  const liveCandidateAuthority = releaseCandidate.value?.operator_policy || {};
  const semanticInputsReady = args.authorityStage === "live_activation"
    && !args.skipNetwork
    && Object.values(semanticInputFiles).every((file) => file.valid === true)
    && releaseCandidate.valid === true
    && releaseCore.valid === true
    && ledger.valid === true
    && deploymentIntentFileHashBound
    && finalAuthorityFileHashBound
    && clean(finalAuthorityDescriptor?.subject?.deployment_intent_sha256).toLowerCase()
      === deploymentIntentSha256
    && clean(finalAuthorityDescriptor?.subject?.cvm_launch_intent_sha256).toLowerCase()
      === cvmLaunchIntentSha256
    && cvmLaunchArtifactBindingsValid
    && contractDeploymentReceipt.valid
    && artifactEvidence.valid === true
    && arenaEvidence.valid === true
    && anchorWriterEvidence.valid === true
    && emailOracleEvidence.valid === true;
  const semanticStableBindings = SEMANTIC_VALIDATOR_INPUT_FLAGS.map((flag) => {
    const key = semanticValidatorPathKey(flag);
    return {
      path: evidencePaths[key],
      initial: semanticInputFiles[key],
      options: { json: true },
    };
  });
  const semanticValidation = semanticInputsReady
    ? await runStableSemanticReleaseValidation({
      paths: evidencePaths,
      env,
      expectedAuthority: {
        releaseSha: authorityReleaseSha,
        deploymentIntentSha256,
        reviewerAuthorityGenesisAcceptanceSha256,
        ceremonyAuthorizationSha256: clean(
          liveCandidateAuthority.ceremony_authorization_sha256,
        ).toLowerCase(),
        liveActivationAuthoritySha256: clean(
          liveCandidateAuthority.live_activation_authority_sha256,
        ).toLowerCase(),
        runtimeAuthorityDependencySha256: clean(
          liveCandidateAuthority.runtime_authority_dependency_sha256,
        ).toLowerCase(),
        royaltyReleaseHistorySha256,
        royaltyReleaseHistoryReceiptSha256,
      },
    }, semanticStableBindings)
    : {
      valid: false,
      reason: args.authorityStage === "fresh_deployment"
        ? "canonical_semantic_validator_not_applicable_fresh_deployment"
        : args.authorityStage === "cvm_launch"
          ? "canonical_semantic_validator_not_applicable_cvm_launch"
          : args.authorityStage === "release_ceremony"
            ? "canonical_live_chain_validator_not_applicable_release_ceremony"
          : args.skipNetwork
            ? "canonical_semantic_validator_skipped_network"
            : "canonical_semantic_validator_inputs_invalid",
    };
  // Production authority deliberately does not run an independent online QVL
  // protocol here. The retired v2 probe had an in-memory replay ledger and an
  // ambient Python verifier that did not enforce the signed release lineage or
  // exact measurement policy. The shared ceremony validator must supply this
  // result after authenticating fresh v3 evidence at release_ceremony, or the
  // persisted signed C -> B/R/L/O/D dependency chain at live_activation.
  // Until that shared validator has a frozen honest-provenance API, this stays
  // fail-closed and cannot be populated from environment values or endpoints.
  const canonicalSevenCvmAuthorityValidation = null;
  const canonicalSevenCvmAuthorityReason = args.authorityStage === "fresh_deployment"
    ? "canonical_seven_cvm_authority_not_applicable_fresh_deployment"
    : args.authorityStage === "cvm_launch"
      ? "canonical_seven_cvm_authority_not_applicable_cvm_launch"
      : "canonical_seven_cvm_authority_validator_unavailable";
  const tinkerAccountBindingStableBindings = [
    {
      path: evidencePaths.tinkerAccountBindingCeremony,
      initial: tinkerAccountBindingCeremonyFile,
      options: {
        json: true,
        mode0600: true,
        strictReleaseEvidence: true,
      },
    },
    {
      path: evidencePaths.tinkerAccountBindingCeremonyReceipt,
      initial: tinkerAccountBindingCeremonyReceiptFile,
      options: {
        json: true,
        mode0600: true,
        strictReleaseEvidence: true,
      },
    },
    {
      path: evidencePaths.reviewerAuthorityGenesis,
      initial: reviewerAuthorityGenesisFile,
      options: { json: true, mode0600: true },
    },
    {
      path: evidencePaths.reviewerCurrentStatus,
      initial: reviewerCurrentStatusFile,
      options: { json: true, mode0600: true },
    },
    {
      path: evidencePaths.reviewerStatusHistory,
      initial: reviewerStatusHistoryFile,
      options: { json: true, mode0600: true },
    },
  ];
  let finalInputFilesStable;
  if (args.authorityStage === "fresh_deployment") {
    finalInputFilesStable = await validateStableFileBindings([
      { path: args.env, initial: envFile },
      { path: evidencePaths.deploymentIntent, initial: deploymentIntentFile },
      ...tinkerAccountBindingStableBindings,
    ]);
  } else {
    const readinessStableBindings = [
      { path: args.env, initial: envFile },
      { path: args.compose, initial: composeFile },
      { path: args.diligenceQvlCompose, initial: diligenceQvlComposeFile },
      { path: args.arenaQvlCompose, initial: arenaQvlComposeFile },
      { path: args.anchorWriterQvlCompose, initial: anchorWriterQvlComposeFile },
      { path: args.computeWorkloadQvlCompose, initial: computeWorkloadQvlComposeFile },
      { path: args.computeMeteringQvlCompose, initial: computeMeteringQvlComposeFile },
      { path: args.meteringCompose, initial: meteringComposeFile },
      { path: args.imageRelease, initial: imageReleaseFile, options: { json: true } },
      {
        path: args.imageReleaseAttestationBundle,
        initial: imageReleaseAttestationBundleFile,
      },
      {
        path: args.imageReleaseSigstoreVerificationReceipt,
        initial: imageReleaseSigstoreVerificationReceiptFile,
        options: { json: true },
      },
      { path: args.topology, initial: topologyFile, options: { json: true } },
      { path: evidencePaths.deploymentIntent, initial: deploymentIntentFile },
      { path: evidencePaths.cvmLaunchIntent, initial: cvmLaunchIntentFile },
      { path: evidencePaths.ledger, initial: ledger, options: { json: true } },
      ...tinkerAccountBindingStableBindings,
    ];
    if (args.authorityStage === "live_activation") {
      readinessStableBindings.push(...semanticStableBindings.filter((binding) => ![
        evidencePaths.deploymentIntent,
        evidencePaths.ledger,
      ].includes(binding.path)));
    } else if (args.authorityStage === "release_ceremony") {
      // The release-ceremony stage precedes O, D, and separately signed C.
      // Bind only the current artifacts this preflight actually interprets;
      // Current exact-38 is reserved for live activation and must not make a
      // pre-mutation ceremony depend on its own future outputs.
      readinessStableBindings.push(
        { path: evidencePaths.release, initial: releaseCandidate, options: { json: true } },
        { path: evidencePaths.releaseCore, initial: releaseCore, options: { json: true } },
        { path: evidencePaths.artifactEvidence, initial: artifactEvidence, options: { json: true } },
        { path: evidencePaths.arenaEvidence, initial: arenaEvidence, options: { json: true } },
        {
          path: evidencePaths.anchorWriterEvidence,
          initial: anchorWriterEvidence,
          options: { json: true, mode0600: true },
        },
        { path: evidencePaths.emailOracleEvidence, initial: emailOracleEvidence },
      );
    }
    finalInputFilesStable = await validateStableFileBindings(readinessStableBindings);
    if (!finalInputFilesStable) {
      activationReadinessSnapshot = null;
      activationReadinessSnapshotSha256 = "";
    }
  }
  const diligenceReleaseCeremony =
    await collectCompletedDiligenceReleaseCeremony({
      authorityStage: args.authorityStage,
      evidencePaths,
      sourceManifestFile: ledger,
      releaseCeremonyLedgerFile,
      reviewEnvelopeFiles: diligencePhaseReviewEnvelopeFiles,
      deploymentIntentFile,
      cvmLaunchIntentFile,
      finalAuthorityFile: releaseCore,
      deploymentIntentResult,
      cvmLaunchIntentResult,
      finalAuthorityDescriptor,
      deploymentIntentSha256,
      finalAuthoritySha256,
      reviewerAuthorityGenesisAcceptanceSha256,
      tinkerAccountBindingCeremonyReceiptSha256:
        tinkerAccountBindingCeremony.persistedCeremonyReceiptSha256,
      contractDeploymentChainEvidence,
      finalInputFilesStable,
    });
  const reportCheckedAtMs = Date.now();

  return {
    env,
    tools,
    toolVersions,
    git: {
      head: headProbe.ok ? clean(headProbe.stdout) : "",
      dirty: dirtyProbe.ok ? clean(dirtyProbe.stdout) !== "" : null,
    },
    probes,
    files: {
      env: {
        exists: envFile.exists,
        mode: envFile.mode,
      },
      releaseCandidate,
      releaseCore,
      ledger,
      releaseCeremonyLedger: releaseCeremonyLedgerFile,
      diligencePhaseReviewEnvelopes:
        diligencePhaseReviewEnvelopeFiles,
      artifactEvidence,
      arenaEvidence,
      anchorWriterEvidence,
      emailOracleEvidence,
      imageRelease: imageReleaseFile,
      imageReleaseAttestationBundle: imageReleaseAttestationBundleFile,
      imageReleaseSigstoreVerificationReceipt:
        imageReleaseSigstoreVerificationReceiptFile,
      topology: topologyFile,
      deploymentIntent: deploymentIntentFile,
      cvmLaunchIntent: cvmLaunchIntentFile,
      tinkerAccountBindingCeremony: tinkerAccountBindingCeremonyFile,
      tinkerAccountBindingCeremonyReceipt:
        tinkerAccountBindingCeremonyReceiptFile,
      reviewerAuthorityGenesis: reviewerAuthorityGenesisFile,
      reviewerCurrentStatus: reviewerCurrentStatusFile,
      reviewerStatusHistory: reviewerStatusHistoryFile,
      semanticInputs: semanticInputFiles,
      mainCompose: composeFile,
      diligenceQvlCompose: diligenceQvlComposeFile,
      arenaQvlCompose: arenaQvlComposeFile,
      anchorWriterQvlCompose: anchorWriterQvlComposeFile,
      computeWorkloadQvlCompose: computeWorkloadQvlComposeFile,
      computeMeteringQvlCompose: computeMeteringQvlComposeFile,
      meteringCompose: meteringComposeFile,
    },
    compose,
    diligenceQvlCompose,
    arenaQvlCompose,
    anchorWriterQvlCompose,
    computeWorkloadQvlCompose,
    computeMeteringQvlCompose,
    meteringCompose,
    imageRelease,
    topology,
    authorityStage: args.authorityStage,
    diligenceReleaseCeremony,
    contractDeploymentChainEvidence,
    activationReadinessSnapshot,
    activationReadinessSnapshotSha256,
    activationReadinessValidationNowMs: reportCheckedAtMs,
    releaseAuthority: {
      deploymentIntentValid: deploymentIntentResult.ok === true,
      deploymentIntentFileHashBound: deploymentIntentFileHashBound && finalInputFilesStable,
      deploymentIntentSha256,
      reviewerAuthorityGenesisAcceptanceSha256,
      reviewerAuthorityCurrentStatusEpoch:
        deploymentIntentResult?.receipt?.reviewerAuthorityCurrentStatusEpoch,
      reviewerAuthorityCurrentStatusSha256: clean(
        deploymentIntentResult?.receipt?.reviewerAuthorityCurrentStatusSha256,
      ).toLowerCase(),
      releaseSha: authorityReleaseSha,
      gitObjectIsCommit:
        authorityObjectProbe.ok && clean(authorityObjectProbe.stdout) === "commit",
      commitTime: authorityCommitTimeProbe.ok
        && /^[0-9]+$/.test(clean(authorityCommitTimeProbe.stdout))
        ? Number(clean(authorityCommitTimeProbe.stdout))
        : 0,
      deploymentIntentEnvironmentProjection,
      deploymentIntentFreshChallengeStateValid:
        validateDeploymentIntentFreshChallengeState(deploymentIntentResult.intent),
      tinkerAccountBindingCeremony: {
        ...tinkerAccountBindingCeremony,
        valid: tinkerAccountBindingCeremony.valid === true
          && finalInputFilesStable === true,
      },
      finalAuthorityValid: finalAuthorityDescriptor.ok === true
        && finalAuthorityDescriptor.subjectKind === "final_release_authority",
      finalAuthorityFileHashBound: finalAuthorityFileHashBound && finalInputFilesStable,
      finalAuthoritySha256,
      finalAuthorityDeploymentIntentSha256: clean(
        finalAuthorityDescriptor?.subject?.deployment_intent_sha256,
      ).toLowerCase(),
      finalAuthorityCvmLaunchIntentSha256: clean(
        finalAuthorityDescriptor?.subject?.cvm_launch_intent_sha256,
      ).toLowerCase(),
      finalAuthorityCollaborationRequested:
        collaborationLaunchGate.finalAuthorityCollaborationRequested,
      finalAuthorityCollaborationEnvironmentValue:
        collaborationLaunchGate.finalAuthorityCollaborationEnvironmentValue,
      checkedAtMs: reportCheckedAtMs,
    },
    cvmLaunchAuthority: {
      valid: cvmLaunchIntentResult.ok === true,
      fileHashBound: cvmLaunchIntentResult.ok === true
        && /^sha256:[0-9a-f]{64}$/.test(cvmLaunchIntentSha256),
      sha256: cvmLaunchIntentSha256,
      deploymentIntentSha256: clean(cvmLaunchReceipt?.deploymentIntentSha256).toLowerCase(),
      releaseSha: clean(cvmLaunchReceipt?.releaseSha).toLowerCase(),
      checkedAtMs: reportCheckedAtMs,
      contractDeploymentReceipt: contractDeploymentReceipt.receipt,
      contractDeploymentReceiptValid: contractDeploymentReceipt.valid,
      contractDeploymentReceiptSha256: clean(
        cvmLaunchReceipt?.contractDeploymentReceiptSha256,
      ).toLowerCase(),
      imageReleaseManifestSha256: clean(
        cvmLaunchReceipt?.imageReleaseManifestSha256,
      ).toLowerCase(),
      imageAttestationBundleSha256: clean(
        cvmLaunchReceipt?.imageAttestationBundleSha256,
      ).toLowerCase(),
      topologySha256: clean(cvmLaunchReceipt?.topologySha256).toLowerCase(),
      descriptorSha256ByDomain,
      artifactBindingsValid: cvmLaunchArtifactBindingsValid && finalInputFilesStable,
      contractDeploymentContractCount: contractDeploymentReceipt.contractCount,
      imageReleaseValid: imageRelease.valid === true,
      imageCount: imageRelease.images?.length || 0,
      topologyValid: topology.valid === true,
      descriptorCount: Object.keys(descriptorSha256ByDomain).length,
      descriptorHashesDistinct: Object.values(descriptorSha256ByDomain).length
        === new Set(Object.values(descriptorSha256ByDomain)).size,
      productionPostureValid: cvmLaunchProductionPostureValid,
      collaborationGatePolicyValid:
        collaborationLaunchGate.launchPolicyValid,
      collaborationGateBootstrapDefault:
        collaborationLaunchGate.bootstrapDefault,
    },
    releaseImages,
    attestations,
    releaseManifestAttestation,
    canonicalSevenCvmAuthorityValidation,
    canonicalSevenCvmAuthorityReason,
    semanticEvidenceValidated: semanticValidation.valid === true,
    semanticEvidenceReason: semanticValidation.reason,
    semanticValidationReceipt: semanticValidation.receipt || null,
  };
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  if (args.authorityStageExplicit !== true) {
    process.stderr.write(
      "activation preflight requires explicit --stage fresh-deployment, cvm-launch, release-ceremony, or live-activation; no probes were run\n",
    );
    return 2;
  }
  const snapshot = await collectSnapshot(args);
  const report = buildPreflightReport(snapshot);
  assertReportContainsNoSensitiveValues(report, snapshot.env);
  process.stdout.write(args.json ? `${JSON.stringify(report, null, 2)}\n` : formatHumanReport(report));
  return report.verdict === "READY" ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(
    (code) => { process.exitCode = code; },
    () => {
      console.error("activation preflight failed safely; no secret values or probe errors were printed");
      process.exitCode = 2;
    },
  );
}
