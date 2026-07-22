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
  ACTIVATION_READINESS_MAX_LIFETIME_MS,
  BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS,
  CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS,
  CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE,
  CONTRACT_STATELESS_POSTSTATE_EXCEPTION,
  EXPECTED_GITHUB_REPOSITORY,
  EXPECTED_GITHUB_WORKFLOW,
  SEMANTIC_VALIDATION_SCHEMA,
  SEMANTIC_VALIDATION_STATUS,
  SEMANTIC_VALIDATION_TRUTH_STATUS,
  buildPreflightReport,
  activationReadinessRpcEndpointDigest,
  activationReadinessRpcOriginDigest,
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
  SEMANTIC_VALIDATOR_INPUT_FLAGS,
} from "../web/scripts/build-release-env.mjs";

export { SEMANTIC_VALIDATOR_INPUT_FLAGS };
import {
  describeAuthorityReviewSubjectText,
  parseAuthorityReviewEnvelopeText,
  parseDeploymentIntentCoreText,
} from "./operator-policy-packet-core.mjs";
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
  RELEASE_MANIFEST_SIGSTORE_BLOCKER,
  assertProductionReleaseManifestSigstoreVerificationReceipt,
  canonicalReleaseManifestSigstoreVerificationReceiptText,
  releaseManifestSigstoreVerificationReceiptSha256,
  verifyReleaseManifestSigstoreAttestation,
} from "./release-manifest-sigstore-verifier.mjs";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const semanticValidatorScript = path.join(rootDir, "web", "scripts", "build-release-env.mjs");
const contractsProject = path.join(rootDir, "⚙️", "tinker-delegate", "contracts");
const defaultLedger = path.join(rootDir, "deployments", "base-sepolia.json");
const defaultDeploymentIntent = path.join(rootDir, ".release", "deployment-intent.json");
const defaultCvmLaunchIntent = path.join(rootDir, ".release", "cvm-launch-intent.json");
const authorityReviewDefaults = Object.freeze({
  fresh_deployment: ["deployment-intent.review.json", "deployment-intent.review-evidence.json"],
  cvm_launch: ["cvm-launch-intent.review.json", "cvm-launch-intent.review-evidence.json"],
  release_ceremony: ["final-authority.review.json", "final-authority.review-evidence.json"],
  live_activation: ["final-authority.review.json", "final-authority.review-evidence.json"],
});
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
const CONTRACT_POSTSTATE_VIEW_SIGNATURES = new Set([
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
  "approvalRequirementsFrozen()(bool)",
  "assetAdditionsFrozen()(bool)",
  "attestationBindingFrozen()(bool)",
  "attestationReleasePolicyHash()(bytes32)",
  "attestationVerifier()(address)",
  "challengeCount()(uint256)",
  "challengeExists(uint256)(bool)",
  "composeAdditionsFrozen()(bool)",
  "composeApprovalRequired()(bool)",
  "composePolicyFrozen()(bool)",
  "computeComposeRoot(bytes32[])(bytes32)",
  "computeManagerRoot(address[])(bytes32)",
  "computeSettlementPolicyEnabled()(bool)",
  "consumerComposeHashCount(address)(uint256)",
  "consumerEmergencyRevoked(address)(bool)",
  "consumerManagerAdditionsFrozen()(bool)",
  "consumerManagerCount()(uint256)",
  "consumerManagers(address)(bool)",
  "consumerRegistryFrozen()(bool)",
  "controllerChallengePaused(uint256)(bool)",
  "dealCount()(uint256)",
  "developer()(address)",
  "developerFeeBps()(uint16)",
  "developerFeeFrozen()(bool)",
  "emergencyHalted()(bool)",
  "evaluatorPolicies()(bytes32[3])",
  "evaluatorPolicySetFrozen()(bool)",
  "evaluatorPolicySetRoot()(bytes32)",
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
  "pendingAttestationBindingActivatesAt()(uint64)",
  "pendingAttestationReleasePolicyHash()(bytes32)",
  "pendingAttestationVerifier()(address)",
  "pendingComposeActivations(bytes32)(uint64)",
  "pendingComposeActivations(bytes32)(uint256)",
  "pendingComposeCount()(uint256)",
  "pendingComposeRoot()(bytes32)",
  "pendingEvaluatorPolicyActivations(bytes32)(uint256)",
  "pendingEvaluatorPolicyCount()(uint256)",
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
  "pendingRatePolicies(bytes32)(address,address,uint16,uint64)",
  "pendingRatePolicyCount()(uint256)",
  "pendingReleasePolicyActivatesAt()(uint64)",
  "pendingReleasePolicyCommitment()(bytes32)",
  "pendingRestartKeyDerivationProofHash()(bytes32)",
  "pendingResultVerifier()(address)",
  "pendingResultVerifierActivatesAt()(uint256)",
  "pendingTargetBootInfoHash()(bytes32)",
  "pendingTeeIdentityActivations(address)(uint64)",
  "pendingTeeIdentityActivations(address)(uint256)",
  "pendingTeeIdentityComposeHash(address)(bytes32)",
  "pendingTeeIdentityCount()(uint256)",
  "pendingWriter()(address)",
  "pendingWriterActivatesAt()(uint64)",
  "pendingWriterReleaseCommitment()(bytes32)",
  "productionRelease()(bool)",
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
  "restartKeyDerivationProofHash()(bytes32)",
  "resultVerifier()(address)",
  "reviewEligibleAt(uint256)(uint64)",
  "resultVerifierFrozen()(bool)",
  "targetBootInfoHash()(bytes32)",
  "teeIdentityAdditionsFrozen()(bool)",
  "teeIdentityApprovalRequired()(bool)",
  "teeIdentityComposeHash(address)(bytes32)",
  "totalConsumerComposeHashCount()(uint256)",
  "writer()(address)",
  "writerReleaseCommitment()(bytes32)",
  "writerRotationsFrozen()(bool)",
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
    "  --authority-review-envelope FILE Renewable review of the selected stage authority",
    "  --authority-review-evidence FILE Public evidence hash-bound by that review",
    "  --artifact-evidence FILE         Independent diligence deployment evidence",
    "  --arena-evidence FILE            Independent Arena deployment evidence",
    "  --anchor-writer-evidence FILE    Canonical bounded writer QVL artifact",
    "  --email-oracle-evidence FILE     Canonical bounded Email/KMS/restart evidence",
    "  --stage MODE                     fresh-deployment, cvm-launch, release-ceremony, or live-activation (default)",
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
    ledger: defaultLedger,
    deploymentIntent: defaultDeploymentIntent,
    cvmLaunchIntent: defaultCvmLaunchIntent,
    authorityReviewEnvelope: "",
    authorityReviewEvidence: "",
    authorityStage: "live_activation",
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
    ["--authority-review-envelope", "authorityReviewEnvelope"],
    ["--authority-review-evidence", "authorityReviewEvidence"],
    ["--artifact-evidence", "artifactEvidence"],
    ["--arena-evidence", "arenaEvidence"],
    ["--anchor-writer-evidence", "anchorWriterEvidence"],
    ["--email-oracle-evidence", "emailOracleEvidence"],
  ]);
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
      index += 1;
      continue;
    }
    if (!pathFlags.has(flag)) throw new Error(`unknown argument: ${flag}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${flag}`);
    args[pathFlags.get(flag)] = path.resolve(value);
    index += 1;
  }
  const [reviewEnvelopeName, reviewEvidenceName] = authorityReviewDefaults[args.authorityStage];
  if (!args.authorityReviewEnvelope) {
    args.authorityReviewEnvelope = path.join(rootDir, ".release", reviewEnvelopeName);
  }
  if (!args.authorityReviewEvidence) {
    args.authorityReviewEvidence = path.join(rootDir, ".release", reviewEvidenceName);
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
    "constructor(bool)",
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
      && callArguments.length <= 2
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
    || value.raw_secret_egress !== false
  ) return { valid: false };
  return { valid: true, receipt: value };
}

export function validateAuthorityReviewEvidence(file, expectedSha256) {
  return file?.valid === true
    && /^[0-9a-f]{64}$/.test(clean(file.sha256).toLowerCase())
    && /^sha256:[0-9a-f]{64}$/.test(clean(expectedSha256).toLowerCase())
    && clean(expectedSha256).toLowerCase() !== `sha256:${"0".repeat(64)}`
    && `sha256:${clean(file.sha256).toLowerCase()}` === clean(expectedSha256).toLowerCase();
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
  return initial?.exists === true
    && initial?.valid === true
    && current?.exists === true
    && current?.valid === true
    && Number.isInteger(initial.mode)
    && initial.mode === current.mode
    && /^[0-9a-f]{64}$/.test(clean(initial.sha256).toLowerCase())
    && clean(initial.sha256).toLowerCase() === clean(current.sha256).toLowerCase();
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

export async function inspectFile(filePath, { json = false, mode0600 = false } = {}) {
  if (!filePath) return { exists: false, valid: false, mode: null, value: null };
  let handle;
  try {
    handle = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const mode = Number(before.mode & 0o777n);
    if (!before.isFile() || before.size < 2n || before.size > BigInt(MAX_INPUT_BYTES)) {
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
    return {
      exists: true,
      valid: !mode0600 || mode === 0o600,
      mode,
      value,
      text,
      sha256: createHash("sha256").update(bytes).digest("hex"),
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
) {
  try {
    const authorityPins = {
      expectedDeploymentIntentSha256: expectedIntentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256,
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
      developer_matches_operator: scalarAssertions([["developer()(address)", [], operator]]),
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
    TinkerAccountEncumbrance: {
      owner_matches_operator: scalarAssertions([["owner()(address)", [], operator]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
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

export function finalPoststatePolicies(finalAuthority, finalAuthoritySha256) {
  const diligence = finalAuthority?.contracts?.diligence_room || {};
  const compute = finalAuthority?.contracts?.compute_credit_vault || {};
  const email = finalAuthority?.contracts?.email_oracle_auth || {};
  const tinker = finalAuthority?.contracts?.tinker_account_encumbrance || {};
  const challenge = finalAuthority?.contracts?.challenge_registry || {};
  const anchor = finalAuthority?.execution_policy?.rollback_anchor_target || {};
  const operator = finalAuthority?.operator_address;
  const diligenceCompose = `0x${clean(diligence.release_admission?.compose_hash)}`;
  const computeCompose = `0x${clean(compute.compose_hash)}`;
  const finalAuthorityCommitment = /^sha256:[0-9a-f]{64}$/.test(finalAuthoritySha256)
    ? `0x${finalAuthoritySha256.slice("sha256:".length)}`
    : "";
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
      developer_matches_final_authority: scalarAssertions([[
        "developer()(address)", [], diligence.developer,
      ]]),
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
      global_sequence_at_least_one: (read) => {
        const value = read("globalSequence()(uint256)", []);
        return /^(?:[1-9][0-9]*)$/.test(clean(value));
      },
      global_head_matches_final_authority_digest: scalarAssertions([[
        "globalHead()(bytes32)", [], finalAuthorityCommitment,
      ]]),
    },
    TinkerAccountEncumbrance: {
      owner_matches_final_authority: scalarAssertions([["owner()(address)", [], tinker.owner]]),
      pending_owner_unset: scalarAssertions([["pendingOwner()(address)", [], ZERO_ADDRESS]]),
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
    statelessPoststateException: CONTRACT_STATELESS_POSTSTATE_EXCEPTION,
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
  snapshotBlockNumber,
  rpcUrl,
  runner,
}) {
  const expectedMap = CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE[mode] || {};
  const policies = mode === "fresh_fail_closed"
    ? freshPoststatePolicies(deploymentIntent, receipt)
    : finalPoststatePolicies(finalAuthority, finalAuthoritySha256);
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
    const policy = policies[name] || {};
    const valid = Boolean(contract)
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
    poststateValid: poststates.length === 6 && poststates.every((entry) => entry.valid),
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
  releaseSha = "",
  releaseWorktree = rootDir,
  reconstructionCommandRunner,
  secondaryReconstructionCommandRunner,
  independentReconstruction = null,
  secondaryIndependentReconstruction = null,
  finalAuthority,
  finalAuthoritySha256 = "",
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
  const valid = immutableProvenanceValid
    && broadcastTransactionProvenanceValid
    && broadcastTransactionRpcAgreement
    && independentReconstructionValid
    && independentReconstructionRpcAgreement
    && secondaryRuntimeCodeMatchCount === receipt.contracts.length
    && poststateRpcAgreement
    && snapshotBlockHashVerified;
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
    statelessPoststateException: CONTRACT_STATELESS_POSTSTATE_EXCEPTION,
  };
}

export function verifyContractDeploymentChainEvidence(options = {}) {
  return verifyContractDeploymentChainEvidenceInternal({
    contractDeploymentReceipt: options.contractDeploymentReceipt,
    deploymentIntent: options.deploymentIntent,
    deploymentIntentText: options.deploymentIntentText,
    deploymentIntentSha256: options.deploymentIntentSha256,
    releaseSha: options.releaseSha,
    releaseWorktree: rootDir,
    finalAuthority: options.finalAuthority,
    finalAuthoritySha256: options.finalAuthoritySha256,
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

function resolveEvidencePaths(args, env) {
  return {
    release: args.release || clean(env.ACTIVATION_RELEASE_CANDIDATE_PATH),
    releaseCore: args.releaseCore || clean(env.FINAL_RELEASE_AUTHORITY_CORE_PATH),
    deploymentIntent: args.deploymentIntent,
    cvmLaunchIntent: args.cvmLaunchIntent,
    authorityReviewEnvelope: args.authorityReviewEnvelope,
    ledger: args.ledger,
    artifactEvidence:
      args.artifactEvidence || clean(env.ACTIVATION_ARTIFACT_EVIDENCE_PATH),
    arenaEvidence: args.arenaEvidence || clean(env.ACTIVATION_ARENA_EVIDENCE_PATH),
    anchorWriterEvidence:
      args.anchorWriterEvidence || clean(env.ACTIVATION_ANCHOR_WRITER_EVIDENCE_PATH),
    emailOracleEvidence:
      args.emailOracleEvidence || clean(env.ACTIVATION_EMAIL_ORACLE_EVIDENCE_PATH),
  };
}

export async function collectSnapshot(args) {
  const checkedAtMs = Date.now();
  const envFile = await inspectFile(args.env);
  const fileEnv = envFile.exists ? parseEnvText(envFile.text) : {};
  const env = { ...fileEnv, ...process.env };
  const evidencePaths = resolveEvidencePaths(args, env);

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
    authorityReviewEnvelopeFile,
    authorityReviewEvidenceFile,
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
      inspectFile(args.deploymentIntent),
      inspectFile(args.cvmLaunchIntent),
      inspectFile(args.authorityReviewEnvelope),
      inspectFile(args.authorityReviewEvidence),
      inspectFile(evidencePaths.release, { json: true }),
      inspectFile(evidencePaths.releaseCore, { json: true }),
      inspectFile(evidencePaths.ledger, { json: true }),
      inspectFile(evidencePaths.artifactEvidence, { json: true }),
      inspectFile(evidencePaths.arenaEvidence, { json: true }),
      inspectFile(evidencePaths.anchorWriterEvidence, { json: true, mode0600: true }),
      inspectFile(evidencePaths.emailOracleEvidence),
    ]);

  const deploymentIntentResult = deploymentIntentFile.valid === true
    ? parseDeploymentIntentCoreText(deploymentIntentFile.text || "")
    : { ok: false, errors: [] };
  const preReviewContractDeploymentReceipt = deploymentIntentResult.ok === true
    ? inspectFreshContractDeploymentReceipt(
      ledger.value,
      clean(deploymentIntentResult.receipt?.deploymentIntentSha256).toLowerCase(),
      clean(deploymentIntentResult.receipt?.releaseSha).toLowerCase(),
      clean(
        deploymentIntentResult.intent?.release
          ?.reviewerAuthorityGenesisAcceptanceSha256,
      ).toLowerCase(),
    )
    : { valid: false, receipt: null, sha256: "", contractCount: 0 };
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
  const reviewSubjectDescriptor = args.authorityStage === "fresh_deployment"
    ? deploymentIntentDescriptor
    : args.authorityStage === "cvm_launch"
      ? cvmLaunchIntentDescriptor
      : finalAuthorityDescriptor;
  const authorityDependencies = args.authorityStage === "fresh_deployment"
    ? undefined
    : args.authorityStage === "cvm_launch"
      ? {
        deploymentIntent: deploymentIntentResult.intent,
        freshContractDeploymentReceipt: preReviewContractDeploymentReceipt.receipt,
      }
      : {
        deploymentIntent: deploymentIntentResult.intent,
        cvmLaunchIntent: cvmLaunchIntentResult.intent,
      };
  const authorityReviewResult = authorityReviewEnvelopeFile.valid === true
    ? parseAuthorityReviewEnvelopeText(authorityReviewEnvelopeFile.text || "", {
      checkedAtMs,
      subjectDescriptor: reviewSubjectDescriptor,
      authorityDependencies,
    })
    : { ok: false, errors: [] };
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
  const finalAuthoritySha256 = finalAuthorityDescriptor?.subjectKind
      === "final_release_authority"
    ? clean(finalAuthorityDescriptor.subjectSha256).toLowerCase()
    : "";
  const reviewEnvelopeSha256 = clean(
    authorityReviewResult?.receipt?.reviewEnvelopeSha256,
  ).toLowerCase();
  const reviewEvidenceSha256 = clean(
    authorityReviewResult?.receipt?.reviewEvidenceSha256,
  ).toLowerCase();
  const reviewEvidenceValid = validateAuthorityReviewEvidence(
    authorityReviewEvidenceFile,
    reviewEvidenceSha256,
  );
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
  const cvmLaunchDescriptorBindingsValid = cvmLaunchIntentResult.ok === true
    && CVM_LAUNCH_DOMAINS.every((domain) => (
      descriptorSha256ByDomain[domain] === actualDescriptorSha256ByDomain[domain]
      && descriptorSha256ByDomain[domain] === topologyDescriptorSha256ByDomain[domain]
    ));
  const contractDeploymentReceipt = preReviewContractDeploymentReceipt;
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
    && Object.values(descriptorFilesByDomain).every((file) => file?.valid === true)
    && Object.values(descriptorInspectionsByDomain).every((inspection) => (
      inspection?.valid === true
    ));
  const contractDeploymentChainEvidence = verifyContractDeploymentChainEvidence({
    contractDeploymentReceipt: contractDeploymentReceipt.receipt,
    deploymentIntent: deploymentIntentResult.intent,
    deploymentIntentText: deploymentIntentFile.text || "",
    deploymentIntentSha256,
    releaseSha: authorityReleaseSha,
    finalAuthority: finalAuthorityDescriptor.subject,
    finalAuthoritySha256,
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
  const reviewEnvelopeFileHashBound = authorityReviewResult.ok === true
    && reviewEnvelopeSha256
      === `sha256:${clean(authorityReviewEnvelopeFile.sha256).toLowerCase()}`;
  const liveCandidateAuthority = releaseCandidate.value?.operator_policy || {};
  const semanticInputsReady = args.authorityStage === "live_activation"
    && !args.skipNetwork
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
    && authorityReviewResult.ok === true
    && reviewEnvelopeFileHashBound
    && reviewEvidenceValid
    && artifactEvidence.valid === true
    && arenaEvidence.valid === true
    && anchorWriterEvidence.valid === true
    && emailOracleEvidence.valid === true;
  const semanticStableBindings = [
    { path: evidencePaths.release, initial: releaseCandidate, options: { json: true } },
    { path: evidencePaths.releaseCore, initial: releaseCore, options: { json: true } },
    { path: evidencePaths.deploymentIntent, initial: deploymentIntentFile },
    { path: evidencePaths.authorityReviewEnvelope, initial: authorityReviewEnvelopeFile },
    { path: evidencePaths.ledger, initial: ledger, options: { json: true } },
    { path: evidencePaths.artifactEvidence, initial: artifactEvidence, options: { json: true } },
    { path: evidencePaths.arenaEvidence, initial: arenaEvidence, options: { json: true } },
    {
      path: evidencePaths.anchorWriterEvidence,
      initial: anchorWriterEvidence,
      options: { json: true, mode0600: true },
    },
    { path: evidencePaths.emailOracleEvidence, initial: emailOracleEvidence },
  ];
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
  let finalInputFilesStable;
  if (args.authorityStage === "fresh_deployment") {
    finalInputFilesStable = await validateStableFileBindings([
      { path: args.env, initial: envFile },
      { path: args.deploymentIntent, initial: deploymentIntentFile },
      { path: args.authorityReviewEnvelope, initial: authorityReviewEnvelopeFile },
      { path: args.authorityReviewEvidence, initial: authorityReviewEvidenceFile },
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
      { path: args.deploymentIntent, initial: deploymentIntentFile },
      { path: args.cvmLaunchIntent, initial: cvmLaunchIntentFile },
      { path: args.authorityReviewEnvelope, initial: authorityReviewEnvelopeFile },
      { path: args.authorityReviewEvidence, initial: authorityReviewEvidenceFile },
      { path: evidencePaths.ledger, initial: ledger, options: { json: true } },
    ];
    if (args.authorityStage !== "cvm_launch") {
      readinessStableBindings.push(...semanticStableBindings.filter((binding) => ![
        evidencePaths.deploymentIntent,
        evidencePaths.authorityReviewEnvelope,
        evidencePaths.ledger,
      ].includes(binding.path)));
    }
    finalInputFilesStable = await validateStableFileBindings(readinessStableBindings);
    if (!finalInputFilesStable) {
      activationReadinessSnapshot = null;
      activationReadinessSnapshotSha256 = "";
    }
  }
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
      authorityReviewEnvelope: authorityReviewEnvelopeFile,
      authorityReviewEvidence: authorityReviewEvidenceFile,
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
    contractDeploymentChainEvidence,
    activationReadinessSnapshot,
    activationReadinessSnapshotSha256,
    activationReadinessValidationNowMs: reportCheckedAtMs,
    releaseAuthority: {
      deploymentIntentValid: deploymentIntentResult.ok === true,
      deploymentIntentFileHashBound: deploymentIntentFileHashBound && finalInputFilesStable,
      deploymentIntentSha256,
      reviewerAuthorityGenesisAcceptanceSha256,
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
      reviewEnvelopeValid: authorityReviewResult.ok === true,
      reviewEnvelopeFileHashBound: reviewEnvelopeFileHashBound && finalInputFilesStable,
      reviewEnvelopeSha256,
      reviewSubjectKind: clean(authorityReviewResult?.receipt?.subjectKind),
      reviewSubjectSha256: clean(authorityReviewResult?.receipt?.subjectSha256).toLowerCase(),
      reviewEvidenceValid: reviewEvidenceValid && finalInputFilesStable,
      reviewEvidenceFileHashBound: reviewEvidenceValid && finalInputFilesStable,
      reviewEvidenceSha256,
      approvedAt: clean(authorityReviewResult?.envelope?.approved_at),
      expiresAt: clean(authorityReviewResult?.envelope?.expires_at),
      checkedAtMs: reportCheckedAtMs,
    },
    cvmLaunchAuthority: {
      valid: cvmLaunchIntentResult.ok === true,
      fileHashBound: cvmLaunchIntentResult.ok === true
        && /^sha256:[0-9a-f]{64}$/.test(cvmLaunchIntentSha256),
      sha256: cvmLaunchIntentSha256,
      deploymentIntentSha256: clean(cvmLaunchReceipt?.deploymentIntentSha256).toLowerCase(),
      releaseSha: clean(cvmLaunchReceipt?.releaseSha).toLowerCase(),
      reviewEnvelopeValid: authorityReviewResult.ok === true,
      reviewEnvelopeFileHashBound: reviewEnvelopeFileHashBound && finalInputFilesStable,
      reviewEnvelopeSha256,
      reviewSubjectKind: clean(authorityReviewResult?.receipt?.subjectKind),
      reviewSubjectSha256: clean(authorityReviewResult?.receipt?.subjectSha256).toLowerCase(),
      reviewEvidenceValid: reviewEvidenceValid && finalInputFilesStable,
      reviewEvidenceFileHashBound: reviewEvidenceValid && finalInputFilesStable,
      reviewEvidenceSha256,
      approvedAt: clean(authorityReviewResult?.envelope?.approved_at),
      expiresAt: clean(authorityReviewResult?.envelope?.expires_at),
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
