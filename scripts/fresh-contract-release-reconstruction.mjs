#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import {
  canonicalArtifactSha256,
  DEPLOYMENT_TOOLCHAIN_AUTHORITY,
  parseDeploymentIntentCoreText,
} from "./operator-policy-packet-core.mjs";
import { FRESH_DEPLOYMENT_TRANSACTION_SPEC } from "./cvm-launch-intent-core.mjs";

export const FRESH_CONTRACT_RELEASE_RECONSTRUCTION_SCHEMA =
  "dnai.fresh-contract-release-reconstruction.v2";
export const FRESH_CONTRACT_RELEASE_RECONSTRUCTION_DOMAIN =
  "dnai-wikigen/fresh-contract-release-reconstruction/v2\0";
export const FRESH_CONTRACT_RELEASE_RECONSTRUCTION_TRUTH_STATUS =
  "expected_inputs_and_runtime_hashes_derived_from_immutable_release_and_reviewed_intent_not_receipt_or_chain_authority";

const MAX_COMMAND_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_RECONSTRUCTION_BYTES = 2 * 1024 * 1024;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const BYTECODE = /^0x(?:[0-9a-f]{2})+$/;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const RECONSTRUCTION_PAYLOAD_FIELDS = Object.freeze([
  "deployment_intent_sha256",
  "network",
  "operator_address",
  "release_sha",
  "reviewer_authority_genesis_acceptance_sha256",
  "schema",
  "source_proof",
  "transactions",
  "truth_status",
]);
const RECONSTRUCTION_TRANSACTION_FIELDS = Object.freeze([
  "contract_key",
  "contract_name",
  "expected_input",
  "expected_input_sha256",
  "expected_runtime_code_hash",
  "function_signature",
  "sequence",
  "transaction_type",
]);
const RECONSTRUCTION_SOURCE_PROOF_FIELDS = Object.freeze([
  "canonical_forge_script",
  "clean_worktree",
  "detached_head",
  "submodules_clean",
  "toolchain",
  "worktree_head",
]);

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function exactLowerHex(value, pattern, label) {
  const normalized = String(value).trim().toLowerCase();
  if (!pattern.test(normalized) || /^0x0+$/.test(normalized)) {
    throw new Error(`${label} is not canonical nonzero lowercase hex`);
  }
  return normalized;
}

function exactRecord(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} fields do not match the exact schema`);
  }
  return value;
}

function safeUint(value, label) {
  const text = String(value);
  if (!/^(?:0|[1-9][0-9]*)$/.test(text)) throw new Error(`${label} must be canonical decimal`);
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(`${label} exceeds the safe integer range`);
  return parsed;
}

function normalizeDeploymentToolchainAuthority(value, label) {
  const authority = exactRecord(value, ["foundry", "solidity"], label);
  exactRecord(
    authority.foundry,
    ["buildProfile", "castExecutableSha256", "castVersion", "commitSha", "forgeVersion"],
    `${label}.foundry`,
  );
  exactRecord(
    authority.solidity,
    [
      "bytecodeHash",
      "cborMetadata",
      "compilerVersion",
      "configuredVersion",
      "evmVersion",
      "libraries",
      "optimizer",
      "optimizerRuns",
      "profile",
      "useLiteralContent",
      "viaIr",
    ],
    `${label}.solidity`,
  );
  if (JSON.stringify(sortedObject(authority))
    !== JSON.stringify(sortedObject(DEPLOYMENT_TOOLCHAIN_AUTHORITY))) {
    throw new Error(`${label} does not match the supported reviewed toolchain`);
  }
  return {
    foundry: { ...DEPLOYMENT_TOOLCHAIN_AUTHORITY.foundry },
    solidity: {
      ...DEPLOYMENT_TOOLCHAIN_AUTHORITY.solidity,
      libraries: [],
    },
  };
}

function assertFoundryBinaryIdentity(output, tool, authority) {
  const lines = String(output).trim().split(/\r?\n/);
  if (lines.length !== 4
    || lines[0] !== `${tool} Version: ${authority[`${tool}Version`]}`
    || lines[1] !== `Commit SHA: ${authority.commitSha}`
    || !/^Build Timestamp: [^\r\n]+$/.test(lines[2])
    || lines[3] !== `Build Profile: ${authority.buildProfile}`) {
    throw new Error(`${tool} binary identity does not match the reviewed deployment-intent toolchain`);
  }
}

function assertFoundryConfig(configText, authority) {
  let config;
  try {
    config = JSON.parse(configText);
  } catch {
    throw new Error("Foundry compilation configuration is not valid JSON");
  }
  const expected = authority.solidity;
  if (config.solc !== expected.configuredVersion
    || config.optimizer !== expected.optimizer
    || config.optimizer_runs !== expected.optimizerRuns
    || config.via_ir !== expected.viaIr
    || config.evm_version !== expected.evmVersion
    || config.bytecode_hash !== expected.bytecodeHash
    || config.cbor_metadata !== expected.cborMetadata
    || config.use_literal_content !== expected.useLiteralContent
    || !Array.isArray(config.libraries)
    || config.libraries.length !== expected.libraries.length) {
    throw new Error("Foundry compilation settings do not match the reviewed deployment-intent toolchain");
  }
}

function assertContractArtifactMetadata(metadataText, contractName, authority) {
  let metadata;
  try {
    metadata = JSON.parse(metadataText);
  } catch {
    throw new Error(`${contractName} compiler metadata is not valid JSON`);
  }
  const expected = authority.solidity;
  const optimizer = metadata?.settings?.optimizer;
  const libraries = metadata?.settings?.libraries;
  const metadataSettings = metadata?.settings?.metadata;
  if (metadata?.compiler?.version !== expected.compilerVersion
    || optimizer?.enabled !== expected.optimizer
    || optimizer?.runs !== expected.optimizerRuns
    || metadata?.settings?.viaIR !== expected.viaIr
    || metadata?.settings?.evmVersion !== expected.evmVersion
    || metadataSettings?.bytecodeHash !== expected.bytecodeHash
    || Object.keys(metadataSettings || {}).length !== 1
    || !libraries
    || Array.isArray(libraries)
    || Object.keys(libraries).length !== 0) {
    throw new Error(`${contractName} artifact compiler metadata does not match the reviewed toolchain`);
  }
}

function rawInputSha256(input) {
  const normalized = exactLowerHex(input, BYTECODE, "reconstructed transaction input");
  return `sha256:${createHash("sha256")
    .update(Buffer.from(normalized.slice(2), "hex"))
    .digest("hex")}`;
}

function defaultCommandRunner({ command, args, cwd, env }) {
  try {
    return execFileSync(command, args, {
      cwd,
      env,
      encoding: "utf8",
      maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
      timeout: 120_000,
      killSignal: "SIGKILL",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    throw new Error(`read-only reconstruction command failed: ${command}`);
  }
}

function quantityToSafeUint(value, label) {
  if (typeof value === "number") return safeUint(String(value), label);
  if (typeof value !== "string") throw new Error(`${label} is missing`);
  if (/^0x[0-9a-fA-F]+$/.test(value)) return safeUint(BigInt(value).toString(10), label);
  return safeUint(value, label);
}

function canonicalReconstructionPayload(value) {
  return JSON.stringify(sortedObject(value));
}

function normalizeFreshContractReleaseReconstructionPayload(value) {
  const hasDigest = Boolean(
    value && typeof value === "object" && Object.hasOwn(value, "reconstruction_sha256"),
  );
  const parsed = exactRecord(
    value,
    hasDigest
      ? [...RECONSTRUCTION_PAYLOAD_FIELDS, "reconstruction_sha256"]
      : RECONSTRUCTION_PAYLOAD_FIELDS,
    "fresh contract release reconstruction",
  );
  if (parsed.schema !== FRESH_CONTRACT_RELEASE_RECONSTRUCTION_SCHEMA
    || parsed.truth_status !== FRESH_CONTRACT_RELEASE_RECONSTRUCTION_TRUTH_STATUS) {
    throw new Error("fresh contract release reconstruction schema or truth status mismatch");
  }
  if (!SHA40.test(parsed.release_sha)) {
    throw new Error("fresh contract release reconstruction release SHA is invalid");
  }
  if (!SHA256.test(parsed.deployment_intent_sha256)
    || parsed.deployment_intent_sha256 === `sha256:${"0".repeat(64)}`) {
    throw new Error("fresh contract release reconstruction intent SHA-256 is invalid");
  }
  if (!SHA256.test(parsed.reviewer_authority_genesis_acceptance_sha256)
    || parsed.reviewer_authority_genesis_acceptance_sha256
      === `sha256:${"0".repeat(64)}`) {
    throw new Error(
      "fresh contract release reconstruction reviewer genesis acceptance SHA-256 is invalid",
    );
  }
  const operatorAddress = exactLowerHex(
    parsed.operator_address,
    ADDRESS,
    "fresh contract release reconstruction operator",
  );
  const network = exactRecord(
    parsed.network,
    ["chain_id", "name", "snapshot_block", "snapshot_block_hash"],
    "fresh contract release reconstruction network",
  );
  if (network.chain_id !== 84_532 || network.name !== "base-sepolia") {
    throw new Error("fresh contract release reconstruction network is not Base Sepolia");
  }
  const snapshotBlock = safeUint(network.snapshot_block, "reconstruction snapshot block");
  if (snapshotBlock < 1) throw new Error("reconstruction snapshot block must be positive");
  const snapshotBlockHash = exactLowerHex(
    network.snapshot_block_hash,
    BYTES32,
    "reconstruction snapshot block hash",
  );
  const sourceProof = exactRecord(
    parsed.source_proof,
    RECONSTRUCTION_SOURCE_PROOF_FIELDS,
    "fresh contract release reconstruction source proof",
  );
  if (sourceProof.clean_worktree !== true
    || sourceProof.detached_head !== true
    || sourceProof.submodules_clean !== true
    || sourceProof.worktree_head !== parsed.release_sha
    || sourceProof.canonical_forge_script
      !== "⚙️/tinker-delegate/contracts/script/DeployFreshSuite.s.sol") {
    throw new Error("fresh contract release reconstruction source proof mismatch");
  }
  const toolchain = normalizeDeploymentToolchainAuthority(
    sourceProof.toolchain,
    "fresh contract release reconstruction source proof toolchain",
  );
  if (!Array.isArray(parsed.transactions)
    || parsed.transactions.length !== FRESH_DEPLOYMENT_TRANSACTION_SPEC.length) {
    throw new Error("fresh contract release reconstruction must contain exactly 13 transactions");
  }
  const transactions = FRESH_DEPLOYMENT_TRANSACTION_SPEC.map((spec, index) => {
    const entry = exactRecord(
      parsed.transactions[index],
      RECONSTRUCTION_TRANSACTION_FIELDS,
      `fresh contract release reconstruction transactions[${index}]`,
    );
    if (entry.sequence !== index
      || entry.contract_key !== spec.contract_key
      || entry.contract_name !== spec.name
      || entry.transaction_type !== spec.transaction_type
      || entry.function_signature !== spec.function_signature) {
      throw new Error(`fresh contract release reconstruction transaction ${index} order mismatch`);
    }
    const expectedInput = exactLowerHex(
      entry.expected_input,
      BYTECODE,
      `fresh contract release reconstruction transaction ${index} input`,
    );
    if (entry.transaction_type === "CALL" && expectedInput.length < 10) {
      throw new Error(`fresh contract release reconstruction CALL ${index} lacks a selector`);
    }
    const expectedInputSha256 = rawInputSha256(expectedInput);
    if (entry.expected_input_sha256 !== expectedInputSha256) {
      throw new Error(`fresh contract release reconstruction transaction ${index} input digest mismatch`);
    }
    let expectedRuntimeCodeHash = null;
    if (entry.transaction_type === "CREATE") {
      expectedRuntimeCodeHash = exactLowerHex(
        entry.expected_runtime_code_hash,
        BYTES32,
        `fresh contract release reconstruction transaction ${index} runtime hash`,
      );
    } else if (entry.expected_runtime_code_hash !== null) {
      throw new Error(`fresh contract release reconstruction CALL ${index} runtime hash must be null`);
    }
    return {
      sequence: index,
      contract_key: spec.contract_key,
      contract_name: spec.name,
      transaction_type: spec.transaction_type,
      function_signature: spec.function_signature,
      expected_input: expectedInput,
      expected_input_sha256: expectedInputSha256,
      expected_runtime_code_hash: expectedRuntimeCodeHash,
    };
  });
  return {
    schema: FRESH_CONTRACT_RELEASE_RECONSTRUCTION_SCHEMA,
    truth_status: FRESH_CONTRACT_RELEASE_RECONSTRUCTION_TRUTH_STATUS,
    release_sha: parsed.release_sha,
    deployment_intent_sha256: parsed.deployment_intent_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      parsed.reviewer_authority_genesis_acceptance_sha256,
    network: {
      chain_id: 84_532,
      name: "base-sepolia",
      snapshot_block: snapshotBlock,
      snapshot_block_hash: snapshotBlockHash,
    },
    operator_address: operatorAddress,
    source_proof: {
      clean_worktree: true,
      detached_head: true,
      submodules_clean: true,
      worktree_head: parsed.release_sha,
      canonical_forge_script: "⚙️/tinker-delegate/contracts/script/DeployFreshSuite.s.sol",
      toolchain,
    },
    transactions,
  };
}

export function freshContractReleaseReconstructionDigest(value) {
  const normalized = normalizeFreshContractReleaseReconstructionPayload(value);
  return `sha256:${createHash("sha256")
    .update(Buffer.from(FRESH_CONTRACT_RELEASE_RECONSTRUCTION_DOMAIN, "utf8"))
    .update(Buffer.from(canonicalReconstructionPayload(normalized), "utf8"))
    .digest("hex")}`;
}

export function normalizeFreshContractReleaseReconstruction(value) {
  const payload = normalizeFreshContractReleaseReconstructionPayload(value);
  if (!Object.hasOwn(value, "reconstruction_sha256")
    || !SHA256.test(value.reconstruction_sha256)
    || value.reconstruction_sha256 !== freshContractReleaseReconstructionDigest(payload)) {
    throw new Error("fresh contract release reconstruction authority digest mismatch");
  }
  return { ...payload, reconstruction_sha256: value.reconstruction_sha256 };
}

export function canonicalFreshContractReleaseReconstructionText(value) {
  return `${JSON.stringify(
    sortedObject(normalizeFreshContractReleaseReconstruction(value)),
    null,
    2,
  )}\n`;
}

export function reconstructFreshContractRelease({
  releaseWorktree,
  expectedReleaseSha,
  deploymentIntentText,
  rpcUrl,
  snapshotBlock,
  snapshotBlockHash,
  commandRunner = defaultCommandRunner,
}) {
  if (!path.isAbsolute(releaseWorktree) || !fs.existsSync(releaseWorktree)) {
    throw new Error("release worktree must be an existing absolute path");
  }
  const worktreeStat = fs.lstatSync(releaseWorktree);
  if (worktreeStat.isSymbolicLink() || !worktreeStat.isDirectory()) {
    throw new Error("release worktree must be a non-symlink directory");
  }
  if (!SHA40.test(expectedReleaseSha)) {
    throw new Error("expected release SHA must be lowercase 40-hex");
  }
  if (typeof rpcUrl !== "string" || rpcUrl.length < 1 || rpcUrl.length > 4096) {
    throw new Error("read-only reconstruction RPC URL is missing or overlong");
  }
  const normalizedSnapshotBlock = safeUint(String(snapshotBlock), "snapshot block");
  if (normalizedSnapshotBlock < 1) throw new Error("snapshot block must be greater than zero");
  const normalizedSnapshotHash = exactLowerHex(
    snapshotBlockHash,
    BYTES32,
    "snapshot block hash",
  );

  const parsedIntent = parseDeploymentIntentCoreText(deploymentIntentText);
  if (!parsedIntent.ok) {
    throw new Error("deployment intent failed canonical semantic validation");
  }
  const intent = parsedIntent.intent;
  const deploymentIntentSha256 = canonicalArtifactSha256(intent);
  if (!SHA256.test(deploymentIntentSha256)
    || intent.release.releaseSha !== expectedReleaseSha) {
    throw new Error("deployment intent release does not match expected RELEASE_SHA");
  }
  const reviewerAuthorityGenesisAcceptanceSha256 =
    intent.release.reviewerAuthorityGenesisAcceptanceSha256;
  if (!SHA256.test(reviewerAuthorityGenesisAcceptanceSha256)
    || reviewerAuthorityGenesisAcceptanceSha256 === `sha256:${"0".repeat(64)}`) {
    throw new Error(
      "deployment intent lacks the signed reviewer authority genesis acceptance digest",
    );
  }
  const deploymentIntentSha256Bytes32 =
    `0x${deploymentIntentSha256.slice("sha256:".length)}`;
  const reviewerAuthorityGenesisAcceptanceSha256Bytes32 =
    `0x${reviewerAuthorityGenesisAcceptanceSha256.slice("sha256:".length)}`;
  const reviewedToolchain = normalizeDeploymentToolchainAuthority(
    intent.release.toolchain,
    "deployment intent release toolchain",
  );

  const commandEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    USER: process.env.USER,
    TMPDIR: process.env.TMPDIR,
  };
  const run = (command, args, options = {}) => String(commandRunner({
    command,
    args,
    cwd: options.cwd ?? releaseWorktree,
    env: { ...commandEnv, ...(options.env ?? {}) },
  })).trim();

  const sourceHead = run("git", ["rev-parse", "HEAD"]).toLowerCase();
  const sourceBranch = run("git", ["rev-parse", "--abbrev-ref", "HEAD"]);
  const sourceStatus = run("git", [
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
    "--ignore-submodules=none",
  ]);
  const submoduleStatus = run("git", ["submodule", "status", "--recursive"]);
  const submoduleWorktreeStatus = run("git", [
    "submodule",
    "foreach",
    "--recursive",
    "--quiet",
    "git status --porcelain=v1 --untracked-files=all --ignore-submodules=none",
  ]);
  const sourceTopLevel = path.resolve(run("git", ["rev-parse", "--show-toplevel"]));
  const submoduleStatusClean = submoduleStatus === ""
    || submoduleStatus.split(/\r?\n/).every((line) => /^[ -][0-9a-f]{40}\s/.test(line));
  if (sourceHead !== expectedReleaseSha
    || sourceBranch !== "HEAD"
    || sourceStatus !== ""
    || submoduleWorktreeStatus !== ""
    || !submoduleStatusClean
    || sourceTopLevel !== path.resolve(releaseWorktree)) {
    throw new Error("release reconstruction requires an exact clean detached RELEASE_SHA worktree");
  }

  const contractsDirectory = path.join(
    releaseWorktree,
    "⚙️",
    "tinker-delegate",
    "contracts",
  );
  if (!fs.existsSync(path.join(contractsDirectory, "script", "DeployFreshSuite.s.sol"))) {
    throw new Error("release worktree lacks the canonical DeployFreshSuite source");
  }
  const toolchainEnv = { FOUNDRY_PROFILE: "default" };
  assertFoundryBinaryIdentity(
    run("forge", ["--version"], { cwd: contractsDirectory, env: toolchainEnv }),
    "forge",
    reviewedToolchain.foundry,
  );
  assertFoundryBinaryIdentity(
    run("cast", ["--version"], { cwd: contractsDirectory, env: toolchainEnv }),
    "cast",
    reviewedToolchain.foundry,
  );
  assertFoundryConfig(
    run("forge", ["config", "--json"], { cwd: contractsDirectory, env: toolchainEnv }),
    reviewedToolchain,
  );

  const chainId = safeUint(run("cast", ["chain-id", "--rpc-url", rpcUrl]), "RPC chain id");
  if (chainId !== 84_532) throw new Error("release reconstruction RPC is not Base Sepolia");
  let block;
  try {
    block = JSON.parse(run("cast", [
      "block",
      String(normalizedSnapshotBlock),
      "--rpc-url",
      rpcUrl,
      "--json",
    ]));
  } catch {
    throw new Error("release reconstruction snapshot block could not be read");
  }
  const observedBlockNumber = quantityToSafeUint(block.number, "observed snapshot block");
  const observedBlockHash = exactLowerHex(block.hash, BYTES32, "observed snapshot block hash");
  if (observedBlockNumber !== normalizedSnapshotBlock
    || observedBlockHash !== normalizedSnapshotHash) {
    throw new Error("release reconstruction snapshot block number or hash changed");
  }

  const buildDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-release-reconstruction-"));
  const foundryEnv = {
    FOUNDRY_OUT: path.join(buildDirectory, "out"),
    FOUNDRY_CACHE_PATH: path.join(buildDirectory, "cache"),
    FOUNDRY_BROADCAST: path.join(buildDirectory, "broadcast"),
    FOUNDRY_PROFILE: "default",
  };

  const operator = exactLowerHex(
    intent.deploymentControl.operatorAddress,
    ADDRESS,
    "deployment operator",
  );
  const computeDeveloper = exactLowerHex(
    intent.staticContractInputs.computeCreditVault.developer,
    ADDRESS,
    "compute developer",
  );
  const accountCommitment = exactLowerHex(
    intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment,
    BYTES32,
    "Tinker account commitment",
  );
  const contractPolicy = intent.numericPolicy.contract;
  const castRead = (args) => run("cast", args, { cwd: contractsDirectory, env: foundryEnv });
  const forgeRead = (args) => run("forge", args, { cwd: contractsDirectory, env: foundryEnv });

  const transactions = [];
  const create = ({ sequence, contractKey, contractName, signature, args }) => {
    assertContractArtifactMetadata(
      forgeRead(["inspect", contractName, "metadata"]),
      contractName,
      reviewedToolchain,
    );
    const creationCode = exactLowerHex(
      forgeRead(["inspect", contractName, "bytecode"]),
      BYTECODE,
      `${contractName} release bytecode`,
    );
    const encodedArgs = signature === "constructor()"
      ? "0x"
      : exactLowerHex(
        castRead(["abi-encode", signature, ...args]),
        BYTECODE,
        `${contractName} constructor arguments`,
      );
    const expectedInput = `0x${creationCode.slice(2)}${encodedArgs.slice(2)}`;
    const runtimeArgs = [
      "call",
      "--from",
      operator,
      "--rpc-url",
      rpcUrl,
      "--block",
      String(normalizedSnapshotBlock),
      "--create",
      creationCode,
    ];
    if (signature !== "constructor()") runtimeArgs.push(signature, ...args);
    const expectedRuntime = exactLowerHex(
      castRead(runtimeArgs),
      BYTECODE,
      `${contractName} reconstructed runtime`,
    );
    const expectedRuntimeCodeHash = exactLowerHex(
      castRead(["keccak", expectedRuntime]),
      BYTES32,
      `${contractName} reconstructed runtime hash`,
    );
    transactions.push({
      sequence,
      contract_key: contractKey,
      contract_name: contractName,
      transaction_type: "CREATE",
      function_signature: signature,
      expected_input: expectedInput,
      expected_input_sha256: rawInputSha256(expectedInput),
      expected_runtime_code_hash: expectedRuntimeCodeHash,
    });
  };
  const call = ({ sequence, contractKey, contractName, signature, args = [] }) => {
    const expectedInput = exactLowerHex(
      castRead(["calldata", signature, ...args]),
      BYTECODE,
      `${contractName} ${signature} calldata`,
    );
    transactions.push({
      sequence,
      contract_key: contractKey,
      contract_name: contractName,
      transaction_type: "CALL",
      function_signature: signature,
      expected_input: expectedInput,
      expected_input_sha256: rawInputSha256(expectedInput),
      expected_runtime_code_hash: null,
    });
  };

  try {
    forgeRead(["build"]);
    create({ sequence: 0, contractKey: "diligenceRoom", contractName: "DiligenceRoom", signature: "constructor(bool)", args: ["true"] });
    call({ sequence: 1, contractKey: "diligenceRoom", contractName: "DiligenceRoom", signature: "freezeFeeBps()" });
    call({ sequence: 2, contractKey: "diligenceRoom", contractName: "DiligenceRoom", signature: "enableComputeSettlementPolicy()" });
    call({ sequence: 3, contractKey: "diligenceRoom", contractName: "DiligenceRoom", signature: "setComposeApprovalRequired(bool)", args: ["true"] });
    call({ sequence: 4, contractKey: "diligenceRoom", contractName: "DiligenceRoom", signature: "setTeeIdentityApprovalRequired(bool)", args: ["true"] });
    call({ sequence: 5, contractKey: "diligenceRoom", contractName: "DiligenceRoom", signature: "freezeApprovalRequirements()" });
    create({
      sequence: 6,
      contractKey: "tinkerAccountEncumbrance",
      contractName: "TinkerAccountEncumbrance",
      signature: "constructor(address,bytes32,bytes32,uint256,uint256)",
      args: [
        operator,
        accountCommitment,
        ZERO_BYTES32,
        contractPolicy.tinkerMaxAddBalanceWei,
        contractPolicy.tinkerMaxSpendWei,
      ],
    });
    create({ sequence: 7, contractKey: "royaltyDistributor", contractName: "RoyaltyDistributor", signature: "constructor()", args: [] });
    create({ sequence: 8, contractKey: "challengeRegistry", contractName: "ChallengeRegistry", signature: "constructor(address)", args: [operator] });
    create({
      sequence: 9,
      contractKey: "computeCreditVault",
      contractName: "ComputeCreditVault",
      signature: "constructor(address,address,uint16)",
      args: [operator, computeDeveloper, String(contractPolicy.computeDeveloperFeeBps)],
    });
    call({ sequence: 10, contractKey: "computeCreditVault", contractName: "ComputeCreditVault", signature: "freezeDeveloperFee()" });
    create({
      sequence: 11,
      contractKey: "emailOracleAuth",
      contractName: "EmailOracleAuth",
      signature: "constructor(address,uint256,bool,bytes32,bytes32,bool)",
      args: [
        operator,
        String(contractPolicy.emailOracleUpgradeDelaySeconds),
        "false",
        ZERO_BYTES32,
        ZERO_BYTES32,
        "true",
      ],
    });
    create({
      sequence: 12,
      contractKey: "executionPolicyAnchor",
      contractName: "ExecutionPolicyAnchor",
      signature: "constructor(address,bytes32,bytes32)",
      args: [
        operator,
        deploymentIntentSha256Bytes32,
        reviewerAuthorityGenesisAcceptanceSha256Bytes32,
      ],
    });
  } finally {
    fs.rmSync(buildDirectory, { recursive: true, force: true });
  }

  const payload = {
    schema: FRESH_CONTRACT_RELEASE_RECONSTRUCTION_SCHEMA,
    truth_status: FRESH_CONTRACT_RELEASE_RECONSTRUCTION_TRUTH_STATUS,
    release_sha: expectedReleaseSha,
    deployment_intent_sha256: deploymentIntentSha256,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerAuthorityGenesisAcceptanceSha256,
    network: {
      chain_id: 84_532,
      name: "base-sepolia",
      snapshot_block: normalizedSnapshotBlock,
      snapshot_block_hash: normalizedSnapshotHash,
    },
    operator_address: operator,
    source_proof: {
      clean_worktree: true,
      detached_head: true,
      submodules_clean: true,
      worktree_head: sourceHead,
      canonical_forge_script: "⚙️/tinker-delegate/contracts/script/DeployFreshSuite.s.sol",
      toolchain: reviewedToolchain,
    },
    transactions,
  };
  const result = {
    ...payload,
    reconstruction_sha256: freshContractReleaseReconstructionDigest(payload),
  };
  const text = canonicalFreshContractReleaseReconstructionText(result);
  if (Buffer.byteLength(text, "utf8") > MAX_RECONSTRUCTION_BYTES) {
    throw new Error("fresh contract release reconstruction exceeds the 2 MiB bound");
  }
  return result;
}

function parseCli(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || value === undefined || values.has(flag)) {
      throw new Error("reconstruction arguments must be unique --flag value pairs");
    }
    values.set(flag, value);
  }
  const expected = [
    "--deployment-intent",
    "--release-sha",
    "--rpc-url",
    "--snapshot-block",
    "--snapshot-block-hash",
    "--worktree",
  ];
  if (values.size !== expected.length || expected.some((flag) => !values.has(flag))) {
    throw new Error(`reconstruction requires exactly: ${expected.join(", ")}`);
  }
  return {
    releaseWorktree: values.get("--worktree"),
    expectedReleaseSha: values.get("--release-sha"),
    deploymentIntentText: fs.readFileSync(values.get("--deployment-intent"), "utf8"),
    rpcUrl: values.get("--rpc-url"),
    snapshotBlock: values.get("--snapshot-block"),
    snapshotBlockHash: values.get("--snapshot-block-hash"),
  };
}

const isMain = process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  try {
    const result = reconstructFreshContractRelease(parseCli(process.argv.slice(2)));
    process.stdout.write(canonicalFreshContractReleaseReconstructionText(result));
  } catch (error) {
    process.stderr.write(`fresh contract release reconstruction failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
