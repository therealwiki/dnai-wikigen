import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  canonicalArtifactText,
  createDraftDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import {
  canonicalFreshContractReleaseReconstructionText,
  freshContractReleaseReconstructionDigest,
  FRESH_CONTRACT_RELEASE_RECONSTRUCTION_SCHEMA,
  normalizeFreshContractReleaseReconstruction,
  reconstructFreshContractRelease,
} from "./fresh-contract-release-reconstruction.mjs";

const RELEASE_SHA = "a".repeat(40);
const SNAPSHOT_HASH = `0x${"1".repeat(64)}`;
const REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256 =
  `sha256:${"91".repeat(32)}`;
const REVIEWER_AUTHORITY_CURRENT_STATUS_SHA256 =
  `sha256:${"92".repeat(32)}`;

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

function validIntent() {
  const intent = createDraftDeploymentIntentCore();
  intent.release.releaseSha = RELEASE_SHA;
  intent.release.reviewerAuthorityGenesisAcceptanceSha256 =
    REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256;
  intent.release.reviewerAuthorityCurrentStatusEpoch = 1;
  intent.release.reviewerAuthorityCurrentStatusSha256 =
    REVIEWER_AUTHORITY_CURRENT_STATUS_SHA256;
  intent.deploymentControl.controllerId = "operator-control-01";
  intent.deploymentControl.operatorAddress = address(1);
  intent.staticContractInputs.computeCreditVault.developer = address(20);
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

function reconstructionFixture({
  sourceStatus = "",
  sourceBranch = "HEAD",
  submoduleStatus = "",
  submoduleWorktreeStatus = "",
  observedHash = SNAPSHOT_HASH,
  foundryCommit = "b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2",
  configuredSolc = "0.8.28",
  compilerVersion = "0.8.28+commit.7893614a",
} = {}) {
  const worktree = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-reconstruction-worktree-"));
  const scriptDirectory = path.join(
    worktree,
    "⚙️",
    "tinker-delegate",
    "contracts",
    "script",
  );
  fs.mkdirSync(scriptDirectory, { recursive: true });
  fs.writeFileSync(path.join(scriptDirectory, "DeployFreshSuite.s.sol"), "// synthetic test fixture\n");
  const commands = [];
  const contractIds = new Map([
    ["DiligenceRoom", "01"],
    ["TinkerAccountEncumbrance", "02"],
    ["RoyaltyDistributor", "03"],
    ["ChallengeRegistry", "04"],
    ["ComputeCreditVault", "05"],
    ["EmailOracleAuth", "06"],
    ["ExecutionPolicyAnchor", "07"],
  ]);
  const hexDigest = (value) => createHash("sha256").update(value).digest("hex");
  const foundryVersion = (tool) => [
    `${tool} Version: 1.5.1-stable`,
    `Commit SHA: ${foundryCommit}`,
    "Build Timestamp: 2025-12-22T11:41:09.812070000Z (1766403669)",
    "Build Profile: maxperf",
  ].join("\n");
  const commandRunner = ({ command, args, cwd, env }) => {
    commands.push({ command, args: [...args], cwd, env: { ...env } });
    if (command === "git" && args.join(" ") === "rev-parse HEAD") return RELEASE_SHA;
    if (command === "git" && args.join(" ") === "rev-parse --abbrev-ref HEAD") return sourceBranch;
    if (command === "git" && args[0] === "status") return sourceStatus;
    if (command === "git" && args.join(" ") === "submodule status --recursive") return submoduleStatus;
    if (command === "git" && args[0] === "submodule" && args[1] === "foreach") return submoduleWorktreeStatus;
    if (command === "git" && args.join(" ") === "rev-parse --show-toplevel") return worktree;
    if (command === "forge" && args.join(" ") === "--version") return foundryVersion("forge");
    if (command === "cast" && args.join(" ") === "--version") return foundryVersion("cast");
    if (command === "forge" && args.join(" ") === "config --json") {
      return JSON.stringify({
        solc: configuredSolc,
        optimizer: true,
        optimizer_runs: 200,
        via_ir: true,
        evm_version: "prague",
        bytecode_hash: "ipfs",
        cbor_metadata: true,
        use_literal_content: false,
        libraries: [],
      });
    }
    if (command === "cast" && args[0] === "chain-id") return "84532";
    if (command === "cast" && args[0] === "block") {
      return JSON.stringify({ number: "0x3e8", hash: observedHash });
    }
    if (command === "forge" && args[0] === "build") return "";
    if (command === "forge" && args[0] === "inspect") {
      if (args[2] === "metadata") {
        return JSON.stringify({
          compiler: { version: compilerVersion },
          settings: {
            optimizer: { enabled: true, runs: 200 },
            viaIR: true,
            evmVersion: "prague",
            metadata: { bytecodeHash: "ipfs" },
            libraries: {},
          },
        });
      }
      return `0x60${contractIds.get(args[1])}`;
    }
    if (command === "cast" && args[0] === "abi-encode") {
      return `0x${hexDigest(args.join("\0"))}`;
    }
    if (command === "cast" && args[0] === "calldata") {
      return `0x${hexDigest(args.join("\0")).slice(0, 8)}`;
    }
    if (command === "cast" && args[0] === "call") {
      return `0x60${hexDigest(args.join("\0")).slice(0, 2)}`;
    }
    if (command === "cast" && args[0] === "keccak") {
      return `0x${hexDigest(args[1])}`;
    }
    throw new Error(`unexpected command in reconstruction test: ${command} ${args.join(" ")}`);
  };
  return { worktree, commands, commandRunner };
}

function runFixture(fixture, intent = validIntent()) {
  return reconstructFreshContractRelease({
    releaseWorktree: fixture.worktree,
    expectedReleaseSha: RELEASE_SHA,
    deploymentIntentText: canonicalArtifactText(intent),
    rpcUrl: "https://base-sepolia.example.invalid/read-only",
    snapshotBlock: 1_000,
    snapshotBlockHash: SNAPSHOT_HASH,
    commandRunner: fixture.commandRunner,
  });
}

test("reconstructs the exact ordered 13 inputs and seven runtime hashes without receipt authority", (t) => {
  const fixture = reconstructionFixture();
  t.after(() => fs.rmSync(fixture.worktree, { recursive: true, force: true }));
  const result = runFixture(fixture);

  assert.equal(result.schema, FRESH_CONTRACT_RELEASE_RECONSTRUCTION_SCHEMA);
  assert.equal(result.release_sha, RELEASE_SHA);
  assert.equal(
    result.reviewer_authority_genesis_acceptance_sha256,
    REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
  );
  assert.equal(result.network.snapshot_block, 1_000);
  assert.equal(result.network.snapshot_block_hash, SNAPSHOT_HASH);
  assert.equal(result.source_proof.detached_head, true);
  assert.equal(result.source_proof.submodules_clean, true);
  assert.equal(result.source_proof.toolchain.solidity.compilerVersion, "0.8.28+commit.7893614a");
  assert.equal(result.transactions.length, 13);
  assert.deepEqual(result.transactions.map(({ sequence }) => sequence), [...Array(13).keys()]);
  assert.deepEqual(
    result.transactions.filter(({ transaction_type }) => transaction_type === "CREATE").map(({ sequence }) => sequence),
    [0, 6, 7, 8, 9, 11, 12],
  );
  assert.deepEqual(
    result.transactions.filter(({ transaction_type }) => transaction_type === "CALL").map(({ sequence }) => sequence),
    [1, 2, 3, 4, 5, 10],
  );
  assert.equal(result.transactions[0].function_signature, "constructor(bool)");
  assert.equal(result.transactions[0].expected_input.endsWith(hexDigestForArgs(["abi-encode", "constructor(bool)", "true"])), true);
  assert.equal(result.transactions[11].function_signature, "constructor(address,uint256,bool,bytes32,bytes32,bool)");
  assert.equal(
    result.transactions[12].function_signature,
    "constructor(address,bytes32,bytes32)",
  );
  assert.equal(
    result.transactions[12].expected_input.endsWith(hexDigestForArgs([
      "abi-encode",
      "constructor(address,bytes32,bytes32)",
      address(1),
      `0x${result.deployment_intent_sha256.slice("sha256:".length)}`,
      `0x${REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256.slice("sha256:".length)}`,
    ])),
    true,
  );
  assert.ok(result.transactions.every(({ expected_input_sha256 }) => /^sha256:[0-9a-f]{64}$/.test(expected_input_sha256)));
  assert.ok(result.transactions.filter(({ transaction_type }) => transaction_type === "CREATE")
    .every(({ expected_runtime_code_hash }) => /^0x[0-9a-f]{64}$/.test(expected_runtime_code_hash)));
  assert.ok(result.transactions.filter(({ transaction_type }) => transaction_type === "CALL")
    .every(({ expected_runtime_code_hash }) => expected_runtime_code_hash === null));
  assert.match(result.reconstruction_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(
    canonicalFreshContractReleaseReconstructionText(result),
    canonicalFreshContractReleaseReconstructionText(result),
  );

  const commandText = fixture.commands.map(({ command, args }) => `${command} ${args.join(" ")}`).join("\n");
  assert.doesNotMatch(commandText, /--account|--private-key|--broadcast|cast send|cast wallet/);
  const runtimeCalls = fixture.commands.filter(({ command, args }) => command === "cast" && args[0] === "call");
  assert.equal(runtimeCalls.length, 7);
  assert.ok(runtimeCalls.every(({ args }) => {
    const blockIndex = args.indexOf("--block");
    return blockIndex >= 0 && args[blockIndex + 1] === "1000" && args.includes("--create");
  }));
  assert.ok(fixture.commands.some(({ command, args }) => command === "git"
    && args.join(" ") === "status --porcelain=v1 --untracked-files=all --ignore-submodules=none"));
  assert.ok(fixture.commands.some(({ command, args }) => command === "git"
    && args[0] === "submodule" && args[1] === "foreach"));
  assert.equal(fixture.commands.filter(({ command, args }) => command === "forge"
    && args[0] === "inspect" && args[2] === "metadata").length, 7);
});

function hexDigestForArgs(args) {
  return createHash("sha256").update(args.join("\0")).digest("hex");
}

test("reviewed intent changes independently change reconstructed inputs and authority digest", (t) => {
  const firstFixture = reconstructionFixture();
  const secondFixture = reconstructionFixture();
  t.after(() => {
    fs.rmSync(firstFixture.worktree, { recursive: true, force: true });
    fs.rmSync(secondFixture.worktree, { recursive: true, force: true });
  });
  const first = runFixture(firstFixture);
  const changedIntent = validIntent();
  changedIntent.numericPolicy.contract.computeDeveloperFeeBps = 101;
  const second = runFixture(secondFixture, changedIntent);
  assert.notEqual(first.transactions[9].expected_input, second.transactions[9].expected_input);
  assert.notEqual(first.transactions[9].expected_runtime_code_hash, second.transactions[9].expected_runtime_code_hash);
  assert.notEqual(first.reconstruction_sha256, second.reconstruction_sha256);
});

test("signed reviewer genesis acceptance changes the anchored creation input", (t) => {
  const firstFixture = reconstructionFixture();
  const secondFixture = reconstructionFixture();
  t.after(() => {
    fs.rmSync(firstFixture.worktree, { recursive: true, force: true });
    fs.rmSync(secondFixture.worktree, { recursive: true, force: true });
  });
  const first = runFixture(firstFixture);
  const changedIntent = validIntent();
  changedIntent.release.reviewerAuthorityGenesisAcceptanceSha256 =
    `sha256:${"92".repeat(32)}`;
  const second = runFixture(secondFixture, changedIntent);
  assert.notEqual(first.transactions[12].expected_input, second.transactions[12].expected_input);
  assert.notEqual(
    first.transactions[12].expected_runtime_code_hash,
    second.transactions[12].expected_runtime_code_hash,
  );
  assert.notEqual(first.reconstruction_sha256, second.reconstruction_sha256);
});

test("dirty or wrong source authority fails before build or runtime derivation", (t) => {
  const fixture = reconstructionFixture({ sourceStatus: " M src/DiligenceRoom.sol" });
  t.after(() => fs.rmSync(fixture.worktree, { recursive: true, force: true }));
  assert.throws(() => runFixture(fixture), /exact clean detached RELEASE_SHA worktree/);
  assert.equal(fixture.commands.some(({ command }) => command === "forge"), false);
  assert.equal(fixture.commands.some(({ command, args }) => command === "cast" && args[0] === "call"), false);
});

test("snapshot hash drift fails closed before compilation", (t) => {
  const fixture = reconstructionFixture({ observedHash: `0x${"2".repeat(64)}` });
  t.after(() => fs.rmSync(fixture.worktree, { recursive: true, force: true }));
  assert.throws(() => runFixture(fixture), /snapshot block number or hash changed/);
  assert.equal(fixture.commands.some(({ command, args }) => command === "forge" && args[0] === "build"), false);
});

test("noncanonical or release-mismatched deployment intent is rejected before tool execution", (t) => {
  const fixture = reconstructionFixture();
  t.after(() => fs.rmSync(fixture.worktree, { recursive: true, force: true }));
  const intent = validIntent();
  intent.release.releaseSha = "b".repeat(40);
  intent.release.reviewerAuthorityGenesisAcceptanceSha256 =
    REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256;
  assert.throws(() => runFixture(fixture, intent), /does not match expected RELEASE_SHA/);
  assert.equal(fixture.commands.length, 0);
});

test("detached HEAD and recursive submodule cleanliness are mandatory", (t) => {
  const attached = reconstructionFixture({ sourceBranch: "main" });
  const drifted = reconstructionFixture({
    submoduleStatus: `+${"b".repeat(40)} 🔬/example (heads/main)`,
  });
  const nestedDirty = reconstructionFixture({ submoduleWorktreeStatus: "?? unexpected.txt" });
  t.after(() => {
    for (const fixture of [attached, drifted, nestedDirty]) {
      fs.rmSync(fixture.worktree, { recursive: true, force: true });
    }
  });
  assert.throws(() => runFixture(attached), /exact clean detached RELEASE_SHA worktree/);
  assert.throws(() => runFixture(drifted), /exact clean detached RELEASE_SHA worktree/);
  assert.throws(() => runFixture(nestedDirty), /exact clean detached RELEASE_SHA worktree/);
  assert.ok([attached, drifted, nestedDirty].every((fixture) => !fixture.commands.some(
    ({ command }) => command === "forge",
  )));
});

test("reviewed Foundry identity, configuration, and compiled metadata fail closed on drift", (t) => {
  const binaryDrift = reconstructionFixture({ foundryCommit: "c".repeat(40) });
  const configDrift = reconstructionFixture({ configuredSolc: "0.8.27" });
  const compilerDrift = reconstructionFixture({ compilerVersion: "0.8.28+commit.deadbeef" });
  t.after(() => {
    for (const fixture of [binaryDrift, configDrift, compilerDrift]) {
      fs.rmSync(fixture.worktree, { recursive: true, force: true });
    }
  });
  assert.throws(() => runFixture(binaryDrift), /binary identity/);
  assert.throws(() => runFixture(configDrift), /compilation settings/);
  assert.throws(() => runFixture(compilerDrift), /artifact compiler metadata/);
  assert.equal(binaryDrift.commands.some(({ command, args }) => command === "cast" && args[0] === "call"), false);
  assert.equal(configDrift.commands.some(({ command, args }) => command === "forge" && args[0] === "build"), false);
  assert.equal(compilerDrift.commands.some(({ command, args }) => command === "cast" && args[0] === "call"), false);
});

test("normalizer rejects schema extension, input digest drift, CALL runtime injection, and authority digest drift", (t) => {
  const fixture = reconstructionFixture();
  t.after(() => fs.rmSync(fixture.worktree, { recursive: true, force: true }));
  const result = runFixture(fixture);
  assert.deepEqual(normalizeFreshContractReleaseReconstruction(result), result);
  assert.equal(freshContractReleaseReconstructionDigest(result), result.reconstruction_sha256);

  const extra = structuredClone(result);
  extra.unreviewed = true;
  assert.throws(() => normalizeFreshContractReleaseReconstruction(extra), /exact schema/);

  const digestDrift = structuredClone(result);
  digestDrift.transactions[0].expected_input_sha256 = `sha256:${"f".repeat(64)}`;
  digestDrift.reconstruction_sha256 = freshContractReleaseReconstructionDigest(result);
  assert.throws(() => normalizeFreshContractReleaseReconstruction(digestDrift), /input digest mismatch/);

  const callRuntime = structuredClone(result);
  callRuntime.transactions[1].expected_runtime_code_hash = `0x${"f".repeat(64)}`;
  assert.throws(() => normalizeFreshContractReleaseReconstruction(callRuntime), /runtime hash must be null/);

  const authorityDrift = structuredClone(result);
  authorityDrift.reconstruction_sha256 = `sha256:${"f".repeat(64)}`;
  assert.equal(freshContractReleaseReconstructionDigest(authorityDrift), result.reconstruction_sha256);
  assert.throws(() => normalizeFreshContractReleaseReconstruction(authorityDrift), /authority digest mismatch/);
});
