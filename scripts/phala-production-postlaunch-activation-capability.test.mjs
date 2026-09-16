import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const REPOSITORY_ROOT = fileURLToPath(new URL("../", import.meta.url));

const HARNESS = String.raw`
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { mock } from "node:test";
import { pathToFileURL } from "node:url";

const scenario = process.env.POSTLAUNCH_CAPABILITY_SCENARIO;
const url = (name) => pathToFileURL(path.join(process.cwd(), "scripts", name)).href;
const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
};
const text = (value) => JSON.stringify(canonical(value), null, 2) + "\n";
const raw = (bytes) => "sha256:" + createHash("sha256").update(bytes).digest("hex");
const sha = (pair) => "sha256:" + pair.repeat(32);
const releaseSha = "ab".repeat(20);
const batchId = "postlaunch-capability-batch";
const releaseDigest = sha("11");
const evidenceDigest = sha("12");
const completionDigest = sha("13");
const releaseAuthority = Object.freeze({ qvl_measurement_policy_set_sha256: sha("14") });
const evidenceSet = Object.freeze({
  minimum_activation_evidence_lease_expires_at: Math.floor(Date.now() / 1000) + 600,
});
const domain = (index) => Object.freeze({
  app_id: String(index + 1).repeat(40),
  bound_contract_address: index === 0 ? "0x" + "11".repeat(20) : null,
  bound_contract_name: index === 0 ? "DiligenceRoom" : null,
  committed_compose_hash: String(index + 1).repeat(64),
  cvm_id: "cvm-" + index,
  descriptor_sha256: sha("2" + index),
  disk_size: 20,
  domain: "domain_" + index,
  instance_type: "tdx.small",
  kms_id: "kms-test",
  machine_evidence_kind: "test-evidence",
  machine_evidence_sha256: sha("3" + index),
  os_image_hash: String(index + 2).repeat(64),
  production_posture_verification_receipt_sha256: sha("4" + index),
  qvl_identity_sha256: sha("5" + index),
  qvl_release_policy_sha256: sha("6" + index),
  qvl_verification_receipt_sha256: sha("7" + index),
  tdx_attestation_evidence_sha256: sha("8" + index),
  tdx_attestation_verification_receipt_sha256: sha("9" + index),
  tdx_measurement_authority_sha256: sha("a" + index),
  tdx_measurements_sha256: sha("b" + index),
  tee_identity: "0x" + String(index + 2).repeat(40),
});
const launchCompletion = Object.freeze({
  release_sha: releaseSha,
  batch_id: batchId,
  deployment_intent_sha256: sha("21"),
  cvm_launch_intent_sha256: sha("22"),
  fresh_contract_deployment_receipt_sha256: sha("23"),
  release_verification_authority_sha256: releaseDigest,
  machine_verifier_evidence_set_sha256: evidenceDigest,
  historical_transcript_file_set_sha256: sha("24"),
  completed_at: Math.floor(Date.now() / 1000),
  activation_evidence_lease_expires_at: Math.floor(Date.now() / 1000) + 600,
  domains: Object.freeze(Array.from({ length: 7 }, (_, index) => domain(index))),
});
const mockWithOriginal = async (name, overrides) => {
  const target = url(name);
  const original = await import(target);
  mock.module(target, { namedExports: { ...original, ...overrides } });
};
await mockWithOriginal("phala-seven-cvm-verifier-evidence.mjs", {
  assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(value) {
    if (value !== releaseAuthority) throw new Error("wrong release authority brand");
    return value;
  },
  assertProductionPhalaSevenCvmEvidenceSet(value) {
    if (value !== evidenceSet) throw new Error("wrong evidence-set brand");
    return value;
  },
  phalaSevenCvmReleaseVerificationAuthoritySha256(value) {
    if (value !== releaseAuthority) throw new Error("wrong release digest brand");
    return releaseDigest;
  },
  phalaSevenCvmVerifiedEvidenceSetSha256(value) {
    if (value !== evidenceSet) throw new Error("wrong evidence digest brand");
    return evidenceDigest;
  },
});
await mockWithOriginal("phala-seven-cvm-launch-completion.mjs", {
  assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(value) {
    if (value !== launchCompletion) throw new Error("wrong L brand");
    return value;
  },
  canonicalPhalaSevenCvmLaunchCompletionReceiptText(value) {
    if (value !== launchCompletion) throw new Error("wrong L canonical brand");
    return text(value);
  },
  phalaSevenCvmLaunchCompletionReceiptSha256(value) {
    if (value !== launchCompletion) throw new Error("wrong L digest brand");
    return completionDigest;
  },
});

const pinned = await import(url("phala-pinned-private-directory.mjs"));
const gate = await import(url("phala-production-postlaunch-activation-capability.mjs") + "?scenario=" + scenario);
const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "dnai-postlaunch-capability-")));
fs.chmodSync(root, 0o700);
const evidencePath = path.join(root, "evidence");
const authorityPath = path.join(root, "authority");
fs.mkdirSync(evidencePath, { mode: 0o700 });
fs.mkdirSync(authorityPath, { mode: 0o700 });
const evidenceHandle = pinned.pinPhalaPrivateDirectory(evidencePath);
const authorityHandle = pinned.pinPhalaPrivateDirectory(authorityPath);
const evidenceSession = Object.freeze({
  release_sha: releaseSha,
  batch_id: batchId,
  release_verification_authority_sha256: releaseDigest,
});
const checkpoint = Object.freeze({
  release_sha: releaseSha,
  batch_id: batchId,
  releaseVerificationAuthority: releaseAuthority,
  verifiedEvidenceSet: evidenceSet,
  launchCompletionReceipt: launchCompletion,
  activation_mutation_authorized: false,
  live_traffic_authorized: false,
});
const write = (basename, value, mode = 0o600) => {
  const bytes = Buffer.from(text(value));
  const file = path.join(root, basename);
  fs.writeFileSync(file, bytes, { mode });
  fs.chmodSync(file, mode);
  return Object.freeze({ path: file, sha256: raw(bytes) });
};
let capability;
let handoff;
try {
  const postlaunchAuthorityTimeoutSeconds = scenario === "deadline" ? 3 : 10;
  handoff = gate.publishPhalaProductionPostlaunchHandoff({
    checkpointValue: checkpoint,
    evidenceHandle,
    evidenceSession,
    postlaunchAuthorityTimeoutSeconds,
    postlaunchAuthorityHandle: authorityHandle,
  });
  assert.equal(
    handoff.request.schema,
    "dnai.phala-production-postlaunch-authority-request.v2",
  );
  assert.equal(
    handoff.request.required_input.schema,
    "dnai.phala-production-postlaunch-activation-input-manifest.v2",
  );
  assert.match(
    handoff.request.manifest_acceptance_deadline,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
  );
  if (scenario === "parallel-handoff") {
    assert.throws(
      () => gate.publishPhalaProductionPostlaunchHandoff({
        checkpointValue: checkpoint,
        evidenceHandle,
        evidenceSession,
        postlaunchAuthorityTimeoutSeconds,
        postlaunchAuthorityHandle: authorityHandle,
      }),
      /already attempted one postlaunch handoff/,
    );
  } else if (scenario === "parallel-authority") {
    const competingSession = Object.freeze({ ...evidenceSession });
    assert.throws(
      () => gate.publishPhalaProductionPostlaunchHandoff({
        checkpointValue: checkpoint,
        evidenceHandle,
        evidenceSession: competingSession,
        postlaunchAuthorityTimeoutSeconds,
        postlaunchAuthorityHandle: authorityHandle,
      }),
      /already assigned to another one-shot handoff/,
    );
  } else {
    const dependency = (name, mode = 0o600) => write(name + ".json", { name }, mode);
    const canonicalHistoryBytes = Buffer.from(text([]));
    const historyPath = path.join(root, "stage-b-reviewer-status-history.json");
    fs.writeFileSync(historyPath, canonicalHistoryBytes, { mode: 0o600 });
    fs.chmodSync(historyPath, 0o600);
    let historyBinding = Object.freeze({
      path: historyPath,
      sha256: raw(canonicalHistoryBytes),
    });
    if (scenario === "history-wrong-mode") {
      fs.chmodSync(historyPath, 0o644);
    } else if (scenario === "history-symlink") {
      const symlinkPath = path.join(root, "stage-b-reviewer-status-history-link.json");
      fs.symlinkSync(historyPath, symlinkPath);
      historyBinding = Object.freeze({ ...historyBinding, path: symlinkPath });
    } else if (scenario === "history-hardlink") {
      fs.linkSync(
        historyPath,
        path.join(root, "stage-b-reviewer-status-history-hardlink.json"),
      );
    } else if (scenario === "history-digest-mismatch") {
      historyBinding = Object.freeze({ ...historyBinding, sha256: sha("fe") });
    } else if (scenario === "history-noncanonical") {
      const bytes = Buffer.from("[]", "utf8");
      fs.writeFileSync(historyPath, bytes);
      historyBinding = Object.freeze({ ...historyBinding, sha256: raw(bytes) });
    } else if (scenario === "history-wrapped-object") {
      const bytes = Buffer.from(text({ history: [] }));
      fs.writeFileSync(historyPath, bytes);
      historyBinding = Object.freeze({ ...historyBinding, sha256: raw(bytes) });
    }

    let dependencies = {
      ceremonyLedgerInitial: dependency("ledger"),
      ceremonyLedgerInitializationReceipt: dependency("ledger-init", 0o444),
      ceremonyTransactionPlan: dependency("plan"),
      deferredAuthorityReview: dependency("deferred"),
      immutableDeploymentManifest: dependency("manifest", 0o444),
      reviewedFinalAuthorityFiles: Object.freeze({
        cvmLaunchIntent: dependency("cvm-launch"),
        deploymentIntent: dependency("deployment"),
        finalAuthority: dependency("final-authority"),
        reviewEnvelope: dependency("review-envelope"),
        reviewEvidence: dependency("review-evidence"),
      }),
      stageBReviewerStatusHistory: historyBinding,
    };
    if (scenario === "missing-history-binding") {
      const { stageBReviewerStatusHistory: omitted, ...withoutHistory } = dependencies;
      assert.ok(omitted);
      dependencies = withoutHistory;
    } else if (scenario === "extra-history-binding") {
      dependencies = {
        ...dependencies,
        reviewerStatusHistory: historyBinding,
      };
    }
    dependencies = Object.freeze(dependencies);

    const manifestDeadline = scenario === "deadline-extension"
      ? new Date(
        Date.parse(handoff.request.manifest_acceptance_deadline) + 1_000,
      ).toISOString()
      : handoff.request.manifest_acceptance_deadline;
    const manifest = Object.freeze({
      schema: scenario === "manifest-v1"
        ? "dnai.phala-production-postlaunch-activation-input-manifest.v1"
        : gate.PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA,
      status: "postlaunch_activation_inputs_ready_for_validation",
      truth_status: "file_bindings_only_pending_same_process_validation_not_mutation_or_live_authority",
      release_sha: handoff.projection.release_sha,
      batch_id: handoff.projection.batch_id,
      deployment_intent_sha256: handoff.projection.deployment_intent_sha256,
      cvm_launch_intent_sha256: handoff.projection.cvm_launch_intent_sha256,
      manifest_acceptance_deadline: manifestDeadline,
      release_verification_authority_sha256: handoff.projection.release_verification_authority_sha256,
      seven_cvm_verified_evidence_set_sha256: handoff.projection.seven_cvm_verified_evidence_set_sha256,
      seven_cvm_launch_completion_receipt_sha256: handoff.projection.seven_cvm_launch_completion_receipt_sha256,
      postlaunch_projection_raw_file_sha256: handoff.postlaunch_projection_raw_file_sha256,
      postlaunch_request_raw_file_sha256: handoff.postlaunch_request_raw_file_sha256,
      dependencies,
      automatic_retry_authorized: false,
      activation_mutation_authorized: false,
      live_traffic_authorized: false,
    });
    const manifestBytes = Buffer.from(text(manifest));
    pinned.createExclusivePhalaPinnedPrivateFile(
      authorityHandle,
      gate.PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
      manifestBytes,
      { mode: 0o600 },
    );
    const waitInput = {
      evidenceSession,
      handle: authorityHandle,
      handoff,
      launchCompletionReceipt: launchCompletion,
      pollIntervalMilliseconds: 25,
      releaseVerificationAuthority: releaseAuthority,
      verifiedEvidenceSet: evidenceSet,
    };
    const preMintRejections = new Map([
      ["manifest-v1", /lineage or posture is invalid/],
      ["missing-history-binding", /fields do not match the exact schema/],
      ["extra-history-binding", /fields do not match the exact schema/],
      ["history-wrong-mode", /exact-mode-0600/],
      ["history-symlink", /canonical and symlink-free/],
      ["history-hardlink", /single-link/],
      ["history-digest-mismatch", /bytes differ from its binding/],
      ["history-noncanonical", /recursively sorted/],
      ["history-wrapped-object", /canonical bare array/],
      ["deadline-extension", /lineage or posture is invalid/],
    ]);
    if (preMintRejections.has(scenario)) {
      await assert.rejects(
        () => gate.waitForPhalaProductionPostlaunchActivationCapability(waitInput),
        preMintRejections.get(scenario),
      );
    } else {
      capability = await gate.waitForPhalaProductionPostlaunchActivationCapability(
        waitInput,
      );
      assert.equal(
        capability.manifest_acceptance_deadline,
        handoff.request.manifest_acceptance_deadline,
      );
      assert.equal(
        capability.acceptance_deadline_ms,
        Date.parse(handoff.request.manifest_acceptance_deadline),
      );
      const expectation = {
        evidenceSession,
        releaseSha,
        batchId,
        releaseVerificationAuthority: releaseAuthority,
        verifiedEvidenceSet: evidenceSet,
        launchCompletionReceipt: launchCompletion,
      };
      if (scenario === "clone") {
        const clone = structuredClone(capability);
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(clone, expectation),
          /same-process/,
        );
        const result = gate.consumePhalaProductionPostlaunchActivationCapability(capability, expectation);
        assert.deepEqual(result.stageBReviewerStatusHistory, []);
      } else if (scenario === "wrong-session") {
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(capability, {
            ...expectation,
            evidenceSession: { ...evidenceSession },
          }),
          /another checkpoint/,
        );
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(capability, expectation),
          /same-process/,
        );
      } else if (scenario === "dependency-substitution") {
        fs.writeFileSync(dependencies.deferredAuthorityReview.path, text({ changed: true }), { mode: 0o600 });
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(capability, expectation),
          /bytes or file identity changed/,
        );
      } else if (scenario === "history-mutation") {
        fs.writeFileSync(historyPath, text([{ epoch: 2 }]), { mode: 0o600 });
        fs.chmodSync(historyPath, 0o600);
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(capability, expectation),
          /bytes differ from its binding|changed before capability consumption/,
        );
      } else if (scenario === "manifest-substitution") {
        const target = path.join(authorityPath, gate.PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME);
        const old = path.join(authorityPath, "old-manifest.json");
        fs.renameSync(target, old);
        fs.writeFileSync(target, manifestBytes, { mode: 0o600 });
        fs.chmodSync(target, 0o600);
        fs.unlinkSync(old);
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(capability, expectation),
          /identity differs|changed/,
        );
      } else if (scenario === "extra-entry") {
        fs.writeFileSync(path.join(authorityPath, "unexpected.json"), text({}), { mode: 0o600 });
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(capability, expectation),
          /unexpected entries/,
        );
      } else if (scenario === "deadline") {
        const remaining = Date.parse(handoff.request.manifest_acceptance_deadline) - Date.now();
        if (remaining > 0) {
          await new Promise((resolve) => setTimeout(resolve, remaining + 25));
        }
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(capability, expectation),
          /deadline expired/,
        );
      } else if (scenario === "explicit-dispose") {
        assert.equal(
          gate.disposePhalaProductionPostlaunchActivationCapability(capability),
          true,
        );
        assert.equal(
          gate.disposePhalaProductionPostlaunchActivationCapability(capability),
          false,
        );
        assert.throws(
          () => gate.assertPhalaProductionPostlaunchActivationCapability(capability),
          /same-process/,
        );
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(
            capability,
            expectation,
          ),
          /same-process/,
        );
      } else if (scenario === "malformed-expectation") {
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(
            capability,
            { ...expectation, unexpected: true },
          ),
          /fields do not match the exact schema/,
        );
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(
            capability,
            expectation,
          ),
          /same-process/,
        );
      } else if (scenario === "success-replay") {
        const result = gate.consumePhalaProductionPostlaunchActivationCapability(capability, expectation);
        assert.deepEqual(
          result.dependencies.reviewedFinalAuthorityFiles.finalAuthority,
          dependencies.reviewedFinalAuthorityFiles.finalAuthority,
        );
        assert.deepEqual(result.stageBReviewerStatusHistory, []);
        assert.deepEqual(result.stageBReviewerStatusHistoryBinding, historyBinding);
        assert.throws(
          () => gate.consumePhalaProductionPostlaunchActivationCapability(capability, expectation),
          /same-process/,
        );
      } else {
        throw new Error("unknown scenario");
      }
    }
  }
  console.log(JSON.stringify({ scenario, rejected: true }));
} finally {
  pinned.closePhalaPinnedPrivateDirectory(evidenceHandle);
  pinned.closePhalaPinnedPrivateDirectory(authorityHandle);
  fs.rmSync(root, { recursive: true, force: true });
}
`;

async function runScenario(scenario) {
  const result = await execFileAsync(process.execPath, [
    "--experimental-test-module-mocks",
    "--input-type=module",
    "-e",
    HARNESS,
  ], {
    cwd: REPOSITORY_ROOT,
    env: { ...process.env, POSTLAUNCH_CAPABILITY_SCENARIO: scenario },
    maxBuffer: 4 * 1024 * 1024,
    timeout: 20_000,
  });
  return JSON.parse(result.stdout.trim().split("\n").at(-1));
}

for (const scenario of [
  "success-replay",
  "clone",
  "wrong-session",
  "dependency-substitution",
  "history-mutation",
  "manifest-substitution",
  "extra-entry",
  "deadline",
  "deadline-extension",
  "manifest-v1",
  "missing-history-binding",
  "extra-history-binding",
  "history-wrong-mode",
  "history-symlink",
  "history-hardlink",
  "history-digest-mismatch",
  "history-noncanonical",
  "history-wrapped-object",
  "explicit-dispose",
  "malformed-expectation",
  "parallel-authority",
  "parallel-handoff",
]) {
  test(`postlaunch capability rejects ${scenario}`, async () => {
    const result = await runScenario(scenario);
    assert.equal(result.scenario, scenario);
    assert.equal(result.rejected, true);
  });
}
