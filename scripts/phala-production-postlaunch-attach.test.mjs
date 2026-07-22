import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import {
  closePhalaPinnedPrivateDirectory,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  pinPhalaPrivateDirectory,
} from "./phala-pinned-private-directory.mjs";
import {
  PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
  PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA,
  PHALA_PRODUCTION_POSTLAUNCH_PROJECTION_SCHEMA,
  PHALA_PRODUCTION_POSTLAUNCH_REQUEST_SCHEMA,
} from "./phala-production-postlaunch-activation-capability.mjs";
import {
  PHALA_PRODUCTION_POSTLAUNCH_ATTACHMENT_RECEIPT_SCHEMA,
  attachPhalaProductionPostlaunchManifest,
  parsePhalaProductionPostlaunchAttachmentArgs,
} from "./phala-production-postlaunch-attach.mjs";
import {
  canonicalResidentJsonText,
  residentRawSha256,
} from "./phala-production-resident-io.mjs";

const execFileAsync = promisify(execFile);
const CLI_PATH = fileURLToPath(new URL(
  "./phala-production-postlaunch-attach.mjs",
  import.meta.url,
));
const FUTURE_MANIFEST_ACCEPTANCE_DEADLINE =
  "2099-01-01T00:00:00.000Z";
const EXPIRED_MANIFEST_ACCEPTANCE_DEADLINE =
  "2000-01-01T00:00:00.000Z";

function privateRoot(t) {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-postlaunch-attach-")),
  );
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function writeCanonical(root, basename, value, mode = 0o600) {
  const bytes = Buffer.from(canonicalResidentJsonText(value), "utf8");
  const filePath = path.join(root, basename);
  fs.writeFileSync(filePath, bytes, { mode });
  fs.chmodSync(filePath, mode);
  return Object.freeze({ path: filePath, sha256: residentRawSha256(bytes), bytes });
}

function targetPath(value) {
  return path.join(
    value.exchange,
    PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
  );
}

function assertTargetAbsent(value) {
  assert.equal(fs.existsSync(targetPath(value)), false);
}

function fixture(t) {
  const root = privateRoot(t);
  const exchange = path.join(root, "postlaunch-exchange");
  fs.mkdirSync(exchange, { mode: 0o700 });
  const handle = pinPhalaPrivateDirectory(exchange);
  const anchor = phalaPinnedPrivateDirectoryIdentityAnchorSha256(handle);
  closePhalaPinnedPrivateDirectory(handle);
  const sha = (pair) => `sha256:${pair.repeat(32)}`;
  const binding = (name, mode = 0o600) => {
    const written = writeCanonical(root, `${name}.json`, { name }, mode);
    return Object.freeze({ path: written.path, sha256: written.sha256 });
  };
  const dependencies = Object.freeze({
    ceremonyLedgerInitial: binding("ledger"),
    ceremonyLedgerInitializationReceipt: binding("ledger-init", 0o444),
    ceremonyTransactionPlan: binding("transaction-plan"),
    deferredAuthorityReview: binding("deferred-review"),
    immutableDeploymentManifest: binding("immutable-manifest", 0o444),
    reviewedFinalAuthorityFiles: Object.freeze({
      cvmLaunchIntent: binding("cvm-launch-intent"),
      deploymentIntent: binding("deployment-intent"),
      finalAuthority: binding("final-authority"),
      reviewEnvelope: binding("review-envelope"),
      reviewEvidence: binding("review-evidence"),
    }),
    stageBReviewerStatusHistory: (() => {
      const written = writeCanonical(
        root,
        "stage-b-reviewer-status-history.json",
        [],
      );
      return Object.freeze({ path: written.path, sha256: written.sha256 });
    })(),
  });
  const projectionValue = Object.freeze({
    schema: PHALA_PRODUCTION_POSTLAUNCH_PROJECTION_SCHEMA,
    status:
      "seven_cvm_launch_completion_persisted_pending_reviewed_final_authority",
    truth_status:
      "public_machine_evidence_projection_not_review_signature_mutation_or_live_authority",
    chain_id: 84_532,
    release_sha: "ab".repeat(20),
    batch_id: "postlaunch-attach-batch",
    deployment_intent_sha256: sha("11"),
    cvm_launch_intent_sha256: sha("12"),
    fresh_contract_deployment_receipt_sha256: sha("13"),
    release_verification_authority_sha256: sha("14"),
    seven_cvm_verified_evidence_set_sha256: sha("15"),
    seven_cvm_launch_completion_receipt_sha256: sha("16"),
    historical_transcript_file_set_sha256: sha("17"),
    qvl_measurement_policy_set_sha256: sha("18"),
    completed_at: 1_750_000_000,
    activation_evidence_lease_expires_at: 1_750_000_300,
    domains: Object.freeze(Array.from({ length: 7 }, (_, index) => ({
      domain: `test-${index}`,
    }))),
    private_historical_transcript_contains_raw_quote_bytes: true,
    raw_quote_external_egress: false,
    raw_secret_egress: false,
    raw_private_artifact_egress: false,
    encrypted_environment_ciphertext_egress: false,
    activation_mutation_authorized: false,
    live_traffic_authorized: false,
  });
  const projection = writeCanonical(root, "projection.json", projectionValue);
  const requestValue = Object.freeze({
    schema: PHALA_PRODUCTION_POSTLAUNCH_REQUEST_SCHEMA,
    status: "waiting_for_exact_postlaunch_activation_input_manifest",
    truth_status:
      "transport_request_only_not_review_signature_mutation_or_live_authority",
    release_sha: projectionValue.release_sha,
    batch_id: projectionValue.batch_id,
    deployment_intent_sha256: projectionValue.deployment_intent_sha256,
    cvm_launch_intent_sha256: projectionValue.cvm_launch_intent_sha256,
    release_verification_authority_sha256:
      projectionValue.release_verification_authority_sha256,
    seven_cvm_verified_evidence_set_sha256:
      projectionValue.seven_cvm_verified_evidence_set_sha256,
    seven_cvm_launch_completion_receipt_sha256:
      projectionValue.seven_cvm_launch_completion_receipt_sha256,
    manifest_acceptance_deadline: FUTURE_MANIFEST_ACCEPTANCE_DEADLINE,
    launch_completion_raw_file_sha256: sha("19"),
    postlaunch_projection_raw_file_sha256: projection.sha256,
    postlaunch_authority_exchange_identity_anchor_sha256: anchor,
    required_input: Object.freeze({
      basename: PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
      mode: "0600",
      canonical_json_required: true,
      schema: PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA,
    }),
    automatic_retry_authorized: false,
    activation_mutation_authorized: false,
    live_traffic_authorized: false,
  });
  const request = writeCanonical(root, "request.json", requestValue);
  const manifestValue = Object.freeze({
    schema: PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA,
    status: "postlaunch_activation_inputs_ready_for_validation",
    truth_status:
      "file_bindings_only_pending_same_process_validation_not_mutation_or_live_authority",
    release_sha: requestValue.release_sha,
    batch_id: requestValue.batch_id,
    deployment_intent_sha256: requestValue.deployment_intent_sha256,
    cvm_launch_intent_sha256: requestValue.cvm_launch_intent_sha256,
    release_verification_authority_sha256:
      requestValue.release_verification_authority_sha256,
    seven_cvm_verified_evidence_set_sha256:
      requestValue.seven_cvm_verified_evidence_set_sha256,
    seven_cvm_launch_completion_receipt_sha256:
      requestValue.seven_cvm_launch_completion_receipt_sha256,
    manifest_acceptance_deadline:
      requestValue.manifest_acceptance_deadline,
    postlaunch_projection_raw_file_sha256:
      requestValue.postlaunch_projection_raw_file_sha256,
    postlaunch_request_raw_file_sha256: request.sha256,
    dependencies,
    automatic_retry_authorized: false,
    activation_mutation_authorized: false,
    live_traffic_authorized: false,
  });
  const source = writeCanonical(root, "source.json", manifestValue);
  return {
    anchor,
    dependencies,
    exchange,
    manifestValue,
    projection,
    request,
    requestValue,
    root,
    source,
  };
}

function attachInput(value) {
  return {
    source: value.source.path,
    request: value.request.path,
    projection: value.projection.path,
    exchange: value.exchange,
    expectedAnchorSha256: value.anchor,
  };
}

test("atomic helper attaches exact validated source once without authority", (t) => {
  const value = fixture(t);
  const receipt = attachPhalaProductionPostlaunchManifest(attachInput(value));
  assert.equal(receipt.schema, PHALA_PRODUCTION_POSTLAUNCH_ATTACHMENT_RECEIPT_SCHEMA);
  assert.equal(receipt.postlaunch_request_raw_file_sha256, value.request.sha256);
  assert.equal(receipt.postlaunch_projection_raw_file_sha256, value.projection.sha256);
  assert.equal(
    receipt.manifest_acceptance_deadline,
    FUTURE_MANIFEST_ACCEPTANCE_DEADLINE,
  );
  assert.equal(receipt.source_bytes_copied_exactly, true);
  assert.equal(receipt.signer_key_material_accepted, false);
  assert.equal(receipt.raw_secret_input_accepted, false);
  assert.equal(receipt.activation_mutation_authorized, false);
  assert.equal(receipt.live_traffic_authorized, false);
  const target = targetPath(value);
  assert.deepEqual(fs.readFileSync(target), value.source.bytes);
  assert.equal(fs.statSync(target).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(value.exchange), [
    PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
  ]);
});

test("helper rejects secret/signer flags and any source inside the exchange", (t) => {
  const value = fixture(t);
  for (const argv of [
    ["--private-key", "0xdead"],
    ["--account", "dev"],
    ["--rpc-url", "https://example.test"],
    ["--source", value.source.path, "--request", value.request.path],
  ]) {
    assert.throws(
      () => parsePhalaProductionPostlaunchAttachmentArgs(argv),
      /requires exactly|unsupported/,
    );
  }
  assert.throws(
    () => attachPhalaProductionPostlaunchManifest({
      ...attachInput(value),
      source: path.join(value.exchange, "source.json"),
    }),
    /outside the exchange/,
  );
  assert.throws(
    () => attachPhalaProductionPostlaunchManifest({
      ...attachInput(value),
      privateKey: "0xdead",
    }),
    /fields do not match the exact schema/,
  );
});

test("wrong mode, noncanonical JSON, and lineage mismatch fail before create", (t) => {
  for (const scenario of ["mode", "noncanonical", "mismatch"]) {
    const value = fixture(t);
    if (scenario === "mode") fs.chmodSync(value.source.path, 0o644);
    if (scenario === "noncanonical") {
      fs.writeFileSync(value.source.path, JSON.stringify(value.manifestValue), {
        mode: 0o600,
      });
    }
    if (scenario === "mismatch") {
      const changed = { ...value.manifestValue, batch_id: "different-batch" };
      fs.writeFileSync(
        value.source.path,
        canonicalResidentJsonText(changed),
        { mode: 0o600 },
      );
    }
    assert.throws(
      () => attachPhalaProductionPostlaunchManifest(attachInput(value)),
      /mode-0600|canonical|lineage or posture/,
    );
    assertTargetAbsent(value);
  }
});

test("legacy request v1 and manifest v1 are rejected before target create", (t) => {
  for (const scenario of ["request-v1", "manifest-v1"]) {
    const value = fixture(t);
    if (scenario === "request-v1") {
      writeCanonical(value.root, "request.json", {
        ...value.requestValue,
        schema: "dnai.phala-production-postlaunch-authority-request.v1",
      });
    } else {
      writeCanonical(value.root, "source.json", {
        ...value.manifestValue,
        schema: "dnai.phala-production-postlaunch-activation-input-manifest.v1",
      });
    }
    assert.throws(
      () => attachPhalaProductionPostlaunchManifest(attachInput(value)),
      /request posture|manifest lineage or posture/,
    );
    assertTargetAbsent(value);
  }
});

test("expired fixed manifest acceptance deadline is rejected before create", (t) => {
  const value = fixture(t);
  writeCanonical(value.root, "request.json", {
    ...value.requestValue,
    manifest_acceptance_deadline: EXPIRED_MANIFEST_ACCEPTANCE_DEADLINE,
  });
  assert.throws(
    () => attachPhalaProductionPostlaunchManifest(attachInput(value)),
    /manifest acceptance deadline expired/,
  );
  assertTargetAbsent(value);
});

test("Stage-B reviewer history must remain exact mode-0600 canonical bare-array bytes", (t) => {
  for (const scenario of [
    "wrong-mode",
    "wrapped-object",
    "noncanonical",
    "digest-substitution",
  ]) {
    const value = fixture(t);
    const history = value.dependencies.stageBReviewerStatusHistory;
    if (scenario === "wrong-mode") {
      fs.chmodSync(history.path, 0o644);
    } else if (scenario === "wrapped-object") {
      const written = writeCanonical(
        value.root,
        path.basename(history.path),
        { history: [] },
      );
      writeCanonical(value.root, "source.json", {
        ...value.manifestValue,
        dependencies: {
          ...value.dependencies,
          stageBReviewerStatusHistory: {
            path: written.path,
            sha256: written.sha256,
          },
        },
      });
    } else if (scenario === "noncanonical") {
      fs.writeFileSync(history.path, "[]", { mode: 0o600 });
      fs.chmodSync(history.path, 0o600);
    } else {
      writeCanonical(
        value.root,
        path.basename(history.path),
        [{ epoch: 2 }],
      );
    }
    assert.throws(
      () => attachPhalaProductionPostlaunchManifest(attachInput(value)),
      /exact-mode-0600|canonical bare array|canonical recursively sorted|bytes differ from its binding/,
    );
    assertTargetAbsent(value);
  }
});

test("symlink and hardlink source aliases fail before create", (t) => {
  for (const scenario of ["symlink", "hardlink"]) {
    const value = fixture(t);
    const alias = path.join(value.root, `${scenario}-source.json`);
    if (scenario === "symlink") fs.symlinkSync(value.source.path, alias);
    else fs.linkSync(value.source.path, alias);
    assert.throws(
      () => attachPhalaProductionPostlaunchManifest({
        ...attachInput(value),
        source: alias,
      }),
      /symlink|single-link|exactly one hard link/,
    );
    assertTargetAbsent(value);
  }
});

test("existing or extra authority entry is rejected without clobber", (t) => {
  for (const scenario of ["target", "extra"]) {
    const value = fixture(t);
    const basename = scenario === "target"
      ? PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME
      : "unexpected.json";
    const existingPath = path.join(value.exchange, basename);
    const existing = Buffer.from("existing-authority\n", "utf8");
    fs.writeFileSync(existingPath, existing, { mode: 0o600 });
    assert.throws(
      () => attachPhalaProductionPostlaunchManifest(attachInput(value)),
      /exactly empty/,
    );
    assert.deepEqual(fs.readFileSync(existingPath), existing);
  }
});

test("concurrent create has exactly one winner and never exposes a temp inode", async (t) => {
  const value = fixture(t);
  const args = [
    "--source", value.source.path,
    "--request", value.request.path,
    "--projection", value.projection.path,
    "--exchange", value.exchange,
    "--expected-anchor-sha256", value.anchor,
  ];
  const outcomes = await Promise.allSettled([
    execFileAsync(process.execPath, [CLI_PATH, ...args]),
    execFileAsync(process.execPath, [CLI_PATH, ...args]),
  ]);
  assert.equal(outcomes.filter((entry) => entry.status === "fulfilled").length, 1);
  assert.equal(outcomes.filter((entry) => entry.status === "rejected").length, 1);
  assert.deepEqual(fs.readdirSync(value.exchange), [
    PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
  ]);
  assert.deepEqual(
    fs.readFileSync(path.join(
      value.exchange,
      PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
    )),
    value.source.bytes,
  );
});
