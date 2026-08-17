import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  CLOUDFLARE_D_BUILD_CONTROL_PATHS,
} from "./cloudflare-release-artifact-core.mjs";
import {
  CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
  CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
  CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS,
  CLOUDFLARE_EXTERNAL_BUILD_FILES,
  __test as externalClosureTest,
  cloudflareExternalBuildClosureSha256,
  normalizeCloudflareExternalBuildClosure,
} from "./cloudflare-external-build-closure-core.mjs";
import {
  FRONTEND_BUILD_AUTHORITY_ROOT_FIELDS,
  FRONTEND_BUILD_CANDIDATE_SCHEMA,
  FRONTEND_BUILD_CANDIDATE_STATUS,
  FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
  FRONTEND_BUILD_EXCLUDED_CYCLIC_INPUT_FLAGS,
  FRONTEND_BUILD_INPUT_MANIFEST_SCHEMA,
  FRONTEND_BUILD_INPUT_MANIFEST_TRUTH_STATUS,
  FRONTEND_BUILD_LIVE_CANDIDATE_PROJECTION,
  FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS,
  FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS,
  FRONTEND_BUILD_RAW_INPUT_PROJECTION,
  FRONTEND_BUILD_ROYALTY_RELEASE_HISTORY_FIELDS,
  FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS,
  assertFrontendBuildCandidateLineage,
  canonicalFrontendBuildInputManifestText,
  createFrontendBuildCandidateReceipt,
  createFrontendBuildInputManifest,
  createFrontendBuildPreDPrivateInputs,
  frontendBuildCandidateReceiptSha256,
  frontendBuildInputFile,
  frontendBuildInputManifestSha256,
  frontendBuildProjectedEnvSha256,
  normalizeFrontendBuildCandidateReceipt,
  normalizeFrontendBuildInputManifest,
} from "./frontend-build-candidate-core.mjs";

const pin = (byte) => `sha256:${byte.toString(16).padStart(2, "0").repeat(32)}`;
const labeledPin = (label) => `sha256:${createHash("sha256")
  .update(`dnai-test-pin:${label}`, "utf8")
  .digest("hex")}`;
const ROOTS = [1, 2, 3, 4, 5]
  .map((value) => `0x${value.toString(16).padStart(40, "0")}`);
const RELEASE_SHA = "a".repeat(40);
const SERIALIZED_ENV = `VITE_RELEASE_SHA=${RELEASE_SHA}\n`;

const LINEAGE = Object.freeze(Object.fromEntries(
  FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS.map((field, index) => [
    field,
    pin(80 + index),
  ]),
));
const AUTHORITY_ROOTS = Object.freeze({
  contract_release_set_sha256:
    LINEAGE.fresh_contract_deployment_receipt_sha256,
  cvm_release_set_sha256:
    LINEAGE.seven_cvm_launch_completion_receipt_sha256,
  qvl_measurement_policy_set_sha256:
    LINEAGE.qvl_measurement_policy_set_sha256,
});
const BINDING = Object.freeze({
  deploymentIntentSha256: LINEAGE.deployment_intent_sha256,
  reviewerAuthorityGenesisAcceptanceSha256:
    LINEAGE.reviewer_authority_genesis_acceptance_sha256,
  ceremonyAuthorizationSha256: LINEAGE.ceremony_authorization_sha256,
  runtimeAuthorityDependencySha256:
    LINEAGE.runtime_authority_dependency_sha256,
  computeWorkloadActivationObservationSha256:
    LINEAGE.compute_workload_activation_observation_sha256,
  frontendBuildSha256: pin(200),
});

function preDPrivateInputs() {
  return createFrontendBuildPreDPrivateInputs({
    liveCandidatePrebuildProjectionSha256: pin(1),
    rawSha256ByFlag: Object.fromEntries(
      FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS.map((flag, index) => [
        flag,
        pin(2 + index),
      ]),
    ),
  });
}

function royaltyReleaseHistoryBinding(inputs = preDPrivateInputs()) {
  const historyReceipt = inputs.find(
    ({ flag }) => flag === "--royalty-release-history-receipt",
  );
  assert.ok(historyReceipt);
  return {
    history_receipt_raw_sha256: historyReceipt.sha256,
    history_sha256: LINEAGE.royalty_release_history_sha256,
    receipt_sha256: LINEAGE.royalty_release_history_receipt_sha256,
  };
}

function buildControls() {
  return CLOUDFLARE_D_BUILD_CONTROL_PATHS.map((controlPath, index) => ({
    path: controlPath,
    sha256: pin(160 + index),
  }));
}

function withExternalClosureAggregate(value) {
  const payload = {
    schema: value.schema,
    truth_status: value.truth_status,
    entrypoints: value.entrypoints,
    files: value.files,
    raw_secret_egress: value.raw_secret_egress,
  };
  return {
    ...value,
    aggregate_sha256: `sha256:${createHash("sha256")
      .update(externalClosureTest.AGGREGATE_DOMAIN, "utf8")
      .update("\0", "ascii")
      .update(`${JSON.stringify(payload, null, 2)}\n`, "utf8")
      .digest("hex")}`,
  };
}

function externalBuildClosure() {
  return normalizeCloudflareExternalBuildClosure(withExternalClosureAggregate({
    schema: CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
    truth_status: CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
    entrypoints: CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS.map(({ kind, path }) => ({
      kind,
      path,
    })),
    files: CLOUDFLARE_EXTERNAL_BUILD_FILES.map(({ kind, path }, index) => ({
      kind,
      path,
      mode: 0o600,
      size: index + 1,
      sha256: pin(10 + index),
    })),
    aggregate_sha256: pin(250),
    raw_secret_egress: false,
  }));
}

function manifest() {
  const inputs = preDPrivateInputs();
  return createFrontendBuildInputManifest({
    releaseSha: RELEASE_SHA,
    gitTreeOid: `sha1:${"b".repeat(40)}`,
    sourceFingerprintSha256: pin(150),
    preDPrivateInputs: inputs,
    semanticLineage: LINEAGE,
    royaltyReleaseHistoryBinding: royaltyReleaseHistoryBinding(inputs),
    serializedEnv: SERIALIZED_ENV,
    primaryRpcUrl: "https://sepolia.base.org",
    secondaryRpcUrl: "https://base-sepolia-rpc.publicnode.com",
    qvlVerifierRoots: ROOTS,
    authorityRoots: AUTHORITY_ROOTS,
    buildControls: buildControls(),
    externalBuildClosure: externalBuildClosure(),
  });
}

function receipt() {
  return createFrontendBuildCandidateReceipt({
    releaseSha: RELEASE_SHA,
    serializedEnv: SERIALIZED_ENV,
    ...BINDING,
    inputManifest: manifest(),
  });
}

test("D manifest freezes the exact acyclic producer/validator recipe and digest KAT", () => {
  const value = manifest();
  assert.equal(value.schema, FRONTEND_BUILD_INPUT_MANIFEST_SCHEMA);
  assert.equal(value.truth_status, FRONTEND_BUILD_INPUT_MANIFEST_TRUTH_STATUS);
  assert.equal(value.pre_D_private_inputs.length, 36);
  assert.deepEqual(
    value.pre_D_private_inputs.map(({ flag }) => flag),
    FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS,
  );
  assert.deepEqual(FRONTEND_BUILD_EXCLUDED_CYCLIC_INPUT_FLAGS, [
    "--live-activation-authority",
    "--frontend-build-candidate-receipt",
  ]);
  assert.equal(value.pre_D_private_inputs[0].projection,
    FRONTEND_BUILD_LIVE_CANDIDATE_PROJECTION);
  assert.equal(value.pre_D_private_inputs.slice(1).every(
    ({ projection }) => projection === FRONTEND_BUILD_RAW_INPUT_PROJECTION,
  ), true);
  assert.equal(value.frontend_dist_included, false);
  assert.equal(value.raw_secret_egress, false);
  assert.deepEqual(value.build_controls.map(({ path }) => path),
    CLOUDFLARE_D_BUILD_CONTROL_PATHS);
  assert.deepEqual(value.external_build_closure, externalBuildClosure());
  assert.match(
    cloudflareExternalBuildClosureSha256(value.external_build_closure),
    /^sha256:[0-9a-f]{64}$/,
  );
  assert.deepEqual(Object.keys(value.semantic_lineage),
    FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS);
  assert.deepEqual(Object.keys(value.royalty_release_history),
    FRONTEND_BUILD_ROYALTY_RELEASE_HISTORY_FIELDS);
  assert.deepEqual(value.royalty_release_history,
    royaltyReleaseHistoryBinding(value.pre_D_private_inputs));
  assert.deepEqual(Object.keys(value.authority_roots),
    FRONTEND_BUILD_AUTHORITY_ROOT_FIELDS);
  assert.equal(value.projected_env_sha256,
    frontendBuildProjectedEnvSha256(SERIALIZED_ENV));
  assert.deepEqual(normalizeFrontendBuildInputManifest(value), value);
  assert.equal(
    canonicalFrontendBuildInputManifestText(value),
    `${JSON.stringify(value, null, 2)}\n`,
  );
  // Frozen after the schema fixture settles; this assertion prevents a silent
  // producer/validator recipe drift.
  assert.equal(
    frontendBuildInputManifestSha256(value),
    "sha256:421ea1a794b17587b522106143bfcbd281ea271ffe5b9a80ed76ec97e7db0f52",
  );
});

test("D receipt is hash-only, nonauthorizing, and independently reprojectable", () => {
  const value = receipt();
  assert.deepEqual(Object.keys(value).sort(), [
    "ceremony_authorization_sha256",
    "chain_id",
    "compute_workload_activation_observation_sha256",
    "deployment_intent_sha256",
    "frontend_build_sha256",
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
  ]);
  assert.equal(value.schema, FRONTEND_BUILD_CANDIDATE_SCHEMA);
  assert.equal(value.status, FRONTEND_BUILD_CANDIDATE_STATUS);
  assert.equal(value.truth_status, FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS);
  assert.equal(value.frontend_build_sha256, BINDING.frontendBuildSha256);
  assert.equal(value.release_inputs_sha256,
    frontendBuildInputManifestSha256(manifest()));
  assert.equal(value.release_env_sha256,
    frontendBuildProjectedEnvSha256(SERIALIZED_ENV));
  assert.equal(value.royalty_release_history_sha256,
    manifest().royalty_release_history.history_sha256);
  assert.equal(value.royalty_release_history_receipt_sha256,
    manifest().royalty_release_history.receipt_sha256);
  assert.match(frontendBuildCandidateReceiptSha256(value), /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(value).includes("VITE_"), false);
  assert.equal(JSON.stringify(value).includes("/Users/"), false);
  assert.deepEqual(normalizeFrontendBuildCandidateReceipt(value), value);
  assert.deepEqual(assertFrontendBuildCandidateLineage({
    receipt: value,
    serializedEnv: SERIALIZED_ENV,
    inputManifest: manifest(),
    authorityBinding: BINDING,
  }), value);
});

test("D manifest rejects omission, substitution, reordering, extras, and cyclic inputs", () => {
  const base = manifest();
  const mutations = [
    (copy) => { copy.pre_D_private_inputs.pop(); },
    (copy) => { copy.pre_D_private_inputs[1].flag = "--live-activation-authority"; },
    (copy) => { copy.pre_D_private_inputs[1].flag = "--frontend-build-candidate-receipt"; },
    (copy) => { copy.pre_D_private_inputs.reverse(); },
    (copy) => { copy.pre_D_private_inputs.push(structuredClone(copy.pre_D_private_inputs[0])); },
    (copy) => { copy.pre_D_private_inputs[0].projection = FRONTEND_BUILD_RAW_INPUT_PROJECTION; },
    (copy) => { copy.pre_D_private_inputs[1].projection = FRONTEND_BUILD_LIVE_CANDIDATE_PROJECTION; },
    (copy) => { copy.pre_D_private_inputs[2].sha256 = copy.pre_D_private_inputs[1].sha256; },
    (copy) => { delete copy.royalty_release_history; },
    (copy) => { copy.royalty_release_history.unreviewed = pin(253); },
    (copy) => { copy.build_controls.pop(); },
    (copy) => { copy.build_controls[0].path = "web/dist/index.html"; },
    (copy) => { copy.build_controls.reverse(); },
    (copy) => { delete copy.external_build_closure; },
    (copy) => { copy.external_build_closure.entrypoints[0].kind = "module"; },
    (copy) => { copy.external_build_closure.files[0].path = "README-copy.md"; },
    (copy) => { copy.external_build_closure.files[0].kind = "module"; },
    (copy) => { copy.external_build_closure.files[0].mode = 0o777; },
    (copy) => { copy.external_build_closure.files[0].size = 0; },
    (copy) => { copy.external_build_closure.files.push(
      structuredClone(copy.external_build_closure.files[0]),
    ); },
    (copy) => { copy.external_build_closure.aggregate_sha256 = pin(252); },
    (copy) => { copy.frontend_dist_included = true; },
    (copy) => { copy.raw_secret_egress = true; },
    (copy) => { copy.unreviewed = true; },
  ];
  for (const mutate of mutations) {
    const copy = structuredClone(base);
    mutate(copy);
    assert.throws(() => normalizeFrontendBuildInputManifest(copy));
  }
});

test("D rejects independent Royalty H raw, history, and receipt mismatches", () => {
  const mutations = [
    (copy) => { copy.royalty_release_history.history_receipt_raw_sha256 = pin(241); },
    (copy) => { copy.royalty_release_history.history_sha256 = pin(242); },
    (copy) => { copy.royalty_release_history.receipt_sha256 = pin(243); },
    (copy) => {
      const historyReceipt = copy.pre_D_private_inputs.find(
        ({ flag }) => flag === "--royalty-release-history-receipt",
      );
      historyReceipt.sha256 = pin(244);
    },
    (copy) => { copy.semantic_lineage.royalty_release_history_sha256 = pin(245); },
    (copy) => {
      copy.semantic_lineage.royalty_release_history_receipt_sha256 = pin(246);
    },
  ];
  for (const mutate of mutations) {
    const copy = structuredClone(manifest());
    mutate(copy);
    assert.throws(
      () => normalizeFrontendBuildInputManifest(copy),
      /Royalty H raw bytes, receipt digest, and history digest are not exact-bound/,
    );
  }
});

test("pre-D projector refuses raw live-candidate, raw C, raw D, and alternate projections", () => {
  const raw = Object.fromEntries(
    FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS.map((flag, index) => [flag, pin(2 + index)]),
  );
  assert.deepEqual(
    createFrontendBuildPreDPrivateInputs({
      liveCandidatePrebuildProjectionSha256: pin(1),
      rawSha256ByFlag: raw,
    }),
    preDPrivateInputs(),
  );
  for (const forbidden of [
    "--release",
    "--live-activation-authority",
    "--frontend-build-candidate-receipt",
    "--unknown",
  ]) {
    assert.throws(() => createFrontendBuildPreDPrivateInputs({
      liveCandidatePrebuildProjectionSha256: pin(1),
      rawSha256ByFlag: { ...raw, [forbidden]: pin(240) },
    }));
  }
  const missing = { ...raw };
  delete missing[FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS[0]];
  assert.throws(() => createFrontendBuildPreDPrivateInputs({
    liveCandidatePrebuildProjectionSha256: pin(1),
    rawSha256ByFlag: missing,
  }));
});

test("every raw/projection, lineage, source, env, RPC, QVL, contract, CVM, and control pin affects D", () => {
  const base = manifest();
  const baseDigest = frontendBuildInputManifestSha256(base);
  const mutations = [
    (copy) => { copy.pre_D_private_inputs[0].sha256 = pin(220); },
    (copy) => { copy.pre_D_private_inputs.at(-1).sha256 = pin(221); },
    (copy) => { copy.semantic_lineage.release_core_sha256 = pin(222); },
    (copy) => { copy.semantic_lineage.compute_workload_activation_observation_sha256 = pin(223); },
    (copy) => { copy.git_source.git_tree_oid = `sha1:${"c".repeat(40)}`; },
    (copy) => { copy.git_source.source_fingerprint_sha256 = pin(224); },
    (copy) => { copy.projected_env_sha256 = pin(225); },
    (copy) => { copy.secondary_rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"; },
    (copy) => { copy.qvl_verifier_roots[4] = `0x${"f".repeat(40)}`; },
    (copy) => {
      copy.semantic_lineage.fresh_contract_deployment_receipt_sha256 = pin(226);
      copy.authority_roots.contract_release_set_sha256 = pin(226);
    },
    (copy) => {
      copy.semantic_lineage.seven_cvm_launch_completion_receipt_sha256 = pin(227);
      copy.authority_roots.cvm_release_set_sha256 = pin(227);
    },
    (copy) => { copy.build_controls[0].sha256 = pin(228); },
    (copy) => {
      copy.external_build_closure.files[0].sha256 = pin(229);
      copy.external_build_closure = withExternalClosureAggregate(
        copy.external_build_closure,
      );
    },
  ];
  for (const mutate of mutations) {
    const copy = structuredClone(base);
    mutate(copy);
    const normalized = normalizeFrontendBuildInputManifest(copy);
    assert.notEqual(frontendBuildInputManifestSha256(normalized), baseDigest);
  }
});

test("every exact private input, build control, external file, and lineage pin changes D", () => {
  const base = manifest();
  const baseDigest = frontendBuildInputManifestSha256(base);
  const assertMutationChangesD = (mutate, label) => {
    const copy = structuredClone(base);
    mutate(copy);
    const normalized = normalizeFrontendBuildInputManifest(copy);
    assert.notEqual(
      frontendBuildInputManifestSha256(normalized),
      baseDigest,
      `${label} did not affect D`,
    );
  };

  for (let index = 0; index < base.pre_D_private_inputs.length; index += 1) {
    assertMutationChangesD((copy) => {
      const replacement = labeledPin(`private:${index}`);
      copy.pre_D_private_inputs[index].sha256 = replacement;
      if (copy.pre_D_private_inputs[index].flag
        === "--royalty-release-history-receipt") {
        copy.royalty_release_history.history_receipt_raw_sha256 = replacement;
      }
    }, `private input ${index}`);
  }
  for (let index = 0; index < base.build_controls.length; index += 1) {
    assertMutationChangesD((copy) => {
      copy.build_controls[index].sha256 = labeledPin(`control:${index}`);
    }, `build control ${index}`);
  }
  for (let index = 0; index < base.external_build_closure.files.length; index += 1) {
    assertMutationChangesD((copy) => {
      copy.external_build_closure.files[index].sha256 = labeledPin(`external:${index}`);
      copy.external_build_closure = withExternalClosureAggregate(
        copy.external_build_closure,
      );
    }, `external closure file ${index}`);
  }
  const authorityForLineage = new Map([
    ["fresh_contract_deployment_receipt_sha256", "contract_release_set_sha256"],
    ["seven_cvm_launch_completion_receipt_sha256", "cvm_release_set_sha256"],
    ["qvl_measurement_policy_set_sha256", "qvl_measurement_policy_set_sha256"],
  ]);
  for (const field of FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS) {
    assertMutationChangesD((copy) => {
      const replacement = labeledPin(`lineage:${field}`);
      copy.semantic_lineage[field] = replacement;
      const authorityField = authorityForLineage.get(field);
      if (authorityField) copy.authority_roots[authorityField] = replacement;
      if (field === "royalty_release_history_sha256") {
        copy.royalty_release_history.history_sha256 = replacement;
      }
      if (field === "royalty_release_history_receipt_sha256") {
        copy.royalty_release_history.receipt_sha256 = replacement;
      }
    }, `semantic lineage ${field}`);
  }
});

test("D enforces transitive L-R-B-O/env roots and rejects candidate-lineage drift", () => {
  for (const [bindingKey, lineageKey] of [
    ["deploymentIntentSha256", "deployment_intent_sha256"],
    ["reviewerAuthorityGenesisAcceptanceSha256", "reviewer_authority_genesis_acceptance_sha256"],
    ["ceremonyAuthorizationSha256", "ceremony_authorization_sha256"],
    ["runtimeAuthorityDependencySha256", "runtime_authority_dependency_sha256"],
    ["computeWorkloadActivationObservationSha256", "compute_workload_activation_observation_sha256"],
  ]) {
    assert.throws(() => createFrontendBuildCandidateReceipt({
      releaseSha: RELEASE_SHA,
      serializedEnv: SERIALIZED_ENV,
      ...BINDING,
      [bindingKey]: pin(230),
      inputManifest: manifest(),
    }), new RegExp("exact-bind"));
    const drift = manifest();
    drift.semantic_lineage[lineageKey] = pin(231);
    assert.throws(() => createFrontendBuildCandidateReceipt({
      releaseSha: RELEASE_SHA,
      serializedEnv: SERIALIZED_ENV,
      ...BINDING,
      inputManifest: drift,
    }));
  }
  assert.throws(() => createFrontendBuildCandidateReceipt({
    releaseSha: RELEASE_SHA,
    serializedEnv: `${SERIALIZED_ENV}VITE_EXTRA=true\n`,
    ...BINDING,
    inputManifest: manifest(),
  }), /exact-bind/);
});

test("absolute host paths project only to repo-relative POSIX file pins", () => {
  assert.deepEqual(frontendBuildInputFile({
    repoRoot: "/workspace/dnai-wikigen",
    filePath: "/workspace/dnai-wikigen/web/package.json",
    bytes: Buffer.from("{}\n"),
  }), {
    path: "web/package.json",
    sha256: "sha256:ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
  });
  for (const value of [
    { repoRoot: "workspace", filePath: "/workspace/a", bytes: Buffer.from("{}") },
    { repoRoot: "/workspace", filePath: "workspace/a", bytes: Buffer.from("{}") },
    { repoRoot: "/workspace", filePath: "/outside/a", bytes: Buffer.from("{}") },
    { repoRoot: "/workspace", filePath: "/workspace/a", bytes: Buffer.alloc(1) },
  ]) {
    assert.throws(() => frontendBuildInputFile(value));
  }
});
