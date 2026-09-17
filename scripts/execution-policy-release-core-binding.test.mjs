import assert from "node:assert/strict";
import test from "node:test";
import {
  LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
  PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
  finalReleaseAuthorityCoreFromCandidate,
  validateExecutionPolicyReleaseCoreBinding,
} from "../web/scripts/execution-policy-release-core-binding.mjs";
import { syntheticCurrentReleaseCoreBindingFixture } from "./execution-policy-release-core-binding.fixture.mjs";
import { finalReleaseAuthorityCoreDigest, normalizeFinalReleaseAuthorityCore } from "./execution-policy-release-core.mjs";
import { rebindKnownVectorV4AuthorityFixture } from "./execution-policy-release-core.fixture.mjs";
import { syntheticPreCeremonyRuntimeAuthorityFixture } from "./pre-ceremony-runtime-authority.fixture.mjs";
import { preCeremonyRuntimeAuthoritySha256 } from "./pre-ceremony-runtime-authority-core.mjs";
import { syntheticReleaseAuthorityStagesFixture } from "./release-authority-current-stages.fixture.mjs";
import { projectRoyaltyReleaseHistoryReceipt } from "./royalty-release-history-receipt-core.mjs";

const base = await syntheticCurrentReleaseCoreBindingFixture();
const clone = () => structuredClone(base);
const pin = (byte) => `sha256:${byte.repeat(32)}`;
function options(fixture, authorityStage = "prebuild") {
  return {
    authorityStage,
    authenticatedRuntimeAuthoritySha256: fixture.authenticatedRuntimeAuthoritySha256,
    royaltyReleaseHistoryReceipt: fixture.royaltyReleaseHistoryReceipt,
  };
}
function validate(fixture, overrides = {}) {
  return validateExecutionPolicyReleaseCoreBinding(fixture.candidate, fixture.core,
    fixture.runtimeAuthority, { ...options(fixture), ...overrides });
}
function rebind(core) {
  rebindKnownVectorV4AuthorityFixture(core, {
    deploymentIntentSha256: core.deployment_intent_sha256,
    cvmLaunchIntentSha256: core.cvm_launch_intent_sha256,
  });
  return normalizeFinalReleaseAuthorityCore(core);
}

test("current v4 core binds nine shared feature flags, authenticated current R, and H before C exists", () => {
  const result = validate(base);
  assert.equal(Object.keys(base.candidate.requested_features).length, 9);
  assert.equal(Object.keys(result.core.requested_features).length, 12);
  assert.equal(base.candidate.execution_policy.rollback_anchor.schema, "dnai.execution-policy-rollback-anchor.v1");
  assert.equal(result.core.execution_policy.rollback_anchor_target.schema, "dnai.execution-policy-rollback-anchor.v2");
  assert.equal(result.coreSha256, `sha256:${finalReleaseAuthorityCoreDigest(base.core)}`);
  assert.equal(result.digest, result.coreSha256.slice(7));
  assert.equal(result.runtimeAuthoritySha256, base.authenticatedRuntimeAuthoritySha256);
  assert.equal(result.runtimeAuthority.activation_execution_authorized, false);
  assert.equal(result.runtimeAuthority.live_traffic_authorized, false);
  assert.equal(Object.hasOwn(base.candidate.operator_policy, "live_activation_authority_sha256"), false);
  assert.equal(base.candidate.operator_policy.schema, PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.core.shared_release_lineage));
  assert.ok(Object.isFrozen(result.runtimeAuthority.post_measurement_activation_plan.target));
});

test("live binding requires C pin but leaves its signature authentication to the caller", () => {
  const f = clone();
  assert.throws(() => validate(f, { authorityStage: "live" }), /live authority evidence fields/);
  f.candidate.operator_policy.live_activation_authority_sha256 = pin("cd");
  assert.throws(() => validate(f, { authorityStage: "live" }), /live authority evidence schema/);
  f.candidate.operator_policy.schema = LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA;
  assert.equal(validate(f, { authorityStage: "live" }).coreSha256, validate(base).coreSha256);
  assert.throws(() => validate(f), /prebuild authority evidence fields/);
  f.candidate.operator_policy.live_activation_authority_sha256 = "sha256:" + "0".repeat(64);
  assert.throws(() => validate(f, { authorityStage: "live" }), /live-activation-authority SHA-256/);
});

test("current prebuild and live bindings reject each other's authority schema", () => {
  const f = clone();
  f.candidate.operator_policy.schema = LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA;
  assert.throws(() => validate(f), /prebuild authority evidence schema/);
  f.candidate.operator_policy.schema = PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA;
  assert.equal(validate(f).coreSha256, validate(base).coreSha256);
  f.candidate.operator_policy.live_activation_authority_sha256 = pin("cd");
  assert.throws(() => validate(f, { authorityStage: "live" }), /live authority evidence schema/);
  f.candidate.operator_policy.schema = LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA;
  assert.equal(validate(f, { authorityStage: "live" }).coreSha256, validate(base).coreSha256);
});

for (const royaltyExecutionMode of ["activate_and_unpause", "recover_reverted_unpause"]) {
  test(`current H v2 binds its actual ${royaltyExecutionMode} history without rewriting it`, async () => {
    const stages = await syntheticReleaseAuthorityStagesFixture({ royaltyExecutionMode });
    const history = projectRoyaltyReleaseHistoryReceipt({
      contracts: stages.stageTwo.contract_state.contracts,
      commonFinalizedState: stages.stageTwo.common_finalized_state,
      royaltyReleaseHistory: stages.stageTwo.contract_state.royalty_release_history,
    });
    const f = await syntheticCurrentReleaseCoreBindingFixture({ royaltyReleaseHistoryReceipt: history });
    assert.equal(history.schema, "dnai.royalty-release-history-receipt.v2");
    const result = validate(f);
    assert.equal(result.core.royalty_release_history_sha256, history.royalty_release_history_sha256);
    assert.notEqual(result.coreSha256, validate(base).coreSha256);
    assert.equal(result.runtimeAuthoritySha256, base.authenticatedRuntimeAuthoritySha256);
  });
}

test("candidate alone cannot manufacture missing current extension authorities", () => {
  assert.throws(() => finalReleaseAuthorityCoreFromCandidate(base.candidate), /plain-data graph/);
  const f = clone();
  delete f.core.shared_release_lineage;
  assert.throws(() => validate(f), /missing: shared_release_lineage/);
  const old = clone();
  old.core.schema = "dnai.execution-policy-release-core.v3";
  assert.throws(() => validate(old), /schema/);
});

for (const [name, mutate] of [
  ["requested shared feature", (f) => { f.candidate.requested_features.artifact_upload = !f.core.requested_features.artifact_upload; }],
  ["CVM runtime control", (f) => { f.candidate.cvm.runtime_controls.provider_dispatch_enabled = true; }],
  ["CVM image provenance", (f) => { f.candidate.cvm.images[0].source_digest = "f".repeat(40); }],
  ["contract hash", (f) => { f.candidate.contracts.royalty_distributor.runtime_code_hash = `0x${"81".repeat(32)}`; }],
  ["anchor writer", (f) => { f.candidate.execution_policy.rollback_anchor.writer_address = `0x${"82".repeat(20)}`; }],
  ["extra current feature in legacy candidate", (f) => { f.candidate.requested_features.royalty_settlement = true; }],
  ["candidate anchor schema substitution", (f) => { f.candidate.execution_policy.rollback_anchor.schema = "dnai.execution-policy-rollback-anchor.v2"; }],
]) {
  test(`shared-fact mismatch fails closed: ${name}`, () => {
    const f = clone();
    mutate(f);
    assert.throws(() => validate(f), /shared|schema/);
  });
}

test("object order and canonical set order do not invent a different shared core", () => {
  const f = clone();
  f.candidate = Object.fromEntries(Object.entries(f.candidate).reverse());
  f.candidate.cvm.images.reverse();
  f.candidate.cvm.allowed_browser_origins.reverse();
  assert.equal(validate(f).coreSha256, validate(base).coreSha256);
  f.candidate.cvm.allowed_browser_origins.push(f.candidate.cvm.allowed_browser_origins[0]);
  assert.throws(() => validate(f), /shared pre-anchor facts/);
});

test("R cannot authenticate its own digest or substitute the separately authenticated B dependency", () => {
  assert.throws(() => validate(base, { authenticatedRuntimeAuthoritySha256: pin("88") }), /authenticated B dependency/);
  const f = clone();
  f.runtimeAuthority.issued_at += 1;
  f.candidate.operator_policy.runtime_authority_dependency_sha256 = preCeremonyRuntimeAuthoritySha256(f.runtimeAuthority);
  f.candidate.execution_policy.rollback_anchor.release_manifest_commitment = f.candidate.operator_policy.runtime_authority_dependency_sha256.slice(7);
  assert.throws(() => validate(f), /authenticated B dependency/);
});

test("candidate R and rollback commitment remain independent exact pins", () => {
  const f = clone();
  f.candidate.operator_policy.runtime_authority_dependency_sha256 = pin("89");
  assert.throws(() => validate(f), /runtime-authority dependency/);
  f.candidate.operator_policy.runtime_authority_dependency_sha256 = base.authenticatedRuntimeAuthoritySha256;
  f.candidate.execution_policy.rollback_anchor.release_manifest_commitment = "89".repeat(32);
  assert.throws(() => validate(f), /release-manifest commitment/);
});

test("self-consistent replacement seven-CVM core root cannot replace authenticated R", () => {
  const f = clone();
  f.core.seven_cvm_release_verification_authority_sha256 = pin("83");
  f.core = rebind(f.core);
  assert.throws(() => validate(f), /seven-CVM authority and authenticated runtime/);
});

test("self-consistent main-runtime candidate/core identity must still match R target", () => {
  const f = clone();
  f.core.cvm.cvm_id = "cvm-another-main";
  f.candidate.cvm.cvm_id = f.core.cvm.cvm_id;
  f.core = rebind(f.core);
  assert.throws(() => validate(f), /core main-runtime cvm_id/);
});

test("shared contract substitution cannot drift from authenticated runtime contract bindings", () => {
  const f = clone();
  f.core.contracts.diligence_room.address = `0x${"84".repeat(20)}`;
  f.candidate.contracts.diligence_room.address = f.core.contracts.diligence_room.address;
  assert.throws(() => validate(f), /runtime DiligenceRoom address/);
});

test("historical embedded release authority is not accepted on the current binding path", () => {
  const f = clone();
  f.runtimeAuthority = syntheticPreCeremonyRuntimeAuthorityFixture({
    releaseSha: f.core.release_sha,
    deploymentIntentSha256: f.core.deployment_intent_sha256,
    cvmLaunchIntentSha256: f.core.cvm_launch_intent_sha256,
  });
  f.authenticatedRuntimeAuthoritySha256 = preCeremonyRuntimeAuthoritySha256(f.runtimeAuthority);
  f.candidate.operator_policy.runtime_authority_dependency_sha256 = f.authenticatedRuntimeAuthoritySha256;
  f.candidate.execution_policy.rollback_anchor.release_manifest_commitment = f.authenticatedRuntimeAuthoritySha256.slice(7);
  assert.throws(() => validate(f), /current runtime release-verification authority schema/);
});

for (const [field, message] of [
  ["royalty_release_history_receipt_sha256", /Royalty H receipt digest/],
  ["royalty_release_history_sha256", /Royalty history digest/],
]) {
  test(`Royalty H independently binds ${field}`, () => {
    const f = clone();
    f.core[field] = pin("85");
    assert.throws(() => validate(f), message);
  });
}

test("H contract byte identity cannot be replaced through matching candidate/core edits", () => {
  const f = clone();
  f.core.execution_policy.rollback_anchor_target.runtime_code_hash = `0x${"86".repeat(32)}`;
  f.candidate.execution_policy.rollback_anchor.runtime_code_hash = f.core.execution_policy.rollback_anchor_target.runtime_code_hash;
  assert.throws(() => validate(f), /Royalty H anchor runtime hash/);
});

test("H receipt internal validation and core active-state hash remain mandatory", () => {
  const f = clone();
  f.royaltyReleaseHistoryReceipt.royalty_release_history_sha256 = pin("87");
  assert.throws(() => validate(f), /history|receipt/);
  const brokenCore = clone();
  brokenCore.core.royalty_release_active_state_sha256 = pin("87");
  assert.throws(() => validate(brokenCore), /active-state digest/);
});

test("Royalty template ceremony nonce is observed runtime lineage, not a free prescription", () => {
  const f = clone();
  f.core.royalty_settlement_release_binding_template.ceremony_nonce = `0x${"88".repeat(32)}`;
  assert.throws(() => validate(f), /Royalty template ceremony nonce/);
});

test("remaining reviewed prescriptions alter the D/C core commitment without pretending R authenticated them", () => {
  const f = clone();
  f.core.requested_features.compute_workload_wallet_adoption = !f.core.requested_features.compute_workload_wallet_adoption;
  f.core.compute_workload_wallet_adoption.enabled = f.core.requested_features.compute_workload_wallet_adoption;
  f.core.royalty_settlement_release_binding_template.royalty_qvl_policy_template_sha256 = pin("92");
  const result = validate(f);
  assert.notEqual(result.coreSha256, validate(base).coreSha256);
  assert.equal(result.runtimeAuthoritySha256, base.authenticatedRuntimeAuthoritySha256);
  assert.equal(result.runtimeAuthority.live_traffic_authorized, false);
  f.core.royalty_settlement_release_binding_template.max_authorization_lifetime_seconds = 300;
  assert.throws(() => validate(f), /integer from 600 through 600/);
});

test("binding options are exact and mandatory, with no default live/prebuild fallback", () => {
  assert.throws(() => validateExecutionPolicyReleaseCoreBinding(base.candidate, base.core, base.runtimeAuthority), /plain-data graph/);
  assert.throws(() => validate(base, { authorityStage: "historical" }), /authorityStage/);
  assert.throws(() => validate(base, { expectedCoreSha256: pin("89") }), /options fields/);
  assert.throws(() => validate(base, { royaltyReleaseHistoryReceipt: null }), /receipt|object/);
});

test("candidate, core, options, and H reject executable accessors/proxies without invoking them", () => {
  let accesses = 0;
  for (const which of ["candidate", "core", "royaltyReleaseHistoryReceipt"]) {
    const f = clone();
    Object.defineProperty(f[which], "injected", { enumerable: true, get() { accesses += 1; return true; } });
    assert.throws(() => validate(f), /plain-data graph/);
    assert.equal(accesses, 0);
  }
  const f = clone();
  f.candidate = new Proxy(f.candidate, { ownKeys() { accesses += 1; return []; } });
  assert.throws(() => validate(f), /Proxy objects/);
  const optionProxy = new Proxy(options(base), { ownKeys() { accesses += 1; return []; } });
  assert.throws(() => validateExecutionPolicyReleaseCoreBinding(base.candidate, base.core, base.runtimeAuthority, optionProxy), /Proxy objects/);
  assert.equal(accesses, 0);
});

test("returned normalized authority is detached from subsequent caller mutations", () => {
  const f = clone();
  const result = validate(f);
  const digest = result.coreSha256;
  f.core.royalty_settlement_release_binding_template.ceremony_nonce = `0x${"89".repeat(32)}`;
  f.candidate.cvm.cvm_id = "cvm-mutated";
  f.royaltyReleaseHistoryReceipt.royalty_release_history_sha256 = pin("89");
  assert.equal(result.coreSha256, digest);
  assert.equal(result.coreSha256, `sha256:${finalReleaseAuthorityCoreDigest(result.core)}`);
});
