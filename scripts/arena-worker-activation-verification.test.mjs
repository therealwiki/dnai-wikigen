import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  canonicalCvmLaunchIntentCoreArtifactText,
  createDraftCvmLaunchIntentCore,
  cvmLaunchIntentCoreDigest,
} from "./cvm-launch-intent-core.mjs";
import {
  canonicalFinalReleaseAuthorityCoreArtifactText,
  finalReleaseAuthorityCoreDigest,
} from "./execution-policy-release-core.mjs";
import {
  knownVector,
  rebindKnownVectorV4AuthorityFixture,
} from "./execution-policy-release-core.fixture.mjs";
import {
  canonicalArtifactSha256,
  canonicalArtifactText,
  createDraftAuthorityReviewEnvelope,
  createDraftDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import {
  readReviewedFinalAuthorityRuntimeProjection,
} from "./reviewed-final-authority-runtime.mjs";
import {
  PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
} from "./phala-post-measurement-activation-receipt-core.mjs";
import {
  phalaArenaWorkerPresenceEndpointCommitmentSha256,
} from "./phala-post-measurement-activation-receipt.mjs";
import {
  ARENA_WORKER_CAPABILITY_SCHEMA_VERSION,
  ARENA_WORKER_CAPABILITY_WARNING,
  ARENA_WORKER_CATALOG_MANIFEST_HASH,
  ARENA_WORKER_CHALLENGE_ID,
  ARENA_WORKER_CHALLENGE_KEY,
  ARENA_WORKER_CHALLENGE_VERSION,
  ARENA_WORKER_SAFE_IR_POLICY_COMMITMENT,
  ARENA_WORKER_SAFE_IR_RUNTIME,
  __test,
  arenaWorkerHeartbeatBindingSha256,
  arenaWorkerReleaseBindingSha256,
  assertVerifiedArenaWorkerActivationProof,
  canonicalArenaWorkerCapabilityV2Text,
  normalizeArenaWorkerCapabilityV2,
  normalizeArenaWorkerCapabilityV2Text,
  readVerifiedArenaWorkerActivationProofDependencies,
  verifyArenaWorkerActivationCapability,
} from "./arena-worker-activation-verification.mjs";

const WORKER_RELEASE_MANIFEST_SHA256 = `sha256:${"b4".repeat(32)}`;

function instant(second) {
  return new Date(second * 1_000).toISOString().replace(".000Z", "Z");
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

function writeOwned(directory, name, bytes) {
  const filePath = path.join(directory, name);
  fs.writeFileSync(filePath, bytes, { flag: "wx", mode: 0o400 });
  fs.chmodSync(filePath, 0o400);
  return filePath;
}

function temporaryDirectory(prefix) {
  return fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()), prefix));
}

function reviewedProjectionFixture(directory, { delegateUrl } = {}) {
  const intent = createDraftDeploymentIntentCore();
  intent.release.releaseSha = "0123456789abcdef0123456789abcdef01234567";
  intent.release.reviewerAuthorityGenesisAcceptanceSha256 =
    `sha256:${"91".repeat(32)}`;
  intent.release.reviewerAuthorityCurrentStatusEpoch = 1;
  intent.release.reviewerAuthorityCurrentStatusSha256 =
    `sha256:${"92".repeat(32)}`;
  intent.deploymentControl.controllerId = "operator-control-01";
  intent.deploymentControl.operatorAddress =
    "0x0000000000000000000000000000000000000001";
  intent.staticContractInputs.diligenceRoom.governanceController =
    "0x0000000000000000000000000000000000000015";
  intent.staticContractInputs.computeCreditVault.developer =
    "0x000000000000000000000000000000000000000a";
  intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment =
    `0x${"22".repeat(32)}`;
  intent.numericPolicy.contract = {
    computeDeveloperFeeBps: 100,
    emailOracleUpgradeDelaySeconds: 172_800,
    tinkerMaxAddBalanceWei: "1000000000000000000",
    tinkerMaxSpendWei: "250000000000000000",
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

  const deploymentIntentSha256 = canonicalArtifactSha256(intent);
  const authority = knownVector();
  authority.cvm.app_id = "a".repeat(40);
  if (delegateUrl) authority.cvm.delegate_url = delegateUrl;
  const legacyBinding =
    authority.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"];
  delete authority.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"];
  authority.arena_registry_bindings[ARENA_WORKER_CHALLENGE_KEY] = {
    ...legacyBinding,
    catalog_manifest_hash: ARENA_WORKER_CATALOG_MANIFEST_HASH,
    metadata_hash: `0x${ARENA_WORKER_CATALOG_MANIFEST_HASH}`,
  };

  const launch = createDraftCvmLaunchIntentCore();
  launch.release_sha = intent.release.releaseSha;
  launch.deployment_intent_sha256 = deploymentIntentSha256;
  launch.contract_deployment_receipt_sha256 = `sha256:${"a1".repeat(32)}`;
  launch.topology_sha256 = `sha256:${"a2".repeat(32)}`;
  launch.image_release_manifest_sha256 = `sha256:${"a3".repeat(32)}`;
  launch.image_attestation_bundle_sha256 = `sha256:${"a4".repeat(32)}`;
  launch.descriptors.forEach((descriptor, index) => {
    descriptor.descriptor_sha256 =
      `sha256:${(index + 16).toString(16).padStart(2, "0").repeat(32)}`;
    descriptor.app_compose_candidate.docker_compose_file_sha256 =
      descriptor.descriptor_sha256;
    descriptor.app_compose_candidate.docker_compose_file_byte_length =
      2_000 + index;
    descriptor.app_compose_candidate.expected_compose_hash =
      (index + 1).toString(16).repeat(64);
  });
  const launchDigest = cvmLaunchIntentCoreDigest(launch);
  rebindKnownVectorV4AuthorityFixture(authority, {
    deploymentIntentSha256,
    cvmLaunchIntentSha256: `sha256:${launchDigest}`,
  });

  const finalAuthoritySha256 =
    `sha256:${finalReleaseAuthorityCoreDigest(authority)}`;
  const evidence = Buffer.from('{"review":"approved"}\n', "utf8");
  const review = createDraftAuthorityReviewEnvelope(
    "final_release_authority",
    finalAuthoritySha256,
  );
  const now = Math.floor(Date.now() / 1_000);
  review.approved_at = instant(now - 60);
  review.expires_at = instant(now + 3_600);
  review.review_evidence_sha256 = `sha256:${createHash("sha256")
    .update(evidence)
    .digest("hex")}`;
  review.reviewers = [
    {
      address: "0x0000000000000000000000000000000000000028",
      controllerId: "reviewer-root-01",
    },
    {
      address: "0x0000000000000000000000000000000000000029",
      controllerId: "reviewer-root-02",
    },
  ];
  const input = {
    deploymentIntentPath: writeOwned(
      directory,
      "deployment-intent.json",
      canonicalArtifactText(intent),
    ),
    cvmLaunchIntentPath: writeOwned(
      directory,
      "cvm-launch-intent.json",
      canonicalCvmLaunchIntentCoreArtifactText(launch),
    ),
    finalAuthorityPath: writeOwned(
      directory,
      "final-authority.json",
      canonicalFinalReleaseAuthorityCoreArtifactText(authority),
    ),
    reviewEnvelopePath: writeOwned(
      directory,
      "review-envelope.json",
      canonicalArtifactText(review),
    ),
    reviewEvidencePath: writeOwned(directory, "review-evidence.json", evidence),
    expectedFinalAuthoritySha256: finalAuthoritySha256,
    expectedReleaseSha: intent.release.releaseSha,
  };
  return readReviewedFinalAuthorityRuntimeProjection(input);
}

function crossLanguageBinding() {
  return {
    release_sha: "1".repeat(40),
    image_digest: `sha256:${"2".repeat(64)}`,
    release_manifest_sha256: `sha256:${"3".repeat(64)}`,
    approved_challenge_set_sha256: `sha256:${"a".repeat(64)}`,
    approved_challenge_key: ARENA_WORKER_CHALLENGE_KEY,
    release_policy_commitment: `0x${"4".repeat(64)}`,
    catalog_manifest_hash: ARENA_WORKER_CATALOG_MANIFEST_HASH,
    runtime: ARENA_WORKER_SAFE_IR_RUNTIME,
    runtime_policy_commitment: ARENA_WORKER_SAFE_IR_POLICY_COMMITMENT,
    compose_hash: "5".repeat(64),
    app_id: "app_arena_safe_ir",
    os_image_hash: "6".repeat(64),
  };
}

function liveCapability(releaseBinding, heartbeatObservedAt) {
  const releaseBindingSha256 = arenaWorkerReleaseBindingSha256(releaseBinding);
  const heartbeatBindingSha256 = arenaWorkerHeartbeatBindingSha256({
    challengeId: ARENA_WORKER_CHALLENGE_ID,
    challengeVersion: ARENA_WORKER_CHALLENGE_VERSION,
    heartbeatObservedAt,
    releaseBindingSha256,
  });
  return {
    surface: "arena_worker_capability",
    schema_version: ARENA_WORKER_CAPABILITY_SCHEMA_VERSION,
    challenge_id: ARENA_WORKER_CHALLENGE_ID,
    challenge_version: ARENA_WORKER_CHALLENGE_VERSION,
    status: "live",
    backend: "release_bound_safe_ir_worker",
    isolation: "independent_job_gate_required",
    live_execution: true,
    worker_connected: true,
    safe_ir_execution_ready: true,
    hostile_general_code_ready: false,
    python_preview_live: false,
    freshness: "fresh",
    evidence_authenticity: "hmac_verified",
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    gate_reason: "ready",
    heartbeat_observed_at: heartbeatObservedAt,
    heartbeat_binding_sha256: heartbeatBindingSha256,
    release_binding_sha256: releaseBindingSha256,
    release_binding: releaseBinding,
    warning: ARENA_WORKER_CAPABILITY_WARNING,
    product_status: "live",
    exact_timing_egress: false,
    internal_error_egress: false,
    raw_candidate_egress: false,
    tdx_attestation_egress: false,
  };
}

function testActivationPlan(projection, checkedAt) {
  return __test.createTestActivationPlan({
    checkedAt,
    reviewedFinalAuthorityRuntimeProjection: projection,
    workerReleaseManifestSha256: WORKER_RELEASE_MANIFEST_SHA256,
  });
}

test("Arena worker JS commitments match the Python schema-v2 KATs", () => {
  const releaseBindingSha256 = arenaWorkerReleaseBindingSha256(
    crossLanguageBinding(),
  );
  assert.equal(
    releaseBindingSha256,
    "sha256:dda813e4a5aa72ad6b8058447919e78d9bc8b07291679d147f536ba6c59ddc99",
  );
  assert.equal(
    arenaWorkerHeartbeatBindingSha256({
      challengeId: ARENA_WORKER_CHALLENGE_ID,
      challengeVersion: ARENA_WORKER_CHALLENGE_VERSION,
      heartbeatObservedAt: 1_899_999_998,
      releaseBindingSha256,
    }),
    "sha256:63a4a9a1ba70fb1027860faa4e25498c2ea9397ecbe9f17c3d38d82f68f4e4d0",
  );
});

test("schema-v2 capability normalization is exact and canonical on the wire", () => {
  const capability = liveCapability(crossLanguageBinding(), 1_899_999_998);
  const text = canonicalArenaWorkerCapabilityV2Text(capability);
  assert.deepEqual(normalizeArenaWorkerCapabilityV2(capability), capability);
  assert.deepEqual(normalizeArenaWorkerCapabilityV2Text(text), capability);
  assert.equal(text, JSON.stringify(capability));

  const mutations = [
    (value) => { value.schema_version = 1; },
    (value) => { value.unreviewed = true; },
    (value) => { value.warning = "TDX verified"; },
    (value) => { value.live_execution = false; },
    (value) => { value.evidence_authenticity = "unverified"; },
    (value) => { value.release_binding.runtime_policy_commitment = `sha256:${"b".repeat(64)}`; },
    (value) => { value.heartbeat_binding_sha256 = `sha256:${"c".repeat(64)}`; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(capability);
    mutate(changed);
    assert.throws(() => normalizeArenaWorkerCapabilityV2(changed));
  }
  assert.throws(() => normalizeArenaWorkerCapabilityV2Text(` ${text}`));
  assert.throws(() => normalizeArenaWorkerCapabilityV2Text(`${text}\n`));
  assert.throws(() => normalizeArenaWorkerCapabilityV2Text(
    text.replace('"schema_version":2', '"schema_version":2,"schema_version":2'),
  ));
  const reordered = { ...capability };
  delete reordered.surface;
  reordered.surface = capability.surface;
  assert.throws(() => normalizeArenaWorkerCapabilityV2Text(JSON.stringify(reordered)));
});

test("reviewed authority and branded plan mint a frozen clone-resistant post-restart proof", (t) => {
  const directory = temporaryDirectory("arena-worker-proof-");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const projection = reviewedProjectionFixture(directory);
  const checkedAt = Math.floor(Date.now() / 1_000);
  const plan = testActivationPlan(projection, checkedAt);
  const authority = __test.expectedAuthorityFromReviewedProjectionAndPlan(
    projection,
    plan,
    checkedAt,
  );
  assert.notEqual(
    authority.globalImageReleaseManifestSha256,
    authority.workerReleaseManifestSha256,
  );
  assert.equal(
    authority.globalImageReleaseManifestSha256,
    `sha256:${"a3".repeat(32)}`,
  );
  assert.equal(
    authority.expectedReleaseBinding.release_manifest_sha256,
    WORKER_RELEASE_MANIFEST_SHA256,
  );
  assert.equal(
    authority.endpoint,
    `https://delegate.example.com/arena/challenges/${ARENA_WORKER_CHALLENGE_ID}`
      + `/versions/${ARENA_WORKER_CHALLENGE_VERSION}/worker-capability`,
  );
  assert.equal(
    authority.endpointCommitmentSha256,
    phalaArenaWorkerPresenceEndpointCommitmentSha256(authority.endpoint),
  );
  const heartbeatObservedAt = checkedAt - 1;
  const responseText = canonicalArenaWorkerCapabilityV2Text(
    liveCapability(authority.expectedReleaseBinding, heartbeatObservedAt),
  );
  const proof = __test.verifyCanonicalResponse({
    checkedAt,
    postMeasurementActivationPlan: plan,
    postRestartAttestationObservedAt: instant(checkedAt - 2),
    responseText,
    reviewedFinalAuthorityRuntimeProjection: projection,
  });
  assert.deepEqual(proof, {
    schema: PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
    heartbeat_schema: PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    endpoint_commitment_sha256: authority.endpointCommitmentSha256,
    challenge_id: ARENA_WORKER_CHALLENGE_ID,
    challenge_version: ARENA_WORKER_CHALLENGE_VERSION,
    response_sha256: `sha256:${createHash("sha256")
      .update(responseText, "ascii")
      .digest("hex")}`,
    release_binding_sha256: authority.expectedReleaseBindingSha256,
    heartbeat_observed_at: heartbeatObservedAt,
    verified_at: checkedAt,
  });
  assert.equal(Object.isFrozen(proof), true);
  assert.equal(assertVerifiedArenaWorkerActivationProof(proof), proof);
  const dependencies = readVerifiedArenaWorkerActivationProofDependencies(proof);
  assert.equal(
    dependencies.reviewed_final_authority_runtime_projection,
    projection,
  );
  assert.equal(dependencies.post_measurement_activation_plan, plan);
  assert.deepEqual(
    dependencies.expected_release_binding,
    authority.expectedReleaseBinding,
  );
  assert.equal(
    dependencies.heartbeat_binding_sha256,
    arenaWorkerHeartbeatBindingSha256({
      challengeId: proof.challenge_id,
      challengeVersion: proof.challenge_version,
      heartbeatObservedAt: proof.heartbeat_observed_at,
      releaseBindingSha256: proof.release_binding_sha256,
    }),
  );
  const serialized = JSON.stringify(proof);
  assert.equal(serialized.includes(authority.endpoint), false);
  assert.equal(serialized.includes(responseText), false);
  assert.equal(serialized.toLowerCase().includes("mac"), false);
  assert.throws(() => assertVerifiedArenaWorkerActivationProof(
    structuredClone(proof),
  ));
});

test("authority drift, stale evidence, and non-post-restart observations fail closed", (t) => {
  const directory = temporaryDirectory("arena-worker-fail-");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const projection = reviewedProjectionFixture(directory);
  const checkedAt = Math.floor(Date.now() / 1_000);
  const plan = testActivationPlan(projection, checkedAt);
  const authority = __test.expectedAuthorityFromReviewedProjectionAndPlan(
    projection,
    plan,
    checkedAt,
  );
  const exactHeartbeat = checkedAt - 1;
  const exactText = canonicalArenaWorkerCapabilityV2Text(
    liveCapability(authority.expectedReleaseBinding, exactHeartbeat),
  );
  assert.throws(() => __test.verifyCanonicalResponse({
    checkedAt,
    postMeasurementActivationPlan: plan,
    postRestartAttestationObservedAt: instant(exactHeartbeat),
    responseText: exactText,
    reviewedFinalAuthorityRuntimeProjection: projection,
  }), /strictly later/);

  const staleHeartbeat = checkedAt - 301;
  const staleText = canonicalArenaWorkerCapabilityV2Text(
    liveCapability(authority.expectedReleaseBinding, staleHeartbeat),
  );
  assert.throws(() => __test.verifyCanonicalResponse({
    checkedAt,
    postMeasurementActivationPlan: plan,
    postRestartAttestationObservedAt: instant(staleHeartbeat - 1),
    responseText: staleText,
    reviewedFinalAuthorityRuntimeProjection: projection,
  }), /not fresh/);

  const driftedBinding = {
    ...authority.expectedReleaseBinding,
    image_digest: `sha256:${"f".repeat(64)}`,
  };
  const driftedText = canonicalArenaWorkerCapabilityV2Text(
    liveCapability(driftedBinding, exactHeartbeat),
  );
  assert.throws(() => __test.verifyCanonicalResponse({
    checkedAt,
    postMeasurementActivationPlan: plan,
    postRestartAttestationObservedAt: instant(exactHeartbeat - 1),
    responseText: driftedText,
    reviewedFinalAuthorityRuntimeProjection: projection,
  }), /reviewed release authority/);

  const globallyBoundImageManifest = {
    ...authority.expectedReleaseBinding,
    release_manifest_sha256: authority.globalImageReleaseManifestSha256,
  };
  const globallyBoundText = canonicalArenaWorkerCapabilityV2Text(
    liveCapability(globallyBoundImageManifest, exactHeartbeat),
  );
  assert.throws(() => __test.verifyCanonicalResponse({
    checkedAt,
    postMeasurementActivationPlan: plan,
    postRestartAttestationObservedAt: instant(exactHeartbeat - 1),
    responseText: globallyBoundText,
    reviewedFinalAuthorityRuntimeProjection: projection,
  }), /reviewed release authority/);
});

test("the production facade accepts no caller-authored endpoint, response, transport, or clock", async (t) => {
  const directory = temporaryDirectory("arena-worker-input-");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const projection = reviewedProjectionFixture(directory);
  const now = Math.floor(Date.now() / 1_000);
  const plan = testActivationPlan(projection, now);
  await assert.rejects(verifyArenaWorkerActivationCapability({
    postMeasurementActivationPlan: plan,
    reviewedFinalAuthorityRuntimeProjection: projection,
    postRestartAttestationObservedAt: instant(now - 2),
    endpoint: "https://attacker.example/worker-capability",
  }), /fields are not exact/);
  await assert.rejects(verifyArenaWorkerActivationCapability({
    postMeasurementActivationPlan: plan,
    reviewedFinalAuthorityRuntimeProjection: projection,
    postRestartAttestationObservedAt: now - 2,
  }), /canonical UTC second/);

  await assert.rejects(verifyArenaWorkerActivationCapability({
    postMeasurementActivationPlan: structuredClone(plan),
    reviewedFinalAuthorityRuntimeProjection: projection,
    postRestartAttestationObservedAt: instant(now - 2),
  }), /fresh dependency-reconstructed activation plan/);
});
