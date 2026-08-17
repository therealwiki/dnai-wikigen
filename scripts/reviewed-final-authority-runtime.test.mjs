import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  assertReviewedCeremonyAuthorityProjection,
} from "./ceremony-authority-projector.mjs";
import {
  assertProjectedChallengeRegistryRuntimeEnvironment,
} from "./challenge-registry-authority-projector.mjs";
import {
  canonicalCvmLaunchIntentCoreArtifactText,
  createDraftCvmLaunchIntentCore,
  cvmLaunchIntentCoreDigest,
} from "./cvm-launch-intent-core.mjs";
import {
  canonicalFinalReleaseAuthorityCoreArtifactText,
  finalReleaseAuthorityCoreDigest,
} from "./execution-policy-release-core.mjs";
import { knownVector } from "./execution-policy-release-core.fixture.mjs";
import {
  canonicalArtifactSha256,
  canonicalArtifactText,
  createDraftAuthorityReviewEnvelope,
  createDraftDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import {
  royaltyReleasePolicyCommitment,
  royaltyReleaseStateSha256,
} from "./royalty-release-authority-core.mjs";
import {
  REVIEWED_FINAL_AUTHORITY_RUNTIME_PROJECTION_SCHEMA,
  assertReviewedFinalAuthorityRuntimeProjection,
  readReviewedFinalAuthorityRuntimeDependencies,
  readReviewedFinalAuthorityRuntimeProjection,
  reviewedFinalAuthorityRuntimeProjectionSha256,
} from "./reviewed-final-authority-runtime.mjs";

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

function writeOwned(directory, name, bytes, mode = 0o400) {
  const filePath = path.join(directory, name);
  fs.writeFileSync(filePath, bytes, { flag: "wx", mode });
  fs.chmodSync(filePath, mode);
  return filePath;
}

function rebindReleaseAuthority(authority, {
  deploymentIntentSha256,
  cvmLaunchIntentSha256,
}) {
  const writerReleaseCommitment =
    `0x${cvmLaunchIntentSha256.slice("sha256:".length)}`;

  authority.deployment_intent_sha256 = deploymentIntentSha256;
  authority.cvm_launch_intent_sha256 = cvmLaunchIntentSha256;
  authority.execution_policy.rollback_anchor_target.writer_release_commitment =
    writerReleaseCommitment;

  Object.assign(authority.shared_release_lineage, {
    release_sha: authority.release_sha,
    deployment_intent_sha256: deploymentIntentSha256,
    cvm_launch_intent_sha256: cvmLaunchIntentSha256,
    seven_cvm_release_verification_authority_sha256:
      authority.seven_cvm_release_verification_authority_sha256,
    main_runtime_cvm_id: authority.cvm.cvm_id,
    main_runtime_compose_hash: authority.cvm.compose_hash,
    main_runtime_app_id: authority.cvm.app_id,
    main_runtime_os_image_hash: authority.cvm.os_image_hash,
  });

  const royaltyAuthority = authority.royalty_release_authority;
  royaltyAuthority.anchor_writer_release_commitment = writerReleaseCommitment;
  const releasePolicyCommitment = royaltyReleasePolicyCommitment({
    chainId: royaltyAuthority.chain_id,
    distributorAddress: royaltyAuthority.distributor_address,
    authorityNonce: royaltyAuthority.authority_nonce,
    settlementVerifier: royaltyAuthority.settlement_verifier,
    qvlVerifier: royaltyAuthority.qvl_verifier,
    executionPolicyAnchor: royaltyAuthority.execution_policy_anchor,
    anchorWriterReleaseCommitment: writerReleaseCommitment,
  });
  royaltyAuthority.release_policy_commitment = releasePolicyCommitment;

  const activeState = authority.royalty_release_active_state;
  activeState.anchor_writer_release_commitment = writerReleaseCommitment;
  activeState.release_policy_commitment = releasePolicyCommitment;
  activeState.computed_release_policy_commitment = releasePolicyCommitment;
  authority.royalty_release_active_state_sha256 = royaltyReleaseStateSha256(
    activeState,
    {
      authority: royaltyAuthority,
      phase: "phase_two_active",
    },
  );

  Object.assign(authority.royalty_settlement_release_binding_template, {
    anchor_writer_release_commitment: writerReleaseCommitment,
    release_policy_commitment: releasePolicyCommitment,
    main_runtime_cvm_id: authority.cvm.cvm_id,
    deployment_intent_sha256: deploymentIntentSha256,
    compose_hash: `0x${authority.cvm.compose_hash}`,
    app_id: authority.cvm.app_id,
    os_image_hash: authority.cvm.os_image_hash,
  });
}

function fixture(directory, { expired = false } = {}) {
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
    descriptor.app_compose_candidate.docker_compose_file_byte_length = 2_000 + index;
    descriptor.app_compose_candidate.expected_compose_hash =
      (index + 1).toString(16).repeat(64);
  });
  const launchDigest = cvmLaunchIntentCoreDigest(launch);
  rebindReleaseAuthority(authority, {
    deploymentIntentSha256,
    cvmLaunchIntentSha256: `sha256:${launchDigest}`,
  });

  const finalAuthoritySha256 =
    `sha256:${finalReleaseAuthorityCoreDigest(authority)}`;
  const reviewEvidence = Buffer.from('{"review":"approved"}\n', "utf8");
  const reviewEnvelope = createDraftAuthorityReviewEnvelope(
    "final_release_authority",
    finalAuthoritySha256,
  );
  const nowSeconds = Math.floor(Date.now() / 1_000);
  const approvedSeconds = expired ? nowSeconds - 7_200 : nowSeconds - 60;
  const expiresSeconds = expired ? nowSeconds - 3_600 : nowSeconds + 3_600;
  reviewEnvelope.approved_at = new Date(approvedSeconds * 1_000)
    .toISOString().replace(".000Z", "Z");
  reviewEnvelope.expires_at = new Date(expiresSeconds * 1_000)
    .toISOString().replace(".000Z", "Z");
  reviewEnvelope.review_evidence_sha256 = `sha256:${createHash("sha256")
    .update(reviewEvidence)
    .digest("hex")}`;
  reviewEnvelope.reviewers = [
    {
      address: "0x0000000000000000000000000000000000000028",
      controllerId: "reviewer-root-01",
    },
    {
      address: "0x0000000000000000000000000000000000000029",
      controllerId: "reviewer-root-02",
    },
  ];

  return {
    authority,
    finalAuthoritySha256,
    paths: {
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
        canonicalArtifactText(reviewEnvelope),
      ),
      reviewEvidencePath: writeOwned(
        directory,
        "review-evidence.json",
        reviewEvidence,
      ),
    },
    releaseSha: intent.release.releaseSha,
  };
}

function temporaryDirectory() {
  const root = fs.realpathSync.native(os.tmpdir());
  const directory = fs.mkdtempSync(path.join(root, "reviewed-final-authority-"));
  fs.chmodSync(directory, 0o700);
  return directory;
}

test("stable reviewed files mint one parent brand with exact private children", (t) => {
  const directory = temporaryDirectory();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const value = fixture(directory);
  const projection = readReviewedFinalAuthorityRuntimeProjection({
    ...value.paths,
    expectedReleaseSha: value.releaseSha,
    expectedFinalAuthoritySha256: value.finalAuthoritySha256,
  });

  assert.equal(
    projection.schema,
    REVIEWED_FINAL_AUTHORITY_RUNTIME_PROJECTION_SCHEMA,
  );
  assert.equal(projection.final_authority_sha256, value.finalAuthoritySha256);
  assert.match(reviewedFinalAuthorityRuntimeProjectionSha256(projection), /^sha256:[0-9a-f]{64}$/);
  assert.equal(assertReviewedFinalAuthorityRuntimeProjection(projection), projection);
  assert.equal(Object.isFrozen(projection), true);

  const dependencies = readReviewedFinalAuthorityRuntimeDependencies(projection);
  assert.equal(
    assertReviewedCeremonyAuthorityProjection(
      dependencies.ceremony_authority_projection,
    ),
    dependencies.ceremony_authority_projection,
  );
  assert.equal(
    assertProjectedChallengeRegistryRuntimeEnvironment(
      dependencies.challenge_registry_runtime_environment_projection,
    ),
    dependencies.challenge_registry_runtime_environment_projection,
  );
  assert.equal(
    `sha256:${finalReleaseAuthorityCoreDigest(dependencies.final_authority)}`,
    value.finalAuthoritySha256,
  );
  assert.throws(
    () => assertReviewedFinalAuthorityRuntimeProjection(structuredClone(projection)),
    /exact live reviewed final-authority runtime projection/,
  );
});

test("wrong pins, expired review, symlink, and writable artifacts fail closed", (t) => {
  const directory = temporaryDirectory();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const value = fixture(directory);
  const input = {
    ...value.paths,
    expectedReleaseSha: value.releaseSha,
    expectedFinalAuthoritySha256: value.finalAuthoritySha256,
  };
  assert.throws(
    () => readReviewedFinalAuthorityRuntimeProjection({
      ...input,
      expectedFinalAuthoritySha256: `sha256:${"ff".repeat(32)}`,
    }),
    /immutable expected pins/,
  );

  const linkPath = path.join(directory, "final-authority-link.json");
  fs.symlinkSync(value.paths.finalAuthorityPath, linkPath);
  assert.throws(
    () => readReviewedFinalAuthorityRuntimeProjection({
      ...input,
      finalAuthorityPath: linkPath,
    }),
    /symlink or alias/,
  );

  fs.chmodSync(value.paths.reviewEvidencePath, 0o620);
  assert.throws(
    () => readReviewedFinalAuthorityRuntimeProjection(input),
    /non-writable bounded regular file/,
  );

  const expiredDirectory = temporaryDirectory();
  t.after(() => fs.rmSync(expiredDirectory, { recursive: true, force: true }));
  const expired = fixture(expiredDirectory, { expired: true });
  assert.throws(
    () => readReviewedFinalAuthorityRuntimeProjection({
      ...expired.paths,
      expectedReleaseSha: expired.releaseSha,
      expectedFinalAuthoritySha256: expired.finalAuthoritySha256,
    }),
    /must still be active when checked/,
  );
});
