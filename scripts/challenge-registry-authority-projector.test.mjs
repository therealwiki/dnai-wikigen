import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

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
  canonicalCvmLaunchIntentCoreArtifactText,
  createDraftCvmLaunchIntentCore,
  cvmLaunchIntentCoreDigest,
} from "./cvm-launch-intent-core.mjs";
import {
  projectReviewedCanonicalCeremonyAuthorityText,
} from "./ceremony-authority-projector.mjs";
import {
  ARENA_APPROVED_CHALLENGE_SET_SCHEMA,
  CHALLENGE_REGISTRY_AUTHORITY_PROJECTION_SCHEMA,
  CHALLENGE_REGISTRY_RUNTIME_ENVIRONMENT_PROJECTION_SCHEMA,
  assertProjectedChallengeRegistryRuntimeEnvironment,
  normalizeChallengeRegistryRuntimeEnvironmentValues,
  projectCanonicalChallengeRegistryAuthorityText,
  projectCanonicalChallengeRegistryRuntimeEnvironmentText,
} from "./challenge-registry-authority-projector.mjs";

function canonical(value) {
  return canonicalFinalReleaseAuthorityCoreArtifactText(value);
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

function reviewedAuthorityContext(authority = knownVector()) {
  const intent = createDraftDeploymentIntentCore();
  intent.release.releaseSha = authority.release_sha;
  intent.release.reviewerAuthorityGenesisAcceptanceSha256 = `sha256:${"91".repeat(32)}`;
  intent.release.reviewerAuthorityCurrentStatusEpoch = 1;
  intent.release.reviewerAuthorityCurrentStatusSha256 = `sha256:${"92".repeat(32)}`;
  intent.deploymentControl.controllerId = "operator-control-01";
  intent.deploymentControl.operatorAddress = authority.operator_address;
  intent.staticContractInputs.computeCreditVault.developer =
    authority.contracts.compute_credit_vault.developer;
  intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment =
    authority.contracts.tinker_account_encumbrance.account_commitment;
  intent.numericPolicy.contract = {
    computeDeveloperFeeBps: authority.contracts.compute_credit_vault.developer_fee_bps,
    emailOracleUpgradeDelaySeconds:
      authority.contracts.email_oracle_auth.upgrade_delay_seconds,
    tinkerMaxAddBalanceWei:
      authority.contracts.tinker_account_encumbrance.max_add_balance_wei,
    tinkerMaxSpendWei: authority.contracts.tinker_account_encumbrance.max_spend_wei,
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

  const launch = createDraftCvmLaunchIntentCore();
  launch.release_sha = intent.release.releaseSha;
  launch.deployment_intent_sha256 = canonicalArtifactSha256(intent);
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
  authority.deployment_intent_sha256 = canonicalArtifactSha256(intent);
  authority.cvm_launch_intent_sha256 = `sha256:${launchDigest}`;
  authority.execution_policy.rollback_anchor_target.writer_release_commitment =
    `0x${launchDigest}`;

  const finalAuthorityText = canonical(authority);
  const finalAuthoritySha256 = `sha256:${finalReleaseAuthorityCoreDigest(authority)}`;
  const reviewEvidenceBytes = Buffer.from('{"review":"approved"}\n', "utf8");
  const envelope = createDraftAuthorityReviewEnvelope(
    "final_release_authority",
    finalAuthoritySha256,
  );
  envelope.approved_at = "2026-07-21T11:59:00Z";
  envelope.expires_at = "2026-07-22T12:00:00Z";
  envelope.review_evidence_sha256 = `sha256:${createHash("sha256")
    .update(reviewEvidenceBytes)
    .digest("hex")}`;
  envelope.reviewers = [
    {
      address: "0x0000000000000000000000000000000000000028",
      controllerId: "reviewer-root-01",
    },
    {
      address: "0x0000000000000000000000000000000000000029",
      controllerId: "reviewer-root-02",
    },
  ];
  const reviewedCeremonyAuthorityProjection =
    projectReviewedCanonicalCeremonyAuthorityText({
      deploymentIntentText: canonicalArtifactText(intent),
      cvmLaunchIntentText: canonicalCvmLaunchIntentCoreArtifactText(launch),
      finalAuthorityText,
      reviewEnvelopeText: canonicalArtifactText(envelope),
      reviewEvidenceBytes,
      checkedAtMs: Date.parse("2026-07-21T12:00:00Z"),
    });
  return { authority, finalAuthorityText, reviewedCeremonyAuthorityProjection };
}

test("projects the exact reviewed ChallengeRegistry genesis tuple", () => {
  const authority = knownVector();
  const finalAuthoritySha256 = `sha256:${finalReleaseAuthorityCoreDigest(authority)}`;
  const projected = projectCanonicalChallengeRegistryAuthorityText(
    canonical(authority),
    { finalAuthoritySha256, releaseSha: authority.release_sha },
  );

  assert.equal(projected.schema, CHALLENGE_REGISTRY_AUTHORITY_PROJECTION_SCHEMA);
  assert.equal(projected.finalAuthoritySha256, finalAuthoritySha256);
  assert.deepEqual(projected.registry, {
    address: authority.contracts.challenge_registry.address,
    runtimeCodeHash: authority.contracts.challenge_registry.runtime_code_hash,
    owner: authority.contracts.challenge_registry.owner,
    pendingOwner: authority.contracts.challenge_registry.pending_owner,
    registryPaused: false,
    minimumVersionReviewDelaySeconds: 172800,
    expectedChallengeCount: 1,
  });
  assert.deepEqual(projected.entries, [{
    catalogKey: "synthetic-bio-assay-qc@1.0.0",
    challengeId: 1,
    version: 1,
    controller: authority.operator_address,
    pendingController: "0x0000000000000000000000000000000000000000",
    lifecycle: "open",
    paused: false,
    configurationFrozen: true,
    catalogManifestHash: `0x${"d1".repeat(32)}`,
    metadataURI: "ipfs://bafy-arena-release-core-vector",
    metadataHash: `0x${"d1".repeat(32)}`,
    sealedArtifactCommitment: `0x${"d2".repeat(32)}`,
    evaluatorCommitment: `0x${"d3".repeat(32)}`,
    releasePolicyCommitment: `0x${"d4".repeat(32)}`,
  }]);
});

test("rejects stale pins, noncanonical bytes, and invalid catalogs", () => {
  const authority = knownVector();
  const text = canonical(authority);
  const digest = `sha256:${finalReleaseAuthorityCoreDigest(authority)}`;

  assert.throws(
    () => projectCanonicalChallengeRegistryAuthorityText(text, {
      finalAuthoritySha256: `sha256:${"f".repeat(64)}`,
      releaseSha: authority.release_sha,
    }),
    /final-authority SHA-256 pin/,
  );
  assert.throws(
    () => projectCanonicalChallengeRegistryAuthorityText(text, {
      finalAuthoritySha256: digest,
      releaseSha: "f".repeat(40),
    }),
    /release SHA/,
  );
  assert.throws(
    () => projectCanonicalChallengeRegistryAuthorityText(JSON.stringify(authority), {
      finalAuthoritySha256: digest,
      releaseSha: authority.release_sha,
    }),
    /canonical sorted two-space JSON/,
  );

  const noncontiguous = structuredClone(authority);
  noncontiguous.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"]
    .registry_challenge_id = "2";
  assert.throws(
    () => projectCanonicalChallengeRegistryAuthorityText(
      canonicalArtifactText(noncontiguous),
    ),
    /contiguous range 1\.\.N/,
  );
});

test("derives branded proxy registry pins and the cross-language approved-set digest", () => {
  const {
    authority,
    finalAuthorityText,
    reviewedCeremonyAuthorityProjection,
  } = reviewedAuthorityContext();
  const finalAuthoritySha256 = `sha256:${finalReleaseAuthorityCoreDigest(authority)}`;
  const projection = projectCanonicalChallengeRegistryRuntimeEnvironmentText(
    finalAuthorityText,
    { reviewedCeremonyAuthorityProjection },
  );
  assert.equal(
    projection.schema,
    CHALLENGE_REGISTRY_RUNTIME_ENVIRONMENT_PROJECTION_SCHEMA,
  );
  assert.equal(projection.finalAuthoritySha256, finalAuthoritySha256);
  assert.equal(projection.chainId, 84_532);
  assert.equal(
    projection.environment.TINKER_ARENA_REGISTRY_ADDRESS,
    authority.contracts.challenge_registry.address,
  );
  assert.equal(
    projection.environment.TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH,
    authority.contracts.challenge_registry.runtime_code_hash,
  );
  const bindings = JSON.parse(
    projection.environment.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON,
  );
  assert.deepEqual(bindings, authority.arena_registry_bindings);
  assert.match(
    projection.environment.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256,
    /^sha256:[0-9a-f]{64}$/,
  );
  assert.deepEqual(
    normalizeChallengeRegistryRuntimeEnvironmentValues(projection.environment),
    projection.environment,
  );
  assert.equal(assertProjectedChallengeRegistryRuntimeEnvironment(projection), projection);
  assert.throws(
    () => assertProjectedChallengeRegistryRuntimeEnvironment(structuredClone(projection)),
    /lacks final-authority provenance/,
  );

  const committed = structuredClone(bindings);
  delete committed["synthetic-bio-assay-qc@1.0.0"].release_policy_commitment;
  assert.deepEqual(Object.keys({
    schema: ARENA_APPROVED_CHALLENGE_SET_SCHEMA,
    bindings: committed,
  }), ["schema", "bindings"]);

  const tampered = structuredClone(projection.environment);
  const decoded = JSON.parse(
    tampered.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON,
  );
  decoded["synthetic-bio-assay-qc@1.0.0"].metadata_uri = "ipfs://tampered";
  tampered.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON =
    JSON.stringify(decoded);
  assert.throws(
    () => normalizeChallengeRegistryRuntimeEnvironmentValues(tampered),
    /digest does not match/,
  );
});

test("runtime brand rejects self-supplied pins and mix-and-match reviewed authorities", () => {
  const first = reviewedAuthorityContext();
  assert.throws(
    () => projectCanonicalChallengeRegistryRuntimeEnvironmentText(
      first.finalAuthorityText,
      {
        finalAuthoritySha256: first.reviewedCeremonyAuthorityProjection
          .finalAuthoritySha256,
        releaseSha: first.authority.release_sha,
      },
    ),
    /lacks current review provenance/,
  );

  const changedAuthority = knownVector();
  changedAuthority.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"]
    .metadata_uri = "ipfs://bafy-arena-different-reviewed-authority";
  const second = reviewedAuthorityContext(changedAuthority);
  assert.equal(
    first.authority.deployment_intent_sha256,
    second.authority.deployment_intent_sha256,
  );
  assert.equal(
    first.authority.cvm_launch_intent_sha256,
    second.authority.cvm_launch_intent_sha256,
  );
  assert.notEqual(
    first.reviewedCeremonyAuthorityProjection.finalAuthoritySha256,
    second.reviewedCeremonyAuthorityProjection.finalAuthoritySha256,
  );
  assert.throws(
    () => projectCanonicalChallengeRegistryRuntimeEnvironmentText(
      second.finalAuthorityText,
      {
        reviewedCeremonyAuthorityProjection:
          first.reviewedCeremonyAuthorityProjection,
      },
    ),
    /final-authority SHA-256 pin/,
  );
});
