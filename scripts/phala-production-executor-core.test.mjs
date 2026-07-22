import assert from "node:assert/strict";
import test from "node:test";

import {
  PHALA_EXECUTION_ORDER,
  assertProvenanceVerifiedCompletedPhalaExecutorState,
  assertImmediateSignedEnvironmentKeyRefetch,
  assertPairwiseDistinctSignedEnvironmentKeys,
  assertPreparedCvmObservation,
  assertProductionCvmPosture,
  buildExactCommitMetadata,
  buildExactProvisionRequest,
  buildExplicitAppCompose,
  cloudLegacyPrettyComposeHashForRejection,
  createInitialPhalaExecutorState,
  dstackCanonicalComposeHash,
  normalizeCompletedPhalaExecutorState,
  normalizeFinalizedMutationGate,
  transitionPhalaExecutorState,
} from "./phala-production-executor-core.mjs";
import {
  assertPinnedDstackComposeHash,
  assertPinnedPhalaClientTransport,
  assertProductionExecutionPolicyAvailable,
  assertProductionExecutionRemainsSealed,
  assertSafePhalaSdkProcessEnvironment,
  encryptExactEnvironmentWithPinnedDstack,
  phalaSdkJsonBodySemanticDigest,
  projectPinnedProvisionWireBody,
  projectPinnedProvisionWireEvidence,
  projectPinnedSdkCompatibilityIdentity,
  resolvePinnedPhalaPackageIdentity,
  verifyImmediatePinnedLegacyEnvironmentKeyRefetch,
  verifyPinnedLegacyEnvironmentKey,
} from "./phala-production-sdk-adapter.mjs";
import { PHALA_OS_IMAGE_CATALOG_ENTRY } from "./cvm-launch-intent-core.mjs";

const digest = (character) => `sha256:${character.repeat(64)}`;
const mutationTime = (seconds) => new Date(Date.UTC(2026, 6, 21, 12, 0, seconds))
  .toISOString().replace(".000Z", "Z");

const PROFILE = Object.freeze({
  name: "dnai-main-runtime",
  manifest_version: 2,
  runner: "docker-compose",
  kms_enabled: true,
  gateway_enabled: true,
  tproxy_enabled: false,
  skip_gateway: false,
  storage_fs: "ext4",
  secure_time: true,
  public_logs: false,
  public_sysinfo: false,
  public_tcbinfo: false,
});

const RESOURCE = Object.freeze({
  authority_status: "reviewed_authenticated_catalog_and_quota_validated",
  instance_type: "tdx.large",
  disk_size: 40,
  placement: Object.freeze({
    selection_mode: "automatic_best_match",
    node_id: null,
    region: null,
  }),
});

const SIGNED_KEY_KNOWN_ANSWER = Object.freeze({
  appId: "1111111111111111111111111111111111111111",
  publicKey: "2".repeat(64),
  signature:
    "b3c07db1884a9a15a3d673eabd00bb6f92c1a17576d6046ca793a4af29698d14"
    + "7adcb954de65613f911c96b37bdc4ae4281b4065b51f5a0b4086a38c4a07fe6301",
  signer: "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
});

test("explicit AppCompose and provision request contain no mutable SDK defaults", async () => {
  const compose = buildExplicitAppCompose({
    profile: PROFILE,
    dockerComposeFile: "services:\n  delegate:\n    image: example.invalid/x@sha256:" + "1".repeat(64),
    allowedEnvironmentKeys: ["A", "B"],
  });
  assert.deepEqual(Object.keys(compose).sort(), [
    "allowed_envs",
    "docker_compose_file",
    "gateway_enabled",
    "kms_enabled",
    "manifest_version",
    "name",
    "public_logs",
    "public_sysinfo",
    "public_tcbinfo",
    "runner",
    "secure_time",
    "storage_fs",
    "tproxy_enabled",
  ].sort());
  const request = buildExactProvisionRequest({
    domain: "main_runtime_cvm",
    applicationName: "dnai-main-runtime",
    resourceTarget: RESOURCE,
    appCompose: compose,
    activeEnvironmentKeys: ["A", "B"],
    appId: "1".repeat(40),
    nonce: 42,
    kmsId: "kms-production-1",
  });
  assert.equal(request.instance_type, "tdx.large");
  assert.equal(request.disk_size, 40);
  assert.equal(request.image, "dstack-0.5.10");
  assert.equal(request.listed, false);
  assert.equal(request.key_provider_mode, "kms");
  assert.equal(request.skip_gateway, false);
  assert.equal("node_id" in request, false);
  assert.equal("region" in request, false);

  const identity = resolvePinnedPhalaPackageIdentity();
  assert.equal(
    identity.cloud.module_sha256,
    "sha256:ad67b0bda91dd37566dac18030aac8c267e5b88b931f12e37614e537b465729f",
  );
  assert.equal(
    identity.cloud.npm_dist_integrity_sha512,
    "sha512-eQXJxbBlJ8xA4e+MmB3AZd9jgdbO3tFh+qu7KL6CS5Ta64LNKlrV3vdke3oUvB22xbc/qqKQ6dIkJx5pTdY7gA==",
  );
  assert.match(identity.dstack.compose_hash_module_sha256, /^sha256:[0-9a-f]{64}$/);
  const compatibilityIdentity = projectPinnedSdkCompatibilityIdentity(identity);
  assert.equal(
    compatibilityIdentity.phala_cloud_module_sha256,
    identity.cloud.module_sha256,
  );
  assert.equal(
    compatibilityIdentity.dstack_encryption_module_sha256,
    identity.dstack.encryption_module_sha256,
  );
  const hash = dstackCanonicalComposeHash(compose);
  assert.equal(await assertPinnedDstackComposeHash({
    identity,
    appCompose: compose,
    observedComposeHash: hash,
  }), hash);
  assert.notEqual(cloudLegacyPrettyComposeHashForRejection(compose), hash);
  await assert.rejects(
    assertPinnedDstackComposeHash({
      identity,
      appCompose: compose,
      observedComposeHash: cloudLegacyPrettyComposeHashForRejection(compose),
    }),
    /pinned dstack canonical hash/,
  );
});

test("pinned cloud SDK wire projection models its exact destructive compatibility transform", () => {
  const compose = buildExplicitAppCompose({
    profile: PROFILE,
    dockerComposeFile: "services:\n  delegate:\n    image: example.invalid/x@sha256:" + "1".repeat(64),
    allowedEnvironmentKeys: ["A", "B"],
  });
  const request = buildExactProvisionRequest({
    domain: "main_runtime_cvm",
    applicationName: "dnai-main-runtime",
    resourceTarget: RESOURCE,
    appCompose: compose,
    activeEnvironmentKeys: ["A", "B"],
    appId: "1".repeat(40),
    nonce: 42,
    kmsId: "kms-production-1",
  });
  const wire = projectPinnedProvisionWireBody(request);
  assert.equal(request.compose_file.tproxy_enabled, false);
  assert.equal(Object.hasOwn(wire.compose_file, "tproxy_enabled"), false);
  assert.equal(wire.compose_file.gateway_enabled, true);
  assert.notEqual(
    phalaSdkJsonBodySemanticDigest(request),
    phalaSdkJsonBodySemanticDigest(wire),
  );
  const evidence = projectPinnedProvisionWireEvidence(request);
  assert.equal(evidence.evidence_complete, false);
  assert.equal(evidence.mutation_authorized, false);
  assert.equal(evidence.captured_post_transform_body_sha256, null);
  assert.notEqual(
    evidence.pre_transform_compose_hash,
    evidence.expected_post_transform_compose_hash,
  );
  assert.throws(
    () => projectPinnedProvisionWireBody({ ...request, unexpected: true }),
    /exact pinned fields/,
  );
});

test("prepare observation binds app, compose, KMS, resource, OS, and returned key", () => {
  const observed = assertPreparedCvmObservation({
    response: {
      app_id: "1".repeat(40),
      compose_hash: "2".repeat(64),
      kms_id: "kms-production-1",
      instance_type: "tdx.large",
      os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
      node_id: 7,
      device_id: "device-7",
      app_env_encrypt_pubkey: "3".repeat(64),
    },
    appId: "1".repeat(40),
    expectedComposeHash: "2".repeat(64),
    expectedKmsId: "kms-production-1",
    expectedInstanceType: "tdx.large",
  });
  assert.equal(observed.node_id, 7);
  assert.equal(observed.prepared_public_key, "3".repeat(64));

  assert.throws(() => assertPreparedCvmObservation({
    response: { ...observed, os_image_hash: "4".repeat(64) },
    appId: "1".repeat(40),
    expectedComposeHash: "2".repeat(64),
    expectedKmsId: "kms-production-1",
    expectedInstanceType: "tdx.large",
  }), /reviewed request and catalogs/);
});

test("pinned dstack verifier accepts one known-answer app binding and rejects substitutions", async () => {
  const identity = resolvePinnedPhalaPackageIdentity();
  const response = {
    public_key: SIGNED_KEY_KNOWN_ANSWER.publicKey,
    signature: SIGNED_KEY_KNOWN_ANSWER.signature,
  };
  const binding = await verifyPinnedLegacyEnvironmentKey({
    identity,
    appId: SIGNED_KEY_KNOWN_ANSWER.appId,
    response,
    pinnedSigner: SIGNED_KEY_KNOWN_ANSWER.signer,
  });
  assert.equal(binding.app_id, SIGNED_KEY_KNOWN_ANSWER.appId);
  assert.equal(binding.signature_verified, true);
  assert.equal(binding.legacy_signature_has_no_timestamp, true);

  await assert.rejects(
    verifyPinnedLegacyEnvironmentKey({
      identity,
      appId: "2".repeat(40),
      response,
      pinnedSigner: SIGNED_KEY_KNOWN_ANSWER.signer,
    }),
    /independently pinned KMS signer/,
  );
  await assert.rejects(
    verifyPinnedLegacyEnvironmentKey({
      identity,
      appId: SIGNED_KEY_KNOWN_ANSWER.appId,
      response,
      pinnedSigner: `0x03${"1".repeat(64)}`,
    }),
    /independently pinned KMS signer/,
  );
  await assert.rejects(
    verifyImmediatePinnedLegacyEnvironmentKeyRefetch({
      identity,
      appId: SIGNED_KEY_KNOWN_ANSWER.appId,
      firstResponse: response,
      secondResponse: { ...response, public_key: "3".repeat(64) },
      pinnedSigner: SIGNED_KEY_KNOWN_ANSWER.signer,
    }),
    /independently pinned KMS signer|refetch changed/,
  );
});

test("pinned dstack encryption accepts only exact sorted entries and stays outside public state", async () => {
  const identity = resolvePinnedPhalaPackageIdentity();
  const first = await encryptExactEnvironmentWithPinnedDstack({
    identity,
    entries: [{ key: "A", value: "first-secret-canary" }],
    publicKey: SIGNED_KEY_KNOWN_ANSWER.publicKey,
  });
  const second = await encryptExactEnvironmentWithPinnedDstack({
    identity,
    entries: [{ key: "A", value: "second-secret-canary" }],
    publicKey: SIGNED_KEY_KNOWN_ANSWER.publicKey,
  });
  assert.match(first, /^[0-9a-f]+$/);
  assert.notEqual(first, second);
  assert.equal(first.includes(Buffer.from("first-secret-canary").toString("hex")), false);
  await assert.rejects(
    encryptExactEnvironmentWithPinnedDstack({
      identity,
      entries: [{ key: "B", value: "x" }, { key: "A", value: "y" }],
      publicKey: SIGNED_KEY_KNOWN_ANSWER.publicKey,
    }),
    /sorted and duplicate-free/,
  );
});

test("signed bindings reject duplicate keys and refetch drift", () => {
  const binding = {
    schema: "dnai.phala-signed-env-key-binding.v1",
    app_id: "1".repeat(40),
    public_key: "2".repeat(64),
    public_key_sha256: digest("3"),
    signer_k256: SIGNED_KEY_KNOWN_ANSWER.signer,
    signature_verified: true,
    legacy_signature_has_no_timestamp: true,
  };
  assert.deepEqual(assertImmediateSignedEnvironmentKeyRefetch(binding, binding), binding);
  assert.throws(
    () => assertImmediateSignedEnvironmentKeyRefetch(
      binding,
      { ...binding, public_key: "4".repeat(64) },
    ),
    /refetch changed/,
  );
  const seven = PHALA_EXECUTION_ORDER.map((domain, index) => ({
    ...binding,
    app_id: String(index + 1).repeat(40),
    public_key: String(index + 2).repeat(64),
  }));
  assert.equal(assertPairwiseDistinctSignedEnvironmentKeys(seven), true);
  seven.at(-1).public_key = seven[0].public_key;
  assert.throws(
    () => assertPairwiseDistinctSignedEnvironmentKeys(seven),
    /pairwise distinct/,
  );
});

test("exact-looking caller JSON cannot become a finalized mutation gate", () => {
  const gate = {
    schema: "dnai.phala-finalized-mutation-gate.v1",
    stage: "cvm_launch",
    action: "provisionCvm",
    batch_id: digest("1"),
    bootstrap_authorization_id: digest("6"),
    bootstrap_authorization_receipt_sha256: digest("7"),
    bootstrap_authorization_status: "non_live_bootstrap_signatures_verified",
    domain: PHALA_EXECUTION_ORDER[0],
    readiness_sha256: digest("2"),
    snapshot_finality: "rpc_finalized",
    snapshot_block_number: 123,
    snapshot_block_hash: `0x${"3".repeat(64)}`,
    checked_at: "2026-07-21T12:00:00Z",
    expires_at: "2026-07-21T12:02:00Z",
    live_traffic_authorized: false,
  };
  assert.throws(() => normalizeFinalizedMutationGate(gate, {
    nowMs: Date.parse("2026-07-21T12:01:00Z"),
    minimumRemainingMs: 30_000,
  }), /unforgeable|stable-file/);
  assert.throws(() => normalizeFinalizedMutationGate(Object.freeze({
    ...gate,
    bootstrap_authorization_status: "non_live_bootstrap_authorized",
  })), /unforgeable|stable-file/);
});

function initialState() {
  return createInitialPhalaExecutorState({
    batchId: digest("1"),
    bootstrapAuthorizationId: digest("f"),
    bootstrapAuthorizationReceiptSha256: digest("e"),
    releaseSha: "a".repeat(40),
    launchIntentSha256: digest("2"),
    targetAuthoritySha256: digest("3"),
    phalaRecoveryDirectoryIdentityAnchorSha256: digest("4"),
  });
}

function reserve(state) {
  return transitionPhalaExecutorState(state, {
    type: "app_ids_observed",
    reservations: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      app_id: (index + 1).toString(16).repeat(40),
      nonce: 100 + index,
    })),
  });
}

test("live executor events reject impossible UTC dates and cross a real leap-day boundary", () => {
  const state = reserve(initialState());
  const baseAttempt = {
    type: "provision_attempt",
    domain: PHALA_EXECUTION_ORDER[0],
    request_sha256: digest("4"),
    readiness_sha256: digest("5"),
  };
  for (const impossible of [
    "2025-02-29T12:00:00Z",
    "2026-04-31T12:00:00Z",
    "2024-02-29T23:59:60Z",
  ]) {
    assert.throws(
      () => transitionPhalaExecutorState(state, {
        ...baseAttempt,
        attempted_at: impossible,
      }),
      /canonical UTC second/,
    );
  }

  const attempted = transitionPhalaExecutorState(state, {
    ...baseAttempt,
    attempted_at: "2024-02-29T23:59:59Z",
  });
  const observed = transitionPhalaExecutorState(attempted, {
    type: "provision_observed",
    domain: PHALA_EXECUTION_ORDER[0],
    observation_sha256: digest("6"),
    observed_at: "2024-03-01T00:00:00Z",
  });
  assert.equal(
    observed.preparations[0].attempted_at,
    "2024-02-29T23:59:59Z",
  );
  assert.equal(
    observed.preparations[0].observed_at,
    "2024-03-01T00:00:00Z",
  );
});

test("isolated fake interpreter proves attempt-before-observation for all fourteen mutations", () => {
  let state = reserve(initialState());
  const transcript = [];
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    const domain = PHALA_EXECUTION_ORDER[index];
    state = transitionPhalaExecutorState(state, {
      type: "provision_attempt",
      domain,
      request_sha256: digest(((index + 4) % 15).toString(16)),
      readiness_sha256: digest("e"),
      attempted_at: mutationTime(index * 2),
    });
    transcript.push(`durable:provision:${domain}`);
    state = transitionPhalaExecutorState(state, {
      type: "provision_observed",
      domain,
      observation_sha256: digest(((index + 5) % 15).toString(16)),
      observed_at: mutationTime(index * 2 + 1),
    });
    transcript.push(`observed:provision:${domain}`);
  }
  state = transitionPhalaExecutorState(state, {
    type: "preparations_validated",
    validation_sha256: digest("d"),
  });
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    state = transitionPhalaExecutorState(state, {
      type: "signed_key_observed",
      domain: PHALA_EXECUTION_ORDER[index],
      binding_sha256: digest(((index + 1) % 15).toString(16)),
      public_key_sha256: digest(((index + 7) % 15).toString(16)),
    });
  }
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    const domain = PHALA_EXECUTION_ORDER[index];
    state = transitionPhalaExecutorState(state, {
      type: "commit_attempt",
      domain,
      request_sha256: digest(((index + 8) % 15).toString(16)),
      readiness_sha256: digest("e"),
      attempted_at: mutationTime(20 + index * 2),
    });
    transcript.push(`durable:commit:${domain}`);
    state = transitionPhalaExecutorState(state, {
      type: "commit_observed",
      domain,
      cvm_id: `cvm-${index + 1}`,
      observation_sha256: digest((index + 1).toString(16)),
      observed_at: mutationTime(21 + index * 2),
    });
    transcript.push(`observed:commit:${domain}`);
  }
  state = transitionPhalaExecutorState(state, {
    type: "posture_validated",
    receipts: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      receipt_sha256: digest(((index + 1) % 15).toString(16)),
    })),
  });
  assert.equal(
    state.status,
    "complete_seven_commits_posture_observed_attestation_unverified",
  );
  assert.equal(state.committed_prefix.length, 7);
  const completed = normalizeCompletedPhalaExecutorState(state);
  assert.equal(completed.sequence, 38);
  assert.equal(completed.preparations[0].attempted_at, mutationTime(0));
  assert.equal(completed.committed_prefix[6].observed_at, mutationTime(33));
  assert.throws(
    () => assertProvenanceVerifiedCompletedPhalaExecutorState(completed),
    /lacks durable journal.*authenticated SDK observation.*release-replay provenance/,
  );
  const fabricated = structuredClone(completed);
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    fabricated.preparations[index].request_sha256 = digest("b");
    fabricated.preparations[index].readiness_sha256 = digest("c");
    fabricated.preparations[index].observation_sha256 = digest("d");
    fabricated.committed_prefix[index].request_sha256 = digest("8");
    fabricated.committed_prefix[index].readiness_sha256 = digest("9");
    fabricated.committed_prefix[index].observation_sha256 = digest("a");
    fabricated.preparations[index].attempted_at = new Date(
      Date.UTC(2026, 6, 21, 11, 0, index * 2),
    ).toISOString().replace(".000Z", "Z");
    fabricated.preparations[index].observed_at = new Date(
      Date.UTC(2026, 6, 21, 11, 0, index * 2 + 1),
    ).toISOString().replace(".000Z", "Z");
    fabricated.committed_prefix[index].attempted_at = new Date(
      Date.UTC(2026, 6, 21, 11, 0, 20 + index * 2),
    ).toISOString().replace(".000Z", "Z");
    fabricated.committed_prefix[index].observed_at = new Date(
      Date.UTC(2026, 6, 21, 11, 0, 21 + index * 2),
    ).toISOString().replace(".000Z", "Z");
  }
  assert.doesNotThrow(() => normalizeCompletedPhalaExecutorState(fabricated));
  assert.throws(
    () => assertProvenanceVerifiedCompletedPhalaExecutorState(fabricated),
    /lacks durable journal.*authenticated SDK observation.*release-replay provenance/,
  );
  for (const domain of PHALA_EXECUTION_ORDER) {
    assert.ok(
      transcript.indexOf(`durable:provision:${domain}`)
        < transcript.indexOf(`observed:provision:${domain}`),
    );
    assert.ok(
      transcript.indexOf(`durable:commit:${domain}`)
        < transcript.indexOf(`observed:commit:${domain}`),
    );
  }
});

test("ambiguous mutation outcomes are terminal until manual reconciliation", () => {
  let state = reserve(initialState());
  const domain = PHALA_EXECUTION_ORDER[0];
  state = transitionPhalaExecutorState(state, {
    type: "provision_attempt",
    domain,
    request_sha256: digest("4"),
    readiness_sha256: digest("5"),
    attempted_at: mutationTime(0),
  });
  state = transitionPhalaExecutorState(state, {
    type: "mutation_outcome_ambiguous",
    action: "provisionCvm",
    domain,
    reason_code: "network-timeout-after-send",
  });
  assert.equal(state.status, "ambiguous_reconcile_required");
  assert.throws(() => transitionPhalaExecutorState(state, {
    type: "provision_attempt",
    domain,
    request_sha256: digest("4"),
    readiness_sha256: digest("5"),
    attempted_at: mutationTime(0),
  }), /illegal executor transition/);
  state = transitionPhalaExecutorState(state, {
    type: "reconciliation_recorded",
    observed_committed_domains: [],
    observation_sha256: digest("6"),
  });
  assert.equal(state.status, "reconciled_no_mutation_operator_review_required");
  assert.throws(() => transitionPhalaExecutorState(state, {
    type: "app_ids_observed",
    reservations: [],
  }), /illegal executor transition/);
});

test("executor events and commit metadata cannot carry secret values", () => {
  const state = reserve(initialState());
  assert.throws(() => transitionPhalaExecutorState(state, {
    type: "provision_attempt",
    domain: PHALA_EXECUTION_ORDER[0],
    request_sha256: digest("4"),
    readiness_sha256: digest("5"),
    attempted_at: mutationTime(0),
    api_key: ["phak_", "should-never-enter-state"].join(""),
  }), /secret-bearing field/);
  assert.deepEqual(buildExactCommitMetadata({
    appId: "1".repeat(40),
    composeHash: "2".repeat(64),
    kmsId: "kms-production-1",
    environmentKeys: ["A", "B"],
  }), {
    app_id: "1".repeat(40),
    compose_hash: "2".repeat(64),
    kms_id: "kms-production-1",
    env_keys: ["A", "B"],
  });
});

test("postcommit posture requires the exact private KMS, OS, resource, and hash facts", () => {
  const info = {
    app_id: "1".repeat(40),
    compose_hash: "2".repeat(64),
    kms_type: "phala",
    kms_info: { id: "kms-production-1" },
    os: { is_dev: false, os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash },
    resource: { instance_type: "tdx.large", disk_in_gb: 40 },
    listed: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
  };
  assert.equal(assertProductionCvmPosture(info, {
    appId: "1".repeat(40),
    composeHash: "2".repeat(64),
    kmsId: "kms-production-1",
    instanceType: "tdx.large",
    diskSize: 40,
  }), info);
  assert.throws(() => assertProductionCvmPosture({ ...info, public_tcbinfo: true }, {
    appId: "1".repeat(40),
    composeHash: "2".repeat(64),
    kmsId: "kms-production-1",
    instanceType: "tdx.large",
    diskSize: 40,
  }), /private production posture/);
});

test("SDK process and transport guards reject environment, origin, retry, and redirect drift", () => {
  assert.equal(assertSafePhalaSdkProcessEnvironment({}), true);
  for (const environment of [
    { DEBUG: "*" },
    { NODE_DEBUG: "http" },
    { PHALA_CLOUD_API_KEY: "phak_hidden" },
    { PHALA_CLOUD_API_PREFIX: "https://evil.invalid" },
  ]) {
    assert.throws(() => assertSafePhalaSdkProcessEnvironment(environment));
  }
  const exact = {
    baseURL: "https://cloud-api.phala.network/api/v1",
    version: "2026-01-21",
    timeout: 20_000,
    retry: 0,
    redirect: "error",
  };
  assert.deepEqual(assertPinnedPhalaClientTransport(exact), exact);
  for (const drift of [
    { baseURL: "https://cloud-api.phala.com/api/v1" },
    { retry: 1 },
    { redirect: "follow" },
    { timeout: 60_000 },
  ]) {
    assert.throws(() => assertPinnedPhalaClientTransport({ ...exact, ...drift }));
  }
});

test("production adapter is available only through the exact no-bypass policy", () => {
  const policy = assertProductionExecutionPolicyAvailable();
  assert.equal(policy.availability, true);
  assert.deepEqual(policy.blocker_codes, []);
  assert.equal(policy.caller_supplied_clients_accepted, false);
  assert.equal(policy.caller_supplied_callbacks_accepted, false);
  assert.equal(policy.manual_cli_or_sdk_bypass_authorized, false);
  assert.throws(
    () => assertProductionExecutionRemainsSealed(),
    /legacy sealed adapter entrypoint is retired/,
  );
});
