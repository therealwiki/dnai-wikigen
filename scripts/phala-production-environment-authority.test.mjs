import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
} from "./cvm-launch-intent-core.mjs";
import { canonicalArtifactText } from "./operator-policy-packet-core.mjs";
import {
  finalReleaseAuthorityCoreDigest,
} from "./execution-policy-release-core.mjs";
import { knownVector } from "./execution-policy-release-core.fixture.mjs";
import {
  ARENA_APPROVED_CHALLENGE_SET_DOMAIN,
  ARENA_APPROVED_CHALLENGE_SET_SCHEMA,
} from "./challenge-registry-authority-projector.mjs";
import {
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
  PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
  PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
  PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_SCHEMA,
  PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_TRUTH,
  PHALA_PHASE_SECRET_INPUT_SCHEMA,
  assemblePrivateBootstrapEnvironment,
  assertPostCommitProvisioningEnvironmentAuthority,
  bootstrapPublicEnvironmentAuthorityDigest,
  canonicalBootstrapPublicEnvironmentAuthorityText,
  canonicalPrivateEnvironmentAssemblyReceiptText,
  createDeferredEnvironmentAssemblyPlan,
  normalizeBootstrapPublicEnvironmentAuthority,
  normalizeDeferredPublicEnvironmentAuthority,
  normalizePostCommitProvisioningEnvironmentAuthority,
  normalizePhaseSecretInput,
  normalizeProvisioningEnvironmentAuthority,
  postCommitProvisioningEnvironmentAuthorityDigest,
  privateEnvironmentAssemblyReceipt,
  privateEnvironmentEntries,
  projectProvisioningEnvironmentAuthority,
  provisioningEnvironmentAuthorityDigest,
  readExactPhaseSecretInputFile,
  readExactBoundPhaseSecretInputFile,
  verifyArenaSealedPolicyProvisionEnvelopeCommitments,
} from "./phala-production-environment-authority.mjs";

const sha = (digit) => `sha256:${String(digit).repeat(64)}`;
const bare = (digit) => String(digit).repeat(64);
const app = (digit) => String(digit).repeat(40);
const address = (digit) => `0x${String(digit).repeat(40)}`;
const exactCorsAllowedOrigins =
  "https://wikigen.me,https://wikigenme.pages.dev,https://www.wikigen.me";
const registryAuthorityVector = knownVector();

function compactSorted(value) {
  if (Array.isArray(value)) return value.map(compactSorted);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, compactSorted(value[key])]),
  );
}

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

// These normalization-only tests intentionally use plain fixture values. The
// production projector brand and its reviewed provenance are covered by the
// ChallengeRegistry projector tests and cannot be forged in this module.
const registryBindings = structuredClone(registryAuthorityVector.arena_registry_bindings);
const approvedBindings = structuredClone(registryBindings);
for (const binding of Object.values(approvedBindings)) {
  delete binding.release_policy_commitment;
}
const registryRuntimeProjection = {
  finalAuthoritySha256:
    `sha256:${finalReleaseAuthorityCoreDigest(registryAuthorityVector)}`,
  environment: {
    TINKER_ARENA_REGISTRY_ADDRESS:
      registryAuthorityVector.contracts.challenge_registry.address,
    TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON:
      JSON.stringify(compactSorted(registryBindings)),
    TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:
      `sha256:${createHash("sha256")
        .update(ARENA_APPROVED_CHALLENGE_SET_DOMAIN, "utf8")
        .update(JSON.stringify(compactSorted({
          schema: ARENA_APPROVED_CHALLENGE_SET_SCHEMA,
          bindings: approvedBindings,
        })), "utf8")
        .digest("hex")}`,
    TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH:
      registryAuthorityVector.contracts.challenge_registry.runtime_code_hash,
  },
};

function publicValue(key, digit = "a") {
  if (Object.hasOwn(registryRuntimeProjection.environment, key)) {
    return registryRuntimeProjection.environment[key];
  }
  if (key === "TINKER_WALLET_AUTH_DOMAIN") return "www.wikigen.me";
  if (key === "TINKER_WALLET_AUTH_URI") return "https://www.wikigen.me";
  if (key.endsWith("_ADDRESS")) return address(digit);
  if (key.endsWith("_APP_ID")) return app(digit);
  if (key.endsWith("_COMPOSE_HASH") || key.endsWith("_OS_IMAGE_HASH")) {
    return bare(digit);
  }
  if (key.endsWith("_URL") || key.endsWith("_URI")) {
    return `https://authority.example/${key.toLowerCase()}`;
  }
  if (key === "TINKER_CORS_ALLOWED_ORIGINS") return exactCorsAllowedOrigins;
  if (key === "TINKER_FUNDING_PREFLIGHT_ALLOWED_HOSTS") return "api.tinker.example";
  if (key === "TINKER_EXECUTION_POLICY_APPROVED_SIGNERS") return address(digit);
  if (key === "TINKER_WALLET_AUTH_CHAIN_ID") return "84532";
  if (key === "TINKER_CHAIN_START_BLOCK") return "12345678";
  if (key.endsWith("_RUNTIME_CODE_HASH")) return `0x${bare(digit)}`;
  if (key.endsWith("_SHA256") || key.endsWith("_HASH")) return bare(digit);
  return `reviewed-${key.toLowerCase()}`;
}

function bootstrapKeys(domain) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const allowed = new Set(policy.exact_allowed_environment_keys);
  return policy.public_environment_key_classification.descriptor_static_keys
    .filter((key) => allowed.has(key));
}

function bootstrapAuthority() {
  return {
    schema: PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    release_sha: "a".repeat(40),
    deployment_intent_sha256: sha("1"),
    deployment_transaction_plan_sha256: sha("2"),
    fresh_contract_deployment_receipt_sha256: sha("3"),
    image_release_manifest_sha256: sha("4"),
    image_release_sigstore_verification_receipt_sha256: sha("e"),
    topology_sha256: sha("5"),
    cvm_launch_intent_sha256: sha("6"),
    cvm_launch_review_receipt_sha256: sha("7"),
    production_target_authority_sha256: sha("8"),
    sdk_wire_transform_staging_receipt_sha256: sha("9"),
    qvl_measurement_policy_set_sha256: sha("d"),
    reviewed_at: "2026-07-21T10:00:00Z",
    valid_until: "2026-07-21T11:00:00Z",
    domains: CVM_LAUNCH_DOMAINS.map((domain, index) => ({
      domain,
      descriptor_sha256: sha(String(index + 1)),
      values: Object.fromEntries(
        bootstrapKeys(domain).map((key) => [key, publicValue(key)]),
      ),
    })),
  };
}

function prepareObservations() {
  return CVM_LAUNCH_DOMAINS.map((domain, index) => {
    const digit = String(index + 1);
    return {
      domain,
      app_id: app(digit),
      compose_hash: bare(digit),
      os_image_hash: bare("a"),
      prepare_response_sha256: sha(digit),
    };
  });
}

function provisioningAuthority(bootstrap = bootstrapAuthority()) {
  return projectProvisioningEnvironmentAuthority({
    batchId: sha("b"),
    targetAuthoritySha256: sha("8"),
    cvmLaunchIntentSha256: bootstrap.cvm_launch_intent_sha256,
    bootstrapAuthoritySha256: bootstrapPublicEnvironmentAuthorityDigest(bootstrap),
    preparedAt: "2026-07-21T10:10:00Z",
    prepareObservations: prepareObservations(),
  });
}

function postcommitAuthority() {
  return {
    schema: PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    batch_id: sha("b"),
    target_authority_sha256: sha("8"),
    cvm_launch_intent_sha256: sha("6"),
    bootstrap_authority_sha256: sha("7"),
    provisioning_authority_sha256: sha("9"),
    executor_final_state_sha256: sha("f"),
    observed_at: "2026-07-21T10:25:00Z",
    domains: CVM_LAUNCH_DOMAINS.map((domain, index) => ({
      domain,
      commit_observation_sha256: sha(String(index + 1)),
      values: Object.fromEntries(
        CVM_LAUNCH_DESCRIPTOR_POLICY[domain]
          .public_environment_key_classification.provisioning_result_keys
          .filter((key) => key.endsWith("_CVM_ID"))
          .map((key) => [key, `cvm-production-${index + 1}`]),
      ),
    })),
  };
}

function secretInput(domain, bootstrap = bootstrapAuthority(), suffix = "one") {
  const keys = CVM_LAUNCH_DESCRIPTOR_POLICY[domain]
    .encrypted_secret_environment_keys_by_phase.bootstrap_provision;
  const values = Object.fromEntries(keys.map((key) => [
    key,
    key === "TINKER_WALLET_AUTH_RPC_URL"
      ? `https://wallet-primary.example/rpc-${suffix}`
      : key === "TINKER_WALLET_AUTH_RPC_URL_SECONDARY"
        ? `https://wallet-secondary.example/rpc-${suffix}`
        : `private-${suffix}-${key}`,
  ]));
  return {
    schema: PHALA_PHASE_SECRET_INPUT_SCHEMA,
    domain,
    phase: "bootstrap_provision",
    batch_id: sha("b"),
    cvm_launch_intent_sha256: bootstrap.cvm_launch_intent_sha256,
    values,
  };
}

function finalSecretInput({
  bootstrap = bootstrapAuthority(),
  arenaRegistryRpcUrl = "https://base-sepolia-rpc.example.test/v1",
} = {}) {
  const domain = "main_runtime_cvm";
  const phase = "final_authority_runtime";
  const keys = CVM_LAUNCH_DESCRIPTOR_POLICY[domain]
    .encrypted_secret_environment_keys_by_phase[phase];
  return {
    schema: PHALA_PHASE_SECRET_INPUT_SCHEMA,
    domain,
    phase,
    batch_id: sha("b"),
    cvm_launch_intent_sha256: bootstrap.cvm_launch_intent_sha256,
    values: Object.fromEntries(keys.map((key) => [
      key,
      key === "TINKER_ARENA_REGISTRY_RPC_URL"
        ? arenaRegistryRpcUrl
        : `private-${key}`,
    ])),
  };
}

function deferredAuthority() {
  return {
    schema: PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    release_sha: "a".repeat(40),
    batch_id: sha("b"),
    target_authority_sha256: sha("8"),
    cvm_launch_intent_sha256: sha("6"),
    bootstrap_authorization_sha256: sha("a"),
    deployment_intent_sha256: sha("1"),
    final_release_authority_sha256: registryRuntimeProjection.finalAuthoritySha256,
    release_verification_authority_sha256: sha("c"),
    seven_cvm_verified_evidence_set_sha256: sha("e"),
    seven_cvm_launch_completion_receipt_sha256: sha("f"),
    reviewed_at: "2026-07-21T10:30:00Z",
    valid_until: "2026-07-21T11:00:00Z",
    domains: CVM_LAUNCH_DOMAINS.map((domain, index) => ({
      domain,
      measured_cvm_authority_sha256: sha(String(index + 1)),
      values: Object.fromEntries(
        CVM_LAUNCH_DESCRIPTOR_POLICY[domain]
          .public_environment_key_classification.post_measurement_deferred_keys
          .map((key) => [key, publicValue(key)]),
      ),
    })),
  };
}

test("bootstrap public authority is strict, canonical, and imports canonical key classifications", () => {
  const authority = bootstrapAuthority();
  const normalized = normalizeBootstrapPublicEnvironmentAuthority(authority);
  assert.deepEqual(normalized, authority);
  assert.equal(
    canonicalBootstrapPublicEnvironmentAuthorityText(authority),
    canonicalArtifactText(authority),
  );
  assert.match(bootstrapPublicEnvironmentAuthorityDigest(authority), /^sha256:[0-9a-f]{64}$/);
  const bootstrapText = canonicalBootstrapPublicEnvironmentAuthorityText(authority);
  for (const preProvisionEvidence of [
    "fresh_contract_deployment_receipt_sha256",
    "cvm_launch_intent_sha256",
    "cvm_launch_review_receipt_sha256",
    "production_target_authority_sha256",
    "sdk_wire_transform_staging_receipt_sha256",
  ]) {
    assert.equal(bootstrapText.includes(preProvisionEvidence), true);
  }
  assert.equal(bootstrapText.includes("live_activation"), false);
  assert.equal(bootstrapText.includes("ceremony_authorization"), false);
  assert.equal(bootstrapText.includes("measured_cvm"), false);
  assert.equal(bootstrapText.includes("final_ceremony_ledger"), false);
  assert.equal(bootstrapText.includes("final_release_authority"), false);
  for (const entry of normalized.domains) {
    assert.deepEqual(Object.keys(entry.values), bootstrapKeys(entry.domain));
    for (const embedded of CVM_LAUNCH_DESCRIPTOR_POLICY[entry.domain]
      .public_environment_key_classification.descriptor_defaulted_keys) {
      assert.equal(Object.hasOwn(entry.values, embedded), false);
    }
  }

  const extra = structuredClone(authority);
  extra.domains[0].values.PHALA_CLOUD_API_KEY = ["phak_", "must-never-be-public"].join("");
  assert.throws(
    () => normalizeBootstrapPublicEnvironmentAuthority(extra),
    /exactly the reviewed fields/,
  );

  const secretShaped = structuredClone(authority);
  secretShaped.domains[0].values.TINKER_WALLET_AUTH_DOMAIN = "phak_abcdefghijk";
  assert.throws(
    () => normalizeBootstrapPublicEnvironmentAuthority(secretShaped),
    /secret-shaped/,
  );

  for (const [key, value] of [
    ["TINKER_WALLET_AUTH_DOMAIN", "dnai-wikigen"],
    ["TINKER_WALLET_AUTH_URI", "urn:dnai:wikigen"],
  ]) {
    const driftedWalletAuth = structuredClone(authority);
    driftedWalletAuth.domains[0].values[key] = value;
    assert.throws(
      () => normalizeBootstrapPublicEnvironmentAuthority(driftedWalletAuth),
      /must equal the final-release wallet-auth value/,
    );
  }

  for (const driftedOrigins of [
    "https://attacker.invalid",
    "https://www.wikigen.me,https://wikigen.me,https://wikigenme.pages.dev",
    `${exactCorsAllowedOrigins},https://attacker.invalid`,
  ]) {
    const driftedCors = structuredClone(authority);
    driftedCors.domains[0].values.TINKER_CORS_ALLOWED_ORIGINS = driftedOrigins;
    assert.throws(
      () => normalizeBootstrapPublicEnvironmentAuthority(driftedCors),
      /must equal the final-release browser-origin value/,
    );
  }

  const reordered = structuredClone(authority);
  [reordered.domains[0], reordered.domains[1]] = [
    reordered.domains[1],
    reordered.domains[0],
  ];
  assert.throws(
    () => normalizeBootstrapPublicEnvironmentAuthority(reordered),
    /canonical seven-domain order/,
  );

  const causalCycle = structuredClone(authority);
  causalCycle.live_activation_authority_sha256 = sha("a");
  assert.throws(
    () => normalizeBootstrapPublicEnvironmentAuthority(causalCycle),
    /exactly the reviewed fields/,
  );
});

test("provisioning projector derives exact values from all seven observations and rejects drift", () => {
  const bootstrap = bootstrapAuthority();
  const authority = provisioningAuthority(bootstrap);
  assert.deepEqual(normalizeProvisioningEnvironmentAuthority(authority), authority);
  const main = authority.domains[0].values;
  assert.equal(main.EMAIL_ORACLE_CONSUMER_APP_ID, app("1"));
  assert.equal(main.TINKER_ARENA_WORKER_COMPOSE_HASH, bare("1"));
  assert.equal(main.TINKER_DILIGENCE_ALLOWED_OS_IMAGE_HASH, bare("a"));
  assert.equal(Object.keys(main).length, 9);
  assert.ok(authority.domains.slice(1).every(({ values }) => (
    Object.keys(values).length === 0
  )));
  assert.match(provisioningEnvironmentAuthorityDigest(authority), /^sha256:[0-9a-f]{64}$/);

  const drift = structuredClone(authority);
  drift.domains[0].values.EMAIL_ORACLE_CONSUMER_APP_ID = app("9");
  assert.throws(
    () => normalizeProvisioningEnvironmentAuthority(drift),
    /not exactly derived from prepare/,
  );

  const duplicate = prepareObservations();
  duplicate[1].app_id = duplicate[0].app_id;
  assert.throws(
    () => projectProvisioningEnvironmentAuthority({
      batchId: sha("b"),
      targetAuthoritySha256: sha("8"),
      cvmLaunchIntentSha256: sha("5"),
      bootstrapAuthoritySha256: sha("9"),
      preparedAt: "2026-07-21T10:10:00Z",
      prepareObservations: duplicate,
    }),
    /pairwise distinct/,
  );
});

test("post-commit normalization deep-freezes nested values before production branding", () => {
  const normalized = normalizePostCommitProvisioningEnvironmentAuthority(
    postcommitAuthority(),
  );
  const before = structuredClone(normalized);
  const pending = [normalized];
  const seen = new WeakSet();
  while (pending.length > 0) {
    const value = pending.pop();
    if (!value || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    assert.equal(Object.isFrozen(value), true);
    pending.push(...Object.values(value));
  }

  const main = normalized.domains.find(({ domain }) => domain === "main_runtime_cvm");
  assert.ok(main);
  assert.equal(Object.isFrozen(normalized.domains), true);
  assert.equal(Object.isFrozen(main), true);
  assert.equal(Object.isFrozen(main.values), true);
  assert.throws(() => {
    main.values.TINKER_COMPUTE_WORKLOAD_CVM_ID = "cvm-attacker-0002";
  }, TypeError);
  assert.deepEqual(normalized, before);

  // Normalization never forges the private production-provenance brand.
  assert.throws(
    () => assertPostCommitProvisioningEnvironmentAuthority(normalized),
    /lacks replayed executor provenance/,
  );
  assert.throws(
    () => postCommitProvisioningEnvironmentAuthorityDigest(normalized),
    /lacks replayed executor provenance/,
  );

  // Pin the real producer's security-critical ordering without exposing a
  // test-only path for minting its module-private WeakMap brand.
  const source = fs.readFileSync(
    new URL("./phala-production-environment-authority.mjs", import.meta.url),
    "utf8",
  );
  const producer = source.slice(
    source.indexOf("export function projectPostCommitProvisioningEnvironmentAuthority"),
    source.indexOf("export function normalizePostCommitProvisioningEnvironmentAuthority"),
  );
  const freezeOffset = producer.indexOf(
    "const normalized = deepFreezeCanonicalPlainDataGraph(",
  );
  const brandOffset = producer.indexOf("POSTCOMMIT_PROVISIONING_AUTHORITIES.set(");
  assert.ok(freezeOffset >= 0);
  assert.ok(brandOffset > freezeOffset);
  assert.match(
    producer,
    /POSTCOMMIT_PROVISIONING_AUTHORITIES\.set\(\s*normalized,\s*phalaExecutorStateDigest\(executor\),\s*\)/,
  );
});

test("production environment authority timestamps reject impossible calendar aliases", () => {
  for (const impossible of [
    "2026-02-29T10:25:00Z",
    "2026-02-30T10:25:00Z",
    "2026-04-31T10:25:00Z",
  ]) {
    const authority = postcommitAuthority();
    authority.observed_at = impossible;
    assert.throws(
      () => normalizePostCommitProvisioningEnvironmentAuthority(authority),
      /canonical UTC second/,
    );
  }

  const leapDay = postcommitAuthority();
  leapDay.observed_at = "2028-02-29T10:25:00Z";
  assert.equal(
    normalizePostCommitProvisioningEnvironmentAuthority(leapDay).observed_at,
    leapDay.observed_at,
  );
});

test("bootstrap private assembly exposes exact entries while its receipt is secret-invariant", () => {
  const bootstrap = bootstrapAuthority();
  const provisioning = provisioningAuthority(bootstrap);
  const first = assemblePrivateBootstrapEnvironment({
    domain: "main_runtime_cvm",
    now: "2026-07-21T10:20:00Z",
    bootstrapAuthority: bootstrap,
    provisioningAuthority: provisioning,
    secretInput: secretInput("main_runtime_cvm", bootstrap, "one"),
  });
  const second = assemblePrivateBootstrapEnvironment({
    domain: "main_runtime_cvm",
    now: "2026-07-21T10:20:00Z",
    bootstrapAuthority: bootstrap,
    provisioningAuthority: provisioning,
    secretInput: secretInput("main_runtime_cvm", bootstrap, "two"),
  });
  const entries = privateEnvironmentEntries(first);
  const receipt = privateEnvironmentAssemblyReceipt(first);
  assert.equal(entries.BASE_SEPOLIA_RPC_URL, "private-one-BASE_SEPOLIA_RPC_URL");
  assert.equal(
    entries.TINKER_WALLET_AUTH_RPC_URL_SECONDARY,
    "https://wallet-secondary.example/rpc-one",
  );
  assert.equal(entries.EMAIL_ORACLE_CONSUMER_APP_ID, app("1"));
  assert.equal(receipt.values_present_in_receipt, false);
  assert.equal(receipt.value_hashes_present_in_receipt, false);
  assert.equal(receipt.ciphertext_present_in_receipt, false);
  assert.equal(receipt.mutation_performed, false);
  assert.equal(receipt.live_traffic_authorized, false);
  assert.equal(
    canonicalPrivateEnvironmentAssemblyReceiptText(first),
    canonicalPrivateEnvironmentAssemblyReceiptText(second),
  );
  const serialized = canonicalPrivateEnvironmentAssemblyReceiptText(first);
  assert.equal(serialized.includes("private-one"), false);
  assert.equal(serialized.includes("BASE_SEPOLIA_RPC_URL\":"), false);
  assert.throws(() => privateEnvironmentEntries({}), /validated private/);

  assert.throws(
    () => assemblePrivateBootstrapEnvironment({
      domain: "main_runtime_cvm",
      now: "2026-07-21T10:20:00Z",
      bootstrapAuthority: bootstrap,
      provisioningAuthority: provisioning,
      secretInput: secretInput("main_runtime_cvm", bootstrap),
      deferredAuthority: deferredAuthority(),
    }),
    /exactly the reviewed fields/,
  );
});

test("bootstrap assembly rejects stale, cross-batch, cross-launch, and wrong-phase inputs", () => {
  const bootstrap = bootstrapAuthority();
  const provisioning = provisioningAuthority(bootstrap);
  const base = {
    domain: "main_runtime_cvm",
    now: "2026-07-21T10:20:00Z",
    bootstrapAuthority: bootstrap,
    provisioningAuthority: provisioning,
    secretInput: secretInput("main_runtime_cvm", bootstrap),
  };
  assert.throws(
    () => assemblePrivateBootstrapEnvironment({ ...base, now: bootstrap.valid_until }),
    /outside its review window/,
  );
  const wrongBatch = structuredClone(base.secretInput);
  wrongBatch.batch_id = sha("c");
  assert.throws(
    () => assemblePrivateBootstrapEnvironment({ ...base, secretInput: wrongBatch }),
    /batch_id does not match/,
  );
  const wrongPhase = structuredClone(base.secretInput);
  wrongPhase.phase = "final_authority_runtime";
  wrongPhase.values = Object.fromEntries(
    CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm
      .encrypted_secret_environment_keys_by_phase.final_authority_runtime
      .map((key) => [key, `private-${key}`]),
  );
  assert.throws(
    () => assemblePrivateBootstrapEnvironment({ ...base, secretInput: wrongPhase }),
    /requested phase/,
  );
  const unbound = structuredClone(provisioning);
  unbound.bootstrap_authority_sha256 = sha("9");
  assert.throws(
    () => assemblePrivateBootstrapEnvironment({ ...base, provisioningAuthority: unbound }),
    /not bound/,
  );
});

test("phase-secret parser requires exact phase keys and mode-0600 canonical file input", () => {
  const bootstrap = bootstrapAuthority();
  const input = secretInput("main_runtime_cvm", bootstrap);
  assert.deepEqual(normalizePhaseSecretInput(input), input);
  const missing = structuredClone(input);
  delete missing.values.BASE_SEPOLIA_RPC_URL;
  assert.throws(() => normalizePhaseSecretInput(missing), /exactly the reviewed fields/);
  const extra = structuredClone(input);
  extra.values.PHALA_CLOUD_API_KEY = "phak_forbidden";
  assert.throws(() => normalizePhaseSecretInput(extra), /exactly the reviewed fields/);
  const sameWalletOrigin = structuredClone(input);
  sameWalletOrigin.values.TINKER_WALLET_AUTH_RPC_URL_SECONDARY =
    "https://wallet-primary.example/another-path";
  assert.throws(
    () => normalizePhaseSecretInput(sameWalletOrigin),
    /distinct canonical HTTPS origins/,
  );
  const credentialedWalletRpc = structuredClone(input);
  credentialedWalletRpc.values.TINKER_WALLET_AUTH_RPC_URL =
    "https://user:password@wallet-primary.example/rpc";
  assert.throws(
    () => normalizePhaseSecretInput(credentialedWalletRpc),
    /credential-free HTTPS endpoint/,
  );

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-phase-secret-"));
  try {
    const file = path.join(directory, "input.json");
    fs.writeFileSync(file, canonicalArtifactText(input), { mode: 0o600 });
    assert.deepEqual(readExactPhaseSecretInputFile(file, {
      expectedDomain: "main_runtime_cvm",
      expectedPhase: "bootstrap_provision",
      expectedBatchId: input.batch_id,
      expectedCvmLaunchIntentSha256: input.cvm_launch_intent_sha256,
    }), input);

    fs.chmodSync(file, 0o644);
    assert.throws(
      () => readExactPhaseSecretInputFile(file),
      /mode-0600/,
    );
    fs.chmodSync(file, 0o600);
    const link = path.join(directory, "link.json");
    fs.symlinkSync(file, link);
    assert.throws(() => readExactPhaseSecretInputFile(link));

    const noncanonical = path.join(directory, "noncanonical.json");
    fs.writeFileSync(noncanonical, JSON.stringify(input), { mode: 0o600 });
    assert.throws(
      () => readExactPhaseSecretInputFile(noncanonical),
      /canonical sorted two-space JSON/,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("phase-secret binding rejects a same-path byte replacement before mutation", () => {
  const bootstrap = bootstrapAuthority();
  const input = secretInput("main_runtime_cvm", bootstrap);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-phase-binding-"));
  try {
    const file = path.join(directory, "input.json");
    const originalBytes = Buffer.from(canonicalArtifactText(input), "utf8");
    fs.writeFileSync(file, originalBytes, { mode: 0o600 });
    const binding = Object.freeze({
      path: file,
      sha256: sha256Bytes(originalBytes),
    });
    const expected = {
      expectedDomain: "main_runtime_cvm",
      expectedPhase: "bootstrap_provision",
      expectedBatchId: input.batch_id,
      expectedCvmLaunchIntentSha256: input.cvm_launch_intent_sha256,
    };
    assert.deepEqual(
      readExactBoundPhaseSecretInputFile(binding, expected),
      input,
    );

    const replacement = structuredClone(input);
    replacement.values.OPENROUTER_API_KEY = "private-replacement-value";
    fs.writeFileSync(file, canonicalArtifactText(replacement), { mode: 0o600 });
    assert.throws(
      () => readExactBoundPhaseSecretInputFile(binding, expected),
      /changed during its bounded read/,
    );
    assert.throws(
      () => readExactBoundPhaseSecretInputFile({ ...binding, extra: true }, expected),
      /exactly the reviewed fields/,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("final-phase secret parser validates the Arena registry RPC before mutation", () => {
  const valid = finalSecretInput();
  assert.deepEqual(normalizePhaseSecretInput(valid), valid);

  const secretMarker = "operator-rpc-secret";
  const invalidEndpoints = [
    `http://${secretMarker}.example/rpc`,
    `https://${secretMarker}:password@rpc.example/rpc`,
    `https://rpc.example/rpc?token=${secretMarker}`,
    `https://rpc.example/rpc#${secretMarker}`,
    ` https://rpc.example/${secretMarker}`,
    `https://rpc.example/${secretMarker} path`,
    `https://rpc.example:0/${secretMarker}`,
    `https://rpc.example:65536/${secretMarker}`,
    `https://${"a".repeat(254)}/${secretMarker}`,
    `https://rpc.example/${"p".repeat(2_049)}`,
  ];
  for (const arenaRegistryRpcUrl of invalidEndpoints) {
    let thrown;
    try {
      normalizePhaseSecretInput(finalSecretInput({ arenaRegistryRpcUrl }));
    } catch (error) {
      thrown = error;
    }
    assert.ok(thrown instanceof Error, "unsafe Arena registry RPC URL must fail closed");
    assert.match(thrown.message, /Arena registry RPC URL/);
    assert.equal(thrown.message.includes(secretMarker), false);
    assert.equal(thrown.message.includes(arenaRegistryRpcUrl), false);
  }

  const canonicalPort = finalSecretInput({
    arenaRegistryRpcUrl: "https://rpc.example:65535/base-sepolia",
  });
  assert.deepEqual(normalizePhaseSecretInput(canonicalPort), canonicalPort);
});

test("Arena sealed policy payloads match reviewed hashes and authentication before mutation", () => {
  const release = Buffer.from(JSON.stringify(compactSorted({
    chain_id: 84_532,
    schema: "dnai.arena.safe-worker-release.v3",
  })), "ascii");
  const evaluator = Buffer.from(JSON.stringify(compactSorted({
    schema: "dnai.arena.sealed-synthetic-evaluator.v1",
    version: 1,
  })), "ascii");
  const authenticationKey = Buffer.alloc(32, 0x5a);
  const reviewedReleaseManifestSha256 = sha256Bytes(release);
  const reviewedEvaluatorSha256 = sha256Bytes(evaluator);
  const envelope = compactSorted({
    schema: "dnai.arena.sealed-policy-provision.v1",
    release_filename: "release-v2.json",
    release_sha256: reviewedReleaseManifestSha256,
    release_size: release.length,
    evaluator_filename: "sealed-evaluator-v1.json",
    evaluator_sha256: reviewedEvaluatorSha256,
    evaluator_size: evaluator.length,
  });
  const authenticationTag = `hmac-sha256:${createHmac(
    "sha256",
    authenticationKey,
  ).update("dnai-wikigen/arena-sealed-policy-provision/v1\0", "utf8")
    .update(JSON.stringify(envelope), "ascii")
    .digest("hex")}`;
  const input = {
    reviewedReleaseManifestSha256,
    reviewedEvaluatorSha256,
    releasePayloadBase64url: release.toString("base64url"),
    evaluatorPayloadBase64url: evaluator.toString("base64url"),
    authenticationKeyBase64url: authenticationKey.toString("base64url"),
    authenticationTag,
  };
  assert.deepEqual(
    verifyArenaSealedPolicyProvisionEnvelopeCommitments(input),
    {
      payload_hashes_verified: true,
      authentication_tag_verified: true,
    },
  );

  const payloadDrift = { ...input };
  payloadDrift.releasePayloadBase64url = Buffer.from(
    `${release.toString("ascii")} `,
    "ascii",
  ).toString("base64url");
  assert.throws(
    () => verifyArenaSealedPolicyProvisionEnvelopeCommitments(payloadDrift),
    /does not match reviewed commitments/,
  );
  const tagDrift = {
    ...input,
    authenticationTag: `hmac-sha256:${"f".repeat(64)}`,
  };
  assert.throws(
    () => verifyArenaSealedPolicyProvisionEnvelopeCommitments(tagDrift),
    /authentication failed/,
  );
  assert.throws(
    () => verifyArenaSealedPolicyProvisionEnvelopeCommitments({
      ...input,
      transport: {},
    }),
    /exactly the reviewed fields/,
  );
});

test("deferred authority is strict and remains a non-mutating blocked plan", () => {
  const authority = deferredAuthority();
  assert.deepEqual(normalizeDeferredPublicEnvironmentAuthority(authority), authority);
  const plan = createDeferredEnvironmentAssemblyPlan({
    domain: "main_runtime_cvm",
    phase: "final_authority_runtime",
    deferredAuthority: authority,
  });
  assert.equal(plan.availability, "blocked");
  assert.equal(plan.environment_values_present, false);
  assert.equal(plan.mutation_authorized, false);
  assert.deepEqual(plan.phase_control_keys, ["COMPOSE_PROFILES"]);
  assert.ok(plan.secret_value_keys.includes("TINKER_DILIGENCE_QVL_AUTH_TOKEN"));
  assert.throws(
    () => createDeferredEnvironmentAssemblyPlan({
      domain: "main_runtime_cvm",
      phase: "bootstrap_provision",
      deferredAuthority: authority,
    }),
    /must never be used for bootstrap/,
  );
  assert.throws(
    () => createDeferredEnvironmentAssemblyPlan({
      domain: "main_runtime_cvm",
      phase: "final_authority_runtime",
      deferredAuthority: authority,
      legacyFinalReleaseAuthority: {
        schema: "dnai.final-release-authority-core.v2",
      },
    }),
    /exactly the reviewed fields/,
  );

  const badAddress = structuredClone(authority);
  badAddress.domains[0].values.TINKER_DILIGENCE_QVL_VERIFIER_ADDRESS =
    "0x0000000000000000000000000000000000000000";
  assert.throws(
    () => normalizeDeferredPublicEnvironmentAuthority(badAddress),
    /nonzero canonical EVM address/,
  );

  const collapsedDomains = structuredClone(authority);
  collapsedDomains.domains[1].measured_cvm_authority_sha256 =
    collapsedDomains.domains[0].measured_cvm_authority_sha256;
  assert.throws(
    () => normalizeDeferredPublicEnvironmentAuthority(collapsedDomains),
    /pairwise distinct across trust domains/,
  );
});
