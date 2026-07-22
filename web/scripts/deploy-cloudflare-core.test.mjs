import assert from "node:assert/strict";
import test from "node:test";
import { semanticValidationReceipt } from "./build-release-env.mjs";
import {
  __test,
  assertCloudflareControlEnvironment,
  CLOUDFLARE_ACCOUNT_ID,
  CLOUDFLARE_MODELED_PREVIEW_BRANCH,
  CLOUDFLARE_PRODUCTION_BRANCH,
  cloudflareBuildEnvironment,
  cloudflareDeploymentPolicy,
  cloudflareWranglerEnvironment,
  prepareCloudflareDeployment,
} from "./deploy-cloudflare-core.mjs";
import {
  __test as releaseEnvTest,
  arenaReleaseApprovedChallengeSetSha256,
  serializeEnv,
} from "./release-env-core.mjs";
import { COMPUTE_WORKLOAD_BROWSER_ENV_KEYS } from "../../scripts/compute-workload-activation-observation-core.mjs";
import {
  FRONTEND_BUILD_CANDIDATE_SCHEMA,
  FRONTEND_BUILD_CANDIDATE_STATUS,
  FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
} from "./frontend-build-candidate-core.mjs";

const SHA = "1".repeat(40);
const AUTHORITY_BINDING = Object.freeze({
  deploymentIntentSha256: `sha256:${"a1".repeat(32)}`,
  reviewerAuthorityGenesisAcceptanceSha256: `sha256:${"a2".repeat(32)}`,
  ceremonyAuthorizationSha256: `sha256:${"a3".repeat(32)}`,
  computeWorkloadActivationObservationSha256: `sha256:${"a8".repeat(32)}`,
  computeWorkloadBrowserBindingSha256: `sha256:${"a9".repeat(32)}`,
  liveActivationAuthoritySha256: `sha256:${"a4".repeat(32)}`,
  runtimeAuthorityDependencySha256: `sha256:${"a5".repeat(32)}`,
  releaseInputsSha256: `sha256:${"a6".repeat(32)}`,
  frontendBuildCandidateReceiptSha256: `sha256:${"aa".repeat(32)}`,
  frontendBuildSha256: `sha256:${"a7".repeat(32)}`,
});
const ARENA_BINDINGS = Object.freeze({
  "variant-call@1.0.0": Object.freeze({
    registry_challenge_id: "1",
    registry_version: 1,
    controller_address: "0x1111111111111111111111111111111111111111",
    pending_controller_address: "0x0000000000000000000000000000000000000000",
    lifecycle: "open",
    paused: false,
    configuration_frozen: true,
    catalog_manifest_hash: "11".repeat(32),
    metadata_uri: "ipfs://bafybeigdyrzt-reviewed-arena-metadata",
    metadata_hash: `0x${"11".repeat(32)}`,
    sealed_artifact_commitment: `0x${"22".repeat(32)}`,
    evaluator_commitment: `0x${"33".repeat(32)}`,
    release_policy_commitment: `0x${"44".repeat(32)}`,
  }),
});
const ARENA_BINDINGS_JSON = JSON.stringify(ARENA_BINDINGS);
const LIVE_ENV = {
  ...Object.fromEntries(releaseEnvTest.ENV_KEYS.map((key) => [key, ""])),
  ...Object.fromEntries(__test.REQUIRED_LIVE_BINDINGS.map((key) => [key, "release-pinned"])),
  VITE_BASE_SEPOLIA_RPC_URL: "https://sepolia.base.org",
  VITE_BASE_SEPOLIA_SECONDARY_RPC_URL: "https://base-sepolia-rpc.publicnode.com",
  VITE_RELEASE_SHA: SHA,
  VITE_DILIGENCE_ROOM_ADDRESS: "0x1111111111111111111111111111111111111111",
  VITE_COMPUTE_CREDIT_VAULT_ADDRESS: "0x7777777777777777777777777777777777777777",
  VITE_COMPUTE_CREDIT_VAULT_CODE_HASH: `0x${"88".repeat(32)}`,
  VITE_ENABLE_CONTRACT_WRITES: "true",
  VITE_ENABLE_ARTIFACT_UPLOAD: "true",
  VITE_ENABLE_COMPUTE_CONSOLE: "true",
  VITE_ENABLE_ARENA_SUBMISSION: "true",
  VITE_ENABLE_COMPUTE_VAULT_FUNDING: "true",
  VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION: "true",
  VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD: "true",
  VITE_COMPUTE_WORKLOAD_QVL_VERIFIER: "0x2222222222222222222222222222222222222222",
  VITE_COMPUTE_WORKLOAD_CVM_ID: "main-runtime-cvm-0001",
  VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256: `sha256:${"23".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256: `sha256:${"24".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE: `0x${"25".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256: `sha256:${"26".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256: `sha256:${"27".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256: `sha256:${"28".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH: `0x${"33".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_COMPOSE_HASH: `0x${"44".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_APP_ID: "55".repeat(20),
  VITE_COMPUTE_WORKLOAD_OS_IMAGE_HASH: "66".repeat(32),
  VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER: "0x9999999999999999999999999999999999999999",
  VITE_COMPUTE_WORKLOAD_CHAIN_ID: "84532",
  VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS: "0x7777777777777777777777777777777777777777",
  VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH: `0x${"88".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256: `0x${"aa".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS: "300",
  VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON: "[]",
  VITE_ARENA_CHALLENGE_REGISTRY_BINDINGS_JSON: ARENA_BINDINGS_JSON,
  VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256:
    arenaReleaseApprovedChallengeSetSha256(ARENA_BINDINGS),
};

function receiptFor(env = LIVE_ENV) {
  return semanticValidationReceipt(
    SHA,
    serializeEnv(env),
    AUTHORITY_BINDING,
  );
}

test("modeled preview is explicit and may report a dirty working tree", () => {
  const policy = cloudflareDeploymentPolicy({ env: {}, headSha: SHA, dirty: " M README.md" });
  assert.equal(policy.mode, "modeled");
  assert.equal(policy.accountId, CLOUDFLARE_ACCOUNT_ID);
  assert.equal(policy.branch, CLOUDFLARE_MODELED_PREVIEW_BRANCH);
  assert.deepEqual(policy.args.slice(-5), [
    "--branch",
    CLOUDFLARE_MODELED_PREVIEW_BRANCH,
    "--commit-hash",
    SHA,
    "--commit-dirty=true",
  ]);
  assert.equal(policy.args.includes(CLOUDFLARE_PRODUCTION_BRANCH), false);
  assert.ok(policy.args.includes("--commit-dirty=true"));
});

test("live release requires exact clean HEAD and targets only the production branch", () => {
  const policy = cloudflareDeploymentPolicy({
    env: LIVE_ENV,
    headSha: SHA,
    dirty: "",
    semanticValidationReceipt: receiptFor(),
  });
  assert.equal(policy.mode, "live");
  assert.equal(policy.accountId, CLOUDFLARE_ACCOUNT_ID);
  assert.equal(policy.branch, CLOUDFLARE_PRODUCTION_BRANCH);
  assert.equal(
    policy.semanticAuthority.frontendBuildCandidateReceiptSha256,
    AUTHORITY_BINDING.frontendBuildCandidateReceiptSha256,
  );
  assert.equal(
    policy.frontendBuildSha256,
    AUTHORITY_BINDING.frontendBuildSha256,
  );
  assert.deepEqual(policy.args.slice(-5), [
    "--branch",
    CLOUDFLARE_PRODUCTION_BRANCH,
    "--commit-hash",
    SHA,
    "--commit-dirty=false",
  ]);
  assert.equal(policy.args.includes(CLOUDFLARE_MODELED_PREVIEW_BRANCH), false);
});

test("Cloudflare control environment cannot redirect credentials or change the reviewed account", () => {
  assert.doesNotThrow(() => assertCloudflareControlEnvironment({}));
  assert.doesNotThrow(() => assertCloudflareControlEnvironment({
    CLOUDFLARE_ACCOUNT_ID,
    CLOUDFLARE_API_TOKEN: "opaque-auth-value",
  }));
  assert.doesNotThrow(() => assertCloudflareControlEnvironment({
    CLOUDFLARE_ACCOUNT_ID,
    CLOUDFLARE_API_KEY: "opaque-global-key",
    CLOUDFLARE_EMAIL: "release-operator@example.com",
  }));
  for (const env of [
    { CLOUDFLARE_ACCOUNT_ID: "0".repeat(32) },
    { CLOUDFLARE_ACCOUNT_ID: " undefined " },
    { CLOUDFLARE_BASE_URL: "https://attacker.invalid" },
    { CLOUDFLARE_API_BASE_URL: "https://attacker.invalid/client/v4" },
    { CF_API_BASE_URL: "https://attacker.invalid/client/v4" },
    { CLOUDFLARE_COMPLIANCE_REGION: "fedramp_high" },
    { CF_ACCOUNT_ID: CLOUDFLARE_ACCOUNT_ID },
    { CF_API_TOKEN: "deprecated-token" },
    { CF_API_KEY: "deprecated-key" },
    { CF_EMAIL: "deprecated@example.com" },
    { CLOUDFLARE_ACCESS_CLIENT_ID: "unreviewed-access-client" },
    { CLOUDFLARE_ACCESS_CLIENT_SECRET: "unreviewed-access-secret" },
    { CF_PAGES_UPLOAD_JWT: "alternate-upload-authority" },
    { WRANGLER_API_ENVIRONMENT: "staging" },
    { WRANGLER_AUTH_DOMAIN: "attacker.invalid" },
    { WRANGLER_AUTH_URL: "https://attacker.invalid/oauth2/auth" },
    { WRANGLER_TOKEN_URL: "https://attacker.invalid/oauth2/token" },
    { WRANGLER_REVOKE_URL: "https://attacker.invalid/oauth2/revoke" },
    { WRANGLER_CLIENT_ID: "unreviewed-client" },
    { WRANGLER_CF_AUTHORIZATION_TOKEN: "alternate-authorization" },
    { WRANGLER_LOG: "debug" },
    { WRANGLER_LOG_PATH: "/tmp/unreviewed-wrangler.log" },
    { WRANGLER_LOG_SANITIZE: "false" },
    { WRANGLER_WRITE_LOGS: "true" },
    { HTTP_PROXY: "https://attacker.invalid" },
    { http_proxy: "https://attacker.invalid" },
    { HTTPS_PROXY: "https://attacker.invalid" },
    { https_proxy: "https://attacker.invalid" },
    { ALL_PROXY: "https://attacker.invalid" },
    { all_proxy: "https://attacker.invalid" },
    { NO_PROXY: "api.cloudflare.com" },
    { no_proxy: "api.cloudflare.com" },
    { NODE_OPTIONS: "--import=/tmp/unreviewed-hook.mjs" },
    { NODE_PATH: "/tmp/unreviewed-modules" },
    { NODE_USE_ENV_PROXY: "1" },
    { NODE_EXTRA_CA_CERTS: "/tmp/unreviewed-ca.pem" },
    { NODE_TLS_REJECT_UNAUTHORIZED: "0" },
    { SSL_CERT_FILE: "/tmp/unreviewed-ca.pem" },
    { SSL_CERT_DIR: "/tmp/unreviewed-ca-directory" },
    { SSLKEYLOGFILE: "/tmp/cloudflare-tls-keys.log" },
    { LD_PRELOAD: "/tmp/unreviewed-hook.so" },
    { DYLD_INSERT_LIBRARIES: "/tmp/unreviewed-hook.dylib" },
    { HTTPS_PROXY: " " },
    { CLOUDFLARE_API_BASE_URL: "undefined" },
    { CLOUDFLARE_API_KEY: "global-key-without-email" },
    { CLOUDFLARE_EMAIL: "global-email-without-key@example.com" },
    {
      CLOUDFLARE_API_TOKEN: "api-token",
      CLOUDFLARE_API_KEY: "global-key",
      CLOUDFLARE_EMAIL: "global@example.com",
    },
  ]) {
    assert.throws(() => assertCloudflareControlEnvironment(env), /Cloudflare release/);
  }
});

test("Wrangler receives only Cloudflare auth and a minimal execution environment", () => {
  const child = cloudflareWranglerEnvironment({
    PATH: "/reviewed/bin",
    HOME: "/Users/release",
    TMPDIR: "/private/tmp/release",
    LANG: "C.UTF-8",
    CLOUDFLARE_ACCOUNT_ID,
    CLOUDFLARE_API_TOKEN: "cloudflare-token",
    PHALA_CLOUD_API_KEY: ["phak_", "must_not_reach_wrangler"].join(""),
    OPENROUTER_API_KEY: ["sk-", "or-v1-must-not-reach-wrangler"].join(""),
    GITHUB_TOKEN: ["ghp_", "must_not_reach_wrangler"].join(""),
    VITE_RELEASE_SHA: SHA,
  });
  assert.deepEqual(child, {
    HOME: "/Users/release",
    TMPDIR: "/private/tmp/release",
    LANG: "C.UTF-8",
    CLOUDFLARE_API_TOKEN: "cloudflare-token",
    PATH: __test.RELEASE_CHILD_PATH,
    CLOUDFLARE_ACCOUNT_ID,
    WRANGLER_SEND_METRICS: "false",
    WRANGLER_SEND_ERROR_REPORTS: "false",
    WRANGLER_LOG_SANITIZE: "true",
    WRANGLER_WRITE_LOGS: "false",
  });
  assert.equal(Object.isFrozen(child), true);
});

test("fresh frontend builds receive only public release values and a minimal host environment", () => {
  const buildEnv = cloudflareBuildEnvironment({
    VITE_RELEASE_SHA: SHA,
    OPENROUTER_API_KEY: "must-not-reach-build",
    PHALA_CLOUD_API_KEY: "must-not-reach-build",
    CLOUDFLARE_API_TOKEN: "must-not-reach-build",
  }, {
    PATH: "/usr/bin:/bin",
    HOME: "/Users/release",
    LANG: "C.UTF-8",
    GITHUB_TOKEN: "must-not-reach-build",
    KMS_PRIVATE_KEY: "must-not-reach-build",
    NODE_OPTIONS: "--require=/tmp/unreviewed.cjs",
  }, "/private/tmp/dnai-isolated-home");
  assert.deepEqual(buildEnv, {
    PATH: __test.RELEASE_CHILD_PATH,
    LANG: "C",
    LC_ALL: "C",
    TZ: "UTC",
    CI: "true",
    NO_COLOR: "1",
    TERM: "dumb",
    VITE_RELEASE_SHA: SHA,
    HOME: "/private/tmp/dnai-isolated-home",
    TMPDIR: "/private/tmp/dnai-isolated-home/tmp",
    XDG_CACHE_HOME: "/private/tmp/dnai-isolated-home/.cache",
    XDG_CONFIG_HOME: "/private/tmp/dnai-isolated-home/.config",
    XDG_DATA_HOME: "/private/tmp/dnai-isolated-home/.local/share",
    NODE_ENV: "production",
    NPM_CONFIG_AUDIT: "false",
    NPM_CONFIG_CACHE: "/private/tmp/dnai-isolated-home/.npm-cache",
    NPM_CONFIG_FUND: "false",
    NPM_CONFIG_UPDATE_NOTIFIER: "false",
    NPM_CONFIG_USERCONFIG: "/private/tmp/dnai-isolated-home/.npmrc",
  });
  for (const forbidden of [
    "OPENROUTER_API_KEY",
    "PHALA_CLOUD_API_KEY",
    "CLOUDFLARE_API_TOKEN",
    "GITHUB_TOKEN",
    "KMS_PRIVATE_KEY",
    "NODE_OPTIONS",
  ]) {
    assert.equal(Object.prototype.hasOwnProperty.call(buildEnv, forbidden), false);
  }
  assert.notEqual(buildEnv.HOME, "/Users/release");
  assert.throws(
    () => cloudflareBuildEnvironment({}, {}, "relative-home"),
    /canonical absolute isolated HOME/,
  );
});

test("modeled preview rejects every VITE override, including unknown secret-shaped keys", () => {
  for (const env of [
    { VITE_ENABLE_ARENA_SUBMISSION: "false" },
    { VITE_DISPLAY_COPY: "unreviewed" },
    { VITE_PRIVATE_KEY: "must-never-enter-vite" },
  ]) {
    assert.throws(
      () => cloudflareDeploymentPolicy({ env, headSha: SHA, dirty: "" }),
      /empty VITE_ environment/,
    );
  }
  for (const value of ["", `0x${"55".repeat(20)}`]) {
    assert.throws(
      () => cloudflareDeploymentPolicy({
        env: { VITE_COMPUTE_WORKLOAD_EXECUTION_SIGNER: value },
        headSha: SHA,
        dirty: "",
      }),
      /legacy or ambiguous VITE_COMPUTE_WORKLOAD_EXECUTION_SIGNER/,
    );
  }
});

test("live release requires the in-process semantic receipt and its exact env digest", () => {
  assert.throws(
    () => cloudflareDeploymentPolicy({ env: LIVE_ENV, headSha: SHA, dirty: "" }),
    /in-process canonical semantic validation receipt/,
  );
  assert.throws(
    () => cloudflareDeploymentPolicy({
      env: { ...LIVE_ENV, VITE_DELEGATE_URL: "https://other.release.wikigen.me" },
      headSha: SHA,
      dirty: "",
      semanticValidationReceipt: receiptFor(),
    }),
    /does not match the semantic validation digest/,
  );
  assert.throws(
    () => cloudflareDeploymentPolicy({
      env: { ...LIVE_ENV, VITE_PRIVATE_KEY: "must-never-enter-vite" },
      headSha: SHA,
      dirty: "",
      semanticValidationReceipt: receiptFor(),
    }),
    /not the canonical allowlisted output/,
  );
  assert.throws(
    () => cloudflareDeploymentPolicy({
      env: LIVE_ENV,
      headSha: SHA,
      dirty: "",
      semanticValidationReceipt: { ...receiptFor(), unexpected: true },
    }),
    /unexpected shape/,
  );
  const receiptWithoutAuthority = receiptFor();
  delete receiptWithoutAuthority.live_activation_authority_sha256;
  assert.throws(
    () => cloudflareDeploymentPolicy({
      env: LIVE_ENV,
      headSha: SHA,
      dirty: "",
      semanticValidationReceipt: receiptWithoutAuthority,
    }),
    /unexpected shape/,
  );
  for (const invalidAuthorityHash of [
    `sha256:${"0".repeat(64)}`,
    `sha256:${"AB".repeat(32)}`,
    "a1".repeat(32),
  ]) {
    assert.throws(
      () => cloudflareDeploymentPolicy({
        env: LIVE_ENV,
        headSha: SHA,
        dirty: "",
        semanticValidationReceipt: {
          ...receiptFor(),
          live_activation_authority_sha256: invalidAuthorityHash,
        },
      }),
      /does not authorize this release/,
    );
  }
  for (const key of [
    "compute_workload_activation_observation_sha256",
    "compute_workload_browser_binding_sha256",
    "frontend_build_candidate_receipt_sha256",
  ]) {
    assert.throws(
      () => cloudflareDeploymentPolicy({
        env: LIVE_ENV,
        headSha: SHA,
        dirty: "",
        semanticValidationReceipt: {
          ...receiptFor(),
          [key]: `sha256:${"0".repeat(64)}`,
        },
      }),
      /does not authorize this release/,
    );
  }
  assert.throws(
    () => cloudflareDeploymentPolicy({
      env: LIVE_ENV,
      headSha: SHA,
      dirty: "",
      semanticValidationReceipt: {
        ...receiptFor(),
        frontend_build_candidate_receipt_sha256:
          AUTHORITY_BINDING.frontendBuildSha256,
      },
    }),
    /collapses D into the dist manifest/,
  );
  const candidateReceipt = {
    schema: FRONTEND_BUILD_CANDIDATE_SCHEMA,
    status: FRONTEND_BUILD_CANDIDATE_STATUS,
    truth_status: FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
    release_sha: SHA,
    chain_id: 84_532,
    deployment_intent_sha256: AUTHORITY_BINDING.deploymentIntentSha256,
    reviewer_authority_genesis_acceptance_sha256:
      AUTHORITY_BINDING.reviewerAuthorityGenesisAcceptanceSha256,
    ceremony_authorization_sha256: AUTHORITY_BINDING.ceremonyAuthorizationSha256,
    runtime_authority_dependency_sha256:
      AUTHORITY_BINDING.runtimeAuthorityDependencySha256,
    compute_workload_activation_observation_sha256:
      AUTHORITY_BINDING.computeWorkloadActivationObservationSha256,
    frontend_build_sha256: AUTHORITY_BINDING.frontendBuildSha256,
    release_inputs_sha256: AUTHORITY_BINDING.releaseInputsSha256,
    release_env_sha256: receiptFor().release_env_sha256,
    raw_secret_egress: false,
  };
  const legacyReceipt = {
    schema: "dnai.semantic-release-validation.v2",
    status: "semantic_release_authority_validated",
    release_sha: SHA,
    chain_id: 84_532,
    deployment_intent_sha256: AUTHORITY_BINDING.deploymentIntentSha256,
    final_authority_sha256: AUTHORITY_BINDING.liveActivationAuthoritySha256,
    review_envelope_sha256: AUTHORITY_BINDING.ceremonyAuthorizationSha256,
    review_evidence_sha256: AUTHORITY_BINDING.reviewerAuthorityGenesisAcceptanceSha256,
    release_env_sha256: receiptFor().release_env_sha256.slice(7),
    raw_secret_egress: false,
  };
  for (const receipt of [candidateReceipt, legacyReceipt]) {
    assert.throws(
      () => cloudflareDeploymentPolicy({
        env: LIVE_ENV,
        headSha: SHA,
        dirty: "",
        semanticValidationReceipt: receipt,
      }),
      /unexpected shape/,
    );
  }
});

test("live release rejects RPC endpoint drift before any Cloudflare deployment", () => {
  for (const env of [
    { ...LIVE_ENV, VITE_BASE_SEPOLIA_RPC_URL: "https://user@sepolia.base.org" },
    { ...LIVE_ENV, VITE_BASE_SEPOLIA_RPC_URL: "https://primary-rpc.wikigen.me/base-sepolia" },
    { ...LIVE_ENV, VITE_BASE_SEPOLIA_SECONDARY_RPC_URL: "https://base-sepolia-rpc.publicnode.com?key=value" },
    { ...LIVE_ENV, VITE_BASE_SEPOLIA_SECONDARY_RPC_URL: "https://sepolia.base.org/other" },
  ]) {
    assert.throws(
      () => cloudflareDeploymentPolicy({
        env,
        headSha: SHA,
        dirty: "",
        semanticValidationReceipt: receiptFor(env),
      }),
      /RPC URL|provider origin|public HTTPS|canonical primary RPC/,
    );
  }
});

test("deployment preparation re-runs the canonical check-only validator only for live mode", async () => {
  let modeledCalls = 0;
  const modeled = await prepareCloudflareDeployment({
    env: {},
    headSha: SHA,
    dirty: " M README.md",
    validateReleaseEnvironment: async () => {
      modeledCalls += 1;
      throw new Error("modeled validation must not run");
    },
  });
  assert.equal(modeled.mode, "modeled");
  assert.equal(modeledCalls, 0);
  await assert.rejects(
    prepareCloudflareDeployment({
      env: {},
      headSha: SHA,
      dirty: "",
      releaseArguments: ["--release", "/tmp/release.json"],
      validateReleaseEnvironment: async () => undefined,
    }),
    /modeled Cloudflare deployment does not accept live release evidence arguments/,
  );

  const releaseArguments = [
    "--release", "/tmp/release.json",
    "--release-core", "/tmp/release-core.json",
  ];
  let validatorArguments;
  const live = await prepareCloudflareDeployment({
    env: LIVE_ENV,
    headSha: SHA,
    dirty: "",
    releaseArguments,
    validateReleaseEnvironment: async (args) => {
      validatorArguments = args;
      return receiptFor();
    },
  });
  assert.equal(live.mode, "live");
  assert.deepEqual(validatorArguments, ["--check-only", ...releaseArguments]);
  await assert.rejects(
    prepareCloudflareDeployment({
      env: LIVE_ENV,
      headSha: SHA,
      dirty: "",
      releaseArguments,
      validateReleaseEnvironment: async () => {
        throw new Error("semantic validator rejected placeholders");
      },
    }),
    /semantic validator rejected placeholders/,
  );
});

test("partial or dirty live configuration fails closed", () => {
  assert.throws(
    () => cloudflareDeploymentPolicy({
      env: { VITE_DILIGENCE_ROOM_ADDRESS: LIVE_ENV.VITE_DILIGENCE_ROOM_ADDRESS },
      headSha: SHA,
      dirty: "",
    }),
    /full generated VITE_RELEASE_SHA/,
  );
  assert.throws(
    () => cloudflareDeploymentPolicy({
      env: { VITE_COMPUTE_CREDIT_VAULT_ADDRESS: "0x2222222222222222222222222222222222222222" },
      headSha: SHA,
      dirty: "",
    }),
    /full generated VITE_RELEASE_SHA/,
  );
  assert.throws(
    () => cloudflareDeploymentPolicy({
      env: { VITE_ENABLE_COMPUTE_VAULT_FUNDING: "true" },
      headSha: SHA,
      dirty: "",
    }),
    /full generated VITE_RELEASE_SHA/,
  );
  assert.throws(
    () => cloudflareDeploymentPolicy({ env: LIVE_ENV, headSha: "2".repeat(40), dirty: "" }),
    /does not match HEAD/,
  );
  assert.throws(
    () => cloudflareDeploymentPolicy({ env: LIVE_ENV, headSha: SHA, dirty: "?? local.txt" }),
    /dirty worktree/,
  );
});

test("live release requires the complete generated feature set", () => {
  for (const key of __test.REQUIRED_LIVE_FEATURE_FLAGS) {
    for (const value of ["false", ""]) {
      assert.throws(
        () => cloudflareDeploymentPolicy({
          env: { ...LIVE_ENV, [key]: value },
          headSha: SHA,
          dirty: "",
        }),
        new RegExp(`${key}=true`),
      );
    }
  }
});

test("all-features release requires the exact O-derived workload gate and nineteen pins", () => {
  const [gate, ...pins] = COMPUTE_WORKLOAD_BROWSER_ENV_KEYS;
  assert.equal(gate, "VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD");
  assert.equal(pins.length, 19);
  assert.ok(__test.LIVE_FEATURE_FLAGS.includes(gate));
  assert.ok(__test.REQUIRED_LIVE_FEATURE_FLAGS.includes(gate));
  assert.equal(__test.REQUIRED_LIVE_BINDINGS.includes(gate), false);
  assert.equal(__test.RELEASE_BINDINGS.includes(gate), false);
  assert.deepEqual(
    __test.REQUIRED_LIVE_BINDINGS.filter((key) => key.startsWith("VITE_COMPUTE_WORKLOAD_")),
    pins,
  );
  assert.deepEqual(
    __test.RELEASE_BINDINGS.filter((key) => key.startsWith("VITE_COMPUTE_WORKLOAD_")),
    pins,
  );
  for (const key of pins) {
    assert.ok(__test.REQUIRED_LIVE_BINDINGS.includes(key), `${key} is not required`);
    assert.ok(__test.RELEASE_BINDINGS.includes(key), `${key} is not release-bound`);
  }
  assert.ok(__test.REQUIRED_LIVE_BINDINGS.includes("VITE_DELEGATE_URL"));
});

test("live release exact-binds the generated Arena approved challenge set", () => {
  for (const list of [__test.REQUIRED_LIVE_BINDINGS, __test.RELEASE_BINDINGS]) {
    const bindingsIndex = list.indexOf("VITE_ARENA_CHALLENGE_REGISTRY_BINDINGS_JSON");
    assert.ok(bindingsIndex >= 0);
    assert.equal(
      list[bindingsIndex + 1],
      "VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256",
    );
  }

  for (const [key, value, error] of [
    [
      "VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256",
      "",
      /VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256/,
    ],
    [
      "VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256",
      `sha256:${"0".repeat(64)}`,
      /exact nonzero Arena approved challenge-set SHA-256/,
    ],
    [
      "VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256",
      `sha256:${"aa".repeat(32)}`,
      /digest does not match the exact registry bindings/,
    ],
    [
      "VITE_ARENA_CHALLENGE_REGISTRY_BINDINGS_JSON",
      `${ARENA_BINDINGS_JSON} `,
      /exact compact JSON/,
    ],
    [
      "VITE_ARENA_CHALLENGE_REGISTRY_BINDINGS_JSON",
      JSON.stringify({
        ...ARENA_BINDINGS,
        "variant-call@1.0.0": {
          ...ARENA_BINDINGS["variant-call@1.0.0"],
          metadata_uri: "ipfs://bafybeigdyrzt-mutated-arena-metadata",
        },
      }),
      /digest does not match the exact registry bindings/,
    ],
  ]) {
    const env = { ...LIVE_ENV, [key]: value };
    assert.throws(
      () => cloudflareDeploymentPolicy({
        env,
        headSha: SHA,
        dirty: "",
        semanticValidationReceipt: receiptFor(env),
      }),
      error,
      `${key}=${value}`,
    );
  }
});

test("workload release pins cannot drift from Base Sepolia or the exact fresh vault", () => {
  for (const [key, value, error] of [
    ["VITE_COMPUTE_WORKLOAD_CVM_ID", "Main-Runtime-CVM-0001", /exact canonical VITE_COMPUTE_WORKLOAD_CVM_ID/],
    ["VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256", `sha256:${"0".repeat(64)}`, /exact canonical VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256/],
    ["VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256", `sha256:${"AB".repeat(32)}`, /exact canonical VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256/],
    ["VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE", `0x${"0".repeat(64)}`, /exact canonical VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE/],
    ["VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256", `sha256:${"0".repeat(64)}`, /exact canonical VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256/],
    ["VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256", `sha256:${"0".repeat(64)}`, /exact canonical VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256/],
    ["VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256", `sha256:${"0".repeat(64)}`, /exact canonical VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256/],
    ["VITE_COMPUTE_WORKLOAD_CHAIN_ID", "8453", /must target Base Sepolia/],
    ["VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS", "0x6666666666666666666666666666666666666666", /contract does not match ComputeCreditVault/],
    ["VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH", `0x${"77".repeat(32)}`, /runtime does not match ComputeCreditVault/],
    ["VITE_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256", `0x${"88".repeat(32)}`, /receipt cannot collapse into runtime code/],
    ["VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS", "301", /1 through 300 seconds/],
    ["VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON", "[ ]", /not exact, sorted, and unique/],
    ["VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON", JSON.stringify([`0x${"bb".repeat(32)}`, `0x${"aa".repeat(32)}`]), /not exact, sorted, and unique/],
  ]) {
    assert.throws(
      () => cloudflareDeploymentPolicy({
        env: { ...LIVE_ENV, [key]: value },
        headSha: SHA,
        dirty: "",
      }),
      error,
      key,
    );
  }
});

test("live release refuses any missing baseline trust-chain binding", () => {
  for (const key of [
    "VITE_DILIGENCE_ROOM_CODE_HASH",
    "VITE_ROYALTY_DISTRIBUTOR_CODE_HASH",
    "VITE_TINKER_ENCUMBRANCE_CODE_HASH",
    "VITE_EMAIL_ORACLE_AUTH_CODE_HASH",
    "VITE_PHALA_COMPOSE_HASH",
    "VITE_ARENA_VERIFIED_QUOTE_SHA256",
    "VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256",
    "VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256",
    "VITE_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT",
    "VITE_EXECUTION_POLICY_APPROVER_ROOT_HASH",
    "VITE_BASE_SEPOLIA_RPC_URL",
    "VITE_BASE_SEPOLIA_SECONDARY_RPC_URL",
    "VITE_COMPUTE_CREDIT_VAULT_ADDRESS",
    "VITE_COMPUTE_CREDIT_VAULT_CODE_HASH",
    "VITE_COMPUTE_VAULT_METERING_VERIFIER",
    "VITE_COMPUTE_VAULT_METERING_POLICY_SET_HASH",
    "VITE_COMPUTE_VAULT_ERC20_ASSET_ADDRESS",
    "VITE_COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT",
  ]) {
    assert.throws(
      () => cloudflareDeploymentPolicy({
        env: { ...LIVE_ENV, [key]: "" },
        headSha: SHA,
        dirty: "",
      }),
      new RegExp(key),
    );
  }
});

test("Cloudflare treats every application contract runtime hash as a live binding", () => {
  for (const key of [
    "VITE_DILIGENCE_ROOM_CODE_HASH",
    "VITE_CHALLENGE_REGISTRY_CODE_HASH",
    "VITE_ROYALTY_DISTRIBUTOR_CODE_HASH",
    "VITE_TINKER_ENCUMBRANCE_CODE_HASH",
    "VITE_EMAIL_ORACLE_AUTH_CODE_HASH",
    "VITE_COMPUTE_CREDIT_VAULT_CODE_HASH",
    "VITE_EXECUTION_POLICY_ANCHOR_CODE_HASH",
  ]) {
    assert.ok(__test.RELEASE_BINDINGS.includes(key), `${key} is not release-bound`);
  }
});

test("Cloudflare treats the independently verified compute-metering quote as a live binding", () => {
  assert.ok(__test.REQUIRED_LIVE_BINDINGS.includes("VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256"));
  assert.ok(__test.RELEASE_BINDINGS.includes("VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256"));
});

test("Cloudflare treats every active execution-policy anchor pin as a live release binding", () => {
  for (const key of [
    "VITE_EXECUTION_POLICY_ANCHOR_ADDRESS",
    "VITE_EXECUTION_POLICY_ANCHOR_CODE_HASH",
    "VITE_EXECUTION_POLICY_ANCHOR_WRITER",
    "VITE_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT",
    "VITE_EXECUTION_POLICY_ANCHOR_CONFIRMATIONS",
    "VITE_EXECUTION_POLICY_ANCHOR_MAX_BLOCK_AGE_SECONDS",
    "VITE_EXECUTION_POLICY_ANCHOR_MAX_FUTURE_BLOCK_SKEW_SECONDS",
  ]) {
    assert.ok(__test.RELEASE_BINDINGS.includes(key));
  }
});
