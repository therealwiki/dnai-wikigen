import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
} from "./cvm-launch-intent-core.mjs";
import {
  canonicalArtifactSha256,
  canonicalArtifactText,
  createDraftDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import {
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
  canonicalBootstrapPublicEnvironmentAuthorityText,
} from "./phala-production-environment-authority.mjs";
import {
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH,
  canonicalPhalaNonLiveBootstrapAuthorizationText,
  readAndVerifyPhalaNonLiveBootstrapAuthorization,
} from "./phala-nonlive-bootstrap-authorization.mjs";
import {
  PHALA_NONLIVE_BOOTSTRAP_EXTERNAL_SIGNATURES_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_LOCAL_PUBLICATION_BLOCKER_CODES,
  PHALA_NONLIVE_BOOTSTRAP_SIGNING_DIAGNOSTIC_SCHEMA,
  parsePhalaNonLiveBootstrapAuthorizationCliArgs,
} from "./phala-nonlive-bootstrap-authorization-cli.mjs";
import {
  PINNED_EIP191_SIGNATURE_SCHEME,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
} from "./release-authority-signature-verifier.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
  canonicalReleaseReviewerAuthorityGenesisArtifactText,
  reviewerControllerSetSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
  canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText,
  createReleaseReviewerAuthorityCurrentStatusSigningPayload,
  createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityCurrentStatusSigningMessage,
  releaseReviewerAuthorityCurrentStatusSigningPayloadSha256,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
  releaseReviewerAuthorityGenesisAcceptanceSigningMessage,
  releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";

const REPOSITORY_ROOT = fs.realpathSync(path.resolve(import.meta.dirname, ".."));
const CLI_PATH = path.join(
  REPOSITORY_ROOT,
  "scripts/phala-nonlive-bootstrap-authorization-cli.mjs",
);
const SCHEMA_PATH = path.join(
  REPOSITORY_ROOT,
  "deployments/phala-nonlive-bootstrap-authorization.schema.json",
);
const TEMPLATE_PATH = path.join(
  REPOSITORY_ROOT,
  "deployments/phala-nonlive-bootstrap-authorization.template.json",
);
const TEST_ALPHA = privateKeyToAccount(`0x${"11".repeat(32)}`);
const TEST_BRAVO = privateKeyToAccount(`0x${"22".repeat(32)}`);
const TEST_GUARDIAN_ALPHA = privateKeyToAccount(`0x${"33".repeat(32)}`);
const TEST_GUARDIAN_BRAVO = privateKeyToAccount(`0x${"44".repeat(32)}`);
const sha = (digit) => `sha256:${String(digit).repeat(64)}`;
const bare = (digit) => String(digit).repeat(64);
const address = (digit) => `0x${String(digit).repeat(40)}`;
const BATCH_ID = sha("b");
const ISSUED_AT = "2026-07-21T10:01:00Z";
const EXPIRES_AT = "2026-07-21T10:11:00Z";
const NOW = "2026-07-21T10:02:00Z";

function canonicalFile(filePath, value, mode = 0o600) {
  fs.writeFileSync(filePath, canonicalArtifactText(value), { mode });
  fs.chmodSync(filePath, mode);
  return fs.realpathSync(filePath);
}

function publicValue(key) {
  if (key === "TINKER_WALLET_AUTH_DOMAIN") return "www.wikigen.me";
  if (key === "TINKER_WALLET_AUTH_URI") return "https://www.wikigen.me";
  if (key.endsWith("_ADDRESS")) return address("a");
  if (key.endsWith("_URL") || key.endsWith("_URI")) {
    return `https://authority.example/${key.toLowerCase()}`;
  }
  if (key === "TINKER_CORS_ALLOWED_ORIGINS") {
    return "https://wikigen.me,https://wikigenme.pages.dev,https://www.wikigen.me";
  }
  if (key === "TINKER_FUNDING_PREFLIGHT_ALLOWED_HOSTS") {
    return "api.tinker.example";
  }
  if (key === "TINKER_EXECUTION_POLICY_APPROVED_SIGNERS") {
    return [TEST_ALPHA.address, TEST_BRAVO.address]
      .map((value) => value.toLowerCase()).sort().join(",");
  }
  if (key === "TINKER_WALLET_AUTH_CHAIN_ID") return "84532";
  if (key === "TINKER_CHAIN_START_BLOCK") return "12345678";
  if (key.endsWith("_RUNTIME_CODE_HASH")) return `0x${bare("a")}`;
  if (key.endsWith("_SHA256") || key.endsWith("_HASH")) return bare("a");
  return `reviewed-${key.toLowerCase()}`;
}

function bootstrapKeys(domain) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const allowed = new Set(policy.exact_allowed_environment_keys);
  return policy.public_environment_key_classification.descriptor_static_keys
    .filter((key) => allowed.has(key));
}

function reviewerFixture() {
  const identities = [
    {
      account: TEST_ALPHA,
      address: TEST_ALPHA.address.toLowerCase(),
      controller_id: "reviewer-alpha",
    },
    {
      account: TEST_BRAVO,
      address: TEST_BRAVO.address.toLowerCase(),
      controller_id: "reviewer-bravo",
    },
  ].sort((left, right) => left.address.localeCompare(right.address));
  const reviewers = identities.map(({ address: reviewerAddress, controller_id }) => ({
    address: reviewerAddress,
    controller_id,
  }));
  const reviewerControllers = reviewers.map((entry) => ({
    controller_id: entry.controller_id,
    preauthorized_addresses: [entry.address],
  })).sort((left, right) => left.controller_id.localeCompare(right.controller_id));
  const guardianAccounts = [TEST_GUARDIAN_ALPHA, TEST_GUARDIAN_BRAVO];
  const statusGuardians = guardianAccounts.map((account, index) => ({
    address: account.address.toLowerCase(),
    controller_id: `status-guardian-${index + 1}`,
  })).sort((left, right) => left.address.localeCompare(right.address));
  const guardianHashes = statusGuardians
    .map((entry) => executionPolicyReviewerHash(entry.address)).sort();
  const genesis = {
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
    truth_status: RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
    release_sha: "a".repeat(40),
    chain_id: 84_532,
    minimum_active_reviewers: RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
    reviewer_controllers: reviewerControllers,
    reviewer_controller_set_sha256: reviewerControllerSetSha256(reviewerControllers),
    status_guardians: statusGuardians,
    status_guardian_hashes: guardianHashes,
    status_guardian_root_hash: executionPolicyReviewerRootHash(guardianHashes),
    status_guardian_set_sha256: reviewerSetSha256(statusGuardians),
  };
  return { genesis, guardianAccounts, identities, reviewers };
}

async function genesisAcceptanceFixture(reviewers) {
  const statusPayload = createReleaseReviewerAuthorityCurrentStatusSigningPayload({
    epoch: 1,
    not_before: "2026-07-21T09:58:00Z",
    expires_at: "2026-07-21T10:13:00Z",
    previous_status_sha256: `sha256:${"0".repeat(64)}`,
    active_reviewers: reviewers.reviewers,
    revoked_controller_ids: [],
    revoked_reviewer_addresses: [],
  }, { reviewerGenesis: reviewers.genesis });
  const statusMessage = releaseReviewerAuthorityCurrentStatusSigningMessage(
    statusPayload,
    { reviewerGenesis: reviewers.genesis },
  );
  const guardianByAddress = new Map(reviewers.guardianAccounts.map((account) => [
    account.address.toLowerCase(),
    account,
  ]));
  const currentStatus = {
    ...statusPayload,
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
    signing_payload_sha256:
      releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
        statusPayload,
        { reviewerGenesis: reviewers.genesis },
      ),
    guardian_signatures: await Promise.all(
      reviewers.genesis.status_guardians.map(async (guardian) => ({
        ...guardian,
        signature: (await guardianByAddress.get(guardian.address)
          .signMessage({ message: statusMessage })).toLowerCase(),
      })),
    ),
  };
  const payload = createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
    reviewers.genesis,
    { reviewerCurrentStatus: currentStatus },
  );
  const message = releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
    payload,
    { reviewerGenesis: reviewers.genesis },
  );
  const accountByAddress = new Map(
    reviewers.identities.map((identity) => [identity.address, identity.account]),
  );
  const acceptances = [];
  for (const reviewer of reviewers.reviewers) {
    acceptances.push({
      ...reviewer,
      signature: await accountByAddress.get(reviewer.address).signMessage({ message }),
    });
  }
  const acceptance = {
    ...payload,
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
    signing_payload_sha256:
      releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
        payload,
        { reviewerGenesis: reviewers.genesis },
    ),
    acceptances,
  };
  return { acceptance, currentStatus };
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

function deploymentIntentFixture(genesis, genesisAcceptance) {
  const intent = createDraftDeploymentIntentCore();
  intent.release.releaseSha = "a".repeat(40);
  intent.release.reviewerAuthorityGenesisAcceptanceSha256 =
    releaseReviewerAuthorityGenesisAcceptanceSha256(
      genesisAcceptance,
      { reviewerGenesis: genesis },
    );
  intent.release.reviewerAuthorityCurrentStatusEpoch =
    genesisAcceptance.reviewer_authority_current_status.epoch;
  intent.release.reviewerAuthorityCurrentStatusSha256 =
    genesisAcceptance.reviewer_authority_current_status_sha256;
  intent.deploymentControl.controllerId = "deployment-operator-01";
  intent.deploymentControl.operatorAddress = address("1");
  intent.staticContractInputs.computeCreditVault.developer = address("2");
  intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment =
    `0x${bare("3")}`;
  intent.numericPolicy.contract = {
    computeDeveloperFeeBps: 100,
    emailOracleUpgradeDelaySeconds: 172_800,
    tinkerMaxAddBalanceWei: "5000000000000000000",
    tinkerMaxSpendWei: "2000000000000000000",
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
  return intent;
}

function bootstrapAuthority(deploymentIntentSha256) {
  return {
    schema: PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    release_sha: "a".repeat(40),
    deployment_intent_sha256: deploymentIntentSha256,
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

async function fixture(t) {
  const tempRoot = fs.realpathSync(fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "dnai-phala-bootstrap-cli-",
  )));
  fs.chmodSync(tempRoot, 0o700);
  t.after(() => fs.rmSync(tempRoot, { force: true, recursive: true }));
  const reviewers = reviewerFixture();
  const {
    acceptance: genesisAcceptance,
    currentStatus,
  } = await genesisAcceptanceFixture(reviewers);
  const deploymentIntent = deploymentIntentFixture(
    reviewers.genesis,
    genesisAcceptance,
    currentStatus,
  );
  const bootstrap = bootstrapAuthority(canonicalArtifactSha256(deploymentIntent));
  const deploymentIntentPath = path.join(tempRoot, "deployment-intent.json");
  const genesisPath = path.join(tempRoot, "reviewer-genesis.json");
  const genesisAcceptancePath = path.join(
    tempRoot,
    "reviewer-genesis-acceptance.json",
  );
  const bootstrapPath = path.join(tempRoot, "bootstrap-authority.json");
  fs.writeFileSync(
    deploymentIntentPath,
    canonicalArtifactText(deploymentIntent),
    { mode: 0o600 },
  );
  fs.writeFileSync(
    genesisPath,
    canonicalReleaseReviewerAuthorityGenesisArtifactText(reviewers.genesis),
    { mode: 0o600 },
  );
  fs.writeFileSync(
    genesisAcceptancePath,
    canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
      genesisAcceptance,
      { reviewerGenesis: reviewers.genesis },
    ),
    { mode: 0o600 },
  );
  fs.writeFileSync(
    bootstrapPath,
    canonicalBootstrapPublicEnvironmentAuthorityText(bootstrap),
    { mode: 0o600 },
  );
  for (const filePath of [
    deploymentIntentPath,
    genesisPath,
    genesisAcceptancePath,
    bootstrapPath,
  ]) {
    fs.chmodSync(filePath, 0o600);
  }
  return {
    tempRoot,
    reviewers,
    deploymentIntent,
    deploymentIntentPath: fs.realpathSync(deploymentIntentPath),
    genesisAcceptance,
    currentStatus,
    genesisAcceptancePath: fs.realpathSync(genesisAcceptancePath),
    genesisPath: fs.realpathSync(genesisPath),
    bootstrap,
    bootstrapPath: fs.realpathSync(bootstrapPath),
  };
}

function commonArgs(value, batchId = BATCH_ID) {
  return [
    "--bootstrap-authority", value.bootstrapPath,
    "--deployment-intent", value.deploymentIntentPath,
    "--reviewer-genesis", value.genesisPath,
    "--reviewer-genesis-acceptance", value.genesisAcceptancePath,
    "--batch-id", batchId,
    "--issued-at", ISSUED_AT,
    "--expires-at", EXPIRES_AT,
  ];
}

function runCli(args) {
  return spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: REPOSITORY_ROOT,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    maxBuffer: 2 * 1024 * 1024,
    timeout: 30_000,
  });
}

function parserArgs({
  command = "diagnose",
  issuedAt = "2024-02-29T23:59:59Z",
  expiresAt = "2024-03-01T00:00:00Z",
  now,
} = {}) {
  const args = [
    command,
    "--bootstrap-authority", "/tmp/bootstrap.json",
    "--deployment-intent", "/tmp/deployment-intent.json",
    "--reviewer-genesis", "/tmp/reviewer-genesis.json",
    "--reviewer-genesis-acceptance", "/tmp/reviewer-genesis-acceptance.json",
    "--batch-id", BATCH_ID,
    "--issued-at", issuedAt,
    "--expires-at", expiresAt,
  ];
  if (command === "create-new") {
    args.push(
      "--signatures", "/tmp/signatures.json",
      "--authorization-out", "/tmp/authorization.json",
      "--receipt-out", "/tmp/receipt.json",
    );
    if (now !== undefined) args.push("--now", now);
  }
  return args;
}

async function signatureEnvelope(value, diagnostic) {
  const signatures = [];
  for (const identity of value.reviewers.identities) {
    signatures.push({
      address: identity.address,
      controller_id: identity.controller_id,
      signature: await identity.account.signMessage({
        message: diagnostic.eip191.message,
      }),
    });
  }
  return {
    schema: PHALA_NONLIVE_BOOTSTRAP_EXTERNAL_SIGNATURES_SCHEMA,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signed_payload_sha256: diagnostic.eip191.signed_payload_sha256,
    signatures,
  };
}

test("schema is strict and the checked-in template is intentionally invalid", async (t) => {
  const value = await fixture(t);
  const schema = JSON.parse(fs.readFileSync(SCHEMA_PATH, "utf8"));
  const templateText = fs.readFileSync(TEMPLATE_PATH, "utf8");
  const template = JSON.parse(templateText);
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.schema.const, PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA);
  assert.equal(schema.properties.status.const, PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS);
  assert.equal(schema.properties.truth_status.const, PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH);
  assert.equal(schema.properties.chain_id.const, 84_532);
  assert.equal(schema.properties.signatures.minItems, 2);
  assert.equal(schema.properties.signatures.maxItems, 2);
  assert.equal(templateText, canonicalArtifactText(template));
  assert.equal(template.authorization_id, null);
  assert.equal(template.signatures.length, 0);
  assert.throws(() => canonicalPhalaNonLiveBootstrapAuthorizationText(
    template,
    { bootstrapAuthority: value.bootstrap },
  ));
});

test("CLI timestamp flags require real canonical calendar seconds", () => {
  assert.doesNotThrow(() => parsePhalaNonLiveBootstrapAuthorizationCliArgs(
    parserArgs(),
  ));
  assert.doesNotThrow(() => parsePhalaNonLiveBootstrapAuthorizationCliArgs(
    parserArgs({
      command: "create-new",
      now: "2024-03-01T00:00:00Z",
    }),
  ));
  for (const impossible of [
    "2026-02-29T23:59:59Z",
    "2026-02-30T23:59:59Z",
  ]) {
    assert.throws(
      () => parsePhalaNonLiveBootstrapAuthorizationCliArgs(
        parserArgs({ issuedAt: impossible }),
      ),
      /bootstrap issued_at must be a canonical UTC second/,
    );
    assert.throws(
      () => parsePhalaNonLiveBootstrapAuthorizationCliArgs(parserArgs({
        command: "create-new",
        now: impossible,
      })),
      /verification now must be a canonical UTC second/,
    );
  }
});

test("diagnose emits one canonical transitive signing payload without writes", async (t) => {
  const value = await fixture(t);
  const before = fs.readdirSync(value.tempRoot).sort();
  const result = runCli(["diagnose", ...commonArgs(value)]);
  assert.equal(result.status, 0, result.stderr);
  const diagnostic = JSON.parse(result.stdout);
  assert.equal(result.stdout, canonicalArtifactText(diagnostic));
  assert.equal(diagnostic.schema, PHALA_NONLIVE_BOOTSTRAP_SIGNING_DIAGNOSTIC_SCHEMA);
  assert.equal(diagnostic.batch_id, BATCH_ID);
  assert.equal(
    diagnostic.deployment_intent_sha256,
    canonicalArtifactSha256(value.deploymentIntent),
  );
  assert.equal(
    diagnostic.reviewer_authority_genesis_acceptance_sha256,
    value.deploymentIntent.release.reviewerAuthorityGenesisAcceptanceSha256,
  );
  assert.equal(
    diagnostic.reviewer_authority_genesis_sha256,
    value.genesisAcceptance.reviewer_authority_genesis_sha256,
  );
  assert.deepEqual(
    diagnostic.signing_payload.reviewers,
    value.currentStatus.active_reviewers,
  );
  assert.match(diagnostic.eip191.message, new RegExp(
    `${diagnostic.eip191.signed_payload_sha256}$`,
  ));
  assert.equal(diagnostic.operator_controls.private_or_raw_key_input_accepted, false);
  assert.equal(diagnostic.operator_controls.signer_subprocess_invoked, false);
  assert.equal(
    diagnostic.bootstrap_evidence.image_release_sigstore_verification_receipt_sha256,
    value.bootstrap.image_release_sigstore_verification_receipt_sha256,
  );
  assert.equal(diagnostic.production_mutation_ready, false);
  assert.deepEqual(
    diagnostic.blocker_codes,
    PHALA_NONLIVE_BOOTSTRAP_LOCAL_PUBLICATION_BLOCKER_CODES,
  );
  assert.equal(diagnostic.network_request_performed, false);
  assert.equal(diagnostic.phala_mutation_performed, false);
  assert.equal(diagnostic.live_traffic_authorized, false);
  assert.deepEqual(fs.readdirSync(value.tempRoot).sort(), before);
});

test("create-new accepts only external signatures and writes canonical verified files", async (t) => {
  const value = await fixture(t);
  const diagnosticResult = runCli(["diagnose", ...commonArgs(value)]);
  assert.equal(diagnosticResult.status, 0, diagnosticResult.stderr);
  const diagnostic = JSON.parse(diagnosticResult.stdout);
  const signatures = await signatureEnvelope(value, diagnostic);
  const signaturesPath = canonicalFile(
    path.join(value.tempRoot, "external-signatures.json"),
    signatures,
  );
  const authorizationPath = path.join(value.tempRoot, "authorization.json");
  const receiptPath = path.join(value.tempRoot, "authorization-receipt.json");
  const result = runCli([
    "create-new",
    ...commonArgs(value),
    "--signatures", signaturesPath,
    "--authorization-out", authorizationPath,
    "--receipt-out", receiptPath,
    "--now", NOW,
  ]);
  assert.equal(result.status, 0, result.stderr);
  const publication = JSON.parse(result.stdout);
  assert.equal(result.stdout, canonicalArtifactText(publication));
  assert.equal(publication.phala_mutation_performed, false);
  assert.equal(publication.network_request_performed, false);
  assert.equal(publication.production_mutation_ready, false);
  assert.deepEqual(
    publication.blocker_codes,
    PHALA_NONLIVE_BOOTSTRAP_LOCAL_PUBLICATION_BLOCKER_CODES,
  );
  assert.equal(publication.live_traffic_authorized, false);
  assert.equal(publication.late_secret_activation_authorized, false);
  assert.equal(publication.signer_subprocess_invoked, false);
  assert.equal(fs.statSync(authorizationPath).mode & 0o777, 0o600);
  assert.equal(fs.statSync(receiptPath).mode & 0o777, 0o600);
  const authorizationText = fs.readFileSync(authorizationPath, "utf8");
  const authorization = JSON.parse(authorizationText);
  assert.equal(
    authorizationText,
    canonicalPhalaNonLiveBootstrapAuthorizationText(authorization, {
      bootstrapAuthority: value.bootstrap,
    }),
  );
  const receiptText = fs.readFileSync(receiptPath, "utf8");
  const receipt = JSON.parse(receiptText);
  assert.equal(receiptText, canonicalArtifactText(receipt));
  assert.equal(receipt.live_traffic_authorized, false);
  assert.equal(receipt.late_secret_activation_authorized, false);
  assert.equal(receipt.production_mutation_ready, false);
  assert.deepEqual(
    receipt.blocker_codes,
    PHALA_NONLIVE_BOOTSTRAP_LOCAL_PUBLICATION_BLOCKER_CODES,
  );
  assert.equal(
    receipt.reviewer_authority_evidence
      .reviewer_genesis_acceptance_cryptographically_verified,
    true,
  );
  assert.equal(
    receipt.reviewer_authority_evidence.reviewer_genesis_independently_anchored,
    false,
  );
  assert.equal(receipt.authorization_receipt.live_traffic_authorized, false);
  assert.equal(Object.hasOwn(receipt.authorization_receipt, "signatures"), false);
  for (const entry of signatures.signatures) {
    assert.equal(result.stdout.includes(entry.signature), false);
    assert.equal(receiptText.includes(entry.signature), false);
  }
  const verified = readAndVerifyPhalaNonLiveBootstrapAuthorization({
    authorizationPath: fs.realpathSync(authorizationPath),
    bootstrapAuthorityPath: value.bootstrapPath,
    deploymentIntentPath: value.deploymentIntentPath,
    reviewerAuthorityGenesisPath: value.genesisPath,
    reviewerAuthorityGenesisAcceptancePath: value.genesisAcceptancePath,
    nowMs: Date.parse(NOW),
  });
  assert.equal(verified.receipt.authorization_id, publication.authorization_id);

  const retry = runCli([
    "create-new",
    ...commonArgs(value),
    "--signatures", signaturesPath,
    "--authorization-out", authorizationPath,
    "--receipt-out", receiptPath,
    "--now", NOW,
  ]);
  assert.equal(retry.status, 1);
  assert.match(retry.stderr, /create-new never replaces authority/);
});

test("raw-key, invalid-template, legacy, live, and cross-batch inputs fail closed", async (t) => {
  const value = await fixture(t);
  const rawSecret = `0x${"de".repeat(32)}`;
  const rawFlag = runCli([
    "diagnose",
    `--private-key=${rawSecret}`,
    ...commonArgs(value),
  ]);
  assert.equal(rawFlag.status, 1);
  assert.match(rawFlag.stderr, /forbidden signer or credential flag: --private-key/);
  assert.equal(rawFlag.stderr.includes(rawSecret), false);
  assert.throws(
    () => parsePhalaNonLiveBootstrapAuthorizationCliArgs([
      "diagnose", "--account", "dev", ...commonArgs(value),
    ]),
    /forbidden signer or credential flag: --account/,
  );

  const diagnosticResult = runCli(["diagnose", ...commonArgs(value)]);
  assert.equal(diagnosticResult.status, 0, diagnosticResult.stderr);
  const diagnostic = JSON.parse(diagnosticResult.stdout);
  const validEnvelope = await signatureEnvelope(value, diagnostic);
  const crossResult = runCli(["diagnose", ...commonArgs(value, sha("c"))]);
  assert.equal(crossResult.status, 0, crossResult.stderr);
  const crossDiagnostic = JSON.parse(crossResult.stdout);
  const cases = [
    {
      name: "template",
      path: TEMPLATE_PATH,
    },
    {
      name: "legacy",
      value: {
        ...validEnvelope,
        schema: "dnai.final-release-authority-core.v2",
      },
    },
    {
      name: "live",
      value: {
        ...validEnvelope,
        live_traffic_authorized: true,
      },
    },
    {
      name: "cross-batch",
      value: {
        ...validEnvelope,
        signed_payload_sha256:
          crossDiagnostic.eip191.signed_payload_sha256,
      },
    },
  ];
  for (const entry of cases) {
    const signaturesPath = entry.path ?? canonicalFile(
      path.join(value.tempRoot, `${entry.name}-signatures.json`),
      entry.value,
    );
    const authorizationPath = path.join(
      value.tempRoot,
      `${entry.name}-authorization.json`,
    );
    const receiptPath = path.join(value.tempRoot, `${entry.name}-receipt.json`);
    const result = runCli([
      "create-new",
      ...commonArgs(value),
      "--signatures", signaturesPath,
      "--authorization-out", authorizationPath,
      "--receipt-out", receiptPath,
      "--now", NOW,
    ]);
    assert.equal(result.status, 1, `${entry.name}: ${result.stdout}`);
    assert.equal(fs.existsSync(authorizationPath), false, entry.name);
    assert.equal(fs.existsSync(receiptPath), false, entry.name);
  }
});

test("CLI contains no signer, credential, network, or Phala mutation implementation", () => {
  const source = fs.readFileSync(CLI_PATH, "utf8");
  assert.doesNotMatch(source, /from\s+["']node:child_process["']/);
  assert.doesNotMatch(source, /from\s+["']node:(?:http|https|net|tls)["']/);
  assert.doesNotMatch(source, /\bfetch\s*\(/);
  assert.doesNotMatch(source, /\b(?:spawn|spawnSync|exec|execFile|fork)\s*\(/);
  assert.doesNotMatch(source, /\b(?:provisionCvm|commitCvmProvision|deployCvm)\s*\(/);
  assert.doesNotMatch(source, /\b(?:signMessage|signTypedData|signTransaction)\s*\(/);
  for (const forbidden of [
    "--private-key", "--raw-key", "--mnemonic", "--account", "--signer-command",
  ]) {
    assert.equal(source.includes(`"${forbidden}"`), true);
  }
});
