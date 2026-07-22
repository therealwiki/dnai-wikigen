import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
  bootstrapPublicEnvironmentAuthorityDigest,
  canonicalBootstrapPublicEnvironmentAuthorityText,
  normalizeBootstrapPublicEnvironmentAuthority,
} from "./phala-bootstrap-public-environment-authority-core.mjs";
import {
  PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_STATUS,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_TRUTH,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH,
  PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE,
  canonicalPhalaNonLiveBootstrapAuthorizationReceiptText,
  canonicalPhalaNonLiveBootstrapAuthorizationText,
  createPhalaNonLiveBootstrapSigningPayload,
  normalizePhalaNonLiveBootstrapAuthorizationReceipt,
  phalaNonLiveBootstrapAuthorizationId,
  phalaNonLiveBootstrapAuthorizationReceiptSha256,
  phalaNonLiveBootstrapSigningDigest,
  phalaNonLiveBootstrapSigningMessage,
  reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch,
} from "./phala-nonlive-bootstrap-authorization-core.mjs";
import {
  canonicalPhalaNonLiveBootstrapAuthorizationReceiptText as facadeReceiptText,
  canonicalPhalaNonLiveBootstrapAuthorizationText as facadeAuthorizationText,
  phalaNonLiveBootstrapAuthorizationReceiptSha256 as facadeReceiptSha256,
} from "./phala-nonlive-bootstrap-authorization.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  releaseAuthoritySignatureSha256,
  reviewerSetSha256,
} from "./release-authority-signature-verifier-core.mjs";

const accounts = [
  privateKeyToAccount(`0x${"11".repeat(32)}`),
  privateKeyToAccount(`0x${"22".repeat(32)}`),
].sort((left, right) => left.address.toLowerCase().localeCompare(
  right.address.toLowerCase(),
));
const sha = (digit) => `sha256:${String(digit).repeat(64)}`;
const bare = (digit) => String(digit).repeat(64);
const address = (digit) => `0x${String(digit).repeat(40)}`;

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
    return accounts.map((account) => account.address.toLowerCase()).sort().join(",");
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

test("bootstrap public authority rejects impossible UTC dates and accepts a real leap-day boundary", () => {
  for (const impossible of [
    "2025-02-29T10:00:00Z",
    "2026-04-31T10:00:00Z",
    "2024-02-29T23:59:60Z",
  ]) {
    const authority = bootstrapAuthority();
    authority.reviewed_at = impossible;
    assert.throws(
      () => normalizeBootstrapPublicEnvironmentAuthority(authority),
      /canonical UTC second/,
    );
  }

  const leapDay = bootstrapAuthority();
  leapDay.reviewed_at = "2024-02-29T23:59:59Z";
  leapDay.valid_until = "2024-03-01T00:00:00Z";
  const normalized = normalizeBootstrapPublicEnvironmentAuthority(leapDay);
  assert.equal(normalized.reviewed_at, "2024-02-29T23:59:59Z");
  assert.equal(normalized.valid_until, "2024-03-01T00:00:00Z");
});

async function fixture() {
  const bootstrap = bootstrapAuthority();
  const reviewers = accounts.map((account, index) => ({
    address: account.address.toLowerCase(),
    controller_id: `controller-${index === 0 ? "alpha" : "bravo"}`,
  }));
  const reviewerHashes = reviewers
    .map(({ address: reviewerAddress }) => executionPolicyReviewerHash(
      reviewerAddress,
    ))
    .sort();
  const reviewerAuthority = {
    approved_reviewers: reviewers,
    approved_reviewer_hashes: reviewerHashes,
    reviewer_root_hash: executionPolicyReviewerRootHash(reviewerHashes),
    reviewer_set_sha256: reviewerSetSha256(reviewers),
  };
  const bootstrapDigest = bootstrapPublicEnvironmentAuthorityDigest(bootstrap);
  const payload = createPhalaNonLiveBootstrapSigningPayload({
    schema: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA,
    status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS,
    truth_status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH,
    authorization_id: phalaNonLiveBootstrapAuthorizationId({
      releaseSha: bootstrap.release_sha,
      batchId: sha("b"),
      bootstrapPublicEnvironmentAuthoritySha256: bootstrapDigest,
    }),
    chain_id: 84_532,
    release_sha: bootstrap.release_sha,
    batch_id: sha("b"),
    bootstrap_public_environment_authority_sha256: bootstrapDigest,
    deployment_intent_sha256: bootstrap.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      bootstrap.fresh_contract_deployment_receipt_sha256,
    image_release_sigstore_verification_receipt_sha256:
      bootstrap.image_release_sigstore_verification_receipt_sha256,
    cvm_launch_intent_sha256: bootstrap.cvm_launch_intent_sha256,
    cvm_launch_review_receipt_sha256:
      bootstrap.cvm_launch_review_receipt_sha256,
    production_target_authority_sha256:
      bootstrap.production_target_authority_sha256,
    sdk_wire_transform_staging_receipt_sha256:
      bootstrap.sdk_wire_transform_staging_receipt_sha256,
    qvl_measurement_policy_set_sha256:
      bootstrap.qvl_measurement_policy_set_sha256,
    action_scope: [...PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE],
    forbidden_scope: [...PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE],
    issued_at: "2026-07-21T10:01:00Z",
    expires_at: "2026-07-21T10:10:00Z",
    reviewer_root_hash: reviewerAuthority.reviewer_root_hash,
    reviewer_set_sha256: reviewerAuthority.reviewer_set_sha256,
    reviewers,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
  }, { bootstrapAuthority: bootstrap });
  const signedPayloadSha256 = phalaNonLiveBootstrapSigningDigest(payload, {
    bootstrapAuthority: bootstrap,
  });
  const message = phalaNonLiveBootstrapSigningMessage(payload, {
    bootstrapAuthority: bootstrap,
  });
  const signatures = await Promise.all(accounts.map(async (account, index) => ({
    ...reviewers[index],
    signature: (await account.signMessage({ message })).toLowerCase(),
  })));
  const authorization = {
    ...payload,
    signed_payload_sha256: signedPayloadSha256,
    signatures,
  };
  const authorizationText = canonicalPhalaNonLiveBootstrapAuthorizationText(
    authorization,
    { bootstrapAuthority: bootstrap },
  );
  const bootstrapText = canonicalBootstrapPublicEnvironmentAuthorityText(bootstrap);
  const fileIdentity = (text) => ({
    sha256: `sha256:${createHash("sha256")
      .update(text, "utf8").digest("hex")}`,
    size: Buffer.byteLength(text, "utf8"),
  });
  const authorizationFileIdentity = fileIdentity(authorizationText);
  const bootstrapAuthorityFileIdentity = fileIdentity(bootstrapText);
  const receipt = normalizePhalaNonLiveBootstrapAuthorizationReceipt({
    schema: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
    status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_STATUS,
    truth_status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_TRUTH,
    authorization_id: payload.authorization_id,
    batch_id: payload.batch_id,
    release_sha: payload.release_sha,
    bootstrap_public_environment_authority_sha256: bootstrapDigest,
    image_release_manifest_sha256: bootstrap.image_release_manifest_sha256,
    topology_sha256: bootstrap.topology_sha256,
    descriptor_sha256_by_domain: Object.fromEntries(
      bootstrap.domains.map((entry) => [entry.domain, entry.descriptor_sha256]),
    ),
    deployment_intent_sha256: payload.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      payload.fresh_contract_deployment_receipt_sha256,
    image_release_sigstore_verification_receipt_sha256:
      payload.image_release_sigstore_verification_receipt_sha256,
    cvm_launch_intent_sha256: payload.cvm_launch_intent_sha256,
    cvm_launch_review_receipt_sha256: payload.cvm_launch_review_receipt_sha256,
    production_target_authority_sha256:
      payload.production_target_authority_sha256,
    sdk_wire_transform_staging_receipt_sha256:
      payload.sdk_wire_transform_staging_receipt_sha256,
    qvl_measurement_policy_set_sha256:
      payload.qvl_measurement_policy_set_sha256,
    action_scope: payload.action_scope,
    forbidden_scope: payload.forbidden_scope,
    signed_payload_sha256: signedPayloadSha256,
    authorization_artifact_file_sha256: authorizationFileIdentity.sha256,
    bootstrap_authority_artifact_file_sha256:
      bootstrapAuthorityFileIdentity.sha256,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
    reviewer_root_hash: reviewerAuthority.reviewer_root_hash,
    reviewer_set_sha256: reviewerAuthority.reviewer_set_sha256,
    signer_count: 2,
    signers: signatures.map((entry) => ({
      address: entry.address,
      controller_id: entry.controller_id,
      signature_sha256: releaseAuthoritySignatureSha256(entry.signature),
    })),
    issued_at: payload.issued_at,
    expires_at: payload.expires_at,
    live_traffic_authorized: false,
    late_secret_activation_authorized: false,
    mutation_performed: false,
  });
  return {
    authorization,
    authorizationFileIdentity,
    bootstrap,
    bootstrapAuthorityFileIdentity,
    payload,
    receipt,
    reviewerAuthority,
  };
}

test("pure signed-A bytes and receipt digest remain facade-compatible", async () => {
  const value = await fixture();
  assert.equal(
    canonicalPhalaNonLiveBootstrapAuthorizationText(value.authorization, {
      bootstrapAuthority: value.bootstrap,
    }),
    facadeAuthorizationText(value.authorization, {
      bootstrapAuthority: value.bootstrap,
    }),
  );
  assert.equal(
    canonicalPhalaNonLiveBootstrapAuthorizationReceiptText(value.receipt),
    facadeReceiptText(value.receipt),
  );
  assert.equal(
    phalaNonLiveBootstrapAuthorizationReceiptSha256(value.receipt),
    facadeReceiptSha256(value.receipt),
  );
});

test("historical signed-A replay verifies signatures without rerunning Cast", async () => {
  const value = await fixture();
  const originalDateNow = Date.now;
  Date.now = () => {
    throw new Error("current clock must not be consulted");
  };
  try {
    const result =
      reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch({
        authorization: value.authorization,
        bootstrapAuthority: value.bootstrap,
        reviewerAuthority: value.reviewerAuthority,
        persistedReceipt: value.receipt,
        launchCompletedAt:
          Math.floor(Date.parse("2026-07-21T10:05:00Z") / 1_000),
        authorizationFileIdentity: value.authorizationFileIdentity,
        bootstrapAuthorityFileIdentity: value.bootstrapAuthorityFileIdentity,
      });
    assert.equal(result.receipt_sha256,
      phalaNonLiveBootstrapAuthorizationReceiptSha256(value.receipt));
    assert.deepEqual(result.original_signature_verifier,
      PINNED_CAST_SIGNATURE_VERIFIER);
    assert.equal(result.independent_signature_replay_performed, true);
    assert.equal(result.original_signature_verifier_reexecuted, false);
    assert.equal(result.current_clock_consulted, false);
    assert.equal(result.production_brand_minted, false);
  } finally {
    Date.now = originalDateNow;
  }
});

test("historical signed-A replay rejects signer, file, and original-window drift", async () => {
  const value = await fixture();
  const forged = structuredClone(value.authorization);
  forged.signatures[0].signature = value.authorization.signatures[1].signature;
  for (const override of [
    { authorization: forged },
    {
      authorizationFileIdentity: {
        ...value.authorizationFileIdentity,
        sha256: sha("f"),
      },
    },
    {
      launchCompletedAt:
        Math.floor(Date.parse(value.authorization.expires_at) / 1_000),
    },
  ]) {
    assert.throws(() => (
      reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch({
        authorization: value.authorization,
        bootstrapAuthority: value.bootstrap,
        reviewerAuthority: value.reviewerAuthority,
        persistedReceipt: value.receipt,
        launchCompletedAt:
          Math.floor(Date.parse("2026-07-21T10:05:00Z") / 1_000),
        authorizationFileIdentity: value.authorizationFileIdentity,
        bootstrapAuthorityFileIdentity: value.bootstrapAuthorityFileIdentity,
        ...override,
      })
    ), /signature|file identities|original mutation window/i);
  }
});

test("signed-A core rejects accessors before execution and has no effectful edge", () => {
  let getterCalls = 0;
  const accessor = Object.defineProperty({}, "authorization", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return {};
    },
  });
  assert.throws(
    () => reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch(
      accessor,
    ),
    /canonical plain-data graph/i,
  );
  assert.equal(getterCalls, 0);
  const sources = [
    "phala-nonlive-bootstrap-authorization-core.mjs",
    "release-authority-signature-verifier-core.mjs",
  ].map((basename) => readFileSync(
    new URL(`./${basename}`, import.meta.url),
    "utf8",
  )).join("\n");
  for (const forbidden of [
    "node:fs",
    "node:path",
    "node:os",
    "node:child_process",
    "Date.now",
    "process.",
    "WeakMap",
    "WeakSet",
    "Symbol(",
    "import(",
  ]) assert.equal(sources.includes(forbidden), false, forbidden);
});

test("signed-A historical replay rejects a sequential-get Proxy before any trap runs", async () => {
  const value = await fixture();
  let issuedAtReads = 0;
  const authorization = new Proxy(value.authorization, {
    get(target, key, receiver) {
      if (key === "issued_at") {
        issuedAtReads += 1;
        return issuedAtReads === 1
          ? Reflect.get(target, key, receiver)
          : "2025-02-29T10:01:00Z";
      }
      return Reflect.get(target, key, receiver);
    },
  });
  assert.throws(
    () => reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch({
      authorization,
      bootstrapAuthority: value.bootstrap,
      reviewerAuthority: value.reviewerAuthority,
      persistedReceipt: value.receipt,
      launchCompletedAt:
        Math.floor(Date.parse("2026-07-21T10:05:00Z") / 1_000),
      authorizationFileIdentity: value.authorizationFileIdentity,
      bootstrapAuthorityFileIdentity: value.bootstrapAuthorityFileIdentity,
    }),
    /canonical plain-data graph: Proxy objects are forbidden/,
  );
  assert.equal(issuedAtReads, 0);
});
