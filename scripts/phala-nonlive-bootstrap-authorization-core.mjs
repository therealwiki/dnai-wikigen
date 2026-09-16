import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  CVM_LAUNCH_DOMAINS,
} from "./cvm-launch-intent-core.mjs";
import {
  bootstrapPublicEnvironmentAuthorityDigest,
  canonicalBootstrapPublicEnvironmentAuthorityText,
  normalizeBootstrapPublicEnvironmentAuthority,
} from "./phala-bootstrap-public-environment-authority-core.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  INDEPENDENT_EIP191_REPLAY_VERIFIER,
  canonicalLowSEip191Signature,
  eip191AuthorizationSigningDigest,
  eip191AuthorizationSigningMessage,
  normalizeExpectedReviewerAuthority,
  normalizeReviewerAuthorizationSignatures,
  verifyIndependentEip191PersonalSignature,
} from "./release-authority-signature-verifier-core.mjs";

export const PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA =
  "dnai.phala-nonlive-bootstrap-authorization.v3";
export const PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA =
  "dnai.phala-nonlive-bootstrap-authorization-receipt.v4";
export const PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_DOMAIN =
  "dnai-wikigen/phala-nonlive-bootstrap-authorization-receipt/v4\0";
export const PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_STATUS =
  "non_live_bootstrap_signatures_verified";
export const PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_TRUTH =
  "two_transitively_allowlisted_signatures_verified_and_exact_signed_dependencies_bound_not_phala_mutation_commit_tdx_or_live_authority";
export const PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS =
  "non_live_bootstrap_authorized";
export const PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH =
  "two_transitively_allowlisted_eip191_signatures_authorize_one_non_live_seven_cvm_bootstrap_batch_not_late_secrets_governance_live_traffic_or_cloudflare";
export const PHALA_NONLIVE_BOOTSTRAP_SIGNING_DOMAIN =
  "dnai-wikigen/phala-nonlive-bootstrap-authorization/v3\0";
export const PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_ID_DOMAIN =
  "dnai-wikigen/phala-nonlive-bootstrap-authorization-id/v3\0";
export const PHALA_NONLIVE_BOOTSTRAP_SIGNING_MESSAGE_PREFIX =
  "dnai-wikigen phala non-live bootstrap authorization v3:";
export const PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE = Object.freeze([
  "phala.nextAppIds.predict_exact_seven",
  "phala.provisionCvm.prepare_exact_seven_supporting_then_main",
  "phala.commitCvmProvision.bootstrap_exact_seven_supporting_then_main",
]);
export const PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE = Object.freeze([
  "post_measurement_secret_activation",
  "governance_release_ceremony",
  "live_traffic",
  "cloudflare_deploy",
]);
export const PHALA_NONLIVE_BOOTSTRAP_MAX_LIFETIME_MS = 60 * 60 * 1_000;
export const PHALA_NONLIVE_BOOTSTRAP_MAX_FUTURE_SKEW_MS = 5 * 60 * 1_000;
export const PHALA_NONLIVE_BOOTSTRAP_RECHECK_CHECKPOINTS = Object.freeze([
  "before_prediction",
  "before_each_prepare",
  "before_each_provision",
  "before_each_commit",
]);
export const PHALA_PERSISTED_NONLIVE_BOOTSTRAP_HISTORICAL_RECONSTRUCTION_SCHEMA =
  "dnai.phala-persisted-nonlive-bootstrap-historical-reconstruction.v1";
export const PHALA_PERSISTED_NONLIVE_BOOTSTRAP_HISTORICAL_RECONSTRUCTION_TRUTH =
  "persisted_signed_a_signatures_independently_replayed_at_original_l_completion_original_cast_metadata_preserved_without_reexecution_current_freshness_brand_or_live_authority";

const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MAX_AUTHORIZATION_BYTES = 256 * 1024;
const SIGNING_PAYLOAD_FIELDS = Object.freeze([
  "schema",
  "status",
  "truth_status",
  "authorization_id",
  "chain_id",
  "release_sha",
  "batch_id",
  "bootstrap_public_environment_authority_sha256",
  "deployment_intent_sha256",
  "fresh_contract_deployment_receipt_sha256",
  "image_release_sigstore_verification_receipt_sha256",
  "cvm_launch_intent_sha256",
  "cvm_launch_review_receipt_sha256",
  "production_target_authority_sha256",
  "sdk_wire_transform_staging_receipt_sha256",
  "qvl_measurement_policy_set_sha256",
  "action_scope",
  "forbidden_scope",
  "issued_at",
  "expires_at",
  "reviewer_root_hash",
  "reviewer_set_sha256",
  "reviewers",
  "signature_scheme",
  "signature_verifier",
]);
const AUTHORIZATION_FIELDS = Object.freeze([
  ...SIGNING_PAYLOAD_FIELDS,
  "signed_payload_sha256",
  "signatures",
]);
const AUTHORIZATION_RECEIPT_FIELDS = Object.freeze([
  "schema",
  "status",
  "truth_status",
  "authorization_id",
  "batch_id",
  "release_sha",
  "bootstrap_public_environment_authority_sha256",
  "image_release_manifest_sha256",
  "topology_sha256",
  "descriptor_sha256_by_domain",
  "deployment_intent_sha256",
  "fresh_contract_deployment_receipt_sha256",
  "image_release_sigstore_verification_receipt_sha256",
  "cvm_launch_intent_sha256",
  "cvm_launch_review_receipt_sha256",
  "production_target_authority_sha256",
  "sdk_wire_transform_staging_receipt_sha256",
  "qvl_measurement_policy_set_sha256",
  "action_scope",
  "forbidden_scope",
  "signed_payload_sha256",
  "authorization_artifact_file_sha256",
  "bootstrap_authority_artifact_file_sha256",
  "signature_scheme",
  "signature_verifier",
  "reviewer_root_hash",
  "reviewer_set_sha256",
  "signer_count",
  "signers",
  "issued_at",
  "expires_at",
  "live_traffic_authorized",
  "late_secret_activation_authorized",
  "mutation_performed",
]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...keys].sort())) {
    throw new TypeError(`${label} must contain exactly the reviewed fields`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactReleaseSha(value, label) {
  if (typeof value !== "string" || !SHA40.test(value)) {
    throw new TypeError(
      `${label} must be a nonzero lowercase 40-hex release SHA`,
    );
  }
  return value;
}

function canonicalTimestamp(value, label) {
  if (typeof value !== "string" || !ISO_SECOND.test(value)) {
    throw new TypeError(`${label} must be a canonical UTC second`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)
    || new Date(parsed).toISOString().replace(".000Z", "Z") !== value) {
    throw new TypeError(`${label} must round-trip as a canonical UTC second`);
  }
  return value;
}

function exactStringArray(value, expected, label) {
  if (!Array.isArray(value)
    || JSON.stringify(value) !== JSON.stringify(expected)) {
    throw new TypeError(`${label} must equal the exact ordered authorization scope`);
  }
  return [...expected];
}

function exactDescriptorSha256ByDomain(value, label) {
  const parsed = exactRecord(value, CVM_LAUNCH_DOMAINS, label);
  return Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => [
    domain,
    exactSha256(parsed[domain], `${label} ${domain}`),
  ]));
}

function canonicalSignatureVerifier(value) {
  const parsed = exactRecord(value, [
    "build_profile",
    "commit_sha",
    "executable_sha256",
    "executable_user_relative_path",
    "tool",
    "version",
  ], "bootstrap signature verifier");
  if (JSON.stringify(parsed) !== JSON.stringify(PINNED_CAST_SIGNATURE_VERIFIER)) {
    throw new TypeError(
      "bootstrap signature verifier is not the deployment-intent toolchain",
    );
  }
  return { ...PINNED_CAST_SIGNATURE_VERIFIER };
}

function normalizeReviewerIdentities(value) {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new TypeError("bootstrap authorization requires two reviewer identities");
  }
  const reviewers = value.map((raw, index) => {
    const entry = exactRecord(raw, [
      "address",
      "controller_id",
    ], `bootstrap reviewer[${index}]`);
    if (typeof entry.address !== "string"
      || !/^0x(?!0{40}$)[0-9a-f]{40}$/.test(entry.address)
      || typeof entry.controller_id !== "string"
      || !/^[a-z0-9][a-z0-9._-]{7,63}$/.test(entry.controller_id)) {
      throw new TypeError(`bootstrap reviewer[${index}] identity is invalid`);
    }
    return { ...entry };
  });
  if (reviewers[0].address >= reviewers[1].address
    || reviewers[0].controller_id === reviewers[1].controller_id) {
    throw new TypeError(
      "bootstrap reviewers must use distinct sorted addresses and controllers",
    );
  }
  return reviewers;
}

function normalizeSignatures(value, reviewers) {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new TypeError("bootstrap authorization requires exactly two signatures");
  }
  return value.map((raw, index) => {
    const entry = exactRecord(raw, [
      "address",
      "controller_id",
      "signature",
    ], `bootstrap signature[${index}]`);
    if (entry.address !== reviewers[index].address
      || entry.controller_id !== reviewers[index].controller_id) {
      throw new TypeError(
        "bootstrap signature identities do not match the signed payload",
      );
    }
    return {
      address: entry.address,
      controller_id: entry.controller_id,
      signature: canonicalLowSEip191Signature(
        entry.signature,
        `bootstrap signature[${index}]`,
      ),
    };
  });
}

export function phalaNonLiveBootstrapAuthorizationId(input = {}) {
  assertCanonicalPlainDataGraph(input, {
    label: "non-live bootstrap authorization ID input",
  });
  const parsed = exactRecord(input, [
    "releaseSha",
    "batchId",
    "bootstrapPublicEnvironmentAuthoritySha256",
  ], "non-live bootstrap authorization ID input");
  const payload = {
    release_sha: exactReleaseSha(
      parsed.releaseSha,
      "authorization release_sha",
    ),
    batch_id: exactSha256(parsed.batchId, "authorization batch_id"),
    bootstrap_public_environment_authority_sha256: exactSha256(
      parsed.bootstrapPublicEnvironmentAuthoritySha256,
      "bootstrap public environment authority digest",
    ),
  };
  return `sha256:${createHash("sha256")
    .update(PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_ID_DOMAIN, "utf8")
    .update(JSON.stringify(sorted(payload)), "utf8")
    .digest("hex")}`;
}

export function createPhalaNonLiveBootstrapSigningPayload(value, options = {}) {
  assertCanonicalPlainDataGraph({ value, options }, {
    label: "non-live bootstrap signing payload input",
  });
  const { bootstrapAuthority } = exactRecord(
    options,
    ["bootstrapAuthority"],
    "non-live bootstrap signing payload options",
  );
  const bootstrap = normalizeBootstrapPublicEnvironmentAuthority(
    bootstrapAuthority,
  );
  const parsed = exactRecord(
    value,
    SIGNING_PAYLOAD_FIELDS,
    "non-live bootstrap signing payload",
  );
  if (parsed.schema !== PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA
    || parsed.status !== PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS
    || parsed.truth_status !== PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH
    || parsed.chain_id !== 84_532
    || parsed.release_sha !== bootstrap.release_sha
    || parsed.deployment_intent_sha256 !== bootstrap.deployment_intent_sha256
    || parsed.fresh_contract_deployment_receipt_sha256
      !== bootstrap.fresh_contract_deployment_receipt_sha256
    || parsed.image_release_sigstore_verification_receipt_sha256
      !== bootstrap.image_release_sigstore_verification_receipt_sha256
    || parsed.cvm_launch_intent_sha256 !== bootstrap.cvm_launch_intent_sha256
    || parsed.cvm_launch_review_receipt_sha256
      !== bootstrap.cvm_launch_review_receipt_sha256
    || parsed.production_target_authority_sha256
      !== bootstrap.production_target_authority_sha256
    || parsed.sdk_wire_transform_staging_receipt_sha256
      !== bootstrap.sdk_wire_transform_staging_receipt_sha256
    || parsed.qvl_measurement_policy_set_sha256
      !== bootstrap.qvl_measurement_policy_set_sha256
    || parsed.signature_scheme !== PINNED_EIP191_SIGNATURE_SCHEME) {
    throw new TypeError(
      "non-live bootstrap signing payload dependency binding is invalid",
    );
  }
  const bootstrapDigest = bootstrapPublicEnvironmentAuthorityDigest(bootstrap);
  if (parsed.bootstrap_public_environment_authority_sha256 !== bootstrapDigest) {
    throw new TypeError(
      "non-live bootstrap signing payload does not bind public values",
    );
  }
  const batchId = exactSha256(parsed.batch_id, "bootstrap batch_id");
  const authorizationId = phalaNonLiveBootstrapAuthorizationId({
    releaseSha: bootstrap.release_sha,
    batchId,
    bootstrapPublicEnvironmentAuthoritySha256: bootstrapDigest,
  });
  if (parsed.authorization_id !== authorizationId) {
    throw new TypeError(
      "non-live bootstrap authorization_id is not deterministically derived",
    );
  }
  const issuedAt = canonicalTimestamp(parsed.issued_at, "bootstrap issued_at");
  const expiresAt = canonicalTimestamp(parsed.expires_at, "bootstrap expires_at");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)
    || Date.parse(expiresAt) - Date.parse(issuedAt)
      > PHALA_NONLIVE_BOOTSTRAP_MAX_LIFETIME_MS
    || Date.parse(issuedAt) < Date.parse(bootstrap.reviewed_at)
    || Date.parse(expiresAt) > Date.parse(bootstrap.valid_until)) {
    throw new TypeError(
      "non-live bootstrap authorization lifetime is invalid or outlives its subject",
    );
  }
  if (typeof parsed.reviewer_root_hash !== "string"
    || !BARE_SHA256.test(parsed.reviewer_root_hash)) {
    throw new TypeError("non-live bootstrap reviewer root is invalid");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_SCHEMA,
    status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_STATUS,
    truth_status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_TRUTH,
    authorization_id: authorizationId,
    chain_id: 84_532,
    release_sha: bootstrap.release_sha,
    batch_id: batchId,
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
    action_scope: exactStringArray(
      parsed.action_scope,
      PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE,
      "bootstrap action_scope",
    ),
    forbidden_scope: exactStringArray(
      parsed.forbidden_scope,
      PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE,
      "bootstrap forbidden_scope",
    ),
    issued_at: issuedAt,
    expires_at: expiresAt,
    reviewer_root_hash: parsed.reviewer_root_hash,
    reviewer_set_sha256: exactSha256(
      parsed.reviewer_set_sha256,
      "bootstrap reviewer_set_sha256",
    ),
    reviewers: normalizeReviewerIdentities(parsed.reviewers),
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: canonicalSignatureVerifier(parsed.signature_verifier),
  }, { label: "non-live bootstrap signing payload" });
}

export function phalaNonLiveBootstrapSigningDigest(value, options) {
  return eip191AuthorizationSigningDigest({
    domain: PHALA_NONLIVE_BOOTSTRAP_SIGNING_DOMAIN,
    payload: createPhalaNonLiveBootstrapSigningPayload(value, options),
  });
}

export function phalaNonLiveBootstrapSigningMessage(value, options) {
  return eip191AuthorizationSigningMessage({
    prefix: PHALA_NONLIVE_BOOTSTRAP_SIGNING_MESSAGE_PREFIX,
    digest: phalaNonLiveBootstrapSigningDigest(value, options),
  });
}

export function normalizePhalaNonLiveBootstrapAuthorization(value, options) {
  assertCanonicalPlainDataGraph(value, {
    label: "non-live bootstrap authorization input",
  });
  const parsed = exactRecord(
    value,
    AUTHORIZATION_FIELDS,
    "non-live bootstrap authorization",
  );
  const payload = createPhalaNonLiveBootstrapSigningPayload(
    Object.fromEntries(SIGNING_PAYLOAD_FIELDS.map((key) => [key, parsed[key]])),
    options,
  );
  const signatures = normalizeSignatures(parsed.signatures, payload.reviewers);
  const signedPayloadSha256 = phalaNonLiveBootstrapSigningDigest(
    payload,
    options,
  );
  if (parsed.signed_payload_sha256 !== signedPayloadSha256) {
    throw new TypeError("non-live bootstrap signed payload digest is invalid");
  }
  return deepFreezeCanonicalPlainDataGraph({
    ...payload,
    signed_payload_sha256: signedPayloadSha256,
    signatures,
  }, { label: "normalized non-live bootstrap authorization" });
}

export function canonicalPhalaNonLiveBootstrapAuthorizationText(value, options) {
  return canonicalText(normalizePhalaNonLiveBootstrapAuthorization(value, options));
}

function normalizeAuthorizationReceiptSigners(value) {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new TypeError(
      "bootstrap authorization receipt requires exactly two signer results",
    );
  }
  const signers = value.map((raw, index) => {
    const entry = exactRecord(raw, [
      "address",
      "controller_id",
      "signature_sha256",
    ], `bootstrap authorization receipt signer[${index}]`);
    if (typeof entry.address !== "string"
      || !/^0x(?!0{40}$)[0-9a-f]{40}$/.test(entry.address)
      || typeof entry.controller_id !== "string"
      || !/^[a-z0-9][a-z0-9._-]{7,63}$/.test(entry.controller_id)) {
      throw new TypeError(
        `bootstrap authorization receipt signer[${index}] identity is invalid`,
      );
    }
    return {
      address: entry.address,
      controller_id: entry.controller_id,
      signature_sha256: exactSha256(
        entry.signature_sha256,
        `bootstrap authorization receipt signer[${index}] signature digest`,
      ),
    };
  });
  if (signers[0].address >= signers[1].address
    || signers[0].controller_id === signers[1].controller_id) {
    throw new TypeError(
      "bootstrap authorization receipt signers must be sorted and independent",
    );
  }
  return signers;
}

export function normalizePhalaNonLiveBootstrapAuthorizationReceipt(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "non-live bootstrap authorization receipt",
  });
  const parsed = exactRecord(
    value,
    AUTHORIZATION_RECEIPT_FIELDS,
    "non-live bootstrap authorization receipt",
  );
  if (parsed.schema !== PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA
    || parsed.status !== PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_STATUS
    || parsed.truth_status !== PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_TRUTH
    || parsed.signature_scheme !== PINNED_EIP191_SIGNATURE_SCHEME
    || parsed.signer_count !== 2
    || parsed.live_traffic_authorized !== false
    || parsed.late_secret_activation_authorized !== false
    || parsed.mutation_performed !== false) {
    throw new TypeError(
      "non-live bootstrap authorization receipt posture is invalid",
    );
  }
  const issuedAt = canonicalTimestamp(
    parsed.issued_at,
    "bootstrap authorization receipt issued_at",
  );
  const expiresAt = canonicalTimestamp(
    parsed.expires_at,
    "bootstrap authorization receipt expires_at",
  );
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)
    || Date.parse(expiresAt) - Date.parse(issuedAt)
      > PHALA_NONLIVE_BOOTSTRAP_MAX_LIFETIME_MS) {
    throw new TypeError(
      "non-live bootstrap authorization receipt lifetime is invalid",
    );
  }
  if (typeof parsed.reviewer_root_hash !== "string"
    || !BARE_SHA256.test(parsed.reviewer_root_hash)) {
    throw new TypeError(
      "non-live bootstrap authorization receipt reviewer root is invalid",
    );
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
    status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_STATUS,
    truth_status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_TRUTH,
    authorization_id: exactSha256(
      parsed.authorization_id,
      "receipt authorization_id",
    ),
    batch_id: exactSha256(parsed.batch_id, "receipt batch_id"),
    release_sha: exactReleaseSha(parsed.release_sha, "receipt release_sha"),
    bootstrap_public_environment_authority_sha256: exactSha256(
      parsed.bootstrap_public_environment_authority_sha256,
      "receipt bootstrap public authority digest",
    ),
    image_release_manifest_sha256: exactSha256(
      parsed.image_release_manifest_sha256,
      "receipt signed bootstrap image release manifest digest",
    ),
    topology_sha256: exactSha256(
      parsed.topology_sha256,
      "receipt signed bootstrap topology digest",
    ),
    descriptor_sha256_by_domain: exactDescriptorSha256ByDomain(
      parsed.descriptor_sha256_by_domain,
      "receipt signed bootstrap descriptor digests",
    ),
    deployment_intent_sha256: exactSha256(
      parsed.deployment_intent_sha256,
      "receipt deployment intent digest",
    ),
    fresh_contract_deployment_receipt_sha256: exactSha256(
      parsed.fresh_contract_deployment_receipt_sha256,
      "receipt fresh contract deployment digest",
    ),
    image_release_sigstore_verification_receipt_sha256: exactSha256(
      parsed.image_release_sigstore_verification_receipt_sha256,
      "receipt image release Sigstore verification digest",
    ),
    cvm_launch_intent_sha256: exactSha256(
      parsed.cvm_launch_intent_sha256,
      "receipt CVM launch intent digest",
    ),
    cvm_launch_review_receipt_sha256: exactSha256(
      parsed.cvm_launch_review_receipt_sha256,
      "receipt CVM launch review digest",
    ),
    production_target_authority_sha256: exactSha256(
      parsed.production_target_authority_sha256,
      "receipt production target authority digest",
    ),
    sdk_wire_transform_staging_receipt_sha256: exactSha256(
      parsed.sdk_wire_transform_staging_receipt_sha256,
      "receipt SDK wire-transform staging digest",
    ),
    qvl_measurement_policy_set_sha256: exactSha256(
      parsed.qvl_measurement_policy_set_sha256,
      "receipt QVL measurement policy-set digest",
    ),
    action_scope: exactStringArray(
      parsed.action_scope,
      PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE,
      "receipt action_scope",
    ),
    forbidden_scope: exactStringArray(
      parsed.forbidden_scope,
      PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE,
      "receipt forbidden_scope",
    ),
    signed_payload_sha256: exactSha256(
      parsed.signed_payload_sha256,
      "receipt signed payload digest",
    ),
    authorization_artifact_file_sha256: exactSha256(
      parsed.authorization_artifact_file_sha256,
      "receipt authorization artifact file digest",
    ),
    bootstrap_authority_artifact_file_sha256: exactSha256(
      parsed.bootstrap_authority_artifact_file_sha256,
      "receipt bootstrap authority artifact file digest",
    ),
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: canonicalSignatureVerifier(parsed.signature_verifier),
    reviewer_root_hash: parsed.reviewer_root_hash,
    reviewer_set_sha256: exactSha256(
      parsed.reviewer_set_sha256,
      "receipt reviewer set digest",
    ),
    signer_count: 2,
    signers: normalizeAuthorizationReceiptSigners(parsed.signers),
    issued_at: issuedAt,
    expires_at: expiresAt,
    live_traffic_authorized: false,
    late_secret_activation_authorized: false,
    mutation_performed: false,
  }, { label: "normalized non-live bootstrap authorization receipt" });
}

export function canonicalPhalaNonLiveBootstrapAuthorizationReceiptText(value) {
  return canonicalText(normalizePhalaNonLiveBootstrapAuthorizationReceipt(value));
}

export function phalaNonLiveBootstrapAuthorizationReceiptSha256(value) {
  return `sha256:${createHash("sha256")
    .update(PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_DOMAIN, "utf8")
    .update(canonicalPhalaNonLiveBootstrapAuthorizationReceiptText(value), "utf8")
    .digest("hex")}`;
}

function normalizeFileIdentity(value, label) {
  const parsed = exactRecord(value, ["sha256", "size"], label);
  if (!Number.isSafeInteger(parsed.size) || parsed.size < 2
    || parsed.size > MAX_AUTHORIZATION_BYTES) {
    throw new TypeError(`${label} size must be a bounded positive integer`);
  }
  return {
    sha256: exactSha256(parsed.sha256, `${label} SHA-256`),
    size: parsed.size,
  };
}

/**
 * Independently replay persisted signed A using static JavaScript EIP-191
 * recovery and L's original completion second. Original pinned-Cast metadata
 * remains in the reconstructed receipt, but this function does not claim to
 * re-execute that historical verifier or renew current authority.
 */
export function reconstructPersistedPhalaNonLiveBootstrapAuthorizationForHistoricalLaunch(
  input = {},
) {
  assertCanonicalPlainDataGraph(input, {
    label: "persisted signed-A historical reconstruction input",
  });
  const parsed = exactRecord(input, [
    "authorization",
    "bootstrapAuthority",
    "reviewerAuthority",
    "persistedReceipt",
    "launchCompletedAt",
    "authorizationFileIdentity",
    "bootstrapAuthorityFileIdentity",
  ], "persisted signed-A historical reconstruction input");
  const bootstrap = normalizeBootstrapPublicEnvironmentAuthority(
    parsed.bootstrapAuthority,
  );
  const authorization = normalizePhalaNonLiveBootstrapAuthorization(
    parsed.authorization,
    { bootstrapAuthority: bootstrap },
  );
  const launchCompletedAt = parsed.launchCompletedAt;
  const issuedAtMs = Date.parse(authorization.issued_at);
  const expiresAtMs = Date.parse(authorization.expires_at);
  if (!Number.isSafeInteger(launchCompletedAt)
    || launchCompletedAt < 1 || launchCompletedAt > 4_102_444_800
    || launchCompletedAt * 1_000 < issuedAtMs
    || launchCompletedAt * 1_000 >= expiresAtMs) {
    throw new TypeError(
      "persisted launch completion is outside signed A's original mutation window",
    );
  }
  const reviewerAuthority = normalizeExpectedReviewerAuthority(
    parsed.reviewerAuthority,
    {
      expectedReviewerRootHash: authorization.reviewer_root_hash,
      expectedReviewerSetSha256: authorization.reviewer_set_sha256,
    },
  );
  const signatureStructure = normalizeReviewerAuthorizationSignatures({
    signatures: authorization.signatures,
    reviewerAuthority,
    expectedReviewerRootHash: authorization.reviewer_root_hash,
    expectedReviewerSetSha256: authorization.reviewer_set_sha256,
    expectedSignerCount: 2,
    requireEveryReviewer: false,
  });
  const message = phalaNonLiveBootstrapSigningMessage(
    Object.fromEntries(SIGNING_PAYLOAD_FIELDS.map((field) => [
      field,
      authorization[field],
    ])),
    { bootstrapAuthority: bootstrap },
  );
  const signers = signatureStructure.signatures.map((entry) => {
    const verified = verifyIndependentEip191PersonalSignature({
      address: entry.address,
      message,
      signature: entry.signature,
    });
    return {
      address: entry.address,
      controller_id: entry.controller_id,
      signature_sha256: verified.signature_sha256,
    };
  });

  const authorizationBytes = Buffer.from(
    canonicalPhalaNonLiveBootstrapAuthorizationText(authorization, {
      bootstrapAuthority: bootstrap,
    }),
    "utf8",
  );
  const bootstrapBytes = Buffer.from(
    canonicalBootstrapPublicEnvironmentAuthorityText(bootstrap),
    "utf8",
  );
  const authorizationFileIdentity = normalizeFileIdentity(
    parsed.authorizationFileIdentity,
    "authorization artifact file identity",
  );
  const bootstrapAuthorityFileIdentity = normalizeFileIdentity(
    parsed.bootstrapAuthorityFileIdentity,
    "bootstrap authority artifact file identity",
  );
  if (authorizationFileIdentity.sha256 !== sha256Bytes(authorizationBytes)
    || authorizationFileIdentity.size !== authorizationBytes.length
    || bootstrapAuthorityFileIdentity.sha256 !== sha256Bytes(bootstrapBytes)
    || bootstrapAuthorityFileIdentity.size !== bootstrapBytes.length) {
    throw new TypeError(
      "exact input file identities differ from canonical signed-A bytes",
    );
  }

  const receipt = normalizePhalaNonLiveBootstrapAuthorizationReceipt({
    schema: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
    status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_STATUS,
    truth_status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_TRUTH,
    authorization_id: authorization.authorization_id,
    batch_id: authorization.batch_id,
    release_sha: authorization.release_sha,
    bootstrap_public_environment_authority_sha256:
      authorization.bootstrap_public_environment_authority_sha256,
    image_release_manifest_sha256: bootstrap.image_release_manifest_sha256,
    topology_sha256: bootstrap.topology_sha256,
    descriptor_sha256_by_domain: Object.fromEntries(
      bootstrap.domains.map((entry) => [entry.domain, entry.descriptor_sha256]),
    ),
    deployment_intent_sha256: authorization.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      authorization.fresh_contract_deployment_receipt_sha256,
    image_release_sigstore_verification_receipt_sha256:
      authorization.image_release_sigstore_verification_receipt_sha256,
    cvm_launch_intent_sha256: authorization.cvm_launch_intent_sha256,
    cvm_launch_review_receipt_sha256:
      authorization.cvm_launch_review_receipt_sha256,
    production_target_authority_sha256:
      authorization.production_target_authority_sha256,
    sdk_wire_transform_staging_receipt_sha256:
      authorization.sdk_wire_transform_staging_receipt_sha256,
    qvl_measurement_policy_set_sha256:
      authorization.qvl_measurement_policy_set_sha256,
    action_scope: authorization.action_scope,
    forbidden_scope: authorization.forbidden_scope,
    signed_payload_sha256: authorization.signed_payload_sha256,
    authorization_artifact_file_sha256: authorizationFileIdentity.sha256,
    bootstrap_authority_artifact_file_sha256:
      bootstrapAuthorityFileIdentity.sha256,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
    reviewer_root_hash: authorization.reviewer_root_hash,
    reviewer_set_sha256: authorization.reviewer_set_sha256,
    signer_count: 2,
    signers,
    issued_at: authorization.issued_at,
    expires_at: authorization.expires_at,
    live_traffic_authorized: false,
    late_secret_activation_authorized: false,
    mutation_performed: false,
  });
  const persisted = normalizePhalaNonLiveBootstrapAuthorizationReceipt(
    parsed.persistedReceipt,
  );
  if (canonicalPhalaNonLiveBootstrapAuthorizationReceiptText(persisted)
      !== canonicalPhalaNonLiveBootstrapAuthorizationReceiptText(receipt)) {
    throw new TypeError(
      "persisted signed-A receipt differs from independent signature reconstruction",
    );
  }
  const receiptSha256 = phalaNonLiveBootstrapAuthorizationReceiptSha256(receipt);
  return deepFreezeCanonicalPlainDataGraph({
    schema:
      PHALA_PERSISTED_NONLIVE_BOOTSTRAP_HISTORICAL_RECONSTRUCTION_SCHEMA,
    truth_status:
      PHALA_PERSISTED_NONLIVE_BOOTSTRAP_HISTORICAL_RECONSTRUCTION_TRUTH,
    receipt,
    receipt_sha256: receiptSha256,
    historical_bootstrap_authorization_binding: {
      authorization_id: receipt.authorization_id,
      batch_id: receipt.batch_id,
      receipt_sha256: receiptSha256,
      issued_at: receipt.issued_at,
      expires_at: receipt.expires_at,
    },
    launch_completed_at: launchCompletedAt,
    original_signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
    replay_signature_verifier: { ...INDEPENDENT_EIP191_REPLAY_VERIFIER },
    signature_verification_performed: true,
    independent_signature_replay_performed: true,
    original_signature_verifier_reexecuted: false,
    current_clock_consulted: false,
    freshness_renewed: false,
    production_brand_minted: false,
    live_traffic_authorized: false,
  }, { label: "persisted signed-A historical reconstruction result" });
}
