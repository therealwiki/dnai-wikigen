import { createHash } from "node:crypto";

import {
  CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
  CVM_MAIN_DISABLED_PROFILE_POLICY,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
  CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
  CVM_MAIN_PRODUCTION_PROFILE_TRANSITIONS,
} from "./cvm-launch-intent-core.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  eip191AuthorizationSigningDigest,
  eip191AuthorizationSigningMessage,
  normalizeExpectedReviewerAuthority,
  verifyPinnedTwoSignerAuthorization,
} from "./release-authority-signature-verifier.mjs";
import {
  TINKER_ACCOUNT_BINDING_CHAIN_ID,
  TINKER_ACCOUNT_BINDING_SCHEMA,
  TINKER_ACCOUNT_BINDING_TYPE,
  TINKER_ACCOUNT_BINDING_TYPEHASH,
  TINKER_PROVIDER_NAMESPACE,
  TINKER_PROVIDER_NAMESPACE_LABEL,
} from "./tinker-account-binding-core.mjs";
import {
  normalizePhalaPostMeasurementActivationExecutionReceipt,
  phalaPostMeasurementActivationExecutionReceiptSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";
import {
  assertLocallyVerifiedCompletedDiligenceReleaseGate,
} from "./diligence-release-activation-gate.mjs";

export const PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_SCHEMA =
  "dnai.phala-account-genesis-activation-authority.v1";
export const PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_STATUS =
  "account_genesis_start_and_retirement_authorized";
export const PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_TRUTH =
  "two_current_reviewers_authorized_one_exact_main_cvm_account_genesis_attempt_and_mandatory_profile_retirement_not_live_traffic";
export const PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_DOMAIN =
  "dnai-wikigen/phala-account-genesis-activation-authority/v1\0";
export const PHALA_ACCOUNT_GENESIS_ACTIVATION_SIGNING_DOMAIN =
  "dnai-wikigen/phala-account-genesis-activation-signing/v1\0";
export const PHALA_ACCOUNT_GENESIS_ACTIVATION_SIGNING_PREFIX =
  "dnai-wikigen phala account genesis activation v1:";
export const PHALA_ACCOUNT_GENESIS_ACTIVATION_SIGNATURE_PURPOSE =
  "phala_main_cvm_account_genesis_activation";

export const PHALA_ACCOUNT_GENESIS_COMPLETION_SCHEMA =
  "dnai.phala-account-genesis-completion.v1";
export const PHALA_ACCOUNT_GENESIS_COMPLETION_STATUS =
  "account_genesis_succeeded_and_one_shot_profiles_retired";
export const PHALA_ACCOUNT_GENESIS_COMPLETION_TRUTH =
  "bounded_tee_local_receipts_and_retirements_exactly_bound_not_standalone_tdx_or_qvl_evidence";
export const PHALA_ACCOUNT_GENESIS_COMPLETION_DOMAIN =
  "dnai-wikigen/phala-account-genesis-completion/v1\0";

export const PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_SCHEMA =
  "dnai.phala-live-deal-profile-activation-gate.v1";
export const PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_STATUS =
  "deal_profile_transition_authorized_pending_mutation";
export const PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_TRUTH =
  "signed_live_activation_completed_diligence_ceremony_nonlive_runtime_and_genesis_retirement_exactly_bound_not_mutation_or_service_presence";
export const PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_DOMAIN =
  "dnai-wikigen/phala-live-deal-profile-activation-gate/v1\0";

export const MAIN_CVM_MAILBOX_GENESIS_RECEIPT_SCHEMA =
  "dnai.main-cvm-mailbox-genesis-receipt.v1";
export const MAIN_CVM_MAILBOX_GENESIS_RETIREMENT_SCHEMA =
  "dnai.main-cvm-mailbox-genesis-retirement.v1";
export const MAIN_CVM_TINKER_ACCOUNT_GENESIS_RECEIPT_SCHEMA =
  "dnai.main-cvm-tinker-account-genesis-receipt.v1";
export const MAIN_CVM_TINKER_ACCOUNT_GENESIS_RETIREMENT_SCHEMA =
  "dnai.main-cvm-tinker-account-genesis-retirement.v1";
export const MAIN_CVM_MAILBOX_HANDOFF_RETIREMENT_SCHEMA =
  "dnai.main-cvm-mailbox-handoff-retirement.v1";

const CHAIN_ID = 84_532;
const MAX_AUTHORITY_LIFETIME_SECONDS = 60 * 60;
const MIN_AUTHORITY_HEADROOM_SECONDS = 5 * 60;
const MAX_FUTURE_SKEW_SECONDS = 5 * 60;
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const LOCALLY_CREATED_LIVE_DEAL_GATES = new WeakSet();

function fail(message) {
  throw new TypeError(message);
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} must contain exactly the frozen fields`);
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

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function digest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function exactString(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(`${label} is not canonical`);
  }
  return value;
}

function sha256(value, label) {
  return exactString(value, SHA256, label);
}

function integer(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail(`${label} must be a bounded safe integer`);
  }
  return value;
}

function canonicalSecond(value, label) {
  if (typeof value !== "string" || !ISO_SECOND.test(value)
    || new Date(Date.parse(value)).toISOString().replace(".000Z", "Z")
      !== value) {
    fail(`${label} must be a canonical UTC second`);
  }
  return value;
}

function exactLiteral(value, expected, label) {
  if (value !== expected) fail(`${label} must equal ${String(expected)}`);
  return value;
}

function exactProfilePolicy(value, expected, label) {
  const parsed = exactRecord(
    value,
    ["compose_profiles_value", "profile_names"],
    label,
  );
  if (JSON.stringify(parsed) !== JSON.stringify(expected)) {
    fail(`${label} is omitted, reordered, substituted, or widened`);
  }
  return {
    profile_names: [...expected.profile_names],
    compose_profiles_value: expected.compose_profiles_value,
  };
}

function normalizeTarget(value) {
  const parsed = exactRecord(value, [
    "app_id",
    "compose_hash",
    "cvm_id",
    "domain",
    "os_image_hash",
  ], "account-genesis main-CVM target");
  exactLiteral(parsed.domain, "main_runtime_cvm", "account-genesis target domain");
  return {
    domain: "main_runtime_cvm",
    app_id: exactString(parsed.app_id, APP_ID, "account-genesis target app ID"),
    cvm_id: exactString(parsed.cvm_id, CVM_ID, "account-genesis target CVM ID"),
    compose_hash: exactString(
      parsed.compose_hash,
      BARE_SHA256,
      "account-genesis target compose hash",
    ),
    os_image_hash: exactString(
      parsed.os_image_hash,
      BARE_SHA256,
      "account-genesis target OS image hash",
    ),
  };
}

function normalizeGenesisReviewerAuthority(value) {
  const parsed = exactRecord(value, [
    "approved_reviewer_hashes",
    "current_status_epoch",
    "current_status_expires_at",
    "current_status_not_before",
    "current_status_sha256",
    "genesis_acceptance_sha256",
    "genesis_sha256",
    "reviewer_root_hash",
    "reviewer_set_sha256",
    "reviewers",
  ], "account-genesis reviewer authority");
  const reviewers = Array.isArray(parsed.reviewers)
    ? parsed.reviewers.map((entry, index) => {
      const reviewer = exactRecord(
        entry,
        ["address", "controller_id"],
        `account-genesis reviewer ${index}`,
      );
      return {
        address: exactString(
          reviewer.address,
          ADDRESS,
          `account-genesis reviewer ${index} address`,
        ),
        controller_id: exactString(
          reviewer.controller_id,
          CONTROLLER,
          `account-genesis reviewer ${index} controller`,
        ),
      };
    })
    : fail("account-genesis reviewer authority requires an exact reviewer array");
  if (reviewers.length !== 2
    || reviewers[0].address >= reviewers[1].address
    || reviewers[0].controller_id === reviewers[1].controller_id) {
    fail("account-genesis requires two address-sorted independent reviewers");
  }
  const authority = normalizeExpectedReviewerAuthority({
    approved_reviewer_hashes: parsed.approved_reviewer_hashes,
    approved_reviewers: reviewers,
    reviewer_root_hash: parsed.reviewer_root_hash,
    reviewer_set_sha256: parsed.reviewer_set_sha256,
  }, {
    expectedReviewerRootHash: exactString(
      parsed.reviewer_root_hash,
      BARE_SHA256,
      "account-genesis reviewer root",
    ),
    expectedReviewerSetSha256: sha256(
      parsed.reviewer_set_sha256,
      "account-genesis reviewer set",
    ),
  });
  return {
    approved_reviewer_hashes: [...authority.approved_reviewer_hashes],
    current_status_epoch: integer(
      parsed.current_status_epoch,
      "account-genesis reviewer current-status epoch",
      1,
    ),
    current_status_expires_at: canonicalSecond(
      parsed.current_status_expires_at,
      "account-genesis reviewer current-status expires_at",
    ),
    current_status_not_before: canonicalSecond(
      parsed.current_status_not_before,
      "account-genesis reviewer current-status not_before",
    ),
    current_status_sha256: sha256(
      parsed.current_status_sha256,
      "account-genesis reviewer current-status digest",
    ),
    genesis_acceptance_sha256: sha256(
      parsed.genesis_acceptance_sha256,
      "account-genesis reviewer genesis-acceptance digest",
    ),
    genesis_sha256: sha256(
      parsed.genesis_sha256,
      "account-genesis reviewer genesis digest",
    ),
    reviewer_root_hash: authority.reviewer_root_hash,
    reviewer_set_sha256: authority.reviewer_set_sha256,
    reviewers,
  };
}

function normalizeGenesisAuthorityBody(value) {
  const parsed = exactRecord(value, [
    "automatic_retry_authorized",
    "chain_id",
    "cvm_launch_intent_sha256",
    "deployment_intent_sha256",
    "expires_at",
    "issued_at",
    "live_traffic_authorized",
    "main_qvl_verdict_sha256",
    "measurement_policy_sha256",
    "release_sha",
    "reviewer_authority",
    "schema",
    "seven_cvm_launch_completion_receipt_sha256",
    "signature_purpose",
    "signature_scheme",
    "signature_verifier",
    "status",
    "target",
    "tinker_account_binding_ceremony_receipt_sha256",
    "transition_sequence",
    "truth_status",
  ], "account-genesis activation authority body");
  exactLiteral(
    parsed.schema,
    PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_SCHEMA,
    "account-genesis authority schema",
  );
  exactLiteral(
    parsed.status,
    PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_STATUS,
    "account-genesis authority status",
  );
  exactLiteral(
    parsed.truth_status,
    PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_TRUTH,
    "account-genesis authority truth status",
  );
  exactLiteral(parsed.chain_id, CHAIN_ID, "account-genesis chain ID");
  exactLiteral(
    parsed.signature_purpose,
    PHALA_ACCOUNT_GENESIS_ACTIVATION_SIGNATURE_PURPOSE,
    "account-genesis signature purpose",
  );
  exactLiteral(
    parsed.signature_scheme,
    PINNED_EIP191_SIGNATURE_SCHEME,
    "account-genesis signature scheme",
  );
  if (JSON.stringify(parsed.signature_verifier)
      !== JSON.stringify(PINNED_CAST_SIGNATURE_VERIFIER)) {
    fail("account-genesis signature verifier is not the pinned cast build");
  }
  exactLiteral(
    parsed.automatic_retry_authorized,
    false,
    "account-genesis automatic retry marker",
  );
  exactLiteral(
    parsed.live_traffic_authorized,
    false,
    "account-genesis live-traffic marker",
  );
  const transitionSequence = Array.isArray(parsed.transition_sequence)
    ? parsed.transition_sequence.map((entry, index) => {
      const transition = exactRecord(entry, [
        "from",
        "live_traffic_after_transition",
        "name",
        "one_shot",
        "sequence",
        "to",
      ], `account-genesis transition ${index}`);
      const expected = CVM_MAIN_PRODUCTION_PROFILE_TRANSITIONS[index];
      if (!expected || !["account_genesis_start", "account_genesis_retire"]
        .includes(expected.name)
        || transition.sequence !== index + 1
        || transition.name !== expected.name
        || transition.one_shot !== true
        || transition.live_traffic_after_transition !== false) {
        fail("account-genesis transition order or truth boundary drifted");
      }
      return {
        sequence: index + 1,
        name: expected.name,
        from: exactProfilePolicy(
          transition.from,
          expected.from,
          `account-genesis transition ${index} from`,
        ),
        to: exactProfilePolicy(
          transition.to,
          expected.to,
          `account-genesis transition ${index} to`,
        ),
        one_shot: true,
        live_traffic_after_transition: false,
      };
    })
    : fail("account-genesis transition sequence must be an array");
  if (transitionSequence.length !== 2) {
    fail("account-genesis authority requires exactly start and retirement transitions");
  }
  const issuedAt = canonicalSecond(parsed.issued_at, "account-genesis issued_at");
  const expiresAt = canonicalSecond(
    parsed.expires_at,
    "account-genesis expires_at",
  );
  const issuedSecond = Math.floor(Date.parse(issuedAt) / 1_000);
  const expiresSecond = Math.floor(Date.parse(expiresAt) / 1_000);
  if (expiresSecond <= issuedSecond
    || expiresSecond - issuedSecond > MAX_AUTHORITY_LIFETIME_SECONDS) {
    fail("account-genesis authority lifetime is invalid");
  }
  return deepFreeze({
    schema: PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_SCHEMA,
    status: PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_STATUS,
    truth_status: PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_TRUTH,
    chain_id: CHAIN_ID,
    release_sha: exactString(
      parsed.release_sha,
      SHA40,
      "account-genesis release SHA",
    ),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "account-genesis deployment intent",
    ),
    cvm_launch_intent_sha256: sha256(
      parsed.cvm_launch_intent_sha256,
      "account-genesis CVM launch intent",
    ),
    seven_cvm_launch_completion_receipt_sha256: sha256(
      parsed.seven_cvm_launch_completion_receipt_sha256,
      "account-genesis seven-CVM launch completion",
    ),
    tinker_account_binding_ceremony_receipt_sha256: sha256(
      parsed.tinker_account_binding_ceremony_receipt_sha256,
      "account-genesis binding ceremony receipt",
    ),
    main_qvl_verdict_sha256: sha256(
      parsed.main_qvl_verdict_sha256,
      "account-genesis main-CVM QVL verdict",
    ),
    measurement_policy_sha256: sha256(
      parsed.measurement_policy_sha256,
      "account-genesis measurement policy",
    ),
    target: normalizeTarget(parsed.target),
    transition_sequence: transitionSequence,
    reviewer_authority: normalizeGenesisReviewerAuthority(
      parsed.reviewer_authority,
    ),
    issued_at: issuedAt,
    expires_at: expiresAt,
    signature_purpose: PHALA_ACCOUNT_GENESIS_ACTIVATION_SIGNATURE_PURPOSE,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  });
}

export function accountGenesisActivationSigningPayloadSha256(value) {
  return eip191AuthorizationSigningDigest({
    domain: PHALA_ACCOUNT_GENESIS_ACTIVATION_SIGNING_DOMAIN,
    payload: normalizeGenesisAuthorityBody(value),
  });
}

export function accountGenesisActivationSigningMessage(value) {
  return eip191AuthorizationSigningMessage({
    digest: accountGenesisActivationSigningPayloadSha256(value),
    prefix: PHALA_ACCOUNT_GENESIS_ACTIVATION_SIGNING_PREFIX,
  });
}

export function normalizePhalaAccountGenesisActivationAuthority(
  value,
  {
    checkedAt = Math.floor(Date.now() / 1_000),
    expected,
    verifySignatures = verifyPinnedTwoSignerAuthorization,
  } = {},
) {
  const parsed = exactRecord(value, [
    "automatic_retry_authorized",
    "chain_id",
    "cvm_launch_intent_sha256",
    "deployment_intent_sha256",
    "expires_at",
    "issued_at",
    "live_traffic_authorized",
    "main_qvl_verdict_sha256",
    "measurement_policy_sha256",
    "release_sha",
    "reviewer_authority",
    "schema",
    "seven_cvm_launch_completion_receipt_sha256",
    "signature_purpose",
    "signature_scheme",
    "signature_verifier",
    "signatures",
    "status",
    "target",
    "tinker_account_binding_ceremony_receipt_sha256",
    "transition_sequence",
    "truth_status",
  ], "signed account-genesis activation authority");
  const body = normalizeGenesisAuthorityBody(
    Object.fromEntries(
      Object.entries(parsed).filter(([key]) => key !== "signatures"),
    ),
  );
  const pins = exactRecord(expected, [
    "cvm_launch_intent_sha256",
    "deployment_intent_sha256",
    "main_qvl_verdict_sha256",
    "measurement_policy_sha256",
    "release_sha",
    "reviewer_current_status_epoch",
    "reviewer_current_status_sha256",
    "reviewer_genesis_acceptance_sha256",
    "reviewer_genesis_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
    "target",
    "tinker_account_binding_ceremony_receipt_sha256",
  ], "expected account-genesis authority pins");
  const expectedTarget = normalizeTarget(pins.target);
  if (body.release_sha !== pins.release_sha
    || body.deployment_intent_sha256 !== pins.deployment_intent_sha256
    || body.cvm_launch_intent_sha256 !== pins.cvm_launch_intent_sha256
    || body.seven_cvm_launch_completion_receipt_sha256
      !== pins.seven_cvm_launch_completion_receipt_sha256
    || body.tinker_account_binding_ceremony_receipt_sha256
      !== pins.tinker_account_binding_ceremony_receipt_sha256
    || body.main_qvl_verdict_sha256 !== pins.main_qvl_verdict_sha256
    || body.measurement_policy_sha256 !== pins.measurement_policy_sha256
    || body.reviewer_authority.genesis_sha256
      !== pins.reviewer_genesis_sha256
    || body.reviewer_authority.genesis_acceptance_sha256
      !== pins.reviewer_genesis_acceptance_sha256
    || body.reviewer_authority.current_status_epoch
      !== pins.reviewer_current_status_epoch
    || body.reviewer_authority.current_status_sha256
      !== pins.reviewer_current_status_sha256
    || canonicalText(body.target) !== canonicalText(expectedTarget)) {
    fail("account-genesis authority does not match the exact release evidence pins");
  }
  const issuedAt = Math.floor(Date.parse(body.issued_at) / 1_000);
  const expiresAt = Math.floor(Date.parse(body.expires_at) / 1_000);
  const statusNotBefore = Math.floor(
    Date.parse(body.reviewer_authority.current_status_not_before) / 1_000,
  );
  const statusExpiresAt = Math.floor(
    Date.parse(body.reviewer_authority.current_status_expires_at) / 1_000,
  );
  if (!Number.isSafeInteger(checkedAt)
    || issuedAt > checkedAt + MAX_FUTURE_SKEW_SECONDS
    || checkedAt >= expiresAt
    || expiresAt - checkedAt < MIN_AUTHORITY_HEADROOM_SECONDS
    || issuedAt < statusNotBefore
    || issuedAt >= statusExpiresAt
    || expiresAt > statusExpiresAt) {
    fail("account-genesis authority is stale or outside current reviewer authority");
  }
  if (!Array.isArray(parsed.signatures) || parsed.signatures.length !== 2) {
    fail("account-genesis authority requires exactly two signatures");
  }
  const signatures = parsed.signatures.map((entry, index) => {
    const signature = exactRecord(
      entry,
      ["address", "controller_id", "signature"],
      `account-genesis signature ${index}`,
    );
    return {
      address: exactString(
        signature.address,
        ADDRESS,
        `account-genesis signature ${index} address`,
      ),
      controller_id: exactString(
        signature.controller_id,
        CONTROLLER,
        `account-genesis signature ${index} controller`,
      ),
      signature: signature.signature,
    };
  });
  const expectedSigners = body.reviewer_authority.reviewers;
  if (JSON.stringify(signatures.map(({ address, controller_id }) => ({
    address,
    controller_id,
  }))) !== JSON.stringify(expectedSigners)) {
    fail("account-genesis signatures do not use the exact reviewer order");
  }
  if (typeof verifySignatures !== "function") {
    fail("account-genesis signature verifier is unavailable");
  }
  verifySignatures({
    signatures,
    message: accountGenesisActivationSigningMessage(body),
    reviewerAuthority: normalizeExpectedReviewerAuthority({
      approved_reviewer_hashes:
        body.reviewer_authority.approved_reviewer_hashes,
      approved_reviewers: body.reviewer_authority.reviewers,
      reviewer_root_hash: body.reviewer_authority.reviewer_root_hash,
      reviewer_set_sha256: body.reviewer_authority.reviewer_set_sha256,
    }, {
      expectedReviewerRootHash:
        body.reviewer_authority.reviewer_root_hash,
      expectedReviewerSetSha256:
        body.reviewer_authority.reviewer_set_sha256,
    }),
  });
  return deepFreeze({ ...body, signatures });
}

export function phalaAccountGenesisActivationAuthoritySha256(value, options) {
  return digest(
    PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_DOMAIN,
    normalizePhalaAccountGenesisActivationAuthority(value, options),
  );
}

function normalizeGenesisLineage(value, expected, {
  mailbox,
} = {}) {
  const fields = [
    "deployment_intent_sha256",
    "genesis_authorization_sha256",
    "main_app_id",
    "main_compose_hash",
    "main_os_image_hash",
    "main_qvl_verdict_sha256",
    "main_runtime_cvm_id",
    "measurement_policy_sha256",
    "release_sha",
    "reviewer_current_status_epoch",
    "reviewer_current_status_sha256",
    "reviewer_genesis_acceptance_sha256",
    "tinker_account_binding_ceremony_receipt_sha256",
    ...(mailbox ? ["account_binding_commitment"] : []),
  ];
  const parsed = exactRecord(value, fields, "account-genesis receipt lineage");
  const normalized = {
    release_sha: exactString(parsed.release_sha, SHA40, "genesis release SHA"),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "genesis deployment intent",
    ),
    genesis_authorization_sha256: sha256(
      parsed.genesis_authorization_sha256,
      "genesis authorization",
    ),
    main_qvl_verdict_sha256: sha256(
      parsed.main_qvl_verdict_sha256,
      "genesis main QVL verdict",
    ),
    measurement_policy_sha256: sha256(
      parsed.measurement_policy_sha256,
      "genesis measurement policy",
    ),
    main_runtime_cvm_id: exactString(
      parsed.main_runtime_cvm_id,
      CVM_ID,
      "genesis main CVM ID",
    ),
    main_app_id: exactString(
      parsed.main_app_id,
      ADDRESS,
      "genesis main app ID",
    ),
    main_compose_hash: exactString(
      parsed.main_compose_hash,
      BARE_SHA256,
      "genesis main compose hash",
    ),
    main_os_image_hash: exactString(
      parsed.main_os_image_hash,
      BARE_SHA256,
      "genesis main OS image hash",
    ),
    tinker_account_binding_ceremony_receipt_sha256: sha256(
      parsed.tinker_account_binding_ceremony_receipt_sha256,
      "genesis binding ceremony receipt",
    ),
    reviewer_genesis_acceptance_sha256: sha256(
      parsed.reviewer_genesis_acceptance_sha256,
      "genesis reviewer acceptance",
    ),
    reviewer_current_status_epoch: integer(
      parsed.reviewer_current_status_epoch,
      "genesis reviewer current-status epoch",
      1,
    ),
    reviewer_current_status_sha256: sha256(
      parsed.reviewer_current_status_sha256,
      "genesis reviewer current-status digest",
    ),
    ...(mailbox ? {
      account_binding_commitment: exactString(
        parsed.account_binding_commitment,
        BYTES32,
        "genesis account-binding commitment",
      ),
    } : {}),
  };
  const expectedLineage = {
    release_sha: expected.release_sha,
    deployment_intent_sha256: expected.deployment_intent_sha256,
    genesis_authorization_sha256: expected.genesis_authorization_sha256,
    main_qvl_verdict_sha256: expected.main_qvl_verdict_sha256,
    measurement_policy_sha256: expected.measurement_policy_sha256,
    main_runtime_cvm_id: expected.target.cvm_id,
    main_app_id: `0x${expected.target.app_id}`,
    main_compose_hash: expected.target.compose_hash,
    main_os_image_hash: expected.target.os_image_hash,
    tinker_account_binding_ceremony_receipt_sha256:
      expected.tinker_account_binding_ceremony_receipt_sha256,
    reviewer_genesis_acceptance_sha256:
      expected.reviewer_genesis_acceptance_sha256,
    reviewer_current_status_epoch: expected.reviewer_current_status_epoch,
    reviewer_current_status_sha256:
      expected.reviewer_current_status_sha256,
    ...(mailbox ? {
      account_binding_commitment: expected.account_binding_commitment,
    } : {}),
  };
  if (canonicalText(normalized) !== canonicalText(expectedLineage)) {
    fail("account-genesis receipt lineage differs from the activation authority");
  }
  return normalized;
}

function normalizeRuntime(value, expected) {
  const parsed = exactRecord(
    value,
    ["app_id", "compose_hash", "os_image_hash"],
    "account-genesis runtime identity",
  );
  const normalized = {
    app_id: exactString(parsed.app_id, ADDRESS, "genesis runtime app ID"),
    compose_hash: exactString(
      parsed.compose_hash,
      BARE_SHA256,
      "genesis runtime compose hash",
    ),
    os_image_hash: exactString(
      parsed.os_image_hash,
      BARE_SHA256,
      "genesis runtime OS image hash",
    ),
  };
  if (normalized.app_id !== `0x${expected.target.app_id}`
    || normalized.compose_hash !== expected.target.compose_hash
    || normalized.os_image_hash !== expected.target.os_image_hash) {
    fail("account-genesis receipt runtime differs from the exact main CVM");
  }
  return normalized;
}

function normalizeMailboxReceipt(value, expected) {
  const parsed = exactRecord(value, [
    "attempt_count",
    "completed_at",
    "credential_material_committed",
    "evidence_mode",
    "independent_qvl_evidence_bound",
    "independent_qvl_verified_by_profile",
    "lineage",
    "live_traffic_authorized",
    "mailbox_created",
    "provider_identifier_committed",
    "raw_secret_egress",
    "runtime",
    "schema",
    "sealed_credentials_roundtrip_verified",
    "sealed_mailbox_handoff_created",
    "status",
    "success",
  ], "mailbox-genesis receipt");
  for (const [field, literal] of Object.entries({
    schema: MAIN_CVM_MAILBOX_GENESIS_RECEIPT_SCHEMA,
    status: "mailbox_created_and_sealed",
    success: true,
    attempt_count: 1,
    mailbox_created: true,
    sealed_credentials_roundtrip_verified: true,
    sealed_mailbox_handoff_created: true,
    provider_identifier_committed: false,
    credential_material_committed: false,
    raw_secret_egress: false,
    live_traffic_authorized: false,
    independent_qvl_verified_by_profile: false,
    independent_qvl_evidence_bound: true,
    evidence_mode: "measured_runtime_pending_independent_qvl_recheck",
  })) {
    exactLiteral(parsed[field], literal, `mailbox-genesis ${field}`);
  }
  return {
    ...parsed,
    completed_at: integer(parsed.completed_at, "mailbox-genesis completed_at"),
    lineage: normalizeGenesisLineage(parsed.lineage, expected, { mailbox: true }),
    runtime: normalizeRuntime(parsed.runtime, expected),
  };
}

function normalizeAccountBinding(value, expected) {
  const parsed = exactRecord(value, [
    "attested_provider_binding_required",
    "chain_id",
    "commitment",
    "provider_identifier_committed",
    "provider_namespace",
    "provider_namespace_label",
    "schema",
    "type",
    "typehash",
  ], "account-genesis public binding");
  const literals = {
    schema: TINKER_ACCOUNT_BINDING_SCHEMA,
    chain_id: Number(TINKER_ACCOUNT_BINDING_CHAIN_ID),
    provider_namespace_label: TINKER_PROVIDER_NAMESPACE_LABEL,
    provider_namespace: TINKER_PROVIDER_NAMESPACE,
    type: TINKER_ACCOUNT_BINDING_TYPE,
    typehash: TINKER_ACCOUNT_BINDING_TYPEHASH,
    commitment: expected.account_binding_commitment,
    provider_identifier_committed: false,
    attested_provider_binding_required: true,
  };
  if (canonicalText(parsed) !== canonicalText(literals)) {
    fail("account-genesis public binding differs from deployment intent");
  }
  return { ...literals };
}

function normalizeAccountReceipt(value, expected) {
  const parsed = exactRecord(value, [
    "api_key_sealed",
    "attempt_count",
    "binding",
    "completed_at",
    "evidence_mode",
    "funding_authorized",
    "identity_check_method",
    "identity_check_performed",
    "identity_check_status",
    "independent_qvl_evidence_bound",
    "independent_qvl_verified_by_profile",
    "lineage",
    "live_traffic_authorized",
    "mailbox_handoff_consumed_inside_cvm",
    "raw_secret_egress",
    "runtime",
    "schema",
    "status",
    "success",
    "upstream_account_exists",
  ], "Tinker account-genesis receipt");
  for (const [field, literal] of Object.entries({
    schema: MAIN_CVM_TINKER_ACCOUNT_GENESIS_RECEIPT_SCHEMA,
    status: "account_created_bound_and_sealed",
    success: true,
    attempt_count: 1,
    upstream_account_exists: true,
    identity_check_performed: true,
    identity_check_status: "passed",
    identity_check_method: "signup_and_sealed_api_key_roundtrip",
    api_key_sealed: true,
    mailbox_handoff_consumed_inside_cvm: true,
    raw_secret_egress: false,
    live_traffic_authorized: false,
    funding_authorized: false,
    independent_qvl_verified_by_profile: false,
    independent_qvl_evidence_bound: true,
    evidence_mode: "measured_runtime_pending_independent_qvl_recheck",
  })) {
    exactLiteral(parsed[field], literal, `Tinker account-genesis ${field}`);
  }
  return {
    ...parsed,
    completed_at: integer(parsed.completed_at, "account-genesis completed_at"),
    binding: normalizeAccountBinding(parsed.binding, expected),
    lineage: normalizeGenesisLineage(parsed.lineage, expected),
    runtime: normalizeRuntime(parsed.runtime, expected),
  };
}

function normalizeMailboxRetirement(value, expected) {
  const parsed = exactRecord(value, [
    "account_binding_commitment",
    "genesis_authorization_sha256",
    "mailbox_genesis_success",
    "profile_must_remain_disabled",
    "raw_secret_egress",
    "release_sha",
    "retired_at",
    "retry_permitted",
    "schema",
    "status",
    "tinker_account_binding_ceremony_receipt_sha256",
  ], "mailbox-genesis retirement");
  const normalized = {
    schema: exactLiteral(
      parsed.schema,
      MAIN_CVM_MAILBOX_GENESIS_RETIREMENT_SCHEMA,
      "mailbox retirement schema",
    ),
    status: exactLiteral(
      parsed.status,
      "retired_after_single_attempt",
      "mailbox retirement status",
    ),
    mailbox_genesis_success: exactLiteral(
      parsed.mailbox_genesis_success,
      true,
      "mailbox retirement success",
    ),
    retry_permitted: exactLiteral(
      parsed.retry_permitted,
      false,
      "mailbox retirement retry marker",
    ),
    profile_must_remain_disabled: exactLiteral(
      parsed.profile_must_remain_disabled,
      true,
      "mailbox retirement disabled marker",
    ),
    retired_at: integer(parsed.retired_at, "mailbox retirement timestamp"),
    release_sha: exactString(parsed.release_sha, SHA40, "mailbox retirement release"),
    genesis_authorization_sha256: sha256(
      parsed.genesis_authorization_sha256,
      "mailbox retirement authorization",
    ),
    tinker_account_binding_ceremony_receipt_sha256: sha256(
      parsed.tinker_account_binding_ceremony_receipt_sha256,
      "mailbox retirement binding ceremony",
    ),
    account_binding_commitment: exactString(
      parsed.account_binding_commitment,
      BYTES32,
      "mailbox retirement binding commitment",
    ),
    raw_secret_egress: exactLiteral(
      parsed.raw_secret_egress,
      false,
      "mailbox retirement secret egress",
    ),
  };
  if (normalized.release_sha !== expected.release_sha
    || normalized.genesis_authorization_sha256
      !== expected.genesis_authorization_sha256
    || normalized.tinker_account_binding_ceremony_receipt_sha256
      !== expected.tinker_account_binding_ceremony_receipt_sha256
    || normalized.account_binding_commitment
      !== expected.account_binding_commitment) {
    fail("mailbox retirement lineage differs from account-genesis authority");
  }
  return normalized;
}

function normalizeAccountRetirement(value, expected) {
  const parsed = exactRecord(value, [
    "account_binding_commitment",
    "account_genesis_success",
    "deployment_intent_sha256",
    "genesis_authorization_sha256",
    "profile_must_remain_disabled",
    "raw_secret_egress",
    "release_sha",
    "retired_at",
    "retry_permitted",
    "reviewer_current_status_epoch",
    "reviewer_current_status_sha256",
    "reviewer_genesis_acceptance_sha256",
    "schema",
    "status",
    "tinker_account_binding_ceremony_receipt_sha256",
  ], "Tinker account-genesis retirement");
  const normalized = {
    schema: exactLiteral(
      parsed.schema,
      MAIN_CVM_TINKER_ACCOUNT_GENESIS_RETIREMENT_SCHEMA,
      "account retirement schema",
    ),
    status: exactLiteral(
      parsed.status,
      "retired_after_single_attempt",
      "account retirement status",
    ),
    account_genesis_success: exactLiteral(
      parsed.account_genesis_success,
      true,
      "account retirement success",
    ),
    retry_permitted: exactLiteral(
      parsed.retry_permitted,
      false,
      "account retirement retry marker",
    ),
    profile_must_remain_disabled: exactLiteral(
      parsed.profile_must_remain_disabled,
      true,
      "account retirement disabled marker",
    ),
    retired_at: integer(parsed.retired_at, "account retirement timestamp"),
    release_sha: exactString(parsed.release_sha, SHA40, "account retirement release"),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "account retirement deployment intent",
    ),
    genesis_authorization_sha256: sha256(
      parsed.genesis_authorization_sha256,
      "account retirement authorization",
    ),
    tinker_account_binding_ceremony_receipt_sha256: sha256(
      parsed.tinker_account_binding_ceremony_receipt_sha256,
      "account retirement binding ceremony",
    ),
    account_binding_commitment: exactString(
      parsed.account_binding_commitment,
      BYTES32,
      "account retirement binding commitment",
    ),
    reviewer_genesis_acceptance_sha256: sha256(
      parsed.reviewer_genesis_acceptance_sha256,
      "account retirement reviewer acceptance",
    ),
    reviewer_current_status_epoch: integer(
      parsed.reviewer_current_status_epoch,
      "account retirement reviewer epoch",
      1,
    ),
    reviewer_current_status_sha256: sha256(
      parsed.reviewer_current_status_sha256,
      "account retirement reviewer status",
    ),
    raw_secret_egress: exactLiteral(
      parsed.raw_secret_egress,
      false,
      "account retirement secret egress",
    ),
  };
  const expectedProjection = {
    release_sha: expected.release_sha,
    deployment_intent_sha256: expected.deployment_intent_sha256,
    genesis_authorization_sha256: expected.genesis_authorization_sha256,
    tinker_account_binding_ceremony_receipt_sha256:
      expected.tinker_account_binding_ceremony_receipt_sha256,
    account_binding_commitment: expected.account_binding_commitment,
    reviewer_genesis_acceptance_sha256:
      expected.reviewer_genesis_acceptance_sha256,
    reviewer_current_status_epoch: expected.reviewer_current_status_epoch,
    reviewer_current_status_sha256:
      expected.reviewer_current_status_sha256,
  };
  if (Object.entries(expectedProjection).some(
    ([key, valueExpected]) => normalized[key] !== valueExpected,
  )) {
    fail("account retirement lineage differs from account-genesis authority");
  }
  return normalized;
}

function normalizeHandoffRetirement(value, expected) {
  const parsed = exactRecord(value, [
    "account_genesis_retirement_observed",
    "genesis_authorization_sha256",
    "handoff_path_absent_after_directory_fsync",
    "raw_secret_egress",
    "release_sha",
    "retired_at",
    "schema",
    "status",
    "tinker_account_binding_ceremony_receipt_sha256",
  ], "mailbox handoff retirement receipt");
  const normalized = {
    schema: exactLiteral(
      parsed.schema,
      MAIN_CVM_MAILBOX_HANDOFF_RETIREMENT_SCHEMA,
      "handoff retirement schema",
    ),
    status: exactLiteral(
      parsed.status,
      "encrypted_mailbox_handoff_retired",
      "handoff retirement status",
    ),
    account_genesis_retirement_observed: exactLiteral(
      parsed.account_genesis_retirement_observed,
      true,
      "handoff account-retirement observation",
    ),
    handoff_path_absent_after_directory_fsync: exactLiteral(
      parsed.handoff_path_absent_after_directory_fsync,
      true,
      "handoff unlink proof",
    ),
    release_sha: exactString(parsed.release_sha, SHA40, "handoff retirement release"),
    genesis_authorization_sha256: sha256(
      parsed.genesis_authorization_sha256,
      "handoff retirement authorization",
    ),
    tinker_account_binding_ceremony_receipt_sha256: sha256(
      parsed.tinker_account_binding_ceremony_receipt_sha256,
      "handoff retirement binding ceremony",
    ),
    retired_at: integer(parsed.retired_at, "handoff retirement timestamp"),
    raw_secret_egress: exactLiteral(
      parsed.raw_secret_egress,
      false,
      "handoff retirement secret egress",
    ),
  };
  if (normalized.release_sha !== expected.release_sha
    || normalized.genesis_authorization_sha256
      !== expected.genesis_authorization_sha256
    || normalized.tinker_account_binding_ceremony_receipt_sha256
      !== expected.tinker_account_binding_ceremony_receipt_sha256) {
    fail("handoff retirement lineage differs from account-genesis authority");
  }
  return normalized;
}

export function normalizePhalaAccountGenesisCompletion(value, {
  expected,
} = {}) {
  const parsed = exactRecord(value, [
    "account_receipt",
    "account_receipt_sha256",
    "account_retirement",
    "account_retirement_sha256",
    "automatic_retry_authorized",
    "genesis_authorization_sha256",
    "handoff_retirement",
    "handoff_retirement_sha256",
    "live_traffic_authorized",
    "mailbox_receipt",
    "mailbox_receipt_sha256",
    "mailbox_retirement",
    "mailbox_retirement_sha256",
    "profile_after_completion",
    "profile_during_attempt",
    "release_sha",
    "schema",
    "status",
    "truth_status",
  ], "account-genesis completion");
  const expectedPins = exactRecord(expected, [
    "account_binding_commitment",
    "deployment_intent_sha256",
    "genesis_authorization_sha256",
    "main_qvl_verdict_sha256",
    "measurement_policy_sha256",
    "release_sha",
    "reviewer_current_status_epoch",
    "reviewer_current_status_sha256",
    "reviewer_genesis_acceptance_sha256",
    "target",
    "tinker_account_binding_ceremony_receipt_sha256",
  ], "expected account-genesis completion pins");
  const normalizedExpected = {
    ...expectedPins,
    target: normalizeTarget(expectedPins.target),
  };
  exactLiteral(
    parsed.schema,
    PHALA_ACCOUNT_GENESIS_COMPLETION_SCHEMA,
    "account-genesis completion schema",
  );
  exactLiteral(
    parsed.status,
    PHALA_ACCOUNT_GENESIS_COMPLETION_STATUS,
    "account-genesis completion status",
  );
  exactLiteral(
    parsed.truth_status,
    PHALA_ACCOUNT_GENESIS_COMPLETION_TRUTH,
    "account-genesis completion truth status",
  );
  exactLiteral(
    parsed.automatic_retry_authorized,
    false,
    "account-genesis completion retry marker",
  );
  exactLiteral(
    parsed.live_traffic_authorized,
    false,
    "account-genesis completion live marker",
  );
  if (parsed.release_sha !== normalizedExpected.release_sha
    || parsed.genesis_authorization_sha256
      !== normalizedExpected.genesis_authorization_sha256) {
    fail("account-genesis completion release lineage drifted");
  }
  const mailboxReceipt = normalizeMailboxReceipt(
    parsed.mailbox_receipt,
    normalizedExpected,
  );
  const mailboxRetirement = normalizeMailboxRetirement(
    parsed.mailbox_retirement,
    normalizedExpected,
  );
  const accountReceipt = normalizeAccountReceipt(
    parsed.account_receipt,
    normalizedExpected,
  );
  const accountRetirement = normalizeAccountRetirement(
    parsed.account_retirement,
    normalizedExpected,
  );
  const handoffRetirement = normalizeHandoffRetirement(
    parsed.handoff_retirement,
    normalizedExpected,
  );
  const receiptDigests = {
    mailbox_receipt_sha256: digest(
      "dnai-wikigen/main-cvm-mailbox-genesis-receipt/v1\0",
      mailboxReceipt,
    ),
    mailbox_retirement_sha256: digest(
      "dnai-wikigen/main-cvm-mailbox-genesis-retirement/v1\0",
      mailboxRetirement,
    ),
    account_receipt_sha256: digest(
      "dnai-wikigen/main-cvm-tinker-account-genesis-receipt/v1\0",
      accountReceipt,
    ),
    account_retirement_sha256: digest(
      "dnai-wikigen/main-cvm-tinker-account-genesis-retirement/v1\0",
      accountRetirement,
    ),
    handoff_retirement_sha256: digest(
      "dnai-wikigen/main-cvm-mailbox-handoff-retirement/v1\0",
      handoffRetirement,
    ),
  };
  if (Object.entries(receiptDigests).some(
    ([key, expectedDigest]) => parsed[key] !== expectedDigest,
  )) {
    fail("account-genesis completion carries an invalid evidence digest");
  }
  if (mailboxReceipt.completed_at > accountReceipt.completed_at
    || mailboxRetirement.retired_at < mailboxReceipt.completed_at
    || accountRetirement.retired_at < accountReceipt.completed_at
    || handoffRetirement.retired_at < accountRetirement.retired_at) {
    fail("account-genesis evidence ordering is invalid");
  }
  return deepFreeze({
    schema: PHALA_ACCOUNT_GENESIS_COMPLETION_SCHEMA,
    status: PHALA_ACCOUNT_GENESIS_COMPLETION_STATUS,
    truth_status: PHALA_ACCOUNT_GENESIS_COMPLETION_TRUTH,
    release_sha: normalizedExpected.release_sha,
    genesis_authorization_sha256:
      normalizedExpected.genesis_authorization_sha256,
    profile_during_attempt: exactProfilePolicy(
      parsed.profile_during_attempt,
      CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
      "account-genesis active profile set",
    ),
    profile_after_completion: exactProfilePolicy(
      parsed.profile_after_completion,
      CVM_MAIN_DISABLED_PROFILE_POLICY,
      "account-genesis retired profile set",
    ),
    mailbox_receipt: mailboxReceipt,
    mailbox_receipt_sha256: receiptDigests.mailbox_receipt_sha256,
    mailbox_retirement: mailboxRetirement,
    mailbox_retirement_sha256: receiptDigests.mailbox_retirement_sha256,
    account_receipt: accountReceipt,
    account_receipt_sha256: receiptDigests.account_receipt_sha256,
    account_retirement: accountRetirement,
    account_retirement_sha256: receiptDigests.account_retirement_sha256,
    handoff_retirement: handoffRetirement,
    handoff_retirement_sha256: receiptDigests.handoff_retirement_sha256,
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  });
}

export function phalaAccountGenesisCompletionSha256(value, options) {
  return digest(
    PHALA_ACCOUNT_GENESIS_COMPLETION_DOMAIN,
    normalizePhalaAccountGenesisCompletion(value, options),
  );
}

export function buildPhalaAccountGenesisCompletion({
  accountReceipt,
  accountRetirement,
  expected,
  handoffRetirement,
  mailboxReceipt,
  mailboxRetirement,
} = {}) {
  const candidate = {
    schema: PHALA_ACCOUNT_GENESIS_COMPLETION_SCHEMA,
    status: PHALA_ACCOUNT_GENESIS_COMPLETION_STATUS,
    truth_status: PHALA_ACCOUNT_GENESIS_COMPLETION_TRUTH,
    release_sha: expected?.release_sha,
    genesis_authorization_sha256: expected?.genesis_authorization_sha256,
    profile_during_attempt: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
    profile_after_completion: CVM_MAIN_DISABLED_PROFILE_POLICY,
    mailbox_receipt: mailboxReceipt,
    mailbox_receipt_sha256: digest(
      "dnai-wikigen/main-cvm-mailbox-genesis-receipt/v1\0",
      mailboxReceipt,
    ),
    mailbox_retirement: mailboxRetirement,
    mailbox_retirement_sha256: digest(
      "dnai-wikigen/main-cvm-mailbox-genesis-retirement/v1\0",
      mailboxRetirement,
    ),
    account_receipt: accountReceipt,
    account_receipt_sha256: digest(
      "dnai-wikigen/main-cvm-tinker-account-genesis-receipt/v1\0",
      accountReceipt,
    ),
    account_retirement: accountRetirement,
    account_retirement_sha256: digest(
      "dnai-wikigen/main-cvm-tinker-account-genesis-retirement/v1\0",
      accountRetirement,
    ),
    handoff_retirement: handoffRetirement,
    handoff_retirement_sha256: digest(
      "dnai-wikigen/main-cvm-mailbox-handoff-retirement/v1\0",
      handoffRetirement,
    ),
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  };
  return normalizePhalaAccountGenesisCompletion(candidate, { expected });
}

export function createPhalaLiveDealProfileActivationGate({
  accountGenesisCompletion,
  accountGenesisExpected,
  diligenceReleaseGate,
  liveActivationAuthoritySha256,
  nonliveActivationExecutionReceipt,
  nonliveActivationExecutionReceiptSha256,
  releaseSha,
  target,
} = {}) {
  const completion = normalizePhalaAccountGenesisCompletion(
    accountGenesisCompletion,
    { expected: accountGenesisExpected },
  );
  const normalizedTarget = normalizeTarget(target);
  const receipt =
    normalizePhalaPostMeasurementActivationExecutionReceipt(
      nonliveActivationExecutionReceipt,
    );
  const receiptSha256 =
    phalaPostMeasurementActivationExecutionReceiptSha256(receipt);
  if (receipt.live_traffic_authorized !== false
    || receipt.release_sha !== releaseSha
    || receipt.target?.domain !== "main_runtime_cvm"
    || receipt.target?.app_id !== normalizedTarget.app_id
    || receipt.target?.cvm_id !== normalizedTarget.cvm_id
    || receipt.target?.compose_hash !== normalizedTarget.compose_hash
    || receipt.target?.os_image_hash !== normalizedTarget.os_image_hash
    || canonicalText(receipt.profile_activation)
      !== canonicalText(CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY)
    || receiptSha256 !== nonliveActivationExecutionReceiptSha256) {
    fail("live deal gate lacks the exact completed nonlive Arena/Compute state");
  }
  const diligence = exactRecord(
    assertLocallyVerifiedCompletedDiligenceReleaseGate(diligenceReleaseGate),
    [
    "chainId",
    "currentLedgerSha256",
    "diligenceRoomAddress",
    "distinctReviewEnvelopeCount",
    "finalizationReceiptSha256",
    "finalizedThroughBlock",
    "governanceAcceptanceClaim",
    "governanceAcceptanceMode",
    "governanceAcceptanceTransactionHash",
    "governanceController",
    "operatorTransactionCount",
    "phaseCount",
    "releaseSha",
    "reviewEnvelopeCount",
    "revisionChainSha256",
    "schema",
    "status",
    "truthStatus",
    "valid",
  ], "completed Diligence release gate");
  if (diligence.valid !== true
    || diligence.releaseSha !== releaseSha
    || diligence.chainId !== CHAIN_ID
    || diligence.phaseCount !== 4
    || diligence.reviewEnvelopeCount !== 4
    || diligence.distinctReviewEnvelopeCount !== 4
    || diligence.operatorTransactionCount !== 13) {
    fail("live deal gate requires the completed four-phase Diligence release gate");
  }
  const candidate = {
    schema: PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_SCHEMA,
    status: PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_STATUS,
    truth_status: PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_TRUTH,
    release_sha: exactString(releaseSha, SHA40, "live deal release SHA"),
    chain_id: CHAIN_ID,
    target: normalizedTarget,
    from_profile: CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
    to_profile: CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
    live_activation_authority_sha256: sha256(
      liveActivationAuthoritySha256,
      "signed live activation authority",
    ),
    nonlive_activation_execution_receipt_sha256: sha256(
      receiptSha256,
      "nonlive activation execution receipt",
    ),
    account_genesis_completion_sha256:
      phalaAccountGenesisCompletionSha256(completion, {
        expected: accountGenesisExpected,
      }),
    diligence_release_gate_sha256: digest(
      "dnai-wikigen/diligence-release-activation-gate/v1\0",
      diligence,
    ),
    diligence_finalized_through_block: integer(
      diligence.finalizedThroughBlock,
      "Diligence finalized block",
      1,
    ),
    mutation_performed: false,
    post_restart_service_presence_verified: false,
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  };
  const gate = deepFreeze(candidate);
  LOCALLY_CREATED_LIVE_DEAL_GATES.add(gate);
  return gate;
}

export function normalizePhalaLiveDealProfileActivationGate(value) {
  const parsed = exactRecord(value, [
    "account_genesis_completion_sha256",
    "automatic_retry_authorized",
    "chain_id",
    "diligence_finalized_through_block",
    "diligence_release_gate_sha256",
    "from_profile",
    "live_activation_authority_sha256",
    "live_traffic_authorized",
    "mutation_performed",
    "nonlive_activation_execution_receipt_sha256",
    "post_restart_service_presence_verified",
    "release_sha",
    "schema",
    "status",
    "target",
    "to_profile",
    "truth_status",
  ], "live deal profile activation gate");
  exactLiteral(
    parsed.schema,
    PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_SCHEMA,
    "live deal gate schema",
  );
  exactLiteral(
    parsed.status,
    PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_STATUS,
    "live deal gate status",
  );
  exactLiteral(
    parsed.truth_status,
    PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_TRUTH,
    "live deal gate truth status",
  );
  for (const field of [
    "mutation_performed",
    "post_restart_service_presence_verified",
    "automatic_retry_authorized",
    "live_traffic_authorized",
  ]) {
    exactLiteral(parsed[field], false, `live deal gate ${field}`);
  }
  return deepFreeze({
    ...parsed,
    release_sha: exactString(parsed.release_sha, SHA40, "live deal release SHA"),
    chain_id: exactLiteral(parsed.chain_id, CHAIN_ID, "live deal chain ID"),
    target: normalizeTarget(parsed.target),
    from_profile: exactProfilePolicy(
      parsed.from_profile,
      CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
      "live deal source profile",
    ),
    to_profile: exactProfilePolicy(
      parsed.to_profile,
      CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
      "live deal target profile",
    ),
    live_activation_authority_sha256: sha256(
      parsed.live_activation_authority_sha256,
      "live deal signed authority",
    ),
    nonlive_activation_execution_receipt_sha256: sha256(
      parsed.nonlive_activation_execution_receipt_sha256,
      "live deal nonlive receipt",
    ),
    account_genesis_completion_sha256: sha256(
      parsed.account_genesis_completion_sha256,
      "live deal genesis completion",
    ),
    diligence_release_gate_sha256: sha256(
      parsed.diligence_release_gate_sha256,
      "live deal Diligence gate",
    ),
    diligence_finalized_through_block: integer(
      parsed.diligence_finalized_through_block,
      "live deal finalized block",
      1,
    ),
  });
}

export function phalaLiveDealProfileActivationGateSha256(value) {
  return digest(
    PHALA_LIVE_DEAL_PROFILE_ACTIVATION_GATE_DOMAIN,
    normalizePhalaLiveDealProfileActivationGate(value),
  );
}

export function assertLocallyCreatedPhalaLiveDealProfileActivationGate(value) {
  if (!value || !LOCALLY_CREATED_LIVE_DEAL_GATES.has(value)) {
    fail(
      "a locally derived live-deal gate from the complete authority chain is required",
    );
  }
  normalizePhalaLiveDealProfileActivationGate(value);
  return value;
}
