import {
  CVM_MAIN_PRODUCTION_PROFILE_TRANSITIONS,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_SCHEMA,
  PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_STATUS,
  PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_TRUTH,
  MAIN_CVM_MAILBOX_GENESIS_RECEIPT_SCHEMA,
  MAIN_CVM_MAILBOX_GENESIS_RETIREMENT_SCHEMA,
  MAIN_CVM_MAILBOX_HANDOFF_RETIREMENT_SCHEMA,
  MAIN_CVM_TINKER_ACCOUNT_GENESIS_RECEIPT_SCHEMA,
  MAIN_CVM_TINKER_ACCOUNT_GENESIS_RETIREMENT_SCHEMA,
  buildPhalaAccountGenesisCompletion,
  phalaAccountGenesisActivationAuthoritySha256,
} from "./phala-main-profile-activation-core.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
} from "./release-authority-signature-verifier-core.mjs";
import {
  TINKER_ACCOUNT_BINDING_CHAIN_ID,
  TINKER_ACCOUNT_BINDING_SCHEMA,
  TINKER_ACCOUNT_BINDING_TYPE,
  TINKER_ACCOUNT_BINDING_TYPEHASH,
  TINKER_PROVIDER_NAMESPACE,
  TINKER_PROVIDER_NAMESPACE_LABEL,
} from "./tinker-account-binding-core.mjs";
import {
  PHALA_ACCOUNT_GENESIS_ACTIVATION_SIGNATURE_PURPOSE,
} from "./phala-main-profile-activation-core.mjs";

export const SYNTHETIC_ACCOUNT_GENESIS_CHECKED_AT =
  Date.parse("2026-07-23T10:15:00Z") / 1_000;

const releaseSha = "a".repeat(40);
const digest = (character) => `sha256:${character.repeat(64)}`;
const target = Object.freeze({
  domain: "main_runtime_cvm",
  app_id: "b".repeat(40),
  cvm_id: "cvm-main-0001",
  compose_hash: "c".repeat(64),
  os_image_hash: "d".repeat(64),
});
const accountBindingCommitment = `0x${"e".repeat(64)}`;
const reviewers = Object.freeze([
  Object.freeze({
    address: `0x${"1".repeat(40)}`,
    controller_id: "reviewer-alpha",
  }),
  Object.freeze({
    address: `0x${"2".repeat(40)}`,
    controller_id: "reviewer-bravo",
  }),
]);
const reviewerHashes = Object.freeze(reviewers
  .map(({ address }) => executionPolicyReviewerHash(address))
  .sort());

function clone(value) {
  return structuredClone(value);
}

function fakeSignatureVerifier({ message, reviewerAuthority, signatures }) {
  if (typeof message !== "string" || !message.startsWith(
    "dnai-wikigen phala account genesis activation v1:",
  ) || signatures.length !== 2
    || reviewerAuthority.approved_reviewers.length !== 2) {
    throw new Error("synthetic signature-verifier inputs drifted");
  }
  return signatures.map(({ address }) => ({
    address,
    signature_sha256: digest("f"),
  }));
}

function authorityExpected() {
  return {
    release_sha: releaseSha,
    deployment_intent_sha256: digest("1"),
    cvm_launch_intent_sha256: digest("2"),
    seven_cvm_launch_completion_receipt_sha256: digest("3"),
    tinker_account_binding_ceremony_receipt_sha256: digest("4"),
    main_qvl_verdict_sha256: digest("5"),
    measurement_policy_sha256: digest("6"),
    reviewer_genesis_sha256: digest("7"),
    reviewer_genesis_acceptance_sha256: digest("8"),
    reviewer_current_status_epoch: 3,
    reviewer_current_status_sha256: digest("9"),
    target: clone(target),
  };
}

function signedAuthority() {
  return {
    schema: PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_SCHEMA,
    status: PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_STATUS,
    truth_status: PHALA_ACCOUNT_GENESIS_ACTIVATION_AUTHORITY_TRUTH,
    chain_id: 84_532,
    release_sha: releaseSha,
    deployment_intent_sha256: digest("1"),
    cvm_launch_intent_sha256: digest("2"),
    seven_cvm_launch_completion_receipt_sha256: digest("3"),
    tinker_account_binding_ceremony_receipt_sha256: digest("4"),
    main_qvl_verdict_sha256: digest("5"),
    measurement_policy_sha256: digest("6"),
    target: clone(target),
    transition_sequence: clone(
      CVM_MAIN_PRODUCTION_PROFILE_TRANSITIONS.slice(0, 2),
    ),
    reviewer_authority: {
      approved_reviewer_hashes: [...reviewerHashes],
      reviewer_root_hash: executionPolicyReviewerRootHash(reviewerHashes),
      reviewer_set_sha256: reviewerSetSha256(reviewers),
      reviewers: clone(reviewers),
      genesis_sha256: digest("7"),
      genesis_acceptance_sha256: digest("8"),
      current_status_epoch: 3,
      current_status_sha256: digest("9"),
      current_status_not_before: "2026-07-23T10:00:00Z",
      current_status_expires_at: "2026-07-23T11:00:00Z",
    },
    issued_at: "2026-07-23T10:10:00Z",
    expires_at: "2026-07-23T10:45:00Z",
    signature_purpose:
      PHALA_ACCOUNT_GENESIS_ACTIVATION_SIGNATURE_PURPOSE,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
    signatures: reviewers.map((reviewer, index) => ({
      ...reviewer,
      signature: `synthetic-signature-${index + 1}`,
    })),
  };
}

function completionExpected(genesisAuthorizationSha256) {
  return {
    release_sha: releaseSha,
    deployment_intent_sha256: digest("1"),
    genesis_authorization_sha256: genesisAuthorizationSha256,
    main_qvl_verdict_sha256: digest("5"),
    measurement_policy_sha256: digest("6"),
    target: clone(target),
    tinker_account_binding_ceremony_receipt_sha256: digest("4"),
    account_binding_commitment: accountBindingCommitment,
    reviewer_genesis_acceptance_sha256: digest("8"),
    reviewer_current_status_epoch: 3,
    reviewer_current_status_sha256: digest("9"),
  };
}

function lineage(expected, { mailbox = false } = {}) {
  return {
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
    ...(mailbox
      ? { account_binding_commitment: expected.account_binding_commitment }
      : {}),
  };
}

function runtime(expected) {
  return {
    app_id: `0x${expected.target.app_id}`,
    compose_hash: expected.target.compose_hash,
    os_image_hash: expected.target.os_image_hash,
  };
}

function evidence(expected) {
  return {
    mailboxReceipt: {
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
      completed_at: 100,
      lineage: lineage(expected, { mailbox: true }),
      runtime: runtime(expected),
    },
    mailboxRetirement: {
      schema: MAIN_CVM_MAILBOX_GENESIS_RETIREMENT_SCHEMA,
      status: "retired_after_single_attempt",
      mailbox_genesis_success: true,
      retry_permitted: false,
      profile_must_remain_disabled: true,
      retired_at: 101,
      release_sha: expected.release_sha,
      genesis_authorization_sha256: expected.genesis_authorization_sha256,
      tinker_account_binding_ceremony_receipt_sha256:
        expected.tinker_account_binding_ceremony_receipt_sha256,
      account_binding_commitment: expected.account_binding_commitment,
      raw_secret_egress: false,
    },
    accountReceipt: {
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
      binding: {
        schema: TINKER_ACCOUNT_BINDING_SCHEMA,
        chain_id: Number(TINKER_ACCOUNT_BINDING_CHAIN_ID),
        provider_namespace_label: TINKER_PROVIDER_NAMESPACE_LABEL,
        provider_namespace: TINKER_PROVIDER_NAMESPACE,
        type: TINKER_ACCOUNT_BINDING_TYPE,
        typehash: TINKER_ACCOUNT_BINDING_TYPEHASH,
        commitment: expected.account_binding_commitment,
        provider_identifier_committed: false,
        attested_provider_binding_required: true,
      },
      raw_secret_egress: false,
      live_traffic_authorized: false,
      funding_authorized: false,
      independent_qvl_verified_by_profile: false,
      independent_qvl_evidence_bound: true,
      evidence_mode: "measured_runtime_pending_independent_qvl_recheck",
      completed_at: 102,
      lineage: lineage(expected),
      runtime: runtime(expected),
    },
    accountRetirement: {
      schema: MAIN_CVM_TINKER_ACCOUNT_GENESIS_RETIREMENT_SCHEMA,
      status: "retired_after_single_attempt",
      account_genesis_success: true,
      retry_permitted: false,
      profile_must_remain_disabled: true,
      retired_at: 103,
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
      raw_secret_egress: false,
    },
    handoffRetirement: {
      schema: MAIN_CVM_MAILBOX_HANDOFF_RETIREMENT_SCHEMA,
      status: "encrypted_mailbox_handoff_retired",
      account_genesis_retirement_observed: true,
      handoff_path_absent_after_directory_fsync: true,
      release_sha: expected.release_sha,
      genesis_authorization_sha256: expected.genesis_authorization_sha256,
      tinker_account_binding_ceremony_receipt_sha256:
        expected.tinker_account_binding_ceremony_receipt_sha256,
      retired_at: 104,
      raw_secret_egress: false,
    },
  };
}

export function syntheticPhalaAccountGenesisFixture() {
  const authority = signedAuthority();
  const authorityOptions = {
    checkedAt: SYNTHETIC_ACCOUNT_GENESIS_CHECKED_AT,
    expected: authorityExpected(),
    verifySignatures: fakeSignatureVerifier,
  };
  const genesisAuthorizationSha256 =
    phalaAccountGenesisActivationAuthoritySha256(
      authority,
      authorityOptions,
    );
  const expected = completionExpected(genesisAuthorizationSha256);
  const boundedEvidence = evidence(expected);
  return {
    authority,
    authorityOptions,
    authorityExpected: authorityOptions.expected,
    completionExpected: expected,
    evidence: boundedEvidence,
    completion: buildPhalaAccountGenesisCompletion({
      ...boundedEvidence,
      expected,
    }),
    target: clone(target),
  };
}
