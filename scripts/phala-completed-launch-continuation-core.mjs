import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
import {
  PHALA_EXECUTION_ORDER,
} from "./phala-production-posture-core.mjs";
import {
  normalizePhalaNonLiveBootstrapAuthorizationReceipt,
  phalaNonLiveBootstrapAuthorizationReceiptSha256,
} from "./phala-nonlive-bootstrap-authorization-core.mjs";
import {
  PHALA_SEVEN_CVM_COMPLETION_ORDER,
  PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA,
  PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_STATUS,
  PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_TRUTH,
} from "./phala-seven-cvm-launch-completion-core.mjs";

export const PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_SCHEMA =
  "dnai.phala-completed-seven-cvm-launch-continuity-receipt.v2";
export const PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_DOMAIN =
  "dnai-wikigen/phala-completed-seven-cvm-launch-continuity-receipt/v2\0";
export const PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_STATUS =
  "recorded_time_dcap_replayed_and_current_authenticated_read_only_exact_seven_cvm_continuity_reconciled";
export const PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_TRUTH =
  "signed_a_l_r_b_exact14_recorded_time_dcap_and_persisted_collateral_replay_matches_immutable_historical_L_and_current_authenticated_phala_account_info_attestation_and_signed_environment_key_observations_without_freshness_renewal_or_mutation_authority";

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const INSTANCE_TYPE = /^[a-z][a-z0-9.-]{1,63}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const ACCOUNT_FIELDS = Object.freeze([
  "account_subject_sha256",
  "call_sequence",
  "observation_sha256",
  "observed_at",
]);
const CURRENT_DOMAIN_FIELDS = Object.freeze([
  "app_id",
  "attestation_call_sequence",
  "attestation_observation_sha256",
  "attestation_observed_at",
  "attestation_response_sha256",
  "compose_hash",
  "cvm_id",
  "cvm_info_call_sequence",
  "cvm_info_observation_sha256",
  "cvm_info_observed_at",
  "disk_size",
  "domain",
  "environment_key_binding_sha256",
  "environment_key_call_sequence",
  "environment_key_observation_sha256",
  "environment_key_observed_at",
  "environment_public_key_sha256",
  "instance_type",
  "kms_id",
  "kms_type",
  "listed",
  "os_image_hash",
  "production_posture_verification_receipt_sha256",
  "public_logs",
  "public_sysinfo",
  "public_tcbinfo",
]);
const RECEIPT_DOMAIN_FIELDS = Object.freeze([...CURRENT_DOMAIN_FIELDS]);
const RECEIPT_FIELDS = Object.freeze([
  "adapter_identity_sha256",
  "all_seven_attestations_observed",
  "all_seven_current_private_postures_verified",
  "all_seven_environment_keys_signature_verified_and_unchanged",
  "automatic_retry_authorized",
  "batch_id",
  "completed_at",
  "continuity_observation_count",
  "current_account",
  "domains",
  "executor_final_state_sha256",
  "historical_evidence_refreshed",
  "historical_freshness_renewed",
  "historical_transcript_file_set_sha256",
  "launch_completion_receipt_sha256",
  "launch_completion_raw_file_sha256",
  "launch_completion_refreshed",
  "live_traffic_authorized",
  "mutation_methods_called",
  "nonlive_bootstrap_authorization_receipt_sha256",
  "post_measurement_mutation_observed",
  "persisted_intel_collateral_revalidated",
  "production_target_authority_sha256",
  "raw_quote_external_egress",
  "raw_secret_egress",
  "release_sha",
  "recorded_time_dcap_replayed",
  "schema",
  "seven_cvm_verified_evidence_set_sha256",
  "started_at",
  "status",
  "truth_status",
]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new TypeError(`${label} must contain exactly the frozen fields`);
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

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function bareSha256(value, label) {
  if (typeof value !== "string" || !BARE_SHA256.test(value)) {
    throw new TypeError(`${label} must be a nonzero bare SHA-256 digest`);
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new TypeError(`${label} must be a canonical bounded identifier`);
  }
  return value;
}

function appId(value, label) {
  const normalized = typeof value === "string"
    ? value.replace(/^0x/, "").toLowerCase()
    : "";
  if (!APP_ID.test(normalized)) {
    throw new TypeError(`${label} must be exactly 20 nonzero bytes`);
  }
  return normalized;
}

function timestamp(value, label) {
  const parsed = typeof value === "string" && ISO_SECOND.test(value)
    ? Date.parse(value)
    : Number.NaN;
  if (!Number.isFinite(parsed)
    || new Date(parsed).toISOString().replace(".000Z", "Z") !== value) {
    throw new TypeError(`${label} must be a canonical UTC second`);
  }
  return value;
}

function sequence(value, expected, label) {
  if (!Number.isSafeInteger(value) || value !== expected) {
    throw new TypeError(`${label} must equal authenticated call sequence ${expected}`);
  }
  return value;
}

function exactLaunchShape(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "immutable historical seven-CVM launch receipt",
  });
  if (!isRecord(value)
    || value.schema !== PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA
    || value.status !== PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_STATUS
    || value.truth_status !== PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_TRUTH
    || value.commit_count !== 7
    || value.all_seven_committed !== true
    || value.all_seven_production_posture_validated !== true
    || value.all_seven_machine_verified !== true
    || value.live_traffic_authorized !== false
    || value.late_secret_activation_authorized !== false
    || value.compute_workload_recipient_activation_authorized !== false
    || value.raw_quote_external_egress !== false
    || value.raw_private_artifact_egress !== false
    || value.raw_secret_egress !== false
    || JSON.stringify(value.completion_order)
      !== JSON.stringify(PHALA_SEVEN_CVM_COMPLETION_ORDER)
    || JSON.stringify(value.mutation_order)
      !== JSON.stringify(PHALA_EXECUTION_ORDER)
    || !Array.isArray(value.domains) || value.domains.length !== 7) {
    throw new TypeError("immutable historical L is incomplete or has an invalid truth boundary");
  }
  const byDomain = new Map(value.domains.map((entry) => [entry?.domain, entry]));
  if (byDomain.size !== 7
    || PHALA_SEVEN_CVM_COMPLETION_ORDER.some((domain) => !byDomain.has(domain))) {
    throw new TypeError("immutable historical L omits, duplicates, or reorders a CVM domain");
  }
  return { launch: value, byDomain };
}

function exactCompletedJournal(value) {
  assertCanonicalPlainDataGraph(value, { label: "completed production recovery journal" });
  const journal = exactRecord(value, [
    "automatic_cleanup_authorized",
    "automatic_retry_authorized",
    "batch_id",
    "schema",
    "seven_commit_batch_is_atomic",
    "state",
    "state_sha256",
    "truth_status",
  ], "completed production recovery journal");
  if (journal.schema !== "dnai.phala-production-recovery-journal.v2"
    || journal.truth_status
      !== "private_recovery_metadata_no_secrets_ciphertext_or_phala_atomicity_claim"
    || journal.seven_commit_batch_is_atomic !== false
    || journal.automatic_retry_authorized !== false
    || journal.automatic_cleanup_authorized !== false) {
    throw new TypeError("production recovery journal truth boundary is invalid");
  }
  const state = normalizeCompletedPhalaExecutorState(journal.state);
  const stateSha256 = phalaExecutorStateDigest(state);
  if (journal.batch_id !== state.batch_id || journal.state_sha256 !== stateSha256) {
    throw new TypeError("completed production recovery journal digest or batch drifted");
  }
  return { journal, state, stateSha256 };
}

function normalizeCurrentAccount(value, startedMs, completedMs) {
  const parsed = exactRecord(value, ACCOUNT_FIELDS, "current Phala account reconciliation");
  const observedAt = timestamp(parsed.observed_at, "current account observed_at");
  const observedMs = Date.parse(observedAt);
  if (observedMs < startedMs || observedMs > completedMs) {
    throw new TypeError("current account observation is outside the continuity window");
  }
  return {
    account_subject_sha256: sha256(
      parsed.account_subject_sha256,
      "current authenticated account subject",
    ),
    call_sequence: sequence(parsed.call_sequence, 1, "current account"),
    observation_sha256: sha256(
      parsed.observation_sha256,
      "current account observation",
    ),
    observed_at: observedAt,
  };
}

function normalizeCurrentDomain(value, domain, index, historical, stateBinding,
  startedMs, completedMs) {
  const parsed = exactRecord(
    value,
    CURRENT_DOMAIN_FIELDS,
    `${domain} current continuity reconciliation`,
  );
  const firstSequence = 2 + index * 3;
  const times = {
    cvm_info_observed_at: timestamp(
      parsed.cvm_info_observed_at,
      `${domain} CVM-info observed_at`,
    ),
    attestation_observed_at: timestamp(
      parsed.attestation_observed_at,
      `${domain} attestation observed_at`,
    ),
    environment_key_observed_at: timestamp(
      parsed.environment_key_observed_at,
      `${domain} environment-key observed_at`,
    ),
  };
  const milliseconds = Object.values(times).map(Date.parse);
  if (milliseconds.some((time) => time < startedMs || time > completedMs)
    || milliseconds[1] < milliseconds[0] || milliseconds[2] < milliseconds[1]) {
    throw new TypeError(`${domain} current observations are outside or reorder the continuity window`);
  }
  const normalized = {
    domain,
    app_id: appId(parsed.app_id, `${domain} current app ID`),
    cvm_id: identifier(parsed.cvm_id, `${domain} current CVM ID`),
    compose_hash: bareSha256(parsed.compose_hash, `${domain} current compose hash`),
    kms_id: identifier(parsed.kms_id, `${domain} current KMS ID`),
    instance_type: typeof parsed.instance_type === "string"
      && INSTANCE_TYPE.test(parsed.instance_type)
      ? parsed.instance_type
      : (() => { throw new TypeError(`${domain} current instance type is invalid`); })(),
    disk_size: parsed.disk_size,
    os_image_hash: bareSha256(parsed.os_image_hash, `${domain} current OS image`),
    kms_type: parsed.kms_type,
    listed: parsed.listed,
    public_logs: parsed.public_logs,
    public_sysinfo: parsed.public_sysinfo,
    public_tcbinfo: parsed.public_tcbinfo,
    cvm_info_call_sequence: sequence(
      parsed.cvm_info_call_sequence,
      firstSequence,
      `${domain} CVM-info`,
    ),
    cvm_info_observation_sha256: sha256(
      parsed.cvm_info_observation_sha256,
      `${domain} CVM-info observation`,
    ),
    ...times,
    production_posture_verification_receipt_sha256: sha256(
      parsed.production_posture_verification_receipt_sha256,
      `${domain} current posture receipt`,
    ),
    attestation_call_sequence: sequence(
      parsed.attestation_call_sequence,
      firstSequence + 1,
      `${domain} attestation`,
    ),
    attestation_observation_sha256: sha256(
      parsed.attestation_observation_sha256,
      `${domain} attestation observation`,
    ),
    attestation_response_sha256: sha256(
      parsed.attestation_response_sha256,
      `${domain} attestation response`,
    ),
    environment_key_call_sequence: sequence(
      parsed.environment_key_call_sequence,
      firstSequence + 2,
      `${domain} environment key`,
    ),
    environment_key_observation_sha256: sha256(
      parsed.environment_key_observation_sha256,
      `${domain} environment-key observation`,
    ),
    environment_key_binding_sha256: sha256(
      parsed.environment_key_binding_sha256,
      `${domain} environment-key binding`,
    ),
    environment_public_key_sha256: sha256(
      parsed.environment_public_key_sha256,
      `${domain} environment public key`,
    ),
  };
  if (!Number.isSafeInteger(normalized.disk_size)
    || normalized.disk_size < 20 || normalized.disk_size > 16_384
    || normalized.os_image_hash !== PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash
    || normalized.kms_type !== "phala"
    || normalized.listed !== false
    || normalized.public_logs !== false
    || normalized.public_sysinfo !== false
    || normalized.public_tcbinfo !== false) {
    throw new TypeError(`${domain} current private production posture is invalid`);
  }
  for (const [currentField, historicalField] of [
    ["app_id", "app_id"],
    ["cvm_id", "cvm_id"],
    ["compose_hash", "committed_compose_hash"],
    ["kms_id", "kms_id"],
    ["instance_type", "instance_type"],
    ["disk_size", "disk_size"],
    ["os_image_hash", "os_image_hash"],
  ]) {
    if (normalized[currentField] !== historical[historicalField]) {
      throw new TypeError(`${domain} current ${currentField} drifted from immutable historical L`);
    }
  }
  if (normalized.environment_key_binding_sha256 !== stateBinding.binding_sha256
    || normalized.environment_public_key_sha256
      !== stateBinding.public_key_sha256) {
    throw new TypeError(`${domain} current signed environment key drifted from the completed journal`);
  }
  return normalized;
}

function normalizeHistoricalEvidence(value, launch, launchSha256) {
  assertCanonicalPlainDataGraph(value, {
    label: "historical seven-CVM evidence reconstruction",
  });
  const parsed = exactRecord(value, [
    "all_seven_recorded_time_dcap_replayed",
    "freshness_renewed",
    "historical_transcript_file_set_sha256",
    "launch_completion_receipt_sha256",
    "live_traffic_authorized",
    "persisted_intel_collateral_revalidated",
    "production_live_brand_minted",
    "raw_collateral_publicly_disclosed",
    "raw_quote_publicly_disclosed",
    "raw_secret_egress",
    "release_verification_authority_sha256",
    "schema",
    "seven_cvm_verified_evidence_set_sha256",
    "truth_status",
    "workload_eip191_signatures_replayed",
  ], "recorded-time historical seven-CVM replay summary");
  if (parsed.schema !== "dnai.phala-seven-cvm-recorded-time-dcap-replay.v1"
    || parsed.truth_status
      !== "signed_a_l_r_b_authority_exact14_protocol_signatures_recorded_time_dcap_and_persisted_intel_collateral_replayed_without_freshness_renewal_or_live_authority"
    || parsed.all_seven_recorded_time_dcap_replayed !== true
    || parsed.persisted_intel_collateral_revalidated !== true
    || parsed.workload_eip191_signatures_replayed !== true
    || parsed.freshness_renewed !== false
    || parsed.production_live_brand_minted !== false
    || parsed.live_traffic_authorized !== false
    || parsed.raw_quote_publicly_disclosed !== false
    || parsed.raw_collateral_publicly_disclosed !== false
    || parsed.raw_secret_egress !== false
    || parsed.launch_completion_receipt_sha256
      !== launchSha256
    || parsed.release_verification_authority_sha256
      !== launch.release_verification_authority_sha256
    || parsed.seven_cvm_verified_evidence_set_sha256
      !== launch.machine_verifier_evidence_set_sha256
    || parsed.historical_transcript_file_set_sha256
      !== launch.historical_transcript_file_set_sha256) {
    throw new TypeError(
      "recorded-time historical seven-CVM replay differs from immutable L or refreshes authority",
    );
  }
  return parsed;
}

function mutationTimes(state, launchByDomain) {
  const values = [];
  for (const [kind, entries, prefix] of [
    ["provision", state.preparations, "provision"],
    ["commit", state.committed_prefix, "commit"],
  ]) {
    for (const entry of entries) {
      const historical = launchByDomain.get(entry.domain);
      for (const suffix of ["attempted_at", "observed_at"]) {
        const field = `${prefix}_${suffix}`;
        if (entry[suffix] !== historical[field]) {
          throw new TypeError(
            `${entry.domain} ${kind} chronology drifted between the completed journal and immutable L`,
          );
        }
        values.push({ domain: entry.domain, field, value: entry[suffix] });
      }
    }
  }
  return values;
}

export function createPhalaCompletedLaunchContinuityReceipt(input = {}) {
  assertCanonicalPlainDataGraph(input, {
    label: "completed seven-CVM launch continuity input",
  });
  const parsed = exactRecord(input, [
    "adapterIdentitySha256",
    "completedAt",
    "completedJournal",
    "currentAccount",
    "currentDomains",
    "historicalEvidenceReconstruction",
    "launchCompletionReceipt",
    "launchCompletionReceiptSha256",
    "launchCompletionRawFileSha256",
    "signedAReceipt",
    "startedAt",
  ], "completed seven-CVM launch continuity input");
  const startedAt = timestamp(parsed.startedAt, "continuity started_at");
  const completedAt = timestamp(parsed.completedAt, "continuity completed_at");
  const startedMs = Date.parse(startedAt);
  const completedMs = Date.parse(completedAt);
  if (completedMs < startedMs || completedMs - startedMs > 5 * 60_000) {
    throw new TypeError("current continuity observation window is reordered or unbounded");
  }
  const { state, stateSha256 } = exactCompletedJournal(parsed.completedJournal);
  const { launch, byDomain: launchByDomain } = exactLaunchShape(
    parsed.launchCompletionReceipt,
  );
  const launchSha256 = sha256(
    parsed.launchCompletionReceiptSha256,
    "immutable historical L",
  );
  const signedA = normalizePhalaNonLiveBootstrapAuthorizationReceipt(
    parsed.signedAReceipt,
  );
  const signedASha256 = phalaNonLiveBootstrapAuthorizationReceiptSha256(signedA);
  const historicalEvidence = normalizeHistoricalEvidence(
    parsed.historicalEvidenceReconstruction,
    launch,
    launchSha256,
  );
  if (launch.executor_final_state_sha256 !== stateSha256
    || launch.release_sha !== state.release_sha
    || launch.batch_id !== state.batch_id
    || launch.bootstrap_authorization_id !== state.bootstrap_authorization_id
    || launch.cvm_launch_intent_sha256 !== state.launch_intent_sha256
    || launch.production_target_authority_sha256
      !== state.target_authority_sha256
    || launch.phala_recovery_directory_identity_anchor_sha256
      !== state.phala_recovery_directory_identity_anchor_sha256
    || launch.nonlive_bootstrap_authorization_receipt_sha256 !== signedASha256
    || state.bootstrap_authorization_receipt_sha256 !== signedASha256
    || signedA.authorization_id !== state.bootstrap_authorization_id
    || signedA.batch_id !== state.batch_id
    || signedA.release_sha !== state.release_sha
    || signedA.cvm_launch_intent_sha256 !== state.launch_intent_sha256
    || signedA.production_target_authority_sha256
      !== state.target_authority_sha256) {
    throw new TypeError("completed journal, historical signed A, and immutable L do not share one lineage");
  }
  const issuedMs = Date.parse(signedA.issued_at);
  const expiresMs = Date.parse(signedA.expires_at);
  for (const entry of mutationTimes(state, launchByDomain)) {
    const time = Date.parse(entry.value);
    if (time < issuedMs || time >= expiresMs) {
      throw new TypeError(
        `${entry.domain} ${entry.field} was outside original historical signed A`,
      );
    }
  }
  const currentAccount = normalizeCurrentAccount(
    parsed.currentAccount,
    startedMs,
    completedMs,
  );
  if (!Array.isArray(parsed.currentDomains) || parsed.currentDomains.length !== 7) {
    throw new TypeError("current continuity requires exactly seven domain observations");
  }
  const signedKeyByDomain = new Map(
    state.signed_key_bindings.map((entry) => [entry.domain, entry]),
  );
  const currentInputByDomain = new Map(
    parsed.currentDomains.map((entry) => [entry?.domain, entry]),
  );
  if (currentInputByDomain.size !== 7
    || PHALA_EXECUTION_ORDER.some((domain) => !currentInputByDomain.has(domain))) {
    throw new TypeError("current continuity domains are omitted or duplicated");
  }
  const domains = PHALA_EXECUTION_ORDER.map((domain, index) => (
    normalizeCurrentDomain(
      currentInputByDomain.get(domain),
      domain,
      index,
      launchByDomain.get(domain),
      signedKeyByDomain.get(domain),
      startedMs,
      completedMs,
    )
  ));
  if (new Set(domains.map(({ app_id: value }) => value)).size !== 7
    || new Set(domains.map(({ cvm_id: value }) => value)).size !== 7
    || new Set(domains.map(({ environment_public_key_sha256: value }) => value))
      .size !== 7) {
    throw new TypeError("current app, CVM, and signed environment keys must remain pairwise distinct");
  }
  const receipt = {
    schema: PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_SCHEMA,
    status: PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_STATUS,
    truth_status: PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_TRUTH,
    release_sha: state.release_sha,
    batch_id: state.batch_id,
    executor_final_state_sha256: stateSha256,
    launch_completion_receipt_sha256: launchSha256,
    launch_completion_raw_file_sha256: sha256(
      parsed.launchCompletionRawFileSha256,
      "immutable historical L raw file",
    ),
    nonlive_bootstrap_authorization_receipt_sha256: signedASha256,
    production_target_authority_sha256: state.target_authority_sha256,
    seven_cvm_verified_evidence_set_sha256:
      historicalEvidence.seven_cvm_verified_evidence_set_sha256,
    historical_transcript_file_set_sha256:
      historicalEvidence.historical_transcript_file_set_sha256,
    adapter_identity_sha256: sha256(
      parsed.adapterIdentitySha256,
      "current read-only adapter identity",
    ),
    started_at: startedAt,
    completed_at: completedAt,
    current_account: currentAccount,
    domains,
    continuity_observation_count: 1 + domains.length * 3,
    all_seven_current_private_postures_verified: true,
    all_seven_attestations_observed: true,
    all_seven_environment_keys_signature_verified_and_unchanged: true,
    mutation_methods_called: false,
    launch_completion_refreshed: false,
    historical_evidence_refreshed: false,
    historical_freshness_renewed: false,
    post_measurement_mutation_observed: false,
    recorded_time_dcap_replayed: true,
    persisted_intel_collateral_revalidated: true,
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
    raw_quote_external_egress: false,
    raw_secret_egress: false,
  };
  return normalizePhalaCompletedLaunchContinuityReceipt(receipt);
}

export function normalizePhalaCompletedLaunchContinuityReceipt(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "completed seven-CVM launch continuity receipt",
  });
  const parsed = exactRecord(
    value,
    RECEIPT_FIELDS,
    "completed seven-CVM launch continuity receipt",
  );
  if (parsed.schema !== PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_SCHEMA
    || parsed.status !== PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_STATUS
    || parsed.truth_status !== PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_TRUTH
    || parsed.continuity_observation_count !== 22
    || parsed.all_seven_current_private_postures_verified !== true
    || parsed.all_seven_attestations_observed !== true
    || parsed.all_seven_environment_keys_signature_verified_and_unchanged !== true
    || parsed.mutation_methods_called !== false
    || parsed.launch_completion_refreshed !== false
    || parsed.historical_evidence_refreshed !== false
    || parsed.historical_freshness_renewed !== false
    || parsed.post_measurement_mutation_observed !== false
    || parsed.recorded_time_dcap_replayed !== true
    || parsed.persisted_intel_collateral_revalidated !== true
    || parsed.automatic_retry_authorized !== false
    || parsed.live_traffic_authorized !== false
    || parsed.raw_quote_external_egress !== false
    || parsed.raw_secret_egress !== false
    || !Array.isArray(parsed.domains) || parsed.domains.length !== 7) {
    throw new TypeError("completed-launch continuity receipt truth boundary is invalid");
  }
  const startedAt = timestamp(parsed.started_at, "continuity receipt started_at");
  const completedAt = timestamp(parsed.completed_at, "continuity receipt completed_at");
  if (Date.parse(completedAt) < Date.parse(startedAt)
    || Date.parse(completedAt) - Date.parse(startedAt) > 5 * 60_000) {
    throw new TypeError("continuity receipt observation window is invalid");
  }
  const currentAccount = normalizeCurrentAccount(
    parsed.current_account,
    Date.parse(startedAt),
    Date.parse(completedAt),
  );
  const domains = parsed.domains.map((entry, index) => {
    const raw = exactRecord(
      entry,
      RECEIPT_DOMAIN_FIELDS,
      `continuity receipt domain ${index}`,
    );
    const domain = PHALA_EXECUTION_ORDER[index];
    if (raw.domain !== domain) {
      throw new TypeError("continuity receipt domains are reordered or substituted");
    }
    // Standalone normalization is a security boundary too: a caller must not
    // be able to edit a sequence, timestamp, resource, privacy flag,
    // observation digest, or key binding and legitimize it by recomputing the
    // outer receipt digest. Reuse the creation-time field validator against a
    // self-identical historical projection; the original L comparison remains
    // the stronger check performed by the creator.
    return normalizeCurrentDomain(
      raw,
      domain,
      index,
      {
        app_id: raw.app_id,
        cvm_id: raw.cvm_id,
        committed_compose_hash: raw.compose_hash,
        kms_id: raw.kms_id,
        instance_type: raw.instance_type,
        disk_size: raw.disk_size,
        os_image_hash: raw.os_image_hash,
      },
      {
        binding_sha256: raw.environment_key_binding_sha256,
        public_key_sha256: raw.environment_public_key_sha256,
      },
      Date.parse(startedAt),
      Date.parse(completedAt),
    );
  });
  if (new Set(domains.map(({ app_id: value }) => value)).size !== 7
    || new Set(domains.map(({ cvm_id: value }) => value)).size !== 7
    || new Set(domains.map(({ environment_public_key_sha256: value }) => value))
      .size !== 7) {
    throw new TypeError(
      "continuity receipt app, CVM, and environment keys must be pairwise distinct",
    );
  }
  if (typeof parsed.release_sha !== "string"
    || !/^(?!0{40}$)[0-9a-f]{40}$/.test(parsed.release_sha)) {
    throw new TypeError("continuity receipt release_sha must be one exact nonzero git SHA");
  }
  sha256(parsed.batch_id, "continuity receipt batch_id");
  for (const field of [
    "executor_final_state_sha256",
    "launch_completion_receipt_sha256",
    "launch_completion_raw_file_sha256",
    "nonlive_bootstrap_authorization_receipt_sha256",
    "production_target_authority_sha256",
    "seven_cvm_verified_evidence_set_sha256",
    "historical_transcript_file_set_sha256",
    "adapter_identity_sha256",
  ]) sha256(parsed[field], `continuity receipt ${field}`);
  const normalized = {
    ...parsed,
    started_at: startedAt,
    completed_at: completedAt,
    current_account: currentAccount,
    domains,
  };
  return deepFreezeCanonicalPlainDataGraph(normalized, {
    label: "normalized completed-launch continuity receipt",
  });
}

export function canonicalPhalaCompletedLaunchContinuityReceiptText(value) {
  return canonicalText(normalizePhalaCompletedLaunchContinuityReceipt(value));
}

export function phalaCompletedLaunchContinuityReceiptSha256(value) {
  return `sha256:${createHash("sha256")
    .update(PHALA_COMPLETED_LAUNCH_CONTINUITY_RECEIPT_DOMAIN, "utf8")
    .update(canonicalPhalaCompletedLaunchContinuityReceiptText(value), "utf8")
    .digest("hex")}`;
}
