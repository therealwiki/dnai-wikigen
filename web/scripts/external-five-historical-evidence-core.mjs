import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "../../scripts/canonical-authority-graph.mjs";

export const EXTERNAL_FIVE_EVIDENCE_FLAGS = Object.freeze([
  "--ledger",
  "--artifact-evidence",
  "--arena-evidence",
  "--anchor-writer-evidence",
  "--email-oracle-evidence",
]);

export const EXTERNAL_FIVE_HISTORICAL_EVIDENCE_SCHEMA =
  "dnai.external-five-historical-evidence-boundary.v2";
export const EXTERNAL_FIVE_HISTORICAL_EVIDENCE_STATUS =
  "historical_bytes_lineage_schemas_and_v4_qvl_verdict_signatures_authenticated_current_observations_pending";
export const EXTERNAL_FIVE_HISTORICAL_EVIDENCE_TRUTH_STATUS =
  "signed_C_to_D_raw_bytes_v4_verdict_signatures_and_recorded_window_relations_checked_without_claiming_challenge_signature_raw_quote_consumption_freshness_chain_KMS_or_restart_observation";

const BASE_SEPOLIA_CHAIN_ID = 84_532;
const VERDICT_SCHEMA = "dnai.independent-tdx-verdict.v4";
const VERIFICATION_METHOD = "intel_tdx_dcap_qvl";
const VERDICT_DOMAIN = Buffer.from(
  "dnai-wikigen/independent-tdx-verdict/v4\0",
  "utf8",
);
const ACTIVATION_EVIDENCE_LEASE_SECONDS = 900;
const HISTORICAL_QVL_AUTHORITY_SCHEMA =
  "dnai.external-five-historical-qvl-authority.v1";
const HISTORICAL_QVL_AUTHORITY_TRUTH_STATUS =
  "historical_raw14_QVL_identity_projection_not_current_QVL_or_freshness_authority";
const HISTORICAL_QVL_DOMAIN_ORDER = Object.freeze([
  "diligence_qvl_cvm",
  "arena_qvl_cvm",
  "anchor_writer_qvl_cvm",
  "compute_workload_qvl_cvm",
  "compute_metering_qvl_cvm",
]);
const CANDIDATE_QVL_KEY_BY_HISTORICAL_DOMAIN = Object.freeze({
  diligence_qvl_cvm: "diligence_qvl",
  arena_qvl_cvm: "arena_qvl",
  anchor_writer_qvl_cvm: "anchor_writer_qvl",
  compute_workload_qvl_cvm: "compute_workload_qvl",
  compute_metering_qvl_cvm: "compute_metering_qvl",
});
const ANCHOR_EVIDENCE_SCHEMA =
  "dnai.execution-policy-anchor-writer-qvl-evidence.v2";
const ANCHOR_REPORT_DATA_SCHEMA =
  "dnai.execution-policy-anchor-writer-qvl-evidence.v1";
const ANCHOR_REPORT_DATA_DOMAIN = Buffer.from(
  "dnai-wikigen/execution-policy-anchor-writer-evidence/v1\0",
  "utf8",
);
const ANCHOR_KEY_PATH = "tinker/execution_policy_anchor_writer";
const ANCHOR_KEY_CUSTODY =
  "dstack_derived_execution_policy_anchor_writer";
const ANCHOR_KEY_PATH_DOMAIN = Buffer.from(
  "dnai-wikigen/execution-policy-anchor-writer-key-path/v1\0",
  "utf8",
);
const EMAIL_EVIDENCE_SCHEMA =
  "dnai.email-oracle-external-release-evidence.v1";
const EMAIL_REPORT_DATA_DOMAIN = Buffer.from(
  "dnai-wikigen/email-oracle-kms-restart-attestation/v1\0",
  "utf8",
);
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const BARE_BYTES32 = /^(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const CANONICAL_SIGNATURE = /^0x[0-9a-f]{130}$/;
const SECP256K1_N = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
);
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024;
const MAX_BYTES_BY_EXTERNAL_FLAG = Object.freeze({
  "--ledger": MAX_EVIDENCE_BYTES,
  "--artifact-evidence": 64 * 1024,
  "--arena-evidence": 64 * 1024,
  "--anchor-writer-evidence": 64 * 1024,
  "--email-oracle-evidence": 64 * 1024,
});
const EXACT37_KEY_BY_EXTERNAL_FLAG = Object.freeze({
  "--ledger": "ledger",
  "--artifact-evidence": "artifactEvidence",
  "--arena-evidence": "arenaEvidence",
  "--anchor-writer-evidence": "anchorWriterEvidence",
  "--email-oracle-evidence": "emailOracleEvidence",
});

function fail(message) {
  throw new TypeError(message);
}

function exact(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must contain exactly the canonical fields`);
  }
  const prototype = Object.getPrototypeOf(value);
  const keys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if ((prototype !== Object.prototype && prototype !== null)
    || keys.some((key) => typeof key !== "string")
    || JSON.stringify(keys.sort()) !== JSON.stringify([...fields].sort())
    || Object.values(descriptors).some((descriptor) => (
      !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true
    ))) {
    fail(`${label} must contain exactly the canonical fields`);
  }
  return value;
}

function record(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be a record`);
  }
  return value;
}

function integer(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be a bounded integer`);
  }
  return value;
}

function digest(value, label) {
  if (!SHA256.test(String(value || ""))) fail(`${label} is not a nonzero SHA-256 pin`);
  return value;
}

function bytes32(value, label, { allowZero = false } = {}) {
  if (!BYTES32.test(String(value || "")) || (!allowZero && value === ZERO_BYTES32)) {
    fail(`${label} is not a canonical bytes32 value`);
  }
  return value;
}

function bareBytes32(value, label) {
  if (!BARE_BYTES32.test(String(value || ""))) {
    fail(`${label} is not a canonical bare bytes32 value`);
  }
  return value;
}

function address(value, label) {
  if (!ADDRESS.test(String(value || ""))) fail(`${label} is not a nonzero lowercase address`);
  return value;
}

function canonicalJson(value) {
  const normalize = (entry) => {
    if (Array.isArray(entry)) return entry.map(normalize);
    if (entry && typeof entry === "object") {
      return Object.fromEntries(
        Object.keys(entry).sort().map((key) => [key, normalize(entry[key])]),
      );
    }
    return entry;
  };
  return JSON.stringify(normalize(value));
}

function prettyBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function hashDomainJson(domain, value) {
  return `0x${createHash("sha256")
    .update(domain)
    .update(Buffer.from(canonicalJson(value), "ascii"))
    .digest("hex")}`;
}

function isoSecond(value, label) {
  if (typeof value !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$/.test(value)) {
    fail(`${label} must be canonical UTC whole-second precision`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isSafeInteger(milliseconds)
    || milliseconds % 1_000 !== 0) {
    fail(`${label} must be a real canonical timestamp`);
  }
  const canonicalMilliseconds = new Date(milliseconds).toISOString();
  if (value !== canonicalMilliseconds) {
    fail(`${label} must be a real canonical timestamp`);
  }
  return milliseconds / 1_000;
}

function same(actual, expected, label) {
  if (actual !== expected) fail(`${label} drifted`);
}

function canonicalSignature(value, label) {
  if (!CANONICAL_SIGNATURE.test(String(value || ""))) {
    fail(`${label} is not a canonical lowercase 65-byte signature`);
  }
  const raw = Buffer.from(value.slice(2), "hex");
  const r = BigInt(`0x${raw.subarray(0, 32).toString("hex")}`);
  const s = BigInt(`0x${raw.subarray(32, 64).toString("hex")}`);
  const v = raw[64];
  if (r < 1n || r >= SECP256K1_N || s < 1n || s > SECP256K1_N / 2n
    || (v !== 27 && v !== 28)) {
    fail(`${label} is not canonical low-s Ethereum ECDSA`);
  }
  return value;
}

function normalizeFiles(value) {
  if (!Array.isArray(value) || value.length !== EXTERNAL_FIVE_EVIDENCE_FLAGS.length) {
    fail("external-five evidence requires exactly five files");
  }
  const normalized = value.map((entry, index) => {
    const parsed = exact(
      entry,
      ["byteLength", "flag", "rawSha256", "value"],
      `external-five file ${index}`,
    );
    const expectedFlag = EXTERNAL_FIVE_EVIDENCE_FLAGS[index];
    if (parsed.flag !== expectedFlag) fail(`external-five file ${index} must be ${expectedFlag}`);
    assertCanonicalPlainDataGraph(parsed.value, { label: `${expectedFlag} value` });
    const bytes = prettyBytes(parsed.value);
    if (bytes.length < 2 || bytes.length > MAX_BYTES_BY_EXTERNAL_FLAG[expectedFlag]
      || parsed.byteLength !== bytes.length
      || digest(parsed.rawSha256, `${expectedFlag} raw digest`) !== sha256(bytes)) {
      fail(`${expectedFlag} canonical bytes do not match their carried size and digest`);
    }
    return [expectedFlag, Object.freeze({
      flag: expectedFlag,
      byteLength: bytes.length,
      rawSha256: parsed.rawSha256,
      value: parsed.value,
    })];
  });
  if (new Set(normalized.map(([, entry]) => entry.rawSha256)).size
      !== EXTERNAL_FIVE_EVIDENCE_FLAGS.length) {
    fail("external-five files must have pairwise-distinct canonical bytes");
  }
  return Object.fromEntries(normalized);
}

export function projectExternalFiveEvidenceFilesFromExact37ByKey(byKey) {
  record(byKey, "exact-37 by-key input projection");
  return EXTERNAL_FIVE_EVIDENCE_FLAGS.map((flag) => {
    const key = EXACT37_KEY_BY_EXTERNAL_FLAG[flag];
    const entry = record(byKey[key], `exact-37 ${flag} entry`);
    const projected = {
      flag,
      byteLength: entry.byteLength,
      rawSha256: entry.rawSha256,
      value: entry.value,
    };
    assertCanonicalPlainDataGraph(projected, {
      label: `exact-37 ${flag} byte identity`,
    });
    return projected;
  });
}

function normalizeHistoricalQvlAuthority(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "external-five historical QVL authority",
  });
  const parsed = exact(value, [
    "activation_evidence_lease_seconds",
    "current_clock_consulted",
    "identities",
    "live_traffic_authorized",
    "schema",
    "truth_status",
  ], "external-five historical QVL authority");
  if (parsed.schema !== HISTORICAL_QVL_AUTHORITY_SCHEMA
    || parsed.truth_status !== HISTORICAL_QVL_AUTHORITY_TRUTH_STATUS
    || parsed.activation_evidence_lease_seconds
      !== ACTIVATION_EVIDENCE_LEASE_SECONDS
    || parsed.current_clock_consulted !== false
    || parsed.live_traffic_authorized !== false
    || !Array.isArray(parsed.identities)
    || parsed.identities.length !== HISTORICAL_QVL_DOMAIN_ORDER.length) {
    fail("external-five historical QVL authority shape or truth boundary is invalid");
  }
  const identities = parsed.identities.map((valueEntry, index) => {
    const entry = exact(valueEntry, [
      "activation_evidence_lease_expires_at",
      "ceremony_nonce",
      "deployment_intent_sha256",
      "domain",
      "measurement_policy_sha256",
      "release_authority_sha256",
      "release_policy_sha256",
      "verifier_address",
    ], `external-five historical QVL identity ${index}`);
    const expectedDomain = HISTORICAL_QVL_DOMAIN_ORDER[index];
    if (entry.domain !== expectedDomain) {
      fail(`external-five historical QVL identity ${index} must be ${expectedDomain}`);
    }
    return Object.freeze({
      domain: expectedDomain,
      deployment_intent_sha256: digest(
        entry.deployment_intent_sha256,
        `${expectedDomain} historical deployment intent`,
      ),
      release_authority_sha256: digest(
        entry.release_authority_sha256,
        `${expectedDomain} historical release authority`,
      ),
      ceremony_nonce: bytes32(
        entry.ceremony_nonce,
        `${expectedDomain} historical ceremony nonce`,
      ),
      measurement_policy_sha256: digest(
        entry.measurement_policy_sha256,
        `${expectedDomain} historical measurement policy`,
      ),
      release_policy_sha256: digest(
        entry.release_policy_sha256,
        `${expectedDomain} historical release policy`,
      ),
      verifier_address: address(
        entry.verifier_address,
        `${expectedDomain} historical verifier`,
      ),
      activation_evidence_lease_expires_at: integer(
        entry.activation_evidence_lease_expires_at,
        `${expectedDomain} historical activation evidence lease expiry`,
        1,
        4_102_444_800,
      ),
    });
  });
  for (const field of [
    "measurement_policy_sha256",
    "release_policy_sha256",
    "verifier_address",
  ]) {
    if (new Set(identities.map((entry) => entry[field])).size !== identities.length) {
      fail(`external-five historical QVL ${field} values must be distinct`);
    }
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: HISTORICAL_QVL_AUTHORITY_SCHEMA,
    truth_status: HISTORICAL_QVL_AUTHORITY_TRUTH_STATUS,
    activation_evidence_lease_seconds: ACTIVATION_EVIDENCE_LEASE_SECONDS,
    identities,
    current_clock_consulted: false,
    live_traffic_authorized: false,
  }, { label: "normalized external-five historical QVL authority" });
}

export function projectExternalFiveHistoricalQvlAuthority({
  qvlIdentityEvidence,
  activationEvidenceLeaseSeconds,
} = {}) {
  assertCanonicalPlainDataGraph(qvlIdentityEvidence, {
    label: "external-five reconstructed QVL identity evidence",
  });
  if (!Array.isArray(qvlIdentityEvidence)
    || qvlIdentityEvidence.length !== HISTORICAL_QVL_DOMAIN_ORDER.length
    || activationEvidenceLeaseSeconds !== ACTIVATION_EVIDENCE_LEASE_SECONDS) {
    fail("external-five requires the exact reconstructed five-QVL historical authority");
  }
  const identities = HISTORICAL_QVL_DOMAIN_ORDER.map((domain) => {
    const matches = qvlIdentityEvidence.filter((entry) => entry?.domain === domain);
    if (matches.length !== 1) {
      fail(`external-five reconstructed QVL authority must contain ${domain} exactly once`);
    }
    const proof = record(matches[0], `${domain} reconstructed QVL identity proof`);
    return {
      domain,
      deployment_intent_sha256: proof.deployment_intent_sha256,
      release_authority_sha256: proof.release_authority_sha256,
      ceremony_nonce: proof.ceremony_nonce,
      measurement_policy_sha256: proof.measurement_policy_sha256,
      release_policy_sha256: proof.release_policy_sha256,
      verifier_address: proof.tee_identity,
      activation_evidence_lease_expires_at:
        proof.activation_evidence_lease_expires_at,
    };
  });
  return normalizeHistoricalQvlAuthority({
    schema: HISTORICAL_QVL_AUTHORITY_SCHEMA,
    truth_status: HISTORICAL_QVL_AUTHORITY_TRUTH_STATUS,
    activation_evidence_lease_seconds: activationEvidenceLeaseSeconds,
    identities,
    current_clock_consulted: false,
    live_traffic_authorized: false,
  });
}

function findPrivateInput(manifest, flag) {
  if (!Array.isArray(manifest.pre_D_private_inputs)) {
    fail("frontend D manifest omits its private input list");
  }
  const matches = manifest.pre_D_private_inputs.filter((entry) => entry?.flag === flag);
  if (matches.length !== 1) fail(`frontend D manifest must commit ${flag} exactly once`);
  const input = exact(matches[0], ["flag", "projection", "sha256"], `frontend D ${flag} input`);
  if (input.projection !== "raw_canonical_file_bytes") {
    fail(`frontend D ${flag} input is not a raw-byte commitment`);
  }
  return digest(input.sha256, `frontend D ${flag} digest`);
}

function validateAuthorityLineage({
  files,
  releaseCandidate,
  ceremonyAuthorization,
  computeWorkloadActivationObservation,
  frontendBuildInputManifest,
  frontendBuildCandidateReceipt,
  liveActivationAuthority,
  authorityDigests,
}) {
  const roots = exact(authorityDigests, [
    "ceremonyAuthorizationSha256",
    "ceremonyNonce",
    "computeWorkloadActivationObservationSha256",
    "frontendBuildCandidateReceiptSha256",
    "frontendBuildInputManifestSha256",
    "liveActivationAuthoritySha256",
    "releaseVerificationAuthoritySha256",
    "runtimeAuthorityDependencySha256",
  ], "external-five authority digests");
  for (const [key, value] of Object.entries(roots)) {
    if (key === "ceremonyNonce") bytes32(value, "external-five ceremony nonce");
    else digest(value, `external-five ${key}`);
  }
  const releaseSha = String(releaseCandidate.release_sha || "");
  if (!RELEASE_SHA.test(releaseSha)) fail("external-five release SHA is invalid");
  same(ceremonyAuthorization.release_sha, releaseSha, "signed B release SHA");
  same(
    ceremonyAuthorization.pre_ceremony_runtime_authority_sha256,
    roots.runtimeAuthorityDependencySha256,
    "signed B runtime authority R",
  );
  const operatorPolicy = record(releaseCandidate.operator_policy, "release operator policy");
  same(operatorPolicy.ceremony_authorization_sha256,
    roots.ceremonyAuthorizationSha256, "release candidate signed B");
  same(operatorPolicy.runtime_authority_dependency_sha256,
    roots.runtimeAuthorityDependencySha256, "release candidate R");
  same(operatorPolicy.live_activation_authority_sha256,
    roots.liveActivationAuthoritySha256, "release candidate signed C");
  const observation = record(
    computeWorkloadActivationObservation,
    "compute-workload activation observation O",
  );
  same(observation.release_sha, releaseSha, "O release SHA");
  const observationLineage = record(observation.lineage, "O lineage");
  same(observationLineage.deployment_intent_sha256,
    releaseCandidate.deployment_intent_sha256, "O deployment intent");
  same(observationLineage.release_verification_authority_sha256,
    roots.releaseVerificationAuthoritySha256, "O release verification authority");
  same(observationLineage.ceremony_nonce,
    roots.ceremonyNonce, "O ceremony nonce");
  same(observationLineage.ceremony_authorization_sha256,
    roots.ceremonyAuthorizationSha256, "O signed B");
  same(observationLineage.pre_ceremony_runtime_authority_sha256,
    roots.runtimeAuthorityDependencySha256, "O runtime authority R");
  const manifest = record(frontendBuildInputManifest, "frontend D input manifest");
  same(manifest.release_sha, releaseSha, "frontend D manifest release SHA");
  const semantic = record(manifest.semantic_lineage, "frontend D semantic lineage");
  same(semantic.deployment_intent_sha256,
    releaseCandidate.deployment_intent_sha256, "frontend D deployment intent");
  same(semantic.ceremony_authorization_sha256,
    roots.ceremonyAuthorizationSha256, "frontend D signed B");
  same(semantic.runtime_authority_dependency_sha256,
    roots.runtimeAuthorityDependencySha256, "frontend D runtime authority R");
  same(semantic.compute_workload_activation_observation_sha256,
    roots.computeWorkloadActivationObservationSha256, "frontend D observation O");
  for (const flag of EXTERNAL_FIVE_EVIDENCE_FLAGS) {
    same(findPrivateInput(manifest, flag), files[flag].rawSha256,
      `frontend D raw-byte commitment for ${flag}`);
  }
  const build = record(frontendBuildCandidateReceipt, "frontend D receipt");
  same(build.release_sha, releaseSha, "frontend D receipt release SHA");
  same(build.deployment_intent_sha256,
    releaseCandidate.deployment_intent_sha256, "frontend D receipt deployment intent");
  same(build.release_inputs_sha256,
    roots.frontendBuildInputManifestSha256, "frontend D input manifest");
  same(build.ceremony_authorization_sha256,
    roots.ceremonyAuthorizationSha256, "frontend D receipt signed B");
  same(build.runtime_authority_dependency_sha256,
    roots.runtimeAuthorityDependencySha256, "frontend D receipt runtime authority R");
  same(build.compute_workload_activation_observation_sha256,
    roots.computeWorkloadActivationObservationSha256, "frontend D receipt observation O");
  const stageTwo = record(liveActivationAuthority, "signed C");
  same(stageTwo.release_sha, releaseSha, "signed C release SHA");
  same(stageTwo.ceremony_authorization_sha256,
    roots.ceremonyAuthorizationSha256, "signed C signed B dependency");
  const post = record(stageTwo.post_ceremony_evidence, "signed C post-ceremony evidence");
  same(post.compute_workload_activation_observation_sha256,
    roots.computeWorkloadActivationObservationSha256, "signed C observation O");
  same(post.frontend_build_candidate_receipt_sha256,
    roots.frontendBuildCandidateReceiptSha256, "signed C frontend D receipt");
  return Object.freeze({
    releaseSha,
    evidenceTimeSeconds: isoSecond(stageTwo.review?.signed_at, "signed C review time"),
    roots,
  });
}

function validateHistoricalQvlAuthorityBinding({
  candidate,
  historicalQvlAuthority,
  authorityDigests,
  evidenceTimeSeconds,
}) {
  const authority = normalizeHistoricalQvlAuthority(historicalQvlAuthority);
  const byCandidateKey = {};
  for (const identity of authority.identities) {
    const candidateKey = CANDIDATE_QVL_KEY_BY_HISTORICAL_DOMAIN[identity.domain];
    const candidateIdentity = candidate.trust_domains?.[candidateKey]?.identity;
    if (!candidateIdentity
      || identity.deployment_intent_sha256 !== candidate.deployment_intent_sha256
      || identity.release_authority_sha256
        !== authorityDigests.releaseVerificationAuthoritySha256
      || identity.ceremony_nonce !== authorityDigests.ceremonyNonce
      || identity.verifier_address !== candidateIdentity.verifier_address
      || identity.release_policy_sha256
        !== `sha256:${String(candidateIdentity.release_policy_hash || "").slice(2)}`
      || identity.activation_evidence_lease_expires_at <= evidenceTimeSeconds) {
      fail(`${identity.domain} historical QVL authority drifted from release/L/R/C`);
    }
    byCandidateKey[candidateKey] = identity;
  }
  return Object.freeze({
    activationEvidenceLeaseSeconds:
      authority.activation_evidence_lease_seconds,
    byCandidateKey: Object.freeze(byCandidateKey),
  });
}

function validateTrustedRoots(candidate, manifest, historicalQvlBinding) {
  if (!Array.isArray(manifest.qvl_verifier_roots)
    || manifest.qvl_verifier_roots.length !== 5) {
    fail("frontend D must bind exactly five QVL verifier roots");
  }
  const actual = manifest.qvl_verifier_roots.map((item, index) =>
    address(item, `frontend D QVL root ${index}`));
  if (new Set(actual).size !== 5) fail("frontend D QVL roots must be distinct");
  const expected = [
    "diligence_qvl",
    "arena_qvl",
    "anchor_writer_qvl",
    "compute_metering_qvl",
    "compute_workload_qvl",
  ].map((key) => address(
    candidate.trust_domains?.[key]?.identity?.verifier_address,
    `${key} verifier`,
  ));
  if (actual.some((root) => !expected.includes(root))
    || expected.some((root) => !actual.includes(root))) {
    fail("frontend D QVL roots drifted from the release candidate");
  }
  const historical = Object.values(historicalQvlBinding.byCandidateKey)
    .map((entry) => entry.verifier_address);
  if (historical.length !== 5
    || actual.some((root) => !historical.includes(root))
    || historical.some((root) => !actual.includes(root))) {
    fail("frontend D QVL roots drifted from authenticated historical L/R identities");
  }
  return new Set(actual);
}

function verdictDigest(verdict) {
  const payload = Object.fromEntries([
    "activation_evidence_lease_expires_at",
    "app_id", "ceremony_nonce", "chain_id", "challenge_digest",
    "challenge_expires_at", "challenge_id", "challenge_issued_at",
    "compose_hash", "contract_address", "cvm_id",
    "deployment_intent_sha256", "domain", "expires_at", "issued_at",
    "measurement_policy_sha256", "os_image_hash", "profile", "quote_hash",
    "release_policy_hash", "report_data", "release_authority_sha256",
    "schema", "signer_address", "verification_method", "verified",
    "verifier_address",
  ].map((key) => [key, verdict[key]]).sort(([left], [right]) => left.localeCompare(right)));
  return `0x${createHash("sha256")
    .update(VERDICT_DOMAIN)
    .update(Buffer.from(JSON.stringify(payload), "utf8"))
    .digest("hex")}`;
}

function validateVerdict({
  wrapper,
  context,
  candidate,
  expectedContract,
  expectedProfile,
  expectedSigner,
  qvlDomainKey,
  trustedRoots,
  historicalQvlBinding,
  evidenceTimeSeconds,
  authorityDigests,
  recoverIndependentEip191PersonalSigner,
}) {
  const parsedWrapper = exact(
    wrapper,
    ["context", "quote_sha256", "verdict"],
    `${context} verdict wrapper`,
  );
  if (parsedWrapper.context !== context) fail(`${context} verdict wrapper context drifted`);
  const quotePin = digest(parsedWrapper.quote_sha256, `${context} quote pin`);
  const verdict = exact(parsedWrapper.verdict, [
    "schema", "verification_method", "verified", "chain_id", "domain",
    "profile", "cvm_id", "deployment_intent_sha256",
    "release_authority_sha256", "ceremony_nonce", "measurement_policy_sha256",
    "release_policy_hash", "challenge_id", "challenge_digest",
    "challenge_issued_at", "challenge_expires_at", "quote_hash",
    "report_data", "compose_hash", "app_id", "os_image_hash",
    "signer_address", "contract_address", "issued_at",
    "activation_evidence_lease_expires_at", "expires_at",
    "verifier_address", "verifier_signature",
  ], `${context} verdict`);
  if (verdict.schema !== VERDICT_SCHEMA
    || verdict.verification_method !== VERIFICATION_METHOD
    || verdict.verified !== true
    || verdict.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || verdict.domain !== "main_runtime_cvm"
    || verdict.profile !== expectedProfile
    || verdict.cvm_id !== candidate.cvm.cvm_id
    || verdict.app_id !== candidate.cvm.app_id
    || verdict.compose_hash !== `0x${candidate.cvm.compose_hash}`
    || verdict.os_image_hash !== candidate.cvm.os_image_hash
    || verdict.signer_address !== expectedSigner
    || verdict.contract_address !== expectedContract
    || verdict.deployment_intent_sha256 !== candidate.deployment_intent_sha256
    || verdict.release_authority_sha256
      !== authorityDigests.releaseVerificationAuthoritySha256
    || verdict.ceremony_nonce !== authorityDigests.ceremonyNonce) {
    fail(`${context} verdict drifted from release/C/B/R/O/D authority`);
  }
  if (!CVM_ID.test(verdict.cvm_id) || !APP_ID.test(verdict.app_id)) {
    fail(`${context} verdict CVM identity is invalid`);
  }
  digest(verdict.deployment_intent_sha256, `${context} deployment intent`);
  digest(verdict.release_authority_sha256, `${context} release authority`);
  digest(verdict.measurement_policy_sha256, `${context} measurement policy`);
  for (const field of [
    "ceremony_nonce", "release_policy_hash", "challenge_id", "challenge_digest",
    "quote_hash", "report_data", "compose_hash",
  ]) bytes32(verdict[field], `${context} verdict ${field}`);
  address(verdict.signer_address, `${context} signer`);
  address(verdict.contract_address, `${context} contract`);
  const qvl = candidate.trust_domains?.[qvlDomainKey]?.identity;
  if (!qvl
    || verdict.release_policy_hash !== qvl.release_policy_hash
    || verdict.verifier_address !== qvl.verifier_address
    || !trustedRoots.has(verdict.verifier_address)) {
    fail(`${context} verdict QVL root drifted from frontend D and release policy`);
  }
  const historicalIdentity = historicalQvlBinding.byCandidateKey[qvlDomainKey];
  if (!historicalIdentity
    || verdict.verifier_address !== historicalIdentity.verifier_address
    || verdict.release_policy_hash
      !== `0x${historicalIdentity.release_policy_sha256.slice(7)}`
    || verdict.measurement_policy_sha256
      !== historicalIdentity.measurement_policy_sha256
    || verdict.release_authority_sha256
      !== historicalIdentity.release_authority_sha256
    || verdict.deployment_intent_sha256
      !== historicalIdentity.deployment_intent_sha256
    || verdict.ceremony_nonce !== historicalIdentity.ceremony_nonce) {
    fail(`${context} verdict drifted from its authenticated historical QVL identity`);
  }
  address(verdict.verifier_address, `${context} verifier`);
  const forbidden = new Set([
    candidate.operator_address,
    candidate.cvm.tee_identity,
    candidate.contracts.diligence_room.result_verifier,
    candidate.contracts.compute_credit_vault.developer,
    candidate.trust_domains.compute_metering.identity.metering_verifier,
    candidate.execution_policy.rollback_anchor.writer_address,
  ]);
  if (forbidden.has(verdict.verifier_address)) {
    fail(`${context} QVL verifier conflicts with a release control role`);
  }
  const challengeIssued = integer(verdict.challenge_issued_at,
    `${context} challenge issued`, 1, 4_102_444_800);
  const challengeExpires = integer(verdict.challenge_expires_at,
    `${context} challenge expiry`, 1, 4_102_444_800);
  const issued = integer(
    verdict.issued_at,
    `${context} verdict issued`,
    1,
    4_102_444_800,
  );
  const leaseExpires = integer(
    verdict.activation_evidence_lease_expires_at,
    `${context} activation evidence lease expiry`,
    1,
    4_102_444_800,
  );
  const expires = integer(
    verdict.expires_at,
    `${context} verdict expiry`,
    1,
    4_102_444_800,
  );
  if (challengeIssued > evidenceTimeSeconds + 5 || issued > evidenceTimeSeconds + 5
    || leaseExpires <= evidenceTimeSeconds
    || challengeExpires <= challengeIssued || challengeExpires - challengeIssued > 120
    || issued < challengeIssued || issued >= challengeExpires
    || leaseExpires !== expires || expires <= issued
    || expires - issued > historicalQvlBinding.activationEvidenceLeaseSeconds
    || expires > historicalIdentity.activation_evidence_lease_expires_at) {
    fail(`${context} v4 verdict recorded challenge or activation evidence lease relation is invalid`);
  }
  same(quotePin, `sha256:${verdict.quote_hash.slice(2)}`, `${context} quote pin`);
  const signature = canonicalSignature(verdict.verifier_signature, `${context} signature`);
  let recovered;
  try {
    recovered = recoverIndependentEip191PersonalSigner({
      digest: verdictDigest(verdict),
      signature,
    });
  } catch {
    fail(`${context} signature cannot be recovered`);
  }
  if (recovered && typeof recovered.then === "function") {
    fail(`${context} signature recovery must be a synchronous static implementation`);
  }
  if (String(recovered).toLowerCase() !== verdict.verifier_address) {
    fail(`${context} signature is not authenticated by its release-pinned QVL root`);
  }
  return verdict;
}

function validateLedger(ledger, candidate, authorityDigests) {
  const parsed = exact(ledger, [
    "contracts", "currentOperatorDeployer", "deploymentHistory",
    "freshDeployment", "network", "phala", "schemaVersion",
    "tinkerReleaseHistory",
  ], "fresh deployment ledger");
  if (parsed.schemaVersion !== 1
    || parsed.network?.name !== "Base Sepolia"
    || parsed.network?.chainId !== BASE_SEPOLIA_CHAIN_ID) {
    fail("fresh deployment ledger schema or network is invalid");
  }
  const operator = exact(parsed.currentOperatorDeployer, [
    "address", "fundingStatus", "keystoreAccount", "privateKeyMaterial",
  ], "fresh deployment ledger operator");
  if (operator.address !== candidate.operator_address
    || operator.keystoreAccount !== "dev"
    || operator.privateKeyMaterial !== "not_used") {
    fail("fresh deployment ledger operator custody drifted");
  }
  const suite = record(parsed.freshDeployment?.contractSuite,
    "fresh deployment ledger suite");
  if (suite.status !== "broadcast_complete_pending_cvm_binding"
    || suite.sourceCommit !== candidate.release_sha
    || suite.deploymentIntentSha256 !== candidate.deployment_intent_sha256
    || suite.keystoreAccount !== "dev"
    || suite.includesReviewedComputeCreditVault !== true
    || suite.excludesChallengePrizeAndCandidateCustodyContracts !== true) {
    fail("fresh deployment ledger suite identity or safety posture drifted");
  }
  const contracts = record(parsed.contracts, "fresh deployment ledger contracts");
  for (const [ledgerKey, candidateKey] of [
    ["diligenceRoom", "diligence_room"],
    ["challengeRegistry", "challenge_registry"],
    ["royaltyDistributor", "royalty_distributor"],
    ["tinkerAccountEncumbrance", "tinker_account_encumbrance"],
    ["computeCreditVault", "compute_credit_vault"],
    ["emailOracleAuth", "email_oracle_auth"],
  ]) {
    const entry = record(contracts[ledgerKey], `ledger ${ledgerKey}`);
    const expected = record(candidate.contracts[candidateKey], `candidate ${candidateKey}`);
    same(entry.address, expected.address, `ledger ${ledgerKey} address`);
    same(entry.runtimeCodeHash, expected.runtime_code_hash,
      `ledger ${ledgerKey} runtime code hash`);
    same(entry.sourceCommit, candidate.release_sha, `ledger ${ledgerKey} release SHA`);
  }
  const anchor = record(contracts.executionPolicyAnchor,
    "ledger ExecutionPolicyAnchor");
  const expectedAnchor = candidate.execution_policy.rollback_anchor;
  same(anchor.address, expectedAnchor.contract_address, "ledger anchor address");
  same(anchor.runtimeCodeHash, expectedAnchor.runtime_code_hash,
    "ledger anchor runtime code hash");
  same(anchor.writer, expectedAnchor.writer_address, "ledger anchor writer");
  same(anchor.writerReleaseCommitment, expectedAnchor.writer_release_commitment,
    "ledger anchor writer commitment");
  if (anchor.status !== "verified_active_frozen_release_writer"
    || anchor.sourceCommit !== candidate.release_sha
    || anchor.paused !== false || anchor.writerRotationsFrozen !== true
    || !Number.isSafeInteger(anchor.globalSequence)
    || !BYTES32.test(String(anchor.globalHead || ""))
    || !Number.isSafeInteger(anchor.releaseSnapshotBlockNumber)
    || anchor.releaseSnapshotBlockNumber < 1) {
    fail("ledger anchor recorded snapshot is malformed or not active/frozen");
  }
  same(anchor.deploymentIntentSha256Bytes32,
    `0x${candidate.deployment_intent_sha256.slice(7)}`,
    "ledger anchor deployment intent");
  const phala = exact(parsed.phala, [
    "appId", "composeHash", "cvmId", "endpoints", "imageDigests",
    "localRawComposeImagePolicyHash", "osImageHash", "osIsDev",
    "publicLogs", "publicSysinfo", "publicTcbinfo",
    "renderedComposeSha256", "sourceDigest",
  ], "fresh deployment ledger Phala binding");
  if (phala.cvmId !== candidate.cvm.cvm_id
    || phala.appId !== candidate.cvm.app_id
    || String(phala.composeHash).replace(/^0x/, "") !== candidate.cvm.compose_hash
    || String(phala.localRawComposeImagePolicyHash).replace(/^0x/, "")
      !== candidate.cvm.local_compose_hash
    || String(phala.renderedComposeSha256).replace(/^0x/, "")
      !== candidate.cvm.rendered_compose_sha256
    || String(phala.osImageHash).replace(/^0x/, "") !== candidate.cvm.os_image_hash
    || phala.osIsDev !== false || phala.publicLogs !== false
    || phala.publicSysinfo !== false || phala.publicTcbinfo !== false
    || phala.sourceDigest !== candidate.release_sha
    || phala.endpoints?.delegate !== candidate.cvm.delegate_url) {
    fail("fresh deployment ledger Phala binding drifted");
  }
  if (!Array.isArray(phala.imageDigests)
    || phala.imageDigests.length !== candidate.cvm.images.length) {
    fail("fresh deployment ledger image set is incomplete");
  }
  for (const expected of candidate.cvm.images) {
    const matches = phala.imageDigests.filter((entry) => entry?.service === expected.service);
    if (matches.length !== 1 || matches[0].image !== expected.image
      || matches[0].githubProvenanceAttestation !== "verified"
      || matches[0].githubSbomAttestation !== "verified") {
      fail(`fresh deployment ledger image ${expected.service} drifted`);
    }
  }
  if (!Array.isArray(parsed.deploymentHistory)
    || !parsed.deploymentHistory.some((entry) => (
      entry?.kind === "fresh_reviewed_scope_contract_suite"
      && entry.sourceCommit === candidate.release_sha
      && entry.deploymentIntentSha256 === candidate.deployment_intent_sha256
      && entry.reviewerAuthorityGenesisAcceptanceSha256
        === suite.reviewerAuthorityGenesisAcceptanceSha256
    ))) {
    fail("fresh deployment ledger omits its matching append-only deployment record");
  }
  digest(authorityDigests.ceremonyAuthorizationSha256, "ledger signed B context");
  return Object.freeze({
    releaseSnapshotBlockNumber: anchor.releaseSnapshotBlockNumber,
    globalSequence: anchor.globalSequence,
    globalHead: anchor.globalHead,
  });
}

function validateDeploymentEvidence(value, candidate, context, evidenceTimeSeconds) {
  const evidence = exact(value, [
    "api_url", "checks", "claims", "context", "cvm", "images", "schema", "status",
  ], `${context} deployment evidence`);
  if (evidence.schema !== "dnai.deployment.evidence.v2"
    || evidence.context !== context
    || evidence.status !== "evidence_checked_tdx_unverified"
    || evidence.api_url !== candidate.cvm.delegate_url) {
    fail(`${context} deployment evidence schema or identity drifted`);
  }
  const checks = exact(evidence.checks, [
    "cvm_attestation_envelope", "digest_pinned_compose",
    "github_provenance_attestations", "github_sbom_attestations",
    "intel_tdx_quote", "raw_secret_egress",
  ], `${context} deployment evidence checks`);
  const claims = exact(evidence.claims, [
    "independent_attestation_verdict_present", "intel_tdx_quote_verified",
    "production_authorization_allowed",
  ], `${context} deployment evidence claims`);
  if (checks.github_provenance_attestations !== "verified_by_github_cli"
    || checks.github_sbom_attestations !== "verified_by_github_cli"
    || checks.digest_pinned_compose !== "matched_expected_inputs"
    || checks.cvm_attestation_envelope
      !== "matched_claimed_identity_not_cryptographically_verified"
    || checks.intel_tdx_quote !== "not_verified_no_independent_qvl_verdict"
    || checks.raw_secret_egress !== false
    || claims.intel_tdx_quote_verified !== false
    || claims.independent_attestation_verdict_present !== false
    || claims.production_authorization_allowed !== false) {
    fail(`${context} evidence elevated its explicitly unverified trust label`);
  }
  if (!Array.isArray(evidence.images)
    || evidence.images.length !== candidate.cvm.images.length) {
    fail(`${context} deployment evidence image count drifted`);
  }
  for (const [index, raw] of evidence.images.entries()) {
    const image = exact(raw, [
      "image", "provenance_attestation", "repo", "sbom_attestation",
      "signer_workflow", "source_digest", "source_ref",
    ], `${context} image ${index}`);
    const expected = candidate.cvm.images.find((entry) => entry.image === image.image);
    if (!expected || [
      "repo", "signer_workflow", "source_digest", "source_ref",
      "provenance_attestation", "sbom_attestation",
    ].some((field) => image[field] !== expected[field])) {
      fail(`${context} deployment evidence image ${index} drifted`);
    }
  }
  const cvm = exact(evidence.cvm, [
    "api_url", "app_id", "attested_compose_hash", "compose_hash", "context",
    "encryption_public_key", "fetched_at", "images", "mode", "os_image_hash",
    "quote_size", "quote_verification", "rendered_compose_sha256", "report_data",
  ], `${context} CVM evidence`);
  const signedReport = candidate.attestations[context].verdict.report_data;
  if (cvm.api_url !== candidate.cvm.delegate_url || cvm.context !== context
    || cvm.mode !== "tdx" || cvm.compose_hash !== candidate.cvm.local_compose_hash
    || cvm.attested_compose_hash !== candidate.cvm.compose_hash
    || cvm.rendered_compose_sha256 !== candidate.cvm.rendered_compose_sha256
    || cvm.app_id !== candidate.cvm.app_id || cvm.os_image_hash !== candidate.cvm.os_image_hash
    || cvm.report_data !== signedReport.slice(2)
    || cvm.quote_verification
      !== "public-envelope-only; Intel TDX quote internals not parsed") {
    fail(`${context} CVM envelope drifted from the release candidate`);
  }
  bareBytes32(cvm.encryption_public_key, `${context} encryption public key`);
  integer(cvm.quote_size, `${context} quote size`, 632, 16 * 1024);
  const fetchedAt = integer(cvm.fetched_at, `${context} fetched_at`, 1);
  if (fetchedAt > evidenceTimeSeconds + 5 || fetchedAt < evidenceTimeSeconds - 300) {
    fail(`${context} evidence was not fresh at signed C's authenticated time`);
  }
  if (!Array.isArray(cvm.images) || cvm.images.length !== candidate.cvm.images.length) {
    fail(`${context} CVM image set drifted`);
  }
  for (const expected of candidate.cvm.images) {
    const matches = cvm.images.filter((entry) => entry?.service === expected.service);
    if (matches.length !== 1 || matches[0].image !== expected.image) {
      fail(`${context} CVM image ${expected.service} drifted`);
    }
  }
}

function validateAnchorEvidence({
  entry, candidate, trustedRoots, historicalQvlBinding, evidenceTimeSeconds,
  authorityDigests,
  recoverIndependentEip191PersonalSigner,
}) {
  const artifact = exact(entry.value, [
    "anchor_address", "app_id", "chain_id", "compose_hash", "os_image_hash",
    "quote_report_data", "quote_sha256", "quote_size", "qvl_release_policy_hash",
    "qvl_verdict", "qvl_verifier_address", "raw_private_key_egress",
    "raw_quote_egress", "raw_quote_in_artifact", "report_data", "schema", "status",
    "tdx_measurement_policy", "verification_method", "writer_address",
    "writer_custody", "writer_key_path", "writer_key_path_sha256",
    "writer_release_commitment",
  ], "anchor-writer evidence");
  const anchor = candidate.execution_policy.rollback_anchor;
  if (artifact.schema !== ANCHOR_EVIDENCE_SCHEMA
    || artifact.status !== "independent_qvl_verified"
    || artifact.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || artifact.anchor_address !== anchor.contract_address
    || artifact.writer_address !== anchor.writer_address
    || artifact.writer_release_commitment !== anchor.writer_release_commitment
    || artifact.writer_key_path !== ANCHOR_KEY_PATH
    || artifact.writer_custody !== ANCHOR_KEY_CUSTODY
    || artifact.app_id !== candidate.cvm.app_id
    || artifact.compose_hash !== `0x${candidate.cvm.compose_hash}`
    || artifact.os_image_hash !== candidate.cvm.os_image_hash
    || artifact.verification_method !== VERIFICATION_METHOD
    || artifact.tdx_measurement_policy !== "exact_release_pinned_measurements"
    || artifact.raw_quote_egress !== "authenticated_https_qvl_only"
    || artifact.raw_quote_in_artifact !== false
    || artifact.raw_private_key_egress !== false
    || entry.rawSha256 !== anchor.evidence_sha256) {
    fail("anchor-writer evidence schema or release binding drifted");
  }
  const expectedKeyPathHash = createHash("sha256")
    .update(ANCHOR_KEY_PATH_DOMAIN)
    .update(Buffer.from(ANCHOR_KEY_PATH, "ascii"))
    .digest("hex");
  same(artifact.writer_key_path_sha256, expectedKeyPathHash,
    "anchor-writer key-path commitment");
  const expectedReportData = hashDomainJson(ANCHOR_REPORT_DATA_DOMAIN, {
    schema: ANCHOR_REPORT_DATA_SCHEMA,
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    anchor_address: anchor.contract_address,
    writer_address: anchor.writer_address,
    writer_release_commitment: anchor.writer_release_commitment,
    writer_key_path: ANCHOR_KEY_PATH,
    writer_custody: ANCHOR_KEY_CUSTODY,
  });
  same(artifact.report_data, expectedReportData, "anchor-writer report data");
  same(artifact.quote_report_data,
    `${expectedReportData}${artifact.qvl_verdict.challenge_digest.slice(2)}`,
    "anchor-writer quote report data");
  integer(artifact.quote_size, "anchor-writer quote size", 1_024, 16 * 1024);
  const qvl = candidate.trust_domains.anchor_writer_qvl.identity;
  same(artifact.qvl_release_policy_hash, qvl.release_policy_hash,
    "anchor-writer QVL policy");
  same(artifact.qvl_verifier_address, qvl.verifier_address,
    "anchor-writer QVL verifier");
  const verdict = validateVerdict({
    wrapper: {
      context: "anchor_writer",
      quote_sha256: artifact.quote_sha256,
      verdict: artifact.qvl_verdict,
    },
    context: "anchor_writer",
    candidate,
    expectedContract: anchor.contract_address,
    expectedProfile: "execution_policy_anchor_writer",
    expectedSigner: anchor.writer_address,
    qvlDomainKey: "anchor_writer_qvl",
    trustedRoots,
    historicalQvlBinding,
    evidenceTimeSeconds,
    authorityDigests,
    recoverIndependentEip191PersonalSigner,
  });
  same(verdict.report_data, expectedReportData, "anchor-writer signed report data");
}

function validateEmailEvidence({
  entry, candidate, trustedRoots, historicalQvlBinding, evidenceTimeSeconds,
  authorityDigests,
  recoverIndependentEip191PersonalSigner,
}) {
  const artifact = exact(entry.value, [
    "chain_id", "email_oracle_auth", "kms", "main_cvm", "qvl_verification",
    "registration", "release_sha", "restart_key_derivation", "schema", "status",
    "target_boot",
  ], "email-oracle evidence");
  const email = candidate.contracts.email_oracle_auth;
  const release = email.release;
  if (artifact.schema !== EMAIL_EVIDENCE_SCHEMA
    || artifact.status !== "external_evidence_verified"
    || artifact.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || artifact.release_sha !== candidate.release_sha
    || artifact.email_oracle_auth !== email.address
    || `0x${entry.rawSha256.slice(7)}` !== release.external_evidence_sha256) {
    fail("email-oracle evidence schema or release hash binding drifted");
  }
  const main = exact(artifact.main_cvm, [
    "compose_hash", "consumer_app_id", "cvm_id", "device_id",
  ], "email-oracle main CVM");
  if (main.cvm_id !== candidate.cvm.cvm_id
    || main.compose_hash !== `0x${candidate.cvm.compose_hash}`
    || main.consumer_app_id !== email.consumer_address
    || main.device_id !== release.device_id) {
    fail("email-oracle main CVM binding drifted");
  }
  const kms = exact(artifact.kms, [
    "contract_address", "implementation_address", "implementation_runtime_code_hash",
    "kms_eip1967_implementation_slot_word", "runtime_code_hash", "source_commit",
    "source_repository", "verification_status", "verification_url",
  ], "email-oracle KMS evidence");
  if (kms.contract_address !== release.kms_contract_address
    || kms.implementation_address !== release.kms_implementation_address
    || kms.implementation_runtime_code_hash
      !== release.kms_implementation_runtime_code_hash
    || kms.kms_eip1967_implementation_slot_word
      !== `0x${"0".repeat(24)}${release.kms_implementation_address.slice(2)}`
    || kms.runtime_code_hash !== release.kms_runtime_code_hash
    || kms.source_repository !== "https://github.com/Dstack-TEE/dstack"
    || kms.verification_status !== "verified_source_and_runtime"
    || !RELEASE_SHA.test(kms.source_commit)
    || typeof kms.verification_url !== "string"
    || !kms.verification_url.startsWith("https://")) {
    fail("email-oracle KMS source/runtime claims drifted");
  }
  const registration = exact(artifact.registration, [
    "block_hash", "block_number", "registered_apps_readback", "transaction_hash",
  ], "email-oracle KMS registration");
  if (registration.transaction_hash !== release.kms_registration_tx_hash
    || registration.block_number !== release.kms_registration_block
    || registration.block_hash !== release.kms_registration_block_hash
    || registration.registered_apps_readback !== true) {
    fail("email-oracle KMS registration claims drifted");
  }
  const boot = exact(artifact.target_boot, [
    "advisory_ids", "instance_id", "kms_is_app_allowed", "mr_aggregated",
    "mr_system", "os_image_hash", "tcb_status",
  ], "email-oracle target boot");
  if (boot.instance_id !== release.target_boot.instance_id
    || boot.mr_aggregated !== release.target_boot.mr_aggregated
    || boot.mr_system !== release.target_boot.mr_system
    || boot.os_image_hash !== release.target_boot.os_image_hash
    || boot.tcb_status !== "UpToDate" || boot.kms_is_app_allowed !== true
    || !Array.isArray(boot.advisory_ids) || boot.advisory_ids.length !== 0) {
    fail("email-oracle target boot claims drifted");
  }
  const restart = exact(artifact.restart_key_derivation, [
    "derive_key_succeeded_after", "derive_key_succeeded_before", "key_path",
    "post_restart_commitment", "pre_restart_commitment", "raw_key_egress",
    "raw_secret_egress", "restart_observed", "restart_proof_hash", "status",
  ], "email-oracle restart proof");
  if (restart.status !== "verified_after_real_cvm_restart"
    || restart.key_path !== "email/creds" || restart.restart_observed !== true
    || restart.derive_key_succeeded_before !== true
    || restart.derive_key_succeeded_after !== true
    || restart.raw_key_egress !== false || restart.raw_secret_egress !== false
    || restart.restart_proof_hash !== release.restart_key_derivation_proof_hash
    || restart.post_restart_commitment !== restart.pre_restart_commitment) {
    fail("email-oracle restart continuity claims drifted");
  }
  const qvl = exact(artifact.qvl_verification, [
    "qvl_release_policy_hash", "qvl_verdict", "qvl_verifier_address",
    "quote_sha256", "status", "verification_method",
  ], "email-oracle QVL evidence");
  const diligenceQvl = candidate.trust_domains.diligence_qvl.identity;
  if (qvl.status !== "independent_qvl_verified"
    || qvl.verification_method !== VERIFICATION_METHOD
    || qvl.qvl_release_policy_hash !== diligenceQvl.release_policy_hash
    || qvl.qvl_verifier_address !== diligenceQvl.verifier_address) {
    fail("email-oracle QVL root or status drifted");
  }
  const binding = candidate.trust_domains.diligence_qvl.policy_binding
    .email_oracle_kms_restart_binding;
  const expectedReportData = hashDomainJson(EMAIL_REPORT_DATA_DOMAIN, {
    schema: "dnai.email-oracle-kms-restart-attestation.v1",
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    main_cvm_signer: candidate.cvm.tee_identity,
    ...Object.fromEntries(Object.entries(binding).filter(([key]) => key !== "kind")),
  });
  const verdict = validateVerdict({
    wrapper: {
      context: "email_oracle_kms_restart",
      quote_sha256: qvl.quote_sha256,
      verdict: qvl.qvl_verdict,
    },
    context: "email_oracle_kms_restart",
    candidate,
    expectedContract: candidate.contracts.diligence_room.address,
    expectedProfile: "email_oracle_kms_restart",
    expectedSigner: candidate.cvm.tee_identity,
    qvlDomainKey: "diligence_qvl",
    trustedRoots,
    historicalQvlBinding,
    evidenceTimeSeconds,
    authorityDigests,
    recoverIndependentEip191PersonalSigner,
  });
  same(verdict.report_data, expectedReportData, "email-oracle signed report data");
}

export function validateExternalFiveHistoricalEvidenceBoundary({
  files,
  releaseCandidate,
  ceremonyAuthorization,
  computeWorkloadActivationObservation,
  frontendBuildInputManifest,
  frontendBuildCandidateReceipt,
  liveActivationAuthority,
  historicalQvlAuthority,
  authorityDigests,
  recoverIndependentEip191PersonalSigner,
} = {}) {
  if (typeof recoverIndependentEip191PersonalSigner !== "function") {
    fail("external-five requires an explicit synchronous static EIP-191 signer recovery function");
  }
  for (const [label, value] of Object.entries({
    files,
    releaseCandidate,
    ceremonyAuthorization,
    computeWorkloadActivationObservation,
    frontendBuildInputManifest,
    frontendBuildCandidateReceipt,
    liveActivationAuthority,
    historicalQvlAuthority,
    authorityDigests,
  })) assertCanonicalPlainDataGraph(value, { label: `external-five ${label}` });
  const normalizedFiles = normalizeFiles(files);
  const lineage = validateAuthorityLineage({
    files: normalizedFiles,
    releaseCandidate,
    ceremonyAuthorization,
    computeWorkloadActivationObservation,
    frontendBuildInputManifest,
    frontendBuildCandidateReceipt,
    liveActivationAuthority,
    authorityDigests,
  });
  const historicalQvlBinding = validateHistoricalQvlAuthorityBinding({
    candidate: releaseCandidate,
    historicalQvlAuthority,
    authorityDigests,
    evidenceTimeSeconds: lineage.evidenceTimeSeconds,
  });
  const trustedRoots = validateTrustedRoots(
    releaseCandidate,
    frontendBuildInputManifest,
    historicalQvlBinding,
  );
  const ledgerProjection = validateLedger(
    normalizedFiles["--ledger"].value,
    releaseCandidate,
    authorityDigests,
  );
  validateDeploymentEvidence(
    normalizedFiles["--artifact-evidence"].value,
    releaseCandidate,
    "artifact",
    lineage.evidenceTimeSeconds,
  );
  validateDeploymentEvidence(
    normalizedFiles["--arena-evidence"].value,
    releaseCandidate,
    "arena",
    lineage.evidenceTimeSeconds,
  );
  validateVerdict({
    wrapper: releaseCandidate.attestations.artifact,
    context: "artifact",
    candidate: releaseCandidate,
    expectedContract: releaseCandidate.contracts.diligence_room.address,
    expectedProfile: "diligence",
    expectedSigner: releaseCandidate.cvm.tee_identity,
    qvlDomainKey: "diligence_qvl",
    trustedRoots,
    historicalQvlBinding,
    evidenceTimeSeconds: lineage.evidenceTimeSeconds,
    authorityDigests,
    recoverIndependentEip191PersonalSigner,
  });
  validateVerdict({
    wrapper: releaseCandidate.attestations.arena,
    context: "arena",
    candidate: releaseCandidate,
    expectedContract: releaseCandidate.contracts.challenge_registry.address,
    expectedProfile: "arena",
    expectedSigner: releaseCandidate.cvm.tee_identity,
    qvlDomainKey: "arena_qvl",
    trustedRoots,
    historicalQvlBinding,
    evidenceTimeSeconds: lineage.evidenceTimeSeconds,
    authorityDigests,
    recoverIndependentEip191PersonalSigner,
  });
  validateAnchorEvidence({
    entry: normalizedFiles["--anchor-writer-evidence"],
    candidate: releaseCandidate,
    trustedRoots,
    historicalQvlBinding,
    evidenceTimeSeconds: lineage.evidenceTimeSeconds,
    authorityDigests,
    recoverIndependentEip191PersonalSigner,
  });
  validateEmailEvidence({
    entry: normalizedFiles["--email-oracle-evidence"],
    candidate: releaseCandidate,
    trustedRoots,
    historicalQvlBinding,
    evidenceTimeSeconds: lineage.evidenceTimeSeconds,
    authorityDigests,
    recoverIndependentEip191PersonalSigner,
  });
  return deepFreezeCanonicalPlainDataGraph({
    schema: EXTERNAL_FIVE_HISTORICAL_EVIDENCE_SCHEMA,
    status: EXTERNAL_FIVE_HISTORICAL_EVIDENCE_STATUS,
    truth_status: EXTERNAL_FIVE_HISTORICAL_EVIDENCE_TRUTH_STATUS,
    release_sha: lineage.releaseSha,
    signed_C_evidence_time_seconds: lineage.evidenceTimeSeconds,
    frontend_D_raw_byte_commitments_authenticated: true,
    release_B_R_O_C_D_lineage_authenticated: true,
    external_file_schemas_authenticated: true,
    historical_qvl_identity_evidence_authenticated: true,
    historical_v4_qvl_verdict_signatures_authenticated: true,
    qvl_signature_recovery_authority:
      "explicit_synchronous_static_raw_digest_EIP_191_adapter",
    recorded_challenge_and_activation_lease_relations_checked: true,
    qvl_challenge_signatures_authenticated: false,
    raw_quotes_authenticated: false,
    qvl_challenge_consumption_authenticated: false,
    freshness_renewed: false,
    current_qvl_operation_performed: false,
    artifact_and_arena_unverified_trust_labels_preserved: true,
    recorded_ledger_projection: ledgerProjection,
    ledger_chain_observations_authenticated: false,
    execution_policy_anchor_chain_state_authenticated: false,
    email_kms_registration_chain_state_authenticated: false,
    email_kms_source_verification_authenticated: false,
    email_restart_observation_authenticated: false,
    current_live_chain_authenticated: false,
    current_clock_consulted: false,
    live_traffic_authorized: false,
    canonicalDependencyChainVerified: false,
    required_downstream_proofs: [
      "fresh_QVL_challenge_signatures_for_external_verdicts",
      "fresh_raw_TDX_quotes_and_current_DCAP_QVL_appraisals",
      "single_use_QVL_challenge_consumption_receipts",
      "current_clock_activation_evidence_lease_validation",
      "independent_Base_Sepolia_consensus_or_dual_RPC_state_and_receipt_proofs_at_the_release_snapshot",
      "ExecutionPolicyAnchor_storage_proof_at_the_release_snapshot",
      "KMS_registration_transaction_receipt_and_registered_apps_storage_proof",
      "authenticated_Dstack_source_runtime_verification_receipt",
      "authenticated_real_CVM_restart_and_key_continuity_receipt",
    ],
  }, { label: "external-five historical boundary result" });
}
