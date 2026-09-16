import { createHash } from "node:crypto";

export const PHALA_QVL_MEASUREMENT_POLICY_SCHEMA =
  "dnai.phala-qvl-measurement-policy.v1";
export const PHALA_QVL_MEASUREMENT_POLICY_DOMAIN =
  "dnai-wikigen/phala-qvl-measurement-policy/v1\0";
export const PHALA_QVL_MEASUREMENT_POLICY_SET_SCHEMA =
  "dnai.phala-qvl-measurement-policy-set.v2";
export const PHALA_QVL_MEASUREMENT_POLICY_SET_DOMAIN =
  "dnai-wikigen/phala-qvl-measurement-policy-set/v2\0";
export const PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS = 900;

export const PHALA_QVL_MEASUREMENT_POLICY_ORDER = Object.freeze([
  "diligence_qvl_cvm",
  "arena_qvl_cvm",
  "anchor_writer_qvl_cvm",
  "compute_workload_qvl_cvm",
  "compute_metering_qvl_cvm",
]);

export const PHALA_QVL_MEASUREMENT_POLICY_PROFILE = Object.freeze({
  diligence_qvl_cvm: "diligence",
  arena_qvl_cvm: "arena",
  anchor_writer_qvl_cvm: "execution_policy_anchor_writer",
  compute_workload_qvl_cvm: "compute_workload",
  compute_metering_qvl_cvm: "compute_metering",
});

const CHAIN_ID = 84_532;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const HEX_8 = /^[0-9a-f]{16}$/;
const HEX_48 = /^[0-9a-f]{96}$/;
const REFERENCE_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;

function exactRecord(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.getOwnPropertySymbols(value).length !== 0) {
    throw new Error(`${label} must be one exact plain object`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) =>
    !descriptor.enumerable || !Object.hasOwn(descriptor, "value"))) {
    throw new Error(`${label} cannot contain accessors or hidden fields`);
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    throw new Error(`${label} fields are incomplete or unexpected`);
  }
  return value;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
}

function compact(value) {
  return JSON.stringify(canonical(value));
}

function domainSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(compact(value), "ascii")
    .digest("hex")}`;
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be one nonzero sha256 digest`);
  }
  return value;
}

function fixedHex(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`${label} is not canonical lowercase fixed-width hex`);
  }
  return value;
}

function bytewiseAnd(left, right) {
  const a = Buffer.from(left, "hex");
  const b = Buffer.from(right, "hex");
  return Buffer.from(a.map((byte, index) => byte & b[index]));
}

function isZero(bytes) {
  return bytes.every((byte) => byte === 0);
}

function equalsHex(left, right) {
  return Buffer.from(left, "hex").equals(Buffer.from(right, "hex"));
}

function normalizeMaskedExactValue(value, requiredMask, forbiddenMask, label) {
  const exact = fixedHex(value, HEX_8, `${label} exact value`);
  const required = fixedHex(requiredMask, HEX_8, `${label} required mask`);
  const forbidden = fixedHex(forbiddenMask, HEX_8, `${label} forbidden mask`);
  if (!isZero(bytewiseAnd(required, forbidden))
    || !bytewiseAnd(exact, required).equals(Buffer.from(required, "hex"))
    || !isZero(bytewiseAnd(exact, forbidden))) {
    throw new Error(`${label} exact value does not satisfy its required/forbidden masks`);
  }
  return { exact, required, forbidden };
}

export function normalizePhalaQvlMeasurementPolicy(value) {
  const parsed = exactRecord(value, [
    "deployment_intent_sha256", "domain", "mr_config_id", "mr_owner",
    "mr_owner_config", "mr_td", "profile", "reference_id", "rt_mr0",
    "rt_mr1", "rt_mr2", "rt_mr3", "schema", "td_attributes",
    "td_attributes_forbidden_mask", "td_attributes_required_mask", "xfam",
    "xfam_forbidden_mask", "xfam_required_mask",
  ], "QVL measurement policy");
  const profile = PHALA_QVL_MEASUREMENT_POLICY_PROFILE[parsed.domain];
  if (parsed.schema !== PHALA_QVL_MEASUREMENT_POLICY_SCHEMA
    || !profile || parsed.profile !== profile
    || typeof parsed.reference_id !== "string" || !REFERENCE_ID.test(parsed.reference_id)) {
    throw new Error("QVL measurement policy role or reference is invalid");
  }
  const td = normalizeMaskedExactValue(
    parsed.td_attributes,
    parsed.td_attributes_required_mask,
    parsed.td_attributes_forbidden_mask,
    "QVL TDATTRIBUTES",
  );
  const xfam = normalizeMaskedExactValue(
    parsed.xfam,
    parsed.xfam_required_mask,
    parsed.xfam_forbidden_mask,
    "QVL XFAM",
  );
  if ((Buffer.from(td.exact, "hex")[0] & 1) !== 0
    || (Buffer.from(td.forbidden, "hex")[0] & 1) !== 1) {
    throw new Error("QVL measurement policy must independently forbid TDX DEBUG");
  }
  return Object.freeze({
    schema: PHALA_QVL_MEASUREMENT_POLICY_SCHEMA,
    domain: parsed.domain,
    profile,
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "QVL measurement policy deployment intent",
    ),
    reference_id: parsed.reference_id,
    mr_td: fixedHex(parsed.mr_td, HEX_48, "QVL MRTD"),
    mr_config_id: fixedHex(parsed.mr_config_id, HEX_48, "QVL MRCONFIGID"),
    mr_owner: fixedHex(parsed.mr_owner, HEX_48, "QVL MROWNER"),
    mr_owner_config: fixedHex(parsed.mr_owner_config, HEX_48, "QVL MROWNERCONFIG"),
    rt_mr0: fixedHex(parsed.rt_mr0, HEX_48, "QVL RTMR0"),
    rt_mr1: fixedHex(parsed.rt_mr1, HEX_48, "QVL RTMR1"),
    rt_mr2: fixedHex(parsed.rt_mr2, HEX_48, "QVL RTMR2"),
    rt_mr3: fixedHex(parsed.rt_mr3, HEX_48, "QVL RTMR3"),
    td_attributes: td.exact,
    td_attributes_required_mask: td.required,
    td_attributes_forbidden_mask: td.forbidden,
    xfam: xfam.exact,
    xfam_required_mask: xfam.required,
    xfam_forbidden_mask: xfam.forbidden,
  });
}

export function phalaQvlMeasurementPolicySha256(value) {
  return domainSha256(
    PHALA_QVL_MEASUREMENT_POLICY_DOMAIN,
    normalizePhalaQvlMeasurementPolicy(value),
  );
}

export function appraisePhalaQvlMeasurementsAgainstPolicy(measurements, policyValue) {
  const policy = normalizePhalaQvlMeasurementPolicy(policyValue);
  const base = [
    "tee_tcb_svn", "mr_seam", "mr_signer_seam", "seam_attributes",
    "td_attributes", "xfam", "mr_td", "mr_config_id", "mr_owner",
    "mr_owner_config", "rt_mr0", "rt_mr1", "rt_mr2", "rt_mr3",
  ];
  const v15 = ["tee_tcb_svn2", "mr_service_td"];
  if (!measurements || typeof measurements !== "object" || Array.isArray(measurements)) {
    throw new Error("TDX measurements cannot be appraised against the QVL policy");
  }
  const expectedFields = Object.hasOwn(measurements, "tee_tcb_svn2")
    ? [...base, ...v15]
    : base;
  exactRecord(measurements, expectedFields, "observed TDX measurements");
  const exactPolicyFields = [
    "mr_td", "mr_config_id", "mr_owner", "mr_owner_config",
    "rt_mr0", "rt_mr1", "rt_mr2", "rt_mr3", "td_attributes", "xfam",
  ];
  const lengths = {
    tee_tcb_svn: 32,
    seam_attributes: 16,
    td_attributes: 16,
    xfam: 16,
    tee_tcb_svn2: 32,
  };
  for (const field of expectedFields) {
    const length = lengths[field] ?? 96;
    if (typeof measurements[field] !== "string"
      || !new RegExp(`^[0-9a-f]{${length}}$`).test(measurements[field])) {
      throw new Error(`observed ${field} is not canonical fixed-width lowercase hex`);
    }
  }
  for (const field of exactPolicyFields.slice(0, 8)) {
    if (!equalsHex(fixedHex(measurements[field], HEX_48, `observed ${field}`), policy[field])) {
      throw new Error(`observed ${field} is not authorized by the QVL measurement policy`);
    }
  }
  const observedTd = fixedHex(measurements.td_attributes, HEX_8, "observed TDATTRIBUTES");
  const observedXfam = fixedHex(measurements.xfam, HEX_8, "observed XFAM");
  const maskedChecks = [
    [
      "TDATTRIBUTES",
      observedTd,
      policy.td_attributes,
      policy.td_attributes_required_mask,
      policy.td_attributes_forbidden_mask,
    ],
    [
      "XFAM",
      observedXfam,
      policy.xfam,
      policy.xfam_required_mask,
      policy.xfam_forbidden_mask,
    ],
  ];
  for (const [label, observed, exact, requiredMask, forbiddenMask] of maskedChecks) {
    if (!equalsHex(observed, exact)
      || !bytewiseAnd(observed, requiredMask).equals(Buffer.from(requiredMask, "hex"))
      || !isZero(bytewiseAnd(observed, forbiddenMask))) {
      throw new Error(`observed ${label} is not authorized by the QVL measurement policy`);
    }
  }
  const debugEnabled = (Buffer.from(observedTd, "hex")[0] & 1) !== 0;
  if (debugEnabled) {
    throw new Error("Intel TDX DEBUG TDs are forbidden by release measurement policy");
  }
  return Object.freeze({
    measurement_policy_sha256: phalaQvlMeasurementPolicySha256(policy),
    measurement_policy_reference_id: policy.reference_id,
    measurement_policy_matched: true,
    debug_td: false,
  });
}

export function normalizePhalaQvlMeasurementPolicySet(value) {
  const parsed = exactRecord(value, [
    "activation_evidence_lease_seconds", "chain_id", "deployment_intent_sha256",
    "policies", "schema",
  ], "QVL measurement policy set");
  const deploymentIntent = sha256(
    parsed.deployment_intent_sha256,
    "QVL measurement policy set deployment intent",
  );
  if (parsed.schema !== PHALA_QVL_MEASUREMENT_POLICY_SET_SCHEMA
    || parsed.chain_id !== CHAIN_ID || !Array.isArray(parsed.policies)
    || parsed.activation_evidence_lease_seconds
      !== PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS
    || parsed.policies.length !== PHALA_QVL_MEASUREMENT_POLICY_ORDER.length) {
    throw new Error("QVL measurement policy set authority is invalid");
  }
  const policies = parsed.policies.map(normalizePhalaQvlMeasurementPolicy);
  if (JSON.stringify(policies.map(({ domain }) => domain))
      !== JSON.stringify(PHALA_QVL_MEASUREMENT_POLICY_ORDER)
    || policies.some(({ deployment_intent_sha256: digest }) => digest !== deploymentIntent)
    || new Set(policies.map(phalaQvlMeasurementPolicySha256)).size !== policies.length) {
    throw new Error("QVL measurement policies are reordered, cross-release, or duplicated");
  }
  return Object.freeze({
    schema: PHALA_QVL_MEASUREMENT_POLICY_SET_SCHEMA,
    chain_id: CHAIN_ID,
    deployment_intent_sha256: deploymentIntent,
    activation_evidence_lease_seconds:
      PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
    policies: Object.freeze(policies),
  });
}

export function phalaQvlMeasurementPolicySetSha256(value) {
  return domainSha256(
    PHALA_QVL_MEASUREMENT_POLICY_SET_DOMAIN,
    normalizePhalaQvlMeasurementPolicySet(value),
  );
}

export function canonicalPhalaQvlMeasurementPolicySetText(value) {
  return `${JSON.stringify(canonical(normalizePhalaQvlMeasurementPolicySet(value)), null, 2)}\n`;
}
