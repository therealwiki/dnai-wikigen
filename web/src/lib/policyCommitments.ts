import type {
  ExecutionPolicyDecision,
  ExecutionPolicySurface,
  PolicyBundle,
  PolicyStageOutcome,
} from "./policy";

export const POLICY_CANONICALIZATION_VERSION = "policy-kernel-canonicalization/v2";
export const SUPPORTED_POLICY_VERSION = "policy-kernel/v1";
export const PUBLIC_REVIEW_ROLES = [
  "access-review-officer",
  "expert-in-the-loop",
  "ethics-legal-reviewer",
] as const;

const encoder = new TextEncoder();

interface NormalizedRequest {
  request_id: string;
  requester_ref: string;
  purpose: string;
  pipeline: string;
  data_classes: string[];
  output_schema: string;
  operations: string[];
  risk_tags: string[];
}

interface NormalizedPolicy {
  policy_id: string;
  version: string;
  corpus_ref: string;
  allowed_purposes: string[];
  denied_purposes: string[];
  allowed_pipelines: string[];
  allowed_output_schemas: string[];
  allowed_operations: string[];
  known_data_classes: string[];
  restricted_categories: string[];
  hold_categories: string[];
  ambiguous_categories: string[];
  hold_routes: Record<string, string>;
}

export interface LocalPolicyEvaluation {
  decision: ExecutionPolicyDecision;
  stage: number;
  reason_code: string;
  routed_role: string;
  outcomes: PolicyStageOutcome[];
}

export interface PolicyCommitments {
  canonicalization_version: typeof POLICY_CANONICALIZATION_VERSION;
  request_hash: string;
  policy_hash: string;
  resource_id_hash: string;
  purpose_hash: string;
  pipeline_hash: string;
  output_schema_hash: string;
  corpus_ref_hash: string;
  local_evaluation: LocalPolicyEvaluation;
}

function comparePythonStrings(left: string, right: string): number {
  const leftPoints = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index];
  }
  return leftPoints.length - rightPoints.length;
}

function pythonJsonString(value: string): string {
  const json = JSON.stringify(value);
  let encoded = "";
  for (let index = 0; index < json.length; index += 1) {
    const codeUnit = json.charCodeAt(index);
    encoded += codeUnit >= 0x7f
      ? `\\u${codeUnit.toString(16).padStart(4, "0")}`
      : json[index];
  }
  return encoded;
}

/** Match Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True). */
export function pythonCanonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return pythonJsonString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(pythonCanonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const item = value as Record<string, unknown>;
    const keys = Object.keys(item).sort(comparePythonStrings);
    if (keys.some((key) => item[key] === undefined)) {
      throw new Error("Policy canonicalization does not accept undefined values");
    }
    return `{${keys.map((key) => `${pythonJsonString(key)}:${pythonCanonicalJson(item[key])}`).join(",")}}`;
  }
  throw new Error("Policy canonicalization encountered a non-JSON value");
}

async function sha256HexBytes(value: Uint8Array): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is required to verify policy commitments");
  const digest = await globalThis.crypto.subtle.digest("SHA-256", value as BufferSource);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Parts(...parts: Uint8Array[]): Promise<string> {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const combined = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    combined.set(part, offset);
    offset += part.byteLength;
  }
  return sha256HexBytes(combined);
}

export async function computeExecutionResourceHash(
  surface: ExecutionPolicySurface,
  resourceId: string,
): Promise<string> {
  return sha256Parts(
    encoder.encode("dnai-wikigen/execution-policy-resource/v1"),
    new Uint8Array([0]),
    encoder.encode(surface),
    new Uint8Array([0]),
    encoder.encode(resourceId),
  );
}

async function stableHash(prefix: string, value: string | Record<string, unknown>): Promise<string> {
  const payload = typeof value === "string" ? value : pythonCanonicalJson(value);
  return sha256Parts(encoder.encode(prefix), new Uint8Array([0]), encoder.encode(payload));
}

function stringList(value: unknown, fallback: readonly string[] = []): string[] {
  return Array.isArray(value) ? [...value] as string[] : [...fallback];
}

function normalizeRequest(bundle: PolicyBundle): NormalizedRequest {
  const source = bundle.request;
  return {
    request_id: source.request_id as string,
    requester_ref: source.requester_ref as string,
    purpose: source.purpose as string,
    pipeline: source.pipeline as string,
    data_classes: stringList(source.data_classes),
    output_schema: source.output_schema as string,
    operations: stringList(source.operations, ["score"]),
    risk_tags: stringList(source.risk_tags),
  };
}

function normalizePolicy(bundle: PolicyBundle): NormalizedPolicy {
  const source = bundle.policy;
  return {
    policy_id: source.policy_id as string,
    version: (source.version as string | undefined) || SUPPORTED_POLICY_VERSION,
    corpus_ref: source.corpus_ref as string,
    allowed_purposes: stringList(source.allowed_purposes),
    denied_purposes: stringList(source.denied_purposes),
    allowed_pipelines: stringList(source.allowed_pipelines),
    allowed_output_schemas: stringList(source.allowed_output_schemas),
    allowed_operations: stringList(source.allowed_operations),
    known_data_classes: stringList(source.known_data_classes),
    restricted_categories: stringList(source.restricted_categories),
    hold_categories: stringList(source.hold_categories),
    ambiguous_categories: stringList(source.ambiguous_categories),
    hold_routes: source.hold_routes ? { ...(source.hold_routes as Record<string, string>) } : {},
  };
}

function sorted(values: Iterable<string>): string[] {
  return [...values].sort(comparePythonStrings);
}

async function categoryHashes(values: Iterable<string>): Promise<string[]> {
  return Promise.all(sorted(values).map((value) => stableHash("category", value)));
}

function setIntersection(left: Iterable<string>, right: Iterable<string>): string[] {
  const rightSet = new Set(right);
  return sorted(new Set([...left].filter((value) => rightSet.has(value))));
}

async function outcome(
  stage: number,
  decision: ExecutionPolicyDecision,
  reasonCode: string,
  matched: Iterable<string> = [],
  routedRole = "",
): Promise<PolicyStageOutcome> {
  const hashes = await categoryHashes(matched);
  return {
    stage,
    decision,
    reason_code: reasonCode,
    routed_role: routedRole,
    matched_category_count: hashes.length,
    matched_category_hashes: hashes,
  };
}

function reviewRoute(categories: string[], policy: NormalizedPolicy): string {
  for (const category of categories) {
    const configured = Object.prototype.hasOwnProperty.call(policy.hold_routes, category)
      ? policy.hold_routes[category]
      : undefined;
    if (configured) return configured;
  }
  return categories.some((category) => category.includes("clinical") || category.includes("bio"))
    ? "expert-in-the-loop"
    : "access-review-officer";
}

async function evaluateLocally(
  request: NormalizedRequest,
  policy: NormalizedPolicy,
): Promise<LocalPolicyEvaluation> {
  const outcomes: PolicyStageOutcome[] = [];
  const finish = (latest: PolicyStageOutcome): LocalPolicyEvaluation => ({
    decision: latest.decision,
    stage: latest.stage,
    reason_code: latest.reason_code,
    routed_role: latest.routed_role,
    outcomes,
  });

  if (policy.version !== SUPPORTED_POLICY_VERSION) {
    const latest = await outcome(0, "deny", "unsupported_policy_version");
    outcomes.push(latest);
    return finish(latest);
  }
  if (policy.denied_purposes.includes(request.purpose)) {
    const latest = await outcome(1, "deny", "denied_purpose");
    outcomes.push(latest);
    return finish(latest);
  }
  if (!policy.allowed_purposes.includes(request.purpose)) {
    const latest = await outcome(1, "deny", "unknown_or_unallowed_purpose");
    outcomes.push(latest);
    return finish(latest);
  }
  outcomes.push(await outcome(1, "pass", "purpose_allowed"));

  if (!policy.allowed_pipelines.includes(request.pipeline)) {
    const latest = await outcome(2, "deny", "unsupported_pipeline");
    outcomes.push(latest);
    return finish(latest);
  }
  if (!policy.allowed_output_schemas.includes(request.output_schema)) {
    const latest = await outcome(2, "deny", "unsupported_output_schema");
    outcomes.push(latest);
    return finish(latest);
  }
  if (request.operations.some((operation) => !policy.allowed_operations.includes(operation))) {
    const latest = await outcome(2, "deny", "unsupported_operation");
    outcomes.push(latest);
    return finish(latest);
  }
  outcomes.push(await outcome(2, "pass", "pipeline_output_allowed"));

  const unknown = sorted(new Set(request.data_classes.filter(
    (category) => !policy.known_data_classes.includes(category),
  )));
  if (unknown.length) {
    const latest = await outcome(3, "deny", "unknown_data_class", unknown);
    outcomes.push(latest);
    return finish(latest);
  }
  const restricted = setIntersection(request.data_classes, policy.restricted_categories);
  if (restricted.length) {
    const latest = await outcome(3, "deny", "restricted_category", restricted);
    outcomes.push(latest);
    return finish(latest);
  }
  const review = setIntersection(
    request.data_classes,
    new Set([...policy.hold_categories, ...policy.ambiguous_categories]),
  );
  if (review.length) {
    const latest = await outcome(3, "hold", "review_required", review, reviewRoute(review, policy));
    outcomes.push(latest);
    return finish(latest);
  }
  outcomes.push(await outcome(3, "pass", "categories_allowed"));
  const latest = await outcome(4, "pass", "policy_passed");
  outcomes.push(latest);
  return finish(latest);
}

export async function computePolicyCommitments(
  bundle: PolicyBundle,
  surface: ExecutionPolicySurface,
  resourceId: string,
): Promise<PolicyCommitments> {
  const request = normalizeRequest(bundle);
  const policy = normalizePolicy(bundle);
  const [purposeHash, pipelineHash, outputSchemaHash] = await Promise.all([
    stableHash("purpose", request.purpose),
    stableHash("pipeline", request.pipeline),
    stableHash("output_schema", request.output_schema),
  ]);
  const [dataClassHashes, operationHashes, riskTagHashes] = await Promise.all([
    categoryHashes(request.data_classes),
    Promise.all(request.operations.map((operation) => stableHash("operation", operation))),
    Promise.all(sorted(request.risk_tags).map((riskTag) => stableHash("risk_tag", riskTag))),
  ]);
  const requestShape: Record<string, unknown> = {
    request_id: request.request_id,
    requester_ref: request.requester_ref,
    purpose_hash: purposeHash,
    pipeline_hash: pipelineHash,
    data_class_hashes: dataClassHashes,
    output_schema_hash: outputSchemaHash,
    operation_hashes: operationHashes,
    risk_tag_hashes: riskTagHashes,
    risk_tag_count: request.risk_tags.length,
  };
  const policyShape: Record<string, unknown> = {
    version: policy.version,
    policy_id: policy.policy_id,
    corpus_ref: policy.corpus_ref,
    allowed_purposes: sorted(policy.allowed_purposes),
    denied_purposes: sorted(policy.denied_purposes),
    allowed_pipelines: sorted(policy.allowed_pipelines),
    allowed_output_schemas: sorted(policy.allowed_output_schemas),
    allowed_operations: sorted(policy.allowed_operations),
    known_data_classes: sorted(policy.known_data_classes),
    restricted_categories: sorted(policy.restricted_categories),
    hold_categories: sorted(policy.hold_categories),
    ambiguous_categories: sorted(policy.ambiguous_categories),
    hold_routes: policy.hold_routes,
  };
  const resourceHash = await computeExecutionResourceHash(surface, resourceId);
  const [requestHash, policyHash, corpusRefHash, localEvaluation] = await Promise.all([
    stableHash("access_request", requestShape),
    stableHash("corpus_policy", policyShape),
    stableHash("corpus_ref", policy.corpus_ref),
    evaluateLocally(request, policy),
  ]);
  return {
    canonicalization_version: POLICY_CANONICALIZATION_VERSION,
    request_hash: requestHash,
    policy_hash: policyHash,
    resource_id_hash: resourceHash,
    purpose_hash: purposeHash,
    pipeline_hash: pipelineHash,
    output_schema_hash: outputSchemaHash,
    corpus_ref_hash: corpusRefHash,
    local_evaluation: localEvaluation,
  };
}
