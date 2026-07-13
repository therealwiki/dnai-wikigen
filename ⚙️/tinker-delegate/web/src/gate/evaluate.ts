/*
 * The pre-inference safeguards gate.
 *
 * `evaluateGate(request, policy)` is a PURE function of its two arguments — no
 * clock, no randomness, no I/O. That is deliberate: it must be testable and
 * auditable. Four ordered checks; the run stops at the first non-pass.
 *
 *   1. Identity & authorization
 *   2. Purpose & use-case screening
 *   3. Bio-risk / clinical-safety screening   (screen-and-deny only)
 *   4. Attested execution
 *
 * `runGate(request, policy, env)` wraps the pure core and, using an injected
 * env (clock / uuid / sign / hash), stamps a StageVerdict[] and emits an
 * AttestationRecord for EVERY run — cleared or stopped, including denials.
 *
 * IMPORTANT (non-negotiable): the verdict logic here is illustrative synthetic
 * scaffolding. In production it is replaced by real screening + human review.
 * Stage 3 is intentionally described at the level of "screen and deny"; it
 * contains no operational detail about hazards and no methods of any kind.
 */
import type {
  AccessRequest,
  AttestationRecord,
  BoundedResult,
  CorpusPolicy,
  Decision,
  EnclaveRef,
  GateRun,
  GateStage,
  StageVerdict,
} from "../types";
import { CAPABILITIES_BY_ID } from "../data/capabilities";
import { ENCLAVES } from "../data/identities";

/** Pure per-stage result: no timestamp, no reviewer — those are added later. */
export type StageOutcome = Pick<StageVerdict, "stage" | "decision" | "reason" | "signals">;

/** Capabilities blocked platform-wide. Present only as deny targets. */
const RESTRICTED_PIPELINES = new Set<string>([
  "germline-edit-designer",
  "de-novo-protein-designer",
  "genome-scale-sequence-generator",
  "de-novo-small-molecule-generator",
]);

/**
 * Maps a restricted-category slug to the declared-intent phrases that route a
 * request to it. This is a screen over the requester's OWN declared purpose and
 * intent text — it is not, and must never become, a description of what makes
 * anything hazardous. Denial is the only output.
 */
const CATEGORY_SIGNALS: Record<string, string[]> = {
  "heritable-germline-editing": ["germline", "heritable edit", "heritable-edit", "embryo edit", "edit an embryo", "germ line", "inheritable edit"],
  "embryo-selection": ["embryo selection", "select embryos", "select an embryo"],
  "reproductive-cloning": ["reproductive cloning", "clone a human", "human cloning"],
  "pathogen-enhancement": ["enhance transmissibility", "increase virulence", "gain-of-function", "gain of function", "pathogen enhancement", "make more transmissible"],
  "enhancement-mutation-search": ["search for mutations that increase", "screen for enhancing mutations", "find enhancing variants"],
  "de-novo-protein-design": ["de novo protein", "design a binder", "design a novel binder", "de novo binder", "design a novel protein", "protein design", "design a novel enzyme"],
  "de-novo-genome-design": ["de novo genome", "generate a genome", "design a synthetic sequence", "design a regulatory element"],
  "de-novo-toxicant-design": ["design a toxic molecule", "de novo toxicant", "design a chemical agent"],
  "immune-evasion-engineering": ["evade the immune", "escape the vaccine", "evade diagnostic", "immune evasion"],
  "synthesis-screening-evasion": ["evade synthesis screening", "defeat biosecurity screening", "bypass sequence screening"],
  "non-therapeutic-enhancement-editing": ["enhancement editing", "edit for enhancement", "non-therapeutic edit"],
  "genomic-linkage-reidentification": ["beacon attack", "re-identify from genome", "relative matching", "genomic linkage attack"],
  "select-agent-work": ["select agent", "restricted pathogen", "select-agent"],
  "patient-reidentification": ["re-identify", "reidentify", "de-anonymize", "deanonymize", "link to identity"],
  "donor-reidentification": ["re-identify donor", "reidentify donor", "deanonymize donor"],
  "insurance-underwriting": ["underwriting", "insurance pricing", "risk-price the applicant"],
  "ip-exfiltration": ["exfiltrate", "copy the vault", "leak the ip", "extract the ip"],
};

/** Soft dual-use phrases -> a HOLD (human review), not an automatic deny. */
const DUAL_USE_SIGNALS = ["unspecified downstream", "resale of outputs", "redistribute results", "share with unnamed third party", "commercial redistribution"];

const ASSURANCE_SCORE: Record<string, number> = { standard: 0.6, elevated: 0.95 };

function includesAny(haystack: string, needles: string[]): string | null {
  const h = haystack.toLowerCase();
  for (const n of needles) {
    if (h.includes(n.toLowerCase())) return n;
  }
  return null;
}

/** Which restricted category (if any) this request maps to, given the policy. */
function matchedRestrictedCategory(request: AccessRequest, policy: CorpusPolicy): string | null {
  const text = `${request.declaredPurpose} ${request.intent}`;
  for (const category of policy.restrictedCategories) {
    // Exact declared-purpose match to a restricted slug, or a phrase match.
    if (request.declaredPurpose === category) return category;
    const signals = CATEGORY_SIGNALS[category] ?? [];
    if (includesAny(text, signals)) return category;
  }
  return null;
}

// --- Stage deciders (pure) ---------------------------------------------------

function decideStage1(request: AccessRequest, policy: CorpusPolicy): StageOutcome {
  const req = request.requester;
  const provided = ASSURANCE_SCORE[request.assuranceTier];
  const required = ASSURANCE_SCORE[policy.requiredAssurance];
  const signals = {
    identityVerified: req.verified ? 1 : 0,
    assuranceProvided: provided,
    assuranceRequired: required,
  };

  let decision: Decision = "pass";
  let reason = "Attested identity present; assurance tier satisfies corpus policy.";

  if (!req.verified) {
    decision = "deny";
    reason = "Requester identity is not attested. Access denied at authorization.";
  } else if (policy.requiredAssurance === "elevated" && request.assuranceTier !== "elevated") {
    decision = "hold";
    reason =
      "Corpus requires elevated assurance. Held for opt-in, proportionate step-up verification (e.g. biometric/facial), then human review.";
  }

  return { stage: 1, decision, reason, signals };
}

function decideStage2(request: AccessRequest, policy: CorpusPolicy): StageOutcome {
  const pipelineAllowed = policy.pipelineAllowlist.includes(request.pipelineRef);
  const purposeAllowed = policy.allowedPurposes.includes(request.declaredPurpose);
  const dualUse = includesAny(`${request.declaredPurpose} ${request.intent}`, DUAL_USE_SIGNALS);
  const signals = {
    pipelineAllowlisted: pipelineAllowed ? 1 : 0,
    purposeAllowed: purposeAllowed ? 1 : 0,
    dualUseFlag: dualUse ? 1 : 0,
  };

  let decision: Decision = "pass";
  let reason = "Declared purpose matches the corpus's allowed-use policy; pipeline is allowlisted.";

  if (!pipelineAllowed) {
    decision = "deny";
    reason = `Requested pipeline "${request.pipelineRef}" is not on this corpus's allowlist. Denied.`;
  } else if (!purposeAllowed) {
    decision = "deny";
    reason = `Declared purpose "${request.declaredPurpose}" is not permitted for this corpus. Denied.`;
  } else if (dualUse) {
    decision = "hold";
    reason = "Possible dual-use / improper intent signalled in the request. Held for human review.";
  }

  return { stage: 2, decision, reason, signals };
}

function decideStage3(request: AccessRequest, policy: CorpusPolicy): StageOutcome {
  const pipelineRestricted = RESTRICTED_PIPELINES.has(request.pipelineRef);
  const category = matchedRestrictedCategory(request, policy);
  const signals = {
    pipelineRestricted: pipelineRestricted ? 1 : 0,
    restrictedCategoryMatch: category ? 1 : 0,
    // Coarse, non-operational: high when a restricted category is matched.
    hazardScreen: pipelineRestricted || category ? 1 : 0,
  };

  let decision: Decision = "pass";
  let reason = "Request screened against restricted categories and hazard signatures. Cleared for attested execution.";

  if (pipelineRestricted) {
    decision = "deny";
    reason =
      "Requested capability is a restricted category, blocked platform-wide. Stopped and routed to human + legal + ethics review. No method is ever produced.";
  } else if (category) {
    decision = "deny";
    reason = `Request maps to restricted category "${category}". Denied by default and routed to human + legal + ethics review.`;
  }

  return { stage: 3, decision, reason, signals };
}

function decideStage4(policy: CorpusPolicy): StageOutcome {
  return {
    stage: 4,
    decision: "pass",
    reason: "Cleared request executed inside the attested enclave. Bounded result returned; raw values never surfaced.",
    signals: {
      enclaveAttested: 1,
      boundedOutputOnly: 1,
      rawSurfaced: 0,
      royaltyCharged: policy.royaltyPerQuery,
    },
  };
}

/**
 * THE PURE GATE. Deterministic function of (request, policy). Returns the
 * ordered verdicts up to and including the first non-pass, or all four stages
 * when the request clears.
 */
export function evaluateGate(request: AccessRequest, policy: CorpusPolicy): StageOutcome[] {
  const outcomes: StageOutcome[] = [];

  const s1 = decideStage1(request, policy);
  outcomes.push(s1);
  if (s1.decision !== "pass") return outcomes;

  const s2 = decideStage2(request, policy);
  outcomes.push(s2);
  if (s2.decision !== "pass") return outcomes;

  const s3 = decideStage3(request, policy);
  outcomes.push(s3);
  if (s3.decision !== "pass") return outcomes;

  outcomes.push(decideStage4(policy));
  return outcomes;
}

// --- Impure sealing wrapper --------------------------------------------------

export type GateEnv = {
  now: () => string; // iso-8601, may advance per call
  uuid: () => string;
  sign: (payload: string) => string;
  hash: (payload: string) => string;
};

function enclaveFor(request: AccessRequest): EnclaveRef {
  const cap = CAPABILITIES_BY_ID[request.pipelineRef];
  if (!cap) return ENCLAVES.phalaCvm;
  if (cap.locality === "on-device") return ENCLAVES.deviceSecure;
  if (cap.locality === "enclave") return ENCLAVES.phalaCvm;
  // hybrid / api-only: the gate + egress boundary still runs in the enclave.
  return ENCLAVES.phalaCvm;
}

function boundedResultFor(request: AccessRequest, policy: CorpusPolicy): BoundedResult {
  const cap = CAPABILITIES_BY_ID[request.pipelineRef];
  const leaves = cap && (cap.locality === "hybrid" || cap.locality === "api-only");
  const note = leaves
    ? "Bounded advisory returned. This capability can call out, so egress was gated and metered; no raw corpus values were transmitted."
    : "Bounded advisory returned. Raw corpus values never left the enclave; only this coarse signal and a result hash were surfaced.";
  return {
    kind: "advisory",
    band: "within-expected-range",
    note,
    royaltyCharged: policy.royaltyPerQuery,
  };
}

function routedTo(last: StageOutcome): string | undefined {
  if (last.decision === "pass") return undefined;
  if (last.stage === 1) {
    return last.decision === "hold" ? "access-review · step-up verification" : "rejected · identity not attested";
  }
  if (last.stage === 2) {
    return last.decision === "hold" ? "access-review · dual-use screening" : "rejected · policy violation";
  }
  // stage 3
  return "human + legal + ethics review";
}

/**
 * Run the gate and seal the result. Emits an AttestationRecord for every run.
 */
export function runGate(request: AccessRequest, policy: CorpusPolicy, env: GateEnv): GateRun {
  const outcomes = evaluateGate(request, policy);
  const verdicts: StageVerdict[] = outcomes.map((o) => ({ ...o, reviewer: null, at: env.now() }));

  const last = outcomes[outcomes.length - 1];
  const cleared = last.stage === 4 && last.decision === "pass";
  const stoppedAt = last.stage as GateStage;

  const gateTrace = outcomes.map((o) => ({ stage: o.stage, decision: o.decision }));
  const boundedResult = cleared ? boundedResultFor(request, policy) : null;
  const resultHash = cleared ? env.hash(`${request.requestId}:${request.pipelineRef}:cleared`) : null;

  const where: AttestationRecord["where"] = cleared ? enclaveFor(request) : "gate://pre-inference";

  const attestationBody = {
    requestId: request.requestId,
    outcome: cleared ? "cleared" : "stopped",
    corpusRef: request.corpusRef,
    pipelineRef: request.pipelineRef,
    gateTrace,
    resultHash,
    at: env.now(),
  };
  const signature = env.sign(JSON.stringify(attestationBody));

  const attestation: AttestationRecord = {
    attestationId: env.uuid(),
    outcome: cleared ? "cleared" : "stopped",
    requestId: request.requestId,
    who: request.requester,
    where,
    corpusRef: request.corpusRef,
    pipelineRef: request.pipelineRef,
    gateTrace,
    resultHash,
    boundedResult,
    signature,
    at: attestationBody.at,
    ...(cleared ? {} : { routedTo: routedTo(last) }),
  };

  return {
    request,
    policy,
    verdicts,
    attestation,
    outcome: cleared ? "cleared" : "stopped",
    stoppedAt,
  };
}
