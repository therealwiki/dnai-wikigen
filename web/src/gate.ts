// The pre-inference safeguards gate.
//
// evaluateGate is a PURE function of (AccessRequest, CorpusPolicy). Given the same
// inputs it returns the same verdicts — keep it that way so it stays testable and
// auditable. The only impurity lives in `mint*` helpers that stamp ids/timestamps;
// they are injected so the core decision logic can be exercised deterministically.
//
// NON-NEGOTIABLE: this is illustrative scaffolding. In production the verdict logic
// is replaced by real identity attestation, purpose review, bio-risk screening, and
// human-in-the-loop review. Stage 3 here only ever *screens and denies* — it never
// encodes operational detail about what makes a request hazardous.

import type {
  AccessRequest,
  AttestationRecord,
  CorpusPolicy,
  Decision,
  EnclaveRef,
  StageVerdict,
} from "./types";

export interface GateResult {
  verdicts: StageVerdict[];
  attestation: AttestationRecord;
  cleared: boolean;
}

export interface GateClock {
  now: () => string; // iso-8601
  uuid: () => string;
  hash: (input: string) => string;
}

// Categories the platform blocks by default. Requests that map here are routed to
// human + legal + ethics review and a stop-record is emitted. No methods, targets,
// reagents, or workflows are represented anywhere — only the category label.
const DENY_BY_DEFAULT = new Set<string>([
  "heritable-germline-editing",
  "embryo-germline-modification",
  "pathogen-enhancement",
  "bio-agent-synthesis",
]);

const enclaveFor = (corpusRef: string): EnclaveRef => ({
  enclave: `modeled://cvm-${corpusRef.split(":").pop() ?? "sealed"}`,
  measurement: "illustrative-only:not-a-tdx-quote",
});

function verdict(
  stage: 1 | 2 | 3 | 4,
  decision: Decision,
  reason: string,
  signals: Record<string, number>,
  clock: GateClock,
  reviewer: StageVerdict["reviewer"] = null,
): StageVerdict {
  return { stage, decision, reason, signals, reviewer, at: clock.now() };
}

// --- Stage 1: Identity & authorization -------------------------------------
function stage1(req: AccessRequest, policy: CorpusPolicy, clock: GateClock): StageVerdict {
  const identityScore = req.requester.verified ? 1 : 0;
  const roleKnown = req.requester.role.trim().length > 0 ? 1 : 0;

  if (!req.requester.verified) {
    return verdict(1, "deny", "Requester identity is not attested.", { identityScore, roleKnown }, clock);
  }
  // Elevated corpora require step-up assurance (biometric/facial is opt-in and
  // proportionate — presented as privacy-law-bound, never default surveillance).
  if (policy.requiredAssurance === "elevated" && req.assuranceTier !== "elevated") {
    return verdict(
      1,
      "hold",
      "Corpus requires elevated assurance; step-up (opt-in) verification pending.",
      { identityScore, roleKnown, assuranceGap: 1 },
      clock,
    );
  }
  return verdict(1, "pass", "Attested principal with an authorized role.", { identityScore, roleKnown, assuranceGap: 0 }, clock);
}

// --- Stage 2: Purpose & use-case screening ---------------------------------
function stage2(req: AccessRequest, policy: CorpusPolicy, clock: GateClock): StageVerdict {
  const declared = req.declaredPurpose.trim();
  const allowed = policy.allowedPurposes.includes(declared);
  const hasJustification = req.justification && req.justification.kind !== "none" ? 1 : 0;

  if (!allowed) {
    return verdict(
      2,
      "deny",
      `Declared purpose "${declared || "(none)"}" is outside the corpus allowed-use policy.`,
      { purposeMatch: 0, hasJustification },
      clock,
    );
  }
  // High/restricted corpora need documented justification; missing evidence is a
  // hold for human review rather than an outright deny.
  const needsEvidence = policy.sensitivityTier === "high" || policy.sensitivityTier === "restricted";
  if (needsEvidence && !hasJustification) {
    return verdict(
      2,
      "hold",
      "Purpose is allowed but justification evidence (IRB / clinician order / DUA) is missing.",
      { purposeMatch: 1, hasJustification: 0 },
      clock,
    );
  }
  return verdict(2, "pass", "Declared purpose matches the corpus allowed-use policy.", { purposeMatch: 1, hasJustification }, clock);
}

// --- Stage 3: Bio-risk / clinical-safety screening -------------------------
// Screens the request against restricted categories and hazard signatures BEFORE
// inference. Deterministic deny for restricted categories; the reasons are kept at
// the level of "screen and deny", never operational detail.
function stage3(req: AccessRequest, policy: CorpusPolicy, clock: GateClock): StageVerdict {
  const restricted = new Set([...policy.restrictedCategories, ...DENY_BY_DEFAULT]);

  // Normalize any string to a hyphen-joined token stream, then look for a
  // restricted category phrase as a whole. Simple and auditable: a request is
  // denied iff its capability, purpose, or corpus names a restricted category.
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  const haystack = [req.pipelineRef, req.declaredPurpose, req.corpusRef].map(norm).join("|");
  const matched = [...restricted].find((cat) => haystack.includes(norm(cat)));

  if (matched) {
    return verdict(
      3,
      "deny",
      "Restricted category matched. Routed to human + legal + ethics review; no inference performed.",
      { restrictedMatch: 1, hazardSignature: 1 },
      clock,
    );
  }
  return verdict(3, "pass", "No restricted category or hazard signature matched.", { restrictedMatch: 0, hazardSignature: 0 }, clock);
}

// --- Stage 4: Attested execution -------------------------------------------
function stage4(req: AccessRequest, policy: CorpusPolicy, clock: GateClock): StageVerdict {
  const onAllowlist = policy.pipelineAllowlist.includes(req.pipelineRef);
  if (!onAllowlist) {
    return verdict(
      4,
      "deny",
      `Pipeline "${req.pipelineRef}" is not on the corpus pipeline allowlist.`,
      { allowlisted: 0 },
      clock,
    );
  }
  return verdict(
    4,
    "pass",
    "Cleared request admitted to the enclave; results bounded, raw values never surfaced.",
    { allowlisted: 1 },
    clock,
  );
}

export function evaluateGate(req: AccessRequest, policy: CorpusPolicy, clock: GateClock): GateResult {
  const stages = [stage1, stage2, stage3, stage4] as const;
  const verdicts: StageVerdict[] = [];

  for (const run of stages) {
    const v = run(req, policy, clock);
    verdicts.push(v);
    if (v.decision !== "pass") break; // stop at the first non-pass
  }

  const cleared = verdicts.length === 4 && verdicts.every((v) => v.decision === "pass");
  const outcome: AttestationRecord["outcome"] = cleared ? "cleared" : "stopped";

  // Every modeled run emits a receipt-shaped record. This simulator does not
  // possess a hardware-bound signing key and must never imply that it does.
  const gateTrace = verdicts.map((v) => ({ stage: v.stage, decision: v.decision }));
  const resultHash = cleared ? clock.hash(`${req.requestId}:${req.pipelineRef}:result`) : null;
  const signaturePayload = `${outcome}|${req.requestId}|${gateTrace.map((t) => `${t.stage}${t.decision[0]}`).join("")}`;

  const attestation: AttestationRecord = {
    attestationId: clock.uuid(),
    outcome,
    requestId: req.requestId,
    who: req.requester,
    where: cleared ? enclaveFor(req.corpusRef) : "gate://pre-inference",
    corpusRef: req.corpusRef,
    pipelineRef: req.pipelineRef,
    gateTrace,
    resultHash,
    signature: `modeled-receipt:${clock.hash(signaturePayload)}`,
    at: clock.now(),
  };

  return { verdicts, attestation, cleared };
}

// Browser-backed clock. Deterministic-friendly: swap in a fixed clock for tests.
export const browserClock: GateClock = {
  now: () => new Date().toISOString(),
  uuid: () =>
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : `uuid-${Math.random().toString(16).slice(2, 10)}`,
  hash: (input: string) => {
    // Small non-cryptographic digest — enough to look/behave like a content hash
    // in the demo. Real deployments use the enclave's signing key over the quote.
    let h1 = 0x811c9dc5;
    for (let i = 0; i < input.length; i++) {
      h1 ^= input.charCodeAt(i);
      h1 = Math.imul(h1, 0x01000193);
    }
    const hex = (h1 >>> 0).toString(16).padStart(8, "0");
    return `0x${hex}${hex.split("").reverse().join("")}`;
  },
};
