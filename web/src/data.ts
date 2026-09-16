// Synthetic content for the publication. NO real PHI, genomes, or identifiers —
// every value here is clearly illustrative.

import type { AccessRequest, Capability, CorpusPolicy, HealthApp } from "./types";

// ---------------------------------------------------------------------------
// Health / bio-model app catalog (the "publication" content)
// ---------------------------------------------------------------------------
export const APPS: HealthApp[] = [
  // Everyday / on-device — low sensitivity, minimal gating
  {
    id: "longevity-coach",
    name: "Longevity & healthspan coach",
    valueProp: "Sleep, VO2max, HRV, and metabolic trends from wearables, modeled on the device that holds them.",
    locality: "on-device",
    sensitivity: "low",
    gateStages: [1],
    category: "everyday",
    notes: "Nothing leaves the device. Education and decision-support only — not a diagnosis.",
  },
  {
    id: "nutrition-glucose",
    name: "Nutrition & glucose-response modeling",
    valueProp: "Personal glucose-response curves from CGM + food logs, computed locally.",
    locality: "on-device",
    sensitivity: "low",
    gateStages: [1],
    category: "everyday",
    notes: "On-device inference; consult a clinician before changing a management plan.",
  },
  {
    id: "mood-journal",
    name: "Mental-health journaling & mood support",
    valueProp: "Reflective journaling with an on-device LLM that never uploads entries.",
    locality: "on-device",
    sensitivity: "med",
    gateStages: [1, 2],
    category: "everyday",
    notes:
      "Support and signposting, not clinical diagnosis. Surfaces crisis resources (e.g. 988 in the US, local emergency services) when distress is detected.",
  },

  // Clinical / enclave — medium–high sensitivity, full gate
  {
    id: "cardio-twin",
    name: "Chronic-disease digital twin",
    valueProp: "Cardio-metabolic digital twin built on FHIR/OMOP records, run beside the data.",
    locality: "enclave",
    sensitivity: "high",
    gateStages: [1, 2, 3, 4],
    category: "clinical",
    notes: "Operators can't read raw values; outputs are bounded. Clinician-in-the-loop.",
  },
  {
    id: "imaging-triage",
    name: "Medical imaging triage assistant",
    valueProp: "Prioritizes studies for radiologist review inside a confidential-compute enclave.",
    locality: "enclave",
    sensitivity: "high",
    gateStages: [1, 2, 3, 4],
    category: "clinical",
    notes: "Decision-support for a licensed reader — never an autonomous read.",
  },
  {
    id: "rare-disease-genomic",
    name: "Rare-disease & genomic interpretation",
    valueProp: "Variant-effect prediction on a patient's WGS for a diagnosed condition, clinician-in-the-loop.",
    locality: "enclave",
    sensitivity: "restricted",
    gateStages: [1, 2, 3, 4],
    category: "clinical",
    notes: "Elevated assurance. Analysis only, for an existing diagnosis, with a clinician interpreting results.",
  },
  {
    id: "somatic-companion",
    name: "Somatic genomic-medicine companion",
    valueProp:
      "Decision-support around approved, non-heritable therapies for a diagnosed, consenting patient (e.g. approved cell/gene therapies).",
    locality: "enclave",
    sensitivity: "restricted",
    gateStages: [1, 2, 3, 4],
    category: "clinical",
    notes:
      "The legitimate somatic story: treats an existing consenting patient, is NOT heritable, and is clinician-gated. No editing methods are provided.",
  },

  // Bio-model collaborations (wikigen.me) — pooled/enclave, IP-preserving
  {
    id: "gene-model-pool",
    name: "Gene-modeling collaboration pool",
    valueProp: "Bring a variant-effect model to pooled, sealed sequence corpora without moving anyone's data.",
    locality: "enclave",
    sensitivity: "high",
    gateStages: [1, 2, 3, 4],
    category: "bio-model",
    notes: "IP-preserving: contributors keep custody; only bounded results and royalties-per-query cross the boundary.",
  },
  {
    id: "cell-atlas-sim",
    name: "Cell-atlas simulation access",
    valueProp: "Query and simulate against a shared single-cell atlas inside the enclave that hosts it.",
    locality: "enclave",
    sensitivity: "high",
    gateStages: [1, 2, 3, 4],
    category: "bio-model",
    notes: "Simulation and analysis only. Raw atlas records never surface; outputs are aggregate.",
  },
  {
    id: "organ-on-chip",
    name: "Organ-on-chip access broker",
    valueProp: "Book and parameterize organ-on-chip experiments; results returned as bounded readouts.",
    locality: "hybrid",
    sensitivity: "med",
    gateStages: [1, 2, 3, 4],
    category: "bio-model",
    notes: "Self-hostable broker that calls a general model — egress is gated. Wet-lab protocols stay with the lab.",
  },
  {
    id: "sequence-me-101",
    name: "Sequence-me 101 guidelines",
    valueProp: "Onboarding guidance for individuals/orgs sequencing for the first time: consent, custody, and locality choices.",
    locality: "on-device",
    sensitivity: "low",
    gateStages: [1],
    category: "bio-model",
    notes: "Educational guidelines only — no wet-lab or synthesis instructions. Points to accredited providers.",
  },
  {
    id: "biopharma-tee",
    name: "Biopharma TEE setup advisor",
    valueProp: "Plan confidential-compute deployments for pre-competitive biopharma collaboration on sealed corpora.",
    locality: "enclave",
    sensitivity: "high",
    gateStages: [1, 2, 3, 4],
    category: "bio-model",
    notes: "IP-preserving synergy for experimenting, outsourcing, and budget-saving — bounded outputs, per-query metering.",
  },

  // Restricted — rendered as GATED, never a shippable app
  {
    id: "germline-editing",
    name: "Heritable / germline embryo editing",
    valueProp: "Restricted category. Denied by default and routed to human + legal + ethics review.",
    locality: "enclave",
    sensitivity: "restricted",
    gateStages: [1, 2, 3],
    category: "restricted",
    gated: true,
    notes:
      "Shown only as a gated-deny example. No protocol, method, target, reagent, or workflow appears anywhere — the platform blocks the category and emits a stop-record.",
  },
];

// ---------------------------------------------------------------------------
// Capability registry (what pipelineAllowlist points at)
// ---------------------------------------------------------------------------
export const CAPABILITIES: Capability[] = [
  {
    pipelineRef: "cap://wearable-trends/v3",
    name: "Wearable trend model",
    locality: "on-device",
    misuseSensitivity: "low",
    summary: "Time-series trends over sleep/HRV/VO2max. Runs entirely on-device.",
  },
  {
    pipelineRef: "cap://glucose-response/v2",
    name: "Glucose-response model",
    locality: "on-device",
    misuseSensitivity: "low",
    summary: "Personal post-prandial curve estimation from CGM + food logs.",
  },
  {
    pipelineRef: "cap://mood-support-llm/v1",
    name: "On-device support LLM",
    locality: "on-device",
    misuseSensitivity: "med",
    summary: "Reflective journaling assistant with crisis signposting. No uploads.",
  },
  {
    pipelineRef: "cap://cardio-twin/v4",
    name: "Cardio-metabolic digital twin",
    locality: "enclave",
    misuseSensitivity: "med",
    summary: "FHIR/OMOP-backed twin. Bounded risk-band outputs only.",
  },
  {
    pipelineRef: "cap://imaging-triage/v2",
    name: "Imaging triage ranker",
    locality: "enclave",
    misuseSensitivity: "med",
    summary: "Study prioritization for a licensed reader. No autonomous reads.",
  },
  {
    pipelineRef: "cap://variant-effect/v5",
    name: "Variant-effect predictor",
    locality: "enclave",
    misuseSensitivity: "high",
    summary: "Analysis of a diagnosed patient's variants. Clinician-in-the-loop, elevated assurance.",
  },
  {
    pipelineRef: "cap://somatic-decision-support/v1",
    name: "Somatic therapy decision-support",
    locality: "enclave",
    misuseSensitivity: "high",
    summary: "Guidance around approved non-heritable therapies. No editing methods.",
  },
  {
    pipelineRef: "cap://cell-atlas-sim/v2",
    name: "Cell-atlas simulator",
    locality: "enclave",
    misuseSensitivity: "med",
    summary: "Aggregate queries/simulation over a sealed single-cell atlas.",
  },
  {
    pipelineRef: "cap://organ-on-chip-broker/v1",
    name: "Organ-on-chip broker",
    locality: "hybrid",
    misuseSensitivity: "med",
    summary: "Parameterizes chip runs; returns bounded readouts. Egress gated.",
  },
];

// ---------------------------------------------------------------------------
// Corpus policies (the gate reads these)
// ---------------------------------------------------------------------------
export const POLICIES: Record<string, CorpusPolicy> = {
  "corpus:wearable-me": {
    corpusRef: "corpus:wearable-me",
    sensitivityTier: "low",
    requiredAssurance: "standard",
    allowedPurposes: ["personal-healthspan", "self-tracking"],
    pipelineAllowlist: ["cap://wearable-trends/v3", "cap://glucose-response/v2"],
    restrictedCategories: [],
    royaltyPerQuery: 0,
  },
  "corpus:journal-me": {
    corpusRef: "corpus:journal-me",
    sensitivityTier: "med",
    requiredAssurance: "standard",
    allowedPurposes: ["mood-support", "self-reflection"],
    pipelineAllowlist: ["cap://mood-support-llm/v1"],
    restrictedCategories: [],
    royaltyPerQuery: 0,
  },
  "corpus:health-system-fhir": {
    corpusRef: "corpus:health-system-fhir",
    sensitivityTier: "high",
    requiredAssurance: "standard",
    allowedPurposes: ["clinical-decision-support", "care-planning", "quality-improvement"],
    pipelineAllowlist: ["cap://cardio-twin/v4", "cap://imaging-triage/v2"],
    restrictedCategories: ["heritable-germline-editing", "pathogen-enhancement"],
    royaltyPerQuery: 0.02,
  },
  "corpus:patient-wgs": {
    corpusRef: "corpus:patient-wgs",
    sensitivityTier: "restricted",
    requiredAssurance: "elevated",
    allowedPurposes: ["diagnostic-interpretation", "somatic-decision-support"],
    pipelineAllowlist: ["cap://variant-effect/v5", "cap://somatic-decision-support/v1"],
    restrictedCategories: ["heritable-germline-editing", "embryo-germline-modification"],
    royaltyPerQuery: 0.05,
  },
  "corpus:pooled-atlas": {
    corpusRef: "corpus:pooled-atlas",
    sensitivityTier: "high",
    requiredAssurance: "standard",
    allowedPurposes: ["research-simulation", "target-discovery", "pre-competitive-collaboration"],
    pipelineAllowlist: ["cap://cell-atlas-sim/v2", "cap://variant-effect/v5"],
    restrictedCategories: ["heritable-germline-editing", "pathogen-enhancement", "bio-agent-synthesis"],
    royaltyPerQuery: 0.03,
  },
};

// ---------------------------------------------------------------------------
// Example access requests for the gate simulator
// ---------------------------------------------------------------------------
export interface ExampleRequest {
  label: string;
  expected: "cleared" | "hold" | "stopped";
  blurb: string;
  request: AccessRequest;
  policyRef: keyof typeof POLICIES;
}

export const EXAMPLES: ExampleRequest[] = [
  {
    label: "On-device healthspan (low sensitivity)",
    expected: "cleared",
    blurb: "Owner runs a trend model against their own wearable data. Minimal, proportionate gating.",
    policyRef: "corpus:wearable-me",
    request: {
      requestId: "req-0001-wearable",
      requester: { principal: "did:demo:owner-a", role: "data-owner", verified: true },
      assuranceTier: "standard",
      corpusRef: "corpus:wearable-me",
      pipelineRef: "cap://wearable-trends/v3",
      declaredPurpose: "personal-healthspan",
    },
  },
  {
    label: "Rare-disease genomic interpretation (high sensitivity, CLEARED)",
    expected: "cleared",
    blurb:
      "Clinician runs variant-effect analysis on a diagnosed patient's sealed WGS. Elevated assurance + IRB — proportionate gating clears it, not blanket blocking.",
    policyRef: "corpus:patient-wgs",
    request: {
      requestId: "req-0002-wgs",
      requester: { principal: "did:demo:clinician-k", role: "treating-clinician", verified: true },
      assuranceTier: "elevated",
      corpusRef: "corpus:patient-wgs",
      pipelineRef: "cap://variant-effect/v5",
      declaredPurpose: "diagnostic-interpretation",
      justification: { kind: "irb", ref: "IRB-2026-0417 (synthetic)" },
    },
  },
  {
    label: "Somatic therapy decision-support (CLEARED)",
    expected: "cleared",
    blurb: "Decision-support around approved, non-heritable therapies for a consenting diagnosed patient.",
    policyRef: "corpus:patient-wgs",
    request: {
      requestId: "req-0003-somatic",
      requester: { principal: "did:demo:clinician-k", role: "treating-clinician", verified: true },
      assuranceTier: "elevated",
      corpusRef: "corpus:patient-wgs",
      pipelineRef: "cap://somatic-decision-support/v1",
      declaredPurpose: "somatic-decision-support",
      justification: { kind: "clinician-order", ref: "ORDER-88213 (synthetic)" },
    },
  },
  {
    label: "Pooled cell-atlas simulation (bio-model collaboration)",
    expected: "cleared",
    blurb: "Researcher simulates against a pooled, sealed cell atlas. Per-query royalty metered; raw records never surface.",
    policyRef: "corpus:pooled-atlas",
    request: {
      requestId: "req-0004-atlas",
      requester: { principal: "did:demo:researcher-m", role: "research-collaborator", verified: true },
      assuranceTier: "standard",
      corpusRef: "corpus:pooled-atlas",
      pipelineRef: "cap://cell-atlas-sim/v2",
      declaredPurpose: "research-simulation",
      justification: { kind: "data-use-agreement", ref: "DUA-2026-556 (synthetic)" },
    },
  },
  {
    label: "Elevated corpus, standard assurance (HOLD)",
    expected: "hold",
    blurb: "Right purpose, but the restricted corpus needs opt-in step-up assurance. Held for review, not denied.",
    policyRef: "corpus:patient-wgs",
    request: {
      requestId: "req-0005-stepup",
      requester: { principal: "did:demo:clinician-r", role: "treating-clinician", verified: true },
      assuranceTier: "standard",
      corpusRef: "corpus:patient-wgs",
      pipelineRef: "cap://variant-effect/v5",
      declaredPurpose: "diagnostic-interpretation",
      justification: { kind: "irb", ref: "IRB-2026-0420 (synthetic)" },
    },
  },
  {
    label: "Purpose outside allowed-use (DENY)",
    expected: "stopped",
    blurb: "A marketing purpose against clinical records is outside the corpus policy. Denied at stage 2.",
    policyRef: "corpus:health-system-fhir",
    request: {
      requestId: "req-0006-purpose",
      requester: { principal: "did:demo:vendor-x", role: "third-party-vendor", verified: true },
      assuranceTier: "standard",
      corpusRef: "corpus:health-system-fhir",
      pipelineRef: "cap://cardio-twin/v4",
      declaredPurpose: "marketing-audience-building",
    },
  },
  {
    label: "Heritable germline editing (RESTRICTED — DENY at stage 3)",
    expected: "stopped",
    blurb:
      "A heritable-germline-editing request. The gate denies deterministically at the bio-risk stage, routes to human + legal + ethics review, and emits a stop-record. No methods exist anywhere in this app.",
    policyRef: "corpus:patient-wgs",
    request: {
      requestId: "req-0007-germline",
      requester: { principal: "did:demo:requester-z", role: "external-lab", verified: true },
      assuranceTier: "elevated",
      corpusRef: "corpus:patient-wgs",
      // Benign-looking identity, purpose, and paperwork — the bio-risk stage still
      // catches the restricted capability being requested and denies deterministically.
      pipelineRef: "cap://heritable-germline-editing/v0",
      declaredPurpose: "diagnostic-interpretation",
      justification: { kind: "irb", ref: "IRB-2026-0431 (synthetic)" },
    },
  },
];
