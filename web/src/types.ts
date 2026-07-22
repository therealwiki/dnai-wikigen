// Data contracts for the pre-inference safeguards gate.
// These mirror the shapes an enclave-backed deployment would exchange.
// Everything here is illustrative scaffolding — no real PHI, genomes, or identifiers.

export type Locality = "on-device" | "enclave" | "hybrid" | "api-only";

export type SensitivityTier = "low" | "med" | "high" | "restricted";

export type Assurance = "standard" | "elevated";

export type Decision = "pass" | "hold" | "deny";

export interface IdentityRef {
  principal: string; // opaque handle, never a real identifier
  role: string;
  verified: boolean;
}

export interface JustificationRef {
  kind: "irb" | "clinician-order" | "ethics-approval" | "data-use-agreement" | "none";
  ref: string;
}

export interface EnclaveRef {
  enclave: string; // modeled:// in the browser lab; production types are separate
  measurement: string; // explicit illustrative marker, never a TDX quote
}

export interface AccessRequest {
  requestId: string; // uuid
  requester: IdentityRef; // verified principal + role
  assuranceTier: Assurance; // elevated => biometric/facial (opt-in, proportionate)
  corpusRef: string; // pointer to sealed corpus; never raw data
  pipelineRef: string; // which registry capability is requested
  declaredPurpose: string;
  justification?: JustificationRef; // IRB / clinician order / approval evidence
}

export interface StageVerdict {
  stage: 1 | 2 | 3 | 4;
  decision: Decision;
  reason: string;
  signals: Record<string, number>;
  reviewer: IdentityRef | null; // set when a hold is resolved by a human
  at: string; // iso-8601
}

export interface AttestationRecord {
  attestationId: string;
  outcome: "cleared" | "stopped";
  requestId: string;
  who: IdentityRef;
  where: EnclaveRef | "gate://pre-inference";
  corpusRef: string;
  pipelineRef: string;
  gateTrace: Pick<StageVerdict, "stage" | "decision">[];
  resultHash: string | null; // hash only; raw output never stored
  signature: string; // modeled-receipt marker in this lab; not a hardware signature
  at: string;
}

export interface CorpusPolicy {
  corpusRef: string;
  sensitivityTier: SensitivityTier;
  requiredAssurance: Assurance;
  allowedPurposes: string[];
  pipelineAllowlist: string[];
  restrictedCategories: string[]; // e.g. 'heritable-germline-editing'
  royaltyPerQuery: number; // marketplace metering for the expose path
}

// ---- Catalog + registry view models (publication content) ----

export type GateStage = 1 | 2 | 3 | 4;

export interface HealthApp {
  id: string;
  name: string;
  valueProp: string;
  locality: Locality;
  sensitivity: SensitivityTier;
  gateStages: GateStage[]; // which stages apply
  category: "everyday" | "clinical" | "bio-model" | "restricted";
  notes?: string; // framing notes, e.g. crisis signposting / clinician-in-the-loop
  gated?: boolean; // restricted: rendered as deny-by-default, never shippable
}

export interface Capability {
  pipelineRef: string;
  name: string;
  locality: Locality;
  misuseSensitivity: "low" | "med" | "high";
  summary: string;
}
