/*
 * Data contracts for "The Gate: Health".
 *
 * These are the shapes the UI is built against. The four core contracts
 * (AccessRequest, StageVerdict, AttestationRecord, CorpusPolicy) come straight
 * from the build brief. They intentionally echo the real tinker-delegate /
 * NDAI backend: a request is screened, then a bounded evaluation runs inside a
 * TEE, and a tamper-evident attestation is emitted for every run — cleared or
 * stopped. Raw corpus values are never surfaced; only hashes and score bands.
 *
 * NON-NEGOTIABLE: everything here is illustrative synthetic scaffolding. In
 * production the verdict logic is replaced by real screening + human review.
 */

// --- Shared primitives -------------------------------------------------------

/** A verified principal. Never contains raw identifiers — a pointer + role. */
export type IdentityRef = {
  /** stable pseudonymous handle, e.g. "did:key:z6M…" or "org:mayo-cardio" */
  ref: string;
  displayName: string;
  role: PrincipalRole;
  /** attested by an identity provider / KYC vendor; false => stage 1 denies */
  verified: boolean;
  org?: string;
};

export type PrincipalRole =
  | "patient"
  | "clinician"
  | "researcher"
  | "care-team"
  | "biopharma"
  | "operator"
  | "auditor";

/** Pointer to a confidential-compute enclave. Never raw data. */
export type EnclaveRef = {
  ref: string; // e.g. "enclave://phala/cvm-8f21"
  platform: "intel-tdx" | "amd-sev-snp" | "on-device-secure-enclave";
  region: string;
};

/** Evidence backing a request (IRB approval, clinician order, consent). */
export type JustificationRef = {
  kind: "irb-approval" | "clinician-order" | "patient-consent" | "ethics-review" | "data-use-agreement";
  ref: string;
  present: boolean;
};

export type AssuranceTier = "standard" | "elevated";

// --- Core contract: the request ---------------------------------------------

export type AccessRequest = {
  requestId: string; // uuid
  requester: IdentityRef; // verified principal + role
  assuranceTier: AssuranceTier; // elevated => biometric/facial verification
  corpusRef: string; // pointer to sealed corpus; never raw data
  pipelineRef: string; // which registry capability is requested
  declaredPurpose: string;
  /** free-text intent the requester attests to; screened at stage 2/3 */
  intent: string;
  justification?: JustificationRef; // IRB / clinician order / approval evidence
};

// --- Core contract: a stage verdict -----------------------------------------

export type GateStage = 1 | 2 | 3 | 4;
export type Decision = "pass" | "hold" | "deny";

export type StageVerdict = {
  stage: GateStage;
  decision: Decision;
  reason: string;
  /** illustrative numeric signals, e.g. { identityAssurance: 0.98 } */
  signals: Record<string, number>;
  reviewer: IdentityRef | null; // set when a hold is resolved by a human
  at: string; // iso-8601
};

// --- Core contract: the attestation record ----------------------------------

export type AttestationOutcome = "cleared" | "stopped";

export type AttestationRecord = {
  attestationId: string;
  outcome: AttestationOutcome;
  requestId: string;
  who: IdentityRef;
  where: EnclaveRef | "gate://pre-inference";
  corpusRef: string;
  pipelineRef: string;
  gateTrace: Pick<StageVerdict, "stage" | "decision">[];
  resultHash: string | null; // hash only; raw output never stored
  /** bounded, non-raw result summary the enclave is permitted to surface */
  boundedResult: BoundedResult | null;
  signature: string; // enclave-signed, tamper-evident
  at: string;
  /** where a stopped run was routed (human/legal/ethics), when applicable */
  routedTo?: string;
};

/**
 * The only thing an enclave may surface on a cleared run: coarse, non-raw
 * signal. Mirrors tinker-delegate's ScoreBand / bounded-output model.
 */
export type BoundedResult = {
  kind: "score-band" | "yes-no" | "triage-band" | "advisory";
  band: string; // e.g. "high-confidence", "flag-for-review", "within-range"
  note: string; // human-readable, contains NO raw values
  royaltyCharged: number; // marketplace metering for the expose path
};

// --- Core contract: the corpus policy ---------------------------------------

export type SensitivityTier = "low" | "med" | "high" | "restricted";

export type CorpusPolicy = {
  corpusRef: string;
  label: string;
  sensitivityTier: SensitivityTier;
  requiredAssurance: AssuranceTier;
  allowedPurposes: string[];
  pipelineAllowlist: string[];
  restrictedCategories: string[]; // e.g. 'heritable-germline-editing'
  royaltyPerQuery: number; // marketplace metering for the expose path
  custodian: string;
};

// --- Result of running the gate ---------------------------------------------

/** The full trace of one run: verdicts + the attestation it emitted. */
export type GateRun = {
  request: AccessRequest;
  policy: CorpusPolicy;
  verdicts: StageVerdict[];
  attestation: AttestationRecord;
  outcome: AttestationOutcome;
  /** the stage at which the run stopped, or 4 if fully cleared */
  stoppedAt: GateStage;
};

// --- Catalog / registry (publication content) -------------------------------

export type Locality = "on-device" | "enclave" | "hybrid" | "api-only";

/** How color-coded a locality is on the "does data leave?" axis. */
export type LocalityClass = "stays-local" | "caution" | "data-leaves";

export type AppGroup = "everyday" | "clinical" | "collaboration" | "restricted";

export type HealthApp = {
  id: string;
  name: string;
  group: AppGroup;
  valueProp: string;
  locality: Locality;
  sensitivityTier: SensitivityTier;
  /** which of the four gate stages meaningfully apply to this app */
  gateStages: GateStage[];
  requiredAssurance: AssuranceTier;
  corpusRef: string;
  /** capability ids from the registry this app relies on */
  pipelineRefs: string[];
  /** longer editorial body for the card/article */
  body: string;
  /** short bullet list of what stays local vs what (if anything) leaves */
  dataFlow: string[];
  /** true => shown as GATED / denied-by-default, never as a shippable app */
  gated?: boolean;
  /** clinician-in-the-loop decision support (not autonomous) */
  clinicianGated?: boolean;
  /** mental-health / crisis signposting required on this surface */
  crisisSignposting?: boolean;
  /** "not a diagnosis / consult a clinician" framing shown on this surface */
  notDiagnosis?: boolean;
  tags: string[];
};

export type MisuseSensitivity = "low" | "moderate" | "high" | "restricted";

export type Capability = {
  id: string; // pipelineRef
  name: string;
  summary: string;
  locality: Locality;
  misuseSensitivity: MisuseSensitivity;
  /** which gate stages must clear before this capability may run */
  requiresStages: GateStage[];
  /** true => capability is blocked platform-wide, present only as a deny target */
  restricted?: boolean;
  clinicianGated?: boolean;
  /** true => this capability is (or exemplifies) a bio foundation model */
  foundationModel?: boolean;
  /** illustrative model FAMILIES only — never instructions or hazardous specifics */
  modelClassExamples?: string[];
  tags: string[];
};

// --- Small view-model helpers used across components ------------------------

export type LocalityMeta = {
  id: Locality;
  label: string;
  klass: LocalityClass;
  colorVar: string; // CSS custom property name, e.g. "--local-teal"
  blurb: string;
};
