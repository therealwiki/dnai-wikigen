import type { AccessRequest, AttestationOutcome, GateStage } from "../types";
import { IDENTITIES } from "./identities";

/**
 * A demo scenario = a request template + the corpus it targets + what we expect
 * to happen. `requestId` is filled in fresh on every run so the live JSON
 * regenerates each time. `expected*` fields are for labelling the picker only —
 * the gate itself decides the real outcome.
 */
export type Scenario = {
  id: string;
  title: string;
  summary: string;
  expected: AttestationOutcome;
  expectedStopStage: GateStage;
  /** UI accent for the scenario chip */
  kind: "proportionate-clear" | "sensitive-clear" | "hold" | "deny" | "restricted-deny";
  corpusRef: string;
  request: Omit<AccessRequest, "requestId">;
};

export const SCENARIOS: Scenario[] = [
  {
    id: "longevity",
    title: "On-device longevity coach",
    summary: "Owner runs a healthspan model on their own wearable data. Minimal, proportionate gating.",
    expected: "cleared",
    expectedStopStage: 4,
    kind: "proportionate-clear",
    corpusRef: "corpus://owner/wearable-timeseries",
    request: {
      requester: IDENTITIES.patientOwner,
      assuranceTier: "standard",
      corpusRef: "corpus://owner/wearable-timeseries",
      pipelineRef: "healthspan-coach-lm",
      declaredPurpose: "healthspan-coaching",
      intent: "Summarize my sleep, HRV, and VO2max trends into weekly guidance. Stays on my device.",
    },
  },
  {
    id: "chronic-twin",
    title: "Chronic-disease digital twin",
    summary: "Clinician runs a cardio-metabolic twin on high-sensitivity FHIR/OMOP data inside the enclave.",
    expected: "cleared",
    expectedStopStage: 4,
    kind: "sensitive-clear",
    corpusRef: "corpus://meridian/fhir-omop-cardio",
    request: {
      requester: IDENTITIES.clinicianCardio,
      assuranceTier: "standard",
      corpusRef: "corpus://meridian/fhir-omop-cardio",
      pipelineRef: "chronic-disease-digital-twin",
      declaredPurpose: "digital-twin-simulation",
      intent: "Simulate 12-month cardio-metabolic trajectory to support a care-planning review.",
      justification: { kind: "clinician-order", ref: "order://meridian/co-8841", present: true },
    },
  },
  {
    id: "rare-disease",
    title: "Rare-disease genomic interpretation",
    summary:
      "Clinical geneticist interprets a diagnosed patient's WGS. Restricted-tier corpus CLEARS — because assurance is elevated and the purpose is legitimate.",
    expected: "cleared",
    expectedStopStage: 4,
    kind: "sensitive-clear",
    corpusRef: "corpus://helix/patient-wgs",
    request: {
      requester: IDENTITIES.clinicianGenomics,
      assuranceTier: "elevated",
      corpusRef: "corpus://helix/patient-wgs",
      pipelineRef: "variant-effect-predictor",
      declaredPurpose: "variant-interpretation",
      intent: "Predict effect of candidate variants for this diagnosed patient to support interpretation, clinician-in-the-loop.",
      justification: { kind: "clinician-order", ref: "order://helix/vi-207", present: true },
    },
  },
  {
    id: "somatic",
    title: "Somatic gene-therapy decision support",
    summary:
      "Clinician-gated support around an approved, non-heritable therapy for a consenting patient. The legitimate 'gene therapy' path — and it clears.",
    expected: "cleared",
    expectedStopStage: 4,
    kind: "sensitive-clear",
    corpusRef: "corpus://helix/patient-wgs",
    request: {
      requester: IDENTITIES.clinicianGenomics,
      assuranceTier: "elevated",
      corpusRef: "corpus://helix/patient-wgs",
      pipelineRef: "somatic-therapy-decision-support",
      declaredPurpose: "somatic-therapy-decision-support",
      intent: "Decision support for an approved, non-heritable somatic therapy for a diagnosed, consenting patient.",
      justification: { kind: "patient-consent", ref: "consent://helix/pc-455", present: true },
    },
  },
  {
    id: "biomodel-clear",
    title: "Foundation-model variant interpretation",
    summary:
      "A clinical geneticist runs an ACMG-style foundation-model variant interpreter on a consented genome. Analysis use of a bio foundation model — it clears.",
    expected: "cleared",
    expectedStopStage: 4,
    kind: "sensitive-clear",
    corpusRef: "corpus://helix/patient-wgs",
    request: {
      requester: IDENTITIES.clinicianGenomics,
      assuranceTier: "elevated",
      corpusRef: "corpus://helix/patient-wgs",
      pipelineRef: "clinical-variant-interpreter",
      declaredPurpose: "variant-interpretation",
      intent: "Aggregate pathogenicity evidence (ACMG/AMP) for this diagnosed patient's candidate variants, clinician-in-the-loop.",
      justification: { kind: "clinician-order", ref: "order://helix/vi-311", present: true },
    },
  },
  {
    id: "denovo-design",
    title: "Assay tool steered to de novo design",
    summary:
      "An attested biopharma scientist tries to repurpose an allowlisted assay optimizer to generatively design a novel binder. Analysis pipeline, generative intent — denied at stage 3.",
    expected: "stopped",
    expectedStopStage: 3,
    kind: "restricted-deny",
    corpusRef: "corpus://atlas-bio/assay-vault",
    request: {
      requester: IDENTITIES.biopharmaScientist,
      assuranceTier: "elevated",
      corpusRef: "corpus://atlas-bio/assay-vault",
      pipelineRef: "assay-optimizer-lm",
      declaredPurpose: "assay-optimization",
      intent: "Repurpose the optimizer for de novo protein design — generate a novel binder against this target.",
    },
  },
  {
    id: "step-up",
    title: "Genomic request, standard assurance",
    summary: "A researcher targets restricted WGS with only standard assurance. Held at stage 1 for step-up verification.",
    expected: "stopped",
    expectedStopStage: 1,
    kind: "hold",
    corpusRef: "corpus://helix/patient-wgs",
    request: {
      requester: IDENTITIES.researcherLongevity,
      assuranceTier: "standard",
      corpusRef: "corpus://helix/patient-wgs",
      pipelineRef: "variant-effect-predictor",
      declaredPurpose: "variant-interpretation",
      intent: "Interpret variants for a study cohort.",
    },
  },
  {
    id: "allowlist",
    title: "Clinical data via general LLM",
    summary: "A request tries to route high-sensitivity records through a general LLM gateway that would ship data out. Denied at stage 2.",
    expected: "stopped",
    expectedStopStage: 2,
    kind: "deny",
    corpusRef: "corpus://meridian/fhir-omop-cardio",
    request: {
      requester: IDENTITIES.researcherLongevity,
      assuranceTier: "standard",
      corpusRef: "corpus://meridian/fhir-omop-cardio",
      pipelineRef: "general-llm-gateway",
      declaredPurpose: "clinical-decision-support",
      intent: "Send records to a general model for a quick summary.",
    },
  },
  {
    id: "unverified",
    title: "Unverified requester",
    summary: "An unattested principal requests access. Denied immediately at stage 1 authorization.",
    expected: "stopped",
    expectedStopStage: 1,
    kind: "deny",
    corpusRef: "corpus://consortium/cell-atlas-pooled",
    request: {
      requester: IDENTITIES.unverifiedRequester,
      assuranceTier: "standard",
      corpusRef: "corpus://consortium/cell-atlas-pooled",
      pipelineRef: "single-cell-foundation-model",
      declaredPurpose: "cell-atlas-simulation",
      intent: "Run a cell-atlas simulation.",
    },
  },
  {
    id: "pathogen",
    title: "Pooled atlas · hazardous intent",
    summary:
      "A request to the pooled cell atlas whose declared intent maps to a restricted bio-risk category. Deterministically denied at stage 3 (screen-and-deny) and escalated.",
    expected: "stopped",
    expectedStopStage: 3,
    kind: "restricted-deny",
    corpusRef: "corpus://consortium/cell-atlas-pooled",
    request: {
      requester: IDENTITIES.researcherLongevity,
      assuranceTier: "standard",
      corpusRef: "corpus://consortium/cell-atlas-pooled",
      pipelineRef: "single-cell-foundation-model",
      declaredPurpose: "perturbation-modeling",
      intent: "Model perturbations to enhance transmissibility of a pathogen.",
    },
  },
  {
    id: "germline",
    title: "Heritable / germline embryo editing",
    summary:
      "The restricted category, requested directly. Deterministically denied at stage 3, a stop-record is emitted, and it is routed to human + legal + ethics review. No method is ever produced.",
    expected: "stopped",
    expectedStopStage: 3,
    kind: "restricted-deny",
    corpusRef: "corpus://helix/patient-wgs",
    request: {
      requester: IDENTITIES.clinicianGenomics,
      assuranceTier: "elevated",
      corpusRef: "corpus://helix/patient-wgs",
      pipelineRef: "variant-effect-predictor",
      declaredPurpose: "variant-interpretation",
      intent: "Use the variant analysis to design a heritable germline edit to an embryo for this lineage.",
      justification: { kind: "ethics-review", ref: "ethics://pending", present: false },
    },
  },
];

export const SCENARIOS_BY_ID: Record<string, Scenario> = Object.fromEntries(SCENARIOS.map((s) => [s.id, s]));
