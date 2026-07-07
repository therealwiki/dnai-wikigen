import type { CorpusPolicy } from "../types";

/**
 * Synthetic sealed-corpus policies. The gate is a pure function of
 * (AccessRequest, CorpusPolicy); this is the second argument. `corpusRef` is a
 * pointer to a sealed corpus — never the data itself.
 *
 * `restrictedCategories` is what turns stage 3 into a hard deny: any request
 * whose purpose/pipeline maps to a listed category is stopped and routed to
 * human + legal + ethics review.
 */
export const CORPORA: Record<string, CorpusPolicy> = {
  wearableTimeseries: {
    corpusRef: "corpus://owner/wearable-timeseries",
    label: "Personal wearable time-series (sleep, HRV, VO₂max, glucose)",
    sensitivityTier: "low",
    requiredAssurance: "standard",
    allowedPurposes: ["personal-wellness", "healthspan-coaching", "nutrition-modeling", "self-education"],
    pipelineAllowlist: [
      "metabolic-timeseries-forecaster",
      "healthspan-coach-lm",
      "nutrition-glucose-model",
      "onboarding-literacy-lm",
    ],
    restrictedCategories: [],
    royaltyPerQuery: 0,
    custodian: "self (on-device)",
  },

  fhirOmopClinical: {
    corpusRef: "corpus://meridian/fhir-omop-cardio",
    label: "De-identified FHIR/OMOP cardio-metabolic records (synthetic cohort)",
    sensitivityTier: "high",
    requiredAssurance: "standard",
    allowedPurposes: ["clinical-decision-support", "digital-twin-simulation", "care-planning", "irb-approved-research"],
    pipelineAllowlist: ["chronic-disease-digital-twin", "clinical-note-summarizer", "cohort-risk-model"],
    restrictedCategories: ["patient-reidentification", "insurance-underwriting"],
    royaltyPerQuery: 0.0025,
    custodian: "Meridian Cardiology (enclave / on-prem)",
  },

  imagingDicom: {
    corpusRef: "corpus://meridian/imaging-dicom",
    label: "DICOM imaging study set (synthetic, de-identified)",
    sensitivityTier: "high",
    requiredAssurance: "standard",
    allowedPurposes: ["imaging-triage", "clinical-decision-support", "irb-approved-research"],
    pipelineAllowlist: ["imaging-triage-cnn", "clinical-note-summarizer"],
    restrictedCategories: ["patient-reidentification"],
    royaltyPerQuery: 0.004,
    custodian: "Meridian Radiology (enclave)",
  },

  patientWgs: {
    corpusRef: "corpus://helix/patient-wgs",
    label: "Diagnosed patient whole-genome sequence (synthetic, consented)",
    sensitivityTier: "restricted",
    requiredAssurance: "elevated",
    allowedPurposes: [
      "rare-disease-diagnosis",
      "variant-interpretation",
      "somatic-therapy-decision-support",
      "clinician-in-the-loop-analysis",
    ],
    pipelineAllowlist: [
      "variant-effect-predictor",
      "somatic-therapy-decision-support",
      "clinical-variant-interpreter",
      "pharmacogenomics-interpreter",
      "regulatory-splicing-predictor",
    ],
    // The load-bearing safety line: germline/heritable editing is denied here.
    restrictedCategories: [
      "heritable-germline-editing",
      "embryo-selection",
      "reproductive-cloning",
      "non-therapeutic-enhancement-editing",
      "genomic-linkage-reidentification",
      "enhancement-mutation-search",
      "de-novo-genome-design",
    ],
    royaltyPerQuery: 0.02,
    custodian: "Helix Clinical Genetics (enclave, clinician-gated)",
  },

  cellAtlasPooled: {
    corpusRef: "corpus://consortium/cell-atlas-pooled",
    label: "Federated single-cell atlas (pooled, multi-institution, synthetic)",
    sensitivityTier: "high",
    requiredAssurance: "standard",
    allowedPurposes: ["cell-atlas-simulation", "perturbation-modeling", "irb-approved-research"],
    pipelineAllowlist: ["single-cell-foundation-model", "perturbation-simulator"],
    restrictedCategories: [
      "donor-reidentification",
      "pathogen-enhancement",
      "enhancement-mutation-search",
      "genomic-linkage-reidentification",
    ],
    royaltyPerQuery: 0.006,
    custodian: "Open Cell Atlas Consortium (enclave, federated)",
  },

  biopharmaAssay: {
    corpusRef: "corpus://atlas-bio/assay-vault",
    label: "Proprietary biopharma assay vault (synthetic IP)",
    sensitivityTier: "restricted",
    requiredAssurance: "elevated",
    allowedPurposes: ["ip-preserving-collaboration", "outsourced-analysis", "assay-optimization"],
    pipelineAllowlist: ["assay-optimizer-lm", "ip-preserving-agent", "organ-on-chip-controller", "admet-property-predictor"],
    restrictedCategories: [
      "ip-exfiltration",
      "pathogen-enhancement",
      "select-agent-work",
      "de-novo-protein-design",
      "de-novo-genome-design",
      "de-novo-toxicant-design",
      "immune-evasion-engineering",
      "synthesis-screening-evasion",
      "enhancement-mutation-search",
    ],
    royaltyPerQuery: 0.05,
    custodian: "Atlas Bio (TEE workbench)",
  },

  organChip: {
    corpusRef: "corpus://microtissue/organ-on-chip",
    label: "Organ-on-chip experiment telemetry (synthetic)",
    sensitivityTier: "med",
    requiredAssurance: "standard",
    allowedPurposes: ["organ-on-chip-access", "assay-optimization", "outsourced-analysis", "irb-approved-research"],
    pipelineAllowlist: ["organ-on-chip-controller", "ip-preserving-agent", "general-llm-gateway"],
    restrictedCategories: [
      "pathogen-enhancement",
      "select-agent-work",
      "de-novo-toxicant-design",
      "synthesis-screening-evasion",
    ],
    royaltyPerQuery: 0.03,
    custodian: "MicroTissue Labs (hybrid, egress-gated)",
  },
};

export const CORPORA_LIST: CorpusPolicy[] = Object.values(CORPORA);
