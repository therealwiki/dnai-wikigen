import type { Capability } from "../types";

/**
 * Capability registry — the model/pipeline list a corpus policy's
 * `pipelineAllowlist` points at. Each is tagged with locality + misuse
 * sensitivity. A request naming a pipeline outside a corpus's allowlist is
 * denied at stage 2; a `restricted` capability is blocked platform-wide and
 * exists here only as a deny target.
 */
export const CAPABILITIES: Capability[] = [
  {
    id: "metabolic-timeseries-forecaster",
    name: "Metabolic time-series forecaster",
    summary: "Forecasts glucose / HRV / recovery trends from wearable streams. Small model, runs on the phone.",
    locality: "on-device",
    misuseSensitivity: "low",
    requiresStages: [1],
    tags: ["wearables", "metabolic", "forecasting"],
  },
  {
    id: "healthspan-coach-lm",
    name: "Healthspan coach LM",
    summary: "On-device language model that turns personal trends into plain-language, non-clinical guidance.",
    locality: "on-device",
    misuseSensitivity: "low",
    requiresStages: [1],
    tags: ["coaching", "on-device-llm", "wellness"],
  },
  {
    id: "nutrition-glucose-model",
    name: "Nutrition & glucose-response model",
    summary: "Estimates personal glucose response to meals; keeps the food + CGM log on-device.",
    locality: "on-device",
    misuseSensitivity: "low",
    requiresStages: [1],
    tags: ["nutrition", "cgm", "on-device"],
  },
  {
    id: "onboarding-literacy-lm",
    name: "Sequence-Me 101 literacy LM",
    summary: "Explains what a personal genome / lab report does and does not mean. Education only, on-device.",
    locality: "on-device",
    misuseSensitivity: "low",
    requiresStages: [1],
    tags: ["education", "literacy", "genomics-101"],
  },
  {
    id: "chronic-disease-digital-twin",
    name: "Chronic-disease digital twin",
    summary: "Simulates cardio-metabolic trajectories on FHIR/OMOP data inside the enclave. Decision support only.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    clinicianGated: true,
    tags: ["digital-twin", "fhir", "omop", "cardio"],
  },
  {
    id: "imaging-triage-cnn",
    name: "Imaging triage model",
    summary: "Flags studies for prioritized human read. Returns a triage band, never a diagnosis.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    clinicianGated: true,
    tags: ["imaging", "triage", "radiology"],
  },
  {
    id: "clinical-note-summarizer",
    name: "Clinical note summarizer",
    summary: "Summarizes records for the care team inside the enclave; bounded output, no raw record egress.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    clinicianGated: true,
    tags: ["nlp", "summarization", "ehr"],
  },
  {
    id: "cohort-risk-model",
    name: "Cohort risk model",
    summary: "Population-level risk estimates over a de-identified cohort under IRB-approved purposes.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    tags: ["epidemiology", "risk", "cohort"],
  },
  {
    id: "variant-effect-predictor",
    name: "Variant-effect predictor",
    summary:
      "Predicts effect of variants on a diagnosed patient's WGS for interpretation. Clinician-in-the-loop, elevated assurance.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    clinicianGated: true,
    tags: ["genomics", "variant-effect", "rare-disease"],
  },
  {
    id: "somatic-therapy-decision-support",
    name: "Somatic therapy decision support",
    summary:
      "Decision support around approved, non-heritable cell/gene therapies for a diagnosed, consenting patient. Clinician-gated.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    clinicianGated: true,
    tags: ["somatic", "approved-therapy", "non-heritable", "clinician-gated"],
  },
  {
    id: "single-cell-foundation-model",
    name: "Single-cell foundation model",
    summary: "Cell-atlas simulation and cell-state inference over a pooled, federated atlas inside the enclave.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    tags: ["single-cell", "atlas", "foundation-model"],
  },
  {
    id: "perturbation-simulator",
    name: "Perturbation simulator",
    summary: "Simulates cell-state response to modeled perturbations for research under allowed purposes.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    tags: ["perturbation", "simulation", "research"],
  },
  {
    id: "organ-on-chip-controller",
    name: "Organ-on-chip controller",
    summary:
      "Brokers remote, metered access to instrumented organ-on-chip rigs. Self-hostable; any model call-out is egress-gated.",
    locality: "hybrid",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    tags: ["organ-on-chip", "wet-lab", "metered-access"],
  },
  {
    id: "assay-optimizer-lm",
    name: "Assay optimizer LM",
    summary: "Suggests assay design improvements over a sealed biopharma vault. IP never leaves the TEE.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    tags: ["biopharma", "assay", "optimization"],
  },
  {
    id: "ip-preserving-agent",
    name: "IP-preserving collaboration agent",
    summary:
      "Agentic tool for outsourcing analysis and synergy without disclosing either side's IP. Bounded outputs to your inbox.",
    locality: "hybrid",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    tags: ["agent", "ip-preserving", "collaboration", "outsourcing"],
  },
  {
    id: "general-llm-gateway",
    name: "General-LLM gateway",
    summary:
      "Routes a request to a general third-party model. Data transits — allowed only when the corpus policy permits egress.",
    locality: "api-only",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    tags: ["gateway", "general-llm", "egress"],
  },
  {
    id: "third-party-imaging-api",
    name: "Third-party imaging API",
    summary: "External imaging capability behind a vendor API. Strictest gating; egress must be explicitly allowed.",
    locality: "api-only",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    tags: ["api-only", "imaging", "vendor"],
  },
  {
    id: "germline-edit-designer",
    name: "Germline / heritable-edit designer",
    summary:
      "BLOCKED platform-wide. Heritable human editing is a restricted category. Present only as a deny target — no methods, no parameters, no workflow. Requests routing here are stopped and escalated to human + legal + ethics review.",
    locality: "enclave",
    misuseSensitivity: "restricted",
    requiresStages: [1, 2, 3],
    restricted: true,
    tags: ["restricted", "blocked", "germline", "deny-by-default"],
  },

  // --- Bioinformatics foundation models (analysis-first) ---------------------
  {
    id: "clinical-variant-interpreter",
    name: "Clinical variant interpreter",
    summary:
      "Aggregates pathogenicity evidence for variants in a consented patient's genome to support ACMG/AMP-style interpretation. Returns evidence bands and a classification tier for clinician review — never an autonomous diagnosis, never raw sequence.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    clinicianGated: true,
    foundationModel: true,
    modelClassExamples: ["AlphaMissense", "ESM1b variant-effect", "EVE", "CADD"],
    tags: ["genomics", "variant-interpretation", "acmg", "rare-disease", "clinician-gated"],
  },
  {
    id: "regulatory-splicing-predictor",
    name: "Regulatory & splicing effect predictor",
    summary:
      "Predicts splice-altering and cis-regulatory impact of coding and non-coding variants from sequence context. Analysis and prioritization only; returns effect bands for research or downstream clinician interpretation.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    foundationModel: true,
    modelClassExamples: ["SpliceAI", "Pangolin", "Enformer", "Borzoi"],
    tags: ["genomics", "splicing", "regulatory", "sequence-model"],
  },
  {
    id: "pharmacogenomics-interpreter",
    name: "Pharmacogenomics interpreter",
    summary:
      "Resolves star-allele diplotypes and maps them to CPIC/DPWG-style drug-gene guidance for a consented patient. Decision support surfaced as guideline bands (standard / adjust / avoid) for the prescribing clinician — not a prescription, not a diagnosis.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    clinicianGated: true,
    modelClassExamples: ["PharmCAT", "Stargazer", "Aldy"],
    tags: ["pharmacogenomics", "cpic", "decision-support", "clinician-gated"],
  },
  {
    id: "protein-structure-annotator",
    name: "Protein structure & function annotator",
    summary:
      "Predicts 3D structure and structure-derived annotations (domains, pockets, contact maps, confidence) for a declared protein sequence, for interpretation. Analysis-only: it explains an existing molecule, it never runs a design/inverse-folding mode.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    foundationModel: true,
    modelClassExamples: ["AlphaFold2/3", "ESMFold", "OpenFold", "Boltz-1"],
    tags: ["protein", "structure", "annotation", "analysis"],
  },
  {
    id: "protein-lm-embeddings",
    name: "Protein language-model embeddings",
    summary:
      "Produces PLM embeddings for homology search, function annotation, localization, and stability/property prediction over declared sequences. Discriminative use only. On-device screening here is advisory and cannot be enforced — sensitive checkpoints stay enclave-bound.",
    locality: "on-device",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    foundationModel: true,
    modelClassExamples: ["ESM-2", "ProtT5", "Ankh"],
    tags: ["protein", "embeddings", "plm", "annotation", "on-device"],
  },
  {
    id: "pathology-foundation-model",
    name: "Computational pathology foundation model",
    summary:
      "Slide/tile embeddings and morphology annotation for whole-slide images: tissue annotation, biomarker/morphometric features, cohort retrieval. Returns annotation and triage bands for the pathologist — explicitly not a diagnosis. Raw slides never egress.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    clinicianGated: true,
    foundationModel: true,
    modelClassExamples: ["UNI", "Virchow", "CONCH", "Prov-GigaPath"],
    tags: ["pathology", "imaging", "foundation-model", "not-diagnosis", "clinician-gated"],
  },
  {
    id: "spatial-omics-analyzer",
    name: "Spatial omics analyzer",
    summary:
      "Spatial-domain and tissue-niche detection, cell-cell interaction analysis, and deconvolution over spatial transcriptomics/proteomics. Analysis over a sealed spatial corpus; returns spatial-structure summaries, not per-spot raw values.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    foundationModel: true,
    tags: ["spatial-omics", "analysis", "deconvolution"],
  },
  {
    id: "multiomics-integrator",
    name: "Multi-omics integrator",
    summary:
      "Joint embedding and factor analysis across genomics, transcriptomics, proteomics, methylomics, and metabolomics for stratification and mechanism discovery. Returns factor/cluster structure and stratification bands over a sealed cohort inside the enclave.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    clinicianGated: true,
    foundationModel: true,
    tags: ["multi-omics", "integration", "stratification", "clinician-gated"],
  },
  {
    id: "admet-property-predictor",
    name: "ADMET & molecular property predictor",
    summary:
      "Predicts physchem, ADMET, and bioactivity properties for declared candidate small molecules to prioritize and de-risk a sealed chemistry set. Property PREDICTION over an existing, declared library only — it scores molecules, it does not invent them.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    foundationModel: true,
    tags: ["cheminformatics", "admet", "property-prediction"],
  },
  {
    id: "metagenomics-profiler",
    name: "Microbiome & metagenomics profiler",
    summary:
      "Taxonomic and functional community profiling of microbiome/metagenomic samples for research. Credentialed researchers only; returns coarse profile summaries under query rate limits, with a signed attestation. Marker-detection queries are screened at stage 3 and never returned marker-by-marker, so it cannot be probed as a screening-evasion oracle.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    tags: ["microbiome", "metagenomics", "credentialed", "rate-limited", "surveillance"],
  },

  // --- Restricted generative / de novo design (deny targets only) -----------
  {
    id: "de-novo-protein-designer",
    name: "De novo protein / binder designer",
    summary:
      "BLOCKED platform-wide. Generative design of novel proteins is a restricted category. Present only as a deny target — no methods, parameters, targets, or workflow are ever produced. Requests routing here are stopped at stage 3 and escalated to human + legal + ethics + biosecurity review.",
    locality: "enclave",
    misuseSensitivity: "restricted",
    requiresStages: [1, 2, 3],
    restricted: true,
    tags: ["restricted", "blocked", "de-novo-design", "deny-by-default"],
  },
  {
    id: "genome-scale-sequence-generator",
    name: "Genome / regulatory sequence generator",
    summary:
      "BLOCKED platform-wide. Generative design of genomes, regulatory elements, or synthetic nucleic-acid sequences is a restricted category. Present only as a deny target — no sequences, methods, or design objectives are ever produced. Stopped at stage 3 and escalated.",
    locality: "enclave",
    misuseSensitivity: "restricted",
    requiresStages: [1, 2, 3],
    restricted: true,
    tags: ["restricted", "blocked", "de-novo-design", "deny-by-default"],
  },
  {
    id: "de-novo-small-molecule-generator",
    name: "De novo small-molecule generator",
    summary:
      "BLOCKED platform-wide. Generative de novo design of small molecules is a restricted category. Present only as a deny target — no candidate structures, synthesis routes, or optimization objectives are ever produced. Stopped at stage 3 and escalated.",
    locality: "enclave",
    misuseSensitivity: "restricted",
    requiresStages: [1, 2, 3],
    restricted: true,
    tags: ["restricted", "blocked", "de-novo-design", "deny-by-default"],
  },
];

export const CAPABILITIES_BY_ID: Record<string, Capability> = Object.fromEntries(
  CAPABILITIES.map((c) => [c.id, c]),
);
