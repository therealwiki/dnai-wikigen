import type { HealthApp } from "../types";

/**
 * The catalog. Realistic-but-clearly-illustrative health & bio-model apps,
 * tagged on the locality axis and mapped to the gate stages that apply.
 *
 * Groups:
 *   everyday      — on-device, low sensitivity, minimal gating
 *   clinical      — enclave, medium–high sensitivity, full gate
 *   collaboration — the wikigen.me / NDAI marketplace surface (pooled data,
 *                   IP-preserving agents, biopharma TEE, organ-on-chip)
 *   restricted    — rendered GATED, never as a shippable app
 */
export const APPS: HealthApp[] = [
  // --- Everyday / on-device --------------------------------------------------
  {
    id: "longevity-coach",
    name: "Longevity & healthspan coach",
    group: "everyday",
    valueProp: "Turns sleep, VO₂max, HRV, and metabolic trends from your wearables into plain-language guidance.",
    locality: "on-device",
    sensitivityTier: "low",
    gateStages: [1],
    requiredAssurance: "standard",
    corpusRef: "corpus://owner/wearable-timeseries",
    pipelineRefs: ["healthspan-coach-lm", "metabolic-timeseries-forecaster"],
    body:
      "Your wearable history is the corpus, and it stays on the device. A small on-device model reads the trends and offers healthspan guidance — training load, recovery, sleep regularity. Because nothing leaves, the gate only needs a light identity check: you are the owner of your own data.",
    dataFlow: ["Wearable streams stay on-device", "Model is downloaded to you", "No corpus egress, no third party"],
    notDiagnosis: true,
    tags: ["wearables", "longevity", "hrv", "vo2max"],
  },
  {
    id: "nutrition-glucose",
    name: "Nutrition & glucose-response modeling",
    group: "everyday",
    valueProp: "Learns how your body responds to meals from your food log and CGM — privately, on your phone.",
    locality: "on-device",
    sensitivityTier: "low",
    gateStages: [1],
    requiredAssurance: "standard",
    corpusRef: "corpus://owner/wearable-timeseries",
    pipelineRefs: ["nutrition-glucose-model"],
    body:
      "Continuous-glucose and meal data are intimate. Here they never leave the phone: the personalization model runs locally and only ever shows you your own patterns. The expose path (sharing anonymized response curves into a research pool) is opt-in and, if taken, would itself pass through the full gate.",
    dataFlow: ["Food log + CGM stay on-device", "Personal model trained locally", "Sharing to a pool is opt-in and gated"],
    notDiagnosis: true,
    tags: ["nutrition", "cgm", "metabolic"],
  },
  {
    id: "mental-health-journal",
    name: "Mental-health journaling & mood support",
    group: "everyday",
    valueProp: "A private, on-device companion for journaling and mood reflection — never a diagnosis.",
    locality: "on-device",
    sensitivityTier: "low",
    gateStages: [1],
    requiredAssurance: "standard",
    corpusRef: "corpus://owner/wearable-timeseries",
    pipelineRefs: ["healthspan-coach-lm"],
    body:
      "Journaling entries are among the most sensitive data a person holds, so the model comes to them: it runs on-device and the text never leaves. This surface offers reflection and coping prompts and signposts crisis resources — it is explicitly not built to give clinical diagnoses or replace a professional.",
    dataFlow: ["Journal text stays on-device", "On-device LLM only", "No cloud, no corpus egress"],
    crisisSignposting: true,
    notDiagnosis: true,
    tags: ["mental-health", "journaling", "on-device-llm"],
  },
  {
    id: "sequence-me-101",
    name: "Sequence-Me 101",
    group: "everyday",
    valueProp: "A guided literacy course for reading your own genome and lab reports — what they mean, and what they don't.",
    locality: "on-device",
    sensitivityTier: "low",
    gateStages: [1],
    requiredAssurance: "standard",
    corpusRef: "corpus://owner/wearable-timeseries",
    pipelineRefs: ["onboarding-literacy-lm"],
    body:
      "Before anyone submits sensitive genomic data to any pipeline, they should understand it. Sequence-Me 101 is on-device education: it explains what a personal genome, a polygenic score, or a lab panel does and does not tell you, and how the safeguards gate treats each corpus tier. It is literacy, not clinical instruction, and points to professionals for anything actionable.",
    dataFlow: ["Runs entirely on-device", "Teaches, does not interpret your clinical results", "No data submission required"],
    notDiagnosis: true,
    tags: ["education", "genomics-101", "literacy", "onboarding"],
  },

  // --- Clinical / enclave ----------------------------------------------------
  {
    id: "chronic-disease-twin",
    name: "Chronic-disease digital twin",
    group: "clinical",
    valueProp: "Simulates cardio-metabolic trajectories on FHIR/OMOP data to support care planning — clinician in the loop.",
    locality: "enclave",
    sensitivityTier: "high",
    gateStages: [1, 2, 3, 4],
    requiredAssurance: "standard",
    corpusRef: "corpus://meridian/fhir-omop-cardio",
    pipelineRefs: ["chronic-disease-digital-twin", "cohort-risk-model"],
    body:
      "Structured records (FHIR/OMOP) sit inside a confidential-compute enclave. A clinician submits a care-planning question; the request clears identity, purpose, and safety screening; then the twin runs beside the data and returns a bounded projection — a risk band and a suggested review, never raw record values. Operators of the enclave cannot read the underlying data.",
    dataFlow: ["Records sealed in enclave", "Model runs beside the data", "Only bounded projections returned", "Full attestation emitted"],
    clinicianGated: true,
    notDiagnosis: true,
    tags: ["digital-twin", "fhir", "omop", "cardio-metabolic"],
  },
  {
    id: "imaging-triage",
    name: "Medical imaging triage assistant",
    group: "clinical",
    valueProp: "Prioritizes imaging studies for human read, returning a triage band — not a diagnosis.",
    locality: "enclave",
    sensitivityTier: "high",
    gateStages: [1, 2, 3, 4],
    requiredAssurance: "standard",
    corpusRef: "corpus://meridian/imaging-dicom",
    pipelineRefs: ["imaging-triage-cnn"],
    body:
      "Imaging studies stay inside the enclave. The assistant runs against them and emits only a triage band that helps a radiologist decide read order. The raw pixels and the model's dense outputs never leave; the result a clinician sees is bounded and always routes to a human read.",
    dataFlow: ["DICOM sealed in enclave", "Triage band only", "Human read always required", "Attestation on every run"],
    clinicianGated: true,
    notDiagnosis: true,
    tags: ["imaging", "radiology", "triage"],
  },
  {
    id: "rare-disease-genomics",
    name: "Rare-disease & genomic interpretation",
    group: "clinical",
    valueProp: "Variant-effect prediction on a diagnosed patient's WGS to support interpretation — clinician-led, elevated assurance.",
    locality: "enclave",
    sensitivityTier: "restricted",
    gateStages: [1, 2, 3, 4],
    requiredAssurance: "elevated",
    corpusRef: "corpus://helix/patient-wgs",
    pipelineRefs: ["variant-effect-predictor"],
    body:
      "A diagnosed patient's whole-genome sequence is the most restricted personal corpus in the catalog. Interpretation is legitimate and valuable — but it demands elevated assurance and a clinician in the loop. The request is screened for both purpose (variant interpretation for a diagnosed condition) and restricted categories before the predictor runs inside the enclave. The output is a banded, interpretable summary for the care team.",
    dataFlow: ["WGS sealed, restricted tier", "Elevated assurance required", "Clinician-in-the-loop analysis", "Bounded interpretation returned"],
    clinicianGated: true,
    notDiagnosis: true,
    tags: ["genomics", "rare-disease", "variant-effect", "wgs"],
  },
  {
    id: "somatic-genomic-companion",
    name: "Somatic genomic medicine companion",
    group: "clinical",
    valueProp:
      "Decision support around approved, non-heritable cell/gene therapies for a diagnosed, consenting patient — clinician-gated.",
    locality: "enclave",
    sensitivityTier: "restricted",
    gateStages: [1, 2, 3, 4],
    requiredAssurance: "elevated",
    corpusRef: "corpus://helix/patient-wgs",
    pipelineRefs: ["somatic-therapy-decision-support"],
    body:
      "This is the legitimate 'gene therapy' story. It supports clinicians weighing approved, non-heritable somatic therapies (for example, approved cell and gene therapies) for an existing, consenting patient. It treats a person who is already here; it is not heritable and touches no germline. It is decision support, clinician-gated, at elevated assurance — and the gate distinguishes it cleanly from the restricted germline category, which it will not serve.",
    dataFlow: [
      "Diagnosed, consenting patient only",
      "Approved, non-heritable therapies",
      "Clinician-gated decision support",
      "Elevated assurance + full attestation",
    ],
    clinicianGated: true,
    notDiagnosis: true,
    tags: ["somatic", "approved-therapy", "non-heritable", "cell-gene-therapy"],
  },

  {
    id: "external-imaging-api",
    name: "External imaging second-opinion API",
    group: "clinical",
    valueProp:
      "Route a de-identified study to a third-party imaging model for a second opinion — the strictest gating, because data transits.",
    locality: "api-only",
    sensitivityTier: "high",
    gateStages: [1, 2, 3, 4],
    requiredAssurance: "standard",
    corpusRef: "corpus://meridian/imaging-dicom",
    pipelineRefs: ["third-party-imaging-api"],
    body:
      "Some capabilities live behind a third party, so the data has to transit — this is the amber, data-leaves end of the spine. It is allowed only when the corpus policy explicitly permits egress to that pipeline; against a high-sensitivity imaging corpus that does not allowlist it, the request is denied at stage 2. When egress is permitted, only a bounded second-opinion band returns.",
    dataFlow: [
      "Data transits to a third party (egress)",
      "Allowed only if the corpus policy permits it",
      "Otherwise denied at stage 2 (not on allowlist)",
      "Only a bounded second-opinion band returns",
    ],
    clinicianGated: true,
    notDiagnosis: true,
    tags: ["api-only", "imaging", "second-opinion", "egress"],
  },

  // --- Collaboration / marketplace (wikigen.me / NDAI surface) ----------------
  {
    id: "cell-atlas-sim",
    name: "Cell-atlas simulation",
    group: "collaboration",
    valueProp: "Simulate cell states and perturbations over a pooled, federated single-cell atlas — donors stay unlinkable.",
    locality: "enclave",
    sensitivityTier: "high",
    gateStages: [1, 2, 3, 4],
    requiredAssurance: "standard",
    corpusRef: "corpus://consortium/cell-atlas-pooled",
    pipelineRefs: ["single-cell-foundation-model", "perturbation-simulator"],
    body:
      "Many institutions contribute single-cell data to a shared atlas without any of them shipping raw donor data to the others. The atlas is federated inside enclaves; a researcher's simulation request is screened and metered, and results come back as aggregate cell-state signal. This is the local-to-pooled path: contribution stays local, value is shared, donors remain unlinkable.",
    dataFlow: ["Local-to-pooled contribution", "Federated across enclaves", "Donor re-identification is a restricted category", "Per-query royalty metered"],
    tags: ["single-cell", "atlas", "federated", "pooled"],
  },
  {
    id: "organ-on-chip-access",
    name: "Organ-on-chip access",
    group: "collaboration",
    valueProp: "Broker metered, remote access to instrumented organ-on-chip rigs without exposing either side's IP.",
    locality: "hybrid",
    sensitivityTier: "med",
    gateStages: [1, 2, 3, 4],
    requiredAssurance: "standard",
    corpusRef: "corpus://microtissue/organ-on-chip",
    pipelineRefs: ["organ-on-chip-controller", "ip-preserving-agent"],
    body:
      "A lab with organ-on-chip capacity rents metered access to it. The controller is self-hostable, but any call-out to a general model is egress-gated — hence the hybrid tag and the caution color. A requester's protocol and the host's rig telemetry are each screened; results are bounded and metered per query.",
    dataFlow: ["Self-hostable controller", "Call-outs are egress-gated (hybrid)", "Protocol + telemetry each screened", "Metered per query"],
    tags: ["organ-on-chip", "wet-lab", "metered-access", "hybrid"],
  },
  {
    id: "biopharma-tee-workbench",
    name: "Biopharma confidential-compute workbench",
    group: "collaboration",
    valueProp: "Optimize assays over a sealed proprietary vault inside a TEE — the IP never leaves the enclave.",
    locality: "enclave",
    sensitivityTier: "restricted",
    gateStages: [1, 2, 3, 4],
    requiredAssurance: "elevated",
    corpusRef: "corpus://atlas-bio/assay-vault",
    pipelineRefs: ["assay-optimizer-lm", "ip-preserving-agent"],
    body:
      "This is the NDAI disclosure paradox in bio form: a biopharma team has valuable assay IP but wants outside analysis. The vault is sealed in a TEE; a collaborator's agent inspects it inside the boundary and emits only bounded findings — score bands, yes/no, an offer within cap. Raw IP never leaves. Reserve price, budget cap, and per-query royalty are first-class controls, exactly as in the NDAI paper.",
    dataFlow: ["Proprietary IP sealed in TEE", "Bounded findings only", "Reserve price + budget cap", "Per-query royalty metered"],
    tags: ["biopharma", "tee", "confidential-compute", "assay", "ndai"],
  },
  {
    id: "ip-preserving-agent-collab",
    name: "IP-preserving agentic collaboration",
    group: "collaboration",
    valueProp:
      "Outsource experiments and find synergy without disclosing your IP — bounded results delivered to your inbox via wikigen.me.",
    locality: "hybrid",
    sensitivityTier: "med",
    gateStages: [1, 2, 3, 4],
    requiredAssurance: "standard",
    corpusRef: "corpus://microtissue/organ-on-chip",
    pipelineRefs: ["ip-preserving-agent", "general-llm-gateway"],
    body:
      "An agent brokers collaboration between a person or org and outside capacity — experiments, analysis, second opinions — while keeping each side's IP sealed. It is self-hostable but can call out to general models, so egress is gated. Cleared, bounded results are delivered straight to a person's or org's inbox via wikigen.me, along with the signed attestation for that run.",
    dataFlow: ["IP stays sealed per side", "Egress-gated call-outs", "Bounded results to your inbox (wikigen.me)", "Signed attestation attached"],
    tags: ["agent", "ip-preserving", "outsourcing", "budget-saving", "inbox"],
  },

  // --- Restricted (GATED — never a shippable app) ----------------------------
  {
    id: "germline-editing",
    name: "Heritable / germline embryo editing",
    group: "restricted",
    valueProp: "Restricted category. Denied by default and routed to human + legal + ethics review. Not a shippable app.",
    locality: "enclave",
    sensitivityTier: "restricted",
    gateStages: [1, 2, 3],
    requiredAssurance: "elevated",
    corpusRef: "corpus://helix/patient-wgs",
    pipelineRefs: ["germline-edit-designer"],
    body:
      "Heritable human editing appears in this publication only as a restricted category the gate blocks — never as a capability, method, protocol, or workflow. Any request that maps to it is stopped at the bio-risk / clinical-safety stage, a stop-record is emitted, and the request is routed to human, legal, and ethics review. Showing the deny path is the point: a safeguards platform is defined as much by what it refuses as by what it runs.",
    dataFlow: [
      "No methods, parameters, or workflow — anywhere",
      "Deterministic deny at stage 3",
      "Stop-record emitted",
      "Routed to human + legal + ethics review",
    ],
    gated: true,
    tags: ["restricted", "germline", "deny-by-default", "ethics-review"],
  },
];

export const APPS_BY_ID: Record<string, HealthApp> = Object.fromEntries(APPS.map((a) => [a.id, a]));
