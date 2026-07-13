import type { GateStage, Locality, MisuseSensitivity } from "../types";

/**
 * Skills a scientific agent may wield INSIDE the gate, never around it. Each
 * runs strictly downstream of the four ordered checks, stops at the first
 * non-pass, and emits a signed attestation. Skills surface only bounded outputs
 * — score bands, yes/no, advisories — never raw corpus values.
 *
 * `humanInLoop` is concentrated at exactly the places a machine must not decide
 * alone: physical actuation, any generation near a restricted category,
 * widening the egress envelope, and missing/ambiguous governance evidence.
 */
export type SkillGroup = "frame" | "data" | "analysis" | "orchestrate" | "safety" | "deliver";

export type ScientificSkill = {
  id: string;
  name: string;
  group: SkillGroup;
  summary: string;
  locality: Locality;
  misuseSensitivity: MisuseSensitivity;
  requiresStages: GateStage[];
  humanInLoop: boolean;
  /** short: which stages + when a human must approve */
  gatingProfile: string;
  restricted?: boolean;
  tags: string[];
};

export const SKILLS: ScientificSkill[] = [
  {
    id: "hypothesis-framer",
    name: "Hypothesis & question framer",
    group: "frame",
    summary:
      "Turns a researcher's goal into well-posed hypotheses, prior-art gap notes, and candidate endpoints, entirely on-device. Sees only the request text; no corpus data, no egress.",
    locality: "on-device",
    misuseSensitivity: "low",
    requiresStages: [1],
    humanInLoop: false,
    gatingProfile: "Identity only; touches no corpus.",
    tags: ["framing", "hypothesis", "on-device"],
  },
  {
    id: "lit-evidence-synthesizer",
    name: "Literature & evidence synthesizer",
    group: "frame",
    summary:
      "Retrieves and synthesizes peer-reviewed literature and public evidence into cited, non-hazardous briefs with strength-of-evidence grading. External queries are egress-gated so the research direction is not leaked in the clear.",
    locality: "hybrid",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3],
    humanInLoop: false,
    gatingProfile: "Egress-gated retrieval; bio-risk screened before any external query.",
    tags: ["literature", "evidence", "egress-gated"],
  },
  {
    id: "data-qc-harmonizer",
    name: "Data QC & harmonization (FHIR/OMOP/FAIR)",
    group: "data",
    summary:
      "Runs QC, normalization, and cross-schema harmonization to FHIR/OMOP/FAIR inside the enclave, plus an illustrative de-identification / re-identification-risk check (not a validated privacy guarantee). Raw records never leave; only QC reports and schema/vocabulary mapping tables (never identifier crosswalks) are surfaced.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    humanInLoop: false,
    gatingProfile: "Full gate; de-id check is illustrative scaffolding pending a real linkage-attack harness.",
    tags: ["data-qc", "fhir", "omop", "fair", "de-identification"],
  },
  {
    id: "stat-analysis-doe",
    name: "Statistical analysis & experiment design",
    group: "analysis",
    summary:
      "Statistical analysis over sealed corpora and experiment design (power/sample-size, multiplicity control, design-of-experiments), returning effect-size bands and design recommendations — never row-level data.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    humanInLoop: false,
    gatingProfile: "Full gate; bounded statistical outputs only.",
    tags: ["statistics", "doe", "power-analysis"],
  },
  {
    id: "enclave-notebook-runtime",
    name: "Sandboxed enclave notebook runtime",
    group: "analysis",
    summary:
      "Executes analyst-authored notebooks and code beside the sealed corpus inside the TEE, with network egress denied-by-default and outputs constrained to bounded results. A powerful primitive, so it is tightly sandboxed and every run is attested.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    humanInLoop: false,
    gatingProfile: "Full gate; egress denied-by-default; every run attested.",
    tags: ["notebook", "sandbox", "execution"],
  },
  {
    id: "internal-red-team-critic",
    name: "Internal methodology red-team critic",
    group: "analysis",
    summary:
      "Adversarially critiques a draft analysis in-enclave (methodology, statistical validity, bias, confounding, reproducibility gaps) before results are trusted or delivered. Read-only over the draft; no corpus mutation, no egress.",
    locality: "enclave",
    misuseSensitivity: "low",
    requiresStages: [1, 2],
    humanInLoop: false,
    gatingProfile: "Read-only critique; no corpus mutation, no egress.",
    tags: ["red-team", "methodology", "validity"],
  },
  {
    id: "provenance-attestor",
    name: "Reproducibility & provenance attestor",
    group: "safety",
    summary:
      "Captures signed, tamper-evident run records (inputs by reference, code/model digests, environment, result hash), building the reproducibility and audit trail for every skill invocation. It is the audit surface itself, not a data-touching analysis.",
    locality: "enclave",
    misuseSensitivity: "low",
    requiresStages: [1, 4],
    humanInLoop: false,
    gatingProfile: "Identity + attestation; records provenance, touches no raw data.",
    tags: ["provenance", "reproducibility", "audit"],
  },
  {
    id: "governance-consent-checker",
    name: "Governance & consent evidence checker",
    group: "safety",
    summary:
      "Verifies that the required governance evidence (IRB approval, patient consent, data-use agreement, ethics review) is present and valid before a run proceeds — including captured, jurisdiction-aware opt-in consent for any biometric step-up. A safety-positive precondition; it never fabricates approvals.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2],
    humanInLoop: true,
    gatingProfile: "Precondition gate; missing/ambiguous evidence routes to human review.",
    tags: ["governance", "consent", "irb", "dua"],
  },
  {
    id: "dual-use-prescreen",
    name: "Dual-use self pre-screen",
    group: "safety",
    summary:
      "Runs a stage-3-style screen over the agent's OWN drafted plans, protocols, queries, and code before any action is taken. Screen-and-deny only; it stops unsafe actions and routes them, and never emits the hazard content or its screening criteria.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [3],
    humanInLoop: true,
    gatingProfile: "Turns stage 3 back on the agent's own drafts; deny + escalate.",
    tags: ["dual-use", "self-screen", "screen-and-deny"],
  },
  {
    id: "protocol-drafter",
    name: "Non-hazardous protocol drafter",
    group: "orchestrate",
    summary:
      "Drafts standard, non-hazardous lab and clinical-research protocols (SOPs, consent-flow steps, sample-handling, analysis plans) with structured metadata. High-risk or restricted-category protocols are never produced; the request is stopped and routed to safety review.",
    locality: "enclave",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3],
    humanInLoop: true,
    gatingProfile: "Bio-risk screened; restricted protocols denied and escalated, never drafted.",
    tags: ["protocol", "sop", "non-hazardous"],
  },
  {
    id: "instrument-broker",
    name: "Metered instrument broker",
    group: "orchestrate",
    summary:
      "Brokers remote, metered access to wet-lab instruments such as organ-on-chip rigs and sequencers, scheduling runs and returning telemetry as bounded output. Physical actuation and any synthesis/ordering path are biosecurity-screened.",
    locality: "hybrid",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    humanInLoop: true,
    gatingProfile: "Full gate; physical actuation requires human sign-off and stage-3 screening.",
    tags: ["instrument", "organ-on-chip", "wet-lab", "metered"],
  },
  {
    id: "federated-query-planner",
    name: "Federated query planner",
    group: "orchestrate",
    summary:
      "Plans and coordinates analyses across sealed, multi-institution corpora so that raw data never moves; only bounded aggregate signals return. Enables cross-org collaboration without pooling identifiable data.",
    locality: "enclave",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    humanInLoop: false,
    gatingProfile: "Full gate per corpus; each cross-corpus query is independently gated.",
    tags: ["federated", "multi-institution", "aggregate"],
  },
  {
    id: "ip-preserving-outsourcing-broker",
    name: "IP-preserving outsourcing broker",
    group: "orchestrate",
    summary:
      "Brokers outsourced analysis and cross-organization synergy discovery so neither party's IP is disclosed; each side receives only bounded outputs computed inside the enclave. The agentic outsourcing surface, DUA-gated.",
    locality: "hybrid",
    misuseSensitivity: "high",
    requiresStages: [1, 2, 3, 4],
    humanInLoop: true,
    gatingProfile: "Full gate; egress-gated; DUA + bio-risk screened before any outbound routing.",
    tags: ["outsourcing", "ip-preserving", "synergy", "dua-gated"],
  },
  {
    id: "budget-vendor-router",
    name: "Cost/budget optimizer & vendor router",
    group: "orchestrate",
    summary:
      "Optimizes spend and routes work to the cheapest compliant compute/analysis vendor within a corpus's egress policy and the requester's budget cap. Because it can move data off-platform, it runs the FULL gate — the stage-3 screen classifies any restricted payload and denies it before routing.",
    locality: "hybrid",
    misuseSensitivity: "moderate",
    requiresStages: [1, 2, 3, 4],
    humanInLoop: false,
    gatingProfile: "Full gate — outbound routing passes stage-3 screen-and-deny + attestation, matching the outsourcing broker.",
    tags: ["budget", "vendor-routing", "egress-gated"],
  },
  {
    id: "bounded-result-courier",
    name: "Bounded-result courier",
    group: "deliver",
    summary:
      "Delivers a cleared run's bounded result (score band, yes/no, or advisory) to a person's or organization's inbox, signed and metered. Structurally strips raw values; it is the enforced egress boundary of the whole system.",
    locality: "hybrid",
    misuseSensitivity: "moderate",
    requiresStages: [1, 4],
    humanInLoop: false,
    gatingProfile: "Delivers only bounded output; raw values are structurally stripped.",
    tags: ["delivery", "inbox", "bounded", "wikigen"],
  },
  {
    id: "denovo-bio-design-agent",
    name: "De novo biological-design agent",
    group: "safety",
    summary:
      "BLOCKED platform-wide. De novo design of biological agents, toxins, select agents, pathogen enhancement, or heritable edits is a restricted category, present here only as a deny target. No method, target, reagent, or workflow is ever produced. Requests routing here are stopped and escalated.",
    locality: "enclave",
    misuseSensitivity: "restricted",
    requiresStages: [1, 2, 3],
    humanInLoop: true,
    restricted: true,
    gatingProfile: "Deny target only — stopped at stage 3 and escalated to human + legal + ethics + biosecurity.",
    tags: ["restricted", "blocked", "de-novo-design", "deny-by-default"],
  },
];
