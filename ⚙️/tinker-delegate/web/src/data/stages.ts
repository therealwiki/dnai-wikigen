import type { GateStage } from "../types";

export type StageDef = {
  stage: GateStage;
  key: string;
  title: string;
  short: string;
  detail: string;
  /** what a non-pass here means */
  onHold: string;
  onDeny: string;
};

/**
 * The four ordered pre-inference checks. Each returns pass / hold / deny; the
 * run stops at the first non-pass. Every run emits a signed attestation.
 *
 * Stage 3 is described at the level of "screen and deny" only — deliberately no
 * operational detail about what is screened for.
 */
export const STAGES: StageDef[] = [
  {
    stage: 1,
    key: "identity",
    title: "Identity & authorization",
    short: "Who is asking, and are they allowed?",
    detail:
      "Attested identity and KYC-style vetting. High-assurance tiers may add opt-in biometric/facial verification — presented as privacy-law-bound and proportionate, never default-on surveillance.",
    onHold: "Elevated assurance required — routed to opt-in step-up verification, then human review.",
    onDeny: "Identity not attested, or requester not authorized for this corpus.",
  },
  {
    stage: 2,
    key: "purpose",
    title: "Purpose & use-case screening",
    short: "Is this an allowed use of this corpus?",
    detail:
      "The declared purpose is matched against the corpus's allowed-use policy, and the requested pipeline against its allowlist. Dual-use or improper intent is flagged for human review.",
    onHold: "Possible dual-use intent — held for human review.",
    onDeny: "Purpose not permitted, or pipeline not on the corpus allowlist.",
  },
  {
    stage: 3,
    key: "bio-risk",
    title: "Bio-risk / clinical-safety screening",
    short: "Does this touch a restricted category?",
    detail:
      "The request is screened against restricted categories and hazard signatures before any inference. This stage is screen-and-deny: matched requests are stopped and escalated. It never emits methods, parameters, or workflow of any kind.",
    onHold: "Ambiguous signal — held for expert review.",
    onDeny: "Maps to a restricted category — denied by default and routed to human + legal + ethics review.",
  },
  {
    stage: 4,
    key: "attested",
    title: "Attested execution",
    short: "Run inside the enclave; surface only bounded output.",
    detail:
      "Only cleared requests reach the enclave. The model runs beside the sealed corpus and returns a bounded result — a score band, a yes/no, an advisory. Raw values are never surfaced; provenance (a signed attestation with a result hash) is emitted.",
    onHold: "—",
    onDeny: "—",
  },
];

export const STAGES_BY_NUMBER: Record<GateStage, StageDef> = {
  1: STAGES[0],
  2: STAGES[1],
  3: STAGES[2],
  4: STAGES[3],
};
