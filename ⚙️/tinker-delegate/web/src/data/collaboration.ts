import type { JointAttestation } from "../types-collab";
import { ENCLAVES } from "./identities";

export type CollabRoleInfo = { label: string; who: string; description: string };

export const COLLAB_ROLES: CollabRoleInfo[] = [
  {
    label: "Data owner / corpus custodian",
    who: "human or org",
    description: "Contributes one sealed corpus + its policy; holds consent and revocation rights; their corpus is never readable by any other party.",
  },
  {
    label: "Collaborator agent",
    who: "attested agent",
    description: "A non-human principal running inside the shared enclave that issues gated cross-corpus turns. It can never self-clear its own HOLD.",
  },
  {
    label: "Clinician / expert-in-the-loop",
    who: "human",
    description: "Domain authority who signs off on any decision-support surface (framed as decision-support, not diagnosis) and resolves clinical-safety HOLDs.",
  },
  {
    label: "Access-review officer",
    who: "human",
    description: "Operates the review queue; resolves stage-1 (step-up) and stage-2 (dual-use) HOLDs.",
  },
  {
    label: "Auditor",
    who: "human",
    description: "Read-only verifier who replays the shared gate trace and checks per-corpus and joint signatures after the fact — sees only hashes and bands, never raw data.",
  },
  {
    label: "Session custodian",
    who: "operator",
    description: "Operates the shared attested boundary (the enclave) and the append-only trace; owns no corpus and can read no raw values.",
  },
  {
    label: "Ethics & legal reviewer",
    who: "human",
    description: "Route target for stage-3 restricted-category denials. Consent cannot bypass this route.",
  },
];

export type SessionProperty = { title: string; body: string };

export const SESSION_MODEL: SessionProperty[] = [
  {
    title: "Sealed, not pooled",
    body: "Every corpus enters the session already sealed under its own key inside the shared enclave. The enclave is a shared execution boundary, not a shared data pool — one owner's plaintext is never derivable by another, and the custodian who runs the enclave reads no raw values.",
  },
  {
    title: "Independent policy enforcement",
    body: "The gate stays the shipped pure function of (AccessRequest, CorpusPolicy). A cross-corpus turn fans OUT into one gated query per corpus, each run against that corpus's own policy. Policies are never merged or weakened — if A permits a purpose and B forbids it, B denies and A is unaffected.",
  },
  {
    title: "Shared, corpus-tagged gate trace",
    body: "The session keeps an append-only list of corpus-tagged verdicts — every stage decision from every query, stamped with the corpus it belongs to. An auditor can see enforcement was independent (this DENY came from corpus B's stage 2) and replay the session deterministically.",
  },
  {
    title: "Joint attestation, co-signed",
    body: "Every turn emits a joint attestation whether it clears or stops. It binds the per-corpus attestation ids, the shared trace, the consent snapshot, and a result hash, co-signed once per participating enclave. A shared bounded result is valid only if the signer set equals the contributing corpora.",
  },
  {
    title: "Per-party royalty metering",
    body: "Each corpus keeps its own royalty rate and its own ledger. A two-vault turn accrues to each owner separately at their own rate. HOLD/DENY turns surface no shared output and meter no expose royalty — though the gate run itself is still attested.",
  },
  {
    title: "Consent, unanimity & revocation",
    body: "Each owner posts scoped consent grants that narrow — never widen — their policy. A shared output requires unanimous active consent across every contributing owner. Revocation is a single state flip: immediate and prospective. Turns after a revocation that touch the revoked corpus fail closed; already-emitted attestations stay valid on the append-only trace.",
  },
  {
    title: "Human-in-the-loop, fail-closed",
    body: "A HOLD on any query opens a handoff ticket routed to the correct human role. The joint decision is fail-closed while any ticket is pending. An agent can never self-clear its own HOLD. Stage-3 restricted-category denials are not holds and are never releasable by consent — they deny platform-wide and route to human + legal + ethics.",
  },
];

export type ScenarioStepKind = "open" | "clear" | "hold" | "clinical" | "revoke" | "audit";
export type ScenarioStep = { title: string; detail: string; kind: ScenarioStepKind };

export const COLLAB_SCENARIO: {
  title: string;
  parties: { name: string; role: string }[];
  steps: ScenarioStep[];
} = {
  title: "Two biopharma orgs + a CRO agent + a clinician co-optimize an assay without disclosing IP",
  parties: [
    { name: "Atlas Bio", role: "data-owner · sealed assay vault (restricted, elevated)" },
    { name: "Halcyon Bio", role: "data-owner · sealed compound-response vault (restricted, elevated; synthetic)" },
    { name: "Meridian CRO agent", role: "collaborator-agent · runs ip-preserving-agent inside the enclave, owns no data" },
    { name: "Dr. R. Vasquez", role: "expert-in-the-loop · signs off on any decision-support surface" },
    { name: "Access Review Officer", role: "resolves stage-1 / stage-2 holds" },
    { name: "Independent auditor", role: "read-only · replays trace, checks signatures, sees only hashes + bands" },
  ],
  steps: [
    {
      kind: "open",
      title: "Session opens",
      detail:
        "The shared enclave attests (git SHA → docker digest → compose hash → TDX quote). Each org's vault is sealed under its own key. Atlas and Halcyon each post their policy plus a scoped consent grant (purposes: ip-preserving-collaboration, assay-optimization; shared with the CRO agent). Neither org can read the other's vault.",
    },
    {
      kind: "clear",
      title: "Turn 1 — rank assay conditions",
      detail:
        "The CRO agent issues 'rank assay conditions by cross-cohort response consistency.' It fans out into two gated queries, one per vault. Each vault's gate runs all four stages against its OWN policy; both pass. Unanimous consent is active, so the enclave surfaces ONE bounded result — a score band ('condition set B: high consistency'), never raw values. The joint attestation co-signs with both enclave keys; Atlas and Halcyon each meter their own royalty.",
    },
    {
      kind: "hold",
      title: "Turn 2 — held on dual-use intent",
      detail:
        "The agent's intent reads 'export the ranked compound structures for our own downstream pipeline.' Atlas's stage-2 dual-use screen flags redistribution / unspecified-downstream and returns HOLD. A handoff ticket routes to the access-review officer. Fail-closed: no shared output is surfaced; the turn is suspended pending human review.",
    },
    {
      kind: "clear",
      title: "Re-scoped and cleared",
      detail:
        "The access-review officer and Atlas review the ticket; Atlas keeps its grant narrow. The agent re-scopes the turn to an in-enclave-only, bounded purpose. Re-issued, it clears and surfaces only a band.",
    },
    {
      kind: "clinical",
      title: "Clinical surface — clinician signs off",
      detail:
        "A later turn yields a clinical decision-support surface. Dr. Vasquez (expert-in-the-loop) must sign off, and the surface is framed as decision-support with explicit not-a-diagnosis language.",
    },
    {
      kind: "revoke",
      title: "Halcyon revokes consent",
      detail:
        "Mid-session, Halcyon revokes its consent grant. Revocation is immediate and prospective: subsequent turns touching Halcyon's vault fail closed and surface nothing, while every prior joint attestation stays valid and auditable. The session continues single-corpus, then closes.",
    },
    {
      kind: "audit",
      title: "Auditor replays the trace",
      detail:
        "Post hoc, the auditor replays the corpus-tagged shared gate trace, verifies each per-corpus attestation signature and the joint co-signatures, and confirms no raw values ever crossed the boundary and every surfaced output had unanimous consent — seeing only hashes and bands throughout.",
    },
  ],
};

export const COLLAB_SAFETY: string[] = [
  "No cross-corpus leakage — each corpus stays sealed under its own key; N-corpus turns produce N independent evaluations composed into bounded outputs, never a merged dataset.",
  "Independent policy enforcement — each corpus's policy is evaluated by the pure gate against that corpus alone; policies are never merged or weakened.",
  "Fail-closed joint decision — a shared result is surfaced only if EVERY contributing corpus passes; any DENY denies it, any HOLD suspends it for human handoff.",
  "Unanimous consent for shared outputs — every contributing owner must hold an active grant covering the purpose, pipeline, and requester; missing consent withholds the output.",
  "Revocability — any owner can revoke immediately; revocation is prospective and fail-closed, while already-emitted attestations remain valid on the append-only trace.",
  "Full attestation — every turn emits a co-signed joint attestation (cleared or stopped) binding the per-corpus attestations, the trace, the consent snapshot, and a result hash; raw values never appear.",
  "Consent cannot override bio-risk — stage-3 restricted categories DENY platform-wide regardless of any party's consent and route to human + legal + ethics.",
  "Human-in-the-loop authority — HOLD verdicts route to the correct human role; a collaborator agent can never self-clear its own HOLD.",
  "Attested, opt-in identity — elevated corpora require proportionate, opt-in, privacy-law-bound step-up; unattested principals deny at stage 1.",
  "Least authority — auditors are read-only, the custodian owns no corpus, agents may only issue gated turns; health surfaces are decision-support, not diagnosis.",
];

/** Illustrative joint attestation for Turn 1 (cleared). Synthetic scaffolding. */
export const SAMPLE_JOINT_ATTESTATION: JointAttestation = {
  jointAttestationId: "jatt-3f1c9a20-turn1",
  turnId: "turn-01",
  outcome: "cleared",
  sharedGateTrace: [
    { corpusRef: "corpus://atlas-bio/assay-vault", verdict: { stage: 1, decision: "pass" } },
    { corpusRef: "corpus://atlas-bio/assay-vault", verdict: { stage: 2, decision: "pass" } },
    { corpusRef: "corpus://atlas-bio/assay-vault", verdict: { stage: 3, decision: "pass" } },
    { corpusRef: "corpus://atlas-bio/assay-vault", verdict: { stage: 4, decision: "pass" } },
    { corpusRef: "corpus://halcyon-bio/response-vault", verdict: { stage: 1, decision: "pass" } },
    { corpusRef: "corpus://halcyon-bio/response-vault", verdict: { stage: 2, decision: "pass" } },
    { corpusRef: "corpus://halcyon-bio/response-vault", verdict: { stage: 3, decision: "pass" } },
    { corpusRef: "corpus://halcyon-bio/response-vault", verdict: { stage: 4, decision: "pass" } },
  ],
  memberAttestations: ["att-atlas-9c21", "att-halcyon-4d77"],
  coSignatures: [
    { corpusRef: "corpus://atlas-bio/assay-vault", signer: ENCLAVES.phalaCvm, signature: "tdx:mrenclave=8f21a4c0…:sig=illustrative-not-verified" },
    { corpusRef: "corpus://halcyon-bio/response-vault", signer: ENCLAVES.onPremSev, signature: "sev:measurement=02ab…:sig=illustrative-not-verified" },
  ],
  consentSnapshot: [
    {
      grantId: "grant-atlas-01",
      by: "party-atlas",
      corpusRef: "corpus://atlas-bio/assay-vault",
      allowedPurposes: ["assay-optimization", "ip-preserving-collaboration"],
      allowedPipelines: ["assay-optimizer-lm", "ip-preserving-agent"],
      sharedWith: ["party-cro-agent"],
      status: "active",
      grantedAt: "2026-07-06T18:00:00.000Z",
    },
    {
      grantId: "grant-halcyon-01",
      by: "party-halcyon",
      corpusRef: "corpus://halcyon-bio/response-vault",
      allowedPurposes: ["assay-optimization", "ip-preserving-collaboration"],
      allowedPipelines: ["assay-optimizer-lm", "ip-preserving-agent"],
      sharedWith: ["party-cro-agent"],
      status: "active",
      grantedAt: "2026-07-06T18:00:00.000Z",
    },
  ],
  resultHash: "b7e4d1a09f33c8218e5a6c440c7f97a1",
  boundedResult: {
    kind: "score-band",
    band: "condition-set-B: high cross-cohort consistency",
    note: "Composed from two independently-gated per-corpus evaluations. No raw assay values crossed the boundary; only this band and a result hash.",
    royaltyCharged: 0.05,
  },
  at: "2026-07-06T18:02:14.000Z",
};
