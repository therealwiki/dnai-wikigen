// N-party collaborative sessions — an extension of the shipped 2-party contracts.
// Each cross-corpus query is STILL a gated AccessRequest evaluated by the pure
// four-stage gate against a single CorpusPolicy. A CollabSession accretes those
// independent evaluations into a shared gate trace + joint attestation.
// Synthetic / illustrative scaffolding only.
import type {
  AccessRequest,
  AssuranceTier,
  AttestationOutcome,
  AttestationRecord,
  BoundedResult,
  CorpusPolicy,
  Decision,
  EnclaveRef,
  GateStage,
  IdentityRef,
  StageVerdict,
} from "./types";

// --- Participants ------------------------------------------------------------

export type CollabRole =
  | "data-owner" // contributes a sealed corpus + its policy
  | "collaborator-agent" // attested agent issuing gated turns
  | "expert-in-the-loop" // clinician / domain expert; resolves clinical HOLDs
  | "access-review-officer" // resolves stage-1 / stage-2 HOLDs
  | "auditor" // read-only verifier of trace + attestations
  | "session-custodian" // operates the shared enclave; owns no data
  | "ethics-legal-reviewer"; // stage-3 restricted-category deny route target

export type Participant = {
  participantRef: string; // stable session-local handle
  identity: IdentityRef; // the verified principal (reuses existing shape)
  kind: "human" | "agent";
  collabRole: CollabRole;
  assuranceTier: AssuranceTier; // elevated => opt-in, proportionate step-up
  contributesCorpora: string[]; // corpusRef[] this party owns (data-owners only)
  grants: ConsentGrant[]; // standing consent over the corpora they own
  royaltyAccount?: RoyaltyLedgerRef;
  joinedAt: string; // iso-8601
  status: "active" | "left" | "suspended";
};

// --- Consent & revocation ----------------------------------------------------

export type ConsentGrant = {
  grantId: string;
  by: string; // Participant.participantRef of a data-owner
  corpusRef: string;
  allowedPurposes: string[]; // narrows within the corpus's own allowedPurposes
  allowedPipelines: string[]; // narrows within the corpus's pipelineAllowlist
  sharedWith: string[]; // participantRefs allowed to touch this corpus
  status: "active" | "suspended" | "revoked";
  grantedAt: string;
  revokedAt?: string; // revocation is immediate + prospective
};

// Consent required to surface a SHARED output for one turn.
export type ConsentQuorum = {
  required: string[]; // owners of every corpus the turn touches
  granted: string[]; // owners with an active grant covering the turn
  unanimous: boolean; // granted ⊇ required
};

// --- Turns: a cross-corpus query fans out into per-corpus gated queries -------

export type GatedQuery = {
  corpusRef: string;
  request: AccessRequest; // per-corpus request (existing shape, unchanged)
  policy: CorpusPolicy; // enforced INDEPENDENTLY, never merged
  verdicts: StageVerdict[]; // this corpus's own four-stage trace
  attestation: AttestationRecord; // per-corpus attestation (cleared | stopped)
  outcome: AttestationOutcome;
};

export type CorpusTaggedVerdict = {
  corpusRef: string;
  verdict: Pick<StageVerdict, "stage" | "decision">;
};

export type Turn = {
  turnId: string;
  seq: number; // monotonic position in the session
  by: string; // participantRef that issued the turn
  intent: string; // screened at stage 2/3 like AccessRequest.intent
  queries: GatedQuery[]; // one per corpus touched, each independently gated
  // Joint = deny if ANY query denies; hold if ANY holds; pass iff ALL pass.
  jointDecision: Decision;
  consentQuorum: ConsentQuorum;
  sharedResult: BoundedResult | null; // only on unanimous pass + unanimous consent
  attestation: JointAttestation; // accretes into the session trace
  handoff?: HandoffTicket; // set when any corpus returned HOLD
  at: string;
};

// --- Joint attestation (N-party generalization of AttestationRecord) ----------

export type CoSignature = {
  corpusRef: string;
  signer: EnclaveRef; // the enclave that sealed this corpus's slice
  signature: string; // valid iff signer set == contributing corpora
};

export type JointAttestation = {
  jointAttestationId: string;
  turnId: string;
  outcome: AttestationOutcome; // cleared | stopped — emitted on EVERY turn
  sharedGateTrace: CorpusTaggedVerdict[]; // union trace, tagged by corpus
  memberAttestations: string[]; // AttestationRecord.attestationId[] bound here
  coSignatures: CoSignature[]; // one per participating enclave/custodian
  consentSnapshot: ConsentGrant[]; // consent state captured at seal time
  resultHash: string | null; // hash only; raw output never stored
  boundedResult: BoundedResult | null; // mirror of Turn.sharedResult
  routedTo?: string; // where a HOLD/DENY was handed off
  at: string;
};

// --- Human-in-the-loop handoff for HOLD verdicts ------------------------------

export type HandoffTicket = {
  ticketId: string;
  turnId: string;
  corpusRef: string; // which corpus's gate held
  raisedByStage: GateStage; // 1 step-up, 2 dual-use, 3 clinical-safety
  assignedTo: CollabRole; // review officer / expert / ethics-legal
  reviewer: IdentityRef | null; // set when a human picks it up (cf. StageVerdict.reviewer)
  resolution: "pending" | "released" | "denied";
  at: string;
};

// --- Royalty metering (per party, per corpus) ---------------------------------

export type RoyaltyLedgerRef = {
  ledgerRef: string; // pointer to escrow / marketplace ledger
  currency: "usd" | "credit";
  accrued: number; // running total metered to this owner's corpus
};

// --- The session --------------------------------------------------------------

export type SessionCorpus = {
  corpusRef: string;
  ownerRef: string; // participantRef of the data-owner
  policy: CorpusPolicy; // enforced independently (existing shape)
  sealedIn: EnclaveRef; // each corpus sealed under its own key/keyspace
};

export type SharePolicy = {
  requireUnanimousConsent: true; // shared output needs every owner's active grant
  failClosed: true; // any single corpus DENY denies the shared output
  boundedOutputsOnly: true; // only BoundedResult crosses the boundary
  holdHandoffTo: CollabRole; // default role for HOLD tickets
};

export type CollabSession = {
  sessionId: string;
  label: string;
  enclave: EnclaveRef; // the shared attested boundary all turns run in
  participants: Participant[];
  corpora: SessionCorpus[]; // each still governed by its OWN CorpusPolicy
  sharedGateTrace: CorpusTaggedVerdict[]; // append-only, corpus-tagged
  turns: Turn[]; // in order
  royalties: RoyaltyLedgerRef[]; // running per-party meter
  sharePolicy: SharePolicy;
  status: "open" | "sealed" | "closed" | "aborted";
  openedAt: string;
  closedAt?: string;
};
