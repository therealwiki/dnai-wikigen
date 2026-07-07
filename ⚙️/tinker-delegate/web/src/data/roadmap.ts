/**
 * Private-infrastructure roadmap. Honest about what is real vs. what the word
 * "attested" is currently writing a check for. Each item is tied to the actual
 * file, contract, or paper it maps to. Status is deliberately candid:
 * `shipped` = real code exists; `in-progress` = partial; `planned` = not built.
 */
export type RoadmapStatus = "shipped" | "in-progress" | "planned";
export type RoadmapPriority = "p0" | "p1" | "p2";

export type RoadmapItem = {
  id: string;
  title: string;
  why: string;
  status: RoadmapStatus;
  mapsTo: string;
  priority: RoadmapPriority;
  tags: string[];
};

export const ROADMAP: RoadmapItem[] = [
  {
    id: "quote-verification",
    title: "Real TDX quote verification (PCCS/DCAP + on-chain proof)",
    why: "The whole 'attested' claim is unbacked today: the escrow's submitResult() only checks msg.sender == teeIdentity (a bare address), and the enclave quote is never verified anywhere. Need DCAP verification against Intel PCCS plus an on-chain verifier binding measurement + compose-hash + signer into the quote's report_data — so a result is accepted from the attested measurement, not a trusted address.",
    status: "planned",
    mapsTo: "dstack (arXiv:2509.11555) · DiligenceRoom.sol teeIdentity · dstack_utils.get_attestation",
    priority: "p0",
    tags: ["attestation", "tdx", "verification"],
  },
  {
    id: "honest-attestation-labels",
    title: "Label demo attestations illustrative — and show a real one next to them",
    why: "lib/env.ts demoHash is a non-cryptographic FNV variant and demoSignature only mimics 'tdx:mrenclave=…'; a viewer cannot tell it from a real attestation. Every surfaced signature now carries an 'illustrative-not-verified' disclosure, AND the Live TEE section fetches a genuine, CORS-open TDX quote from amiller's dstack-webhost tee-daemon so the contrast is concrete, not asserted.",
    status: "in-progress",
    mapsTo: "web/src/lib/env.ts · lib/dstackVerifier.ts · LiveAttestation · amiller/dstack-webhost",
    priority: "p0",
    tags: ["honesty", "attestation", "ux"],
  },
  {
    id: "host-on-webhost",
    title: "Host the gate on a tee-daemon and promote to attested",
    why: "dstack-webhost is a ready substrate: the gate's Vite dist/ is a static directory, so it deploys as a runtime:'static' project via POST /_api/projects on a tee-daemon, then promotes to 'attested' — binding the built app's tree_hash into a real TDX quote. That is the single step that turns this app's own 'attested' from illustration into a verifiable claim.",
    status: "planned",
    mapsTo: "amiller/dstack-webhost (proxy/deploy.py · /_api/projects) · web dist/ · Phala CVM",
    priority: "p1",
    tags: ["hosting", "attestation", "dstack-webhost", "static"],
  },
  {
    id: "synthetic-only-guard",
    title: "Interim synthetic-only guard on high/restricted corpora",
    why: "Sealed ingress, egress-DLP, and per-corpus key sealing are not live, yet corpora are tagged high/restricted and the artifact path holds plaintext in memory under one shared key. An enforced flag + banner: high/restricted corpora are declared synthetic, and the ingress path refuses non-synthetic data until sealing + DLP + quote verification are attested-live.",
    status: "planned",
    mapsTo: "control_plane.receive_artifact · CorpusPolicy.sensitivityTier",
    priority: "p0",
    tags: ["privacy", "guardrail", "phi"],
  },
  {
    id: "per-corpus-keys",
    title: "Per-corpus key derivation & sealing (unseal only in-enclave)",
    why: "Sealing works today but only for two fixed paths (tinker/api_key, email/creds). The marketplace needs each sealed corpus keyed by corpusRef via dstack-KMS, with rotation and measurement-bound unseal, so one corpus's key cannot decrypt another's.",
    status: "in-progress",
    mapsTo: "dstack-KMS · api_key_store.py · CorpusPolicy.corpusRef",
    priority: "p0",
    tags: ["kms", "sealing", "keys"],
  },
  {
    id: "conseca-policy",
    title: "ConSECA policy authoring, versioning & deterministic enforcement",
    why: "Screening is hardcoded string-matching in evaluate.ts plus static Solidity allowlists. ConSECA's model is LLM-drafted policies compiled to a deterministic enforcer. Need a policy authoring surface, signed/versioned artifacts, a replay harness — and a hard constraint that every stage-3 policy stays deny-by-default on declared-intent match with zero hazard descriptors; the enforcer fails closed on any artifact containing operational hazard criteria.",
    status: "planned",
    mapsTo: "ConSECA (arXiv:2501.17070) · web/src/gate/evaluate.ts · CorpusPolicy",
    priority: "p1",
    tags: ["policy", "conseca", "screen-and-deny"],
  },
  {
    id: "egress-dlp",
    title: "Egress firewall / DLP — give the locality axis runtime teeth",
    why: "The teal/olive/amber axis is UI-only; boundedResultFor() just prints a note claiming egress was gated. Need a real per-capability egress allowlist, payload inspection/redaction so raw values can never leave on hybrid/api-only paths, and metered logging of every outbound call. A referenceData descriptor lets analysis tools that look up ClinVar/gnomAD/UniProt declare hidden egress (must be mirrored/sealed in-enclave).",
    status: "planned",
    mapsTo: "ConSECA enforcement · Capability.locality · control_plane output bounding",
    priority: "p1",
    tags: ["egress", "dlp", "locality"],
  },
  {
    id: "reviewer-queue",
    title: "Human-review workflow & reviewer queue for HOLD verdicts",
    why: "StageVerdict.reviewer is set to null on every verdict, and routedTo strings point at queues that don't exist. Elevated-assurance and dual-use holds need a real reviewer inbox that writes the reviewer IdentityRef back into the verdict, with SLA, appeal/override, and a two-person rule for restricted routes. Until it exists, the gate must fail closed on uncertain screening of restricted/high corpora.",
    status: "planned",
    mapsTo: "Gate stages 1-2 hold path · StageVerdict.reviewer/routedTo · IDENTITIES.humanReviewer",
    priority: "p1",
    tags: ["human-review", "hold", "fail-closed"],
  },
  {
    id: "transparency-log",
    title: "Tamper-evident transparency log of all attestations",
    why: "An attestation is emitted for every run (cleared and stopped), but there is no append-only, publicly verifiable log of all of them. A Merkle/CT-style transparency log with inclusion proofs makes a stopped/denied run as auditable as a cleared one, without exposing raw outputs.",
    status: "planned",
    mapsTo: "dstack (arXiv:2509.11555) · AttestationRecord · DiligenceRoom EvaluationSubmitted",
    priority: "p1",
    tags: ["transparency", "audit", "merkle"],
  },
  {
    id: "federated-learning",
    title: "Confidential federated learning + differential-privacy budgets",
    why: "The local-to-pooled promise has zero backing code. Need secure aggregation inside the enclave (no single contributor's update visible) plus per-corpus/per-principal DP budget accounting that is metered, enforced, and attested — bound to the policy gate so only analysis objectives are permitted and any generative/de-novo objective is a gated-deny.",
    status: "planned",
    mapsTo: "NDAI (arXiv:2502.07924) · control_plane.py · pooled corpora",
    priority: "p1",
    tags: ["federated", "secure-aggregation", "differential-privacy"],
  },
  {
    id: "sealed-ingress",
    title: "Sealed artifact ingress (ECIES to enclave key) + on-chain hash binding",
    why: "The X25519+AES-256-GCM channel is built for the card path but the deal-artifact path still takes plaintext hex in memory. Reuse encrypt_for_tee so raw datasets are sealed to the attested enclave pubkey and the on-chain artifactHash binds ciphertext the buyer never sees.",
    status: "in-progress",
    mapsTo: "crypto.py encrypt_for_tee · control_plane.receive_artifact · DiligenceRoom.artifactHash",
    priority: "p1",
    tags: ["ingress", "ecies", "sealing"],
  },
  {
    id: "royalty-settlement",
    title: "On-chain royalty settlement + reserve price / budget cap metering",
    why: "The escrow half is real — DiligenceRoom ships reservePrice, budgetCap, a fee, and three-way pull-payment settlement. Missing is the expose path: royaltyPerQuery is surfaced in the UI but never settled on-chain, and there is no cross-query budget accounting for metered inference. Wire royalty metering into settlement so custodians are paid per attested query.",
    status: "in-progress",
    mapsTo: "DiligenceRoom.sol · NDAI escrow (arXiv:2502.07924) · CorpusPolicy.royaltyPerQuery",
    priority: "p1",
    tags: ["royalty", "settlement", "escrow"],
  },
  {
    id: "oracle-hardening",
    title: "Email-oracle trust hardening: register compose hashes & freeze",
    why: "EmailOracleAuth — the identity/authorization root of the whole gate — is deployed wide open (allowAnyDevice=true, code not frozen). Register the final oracle + consumer compose hashes, disable allowAnyDevice, exercise the upgrade timelock, then freeze so only measured code can boot and request OTPs.",
    status: "in-progress",
    mapsTo: "EmailOracleAuth.sol (dstack IAppAuth) · email-oracle CVM",
    priority: "p1",
    tags: ["identity", "measured-boot", "freeze"],
  },
  {
    id: "biometric-step-up",
    title: "Opt-in, proportionate biometric/facial step-up for elevated assurance",
    why: "assuranceTier='elevated' currently just produces a stage-1 HOLD with prose. A genuinely opt-in, privacy-law-bound verifier for elevated-tier corpora only — liveness handled in the enclave / on-device secure enclave, no raw biometric ever persisted, and a non-biometric fallback so verification is never mandatory-by-default.",
    status: "planned",
    mapsTo: "Gate stage 1 · AccessRequest.assuranceTier · on-device-secure-enclave",
    priority: "p2",
    tags: ["biometric", "opt-in", "assurance"],
  },
  {
    id: "multi-enclave-federation",
    title: "Multi-enclave trust federation & cross-attestation",
    why: "Everything assumes a single CVM and one teeIdentity. A real marketplace spans enclaves (per custodian, per region, on-device + Phala). Need cross-enclave attestation exchange, federated key hand-off so a corpus sealed to one enclave can be evaluated in a peer proving an equivalent measurement, and a registry of accepted enclave identities.",
    status: "planned",
    mapsTo: "dstack (arXiv:2509.11555) · EnclaveRef · teeIdentity",
    priority: "p2",
    tags: ["federation", "multi-enclave", "cross-attestation"],
  },
];
