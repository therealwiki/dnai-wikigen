# wikigen — User Functions Catalog

What a user (data owner, requester/clinician, sponsor, or their agent) can do across
the wikigen / NDAI Attested Diligence Room stack — and how real each function is today.

**Status legend**
- ✅ **Real** — working code, deployed and/or unit-tested.
- 🟡 **Modeled** — illustrative/synthetic in the frontend, or a backend stub; the shape exists, the enforcement doesn't.
- 🔴 **Needs work** — roadmap; not built.

> The whole point of the platform: security is *right-sized to the data*. Low-sensitivity/local
> functions need no TEE (access control + audit); high-sensitivity/cross-boundary functions engage
> a confidential-compute enclave. The locality axis (on-device / enclave / hybrid / api-only) is
> that decision surface.

---

## 1. Identity & Assurance

| Function | What the user does | Status | Where |
|---|---|---|---|
| Attested identity | Present a verified principal + role; unattested → denied at stage 1 | 🟡 modeled | `IdentityRef` in gate; real IdP 🔴 |
| Elevated step-up (opt-in biometric/facial) | Raise assurance for restricted corpora; proportionate, privacy-law-bound, never default-on | 🔴 needs work | prose only; consent-encoding + verifier unbuilt |
| Measured-code boot auth | Only attested TEE code may boot the oracle / request OTPs | 🟡 modeled | `EmailOracleAuth.sol` deployed, but `allowAnyDevice=true`, not frozen |

## 2. Data Privacy & Custody

| Function | What the user does | Status | Where |
|---|---|---|---|
| Register a sealed corpus | Publish a data store as *pointer + policy*, never a raw dump | 🟡 modeled | `CorpusPolicy`; `props-room` `ControllerRecord` stub |
| Set corpus policy | Declare sensitivity tier, required assurance, allowed purposes, pipeline allowlist, restricted categories, royalty/query | 🟡 partial | `tinker_delegate.policy_kernel` enforces source-level `CorpusPolicy`; production authoring/migration/review 🔴 |
| Per-corpus key sealing | Data unsealed only inside the same enclave measurement | 🟡 partial | dstack-KMS sealing works for 2 fixed paths; per-`corpusRef` keying 🔴 |
| Bounded output only | Guarantee raw values never leave — only score bands / yes-no / hash | ✅ real | `control_plane` ScoreBand + `submitResult` posts band+hash |
| Egress / DLP control | Give the locality axis runtime teeth; block raw egress on hybrid/api-only | 🔴 needs work | locality is UI-only today |
| De-identification / re-id risk check | Flag re-identification risk before a run | 🟡 illustrative | `data-qc-harmonizer` skill; not a validated guarantee 🔴 |

## 3. Access Requests & Gating

| Function | What the user does | Status | Where |
|---|---|---|---|
| Submit an access request | Ask to run a pipeline against a corpus for a declared purpose | 🟡 partial | `AccessRequest` + `gate_turn_requests` + `policy-gate` CLI; service/API wiring 🔴 |
| Four-stage pre-inference gate | Purpose → pipeline/output → category risk/review → bounded pass; stop at first non-pass | ✅ real (pure fn + CLI proof) | `tinker_delegate.policy_kernel`, `policy-gate`, focused tests; attested service wiring 🔴 |
| Purpose + allowlist enforcement | Only allowed purposes/pipelines clear | ✅ real | deterministic policy stages 1-2 |
| Bio-risk screen-and-deny | Restricted categories deny; ambiguous/dual-use categories hold for review | 🟡 partial | deterministic stage 3; real biosecurity classifier 🔴 |
| Hold → human review | Ambiguous/dual-use requests routed to a reviewer | 🟡 partial | route labels, coordination hold tickets, bounded review queue, expiry/audit real; notification/UI 🔴 |
| ConSECA policy authoring | LLM-drafted policies compiled to a deterministic, fail-closed enforcer | 🔴 needs work | deterministic enforcement exists; LLM draft compiler/review workflow 🔴 |

## 4. Bidding & Economics (NDAI)

| Function | What the user does | Status | Where |
|---|---|---|---|
| Open a deal (reserve price + budget cap) | Seller sets floor; buyer caps spend | ✅ real | `DiligenceRoom.createDeal` / `fundDeal` (Base Sepolia, tested) |
| Buyer-agent bids inside the TEE | Agent inspects sealed artifact, emits an offer **within cap** + bounded findings | 🟡 modeled | `submitResult` (bounded) ✅; evaluator is stub/SFT 🟡 |
| Accept / reject / expire | Settle or walk away; time-boxed | ✅ real | `acceptDeal` / `rejectDeal` / `expireDeal` |
| Pull-payment settlement + fee | Funds flow on accept; safe withdraw pattern | ✅ real | `withdraw` / `pendingWithdrawals` |
| Per-query royalty metering (expose path) | Owner earns per attested query | 🟡 surfaced | `royaltyPerQuery` in UI/types; on-chain settlement 🔴 |
| Budget-cap robustness (agent-error) | Cap prevents runaway overpayment under noisy agents | 🟡 concept | the paper's "error slider" demo; not built |
| Staged rental (raw → train → inference) | Rent access at graduated depth, each unlocked separately | 🟡 stub | `props-room` `DealStage` lifecycle |

## 5. Agentic Coordination

| Function | What the user does | Status | Where |
|---|---|---|---|
| Delegate to a scientific agent | 16 skills run strictly downstream of the gate, bounded outputs only | 🟡 modeled | `skills.ts`; real execution 🔴 |
| Dual-use self-prescreen | Agent runs stage-3 on its own drafts before acting | 🟡 modeled | `dual-use-prescreen` skill |
| N-party collaborative session | Many owners; each cross-corpus turn fans out into independently-gated requests; joint attestation; unanimous or M-of-N consent; per-party royalties | 🟡 modeled | source reducer, tests, `consent-decision` CLI/API receipts; product UI/effect wiring 🔴 |
| IP-preserving outsourcing | Broker outside analysis without disclosing either side's IP | 🟡 modeled | `ip-preserving-outsourcing-broker` skill |
| Federated query planner / matchmaking | Surface viable collaborations across sealed stores without pooling | 🔴 needs work | discovery layer unbuilt |
| Isolated agent session + cost meter | Sandboxed agent run with TTL + output bounding | ✅ real | `IsolatedTinkerSession` (blocked upstream on Tinker bot-check) 🟡 |

## 6. Attestation & Audit

| Function | What the user does | Status | Where |
|---|---|---|---|
| Attestation on every run | Signed record for cleared **and** stopped runs; raw never stored | 🟡 modeled | frontend signature illustrative |
| Verify a live TEE | Fetch a real Intel TDX quote (source hash → measurement) with no token | ✅ real | Live TEE section → dstack-webhost verifier |
| On-chain result hash | `resultHash` emitted per evaluation | ✅ real | `EvaluationSubmitted` event |
| Real quote verification (DCAP/PCCS) | Accept results from the *measurement*, not a trusted address | 🔴 needs work | `submitResult` trusts bare `teeIdentity` |
| Transparency log of all runs | Append-only, publicly verifiable history incl. denials | 🔴 needs work | not built |

## 7. Consent, Revocation & Lifecycle

| Function | What the user does | Status | Where |
|---|---|---|---|
| Time-boxed / temporary grant | Access auto-expires | ✅/🟡 | contract `expireDeal` ✅; session TTL ✅; consent-grant expiry 🟡 |
| Revoke immediately (prospective) | Owner kills future access; prior attestations stay valid | 🟡 modeled | collab `ConsentGrant`; runtime kill-switch 🔴 |
| Governance/consent evidence check | Require IRB / consent / DUA before a run | 🟡 modeled | `governance-consent-checker` skill |
| Provable artifact destruction | Prove the artifact + keys were destroyed on resolution | 🟡 partial | artifact zeroing exists; attestable destruction 🔴 |

## 8. Interoperability & Discovery

| Function | What the user does | Status | Where |
|---|---|---|---|
| Bring your own store (FHIR/OMOP/FAIR/GA4GH) | Present a heterogeneous store through one gated interface | 🟡 modeled | `data-qc-harmonizer` targets FHIR/OMOP/FAIR; adapters 🔴 |
| Discovery (Beacon-style) | Find complementary cohorts without revealing data | 🔴 needs work | unbuilt |
| Multi-enclave federation | Evaluate a corpus in a peer enclave proving equivalent measurement | 🔴 needs work | single-CVM assumption today |
| Inbox delivery of bounded results | Cleared results delivered to a person/org inbox | 🟡 modeled | `bounded-result-courier` skill; tee-email-oracle inbound ✅, outbound 🔴 |

---

## The honest gap summary

**Real and load-bearing today:** the on-chain economics (reserve/cap/escrow/settlement, 39 tests), the pure four-stage gate + tests, bounded-output enforcement, sealed-secret storage (2 paths), the isolated agent session, and live TEE *verification* against dstack-webhost.

**Modeled but not enforced:** every access-control verdict (illustrative scaffolding), corpus policies, N-party sessions, the skills catalog, royalty metering, staged rental, consent/revocation.

**The critical path to "real":** (1) real TDX quote verification, (2) per-corpus sealing + attested ingress, (3) egress/DLP so locality has teeth, (4) the ConSECA screening kernel + a human-review queue (fail-closed until both exist), (5) on-chain royalty settlement, (6) a discovery/matchmaking layer, (7) interop adapters. These are the private-infra roadmap items surfaced in the app.
