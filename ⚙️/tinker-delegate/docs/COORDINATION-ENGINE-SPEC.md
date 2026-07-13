# Coordination Engine & Multi-Party Demo — Spec

Two things, plus where the TEE services fit:

- **Part A** — the coordination *state machine* that sits above the pure gate (fan-out → combine → consent → escalate → hold → revoke → settle).
- **Part B** — a runnable delegated/multi-owner scenario for the gate simulator.
- **Part C** — how **tee-email-oracle** (email TEE) and **tinker-delegate** (tinker) play their roles.

> Anchor: the gate stays `gate(request, policy)` — a **pure function of one (request, policy)**.
> The engine below never touches that. It is a separate, fail-closed reducer that composes many
> single-party decisions. Keep them separate so both stay testable.

---

## Part A — Coordination state machine

### A.1 Inputs

```ts
type Turn = {
  turnId: string;
  by: string;                       // participantRef issuing it (may be a delegated agent)
  intent: string;
  corpora: string[];                // corpusRefs this turn touches
  requests: Record<string, AccessRequest>;  // one per corpus (built from the turn)
};

type CoordinationState = {
  session: CollabSession;           // participants, corpora, consent grants (types-collab.ts)
  turns: Record<string, TurnRecord>;
};

type TurnRecord = {
  turn: Turn;
  status: TurnStatus;
  queries: GatedQuery[];            // per-corpus gate results
  tickets: HandoffTicket[];         // open human-review tickets
  joint: JointAttestation | null;
};

type TurnStatus =
  | "gating"                        // fan-out in flight
  | "denied"                        // terminal: any query denied, or restricted escalation
  | "held"                          // terminal-until-resolved: a hold pending human review
  | "awaiting-consent"              // all passed, waiting on unanimous/quorum consent
  | "surfaced"                      // shared bounded result released
  | "revoked"                       // a contributing corpus was revoked mid-turn
  | "settled";                      // royalties metered + attestation sealed
```

### A.2 State diagram

```
        ┌─────────┐  any DENY / restricted escalation   ┌────────┐
 Turn ─▶│ gating  │────────────────────────────────────▶│ denied │ (terminal, → ethics/legal if restricted)
        └────┬────┘  any HOLD                             └────────┘
             │      ─────────────────────────▶ ┌──────┐  reviewer.deny ─▶ denied
             │                                 │ held │  reviewer.release ─▶ back to gating (re-issue)
             │      all PASS                    └──────┘
             ▼
     ┌────────────────┐  quorum incomplete ─▶ (withheld; waits)
     │ awaiting-consent│  quorum OK ─▶ surfaced
     └────────┬────────┘
              ▼
        ┌──────────┐  meter royalties + emit joint attestation
        │ surfaced │ ─────────────────────────────────────────▶ settled
        └──────────┘
   revoke(corpus) at any point that touches this turn ─▶ revoked (fail-closed, no surface)
```

### A.3 Transition rules (pure)

1. **Fan-out** — a `Turn` over N corpora becomes N `AccessRequest`s; each runs `gate(request_i, policy_i)` independently. No policy is merged.
2. **Combine (joint decision)** — `deny` if *any* query denies; `hold` if *any* holds and none deny; `pass` iff *all* pass. (Fail-closed toward the strictest.)
3. **Escalation supersedes consent** — if any query denied at **stage 3 (restricted)**, the turn is `denied` *terminally* and routed to `ethics-legal-reviewer`; no consent can flip it.
4. **Consent / quorum** — on all-pass, check the `ConsentQuorum`: every contributing owner must hold an *active* grant covering (purpose, pipeline, requester). Unanimous (or M-of-N if configured) → `surfaced`; otherwise withhold.
5. **Hold handling** — each `hold` opens a `HandoffTicket` routed by stage to the right role (1/2 → access-review-officer, clinical-safety → expert-in-the-loop, restricted → ethics-legal). The turn is fail-closed while any ticket is pending. **A delegated agent can never resolve its own ticket.** `reviewer.release` → re-gate; `reviewer.deny` → `denied`.
6. **Revocation** — an owner flips a grant to `revoked` (immediate, prospective). Any *in-flight or future* turn touching that corpus goes `revoked` and surfaces nothing. Already-`settled` attestations stay valid (append-only trace).
7. **Settle** — on `surfaced`: meter each owner's `royaltyPerQuery` to their ledger, seal a co-signed `JointAttestation`, transition to `settled`.

### A.4 Invariants (must hold every transition)

- **Intersection, never union** — coordination can only narrow what's allowed.
- **Non-escalating delegation** — a delegate's authority ⊆ its grantor's.
- **Fail-closed** — deny/withhold/suspend on any deny, any pending hold, any missing consent, any unresolved delegation, or any uncertain screen.
- **Agents can't self-approve.**
- **Attest everything** — a joint attestation is emitted for cleared *and* stopped turns; `reviewer` is recorded on any released hold.

### A.5 Shape: pure reducer + injected effects

```ts
// Pure core — deterministic, unit-testable with fixed env.
function coordinate(state, event, env): CoordinationState

type CoordEvent =
  | { t: "submit-turn"; turn: Turn }
  | { t: "gate-results"; turnId: string; queries: GatedQuery[] }
  | { t: "reviewer-decision"; ticketId: string; decision: "release" | "deny"; reviewer: IdentityRef }
  | { t: "revoke"; corpusRef: string; by: string }

type CoordEnv = {
  gate: (req: AccessRequest, pol: CorpusPolicy) => StageOutcome[];  // the pure gate
  now: () => string; uuid: () => string; sign: (p: string) => string;
  notify: (ticket: HandoffTicket, role: CollabRole) => void;        // → tee-email-oracle
  settle: (turnId: string, meters: RoyaltyMeter[]) => void;         // → DiligenceRoom
};
```

All side effects (human notification, on-chain settlement) are **injected**, so the state machine
is a pure reducer you can property-test; the effects are where the TEE services plug in (Part C).

### A.6 Test matrix (minimum)

| Case | Expect |
|---|---|
| 2 corpora both pass, unanimous consent | surfaced → settled, joint attestation, 2 meters |
| one corpus denies (allowlist/purpose) | denied, no surface, attestation emitted |
| one corpus holds (dual-use) | held; agent cannot resolve; officer.release → re-gate → surfaced |
| restricted intent on any corpus | denied terminal, routed ethics-legal, consent ignored |
| consent missing on one owner | withheld (awaiting-consent), never surfaces |
| revoke mid-turn | revoked, prior settled attestations still valid |
| delegate exceeds grantor scope | rejected at fan-out (non-escalation) |

---

## Part B — Multi-party demo (gate simulator extension)

### B.1 What to add
Today the simulator runs one `(request, policy)`. Add a **"coordinated turn"** mode: pick a turn,
watch it **fan out into per-corpus gate columns**, then the **combine → consent → outcome**, with a
**"resolve as reviewer"** button when a turn is `held`. Reuse the existing `GateSimulator` stage UI
per column; add the join panel + the live `JointAttestation` JSON.

### B.2 Cast & corpora (reuses existing data)
- **Atlas Bio** — `corpus://atlas-bio/assay-vault` (restricted, elevated).
- **Halcyon Bio** — `corpus://halcyon-bio/response-vault` (restricted, elevated; add to `corpora.ts`).
- **Meridian CRO agent** — delegated by a sponsor; issues turns; cannot self-clear holds.
- **Access-review officer**, **ethics-legal reviewer** (existing `IDENTITIES`).

### B.3 Turn script (deterministic)

| Turn | Intent | Fan-out result | Coordination outcome |
|---|---|---|---|
| 1 | "rank assay conditions by cross-cohort consistency" | Atlas PASS · Halcyon PASS | unanimous consent → **surfaced** band + joint attestation + 2 royalty meters |
| 2 | "export ranked compound structures downstream" | Atlas **HOLD** (dual-use) · Halcyon PASS | **held** → ticket to access-review officer → *release (narrowed)* → re-gate → surfaced |
| 3 | "use the analysis for de novo binder design" | Atlas **DENY** (stage-3 restricted) | **denied** terminal → ethics-legal; consent cannot override |
| 4 | (Halcyon revokes consent) then "re-run turn 1" | Halcyon **revoked** | **revoked**, fails closed; turn-1 attestation still valid |

### B.4 What the UI shows
Per turn: N stage columns (the existing pass/hold/deny reveal), a **join row** (deny-if-any /
hold-if-any / pass-iff-all), a **consent chip** per owner, the **terminal stamp** (SURFACED /
DENIED / HELD / REVOKED), the **routedTo** role, and the co-signed `JointAttestation` JSON.

---

## Part C — Roles of the TEE services

Both are **TEE-hosted** (Phala CVMs). They are the effects the coordination engine injects.

### C.1 tee-email-oracle — the attested human-coordination channel
The email oracle runs inside a TEE and handles messages so no operator can read or forge them.
In the coordination engine it is the **`notify` + out-of-band confirmation** effect:
- **Hold routing** — when a turn is `held`, the `HandoffTicket` is delivered to the assigned human
  role's inbox (access-review officer / clinician / ethics-legal). Attested delivery means the
  reviewer can trust the request genuinely came from the gate.
- **Out-of-band confirmation / step-up** — a data owner confirms a consent grant, a revocation, or
  a reviewer confirms a release via an emailed one-time code the oracle verifies **inside the TEE**
  (its existing OTP path). This is the human-approval leg of B1/B3 without exposing credentials.
- **Bounded-result delivery** — the "results to your inbox via wikigen.me": the oracle is the
  outbound courier for a `surfaced` turn's bounded band (the `bounded-result-courier` skill).
- **Live delegation exemplar** — `EmailOracleAuth.sol` is the *tested* B1 primitive: owner delegates
  consumer management to a manager (who can't change oracle policy), with freeze + timelock + revoke.
  So the email TEE both *demonstrates* non-escalating delegation and *carries* the human coordination.

### C.2 tinker-delegate — the attested execution + evaluation + settlement substrate
When a turn reaches **stage 4 (attested execution)**, tinker-delegate is what actually runs it:
- **Bounded execution** — `IsolatedTinkerSession` runs the model against the sealed corpus inside
  the enclave with a **cost meter**; `control_plane` bounds the output to a `ScoreBand` and emits the
  attestation. That *is* the gate's stage-4 for enclave-tier requests.
- **Evaluator agents** — the stub/SFT evaluators are the "buyer-side agent that inspects inside the
  boundary and emits only bounded findings" — the agentic-coordination compute.
- **Economic settlement** — the `settle` effect: the deal lifecycle (`control_plane`) + `DiligenceRoom`
  (reserve, budget cap, per-query royalty, pull-payment) settle a `surfaced` turn.
- **Credential-free delegation** — it provisions API keys *inside* the TEE so no human touches them:
  a metered, scoped delegation of compute authority (B1 in runtime form).

### C.3 End-to-end: a coordinated request through both
```
CRO agent ─turn→ Coordination engine
   ├─ fan-out → gate(req, policy) per corpus            [pure]
   ├─ HOLD?   → notify(ticket) ──▶ tee-email-oracle ──▶ reviewer inbox + OTP confirm  [email TEE]
   ├─ PASS + consent → stage-4 execution ──▶ tinker-delegate IsolatedTinkerSession    [tinker TEE]
   │                                          → ScoreBand + attestation
   ├─ settle → DiligenceRoom (royalty/escrow)                                          [tinker/chain]
   └─ deliver bounded band ──▶ tee-email-oracle ──▶ requester inbox (wikigen.me)       [email TEE]
```
- **Tier-aware:** low-sensitivity/local turns skip tinker-delegate's enclave entirely (access-control +
  audit only); enclave-tier turns engage it. The email TEE is used wherever a *human* or a *notification*
  is in the loop, regardless of tier.

---

## Build order & status

1. **🔴 Coordination reducer** (Part A) — pure `coordinate()` + the A.6 test matrix. Ships without any UI.
2. **🟡→ Demo mode** (Part B) — extend the simulator with coordinated turns over existing data (+ add the Halcyon corpus).
3. **Effects** — wire `notify` to tee-email-oracle (✅ service exists; ticket delivery 🔴) and `settle`/stage-4 to tinker-delegate (✅ session + contract exist; deal↔engine wiring 🔴).

The reducer is the keystone: build it pure and fail-closed first; the two TEE services are already
real, so they slot in as the injected `notify` (email) and `execute/settle` (tinker) effects.
