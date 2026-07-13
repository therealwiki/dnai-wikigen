# Governance & Authorization Coordination

How authority is exercised across the stack — from a single owner authorizing one
requester, up to delegated, multi-party governance — and the invariants that keep every
decision attributable and replayable.

## The invariant that makes it composable

The gate is always a **pure function of one `(AccessRequest, CorpusPolicy)`**. No matter how
many parties govern, wikigen never builds a "multi-party gate." Every governance model is an
**accretion of independent single-party decisions** plus a thin coordination layer that
decides how those decisions combine (consent, quorum, escalation). One authority per corpus;
coordination on top. That is what keeps a 6-party session as auditable as a 1-party request.

---

## Model A — One-party request/auth coordination

The base case: **one requester, one authority.**

```
Requester ──AccessRequest──▶ Gate(request, ownerPolicy) ──verdict──▶ attested run
                                    │
                              CorpusOwner sets the single policy
```

- The **owner's `CorpusPolicy` is the whole authorization surface.** One decision-maker.
- Cleared → bounded result + attestation; the grant is time-boxed and owner-revocable.
- Economic variant: a 2-party NDAI **deal** (one seller, one buyer) with reserve + budget cap.
- **Status:** gate ✅ (verdict logic illustrative); `DiligenceRoom` 2-party deal ✅ on-chain.

Use it when a single custodian owns the data and can decide alone. No coordination overhead,
no quorum, no escalation beyond that owner's own restricted-category denials.

---

## Model B — Multi-governance delegation

Authority is **distributed and/or delegated.** Five composable sub-patterns:

### B1 · Delegated authority (owner → manager / agent), non-escalating
An owner hands a *scoped* slice of authority to a delegate that **cannot exceed the grantor**.
- Concrete, tested: `EmailOracleAuth.sol` — the **owner** delegates *consumer management* to a
  **manager**, but the manager **cannot change oracle policy**; the owner can **freeze** the
  registry (locking even themselves and the manager); compose-hash activation is **timelocked**
  (propose → activate after a delay); removing a hash **revokes** authorization.
- Agent form: an owner delegates to a **collaborator-agent** to *issue* gated requests on their
  behalf — but the agent **can never self-clear its own HOLD**.
- **Coordination:** capability scoping + non-escalation + revocable + freezeable + timelock.
- **Status:** `EmailOracleAuth` ✅ tested; agent delegation 🟡 modeled (`types-collab`).

### B2 · Multi-owner, independent policies (N-party)
Several owners, each with their own corpus + policy. A cross-corpus request **fans out** into N
independently-gated requests. **Policies are never merged** — each is enforced against its own
corpus (intersection semantics, strictest-per-corpus wins). Shared output only on **unanimous
PASS + unanimous consent**; any DENY denies, any HOLD suspends.
- **Coordination:** fan-out + `ConsentQuorum` (unanimous) + fail-closed.
- **Status:** 🟡 modeled (`types-collab.ts` `ConsentQuorum`, `SharePolicy`); engine 🔴.

### B3 · Governance bodies & escalation (supersede consent)
Some routes require a governance body, or are hard-denied regardless of what parties agree.
- Roles: **access-review-officer** (stage-1/2 holds), **expert-in-the-loop** clinician
  (clinical-safety holds), **ethics-legal-reviewer** (stage-3 restricted escalation).
- **Consent cannot override a restricted-category deny** — it routes to human + legal + ethics
  no matter what any owner or requester agreed to.
- **Coordination:** role-routed `HandoffTicket`; escalation that *supersedes* consent.
- **Status:** 🟡 roles/tickets modeled; reviewer queue 🔴 (`reviewer` is null today).

### B4 · Quorum / threshold (M-of-N, two-person rule)
High-stakes routes require **multiple approvers** so no single captured reviewer can release.
- **Coordination:** threshold approval; two-person rule on restricted routes.
- **Status:** 🔴 concept only.

### B5 · Separation of duties (least authority)
Roles that cannot collapse into one another:
- **data-owner** (grants consent) · **session-custodian** (runs the enclave, owns no data) ·
  **auditor** (read-only, sees only hashes + bands) · **reviewer** (resolves holds).
- No role can perform another's job; the custodian can't read data, the auditor can't grant.
- **Status:** 🟡 modeled (`CollabRole` in `types-collab`).

---

## Coordination interaction matrix

| Dimension | Model A (one-party) | Model B (multi-governance) |
|---|---|---|
| Decider | one owner / policy | N owners + delegated managers/agents + governance bodies |
| Policy composition | single policy | per-corpus, **independent — intersection, never union** |
| Consent | one owner grant | **unanimous quorum** (or M-of-N) |
| Delegation | none (direct) | owner→manager, owner→agent — **scoped, non-escalating** |
| Override / escalation | owner's own denials | restricted → ethics+legal, **supersedes all consent** |
| Revocation | owner revokes | any owner revokes their slice; **prospective, fail-closed** |
| Agent authority | agent = the requester | agent issues requests, **cannot self-clear holds** |
| Audit | single attestation | **joint attestation** + corpus-tagged trace + role-attributed reviewer |
| Failure mode | deny on non-pass | **fail-closed** on any single deny/hold |

---

## Authority-composition rules (the safety invariants)

1. **Delegation never escalates** — a delegate's authority ⊆ its grantor's (EmailOracleAuth: manager ⊄ owner).
2. **Policies compose by intersection, never union** — coordination can only *narrow* what's allowed, never widen it.
3. **Consent narrows, never widens** the base `CorpusPolicy` (a grant can restrict purposes/pipelines/participants, not add).
4. **Escalation supersedes consent** — a stage-3 restricted deny routes to human+legal+ethics regardless of unanimous consent.
5. **Agents cannot self-approve** — a collaborator-agent may issue requests but never resolve its own HOLD.
6. **Every decision is attested and role-attributed** — `StageVerdict.reviewer` / `HandoffTicket.reviewer` records *who* released a hold; the trace is corpus-tagged.

---

## Interaction sequences

**(a) One-party — doctor → owner**
```
Doctor ─req→ Gate(req, MediVaultPolicy) → PASS×4 → bounded result + attestation → expires 24h
```

**(b) Delegated — owner delegates to a manager + an agent**
```
Owner ──delegate(consumer-mgmt, scoped)──▶ Manager        (manager ⊄ owner; owner can freeze)
Owner ──delegate(issue-requests)────────▶ CRO Agent
CRO Agent ─req→ Gate → HOLD(dual-use) ─ticket→ Access-Review Officer ─(human)─▶ release/deny
             (agent cannot self-clear; only the assigned human role resolves)
```

**(c) Multi-owner + governance — 2 biobanks + agent + reviewers**
```
Agent ─turn→ ⟨ fan-out ⟩
   ├─ req→ Gate(req, AtlasPolicy)   → PASS
   └─ req→ Gate(req, HalcyonPolicy) → PASS
   ⟨ unanimous consent? yes ⟩ → ONE shared bounded result + joint attestation (co-signed ×2)
Agent ─turn(restricted intent)→ Gate stage-3 DENY → ethics+legal  (no consent can override)
Halcyon ─revoke→ subsequent Halcyon-touching turns fail closed; prior attestations stay valid
```

---

## Built / modeled / needs work

- **✅ Real:** `EmailOracleAuth` delegation (owner/manager, freeze, timelock, revoke — tested); the pure single-party gate; the 2-party on-chain deal.
- **🟡 Modeled:** N-party fan-out, `ConsentQuorum`, roles, `HandoffTicket`, joint attestation, separation of duties (all in `types-collab.ts` + the collab-sessions demo).
- **🔴 Needs work:** the coordination *engine* (fan-out executor, quorum evaluator), the human-review queue (fail-closed until it exists), M-of-N / two-person rule, and delegated-agent authority enforced at runtime rather than by contract types.

The safe way to build this out: keep the gate a pure single-party function, add the coordination
layer as a separate, testable state machine (quorum + escalation + revocation), and make it
**fail-closed** — deny or suspend on any missing consent, any pending hold, or any unresolved
delegation — until the reviewer queue and quote verification are real.
