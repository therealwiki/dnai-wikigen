import { createMemo, createSignal, For } from "solid-js";
import {
  AlertTriangle,
  ArrowRight,
  CircleDashed,
  ClipboardCheck,
  Clock3,
  EyeOff,
  Fingerprint,
  Flag,
  History,
  KeyRound,
  ListChecks,
  LockKeyhole,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Signature,
  UserRoundCheck,
} from "lucide-solid";

export interface ReviewAuthorityReadiness {
  reviewerBackendConfigured: boolean;
  releasePolicyPinned: boolean;
  reviewerSetPinned: boolean;
  signatureDomainPinned: boolean;
  releaseIdentityVerified: boolean;
}

export function reviewAuthorityReady(input: ReviewAuthorityReadiness): boolean {
  return input.reviewerBackendConfigured
    && input.releasePolicyPinned
    && input.reviewerSetPinned
    && input.signatureDomainPinned
    && input.releaseIdentityVerified;
}

type ReviewLane = "Arena result" | "Compute output" | "Diligence finding";

interface ReviewExample {
  id: string;
  lane: ReviewLane;
  title: string;
  purpose: string;
  requestedOutput: string;
  outputClass: string;
  policy: string;
  hold: string;
  sequence: string;
}

const REVIEW_EXAMPLES: readonly ReviewExample[] = Object.freeze([
  Object.freeze({
    id: "RQ-MODEL-041",
    lane: "Arena result",
    title: "Publish a challenge score band",
    purpose: "Update a public ranking after a confidential evaluation",
    requestedOutput: "Score band + candidate commitment",
    outputClass: "Band · commitment",
    policy: "bounded-ranking.v1",
    hold: "Release authority bundle absent",
    sequence: "Illustrative order 01",
  }),
  Object.freeze({
    id: "RQ-MODEL-042",
    lane: "Compute output",
    title: "Return a workload completion receipt",
    purpose: "Report a bounded job outcome to the requesting principal",
    requestedOutput: "Outcome code + usage-receipt reference",
    outputClass: "Code · hash reference",
    policy: "bounded-compute-result.v1",
    hold: "Runtime evidence adapter absent",
    sequence: "Illustrative order 02",
  }),
  Object.freeze({
    id: "RQ-MODEL-043",
    lane: "Diligence finding",
    title: "Release an evaluator finding band",
    purpose: "Return a narrowly declared diligence conclusion",
    requestedOutput: "Finding band + reason code",
    outputClass: "Band · enum",
    policy: "bounded-diligence.v1",
    hold: "Reviewer identity set absent",
    sequence: "Illustrative order 03",
  }),
]);

const OUTPUT_CONTROLS = Object.freeze([
  Object.freeze({
    title: "Declared output class",
    detail: "Only the named band, enum, count range, or commitment may be considered for release.",
    state: "SOURCE REQUIREMENT",
  }),
  Object.freeze({
    title: "Exact schema and field allowlist",
    detail: "Unexpected fields, free-form text, attachments, and nested payloads must fail closed.",
    state: "UNVERIFIED",
  }),
  Object.freeze({
    title: "Anti-reconstruction review",
    detail: "Repeated queries, joins, and auxiliary context must not turn bounded outputs into source recovery.",
    state: "UNVERIFIED",
  }),
  Object.freeze({
    title: "Purpose and recipient binding",
    detail: "The request, intended use, recipient, expiry, and release policy must share one signed domain.",
    state: "UNVERIFIED",
  }),
  Object.freeze({
    title: "Independent execution evidence",
    detail: "A real reviewer must verify the approved release identity and evidence chain outside this browser model.",
    state: "UNVERIFIED",
  }),
]);

const RELEASE_HOLDS = Object.freeze([
  Object.freeze({
    title: "Reviewer service not connected",
    detail: "No authenticated backend can load a real queue, persist a hold, or return an authoritative decision.",
  }),
  Object.freeze({
    title: "Policy authority not pinned",
    detail: "No release manifest, signature domain, reviewer threshold, or revocation state is configured here.",
  }),
  Object.freeze({
    title: "Release identity not verified",
    detail: "The browser has no current, independently verified contract-and-runtime release identity to bind.",
  }),
  Object.freeze({
    title: "Freshness cannot be established",
    detail: "No authoritative clock, monotonic sequence, expiry check, or replay-resistant audit head is available.",
  }),
]);

const REVIEWER_SLOTS = Object.freeze([
  Object.freeze({ role: "Policy reviewer", duty: "Output schema, purpose, and reconstruction risk" }),
  Object.freeze({ role: "Evidence reviewer", duty: "Release identity and execution-evidence chain" }),
  Object.freeze({ role: "Release custodian", duty: "Threshold, expiry, revocation, and final publication" }),
]);

const MODELED_AUDIT_SEQUENCE = Object.freeze([
  Object.freeze({
    n: "01",
    title: "Queue example composed",
    detail: "A source-only example was selected for interface review. Nothing was fetched or persisted.",
  }),
  Object.freeze({
    n: "02",
    title: "Bounded-output screen shown",
    detail: "The UI displays required control categories; it does not report that any control passed.",
  }),
  Object.freeze({
    n: "03",
    title: "Authority action suppressed",
    detail: "Hold, signature, rejection, and release mutations remain disabled while authority is unavailable.",
  }),
]);

function GatePill(props: { children: string }) {
  return <span class="review-gate-pill"><LockKeyhole size={12} />{props.children}</span>;
}

export function ReviewQueue() {
  const [selectedId, setSelectedId] = createSignal(REVIEW_EXAMPLES[0].id);
  const selected = createMemo(
    () => REVIEW_EXAMPLES.find((item) => item.id === selectedId()) ?? REVIEW_EXAMPLES[0],
  );
  return (
    <div class="page-wrap product-page review-queue-page">
      <header class="product-page-head review-page-head">
        <div>
          <p class="overline">Human release review · bounded egress control</p>
          <h1>Review what may leave—not what stayed private.</h1>
          <p>
            A launch-grade review desk should join one declared output, one policy,
            one verified release identity, and an accountable reviewer threshold.
            This source surface demonstrates that workflow without granting authority.
          </p>
        </div>
        <button
          class="primary-button large review-authority-button"
          type="button"
          disabled
          aria-describedby="review-authority-boundary"
        >
          <LockKeyhole size={17} /> Release authority unavailable
        </button>
      </header>

      <div id="review-authority-boundary" class="environment-banner modeled review-roadmap-banner" role="status">
        <ShieldAlert size={18} />
        <div>
          <strong>Roadmap · source-modeled examples only</strong>
          <span>
            No reviewer backend, policy authority, signature domain, reviewer set,
            release identity, or durable audit adapter is verified in this deployment.
            Nothing on this page can decide, sign, hold, reject, or release a real result.
          </span>
        </div>
      </div>

      <dl class="review-summary-strip" aria-label="Modeled review desk status">
        <div><dt>modeled examples<small>not a live queue</small></dt><dd>03</dd></div>
        <div><dt>hard release holds<small>all unresolved</small></dt><dd>04</dd></div>
        <div><dt>authority adapters<small>backend absent</small></dt><dd>00</dd></div>
        <div><dt>reviewer signatures<small>none requested</small></dt><dd>00</dd></div>
      </dl>

      <section class="review-workspace" aria-labelledby="review-workspace-title">
        <div class="review-queue-column">
          <div class="section-heading compact-heading review-column-heading">
            <div>
              <p class="overline">Modeled intake</p>
              <h2 id="review-workspace-title">Reviewer queue</h2>
            </div>
            <span class="review-source-badge"><EyeOff size={13} /> SOURCE ONLY</span>
          </div>
          <p class="review-column-note">
            Selecting an example changes only this in-memory presentation. It is not
            an acknowledgement, assignment, or review action.
          </p>

          <div class="review-queue-list" role="list" aria-label="Source-modeled review examples">
            <For each={REVIEW_EXAMPLES}>
              {(item) => (
                <div role="listitem">
                  <button
                    class={`review-queue-card ${selectedId() === item.id ? "active" : ""}`}
                    type="button"
                    aria-pressed={selectedId() === item.id}
                    aria-controls="review-selected-workbench"
                    onClick={() => setSelectedId(item.id)}
                  >
                    <span class="review-queue-card-top">
                      <span>{item.sequence}</span>
                      <em>MODELED</em>
                    </span>
                    <strong>{item.title}</strong>
                    <span>{item.lane}</span>
                    <small><AlertTriangle size={12} /> {item.hold}</small>
                    <ArrowRight class="review-card-arrow" size={15} aria-hidden="true" />
                  </button>
                </div>
              )}
            </For>
          </div>
        </div>

        <article id="review-selected-workbench" class="review-detail-panel">
          <span class="sr-only" role="status" aria-live="polite">
            Selected modeled review example: {selected().title}. Release authority remains unavailable.
          </span>
          <div class="review-detail-head">
            <div>
              <span class="review-source-badge"><ScanSearch size={13} /> MODELED SAMPLE</span>
              <h2>{selected().title}</h2>
              <p>{selected().purpose}</p>
            </div>
            <GatePill>RELEASE GATED</GatePill>
          </div>

          <dl class="review-fact-grid">
            <div><dt>Example reference</dt><dd>{selected().id}</dd></div>
            <div><dt>Workflow lane</dt><dd>{selected().lane}</dd></div>
            <div><dt>Requested output</dt><dd>{selected().requestedOutput}</dd></div>
            <div><dt>Output class</dt><dd>{selected().outputClass}</dd></div>
            <div><dt>Source policy label</dt><dd>{selected().policy}</dd></div>
            <div><dt>Authority state</dt><dd>Unavailable · no decision</dd></div>
          </dl>

          <div class="review-scope-boundary">
            <EyeOff size={18} />
            <div>
              <strong>Minimum necessary review surface</strong>
              <span>
                A production adapter should provide commitments, allowed output shape,
                purpose, expiry, and verification references. Source content, credentials,
                private prompts, and unrestricted evaluator text do not belong here.
              </span>
            </div>
          </div>

          <div class="review-action-bar" aria-label="Release-gated review actions">
            <button class="secondary-button" type="button" disabled aria-describedby="review-actions-gate">
              <Flag size={15} /> Record hold
            </button>
            <button class="secondary-button" type="button" disabled aria-describedby="review-actions-gate">
              <AlertTriangle size={15} /> Request changes
            </button>
            <button class="primary-button" type="button" disabled aria-describedby="review-actions-gate">
              <Signature size={15} /> Sign and release
            </button>
          </div>
          <p id="review-actions-gate" class="review-action-gate-copy">
            <LockKeyhole size={13} /> Roadmap / release gated: no mutation handler is connected.
          </p>
        </article>
      </section>

      <section class="review-controls-section" aria-labelledby="review-controls-title">
        <div class="section-heading split-heading compact-heading">
          <div>
            <p class="overline">Bounded-output policy</p>
            <h2 id="review-controls-title">Five controls before a human can release less.</h2>
          </div>
          <p>
            These rows describe the launch contract for a reviewer adapter. They are
            requirements, not browser-verified checks, and none is presented as passed.
          </p>
        </div>

        <div class="review-policy-grid">
          <For each={OUTPUT_CONTROLS}>
            {(control, index) => (
              <article class="review-policy-card">
                <div>
                  <span>{String(index() + 1).padStart(2, "0")}</span>
                  <CircleDashed size={18} />
                </div>
                <h3>{control.title}</h3>
                <p>{control.detail}</p>
                <small><Clock3 size={12} /> {control.state}</small>
              </article>
            )}
          </For>
        </div>

        <div class="review-egress-contract">
          <div>
            <ShieldCheck size={20} />
            <span><small>DECLARED RETURN SHAPES</small><strong>bands · yes/no · count ranges · reason enums · commitments</strong></span>
          </div>
          <div>
            <ShieldAlert size={20} />
            <span><small>DENIED BY DEFAULT</small><strong>free text · source excerpts · attachments · credentials · internal configuration</strong></span>
          </div>
        </div>
      </section>

      <section class="review-authority-grid" aria-label="Release holds and reviewer authority">
        <div class="review-holds-panel">
          <div class="section-heading compact-heading">
            <div><p class="overline">Fail-closed launch state</p><h2>Release holds</h2></div>
          </div>
          <div class="review-hold-list">
            <For each={RELEASE_HOLDS}>
              {(hold) => (
                <article>
                  <span><AlertTriangle size={16} /></span>
                  <div><strong>{hold.title}</strong><p>{hold.detail}</p></div>
                  <em>HARD HOLD</em>
                </article>
              )}
            </For>
          </div>
        </div>

        <div class="review-signature-panel">
          <div class="section-heading compact-heading">
            <div><p class="overline">Threshold authority</p><h2>Reviewer signatures</h2></div>
          </div>
          <div class="review-signature-boundary">
            <KeyRound size={18} />
            <p>
              <strong>Illustrative policy: 2 of 3 roles.</strong>
              No people, wallet addresses, public keys, signature bytes, or approvals
              are represented. A real roster must come from the pinned reviewer authority.
            </p>
          </div>
          <div class="reviewer-slot-list">
            <For each={REVIEWER_SLOTS}>
              {(slot) => (
                <article>
                  <span><UserRoundCheck size={17} /></span>
                  <div><strong>{slot.role}</strong><small>{slot.duty}</small></div>
                  <dl>
                    <div><dt>Identity binding</dt><dd>Unconfigured</dd></div>
                    <div><dt>Signature</dt><dd>Not requested</dd></div>
                  </dl>
                  <GatePill>RELEASE GATED</GatePill>
                </article>
              )}
            </For>
          </div>
          <button class="secondary-button review-signature-request" type="button" disabled aria-describedby="review-signature-gate">
            <Signature size={15} /> Request reviewer signatures
          </button>
          <p id="review-signature-gate" class="review-action-gate-copy">
            <LockKeyhole size={13} /> Disabled until reviewer identities and the signature domain are independently pinned.
          </p>
        </div>
      </section>

      <section class="review-audit-section" aria-labelledby="review-audit-title">
        <div class="section-heading split-heading compact-heading">
          <div>
            <p class="overline">Illustrative sequence · not an audit log</p>
            <h2 id="review-audit-title">What an accountable trail must prove.</h2>
          </div>
          <p>
            No event below is signed, timestamp-authoritative, persisted, or immutable.
            The sequence only shows the minimum facts a future audit adapter should bind.
          </p>
        </div>
        <div class="review-audit-timeline">
          <For each={MODELED_AUDIT_SEQUENCE}>
            {(event) => (
              <article>
                <span>{event.n}</span>
                <div><History size={17} /><strong>{event.title}</strong><p>{event.detail}</p></div>
                <em>MODELED · NOT RECORDED</em>
              </article>
            )}
          </For>
        </div>
        <div class="review-launch-verdict held" role="status">
          <LockKeyhole size={22} />
          <div>
            <small>REVIEW AUTHORITY VERDICT</small>
            <strong>HELD · 0 OF 5 AUTHORITY PREREQUISITES</strong>
            <span>
              Backend adapter · release policy · reviewer set · signature domain · verified release identity
            </span>
          </div>
          <GatePill>NO RELEASE AUTHORITY</GatePill>
        </div>
      </section>

      <footer class="review-page-footnote">
        <ClipboardCheck size={17} />
        <p>
          <strong>Design invariant:</strong> the browser may help a human understand a
          bounded request, but only an authenticated, replay-resistant, independently
          verified authority path may make or record the release decision.
        </p>
        <Fingerprint size={17} aria-hidden="true" />
        <ListChecks size={17} aria-hidden="true" />
      </footer>
    </div>
  );
}
