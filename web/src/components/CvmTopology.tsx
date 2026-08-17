import { createMemo, For } from "solid-js";
import {
  AlertTriangle,
  Binary,
  CheckCircle2,
  CircleDashed,
  CloudCog,
  Fingerprint,
  LockKeyhole,
  Network,
} from "lucide-solid";
import { computeWorkloadDeployment, deployment } from "../config";
import {
  buildCvmTopologyInventory,
  type CvmTopologyInput,
  type CvmTopologyInventory,
  type CvmTopologyRow,
  type MainRuntimeObservation,
} from "../lib/cvmTopology";

function currentBrowserTopologyInput(
  mainRuntimeObservation: MainRuntimeObservation,
): CvmTopologyInput {
  const projected = computeWorkloadDeployment.trustPolicy
    ? {
        cvmId: computeWorkloadDeployment.trustPolicy.cvmId,
        appId: computeWorkloadDeployment.trustPolicy.appId,
        composeHash: computeWorkloadDeployment.trustPolicy.composeHash,
        osImageHash: computeWorkloadDeployment.trustPolicy.osImageHash,
      }
    : undefined;
  return Object.freeze({
    releaseBound: deployment.releaseIdentityStatus === "release_bound",
    endpointConfigured: Boolean(deployment.delegateUrl),
    additionalConfigurationPresent: Boolean(
      computeWorkloadDeployment.enabled
      || computeWorkloadDeployment.trustPolicy
      || computeWorkloadDeployment.issues.length,
    ),
    mainRuntimeConfig: Object.freeze({
      cvmId: deployment.cvmId,
      appId: deployment.appId,
      composeHash: deployment.composeHash,
      osImageHash: deployment.osImageHash,
    }),
    computeWorkloadProjection: projected,
    mainRuntimeObservation,
  });
}

function rowIcon(row: CvmTopologyRow) {
  if (row.key === "main_runtime_cvm") return <CloudCog size={18} />;
  if (row.key === "independent_metering_cvm") return <Binary size={18} />;
  return <Fingerprint size={18} />;
}

function EvidenceState(props: {
  label: string;
  detail: string;
  state: string;
}) {
  const affirmative = () => (
    props.state === "configured"
    || props.state === "observed"
  );
  const caution = () => (
    props.state === "partial"
    || props.state === "incomplete"
    || props.state === "modeled"
    || props.state === "loading"
    || props.state === "not_established"
  );
  return (
    <div class={`cvm-evidence-state ${props.state}`}>
      <span aria-hidden="true">
        {affirmative()
          ? <CheckCircle2 size={13} />
          : caution()
            ? <CircleDashed size={13} />
            : <AlertTriangle size={13} />}
      </span>
      <div>
        <strong>{props.label}</strong>
        <small>{props.detail}</small>
      </div>
    </div>
  );
}

export function CvmTopologyView(props: {
  inventory: CvmTopologyInventory;
}) {
  return (
    <section
      class="cvm-topology"
      aria-labelledby="cvm-topology-title"
      aria-describedby="cvm-topology-boundary"
    >
      <div class="cvm-topology-heading">
        <div>
          <p class="overline">Release topology · seven independent roles</p>
          <h2 id="cvm-topology-title">One runtime check cannot cover seven CVMs.</h2>
          <p>The release plan separates workload execution, five policy-specific QVL roots, and deterministic metering. Every machine needs its own descriptor, runtime evidence, and appraisal record.</p>
        </div>
        <div class="cvm-topology-summary" role="group" aria-label="Seven-CVM evidence summary">
          <div><strong>{props.inventory.plannedCount}</strong><span>release-planned</span></div>
          <div><strong>{props.inventory.configuredCount}</strong><span>configured</span></div>
          <div><strong>{props.inventory.runtimeObservedCount}</strong><span>runtime responses</span></div>
          <div><strong>{props.inventory.qvlVerifiedCount}</strong><span>QVL verified</span></div>
        </div>
      </div>

      <div id="cvm-topology-boundary" class="cvm-inventory-boundary">
        <Network size={18} />
        <div>
          <strong>Live seven-CVM inventory unavailable</strong>
          <span>No authenticated inventory endpoint or signed seven-CVM evidence set is consumed by this page. Only the configured main-runtime <code>/attestation</code> path can be queried; that one response never covers the other six machines and never becomes a health or QVL verdict.</span>
        </div>
      </div>

      <div class="cvm-stage-legend" aria-label="Inventory evidence-stage legend">
        <span class="planned"><CheckCircle2 size={12} /> Release-planned</span>
        <span class="configured"><CircleDashed size={12} /> Configured</span>
        <span class="observed"><CircleDashed size={12} /> Runtime-observed</span>
        <span class="verified"><Fingerprint size={12} /> Attestation/QVL verified</span>
        <span class="not-deployed"><AlertTriangle size={12} /> Not deployed</span>
      </div>

      <ol class="cvm-topology-grid" aria-label="Expected seven-CVM release roles">
        <For each={props.inventory.rows}>{(row, index) => (
          <li class={row.key === "main_runtime_cvm" ? "main-runtime" : ""}>
            <article aria-labelledby={`cvm-role-${row.key}`}>
              <header>
                <span class="cvm-role-icon" aria-hidden="true">{rowIcon(row)}</span>
                <div>
                  <small>CVM {String(index() + 1).padStart(2, "0")} · {row.category}</small>
                  <h3 id={`cvm-role-${row.key}`}>{row.label}</h3>
                </div>
                <span class="cvm-role-plan"><CheckCircle2 size={11} /> planned</span>
              </header>
              <p>{row.purpose}</p>
              <p class="cvm-independence"><LockKeyhole size={13} /> {row.independence}</p>
              <div class="cvm-evidence-stack">
                <EvidenceState
                  state={row.configuration.state}
                  label={row.configuration.label}
                  detail={row.configuration.detail}
                />
                <EvidenceState
                  state={row.runtime.state}
                  label={row.runtime.label}
                  detail={row.runtime.detail}
                />
                <EvidenceState
                  state={row.verification.state}
                  label={row.verification.label}
                  detail={row.verification.detail}
                />
                <EvidenceState
                  state={row.deployment.state}
                  label={row.deployment.label}
                  detail={row.deployment.detail}
                />
              </div>
            </article>
          </li>
        )}</For>
      </ol>

      <p class="cvm-topology-footnote">
        <Fingerprint size={14} />
        Public environment values are configuration inputs only. Feature flags, verifier addresses, quote digests, and the main-runtime envelope are never used here to infer that a CVM is online, healthy, deployed, or independently verified.
      </p>
    </section>
  );
}

export function CvmTopology(props: {
  mainRuntimeObservation: MainRuntimeObservation;
}) {
  const inventory = createMemo(() => buildCvmTopologyInventory(
    currentBrowserTopologyInput(props.mainRuntimeObservation),
  ));
  return <CvmTopologyView inventory={inventory()} />;
}
