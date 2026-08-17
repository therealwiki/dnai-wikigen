export const CVM_RELEASE_TOPOLOGY = Object.freeze([
  Object.freeze({
    key: "main_runtime_cvm",
    label: "Main private runtime",
    category: "Workload boundary",
    purpose: "Diligence, sealed Arena execution, Compute dispatch, and the private email-oracle path.",
    independence: "Observed only through the main runtime's own bounded ingress envelope.",
  }),
  Object.freeze({
    key: "diligence_qvl_cvm",
    label: "Diligence QVL",
    category: "Independent verifier",
    purpose: "Intel DCAP appraisal for Diligence and the separate Email/KMS restart-evidence profile.",
    independence: "A distinct QVL root; the secondary Email/KMS profile does not add an eighth CVM.",
  }),
  Object.freeze({
    key: "arena_qvl_cvm",
    label: "Arena QVL",
    category: "Independent verifier",
    purpose: "Challenge-version and runtime-policy appraisal for sealed Bio/DNA submissions.",
    independence: "Must remain distinct from the main runtime and every other verifier root.",
  }),
  Object.freeze({
    key: "anchor_writer_qvl_cvm",
    label: "Anchor-writer QVL",
    category: "Independent verifier",
    purpose: "Appraisal for the monotonic execution-policy anchor writer.",
    independence: "Verifies the writer release separately from the service that asks it to anchor.",
  }),
  Object.freeze({
    key: "compute_workload_qvl_cvm",
    label: "Compute-workload QVL",
    category: "Independent verifier",
    purpose: "Recipient and workload-ingress appraisal for encrypted inference and training inputs.",
    independence: "A signer pin in browser config is not a CVM descriptor or a current QVL verdict.",
  }),
  Object.freeze({
    key: "compute_metering_qvl_cvm",
    label: "Compute-metering QVL",
    category: "Independent verifier",
    purpose: "Appraisal of the independent meter, policy set, signer custody, and release binding.",
    independence: "Separate from both the meter and the ComputeCreditVault settlement contract.",
  }),
  Object.freeze({
    key: "independent_metering_cvm",
    label: "Deterministic Compute meter",
    category: "Independent workload",
    purpose: "Deterministic usage measurement and bounded exact-asset debit evidence.",
    independence: "Measured independently; it does not self-verify its own TDX evidence.",
  }),
] as const);

export type CvmTopologyKey = typeof CVM_RELEASE_TOPOLOGY[number]["key"];

export type MainRuntimeObservation =
  | "not_checked"
  | "loading"
  | "tdx_envelope_observed"
  | "tdx_envelope_incomplete"
  | "local_modeled"
  | "rejected";

export interface CvmIdentityFragment {
  readonly cvmId?: string;
  readonly appId?: string;
  readonly composeHash?: string;
  readonly osImageHash?: string;
}

export interface CvmTopologyInput {
  readonly releaseBound: boolean;
  readonly endpointConfigured: boolean;
  readonly additionalConfigurationPresent?: boolean;
  readonly mainRuntimeConfig: CvmIdentityFragment;
  readonly computeWorkloadProjection?: CvmIdentityFragment;
  readonly mainRuntimeObservation: MainRuntimeObservation;
}

export type CvmConfigurationState =
  | "configured"
  | "partial"
  | "conflict"
  | "unavailable";

export type CvmRuntimeState =
  | "observed"
  | "incomplete"
  | "modeled"
  | "loading"
  | "rejected"
  | "not_observed"
  | "not_observable";

export type CvmDeploymentState = "not_deployed" | "not_established";

export interface CvmTopologyRow {
  readonly key: CvmTopologyKey;
  readonly label: string;
  readonly category: string;
  readonly purpose: string;
  readonly independence: string;
  readonly configuration: Readonly<{
    state: CvmConfigurationState;
    label: string;
    detail: string;
  }>;
  readonly runtime: Readonly<{
    state: CvmRuntimeState;
    label: string;
    detail: string;
  }>;
  readonly verification: Readonly<{
    state: "unavailable";
    label: "Not QVL verified";
    detail: string;
  }>;
  readonly deployment: Readonly<{
    state: CvmDeploymentState;
    label: string;
    detail: string;
  }>;
}

export interface CvmTopologyInventory {
  readonly rows: readonly CvmTopologyRow[];
  readonly plannedCount: 7;
  readonly configuredCount: number;
  readonly runtimeObservedCount: number;
  readonly qvlVerifiedCount: 0;
  readonly hasLiveInventorySource: false;
  readonly currentBuildNotDeployed: boolean;
}

const IDENTITY_FIELDS = [
  "cvmId",
  "appId",
  "composeHash",
  "osImageHash",
] as const satisfies readonly (keyof CvmIdentityFragment)[];

function normalized(value: string | undefined): string {
  return value?.trim().toLowerCase() ?? "";
}

function hasAnyIdentityField(value: CvmIdentityFragment | undefined): boolean {
  return Boolean(value && IDENTITY_FIELDS.some((field) => normalized(value[field])));
}

function hasCompleteIdentity(value: CvmIdentityFragment | undefined): value is Required<CvmIdentityFragment> {
  return Boolean(value && IDENTITY_FIELDS.every((field) => normalized(value[field])));
}

function identitiesMatch(
  left: Required<CvmIdentityFragment>,
  right: Required<CvmIdentityFragment>,
): boolean {
  return IDENTITY_FIELDS.every((field) => normalized(left[field]) === normalized(right[field]));
}

function mainRuntimeConfiguration(
  input: CvmTopologyInput,
): CvmTopologyRow["configuration"] {
  const configured = input.mainRuntimeConfig;
  const projected = input.computeWorkloadProjection;
  const configuredComplete = hasCompleteIdentity(configured);
  const projectedComplete = hasCompleteIdentity(projected);

  if (configuredComplete && projectedComplete && !identitiesMatch(configured, projected)) {
    return Object.freeze({
      state: "conflict" as const,
      label: "Configuration conflict",
      detail: "Main-runtime and Compute-workload release projections disagree; neither is treated as authoritative.",
    });
  }
  if (configuredComplete || projectedComplete) {
    const source = configuredComplete && projectedComplete
      ? "Main-runtime config and the Compute-workload projection agree on the public CVM identity."
      : projectedComplete
        ? "A complete purpose-specific Compute-workload projection carries the main-runtime identity."
        : "The browser carries a complete main-runtime identity fragment.";
    return Object.freeze({
      state: "configured" as const,
      label: "Configured",
      detail: `${source} Configuration is not runtime observation or deployment proof.`,
    });
  }
  if (
    input.endpointConfigured
    || input.additionalConfigurationPresent
    || hasAnyIdentityField(configured)
    || hasAnyIdentityField(projected)
  ) {
    return Object.freeze({
      state: "partial" as const,
      label: "Partial configuration",
      detail: "Some public main-runtime fields are present, but the CVM ID, app ID, compose hash, and OS image identity are not one complete tuple.",
    });
  }
  return Object.freeze({
    state: "unavailable" as const,
    label: "Descriptor unavailable",
    detail: "No project-owned main-runtime identity is configured in this browser build.",
  });
}

function unavailableConfiguration(): CvmTopologyRow["configuration"] {
  return Object.freeze({
    state: "unavailable" as const,
    label: "Descriptor unavailable",
    detail: "This browser build exposes no release-projected CVM descriptor for this independent role.",
  });
}

function mainRuntimeState(
  observation: MainRuntimeObservation,
): CvmTopologyRow["runtime"] {
  switch (observation) {
    case "tdx_envelope_observed":
      return Object.freeze({
        state: "observed" as const,
        label: "TDX response observed",
        detail: "The main endpoint returned bounded tdx-mode fields. This is reachability and report-data-binding evidence, not health or independent QVL verification.",
      });
    case "tdx_envelope_incomplete":
      return Object.freeze({
        state: "incomplete" as const,
        label: "Response observed · incomplete",
        detail: "The main endpoint responded in tdx mode, but its quote or identity fields were incomplete and remain blocked.",
      });
    case "local_modeled":
      return Object.freeze({
        state: "modeled" as const,
        label: "Local model only",
        detail: "A simulator envelope is useful for interface testing but is not observation of a production TDX deployment.",
      });
    case "loading":
      return Object.freeze({
        state: "loading" as const,
        label: "Observation in progress",
        detail: "Only the configured main-runtime endpoint is being queried.",
      });
    case "rejected":
      return Object.freeze({
        state: "rejected" as const,
        label: "Observation rejected",
        detail: "The main-runtime response failed the bounded browser inspection and supplies no accepted runtime evidence.",
      });
    default:
      return Object.freeze({
        state: "not_observed" as const,
        label: "Not observed",
        detail: "The browser has not accepted a production tdx-mode response from the main runtime.",
      });
  }
}

function unavailableRuntime(): CvmTopologyRow["runtime"] {
  return Object.freeze({
    state: "not_observable" as const,
    label: "No observation path",
    detail: "No public runtime endpoint or authenticated inventory record for this role is consumed by the Trust Center.",
  });
}

function unavailableVerification(): CvmTopologyRow["verification"] {
  return Object.freeze({
    state: "unavailable" as const,
    label: "Not QVL verified" as const,
    detail: "No signed seven-CVM evidence set, raw quote appraisal, or current QVL verdict for this role is verified by this page.",
  });
}

function deploymentState(
  currentBuildNotDeployed: boolean,
): CvmTopologyRow["deployment"] {
  if (currentBuildNotDeployed) {
    return Object.freeze({
      state: "not_deployed" as const,
      label: "Not deployed",
      detail: "This build has no project-owned release identity or CVM configuration; source readiness is not a deployment.",
    });
  }
  return Object.freeze({
    state: "not_established" as const,
    label: "Deployment not established",
    detail: "Configuration or endpoint reachability alone is not a deployment receipt or a seven-CVM activation record.",
  });
}

/**
 * Projects only evidence the browser actually owns.
 *
 * The current frontend has one bounded main-runtime observation path and no
 * authenticated seven-CVM inventory feed. In particular, verifier addresses,
 * feature flags, and quote-digest environment values are intentionally not
 * promoted into CVM health, deployment, or independent QVL verdicts.
 */
export function buildCvmTopologyInventory(
  input: CvmTopologyInput,
): CvmTopologyInventory {
  const anyConfiguration = input.endpointConfigured
    || Boolean(input.additionalConfigurationPresent)
    || hasAnyIdentityField(input.mainRuntimeConfig)
    || hasAnyIdentityField(input.computeWorkloadProjection);
  const currentBuildNotDeployed = !input.releaseBound && !anyConfiguration;
  const mainConfiguration = mainRuntimeConfiguration(input);
  const mainRuntime = mainRuntimeState(input.mainRuntimeObservation);
  const deployment = deploymentState(currentBuildNotDeployed);

  const rows = CVM_RELEASE_TOPOLOGY.map((role) => Object.freeze({
    ...role,
    configuration: role.key === "main_runtime_cvm"
      ? mainConfiguration
      : unavailableConfiguration(),
    runtime: role.key === "main_runtime_cvm"
      ? mainRuntime
      : unavailableRuntime(),
    verification: unavailableVerification(),
    deployment,
  })) satisfies CvmTopologyRow[];

  return Object.freeze({
    rows: Object.freeze(rows),
    plannedCount: 7 as const,
    configuredCount: rows.filter((row) => row.configuration.state === "configured").length,
    runtimeObservedCount: rows.filter(
      (row) => row.runtime.state === "observed" || row.runtime.state === "incomplete",
    ).length,
    qvlVerifiedCount: 0 as const,
    hasLiveInventorySource: false as const,
    currentBuildNotDeployed,
  });
}
