import type { ComputeProviderCapability } from "./compute";

export type ComputeProviderPresentationState =
  | "modeled"
  | "unavailable"
  | "live";

export interface ComputeProviderPresentation {
  state: ComputeProviderPresentationState;
  label: string;
  detail: string;
}

function liveGuarantees(
  capability: ComputeProviderCapability,
): boolean {
  if (
    capability.provider_dispatch !== true
    || !("runtime_guarantees" in capability)
    || !("runtime" in capability)
  ) return false;

  const runtime = capability.runtime;
  return Boolean(
    capability.release_configured === true
    && capability.idempotent_provider_replay_claimed === false
    && capability.automatic_provider_redispatch === false
    && capability.runtime_guarantees.at_most_once_attempt_checkpoint === true
    && capability.runtime_guarantees.terminal_ambiguity_hold === true
    && capability.runtime_guarantees.ambiguous_outcome_ciphertext_retained === true
    && runtime?.authenticated === true
    && runtime.fresh === true
    && runtime.process_presence_only === true
    && runtime.tdx_evidence === false
  );
}

function humanReason(value: string | undefined): string {
  return value?.replaceAll("_", " ") ?? "exact provider capability not returned";
}

export function computeProviderPresentation(
  releaseEnabled: boolean,
  capability: ComputeProviderCapability | undefined,
): ComputeProviderPresentation {
  if (!releaseEnabled) {
    return {
      state: "modeled",
      label: "MODELED",
      detail: "Modeled preview; this release does not claim a production provider worker.",
    };
  }

  if (!capability || !liveGuarantees(capability)) {
    return {
      state: "unavailable",
      label: "UNAVAILABLE",
      detail: `Capability gate: ${humanReason(capability?.reason)}. Service reachability is not treated as provider readiness.`,
    };
  }

  return {
    state: "live",
    label: "LIVE · HEARTBEAT FRESH",
    detail: "The exact release capability reports a fresh authenticated at-most-once worker. Ambiguous outcomes enter a terminal quarantine and are never auto-redispatched; process presence is not TDX evidence.",
  };
}
