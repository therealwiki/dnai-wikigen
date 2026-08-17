import {
  LIVE_ACTIVATION_AUTHORITY_SCHEMA,
} from "./release-ceremony-authorization.mjs";
import {
  assertHistoricalLiveActivationComputeWorkloadObservationBinding as
    assertCurrentCWorkloadObservationBinding,
  normalizeLiveActivationAuthority as normalizeCurrentC,
  projectLiveActivationFrontendBinding as projectCurrentCFrontendBinding,
} from "./release-authority-stages.mjs";

/**
 * Narrow, capability-free browser-build facade for signed current C.
 *
 * This module deliberately exposes only v6 C normalization, its v4 frontend
 * projection, and the exact binding to an independently replayed historical O.
 * It does not export deployment executors, production brands, legacy C
 * down-projections, filesystem locks, or ceremony mutation helpers.
 */
export const CURRENT_LIVE_ACTIVATION_AUTHORITY_SCHEMA =
  "dnai.live-activation-authority.v6";

if (LIVE_ACTIVATION_AUTHORITY_SCHEMA
    !== CURRENT_LIVE_ACTIVATION_AUTHORITY_SCHEMA) {
  throw new TypeError("current C facade schema drifted from the v6 authority core");
}

export function normalizeLiveActivationAuthority(value, options = {}) {
  return normalizeCurrentC(value, options);
}

export function projectLiveActivationFrontendBinding(value, options = {}) {
  return projectCurrentCFrontendBinding(value, options);
}

export function assertHistoricalLiveActivationComputeWorkloadObservationBinding(
  options = {},
) {
  return assertCurrentCWorkloadObservationBinding(options);
}
