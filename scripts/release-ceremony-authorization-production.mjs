import {
  assertFreshBrandedPreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
} from "./pre-ceremony-runtime-authority.mjs";
import {
  assertCeremonyReviewInsideRuntimeAuthorityWindow,
  ceremonyAuthorizationReviewSigningPayload,
  normalizeCeremonyAuthorizationCore,
} from "./release-ceremony-authorization.mjs";

function fail(message) {
  throw new TypeError(message);
}

function dependencyPins(payload) {
  return Object.fromEntries(payload.dependencies.map((entry) => [
    entry.kind,
    entry.sha256,
  ]));
}

/**
 * Production-only Stage-B signing projection. The pure validator deliberately
 * has no access to the WeakMap production brand; only this facade can accept a
 * same-process R minted by the live activation coordinator.
 */
export function ceremonyAuthorizationReviewSigningPayloadForProduction(
  unsignedBody,
  reviewMetadata,
  { preCeremonyRuntimeAuthority } = {},
) {
  const authority = assertFreshBrandedPreCeremonyRuntimeAuthority(
    preCeremonyRuntimeAuthority,
  );
  const payload = ceremonyAuthorizationReviewSigningPayload(
    unsignedBody,
    reviewMetadata,
  );
  const dependencies = dependencyPins(payload);
  if (payload.release_sha !== authority.release_sha
    || dependencies.deployment_intent !== authority.deployment_intent_sha256
    || dependencies.cvm_launch_intent !== authority.cvm_launch_intent_sha256
    || dependencies.pre_ceremony_runtime_authority
      !== preCeremonyRuntimeAuthoritySha256(authority)) {
    fail("production ceremony signing body does not bind the exact fresh branded R");
  }
  assertCeremonyReviewInsideRuntimeAuthorityWindow(reviewMetadata, authority);
  return payload;
}

export function assertFreshProductionCeremonyAuthorizationCore(
  value,
  options = {},
) {
  assertFreshBrandedPreCeremonyRuntimeAuthority(
    options.preCeremonyRuntimeAuthority,
  );
  return normalizeCeremonyAuthorizationCore(value, {
    ...options,
    enforceFreshness: true,
  });
}
