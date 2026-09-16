import {
  assertFreshPhalaNonLiveBootstrapAuthorizationReceipt,
} from "./phala-nonlive-bootstrap-authorization.mjs";
import {
  assemblePrivateBootstrapEnvironment,
} from "./phala-production-environment-authority.mjs";

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

/**
 * The private environment assembler deliberately lives outside the
 * cryptographic signed-A verifier module. This prevents verifier-only import
 * graphs from reaching secret-file, executor, replay, or SDK mutation code.
 */
export function assembleAuthorizedPrivateBootstrapEnvironment({
  authorizationReceipt,
  checkpoint,
  nowMs,
  expectedAuthorizationId,
  expectedTargetAuthoritySha256,
  expectedStagingReceiptSha256,
  environmentAssembly,
} = {}) {
  const options = exactRecord(environmentAssembly, [
    "domain",
    "now",
    "bootstrapAuthority",
    "provisioningAuthority",
    "secretInput",
  ], "authorized environment assembly");
  const provisioning = options.provisioningAuthority;
  assertFreshPhalaNonLiveBootstrapAuthorizationReceipt({
    receipt: authorizationReceipt,
    checkpoint,
    nowMs,
    expectedBatchId: provisioning?.batch_id,
    expectedAuthorizationId,
    expectedTargetAuthoritySha256,
    expectedStagingReceiptSha256,
  });
  return assemblePrivateBootstrapEnvironment(options);
}
